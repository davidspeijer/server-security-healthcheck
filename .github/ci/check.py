"""Small stdlib CI checks; runtime mode is intentionally Python 3.6 compatible."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import py_compile

ROOT = Path(__file__).resolve().parents[2]


def git(*args):
    return subprocess.check_output(['git'] + list(args), cwd=str(ROOT)).decode().strip()


def shell_files():
    names = subprocess.check_output(['git', 'ls-files', '-z', '--cached', '--others',
                                     '--exclude-standard'], cwd=str(ROOT)).split(b'\0')
    paths = []
    for name in sorted(set(names)):
        if not name:
            continue
        path = ROOT / os.fsdecode(name)
        if not path.is_file():
            continue
        first = path.read_bytes().split(b'\n', 1)[0]
        if path.suffix == '.sh' or re.match(br'^#!.*\b(?:ba)?sh(?:\s|$)', first):
            paths.append(path.relative_to(ROOT).as_posix())
    assert paths, 'No shell files discovered'
    return paths


def version():
    entry = ROOT / 'bin/server-security-healthcheck'
    current = re.search(r'^APP_VERSION="([0-9]+\.[0-9]+\.[0-9]+)"$',
                        entry.read_text(), re.M).group(1)
    actual = subprocess.check_output(['bash', str(entry), '--version']).decode().strip()
    assert actual == 'server-security-healthcheck v' + current, actual
    readme = re.search(r'^Current (?:release candidate|stable release):.*?\*\*v([^*]+)\*\*',
                       (ROOT / 'README.md').read_text(), re.M).group(1)
    changelog = re.search(r'^## \[([0-9]+\.[0-9]+\.[0-9]+)\]',
                         (ROOT / 'CHANGELOG.md').read_text(), re.M).group(1)
    assert current == readme == changelog, (current, readme, changelog)
    for name in ['test_healthcheck.py', 'test_audit_round3.py']:
        matches = re.findall(r'server-security-healthcheck v([0-9]+\.[0-9]+\.[0-9]+)',
                             (ROOT / 'tests' / name).read_text())
        assert matches and all(x == current for x in matches), (name, matches)
    text = (ROOT / 'tests/test_json_output.py').read_text()
    expected = re.search(r"assertEqual\(data\['application'\]\['version'\], '([^']+)'\)", text).group(1)
    assert expected == current, expected
    print('Version consistency: ' + current)


def whitespace():
    event_path = os.environ.get('GITHUB_EVENT_PATH')
    if event_path:
        with open(event_path) as stream:
            event = json.load(stream)
        kind = os.environ.get('GITHUB_EVENT_NAME')
        if kind == 'pull_request':
            # Checkout's synthetic merge commit includes the base: comparing it
            # with the event base tests only the PR changes, without deep history.
            base = event['pull_request']['base']['sha']
        elif kind == 'push':
            base = event['before']
        else:
            base = git('rev-parse', 'HEAD^') if git('rev-list', '--count', 'HEAD') != '1' else '0' * 40
        assert re.fullmatch(r'[0-9a-fA-F]{40}', base), 'Invalid event commit ID'
        if base == '0' * 40:
            base = git('hash-object', '-t', 'tree', '--stdin')
        elif subprocess.call(['git', 'cat-file', '-e', base + '^{commit}'],
                             cwd=str(ROOT), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL):
            subprocess.check_call(['git', 'fetch', '--no-tags', '--depth=1', 'origin', base], cwd=str(ROOT))
        subprocess.check_call(['git', 'diff', '--check', base, 'HEAD'], cwd=str(ROOT))
        print('Committed whitespace range: ' + base + '..HEAD')
    subprocess.check_call(['git', 'diff', '--check'], cwd=str(ROOT))
    subprocess.check_call(['git', 'diff', '--cached', '--check'], cwd=str(ROOT))


def runtime(expected):
    assert sys.version_info[:3] == tuple(map(int, expected.split('.'))), sys.version
    print(sys.version)
    paths = sorted((ROOT / 'lib').rglob('*.py'))
    assert paths, 'No runtime helpers discovered'
    sys.path.insert(0, str(ROOT / 'lib/checks'))
    with tempfile.TemporaryDirectory(prefix='sshc-runtime-') as scratch:
        for index, path in enumerate(paths):
            py_compile.compile(str(path), cfile=str(Path(scratch) / (str(index) + '.pyc')), doraise=True)
            spec = importlib.util.spec_from_file_location(path.stem, str(path))
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            print('compile/import: ' + str(path.relative_to(ROOT)))
    output = subprocess.check_output([sys.executable, str(ROOT / 'lib/checks/output.py'), 'self-test']).decode().strip()
    assert output == 'SSHC_JSON_SCHEMA_1', output
    print('JSON helper self-test: PASS')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('mode', choices=['static', 'shell-list', 'runtime'])
    parser.add_argument('--expected-python', default='3.6.8')
    args = parser.parse_args()
    if args.mode == 'shell-list':
        print('\n'.join(shell_files()))
    elif args.mode == 'runtime':
        runtime(args.expected_python)
    else:
        whitespace()
        for name in shell_files():
            print('bash -n: ' + name, flush=True)
            subprocess.check_call(['bash', '-n', str(ROOT / name)])
        version()


if __name__ == '__main__':
    main()
