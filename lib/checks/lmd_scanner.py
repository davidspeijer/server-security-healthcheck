"""Read LMD scanner logs as data. Compatible with production Python >=3.6.

No stat of reported paths, subprocesses, imports from logs, or writes. The log
has no scan ID: only a single non-overlapping block inside the session interval
can establish a result. Rotation order is explicit, never based on file mtime.
"""
import gzip
import locale
import re
import sys
import shlex
import datetime
import time
import os
from collections import namedtuple
from pathlib import Path
sys.dont_write_bytecode = True  # Runtime parsing must not write installed libraries.
from bounded_input import lines, arm_timeout, BudgetExceeded, file_identity, local_epoch

MARKER = re.compile(r'^(...\s+\d{1,2} \d{4} \d{2}:\d{2}:\d{2}) (\S+) clamscan (start|end return ([012]))$')
EXECUTED = re.compile(r'^(...\s+\d{1,2} \d{4} \d{2}:\d{2}:\d{2}) (\S+) executed: (.+)$')
ACCESS = re.compile(r"^ERROR: Can't access file (/[^\t\r\n]+)$")
VOLATILE = re.compile(r'/(?:tmp|cache|upgrade)/|/wp-content/uploads/elementor/css/')


def scanner_command(command):
    """Recognize LMD's literal executable/wrapper grammar; never execute input."""
    tokens = shlex.split(command)
    if not tokens or any(c in command for c in '\n\r;|&`$<>'):
        return False
    def binary(token, name):
        return token in ('/usr/bin/' + name, '/bin/' + name)
    i = 0
    if binary(tokens[i], 'cpulimit'):
        if len(tokens) < 5 or tokens[1] != '-l' or not re.fullmatch(r'[1-9]\d*', tokens[2]) or tokens[3] != '--':
            return False
        i = 4
    if binary(tokens[i], 'nice'):
        if len(tokens) < i + 4 or tokens[i+1] != '-n' or not re.fullmatch(r'-?\d+', tokens[i+2]):
            return False
        i += 3
    if i < len(tokens) and binary(tokens[i], 'ionice'):
        if len(tokens) < i + 5 or tokens[i+1] != '-c2' or tokens[i+2] != '-n' or not re.fullmatch(r'[0-7]', tokens[i+3]):
            return False
        i += 4
    if i >= len(tokens) or tokens[i] not in (
        '/usr/bin/clamdscan', '/bin/clamdscan', '/usr/local/bin/clamdscan',
        '/usr/bin/clamscan', '/bin/clamscan', '/usr/local/bin/clamscan',
        '/usr/local/cpanel/3rdparty/bin/clamscan', '/usr/local/cpanel/3rdparty/bin/clamdscan'):
        return False
    args = tokens[i+1:]
    # LMD invokes a file-list scan. A scanner --version/--help invocation is
    # not scan coverage even though its executable and exit zero are genuine.
    if len(args) < 2 or args[-2] != '-f' or not args[-1].startswith('/'):
        return False
    args = args[:-2]
    j = 0
    while j < len(args):
        option = args[j]
        if option in ('--infected', '--no-summary', '--fdpass', '-r'):
            j += 1
        elif option in ('-c', '-d') and j+1 < len(args) and args[j+1].startswith('/'):
            j += 2
        elif re.fullmatch(r'--max-(?:file|scan)size=[0-9]+', option):
            j += 1
        else:
            return False
    return True


def outside_stamp(stamp, started, ended):
    # Offset-free malformed/DST stamps are irrelevant only when their calendar
    # representation proves them outside the requested local interval.
    try:
        value = datetime.datetime.strptime(stamp, '%b %d %Y %H:%M:%S')
    except ValueError:
        try:
            # A valid date with a corrupt time can still prove a remote day.
            value = datetime.datetime.strptime(stamp[:11], '%b %d %Y')
            lo_day = datetime.datetime.fromtimestamp(started).date()
            hi_day = datetime.datetime.fromtimestamp(ended).date()
            return value.date() < lo_day or value.date() > hi_day
        except ValueError:
            return False
    lo = datetime.datetime.fromtimestamp(started)
    hi = datetime.datetime.fromtimestamp(ended)
    return value < lo - datetime.timedelta(hours=2) or value > hi + datetime.timedelta(hours=2)


ScannerSnapshot = namedtuple('ScannerSnapshot', 'files histories')


def capture(directory, sessions=None):
    """Freeze inventory/order/identity/content; reject changes during capture."""
    from bounded_input import limit
    def inventory():
        return {path: file_identity(os.stat(str(path)))
                for path in Path(directory).glob('clamscan_log*')}
    before = inventory()
    files = []
    total = 0
    for path, identity in before.items():
        suffix = path.name[len('clamscan_log'):]
        if not suffix:
            key = (2, 0)
        elif re.fullmatch(r'-\d{8}(?:\.gz)?', suffix):
            key = (0, int(suffix[1:9]))
        elif re.fullmatch(r'\.\d+(?:\.gz)?', suffix):
            key = (1, -int(suffix.split('.')[1]))
        else:
            raise ValueError('unsupported rotation')
        content = tuple(lines(str(path), identity))
        total += sum(len(item.encode('utf-8')) for item in content)
        if total > limit('MAX_EXPANDED_BYTES', 128 * 1024 * 1024):
            raise ValueError('aggregate scanner budget exceeded')
        files.append((key, path, identity, content))
    if not files or len({item[0] for item in files}) != len(files):
        raise ValueError('missing or duplicate logs')
    if any(item[0][0] == 0 for item in files) and any(item[0][0] == 1 for item in files):
        raise ValueError('mixed rotation')
    histories = []
    history_directory = Path(sessions or str(Path(directory).parent / 'sess'))
    history_before = {path: file_identity(os.stat(str(path))) for path in history_directory.glob('scan.meta.*')}
    for path, identity in history_before.items():
        fields = {}
        for line in lines(str(path), identity):
            total += len(line.encode('utf-8'))
            if total > limit('MAX_EXPANDED_BYTES', 128 * 1024 * 1024):
                raise ValueError('aggregate scanner budget exceeded')
            key, separator, value = line.rstrip('\n').partition('=')
            if separator:
                fields[key] = value
        start, end = fields.get('started', ''), fields.get('completed', '')
        if re.fullmatch(r'[0-9]{1,12}', start) and re.fullmatch(r'[0-9]{1,12}', end):
            histories.append((int(start), int(end), fields.get('state', '')))
    history_after = {path: file_identity(os.stat(str(path))) for path in history_directory.glob('scan.meta.*')}
    if history_after != history_before:
        raise ValueError('historical metadata changed during capture')
    if inventory() != before:
        raise ValueError('scanner inventory changed during capture')
    return ScannerSnapshot(tuple(sorted(files)), tuple(histories))


def historical_finished(snapshot, scanner_started, current_started):
    proofs = [state in ('completed', 'failed', 'aborted', 'killed', 'error', 'cancelled', 'canceled')
              for start, end, state in snapshot.histories
              if 0 < start <= scanner_started <= end < current_started]
    return bool(proofs) and all(proofs)


def result(directory, started, ended, sessions=None, snapshot=None):
    if not 0 < started <= ended:
        raise ValueError('invalid interval')
    snapshot = snapshot if snapshot is not None else capture(directory, sessions)
    files = [(key, path) for key, path, identity, content in snapshot.files]
    active = None
    candidates = []
    previous_epoch = 0
    historical_starts = []
    relevant_files = set()
    for _, path, identity, log in snapshot.files:
        opener = gzip.open if path.name.endswith('.gz') else open
        for raw in log:
            if '\x00' in raw:
                raise ValueError('NUL in scanner text')
            line = raw.rstrip('\n')
            marker = MARKER.fullmatch(line)
            if marker:
                stamp, host, kind, code = marker.groups()
                # Local LMD timestamps lack an offset. DST ambiguity must
                # not silently select the wrong scan interval.
                try:
                    epoch = local_epoch(stamp)
                except ValueError:
                    if active is None and outside_stamp(stamp, started, ended):
                        continue
                    raise
                if epoch < started:
                    if active is not None:
                        raise ValueError('out-of-interval marker inside scan')
                    if kind == 'start': historical_starts.append(epoch)
                    elif historical_starts: historical_starts.pop()
                    continue
                if epoch > ended:
                    if active is not None:
                        raise ValueError('interval overlap')
                    continue
                relevant_files.add(path.name)
                if epoch < previous_epoch:
                    raise ValueError('unordered markers')
                previous_epoch = epoch
                if kind == 'start':
                    if active is not None or any(not historical_finished(snapshot, old, started) for old in historical_starts):
                        raise ValueError('overlapping scans')
                    historical_starts = []
                    active = dict(start=epoch, host=host, access=0, volatile=0,
                                  other=0, executed=0, executed_epoch=epoch)
                else:
                    if active is not None:
                        if active['host'] != host:
                            raise ValueError('host conflict')
                        if not active['start'] <= active['executed_epoch'] <= epoch:
                            raise ValueError('invocation timestamp conflict')
                        if started <= active['start'] <= epoch <= ended:
                            active['exit'] = int(code)
                            candidates.append(active)
                        elif active['start'] <= ended and epoch >= started:
                            raise ValueError('interval overlap')
                    elif started <= epoch <= ended:
                        raise ValueError('missing start')
                    active = None
            elif 'clamscan start' in line or 'clamscan end' in line:
                if active is not None or not outside_stamp(line[:20], started, ended):
                    raise ValueError('malformed marker')
            elif active is None and EXECUTED.fullmatch(line):
                stamp = EXECUTED.fullmatch(line).group(1)
                if not outside_stamp(stamp, started, ended):
                    epoch = local_epoch(stamp)
                    if started <= epoch <= ended:
                        raise ValueError('invocation without boundary')
            elif active is not None:
                relevant_files.add(path.name)
                access = ACCESS.fullmatch(line)
                if access:
                    active['access'] += 1
                    active['volatile'] += int(bool(VOLATILE.search(access.group(1))))
                elif EXECUTED.fullmatch(line):
                    stamp, host, command = EXECUTED.fullmatch(line).groups()
                    if host != active['host'] or not scanner_command(command):
                        raise ValueError('invocation conflict')
                    active['executed_epoch'] = local_epoch(stamp)
                    active['executed'] += 1
                elif line.strip():
                    # Unknown stderr, warnings and retries are not evidence
                    # of an access-only outcome.
                    active['other'] += 1
    # A numeric gap between files carrying a scan may hide diagnostics.
    ordered = sorted(files)
    relevant_indices = [i for i, (_, path) in enumerate(ordered) if path.name in relevant_files]
    relevant_keys = [key for key, _ in ordered[min(relevant_indices):max(relevant_indices)+1]] if relevant_indices else []
    if len(relevant_keys) > 1 and all(key[0] in (1, 2) for key in relevant_keys):
        numbers = [-key[1] if key[0] == 1 else 0 for key in relevant_keys]
        if any(a - b != 1 for a, b in zip(numbers, numbers[1:])):
            raise ValueError('missing relevant rotation')
    if active is not None and active['start'] <= ended:
        raise ValueError('missing end')
    if len(candidates) != 1 or candidates[0]['executed'] != 1:
        raise ValueError('ambiguous scanner invocation')
    item = candidates[0]
    code, access, other = item['exit'], item['access'], item['other']
    if other or (code == 2 and not access) or (code == 0 and access):
        state = 'failure'
    elif access:
        state = 'access_errors'
    else:
        state = 'clean' if code == 0 else 'detections'
    return state, code, access, item['volatile'], other


def batch(directory, sessions, metadata, semantic_failures=False):
    """One immutable log snapshot per invocation; interval state remains local."""
    requests = set()
    for path in Path(metadata).glob('scan.meta.*'):
        fields = {}
        for line in lines(str(path)):
            key, sep, value = line.rstrip('\n').partition('=')
            if sep:
                fields[key] = value
        try:
            requests.add((int(fields['started']), int(fields['completed'])))
        except (KeyError, ValueError):
            continue
    try:
        snapshot = capture(directory, sessions)
    except (OSError, EOFError, ValueError, OverflowError):
        if not semantic_failures:
            raise
        snapshot = None
    output = []
    for started, ended in sorted(requests):
        try:
            item = result(directory, started, ended, sessions, snapshot) if snapshot is not None else ('unknown', '-', 0, 0, 0)
        except (OSError, EOFError, ValueError, OverflowError):
            item = ('unknown', '-', 0, 0, 0)
        output.append((str(started) + ':' + str(ended),) + item)
    return output


if __name__ == '__main__':
    locale.setlocale(locale.LC_TIME, 'C')
    arm_timeout()
    try:
        if sys.argv[1] == '--batch':
            for row in batch(*sys.argv[2:5], semantic_failures=True):
                print('\t'.join(map(str, row)))
        else:
            print('\t'.join(map(str, result(sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), sys.argv[4] if len(sys.argv) > 4 else None))))
    except (OSError, EOFError, ValueError, OverflowError, IndexError, BudgetExceeded):
        if sys.argv[1:2] == ['--batch']:
            sys.exit(1)
        print('unknown\t-\t0\t0\t0')
