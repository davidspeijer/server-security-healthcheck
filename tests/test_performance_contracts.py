"""Presentation and JSON bootstrap compatibility boundaries for performance work."""
import json
import shutil
import subprocess
import unittest

import test_healthcheck as fixture


class PresentationTests(unittest.TestCase):
    setUp = fixture.HealthcheckTests.setUp

    def shell(self, code):
        return subprocess.run(['/bin/bash', '-c', 'source ' + fixture.Q(str(fixture.ROOT / 'lib/common.sh')) + '; ' + code],
                              env=self.env, capture_output=True, text=True)

    def test_all_controls_escape_without_changing_printable_unicode(self):
        value = '€😀\u0085' + ''.join(chr(i) for i in range(1, 32)) + chr(127) + r'\n'
        escaped = ''.join({9: r'\t', 10: r'\n', 13: r'\r'}.get(i, r'\x%02x' % i)
                          for i in range(1, 32))
        result = self.shell('hc_present ' + fixture.Q(value))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, '€😀\u0085' + escaped + r'\x7f\n')

    def test_reporter_retains_raw_redacted_state_and_escaped_detail(self):
        value = 'a\nb\t€ fixture_secret'
        result = self.shell('TELEGRAM_BOT_TOKEN=fixture_secret; hc_detail ' + fixture.Q(value) +
                            '; printf "\\0%s\\0%s\\0%s" "$HC_PRESENT_VALUE" "${HC_DETAILS[0]}" "${HC_RESULT_COUNTS[INFO]}"')
        self.assertEqual(result.returncode, 0, result.stderr)
        console, raw, retained, count = result.stdout.split('\0')
        self.assertEqual(console, '  INFO a\\nb\\t€ [REDACTED]\n')
        self.assertEqual(raw, 'a\nb\t€ [REDACTED]')
        self.assertEqual(retained, 'a\\nb\\t€ [REDACTED]')
        self.assertEqual(count, '1')

    def test_reporting_preserves_callers_regex_captures(self):
        result = self.shell('[[ fixture =~ ^(fix)(ture)$ ]]; hc_detail ordinary; '
                            'printf "%s:%s" "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}"')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, '  INFO ordinary\nfix:ture')


class BootstrapTests(unittest.TestCase):
    setUp = fixture.HealthcheckTests.setUp
    main = fixture.HealthcheckTests.main

    def test_self_test_keeps_script_filename_argv_and_import_context(self):
        library = self.work / 'library'
        shutil.copytree(fixture.ROOT / 'lib', library)
        helper = library / 'checks/output.py'
        helper.write_text('import builtins, os, sys\nif __name__ == "__main__":\n'
                          '    assert sys.argv[0] == __file__\n'
                          '    assert sys.path[0] == os.path.dirname(__file__)\n'
                          '    assert __package__ is None and __spec__ is None\n'
                          '    assert sys.modules["__main__"].__dict__ is globals()\n'
                          '    assert __loader__.get_filename("__main__") == __file__\n'
                          '    assert __builtins__ is builtins\n' + helper.read_text())
        result = self.main('', ['--json'], library)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)['run']['exit_code'], 0)
