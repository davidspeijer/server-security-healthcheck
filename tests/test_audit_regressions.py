"""Offline F01-F06 regressions; fixture commands never manage host services."""
import gzip
import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import unittest
import test_healthcheck as fixture

SPEC = importlib.util.spec_from_file_location('scanner', fixture.ROOT / 'lib/checks/lmd_scanner.py')
scanner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(scanner)


class RequiredModulesTests(unittest.TestCase):
    setUp = fixture.HealthcheckTests.setUp
    main = fixture.HealthcheckTests.main

    def library(self, body=None):
        library = self.work / 'library'
        shutil.copytree(fixture.ROOT / 'lib', library)
        if body is not None:
            (library / 'checks/disk.sh').write_text(body)
        return library

    def failed(self, library, cause):
        result = self.main('CHECK_DISK=1\n', lib_dir=library)
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn(cause, result.stdout)
        self.assertNotIn('OK all enabled checks passed', result.stdout)

    def test_missing_required_module(self):
        lib = self.library(); (lib / 'checks/disk.sh').unlink()
        self.failed(lib, 'Required check module missing')

    def test_unreadable_required_module(self):
        lib = self.library()
        config = self.work / 'config'; config.mkdir()
        (config / 'healthcheck.conf').write_text('CHECK_DISK=1\nCHECK_APACHE=0\nCHECK_RSPAMD=0\nCHECK_PUREFTP=0\n')
        # Root can read chmod(000) files: inject only the read predicate rather
        # than falsely claiming that chmod models permission denial for root.
        script = '''[() { if [[ "$1" = ! && "$2" = -r && "$3" = */checks/disk.sh ]]; then return 0; fi; builtin [ "$@"; }
export -f '['
exec bash "$ENTRYPOINT"
'''
        env = dict(self.env, SSHC_CONFIG_DIR=str(config), SSHC_LIB_DIR=str(lib), ENTRYPOINT=str(fixture.ROOT / 'bin/server-security-healthcheck'))
        result = subprocess.run([fixture.BASH, '-c', script], env=env, text=True, capture_output=True)
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn('Check module unreadable', result.stdout)

    def test_syntax_error(self):
        self.failed(self.library('hc_register_check disk\ncheck_disk() {\n'), 'syntax error')

    def test_source_failure(self):
        self.failed(self.library('hc_register_check disk\ncheck_disk() { hc_status PASS BAD; }\nreturn 1\n'), 'source failed')

    def test_function_not_registered(self):
        self.failed(self.library('check_disk() { :; }\n'), 'not registered')

    def test_registered_function_missing(self):
        self.failed(self.library('hc_register_check disk\n'), 'not registered')

    def test_other_module_still_executes(self):
        lib = self.library('return 1\n')
        (lib / 'checks/exim.sh').write_text('hc_register_check exim\ncheck_exim() { hc_status WARNING "fixture executed"; }\n')
        result = self.main('CHECK_DISK=1\nCHECK_EXIM=1\n', lib_dir=lib)
        self.assertEqual(result.returncode, 2)
        self.assertIn('fixture executed', result.stdout)

    def test_disabled_missing_module(self):
        lib = self.library(); (lib / 'checks/disk.sh').unlink()
        self.assertEqual(self.main('', lib_dir=lib).returncode, 0)

    def test_required_check_runs(self):
        lib = self.library('hc_register_check disk\ncheck_disk() { hc_status PASS "fixture executed"; }\n')
        result = self.main('CHECK_DISK=1\n', lib_dir=lib)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('fixture executed', result.stdout)

    def test_auto_requires_discovery_module(self):
        lib = self.library(); (lib / 'checks/apache.sh').unlink()
        result = self.main('CHECK_APACHE=auto\n', lib_dir=lib)
        self.assertEqual(result.returncode, 2)
        self.assertIn('apache.sh', result.stdout)

    def test_lmd_policy_dependency_missing(self):
        lib = self.library(); (lib / 'checks/lmd_policy.sh').unlink()
        result = self.main('CHECK_LMD=1\n', lib_dir=lib)
        self.assertEqual(result.returncode, 2)
        self.assertIn('lmd_policy.sh', result.stdout)
        self.assertNotIn('command not found', result.stderr)

    def test_lmd_policy_missing_expected_function(self):
        lib = self.library(); (lib / 'checks/lmd_policy.sh').write_text(':\n')
        result = self.main('CHECK_LMD=1\n', lib_dir=lib)
        self.assertEqual(result.returncode, 2)
        self.assertIn('LMD policy module function missing', result.stdout)
        self.assertNotIn('command not found', result.stderr)

    def test_extension_cannot_replace_missing_required_module(self):
        lib = self.library(); (lib / 'checks/disk.sh').unlink()
        (lib / 'checks/extension.sh').write_text('hc_register_check disk\ncheck_disk() { :; }\n')
        self.failed(lib, 'Required check module missing')

    def test_failed_execution_is_error(self):
        self.failed(self.library('hc_register_check disk\ncheck_disk() { return 1; }\n'), 'Check execution failed')


class HitConsistencyTests(unittest.TestCase):
    setUp = fixture.HealthcheckTests.setUp
    run_shell = fixture.HealthcheckTests.run_shell
    append_meta = fixture.HealthcheckTests.append_meta
    fullscan = fixture.HealthcheckTests.fullscan

    def report(self, records, hits):
        header = (fixture.FIXTURES / 'session.malware.tsv').read_text().splitlines()[0].split('\t')
        header[11] = str(hits)
        self.session.write_text('\t'.join(header) + '\n' + records)

    def malware(self, signature='{HEX}php.backdoor.example'):
        kind = signature[1:signature.index('}')] if signature.startswith('{') else 'HEX'
        return signature + '\t/home/file\t-\t' + kind + '\tHit Match\t-\t0\troot\troot\t644\t0\n'

    def test_lifecycle_zero_does_not_override_tsv(self):
        self.append_meta(hits=0)
        self.report(self.malware(), 1)
        output = self.fullscan()
        self.assertIn('CRITICAL LMD full scan found malware', output)
        self.assertNotIn('PASS LMD full scan: no hits', output)
        self.assertIn('hit details incomplete', output)
        self.assertFalse((self.lmd / 'sess/session.index').exists())

    def test_consistent_zero_tsv(self):
        self.report('', 0)
        output = self.fullscan()
        self.assertIn('PASS LMD full scan: no hits', output)
        self.assertNotIn('CRITICAL', output)

    def test_noncompleted_zero_metadata_does_not_hide_tsv(self):
        for state in ['running', 'pending', 'failed']:
            with self.subTest(state=state):
                self.append_meta(hits=0, state=state); self.report(self.malware(), 1)
                self.assertIn('CRITICAL LMD full scan found malware', self.fullscan())

    def test_conflicting_header_fields_do_not_pass(self):
        for column, value in [(4, '/wrong/target'), (10, '12'), (14, '42'), (16, 'native'), (6, 'invalid'), (8, '0'), (5, 'recent')]:
            with self.subTest(column=column):
                self.report('', 0)
                fields = self.session.read_text().splitlines()[0].split('\t'); fields[column] = value
                self.session.write_text('\t'.join(fields) + '\n')
                output = self.fullscan()
                self.assertIn('hit details incomplete', output)
                self.assertNotIn('PASS', output)

    def test_truncated_records_fail_closed(self):
        for record in ['signature\n', '/home/file\n', 'sig\t/home/file\n', 'sig\t/home/file\t-\tHEX\tHex Match\n', '\t/home/file\t-\tHEX\tlabel\t-\t0\troot\troot\t644\t0\n']:
            with self.subTest(record=record):
                self.append_meta(hits=1); self.report(record, 1)
                output = self.fullscan()
                self.assertIn('CRITICAL', output)
                self.assertNotIn('PASS LMD full scan: no hits', output)

    def test_empty_and_malformed_tsv(self):
        for content in ['', 'malformed\n', '#LMD:v1\tscan\n']:
            with self.subTest(content=content):
                self.session.write_text(content)
                self.assertIn('CRITICAL', self.fullscan())

    def test_header_and_metadata_count_mismatch(self):
        self.append_meta(hits=1)
        self.report(self.malware(), 0)
        self.assertIn('hit details incomplete', self.fullscan())

    def test_invalid_hitcount_still_reports_malware(self):
        self.append_meta(hits='invalid'); self.report(self.malware(), 1)
        output = self.fullscan()
        self.assertIn('CRITICAL LMD full scan found malware', output)
        self.assertNotIn('PASS', output)

    def test_wrong_header_identity_is_not_clean(self):
        self.report('', 0)
        self.session.write_text(self.session.read_text().replace('260920-0030.1260922', '260920-0030.999'))
        output = self.fullscan()
        self.assertIn('hit details incomplete', output)
        self.assertNotIn('PASS', output)

    def test_multiple_malware(self):
        self.append_meta(hits=2); self.report(self.malware()*2, 2)
        self.assertIn('2 non-test detection(s)', self.fullscan())

    def test_exact_eicar_allowlist(self):
        known = ['{HEX}test.test.eicar.1040', '{HEX}test.test.eicar', '{MD5}test.test.eicar.32555', '{MD5}test.test.eicar.32556', '{MD5}test.test.eicar.32557', '{CAV}Eicar-Test-Signature', '{CAV}Win.Test.EICAR_HDB-1']
        unknown = ['php.backdoor.eicar.disguise', 'EICAR-malware', '{HEX}TEST.TEST.EICAR.1040', '{HEX}test.test.eicar.1040.extra', 'eicar']
        self.append_meta(hits=1)
        for signature in known + unknown:
            with self.subTest(signature=signature):
                self.report(self.malware(signature), 1)
                output = self.fullscan()
                if signature in known:
                    self.assertIn('EICAR/test detections', output)
                    self.assertNotIn('CRITICAL', output)
                else:
                    self.assertIn('CRITICAL LMD full scan found malware', output)

    def test_malformed_eicar_record_is_not_test_context(self):
        self.append_meta(hits=1)
        for record in [self.malware('{HEX}test.test.eicar').replace('\tHEX\t', '\tCAV\t'), self.malware('{HEX}test.test.eicar').replace('\tHEX\t', '\tunknown\t'), self.malware('{HEX}test.test.eicar\x1b')]:
            with self.subTest(record=record):
                self.report(record, 1)
                output = self.fullscan()
                self.assertIn('CRITICAL', output)
                self.assertNotIn('EICAR/test detection', output)

    def test_eicar_and_malware(self):
        self.append_meta(hits=2)
        self.report(self.malware('{HEX}test.test.eicar') + self.malware(), 2)
        self.assertIn('1 non-test detection(s), 1 EICAR/test', self.fullscan())


class NativeConsistencyTests(unittest.TestCase):
    setUp = fixture.NativeLmdTests.setUp
    run_shell = fixture.HealthcheckTests.run_shell
    save = fixture.NativeLmdTests.save
    detection = fixture.NativeLmdTests.detection
    completion = fixture.NativeLmdTests.completion
    fullscan = fixture.NativeLmdTests.fullscan

    def test_zero_index_with_tsv_hit(self):
        record = self.detection(); self.row[5] = self.header[11] = '0'
        self.save(record); self.completion()
        output = self.fullscan()
        self.assertIn('CRITICAL LMD full scan found malware', output)
        self.assertNotIn('PASS LMD full scan: no hits', output)

    def test_lifecycle_native_count_conflict(self):
        self.save(self.detection()); self.completion()
        with self.scan.open('a') as f: f.write('hits=0\n')
        output = self.fullscan()
        self.assertIn('lifecycle/native hit count conflict', output)
        self.assertIn('CRITICAL LMD full scan found malware', output)


class HistoricalRecoveryTests(unittest.TestCase):
    setUp = fixture.HealthcheckTests.setUp
    run_shell = fixture.ScannerReliabilityTests.run_shell
    append_meta = fixture.HealthcheckTests.append_meta
    fullscan = fixture.ScannerReliabilityTests.fullscan
    stamp = fixture.ScannerReliabilityTests.stamp
    block = fixture.ScannerReliabilityTests.block
    prepare = fixture.ScannerReliabilityTests.prepare
    newer = fixture.ScannerReliabilityTests.newer

    def old_malware(self):
        self.prepare(1); self.append_meta(hits=1)
        shutil.copyfile(fixture.FIXTURES / 'session.malware.tsv', self.session)
        lines = self.session.read_text().splitlines(); fields = lines[0].split('\t')
        fields[6:9] = [self.stamp(fixture.NOW-3600) + ' +0200', self.stamp(fixture.NOW-1800) + ' +0200', '1800']
        lines[0] = '\t'.join(fields); self.session.write_text('\n'.join(lines) + '\n')

    def test_verified_clean_recovers_malware(self):
        self.old_malware(); self.newer()
        self.assertNotIn('CRITICAL LMD full scan found malware', self.fullscan())

    def test_exit_two_does_not_recover(self):
        self.old_malware(); self.newer(code=2)
        output = self.fullscan()
        self.assertIn('CRITICAL LMD full scan found malware', output)
        self.assertIn('CRITICAL LMD scanner failure', output)

    def test_access_errors_do_not_recover(self):
        self.old_malware(); self.newer()
        log = self.lmd / 'logs/clamscan_log'
        log.write_text(self.block(code=1) + self.block(fixture.NOW-60, fixture.NOW-1, 2, ['/home/cache/a']))
        output = self.fullscan()
        self.assertIn('CRITICAL LMD full scan found malware', output)
        self.assertIn('WARNING LMD full scan completed with 1 scanner access errors', output)

    def test_running_and_pending_do_not_recover(self):
        for state in ['running', 'pending']:
            with self.subTest(state=state):
                self.old_malware(); self.newer(state)
                self.assertIn('CRITICAL LMD full scan found malware', self.fullscan())

    def test_unknown_does_not_recover(self):
        self.old_malware(); self.newer()
        (self.lmd / 'logs/clamscan_log').write_text(self.block(code=1))
        output = self.fullscan()
        self.assertIn('CRITICAL LMD full scan found malware', output)
        self.assertIn('scanner result UNKNOWN', output)

    def test_conflicting_tsv_does_not_recover(self):
        self.old_malware(); self.newer()
        (self.lmd / 'sess/session.tsv.newer').write_text((fixture.FIXTURES / 'session.malware.tsv').read_text())
        output = self.fullscan()
        self.assertIn('CRITICAL LMD full scan found malware', output)
        self.assertIn('hit details incomplete', output)

    def test_invalid_index_does_not_establish_recovery(self):
        self.old_malware(); self.newer()
        (self.lmd / 'sess/session.index').write_text('invalid index\n')
        output = self.fullscan()
        self.assertIn('CRITICAL LMD full scan found malware', output)
        self.assertNotIn('PASS', output)

    def test_equal_completion_times_do_not_recover(self):
        self.old_malware(); self.newer()
        self.append_meta(completed=fixture.NOW-1)
        output = self.fullscan()
        self.assertIn('completed scan order ambiguous', output)
        self.assertIn('CRITICAL LMD full scan found malware', output)

    def test_multiple_historical_malware_recovered(self):
        self.old_malware()
        other = self.lmd / 'sess/scan.meta.older'
        other.write_text(self.scan.read_text().replace(str(fixture.NOW-3600), str(fixture.NOW-7200)).replace(str(fixture.NOW-1800), str(fixture.NOW-5400)))
        shutil.copyfile(self.session, self.lmd / 'sess/session.tsv.older')
        self.newer()
        self.assertNotIn('CRITICAL LMD full scan found malware', self.fullscan())


class ScannerPeriodTests(unittest.TestCase):
    setUp = fixture.HealthcheckTests.setUp
    stamp = fixture.ScannerReliabilityTests.stamp
    block = fixture.ScannerReliabilityTests.block

    def parse(self, text):
        (self.lmd / 'logs/clamscan_log').write_text(text)
        # Match production local timestamp interpretation.
        old = os.environ.get('TZ'); os.environ['TZ'] = 'Europe/Amsterdam'
        import time
        time.tzset()
        try:
            return scanner.result(self.lmd / 'logs', fixture.NOW-3600, fixture.NOW-1800)
        finally:
            if old is None: os.environ.pop('TZ', None)
            else: os.environ['TZ'] = old
            time.tzset()

    def test_old_incomplete_scans_are_irrelevant(self):
        text = ''
        for i in range(3):
            old = fixture.NOW - (7-i)*86400
            text += self.block(old, old+10).splitlines()[0] + '\n'
            (self.lmd / f'sess/scan.meta.old{i}').write_text(f'started={old}\ncompleted={old+10}\nstate=completed\n')
        self.assertEqual(self.parse(text + self.block())[0], 'clean')

    def test_old_invalid_and_dst_markers_are_irrelevant(self):
        for marker in ['Mar 29 2026 02:30:00 host clamscan start\n', 'Oct 26 2025 02:30:00 host clamscan start\n', 'Sep 01 2026 99:99:99 host clamscan start\n']:
            with self.subTest(marker=marker):
                self.assertEqual(self.parse(marker + self.block())[0], 'clean')

    def test_later_corrupt_marker_is_irrelevant(self):
        self.assertEqual(self.parse(self.block() + 'Oct 25 2026 02:30:00 host clamscan start\n')[0], 'clean')

    def test_old_unfinished_without_completion_proof_is_unknown(self):
        text = self.block(fixture.NOW-7*86400, fixture.NOW-7*86400+10).splitlines()[0] + '\n'
        with self.assertRaises(ValueError): self.parse(text + self.block())

    def test_old_running_metadata_is_not_completion_proof(self):
        old = fixture.NOW-7*86400
        (self.lmd / 'sess/scan.meta.old').write_text(f'started={old}\ncompleted={old+10}\nstate=running\n')
        text = self.block(old, old+10).splitlines()[0] + '\n'
        with self.assertRaises(ValueError): self.parse(text + self.block())

    def test_empty_intermediate_numeric_rotation_is_valid(self):
        lines = self.block().splitlines(keepends=True)
        (self.lmd / 'logs/clamscan_log.2').write_text(''.join(lines[:-1]))
        (self.lmd / 'logs/clamscan_log.1').write_text('')
        self.assertEqual(self.parse(lines[-1])[0], 'clean')

    def test_current_invalid_timestamp_is_unknown(self):
        with self.assertRaises(ValueError):
            self.parse(self.block().replace('host executed:', 'host clamscan start\nSep 20 2026 99:99:99 host executed:'))

    def test_actual_overlap_is_unknown(self):
        with self.assertRaises(ValueError):
            self.parse(self.block().splitlines()[0] + '\n' + self.block())

    def test_cross_boundary_overlap_is_unknown(self):
        with self.assertRaises(ValueError):
            self.parse(self.block(fixture.NOW-4000, fixture.NOW-2000).splitlines()[0] + '\n' + self.block())

    def test_two_nonoverlapping_scans(self):
        self.assertEqual(self.parse(self.block(fixture.NOW-7200, fixture.NOW-5400) + self.block())[0], 'clean')

    def test_gzip_boundary_and_diagnostics(self):
        text = self.block(code=2, paths=['/home/cache/a', '/home/cache/b']).splitlines(keepends=True)
        with gzip.open(self.lmd / 'logs/clamscan_log.1.gz', 'wt') as f: f.write(''.join(text[:3]))
        result = self.parse(''.join(text[3:]))
        self.assertEqual(result[:3], ('access_errors', 2, 2))

    def test_missing_relevant_numeric_rotation(self):
        text = self.block().splitlines(keepends=True)
        (self.lmd / 'logs/clamscan_log.2').write_text(''.join(text[:-1]))
        with self.assertRaises(ValueError): self.parse(text[-1])

    def test_missing_boundary_is_unknown(self):
        with self.assertRaises(ValueError): self.parse('\n'.join(self.block().splitlines()[1:]))

    def test_two_invocations_are_unknown(self):
        lines = self.block().splitlines(keepends=True)
        with self.assertRaises(ValueError): self.parse(lines[0]+lines[1]*2+lines[2])

    def test_executable_grammar(self):
        valid = ['/usr/bin/clamdscan -f /list', '/usr/bin/clamscan -f /list', '/usr/bin/clamscan --max-filesize=100 --max-scansize=200 -d /db -r --infected --no-summary -f /list', '/usr/bin/clamdscan --fdpass -c /config --infected --no-summary -f /list', '/usr/bin/cpulimit -l 80 -- /usr/bin/nice -n 19 /usr/bin/ionice -c2 -n 6 /usr/bin/clamdscan -f /list', '/usr/local/cpanel/3rdparty/bin/clamdscan -f /list', '/usr/bin/nice -n 19 /usr/bin/ionice -c2 -n 6 /usr/bin/clamdscan --infected --no-summary -f /list', '  /usr/bin/nice  -n 19   /usr/bin/clamdscan -f /list']
        invalid = ['/usr/bin/clamdscan --version', '/usr/bin/clamdscan --help -f /list', '/usr/bin/clamdscan --unknown -f /list', '/usr/bin/echo /usr/bin/clamdscan -f /list', '/bin/sh -c "clamdscan -f /list"', '/usr/bin/env /usr/bin/clamdscan -f /list', '/usr/bin/echo /home/clamdscan', '# /usr/bin/clamdscan', '/usr/bin/nice -n nope /usr/bin/clamdscan', '/usr/bin/ionice -c2 -n', '"', '/usr/bin/clamdscan; echo clean']
        for command in valid + invalid:
            with self.subTest(command=command):
                if command in valid:
                    self.assertEqual(self.parse(self.block().replace('/usr/bin/clamdscan -f /literal/filelist', command))[0], 'clean')
                else:
                    with self.assertRaises(ValueError):
                        self.parse(self.block().replace('/usr/bin/clamdscan -f /literal/filelist', command))
