#!/usr/bin/env python3
"""Offline fixture tests: never start LMD, contact Telegram or change host services.

Requires Bash >=4, GNU date/stat/find and Python 3. On macOS, prepend GNU
coreutils/findutils gnubin directories and select a newer Bash via BASH_BIN.
"""
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / 'tests/fixtures'
BASH = os.environ.get('BASH_BIN', shutil.which('bash'))
Q = shlex.quote
NOW = 1789891200  # 2026-09-20 08:00 UTC / 10:00 Europe/Amsterdam


class HealthcheckTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='sshc tests ')
        self.addCleanup(self.temp.cleanup)
        self.work = Path(self.temp.name)
        self.lmd = self.work / 'lmd'
        (self.lmd / 'sess').mkdir(parents=True)
        (self.lmd / 'sigs').mkdir()
        (self.lmd / 'logs').mkdir()
        (self.lmd / 'sigs/maldet.sigs.ver').write_text('2026052490478\n')
        (self.lmd / 'sigs/hex.dat').write_text('fixture signatures\n')
        self.log = self.lmd / 'logs/event_log'
        shutil.copyfile(FIXTURES / 'event_log', self.log)
        self.scan = self.lmd / 'sess/scan.meta.260920-0030.1260922'
        shutil.copyfile(FIXTURES / 'scan.meta.completed', self.scan)
        self.session = self.lmd / 'sess/session.tsv.260920-0030.1260922'
        self.env = dict(os.environ, TZ='Europe/Amsterdam', LC_ALL='C')

    def run_shell(self, script, expected=0):
        prefix = f'''set -u -o pipefail
source {Q(str(ROOT / 'lib/common.sh'))}
HC_REGISTERED_CHECKS=()
source {Q(str(ROOT / 'lib/checks/lmd.sh'))}
source {Q(str(ROOT / 'lib/checks/lmd_policy.sh'))}
source {Q(str(ROOT / 'lib/checks/clamav.sh'))}
LMD_DIR={Q(str(self.lmd))}
LMD_AUDIT={Q(str(self.work / 'absent audit'))}
date() {{ if [ "$*" = +%s ]; then printf '%s\\n' {NOW}; else command date "$@"; fi; }}
systemctl() {{ return 0; }}
pgrep() {{ return 0; }}
'''
        result = subprocess.run([BASH, '-c', prefix + script], env=self.env,
                                text=True, capture_output=True)
        self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
        self.assertEqual(result.stderr, '', result.stderr)
        return result.stdout

    def append_meta(self, **kwargs):
        with self.scan.open('a') as file:
            file.write(''.join(f'{key}={value}\n' for key, value in kwargs.items()))

    def fullscan(self, config=''):
        return self.run_shell(config + '\n_lmd_check_fullscan\n')

    def test_duplicate_metadata_last_wins(self):
        self.assertEqual(self.run_shell(f'_lmd_meta_get {Q(str(self.scan))} state'), 'completed\n')

    def test_healthy_fullscan(self):
        output = self.fullscan()
        self.assertIn('PASS LMD weekly full scan completed', output)
        self.assertIn('PASS LMD full scan: no hits', output)
        self.assertIn('7h 41m', output)
        self.assertNotIn('WARNING', output)
        self.assertNotIn('CRITICAL', output)

    def test_eicar_only(self):
        self.append_meta(hits=2)
        shutil.copyfile(FIXTURES / 'session.eicar.tsv', self.session)
        output = self.fullscan()
        self.assertIn('WARNING Full scan contains 2 EICAR/test detections', output)
        self.assertIn('eicar test.txt', output)
        self.assertNotIn('CRITICAL', output)

    def test_real_malware_filename_is_not_signature(self):
        self.append_meta(hits=1)
        shutil.copyfile(FIXTURES / 'session.malware.tsv', self.session)
        output = self.fullscan()
        self.assertIn('CRITICAL LMD full scan found malware', output)
        self.assertIn('detected files may still be accessible', output)
        self.assertIn('Type: HEX', output)

    def test_mixed_hits(self):
        self.append_meta(hits=3)
        self.session.write_text((FIXTURES / 'session.eicar.tsv').read_text() +
                                (FIXTURES / 'session.malware.tsv').read_text().split('\n', 1)[1])
        self.assertIn('1 non-test detection(s), 2 EICAR/test', self.fullscan())

    def test_missing_hit_details(self):
        self.append_meta(hits=2)
        self.assertIn('CRITICAL', self.fullscan())

    def test_incomplete_hit_details(self):
        self.append_meta(hits=3)
        shutil.copyfile(FIXTURES / 'session.eicar.tsv', self.session)
        self.assertIn('CRITICAL LMD full scan hit details incomplete', self.fullscan())

    def test_malformed_hit_details(self):
        self.append_meta(hits=1)
        self.session.write_text('#LMD:v1\tscan\nmalformed\n')
        self.assertIn('malformed=1', self.fullscan())

    def test_empty_tsv_column_does_not_shift(self):
        self.append_meta(hits=1)
        self.session.write_text('#LMD:v1\tscan\nmalware\t/home/file with spaces.php\t\tHEX\tmalware\n')
        self.assertIn('Type: HEX', self.fullscan())

    def test_unknown_header_fails_closed(self):
        self.append_meta(hits=1)
        self.session.write_text('unknown\neicar\t/home/file\n')
        self.assertIn('CRITICAL LMD hit session format unknown', self.fullscan())

    def test_stale_scan(self):
        self.append_meta(started=NOW-10*86400, completed=NOW-9*86400)
        self.assertIn('WARNING LMD completed full scan stale', self.fullscan())

    def test_old_config_days_alias(self):
        self.append_meta(started=NOW-4*86400, completed=NOW-3*86400)
        self.assertIn('stale', self.fullscan('FULLSCAN_MAX_AGE_DAYS=2'))
        self.assertNotIn('stale', self.fullscan('FULLSCAN_MAX_AGE_DAYS=2\nLMD_FULLSCAN_MAX_AGE_HOURS=192'))

    def test_long_runtime(self):
        self.append_meta(elapsed=50000)
        self.assertIn('WARNING LMD full scan runtime exceeds', self.fullscan())

    def test_legitimate_running(self):
        self.append_meta(state='running', started=NOW-3600, completed='', hits='', elapsed='')
        output = self.fullscan()
        self.assertIn('currently running', output)
        self.assertNotIn('CRITICAL', output)
        self.assertIn('no completed full scan within', output)

    def test_stale_running(self):
        self.append_meta(state='running', started=NOW-13*3600, completed='', elapsed='')
        self.assertIn('CRITICAL LMD stale running full scan', self.fullscan())

    def test_failed_scan(self):
        self.append_meta(state='aborted')
        self.assertIn('CRITICAL LMD latest full scan explicitly aborted', self.fullscan())

    def test_completed_without_timestamp(self):
        self.append_meta(completed='')
        output = self.fullscan()
        self.assertIn('WARNING LMD completed full scan has missing/invalid', output)
        self.assertNotIn('PASS LMD weekly full scan completed', output)

    def test_future_timestamp(self):
        self.append_meta(started=NOW+60)
        self.assertIn('invalid metadata', self.fullscan())

    def test_missing_scan_path(self):
        self.append_meta(path='/tmp')
        self.assertIn('WARNING LMD: no matching full scan metadata', self.fullscan())

    def test_monitor_session_and_mtime_ignored(self):
        (self.lmd / 'sess/session.monitor.current').write_text('anything')
        other = self.lmd / 'sess/scan.meta.newer-monitor'
        other.write_text(f'path=/tmp\nstarted={NOW-1}\nstate=completed\ncompleted={NOW}\nhits=500\n')
        self.assertIn('PASS LMD weekly full scan completed', self.fullscan())
        self.assertNotIn('CRITICAL', self.fullscan())

    def test_new_running_does_not_hide_previous_hits(self):
        self.append_meta(hits=1)
        shutil.copyfile(FIXTURES / 'session.malware.tsv', self.session)
        newer = self.lmd / 'sess/scan.meta.newer'
        newer.write_text(f'path=/home/?/domains/?/public_html/\nstarted={NOW-60}\nstate=running\n')
        output = self.fullscan()
        self.assertIn('currently running', output)
        self.assertIn('CRITICAL LMD full scan found malware', output)

    def test_quarantine_options_fallback(self):
        self.append_meta(quarantine_enabled='')
        self.assertIn('quarantine disabled by scan policy', self.fullscan())

    def test_quarantine_mismatch(self):
        self.assertIn('WARNING LMD quarantine policy mismatch', self.fullscan('LMD_EXPECT_QUARANTINE_ENABLED=1'))

    def test_metadata_is_not_executed(self):
        marker = self.work / 'injected'
        self.append_meta(engine=f'$(touch {marker})', hits='x[0]')
        self.assertIn('hit count unavailable/invalid', self.fullscan())
        self.assertFalse(marker.exists())

    def sigup(self):
        return self.run_shell('_lmd_check_signature_updater')

    def test_sigup_already_current(self):
        self.assertIn('PASS LMD signatures: already current', self.sigup())

    def test_sigup_actual_updated(self):
        self.log.write_text('Sep 20 2026 06:01:00 host maldet(1): {sigup} signature set update completed\n')
        self.assertIn('PASS LMD signatures: updated', self.sigup())

    def test_sigup_download_is_not_success(self):
        self.log.write_text('Sep 20 2026 06:01:00 host maldet(1): {sigup} downloaded maldet.sigs.ver\n')
        self.assertIn('WARNING LMD signature updater: UNKNOWN', self.sigup())

    def test_sigup_failure_then_success(self):
        failure = 'Sep 20 2026 05:01:00 host maldet(1): {sigup} could not download signature data\n'
        self.log.write_text(failure + self.log.read_text())
        self.assertNotIn('CRITICAL', self.sigup())

    def test_sigup_newer_failure(self):
        with self.log.open('a') as file:
            file.write('Sep 20 2026 09:01:00 host maldet(1): {sigup} signature validation failed\n')
        self.assertIn('CRITICAL LMD signature update failed', self.sigup())

    def test_sigup_stale(self):
        self.log.write_text(self.log.read_text().replace('Sep 20 2026 06:01', 'Sep 19 2026 06:01'))
        self.assertIn('WARNING LMD signature check stale', self.sigup())

    def test_sigup_missing_log(self):
        self.log.unlink()
        self.assertIn('UNKNOWN', self.sigup())

    def test_monitor_healthy_and_filtered(self):
        for action in ['scanned', 'filtered']:
            self.log.write_text(self.log.read_text().replace('scanned', action))
            self.assertIn('PASS LMD realtime monitor activity', self.run_shell('_lmd_check_service'))

    def test_monitor_stale_despite_reload(self):
        self.log.write_text(self.log.read_text().replace('09:59:00', '06:00:00'))
        self.assertIn('WARNING LMD realtime monitor: last scan/filter activity', self.run_shell('_lmd_check_service'))

    def test_monitor_reload_alone_not_heartbeat(self):
        self.log.write_text('Sep 20 2026 10:00:00 host maldet(1): {mon} reloaded configuration data\n')
        self.assertIn('no parseable scan/filter heartbeat', self.run_shell('_lmd_check_service'))

    def test_monitor_busy_log_does_not_hide_updates(self):
        with self.log.open('a') as file:
            file.write('Sep 20 2026 09:59:00 host maldet(1): {mon} scanned files\n' * 5000)
        self.assertIn('PASS LMD signatures', self.sigup())

    def test_monitor_missing_process(self):
        self.assertIn('CRITICAL LMD service active', self.run_shell('pgrep() { return 1; }; _lmd_check_service'))

    def test_monitor_service_inactive(self):
        self.assertIn('CRITICAL LMD realtime service is not active', self.run_shell('systemctl() { [ "$1" = cat ]; }; _lmd_check_service'))

    def test_monitor_service_missing(self):
        self.assertIn('CRITICAL LMD realtime service missing', self.run_shell('systemctl() { return 1; }; _lmd_check_service'))

    def test_monitor_optional(self):
        output = self.run_shell('LMD_MONITOR_REQUIRED=0; systemctl() { return 1; }; _lmd_check_service')
        self.assertIn('not required', output)
        self.assertNotIn('CRITICAL', output)

    def test_program_intentionally_disabled(self):
        self.assertIn('intentionally disabled', self.run_shell('_lmd_check_program_updater'))

    def test_program_ignore(self):
        self.assertEqual('', self.run_shell('LMD_PROGRAM_UPDATE_EXPECTED=ignore; _lmd_check_program_updater'))

    def test_program_failure_then_success(self):
        self.log.write_text('Sep 20 2026 08:01:00 host maldet(1): {update} unable to verify sha256\n')
        self.assertIn('WARNING', self.run_shell('LMD_PROGRAM_UPDATE_EXPECTED=enabled; _lmd_check_program_updater'))
        with self.log.open('a') as file:
            file.write('Sep 20 2026 09:01:00 host maldet(1): {update} latest version already installed\n')
        self.assertNotIn('WARNING', self.run_shell('LMD_PROGRAM_UPDATE_EXPECTED=enabled; _lmd_check_program_updater'))

    def test_signature_failures_do_not_become_program_failures(self):
        self.log.write_text('Sep 20 2026 08:01:00 host maldet(1): {sigup} sha256 failed\n')
        self.assertNotIn('WARNING', self.run_shell('LMD_PROGRAM_UPDATE_EXPECTED=enabled; _lmd_check_program_updater'))

    def coverage(self, configured):
        home = self.work / 'home'
        expected = home / 'user/domains/example.nl/public_html'
        expected.mkdir(parents=True, exist_ok=True)
        for domain in ['autoconfig.example.nl', 'autodiscover.example.nl', 'mail.example.nl']:
            (home / f'user/domains/{domain}/public_html').mkdir(parents=True, exist_ok=True)
        monitored = self.work / 'webroots'
        monitored.write_text(configured.format(expected=expected))
        original = monitored.read_bytes()
        output = self.run_shell(f'CHECK_DIRECTADMIN_WEBROOTS=1\nDIRECTADMIN_HOME={Q(str(home))}\nLMD_MONITOR_LIST={Q(str(monitored))}\n_lmd_check_webroots')
        self.assertEqual(monitored.read_bytes(), original, 'Coverage check must not rewrite the synchronized list')
        return output

    def test_coverage_equal_normalizes_trailing_slash_and_duplicates(self):
        output = self.coverage('# comment\n{expected}/\n{expected}\n')
        self.assertIn('1/1 webroots monitored', output)
        self.assertIn('Expected: 1', output)
        self.assertIn('Configured: 1', output)
        self.assertIn('Missing: 0', output)
        self.assertIn('Stale: 0', output)
        self.assertNotIn('WARNING', output)

    def test_coverage_same_count_different_set(self):
        output = self.coverage('/home/stale/domains/old.nl/public_html\n')
        self.assertIn('WARNING LMD realtime coverage mismatch', output)
        self.assertIn('Expected: 1; Configured: 1; Missing: 1; Stale: 1', output)
        self.assertIn('Missing:', output)
        self.assertIn('example.nl/public_html', output)
        self.assertIn('Stale/out-of-scope entries:', output)
        self.assertIn('/home/stale/', output)

    def test_coverage_discovery_error(self):
        listing = self.work / 'roots'
        listing.write_text('')
        output = self.run_shell(f'CHECK_DIRECTADMIN_WEBROOTS=1\nLMD_WEBROOT_LIST={Q(str(listing))}\nfind() {{ return 1; }}\n_lmd_check_webroots')
        self.assertIn('ERROR DirectAdmin webroot discovery failed', output)
        self.assertNotIn('PASS', output)

    def test_audit_types_counted_separately(self):
        audit = self.work / 'audit'
        audit.write_text('{"ts":"2026-09-20T09:00:00+02:00","type":"threat_detected"}\n'
                         '{"ts": "2026-09-20T09:00:00+02:00", "type": "alert_failed"}\n')
        output = self.run_shell(f'LMD_AUDIT={Q(str(audit))}; _lmd_check_events')
        self.assertIn('1 threat_detected, 1 alert_failed', output)

    def config_test(self, content, expected=0):
        config = self.work / 'test.conf'
        config.write_text(content)
        return self.run_shell(f'hc_load_config {Q(str(config))}', expected)

    def test_example_config_valid(self):
        self.config_test((ROOT / 'config/healthcheck.conf.example').read_text())

    def test_legacy_config_valid(self):
        self.config_test('CHECK_LMD=1\nLMD_SIG_MAX_AGE_HOURS=72\nLMD_MONITOR_LIST="/home/a path"\nFULLSCAN_MAX_AGE_DAYS=8\nLMD_BIN=/usr/local/sbin/maldet\n')

    def test_config_shell_injection_blocked(self):
        marker = self.work / 'unsafe'
        self.assertIn('ERROR', self.config_test(f'LMD_DIR="$(touch {marker})"\n', 1))
        self.assertFalse(marker.exists())

    def test_config_numeric_injection_blocked(self):
        self.assertIn('ERROR', self.config_test('LMD_SIGUP_MAX_AGE_HOURS="x[1]"\n', 1))

    def test_config_unknown_key_and_bad_enum(self):
        for data in ['PATH=/tmp\n', 'LMD_PROGRAM_UPDATE_EXPECTED=maybe\n', 'LOOKBACK_HOURS=08\n', 'LMD_ENABLED=2\n', 'CHECK_DISK=auto\n', 'CHECK_DIRECTADMIN_WEBROOTS=auto\n']:
            self.assertIn('ERROR', self.config_test(data, 1))

    def test_config_literal_quotes_comments_crlf_and_final_line(self):
        self.config_test("LMD_DIR='/a path' # comment\r\nLOOKBACK_HOURS=24 # comment\r\nLMD_PROGRAM_UPDATE_EXPECTED=disabled")

    def test_required_dependency_error(self):
        self.assertIn('ERROR Required dependency missing: stat', self.run_shell('hc_have() { [ "$1" != stat ]; }; hc_require_dependencies', 1))

    def clamav(self, timer=True, active=True, daemon=False, failed=False):
        script = f'''
CHECK_CLAMAV=1
_clamav_find_newest_db() {{ echo /fake/daily.cvd; }}
hc_file_age_hours() {{ echo 1; }}
_clamav_last_success_epoch() {{ echo {NOW-3600}; }}
hc_have() {{ return 0; }}
systemctl() {{
    case "$1:$2" in
        cat:clamav-freshclam-once.timer) return {0 if timer else 1} ;;
        cat:clamav-freshclam.service) return {0 if daemon else 1} ;;
        is-active:--quiet)
            if [ "$3" = clamav-freshclam-once.timer ]; then return {0 if active else 1}; fi ;;
        is-failed:--quiet) return {0 if failed else 1} ;;
    esac
    return 0
}}
check_clamav
'''
        return self.run_shell(script)

    def test_clamav_active_timer(self):
        self.assertNotIn('WARNING', self.clamav())

    def test_clamav_inactive_timer(self):
        self.assertIn('timer is enabled but not active', self.clamav(active=False))

    def test_clamav_failed_oneshot(self):
        self.assertIn('oneshot service failed', self.clamav(failed=True))

    def test_clamav_daemon_alternative(self):
        self.assertNotIn('WARNING', self.clamav(timer=False, daemon=True))

    def main(self, content, args=(), lib_dir=None):
        config_dir = self.work / 'config'
        config_dir.mkdir(exist_ok=True)
        config = '''NOTIFY_TELEGRAM=0
CHECK_DISK=0
CHECK_APACHE=0
CHECK_RSPAMD=0
CHECK_PUREFTP=0
CHECK_EXIM=0
CHECK_CLAMAV=0
CHECK_LMD=0
'''
        (config_dir / 'healthcheck.conf').write_text(config + content)
        env = dict(self.env, SSHC_CONFIG_DIR=str(config_dir), SSHC_LIB_DIR=str(lib_dir or ROOT / 'lib'))
        return subprocess.run([BASH, str(ROOT / 'bin/server-security-healthcheck'), *args],
                              env=env, capture_output=True, text=True)

    def test_exit_healthy(self):
        result = self.main('')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_exit_warning(self):
        result = self.main('LMD_ENABLED=1\nLMD_DIR=/no/such/lmd\n')
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn('WARNING', result.stdout)

    def test_exit_config_error(self):
        result = self.main('LMD_SIGUP_MAX_AGE_HOURS=oops\n')
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)

    def test_version(self):
        result = self.main('', ['--version'])
        self.assertEqual(result.returncode, 0)
        self.assertIn('v0.5.2', result.stdout)

    def test_unknown_argument(self):
        self.assertEqual(self.main('', ['--unknown']).returncode, 2)

    def test_lmd_enabled_overrides_legacy(self):
        result = self.main('CHECK_LMD=1\nLMD_ENABLED=0\nLMD_DIR=/no/such/lmd\n')
        self.assertEqual(result.returncode, 0)

    def test_telegram_truncates_without_sending(self):
        output = self.run_shell(f'''source {Q(str(ROOT / 'lib/notify/telegram.sh'))}
NOTIFY_TELEGRAM=1
TELEGRAM_BOT_TOKEN=test
TELEGRAM_CHAT_ID=test
curl() {{ printf '%s\\n' "$@" > {Q(str(self.work / 'curl.args'))}; }}
printf -v long '%5000s' x
notify_telegram "$long"
''')
        self.assertEqual(output, '')
        args = (self.work / 'curl.args').read_text()
        self.assertIn('Truncated', args)
        self.assertLess(len(args), 4096)

    def test_sigup_same_second_order(self):
        success = 'Sep 20 2026 09:01:00 host maldet(1): {sigup} latest signature set already installed\n'
        failure = 'Sep 20 2026 09:01:00 host maldet(1): {sigup} validation failed\n'
        self.log.write_text(success + failure)
        self.assertIn('CRITICAL', self.sigup())
        self.log.write_text(failure + success)
        self.assertNotIn('CRITICAL', self.sigup())

    def test_future_success_does_not_clear_failure(self):
        self.log.write_text('Sep 20 2026 09:01:00 host maldet(1): {sigup} validation failed\n'
                           'Sep 21 2026 09:01:00 host maldet(1): {sigup} latest signature set already installed\n')
        self.assertIn('CRITICAL', self.sigup())

    def test_iso_log_timestamp(self):
        self.log.write_text('2026-09-20T06:01:00+02:00 host maldet(1): {sigup} latest signature set already installed\n')
        self.assertIn('PASS LMD signatures', self.sigup())

    def test_no_signatures_despite_success(self):
        (self.lmd / 'sigs/hex.dat').unlink()
        self.assertIn('WARNING LMD: no readable nonempty recognized signature file', self.sigup())

    def test_exit_critical(self):
        self.append_meta(hits=1)
        shutil.copyfile(FIXTURES / 'session.malware.tsv', self.session)
        result = self.main(f'LMD_ENABLED=1\nLMD_MONITOR_REQUIRED=0\nLMD_DIR="{self.lmd}"\n')
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn('CRITICAL LMD full scan found malware', result.stdout)

    def test_exit_execution_error(self):
        listing = self.work / 'list'
        listing.write_text('')
        result = self.main(f'LMD_ENABLED=1\nLMD_MONITOR_REQUIRED=0\nLMD_DIR="{self.lmd}"\n'
                           f'CHECK_DIRECTADMIN_WEBROOTS=1\nDIRECTADMIN_HOME="{self.work / "absent"}"\nLMD_WEBROOT_LIST="{listing}"\n')
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn('ERROR DirectAdmin webroot discovery failed', result.stdout)

    def install_root(self):
        if not hasattr(self, '_install_root'):
            directory = tempfile.TemporaryDirectory(prefix='sshc-install-')
            self.addCleanup(directory.cleanup)
            self._install_root = Path(directory.name)
        return self._install_root

    def admin_script(self, name):
        # Exercise the real installer/remover with only absolute destination
        # prefixes redirected. Never run host id/systemctl or use host paths.
        destination = self.install_root()
        for relative in ['usr/local/sbin', 'etc/systemd/system']:
            (destination / relative).mkdir(parents=True, exist_ok=True)
        text = (ROOT / name).read_text()
        for prefix in ['/usr/local/', '/etc/']:
            text = text.replace(prefix, str(destination) + prefix)
        lines = text.splitlines()
        lines = [f'ROOT_DIR={Q(str(ROOT))}' if line.startswith('ROOT_DIR=') else line for line in lines]
        stubs = 'id() { printf "0\\n"; }; systemctl() { printf "%s\\n" "$*" >> ' + Q(str(self.work / 'admin calls')) + '; };'
        result = subprocess.run([BASH, '-c', stubs + '\n' + '\n'.join(lines)],
                                env=self.env, text=True, capture_output=True, cwd=self.work)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return destination

    def test_install_upgrade_uninstall_preserves_configuration(self):
        destination = self.admin_script('install.sh')
        config = destination / 'etc/server-security-healthcheck/healthcheck.conf'
        telegram = destination / 'etc/server-security-healthcheck/telegram.conf'
        self.assertEqual(config.read_text(), (ROOT / 'config/healthcheck.conf.example').read_text())
        self.assertEqual(telegram.stat().st_mode & 0o777, 0o600)
        config.write_text('CHECK_LMD=1\nFULLSCAN_MAX_AGE_DAYS=9\n')
        telegram.write_text('TELEGRAM_BOT_TOKEN="existing test value"\n')
        example = destination / 'etc/server-security-healthcheck/healthcheck.conf.example'
        example.write_text('old example')
        self.admin_script('install.sh')
        self.assertEqual(config.read_text(), 'CHECK_LMD=1\nFULLSCAN_MAX_AGE_DAYS=9\n')
        self.assertEqual(telegram.read_text(), 'TELEGRAM_BOT_TOKEN="existing test value"\n')
        self.assertEqual(example.read_text(), (ROOT / 'config/healthcheck.conf.example').read_text())
        unit = destination / 'etc/systemd/system/server-security-healthcheck.service'
        self.assertIn('SuccessExitStatus=1\n', unit.read_text())
        self.admin_script('uninstall.sh')
        self.assertTrue(config.exists())
        self.assertTrue(telegram.exists())
        self.assertFalse((destination / 'usr/local/sbin/server-security-healthcheck').exists())
        self.assertFalse((destination / 'usr/local/lib/server-security-healthcheck').exists())
        calls = (self.work / 'admin calls').read_text()
        self.assertNotIn('restart', calls)
        self.assertIn('disable --now server-security-healthcheck.timer', calls)

    def test_installer_preserves_broken_config_symlink(self):
        destination = self.install_root()
        config = destination / 'etc/server-security-healthcheck/healthcheck.conf'
        config.parent.mkdir(parents=True)
        target = self.work / 'absent user config'
        config.symlink_to(target)
        self.admin_script('install.sh')
        self.assertTrue(config.is_symlink())
        self.assertFalse(target.exists())

    def test_unparseable_signature_failure_is_not_healthy(self):
        with self.log.open('a') as file:
            file.write('invalid timestamp host maldet(1): {sigup} validation failed\n')
        output = self.sigup()
        self.assertIn('WARNING', output)
        self.assertNotIn('PASS LMD signatures', output)

    def test_unparseable_program_failure_is_not_healthy(self):
        self.log.write_text('invalid timestamp host maldet(1): {update} validation failed\n')
        self.assertIn('WARNING', self.run_shell('LMD_PROGRAM_UPDATE_EXPECTED=enabled; _lmd_check_program_updater'))

    def test_coverage_comparison_error_is_not_healthy(self):
        listing = self.work / 'roots'
        listing.write_text('')
        output = self.run_shell(f'CHECK_DIRECTADMIN_WEBROOTS=1\nDIRECTADMIN_HOME={Q(str(self.work))}\nLMD_WEBROOT_LIST={Q(str(listing))}\ncomm() {{ return 2; }}\n_lmd_check_webroots')
        self.assertIn('ERROR', output)
        self.assertNotIn('PASS', output)

    def test_new_tsv_version_is_not_misread_as_v1(self):
        self.append_meta(hits=1)
        self.session.write_text('#LMD:v10\tscan\neicar\t/home/test\n')
        self.assertIn('CRITICAL LMD hit session format unknown', self.fullscan())

    def test_execution_error_does_not_suppress_malware_notification(self):
        library = self.work / 'test library'
        shutil.copytree(ROOT / 'lib', library)
        marker = self.work / 'notification captured'
        (library / 'notify/telegram.sh').write_text('notify_telegram() { printf "%s\\n" "$1" > ' + Q(str(marker)) + '; }\n')
        self.append_meta(hits=1)
        shutil.copyfile(FIXTURES / 'session.malware.tsv', self.session)
        listing = self.work / 'roots'
        listing.write_text('')
        result = self.main(f'LMD_ENABLED=1\nLMD_MONITOR_REQUIRED=0\nLMD_DIR="{self.lmd}"\n'
                           f'CHECK_DIRECTADMIN_WEBROOTS=1\nDIRECTADMIN_HOME="{self.work / "absent"}"\nLMD_WEBROOT_LIST="{listing}"\n', lib_dir=library)
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertTrue(marker.exists(), 'A separate check error suppressed the malware notification')
        self.assertIn('CRITICAL LMD full scan found malware', marker.read_text())

    def policy_setup(self):
        (self.lmd / 'cron').mkdir(exist_ok=True)
        (self.lmd / 'internals').mkdir(exist_ok=True)
        shutil.copyfile(FIXTURES / 'conf.maldet', self.lmd / 'conf.maldet')
        shutil.copyfile(FIXTURES / 'conf.maldet.cron', self.lmd / 'cron/conf.maldet.cron')
        shutil.copyfile(FIXTURES / 'lmd-internals.conf', self.lmd / 'internals/internals.conf')
        self.policy_daily = self.work / 'maldet.daily'
        self.policy_daily.write_text((FIXTURES / 'maldet.daily').read_text().replace('/usr/local/maldetect', str(self.lmd)))
        self.policy_daily.chmod(0o700)
        self.policy_sysconfig = self.work / 'sysconfig'
        self.policy_sysconfig.write_text(f'MONITOR_MODE="{self.lmd}/directadmin-webroots"\n')
        self.policy_default = self.work / 'default'
        self.policy_sigup = self.work / 'maldet-sigup'
        self.policy_sigup.write_text(f'0 */6 * * * root "{self.lmd}/maldet" --cron-sigup >> /dev/null 2>&1\n')
        self.policy_scan = self.work / 'maldet-fullscan'
        self.policy_scan.write_text(f"30 0 * * 0 root /usr/bin/flock -n /var/run/maldet-fullscan.lock '{self.lmd}/maldet' -b -a '/home/?/domains/?/public_html/' >> /var/log/maldet/fullscan-cron.log 2>&1\n")
        self.policy_unit = self.work / 'maldet.service'
        self.policy_unit.write_text('[Service]\nEnvironmentFile=-/etc/sysconfig/maldet\nEnvironmentFile=-/etc/default/maldet\n'
                                    f'ExecStart={self.lmd}/maldet --monitor ${{MONITOR_MODE}}\n')
        self.policy_prefix = f'''
LMD_EXPECT_QUARANTINE_ENABLED=1
LMD_SYSCONFIG_FILE={Q(str(self.policy_sysconfig))}
LMD_DEFAULT_FILE={Q(str(self.policy_default))}
LMD_DAILY_CRON_FILE={Q(str(self.policy_daily))}
LMD_SIGUP_CRON_FILE={Q(str(self.policy_sigup))}
LMD_FULLSCAN_CRON_FILE={Q(str(self.policy_scan))}
systemctl() {{ if [ "$1" = cat ]; then command cat {Q(str(self.policy_unit))}; else return 0; fi; }}
'''

    def policy(self, extra=''):
        return self.run_shell(self.policy_prefix + extra + '\n_lmd_check_configuration')

    def test_production_configuration_and_split_cron_policy(self):
        self.policy_setup()
        output = self.policy()
        self.assertNotIn('WARNING', output)
        self.assertNotIn('ERROR', output)
        self.assertIn('daily autoupdate_version intentionally disabled', output)
        self.assertIn('daily autoupdate_signatures intentionally disabled', output)
        self.assertIn('PASS LMD sigup cron definition matches', output)
        self.assertIn('PASS LMD fullscan cron definition matches', output)
        self.assertIn('PASS LMD effective MONITOR_MODE matches', output)

    def compat_get(self, content, key, base=''):
        self.policy_setup()
        with (self.lmd / 'conf.maldet').open('a') as file:
            file.write(base)
        compat = self.lmd / 'internals/compat.conf'
        compat.write_text(content)
        return self.run_shell(f'''LMD_POLICY_MAIN={Q(str(self.lmd / 'conf.maldet'))}
LMD_POLICY_COMPAT={Q(str(compat))}
value="$(_lmd_policy_get "$LMD_POLICY_COMPAT" {Q(key)})"; rc=$?
printf '%s:%s' "$rc" "$value"
''')

    def test_compat_migrations_do_not_override_modern_policy(self):
        self.policy_setup()
        (self.lmd / 'internals/compat.conf').write_text(
            'if [ ! "$quarantine_clean" ] && [ "$quar_clean" ]; then\n'
            '    quarantine_clean="$quar_clean"\nfi\n'
            'if [ ! "$scan_clamscan" ] && [ "$clamav_scan" ]; then\n'
            '    scan_clamscan="$clamav_scan"\nfi\n')
        with (self.lmd / 'conf.maldet').open('a') as file:
            file.write('quar_clean="1"\nclamav_scan="0"\n')
        self.assertNotIn('WARNING', self.policy())

    def test_compat_fallback_and_chained_mapping(self):
        content = ('if [ ! "$first" ] && [ "$legacy" ]; then\n'
                   'first="$legacy"\nfi\n'
                   'if [ ! "$second" ] && [ "$first" ]; then\n'
                   'second="$first"\nfi\n')
        self.assertEqual('0:0', self.compat_get(content, 'second', 'legacy="0"\n'))

    def test_compat_special_depth_migration(self):
        content = ('if [ "${scan_hexfifo:-0}" = "1" ] && [ "$scan_hexfifo_depth" ]; then\n'
                   'scan_hexdepth="$scan_hexfifo_depth"\nfi\n')
        self.assertEqual('0:4096', self.compat_get(content, 'scan_hexdepth',
                         'scan_hexfifo="1"\nscan_hexfifo_depth="4096"\n'))

    def test_compat_special_workers_migration(self):
        content = 'if [ "$scan_hex_workers" ]; then\nscan_workers="$scan_hex_workers"\nfi\n'
        self.assertEqual('0:4', self.compat_get(content, 'scan_workers', 'scan_hex_workers="4"\n'))

    def test_compat_dynamic_legacy_only_warns_when_needed(self):
        content = 'if [ ! "$quarantine_clean" ] && [ "$quar_clean" ]; then\nquarantine_clean="$quar_clean"\nfi\n'
        self.assertEqual('1:', self.compat_get(content, 'quarantine_clean', 'quar_clean="$unknown"\n'))
        self.assertEqual('2:', self.compat_get(content, 'quarantine_clean',
                         'quarantine_clean=""\nquar_clean="$unknown"\n'))
        self.assertEqual('1:', self.compat_get(content, 'email_alert', 'quar_clean="$unknown"\n'))

    def test_compat_rejects_unknown_shell_and_malformed_migrations(self):
        marker = self.work / 'executed'
        for content in [f'touch {Q(str(marker))}\n',
                        'if [ ! "$a" ] && [ "$b" ]; then\nc="$b"\nfi\n',
                        'if [ ! "$a" ] && [ "$b" ]; then\na="$b"\n',
                        'email_alert="1"; email_alert="0"\n',
                        f'email_alert="$(touch {marker})"\n']:
            with self.subTest(content=content):
                self.assertEqual('2:', self.compat_get(content, 'email_alert'))
        self.assertFalse(marker.exists())

    def test_policy_parses_each_file_and_compat_once_per_run(self):
        self.policy_setup()
        compat = self.lmd / 'internals/compat.conf'
        compat.write_text('if [ ! "$quarantine_clean" ] && [ "$quar_clean" ]; then\n'
                          'quarantine_clean="$quar_clean"\nfi\n')
        counts = self.work / 'parse-counts'
        output = self.policy(f'''
eval "$(declare -f _lmd_config_stream | sed '1s/_lmd_config_stream/_original_config_stream/')"
eval "$(declare -f _lmd_compat_compute | sed '1s/_lmd_compat_compute/_original_compat_compute/')"
_lmd_config_stream() {{ printf 'config:%s\\n' "${{2:-uncached}}" >> {Q(str(counts))}; _original_config_stream "$@"; }}
_lmd_compat_compute() {{ printf 'compat\\n' >> {Q(str(counts))}; _original_compat_compute "$@"; }}
''')
        self.assertNotIn('WARNING', output)
        self.assertCountEqual(counts.read_text().splitlines(), [
            f'config:{self.lmd / "conf.maldet"}',
            f'config:{self.policy_sysconfig}',
            f'config:{self.lmd / "cron/conf.maldet.cron"}', 'compat'])

    def test_policy_cache_refreshes_between_runs(self):
        self.policy_setup()
        compat = self.lmd / 'internals/compat.conf'
        compat.write_text('quarantine_on_error="0"\n')
        output = self.run_shell(self.policy_prefix + f'''
_lmd_check_configuration
printf 'quarantine_on_error="1"\\n' > {Q(str(compat))}
printf 'email_alert="0"\\n' >> {Q(str(self.lmd / 'conf.maldet'))}
printf '\\nSECOND RUN\\n'
_lmd_check_configuration
''')
        first, second = output.split('SECOND RUN')
        self.assertNotIn('WARNING', first)
        self.assertIn('WARNING LMD base configuration: email_alert differs', second)
        self.assertIn('WARNING LMD configuration override: quarantine_on_error differs', second)

    def test_live_quarantine_on_error_drift(self):
        self.policy_setup()
        with (self.lmd / 'conf.maldet').open('a') as file:
            file.write('quarantine_on_error="1"\n')
        self.assertIn('WARNING LMD base configuration: quarantine_on_error differs', self.policy())

    def test_empty_policy_values_are_not_missing(self):
        self.policy_setup()
        output = self.policy()
        self.assertIn('import_config_url matches', output)
        file = self.lmd / 'conf.maldet'
        file.write_text(file.read_text().replace('import_config_url=""\n', ''))
        self.assertIn('import_config_url missing', self.policy())

    def test_unexpected_import_and_hook_redacted(self):
        self.policy_setup()
        with (self.lmd / 'conf.maldet').open('a') as file:
            file.write('import_config_url="https://secret:password@example.invalid/config"\npost_scan_hook="/secret/hook"\n')
        output = self.policy()
        self.assertIn('import_config_url differs', output)
        self.assertIn('post_scan_hook differs', output)
        self.assertNotIn('password', output)
        self.assertNotIn('/secret/hook', output)

    def test_external_config_is_never_executed(self):
        self.policy_setup()
        marker = self.work / 'must not exist'
        with (self.lmd / 'conf.maldet').open('a') as file:
            file.write(f'quarantine_on_error="$(touch \'{marker}\')"\n')
        self.assertIn('quarantine_on_error cannot be safely resolved', self.policy())
        self.assertFalse(marker.exists())

    def test_conditional_configuration_is_unknown(self):
        self.policy_setup()
        with (self.lmd / 'conf.maldet').open('a') as file:
            file.write('if true; then\nquarantine_on_error=1\nfi\n')
        self.assertIn('cannot be safely resolved', self.policy())

    def test_config_literal_comments_crlf_duplicate_keys(self):
        file = self.work / 'literal conf'
        file.write_bytes(b'  quarantine_on_error="1"\r\n export quarantine_on_error = \'0\' # policy\r\n')
        output = self.run_shell(f'_lmd_config_get {Q(str(file))} quarantine_on_error')
        self.assertEqual(output, '0')

    def test_tuning_differences_are_informational(self):
        self.policy_setup()
        with (self.lmd / 'conf.maldet').open('a') as file:
            file.write('scan_workers="4"\ncron_prune_days="14"\nscan_hashtype="sha256"\nemail_addr="private@example.invalid"\n')
        output = self.policy()
        self.assertNotIn('WARNING', output)
        self.assertIn('scan_workers: 4', output)
        self.assertIn('cron_prune_days: 14', output)
        self.assertNotIn('private@example.invalid', output)

    def test_disabled_config_check_retains_operational_helpers(self):
        self.policy_setup()
        (self.lmd / 'conf.maldet').unlink()
        self.assertEqual('', self.policy('LMD_CONFIG_CHECK_ENABLED=0'))

    def test_override_can_enable_program_updates(self):
        self.policy_setup()
        (self.lmd / 'cron/conf.maldet.cron').write_text('autoupdate_version="1"\nautoupdate_signatures="0"\n')
        output = self.policy()
        self.assertIn('WARNING LMD daily program override', output)
        self.assertIn('effective daily program updates conflict', output)

    def test_removed_override_is_detected(self):
        self.policy_setup()
        (self.lmd / 'cron/conf.maldet.cron').unlink()
        output = self.policy()
        self.assertIn('daily program override: configuration unavailable', output)
        self.assertIn('effective daily autoupdate_version differs', output)

    def test_cron_final_override_wins_over_sysconfig(self):
        self.policy_setup()
        with self.policy_sysconfig.open('a') as file:
            file.write('autoupdate_version="1"\nautoupdate_signatures="1"\n')
        self.assertNotIn('WARNING', self.policy())

    def test_compatibility_overlay_quarantine_drift(self):
        self.policy_setup()
        (self.lmd / 'internals/compat.conf').write_text('quarantine_on_error="1"\n')
        self.assertIn('WARNING LMD configuration override: quarantine_on_error differs', self.policy())

    def test_default_monitor_environment_overrides_sysconfig(self):
        self.policy_setup()
        self.policy_default.write_text('MONITOR_MODE="users"\n')
        self.assertIn('effective MONITOR_MODE differs', self.policy())

    def test_monitor_fallback_to_base_configuration(self):
        self.policy_setup()
        self.policy_sysconfig.unlink()
        with (self.lmd / 'conf.maldet').open('a') as file:
            file.write(f'default_monitor_mode="{self.lmd}/directadmin-webroots"\n')
        output = self.policy()
        self.assertIn('uses default_monitor_mode fallback', output)
        self.assertIn('PASS LMD effective MONITOR_MODE', output)

    def test_monitor_unit_changed_to_fixed_target(self):
        self.policy_setup()
        self.policy_unit.write_text(self.policy_unit.read_text().replace('${MONITOR_MODE}', 'users'))
        self.assertIn('effective MONITOR_MODE unknown', self.policy())

    def test_daily_script_ignores_override(self):
        self.policy_setup()
        self.policy_daily.write_text(self.policy_daily.read_text().replace('    . $cron_custom_conf\n', ''))
        self.assertIn('effective update behavior UNKNOWN', self.policy())

    def test_daily_script_unconditional_update(self):
        self.policy_setup()
        with self.policy_daily.open('a') as file:
            file.write('$inspath/maldet -d\n')
        self.assertIn('effective update behavior UNKNOWN', self.policy())

    def test_daily_script_changed_override_binding(self):
        self.policy_setup()
        file = self.lmd / 'internals/internals.conf'
        file.write_text(file.read_text().replace('cron/conf.maldet.cron', 'cron/other.conf'))
        self.assertIn('effective update behavior UNKNOWN', self.policy())

    def test_daily_script_not_executable(self):
        self.policy_setup()
        self.policy_daily.chmod(0o600)
        self.assertIn('effective update behavior UNKNOWN', self.policy())

    def test_sigup_cron_disabled_or_retimed(self):
        self.policy_setup()
        self.policy_sigup.write_text('# disabled job\n')
        self.assertIn('expected exactly one active job, found 0', self.policy())
        self.policy_sigup.write_text(f'0 */12 * * * root "{self.lmd}/maldet" --cron-sigup\n')
        self.assertIn('sigup cron schedule/user mismatch', self.policy())

    def test_signature_interval_drives_cron_expectation(self):
        self.policy_setup()
        with (self.lmd / 'conf.maldet').open('a') as file:
            file.write('sigup_interval="4"\n')
        self.policy_sigup.write_text(self.policy_sigup.read_text().replace('*/6', '*/4'))
        self.assertNotIn('WARNING', self.policy('LMD_EXPECT_SIGUP_INTERVAL=4'))

    def test_cron_unexpected_program_update_command(self):
        self.policy_setup()
        with self.policy_sigup.open('a') as file:
            file.write(f'0 1 * * * root "{self.lmd}/maldet" -d\n')
        output = self.policy()
        self.assertIn('expected independent --cron-sigup', output)
        self.assertIn('expected exactly one active job, found 2', output)

    def test_cron_shell_injection_is_not_executed(self):
        self.policy_setup()
        marker = self.work / 'never execute'
        self.policy_sigup.write_text(f'0 */6 * * * root "{self.lmd}/maldet" --cron-sigup; touch "{marker}"\n')
        self.assertIn('command is not safely recognizable', self.policy())
        self.assertFalse(marker.exists())

    def test_fullscan_schedule_and_target_drift(self):
        self.policy_setup()
        self.policy_scan.write_text(self.policy_scan.read_text().replace('30 0 * * 0', '30 1 * * 1').replace('/home/?/domains/?/public_html/', '/home/'))
        output = self.policy()
        self.assertIn('fullscan cron schedule/user mismatch', output)
        self.assertIn('fullscan cron arguments/target mismatch', output)

    def test_custom_daily_commands_require_review(self):
        self.policy_setup()
        (self.lmd / 'cron/custom.cron').write_text('maldet -d\n')
        self.assertIn('daily custom.cron contains commands', self.policy())

    def test_expected_configuration_validation(self):
        for key, value in [('LMD_EXPECT_QUARANTINE_ON_ERROR', '2'), ('LMD_EXPECT_SCAN_CLAMSCAN', 'maybe'), ('LMD_EXPECT_SIGUP_INTERVAL', '-6')]:
            self.assertIn('ERROR', self.config_test(f'{key}={value}\n', 1))
        self.config_test('LMD_EXPECT_IMPORT_CONFIG_URL=""\nLMD_EXPECT_POST_SCAN_HOOK=""\nLMD_EXPECT_CRON_PRUNE_DAYS=0\n')

    def test_fullscan_unquoted_target_is_not_safe(self):
        self.policy_setup()
        self.policy_scan.write_text(self.policy_scan.read_text().replace("'/home/?/domains/?/public_html/'", '/home/?/domains/?/public_html/'))
        self.assertIn('command is not safely recognizable', self.policy())

    def test_monitor_export_assignment_not_valid_for_systemd(self):
        self.policy_setup()
        self.policy_sysconfig.write_text('export ' + self.policy_sysconfig.read_text())
        self.assertIn('not a systemd EnvironmentFile assignment', self.policy())

    def test_monitor_fallback_includes_runtime_overlay(self):
        self.policy_setup()
        self.policy_sysconfig.write_text('default_monitor_mode="users"\n')
        with (self.lmd / 'conf.maldet').open('a') as file:
            file.write(f'default_monitor_mode="{self.lmd}/directadmin-webroots"\n')
        self.assertIn('effective MONITOR_MODE differs', self.policy())

    def test_daily_override_with_false_file_guard_is_unknown(self):
        self.policy_setup()
        self.policy_daily.write_text(self.policy_daily.read_text().replace('if [ -f "$cron_custom_conf" ]; then', 'if false; then'))
        self.assertIn('effective update behavior UNKNOWN', self.policy())

    def test_intentional_literal_import_query_string(self):
        self.policy_setup()
        with (self.lmd / 'conf.maldet').open('a') as file:
            file.write('import_config_url="https://example.invalid/config?a=1&b=2"\n')
        output = self.policy('LMD_EXPECT_IMPORT_CONFIG_URL="https://example.invalid/config?a=1&b=2"')
        self.assertIn('import_config_url matches', output)
        self.assertNotIn('WARNING', output)

    def test_policy_helper_not_a_separate_registered_integration(self):
        result = self.main('', ['--list-checks'])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines().count('lmd'), 1)
        self.assertNotIn('lmd_policy', result.stdout)

    def test_critical_notification_precedes_many_policy_warnings(self):
        library = self.work / 'test library'
        shutil.copytree(ROOT / 'lib', library)
        marker = self.work / 'captured curl arguments'
        with (library / 'notify/telegram.sh').open('a') as file:
            file.write('\ncurl() { printf "%s\\n" "$@" > ' + Q(str(marker)) + '; }\n')
        (library / 'checks/notification_fixture.sh').write_text(
            'hc_register_check notification_fixture\n'
            'check_notification_fixture() { local i; for i in {1..100}; do hc_warn "Configuration policy drift in setting number $i requiring review"; done; hc_status CRITICAL "LMD full scan found malware"; }\n')
        result = self.main('NOTIFY_TELEGRAM=1\nTELEGRAM_BOT_TOKEN=fixture\nTELEGRAM_CHAT_ID=fixture\n', lib_dir=library)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        output = marker.read_text()
        self.assertIn('1. CRITICAL LMD full scan found malware', output)
        self.assertIn('Truncated', output)
        self.assertLess(len(output), 4096)


if __name__ == '__main__':
    unittest.main(verbosity=2)
