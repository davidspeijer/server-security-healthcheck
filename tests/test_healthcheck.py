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
        return self.run_shell(f'CHECK_DIRECTADMIN_WEBROOTS=1\nDIRECTADMIN_HOME={Q(str(home))}\nLMD_MONITOR_LIST={Q(str(monitored))}\n_lmd_check_webroots')

    def test_coverage_equal_normalizes_trailing_slash_and_duplicates(self):
        output = self.coverage('# comment\n{expected}/\n{expected}\n')
        self.assertIn('1/1 webroots monitored', output)
        self.assertNotIn('WARNING', output)

    def test_coverage_same_count_different_set(self):
        output = self.coverage('/home/stale/domains/old.nl/public_html\n')
        self.assertIn('WARNING LMD realtime coverage mismatch', output)
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
        self.assertIn('v0.4.0', result.stdout)

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


if __name__ == '__main__':
    unittest.main(verbosity=2)
