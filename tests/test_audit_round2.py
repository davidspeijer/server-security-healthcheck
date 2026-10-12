"""Offline F07-F14 regressions and A-H integration scenarios; no host services."""
import datetime
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import unittest
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib/checks"))
from unittest import mock
import test_healthcheck as fixture

SPEC = importlib.util.spec_from_file_location('health_data', fixture.ROOT / 'lib/checks/health_data.py')
data = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(data)
NOW = fixture.NOW
Q = fixture.Q


def iso(epoch):
    return datetime.datetime.fromtimestamp(epoch, datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%S+00:00')


def journal(messages, start=NOW-60):
    return '\n'.join(iso(start+i) + ' host freshclam[42]: ' + message for i, message in enumerate(messages))


SUCCESS = ['ClamAV update process started at Sun Sep 20',
           'daily.cld updated (version: 1)', 'main.cvd database is up-to-date (version: 1)',
           'Database test passed.', 'bytecode.cvd database is up-to-date (version: 1)']


class Fixtures(unittest.TestCase):
    setUp = fixture.HealthcheckTests.setUp
    run_shell = fixture.HealthcheckTests.run_shell
    policy_setup = fixture.HealthcheckTests.policy_setup
    policy = fixture.HealthcheckTests.policy
    append_meta = fixture.HealthcheckTests.append_meta
    main = fixture.HealthcheckTests.main

    def event(self, when=NOW-60, kind='threat_detected'):
        return json.dumps({'ts': iso(when), 'type': kind}) + '\n'

    def audit_source(self, content):
        path = self.work / 'audit.jsonl'
        path.write_text(content)
        return path

    def disk(self, output, status=0, threshold=80):
        path = self.work / 'df.txt'; path.write_text(output)
        return self.run_shell(f'''source {Q(str(fixture.ROOT / 'lib/checks/disk.sh'))}
CHECK_DISK=1
DISK_WARN_PERCENT={threshold}
df() {{ cat {Q(str(path))}; return {status}; }}
check_disk
''')

    def databases(self, files=None, config=None):
        directory = self.work / 'active databases'; directory.mkdir(exist_ok=True)
        for name, age in (files if files is not None else [('daily.cvd', 1), ('main.cvd', 1000), ('bytecode.cvd', 1)]):
            path = directory / name; path.write_text('fixture database')
            os.utime(path, (NOW-age*3600, NOW-age*3600))
        path = self.work / 'clamd.conf'
        path.write_text(config if config is not None else f'DatabaseDirectory "{directory}"\n')
        return directory, path

    def db_check(self, files=None, config=None, extra=''):
        directory, path = self.databases(files, config)
        return self.run_shell(f'CLAMAV_CONFIG_FILE={Q(str(path))}\n' + extra + '\n_clamav_check_databases')

    def monitor_value(self, directives, sysconfig='', default=''):
        self.policy_setup()
        self.policy_sysconfig.write_text(sysconfig)
        self.policy_default.write_text(default)
        unit = '[Service]\n' + directives + f'\nExecStart="{self.lmd}/maldet" --monitor ${{MONITOR_MODE}}\n'
        return data.monitor(unit, str(self.lmd), str(self.policy_sysconfig), str(self.policy_default))

    def lmd_run(self, missing='systemctl', findings='malware', monitor=1):
        if findings in ('malware', 'multiple'):
            self.append_meta(hits=1)
            shutil.copyfile(fixture.FIXTURES / 'session.malware.tsv', self.session)
        return self.run_shell(f'''
CHECK_LMD=1
LMD_MONITOR_REQUIRED={monitor}
hc_have() {{ [ "$1" != {Q(missing)} ]; }}
_lmd_check_configuration() {{ hc_detail 'policy still checked'; }}
_lmd_check_service() {{ hc_status PASS 'monitor checked'; }}
_lmd_check_signature_updater() {{ hc_detail 'signature updater still checked'; }}
_lmd_check_program_updater() {{ hc_detail 'program updater still checked'; }}
_lmd_check_webroots() {{ {'hc_warn "coverage failure"' if findings in ('coverage', 'multiple') else "hc_detail 'coverage still checked'"}; }}
_lmd_scanner_reliability() {{ {'hc_warn "scanner reliability failure"' if findings in ('scanner', 'multiple') else 'LMD_SCANNER_RESULT=clean'}; }}
check_lmd
hc_detail "errors=$HC_ERRORS warnings=${{#HC_WARNINGS[@]}}"
''')

    def telegram(self, token='123456:secret_fixture_token', chat='1234', status=0, trace=False, missing=False, message='hello'):
        args = self.work / 'curl.argv'; request = self.work / 'curl.stdin'
        script = f'''set -u -o pipefail
source {Q(str(fixture.ROOT / 'lib/common.sh'))}
source {Q(str(fixture.ROOT / 'lib/notify/telegram.sh'))}
NOTIFY_TELEGRAM=1
TELEGRAM_BOT_TOKEN={Q(token)}
TELEGRAM_CHAT_ID={Q(chat)}
curl() {{ printf '%s\\n' "$@" > {Q(str(args))}; cat > {Q(str(request))}; printf '%s' "$TELEGRAM_BOT_TOKEN" >&2; printf '%s' '{{"ok":true}}'; return {status}; }}
{'hc_have() { return 1; }' if missing else ''}
{'set -x' if trace else ''}
notify_telegram {Q(message)}
'''
        result = subprocess.run([fixture.BASH, '-c', script], text=True, capture_output=True, env=self.env)
        return result, args, request


class FreshClamTests(Fixtures):
    def test_completed_success(self):
        self.assertEqual(data.freshclam(journal(SUCCESS), NOW), str(NOW-56))
    def test_recent_success(self):
        self.assertEqual(data.freshclam(journal(SUCCESS, NOW-4), NOW), str(NOW))
    def test_two_hours_future(self):
        with self.assertRaises(ValueError): data.freshclam(journal(SUCCESS, NOW+7200), NOW)
    def test_far_future(self):
        with self.assertRaises(ValueError): data.freshclam(journal(SUCCESS, NOW+864000), NOW)
    def test_malformed_timestamp(self):
        with self.assertRaises(ValueError): data.freshclam('garbage host Database updated (1)', NOW)
    def test_intermediate_only(self):
        with self.assertRaises(ValueError): data.freshclam(journal(['Database test passed']), NOW)
    def test_intermediate_then_failure(self):
        with self.assertRaises(ValueError): data.freshclam(journal(['Database test passed', 'ERROR: update failed']), NOW)
    def test_success_then_failure(self):
        with self.assertRaises(ValueError): data.freshclam(journal(SUCCESS+['ERROR: update failed']), NOW)
    def test_failure_then_success(self):
        self.assertEqual(data.freshclam(journal(['ERROR: update failed']+SUCCESS), NOW), str(NOW-55))
    def test_multiple_attempts_latest_pending(self):
        with self.assertRaises(ValueError): data.freshclam(journal(SUCCESS+['ClamAV update process started']), NOW)
    def test_no_rotated_files_journal_failure(self):
        output = self.run_shell('journalctl() { return 1; }; _clamav_last_success_epoch', 1)
        self.assertEqual(output, '')
    def test_empty_journal(self):
        with self.assertRaises(ValueError): data.freshclam('', NOW)
    def test_non_monotone_events(self):
        with self.assertRaises(ValueError): data.freshclam(journal(SUCCESS)+ '\n'+journal(['ERROR: failed'], NOW-500), NOW)
    def test_small_future_skew_rejected(self):
        with self.assertRaises(ValueError): data.freshclam(journal(SUCCESS, NOW-3), NOW)
    def test_explicit_overall_completion(self):
        self.assertEqual(data.freshclam(journal(['ClamAV update process started', 'Database update completed successfully.']), NOW), str(NOW-59))

    def test_interleaved_processes_unknown(self):
        first=journal(SUCCESS[:2])
        second=journal(SUCCESS[0:1]+SUCCESS[2:],NOW-58).replace('freshclam[42]', 'freshclam[43]')
        with self.assertRaises(ValueError): data.freshclam(first+'\n'+second, NOW)
    def test_completion_cannot_recover_same_failed_attempt(self):
        with self.assertRaises(ValueError): data.freshclam(journal(['ERROR: update failed', 'Database update completed successfully.']),NOW)

    def test_partial_epoch_stdout_with_failed_parser_not_success(self):
        output=self.run_shell(f'CHECK_CLAMAV=1\n_clamav_check_databases() {{ :; }}\nhc_have() {{ return 0; }}\nhc_check_service() {{ :; }}\nsystemctl() {{ [ "$1" != is-failed ]; }}\n_clamav_last_success_epoch() {{ echo {NOW-60}; return 1; }}\ncheck_clamav')
        self.assertIn('UNKNOWN',output); self.assertNotIn('last successful update/check:',output)


class DatabaseTests(Fixtures):
    def test_healthy_active_databases(self):
        self.assertNotIn('ERROR', self.db_check())
    def test_stale_daily_recent_bytecode(self):
        self.assertIn('daily signatures are 100h old', self.db_check([('daily.cvd',100),('main.cvd',1),('bytecode.cvd',0)]))
    def test_missing_daily(self):
        self.assertIn('required daily database missing', self.db_check([('main.cvd',1)]))
    def test_inactive_daily_not_selected(self):
        inactive = self.work/'inactive'; inactive.mkdir(); (inactive/'daily.cvd').write_text('recent')
        self.assertIn('required daily database missing', self.db_check([('main.cvd',1)]))
    def test_multiple_directories_active_only(self):
        inactive = self.work/'inactive'; inactive.mkdir(); (inactive/'daily.cvd').write_text('recent')
        self.assertIn('daily signatures are 100h old', self.db_check([('daily.cvd',100),('main.cvd',1)]))
    def test_active_config_from_unit(self):
        directory, config = self.databases()
        output = self.run_shell(f'''systemctl() {{ printf '[Service]\\nExecStart = /usr/sbin/clamd -c "%s"\\n' {Q(str(config))}; }}
_clamav_check_databases''')
        self.assertIn(str(directory), output); self.assertNotIn('ERROR', output)
    def test_malformed_config(self):
        self.assertIn('UNKNOWN', self.db_check(config='DatabaseDirectory relative\n'))
    def test_missing_config(self):
        self.assertIn('UNKNOWN', self.run_shell('CLAMAV_CONFIG_FILE='+Q(str(self.work/'absent-config'))+'\n_clamav_check_databases'))
    def test_cld_format(self):
        self.assertNotIn('ERROR', self.db_check([('daily.cld',1),('main.cld',1)]))
    def test_partial_update_not_database(self):
        self.assertIn('required daily database missing', self.db_check([('daily.cvd.tmp',0),('main.cvd',1)]))
    def test_missing_main(self):
        self.assertIn('required main database missing', self.db_check([('daily.cvd',1)]))
    def test_directory_unreadable(self):
        output=self.db_check(extra='[() { if [[ "$1" = -r && "$2" = *"active databases" ]]; then return 1; fi; builtin [ "$@"; }')
        self.assertIn('directory unavailable/unreadable', output)
    def test_future_database_mtime(self):
        self.assertIn('in the future', self.db_check([('daily.cvd',-2),('main.cvd',1)]))
    def test_duplicate_database_formats_cannot_hide_stale(self):
        self.assertIn('100h old', self.db_check([('daily.cvd',100),('daily.cld',1),('main.cvd',1)]))
    def test_build_default(self):
        self.assertNotIn('ERROR', self.db_check(config='# default\n', extra=f'clamconf() {{ printf "#DatabaseDirectory %s\\n" {Q(str(self.work / "active databases"))}; }}'))
    def test_missing_default_unknown(self):
        self.assertIn('UNKNOWN', self.db_check(config='# default\n', extra='hc_have() { [ "$1" != clamconf ]; }'))

    def test_packaging_specific_compiled_default(self):
        extra=f'clamconf() {{ if [ "$2" = clamd.conf ]; then echo "ERROR: Unknown config file"; else printf "#DatabaseDirectory %s\\n" {Q(str(self.work / "active databases"))}; fi; }}'
        self.assertNotIn('ERROR',self.db_check(config='# default\n',extra=extra))
    def test_explicit_directory_does_not_need_clamconf(self):
        self.assertNotIn('ERROR',self.db_check(extra='clamconf() { return 1; }'))


class AuditTests(Fixtures):
    def test_zero_events(self):
        path=self.audit_source(self.event(kind='other')); self.assertEqual(data.audit(str(path),'threat_detected',24,NOW),'0')
    def test_in_interval(self):
        path=self.audit_source(self.event()); self.assertEqual(data.audit(str(path),'threat_detected',24,NOW),'1')
    def test_missing_source(self):
        with self.assertRaises(ValueError): data.audit('/no/fixture/audit','threat_detected',24,NOW)
    def test_read_failure(self):
        path=self.audit_source(self.event())
        with mock.patch('bounded_input.os.open', side_effect=PermissionError('fixture')):
            with self.assertRaises(OSError): data.audit(str(path),'threat_detected',24,NOW)
    def test_parser_dependency_failure(self):
        output=self.run_shell('hc_data_parse() { return 1; }; hc_json_event_count_since threat_detected /fixture 24',1)
        self.assertEqual(output,'')
    def test_malformed_json(self):
        path=self.audit_source('{broken');
        with self.assertRaises(ValueError): data.audit(str(path),'threat_detected',24,NOW)
    def test_malformed_timestamp(self):
        path=self.audit_source('{"type":"threat_detected","ts":"bad"}\n')
        with self.assertRaises(ValueError): data.audit(str(path),'threat_detected',24,NOW)
    def test_before_interval(self):
        path=self.audit_source(self.event(NOW-86401)); self.assertEqual(data.audit(str(path),'threat_detected',24,NOW),'0')
    def test_future_event(self):
        path=self.audit_source(self.event(NOW+3600))
        with self.assertRaises(ValueError): data.audit(str(path),'threat_detected',24,NOW)
    def test_small_skew_rejected(self):
        path=self.audit_source(self.event(NOW+1))
        with self.assertRaises(ValueError): data.audit(str(path),'threat_detected',24,NOW)
    def test_mixed_invalid_records(self):
        path=self.audit_source(self.event()+'malformed\n')
        with self.assertRaises(ValueError): data.audit(str(path),'threat_detected',24,NOW)
    def test_empty_source(self):
        path=self.audit_source(''); self.assertEqual(data.audit(str(path),'threat_detected',24,NOW),'0')
    def test_boundaries_inclusive(self):
        path=self.audit_source(self.event(NOW-86400)+self.event(NOW)); self.assertEqual(data.audit(str(path),'threat_detected',24,NOW),'2')
    def test_duplicate_json_keys(self):
        path=self.audit_source('{"type":"other","type":"threat_detected","ts":"'+iso(NOW)+'"}\n')
        with self.assertRaises(ValueError): data.audit(str(path),'threat_detected',24,NOW)
    def test_timestamp_timezone_conversion(self):
        path=self.audit_source('{"type":"threat_detected","ts":"2026-09-20T10:00:00+02:00"}\n')
        self.assertEqual(data.audit(str(path),'threat_detected',24,NOW),'1')

    def test_fractional_future_rejected(self):
        with self.assertRaises(ValueError): data.timestamp(iso(NOW).replace('+00:00','.100+00:00'),NOW)
    def test_nonstandard_json_constant(self):
        path=self.audit_source('{"type":"other","ts":"'+iso(NOW)+'","extra":NaN}\n')
        with self.assertRaises(ValueError): data.audit(str(path),'threat_detected',24,NOW)


HEADER='Filesystem Size Used Avail Use% Mounted on\n'
class DiskTests(Fixtures):
    def test_normal(self): self.assertEqual(self.disk(HEADER+'/dev/x 10G 1G 9G 10% /\n'),'')
    def test_mountpoint_space(self): self.assertIn('/media/disk A is 100%',self.disk(HEADER+'/dev/x 10G 10G 0 100% /media/disk A\n'))
    def test_shared_prefix(self):
        output=self.disk(HEADER+'/dev/a 10G 1G 9G 10% /media/disk A\n/dev/b 10G 10G 0 100% /media/disk B\n')
        self.assertIn('/media/disk B is 100%',output); self.assertNotIn('/media/disk A is',output)
    def test_one_malformed(self): self.assertIn('ERROR',self.disk(HEADER+'bad\n/dev/x 10G 10G 0 100% /\n'))
    def test_all_malformed(self): self.assertIn('no usable records',self.disk(HEADER+'bad\n'))
    def test_empty_success(self): self.assertIn('ERROR',self.disk(''))
    def test_command_failure(self): self.assertIn('check failed',self.disk(HEADER,status=1))
    def test_hundred_percent(self): self.assertIn('100% full',self.disk(HEADER+'/dev/x 10G 10G 0 100% /\n'))
    def test_threshold_boundary(self): self.assertIn('80% full',self.disk(HEADER+'/dev/x 10G 8G 2G 80% /\n'))
    def test_below_threshold(self): self.assertEqual(self.disk(HEADER+'/dev/x 10G 8G 2G 79% /\n'),'')
    def test_duplicate_worst_preserved(self):
        output=self.disk(HEADER+'/dev/x 10G 10G 0 100% /same\n/dev/x 10G 1G 9G 10% /same\n')
        self.assertEqual(output.count('/same is'),1); self.assertIn('100% full',output)
    def test_special_filesystem(self): self.assertIn('90% full',self.disk(HEADER+'server:/share-name 10G 9G 1G 90% /mnt/share\n'))
    def test_long_mountpoint(self):
        mount='/mnt/'+'a'*1024; self.assertIn(mount,self.disk(HEADER+f'/dev/x 10G 9G 1G 90% {mount}\n'))
    def test_invalid_threshold(self): self.assertIn('Invalid disk threshold',self.disk(HEADER,threshold=101))
    def test_missing_percent_sign(self): self.assertIn('malformed',self.disk(HEADER+'/dev/x 10G 9G 1G 90 /\n'))

    def test_trailing_mountpoint_spaces_preserved(self):
        output=self.disk(HEADER+'/dev/a 10G 10G 0 100% /mount \n/dev/b 10G 9G 1G 90% /mount\n')
        self.assertIn('/mount  is 100%',output); self.assertIn('/mount is 90%',output)
    def test_zero_threshold_rejected(self): self.assertIn('Invalid disk threshold',self.disk(HEADER,threshold=0))
    def test_mountpoint_shell_text_not_executed(self):
        marker=self.work/'never-executed'
        mount='/media/$(touch '+str(marker)+')'
        output=self.disk(HEADER+f'/dev/x 10G 10G 0 100% {mount}\n')
        self.assertIn(mount,output); self.assertFalse(marker.exists())


class DailyPolicyTests(Fixtures):
    def contract(self, transform=lambda text:text, expected=1):
        self.policy_setup(); self.policy_daily.write_text(transform(self.policy_daily.read_text()))
        return self.run_shell(f'_lmd_daily_contract {Q(str(self.policy_daily))}', expected)
    def test_exact_contract(self): self.contract(expected=0)
    def test_if_false(self): self.contract(lambda text:'if false; then\n'+text+'\nfi\n')
    def test_unknown_function(self): self.contract(lambda text:'hidden() {\n'+text+'\n}\n')
    def test_early_exit(self): self.contract(lambda text:'exit 0\n'+text)
    def test_and_update(self): self.contract(lambda text:text.replace('$inspath/maldet -u','true && $inspath/maldet -u'))
    def test_or_update(self): self.contract(lambda text:text.replace('$inspath/maldet -u','false || $inspath/maldet -u'))
    def test_extra_conditional(self): self.contract(lambda text:'if [ "$UNKNOWN" = 1 ]; then\n'+text+'\nfi\n')
    def test_comments_whitespace(self): self.contract(lambda text:'\n# harmless\n'+ '\n'.join(' \t'+line+'  ' for line in text.splitlines())+'\n',0)
    def test_multiple_supported_statements(self): self.contract(lambda text: text.replace('\nfi\n', '\nfi\n# next supported block\n'), 0)
    def test_unknown_wrapper(self): self.contract(lambda text:'exec /wrapper\n'+text)
    def test_safe_literal_supported_form(self): self.contract(lambda text:text+'\n# end\n',0)
    def test_malformed_script(self): self.contract(lambda text:text+'\nif\n')
    def test_subshell(self): self.contract(lambda text:'(\n'+text+'\n)\n')
    def test_case_wrapper(self): self.contract(lambda text:'case x in x)\n'+text+'\n;; esac\n')
    def test_return(self): self.contract(lambda text:'return 0\n'+text)
    def test_single_quoted_variable_not_expanded(self): self.contract(lambda text:text.replace('$inspath/maldet -u',"'$inspath/maldet' -u"))

    def stock_contract(self, transform=lambda text:text, expected=0):
        self.policy_setup()
        text=(fixture.FIXTURES/'maldet.daily.stock-2.0.1').read_text().replace("inspath='/usr/local/maldetect'", "inspath='"+str(self.lmd)+"'")
        self.policy_daily.write_text(transform(text))
        self.run_shell(f'_lmd_daily_contract {Q(str(self.policy_daily))}',expected)
    def test_full_stock_2_0_1_contract(self): self.stock_contract()
    def test_full_stock_inside_false_guard(self): self.stock_contract(lambda text:'if false; then\n'+text+'\nfi\n',1)
    def test_full_stock_unknown_early_exit(self): self.stock_contract(lambda text:'exit 0\n'+text,1)
    def test_full_stock_changed_flock_condition(self): self.stock_contract(lambda text:text.replace('if command -v flock','if false && command -v flock'),1)
    def test_full_stock_policy_pass(self):
        self.stock_contract(); self.assertNotIn('effective update behavior UNKNOWN',self.policy())


class MonitorEnvironmentTests(Fixtures):
    def test_normal_environment(self): self.assertEqual(self.monitor_value('Environment=MONITOR_MODE=users'),'users')
    def test_indentation(self): self.assertEqual(self.monitor_value('    Environment=MONITOR_MODE=users'),'users')
    def test_tabs(self): self.assertEqual(self.monitor_value('\tEnvironment = MONITOR_MODE=users'),'users')
    def test_multiple(self): self.assertEqual(self.monitor_value('Environment=OTHER=x\nEnvironment=MONITOR_MODE=users'),'users')
    def test_later_override(self): self.assertEqual(self.monitor_value('Environment=MONITOR_MODE=paths\nEnvironment=MONITOR_MODE=users'),'users')
    def test_environment_reset(self): self.assertEqual(self.monitor_value('Environment=MONITOR_MODE=users\nEnvironment='),'')
    def test_environment_file(self): self.assertEqual(self.monitor_value('EnvironmentFile=-/etc/sysconfig/maldet','MONITOR_MODE=users\n'),'users')
    def test_indented_environment_file(self): self.assertEqual(self.monitor_value('  EnvironmentFile = -/etc/sysconfig/maldet','MONITOR_MODE=users\n'),'users')
    def test_conflicting_file_wins(self): self.assertEqual(self.monitor_value('EnvironmentFile=-/etc/sysconfig/maldet\nEnvironment=MONITOR_MODE=paths','MONITOR_MODE=users\n'),'users')
    def test_comments(self): self.assertEqual(self.monitor_value('# Environment=MONITOR_MODE=bad\n; ignored\nEnvironment=MONITOR_MODE=users'),'users')
    def test_continuation(self): self.assertEqual(self.monitor_value('Environment=OTHER=x \\\n# comment\n MONITOR_MODE=users'),'users')
    def test_malformed_directive(self):
        with self.assertRaises(ValueError): self.monitor_value('Environment MONITOR_MODE=users')
    def test_later_file_override(self): self.assertEqual(self.monitor_value('EnvironmentFile=-/etc/sysconfig/maldet\nEnvironmentFile=-/etc/default/maldet','MONITOR_MODE=paths\n','MONITOR_MODE=users\n'),'users')
    def test_environment_file_reset(self): self.assertEqual(self.monitor_value('EnvironmentFile=-/etc/sysconfig/maldet\nEnvironmentFile=\nEnvironment=MONITOR_MODE=users','MONITOR_MODE=bad\n'),'users')
    def test_unknown_specifier(self):
        with self.assertRaises(ValueError): self.monitor_value('Environment=MONITOR_MODE=%i')
    def test_unset_after_expansion_unknown(self):
        with self.assertRaises(ValueError): self.monitor_value('Environment=MONITOR_MODE=users\nUnsetEnvironment=MONITOR_MODE')
    def test_pass_environment_unknown(self):
        with self.assertRaises(ValueError): self.monitor_value('PassEnvironment=MONITOR_MODE')
    def test_dropin_override(self): self.assertEqual(self.monitor_value('Environment=MONITOR_MODE=bad\n# /etc/systemd/system/maldet.service.d/override.conf\n[Service]\n Environment=MONITOR_MODE=users'),'users')

    def test_unquoted_executable_path_with_spaces_unknown(self):
        self.policy_setup()
        unit=f'[Service]\nEnvironment=MONITOR_MODE=users\nExecStart={self.lmd}/maldet --monitor ${{MONITOR_MODE}}\n'
        with self.assertRaises(ValueError): data.monitor(unit,str(self.lmd),str(self.policy_sysconfig),str(self.policy_default))
    def test_unbraced_argument_with_spaces_unknown(self):
        self.policy_setup()
        unit=f'[Service]\nEnvironment="MONITOR_MODE=/path with spaces"\nExecStart="{self.lmd}/maldet" --monitor $MONITOR_MODE\n'
        with self.assertRaises(ValueError): data.monitor(unit,str(self.lmd),str(self.policy_sysconfig),str(self.policy_default))
    def test_execstart_reset(self):
        self.assertEqual(self.monitor_value('ExecStart=/wrong\nExecStart=\nEnvironment=MONITOR_MODE=users'),'users')

    def test_unterminated_unrelated_file_quote_unknown(self):
        with self.assertRaises(ValueError): self.monitor_value('EnvironmentFile=-/etc/sysconfig/maldet', 'OTHER="unterminated\nMONITOR_MODE=users\n')
    def test_double_optional_marker_unknown(self):
        with self.assertRaises(ValueError): self.monitor_value('EnvironmentFile=--/etc/sysconfig/maldet', 'MONITOR_MODE=users\n')
    def test_optional_file_stat_denied_not_missing(self):
        self.policy_setup()
        unit=f'[Service]\nEnvironmentFile=-/etc/sysconfig/maldet\nExecStart="{self.lmd}/maldet" --monitor ${{MONITOR_MODE}}\n'
        with mock.patch.object(data.os,'stat',side_effect=PermissionError('fixture')):
            with self.assertRaises(OSError): data.monitor(unit,str(self.lmd),str(self.policy_sysconfig),str(self.policy_default))
    def test_file_overrides_unknown_pass_environment(self):
        self.assertEqual(self.monitor_value('PassEnvironment=MONITOR_MODE\nEnvironmentFile=-/etc/sysconfig/maldet', 'MONITOR_MODE=users\n'),'users')
    def test_concatenated_unit_quotes_unknown(self):
        with self.assertRaises(ValueError): self.monitor_value('Environment="MONITOR_MODE=us"ers')


class IndependentChecksTests(Fixtures):
    def test_missing_monitor_malware(self):
        output=self.lmd_run(); self.assertIn('ERROR LMD monitor dependency',output); self.assertIn('CRITICAL LMD full scan found malware',output)
    def test_missing_monitor_scanner_failure(self): self.assertIn('scanner reliability failure',self.lmd_run(findings='scanner'))
    def test_missing_monitor_coverage_failure(self): self.assertIn('coverage failure',self.lmd_run(findings='coverage'))
    def test_missing_monitor_clean_scan(self):
        output=self.lmd_run(findings='clean'); self.assertIn('PASS LMD full scan: no hits',output); self.assertIn('ERROR',output)
    def test_multiple_findings(self):
        output=self.lmd_run(findings='multiple'); self.assertIn('CRITICAL',output); self.assertIn('coverage failure',output); self.assertIn('scanner reliability failure',output)
    def test_required_coverage_dependency(self):
        listing=self.work/'webroots'; listing.write_text('/home/a/domains/a/public_html\n')
        output=self.run_shell(f'CHECK_DIRECTADMIN_WEBROOTS=1\nLMD_WEBROOT_LIST={Q(str(listing))}\nhc_have() {{ [ "$1" != rmdir ]; }}\n_lmd_check_webroots')
        self.assertIn('coverage dependency missing: rmdir',output)
    def test_no_duplicate_dependency_errors(self): self.assertEqual(self.lmd_run().count('dependency missing: systemctl'),1)
    def test_final_exit_two_and_critical(self):
        self.append_meta(hits=1); shutil.copyfile(fixture.FIXTURES/'session.malware.tsv',self.session)
        library=self.work/'library'; shutil.copytree(fixture.ROOT/'lib',library)
        with (library/'common.sh').open('a') as stream:
            stream.write('\nhc_have() { [ "$1" != pgrep ] && command -v "$1" >/dev/null; }\n')
        # All systemctl operations are exported mocks, including autodiscovery.
        env=dict(self.env)
        script=f'''systemctl() {{ return 0; }}; export -f systemctl
exec {Q(fixture.BASH)} {Q(str(fixture.ROOT/'bin/server-security-healthcheck'))}
'''
        config=self.work/'config'; config.mkdir(); (config/'healthcheck.conf').write_text(f'CHECK_APACHE=0\nCHECK_RSPAMD=0\nCHECK_PUREFTP=0\nCHECK_LMD=1\nLMD_DIR="{self.lmd}"\nLMD_CONFIG_CHECK_ENABLED=0\n')
        env.update(SSHC_CONFIG_DIR=str(config),SSHC_LIB_DIR=str(library))
        result=subprocess.run([fixture.BASH,'-c',script],env=env,text=True,capture_output=True)
        self.assertEqual(result.returncode,2,result.stdout+result.stderr); self.assertIn('CRITICAL',result.stdout); self.assertIn('dependency missing: pgrep',result.stdout)
    def test_both_monitor_dependencies_reported_once(self):
        output=self.lmd_run(missing='pgrep'); self.assertEqual(output.count('dependency missing: pgrep'),1)
    def test_monitor_disabled_no_dependency_error(self): self.assertNotIn('dependency missing',self.lmd_run(monitor=0,findings='clean'))
    def test_updates_still_checked(self):
        output=self.lmd_run(); self.assertIn('signature updater still checked',output); self.assertIn('program updater still checked',output); self.assertIn('policy still checked',output)

    def native_source(self, hits=0):
        row=(fixture.FIXTURES/'session.index.native').read_text().splitlines()[1].split('\t')
        header=(fixture.FIXTURES/'session.native.tsv').read_text().strip().split('\t')
        row[5]=header[11]=str(hits)
        (self.lmd/'sess/session.index').write_text('#LMD_INDEX:v2\n'+'\t'.join(row)+'\n')
        self.scan.unlink()
        self.scan=self.lmd/('sess/scan.meta.'+row[0])
        self.scan.write_text(f'path={row[8]}\nstarted={row[1]}\ncompleted={int(row[1])+int(row[3])}\nstate=completed\n')
        detail='php.backdoor.example\t/home/example/file.php\t-\tHEX\tmalware\troot\t644\t12\t0\t-\t-\n' if hits else ''
        (self.lmd/('sess/session.tsv.'+row[0])).write_text('\t'.join(header)+'\n'+detail)
    def test_native_malware_survives_missing_monitor(self):
        self.native_source(1); output=self.lmd_run(findings='clean')
        self.assertIn('ERROR LMD monitor dependency',output); self.assertIn('CRITICAL LMD full scan found malware',output)
    def test_native_clean_check_survives_missing_monitor(self):
        self.native_source(); output=self.lmd_run(findings='clean')
        self.assertIn('ERROR LMD monitor dependency',output); self.assertIn('PASS LMD full scan: no hits',output)


class TelegramTests(Fixtures):
    def test_token_absent_argv(self):
        result,args,request=self.telegram(); self.assertEqual(result.returncode,0); self.assertNotIn('secret_fixture_token',args.read_text()); self.assertIn('secret_fixture_token',request.read_text())
    def test_token_absent_stderr(self): self.assertNotIn('secret_fixture_token',self.telegram()[0].stderr)
    def test_token_absent_stdout(self): self.assertNotIn('secret_fixture_token',self.telegram()[0].stdout)
    def test_curl_failure_redacted(self):
        result,_,_=self.telegram(status=22); self.assertEqual(result.returncode,1); self.assertIn('transport failed',result.stdout); self.assertNotIn('secret_fixture_token',result.stdout+result.stderr)
    def test_successful_send(self):
        result,_,request=self.telegram(); self.assertEqual(result.returncode,0); self.assertIn('text=hello',request.read_text())
    def test_malformed_credentials(self):
        result,args,_=self.telegram(token='bad\nurl=evil'); self.assertEqual(result.returncode,1); self.assertFalse(args.exists())
    def test_missing_curl(self):
        result,args,_=self.telegram(missing=True); self.assertEqual(result.returncode,1); self.assertFalse(args.exists()); self.assertIn('curl is required',result.stdout)
    def test_no_temporary_input(self):
        before=set(self.work.iterdir()); self.telegram(); after=set(self.work.iterdir()); self.assertEqual(after-before,{self.work/'curl.argv',self.work/'curl.stdin'})
    def test_shell_tracing_redacted(self):
        result,_,_=self.telegram(trace=True); self.assertNotIn('secret_fixture_token',result.stdout+result.stderr); self.assertIn('set +x',result.stderr)
    def test_chat_id_also_absent_argv(self):
        _,args,_=self.telegram(chat='-10012345'); self.assertNotIn('-10012345',args.read_text())
    def test_configuration_loading_tracing_redacted(self):
        config=self.work/'telegram.conf'; config.write_text('TELEGRAM_BOT_TOKEN="123:secret_fixture_token"\nTELEGRAM_CHAT_ID=1234\n')
        script=f'source {Q(str(fixture.ROOT/"lib/common.sh"))}\nset -x\nhc_load_config {Q(str(config))}\n'
        result=subprocess.run([fixture.BASH,'-c',script],text=True,capture_output=True)
        self.assertEqual(result.returncode,0); self.assertNotIn('secret_fixture_token',result.stdout+result.stderr)
    def test_config_escaping(self):
        _,_,request=self.telegram(message='quote " backslash \\ newline\nnext'); config=request.read_text(); self.assertIn('\\"',config); self.assertIn('\\\\',config); self.assertIn('\\nnext',config)
    def test_valid_application_response_required(self):
        result,_,_=self.telegram(); self.assertEqual(result.returncode,0)

    def test_actual_mock_subprocess_argv_and_tracing(self):
        config=self.work/'credentials'; config.write_text('NOTIFY_TELEGRAM=1\nTELEGRAM_BOT_TOKEN="123:subprocess_secret"\nTELEGRAM_CHAT_ID=1234\n')
        bindir=self.work/'bin'; bindir.mkdir(); curl=bindir/'curl'
        curl.write_text('#!'+shutil.which('python3.12')+'\n'+
                        'import os, sys\n'+
                        'with open(os.environ["MOCK_ARGV"],"w") as f: f.write(repr(sys.argv))\n'+
                        'request=sys.stdin.read()\n'+
                        'with open(os.environ["MOCK_INPUT"],"w") as f: f.write(request)\n'+
                        "sys.stdout.write('{\"ok\":true}'); sys.stderr.write(request)\n")
        curl.chmod(0o700)
        args=self.work/'actual.argv'; request=self.work/'actual.stdin'
        env=dict(self.env,PATH=str(bindir)+os.pathsep+self.env['PATH'],MOCK_ARGV=str(args),MOCK_INPUT=str(request))
        script=f'source {Q(str(fixture.ROOT/"lib/common.sh"))}\nsource {Q(str(fixture.ROOT/"lib/notify/telegram.sh"))}\nset -x\nhc_load_config {Q(str(config))}\nnotify_telegram hello\n'
        result=subprocess.run([fixture.BASH,'-c',script],env=env,text=True,capture_output=True)
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        self.assertNotIn('subprocess_secret',args.read_text()+result.stdout+result.stderr)
        self.assertIn('subprocess_secret',request.read_text())


class IntegrationScenarios(Fixtures):
    def test_A_intermediate_then_failure(self):
        path=self.work/'journal'; path.write_text(journal(['ClamAV update process started','Database test passed','ERROR: update failed']))
        output=self.run_shell(f'''CHECK_CLAMAV=1
_clamav_check_databases() {{ :; }}
hc_have() {{ return 0; }}
hc_check_service() {{ :; }}
journalctl() {{ cat {Q(str(path))}; }}
systemctl() {{ [ "$1" != is-failed ]; }}
check_clamav''')
        self.assertIn('UNKNOWN',output); self.assertNotIn('last successful update/check:',output)
    def test_B_recent_bytecode_stale_daily(self): self.assertIn('daily signatures are 100h old',self.db_check([('daily.cvd',100),('main.cvd',1),('bytecode.cvd',0)]))
    def test_C_unreadable_audit(self):
        output=self.run_shell('hc_data_parse() { return 1; }; _lmd_check_events')
        self.assertIn('ERROR',output); self.assertIn('counts UNKNOWN',output); self.assertNotIn('0 threat_detected',output)
    def test_D_spaced_mountpoints(self): self.assertIn('/media/disk B is 100%',self.disk(HEADER+'/dev/a 10G 1G 9G 10% /media/disk A\n/dev/b 10G 10G 0 100% /media/disk B\n'))
    def test_E_unreachable_update_policy(self):
        self.policy_setup(); text=self.policy_daily.read_text(); self.policy_daily.write_text('if false; then\n'+text+'\nfi\n')
        self.assertIn('effective update behavior UNKNOWN',self.policy())
    def test_F_indented_monitor_override(self):
        self.policy_setup(); self.policy_sysconfig.unlink()
        with self.policy_unit.open('a') as stream: stream.write('    Environment=MONITOR_MODE=users\n')
        output=self.policy(); self.assertIn('effective MONITOR_MODE differs',output); self.assertNotIn('PASS LMD effective MONITOR_MODE',output)
    def test_G_missing_monitor_with_malware(self):
        output=self.lmd_run(); self.assertIn('ERROR',output); self.assertIn('CRITICAL LMD full scan found malware',output)
    def test_H_telegram_stdin_transport(self):
        result,args,request=self.telegram(); self.assertEqual(result.returncode,0); self.assertNotIn('secret_fixture_token',args.read_text()); self.assertIn('url = "https://api.telegram.org/bot',request.read_text())
