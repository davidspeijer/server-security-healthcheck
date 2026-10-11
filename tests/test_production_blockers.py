"""PH01-PH06/PH12: offline regressions through real parsers and Bash callers."""
import gzip
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'lib/checks'))
import bounded_input as bounded
import lmd_scanner as scanner
import test_healthcheck as fixtures
Q = shlex.quote


class Base(unittest.TestCase):
    def setUp(self):
        fixtures.HealthcheckTests.setUp(self)

    def shell(self, code, now=fixtures.NOW, **environment):
        prefix = ('set -uo pipefail\nsource '+Q(str(ROOT/'lib/common.sh'))+
                  '\nHC_REGISTERED_CHECKS=(); source '+Q(str(ROOT/'lib/checks/lmd.sh'))+
                  '\nsource '+Q(str(ROOT/'lib/checks/lmd_policy.sh'))+
                  '\nLMD_DIR='+Q(str(self.lmd))+
                  '\ndate() { if [ "$*" = +%s ]; then echo '+str(now)+'; else command date "$@"; fi; }\n')
        return subprocess.run(['bash', '-c', prefix+code], env=dict(self.env, **environment),
                              text=True, capture_output=True, timeout=10)

    def checked(self, code, **kwargs):
        result = self.shell(code, **kwargs)
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertEqual(result.stderr, '', result.stderr)
        return result.stdout


class EventSnapshotTests(Base):
    success = 'Sep 20 2026 09:01:00 host maldet(1): {sigup} latest signature set already installed\n'
    failure = 'Sep 20 2026 09:01:00 host maldet(1): {sigup} validation failed\n'

    def update(self, mutation=':', content=None, environment=None):
        self.log.write_text(content if content is not None else self.success+self.failure)
        code = '''hc_data_parse() {
    python3 "$HC_DATA_PARSER" "$@" || return $?
    if [ "$1" = bounded ] && [ "$2" = '''+Q(str(self.log))+''' ]; then
        '''+mutation+'''
    fi
}
_lmd_check_signature_updater
printf 'errors=%s\\n' "$HC_ERRORS"
'''
        return self.checked(code, **(environment or {}))

    def test_stable_success_then_failure(self):
        self.assertIn('CRITICAL', self.update())

    def test_stable_failure_then_success(self):
        self.assertIn('PASS LMD signatures', self.update(content=self.failure+self.success))

    def test_delete_after_capture(self):
        output = self.update('rm -- '+Q(str(self.log)))
        self.assertIn('CRITICAL', output); self.assertNotIn('PASS LMD signatures', output)
        self.assertFalse(self.log.exists())

    def test_replace_after_capture(self):
        replacement=self.work/'replacement'; replacement.write_text(self.success)
        self.assertIn('CRITICAL', self.update('mv -- '+Q(str(replacement))+' '+Q(str(self.log))))

    def test_rotate_after_capture(self):
        self.assertIn('CRITICAL', self.update('mv -- '+Q(str(self.log))+' '+Q(str(self.log)+'.1')))

    def test_second_path_missing(self):
        self.assertIn('CRITICAL', self.update('rm -- '+Q(str(self.log))+'; test ! -e '+Q(str(self.log))))

    def test_snapshot_only_read_once(self):
        count=self.work/'reads'
        self.update('echo read >> '+Q(str(count)))
        self.assertEqual(count.read_text().splitlines(), ['read'])

    def test_capture_failure(self):
        output=self.checked('hc_data_parse() { return 1; }; _lmd_check_signature_updater')
        self.assertIn('ERROR',output); self.assertNotIn('PASS',output)

    def test_permission_failure(self):
        with mock.patch.object(bounded.os,'open',side_effect=PermissionError('denied')):
            with self.assertRaises(PermissionError): bounded.text(str(self.log))

    def test_size_budget(self):
        output=self.update(environment={'SSHC_MAX_FILE_BYTES':'10'})
        self.assertIn('ERROR',output); self.assertNotIn('PASS',output)

    def test_record_budget(self):
        output=self.update(environment={'SSHC_MAX_RECORD_BYTES':'10'})
        self.assertIn('ERROR',output); self.assertNotIn('PASS',output)

    def test_program_updater_snapshot(self):
        self.log.write_text('Sep 20 2026 09:01:00 h maldet(1): {update} completed update\n'
                            'Sep 20 2026 09:01:00 h maldet(1): {update} validation failed\n')
        code='hc_data_parse() { python3 "$HC_DATA_PARSER" "$@" || return $?; if [ "$1" = bounded ]; then rm -- '+Q(str(self.log))+'; fi; }; LMD_PROGRAM_UPDATE_EXPECTED=enabled; _lmd_check_program_updater'
        self.assertIn('recent failure without later success',self.checked(code))

    def test_tie_parser_failure_is_unresolved(self):
        self.log.write_text(self.success+self.failure)
        self.assertIn('unresolved',self.checked('awk() { return 2; }; _lmd_failure_unresolved '+Q(str(self.log))+' sigup success failure 1 1 && echo unresolved'))


class HookTests(Base):
    def setUp(self):
        super().setUp()
        fixtures.HealthcheckTests.policy_setup(self)
        self.hook=self.lmd/'cron/custom.cron'

    def policy(self, **environment):
        return self.checked(self.policy_prefix+'\n_lmd_check_configuration', **environment)

    def test_regular_commands(self):
        self.hook.write_text('maldet -d\n')
        self.assertIn('custom.cron contains commands',self.policy())

    def test_comment_only(self):
        self.hook.write_text('# comment\n\n')
        self.assertNotIn('custom.cron contains commands',self.policy())

    def test_fifo(self):
        os.mkfifo(str(self.hook))
        self.assertIn('ERROR LMD daily custom.cron input UNKNOWN',self.policy(SSHC_READ_SECONDS='1'))

    def test_symlink_fifo(self):
        target=self.work/'pipe'; os.mkfifo(str(target)); self.hook.symlink_to(target)
        self.assertIn('ERROR LMD daily custom.cron input UNKNOWN',self.policy(SSHC_READ_SECONDS='1'))

    def test_dangling_symlink(self):
        self.hook.symlink_to(self.work/'absent')
        self.assertIn('ERROR LMD daily custom.cron input UNKNOWN',self.policy())

    def test_oversized_hook(self):
        self.hook.write_text('#'+'x'*70000)
        self.assertIn('ERROR LMD daily custom.cron input UNKNOWN',self.policy())

    def test_classifier_failure(self):
        self.hook.write_text('maldet -d\n')
        code=self.policy_prefix+"\ngrep() { if [ \"$1\" = -Eq ] && [ \"$2\" = '^[[:space:]]*[^#[:space:]]' ]; then return 2; fi; command grep \"$@\"; }; _lmd_check_configuration"
        self.assertIn('ERROR LMD daily custom.cron classification failed',self.checked(code))


class ScannerSnapshotTests(Base):
    def setUp(self):
        super().setUp()
        self.logs=self.lmd/'logs'; self.meta=self.lmd/'sess'
        self.block='Sep 20 2026 08:00:00 h clamscan start\nSep 20 2026 08:00:01 h executed: /usr/bin/clamscan -f /tmp/files\nSep 20 2026 08:00:02 h clamscan end return 0\n'
        # Direct imports use the process timezone; preserve it around each test.
        self.old_tz=os.environ.get('TZ'); os.environ['TZ']='Europe/Amsterdam'; time.tzset()
        self.addCleanup(self.restore_tz)
        self.start=scanner.local_epoch('Sep 20 2026 08:00:00'); self.end=self.start+2
        self.active=self.logs/'clamscan_log'; self.rotation=self.logs/'clamscan_log.1'
        self.active.write_text(self.block); self.rotation.write_text(self.block)
        self.scan.write_text('started='+str(self.start)+'\ncompleted='+str(self.end)+'\nstate=completed\n')

    def restore_tz(self):
        if self.old_tz is None: os.environ.pop('TZ',None)
        else: os.environ['TZ']=self.old_tz
        time.tzset()

    def unknown(self, snapshot):
        with self.assertRaises(ValueError):
            scanner.result(str(self.logs),self.start,self.end,str(self.meta),snapshot)

    def mutate(self, operation):
        snapshot=scanner.capture(str(self.logs),str(self.meta))
        self.unknown(snapshot); operation(); self.unknown(snapshot)
        return snapshot

    def test_stable_duplicate_blocks(self): self.unknown(scanner.capture(str(self.logs),str(self.meta)))
    def test_removed(self): self.mutate(self.rotation.unlink)
    def test_added(self): self.mutate(lambda: (self.logs/'clamscan_log.2').write_text(self.block))
    def test_renamed(self): self.mutate(lambda: self.rotation.rename(self.logs/'clamscan_log.2'))
    def test_replaced(self): self.mutate(lambda: self.rotation.write_text('new unrelated data\n'))

    def test_symlink_target_changed(self):
        target=self.work/'target'; target.write_text(self.block); self.rotation.unlink(); self.rotation.symlink_to(target)
        self.mutate(lambda: target.write_text('new data\n'))

    def test_gzip_removed(self):
        self.rotation.unlink(); self.rotation=self.logs/'clamscan_log.1.gz'
        with gzip.open(str(self.rotation),'wt') as out: out.write(self.block)
        self.mutate(self.rotation.unlink)

    def test_batch_identical_after_capture_mutation(self):
        original=scanner.result
        def mutate(*args):
            self.rotation.unlink(missing_ok=True)
            return original(*args)
        before=scanner.batch(str(self.logs),str(self.meta),str(self.meta))
        with mock.patch.object(scanner,'result',side_effect=mutate):
            after=scanner.batch(str(self.logs),str(self.meta),str(self.meta))
        self.assertEqual(before,after); self.assertEqual(after[0][1],'unknown')

    def test_stable_individual_batch_equivalence(self):
        self.rotation.unlink()
        self.assertEqual(scanner.result(str(self.logs),self.start,self.end,str(self.meta)),scanner.batch(str(self.logs),str(self.meta),str(self.meta))[0][1:])

    def test_missing_during_capture(self):
        original=scanner.lines
        def read(path,*args):
            if path == str(self.rotation): self.rotation.unlink()
            return original(path,*args)
        with mock.patch.object(scanner,'lines',side_effect=read):
            with self.assertRaises(OSError): scanner.capture(str(self.logs),str(self.meta))

    def test_added_during_capture(self):
        original=scanner.lines
        def read(path,*args):
            if path == str(self.active): (self.logs/'clamscan_log.2').write_text('new\n')
            return original(path,*args)
        with mock.patch.object(scanner,'lines',side_effect=read):
            with self.assertRaisesRegex(ValueError,'inventory changed'): scanner.capture(str(self.logs),str(self.meta))

    def test_replaced_during_capture(self):
        original=scanner.lines
        def read(path,*args):
            if path == str(self.rotation): self.rotation.write_text('replacement\n')
            return original(path,*args)
        with mock.patch.object(scanner,'lines',side_effect=read):
            with self.assertRaisesRegex(ValueError,'changed'): scanner.capture(str(self.logs),str(self.meta))

    def test_malformed_gzip_capture(self):
        (self.logs/'clamscan_log.2.gz').write_bytes(b'bad gzip')
        with self.assertRaises(OSError): scanner.capture(str(self.logs),str(self.meta))

    def test_missing_inventory(self):
        self.rotation.unlink(); self.active.unlink()
        with self.assertRaisesRegex(ValueError,'missing'): scanner.capture(str(self.logs),str(self.meta))

    def test_incomplete_rotation_gap(self):
        self.rotation.unlink(); (self.logs/'clamscan_log.2').write_text(self.block.splitlines(True)[0])
        self.active.write_text(''.join(self.block.splitlines(True)[1:]))
        with self.assertRaises(ValueError): scanner.result(str(self.logs),self.start,self.end,str(self.meta))

    def test_classification_never_reopens_snapshot_sources(self):
        self.rotation.unlink()
        snapshot=scanner.capture(str(self.logs),str(self.meta))
        with mock.patch.object(Path,'glob',side_effect=AssertionError('live glob')), mock.patch.object(scanner,'lines',side_effect=AssertionError('live read')):
            self.assertEqual(scanner.result(str(self.logs),self.start,self.end,str(self.meta),snapshot)[0],'clean')

    def test_one_gzip_open_per_batch(self):
        self.rotation.unlink()
        with gzip.open(str(self.logs/'clamscan_log.1.gz'),'wt') as out: out.write('old diagnostic\n')
        with mock.patch.object(scanner,'lines',wraps=scanner.lines) as reads:
            scanner.batch(str(self.logs),str(self.meta),str(self.meta))
        self.assertEqual(sum('.gz' in call.args[0] for call in reads.call_args_list),1)
        self.assertEqual(sum('clamscan_log' in call.args[0] for call in reads.call_args_list),2)


class UnitOperandTests(Base):
    def operand(self, unit, operation='is-active', status=0):
        capture=self.work/'args'
        code='systemctl() { printf "%s\\n" "$@" > '+Q(str(capture))+'; return '+str(status)+'; }; hc_systemctl '+Q(operation)+' '+Q(unit)+' --quiet'
        result=self.shell(code)
        return result, capture

    def test_normal(self):
        result,capture=self.operand('clamd@scan.service')
        self.assertEqual(result.returncode,0); self.assertEqual(capture.read_text().splitlines(),['is-active','--quiet','--','clamd@scan.service'])
    def test_template(self): self.assertEqual(self.operand('clamd@.service')[0].returncode,0)
    def test_service(self): self.assertEqual(self.operand('clamav-freshclam.service')[0].returncode,0)
    def test_escaped(self): self.assertEqual(self.operand(r'unit\x2dname.service')[0].returncode,0)
    def test_version(self): self.assertFalse(self.operand('--version')[1].exists())
    def test_help(self): self.assertFalse(self.operand('--help')[1].exists())
    def test_short_option(self): self.assertFalse(self.operand('-x')[1].exists())
    def test_space(self): self.assertFalse(self.operand('two names.service')[1].exists())
    def test_control(self): self.assertFalse(self.operand('name\n.service')[1].exists())
    def test_command_failure(self): self.assertEqual(self.operand('missing.service',status=4)[0].returncode,4)

    def test_subcommands(self):
        for operation in ['cat','is-active','is-enabled','is-failed','show','status','list-unit-files']:
            with self.subTest(operation=operation):
                result,capture=self.operand('good.service',operation)
                self.assertEqual(result.returncode,0); self.assertEqual(capture.read_text().splitlines()[-2:],['--','good.service'])

    def clamav(self, service, missing=False):
        code='source '+Q(str(ROOT/'lib/checks/clamav.sh'))+'\nCHECK_CLAMAV=1; FRESHCLAM_SERVICE='+Q(service)+''';
hc_have() { return 0; }; _clamav_check_databases() { :; }; _clamav_last_success_epoch() { echo '''+str(fixtures.NOW-60)+'''; };
systemctl() {
    case "${@: -1}" in
        clamd@scan) return 0;;
        clamav-freshclam-once.timer) return 1;;
        good.service) return '''+('1' if missing else '0')+''';;
        *) printf 'systemd version fixture'; return 0;;
    esac
}
check_clamav'''
        return self.checked(code)

    def test_freshclam_version_probe(self):
        output=self.clamav('--version'); self.assertIn('ERROR',output); self.assertNotIn('daemon: active',output)
    def test_freshclam_normal(self): self.assertIn('daemon: active',self.clamav('good.service'))
    def test_freshclam_missing(self): self.assertIn('no enabled automatic updater',self.clamav('good.service',True))


class RawUnitTests(Base):
    def unit(self, field='Environment', nul='\x00', **environment):
        expected=str(self.lmd/'directadmin-webroots')
        body='[Service]\nEnvironment="MONITOR_MODE='+expected+'"\nExecStart="'+str(self.lmd)+'/maldet" --monitor ${MONITOR_MODE}\n'
        if field == 'Environment': body=body.replace(expected,expected+nul)
        elif field == 'EnvironmentFile': body+='EnvironmentFile=-/fixture'+nul+'\n'
        elif field == 'ExecStart': body=body.replace('/maldet"','/mal'+nul+'det"')
        elif field == 'path': body=body.replace(str(self.lmd),str(self.lmd)+nul)
        elif field == 'trailing': body+=nul
        elif field == 'oversized': body+='x'*70000
        elif field == 'invalid': body+='\udcff'
        elif field == 'unicode': body+='# 中文 🙂\n'
        source=self.work/'raw unit'; source.write_bytes(body.encode('utf-8','surrogateescape'))
        code='systemctl() { command cat '+Q(str(source))+'; }; _lmd_check_monitor_config '+Q(str(self.work/'sysconfig'))+' '+Q(str(self.work/'default'))+' '+Q(expected)
        result=self.shell(code,**environment)
        self.assertEqual(result.stderr,'',result.stderr)
        return result.stdout

    def reject(self, **kwargs):
        output=self.unit(**kwargs); self.assertIn('unknown',output.lower()); self.assertNotIn('PASS LMD effective',output)
    def test_environment(self): self.reject()
    def test_environment_file(self): self.reject(field='EnvironmentFile')
    def test_execstart(self): self.reject(field='ExecStart')
    def test_path(self): self.reject(field='path')
    def test_monitor_target(self): self.reject(field='Environment')
    def test_trailing(self): self.reject(field='trailing')
    def test_embedded(self): self.reject(nul='a\x00b')
    def test_multiple(self): self.reject(nul='\x00\x00\x00')
    def test_oversized(self): self.reject(field='oversized')
    def test_invalid_utf8(self): self.reject(field='invalid')
    def test_valid_utf8(self): self.assertIn('PASS LMD effective',self.unit(field='unicode',nul=''))

    def test_stdin_file_nul_consistent(self):
        path=self.work/'nul'; path.write_bytes(b'a\x00b\n')
        with self.assertRaises(ValueError): bounded.text(str(path))
        result=subprocess.run(['python3',str(ROOT/'lib/checks/health_data.py'),'monitor',str(self.lmd),'x','y'],input=b'a\x00b\n',capture_output=True,env=self.env)
        self.assertNotEqual(result.returncode,0); self.assertNotIn(b'ignored null byte',result.stderr)

    def test_clam_config_nul(self):
        source=self.work/'clam unit'; source.write_bytes(b'[Service]\nExecStart=/usr/sbin/clamd -c /tmp/clam\x00.conf\n')
        output=self.checked('source '+Q(str(ROOT/'lib/checks/clamav.sh'))+'\nsystemctl() { command cat '+Q(str(source))+'; }; _clamav_check_databases')
        self.assertIn('ERROR',output)

    def test_unitname_config_nul(self):
        config=self.work/'config'; config.mkdir(); (config/'healthcheck.conf').write_bytes(b'LMD_SERVICE=maldet\x00.service\n')
        result=subprocess.run(['bash',str(ROOT/'bin/server-security-healthcheck')],env=dict(self.env,SSHC_CONFIG_DIR=str(config),SSHC_LIB_DIR=str(ROOT/'lib')),text=True,capture_output=True)
        self.assertEqual(result.returncode,2); self.assertNotIn('ignored null byte',result.stderr)


class BackendTests(Base):
    main=fixtures.HealthcheckTests.main

    def setUp(self):
        super().setUp()
        self.library=self.work/'library'; shutil.copytree(ROOT/'lib',self.library)
        self.backend=self.library/'notify/telegram.sh'
        self.marker=self.work/'sent'
        with (self.library/'checks/disk.sh').open('a') as out:
            out.write("\ndf() { echo 'Filesystem Size Used Avail Use% Mounted on'; echo '/dev/fixture 100G 95G 5G 95% /'; }\n")
        with (self.library/'common.sh').open('a') as out:
            out.write('\ndate() { if [ "$*" = +%s ]; then echo '+str(fixtures.NOW)+'; else command date "$@"; fi; }\n')
        with self.backend.open('a') as out:
            out.write('\ncurl() { cat >/dev/null; echo sent >> '+Q(str(self.marker))+'''; printf '%s' '{"ok":true}'; }\n''')
        self.config='NOTIFY_TELEGRAM=1\nTELEGRAM_BOT_TOKEN=123:fixture_secret\nTELEGRAM_CHAT_ID=123\n'

    def run_main(self, findings=True, extra='', args=()):
        return self.main(self.config+('CHECK_DISK=1\n' if findings else '')+extra,args=args,lib_dir=self.library)

    def failed(self, **kwargs):
        result=self.run_main(**kwargs)
        self.assertEqual(result.returncode,2,result.stdout+result.stderr)
        self.assertIn('ERROR',result.stdout+result.stderr)
        self.assertNotIn('fixture_secret',result.stdout+result.stderr)
        return result

    def test_present_sends(self):
        result=self.run_main(); self.assertEqual(result.returncode,1,result.stdout+result.stderr); self.assertTrue(self.marker.exists())
    def test_missing(self):
        self.backend.unlink(); self.failed()
    def test_unreadable(self):
        # Root ignores chmod read restrictions. Model only the access-test boundary.
        with (self.library/'common.sh').open('a') as out:
            out.write('\n[() { if [[ "$1" = ! && "${2:-}" = -r && "${3:-}" = '+Q(str(self.backend))+' ]]; then return 0; fi; builtin [ "$@"; }\n')
        self.failed()
    def test_syntax(self):
        self.backend.write_text('notify_telegram() {\n'); self.failed()
    def test_source_nonzero(self):
        with self.backend.open('a') as out: out.write('\nreturn 7\n')
        self.failed(); self.assertFalse(self.marker.exists())
    def test_function_missing(self):
        self.backend.write_text('notify_test() { :; }\n'); self.failed()
    def test_test_function_missing(self):
        self.backend.write_text('notify_telegram() { :; }\n'); self.failed()
    def test_wrong_origin(self):
        other=self.work/'other.sh'; other.write_text('notify_telegram() { :; }; notify_test() { :; }\n')
        self.backend.write_text('source '+Q(str(other))+'\n'); self.failed()
    def test_fifo(self):
        self.backend.unlink(); os.mkfifo(str(self.backend)); self.failed()
    def test_symlink_fifo(self):
        self.backend.unlink(); pipe=self.work/'pipe'; os.mkfifo(str(pipe)); self.backend.symlink_to(pipe); self.failed()
    def test_disabled_missing(self):
        self.backend.unlink(); result=self.run_main(findings=False,extra='NOTIFY_TELEGRAM=0\n'); self.assertEqual(result.returncode,0,result.stdout+result.stderr)
    def test_disabled_invalid(self):
        self.backend.write_text('invalid ('); result=self.run_main(findings=False,extra='NOTIFY_TELEGRAM=0\n'); self.assertEqual(result.returncode,0,result.stdout+result.stderr)
    def test_warning_preserved(self):
        self.backend.unlink(); result=self.failed(); self.assertIn('95%',result.stdout)
    def test_healthy_missing(self):
        self.backend.unlink(); self.failed(findings=False)
    def test_test_mode_required_even_disabled(self):
        self.backend.unlink(); self.failed(findings=False,extra='NOTIFY_TELEGRAM=0\n',args=('--test-notification',))
    def test_healthy_present_no_send(self):
        result=self.run_main(findings=False); self.assertEqual(result.returncode,0,result.stdout+result.stderr); self.assertFalse(self.marker.exists())
    def test_function_provenance_spaces(self):
        result=self.run_main(findings=False,args=('--test-notification',)); self.assertEqual(result.returncode,0,result.stdout+result.stderr)

    def test_function_replaced_during_check(self):
        registry=self.library/'checks.registry'
        registry.write_text(registry.read_text()+'override|checks/override.sh|check_override|CHECK_OVERRIDE|1|custom|-\n')
        (self.library/'checks/override.sh').write_text('hc_register_check override\ncheck_override() { notify_telegram() { :; }; }\n')
        self.failed(); self.assertFalse(self.marker.exists())

    def test_malware_and_warning_preserved(self):
        self.backend.unlink(); fixtures.HealthcheckTests.append_meta(self,hits=1)
        shutil.copyfile(fixtures.FIXTURES/'session.malware.tsv',self.session)
        extra='CHECK_LMD=1\nLMD_DIR='+Q(str(self.lmd))+'\nLMD_AUDIT='+Q(str(self.work/'empty audit'))+'\nLMD_MONITOR_REQUIRED=0\nLMD_CONFIG_CHECK_ENABLED=0\n'
        result=self.failed(extra=extra)
        self.assertIn('CRITICAL LMD full scan found malware',result.stdout); self.assertIn('95%',result.stdout)


class HelperFailureTests(Base):
    main=fixtures.HealthcheckTests.main

    def setUp(self):
        super().setUp()
        self.library=self.work/'library'; shutil.copytree(ROOT/'lib',self.library)
        fixtures.ScannerReliabilityTests.prepare(self)
        self.config='LMD_EXPECT_QUARANTINE_ENABLED=1\nCHECK_LMD=1\nLMD_DIR='+Q(str(self.lmd))+'\nLMD_AUDIT='+Q(str(self.work/'empty audit'))+'\nLMD_MONITOR_REQUIRED=0\nLMD_CONFIG_CHECK_ENABLED=0\n'

    append_meta=fixtures.HealthcheckTests.append_meta
    stamp=fixtures.ScannerReliabilityTests.stamp
    block=fixtures.ScannerReliabilityTests.block

    def execute(self, operation='', malware=False, extra_scan=False):
        if malware:
            self.append_meta(hits=1); shutil.copyfile(fixtures.FIXTURES/'session.malware.tsv',self.session)
        if extra_scan:
            (self.lmd/'sess/scan.meta.second').write_text(self.scan.read_text().replace(str(fixtures.NOW-3600),str(fixtures.NOW-7200)).replace(str(fixtures.NOW-1800),str(fixtures.NOW-5400)))
        with (self.library/'common.sh').open('a') as out:
            out.write('\ndate() { if [ "$*" = +%s ]; then echo '+str(fixtures.NOW)+'; else command date "$@"; fi; }\n')
            if operation:
                out.write('\npython3() { if [ "$1" = "${LMD_SCANNER_PARSER:-}" ]; then '+operation+'; else command python3 "$@"; fi; }\n')
        return self.main(self.config,lib_dir=self.library)

    def failed(self, operation, **kwargs):
        result=self.execute(operation,**kwargs)
        self.assertEqual(result.returncode,2,result.stdout+result.stderr)
        self.assertIn('ERROR LMD scanner',result.stdout); self.assertNotIn('PASS LMD full scan: no hits',result.stdout)
        return result

    def test_clean_zero(self):
        result=self.execute(); self.assertEqual(result.returncode,0,result.stdout+result.stderr)
    def test_semantic_unknown_zero(self):
        (self.lmd/'logs/clamscan_log').write_text('malformed evidence\n')
        result=self.execute(); self.assertEqual(result.returncode,1,result.stdout+result.stderr); self.assertIn('CRITICAL LMD scanner result UNKNOWN',result.stdout)
    def test_exit_7(self): self.failed('return 7')
    def test_exit_127(self): self.failed('return 127')
    def test_signal(self): self.failed("command python3 -c 'import os,signal; os.kill(os.getpid(),signal.SIGTERM)'")
    def test_exception(self): self.failed("command python3 -c 'raise RuntimeError(\"fixture crash\")'")
    def test_malformed(self): self.failed("printf '%s\\n' garbage")
    def test_empty(self): self.failed(':')
    def test_partial(self): self.failed("printf '%s\\n' '1:2\tclean\t0\t0\t0\t0'",extra_scan=True)
    def test_multiple_scans(self):
        result=self.failed('return 7',extra_scan=True); self.assertEqual(result.stdout.count('batch helper execution failed'),1)
    def test_malware_preserved(self): self.assertIn('CRITICAL LMD full scan found malware',self.failed('return 7',malware=True).stdout)
    def test_bad_clean_protocol(self): self.failed("printf '%s\\n' '1:2\tclean\t-\t0\t0\t0'")
    def test_duplicate_rows(self): self.failed("printf '%s\\n' '1:2\tclean\t0\t0\t0\t0' '1:2\tclean\t0\t0\t0\t0'")


class DstTests(Base):
    now=1792902600  # 2026-10-25 02:30 UTC, after both repeated hours.

    def epoch(self, value, success=True):
        result=self.shell('hc_data_parse event-epoch '+Q(value)+' '+str(self.now),now=self.now)
        if success: self.assertEqual(result.returncode,0,result.stderr)
        else: self.assertNotEqual(result.returncode,0,result.stdout)
        return result.stdout.strip()

    def test_winter(self): self.epoch('Jan 25 2026 02:15:00')
    def test_summer(self): self.epoch('Jul 25 2026 02:15:00')
    def test_fold_early_clock(self): self.epoch('Oct 25 2026 02:15:00',False)
    def test_fold_late_clock(self): self.epoch('Oct 25 2026 02:45:00',False)
    def test_spring_nonexistent(self): self.epoch('Mar 29 2026 02:15:00',False)
    def test_before_fall(self): self.epoch('Oct 25 2026 01:59:59')
    def test_after_fall(self): self.epoch('Oct 25 2026 03:00:00')
    def test_before_spring(self): self.epoch('Mar 29 2026 01:59:59')
    def test_after_spring(self): self.epoch('Mar 29 2026 03:00:00')
    def test_explicit_summer(self): self.epoch('2026-10-25T02:45:00+02:00')
    def test_explicit_winter(self): self.epoch('2026-10-25T02:15:00+01:00')
    def test_same_clock_different_offsets(self):
        self.assertEqual(int(self.epoch('2026-10-25T02:15:00+01:00'))-int(self.epoch('2026-10-25T02:15:00+02:00')),3600)
    def test_future(self): self.epoch('Oct 26 2026 02:00:00',False)
    def test_iso_local_fold(self): self.epoch('2026-10-25 02:15:00',False)

    def updates(self, success, failure, order='success-first'):
        good=success+' h maldet(1): {sigup} latest signature set already installed\n'
        bad=failure+' h maldet(1): {sigup} validation failed\n'
        self.log.write_text(good+bad if order=='success-first' else bad+good)
        return self.checked('_lmd_check_signature_updater',now=self.now)

    def test_audit_probe_success_then_failure_fold(self):
        output=self.updates('Oct 25 2026 02:45:00','Oct 25 2026 02:15:00'); self.assertIn('UNKNOWN',output); self.assertNotIn('PASS',output)
    def test_failure_then_success_fold(self):
        output=self.updates('Oct 25 2026 02:15:00','Oct 25 2026 02:45:00',order='failure-first'); self.assertIn('UNKNOWN',output); self.assertNotIn('PASS',output)
    def test_explicit_actual_order(self):
        self.assertIn('CRITICAL',self.updates('2026-10-25T02:45:00+02:00','2026-10-25T02:15:00+01:00'))
    def test_same_second_failure_last(self):
        self.assertIn('CRITICAL',self.updates('2026-10-25T03:10:00+01:00','2026-10-25T03:10:00+01:00'))
    def test_same_second_success_last(self):
        self.assertIn('PASS',self.updates('2026-10-25T03:10:00+01:00','2026-10-25T03:10:00+01:00',order='failure-first'))
    def test_shared_scanner_resolver(self):
        old=os.environ.get('TZ'); os.environ['TZ']='Europe/Amsterdam'; time.tzset()
        try:
            with self.assertRaises(ValueError): scanner.local_epoch('Oct 25 2026 02:15:00')
        finally:
            if old is None: os.environ.pop('TZ',None)
            else: os.environ['TZ']=old
            time.tzset()


class RecoveryRaceTests(Base):
    append_meta=fixtures.HealthcheckTests.append_meta
    stamp=fixtures.ScannerReliabilityTests.stamp
    block=fixtures.ScannerReliabilityTests.block
    prepare=fixtures.ScannerReliabilityTests.prepare
    newer=fixtures.ScannerReliabilityTests.newer

    def prepare_history(self):
        from test_audit_regressions import HistoricalRecoveryTests
        HistoricalRecoveryTests.old_malware(self)
        self.newer()
        self.rotation=self.lmd/'logs/clamscan_log.1'
        self.rotation.write_text(self.block(fixtures.NOW-60,fixtures.NOW-1))

    def run_history(self, mutate=False):
        self.prepare_history()
        code='LMD_EXPECT_QUARANTINE_ENABLED=1; '
        if mutate:
            script='import sys;sys.path.insert(0,sys.argv[1]);import lmd_scanner as s;from pathlib import Path; original=s.result\ndef classify(*args):\n Path(sys.argv[2]).unlink(missing_ok=True)\n return original(*args)\ns.result=classify\nfor row in s.batch(*sys.argv[3:6]): print("\\t".join(map(str,row)))'
            code+='python3() { if [ "$1" = "${LMD_SCANNER_PARSER:-}" ]; then shift 2; command python3.12 -c '+Q(script)+' '+Q(str(ROOT/'lib/checks'))+' '+Q(str(self.rotation))+' "$@"; else command python3 "$@"; fi; }; '
        return self.checked(code+'_lmd_check_fullscan')

    def test_old_malware_ambiguous_new_scan(self):
        output=self.run_history(); self.assertIn('CRITICAL LMD full scan found malware',output); self.assertNotIn('PASS LMD weekly full scan',output)
    def test_old_malware_rotation_removed_after_capture(self):
        output=self.run_history(True); self.assertFalse(self.rotation.exists()); self.assertIn('CRITICAL LMD full scan found malware',output); self.assertIn('scanner result UNKNOWN',output); self.assertNotIn('PASS LMD weekly full scan',output)

    def test_partial_batch_cannot_demote_older_malware(self):
        self.prepare_history()
        row=str(fixtures.NOW-60)+':'+str(fixtures.NOW-1)+'\tclean\t0\t0\t0\t0'
        code='LMD_EXPECT_QUARANTINE_ENABLED=1; python3() { if [ "$1" = "${LMD_SCANNER_PARSER:-}" ]; then printf \"%s\\n\" '+Q(row)+'; else command python3 "$@"; fi; }; _lmd_check_fullscan'
        output=self.checked(code)
        self.assertIn('ERROR LMD scanner batch helper output incomplete',output)
        self.assertIn('CRITICAL LMD full scan found malware',output)
        self.assertNotIn('PASS LMD weekly full scan',output)
