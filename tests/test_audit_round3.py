"""Offline F15-F22: real parsers, isolated installers, no host service commands."""
import gzip
import importlib.util
import json
import os
from pathlib import Path
import shlex
import shutil
import socket
import subprocess
import sys
import tempfile
import re
import time
import unittest
from unittest import mock
from isolation import isolated_env

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'lib/checks'))
import bounded_input as bounded
import lmd_scanner as scanner
import health_data as data
import test_healthcheck as fixture
Q = shlex.quote


class Base(unittest.TestCase):
    def setUp(self):
        (ROOT/'tmp').mkdir(exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=ROOT/'tmp', prefix='round3-')
        self.addCleanup(self.temp.cleanup)
        self.work = Path(self.temp.name)
        self.env = isolated_env(self.work)

    def shell(self, code):
        return subprocess.run(['bash', '-c', 'set -uo pipefail\nsource '+Q(str(ROOT/'lib/common.sh'))+'\n'+code], env=self.env, text=True, capture_output=True, timeout=15)

    def scan_log(self, directory=None, error=False, second=False):
        directory = directory or self.work
        directory.mkdir(exist_ok=True)
        minute = '01' if second else '00'
        stamp = 'Sep 20 2026 08:'+minute+':'
        text = stamp+'00 host clamscan start\n'+stamp+'01 host executed: /usr/bin/clamscan --infected -f /tmp/files\n'
        if error:
            text += "ERROR: Can't access file /tmp/gone\n"
        text += stamp+'02 host clamscan end return '+('2' if error else '0')+'\n'
        start = scanner.local_epoch(stamp+'00')
        return text, start, start+2


class ResourceTests(Base):
    def read(self, value='normal\n', **limits):
        path = self.work/'input'
        path.write_text(value)
        with mock.patch.dict(os.environ, {'SSHC_'+key:str(value) for key,value in limits.items()}):
            return list(bounded.lines(str(path)))
    def test_regular(self): self.assertEqual(self.read(), ['normal\n'])
    def test_fifo(self):
        path=self.work/'fifo'; os.mkfifo(str(path))
        with self.assertRaises(ValueError): list(bounded.lines(str(path)))
    def test_socket(self):
        sock=socket.socket(socket.AF_UNIX); self.addCleanup(sock.close)
        path=self.work/'socket'; 
        try: sock.bind(str(path))
        except PermissionError: self.skipTest('sandbox forbids Unix socket bind')
        with self.assertRaises(ValueError): list(bounded.lines(str(path)))
    def test_symlink_regular(self):
        path=self.work/'file'; path.write_text('ok\n'); link=self.work/'link'; link.symlink_to(path)
        self.assertEqual(list(bounded.lines(str(link))), ['ok\n'])
    def test_symlink_fifo(self):
        path=self.work/'fifo'; os.mkfifo(str(path)); link=self.work/'link'; link.symlink_to(path)
        with self.assertRaises(ValueError): list(bounded.lines(str(link)))
    def test_oversize(self):
        with self.assertRaises(ValueError): self.read('x'*30, MAX_FILE_BYTES=20)
    def test_long_record(self):
        with self.assertRaises(ValueError): self.read('x'*30, MAX_RECORD_BYTES=20)
    def gzip_read(self, value, budget=10000):
        path=self.work/'input.gz'
        with gzip.open(str(path),'wb') as output: output.write(value)
        with mock.patch.dict(os.environ, SSHC_MAX_EXPANDED_BYTES=str(budget)):
            return list(bounded.lines(str(path)))
    def test_gzip_valid(self): self.assertEqual(self.gzip_read(b'valid\n'), ['valid\n'])
    def test_gzip_expansion(self):
        with self.assertRaises(ValueError): self.gzip_read(b'x\n'*30,20)
    def test_gzip_corrupt(self):
        path=self.work/'input.gz'; path.write_bytes(b'not gzip')
        with self.assertRaises(OSError): list(bounded.lines(str(path)))
    def test_gzip_empty(self): self.assertEqual(self.gzip_read(b''), [])
    def test_many_records(self):
        with self.assertRaises(ValueError): self.read('x\n'*30, MAX_RECORDS=20)
    def test_no_pass(self):
        text,start,end=self.scan_log(); (self.work/'clamscan_log').write_text(text)
        env=dict(self.env, SSHC_MAX_FILE_BYTES='10')
        result=subprocess.run(['python3',str(ROOT/'lib/checks/lmd_scanner.py'),str(self.work),str(start),str(end)],env=env,text=True,capture_output=True,timeout=3)
        self.assertTrue(result.stdout.startswith('unknown\t')); self.assertNotIn('clean',result.stdout)
    def test_python36(self):
        interpreter = shutil.which('python3.6') or shutil.which('python3')
        if not interpreter: self.skipTest('Python 3.6 unavailable')
        version=subprocess.run([interpreter,'-c','import sys; print("%s.%s" % sys.version_info[:2])'],capture_output=True,text=True,env=self.env)
        if version.returncode != 0 or version.stdout.strip() != '3.6':
            self.skipTest('Available interpreter is not Python 3.6')
        result=subprocess.run([interpreter,'-c','import sys; assert sys.version_info[:2] == (3,6); sys.path.insert(0,sys.argv[1]); import bounded_input, health_data, lmd_scanner',str(ROOT/'lib/checks')],capture_output=True,text=True,env=self.env)
        self.assertEqual(result.returncode,0,result.stderr)
    def test_device(self):
        with self.assertRaises(ValueError): list(bounded.lines('/dev/null'))
    def test_snapshot_fifo(self):
        source=self.work/'source'; source.mkdir(); dest=self.work/'dest'; dest.mkdir(); os.mkfifo(str(source/'session.index'))
        with self.assertRaises(ValueError): bounded.snapshot(str(source),str(dest))
    def test_timeout(self):
        path=self.work/'file'; path.write_text('x\nx\n')
        with mock.patch('bounded_input.time.monotonic',side_effect=[0,30]):
            with self.assertRaises(ValueError): list(bounded.lines(str(path)))
    def test_nul_scanner_unknown(self):
        text,start,end=self.scan_log(); (self.work/'clamscan_log').write_text(text.replace('/tmp/files','/tmp/fi\x00les'))
        with self.assertRaises(ValueError): scanner.result(str(self.work),start,end)
    def test_nul_is_data(self): self.assertEqual(self.read('evil\x00value\n'), ['evil\x00value\n'])


class BatchTests(Base):
    def setup_logs(self):
        logs=self.work/'logs'; logs.mkdir(); meta=self.work/'sess'; meta.mkdir()
        text,start,end=self.scan_log(logs)
        other,start2,end2=self.scan_log(logs,error=True,second=True)
        with gzip.open(str(logs/'clamscan_log.1.gz'),'wt') as out: out.write(text)
        (logs/'clamscan_log').write_text(other)
        for number,lo,hi in [(1,start,end),(2,start2,end2)]:
            (meta/('scan.meta.'+str(number))).write_text('started='+str(lo)+'\ncompleted='+str(hi)+'\nstate=completed\n')
        return logs,meta,[(start,end),(start2,end2)]
    def test_time_budget_aborts_batch(self):
        logs,meta,intervals=self.setup_logs()
        with mock.patch.object(scanner,'result',side_effect=bounded.BudgetExceeded('time')) as classify:
            with self.assertRaises(bounded.BudgetExceeded): scanner.batch(str(logs),str(meta),str(meta))
        self.assertEqual(classify.call_count,1)
    def test_shared_logs(self):
        logs,meta,intervals=self.setup_logs(); self.assertEqual(len(scanner.batch(str(logs),str(meta),str(meta))),2)
    def test_once_gzip(self):
        logs,meta,intervals=self.setup_logs()
        with mock.patch.object(scanner,'lines',wraps=scanner.lines) as reads:
            scanner.batch(str(logs),str(meta),str(meta))
        self.assertEqual(sum(call.args[0].endswith('.gz') for call in reads.call_args_list),1)
    def test_matches_individual(self):
        logs,meta,intervals=self.setup_logs()
        expected=[scanner.result(str(logs),lo,hi,str(meta)) for lo,hi in intervals]
        self.assertEqual([row[1:] for row in scanner.batch(str(logs),str(meta),str(meta))],expected)
    def test_clean_access(self):
        logs,meta,intervals=self.setup_logs(); self.assertEqual([row[1] for row in scanner.batch(str(logs),str(meta),str(meta))],['clean','access_errors'])
    def test_old_corrupt_calendar(self):
        logs,meta,intervals=self.setup_logs()
        with gzip.open(str(logs/'clamscan_log.1.gz'),'rt') as f: old=f.read()
        with gzip.open(str(logs/'clamscan_log.1.gz'),'wt') as f: f.write('Jan 01 2020 99:00:00 host clamscan start\n'+old)
        self.assertEqual(scanner.batch(str(logs),str(meta),str(meta))[1][1],'access_errors')
    def test_corrupt_source_all_fail(self):
        logs,meta,intervals=self.setup_logs(); (logs/'clamscan_log.1.gz').write_bytes(b'bad gzip')
        with self.assertRaises(OSError): scanner.batch(str(logs),str(meta),str(meta))
    def test_no_state_leak(self):
        logs,meta,intervals=self.setup_logs(); first=scanner.batch(str(logs),str(meta),str(meta))
        text,start,end=self.scan_log(logs,second=True); (logs/'clamscan_log').write_text(text)
        second=scanner.batch(str(logs),str(meta),str(meta)); self.assertEqual(first[1][1],'access_errors'); self.assertEqual(second[1][1],'clean')
    def test_multiple_rotations(self):
        logs,meta,intervals=self.setup_logs()
        for number in range(2,10):
            with gzip.open(str(logs/('clamscan_log.'+str(number)+'.gz')),'wt') as output: output.write('historical unrelated diagnostic\n'*100)
        with mock.patch.object(scanner,'lines',wraps=scanner.lines) as reads:
            rows=scanner.batch(str(logs),str(meta),str(meta))
        self.assertEqual(len(rows),2); self.assertEqual(sum('clamscan_log' in c.args[0] for c in reads.call_args_list),10)


class PresentationTests(Base):
    def present(self,value):
        result=self.shell('hc_status CRITICAL '+Q(value)); self.assertEqual(result.returncode,0,result.stderr); return result.stdout
    def test_ascii(self): self.assertEqual(self.present('normal'),'  CRITICAL normal\n')
    def test_newline(self): self.assertEqual(self.present('evil\nCRITICAL fake'),'  CRITICAL evil\\nCRITICAL fake\n')
    def test_crlf(self): self.assertIn('a\\r\\nb',self.present('a\r\nb'))
    def test_tab(self): self.assertIn('a\\tb',self.present('a\tb'))
    def test_escape(self): self.assertIn('\\x1b',self.present('\x1b'))
    def test_ansi(self): self.assertIn('\\x1b[31m',self.present('\x1b[31m'))
    def test_nul_boundary(self):
        path=self.work/'nul'; path.write_bytes(b'evil\x00CRITICAL fake')
        result=self.shell('hc_load_config '+Q(str(path)))
        self.assertEqual(result.returncode,1); self.assertIn('ERROR Configuration input UNKNOWN',result.stdout); self.assertNotIn('CRITICAL fake',result.stdout)
    def test_unicode(self): self.assertIn('é🙂中文',self.present('é🙂中文'))
    def test_long(self):
        result=self.shell('hc_status CRITICAL '+Q('x'*50000)+'; printf "critical=%s truncated=%s" "$HC_CRITICAL_COUNT" "$HC_RESULTS_TRUNCATED"')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(result.stdout,'  CRITICAL '+'x'*4096+'\ncritical=1 truncated=1')
    def test_signature(self): self.assertEqual(len(self.present('signature evil\nfake').splitlines()),1)
    def test_path(self): self.assertIn('/home/\\x01bad',self.present('/home/\x01bad'))
    def test_del(self): self.assertIn('\\x7f',self.present('\x7f'))
    def test_console(self): self.assertNotIn('\x1b',self.present('\x1b'))
    def test_telegram_values(self):
        result=self.shell('hc_warn '+Q('evil\nCRITICAL fake')+'\nprintf "%s" "${HC_WARNINGS[0]}"')
        self.assertEqual(result.stdout.count('\n'),1); self.assertIn('\\nCRITICAL fake',result.stdout)
    def test_external_service_diagnostics(self):
        result=self.shell('systemctl() { printf "%s" "$4" >&2; return 1; }; hc_check_service '+Q('name\x1b[31m')+' label')
        self.assertEqual(result.returncode,1); self.assertEqual(result.stderr,''); self.assertNotIn('\x1b',result.stdout); self.assertIn('\\x1b',result.stdout)
    def test_raw_classification(self):
        result=self.shell('source '+Q(str(ROOT/'lib/checks/lmd.sh'))+'\nvalue='+Q('{CAV}Eicar-Test-Signature\n')+'\n_lmd_test_signature "$value"; status=$?; hc_status CRITICAL "$value"; exit "$status"')
        self.assertEqual(result.returncode,1); self.assertIn('\\n',result.stdout)


class TelegramTests(Base):
    def send(self,body,status=0):
        code='source '+Q(str(ROOT/'lib/notify/telegram.sh'))+'\nNOTIFY_TELEGRAM=1\nTELEGRAM_BOT_TOKEN=123:secret_fixture\nTELEGRAM_CHAT_ID=123\ncurl() { cat >/dev/null; printf "%s" '+Q(body)+'; return '+str(status)+'; }\nnotify_telegram hello'
        return self.shell(code)
    def test_ok(self): self.assertEqual(self.send('{"ok":true}').returncode,0)
    def test_utf8_response_in_c_locale(self):
        body=json.dumps({'ok':True,'result':{'text':'中文🙂'}},ensure_ascii=False)
        result=self.send(body); self.assertEqual(result.returncode,0,result.stdout+result.stderr)
    def test_utf8_truncation_in_c_locale(self):
        capture=self.work/'request'
        code='source '+Q(str(ROOT/'lib/notify/telegram.sh'))+'\nNOTIFY_TELEGRAM=1\nTELEGRAM_BOT_TOKEN=123:fixture\nTELEGRAM_CHAT_ID=123\ncurl() { cat > '+Q(str(capture))+'; printf %s '+Q('{"ok":true}')+'; }\nnotify_telegram '+Q('中'*2000)
        result=self.shell(code)
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        request=capture.read_bytes().decode('utf-8')
        self.assertIn('中'*1166,request)
        self.assertIn('Truncated',request)
    def test_false(self): self.assertEqual(self.send('{"ok":false}').returncode,1)
    def test_bad_json(self): self.assertEqual(self.send('{oops').returncode,1)
    def test_empty(self): self.assertEqual(self.send('').returncode,1)
    def test_http_error(self): self.assertEqual(self.send('{"ok":true}',22).returncode,1)
    def test_network_error(self): self.assertEqual(self.send('',7).returncode,1)
    def test_http_success_reject(self): self.assertIn('application response failed',self.send('{"ok":false,"description":"Bad Request"}').stdout)
    def test_secret_response(self):
        result=self.send('{"ok":false,"description":"123:secret_fixture"}'); self.assertNotIn('secret_fixture',result.stdout+result.stderr)
    def test_long_error(self): self.assertEqual(self.send(json.dumps({'ok':False,'description':'x'*70000})).returncode,1)
    def test_unexpected(self): self.assertEqual(self.send('[true]').returncode,1)
    def test_integer_true(self): self.assertEqual(self.send('{"ok":1}').returncode,1)
    def test_duplicate(self): self.assertEqual(self.send('{"ok":false,"ok":true}').returncode,1)


class DiscoveryTests(Base):
    def discover(self,output='',status=0):
        return self.shell('hc_have() { [ "$1" = systemctl ]; }; systemctl() { printf "%s" '+Q(output)+'; return '+str(status)+'; }; hc_service_present fixture missing; result=$?; printf "errors=%s" "$HC_ERRORS"; exit "$result"')
    def test_present(self): self.assertEqual(self.discover('fixture.service enabled').returncode,0)
    def test_absent(self): self.assertEqual(self.discover().returncode,1)
    def test_disabled_unit_present(self): self.assertEqual(self.discover('fixture.service disabled').returncode,0)
    def test_command_failure(self): self.assertEqual(self.discover(status=1).returncode,2)
    def test_malformed(self):
        for listing in ['junk','fixture.service enabled extra columns','fixture.service made-up','fixture.service enabled \x1b[31m']:
            with self.subTest(listing=listing): self.assertEqual(self.discover(listing).returncode,2)
    def test_auto_module(self):
        result=self.shell('source '+Q(str(ROOT/'lib/checks/apache.sh'))+'\nHC_REGISTERED_CHECKS=(); hc_have() { [ "$1" = systemctl ]; }; systemctl() { return 1; }; CHECK_APACHE=auto; check_apache; printf "errors=%s" "$HC_ERRORS"')
        self.assertIn('ERROR Discovery failed',result.stdout); self.assertIn('errors=1',result.stdout)
    def test_explicit(self):
        result=self.shell('HC_REGISTERED_CHECKS=(); source '+Q(str(ROOT/'lib/checks/apache.sh'))+'\nCHECK_APACHE=1; hc_have() { return 0; }; systemctl() { [ "$1" = is-active ]; }; check_apache')
        self.assertNotIn('Discovery',result.stdout); self.assertEqual(result.returncode,0)
    def test_check_disabled(self):
        result=self.shell('HC_REGISTERED_CHECKS=(); source '+Q(str(ROOT/'lib/checks/apache.sh'))+'\nCHECK_APACHE=0; systemctl() { echo BAD; return 1; }; check_apache')
        self.assertNotIn('BAD',result.stdout)
    def test_lmd_discovery_failure(self):
        result=self.shell('HC_REGISTERED_CHECKS=(); source '+Q(str(ROOT/'lib/checks/lmd.sh'))+'\nLMD_ENABLED=auto; LMD_DIR='+Q(str(self.work/'absent'))+'; hc_data_parse() { return 1; }; check_lmd')
        self.assertIn('ERROR LMD discovery failed',result.stdout); self.assertNotIn('NOT_APPLICABLE',result.stdout)
    def test_lmd_absent(self):
        result=self.shell('HC_REGISTERED_CHECKS=(); source '+Q(str(ROOT/'lib/checks/lmd.sh'))+'\nLMD_ENABLED=auto; LMD_DIR='+Q(str(self.work/'absent'))+'; check_lmd')
        self.assertIn('NOT_APPLICABLE',result.stdout); self.assertNotIn('ERROR',result.stdout)
    def test_reason(self): self.assertIn('NOT_APPLICABLE',self.discover().stdout)
    def test_error_collection(self): self.assertIn('errors=1',self.discover(status=1).stdout)
    def test_multiple(self):
        result=self.shell('hc_have() { [ "$1" = systemctl ]; }; systemctl() { case "${@: -1}" in good.service) echo "good.service enabled";; *) return 1;; esac; }; hc_service_present good missing; hc_service_present bad missing; printf "errors=%s" "$HC_ERRORS"')
        self.assertIn('ERROR Discovery failed: bad',result.stdout); self.assertIn('errors=1',result.stdout)


class ServiceModuleTests(Base):
    def service(self,name,body):
        return self.shell('HC_REGISTERED_CHECKS=(); source '+Q(str(ROOT/'lib/checks'/(name+'.sh')))+'\n'+body)
    def test_apache_inactive(self):
        result=self.service('apache','CHECK_APACHE=1; systemctl() { return 1; }; check_apache')
        self.assertIn('WARNING Apache',result.stdout)
    def test_rspamd_absent(self):
        result=self.service('rspamd','CHECK_RSPAMD=auto; hc_have() { [ "$1" = systemctl ]; }; systemctl() { return 0; }; check_rspamd')
        self.assertIn('NOT_APPLICABLE',result.stdout); self.assertNotIn('WARNING',result.stdout)
    def test_pureftp_discovery_failure(self):
        result=self.service('pureftpd','CHECK_PUREFTP=auto; hc_have() { [ "$1" = systemctl ]; }; systemctl() { return 1; }; check_pureftpd')
        self.assertIn('ERROR Discovery failed',result.stdout)
    def test_service_name_not_cli_option(self):
        # Model getopt stopping at --: a literal missing --version unit is inactive.
        result=self.service('apache','CHECK_APACHE=1; APACHE_SERVICE=--version; hc_have() { return 0; }; systemctl() { [ "$3" != -- ]; }; check_apache')
        self.assertIn('WARNING Apache',result.stdout)
    def test_exim_queue(self):
        result=self.service('exim','CHECK_EXIM=1; hc_have() { return 0; }; systemctl() { return 0; }; exim() { echo 30; }; check_exim')
        self.assertIn('WARNING Exim: queue contains 30',result.stdout)
    def test_exim_queue_failure(self):
        result=self.service('exim','CHECK_EXIM=1; hc_have() { return 0; }; systemctl() { return 0; }; exim() { return 1; }; check_exim')
        self.assertIn('WARNING Exim: unable to read mail queue',result.stdout)


class InstallerTests(Base):
    def setUp(self):
        super().setUp()
        self.source=self.work/'source'; self.source.mkdir()
        for name in ['lib','bin','config','systemd']:
            shutil.copytree(ROOT/name,self.source/name)
        shutil.copy2(ROOT/'runtime.manifest',self.source/'runtime.manifest')
        self.dest=self.work/'destination'; (self.dest/'usr/local/sbin').mkdir(parents=True); (self.dest/'etc/systemd/system').mkdir(parents=True)
        self.active=self.dest/'usr/local/lib/server-security-healthcheck'
    def install(self,fail='',interrupt=False):
        text=(ROOT/'install.sh').read_text()
        for prefix in ['/usr/local/','/etc/']:
            text=text.replace(prefix,str(self.dest)+prefix)
        text='\n'.join('ROOT_DIR='+Q(str(self.source)) if line.startswith('ROOT_DIR=') else line for line in text.splitlines())
        stub='id() { echo 0; }; systemctl() { return 0; };\n'
        if fail:
            stub+='install() { case "$*" in *'+Q(fail)+'*) '+('kill -TERM $$' if interrupt else 'return 1')+';; esac; command install "$@"; };\n'
        return subprocess.run(['bash','-c',stub+text],text=True,capture_output=True,env=self.env,timeout=10)
    def good(self):
        result=self.install(); self.assertEqual(result.returncode,0,result.stdout+result.stderr)
    def test_fresh(self): self.good(); self.assertTrue(self.active.is_symlink()); self.assertTrue((self.active/'common.sh').is_file())
    def test_launcher(self):
        self.good()
        result=subprocess.run([str(self.dest/'usr/local/sbin/server-security-healthcheck'),'--version'],text=True,capture_output=True)
        self.assertEqual(result.returncode,0,result.stderr); self.assertEqual(result.stdout,'server-security-healthcheck v1.1.0\n')
    def test_stage_interrupted(self):
        self.good(); before=self.active.resolve(); result=self.install('health_data.py',interrupt=True); self.assertNotEqual(result.returncode,0); self.assertEqual(self.active.resolve(),before); self.assertIn('previous runtime retained',result.stderr)
    def test_unit_stage_failure(self):
        self.good(); before=self.active.resolve(); result=self.install('server-security-healthcheck.timer'); self.assertNotEqual(result.returncode,0); self.assertEqual(self.active.resolve(),before)
    def test_upgrade(self):
        self.good(); before=self.active.resolve(); self.good(); self.assertNotEqual(self.active.resolve(),before); self.assertTrue(before.exists())
    def test_config(self):
        self.good(); config=self.dest/'etc/server-security-healthcheck/healthcheck.conf'; config.write_text('CUSTOM=value\n'); self.good(); self.assertEqual(config.read_text(),'CUSTOM=value\n')
    def test_config_symlink(self):
        config=self.dest/'etc/server-security-healthcheck'; config.mkdir(); (config/'telegram.conf').symlink_to(self.work/'missing'); self.good(); self.assertTrue((config/'telegram.conf').is_symlink())
    def test_missing_helper(self):
        self.good(); before=self.active.resolve(); (self.source/'lib/checks/lmd_scanner.py').unlink(); result=self.install(); self.assertNotEqual(result.returncode,0); self.assertEqual(self.active.resolve(),before)
    def test_staging_failure(self):
        self.good(); before=self.active.resolve(); result=self.install('health_data.py'); self.assertNotEqual(result.returncode,0); self.assertEqual(self.active.resolve(),before); self.assertIn('previous runtime retained',result.stderr)
    def test_managed_obsolete(self):
        self.good(); old=self.active/'checks/obsolete.sh'; old.write_text('hc_register_check obsolete\n'); manifest=self.active/'.runtime.manifest'; manifest.write_text(manifest.read_text()+'checks/obsolete.sh\n'); self.good(); self.assertFalse((self.active/'checks/obsolete.sh').exists())
    def test_custom_preserved(self):
        self.good(); old=self.active/'checks/custom.sh'; old.write_text('# custom\n'); (self.active/'custom-data').write_text('companion'); external=self.work/'external'; external.write_text('untouched'); (self.active/'launcher').unlink(); (self.active/'launcher').symlink_to(external); self.good(); self.assertEqual(external.read_text(),'untouched'); self.assertEqual((self.active/'checks/custom.sh').read_text(),'# custom\n'); self.assertEqual((self.active/'custom-data').read_text(),'companion')
    def test_half_built(self):
        self.good(); before=self.active.resolve()
        releases_before=sorted(p.name for p in before.parent.iterdir())
        entry=self.source/'bin/server-security-healthcheck'
        old_entry=(before/'bin/server-security-healthcheck').read_bytes()
        candidate, replacements = re.subn(r'^APP_VERSION=.*$',
                                          'APP_VERSION="fixture-interrupted"',
                                          entry.read_text(), flags=re.MULTILINE)
        self.assertEqual(replacements, 1)
        self.assertNotEqual(candidate.encode(), old_entry)
        self.assertIn('APP_VERSION="fixture-interrupted"', candidate)
        entry.write_text(candidate)
        text=(ROOT/'install.sh').read_text()
        for prefix in ['/usr/local/','/etc/']: text=text.replace(prefix,str(self.dest)+prefix)
        text='\n'.join('ROOT_DIR='+Q(str(self.source)) if line.startswith('ROOT_DIR=') else line for line in text.splitlines())
        text=text.replace('mv -Tf -- "$NEXT" "$ACTIVE"','kill -TERM $$\nmv -Tf -- "$NEXT" "$ACTIVE"')
        result=subprocess.run(['bash','-c','id() { echo 0; }; systemctl() { return 0; };\n'+text],env=self.env,text=True,capture_output=True,timeout=10)
        self.assertNotEqual(result.returncode,0); self.assertEqual(self.active.resolve(),before)
        self.assertFalse(list(self.active.parent.glob('server-security-healthcheck.next.*')))
        self.assertEqual(sorted(p.name for p in before.parent.iterdir()),releases_before)
        launcher=self.dest/'usr/local/sbin/server-security-healthcheck'
        result=subprocess.run([str(launcher),'--version'],env=dict(self.env,SSHC_LIB_DIR=str(before),SSHC_CONFIG_DIR=str(self.dest/'etc/server-security-healthcheck')),text=True,capture_output=True)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertNotIn('interrupted',result.stdout)
        self.assertEqual((before/'bin/server-security-healthcheck').read_bytes(),old_entry)
        config=self.work/'interruption-config';config.mkdir()
        (config/'healthcheck.conf').write_text('NOTIFY_TELEGRAM=0\nCHECK_APACHE=0\nCHECK_RSPAMD=0\nCHECK_PUREFTP=0\nCHECK_EXIM=0\nCHECK_DISK=0\nCHECK_CLAMAV=0\nCHECK_LMD=0\nLMD_ENABLED=0\n')
        result=subprocess.run([str(launcher)],env=dict(self.env,SSHC_LIB_DIR=str(before),SSHC_CONFIG_DIR=str(config)),text=True,capture_output=True,timeout=10)
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        self.assertIn('all enabled checks passed',result.stdout)
    def test_shell_syntax(self):
        self.good(); before=self.active.resolve(); (self.source/'lib/checks/disk.sh').write_text('if then\n'); result=self.install(); self.assertNotEqual(result.returncode,0); self.assertEqual(self.active.resolve(),before)
    def test_python_syntax(self):
        self.good(); before=self.active.resolve(); (self.source/'lib/checks/health_data.py').write_text('def broken(\n'); result=self.install(); self.assertNotEqual(result.returncode,0); self.assertEqual(self.active.resolve(),before)
    def test_permissions(self):
        self.good(); self.assertEqual((self.active/'bin/server-security-healthcheck').stat().st_mode&0o777,0o755); self.assertEqual((self.active/'common.sh').stat().st_mode&0o777,0o644)
    def test_python_included(self):
        self.good()
        for name in ['health_data.py','lmd_scanner.py','bounded_input.py']: self.assertTrue((self.active/'checks'/name).is_file())
    def test_idempotent(self):
        self.good(); first=(self.active/'.runtime.manifest').read_text(); self.good(); self.assertEqual((self.active/'.runtime.manifest').read_text(),first)
    def test_legacy_unknown_preserved(self):
        (self.active/'checks').mkdir(parents=True); (self.active/'checks/unknown.sh').write_text('# local legacy\n'); self.good(); self.assertTrue((self.active/'checks/unknown.sh').exists())


class IntegrationTests(unittest.TestCase):
    setUp=fixture.HealthcheckTests.setUp
    run_shell=fixture.HealthcheckTests.run_shell
    main=fixture.HealthcheckTests.main
    append_meta=fixture.HealthcheckTests.append_meta
    def test_A_limit(self):
        text='Sep 20 2026 00:31:00 host clamscan start\nSep 20 2026 00:31:01 host executed: /usr/bin/clamscan --infected -f /tmp/files\nSep 20 2026 01:30:00 host clamscan end return 0\n'
        (self.lmd/'logs/clamscan_log').write_text(text+'harmless history\n'*100)
        control=self.run_shell('_lmd_check_fullscan',reliability=True)
        self.assertIn('PASS LMD full scan: no hits',control)
        # Metadata fits 1 KiB; only the otherwise healthy scannerlog exceeds it.
        output=self.run_shell('export SSHC_MAX_FILE_BYTES=1024; _lmd_check_fullscan',reliability=True)
        self.assertIn('UNKNOWN',output); self.assertNotIn('PASS',output)
    def test_B_shared_history(self):
        new=self.lmd/'sess/scan.meta.260920-0900.2'
        new.write_text(self.scan.read_text()+'\nstarted=1789887600\ncompleted=1789889400\nelapsed=1800\nns_pid=2\npid=2\n')
        old='Sep 20 2026 00:31:00 host clamscan start\nSep 20 2026 00:31:01 host executed: /usr/bin/clamscan --infected -f /tmp/files\nSep 20 2026 01:30:00 host clamscan end return 0\n'
        with gzip.open(str(self.lmd/'logs/clamscan_log.1.gz'),'wt') as stream: stream.write(old)
        (self.lmd/'logs/clamscan_log').write_text('Sep 20 2026 09:00:00 host clamscan start\nSep 20 2026 09:00:01 host executed: /usr/bin/clamscan --infected -f /tmp/files\nSep 20 2026 09:30:00 host clamscan end return 0\n')
        counter=self.work/'scanner starts'
        output=self.run_shell('python3() { [ "$1" != "$LMD_SCANNER_PARSER" ] || echo start >> '+Q(str(counter))+'; command python3 "$@"; }; _lmd_check_fullscan',reliability=True)
        self.assertEqual(output.count('scanner result: clean'),2)
        self.assertEqual(counter.read_text().splitlines(),['start'])
    def test_C_snapshot_failure_preserves_source(self):
        before=self.scan.read_bytes(); os.mkfifo(str(self.lmd/'sess/session.index'))
        output=self.run_shell('_lmd_check_fullscan',reliability=True)
        self.assertIn('ERROR',output); self.assertEqual(self.scan.read_bytes(),before)
    def test_D_malicious_metadata(self):
        output=self.run_shell('hc_detail '+Q('signature: evil\nCRITICAL fake message'))
        self.assertEqual(output.count('\n'),1); self.assertIn('evil\\nCRITICAL fake message',output)
    def test_E_api_reject(self):
        output=self.run_shell('source '+Q(str(ROOT/'lib/notify/telegram.sh'))+'\nNOTIFY_TELEGRAM=1; TELEGRAM_BOT_TOKEN=123:fixture_secret; TELEGRAM_CHAT_ID=123; curl() { cat >/dev/null; echo \'{"ok":false}\'; }; notify_telegram hello',expected=1)
        self.assertIn('ERROR Telegram application response failed',output)
    def test_F_discovery_failure(self):
        # Force discovery independently of installed binaries and host systemctl.
        output=self.run_shell('hc_have() { [ "$1" = systemctl ]; }; systemctl() { return 1; }; hc_service_present nonexistent missing',expected=2)
        self.assertIn('ERROR Discovery failed',output); self.assertNotIn('NOT_APPLICABLE',output)
    def test_G_happy(self):
        text='Sep 20 2026 00:31:00 host clamscan start\nSep 20 2026 00:31:01 host executed: /usr/bin/clamscan --infected -f /tmp/files\nSep 20 2026 01:30:00 host clamscan end return 0\n'
        (self.lmd/'logs/clamscan_log').write_text(text)
        library=self.work/'happy library'; shutil.copytree(ROOT/'lib',library)
        with (library/'checks/disk.sh').open('a') as stream:
            stream.write("\ndf() { echo 'Filesystem Size Used Avail Use% Mounted on'; echo '/dev/fixture 100G 1G 99G 1% /'; }\n")
        with (library/'notify/telegram.sh').open('a') as stream:
            stream.write("\ncurl() { cat >/dev/null; echo '{\"ok\":true}'; }\n")
        with (library/'common.sh').open('a') as stream:
            stream.write('\ndate() { if [ \"$*\" = +%s ]; then echo '+str(fixture.NOW)+'; else command date \"$@\"; fi; }\n')
        config='CHECK_DISK=1\nCHECK_LMD=1\nLMD_DIR='+Q(str(self.lmd))+'\nLMD_AUDIT='+Q(str(self.work/'empty audit'))+'\nLMD_MONITOR_REQUIRED=0\nLMD_CONFIG_CHECK_ENABLED=0\nNOTIFY_TELEGRAM=1\nTELEGRAM_BOT_TOKEN=123:fixture_secret\nTELEGRAM_CHAT_ID=123\n'
        result=self.main(config,lib_dir=library)
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        self.assertIn('PASS LMD full scan: no hits',result.stdout); self.assertNotIn('UNKNOWN',result.stdout)
        notification=self.main(config,args=('--test-notification',),lib_dir=library)
        self.assertEqual(notification.returncode,0,notification.stdout+notification.stderr); self.assertNotIn('fixture_secret',notification.stdout+notification.stderr)
    def test_H_findings(self):
        self.append_meta(hits=1)
        shutil.copy2(fixture.FIXTURES/'session.malware.tsv',self.session)
        (self.lmd/'logs/clamscan_log').write_text('Sep 20 2026 00:31:00 host clamscan start\nSep 20 2026 00:31:01 host executed: /usr/bin/clamscan --infected -f /tmp/files\nSep 20 2026 01:30:00 host clamscan end return 1\n')
        library=self.work/'library'; shutil.copytree(ROOT/'lib',library)
        with (library/'common.sh').open('a') as stream:
            stream.write('\ndate() { if [ "$*" = +%s ]; then echo '+str(fixture.NOW)+'; else command date "$@"; fi; }\n')
        # Only operational boundaries are mocked; disk/LMD/discovery/response logic is real.
        with (library/'checks/apache.sh').open('a') as stream:
            stream.write('\nhc_have() { case "$1" in systemctl) return 0;; httpd|apachectl|apache2ctl) return 1;; *) command -v "$1" >/dev/null 2>&1;; esac; }\nsystemctl() { return 1; }\n')
        with (library/'checks/disk.sh').open('a') as stream:
            stream.write("\ndf() { echo 'Filesystem Size Used Avail Use% Mounted on'; echo '/dev/fixture 100G 95G 5G 95% /'; }\n")
        with (library/'notify/telegram.sh').open('a') as stream:
            stream.write("\ncurl() { cat >/dev/null; echo '{\"ok\":false}'; }\n")
        config='CHECK_DISK=1\nCHECK_APACHE=auto\nCHECK_LMD=1\nLMD_DIR='+Q(str(self.lmd))+'\nLMD_AUDIT='+Q(str(self.work/'empty audit'))+'\nLMD_MONITOR_REQUIRED=0\nLMD_CONFIG_CHECK_ENABLED=0\nNOTIFY_TELEGRAM=1\nTELEGRAM_BOT_TOKEN=123:fixture_secret\nTELEGRAM_CHAT_ID=123\n'
        result=self.main(config,lib_dir=library)
        self.assertEqual(result.returncode,2,result.stdout+result.stderr)
        self.assertIn('WARNING',result.stdout); self.assertIn('95%',result.stdout)
        self.assertIn('CRITICAL LMD full scan found malware',result.stdout)
        self.assertIn('ERROR Discovery failed',result.stdout); self.assertNotIn('NOT_APPLICABLE',result.stdout)
        self.assertIn('Telegram application response failed',result.stdout)
        self.assertNotIn('fixture_secret',result.stdout+result.stderr)


class ShellDeadlineTests(unittest.TestCase):
    setUp=fixture.HealthcheckTests.setUp
    run_shell=fixture.HealthcheckTests.run_shell
    def test_config_deadline(self):
        path=self.work/'bounded config'; path.write_text('CHECK_LMD=0\n')
        output=self.run_shell('hc_budget_expired() { return 0; }; hc_load_config '+Q(str(path)),expected=1)
        self.assertIn('ERROR Configuration processing budget exceeded',output)
    def test_metadata_deadline(self):
        output=self.run_shell('hc_budget_expired() { return 0; }; _lmd_check_fullscan',reliability=True)
        self.assertIn('ERROR LMD metadata processing budget exceeded',output); self.assertNotIn('PASS',output)
    def test_selection_deadline(self):
        output=self.run_shell('hc_budget_expired() { [ "${FUNCNAME[1]}" = _lmd_select_fullscan ]; }; _lmd_check_fullscan',reliability=True)
        self.assertIn('ERROR LMD selection processing budget exceeded',output); self.assertNotIn('PASS',output)
    def test_hit_deadline(self):
        session=self.work/'hits'; shutil.copy2(fixture.FIXTURES/'session.malware.tsv',session)
        output=self.run_shell('hc_budget_expired() { return 0; }; _lmd_check_hits '+Q(str(session))+' 1 0')
        self.assertIn('ERROR LMD hit processing budget exceeded',output); self.assertNotIn('PASS',output)
    def test_native_deadline(self):
        native=fixture.NativeLmdTests('test_duplicate_id_is_not_success'); native.setUp(); self.addCleanup(native.doCleanups)
        output=native.run_shell('hc_budget_expired() { [ "${FUNCNAME[1]}" = _lmd_native_records ]; }; _lmd_check_fullscan',reliability=True)
        self.assertIn('ERROR LMD native parsing budget exceeded',output); self.assertNotIn('PASS',output)


class DirectoryProbeTests(Base):
    def test_absent(self): self.assertEqual(data.directory_state(str(self.work/'missing')),'ABSENT')
    def test_present(self): self.assertEqual(data.directory_state(str(self.work)),'PRESENT')
    def test_permission_failure(self):
        with mock.patch.object(data.os,'stat',side_effect=PermissionError('denied')):
            with self.assertRaises(OSError): data.directory_state(str(self.work))


class OptionalInputTests(unittest.TestCase):
    setUp=fixture.HealthcheckTests.setUp
    run_shell=fixture.HealthcheckTests.run_shell
    main=fixture.HealthcheckTests.main
    def test_telegram_config_fifo(self):
        directory=self.work/'config'; directory.mkdir(); os.mkfifo(str(directory/'telegram.conf'))
        result=self.main(''); self.assertEqual(result.returncode,2); self.assertIn('Telegram configuration source UNKNOWN',result.stdout)
    def test_audit_optional_probe_failure(self):
        output=self.run_shell('unset LMD_AUDIT; hc_data_parse() { return 1; }; _lmd_check_events')
        self.assertIn('ERROR LMD audit source discovery failed',output)
    def test_signature_version_first_line(self):
        (self.lmd/'sigs/maldet.sigs.ver').write_text('12345\nSECOND LINE\n')
        output=self.run_shell('_lmd_check_signature_updater')
        self.assertIn('signature version: 12345',output); self.assertNotIn('SECOND LINE',output)
    def test_file_probe_permission_failure(self):
        with mock.patch.object(data.os,'stat',side_effect=PermissionError('denied')):
            with self.assertRaises(OSError): data.file_state(str(self.work/'file'))
