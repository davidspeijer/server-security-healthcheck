"""Permanent J01-J06 fault injection; every mutation is in a private fixture."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import unittest
import test_healthcheck as f
import test_ph11_registry as registry
import test_audit_round3 as installers

ROOT=f.ROOT
Q=f.Q


class ReleaseFixesTests(unittest.TestCase):
    setUp=f.HealthcheckTests.setUp
    main=f.HealthcheckTests.main
    def library(self):
        lib=self.work/'library';shutil.copytree(ROOT/'lib',lib);self.lib=lib;return lib
    def custom(self, body):
        registry.add_check(self.lib,body='hc_register_check mariadb\ncheck_mariadb() { '+body+'; return 0; }\n')
    def run_json(self, config=''):
        result=self.main(config,['--json'],self.lib)
        if result.stdout:
            document=json.loads(result.stdout)
            self.assertEqual(document['run']['exit_code'],result.returncode)
        return result
    def failed(self, result):
        self.assertEqual(result.returncode,2,result.stdout+result.stderr)
        self.assertEqual(result.stdout,'')
        self.assertIn('ERROR',result.stderr)
    def helper_failure(self, mode):
        self.library();helper=self.lib/'output.sh';text=helper.read_text()
        if mode=='empty':helper.write_text('')
        elif mode=='syntax':helper.write_text('if then\n')
        elif mode=='source':helper.write_text('return 7\n')
        elif mode=='exit_zero':helper.write_text(text+'\nexit 0\n')
        elif mode=='nounset':helper.write_text(text+'\nprintf \'%s\' "$UNDEFINED_OUTPUT_FIXTURE"\n')
        elif mode=='hidden_source':helper.write_text('false\n'+text)
        elif mode=='missing_one':helper.write_text(text.replace('hc_json_clock() {','unused_clock() {'))
        elif mode=='missing_several':helper.write_text('hc_json_clock() { :; }\n')
        elif mode=='foreign':
            foreign=self.work/'foreign.sh';foreign.write_text('hc_json_clock() { :; }\n')
            helper.write_text(text.replace('hc_json_clock() {','unused_clock() {')+'\nsource '+Q(str(foreign))+'\n')
        elif mode=='fifo':helper.unlink();os.mkfifo(helper)
        elif mode=='unreadable':
            common=self.lib/'common.sh'
            common.write_text(common.read_text()+"\nfunction '['() { if builtin [ \"$#\" -eq 2 ] && builtin [ \"$1\" = -r ] && builtin [ \"$2\" = "+Q(str(helper))+" ]; then return 1; fi; builtin [ \"$@\"; }\n")
        elif mode=='python_empty':(self.lib/'checks/output.py').write_text('')
        elif mode=='python_missing':(self.lib/'checks/output.py').unlink()
        self.failed(self.run_json())

    def test_valid_helper(self):
        self.library();result=self.run_json();self.assertEqual(result.returncode,0)

    def late_write(self, stage, severity):
        self.library();self.custom('hc_status '+severity+' '+Q('x'*5000))
        helper=self.lib/'output.sh';target=self.work/'directory';target.mkdir()
        original=helper.read_text().replace('hc_json_record() {','hc_json_original_record() {',1)
        helper.write_text(original+'\nhc_json_record() { if [ "$1" = '+Q(stage)+' ]; then printf "%s" failure >> '+Q(str(target))+' || HC_JSON_FAILED=1; else hc_json_original_record "$@"; fi; }\n')
        self.failed(self.run_json('CHECK_MARIADB=1\n'))

    def renderer_failure(self, mode):
        self.library();helper=self.lib/'checks/output.py';text=helper.read_text()
        if mode=='before':injection="raise RuntimeError('fixture renderer failure')"
        elif mode=='partial':injection="print('{'); sys.stdout.flush(); sys.exit(7)"
        elif mode=='full':
            helper.write_text(text+"\nif len(sys.argv)>1 and sys.argv[1]=='render':\n    sys.stdout.flush()\n    sys.exit(7)\n")
            self.failed(self.run_json());return
        elif mode=='signal':
            helper.write_text(text+"\nif len(sys.argv)>1 and sys.argv[1]=='render':\n    import os, signal\n    sys.stdout.flush()\n    os.kill(os.getpid(), signal.SIGTERM)\n")
            self.failed(self.run_json());return
        helper.write_text(text.replace("    elif mode == 'render':", "    elif mode == 'render':\n        "+injection,1))
        self.failed(self.run_json())

    def test_missing_helper_is_top_level(self):
        self.library();(self.lib/'checks/lmd_policy.sh').unlink()
        result=self.run_json('CHECK_LMD=1\n');data=json.loads(result.stdout)
        self.assertEqual(result.returncode,2)
        self.assertNotIn('lmd_policy',[c['id'] for c in data['checks']])
        self.assertTrue(any('lmd_policy' in event['message'] for event in data['findings']))
        self.assertEqual([c['id'] for c in data['checks']],['apache','rspamd','pureftpd','exim','disk','clamav','lmd'])
    def test_helper_syntax_and_check_missing_order(self):
        self.library();(self.lib/'checks/lmd_policy.sh').write_text('if then\n');(self.lib/'checks/disk.sh').unlink()
        result=self.run_json('CHECK_LMD=1\nCHECK_DISK=1\n');data=json.loads(result.stdout)
        self.assertEqual(result.returncode,2)
        self.assertEqual([c['id'] for c in data['checks']],['apache','rspamd','pureftpd','exim','disk','clamav','lmd'])
        self.assertEqual(next(c for c in data['checks'] if c['id']=='disk')['status'],'error')

    def test_unicode_boundaries_locale_independent(self):
        locales=subprocess.check_output(['locale','-a'],text=True).splitlines()
        utf=next((name for name in locales if 'utf' in name.lower()),'C.UTF-8')
        for character in ['x','€','😀','e\u0301']:
            for size in [1023,1024,1025]:
                message=(character*1025)[:size]
                for locale in ['C',utf]:
                    with self.subTest(character=character,size=size,locale=locale):
                        # Fresh library, same canonical message in each locale.
                        if hasattr(self,'lib'):shutil.rmtree(self.lib)
                        self.library();self.custom('hc_warn '+Q(message));self.env['LC_ALL']=locale
                        result=self.run_json('CHECK_MARIADB=1\n');data=json.loads(result.stdout)
                        event=next(c for c in data['checks'] if c['id']=='mariadb')['findings'][0]
                        self.assertEqual(event['message'],message[:1024])
                        self.assertNotIn('\ufffd',event['message'])
                        self.assertEqual(data['truncated'],size>1024)

    def test_giant_identifier_rejected(self):
        self.library();name='a'*14000
        with (self.lib/'checks.registry').open('a') as stream:stream.write(name+'|checks/long.sh|check_long|CHECK_LONG|0|custom|-\n')
        result=self.run_json('CHECK_LONG=0\n')
        self.assertEqual(result.returncode,2)
        self.assertEqual(json.loads(result.stdout)['run']['status'],'error')

    def test_registry_metadata_lengths(self):
        fields=['a'*128, 'checks/'+('a'*245)+'.sh', 'f'*128, 'CHECK_'+('A'*122)]
        # Relative path is exactly 255 bytes, including checks/ and .sh.
        fields[1]='checks/'+('a'*245)+'.sh'
        for index in range(4):
            for excess in [False,True]:
                with self.subTest(field=index,excess=excess):
                    if hasattr(self,'lib'):shutil.rmtree(self.lib)
                    self.library();row=fields[:]
                    if excess:
                        row[index]=row[index].replace('.sh','a.sh') if index==1 else row[index]+'a' if index!=3 else row[index]+'A'
                    with (self.lib/'checks.registry').open('a') as stream:stream.write('|'.join(row+['0','custom','-'])+'\n')
                    result=self.run_json()
                    self.assertEqual(result.returncode,2 if excess else 0)

    def test_check_cannot_replace_output_callback(self):
        self.library();self.custom('hc_json_finish() { :; }')
        self.failed(self.run_json('CHECK_MARIADB=1\n'))

    def test_total_budget_and_post_budget_severity(self):
        self.library();helper=self.lib/'output.sh'
        # Only the fixture budget is smaller; hard limits have no environment override.
        helper.write_text(helper.read_text().replace('HC_JSON_MAX_BYTES=4194304 HC_JSON_RESERVE_BYTES=262144','HC_JSON_MAX_BYTES=8192 HC_JSON_RESERVE_BYTES=4096'))
        self.custom('for ((i=0;i<1000;i++)); do hc_detail '+Q('😀'*1024)+'; done; hc_status CRITICAL critical; hc_status ERROR failure')
        size=self.work/'size'
        text=helper.read_text().replace('    # Every append opens/closes', '    stat -c %s "$HC_JSON_FILE" > '+Q(str(size))+'\n    # Every append opens/closes')
        helper.write_text(text)
        result=self.run_json('CHECK_MARIADB=1\n');data=json.loads(result.stdout)
        self.assertEqual(result.returncode,2)
        self.assertEqual(data['run']['status'],'error')
        self.assertEqual(data['summary']['info'],1000)
        self.assertEqual(data['summary']['critical'],1);self.assertEqual(data['summary']['error'],1)
        self.assertTrue(data['truncated']);self.assertLessEqual(int(size.read_text()),8192)

    def budget_record(self, size):
        code='source '+Q(str(ROOT/'lib/output.sh'))+'; hc_json_init; HC_JSON_MAX_BYTES=64; HC_JSON_RESERVE_BYTES=0; hc_json_record check "" "" '+Q('x'*(size-9))+'; stat -c %s "$HC_JSON_FILE"; printf "%s" "$HC_JSON_FAILED"; rm -f "$HC_JSON_FILE" "$HC_JSON_RENDERED"; rmdir "$HC_JSON_DIR"'
        result=subprocess.run(['bash','-c',code],env=self.env,text=True,capture_output=True)
        self.assertEqual(result.returncode,0,result.stderr)
        return result.stdout.splitlines()
    def test_exact_total_budget(self):self.assertEqual(self.budget_record(64),['64','0'])
    def test_under_total_budget(self):self.assertEqual(self.budget_record(63),['63','0'])
    def test_over_total_budget(self):self.assertEqual(self.budget_record(65),['0','1'])
    def test_individual_record_budget(self):
        code='source '+Q(str(ROOT/'lib/output.sh'))+'; hc_json_init; HC_JSON_MAX_RECORD=8; hc_json_record check "" "" x; printf "%s" "$HC_JSON_FAILED"; rm -f "$HC_JSON_FILE" "$HC_JSON_RENDERED"; rmdir "$HC_JSON_DIR"'
        result=subprocess.run(['bash','-c',code],env=self.env,text=True,capture_output=True)
        self.assertEqual(result.stdout,'1')

    def test_malformed_clock_protocol(self):
        self.library();helper=self.lib/'checks/output.py'
        helper.write_text(helper.read_text().replace("print('{}|{}'.format(stamp, tick))", "print('not-an-ISO-date|123')"))
        result=self.run_json();self.assertEqual(result.returncode,2)
        self.assertEqual(json.loads(result.stdout)['run']['status'],'error')

    def test_private_scratch_and_cleanup(self):
        self.library();observed=self.work/'observed';helper=self.lib/'output.sh'
        helper.write_text(helper.read_text().replace('    HC_JSON_PID=$BASHPID','    printf "%s\\n" "$HC_JSON_DIR" > '+Q(str(observed))+'\n    stat -c %a "$HC_JSON_DIR" "$HC_JSON_FILE" "$HC_JSON_RENDERED" >> '+Q(str(observed))+'\n    HC_JSON_PID=$BASHPID'))
        self.assertEqual(self.run_json().returncode,0)
        lines=observed.read_text().splitlines();self.assertEqual(lines[1:],['700','600','600']);self.assertFalse(Path(lines[0]).exists())
    def test_cleanup_failure_prevents_publication(self):
        self.library();helper=self.lib/'output.sh';helper.write_text(helper.read_text()+'\nrmdir() { return 1; }\n')
        self.failed(self.run_json())
    def test_notification_failure_exit_invariant(self):
        self.library();self.custom('hc_warn finding')
        (self.lib/'notify/telegram.sh').write_text('notify_telegram() { return 7; }\nnotify_test() { return 7; }\n')
        result=self.run_json('CHECK_MARIADB=1\nNOTIFY_TELEGRAM=1\n');self.assertEqual(result.returncode,2)
        self.assertEqual(json.loads(result.stdout)['run']['status'],'error')


def helper_case(mode):
    def test(self):self.helper_failure(mode)
    return test
for mode in ['empty','syntax','source','exit_zero','nounset','hidden_source','missing_one','missing_several','foreign','fifo','unreadable','python_empty','python_missing']:
    setattr(ReleaseFixesTests,'test_helper_'+mode,helper_case(mode))
def late_case(stage,level):
    def test(self):self.late_write(stage,level)
    return test
for stage in ['finding','counts','truncated','run-end']:
    for level in ['PASS','WARNING','CRITICAL','ERROR']:
        setattr(ReleaseFixesTests,'test_write_'+stage.replace('-','_')+'_'+level.lower(),late_case(stage,level))
def renderer_case(mode):
    def test(self):self.renderer_failure(mode)
    return test
for mode in ['before','partial','full','signal']:
    setattr(ReleaseFixesTests,'test_renderer_'+mode,renderer_case(mode))


class InstalledOutputTests(installers.Base):
    install=installers.InstallerTests.install
    good=installers.InstallerTests.good
    def setUp(self):
        super().setUp();self.source=self.work/'source';self.source.mkdir()
        for directory in ['lib','bin','config','systemd']:shutil.copytree(ROOT/directory,self.source/directory)
        shutil.copy2(ROOT/'runtime.manifest',self.source/'runtime.manifest')
        self.dest=self.work/'destination';(self.dest/'usr/local/sbin').mkdir(parents=True);(self.dest/'etc/systemd/system').mkdir(parents=True)
        self.active=self.dest/'usr/local/lib/server-security-healthcheck'
    def run_active(self,config=''):
        directory=self.work/'config';directory.mkdir(exist_ok=True)
        (directory/'healthcheck.conf').write_text('NOTIFY_TELEGRAM=0\n'+''.join(line.split('|')[3]+'=0\n' for line in (self.active/'checks.registry').read_text().splitlines() if '|builtin|' in line)+config)
        return subprocess.run([str(self.dest/'usr/local/sbin/server-security-healthcheck'),'--json'],env=dict(self.env,SSHC_CONFIG_DIR=str(directory)),capture_output=True,text=True,timeout=20)
    def test_installed_empty_helper(self):
        self.good();(self.active/'output.sh').write_text('');result=self.run_active();self.assertEqual(result.returncode,2);self.assertEqual(result.stdout,'')
    def test_installed_renderer_failure(self):
        self.good();helper=self.active/'checks/output.py';helper.write_text(helper.read_text()+"\nif len(sys.argv)>1 and sys.argv[1]=='render':\n    sys.stdout.flush(); sys.exit(7)\n")
        result=self.run_active();self.assertEqual(result.returncode,2);self.assertEqual(result.stdout,'')
    def test_installed_late_write(self):
        self.good();helper=self.active/'output.sh';text=helper.read_text().replace('hc_json_record() {','hc_json_original_record() {',1)
        helper.write_text(text+'\nhc_json_record() { if [ "$1" = counts ]; then HC_JSON_FAILED=1; else hc_json_original_record "$@"; fi; }\n')
        result=self.run_active();self.assertEqual(result.returncode,2);self.assertEqual(result.stdout,'')
    def test_installed_status_matrix(self):
        registry.add_check(self.source/'lib');self.good()
        for level,code in [('PASS',0),('WARNING',1),('ERROR',2)]:
            (self.active/'checks/mariadb.sh').write_text('hc_register_check mariadb\ncheck_mariadb() { hc_status '+level+' fixture; }\n')
            result=self.run_active('CHECK_MARIADB=1\n');data=json.loads(result.stdout)
            self.assertEqual(result.returncode,code);self.assertEqual(data['run']['exit_code'],code)
    def stage_failure(self,mode):
        self.good();before=self.active.resolve();helper=self.source/'lib/output.sh'
        if mode=='missing_shell':helper.unlink()
        elif mode=='empty_shell':helper.write_text('')
        elif mode=='incomplete_shell':helper.write_text(helper.read_text().replace('hc_json_clock() {','unused_clock() {'))
        elif mode=='missing_python':(self.source/'lib/checks/output.py').unlink()
        elif mode=='invalid_python':(self.source/'lib/checks/output.py').write_text('def invalid(\n')
        elif mode=='empty_python':(self.source/'lib/checks/output.py').write_text('')
        result=self.install();self.assertNotEqual(result.returncode,0);self.assertEqual(self.active.resolve(),before)
        self.assertEqual(self.run_active().returncode,0)

def stage_case(mode):
    def test(self):self.stage_failure(mode)
    return test
for mode in ['missing_shell','empty_shell','incomplete_shell','missing_python','invalid_python','empty_python']:
    setattr(InstalledOutputTests,'test_stage_'+mode,stage_case(mode))
