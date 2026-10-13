"""Synthetic production-shaped policy inputs; never copy production contents."""
import json
import shutil
import subprocess
import unittest
from pathlib import Path
from datetime import datetime, timezone
import test_healthcheck as f


def padded(lines, count, size, maximum):
    lines=list(lines)
    first=len(lines)
    lines.extend(['#']*(count-len(lines)))
    remaining=size-sum(len(x)+1 for x in lines)
    for i in range(first,count):
        n=min(maximum-1,remaining) if i==first else min(maximum-1,(remaining+count-i-1)//(count-i))
        lines[i]+='x'*n;remaining-=n
    assert remaining==0
    text='\n'.join(lines)+'\n'
    assert len(text)==size and len(text.splitlines())==count
    return text


class ProductionBudgetTests(unittest.TestCase):
    setUp=f.NativeLmdTests.setUp
    save=f.NativeLmdTests.save
    completion=f.NativeLmdTests.completion
    run_shell=f.HealthcheckTests.run_shell
    main=f.HealthcheckTests.main

    def policy_shape(self):
        base=['old_setting_%02d=1'%i for i in range(42)]+['cron_prune_days=21']
        compat=[]
        for i in range(42):
            a='new_setting_%02d'%i;b='old_setting_%02d'%i
            compat+=['if [ ! "$'+a+'" ] && [ "$'+b+'" ]; then',a+'="$'+b+'"','fi']
        (self.lmd/'internals').mkdir(exist_ok=True);(self.lmd/'cron').mkdir(exist_ok=True)
        (self.lmd/'conf.maldet').write_text(padded(base,603,25475,144))
        (self.lmd/'internals/compat.conf').write_text(padded(compat,150,5357,80))
        (self.lmd/'cron/conf.maldet.cron').write_text(padded(['autoupdate_version=0'],12,385,75))
        self.envfile=self.work/'environment';self.envfile.write_text('fixture=1\n')
        return 'LMD_SYSCONFIG_FILE='+f.Q(str(self.envfile))+'\n'

    def test_production_shape_retention_reads_each_source_once(self):
        config=self.policy_shape();calls=self.work/'reads'
        code=config+'\neval "$(declare -f hc_data_parse | sed \'1s/hc_data_parse/hc_original_data_parse/\')"\nhc_data_parse() { printf "%s\\n" "$2" >> '+f.Q(str(calls))+'; hc_original_data_parse "$@"; }\n_lmd_session_retention_days\n'
        output=self.run_shell(code)
        self.assertEqual(output,'21')
        rows=calls.read_text().splitlines()
        self.assertEqual(len(rows),4)
        self.assertEqual(len(set(rows)),4)
        self.assertEqual(rows.count(str(self.lmd/'conf.maldet')),1)

    def test_production_equivalent_native_history_completes(self):
        config=self.policy_shape();rows=[]
        for i,days in enumerate([35,34,33,32,31,30,29,6,5,2]):
            row=self.row[:];head=self.header[:];identifier='260920-0030.'+str(1000+i)
            start=f.NOW-days*86400;end=start+3600
            stamp=lambda t:datetime.fromtimestamp(t,timezone.utc).strftime('%b %d %Y %H:%M:%S %z')
            row[0]=head[2]=identifier;row[1]=str(start);row[2]=head[6]=stamp(start)
            row[3]=head[8]='3600';row[11]=head[7]=stamp(end)
            if i<3:row[8]=head[4]='/synthetic/partial'
            rows.append('\t'.join(row))
            if i>=7:
                (self.lmd/('sess/session.tsv.'+identifier)).write_text('\t'.join(head)+'\n')
                if i>=8:(self.lmd/('sess/scan.meta.'+identifier)).write_text('path='+row[8]+'\nstarted='+str(start)+'\ncompleted='+str(end)+'\nstate=completed\n')
        self.session.unlink();self.index.write_text('#LMD_INDEX:v2\n'+'\n'.join(rows)+'\n')
        for i in range(25):(self.lmd/('sess/session.tsv.260901-0000.'+str(i))).write_text('# synthetic unrelated retained report\n')
        output=self.run_shell(config+'LMD_EXPECT_QUARANTINE_ENABLED=1\n_lmd_check_fullscan\nprintf "errors=%s" "$HC_ERRORS"')
        self.assertNotIn('budget exceeded',output);self.assertIn('errors=0',output)
        self.assertIn('PASS LMD weekly full scan completed',output)
        self.assertIn('outside daily retention',output)

    def test_native_deadline_under_exact_above(self):
        self.completion()
        for elapsed,code in [(19,0),(20,2),(21,2)]:
            with self.subTest(elapsed=elapsed):
                body='eval "$(declare -f hc_budget_expired | sed \'1s/hc_budget_expired/hc_real_budget/\')"\nhc_budget_expired() { if [ "${FUNCNAME[1]}" = _lmd_native_records ]; then SECONDS=$(($1+'+str(elapsed)+')); fi; hc_real_budget "$@"; }\n_lmd_check_fullscan\n[ "$HC_ERRORS" = 0 ] || exit 2'
                output=self.run_shell(body,expected=code)
                if code:
                    self.assertIn('time='+str(elapsed)+'s limit=20s; session metadata records=0',output)
                    self.assertNotIn('PASS LMD weekly full scan',output)
                else:self.assertNotIn('ERROR',output)

    def test_native_deadline_real_entrypoint_exit_two(self):
        lib=self.work/'library';shutil.copytree(f.ROOT/'lib',lib)
        common=lib/'common.sh';common.write_text(common.read_text()+'\nhc_budget_expired() { [ "${FUNCNAME[1]}" = _lmd_native_records ]; }\n')
        result=self.main('CHECK_LMD=1\nLMD_CONFIG_CHECK_ENABLED=0\nLMD_MONITOR_REQUIRED=0\n',['--json'],lib)
        data=json.loads(result.stdout)
        self.assertEqual(result.returncode,2);self.assertEqual(data['run']['exit_code'],2)
        events=data['findings']+[x for c in data['checks'] for x in c['findings']]
        self.assertTrue(any('session metadata records=0' in x['message'] for x in events))

    def test_policy_budget_failure_remains_unknown_and_native_error(self):
        config=self.policy_shape()
        output=self.run_shell(config+'hc_budget_expired() { return 0; }\n_lmd_native_records '+f.Q(str(self.lmd/'sess'))+' '+f.Q(str(self.work))+' '+f.Q(self.row[8])+' '+str(f.NOW)+'\n[ "$HC_ERRORS" = 0 ] || exit 2',expected=2)
        self.assertIn('ERROR LMD native parsing budget exceeded',output)

    def test_expected_missing_policy_keys_are_not_execution_failure(self):
        self.policy_shape();self.completion()
        (self.lmd/'cron/custom.cron').write_text('# intentionally no commands\n')
        result=self.main('CHECK_LMD=1\nLMD_SYSCONFIG_FILE='+f.Q(str(self.envfile))+'\nLMD_MONITOR_REQUIRED=0\n')
        self.assertEqual(result.returncode,1,result.stdout+result.stderr)
        self.assertNotIn('Check execution failed',result.stdout+result.stderr)
        self.assertIn('WARNING',result.stdout) # Missing required policies remain findings.

    def test_retention_configuration_read_budget_is_error(self):
        config=self.policy_shape()
        output=self.run_shell(config+'export SSHC_MAX_FILE_BYTES=1000\n_lmd_check_fullscan\n[ "$HC_ERRORS" = 0 ] || exit 2',expected=2)
        self.assertIn('ERROR LMD native retention policy input UNKNOWN: read/resource budget failure',output)
        self.assertNotIn('PASS LMD weekly full scan',output)

    def test_snapshot_file_limit_boundaries(self):
        self.completion()
        size=max(p.stat().st_size for p in (self.lmd/'sess').iterdir())
        for budget,code in [(size-1,2),(size,0),(size+1,0)]:
            with self.subTest(budget=budget):
                output=self.run_shell('export SSHC_MAX_FILE_BYTES='+str(budget)+'\n_lmd_check_fullscan\n[ "$HC_ERRORS" = 0 ] || exit 2',expected=code)
                if code:self.assertIn('ERROR LMD metadata input UNKNOWN',output)
                else:self.assertNotIn('ERROR',output)


class CoveragePresentationTests(unittest.TestCase):
    setUp=f.HealthcheckTests.setUp
    main=f.HealthcheckTests.main

    def test_all_output_modes_use_separate_safe_findings(self):
        home=self.work/'home';site=home/'user/domains/example.invalid/public_html';site.mkdir(parents=True)
        monitored=self.work/'monitored';monitored.write_text(str(site)+'\n')
        lib=self.work/'library';shutil.copytree(f.ROOT/'lib',lib)
        with (lib/'checks/lmd.sh').open('a') as stream:stream.write('\ncheck_lmd() { _lmd_check_webroots; hc_warn fixture; }\n')
        payload=self.work/'notification'
        (lib/'notify/telegram.sh').write_text('notify_telegram() { printf "%s" "$1" > '+f.Q(str(payload))+'; }\nnotify_test() { return 0; }\n')
        conf='CHECK_LMD=1\nCHECK_DIRECTADMIN_WEBROOTS=1\nDIRECTADMIN_HOME='+f.Q(str(home))+'\nLMD_MONITOR_LIST='+f.Q(str(monitored))+'\nNOTIFY_TELEGRAM=1\nTELEGRAM_BOT_TOKEN=123:fixture_secret\nTELEGRAM_CHAT_ID=99887766\n'
        expected=['LMD coverage expected: 1','LMD coverage configured: 1','LMD coverage missing: 0','LMD coverage stale: 0']
        for mode in [[],['--json']]:
            result=self.main(conf,mode,lib);self.assertEqual(result.returncode,1,result.stderr)
            text=result.stdout if not mode else '\n'.join(e['message'] for c in json.loads(result.stdout)['checks'] for e in c['findings'])
            for channel in [text,payload.read_text()]:
                for message in expected:self.assertIn(message,channel)
                self.assertNotIn('\\n',channel);self.assertNotIn('fixture_secret',channel);self.assertNotIn('99887766',channel)
            self.assertLessEqual(payload.stat().st_size,16384)
