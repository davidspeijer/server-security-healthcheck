"""S01/S02: isolated production reporters, retained arrays and notifications."""
import json
import shutil
import subprocess
import unittest
import test_healthcheck as f
import test_ph11_registry as registry


class OutputBoundsTests(unittest.TestCase):
    setUp = f.HealthcheckTests.setUp
    main = f.HealthcheckTests.main

    def library(self, body):
        lib = self.work/'library'
        if lib.exists():
            shutil.rmtree(lib)
        shutil.copytree(f.ROOT/'lib', lib)
        registry.add_check(lib, body='hc_register_check mariadb\ncheck_mariadb() { '+body+'; return 0; }\n')
        return lib

    def shell(self, body):
        return subprocess.run(['bash', '-c', 'set -u; source '+f.Q(str(f.ROOT/'lib/common.sh'))+'; '+body],
                              env=self.env, capture_output=True, text=True, timeout=30)

    def test_known_secrets_overlap_and_literal_patterns(self):
        for token, chat in [('123:fixture_secret', '123'), ('a*[b]?', 'b'), ('short', 'longshortvalue')]:
            for template in ['{}', 'before {} after', '({}),{}!', '€ {} 😀']:
                with self.subTest(token=token, template=template):
                    message=template.format(token, token) if template.count('{}') == 2 else template.format(token)
                    message+=' / '+chat
                    result=self.shell('TELEGRAM_BOT_TOKEN='+f.Q(token)+'; TELEGRAM_CHAT_ID='+f.Q(chat)+'; hc_warn '+f.Q(message))
                    self.assertEqual(result.returncode,0,result.stderr)
                    self.assertNotIn(token,result.stdout+result.stderr)
                    self.assertNotIn(chat,result.stdout+result.stderr)
                    self.assertIn('[REDACTED]',result.stdout)

    def test_unset_empty_credentials_preserve_ordinary_output(self):
        for config in ['', "TELEGRAM_BOT_TOKEN=''; TELEGRAM_CHAT_ID=''; "]:
            result=self.shell(config+'hc_status PASS ordinary; hc_detail context; hc_warn warning; hc_status CRITICAL critical; hc_status ERROR error')
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertEqual(result.stdout,'  PASS ordinary\n  INFO context\n  WARNING warning\n  CRITICAL critical\n  ERROR error\n')

    def test_exact_secret_probe_all_channels(self):
        token='123:fixture_secret';chat='99887766'
        for mode in [[],['--json']]:
            for severity,code in [('WARNING',1),('CRITICAL',1),('ERROR',2)]:
                for fail in [False,True]:
                    with self.subTest(mode=mode,severity=severity,fail=fail):
                        journal=self.work/'snapshot';notification=self.work/'notification'
                        body='hc_status '+severity+' "Authorization: Bearer $TELEGRAM_BOT_TOKEN / $TELEGRAM_CHAT_ID"'
                        if mode:body+='; cp "$HC_JSON_FILE" '+f.Q(str(journal))
                        lib=self.library(body)
                        (lib/'notify/telegram.sh').write_text('notify_telegram() { printf "%s" "$1" > '+f.Q(str(notification))+'; return '+('7' if fail else '0')+'; }\nnotify_test() { return 0; }\n')
                        result=self.main('CHECK_MARIADB=1\nNOTIFY_TELEGRAM=1\nTELEGRAM_BOT_TOKEN='+token+'\nTELEGRAM_CHAT_ID='+chat+'\n',mode,lib)
                        self.assertEqual(result.returncode,2 if fail else code,result.stderr)
                        channels=[result.stdout,result.stderr,notification.read_text()]
                        if mode:
                            data=json.loads(result.stdout)
                            self.assertEqual(data['run']['exit_code'],result.returncode)
                            channels.append(journal.read_text())
                        for value in channels:
                            self.assertNotIn(token,value);self.assertNotIn(chat,value)
                        self.assertIn('[REDACTED]',notification.read_text())
                        self.assertIn('[REDACTED]',result.stdout)
                        if fail:self.assertIn('[REDACTED]',result.stderr)

    def test_count_bound_and_late_severity(self):
        for count in [999,1000,1001]:
            for late,expected in [('WARNING',1),('CRITICAL',1),('ERROR',2)]:
                with self.subTest(count=count,late=late):
                    observed=self.work/'observed'
                    lib=self.library('for ((i=0;i<'+str(count)+';i++)); do hc_detail ordinary; done; hc_status '+late+' late; printf "%s,%s,%s,%s" "$HC_RESULTS_MESSAGES" "${#HC_DETAILS[@]}" "$HC_CRITICAL_COUNT" "$HC_ERRORS" > '+f.Q(str(observed)))
                    result=self.main('CHECK_MARIADB=1\n',['--json'],lib)
                    data=json.loads(result.stdout)
                    self.assertEqual(result.returncode,expected)
                    self.assertEqual(data['run']['exit_code'],expected)
                    self.assertEqual(data['summary']['info'],count)
                    self.assertEqual(data['summary'][late.lower()],1)
                    self.assertEqual(next(c for c in data['checks'] if c['id']=='mariadb')['status'],late.lower())
                    self.assertEqual(data['truncated'],count>=1000)
                    messages,details,critical,error=map(int,observed.read_text().split(','))
                    self.assertEqual(messages,min(count+1,1000));self.assertEqual(details,min(count,1000))
                    self.assertEqual(critical,int(late=='CRITICAL'));self.assertEqual(error,int(late=='ERROR'))

    def test_actual_p2_probe_and_notification_bound(self):
        observed=self.work/'observed';notification=self.work/'notification'
        lib=self.library('for ((i=0;i<1001;i++)); do hc_detail '+f.Q('x'*5000)+'; done; hc_status CRITICAL latecritical; hc_status ERROR lateerror; printf "%s,%s,%s,%s" "$HC_RESULTS_MESSAGES" "$HC_RESULTS_BYTES" "${#HC_DETAILS[@]}" "${#HC_DETAILS[0]}" > '+f.Q(str(observed)))
        (lib/'notify/telegram.sh').write_text('notify_telegram() { printf "%s" "$1" > '+f.Q(str(notification))+'; }\nnotify_test() { return 0; }\n')
        result=self.main('CHECK_MARIADB=1\nNOTIFY_TELEGRAM=1\n',['--json'],lib);data=json.loads(result.stdout)
        self.assertEqual(result.returncode,2);self.assertEqual(data['summary']['info'],1001)
        self.assertEqual(data['summary']['critical'],1);self.assertEqual(data['summary']['error'],1)
        self.assertTrue(data['truncated'])
        messages,size,details,width=map(int,observed.read_text().split(','))
        self.assertLessEqual(messages,1000);self.assertLessEqual(size,3932160)
        self.assertLess(details,1001);self.assertEqual(width,4096)
        self.assertLessEqual(notification.stat().st_size,16384)
        self.assertIn('critical=1 errors=1',notification.read_text())
        self.assertIn('truncated',notification.read_text())

    def test_total_budget_under_exact_above(self):
        for size,expected in [(13,0),(14,0),(15,1)]:
            result=self.shell('HC_RESULTS_MAX_BYTES=14; hc_warn '+f.Q('x'*(size-8))+'; printf "bytes=%s truncated=%s count=%s" "$HC_RESULTS_BYTES" "$HC_RESULTS_TRUNCATED" "$HC_WARNING_COUNT"')
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertIn('truncated='+str(expected)+' count=1',result.stdout)
            self.assertIn('bytes='+str(size if not expected else 0),result.stdout)

    def test_unicode_byte_boundary_and_codepoint_cases(self):
        locales=subprocess.check_output(['locale','-a'],text=True).splitlines()
        utf=next((x for x in locales if 'utf' in x.lower()),'C.UTF-8')
        for locale in ['C',utf]:
            self.env['LC_ALL']=locale
            for character in ['x','€','😀','e\u0301']:
                for size in [1023,1024,1025]:
                    message=(character*1025)[:size]
                    with self.subTest(locale=locale,character=character,size=size):
                        raw=message.encode();expected=raw[:4096].decode('utf-8','ignore')
                        result=self.shell('hc_warn '+f.Q(message)+'; printf "%s" "${HC_WARNINGS[0]}"')
                        self.assertEqual(result.returncode,0,result.stderr)
                        self.assertEqual(result.stdout,'  WARNING '+expected+'\nWARNING '+expected)
                        self.assertNotIn('\ufffd',result.stdout)

    def test_notification_utf8_bound(self):
        result=self.shell("message=''; chunk="+f.Q('€'*5000)+'; for ((i=0;i<10;i++)); do hc_summary_append "$chunk"; done; printf "%s" "$message"')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertLessEqual(len(result.stdout.encode()),16128)
        self.assertNotIn('\ufffd',result.stdout)

    def test_secrets_with_output_and_helper_failures(self):
        for failure in ['journal','renderer','helper']:
            with self.subTest(failure=failure):
                lib=self.library('hc_warn "$TELEGRAM_BOT_TOKEN / $TELEGRAM_CHAT_ID"')
                if failure=='journal':
                    target=self.work/'directory';target.mkdir(exist_ok=True)
                    h=lib/'output.sh';h.write_text(h.read_text().replace('hc_json_record() {','hc_original_record() {',1)+'\nhc_json_record() { if [ "$1" = counts ]; then printf failure >> '+f.Q(str(target))+' || HC_JSON_FAILED=1; else hc_original_record "$@"; fi; }\n')
                elif failure=='renderer':
                    h=lib/'checks/output.py';h.write_text(h.read_text()+"\nif len(sys.argv)>1 and sys.argv[1]=='render':\n    sys.stdout.flush(); sys.exit(7)\n")
                else:(lib/'checks/lmd_policy.sh').unlink()
                result=self.main('CHECK_MARIADB=1\n'+('CHECK_LMD=1\n' if failure=='helper' else '')+'TELEGRAM_BOT_TOKEN=123:fixture_secret\nTELEGRAM_CHAT_ID=99887766\n',['--json'],lib)
                self.assertEqual(result.returncode,2)
                self.assertNotIn('fixture_secret',result.stdout+result.stderr)
                self.assertNotIn('99887766',result.stdout+result.stderr)
                self.assertIn('[REDACTED]',result.stderr)
                if failure!='helper':self.assertEqual(result.stdout,'')

    def test_text_exitcode_after_presentation_exhaustion(self):
        for level,code in [('WARNING',1),('CRITICAL',1),('ERROR',2)]:
            lib=self.library('for ((i=0;i<1001;i++)); do hc_detail context; done; hc_status '+level+' late')
            result=self.main('CHECK_MARIADB=1\n',[],lib)
            self.assertEqual(result.returncode,code)
            self.assertIn('Presentation truncated',result.stdout)
            self.assertNotIn('OK all enabled checks passed',result.stdout)
            if level=='CRITICAL':self.assertIn('critical=1',result.stderr)
            if level=='ERROR':self.assertIn('errors=1',result.stderr)

    def test_escaped_bytes_and_complete_counters(self):
        result=self.shell('HC_RESULTS_MAX_BYTES=12; hc_warn '+f.Q('\x01'*5)+'; hc_detail context; printf "bytes=%s warning=%s info=%s truncated=%s" "$HC_RESULTS_BYTES" "${HC_RESULT_COUNTS[WARNING]}" "${HC_RESULT_COUNTS[INFO]}" "$HC_RESULTS_TRUNCATED"')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(result.stdout,'  INFO context\nbytes=12 warning=1 info=1 truncated=1')

    def test_secret_redaction_precedes_truncation(self):
        result=self.shell('TELEGRAM_BOT_TOKEN=123:fixture_secret; TELEGRAM_CHAT_ID=99887766; hc_warn '+f.Q('x'*4000+' 123:fixture_secret / 99887766 '+'€'*5000)+'; printf "truncated=%s" "$HC_RESULTS_TRUNCATED"')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertNotIn('fixture_secret',result.stdout+result.stderr)
        self.assertNotIn('99887766',result.stdout+result.stderr)
        self.assertIn('[REDACTED]',result.stdout)
        self.assertIn('truncated=1',result.stdout)
        self.assertNotIn('\ufffd',result.stdout)

    def test_config_failure_does_not_echo_raw_line(self):
        for args in [[],['--json']]:
            result=self.main('TELEGRAM_BOT_TOKEN=123:fixture_secret\nTELEGRAM_CHAT_ID=99887766\nbroken 123:fixture_secret / 99887766\n',args)
            self.assertEqual(result.returncode,2)
            self.assertNotIn('fixture_secret',result.stdout+result.stderr)
            self.assertNotIn('99887766',result.stdout+result.stderr)
