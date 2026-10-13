"""JSON contract against isolated real entrypoint and Python renderer."""
import importlib.util
import json
import subprocess
import unittest
from unittest import mock
import test_healthcheck as fixture
import test_ph11_registry as registry

spec = importlib.util.spec_from_file_location('output', str(fixture.ROOT/'lib/checks/output.py'))
output = importlib.util.module_from_spec(spec)
spec.loader.exec_module(output)


class JsonTests(unittest.TestCase):
    setUp = fixture.HealthcheckTests.setUp
    main = fixture.HealthcheckTests.main

    def run_json(self, body=None, config='', args=('--json',)):
        library = None
        if body is not None:
            library = registry.RegistryRuntimeTests.library(self)
            self.module.write_text('hc_register_check mariadb\ncheck_mariadb() { '+body+'; return 0; }\n')
            config += 'CHECK_MARIADB=1\n'
        result = self.main(config, args=args, lib_dir=library)
        data = json.loads(result.stdout)
        self.assertEqual(data['run']['exit_code'], result.returncode)
        self.assertNotIn('fixture_secret', result.stdout)
        return result, data

    def check(self, data):
        return next(c for c in data['checks'] if c['id'] == 'mariadb')

    def test_schema(self):
        result, data = self.run_json('hc_status PASS healthy')
        self.assertEqual(result.returncode, 0)
        self.assertEqual(set(data), {'schema_version','application','run','host','summary','checks','findings','truncated'})
        self.assertEqual(data['schema_version'], 1)
        self.assertEqual(data['application']['name'], 'server-security-healthcheck')
        self.assertEqual(data['application']['version'], '1.1.0')
        self.assertEqual(data['host']['hostname'], 'fixture.example')
        for obj in [data['run'], self.check(data)]:
            for key in ['started_at','finished_at']:
                self.assertRegex(obj[key], r'^\d{4}-\d\d-\d\dT.*\+00:00$')
            self.assertIsInstance(obj['duration_ms'], int)
            self.assertGreaterEqual(obj['duration_ms'], 0)
        self.assertEqual(data['summary']['pass'], 1)
        self.assertEqual(data['summary']['total'], 1)
        self.assertEqual(self.check(data)['findings'][0]['details'], {})

    def test_raw_escaping(self):
        message='newline\nquote" backslash\\ Unicode café \x01 {"run":{"exit_code":0}}'
        _, data = self.run_json('hc_warn '+fixture.Q(message))
        self.assertEqual(self.check(data)['findings'][0]['message'], message)

    def test_stdout_not_mixed(self):
        _, data = self.run_json('value="$(hc_warn child_result)"; printf "unstructured presentation\\n"; hc_warn fixture')
        self.assertEqual(data['run']['status'], 'warning')
        self.assertEqual(data['summary']['warning'],1)
        self.assertEqual(len(self.check(data)['findings']),1)

    def test_not_applicable(self):
        _, data = self.run_json('HC_NOT_APPLICABLE=$((HC_NOT_APPLICABLE+1)); hc_detail "NOT_APPLICABLE: fixture"')
        self.assertEqual(self.check(data)['status'], 'not_applicable')

    def test_disabled(self):
        _, data = self.run_json()
        self.assertTrue(all(c['status']=='skipped' for c in data['checks']))

    def test_missing_module(self):
        library = registry.RegistryRuntimeTests.library(self)
        self.module.unlink()
        result = self.main('CHECK_MARIADB=1\n', ['--json'], library)
        data = json.loads(result.stdout)
        self.assertEqual(result.returncode, 2)
        check = self.check(data)
        self.assertEqual(check['status'], 'error')
        self.assertIsNone(check['started_at'])
        self.assertEqual(check['duration_ms'], 0)

    def test_invalid_config(self):
        result, data = self.run_json(config='CHECK_DOES_NOT_EXIST=1\n')
        self.assertEqual(result.returncode, 2)
        self.assertEqual(data['run']['status'], 'error')

    def test_multiple_checks(self):
        library = registry.RegistryRuntimeTests.library(self)
        registry.add_check(library, 'other', body='hc_register_check other\ncheck_other() { hc_status PASS second; }\n')
        result = self.main('CHECK_MARIADB=1\nCHECK_OTHER=1\n', ['--json'], library)
        data=json.loads(result.stdout)
        self.assertEqual([c['id'] for c in data['checks']][-2:], ['mariadb','other'])
        self.assertTrue(all(c['started_at'] for c in data['checks'][-2:]))

    def test_secret_redaction(self):
        _, data=self.run_json('hc_warn "$TELEGRAM_BOT_TOKEN"', 'TELEGRAM_BOT_TOKEN=123:fixture_secret\n')
        self.assertEqual(self.check(data)['findings'][0]['message'], '[REDACTED]')

    def test_truncation(self):
        _, data=self.run_json('hc_warn '+fixture.Q('x'*5000))
        self.assertTrue(data['truncated'])
        self.assertLessEqual(len(self.check(data)['findings'][0]['message']),1024)

    def test_event_budget(self):
        _, data=self.run_json('for ((i=0;i<1005;i++)); do hc_status WARNING fixture; done')
        self.assertTrue(data['truncated'])
        self.assertEqual(data['summary']['warning'],1005)
        self.assertEqual(len(self.check(data)['findings']),1000)

    def test_omitted_error_keeps_severity(self):
        result, data=self.run_json('for ((i=0;i<1001;i++)); do hc_warn fixture; done; hc_status ERROR failure')
        self.assertEqual(result.returncode,2)
        self.assertEqual(self.check(data)['status'],'error')
        self.assertEqual(data['summary']['error'],1)
        self.assertTrue(data['truncated'])

    def test_nonzero_execution_timed(self):
        result, data=self.run_json('return 7')
        self.assertEqual(result.returncode,2)
        self.assertEqual(self.check(data)['status'],'error')
        self.assertIsNotNone(self.check(data)['finished_at'])

    def test_unexpected_exit_zero(self):
        result,data=self.run_json('exit 0')
        self.assertEqual(self.check(data)['status'],'error')
        self.assertEqual(result.returncode,2)
        self.assertEqual(data['run']['status'],'error')

    def test_unexpected_exit_one(self):
        result,data=self.run_json('exit 1')
        self.assertEqual(result.returncode,2)
        self.assertEqual(data['run']['status'],'error')

    def test_missing_backend(self):
        library=registry.RegistryRuntimeTests.library(self)
        (library/'notify/telegram.sh').unlink()
        result=self.main('NOTIFY_TELEGRAM=1\n',['--json'],library)
        data=json.loads(result.stdout)
        self.assertEqual(result.returncode,2)
        self.assertEqual(data['run']['exit_code'],2)

    def test_json_combinations_rejected(self):
        for flag in ['--version','--test-notification','--help']:
            with self.subTest(flag=flag):
                result,data=self.run_json(args=('--json',flag))
                self.assertEqual(result.returncode,2)

    def test_reverse_combination_rejected(self):
        result=self.main('', ['--version','--json'])
        self.assertEqual(result.returncode,2)

    def test_timing_failure(self):
        library = registry.RegistryRuntimeTests.library(self)
        helper=library/'checks/output.py'
        with helper.open('a') as stream:
            stream.write('\n')
        # A malformed clock response is never accepted as healthy.
        original=helper.read_text()
        helper.write_text(original.replace("print('{}|{}'.format(stamp, tick))", "print('broken')"))
        result=self.main('CHECK_MARIADB=1\n',['--json'],library)
        self.assertEqual(result.returncode,2)
        self.assertIn('timing helper failed',result.stderr)
        self.assertEqual(json.loads(result.stdout)['run']['exit_code'],2)

    def test_notification_failure(self):
        library=registry.RegistryRuntimeTests.library(self)
        (library/'notify/telegram.sh').write_text('notify_telegram() { return 7; }\nnotify_test() { return 7; }\n')
        result=self.main('CHECK_MARIADB=1\nNOTIFY_TELEGRAM=1\n',['--json'],library)
        data=json.loads(result.stdout)
        self.assertEqual(result.returncode,2)
        self.assertEqual(data['run']['status'],'error')


CASES=[('healthy','hc_status PASS verified','pass',0),
       ('info','hc_detail context','info',0),
       ('warning','hc_warn finding','warning',1),
       ('critical','hc_status CRITICAL finding','critical',1),
       ('error','hc_status ERROR failure','error',2),
       ('warning_error','hc_warn finding; hc_status ERROR failure','error',2),
       ('critical_error','hc_status CRITICAL finding; hc_status ERROR failure','error',2),
       ('discovery_failure','hc_service_present fixture missing_binary || true','error',2)]
def matrix(body,status,code):
    def test(self):
        result,data=self.run_json(body)
        self.assertEqual(result.returncode,code)
        self.assertEqual(self.check(data)['status'],status)
        self.assertEqual(data['summary']['total'],sum(data['summary'][k] for k in output.LEVELS))
    return test
for name,body,status,code in CASES:
    setattr(JsonTests,'test_status_'+name,matrix(body,status,code))


class ClockTests(unittest.TestCase):
    def test_monotonic_clock(self):
        with mock.patch.object(output.time,'monotonic',return_value=12.25):
            self.assertEqual(output.clock()[1],12250000000)
    def test_wall_jump(self):
        # Join fields explicitly: octal escape ambiguity cannot alter the fixture.
        raw='\0'.join(['run-start','','2026-10-13T20:00:00+00:00','1000000000','run-end','','2026-10-12T20:00:00+00:00','2500000000','counts','','','0,0,0,0,0',''])
        data=output.render(raw.encode(),'fixture','1.0.0',0,'host')
        self.assertEqual(data['run']['duration_ms'],1500)
    def test_invalid_unicode(self):
        raw='\0'.join(['run-start','','stamp','1','finding','','INFO','bad','run-end','','stamp','2','counts','','','0,1,0,0,0','']).encode().replace(b'bad',b'\xff')
        self.assertIn('\ufffd',output.render(raw,'fixture','1',0,'host')['findings'][0]['message'])
