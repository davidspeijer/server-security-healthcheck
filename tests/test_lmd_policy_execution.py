"""Policy status contracts at the real entrypoint; isolated data and transport."""
import json
import shutil
import unittest

import test_healthcheck as fixture
import test_lmd_production_budget as production_budget


class PolicyExecutionTests(unittest.TestCase):
    setUp = fixture.NativeLmdTests.setUp
    completion = fixture.NativeLmdTests.completion
    save = fixture.NativeLmdTests.save
    policy_shape = production_budget.ProductionBudgetTests.policy_shape
    main = fixture.HealthcheckTests.main
    run_shell = fixture.HealthcheckTests.run_shell

    def failure(self, function, body):
        self.policy_shape()
        self.completion()
        library = self.work / 'library'
        shutil.copytree(fixture.ROOT / 'lib', library)
        with (library / 'checks/lmd_policy.sh').open('a') as stream:
            stream.write('\n' + function + '() { ' + body + '; }\n')
        for enabled in [0, 1]:
            config = ('CHECK_LMD=1\nLMD_MONITOR_REQUIRED=0\n'
                      'LMD_CONFIG_CHECK_ENABLED=' + str(enabled) + '\n'
                      'LMD_SYSCONFIG_FILE=' + fixture.Q(str(self.envfile)) + '\n')
            for mode in [[], ['--json']]:
                with self.subTest(config_check=enabled, mode=mode):
                    result = self.main(config, mode, library)
                    self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                    if mode:
                        data = json.loads(result.stdout)
                        self.assertEqual(data['run']['exit_code'], 2)
                        findings = data['findings'] + [item for check in data['checks']
                                                      for item in check['findings']]
                        self.assertTrue(any(item['severity'].lower() == 'error' and
                                            'execution failed' in item['message']
                                            for item in findings))
                    else:
                        self.assertIn('ERROR LMD', result.stdout)
                        self.assertIn('execution failed', result.stdout)
                    self.assertNotIn('PASS LMD weekly full scan', result.stdout)

    def test_unexpected_explicit_parser_status_is_error(self):
        self.failure('_lmd_config_stream', 'return 7')

    def test_unexpected_generic_parser_failure_is_error(self):
        # Whole-file capture cannot legitimately return the lookup's no-key rc=1.
        self.failure('_lmd_config_stream', 'false')

    def test_unexpected_compatibility_computation_status_is_error(self):
        self.failure('_lmd_compat_compute', 'false')

    def test_unexpected_compatibility_source_lookup_is_error(self):
        self.failure('_lmd_config_get', 'return 7')

    def test_cached_literal_and_no_value_contracts(self):
        self.policy_shape()
        (self.lmd / 'conf.maldet').write_text(
            'present="first"\npresent="last"\nempty=""\n'
            'comment_only= # intentionally empty\nnonliteral="$dynamic"\n')
        (self.lmd / 'internals/compat.conf').write_text(
            'if [ ! "$alias" ] && [ "$missing_source" ]; then\n'
            'alias="$missing_source"\nfi\n')
        script = '''
LMD_POLICY_MAIN="$LMD_DIR/conf.maldet"
LMD_POLICY_COMPAT="$LMD_DIR/internals/compat.conf"
LMD_POLICY_CRON="$LMD_DIR/cron/conf.maldet.cron"
sysconfig=''' + fixture.Q(str(self.envfile)) + '''
default="$LMD_DEFAULT_FILE"
lmd_cache_active=1
lmd_compat_status=0
declare -A lmd_file_status=() lmd_key_status=() lmd_values=()
declare -A compat_state=() compat_value=() compat_changed=()
_lmd_policy_snapshot
for key in present absent empty comment_only nonliteral; do
    if value="$(_lmd_config_get "$LMD_POLICY_MAIN" "$key")"; then rc=0; else rc=$?; fi
    printf '%s:%s:%s\\n' "$key" "$rc" "$value"
done
if value="$(_lmd_compat_get "$LMD_POLICY_COMPAT" alias)"; then rc=0; else rc=$?; fi
printf 'alias:%s\\n' "$rc"
_lmd_policy_compare "$LMD_POLICY_MAIN" absent expected optional 1
printf 'errors:%s\\n' "$HC_ERRORS"
'''
        output = self.run_shell(script)
        self.assertEqual(output, 'present:0:last\nabsent:1:\nempty:0:\n'
                         'comment_only:2:\nnonliteral:2:\nalias:1\nerrors:0\n')

    def test_expected_absence_and_comment_only_hook_do_not_fail_execution(self):
        self.policy_shape()
        self.completion()
        (self.lmd / 'cron/custom.cron').write_text('# no commands\n')
        with (self.lmd / 'conf.maldet').open('a') as stream:
            stream.write('scan_workers= # empty literal\nemail_addr=""\n'
                         'email_subj="$unresolved"\n')
        for mode in [[], ['--json']]:
            result = self.main('CHECK_LMD=1\nLMD_MONITOR_REQUIRED=0\n'
                               'LMD_SYSCONFIG_FILE=' + fixture.Q(str(self.envfile)) + '\n', mode)
            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
            self.assertNotIn('execution failed', result.stdout + result.stderr)
            if mode:
                self.assertEqual(json.loads(result.stdout)['run']['exit_code'], 1)
            else:
                self.assertNotIn('ERROR', result.stdout)


if __name__ == '__main__':
    unittest.main()
