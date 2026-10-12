"""PH11: explicit registry, isolated runtime and staged installation contracts."""
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import unittest
import test_healthcheck as fixture
import test_audit_round3 as installers

ROOT = fixture.ROOT
Q = shlex.quote


def add_check(root, name='mariadb', body=None, default='0'):
    registry = root/'checks.registry'
    with registry.open('a') as stream:
        stream.write('{}|checks/{}.sh|check_{}|CHECK_{}|{}|custom|-\n'.format(name, name, name, name.upper(), default))
    module = root/'checks'/ (name+'.sh')
    module.write_text(body if body is not None else
                     'hc_register_check '+name+'\ncheck_'+name+'() { hc_warn "'+name+': deterministic finding"; return 0; }\n')
    return module


class RegistryRuntimeTests(unittest.TestCase):
    setUp = fixture.HealthcheckTests.setUp
    main = fixture.HealthcheckTests.main

    def library(self):
        library=self.work/'library'
        shutil.copytree(ROOT/'lib',library)
        self.library_root=library
        self.module=add_check(library)
        return library

    def run_custom(self, extra='', library=None):
        return self.main('CHECK_MARIADB=1\n'+extra, lib_dir=library or self.library_root)

    def error(self, result, cause=None):
        self.assertEqual(result.returncode,2,result.stdout+result.stderr)
        self.assertIn('ERROR',result.stdout+result.stderr)
        self.assertNotIn('OK all enabled checks passed',result.stdout)
        if cause: self.assertIn(cause,result.stdout+result.stderr)

    def test_original_A_registered_module_absent(self):
        self.library(); self.module.unlink(); self.error(self.run_custom(),'module missing')

    def test_original_B_registered_finding(self):
        self.library(); result=self.run_custom()
        self.assertEqual(result.returncode,1,result.stdout+result.stderr)
        self.assertIn('mariadb: deterministic finding',result.stdout)
        self.assertNotIn('OK all enabled checks passed',result.stdout)

    def test_old_guide_unknown_enabled_key(self):
        library=self.library(); registry=library/'checks.registry'
        registry.write_text('\n'.join(line for line in registry.read_text().splitlines() if not line.startswith('mariadb|'))+'\n')
        self.error(self.run_custom(),'unknown configuration key CHECK_MARIADB')

    def test_legacy_allowlist_without_registry_cannot_enable_check(self):
        library=self.library(); self.module.unlink(); registry=library/'checks.registry'
        registry.write_text('\n'.join(line for line in registry.read_text().splitlines() if not line.startswith('mariadb|'))+'\n')
        common=library/'common.sh'
        common.write_text(common.read_text().replace('LOOKBACK_HOURS|NOTIFY_TELEGRAM|','CHECK_MARIADB|LOOKBACK_HOURS|NOTIFY_TELEGRAM|'))
        self.error(self.run_custom(),'no check registry entry')

    def test_compatibility_alias_requires_registry_entry(self):
        library=self.library(); registry=library/'checks.registry'
        registry.write_text('\n'.join(line for line in registry.read_text().splitlines() if not line.startswith('lmd|'))+'\n')
        config=self.work/'alias.conf'; config.write_text('LMD_ENABLED=1\n')
        code='source '+Q(str(library/'common.sh'))+'; hc_load_config '+Q(str(config))+' || exit 2'
        result=subprocess.run(['bash','-c',code],env=self.env,text=True,capture_output=True,timeout=10)
        self.error(result,'compatibility alias lacks')

    def test_unknown_check_key(self):
        self.library(); self.error(self.run_custom('CHECK_DOES_NOT_EXIST=1\n'),'unknown configuration key')

    def test_custom_disabled_missing_allowed(self):
        library=self.library(); self.module.unlink()
        result=self.main('CHECK_MARIADB=0\n',lib_dir=library)
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)

    def test_auto_requires_module(self):
        library=self.library(); self.module.unlink()
        self.error(self.main('CHECK_MARIADB=auto\n',lib_dir=library))

    def test_auto_executes_registered_discovery(self):
        library=self.library()
        result=self.main('CHECK_MARIADB=auto\n',lib_dir=library)
        self.assertEqual(result.returncode,1,result.stdout+result.stderr)

    def test_custom_syntax_error(self):
        self.library(); self.module.write_text('check_mariadb() {\n'); self.error(self.run_custom(),'syntax error')

    def test_custom_source_failure(self):
        self.library(); self.module.write_text('return 1\n'); self.error(self.run_custom(),'source failed')

    def test_missing_source_dependency_not_masked(self):
        self.library(); self.module.write_text('source "'+str(self.work/'missing hidden helper')+'"\nhc_register_check mariadb\ncheck_mariadb() { :; }\n')
        self.error(self.run_custom(),'source failed')

    def test_hidden_helper_execution_failure_not_masked(self):
        self.library(); self.module.write_text('hc_register_check mariadb\ncheck_mariadb() { missing_hidden_helper; return 0; }\n')
        self.error(self.run_custom(),'Check execution failed')

    def test_missing_function(self):
        self.library(); self.module.write_text('hc_register_check mariadb\n'); self.error(self.run_custom(),'function missing')

    def test_function_not_registered(self):
        self.library(); self.module.write_text('check_mariadb() { :; }\n'); self.error(self.run_custom(),'not registered')

    def test_wrong_function_provenance(self):
        self.library(); helper=self.work/'helper.sh'; helper.write_text('check_mariadb() { :; }\n')
        self.module.write_text('source '+Q(str(helper))+'\nhc_register_check mariadb\n')
        self.error(self.run_custom(),'provenance')

    def test_later_check_redefines_function(self):
        library=self.library(); add_check(library,'other','hc_register_check other\ncheck_other() { :; }\ncheck_mariadb() { :; }\n')
        self.error(self.run_custom('CHECK_OTHER=1\n'),'unexpected module')

    def test_required_check_not_executed(self):
        library=self.library(); add_check(library,'other','hc_register_check other\ncheck_other() { :; }\nHC_REGISTERED_CHECKS=(other)\n')
        self.error(self.run_custom('CHECK_OTHER=1\n'),'Required check not executed: mariadb')

    def test_multiple_custom_one_missing(self):
        library=self.library(); add_check(library,'other').unlink()
        result=self.run_custom('CHECK_OTHER=1\n'); self.error(result)
        self.assertIn('mariadb: deterministic finding',result.stdout)

    def test_builtin_and_custom(self):
        library=self.library(); (library/'checks/disk.sh').write_text('hc_register_check disk\ncheck_disk() { hc_status PASS "builtin fixture"; }\n')
        result=self.run_custom('CHECK_DISK=1\n')
        self.assertEqual(result.returncode,1,result.stdout+result.stderr); self.assertIn('builtin fixture',result.stdout)

    def test_builtin_missing_custom_still_executes(self):
        library=self.library(); (library/'checks/disk.sh').unlink()
        result=self.run_custom('CHECK_DISK=1\n'); self.error(result); self.assertIn('deterministic finding',result.stdout)

    def test_unregistered_helper_not_executed(self):
        library=self.library(); marker=self.work/'untrusted-executed'
        (library/'checks/untrusted.sh').write_text('touch '+Q(str(marker))+'\nexit 0\n')
        result=self.run_custom(); self.assertEqual(result.returncode,1,result.stdout+result.stderr); self.assertFalse(marker.exists())

    def test_duplicate_registry_key(self):
        library=self.library(); registry=library/'checks.registry'
        registry.write_text(registry.read_text()+'other|checks/other.sh|check_other|CHECK_MARIADB|0|custom|-\n')
        self.error(self.run_custom(),'Invalid registry')

    def test_registry_shell_injection_is_data(self):
        library=self.library(); marker=self.work/'injected'; registry=library/'checks.registry'
        registry.write_text(registry.read_text()+'$(touch '+str(marker)+')|checks/other.sh|check_other|CHECK_OTHER|0|custom|-\n')
        self.error(self.run_custom()); self.assertFalse(marker.exists())

    def test_registry_path_traversal(self):
        library=self.library(); registry=library/'checks.registry'
        registry.write_text(registry.read_text().replace('checks/mariadb.sh','checks/../../mariadb.sh'))
        self.error(self.run_custom(),'Invalid')

    def test_missing_registry(self):
        library=self.library(); (library/'checks.registry').unlink(); self.error(self.run_custom(),'registry')


class RegistryInstallerTests(installers.Base):
    def setUp(self):
        super().setUp()
        self.source=self.work/'source'; self.source.mkdir()
        for name in ['lib','bin','config','systemd']:
            shutil.copytree(ROOT/name,self.source/name)
        shutil.copy2(ROOT/'runtime.manifest',self.source/'runtime.manifest')
        self.dest=self.work/'destination'
        (self.dest/'usr/local/sbin').mkdir(parents=True)
        (self.dest/'etc/systemd/system').mkdir(parents=True)
        self.active=self.dest/'usr/local/lib/server-security-healthcheck'

    install = installers.InstallerTests.install
    good = installers.InstallerTests.good

    def custom(self): return add_check(self.source/'lib')

    def run_active(self, config='CHECK_MARIADB=1\n'):
        directory=self.work/'runtime-config'; directory.mkdir(exist_ok=True)
        (directory/'healthcheck.conf').write_text('NOTIFY_TELEGRAM=0\nCHECK_APACHE=0\nCHECK_RSPAMD=0\nCHECK_PUREFTP=0\nCHECK_EXIM=0\nCHECK_DISK=0\nCHECK_CLAMAV=0\nCHECK_LMD=0\n'+config)
        env=dict(self.env, SSHC_CONFIG_DIR=str(directory), SSHC_LIB_DIR=str(self.active.resolve()))
        return subprocess.run(['bash',str(self.dest/'usr/local/sbin/server-security-healthcheck')],env=env,text=True,capture_output=True,timeout=10)

    def error(self, result):
        self.assertEqual(result.returncode,2,result.stdout+result.stderr)
        self.assertIn('ERROR',result.stdout+result.stderr); self.assertNotIn('OK all enabled checks passed',result.stdout)

    def test_fresh_installs_custom_without_manual_manifest(self):
        self.custom(); self.good(); self.assertTrue((self.active/'checks/mariadb.sh').is_file())
        self.assertIn('checks/mariadb.sh', (self.active/'.runtime.manifest').read_text())
        result=self.run_active(); self.assertEqual(result.returncode,1,result.stdout+result.stderr); self.assertIn('deterministic finding',result.stdout)

    def test_upgrade_installs_custom(self):
        self.good(); old=self.active.resolve(); self.custom(); self.good()
        self.assertNotEqual(self.active.resolve(),old); self.assertTrue(old.exists())
        self.assertEqual(self.run_active().returncode,1)

    def test_original_A_installed_file_missing(self):
        self.custom(); self.good(); (self.active/'checks/mariadb.sh').unlink(); self.error(self.run_active())

    def test_installed_registry_manifest_mismatch(self):
        self.custom(); self.good(); manifest=self.active/'.runtime.manifest'
        manifest.write_text(manifest.read_text().replace('checks/mariadb.sh\n',''))
        self.error(self.run_active())

    def test_installed_manifest_missing(self):
        self.custom(); self.good(); (self.active/'.runtime.manifest').unlink(); self.error(self.run_active())

    def test_missing_source_aborts_before_activation(self):
        self.good(); old=self.active.resolve(); self.custom().unlink(); result=self.install()
        self.assertNotEqual(result.returncode,0); self.assertEqual(self.active.resolve(),old)

    def test_bad_custom_function_aborts_before_activation(self):
        self.good(); old=self.active.resolve(); self.custom().write_text('hc_register_check mariadb\n')
        self.assertNotEqual(self.install().returncode,0); self.assertEqual(self.active.resolve(),old)

    def test_custom_staging_copy_failure_retains_active(self):
        self.good(); old=self.active.resolve(); self.custom(); result=self.install('checks/mariadb.sh')
        self.assertNotEqual(result.returncode,0); self.assertEqual(self.active.resolve(),old)

    def test_staged_file_removed_before_validation(self):
        self.good(); old=self.active.resolve(); self.custom()
        text=(ROOT/'install.sh').read_text()
        for prefix in ['/usr/local/','/etc/']: text=text.replace(prefix,str(self.dest)+prefix)
        text='\n'.join('ROOT_DIR='+Q(str(self.source)) if line.startswith('ROOT_DIR=') else line for line in text.splitlines())
        text=text.replace('# Validate every owned file','rm -f -- "$STAGE/checks/mariadb.sh"\n# Validate every owned file')
        result=subprocess.run(['bash','-c','id() { echo 0; }; systemctl() { return 0; };\n'+text],env=self.env,text=True,capture_output=True,timeout=10)
        self.assertNotEqual(result.returncode,0); self.assertEqual(self.active.resolve(),old); self.assertIn('Required staged module missing',result.stderr)

    def test_obsolete_registered_custom_removed(self):
        self.custom(); self.good(); registry=self.source/'lib/checks.registry'
        registry.write_text('\n'.join(line for line in registry.read_text().splitlines() if not line.startswith('mariadb|'))+'\n')
        self.good(); self.assertFalse((self.active/'checks/mariadb.sh').exists()); self.error(self.run_active())

    def test_unregistered_preserved_file_never_sourced(self):
        self.custom(); self.good(); marker=self.work/'untrusted-executed'
        (self.active/'checks/local.sh').write_text('touch '+Q(str(marker))+'\n')
        self.good(); self.assertTrue((self.active/'checks/local.sh').exists())
        self.assertEqual(self.run_active().returncode,1); self.assertFalse(marker.exists())

    def test_hidden_dependency_preserved_on_upgrade(self):
        self.custom(); self.good(); old=self.active.resolve(); hidden=self.active/'checks/.hidden-helper'
        hidden.write_text('local_dependency() { :; }\n')
        module=self.source/'lib/checks/mariadb.sh'
        module.write_text('source "$(dirname "${BASH_SOURCE[0]}")/.hidden-helper"\nhc_register_check mariadb\ncheck_mariadb() { local_dependency; }\n')
        result=self.install(); self.assertEqual(result.returncode,0,result.stdout+result.stderr); self.assertNotEqual(self.active.resolve(),old); self.assertTrue(old.exists()); self.assertTrue(hidden.exists()); self.assertTrue((self.active/'checks/.hidden-helper').exists()); self.assertEqual(self.run_active().returncode,0)
