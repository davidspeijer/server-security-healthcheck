"""Effective registry defaults: isolated entrypoint and staged-install regression."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from isolation import isolated_env
import test_ph11_registry as registry_tests

ROOT = registry_tests.ROOT
MATRIX = [('0', None, '0'), ('1', None, '1'), ('auto', None, 'auto'),
          ('0', '1', '1'), ('1', '0', '0'), ('auto', '1', '1'),
          ('auto', '0', '0'), ('0', 'auto', 'auto'), ('1', 'auto', 'auto')]


class EffectiveStateTests(unittest.TestCase):
    def setUp(self):
        (ROOT/'tmp').mkdir(exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=ROOT/'tmp', prefix='registry-default-')
        self.addCleanup(self.temp.cleanup)
        self.work = Path(self.temp.name)
        self.lib = self.work/'lib'
        shutil.copytree(ROOT/'lib', self.lib)
        self.config = self.work/'config'; self.config.mkdir()
        self.env = isolated_env(self.work)
        self.env.update(SSHC_CONFIG_DIR=str(self.config), SSHC_LIB_DIR=str(self.lib))
        # No real service calls. Discovery either proves presence/absence or fails.
        with (self.lib/'common.sh').open('a') as stream:
            stream.write('''
hc_have() { case "$1" in httpd|apachectl|apache2ctl|audit_missing_binary) return 1;; esac; command -v "$1" >/dev/null 2>&1; }
systemctl() { case "$1" in
 list-unit-files) case "${AUDIT_DISCOVERY:-present}" in absent) :;; failed) return 1;; *) printf '%s enabled\\n' "${@: -1}";; esac;;
 is-active) return 1;; *) return 1;; esac; }
''')

    def default(self, name, value):
        path = self.lib/'checks.registry'; rows=[]
        for line in path.read_text().splitlines():
            fields=line.split('|')
            if fields[0] == name: fields[4]=value; line='|'.join(fields)
            rows.append(line)
        path.write_text('\n'.join(rows)+'\n')

    def custom(self, name='mariadb', default='0', body=None):
        if body is None:
            body=('hc_register_check '+name+'\ncheck_'+name+'() {\n'
                  'local mode; mode="$(hc_mode "${CHECK_'+name.upper()+':-0}")"\n'
                  '[ "$mode" != off ] || return 0\n'
                  'hc_detail "effective '+name+'=$CHECK_'+name.upper()+'"\n'
                  'if [ "$mode" = auto ]; then if hc_service_present '+name+' audit_missing_binary; then :; else return 0; fi; fi\n'
                  'hc_warn "'+name+' deterministic finding"; return 0; }\n')
        return registry_tests.add_check(self.lib, name, body, default)

    def run_state(self, name, explicit=None, extra='', env=None):
        rows=[line.split('|') for line in (self.lib/'checks.registry').read_text().splitlines()
              if line and not line.startswith('#')]
        key=next(row[3] for row in rows if row[0] == name)
        content='NOTIFY_TELEGRAM=0\n'
        content+=''.join(row[3]+'=0\n' for row in rows if row[3]!='-' and row[0]!=name)
        if explicit is not None: content+=key+'='+explicit+'\n'
        (self.config/'healthcheck.conf').write_text(content+extra)
        return subprocess.run(['bash', str(ROOT/'bin/server-security-healthcheck')],
                              env=dict(self.env, **(env or {})), text=True,
                              capture_output=True, timeout=10)

    def matrix_case(self, kind, default, explicit, effective):
        if kind == 'custom': self.custom(default=default); name='mariadb'
        else:
            name='apache'; self.default(name,default)
            with (self.lib/'checks/apache.sh').open('a') as stream:
                stream.write('\nhc_detail "effective apache=$CHECK_APACHE"\n')
        result=self.run_state(name,explicit)
        self.assertEqual(result.returncode, 0 if effective=='0' else 1, result.stdout+result.stderr)
        if effective=='0': self.assertNotIn('effective '+name+'=',result.stdout)
        else:
            self.assertIn('effective '+name+'='+effective,result.stdout)
            self.assertNotIn('all enabled checks passed',result.stdout)

    def test_original_guard_default_one(self):
        self.custom(default='1',body='hc_register_check mariadb\ncheck_mariadb() { hc_enabled "${CHECK_MARIADB:-0}" || return 0; hc_detail "effective=$CHECK_MARIADB"; hc_warn "original audit finding"; return 0; }\n')
        result=self.run_state('mariadb')
        self.assertEqual(result.returncode,1,result.stdout+result.stderr)
        self.assertIn('effective=1',result.stdout); self.assertIn('original audit finding',result.stdout)
        self.assertNotIn('all enabled checks passed',result.stdout)

    def test_invalid_explicit_values(self):
        self.custom(default='1')
        for value in ('yes','true','banana','""'):
            with self.subTest(value=value):
                result=self.run_state('mariadb',value)
                self.assertEqual(result.returncode,2,result.stdout+result.stderr)
                self.assertIn('ERROR',result.stdout); self.assertNotIn('all enabled checks passed',result.stdout)

    def test_auto_absent(self):
        self.custom(default='auto'); result=self.run_state('mariadb',env={'AUDIT_DISCOVERY':'absent'})
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        self.assertIn('effective mariadb=auto',result.stdout); self.assertIn('NOT_APPLICABLE',result.stdout)

    def test_auto_discovery_failure(self):
        self.custom(default='auto'); result=self.run_state('mariadb',env={'AUDIT_DISCOVERY':'failed'})
        self.assertEqual(result.returncode,2,result.stdout+result.stderr)
        self.assertIn('ERROR Discovery failed',result.stdout); self.assertNotIn('NOT_APPLICABLE',result.stdout)

    def test_multiple_custom_defaults_and_builtin(self):
        self.custom(default='1'); self.custom('other',default='0'); self.custom('third',default='auto')
        # Omit all custom keys so the actual registry defaults are exercised.
        rows=(self.lib/'checks.registry').read_text().splitlines()
        self.default('apache','1')
        (self.config/'healthcheck.conf').write_text('NOTIFY_TELEGRAM=0\n'+''.join(line.split('|')[3]+'=0\n' for line in rows if '|builtin|' in line and not line.startswith('apache|')))
        result=subprocess.run(['bash',str(ROOT/'bin/server-security-healthcheck')],env=self.env,text=True,capture_output=True,timeout=10)
        self.assertEqual(result.returncode,1,result.stdout+result.stderr)
        self.assertIn('mariadb deterministic finding',result.stdout); self.assertIn('third deterministic finding',result.stdout)
        self.assertIn('WARNING Apache',result.stdout); self.assertNotIn('other deterministic finding',result.stdout)

    def test_loading_cannot_disable_selected_check(self):
        self.custom(default='1')
        self.custom('earlier',body='hc_register_check earlier\ncheck_earlier() { CHECK_MARIADB=0; return 0; }\nCHECK_MARIADB=0\n')
        path=self.lib/'checks.registry'; rows=path.read_text().splitlines(); row=rows.pop()
        rows.insert(1,row); path.write_text('\n'.join(rows)+'\n')
        result=self.run_state('mariadb',extra='CHECK_EARLIER=1\n')
        self.assertEqual(result.returncode,1,result.stdout+result.stderr)
        self.assertIn('effective mariadb=1',result.stdout); self.assertIn('mariadb deterministic finding',result.stdout)

    def test_readonly_state_conflict_is_error(self):
        self.custom(default='1',body='hc_register_check mariadb\nCHECK_MARIADB=0; readonly CHECK_MARIADB\ncheck_mariadb() { hc_enabled "${CHECK_MARIADB:-0}" || return 0; hc_warn "finding"; return 0; }\n')
        result=self.run_state('mariadb')
        self.assertEqual(result.returncode,2,result.stdout+result.stderr)
        self.assertIn('Cannot restore effective enable state',result.stdout)
        self.assertIn('Required check not executed: mariadb',result.stdout)
        self.assertNotIn('all enabled checks passed',result.stdout)

    def test_lmd_alias_priority_and_publication(self):
        (self.lib/'checks/lmd.sh').write_text('hc_register_check lmd\ncheck_lmd() { hc_detail "lmd=$CHECK_LMD alias=$LMD_ENABLED"; hc_warn "LMD fixture finding"; return 0; }\n')
        for key,alias,effective in [('0','1','1'),('1','0','0'),('1','auto','auto')]:
            with self.subTest(key=key,alias=alias):
                result=self.run_state('lmd',key,extra='LMD_ENABLED='+alias+'\n')
                self.assertEqual(result.returncode,0 if effective=='0' else 1,result.stdout+result.stderr)
                if effective!='0':self.assertIn('lmd='+effective+' alias='+effective,result.stdout)

    def test_boolean_builtin_rejects_auto_default(self):
        self.default('disk','auto'); result=self.run_state('disk')
        self.assertEqual(result.returncode,2,result.stdout+result.stderr)
        self.assertIn('Invalid effective enable state: CHECK_DISK',result.stdout)
        self.assertNotIn('all enabled checks passed',result.stdout)

    def test_real_disk_builtin_default_one(self):
        self.default('disk','1')
        with (self.lib/'common.sh').open('a') as stream:
            stream.write('\ndf() { printf "Filesystem Size Used Avail Use%% Mounted\\nfixture 100G 99G 1G 99%% /fixture\\n"; }\n')
        result=self.run_state('disk')
        self.assertEqual(result.returncode,1,result.stdout+result.stderr)
        self.assertIn('99%',result.stdout); self.assertNotIn('all enabled checks passed',result.stdout)


# Distinct tests make every builtin/custom matrix row visible in test reports.
def matrix_test(kind, default, explicit, effective):
    def test(self): self.matrix_case(kind, default, explicit, effective)
    return test
for kind in ('builtin','custom'):
    for default,explicit,effective in MATRIX:
        label='test_'+kind+'_default_'+default+'_config_'+(explicit or 'absent')
        setattr(EffectiveStateTests,label,matrix_test(kind,default,explicit,effective))


class InstalledDefaultTests(registry_tests.installers.Base):
    install = registry_tests.installers.InstallerTests.install
    good = registry_tests.installers.InstallerTests.good
    run_active = registry_tests.RegistryInstallerTests.run_active

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
        self.env.pop('CHECK_MARIADB',None)

    def test_installed_original_audit_probe(self):
        registry_tests.add_check(self.source/'lib',default='1',body='hc_register_check mariadb\ncheck_mariadb() { hc_enabled "${CHECK_MARIADB:-0}" || return 0; hc_warn "installed original audit finding"; return 0; }\n')
        self.good(); result=self.run_active('')
        self.assertEqual(result.returncode,1,result.stdout+result.stderr)
        self.assertIn('installed original audit finding',result.stdout)
        self.assertNotIn('all enabled checks passed',result.stdout)
