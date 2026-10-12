"""PH07-PH10: isolated maintenance evidence; no real package/service commands."""
import os
from pathlib import Path
import shlex
import shutil
import stat
import subprocess
import unittest
from unittest import mock
import test_audit_round3 as installers
import test_healthcheck as fixture
import bounded_input

ROOT=fixture.ROOT
Q=shlex.quote


class PreservationTests(installers.Base):
    install=installers.InstallerTests.install
    good=installers.InstallerTests.good
    def setUp(self):
        super().setUp(); self.source=self.work/'source';self.source.mkdir()
        for name in ['lib','bin','config','systemd']:shutil.copytree(ROOT/name,self.source/name)
        shutil.copy2(ROOT/'runtime.manifest',self.source/'runtime.manifest')
        self.dest=self.work/'destination';(self.dest/'usr/local/sbin').mkdir(parents=True);(self.dest/'etc/systemd/system').mkdir(parents=True)
        self.active=self.dest/'usr/local/lib/server-security-healthcheck'
        self.good()

    def entry(self, name, directory=False, symlink=False):
        for container in ['checks','notify','bin']:
            path=self.active/container/name
            if symlink:
                target=self.work/('external-'+container);target.write_text('untouched');path.symlink_to(target)
            elif directory:
                path.mkdir();(path/'.nested').mkdir();(path/'.nested/.data').write_text('custom')
            else:path.write_text('custom')
        old=self.active.resolve();self.good()
        for container in ['checks','notify','bin']:
            path=self.active/container/name
            if symlink:self.assertTrue(path.is_symlink());self.assertEqual(path.read_text(),'untouched')
            elif directory:self.assertEqual((path/'.nested/.data').read_text(),'custom')
            else:self.assertEqual(path.read_text(),'custom')
        self.assertTrue(old.exists())

    def test_regular_file(self):self.entry('custom.conf')
    def test_hidden_file(self):self.entry('.custom.conf')
    def test_regular_directory(self):self.entry('custom-data',directory=True)
    def test_hidden_directory(self):self.entry('.custom-data',directory=True)
    def test_symlink(self):self.entry('custom-link',symlink=True)
    def test_hidden_symlink(self):self.entry('.custom-link',symlink=True)
    def test_nested_hidden_files(self):
        path=self.active/'checks/.nested';path.mkdir();(path/'.one').write_text('one');(path/'.dir').mkdir();(path/'.dir/.two').write_text('two');self.good()
        self.assertEqual((path/'.one').read_text(),'one');self.assertEqual((path/'.dir/.two').read_text(),'two')
    def test_new_managed_wins(self):
        path=self.active/'checks/disk.sh';path.write_text('# local conflict\n');result=self.install()
        self.assertEqual(result.returncode,0,result.stderr);self.assertIn('staged project entry wins: checks/disk.sh',result.stdout)
        self.assertEqual(path.read_text(),(self.source/'lib/checks/disk.sh').read_text())
    def test_obsolete_managed_removed(self):
        (self.active/'checks/.obsolete').write_text('owned')
        manifest=self.active/'.runtime.manifest';manifest.write_text(manifest.read_text()+'checks/.obsolete\n');self.good();self.assertFalse((self.active/'checks/.obsolete').exists())
    def test_unknown_unmanaged_file(self):self.entry('.unknown-state')
    def test_hidden_helper_required_by_registered_module(self):
        hidden=self.active/'checks/.helper';hidden.write_text('local_helper() { :; }\n')
        registry=self.source/'lib/checks.registry';registry.write_text(registry.read_text()+'local|checks/local.sh|check_local|CHECK_LOCAL|0|custom|-\n')
        (self.source/'lib/checks/local.sh').write_text('source "$(dirname "${BASH_SOURCE[0]}")/.helper"\nhc_register_check local\ncheck_local() { local_helper; }\n')
        self.good();self.assertEqual(hidden.read_text(),'local_helper() { :; }\n')
    def test_preservation_failure_retains_previous(self):
        old=self.active.resolve();(self.active/'checks/.fail-copy').write_text('custom')
        with (self.source/'lib/common.sh').open('a') as stream:stream.write('\ncp() { case "$*" in *.fail-copy*) return 1;; esac; command cp "$@"; }\n')
        result=self.install();self.assertNotEqual(result.returncode,0);self.assertEqual(self.active.resolve(),old)
        self.assertEqual((self.active/'checks/.fail-copy').read_text(),'custom')
    def test_actual_pre_activation_interruption(self):installers.InstallerTests.test_half_built(self)
    def test_upgrade_failure_keeps_previous_content(self):
        old=self.active.resolve();(self.active/'checks/.custom').write_text('old');result=self.install('health_data.py')
        self.assertNotEqual(result.returncode,0);self.assertEqual(self.active.resolve(),old);self.assertEqual((self.active/'checks/.custom').read_text(),'old')
    def test_second_upgrade_idempotent(self):
        self.entry('.custom-dir',directory=True);self.good();self.good();self.assertEqual((self.active/'checks/.custom-dir/.nested/.data').read_text(),'custom')
    def test_hidden_dangling_symlink_preserved(self):
        path=self.active/'notify/.dangling';path.symlink_to(self.work/'absent');self.good();self.assertTrue(path.is_symlink());self.assertEqual(os.readlink(path),str(self.work/'absent'))
    def test_newline_filename_not_mistaken_for_manifest_entry(self):
        path=self.active/'checks/.custom\ncommon.sh';path.write_text('custom');self.good();self.assertEqual(path.read_text(),'custom')
    def test_managed_symlink_conflict_leaves_target_untouched(self):
        target=self.work/'external-managed';target.write_text('untouched')
        path=self.active/'checks/disk.sh';path.unlink();path.symlink_to(target)
        self.good();self.assertFalse(path.is_symlink());self.assertEqual(target.read_text(),'untouched')
    def test_container_symlink_not_traversed(self):
        old=self.active.resolve();external=self.work/'external-container';external.mkdir();(external/'.secret').write_text('unchanged')
        shutil.rmtree(self.active/'bin');(self.active/'bin').symlink_to(external)
        result=self.install();self.assertNotEqual(result.returncode,0);self.assertEqual(self.active.resolve(),old);self.assertEqual((external/'.secret').read_text(),'unchanged')


class NotificationTests(unittest.TestCase):
    setUp=fixture.HealthcheckTests.setUp
    main=fixture.HealthcheckTests.main
    def notification(self, response='{"ok":true}', status=0, credentials=True, backend=None, test=True):
        lib=self.work/'notification-lib';shutil.copytree(ROOT/'lib',lib)
        module=lib/'notify/telegram.sh'
        if backend=='missing':module.unlink()
        elif backend is not None:module.write_text(backend)
        else:
            with module.open('a') as stream:
                stream.write('\ncurl() { printf "%s\\n" "$*" > '+Q(str(self.work/'argv'))+'; cat > '+Q(str(self.work/'request'))+'; printf "%s" '+Q(response)+'; return '+str(status)+'; }\n')
        config='NOTIFY_TELEGRAM=1\n'
        if credentials:config+='TELEGRAM_BOT_TOKEN=123:fixture_secret\nTELEGRAM_CHAT_ID=123\n'
        if not test:
            (lib/'checks/disk.sh').write_text('hc_register_check disk\ncheck_disk() { hc_warn "fixture finding"; }\n');config+='CHECK_DISK=1\n'
        result=self.main(config,args=('--test-notification',) if test else (),lib_dir=lib)
        self.assertNotIn('fixture_secret',result.stdout+result.stderr)
        if (self.work/'argv').exists():self.assertNotIn('fixture_secret',(self.work/'argv').read_text())
        return result
    def check(self, expected, **kwargs):
        result=self.notification(**kwargs);self.assertEqual(result.returncode,expected,result.stdout+result.stderr);return result
    def test_success(self):self.check(0)
    def test_transport(self):self.check(2,status=7)
    def test_api_reject(self):self.check(2,response='{"ok":false}')
    def test_malformed(self):self.check(2,response='{broken')
    def test_empty_response(self):self.check(2,response='')
    def test_missing_credentials(self):self.check(2,credentials=False)
    def test_missing_backend(self):self.check(2,backend='missing')
    def test_syntax_backend(self):self.check(2,backend='notify_test() {\n')
    def test_source_backend(self):self.check(2,backend='return 9\n')
    def test_internal_nonzero(self):self.check(2,backend='notify_telegram() { return 7; }\nnotify_test() { return 7; }\n')
    def test_token_only_in_stdin(self):
        self.check(0);self.assertIn('fixture_secret',(self.work/'request').read_text());self.assertEqual((self.work/'argv').read_text().split()[:2],['--config','-'])
    def test_normal_failure_still_two(self):self.check(2,test=False,status=7)
    def test_normal_finding_still_one(self):self.check(1,test=False)


class QualityAndDependenciesTests(installers.Base):
    def test_socket_stat_rejected_before_open(self):
        info=mock.Mock(st_mode=stat.S_IFSOCK | 0o600)
        with mock.patch.object(bounded_input.os,'stat',return_value=info),mock.patch.object(bounded_input.os,'open') as opened:
            with self.assertRaisesRegex(ValueError,'not regular'):list(bounded_input.lines(str(self.work/'socket')))
            opened.assert_not_called()
    def packages(self, manager):
        args=self.work/'package-args'
        script=(ROOT/'install-dependencies.sh').read_text()
        stubs='id() { echo 0; }; command() { if [ "$1" = -v ]; then [ "$2" = '+Q(manager)+' ]; else builtin command "$@"; fi; };\n'
        stubs+=manager+'() { printf "%s\\n" "$*" >> '+Q(str(args))+'; };\n'
        result=subprocess.run(['bash','-c',stubs+script],env=self.env,text=True,capture_output=True,timeout=10)
        self.assertEqual(result.returncode,0,result.stderr)
        lines=args.read_text().splitlines();install=next(line for line in lines if line.startswith('install '));packages=install.split()[2:]
        self.assertIn('hostname',packages);self.assertEqual(len(packages),len(set(packages)))
        for package in ['bash','coreutils','grep','sed','gawk','findutils','util-linux','curl','systemd','python3']:self.assertIn(package,packages)
        return packages,lines
    def test_el_dnf_packages(self):self.assertIn('procps-ng',self.packages('dnf')[0])
    def test_el_yum_packages(self):self.assertIn('procps-ng',self.packages('yum')[0])
    def test_debian_packages_and_mock_update(self):
        packages,lines=self.packages('apt-get');self.assertIn('procps',packages);self.assertEqual(lines[0],'update')
    def test_missing_hostname_runtime_error(self):
        lib=self.work/'lib';shutil.copytree(ROOT/'lib',lib)
        with (lib/'common.sh').open('a') as stream:stream.write('\nhc_have() { [ "$1" != hostname ] && command -v "$1" >/dev/null 2>&1; }\n')
        config=self.work/'config';config.mkdir();(config/'healthcheck.conf').write_text('NOTIFY_TELEGRAM=0\n')
        result=subprocess.run(['bash',str(ROOT/'bin/server-security-healthcheck')],env=dict(self.env,SSHC_LIB_DIR=str(lib),SSHC_CONFIG_DIR=str(config)),capture_output=True,text=True,timeout=10)
        self.assertEqual(result.returncode,2);self.assertIn('Required dependency missing: hostname',result.stdout)
    def test_fixed_hostname_timezone_and_clock(self):
        result=self.shell('hostname; date +%s; printf "%s" "$TZ"')
        self.assertEqual(result.stdout,'fixture.example\n1789891200\nUTC')
    def test_operational_commands_blocked_unless_explicitly_mocked(self):
        for command,expected in [('systemctl',1),('curl',99),('pgrep',1),('journalctl',1),('clamconf',1),('exim',1)]:
            with self.subTest(command=command):
                result=subprocess.run([command,'--fixture-only'],env=self.env,text=True,capture_output=True,timeout=5)
                self.assertEqual(result.returncode,expected)
                self.assertTrue(str(shutil.which(command,path=self.env['PATH'])).startswith(str(self.work)))
    def test_cli_audit_path_is_explicit_fixture(self):
        p=fixture.HealthcheckTests('test_exit_healthy');p.setUp()
        try:
            p.main('');contents=(p.work/'config/healthcheck.conf').read_text();self.assertIn('LMD_AUDIT='+fixture.Q(str(p.work/'empty audit')),contents)
            self.assertNotIn('/usr/local/maldetect/logs/audit',contents)
        finally:p.doCleanups()
