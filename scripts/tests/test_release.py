import argparse
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('release_manage', ROOT / 'scripts/manage.py')
manage = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(manage)
IMAGE = 'ghcr.io/balamutik/familychat-keyserver@sha256:' + 'a' * 64


class ReleaseTests(unittest.TestCase):
    def package(self, output):
        result = subprocess.run([sys.executable, str(ROOT / 'scripts/package-release.py'), '--version', 'v1.2.3',
                                 '--image', IMAGE, '--output', str(output)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_release_contains_immutable_image_and_only_deployment_payload(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            self.package(output)
            with tarfile.open(output / 'familychat-keyserver.tar.gz') as archive:
                names = archive.getnames()
                self.assertIn('scripts/manage.py', names)
                self.assertIn('scripts/chat_bridge.py', names)
                self.assertIn('scripts/link_chat.py', names)
                self.assertIn('scripts/renew.sh', names)
                self.assertNotIn('go.mod', names)
                self.assertNotIn('state/state.json', names)
                compose = archive.extractfile('compose.yaml').read().decode()
                self.assertIn('image: ' + IMAGE, compose)
                self.assertNotIn('build:', compose)
                manifest = json.load(archive.extractfile('release.json'))
                self.assertEqual(manifest['repository'], 'balamutik/familychat-keyserver')
                self.assertEqual(manifest['version'], 'v1.2.3')
                self.assertEqual(manifest['image'], IMAGE)
                self.assertEqual(archive.getmember('scripts/renew.sh').mode, 0o755)
            self.assertEqual((output / 'install.sh').read_bytes(), (ROOT / 'install.sh').read_bytes())
            for line in (output / 'SHA256SUMS').read_text().splitlines():
                digest, filename = line.split()
                self.assertEqual(digest, hashlib.sha256((output / filename).read_bytes()).hexdigest())

    def test_package_refuses_floating_or_other_repository_images(self):
        for image in ('ghcr.io/balamutik/familychat-keyserver:latest',
                      'ghcr.io/other/keyserver@sha256:' + 'a' * 64):
            with tempfile.TemporaryDirectory() as output:
                result = subprocess.run([sys.executable, str(ROOT / 'scripts/package-release.py'), '--version', 'v1.2.3',
                                         '--image', image, '--output', output], capture_output=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse((Path(output) / 'familychat-keyserver.tar.gz').exists())

    def test_update_from_release_preserves_exact_key_and_ticket_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root, payload = Path(directory) / 'installed', Path(directory) / 'release'
            root.mkdir()
            payload.mkdir()
            self.package(payload)
            with tarfile.open(payload / 'familychat-keyserver.tar.gz') as archive:
                archive.extractall(payload / 'extracted', filter='data')
            (root / 'state').mkdir(mode=0o700)
            original = b'{"private_key":"keep-this","ticket_secret":"keep-too"}\n'
            (root / 'state/state.json').write_bytes(original)
            (root / 'state/state.json').chmod(0o600)
            config = dict(install_dir=str(root), domain='keys.example.com', email='admin@example.com',
                          port=8443, client='certbot', challenge='standalone')
            manage.private_json(root / 'deploy.json', config)
            (root / 'service.env').write_text('KEYSERVER_DOMAIN=keys.example.com\nKEYSERVER_PORT=8443\n')
            calls = []
            with mock.patch.object(manage, 'command', side_effect=lambda args, **kw: calls.append(list(map(str, args)))), \
                    mock.patch.object(manage, 'install_timer'):
                manage.update(argparse.Namespace(source=str(payload / 'extracted')), root)
            self.assertEqual((root / 'state/state.json').read_bytes(), original)
            self.assertFalse(any('init' in call or 'build' in call for call in calls))
            self.assertTrue(any('pull' in call for call in calls))
            self.assertIn(IMAGE, (root / 'compose.yaml').read_text())
            self.assertEqual(manage.load_config(root)['release_version'], 'v1.2.3')
            self.assertTrue(list((root / 'backups').glob('*.tar.gz')))
            self.assertTrue((root / 'grants').is_dir(), 'upgrade must provision writable grant state')
            journal = b'{"pending":[],"consumed":["keep-replay-protection"]}\n'
            (root / 'grants/grants.json').write_bytes(journal)
            with mock.patch.object(manage, 'command'), mock.patch.object(manage, 'install_timer'):
                manage.update(argparse.Namespace(source=str(payload / 'extracted')), root)
            self.assertEqual((root / 'grants/grants.json').read_bytes(), journal)
            self.assertEqual(manage.load_config(root)['key_delivery'], 'device-grant-v1')
            self.assertTrue(any(self.backup_has_grants(archive, journal) for archive in (root / 'backups').glob('*.tar.gz')))

    @staticmethod
    def backup_has_grants(path, expected):
        with tarfile.open(path) as archive:
            return 'grants/grants.json' in archive.getnames() and archive.extractfile('grants/grants.json').read() == expected

    def test_update_rejects_legacy_protocol_before_changing_installation(self):
        for installed_manifest in (False, True):
            with self.subTest(installed_manifest=installed_manifest), tempfile.TemporaryDirectory() as directory:
                root, payload = Path(directory) / 'installed', Path(directory) / 'release'
                root.mkdir(); payload.mkdir()
                self.package(payload)
                with tarfile.open(payload / 'familychat-keyserver.tar.gz') as archive:
                    archive.extractall(payload / 'extracted', filter='data')
                source = payload / 'extracted'
                manifest = json.loads((source / 'release.json').read_text())
                if installed_manifest:
                    (root / 'app').mkdir()
                    (root / 'app/release.json').write_text(json.dumps(manifest))
                    (root / 'app/compose.yaml').write_bytes((source / 'compose.yaml').read_bytes())
                config = dict(install_dir=str(root), domain='keys.example.com', email='admin@example.com', port=8443,
                              client='certbot', challenge='standalone')
                if not installed_manifest:
                    config['key_delivery'] = 'device-grant-v1'
                manage.private_json(root / 'deploy.json', config)
                manifest.pop('key_delivery')
                (source / 'release.json').write_text(json.dumps(manifest))
                before = (root / 'deploy.json').read_bytes()
                with mock.patch.object(manage, 'command') as command, self.assertRaisesRegex(ValueError, 'JWT'):
                    manage.update(argparse.Namespace(source=str(source)), root)
                command.assert_not_called()
                self.assertFalse((root / 'backups').exists())
                self.assertEqual((root / 'deploy.json').read_bytes(), before)
                (source / 'release.json').unlink()
                with mock.patch.object(manage, 'command') as command, self.assertRaisesRegex(ValueError, 'JWT'):
                    manage.update(argparse.Namespace(source=str(source)), root)
                command.assert_not_called()

    def test_source_and_release_updates_can_switch_without_stale_image_or_key_rotation(self):
        with tempfile.TemporaryDirectory() as directory:
            root, payload = Path(directory) / 'installed', Path(directory) / 'release'
            root.mkdir()
            payload.mkdir()
            self.package(payload)
            with tarfile.open(payload / 'familychat-keyserver.tar.gz') as archive:
                archive.extractall(payload / 'extracted', filter='data')
            (root / 'state').mkdir(mode=0o700)
            original = b'{"private_key":"preserve","ticket_secret":"preserve-too"}'
            (root / 'state/state.json').write_bytes(original)
            (root / 'state/state.json').chmod(0o600)
            config = dict(install_dir=str(root), domain='keys.example.com', email='admin@example.com',
                          port=8443, client='certbot', challenge='standalone', image=IMAGE, release_version='v1.2.3')
            manage.private_json(root / 'deploy.json', config)
            (root / 'service.env').write_text('KEYSERVER_BUILD_CONTEXT=./app\nKEYSERVER_DOMAIN=keys.example.com\nKEYSERVER_PORT=8443\n')
            calls = []
            with mock.patch.object(manage, 'command', side_effect=lambda args, **kw: calls.append(list(map(str, args)))), \
                    mock.patch.object(manage, 'install_timer'):
                manage.update(argparse.Namespace(source=str(ROOT)), root)
                self.assertTrue(any('build' in call for call in calls))
                self.assertIn('build:', (root / 'compose.yaml').read_text())
                self.assertNotIn('image', manage.load_config(root))
                self.assertNotIn('KEYSERVER_IMAGE=', (root / 'service.env').read_text())
                self.assertTrue((root / 'app/go.mod').exists())
                calls.clear()
                manage.update(argparse.Namespace(source=str(payload / 'extracted')), root)
                self.assertFalse(any('build' in call or 'init' in call for call in calls))
                self.assertTrue(any('pull' in call for call in calls))
                self.assertFalse((root / 'app/go.mod').exists())
                self.assertEqual(manage.load_config(root)['image'], IMAGE)
            self.assertEqual((root / 'state/state.json').read_bytes(), original)

    def test_cli_update_dispatch_reaches_backup_and_preserves_state(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'state').mkdir(mode=0o700)
            original = b'{"private_key":"preserve","ticket_secret":"preserve-too"}'
            (root / 'state/state.json').write_bytes(original)
            (root / 'state/state.json').chmod(0o600)
            config = dict(install_dir=str(root), domain='keys.example.com', email='admin@example.com',
                          port=8443, client='certbot', challenge='standalone')
            manage.private_json(root / 'deploy.json', config)
            (root / 'service.env').write_text('KEYSERVER_BUILD_CONTEXT=./app\nKEYSERVER_DOMAIN=keys.example.com\nKEYSERVER_PORT=8443\n')
            calls = []
            with mock.patch.object(manage.sys, 'argv', ['manage.py', 'update', '--source', str(ROOT), '--install-dir', str(root)]), \
                    mock.patch.object(manage.os, 'geteuid', return_value=0), \
                    mock.patch.object(manage.os, 'chown'), \
                    mock.patch.object(manage, 'ensure_docker'), mock.patch.object(manage, 'install_timer'), \
                    mock.patch.object(manage, 'command', side_effect=lambda args, **kw: calls.append(list(map(str, args)))):
                manage.main()
            self.assertTrue(list((root / 'backups').glob('*.tar.gz')))
            self.assertTrue(any('build' in call for call in calls))
            self.assertTrue(any('up' in call for call in calls))
            self.assertFalse(any('init' in call for call in calls))
            self.assertEqual((root / 'state/state.json').read_bytes(), original)

    def test_release_install_initializes_using_exact_service_image(self):
        for address in ('keys.example.com', '2606:4700:4700::1111'):
            with self.subTest(address=address):
                self.check_release_install(address)

    def check_release_install(self, address):
        with tempfile.TemporaryDirectory() as directory:
            root, payload = Path(directory) / 'installed', Path(directory) / 'release'
            root.mkdir()
            payload.mkdir()
            self.package(payload)
            with tarfile.open(payload / 'familychat-keyserver.tar.gz') as archive:
                archive.extractall(payload / 'extracted', filter='data')
            args = argparse.Namespace(install_dir=str(root), source=str(payload / 'extracted'), domain=address,
                                      email='admin@example.com', port=8443, client='certbot', challenge='standalone',
                                      acme_binary='/root/.acme.sh/acme.sh', import_json=None, import_public=None, import_private=None)
            calls = []
            with mock.patch.object(manage, 'command', side_effect=lambda args, **kw: calls.append(list(map(str, args)))), \
                    mock.patch.object(manage, 'ensure_docker'), mock.patch.object(manage, 'ensure_acme'), \
                    mock.patch.object(manage, 'ensure_port_available'), mock.patch.object(manage, 'certificate'), \
                    mock.patch.object(manage, 'install_timer'), mock.patch.object(manage.os, 'chown'):
                manage.install(args)
            init = next(call for call in calls if 'init' in call)
            self.assertEqual(init[init.index('init') - 1], IMAGE)
            self.assertFalse(any('build' in call for call in calls))
            self.assertTrue(any('pull' in call for call in calls))
            self.assertIn(IMAGE, (root / 'compose.yaml').read_text())
            if ':' in address:
                self.assertIn(f'KEYSERVER_DOMAIN=[{address}]\n', (root / 'service.env').read_text())
                self.assertEqual(init[init.index('--url') + 1], f'https://[{address}]:8443/api/v1/keys/current')

    def test_release_manifest_cannot_redirect_image_or_repository(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'release.json').write_text(json.dumps(dict(version='v1.2.3', repository='other/repo', image=IMAGE)))
            with self.assertRaises(ValueError):
                manage.release_manifest(root)
            (root / 'release.json').write_text(json.dumps(dict(version='v1.2.3', repository='balamutik/familychat-keyserver', image=IMAGE)))
            (root / 'compose.yaml').write_text('services:\n  keyserver:\n    image: evil:latest\n')
            with self.assertRaises(ValueError):
                manage.release_manifest(root)

    def test_retry_after_certificate_failure_preserves_existing_keys_and_ticket(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / 'installed'
            (root / 'state').mkdir(parents=True, mode=0o700)
            (root / 'export').mkdir(mode=0o700)
            original = b'{"private_key":"existing-key","ticket_secret":"existing-ticket-secret"}\n'
            exported = b'{"url":"https://213.155.29.175:8443/api/v1/keys/current","ticket_secret":"existing-ticket-secret"}\n'
            (root / 'state/state.json').write_bytes(original)
            (root / 'export/main-server.json').write_bytes(exported)
            args = argparse.Namespace(install_dir=str(root), source=str(ROOT), domain='213.155.29.175',
                                      email='admin@example.com', port=8443, client='acme.sh', challenge='standalone',
                                      acme_binary='/root/.acme.sh/acme.sh', import_json=None, import_public=None, import_private=None)
            calls = []
            with mock.patch.object(manage, 'command', side_effect=lambda args, **kw: calls.append(list(map(str, args)))), \
                    mock.patch.object(manage, 'ensure_docker'), mock.patch.object(manage, 'ensure_acme'), \
                    mock.patch.object(manage, 'ensure_port_available'), mock.patch.object(manage, 'install_timer'), \
                    mock.patch.object(manage.os, 'chown'), \
                    mock.patch.object(manage, 'certificate', side_effect=[RuntimeError('ACME rejected identifier'), None]):
                with self.assertRaisesRegex(RuntimeError, 'ACME rejected'):
                    manage.install(args)
                self.assertFalse((root / 'deploy.json').exists())
                self.assertFalse(any('up' in call for call in calls))
                self.assertEqual((root / 'state/state.json').read_bytes(), original)
                self.assertEqual((root / 'export/main-server.json').read_bytes(), exported)
                manage.install(args)
            self.assertEqual((root / 'state/state.json').read_bytes(), original)
            self.assertEqual((root / 'export/main-server.json').read_bytes(), exported)
            self.assertEqual(manage.load_config(root)['domain'], '213.155.29.175')
            self.assertTrue(any('up' in call for call in calls))
            init = next(call for call in calls if 'init' in call)
            self.assertEqual(init[init.index('--url') + 1], 'https://213.155.29.175:8443/api/v1/keys/current')

    def test_dependency_install_requires_confirmation_before_any_command(self):
        with mock.patch.object(manage, 'prompt', return_value='n'), mock.patch.object(manage, 'command') as execute:
            with self.assertRaises(RuntimeError):
                manage.install_packages(['certbot'])
            execute.assert_not_called()

    def test_acme_corrupt_download_is_never_executed(self):
        with tempfile.TemporaryDirectory() as directory:
            config = dict(acme_binary=str(Path(directory) / 'acme.sh'), email='admin@example.com', client='acme.sh')
            with mock.patch.object(manage, 'prompt', return_value='yes'), \
                    mock.patch.object(manage, 'download', return_value=b'corrupted'), \
                    mock.patch.object(manage, 'command') as execute, \
                    mock.patch.object(manage, 'install_packages'):
                with self.assertRaises(ValueError):
                    manage.ensure_acme(config)
                execute.assert_not_called()
                self.assertFalse(Path(config['acme_binary']).exists())

    def test_prompt_uses_terminal_when_stdin_is_pipe(self):
        output = io.StringIO()
        terminal = io.BytesIO(b'keys.example.com\n')
        class NonClosing:
            def __init__(self, value): self.value = value
            def __enter__(self): return self.value
            def __exit__(self, *args): pass
        def terminal_open(path, mode, **kwargs):
            self.assertEqual(path, '/dev/tty')
            return NonClosing(terminal if 'b' in mode else output)
        with mock.patch('builtins.open', side_effect=terminal_open), mock.patch('sys.stdin', io.StringIO('')):
            self.assertEqual(manage.prompt('Domain:'), 'keys.example.com')
        self.assertIn('Domain:', output.getvalue())


if __name__ == '__main__':
    unittest.main()
