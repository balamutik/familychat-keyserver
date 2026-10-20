import argparse
import base64
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location('import_manage', Path(__file__).parents[1] / 'manage.py')
manage = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(manage)
IMAGE = 'ghcr.io/balamutik/familychat-keyserver@sha256:' + 'a' * 64


class ImportKeysTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        for name in ('state', 'export', 'tls'):
            (self.root / name).mkdir(mode=0o700)
        self.original = self.state(b'a', b'old-ticket')
        self.candidate = self.state(b'b', b'new-ticket')
        manage.private_json(self.root / 'state/state.json', self.original)
        manage.private_json(self.root / 'export/main-server.json', self.integration(self.original))
        self.config = dict(install_dir=str(self.root), domain='keys.example.com', email='admin@example.com',
                           port=8443, client='certbot', challenge='standalone', image=IMAGE)
        manage.private_json(self.root / 'deploy.json', self.config)
        (self.root / 'service.env').write_text('KEYSERVER_DOMAIN=keys.example.com\nKEYSERVER_PORT=8443\n')
        (self.root / 'tls/fullchain.pem').write_bytes(b'keep certificate')
        (self.root / 'tls/privkey.pem').write_bytes(b'keep TLS key')
        self.source = self.root / 'chat-key.json'
        manage.private_json(self.source, self.candidate)
        self.args = argparse.Namespace(import_json=str(self.source), import_public=None, import_private=None,
                                       replace_unused_state=True)
        self.before = self.snapshot()
        self.calls = []
        self.activation_failures = 0
        self.chown = mock.patch.object(manage.os, 'chown').start()
        self.execute = mock.patch.object(manage, 'command', side_effect=self.external_command).start()
        self.addCleanup(mock.patch.stopall)

    @staticmethod
    def state(public, ticket):
        raw = public * 32
        return dict(version=1, scheme='fc1', key_id=hashlib.sha256(raw).hexdigest(),
                    public_key=base64.b64encode(raw).decode(), private_key=base64.b64encode(b'p' * 32).decode(),
                    ticket_issuer='familychat-test-issuer', ticket_secret=base64.b64encode(ticket.ljust(32, b'0')).decode())

    @staticmethod
    def integration(state):
        return {key: value for key, value in state.items() if key not in ('private_key', 'version')} | {
            'key_server_url': 'https://keys.example.com:8443/api/v1/keys/current'}

    def snapshot(self):
        names = ('state/state.json', 'export/main-server.json', 'tls/fullchain.pem', 'tls/privkey.pem', 'deploy.json', 'service.env')
        return {name: (self.root / name).read_bytes() for name in names}

    def external_command(self, arguments, **kwargs):
        args = list(map(str, arguments))
        self.calls.append(args)
        if args[:2] == ['docker', 'run']:
            mounts = {}
            for i, arg in enumerate(args):
                if arg == '--mount':
                    fields = dict(part.split('=', 1) for part in args[i + 1].split(',') if '=' in part)
                    mounts[fields['dst']] = Path(fields['src'])
            manage.private_json(mounts['/state'] / 'state.json', self.candidate)
            manage.private_json(mounts['/export'] / 'main-server.json', self.integration(self.candidate))
        elif 'up' in args and self.activation_failures:
            self.activation_failures -= 1
            raise subprocess.CalledProcessError(1, args)

    def test_import_requires_explicit_replacement_of_unused_state(self):
        self.args.replace_unused_state = False
        with self.assertRaisesRegex(RuntimeError, 'replace-unused-state'):
            manage.import_keys(self.args, self.root)
        self.assertEqual(self.snapshot(), self.before)
        self.assertFalse(any('stop' in call or 'up' in call for call in self.calls))

    def test_import_backs_up_original_then_switches_only_key_state_and_export(self):
        manage.import_keys(self.args, self.root)
        after = self.snapshot()
        self.assertEqual(json.loads(after['state/state.json']), self.candidate)
        self.assertEqual(json.loads(after['export/main-server.json']), self.integration(self.candidate))
        for name in self.before.keys() - {'state/state.json', 'export/main-server.json'}:
            self.assertEqual(after[name], self.before[name], name)
        archives = list((self.root / 'backups').glob('before-key-import-*.tar.gz'))
        self.assertEqual(len(archives), 1)
        with tarfile.open(archives[0]) as archive:
            self.assertEqual(archive.extractfile('state/state.json').read(), self.before['state/state.json'])
            self.assertEqual(archive.extractfile('export/main-server.json').read(), self.before['export/main-server.json'])
        up = next(call for call in self.calls if 'up' in call)
        self.assertIn('--force-recreate', up)
        self.assertIn('--wait', up)
        self.assertFalse(any('--issue' in call or '--renew' in call or 'down' in call for call in self.calls))
        self.assertTrue(self.chown.called)

    def test_same_key_preserves_existing_ticket_and_exact_export_without_restart(self):
        self.candidate = dict(self.original, ticket_secret=self.candidate['ticket_secret'])
        self.args.replace_unused_state = False
        manage.import_keys(self.args, self.root)
        self.assertEqual(self.snapshot(), self.before)
        self.assertFalse(any('stop' in call or 'up' in call for call in self.calls))

    def test_invalid_import_never_stops_current_service(self):
        def reject(args, **kwargs):
            self.calls.append(list(map(str, args)))
            raise subprocess.CalledProcessError(1, args)
        self.execute.side_effect = reject
        with self.assertRaises(subprocess.CalledProcessError):
            manage.import_keys(self.args, self.root)
        self.assertEqual(self.snapshot(), self.before)
        self.assertFalse(any('stop' in call or 'up' in call for call in self.calls))

    def test_failed_activation_restores_original_state_and_restarts_original_service(self):
        self.activation_failures = 1
        with self.assertRaisesRegex(RuntimeError, 'восстановлен'):
            manage.import_keys(self.args, self.root)
        self.assertEqual(self.snapshot(), self.before)
        self.assertEqual(sum('up' in call for call in self.calls), 2)
        self.assertTrue(list((self.root / 'backups').glob('before-key-import-*.tar.gz')))

    def test_failed_rollback_keeps_backup_and_reports_recovery_path(self):
        self.activation_failures = 2
        with self.assertRaisesRegex(RuntimeError, '[Рр]езервн'):
            manage.import_keys(self.args, self.root)
        self.assertEqual(self.snapshot(), self.before)
        self.assertTrue(list((self.root / 'backups').glob('before-key-import-*.tar.gz')))

    def test_failure_between_directory_switches_restores_both_originals(self):
        rename = Path.rename
        failed = False
        def interrupted(path, target):
            nonlocal failed
            if path == self.root / 'export' and not failed:
                failed = True
                raise OSError('simulated rename failure')
            return rename(path, target)
        with mock.patch.object(Path, 'rename', interrupted), self.assertRaisesRegex(RuntimeError, 'восстановлен'):
            manage.import_keys(self.args, self.root)
        self.assertEqual(self.snapshot(), self.before)

    def test_backup_failure_never_stops_current_service(self):
        with mock.patch.object(manage, 'backup', side_effect=OSError('no space for backup')), self.assertRaises(OSError):
            manage.import_keys(self.args, self.root)
        self.assertEqual(self.snapshot(), self.before)
        self.assertFalse(any('stop' in call or 'up' in call for call in self.calls))

    def test_incomplete_or_ambiguous_import_is_rejected(self):
        for fields in ({'import_json': None}, {'import_public': str(self.source)},
                       {'import_json': None, 'import_public': str(self.source)}):
            with self.subTest(fields=fields), self.assertRaises(ValueError):
                manage.import_keys(argparse.Namespace(**(vars(self.args) | fields)), self.root)
        self.assertEqual(self.snapshot(), self.before)
        self.assertEqual(self.calls, [])

    def test_import_sources_inside_directories_being_replaced_are_rejected(self):
        for directory, option in (('state', 'import_json'), ('export', 'import_json'),
                                  ('state', 'import_private'), ('export', 'import_public')):
            source = self.root / directory / 'source-key.json'
            manage.private_json(source, self.candidate)
            values = dict(import_json=None, import_public=str(self.source), import_private=str(self.source), replace_unused_state=True)
            if option == 'import_json':
                values.update(import_json=str(source), import_public=None, import_private=None)
            else:
                values[option] = str(source)
            with self.subTest(directory=directory, option=option), self.assertRaisesRegex(ValueError, 'state|export'):
                manage.import_keys(argparse.Namespace(**values), self.root)
            self.assertTrue(source.exists())
            source.unlink()
        self.assertEqual(self.snapshot(), self.before)
        self.assertFalse(any('stop' in call for call in self.calls))

    def test_cli_import_dispatch(self):
        command = ['manage.py', 'import-keys', '--install-dir', str(self.root), '--import-json', str(self.source), '--replace-unused-state']
        with mock.patch.object(manage.sys, 'argv', command), mock.patch.object(manage.os, 'geteuid', return_value=0), \
                mock.patch.object(manage, 'ensure_docker'):
            try:
                manage.main()
            except SystemExit as error:
                self.fail(f'Import maintenance command unavailable: {error}')
        self.assertEqual(json.loads((self.root / 'state/state.json').read_text()), self.candidate)


if __name__ == '__main__':
    unittest.main()
