import argparse
import base64
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest import mock

SCRIPT = Path(__file__).parents[1] / 'link_chat.py'


class LinkChatTests(unittest.TestCase):
    def setUp(self):
        self.assertTrue(SCRIPT.exists(), 'two-command connector is not implemented')
        spec = importlib.util.spec_from_file_location('link_chat', SCRIPT)
        self.link = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.link)
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        for name in ('state', 'export'):
            (self.root / name).mkdir(mode=0o700)
        self.old = dict(key_id='old-key', private_key='old-private', ticket_secret='old-ticket')
        self.old_export = dict(key_id='old-key', ticket_secret='old-ticket')
        self.write(self.root / 'state/state.json', self.old)
        self.write(self.root / 'export/main-server.json', self.old_export)
        self.public = base64.b64encode(b'p' * 32).decode()
        self.key_id = hashlib.sha256(b'p' * 32).hexdigest()
        self.payload = dict(version=1, nonce='a' * 32, ssh_user='family', ssh_host='chat.example.com',
                            chat_root='/opt/familychat', key=dict(scheme='fc1', key_id=self.key_id,
                            public_key=self.public, private_key=base64.b64encode(b'k' * 32).decode()))
        self.new_export = dict(key_id=self.key_id, key_server_url='https://keys.example.com:8443/api/v1/keys/current', ticket_secret='new-ticket')
        self.imports = 0
        self.compose_calls = []
        self.manager = mock.Mock()
        self.manager.load_config.return_value = dict(domain='keys.example.com', port=8443)
        self.manager.import_keys.side_effect = self.import_keys
        self.manager.compose.side_effect = lambda root, *args: self.compose_calls.append(args)
        self.manager.private_json.side_effect = self.write
        self.manager.server_url.return_value = 'https://keys.example.com:8443'
        self.args = argparse.Namespace(chat='family@chat.example.com', ssh_port=22, ssh_identity=None)
        self.peer = mock.MagicMock()
        self.peer.__enter__.return_value = self.peer
        self.peer.receive.side_effect = self.receive
        self.peer.finish.return_value = 0
        self.payload_available = True
        self.receipt = None
        self.patches = [mock.patch.object(self.link, 'SSHPeer', return_value=self.peer),
                        mock.patch.object(self.link.os, 'chown'), mock.patch.object(self.link.os, 'fchown')]
        for patch in self.patches:
            patch.start()
            self.addCleanup(patch.stop)

    @staticmethod
    def write(path, value):
        Path(path).write_text(json.dumps(value) + '\n')
        Path(path).chmod(0o600)

    def import_keys(self, args, root):
        self.imports += 1
        self.write(root / 'state/state.json', dict(key_id=self.key_id, private_key='chat-private', ticket_secret='new-ticket'))
        self.write(root / 'export/main-server.json', self.new_export)

    def receive(self, name, path, optional=False):
        if name.endswith('payload.json'):
            if not self.payload_available:
                return False
            self.write(path, self.payload)
        else:
            receipt = self.receipt or dict(version=1, nonce=self.payload['nonce'], status='applied', key_id=self.key_id,
                                           config_sha256=hashlib.sha256((self.root / 'export/main-server.json').read_bytes()).hexdigest())
            self.write(path, receipt)
        return True

    def run_connect(self):
        return self.link.connect_chat(self.args, self.root, self.manager)

    def test_import_connects_and_never_prints_private_material(self):
        output = io.StringIO()
        with redirect_stdout(output):
            self.run_connect()
        self.assertEqual(self.imports, 1)
        self.assertTrue(self.peer.send.called)
        self.assertEqual(json.loads((self.root / 'state/state.json').read_text())['key_id'], self.key_id)
        self.assertNotIn(self.payload['key']['private_key'], output.getvalue())
        self.assertNotIn('new-ticket', output.getvalue())

    def test_staged_release_manifest_does_not_skip_interrupted_upgrade(self):
        manifest = {'image': 'new-image', 'key_delivery': 'device-grant-v1'}
        (self.root / 'app').mkdir()
        self.write(self.root / 'app/release.json', manifest)
        self.manager.release_manifest.return_value = manifest
        self.manager.load_config.return_value = {'image': 'old-image'}
        self.link.ensure_keyserver_protocol(self.manager, self.root, self.root / 'source')
        self.manager.update.assert_called_once()
        self.manager.update.reset_mock()
        self.manager.load_config.return_value = manifest
        self.link.ensure_keyserver_protocol(self.manager, self.root, self.root / 'source')
        self.manager.update.assert_not_called()

    def test_confirmed_chat_rollback_restores_keyserver_originals(self):
        self.peer.finish.return_value = 41
        before = [(self.root / name).read_bytes() for name in ('state/state.json', 'export/main-server.json')]
        with self.assertRaisesRegex(RuntimeError, 'восстановлен'):
            self.run_connect()
        self.assertEqual(before, [(self.root / name).read_bytes() for name in ('state/state.json', 'export/main-server.json')])
        self.assertTrue(any('up' in call for call in self.compose_calls))

    def test_unknown_remote_outcome_keeps_imported_key_and_resumes_without_rotation(self):
        self.peer.finish.return_value = 255
        with self.assertRaisesRegex(RuntimeError, 'Повторите'):
            self.run_connect()
        before = (self.root / 'state/state.json').read_bytes()
        self.peer.finish.return_value = 0
        self.run_connect()
        self.assertEqual(self.imports, 1)
        self.assertEqual((self.root / 'state/state.json').read_bytes(), before)

    def test_interrupted_import_recovers_missing_state_before_retry(self):
        def interrupted(args, root):
            (root / 'state/state.json').unlink()
            (root / 'state').rmdir()
            raise SystemExit(9)
        self.manager.import_keys.side_effect = interrupted
        with self.assertRaises(SystemExit):
            self.run_connect()
        self.manager.import_keys.side_effect = self.import_keys
        self.run_connect()
        self.assertEqual(self.imports, 1)
        self.assertEqual(json.loads((self.root / 'state/state.json').read_text())['key_id'], self.key_id)

    def test_completed_retry_accepts_receipt_after_temporary_package_cleanup(self):
        self.run_connect()
        self.payload_available = False
        self.run_connect()
        self.assertEqual(self.imports, 1)
        self.assertEqual(self.peer.finish.call_count, 1)

    def test_wrong_receipt_never_claims_success_or_rolls_back_possible_committed_chat(self):
        self.receipt = dict(version=1, nonce='b' * 32, status='applied', key_id=self.key_id, config_sha256='wrong')
        with self.assertRaisesRegex(RuntimeError, 'Повторите'):
            self.run_connect()
        self.assertEqual(json.loads((self.root / 'state/state.json').read_text())['key_id'], self.key_id)
        self.assertFalse(self.compose_calls)

    def test_changed_keyserver_configuration_is_not_overwritten_on_resume(self):
        self.peer.finish.return_value = 255
        with self.assertRaises(RuntimeError):
            self.run_connect()
        self.write(self.root / 'export/main-server.json', dict(key_id='manual-change'))
        self.peer.finish.return_value = 0
        with self.assertRaisesRegex(RuntimeError, 'измен'):
            self.run_connect()
        self.assertEqual(self.imports, 1)

    def test_rejects_payload_with_wrong_fingerprint_or_ssh_user(self):
        for mutate in (lambda p: p['key'].update(key_id='bad'), lambda p: p.update(ssh_user='another')):
            original = json.loads(json.dumps(self.payload))
            mutate(self.payload)
            with self.assertRaises(ValueError):
                self.run_connect()
            self.payload = original
        self.assertEqual(self.imports, 0)

    def test_ssh_target_validation_blocks_option_and_shell_injection(self):
        for target in ('-oProxyCommand=bad', 'user@host;id', 'user@host\nX', 'user@@host', 'user@-host'):
            with self.subTest(target=target), self.assertRaises(ValueError):
                self.link.parse_peer(target)
        self.assertEqual(self.link.parse_peer('family@[2001:db8::1]'), ('family', '2001:db8::1'))
        self.assertEqual(self.link.parse_peer('john.smith@chat.example.com'), ('john.smith', 'chat.example.com'))


if __name__ == '__main__':
    unittest.main()
