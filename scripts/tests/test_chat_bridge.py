import base64
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import types
import unittest
from unittest import mock

BRIDGE_PATH = Path(__file__).parents[1] / 'chat_bridge.py'
SPEC = importlib.util.spec_from_file_location('chat_bridge', BRIDGE_PATH)
bridge = importlib.util.module_from_spec(SPEC) if SPEC else None
if BRIDGE_PATH.exists():
    SPEC.loader.exec_module(bridge)


class BridgeEntryPointTests(unittest.TestCase):
    def test_preparation_and_finish_are_callable_entrypoints(self):
        self.assertTrue(callable(getattr(bridge, 'prepare_chat', None)))
        self.assertTrue(callable(getattr(bridge, 'finish_chat', None)))


@unittest.skipUnless(hasattr(bridge, 'prepare_chat'), 'entrypoint not implemented')
class ChatBridgeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.root = self.base / 'chat'
        self.root.mkdir(mode=0o700)
        self.home = self.base / 'home'
        self.home.mkdir(mode=0o700)
        self.release = self.root / 'releases/v2.1.0'
        (self.release / 'scripts').mkdir(parents=True)
        # Pin the real main-server controller so this separate repository's tests
        # also work in CI and standalone clones without a sibling server checkout.
        shutil.copyfile(Path(__file__).parent / 'fixtures/familychat_controller.py', self.release / 'scripts/familychat.py')
        (self.release / 'release.json').write_text('{"external_key_service":1}')
        (self.release / 'compose.keyserver.yaml').touch()
        (self.root / 'current').symlink_to(self.release)
        (self.root / 'secrets').mkdir(mode=0o700)
        self.public = base64.b64encode(bytes(range(32))).decode()
        self.private = base64.b64encode(bytes(range(31, -1, -1))).decode()
        self.key_id = '630dcd2966c4336691125448bbb25b4ff412a49c732db2c8abc1b8581bd710dd'
        for name, content in [('content-public-key.txt', self.public), ('content-private-key.txt', self.private), ('admin-password.txt', 'admin')]:
            self.write(self.root / 'secrets' / name, content.encode())
        self.env = b'POSTGRES_PASSWORD=keep-this-secret\n'
        self.write(self.root / '.env', self.env, 0o640)
        self.write(self.root / 'installation.json', b'{"public_ip":"213.155.29.175","project":"familychat","domain":"chat.example.com"}')
        self.patches = contextlib.ExitStack()
        self.addCleanup(self.patches.close)
        self.patches.enter_context(mock.patch.object(bridge, 'ROOT_UID', os.getuid(), create=True))
        self.patches.enter_context(mock.patch.object(bridge, 'HELPER', self.base / 'lib/bridge.py', create=True))
        self.patches.enter_context(mock.patch.object(bridge, 'STATE_DIR', self.base / 'state', create=True))
        self.patches.enter_context(mock.patch.object(bridge.os, 'geteuid', return_value=0))
        self.patches.enter_context(mock.patch('pwd.getpwnam', return_value=types.SimpleNamespace(
            pw_uid=os.getuid(), pw_gid=os.getgid(), pw_dir=str(self.home), pw_name='alice')))
        original_chown = os.chown
        original_fchown = os.fchown
        self.patches.enter_context(mock.patch.object(bridge.os, 'chown', side_effect=lambda path, uid, gid, **kwargs:
            None if uid == 10001 else original_chown(path, uid, os.getgid() if gid == 0 else gid, **kwargs)))
        self.patches.enter_context(mock.patch.object(bridge.os, 'fchown', side_effect=lambda fd, uid, gid:
            original_fchown(fd, os.getuid() if uid == 0 else uid, os.getgid() if gid == 0 else gid)))
        self.output = io.StringIO()
        self.errors = io.StringIO()
        self.patches.enter_context(contextlib.redirect_stdout(self.output))
        self.patches.enter_context(contextlib.redirect_stderr(self.errors))
        self.calls = []
        self.failures = []

    def write(self, path, data, mode=0o600):
        path.write_bytes(data)
        path.chmod(mode)

    @property
    def transport(self):
        return self.home / '.familychat-keyserver-link'

    def prepare(self):
        self.assertEqual(bridge.prepare_chat(self.root, 'alice'), 0)
        return json.loads((bridge.STATE_DIR / 'metadata.json').read_text())['nonce']

    def connection(self, public=None):
        public = public or self.public
        config = dict(scheme='fc1', key_id=hashlib.sha256(base64.b64decode(public)).hexdigest(),
                      public_key=public, key_server_url='https://keys.example.com:8443/api/v1/keys/current',
                      ticket_issuer='familychat', ticket_secret=base64.b64encode(b'S' * 32).decode())
        data = (json.dumps(config, indent=2) + '\n').encode()
        self.write(self.transport / 'connection.json', data)
        return data

    def mock_docker(self):
        def run(args, **kwargs):
            call = [str(value) for value in args]
            self.calls.append(call)
            if self.failures and self.failures[0](call):
                self.failures.pop(0)
                raise subprocess.CalledProcessError(1, call, output='ticket secret leaked upstream')
            return subprocess.CompletedProcess(call, 0, '', '')
        return mock.patch.object(bridge.subprocess, 'run', side_effect=run)

    def result(self):
        lines = [line for line in self.output.getvalue().splitlines() if line.startswith('FAMILYCHAT_LINK_RESULT ')]
        return json.loads(lines[-1].split(' ', 1)[1])

    def test_prepare_exports_existing_keys_privately_without_restarting_chat(self):
        nonce = self.prepare()
        payload = json.loads((self.transport / 'payload.json').read_text())
        self.assertEqual(payload['nonce'], nonce)
        self.assertEqual(payload['key'], {'scheme':'fc1', 'key_id':self.key_id, 'public_key':self.public, 'private_key':self.private})
        self.assertEqual(payload['ssh_host'], '213.155.29.175')
        self.assertEqual(payload['ssh_user'], 'alice')
        self.assertEqual(stat.S_IMODE((self.transport / 'payload.json').stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(self.transport.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(bridge.HELPER.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE((bridge.STATE_DIR / 'metadata.json').stat().st_mode), 0o600)
        self.assertNotIn(self.private, (bridge.STATE_DIR / 'metadata.json').read_text())
        self.assertIn('connect-chat --chat alice@213.155.29.175', self.output.getvalue())
        self.assertNotIn(self.private, self.output.getvalue() + self.errors.getvalue())
        self.assertEqual((self.root / '.env').read_bytes(), self.env)

    def test_finish_applies_same_key_and_keeps_durable_backup_without_private_key_copy(self):
        nonce = self.prepare()
        config_bytes = self.connection()
        with self.mock_docker():
            self.assertEqual(bridge.finish_chat(nonce), 0)
        receipt = json.loads((self.transport / 'receipt.json').read_text())
        self.assertEqual(receipt, {'version':1, 'nonce':nonce, 'status':'applied', 'key_id':self.key_id,
                                   'config_sha256':hashlib.sha256(config_bytes).hexdigest()})
        self.assertFalse((self.transport / 'payload.json').exists())
        self.assertFalse((self.transport / 'connection.json').exists())
        self.assertIn('KEY_SERVICE_CONFIG_FILE=./secrets/key-service.json', (self.root / '.env').read_text())
        self.assertEqual(json.loads((self.root / 'secrets/key-service.json').read_text())['public_key'], self.public)
        backup = self.root / 'backups' / ('before-keyserver-link-' + nonce)
        self.assertEqual((backup / '.env').read_bytes(), self.env)
        self.assertEqual(stat.S_IMODE((backup / '.env').stat().st_mode), 0o600)
        self.assertFalse((backup / 'content-private-key.txt').exists())
        self.assertEqual((self.root / 'secrets/content-private-key.txt').read_text(), self.private)
        self.assertEqual(self.result()['status'], 'applied')
        self.assertNotIn(base64.b64encode(b'S' * 32).decode(), self.output.getvalue() + self.errors.getvalue())

    def test_finish_retry_after_lost_success_response_never_recreates_api_again(self):
        nonce = self.prepare()
        self.connection()
        with self.mock_docker():
            self.assertEqual(bridge.finish_chat(nonce), 0)
            self.assertEqual(bridge.finish_chat(nonce), 0)
        restarts = [call for call in self.calls if '--force-recreate' in call]
        self.assertEqual(len(restarts), 1)
        self.assertEqual(self.result()['status'], 'applied')

    def test_key_mismatch_is_safe_rejection_without_changing_main_server(self):
        nonce = self.prepare()
        self.connection(base64.b64encode(b'X' * 32).decode())
        with self.mock_docker():
            self.assertEqual(bridge.finish_chat(nonce), 41)
        self.assertEqual((self.root / '.env').read_bytes(), self.env)
        self.assertFalse((self.root / 'secrets/key-service.json').exists())
        self.assertEqual(self.calls, [])
        self.assertEqual(self.result()['status'], 'rolled_back')
        self.assertTrue((self.transport / 'connection.json').exists())

    def test_current_key_changed_after_prepare_rejects_connection(self):
        nonce = self.prepare()
        self.connection()
        self.write(self.root / 'secrets/content-public-key.txt', base64.b64encode(b'Y' * 32))
        with self.mock_docker():
            self.assertEqual(bridge.finish_chat(nonce), 41)
        self.assertEqual(self.calls, [])
        self.assertEqual((self.root / '.env').read_bytes(), self.env)

    def test_failed_api_start_restores_exact_bytes_and_file_metadata_then_restarts_original(self):
        nonce = self.prepare()
        self.connection()
        self.failures = [lambda call: '--force-recreate' in call]
        before = (self.root / '.env').stat()
        with self.mock_docker():
            self.assertEqual(bridge.finish_chat(nonce), 41)
        self.assertEqual((self.root / '.env').read_bytes(), self.env)
        after = (self.root / '.env').stat()
        self.assertEqual((stat.S_IMODE(after.st_mode), after.st_uid, after.st_gid),
                         (stat.S_IMODE(before.st_mode), before.st_uid, before.st_gid))
        self.assertFalse((self.root / 'secrets/key-service.json').exists())
        self.assertEqual(len([call for call in self.calls if '--force-recreate' in call]), 2)
        self.assertEqual(self.result()['status'], 'rolled_back')
        self.assertNotIn('leaked upstream', self.output.getvalue() + self.errors.getvalue())

    def test_failed_rollback_reports_attention_and_retains_recovery_files(self):
        nonce = self.prepare()
        self.connection()
        self.failures = [lambda call: '--force-recreate' in call, lambda call: '--force-recreate' in call]
        with self.mock_docker():
            self.assertEqual(bridge.finish_chat(nonce), 42)
        self.assertEqual(self.result()['status'], 'attention')
        self.assertTrue((self.root / 'backups' / ('before-keyserver-link-' + nonce) / '.env').exists())
        self.assertTrue((self.transport / 'connection.json').exists())

    def test_public_only_prepare_requires_already_enabled_external_configuration(self):
        (self.root / 'secrets/content-private-key.txt').unlink()
        self.assertEqual(bridge.prepare_chat(self.root, 'alice'), 41)
        self.transport.mkdir(mode=0o700, exist_ok=True)
        config_bytes = self.connection()
        self.write(self.root / 'secrets/key-service.json', config_bytes, 0o400)
        self.write(self.root / '.env', self.env + b'KEY_SERVICE_CONFIG_FILE=./secrets/key-service.json\n')
        self.prepare()
        self.assertNotIn('private_key', json.loads((self.transport / 'payload.json').read_text())['key'])

    def test_prepare_rejects_permissive_original_private_key(self):
        (self.root / 'secrets/content-private-key.txt').chmod(0o644)
        self.assertEqual(bridge.prepare_chat(self.root, 'alice'), 41)
        self.assertFalse((self.transport / 'payload.json').exists())

    def test_finish_rejects_wrong_nonce_symlink_and_oversized_transfer(self):
        nonce = self.prepare()
        self.connection()
        with self.mock_docker():
            self.assertEqual(bridge.finish_chat('0' * 32), 42)
            connection = self.transport / 'connection.json'
            connection.unlink()
            connection.symlink_to(self.root / '.env')
            self.assertEqual(bridge.finish_chat(nonce), 41)
            connection.unlink()
            self.write(connection, b'X' * 16385)
            self.assertEqual(bridge.finish_chat(nonce), 41)
        self.assertEqual(self.calls, [])

    def test_already_active_matching_configuration_does_not_restart_api(self):
        self.transport.mkdir(mode=0o700)
        config_bytes = self.connection()
        self.write(self.root / 'secrets/key-service.json', config_bytes, 0o400)
        self.write(self.root / '.env', self.env + b'KEY_SERVICE_CONFIG_FILE=./secrets/key-service.json\n')
        nonce = self.prepare()
        self.connection()
        with self.mock_docker():
            self.assertEqual(bridge.finish_chat(nonce), 0)
        self.assertFalse(any('--force-recreate' in call for call in self.calls))
        self.assertTrue(any('--wait' in call and call[-1] == 'api' for call in self.calls))

    def test_interrupted_apply_recovers_original_before_retrying_uploaded_config(self):
        nonce = self.prepare()
        config_bytes = self.connection()
        metadata_path = bridge.STATE_DIR / 'metadata.json'
        metadata = json.loads(metadata_path.read_text())
        metadata['backup'] = bridge._snapshot(self.root, nonce)
        metadata['phase'] = 'applying'
        self.write(metadata_path, json.dumps(metadata).encode())
        self.write(self.root / '.env', b'PARTIAL=wrong\n')
        self.write(self.root / 'secrets/key-service.json', config_bytes, 0o400)
        with self.mock_docker():
            self.assertEqual(bridge.finish_chat(nonce), 0)
        self.assertEqual(len([call for call in self.calls if '--force-recreate' in call]), 2)
        backup = Path(metadata['backup'])
        self.assertEqual((backup / '.env').read_bytes(), self.env)
        self.assertEqual(self.result()['status'], 'applied')

    def test_keyboard_interruption_rolls_back_but_keeps_connection_for_retry(self):
        nonce = self.prepare()
        self.connection()
        original_compose = bridge._compose
        count = 0
        def interrupted(*args, **kwargs):
            nonlocal count
            count += 1
            if count == 1:
                raise KeyboardInterrupt()
            return original_compose(*args, **kwargs)
        with self.mock_docker(), mock.patch.object(bridge, '_compose', side_effect=interrupted):
            self.assertEqual(bridge.finish_chat(nonce), 41)
        self.assertEqual((self.root / '.env').read_bytes(), self.env)
        self.assertTrue((self.transport / 'connection.json').is_file())

    def test_rollback_restores_preexisting_keyservice_content_mode_and_ownership(self):
        self.transport.mkdir(mode=0o700)
        config = json.loads(self.connection())
        config['ticket_issuer'] = 'old-issuer'
        original = (json.dumps(config) + '\n').encode()
        previous = self.root / 'secrets/key-service.json'
        self.write(previous, original, 0o640)
        nonce = self.prepare()
        self.connection()
        self.failures = [lambda call: '--force-recreate' in call]
        before = previous.stat()
        with self.mock_docker():
            self.assertEqual(bridge.finish_chat(nonce), 41)
        self.assertEqual(previous.read_bytes(), original)
        after = previous.stat()
        self.assertEqual((stat.S_IMODE(after.st_mode), after.st_uid, after.st_gid),
                         (stat.S_IMODE(before.st_mode), before.st_uid, before.st_gid))

    def test_failure_after_successful_apply_to_write_receipt_requires_attention(self):
        nonce = self.prepare()
        self.connection()
        with self.mock_docker(), mock.patch.object(bridge, '_receipt', side_effect=OSError('write failed')):
            self.assertEqual(bridge.finish_chat(nonce), 42)
        self.assertEqual(json.loads((bridge.STATE_DIR / 'metadata.json').read_text())['phase'], 'applied')
        with self.mock_docker():
            self.assertEqual(bridge.finish_chat(nonce), 0)
        self.assertEqual(len([call for call in self.calls if '--force-recreate' in call]), 1)

    def test_lost_success_response_with_changed_user_remains_uncertain(self):
        nonce = self.prepare()
        self.connection()
        with self.mock_docker():
            self.assertEqual(bridge.finish_chat(nonce), 0)
            with mock.patch('pwd.getpwnam', side_effect=KeyError('user removed')):
                self.assertEqual(bridge.finish_chat(nonce), 42)
        self.assertEqual(self.result()['status'], 'attention')

    def test_import_does_not_create_python_cache_inside_immutable_release(self):
        nonce = self.prepare()
        self.connection()
        with self.mock_docker():
            self.assertEqual(bridge.finish_chat(nonce), 0)
        self.assertFalse((self.release / 'scripts/__pycache__').exists())

    def test_busy_finish_lock_never_reports_safe_rollback_of_an_inflight_apply(self):
        nonce = self.prepare()
        self.connection()
        metadata_path = bridge.STATE_DIR / 'metadata.json'
        metadata = json.loads(metadata_path.read_text())
        with self.mock_docker(), bridge._lock(bridge.STATE_DIR / '.lock'):
            for phase in ('applying', 'applied'):
                with self.subTest(phase=phase):
                    metadata['phase'] = phase
                    self.write(metadata_path, json.dumps(metadata).encode())
                    self.assertEqual(bridge.finish_chat(nonce), 42)
                    self.assertEqual(self.result()['status'], 'attention')
                    self.assertEqual(json.loads(metadata_path.read_text())['phase'], phase)
        self.assertEqual(self.calls, [])
        self.assertEqual((self.root / '.env').read_bytes(), self.env)
        self.assertTrue((self.transport / 'connection.json').is_file())

    def test_unreadable_pending_state_cannot_authorize_peer_key_rollback(self):
        nonce = self.prepare()
        (bridge.STATE_DIR / 'metadata.json').chmod(0o400)
        with self.mock_docker():
            self.assertEqual(bridge.finish_chat(nonce), 42)
        self.assertEqual(self.result()['status'], 'attention')
        self.assertEqual(self.calls, [])


if __name__ == '__main__':
    unittest.main()
