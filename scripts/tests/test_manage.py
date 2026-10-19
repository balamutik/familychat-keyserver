import importlib.util
import io
import json
import os
from pathlib import Path
import socket
import stat
import tarfile
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location("keyserver_manage", Path(__file__).parents[1] / "manage.py")
manage = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(manage)


class DeployTests(unittest.TestCase):
    def config(self, root, **kwargs):
        return dict(install_dir=str(root), domain="keys.example.com", email="family@example.com", port=8443,
                    client="certbot", challenge="standalone", webroot=None, dns_provider=None,
                    dns_env=None, certbot_dns_args=None, acme_binary="/root/.acme.sh/acme.sh", **kwargs)

    def test_rejects_main_server_ports_and_unsafe_hostnames(self):
        with tempfile.TemporaryDirectory() as root:
            for port in (80, 443, 8080, 0, 65536):
                config = self.config(root)
                config["port"] = port
                with self.assertRaises(ValueError):
                    manage.validate(config)
            for domain in ("https://keys.example", "keys.example:8443", "--bad.example", "keys/example", "keys.example\nX"):
                config = self.config(root)
                config["domain"] = domain
                with self.assertRaises(ValueError):
                    manage.validate(config)

    def test_standalone_port_conflict_does_not_stop_other_service(self):
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            port = listener.getsockname()[1]
            with self.assertRaises(RuntimeError):
                manage.ensure_port_available(port)
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                pass

    def test_backup_really_includes_key_and_ticket_state_with_private_archive(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            (root / "state").mkdir(mode=0o700)
            (root / "state/state.json").write_text(json.dumps({"private_key": "keep", "ticket_secret": "also-keep"}))
            (root / "state/state.json").chmod(0o600)
            (root / "deploy.json").write_text("{}")
            (root / "service.env").write_text("KEYSERVER_PORT=8443\n")
            archive = root.parent / (root.name + ".tar.gz")
            self.addCleanup(archive.unlink, missing_ok=True)
            manage.backup(root, archive)
            self.assertEqual(stat.S_IMODE(archive.stat().st_mode), 0o600)
            with tarfile.open(archive) as tar:
                payload = json.load(tar.extractfile("state/state.json"))
                self.assertEqual(payload, {"private_key": "keep", "ticket_secret": "also-keep"})
                self.assertEqual(tar.getmember("state/state.json").mode, 0o600)
                self.assertIn("deploy.json", tar.getnames())
                self.assertIn("service.env", tar.getnames())
            with self.assertRaises(FileExistsError):
                manage.backup(root, archive)
            with self.assertRaises(ValueError):
                manage.backup(root, root / "state/recursive.tar.gz")

    def test_installed_source_remains_usable_for_updates(self):
        with tempfile.TemporaryDirectory() as root:
            destination = Path(root) / "installed"
            destination.mkdir()
            manage.copy_source(Path(__file__).parents[2], destination)
            self.assertTrue((destination / "app/compose.yaml").is_file())
            manage.copy_source(destination / "app", destination)
            self.assertTrue((destination / "compose.yaml").is_file())

    def test_dns_credentials_loaded_as_values_without_shell_execution(self):
        with tempfile.TemporaryDirectory() as root:
            file = Path(root) / "dns.env"
            file.write_text("CF_Token=abc$(touch /tmp/never-run-keyserver)\n# comment\nCF_Account_ID=123\n")
            file.chmod(0o600)
            env = manage.read_dns_env(file)
            self.assertEqual(env["CF_Token"], "abc$(touch /tmp/never-run-keyserver)")
            file.chmod(0o644)
            with self.assertRaises(ValueError):
                manage.read_dns_env(file)

    def test_certificate_commands_validate_on_standard_ca_port_and_support_both_clients(self):
        with tempfile.TemporaryDirectory() as root:
            config = self.config(root)
            certbot = manage.issue_command(config)
            self.assertIn("--standalone", certbot)
            self.assertNotIn("8443", certbot)
            config["client"] = "acme.sh"
            acme = manage.issue_command(config)
            self.assertIn("--standalone", acme)
            self.assertNotIn("--httpport", acme)
            config.update(challenge="dns", dns_provider="dns_cf")
            acme = manage.issue_command(config)
            self.assertIn("--dns", acme)
            self.assertIn("dns_cf", acme)


if __name__ == "__main__":
    unittest.main()
