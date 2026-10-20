import importlib.util
import io
import json
import os
from pathlib import Path
import socket
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location("keyserver_manage", Path(__file__).parents[1] / "manage.py")
manage = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(manage)


class DeployTests(unittest.TestCase):
    def config(self, root, **kwargs):
        config = dict(install_dir=str(root), domain="keys.example.com", email="family@example.com", port=8443,
                    client="certbot", challenge="standalone", webroot=None, dns_provider=None,
                    dns_env=None, certbot_dns_args=None, acme_binary="/root/.acme.sh/acme.sh")
        return config | kwargs

    def test_public_ip_certificates_require_shortlived_profile_for_both_clients(self):
        with tempfile.TemporaryDirectory() as root:
            for address in ("213.155.29.175", "2606:4700:4700::1111"):
                for client in ("certbot", "acme.sh"):
                    with self.subTest(address=address, client=client):
                        config = self.config(root, domain=address, client=client)
                        manage.validate(config)
                        args = manage.issue_command(config)
                        self.assertIn("shortlived", args)
                        if client == "certbot":
                            self.assertIn("--required-profile", args)
                            self.assertEqual(args[args.index("--ip-address") + 1], address)
                            self.assertNotIn("-d", args)
                        else:
                            self.assertIn("--certificate-profile", args)
                            self.assertEqual(args[args.index("--days") + 1], "3")

    def test_ip_certificate_rejects_nonpublic_addresses_and_dns_challenge(self):
        with tempfile.TemporaryDirectory() as root:
            for address in ("127.0.0.1", "10.0.0.1", "192.168.1.1", "100.64.0.1", "0.0.0.0",
                            "224.0.0.1", "999.1.1.1", "213.155.29.0175", "::1", "fc00::1", "fe80::1%eth0"):
                with self.subTest(address=address), self.assertRaises(ValueError):
                    manage.validate(self.config(root, domain=address))
            with self.assertRaisesRegex(ValueError, "DNS-01"):
                manage.validate(self.config(root, domain="213.155.29.175", client="acme.sh",
                                            challenge="dns", dns_provider="dns_cf"))

    def test_dns_names_keep_normal_certificate_profile(self):
        with tempfile.TemporaryDirectory() as root:
            for client in ("certbot", "acme.sh"):
                args = manage.issue_command(self.config(root, client=client))
                self.assertNotIn("shortlived", args)
                self.assertNotIn("--days", args)
                self.assertNotIn("--ip-address", args)
                self.assertEqual(args[args.index("-d") + 1], "keys.example.com")

    def test_acme_config_home_exists_and_is_private_before_registration_and_renewal(self):
        for renew in (False, True):
            with self.subTest(renew=renew), tempfile.TemporaryDirectory() as root:
                binary = Path(root) / "acme.sh"
                binary.write_text('#!/bin/sh\n[ "$1" = "--config-home" ] || exit 98\n'
                                  '[ -d "$2" ] || exit 99\ntouch "$2/http.header"\n')
                binary.chmod(0o700)
                config = self.config(root, client="acme.sh", acme_binary=str(binary))
                with mock.patch.object(manage, "ensure_port_available"), mock.patch.object(manage, "publish_certificate"):
                    try:
                        manage.certificate(config, renew=renew)
                    except Exception as error:
                        self.fail(f"ACME client ran before its config directory existed: {error}")
                home = Path(root) / "acme/acme.sh"
                self.assertTrue((home / "http.header").is_file())
                self.assertEqual(stat.S_IMODE(home.stat().st_mode), 0o700)

    def test_ip_renewal_keeps_profile_and_short_schedule(self):
        with tempfile.TemporaryDirectory() as root:
            config = self.config(root, client="acme.sh", domain="213.155.29.175")
            with mock.patch.object(manage, "ensure_port_available"), mock.patch.object(manage, "publish_certificate"), \
                    mock.patch.object(manage.subprocess, "run", return_value=mock.Mock(returncode=2)) as execute:
                manage.certificate(config, renew=True)
            args = execute.call_args.args[0]
            self.assertIn("--renew", args)
            self.assertIn("--certificate-profile", args)
            self.assertIn("shortlived", args)
            self.assertEqual(args[args.index("--days") + 1], "3")

    def test_acme_sudo_launch_uses_root_environment_for_issue_renew_and_install_cert(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / 'client/acme.sh'
            binary.parent.mkdir()
            trace = root / 'calls.jsonl'
            binary.write_text(f'#!{sys.executable}\n' + '''import json, os, pathlib, sys
args = sys.argv[1:]
if any(name.startswith('SUDO_') for name in os.environ):
    print('It seems that you are using sudo')
    sys.exit(1)
with open(''' + repr(str(trace)) + ''', 'a') as file:
    file.write(json.dumps({'args':args, 'home':os.environ['HOME'], 'dns_token':os.environ.get('CF_Token')}) + '\\n')
if '--install-cert' in args:
    for flag in ('--key-file', '--fullchain-file'):
        pathlib.Path(args[args.index(flag) + 1]).write_text('test certificate material')
sys.exit(2 if '--renew' in args else 0)
''')
            binary.chmod(0o700)
            dns_env = root / 'dns.env'
            dns_env.write_text('CF_Token=test-dns-token\n')
            dns_env.chmod(0o600)
            config = self.config(root, client='acme.sh', acme_binary=str(binary), dns_env=str(dns_env))
            inherited = dict(SUDO_COMMAND='/usr/bin/bash -s -- --client acme.sh', SUDO_UID='1000',
                             SUDO_GID='1000', SUDO_USER='family', HOME='/home/family')
            with mock.patch.dict(os.environ, inherited), mock.patch.object(manage.os, 'geteuid', return_value=0), \
                    mock.patch('pwd.getpwuid', return_value=mock.Mock(pw_dir='/root')), \
                    mock.patch.object(manage.os, 'chown'), mock.patch.object(manage, 'ensure_port_available'):
                try:
                    manage.certificate(config)
                    manage.certificate(config, renew=True)
                except (subprocess.CalledProcessError, RuntimeError) as error:
                    self.fail(f'ACME inherited sudo metadata from installer: {error}')
                self.assertEqual(os.environ['SUDO_COMMAND'], inherited['SUDO_COMMAND'])
                self.assertEqual(os.environ['HOME'], '/home/family')
            calls = [json.loads(line) for line in trace.read_text().splitlines()]
            self.assertEqual(len(calls), 5)
            for call in calls:
                self.assertEqual(call['home'], '/root')
                self.assertNotIn('--force', call['args'])
                self.assertEqual(call['args'][call['args'].index('--home') + 1], str(binary.parent))
            for call in calls:
                if '--issue' in call['args'] or '--renew' in call['args']:
                    self.assertEqual(call['dns_token'], 'test-dns-token')

    def test_acme_environment_preserves_sudo_identity_for_nonroot_process(self):
        original = dict(SUDO_COMMAND='sudo acme.sh', SUDO_UID='1000', HOME='/home/family', CF_Token='dns-token')
        with mock.patch.object(manage.os, 'geteuid', return_value=1000):
            env = manage.acme_environment(original)
        self.assertEqual(env, original)
        self.assertIsNot(env, original)

    def test_acme_capability_probe_uses_root_environment(self):
        with tempfile.TemporaryDirectory() as root:
            binary = Path(root) / 'acme.sh'
            binary.write_text(f'#!{sys.executable}\nimport os, sys\n'
                              "sys.exit(1) if any(k.startswith('SUDO_') for k in os.environ) else None\n"
                              "print('--certificate-profile --days')\n")
            binary.chmod(0o700)
            config = self.config(root, domain='213.155.29.175', client='acme.sh', acme_binary=str(binary))
            with mock.patch.dict(os.environ, {'SUDO_COMMAND':'/usr/bin/bash --client acme.sh', 'SUDO_UID':'1000'}), \
                    mock.patch.object(manage.os, 'geteuid', return_value=0), \
                    mock.patch('pwd.getpwuid', return_value=mock.Mock(pw_dir='/root')):
                manage.ensure_acme(config)

    def test_old_acme_clients_fail_early_for_ip_certificate(self):
        with tempfile.TemporaryDirectory() as root:
            binary = Path(root) / "acme.sh"
            binary.touch()
            for client in ("certbot", "acme.sh"):
                config = self.config(root, domain="213.155.29.175", client=client, acme_binary=str(binary))
                with self.subTest(client=client), mock.patch.object(manage.shutil, "which", return_value="/bin/certbot"), \
                        mock.patch.object(manage.subprocess, "run", return_value=mock.Mock(stdout="old client", returncode=0)):
                    with self.assertRaisesRegex(RuntimeError, "IP"):
                        manage.ensure_acme(config)

    def test_capable_acme_clients_can_issue_ip_certificates(self):
        with tempfile.TemporaryDirectory() as root:
            binary = Path(root) / "acme.sh"
            binary.touch()
            for client, help_text in (("certbot", "--ip-address --required-profile"),
                                      ("acme.sh", "--certificate-profile --days")):
                config = self.config(root, domain="213.155.29.175", client=client, acme_binary=str(binary))
                with self.subTest(client=client), mock.patch.object(manage.shutil, "which", return_value="/bin/certbot"), \
                        mock.patch.object(manage.subprocess, "run", return_value=mock.Mock(stdout=help_text, returncode=0)):
                    manage.ensure_acme(config)

    def test_server_url_brackets_ipv6_without_changing_certificate_identifier(self):
        config = self.config("/opt/familychat-keyserver", domain="2606:4700:4700::1111")
        self.assertEqual(manage.server_url(config), "https://[2606:4700:4700::1111]:8443")
        self.assertEqual(config["domain"], "2606:4700:4700::1111")

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
