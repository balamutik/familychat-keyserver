import contextlib
import gzip
import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
import urllib.request
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
BOOTSTRAP = ROOT / 'install.sh'
IMAGE = 'ghcr.io/balamutik/familychat-keyserver@sha256:' + 'b' * 64


def bundle(changes=None, extra=None, padding=0):
    files = dict.fromkeys(('README.md', 'scripts/manage.py', 'scripts/install.sh', 'scripts/update.sh',
                          'scripts/renew.sh', 'scripts/backup.sh'), b'echo fixture\n')
    files['release.json'] = json.dumps(dict(version='v1.2.3', image=IMAGE, repository='balamutik/familychat-keyserver')).encode()
    files['compose.yaml'] = ('services:\n  keyserver:\n    image: ' + IMAGE + '\n').encode()
    files.update(changes or {})
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode='w:') as archive:
        for name, value in files.items():
            member = tarfile.TarInfo(name)
            member.size = len(value)
            archive.addfile(member, io.BytesIO(value))
        if extra:
            member = tarfile.TarInfo(extra)
            member.size = 1
            archive.addfile(member, io.BytesIO(b'x'))
    return gzip.compress(raw.getvalue() + b'\0' * padding)


class BootstrapTests(unittest.TestCase):
    def run_payload(self, payload, checksum=None, version='v1.2.3'):
        program = BOOTSTRAP.read_text().split("<<'PY'\n", 1)[1].split('\nPY\n', 1)[0]
        calls = []
        digest = checksum or hashlib.sha256(payload).hexdigest()
        def open_request(request, timeout):
            url = request.full_url
            calls.append(url)
            if url.endswith('/latest'):
                return contextlib.closing(io.BytesIO(b'{"tag_name":"v1.2.3"}'))
            data = (digest + '  familychat-keyserver.tar.gz\n').encode() if url.endswith('SHA256SUMS') else payload
            return contextlib.closing(io.BytesIO(data))
        opener = mock.Mock()
        opener.open.side_effect = open_request
        with tempfile.TemporaryDirectory() as directory:
            with mock.patch.object(urllib.request, 'build_opener', return_value=opener), \
                    mock.patch.object(sys, 'argv', ['-', directory, version]):
                try:
                    exec(compile(program, str(BOOTSTRAP), 'exec'), {})
                except SystemExit as error:
                    return error.code, list(Path(directory).rglob('*')), calls
            return 0, [str(path.relative_to(directory)) for path in Path(directory).rglob('*')], calls

    def test_valid_archive_and_latest_resolution(self):
        code, files, calls = self.run_payload(bundle(), version='')
        self.assertEqual(code, 0)
        self.assertIn('scripts/manage.py', files)
        self.assertEqual(calls[0], 'https://api.github.com/repos/balamutik/familychat-keyserver/releases/latest')
        self.assertTrue(any('/download/v1.2.3/' in url for url in calls))

    def test_checksum_mismatch_never_extracts(self):
        code, files, _ = self.run_payload(bundle(), checksum='0' * 64)
        self.assertNotEqual(code, 0)
        self.assertEqual(files, [])

    def test_rejects_repository_version_image_build_and_path_substitution_before_extraction(self):
        for change, extra in (
            ({'release.json': b'{"repository":"evil/repo","version":"v1.2.3","image":"evil:latest"}'}, None),
            ({'release.json': json.dumps(dict(repository='balamutik/familychat-keyserver', version='v9.9.9', image=IMAGE)).encode()}, None),
            ({'compose.yaml': b'services:\n  keyserver:\n    image: evil:latest\n'}, None),
            ({'compose.yaml': ('services:\n  keyserver:\n    image: '+IMAGE+'\n    build: .\n').encode()}, None),
            ({}, '../escape'), ({}, '/absolute'), ({}, 'state/state.json'),
        ):
            with self.subTest(change=change, extra=extra):
                code, files, _ = self.run_payload(bundle(change, extra))
                self.assertNotEqual(code, 0)
                self.assertEqual(files, [])

    def test_rejects_oversized_uncompressed_archive_even_with_zero_padding(self):
        code, files, _ = self.run_payload(bundle(padding=17 << 20))
        self.assertNotEqual(code, 0)
        self.assertEqual(files, [])

    def test_pipe_invocation_preserves_space_arguments(self):
        script = 'source "$1" --help >/dev/null\nshift\npython3() { printf "%s\\0" "$@"; }\nrun_controller "/tmp/release" update "$@"'
        result = subprocess.run(['bash', '-c', script, 'test', str(BOOTSTRAP), '--certbot-dns-args',
                                 '/root/dns credentials.json', '--webroot', '/srv/acme challenges'], input='', capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.split('\0')[:-1], ['/tmp/release/scripts/manage.py', 'update', '--source',
                         '/tmp/release', '--certbot-dns-args', '/root/dns credentials.json', '--webroot', '/srv/acme challenges'])


if __name__ == '__main__':
    unittest.main()
