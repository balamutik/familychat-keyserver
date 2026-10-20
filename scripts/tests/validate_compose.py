#!/usr/bin/env python3
"""Validate the actual generated Compose deployment without starting containers."""
import json
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile


def validate(archive_path):
    with tempfile.TemporaryDirectory(prefix='keyserver-compose-') as temporary:
        root = Path(temporary)
        with tarfile.open(archive_path) as archive:
            for name in ('compose.yaml', 'release.json'):
                (root / name).write_bytes(archive.extractfile(name).read())
        (root / 'service.env').write_text('KEYSERVER_DOMAIN=keys.example.com\nKEYSERVER_PORT=8443\n')
        result = subprocess.run(['docker', 'compose', '--project-directory', str(root), '--env-file', str(root / 'service.env'),
                                 '-f', str(root / 'compose.yaml'), 'config', '--format', 'json'],
                                check=True, capture_output=True, text=True)
        config = json.loads(result.stdout)
        assert list(config['services']) == ['keyserver'], 'unexpected services'
        service = config['services']['keyserver']
        assert 'build' not in service, 'release must never build application source'
        assert service['image'] == json.loads((root / 'release.json').read_text())['image']
        assert len(service['ports']) == 1
        assert str(service['ports'][0]['published']) == '8443'
        assert service['ports'][0]['target'] == 8443
        mounts = {mount['target']:mount for mount in service['volumes']}
        assert set(mounts) == {'/state', '/tls', '/grants'}
        assert all(mounts[name]['read_only'] for name in ('/state','/tls'))
        assert not mounts['/grants'].get('read_only', False)
        assert service['healthcheck']['test'][1] == '/familychat-keyserver'
        print('Release Compose validated: immutable image, HTTPS 8443, private state/TLS bind mounts')


if __name__ == '__main__':
    validate(sys.argv[1])
