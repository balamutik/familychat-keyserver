#!/usr/bin/env python3
"""Create an immutable deployment bundle without application source or secrets."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import re
import tarfile

ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = 'balamutik/familychat-keyserver'


def package(version, image, output):
    if not re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+', version):
        raise ValueError('version must be vX.Y.Z')
    if not re.fullmatch(r'ghcr\.io/balamutik/familychat-keyserver@sha256:[a-f0-9]{64}', image):
        raise ValueError('image must be the immutable public keyserver GHCR digest')
    files = {name: (ROOT / name).read_bytes() for name in (
        'README.md', 'scripts/manage.py', 'scripts/install.sh', 'scripts/update.sh', 'scripts/renew.sh',
        'scripts/backup.sh', 'scripts/chat_bridge.py', 'scripts/link_chat.py')}
    compose = (ROOT / 'compose.yaml').read_text()
    build = '    build:\n      context: ${KEYSERVER_BUILD_CONTEXT:-.}\n'
    if compose.count(build) != 1:
        raise ValueError('expected one local build declaration')
    compose = compose.replace(build, '').replace('    image: ${KEYSERVER_IMAGE:-familychat-keyserver:local}\n', f'    image: {image}\n')
    files['compose.yaml'] = compose.encode()
    files['release.json'] = (json.dumps(dict(version=version, repository=REPOSITORY, image=image), indent=2) + '\n').encode()
    output.mkdir(parents=True, exist_ok=True)
    with tarfile.open(output / 'familychat-keyserver.tar.gz', 'w:gz') as archive:
        for name, data in files.items():
            member = tarfile.TarInfo(name)
            member.size, member.mode = len(data), 0o755 if name.endswith('.sh') else 0o644
            archive.addfile(member, io.BytesIO(data))
    (output / 'install.sh').write_bytes((ROOT / 'install.sh').read_bytes())
    (output / 'SHA256SUMS').write_text(''.join(
        f'{hashlib.sha256((output / name).read_bytes()).hexdigest()}  {name}\n'
        for name in ('familychat-keyserver.tar.gz', 'install.sh')))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--version', required=True)
    parser.add_argument('--image', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    package(args.version, args.image, args.output)
