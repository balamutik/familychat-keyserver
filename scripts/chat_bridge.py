#!/usr/bin/env python3
"""Standalone, root-run half of the FamilyChat key-server SSH handoff."""
import argparse
import base64
import contextlib
import fcntl
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import shlex
import stat
import subprocess
import sys
import urllib.parse

HELPER = Path('/usr/local/lib/familychat-keyserver-link/bridge.py')
STATE_DIR = Path('/var/lib/familychat-keyserver-link')
TRANSPORT = '.familychat-keyserver-link'
ROOT_UID = 0
NONCE = re.compile(r'[0-9a-f]{32}')
KEY_ID = re.compile(r'[0-9a-f]{64}')
USER = re.compile(r'[A-Za-z_][A-Za-z0-9_.-]{0,63}\$?')


class LinkError(Exception):
    """Safe, public-facing validation failure."""


def _absolute(path):
    path = Path(path)
    if not path.is_absolute() or '..' in path.parts:
        raise LinkError('Нужен абсолютный путь к установленному FamilyChat.')
    return path


@contextlib.contextmanager
def _directory(path):
    """Traverse directories without following any symlink, including parents."""
    path = _absolute(path)
    fd = os.open(path.anchor, os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[1:]:
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        yield fd
    finally:
        os.close(fd)


def _read(path, limit=16384, modes=None, owner=None):
    with _directory(path.parent) as parent:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_size > limit
                    or modes is not None and stat.S_IMODE(info.st_mode) not in modes
                    or owner is not None and info.st_uid != owner):
                raise LinkError('Небезопасный файл настроек или неверные права доступа.')
            data = b''
            while len(data) <= limit:
                chunk = os.read(fd, min(65536, limit + 1 - len(data)))
                if not chunk:
                    break
                data += chunk
            if len(data) > limit:
                raise LinkError('Слишком большой файл настроек.')
            return data, info
        finally:
            os.close(fd)


def _write(path, data, mode=0o600, uid=ROOT_UID, gid=0):
    with _directory(path.parent) as parent:
        name = '.link-' + secrets.token_hex(16)
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode, dir_fd=parent)
        try:
            with os.fdopen(fd, 'wb') as stream:
                stream.write(data)
                stream.flush()
                os.fchmod(stream.fileno(), mode)
                os.fchown(stream.fileno(), uid, gid)
                os.fsync(stream.fileno())
            os.replace(name, path.name, src_dir_fd=parent, dst_dir_fd=parent)
            os.fsync(parent)
        finally:
            try:
                os.unlink(name, dir_fd=parent)
            except FileNotFoundError:
                pass


def _json_write(path, value, uid=None, gid=0):
    _write(path, (json.dumps(value, indent=2) + '\n').encode(), uid=ROOT_UID if uid is None else uid, gid=gid)


def _private_directory(path, uid, gid, create=False):
    if create:
        # Existing ancestors are inspected without following symlinks first.
        missing = []
        ancestor = path
        while not ancestor.exists():
            if ancestor.is_symlink():
                raise LinkError('Ссылка вместо служебного каталога.')
            missing.append(ancestor)
            ancestor = ancestor.parent
        with _directory(ancestor):
            pass
        for item in reversed(missing):
            item.mkdir(mode=0o700)
            os.chown(item, uid, gid)
    with _directory(path) as fd:
        info = os.fstat(fd)
        if info.st_uid != uid or stat.S_IMODE(info.st_mode) != 0o700:
            raise LinkError('Служебный каталог должен принадлежать нужному пользователю и иметь права 700.')


@contextlib.contextmanager
def _lock(path):
    with _directory(path.parent) as parent:
        fd = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600, dir_fd=parent)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != ROOT_UID:
                raise LinkError('Небезопасный файл блокировки.')
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise LinkError('Другая команда FamilyChat уже выполняется.') from None
            yield
        finally:
            os.close(fd)


def _root_required():
    if os.geteuid() != 0:
        raise LinkError('Запустите команду с sudo или от root.')


def _key(public, key_id=None):
    if not isinstance(public, str):
        raise LinkError('Некорректный исходный ключ переписки.')
    raw = base64.b64decode(public, validate=True)
    fingerprint = hashlib.sha256(raw).hexdigest()
    if len(raw) != 32 or key_id is not None and key_id != fingerprint:
        raise LinkError('Отпечаток исходного ключа переписки не совпадает.')
    return {'scheme':'fc1', 'key_id':fingerprint, 'public_key':public}


def _config(data):
    value = json.loads(data)
    expected = {'scheme', 'key_id', 'public_key', 'key_server_url', 'ticket_issuer', 'ticket_secret'}
    if not isinstance(value, dict) or set(value) != expected or not all(isinstance(item, str) for item in value.values()):
        raise LinkError('Некорректный файл подключения сервера ключей.')
    _key(value['public_key'], value['key_id'])
    url = urllib.parse.urlsplit(value['key_server_url'])
    if (value['scheme'] != 'fc1' or len(base64.b64decode(value['ticket_secret'], validate=True)) != 32
            or not value['ticket_issuer'].strip() or len(value['ticket_issuer']) > 200
            or url.scheme != 'https' or not url.hostname or url.username is not None or url.password is not None
            or url.path != '/api/v1/keys/current' or url.query or url.fragment
            or url.port is None or not 1 <= url.port <= 65535 or url.port in (80, 443, 8080)):
        raise LinkError('Некорректный файл подключения сервера ключей.')
    return value


def _external(root):
    env, _ = _read(root / '.env', 1 << 20)
    return any(line.startswith(b'KEY_SERVICE_CONFIG_FILE=') and line.partition(b'=')[2].strip()
               for line in env.splitlines())


def _current_key(root, include_private=False):
    public_path = root / 'secrets/content-public-key.txt'
    key = None
    if public_path.exists() or public_path.is_symlink():
        data, _ = _read(public_path, 256, modes={0o400, 0o600})
        key = _key(data.decode().strip())
    external = _external(root)
    if external:
        config = _config(_read(root / 'secrets/key-service.json')[0])
        active = _key(config['public_key'], config['key_id'])
        if key is not None and active['key_id'] != key['key_id']:
            raise LinkError('Исходный и активный ключи переписки не совпадают.')
        key = active
    if key is None:
        raise LinkError('Не найден исходный публичный ключ переписки.')
    if include_private:
        private = root / 'secrets/content-private-key.txt'
        if private.exists() or private.is_symlink():
            data, _ = _read(private, 256, modes={0o400, 0o600})
            value = data.decode().strip()
            if len(base64.b64decode(value, validate=True)) != 32:
                raise LinkError('Некорректный исходный приватный ключ переписки.')
            key['private_key'] = value
        elif not external:
            raise LinkError('Не найден исходный приватный ключ. Сначала восстановите его из резервной копии.')
    return key


def _release(root):
    # current is the installer's deliberate symlink; its target must stay inside releases.
    release = (root / 'current').resolve(strict=True)
    if release.parent != root / 'releases' or not re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+', release.name):
        raise LinkError('Не найдена завершённая установка FamilyChat.')
    with _directory(release) as fd:
        info = os.fstat(fd)
        if info.st_uid != ROOT_UID or info.st_mode & 0o022:
            raise LinkError('Каталог релиза должен принадлежать root.')
    manifest = json.loads(_read(release / 'release.json', owner=ROOT_UID)[0])
    if type(manifest.get('external_key_service')) is not int or manifest['external_key_service'] < 1:
        raise LinkError('Сначала обновите основной сервер до релиза с поддержкой сервера ключей.')
    _read(release / 'compose.keyserver.yaml', 1 << 20, owner=ROOT_UID)
    _read(release / 'scripts/familychat.py', 1 << 20, owner=ROOT_UID)
    return release


def _controller(release):
    spec = importlib.util.spec_from_file_location('familychat_installed_link_controller', release / 'scripts/familychat.py')
    module = importlib.util.module_from_spec(spec)
    previous = sys.dont_write_bytecode
    try:
        sys.dont_write_bytecode = True
        spec.loader.exec_module(module)
    finally:
        sys.dont_write_bytecode = previous
    for name in ('load_state', 'configure_key_service', 'compose'):
        if not callable(getattr(module, name, None)):
            raise LinkError('Установленный контроллер FamilyChat не поддерживает подключение.')
    return module


def _choose_user(ssh_user):
    if ssh_user is None:
        sudo_user = os.environ.get('SUDO_USER', '')
        if sudo_user and sudo_user != 'root':
            ssh_user = sudo_user
        else:
            with open('/dev/tty', 'r+') as tty:
                tty.write('SSH-пользователь этого сервера [root]: ')
                tty.flush()
                ssh_user = tty.readline().strip() or 'root'
    if not isinstance(ssh_user, str) or not USER.fullmatch(ssh_user):
        raise LinkError('Некорректное имя SSH-пользователя.')
    account = pwd.getpwnam(ssh_user)
    home = _absolute(account.pw_dir)
    with _directory(home) as fd:
        if os.fstat(fd).st_uid != account.pw_uid:
            raise LinkError('Домашний каталог принадлежит другому пользователю.')
    return ssh_user, account, home


def _save_meta(value):
    _json_write(STATE_DIR / 'metadata.json', value)


def prepare_chat(chat_root, ssh_user=None):
    """Export existing key material to the SSH user's private transfer directory."""
    try:
        _root_required()
        root = _absolute(chat_root)
        _private_directory(root, ROOT_UID, 0)
        _private_directory(STATE_DIR, ROOT_UID, 0, create=True)
        with _lock(STATE_DIR / '.lock'), _lock(root / '.lock'):
            _release(root)
            state = json.loads(_read(root / 'installation.json')[0])
            host = str(ipaddress.ip_address(state['public_ip']))
            key = _current_key(root, include_private=True)
            username, account, home = _choose_user(ssh_user)
            transfer = home / TRANSPORT
            _private_directory(transfer, account.pw_uid, account.pw_gid, create=True)
            metadata_path = STATE_DIR / 'metadata.json'
            nonce = secrets.token_hex(16)
            if metadata_path.exists() or metadata_path.is_symlink():
                old = json.loads(_read(metadata_path, owner=ROOT_UID, modes={0o600})[0])
                if old.get('phase') in ('applying', 'attention'):
                    raise LinkError('Завершите предыдущее подключение повторной командой на сервере ключей.')
                if (old.get('phase') == 'prepared' and old.get('chat_root') == str(root)
                        and old.get('ssh_user') == username and old.get('key_id') == key['key_id']
                        and NONCE.fullmatch(str(old.get('nonce', '')))):
                    nonce = old['nonce']
            _private_directory(HELPER.parent, ROOT_UID, 0, create=True)
            _write(HELPER, Path(__file__).read_bytes(), uid=ROOT_UID)
            metadata = {'version':1, 'chat_root':str(root), 'nonce':nonce, 'key_id':key['key_id'],
                        'ssh_user':username, 'uid':account.pw_uid, 'gid':account.pw_gid,
                        'home':str(home), 'transport':str(transfer), 'phase':'prepared'}
            _save_meta(metadata)
            _json_write(transfer / 'payload.json', {'version':1, 'nonce':nonce, 'key':key,
                        'chat_root':str(root), 'ssh_user':username, 'ssh_host':host}, account.pw_uid, account.pw_gid)
            destination = username + '@' + ('[' + host + ']' if ':' in host else host)
            print('Подготовка завершена. На VPS сервера ключей выполните вторую команду:')
            print("curl --proto '=https' --tlsv1.2 -fsSL https://github.com/balamutik/familychat-keyserver/releases/latest/download/install.sh | sudo bash -s -- connect-chat --chat " + shlex.quote(destination))
            return 0
    except (Exception, KeyboardInterrupt):
        print('Ошибка подготовки подключения. Проверьте установку, исходные ключи и права SSH-пользователя.', file=sys.stderr)
        return 41


def _metadata(nonce):
    if not isinstance(nonce, str) or not NONCE.fullmatch(nonce):
        raise LinkError('Некорректный идентификатор подключения.')
    _private_directory(STATE_DIR, ROOT_UID, 0)
    value = json.loads(_read(STATE_DIR / 'metadata.json', owner=ROOT_UID, modes={0o600})[0])
    if (not isinstance(value, dict) or value.get('version') != 1 or value.get('nonce') != nonce
            or not KEY_ID.fullmatch(str(value.get('key_id', '')))
            or not USER.fullmatch(str(value.get('ssh_user', '')))
            or value.get('phase') not in ('prepared', 'applying', 'applied', 'rolled_back', 'attention')
            or type(value.get('uid')) is not int or type(value.get('gid')) is not int):
        raise LinkError('Не совпадают сохранённые данные подключения.')
    root, home = _absolute(value['chat_root']), _absolute(value['home'])
    if value.get('transport') != str(home / TRANSPORT):
        raise LinkError('Некорректный каталог передачи.')
    account = pwd.getpwnam(value['ssh_user'])
    if (account.pw_uid, account.pw_gid, account.pw_dir) != (value['uid'], value['gid'], str(home)):
        raise LinkError('SSH-пользователь изменён после подготовки.')
    _private_directory(root, ROOT_UID, 0)
    _private_directory(home / TRANSPORT, value['uid'], value['gid'])
    return value


def _snapshot(root, nonce):
    backup = root / 'backups' / ('before-keyserver-link-' + nonce)
    _private_directory(backup, ROOT_UID, 0, create=True)
    items = []
    for source, name in ((root / '.env', '.env'), (root / 'secrets/key-service.json', 'key-service.json')):
        try:
            data, info = _read(source, 1 << 20)
        except FileNotFoundError:
            if name == '.env':
                raise
            items.append({'name':name, 'absent':True})
        else:
            _write(backup / name, data, uid=ROOT_UID)
            items.append({'name':name, 'absent':False, 'mode':stat.S_IMODE(info.st_mode),
                          'uid':info.st_uid, 'gid':info.st_gid, 'sha256':hashlib.sha256(data).hexdigest()})
    _json_write(backup / 'snapshot.json', {'version':1, 'files':items})
    return str(backup)


def _restore(root, nonce, backup):
    path = root / 'backups' / ('before-keyserver-link-' + nonce)
    if backup != str(path):
        raise LinkError('Некорректная резервная копия.')
    _private_directory(path, ROOT_UID, 0)
    items = json.loads(_read(path / 'snapshot.json', owner=ROOT_UID, modes={0o600})[0])['files']
    if not isinstance(items, list) or {item.get('name') for item in items} != {'.env', 'key-service.json'} or len(items) != 2:
        raise LinkError('Некорректная резервная копия.')
    for item in items:
        target = root / '.env' if item['name'] == '.env' else root / 'secrets/key-service.json'
        if item['absent']:
            if item['name'] == '.env':
                raise LinkError('Отсутствует резервная копия настроек.')
            with _directory(target.parent) as parent:
                try:
                    os.unlink(target.name, dir_fd=parent)
                    os.fsync(parent)
                except FileNotFoundError:
                    pass
        else:
            data, _ = _read(path / item['name'], 1 << 20, owner=ROOT_UID, modes={0o600})
            if hashlib.sha256(data).hexdigest() != item['sha256']:
                raise LinkError('Резервная копия повреждена.')
            _write(target, data, item['mode'], item['uid'], item['gid'])


def _compose(module, root, release, state, restart=True):
    # Docker diagnostics can include settings; only the public result is forwarded.
    module.compose(root, release, state, 'config', '-q', stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    recreate = ('--force-recreate',) if restart else ()
    module.compose(root, release, state, 'up', '-d', '--no-deps', *recreate, '--wait', '--wait-timeout', '120', 'api',
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    module.compose(root, release, state, 'exec', '-T', 'nginx', 'nginx', '-s', 'reload',
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def _active_matches(root, config):
    return _external(root) and _config(_read(root / 'secrets/key-service.json')[0]) == config


def _result(nonce, status, key_id=None, digest=None):
    result = {'nonce':nonce if isinstance(nonce, str) and NONCE.fullmatch(nonce) else '', 'status':status}
    if key_id is not None:
        result['key_id'] = key_id
    if digest is not None:
        result['config_sha256'] = digest
    print('FAMILYCHAT_LINK_RESULT ' + json.dumps(result, separators=(',', ':')))


def _receipt(metadata):
    transfer = Path(metadata['transport'])
    _json_write(transfer / 'receipt.json', {'version':1, 'nonce':metadata['nonce'], 'status':'applied',
                'key_id':metadata['key_id'], 'config_sha256':metadata['config_sha256']}, metadata['uid'], metadata['gid'])
    with _directory(transfer) as parent:
        for name in ('payload.json', 'connection.json'):
            try:
                os.unlink(name, dir_fd=parent)
            except FileNotFoundError:
                pass
        os.fsync(parent)


def finish_chat(nonce):
    """Apply an uploaded connection, or restore the previous healthy configuration."""
    metadata = None
    # A retry may overlap a previous finish that is still applying or has committed.
    # Until the lock and trusted journal prove otherwise, the peer must retain keys.
    uncertain = True
    try:
        _root_required()
        _private_directory(STATE_DIR, ROOT_UID, 0)
        with _lock(STATE_DIR / '.lock'):
            metadata = _metadata(nonce)
            uncertain = metadata['phase'] not in ('prepared', 'rolled_back')
            root = Path(metadata['chat_root'])
            with _lock(root / '.lock'):
                release = _release(root)
                module = _controller(release)
                state = module.load_state(root)
                if _current_key(root)['key_id'] != metadata['key_id']:
                    raise LinkError('Исходный ключ изменился после подготовки.')
                installed = STATE_DIR / ('connection-' + nonce + '.json')
                if metadata['phase'] == 'applied':
                    data = _read(installed, modes={0o600}, owner=ROOT_UID)[0]
                    if (hashlib.sha256(data).hexdigest() != metadata.get('config_sha256')
                            or not _active_matches(root, _config(data))):
                        raise LinkError('Настройки изменены после подключения.')
                    _receipt(metadata)
                    _result(nonce, 'applied', metadata['key_id'], metadata['config_sha256'])
                    return 0
                if metadata['phase'] in ('applying', 'attention'):
                    # An interrupted process may have changed containers. Restore from its
                    # durable journal before considering another upload or safe failure.
                    _restore(root, nonce, metadata['backup'])
                    _compose(module, root, release, state)
                    metadata['phase'] = 'rolled_back'
                    _save_meta(metadata)
                    uncertain = False
                incoming = Path(metadata['transport']) / 'connection.json'
                data = _read(incoming, modes={0o600}, owner=metadata['uid'])[0]
                config = _config(data)
                if config['key_id'] != metadata['key_id']:
                    raise LinkError('Новый сервер использует другой ключ переписки.')
                _write(installed, data, uid=ROOT_UID)
                digest = hashlib.sha256(data).hexdigest()
                if not _active_matches(root, config):
                    metadata['backup'] = _snapshot(root, nonce)
                    metadata['phase'] = 'applying'
                    metadata['config_sha256'] = digest
                    _save_meta(metadata)
                    uncertain = True
                    try:
                        module.configure_key_service(root, installed)
                        _compose(module, root, release, state)
                    except (Exception, KeyboardInterrupt):
                        _restore(root, nonce, metadata['backup'])
                        _compose(module, root, release, state)
                        metadata['phase'] = 'rolled_back'
                        _save_meta(metadata)
                        uncertain = False
                        _result(nonce, 'rolled_back', metadata['key_id'])
                        print('Подключение не выполнено; прежние настройки и работа API восстановлены.', file=sys.stderr)
                        return 41
                else:
                    _compose(module, root, release, state, restart=False)
                metadata['phase'] = 'applied'
                metadata['config_sha256'] = digest
                _save_meta(metadata)
                uncertain = True  # A receipt failure must never cause the peer to roll keys back.
                _receipt(metadata)
                _result(nonce, 'applied', metadata['key_id'], digest)
                print('Сервер ключей подключён. Исходные ключи и резервная копия настроек сохранены.')
                return 0
    except (Exception, KeyboardInterrupt):
        status = 'attention' if uncertain else 'rolled_back'
        _result(nonce, status, metadata['key_id'] if metadata else None)
        print('Не удалось завершить подключение. ' + ('Повторите команду на сервере ключей; требуется проверка сохранённого состояния.'
              if uncertain else 'Прежние настройки сохранены; проверьте подготовку и повторите команду.'), file=sys.stderr)
        return 42 if uncertain else 41


def main(argv=None):
    parser = argparse.ArgumentParser(description='Подключение FamilyChat к отдельному серверу ключей')
    commands = parser.add_subparsers(dest='command', required=True)
    prepare = commands.add_parser('prepare-chat')
    prepare.add_argument('--chat-root', type=Path, default=Path('/opt/familychat'))
    prepare.add_argument('--ssh-user')
    finish = commands.add_parser('finish-chat')
    finish.add_argument('--nonce', required=True)
    args = parser.parse_args(argv)
    return prepare_chat(args.chat_root, args.ssh_user) if args.command == 'prepare-chat' else finish_chat(args.nonce)


if __name__ == '__main__':
    sys.exit(main())
