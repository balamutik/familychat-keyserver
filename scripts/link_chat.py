#!/usr/bin/env python3
"""Connect an installed key service to an existing chat over authenticated SSH."""
import argparse
import base64
from contextlib import redirect_stdout
import hashlib
import importlib.util
import io
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile

TRANSPORT = '.familychat-keyserver-link'
HELPER = '/usr/local/lib/familychat-keyserver-link/bridge.py'
RETRY = 'Результат подключения пока не подтверждён. Повторите вторую команду; ключи сохранены для продолжения.'


def parse_peer(target):
    if not isinstance(target, str) or target.count('@') != 1:
        raise ValueError('Укажите SSH-адрес в формате пользователь@адрес')
    user, host = target.split('@')
    if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.-]{0,63}\$?', user):
        raise ValueError('Некорректный SSH-пользователь')
    if host.startswith('[') and host.endswith(']'):
        host = host[1:-1]
    try:
        ipaddress.ip_address(host)
    except ValueError:
        if len(host) > 253 or not all(re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?', label)
                                      for label in host.rstrip('.').split('.')):
            raise ValueError('Некорректный адрес SSH-сервера') from None
    return user, host


def private_bytes(path, data, uid=None):
    path = Path(path)
    fd, temporary = tempfile.mkstemp(prefix='.link-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as file:
            os.fchmod(file.fileno(), 0o600)
            if uid is not None:
                os.fchown(file.fileno(), uid, uid)
            file.write(data)
            file.flush()
            os.fsync(file.fileno())
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def private_read(path, limit=32768):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as file:
        info = os.fstat(file.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 or info.st_size > limit:
            raise ValueError('Файл обмена должен быть обычным закрытым файлом допустимого размера')
        data = file.read(limit + 1)
    if len(data) > limit:
        raise ValueError('Слишком большой файл обмена')
    return data


def load_json(path):
    value = json.loads(private_read(path))
    if not isinstance(value, dict):
        raise ValueError('Неверный формат файла обмена')
    return value


class SSHPeer:
    def __init__(self, target, port=22, identity=None):
        self.user, self.host = parse_peer(target)
        if not 1 <= port <= 65535:
            raise ValueError('Некорректный SSH-порт')
        self.options = ['-p', str(port), '-l', self.user, '-o', 'ConnectTimeout=30', '-o', 'ServerAliveInterval=15',
                        '-o', 'ServerAliveCountMax=3']
        self.scp_options = ['-P', str(port), '-o', 'ConnectTimeout=30']
        if identity:
            self.options += ['-i', str(Path(identity).expanduser())]
            self.scp_options += ['-i', str(Path(identity).expanduser())]
        self.temporary = None
        self.terminal = None

    def __enter__(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='fc-link-', dir='/tmp')
        self.control = str(Path(self.temporary.name) / 'ssh')
        self.options += ['-S', self.control, '-o', 'ControlMaster=auto']
        self.scp_options += ['-o', 'ControlPath=' + self.control]
        try:
            self.terminal = open('/dev/tty', 'r+b', buffering=0)
            result = subprocess.run(['ssh', *self.options, '-M', '-N', '-f', '-o', 'ControlPersist=120', '--', self.host],
                                    stdin=self.terminal, stdout=self.terminal, stderr=self.terminal)
            if result.returncode:
                raise RuntimeError('Не удалось подключиться к VPS чата по SSH. Проверьте адрес и доступ')
        except BaseException:
            self.__exit__(None, None, None)
            raise
        return self

    def __exit__(self, *args):
        if self.temporary:
            if hasattr(self, 'control'):
                subprocess.run(['ssh', *self.options, '-O', 'exit', '--', self.host],
                               stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self.temporary.cleanup()
            self.temporary = None
        if self.terminal:
            self.terminal.close()
            self.terminal = None

    def remote(self, name):
        if name not in {TRANSPORT + '/' + file for file in ('payload.json', 'connection.json', 'receipt.json')}:
            raise ValueError('Неверное имя файла обмена')
        host = '[' + self.host + ']' if ':' in self.host else self.host
        return f'{self.user}@{host}:{name}'

    def receive(self, name, path, optional=False):
        result = subprocess.run(['scp', *self.scp_options, '--', self.remote(name), str(path)],
                                stdin=self.terminal, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        if result.returncode:
            if optional:
                return False
            raise RuntimeError('Не удалось получить файл по SSH. Проверьте соединение и выполните первую команду на VPS чата')
        Path(path).chmod(0o600)
        return True

    def send(self, path, name):
        # SFTP's umask may otherwise make the ticket secret readable to others.
        result = subprocess.run(['scp', '-p', *self.scp_options, '--', str(path), self.remote(name)],
                                stdin=self.terminal, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        if result.returncode:
            raise RuntimeError('Не удалось передать конфигурацию по SSH. Повторите вторую команду')

    def finish(self, nonce):
        if not re.fullmatch(r'[a-f0-9]{32}', nonce):
            raise ValueError('Неверный идентификатор переноса')
        command = ([] if self.user == 'root' else ['sudo']) + ['python3', HELPER, 'finish-chat', '--nonce', nonce]
        process = subprocess.Popen(['ssh', *self.options, '-tt', '--', self.host, shlex.join(command)],
                                   stdin=self.terminal, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        try:
            while True:
                chunk = os.read(process.stdout.fileno(), 4096)
                if not chunk:
                    break
                self.terminal.write(chunk)
            return process.wait()
        except BaseException:
            process.terminate()
            process.wait()
            raise
        finally:
            process.stdout.close()


def validate_payload(payload, user):
    key = payload.get('key', {})
    if payload.get('version') != 1 or not re.fullmatch(r'[a-f0-9]{32}', str(payload.get('nonce', ''))):
        raise ValueError('Неверная версия или идентификатор переноса')
    if payload.get('ssh_user') != user or not isinstance(key, dict) or key.get('scheme') != 'fc1':
        raise ValueError('Пакет подготовлен для другого SSH-пользователя или формата ключей')
    try:
        public = base64.b64decode(key['public_key'], validate=True)
        private = base64.b64decode(key['private_key'], validate=True) if key.get('private_key') else None
    except (ValueError, KeyError, TypeError):
        raise ValueError('Некорректный формат пары ключей') from None
    if len(public) != 32 or (private is not None and len(private) != 32) or key.get('key_id') != hashlib.sha256(public).hexdigest():
        raise ValueError('Отпечаток или длина ключа не совпадает')
    return key


def current(root):
    return load_json(root / 'state/state.json')['key_id'], hashlib.sha256(private_read(root / 'export/main-server.json')).hexdigest()


def validate_current(root, record):
    if current(root) != (record['key_id'], record['config_sha256']):
        raise RuntimeError('Настройки сервера ключей изменились после начала подключения. Автоматическое продолжение остановлено')


def receipt_matches(receipt, record):
    return all(receipt.get(key) == value for key, value in dict(version=1, nonce=record['nonce'], status='applied',
               key_id=record['key_id'], config_sha256=record['config_sha256']).items())


def restore(root, journal, record, manager):
    record['phase'] = 'restore-needed'
    manager.private_json(journal / 'record.json', record)
    try:
        manager.compose(root, 'stop', 'keyserver')
        for name, uid in (('state', 10001), ('export', 0)):
            directory = root / name
            if directory.is_symlink():
                raise ValueError('Ссылка вместо каталога состояния')
            directory.mkdir(mode=0o700, exist_ok=True)
            directory.chmod(0o700)
            os.chown(directory, uid, uid)
        private_bytes(root / 'state/state.json', private_read(journal / 'before-state.json'), uid=10001)
        private_bytes(root / 'export/main-server.json', private_read(journal / 'before-export.json'))
        manager.compose(root, 'up', '-d', '--no-deps', '--force-recreate', '--wait', '--wait-timeout', '60', 'keyserver')
    except Exception:
        raise RuntimeError(f'Откат сервера ключей не завершён. Исходное состояние сохранено в {journal}; требуется восстановление') from None
    record['phase'] = 'rolled_back'
    manager.private_json(journal / 'record.json', record)


def connect_chat(args, root, manager):
    root = Path(root)
    manager.load_config(root)
    user, host = parse_peer(args.chat)
    peer_id = dict(user=user, host=host, port=args.ssh_port)
    links = root / 'chat-links'
    if links.is_symlink():
        raise ValueError('Каталог обмена не должен быть символической ссылкой')
    links.mkdir(mode=0o700, exist_ok=True)
    links.chmod(0o700)
    with SSHPeer(args.chat, args.ssh_port, args.ssh_identity) as peer, tempfile.TemporaryDirectory(prefix='.chat-link-', dir=root) as directory:
        temporary = Path(directory)
        payload_file = temporary / 'payload.json'
        if not peer.receive(TRANSPORT + '/payload.json', payload_file, optional=True):
            receipt_file = temporary / 'receipt.json'
            if not peer.receive(TRANSPORT + '/receipt.json', receipt_file, optional=True):
                raise RuntimeError('Пакет не найден. Сначала выполните prepare-chat на VPS чата; проверьте SSH-пользователя')
            receipt = load_json(receipt_file)
            nonce = receipt.get('nonce', '')
            if not isinstance(nonce, str) or not re.fullmatch(r'[a-f0-9]{32}', nonce):
                raise ValueError('Неверное подтверждение переноса')
            journal = links / nonce
            record = load_json(journal / 'record.json')
            if record['peer'] != peer_id or record['phase'] not in ('awaiting', 'complete') or not receipt_matches(receipt, record):
                raise RuntimeError(RETRY)
            validate_current(root, record)
            record['phase'] = 'complete'
            manager.private_json(journal / 'record.json', record)
            print('Подключение уже завершено. Ключи и настройки сохранены.')
            return
        payload = load_json(payload_file)
        key = validate_payload(payload, user)
        nonce = payload['nonce']
        journal = links / nonce
        if journal.is_symlink():
            raise ValueError('Неверный каталог переноса')
        if journal.exists():
            record = load_json(journal / 'record.json')
            if record['peer'] != peer_id or record['key_id'] != key['key_id']:
                raise ValueError('Параметры ранее начатого подключения не совпадают')
        else:
            staging = temporary / 'journal'
            staging.mkdir(mode=0o700)
            for target, source in (('before-state.json', 'state/state.json'), ('before-export.json', 'export/main-server.json')):
                private_bytes(staging / target, private_read(root / source))
            record = dict(version=1, nonce=nonce, peer=peer_id, key_id=key['key_id'],
                          before_key_id=current(root)[0], phase='prepared')
            manager.private_json(staging / 'record.json', record)
            staging.rename(journal)
        if record['phase'] in ('restore-needed', 'importing'):
            restore(root, journal, record, manager)
        if record['phase'] in ('prepared', 'rolled_back'):
            present_id = current(root)[0]
            if present_id not in (record['before_key_id'], key['key_id']):
                raise RuntimeError('Ключи изменились после подготовки; перенос остановлен')
            if present_id != key['key_id']:
                if not key.get('private_key'):
                    raise RuntimeError('На VPS чата отсутствует исходный закрытый ключ. Нужен его импорт из резервной копии')
                source = temporary / 'import.json'
                manager.private_json(source, key)
                record['phase'] = 'importing'
                manager.private_json(journal / 'record.json', record)
                print('Переношу исходные ключи переписки на сервер ключей…')
                # The manual import command prints instructions for manual copying;
                # this workflow performs those steps itself.
                with redirect_stdout(io.StringIO()):
                    manager.import_keys(argparse.Namespace(import_json=str(source), import_public=None, import_private=None,
                                                           replace_unused_state=True), root)
                source.unlink()
            key_id, digest = current(root)
            if key_id != key['key_id']:
                raise RuntimeError('Импорт не подтвердил исходный ключ чата')
            record.update(phase='imported', config_sha256=digest)
            manager.private_json(journal / 'record.json', record)
        validate_current(root, record)
        if record['phase'] == 'complete':
            print('Подключение уже завершено. Ключи и настройки сохранены.')
            return
        peer.send(root / 'export/main-server.json', TRANSPORT + '/connection.json')
        record['phase'] = 'awaiting'
        manager.private_json(journal / 'record.json', record)
        try:
            code = peer.finish(nonce)
        except (OSError, KeyboardInterrupt):
            raise RuntimeError(RETRY) from None
        if code == 41:
            restore(root, journal, record, manager)
            raise RuntimeError('Чат отменил подключение; сервер ключей восстановлен. Исправьте причину на VPS чата и повторите вторую команду')
        if code != 0:
            raise RuntimeError(RETRY)
        receipt_file = temporary / 'receipt.json'
        if not peer.receive(TRANSPORT + '/receipt.json', receipt_file, optional=True) or not receipt_matches(load_json(receipt_file), record):
            raise RuntimeError(RETRY)
        record['phase'] = 'complete'
        manager.private_json(journal / 'record.json', record)
        print('FamilyChat подключён к серверу ключей. Историческая пара ключей сохранена.')
        print('Проверьте открытие старых сообщений в приложении. Исходные файлы ключей на VPS чата пока сохранены.')


def ensure_keyserver_protocol(manager, root, source):
    manifest = manager.release_manifest(source)
    if not manifest:
        return
    installed_manifest = root / 'app/release.json'
    installed = json.loads(installed_manifest.read_text()) if installed_manifest.is_file() else {}
    committed = manager.load_config(root)
    if (installed.get('key_delivery') != 'device-grant-v1' or installed.get('image') != manifest['image']
            or committed.get('key_delivery') != 'device-grant-v1' or committed.get('image') != manifest['image']):
        print('Обновляю сервер ключей для одноразовых допусков устройств…', flush=True)
        manager.update(argparse.Namespace(source=str(source)), root)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['connect-chat'])
    parser.add_argument('--chat', help='SSH user@host чата; если не задан, будет запрошен')
    parser.add_argument('--ssh-port', type=int, default=22)
    parser.add_argument('--ssh-identity', type=Path)
    parser.add_argument('--install-dir', type=Path, default=Path('/opt/familychat-keyserver'))
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('Запустите через sudo')
    spec = importlib.util.spec_from_file_location('keyserver_manage', Path(__file__).with_name('manage.py'))
    manager = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(manager)
    if not args.chat:
        args.chat = manager.prompt('SSH-адрес VPS чата (пользователь@IP или домен):')
    parse_peer(args.chat)
    if not 1 <= args.ssh_port <= 65535:
        parser.error('SSH-порт должен быть от 1 до 65535')
    if not shutil.which('ssh') or not shutil.which('scp'):
        manager.install_packages(['openssh-client'])
    manager.ensure_docker()
    root = args.install_dir.resolve()
    with manager.deployment_lock(root):
        source = Path(__file__).resolve().parents[1]
        ensure_keyserver_protocol(manager, root, source)
        connect_chat(args, root, manager)


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print(f'Ошибка: {error}', file=sys.stderr)
        sys.exit(1)
