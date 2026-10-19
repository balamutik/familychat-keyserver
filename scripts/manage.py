#!/usr/bin/env python3
"""Install the standalone key service without changing any existing web server."""
import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import socket
import stat
import subprocess
import sys
import tarfile
import tempfile


SOURCE = Path(__file__).resolve().parent.parent
DEFAULT_INSTALL = "/opt/familychat-keyserver"
IMAGE = "familychat-keyserver:local"


def command(args, **kwargs):
    # Never print commands: imported file paths/DNS arguments may be sensitive.
    subprocess.run([str(arg) for arg in args], check=True, **kwargs)


def private_json(path, value):
    path = Path(path)
    fd, temporary = tempfile.mkstemp(prefix=".keyserver-", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as file:
            os.fchmod(file.fileno(), 0o600)
            json.dump(value, file, indent=2)
            file.write("\n")
            file.flush()
            os.fsync(file.fileno())
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def restricted_file(path):
    path = Path(path)
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) & 0o077:
        raise ValueError(f"Файл {path.name} должен быть обычным файлом с правами 0600 или 0400")
    return path


def read_dns_env(path):
    values = {}
    for line in restricted_file(path).read_text().splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        name, sep, value = line.partition("=")
        if not sep or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
            raise ValueError("DNS env: ожидаются строки NAME=value без export и команд shell")
        values[name] = value
    return values


def validate(config):
    domain = config["domain"]
    if not isinstance(domain, str) or len(domain) > 253 or not re.fullmatch(
        r"[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?", domain
    ) or "." not in domain or any(not label or len(label) > 63 or label.startswith("-") or label.endswith("-") for label in domain.split(".")):
        raise ValueError("Укажите DNS-имя без https://, порта и пути, например keys.example.com")
    if not isinstance(config["port"], int) or not 1024 <= config["port"] <= 65535 or config["port"] == 8080:
        raise ValueError("Порт сервера ключей должен быть отдельным: 1024–65535, кроме 8080. По умолчанию 8443; 80/443 не используются приложением")
    if config["client"] not in ("certbot", "acme.sh") or config["challenge"] not in ("standalone", "webroot", "dns"):
        raise ValueError("Выберите certbot/acme.sh и standalone/webroot/dns")
    if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", config["email"]):
        raise ValueError("Укажите email для сертификата")
    validate_install_dir(config["install_dir"])
    if config["challenge"] == "webroot" and not config.get("webroot"):
        raise ValueError("Для webroot укажите --webroot: существующий каталог, доступный по HTTP на порту 80")
    if config["challenge"] == "dns":
        if config["client"] == "acme.sh" and not re.fullmatch(r"dns_[A-Za-z0-9_]+", config.get("dns_provider") or ""):
            raise ValueError("Для DNS с acme.sh укажите --dns-provider, например dns_cf")
        if config["client"] == "certbot" and not config.get("certbot_dns_args"):
            raise ValueError("Для DNS с certbot укажите --certbot-dns-args: JSON файл с параметрами установленного DNS-плагина")


def validate_install_dir(value):
    root = Path(value)
    if not root.is_absolute() or str(root) == "/" or not re.fullmatch(r"/[A-Za-z0-9_./-]+", str(root)):
        raise ValueError("Каталог установки должен быть абсолютным путём без пробелов и специальных символов")
    if root.resolve() == Path("/"):
        raise ValueError("Корневой каталог не может быть каталогом установки")


def ensure_port_available(port):
    # Binding is only a preflight. No process is ever stopped or reconfigured.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        try:
            listener.bind(("0.0.0.0", port))
        except OSError as error:
            raise RuntimeError(f"Порт {port} занят. Существующие сервисы не изменены. Для ACME выберите webroot или DNS, для приложения — другой отдельный порт") from error


def certbot_base(config):
    base = Path(config["install_dir"]) / "acme/certbot"
    return ["certbot", "--config-dir", str(base / "config"), "--work-dir", str(base / "work"), "--logs-dir", str(base / "logs")]


def acme_base(config):
    return [config["acme_binary"], "--config-home", str(Path(config["install_dir"]) / "acme/acme.sh")]


def dns_args(config):
    path = restricted_file(config["certbot_dns_args"])
    args = json.loads(path.read_text())
    if not isinstance(args, list) or not args or not all(isinstance(item, str) and "\n" not in item for item in args):
        raise ValueError("DNS параметры certbot должны быть непустым JSON-массивом строк")
    # Credentials are filenames understood by the installed certbot DNS plugin.
    if not any(arg.startswith("--dns-") for arg in args):
        raise ValueError("DNS параметры certbot должны включать --dns-<provider>")
    forbidden = ("--config", "--logs", "--work", "--cert-name", "--domain", "--email", "--standalone", "--webroot", "--manual", "--hook", "--deploy", "--pre-hook", "--post-hook", "--server")
    if any(arg.startswith(forbidden) or arg == "-d" for arg in args):
        raise ValueError("В DNS файле разрешены только параметры DNS-плагина, без доменов, путей ACME и hooks")
    return args


def issue_command(config):
    if config["client"] == "certbot":
        args = certbot_base(config) + ["certonly", "--non-interactive", "--agree-tos", "--email", config["email"], "--cert-name", "familychat-keyserver", "--keep-until-expiring", "-d", config["domain"]]
        if config["challenge"] == "standalone":
            args += ["--standalone", "--preferred-challenges", "http"]
        elif config["challenge"] == "webroot":
            args += ["--webroot", "--webroot-path", config["webroot"]]
        else:
            args += dns_args(config)
        return args
    args = acme_base(config) + ["--issue", "--server", "letsencrypt", "--keylength", "ec-256", "-d", config["domain"]]
    if config["challenge"] == "standalone":
        args += ["--standalone"]
    elif config["challenge"] == "webroot":
        args += ["--webroot", config["webroot"]]
    else:
        args += ["--dns", config["dns_provider"]]
    return args


def protect_tree(path, owner=None):
    path = Path(path)
    if path.is_symlink():
        raise ValueError("Закрытый каталог не может быть символической ссылкой")
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    for entry in [path] + list(path.rglob("*")):
        if entry.is_symlink():
            continue
        entry.chmod(0o700 if entry.is_dir() else 0o600)
        if owner is not None:
            os.chown(entry, owner, owner)


def publish_certificate(config):
    root = Path(config["install_dir"])
    tls_dir = root / "tls"
    tls_dir.mkdir(mode=0o700, exist_ok=True)
    if config["client"] == "certbot":
        lineage = root / "acme/certbot/config/live/familychat-keyserver"
        for source, name in ((lineage / "fullchain.pem", "fullchain.pem"), (lineage / "privkey.pem", "privkey.pem")):
            fd, temporary = tempfile.mkstemp(prefix=".cert-", dir=tls_dir)
            try:
                with os.fdopen(fd, "wb") as file:
                    os.fchmod(file.fileno(), 0o600)
                    file.write(source.read_bytes())
                    file.flush()
                    os.fsync(file.fileno())
                os.chown(temporary, 10001, 10001)
                os.replace(temporary, tls_dir / name)
            finally:
                Path(temporary).unlink(missing_ok=True)
    else:
        command(acme_base(config) + ["--install-cert", "--ecc", "-d", config["domain"], "--key-file", tls_dir / "privkey.pem", "--fullchain-file", tls_dir / "fullchain.pem"])
    protect_tree(tls_dir, 10001)
    # The Go service reads valid renewed PEM pairs at each new TLS handshake.


def certificate(config, renew=False):
    env = os.environ.copy()
    if config.get("dns_env"):
        env.update(read_dns_env(config["dns_env"]))
    if config["challenge"] == "standalone":
        ensure_port_available(80)
    if config["client"] == "certbot":
        args = certbot_base(config) + ["renew", "--non-interactive", "--cert-name", "familychat-keyserver"] if renew else issue_command(config)
        command(args, env=env)
    else:
        if not renew:
            command(acme_base(config) + ["--register-account", "--server", "letsencrypt", "-m", config["email"]], env=env)
        args = acme_base(config) + ["--renew", "--server", "letsencrypt", "--ecc", "-d", config["domain"]] if renew else issue_command(config)
        # acme.sh uses exit 2 when renewal is not due; this is not an error.
        result = subprocess.run([str(arg) for arg in args], env=env)
        if result.returncode not in (0, 2):
            raise RuntimeError("acme.sh не смог выпустить/продлить сертификат")
    publish_certificate(config)


def compose(root, *args):
    command(["docker", "compose", "--project-directory", root, "--env-file", root / "service.env", "-f", root / "compose.yaml", *args])


def copy_source(source, root):
    source, root = Path(source).resolve(), Path(root).resolve()
    target = root / "app"
    if target.resolve() != source:
        staging = root / "app.next"
        if staging.exists():
            shutil.rmtree(staging)
        staging.mkdir(mode=0o755)
        for name in ("go.mod", "Dockerfile", ".dockerignore", "compose.yaml", "cmd", "internal", "scripts", "README.md"):
            path = source / name
            if path.is_dir():
                shutil.copytree(path, staging / name, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
            else:
                shutil.copy2(path, staging / name)
        if target.exists():
            shutil.rmtree(target)
        staging.rename(target)
    shutil.copy2(source / "compose.yaml", root / "compose.yaml")


def backup(root, output):
    root, output = Path(root).resolve(), Path(output).absolute()
    for name in ("state", "tls", "export", "acme"):
        if output.resolve().is_relative_to(root / name):
            raise ValueError("Архив не должен находиться внутри каталогов с ключами, сертификатами или ACME состоянием")
    restricted_file(root / "state/state.json")
    output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as file:
            with tarfile.open(fileobj=file, mode="w:gz") as archive:
                for name in ("state", "tls", "export", "acme", "deploy.json", "service.env", "compose.yaml", "dns.env", "certbot-dns-args.json", "dns-credentials.ini"):
                    path = root / name
                    if path.exists():
                        archive.add(path, arcname=name, recursive=True)
            file.flush()
            os.fsync(file.fileno())
    except BaseException:
        output.unlink(missing_ok=True)
        raise


def install_timer(root):
    if not shutil.which("systemctl") or not Path("/run/systemd/system").is_dir():
        print(f"systemd недоступен. Добавьте ежедневный запуск: {root}/app/scripts/renew.sh --install-dir {root}")
        return
    service = "[Unit]\nDescription=Renew FamilyChat key-server TLS certificate\n[Service]\nType=oneshot\nUMask=0077\nExecStart=" + str(root / "app/scripts/renew.sh") + " --install-dir " + str(root) + "\n"
    timer = "[Unit]\nDescription=Daily FamilyChat key-server certificate renewal\n[Timer]\nOnCalendar=daily\nRandomizedDelaySec=1h\nPersistent=true\n[Install]\nWantedBy=timers.target\n"
    Path("/etc/systemd/system/familychat-keyserver-renew.service").write_text(service)
    Path("/etc/systemd/system/familychat-keyserver-renew.timer").write_text(timer)
    command(["systemctl", "daemon-reload"])
    command(["systemctl", "enable", "--now", "familychat-keyserver-renew.timer"])


@contextmanager
def deployment_lock(root):
    root.mkdir(mode=0o750, parents=True, exist_ok=True)
    with open(root / ".manage.lock", "a") as file:
        os.chmod(file.name, 0o600)
        fcntl.flock(file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield


def install(args):
    config = vars(args).copy()
    for name, prompt, default in (("domain", "Домен сервера ключей", None), ("email", "Email для сертификата", None), ("client", "Клиент сертификатов: certbot или acme.sh", "certbot"), ("challenge", "Проверка домена: standalone, webroot или dns", "standalone")):
        if not config.get(name):
            if not sys.stdin.isatty():
                raise ValueError(f"Укажите --{name.replace('_', '-')}")
            config[name] = input(prompt + (f" [{default}]" if default else "") + ": ").strip() or default
    validate(config)
    if config["client"] == "certbot" and not shutil.which("certbot"):
        raise RuntimeError("Установите certbot (и DNS-плагин при DNS проверке) по инструкции README")
    if config["client"] == "acme.sh" and not Path(config["acme_binary"]).is_file():
        raise RuntimeError("Установите acme.sh или укажите --acme-binary /путь/acme.sh; инструкция в README")
    root = Path(config["install_dir"]).resolve()
    if (root / "deploy.json").exists():
        raise RuntimeError("Сервер уже установлен. Используйте update.sh; ключи не изменены")
    ensure_port_available(config["port"])
    if config["challenge"] == "standalone":
        ensure_port_available(80)
    root.mkdir(mode=0o750, parents=True, exist_ok=True)
    protect_tree(root / "acme")
    for name in ("state", "tls", "export"):
        protect_tree(root / name)
    if config.get("dns_env"):
        source = restricted_file(config["dns_env"])
        read_dns_env(source)
        shutil.copyfile(source, root / "dns.env")
        (root / "dns.env").chmod(0o600)
        config["dns_env"] = str(root / "dns.env")
    if config.get("certbot_dns_args"):
        source = restricted_file(config["certbot_dns_args"])
        arguments = dns_args(config)
        for index, argument in enumerate(arguments):
            if argument.startswith("--dns-") and argument.endswith("-credentials"):
                if index + 1 >= len(arguments):
                    raise ValueError("После DNS credentials укажите путь к файлу")
                credentials = restricted_file(arguments[index + 1])
                shutil.copyfile(credentials, root / "dns-credentials.ini")
                (root / "dns-credentials.ini").chmod(0o600)
                arguments[index + 1] = str(root / "dns-credentials.ini")
        private_json(root / "certbot-dns-args.json", arguments)
        config["certbot_dns_args"] = str(root / "certbot-dns-args.json")
    copy_source(args.source, root)
    env = f"KEYSERVER_BUILD_CONTEXT=./app\nKEYSERVER_STATE_DIR=./state\nKEYSERVER_TLS_DIR=./tls\nKEYSERVER_PORT={config['port']}\nKEYSERVER_DOMAIN={config['domain']}\n"
    (root / "service.env").write_text(env)
    (root / "service.env").chmod(0o600)
    compose(root, "build", "--pull")
    initialize = ["docker", "run", "--rm", "--user", "0:0", "--mount", f"type=bind,src={root}/state,dst=/state", "--mount", f"type=bind,src={root}/export,dst=/export"]
    imports = []
    for flag, name in (("--import-json", "import_json"), ("--import-public", "import_public"), ("--import-private", "import_private")):
        if getattr(args, name):
            source = restricted_file(getattr(args, name)).resolve()
            target = "/import/" + name
            initialize += ["--mount", f"type=bind,src={source},dst={target},readonly"]
            imports += [flag, target]
    initialize += [IMAGE, "init", "--state-dir", "/state", "--url", f"https://{config['domain']}:{config['port']}/api/v1/keys/current", "--export", "/export/main-server.json", *imports]
    command(initialize)
    protect_tree(root / "state", 10001)
    certificate(config)
    private_json(root / "deploy.json", {key: value for key, value in config.items() if key not in ("import_json", "import_public", "import_private", "handler", "command")})
    compose(root, "up", "-d", "--wait", "--wait-timeout", "60")
    install_timer(root)
    print(f"Сервер ключей: https://{config['domain']}:{config['port']}\nДля основного сервера скопируйте только {root}/export/main-server.json\nСохраните резервную копию через backup.sh")


def load_config(root):
    config = json.loads(restricted_file(root / "deploy.json").read_text())
    validate(config)
    return config


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description="Отдельный сервер ключей FamilyChat")
    commands = parser.add_subparsers(dest="command", required=True)
    setup = commands.add_parser("install")
    for option in ("domain", "email", "client", "challenge", "webroot", "dns-provider", "dns-env", "certbot-dns-args", "import-json", "import-public", "import-private"):
        setup.add_argument("--" + option)
    setup.add_argument("--port", type=int, default=8443)
    setup.add_argument("--acme-binary", default="/root/.acme.sh/acme.sh")
    setup.add_argument("--source", default=str(SOURCE))
    update = commands.add_parser("update")
    update.add_argument("--source", default=str(SOURCE))
    commands.add_parser("renew")
    archive = commands.add_parser("backup")
    archive.add_argument("--output")
    for sub in (setup, update, commands.choices["renew"], archive):
        sub.add_argument("--install-dir", default=DEFAULT_INSTALL)
    args = parser.parse_args()
    validate_install_dir(args.install_dir)
    if os.geteuid() != 0:
        raise RuntimeError("Запустите скрипт через sudo: он управляет Docker и закрытыми файлами ключей")
    if args.command != "backup":
        if not shutil.which("docker"):
            raise RuntimeError("Установите Docker Engine и Docker Compose plugin")
        command(["docker", "compose", "version"], stdout=subprocess.DEVNULL)
    root = Path(args.install_dir).resolve()
    with deployment_lock(root):
        if args.command == "install":
            install(args)
        elif args.command == "renew":
            certificate(load_config(root), renew=True)
        elif args.command == "backup":
            output = Path(args.output) if args.output else root / "backups" / (datetime.now(timezone.utc).strftime("keyserver-%Y%m%dT%H%M%SZ.tar.gz"))
            backup(root, output)
            print(f"Резервная копия создана: {output}. Храните её отдельно от этой машины")
        elif args.command == "update":
            load_config(root)
            output = root / "backups" / datetime.now(timezone.utc).strftime("before-update-%Y%m%dT%H%M%SZ.tar.gz")
            backup(root, output)
            copy_source(args.source, root)
            compose(root, "build", "--pull")
            compose(root, "up", "-d", "--wait", "--wait-timeout", "60")
            install_timer(root)
            print("Сервер ключей обновлён. Ключи и билеты сохранены; резервная копия создана")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, RuntimeError, OSError, subprocess.CalledProcessError) as error:
        # CalledProcessError.__str__ would include the entire sensitive command.
        print("Ошибка: " + ("Внешняя команда завершилась с ошибкой; ключи не заменялись" if isinstance(error, subprocess.CalledProcessError) else str(error)), file=sys.stderr)
        sys.exit(1)
