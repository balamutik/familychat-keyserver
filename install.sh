#!/usr/bin/env bash
# Standalone HTTPS bootstrap. Release payloads never contain private state.
set -euo pipefail
run_controller() {
    local payload="$1" action="$2"
    shift 2
    python3 "$payload/scripts/manage.py" "$action" --source "$payload" "$@"
}
main() {
    local selected_version="" action=install controller_args=() answer dependency temp cleanup
    if [[ "${1:-}" == --help ]]; then
        printf 'FamilyChat keyserver: sudo bash install.sh [vX.Y.Z] [install|update] [options]\nOptions are forwarded to scripts/manage.py; prompts use /dev/tty.\n'
        return
    fi
    if [[ "${1:-}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        selected_version="$1"; shift
    fi
    if [[ "${1:-}" == install || "${1:-}" == update ]]; then
        action="$1"; shift
    fi
    controller_args=("$@")
    [[ "$(uname -s)" == Linux && "$EUID" == 0 ]] || { echo 'Запустите на Ubuntu/Debian VPS через sudo.' >&2; return 1; }
    # shellcheck source=/dev/null
    source /etc/os-release
    [[ "$ID" == ubuntu || "$ID" == debian ]] || { echo 'Поддерживаются Ubuntu и Debian.' >&2; return 1; }
    local dependencies=()
    for dependency in python3 curl; do
        command -v "$dependency" >/dev/null || dependencies+=("$dependency")
    done
    [[ -s /etc/ssl/certs/ca-certificates.crt ]] || dependencies+=(ca-certificates)
    if (( ${#dependencies[@]} )); then
        printf 'Нужны пакеты: %s. Установить? [y/N] ' "${dependencies[*]}" >/dev/tty
        read -r answer </dev/tty
        case "$answer" in y|Y|yes|да|д) ;; *) echo 'Установка отменена.'; return 1 ;; esac
        apt-get update
        apt-get install -y "${dependencies[@]}"
    fi
    temp="$(mktemp -d)"
    printf -v cleanup 'rm -rf -- %q' "$temp"
    # shellcheck disable=SC2064
    trap "$cleanup" EXIT
    python3 - "$temp" "$selected_version" <<'PY'
import gzip, hashlib, io, json, pathlib, re, sys, tarfile, urllib.parse, urllib.request
root = pathlib.Path(sys.argv[1])
repo = 'balamutik/familychat-keyserver'
limit = 16 << 20
class HTTPSRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if urllib.parse.urlsplit(newurl).scheme != 'https':
            raise ValueError('HTTPS redirect required')
        return super().redirect_request(req, fp, code, msg, headers, newurl)
opener = urllib.request.build_opener(HTTPSRedirect())
def get(url):
    request = urllib.request.Request(url, headers={'User-Agent': 'FamilyChat-keyserver-installer'})
    with opener.open(request, timeout=60) as response:
        data = response.read(limit + 1)
    if len(data) > limit:
        raise ValueError('Установочный файл слишком большой')
    return data
try:
    version = sys.argv[2] or json.loads(get(f'https://api.github.com/repos/{repo}/releases/latest'))['tag_name']
    if not re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+', version):
        raise ValueError('Ожидается версия vX.Y.Z')
    base = f'https://github.com/{repo}/releases/download/{version}'
    data = get(base + '/familychat-keyserver.tar.gz')
    sums = get(base + '/SHA256SUMS').decode()
    expected = [line.split()[0] for line in sums.splitlines() if len(line.split()) == 2 and line.split()[1] == 'familychat-keyserver.tar.gz']
    if expected != [hashlib.sha256(data).hexdigest()]:
        raise ValueError('SHA256 архива не совпадает')
    allowed = {'compose.yaml', 'release.json', 'README.md', 'scripts/manage.py', 'scripts/install.sh',
               'scripts/update.sh', 'scripts/renew.sh', 'scripts/backup.sh'}
    with gzip.GzipFile(fileobj=io.BytesIO(data)) as compressed:
        unpacked = compressed.read(limit + 1)
    if len(unpacked) > limit:
        raise ValueError('Распакованный архив слишком большой')
    with tarfile.open(fileobj=io.BytesIO(unpacked), mode='r:') as archive:
        total, names, members = 0, set(), []
        for member in archive:
            total += member.size
            if not member.isfile() or member.name not in allowed or member.name in names or total > limit or len(members) >= 64:
                raise ValueError('Небезопасный архив')
            names.add(member.name)
            members.append(member)
        if names != allowed:
            raise ValueError('Неполный установочный комплект')
        manifest = json.load(archive.extractfile('release.json'))
        image = manifest.get('image', '')
        if manifest.get('version') != version or manifest.get('repository') != repo or not re.fullmatch(
                r'ghcr\.io/balamutik/familychat-keyserver@sha256:[a-f0-9]{64}', image):
            raise ValueError('Релиз не совпадает с установочным комплектом')
        compose = archive.extractfile('compose.yaml').read().decode()
        if '    image: ' + image + '\n' not in compose or re.search(r'^\s*(?:build|include|extends):', compose, re.M):
            raise ValueError('Неверный образ релиза')
        for member in members:
            target = root / member.name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(archive.extractfile(member).read())
            target.chmod(0o755 if member.name.endswith('.sh') else 0o644)
except Exception as error:
    sys.exit(f'Не удалось получить релиз FamilyChat keyserver: {error}. Проверьте публичный релиз.')
PY
    run_controller "$temp" "$action" "${controller_args[@]}"
}
main "$@"
