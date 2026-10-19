# Сервер ключей FamilyChat

Отдельный сервис выдаёт приложениям текущую пару ключей `fc1`. Он **не подключается к основному серверу**, не хранит переписку и не требует отдельной регистрации пользователей. После обычного входа приложение получает короткий билет основного сервера, обращается с ним непосредственно сюда и сохраняет ключи на устройстве. Повторный запрос нужен после переустановки, очистки локальных данных или изменения ключа.

Основной сервер получает только публичный ключ, адрес службы и секрет подписи билетов. **Приватный ключ содержимого остаётся здесь и на пользовательских устройствах.** Секрет билетов разрешает выдачу ключа, поэтому файл подключения также закрыт от посторонних. Эта простая схема рассчитана на семейный чат: активный захват основного сервера позволяет выпустить билет от имени клиента; отдельного подтверждения устройств нет.

## Порты и HTTPS

- Сервис слушает **HTTPS TCP 8443**. Другой свободный порт задаётся `--port`, например `9443`.
- Порты `80`, `443`, `8080` и все привилегированные порты запрещены для самого сервиса, чтобы не пересекаться с основным приложением.
- Сертификат выдаёт **certbot** или **acme.sh**, по выбору при установке. Оба являются клиентами ACME; используется Let's Encrypt.
- Проверка HTTP-01 всегда приходит от удостоверяющего центра на **порт 80**, независимо от порта приложения. Для `standalone` порт 80 должен быть свободен и доступен извне; для `webroot` его обслуживает существующий веб-сервер. Скрипты не останавливают и не перенастраивают чужие сервисы.
- Если порт 80 занят или закрыт, используйте `webroot` либо автоматическую проверку **DNS-01**. DNS-01 не требует открытия 80/443 на этой машине.
- Откройте выбранный HTTPS-порт в межсетевом экране/настройках хостинга. DNS A/AAAA имени должны указывать на нужный сервер; не оставляйте неработающую AAAA-запись.

Механизмы подтверждены официальными инструкциями: [certbot: standalone, webroot, DNS и renewal](https://eff-certbot.readthedocs.io/en/stable/using.html), [acme.sh: получение и установка сертификата](https://github.com/acmesh-official/acme.sh), [DNS-провайдеры acme.sh](https://github.com/acmesh-official/acme.sh/wiki/dnsapi). Нельзя перенаправить ACME-проверку на 8443 простым выбором порта приложения.

## Подготовка отдельного Linux-сервера

Нужны Docker Engine, Docker Compose plugin, Python 3.9+ и выбранный клиент сертификатов. Go на машине установки не нужен: образ собирается в Docker. Исходники этого каталога должны быть скопированы на сервер, например в `~/familychat-keyserver`. Каталоги `state`, `tls`, `acme`, `export`, `backups` с уже работающей машины не копируйте как исходники.

Для certbot на Debian/Ubuntu:

```bash
sudo apt update
sudo apt install -y python3 certbot
```

Для acme.sh, следуя [официальной инструкции](https://github.com/acmesh-official/acme.sh/wiki/How-to-install), установите его для root без отдельного cron: собственный таймер ниже будет продлевать сертификаты службы.

```bash
git clone --depth 1 https://github.com/acmesh-official/acme.sh.git /tmp/familychat-acme
sudo /tmp/familychat-acme/acme.sh --install --home /root/.acme.sh --nocron --accountemail admin@example.com
```

Далее выберите один вариант получения сертификата. Скрипт без параметров задаст вопросы о домене, email, certbot/acme.sh и способе проверки. По умолчанию установка находится в `/opt/familychat-keyserver`.

### Новый чат: свободный порт 80

```bash
cd ~/familychat-keyserver
sudo ./scripts/install.sh \
  --domain keys.example.com --email admin@example.com \
  --client certbot --challenge standalone
```

Или с acme.sh:

```bash
sudo ./scripts/install.sh \
  --domain keys.example.com --email admin@example.com \
  --client acme.sh --challenge standalone --port 8443
```

Скрипт соберёт образ, создаст ключи один раз, выпустит сертификат и запустит контейнер. Повторный `install` не заменит ключи; обновлять нужно через `update.sh`.

### Когда порт 80 занят: webroot

Укажите каталог, который **уже** отдаётся существующим веб-сервером по адресу `http://keys.example.com/.well-known/acme-challenge/...`. Его маршрутизацию настраивает администратор существующего веб-сервера; установщик её не меняет.

```bash
sudo ./scripts/install.sh \
  --domain keys.example.com --email admin@example.com \
  --client certbot --challenge webroot --webroot /var/www/acme
```

С `--client acme.sh` параметры те же.

### Без доступа к порту 80: DNS-01

Пример acme.sh + Cloudflare. Создайте закрытый файл `/root/familychat-dns.env`:

```text
CF_Token=your-dns-api-token
CF_Account_ID=your-account-id
```

```bash
sudo chmod 600 /root/familychat-dns.env
sudo ./scripts/install.sh \
  --domain keys.example.com --email admin@example.com \
  --client acme.sh --challenge dns --dns-provider dns_cf \
  --dns-env /root/familychat-dns.env
```

Для другого провайдера выберите его `dns_*` модуль и переменные из официальной инструкции. Файл содержит строки `NAME=value`, без `export`, кавычек и shell-команд; значения передаются напрямую. Установщик копирует его в закрытый каталог установки для автоматического продления.

Вариант certbot + Cloudflare:

```bash
sudo apt install python3-certbot-dns-cloudflare
```

Создайте `/root/cloudflare.ini` с `dns_cloudflare_api_token = ...` и `/root/familychat-certbot-dns.json`:

```json
["--dns-cloudflare", "--dns-cloudflare-credentials", "/root/cloudflare.ini", "--dns-cloudflare-propagation-seconds", "60"]
```

```bash
sudo chmod 600 /root/cloudflare.ini /root/familychat-certbot-dns.json
sudo ./scripts/install.sh \
  --domain keys.example.com --email admin@example.com \
  --client certbot --challenge dns \
  --certbot-dns-args /root/familychat-certbot-dns.json
```

Параметры зависят от установленного DNS-плагина. Файл credentials, указанный отдельным аргументом `--dns-…-credentials`, копируется в каталог установки и включается в резервную копию.

## Перенос уже работающего FamilyChat — сохранить историю

**Не создавайте новую пару ключей для существующей истории.** Перед переключением сохраните согласованную резервную копию основного приложения и его текущих секретов.

1. На основном сервере найдите `secrets/content-public-key.txt` и `secrets/content-private-key.txt` действующей установки. В них находится та пара, отпечаток которой записан в PostgreSQL. Для старых установок вместо пары может использоваться `encryption_keys/key.json` из прежнего тома ключей.
2. Перенесите исходные файлы защищённым каналом на сервер ключей; права на них должны быть `0600` или `0400`. Не передавайте содержимое через сообщения или параметры командной строки.
3. Выполните установку с **импортом**:

```bash
sudo ./scripts/install.sh \
  --domain keys.example.com --email admin@example.com \
  --client certbot --challenge standalone \
  --import-public /root/import/content-public-key.txt \
  --import-private /root/import/content-private-key.txt
```

Для прежнего JSON:

```bash
sudo ./scripts/install.sh \
  --domain keys.example.com --email admin@example.com \
  --client certbot --challenge standalone \
  --import-json /root/import/key.json
```

Импорт проверяет соответствие половин ключа и SHA-256 отпечатка. Конфликт с уже созданным состоянием завершается ошибкой; подмены и автоматической ротации нет. Резервную копию старого ключа сохраняйте отдельно; перенос не меняет ключ для исторических данных.

После успешного переключения основного приложения и проверки истории перенесите все прежние копии приватного ключа, старый том ключей и содержащие их резервные копии **за пределы основного хоста**. Одного отключения Docker secret недостаточно, если исходный файл остаётся на диске основной VPS. Скрипты этого сервиса не удаляют чужие файлы и тома автоматически.

## Подключение основного приложения

После успешной установки на сервере ключей появится закрытый файл:

```text
/opt/familychat-keyserver/export/main-server.json
```

Перенесите **только его** на основной сервер, например в `/root/main-server.json`. В нём нет приватного ключа переписки. `state/state.json`, исходный приватный ключ и DNS/TLS секреты на основной сервер не передаются.

Для новой установки основного сервера передайте `--key-service-config /root/main-server.json` его установщику. Для существующей установки после обновления приложения:

```bash
sudo familychat configure-key-server --key-service-config /root/main-server.json
```

Дальнейшие действия и совместимость клиентов описаны в инструкции основного приложения. При существующей истории отпечаток импортированного ключа должен совпадать с БД; основной сервер откажется переключаться на другую пару.

## Проверка и обслуживание

```bash
curl --fail https://keys.example.com:8443/health/ready
```

Ответ: `{"status":"ready"}`. Запрос `/api/v1/keys/current` без правильного короткоживущего билета возвращает `401`; постоянный токен сессии FamilyChat не принимается. Данные ключей никогда не помещаются в URL или логи; ответы помечены `Cache-Control: no-store`.

Обновление из новой версии исходников:

```bash
cd ~/familychat-keyserver
sudo ./scripts/update.sh
```

Скрипт создаёт резервную копию, собирает новый образ и пересоздаёт только контейнер `familychat-keyserver`. Состояние ключей и секрет билетов сохраняются. Обновление не выпускает новый ключ. TLS-сертификат перечитывается при новых соединениях без перезапуска процесса; при неполной замене пары продолжает работать последний корректный сертификат.

Продление сертификата вручную:

```bash
sudo /opt/familychat-keyserver/app/scripts/renew.sh
sudo systemctl status familychat-keyserver-renew.timer
```

На Linux с systemd установка включает ежедневный таймер. Без systemd скрипт выводит команду для ежедневного задания планировщика. При HTTP-01 порт 80 должен оставаться доступным для последующих проверок. Просматривать результат можно через `journalctl -u familychat-keyserver-renew.service`; секреты в журнал не выводятся скриптом.

Резервная копия:

```bash
sudo /opt/familychat-keyserver/app/scripts/backup.sh --output /root/keyserver-backup.tar.gz
```

Архив имеет права `0600`, включает `state/state.json` **вместе с приватным ключом и секретом билетов**, сертификаты, настройки и локально сохранённые DNS данные. Архив не зашифрован дополнительно; храните его в закрытом хранилище вне машины. Существующий файл архива не перезаписывается.

Восстановление на чистой машине: остановите только контейнер ключей, распакуйте архив в `/opt/familychat-keyserver` с сохранением прав, верните исходники в `app`, установите выбранный ACME-клиент и Docker, затем выполните `update.sh` и проверьте readiness. Каталог `state` и его файл должны принадлежать UID/GID `10001:10001`, иметь права `0700/0600`; `tls` также должен читаться этим UID. Если изменился домен/порт или пути DNS, приведите их в `deploy.json` и `service.env` к новой машине, перевыпустите сертификат и заново экспортируйте файл подключения с сохранённым состоянием.

## CLI без установщика

```bash
go build -o bin/familychat-keyserver ./cmd/familychat-keyserver
./bin/familychat-keyserver init --state-dir ./state \
  --url https://keys.example.com:8443/api/v1/keys/current --export ./main-server.json
./bin/familychat-keyserver export --state-dir ./state \
  --url https://keys.example.com:9443/api/v1/keys/current --out ./main-server.json
./bin/familychat-keyserver serve --state-dir ./state --listen :8443 \
  --tls-cert ./tls/fullchain.pem --tls-key ./tls/privkey.pem
```

`init` поддерживает те же `--import-json` либо `--import-public` / `--import-private`. Повторный `init` сохраняет ключ и секрет билетов. Состояние хранится в отдельном файле вне образа, каталоги закрыты (`0700`), файлы — `0600`. Если `state.json` пропал из непустого каталога, генерация запрещена: требуется восстановить резервную копию.

Билет — compact JWT `HS256`, подписанный декодированным `ticket_secret`, с `iss`, `aud=familychat-keyserver`, `sub`, `key_id`, `iat`, `exp`. Основной сервер выдаёт его на 120 секунд; служба допускает не более 300 секунд срока и до 30 секунд рассинхронизации будущего `iat`. Неверные подписи, аудитория, издатель, ключ и просроченные билеты отклоняются. Синхронизируйте время обеих машин.

Проверки разработки:

```bash
go test -race ./...
go vet ./...
python3 -m unittest discover -s scripts/tests -v
docker compose config --quiet
```
