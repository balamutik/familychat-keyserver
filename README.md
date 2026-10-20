# Сервер ключей FamilyChat

Отдельный сервис выдаёт приложениям текущую пару ключей `fc1`. Он **не подключается к основному серверу**, не хранит переписку и не требует отдельной регистрации пользователей. После обычного входа приложение получает короткий билет основного сервера, обращается с ним непосредственно сюда и сохраняет ключи на устройстве. Повторный запрос нужен после переустановки, очистки локальных данных или изменения ключа.

Основной сервер получает только публичный ключ, адрес службы и секрет подписи билетов. **Приватный ключ содержимого остаётся здесь и на пользовательских устройствах.** Секрет билетов разрешает выдачу ключа, поэтому файл подключения также закрыт от посторонних. Эта простая схема рассчитана на семейный чат: активный захват основного сервера позволяет выпустить билет от имени клиента; отдельного подтверждения устройств нет.

## Порты и HTTPS

- Сервис слушает **HTTPS TCP 8443**. Другой свободный порт задаётся `--port`, например `9443`.
- Порты `80`, `443`, `8080` и все привилегированные порты запрещены для самого сервиса, чтобы не пересекаться с основным приложением.
- Сертификат выдаёт **certbot** или **acme.sh**, по выбору при установке. Оба являются клиентами ACME; используется Let's Encrypt.
- Проверка HTTP-01 всегда приходит от удостоверяющего центра на **порт 80**, независимо от порта приложения. Для `standalone` порт 80 должен быть свободен и доступен извне; для `webroot` его обслуживает существующий веб-сервер. Скрипты не останавливают и не перенастраивают чужие сервисы.
- Если порт 80 занят, используйте `webroot`. Для **доменного имени** также доступна автоматическая проверка **DNS-01**, не требующая открытия 80/443 на этой машине. Для сертификата на IP DNS-01 не подходит: требуется доступ к порту 80.
- Откройте выбранный HTTPS-порт в межсетевом экране/настройках хостинга. DNS A/AAAA имени должны указывать на нужный сервер; не оставляйте неработающую AAAA-запись.

Механизмы подтверждены официальными инструкциями: [certbot: standalone, webroot, DNS и renewal](https://eff-certbot.readthedocs.io/en/stable/using.html), [acme.sh: получение и установка сертификата](https://github.com/acmesh-official/acme.sh), [DNS-провайдеры acme.sh](https://github.com/acmesh-official/acme.sh/wiki/dnsapi). Нельзя перенаправить ACME-проверку на 8443 простым выбором порта приложения.

## Установка публичного релиза на отдельный Linux-сервер

Публичный репозиторий: [balamutik/familychat-keyserver](https://github.com/balamutik/familychat-keyserver). Поддерживаются Ubuntu/Debian на **amd64 и arm64**. Начальная команда требует `curl` и `sudo`; Python 3 и доверенные CA установщик предложит добавить при отсутствии. Для Docker Engine и Compose plugin используется официальный apt-репозиторий Docker с отдельным подтверждением. Существующий Docker сохраняется; недостающий Compose устанавливается из того же источника. Минимальная версия Compose — 2.24.4.

Интерактивная установка последнего опубликованного релиза:

```bash
curl --proto '=https' --tlsv1.2 -fsSL https://github.com/balamutik/familychat-keyserver/releases/latest/download/install.sh | sudo bash
```

Скрипт задаёт вопросы через `/dev/tty`, поэтому ввод работает и при `curl | sudo bash`. Для запуска без терминала укажите все параметры, а зависимости установите заранее. По умолчанию каталог установки — `/opt/familychat-keyserver`.

При запуске через `sudo` установщик вызывает acme.sh от root с домашним каталогом root и явно указанными каталогами клиента и конфигурации. Переменные `SUDO_*` убираются только из окружения дочернего ACME-процесса: аргумент `--client acme.sh` иначе вызывает ложное срабатывание интерактивной проверки acme.sh. Это применяется также к регистрации, продлению и сохранению сертификата; принудительный перевыпуск `--force` не используется. Настройки DNS-провайдера сохраняются.

**certbot** или **acme.sh** выбирается параметром `--client` либо в диалоге. Если certbot отсутствует, установщик предложит apt-пакет `certbot`. DNS-плагины certbot устанавливаются администратором отдельно. При выборе отсутствующего acme.sh установщик предложит официальный архив версии 3.1.6, закреплённый коммитом и SHA-256, и необходимые `curl`, `openssl`, `socat`. Архив проверяется до исполнения; установка выполняется без собственного cron, продление обслуживает таймер keyserver. Уже установленный клиент используется без переустановки; другой путь acme.sh можно задать через `--acme-binary`.

Релиз содержит готовый публичный образ `ghcr.io/balamutik/familychat-keyserver@sha256:…`; Go, git и сборка приложения на VPS не нужны. Архив `familychat-keyserver.tar.gz` проверяется по `SHA256SUMS`, а его манифест — по репозиторию, версии и неизменяемому образу. Загрузка и распаковка ограничены по размеру; состояние и ключи в релиз не включаются. Начальный `install.sh` и суммы загружаются по HTTPS из одного доверенного GitHub-релиза; контрольная сумма не является отдельной подписью издателя.

Чтобы закрепить версию, используйте её URL и первым аргументом ту же версию:

```bash
curl --proto '=https' --tlsv1.2 -fsSL https://github.com/balamutik/familychat-keyserver/releases/download/v1.0.6/install.sh | sudo bash -s -- v1.0.6
```

### Новый чат: свободный порт 80

```bash
curl --proto '=https' --tlsv1.2 -fsSL https://github.com/balamutik/familychat-keyserver/releases/latest/download/install.sh | sudo bash -s -- \
  --domain keys.example.com --email admin@example.com \
  --client certbot --challenge standalone
```

Или с acme.sh:

```bash
curl --proto '=https' --tlsv1.2 -fsSL https://github.com/balamutik/familychat-keyserver/releases/latest/download/install.sh | sudo bash -s -- \
  --domain keys.example.com --email admin@example.com \
  --client acme.sh --challenge standalone --port 8443
```

Скрипт загрузит готовый образ, создаст ключи один раз тем же образом, выпустит сертификат и запустит контейнер. После успешной установки обновлять нужно через `update.sh`.

### Установка на публичный IP без домена

Параметр `--domain` также принимает публичный IPv4 или IPv6 без квадратных скобок и порта. Установщик автоматически выбирает профиль Let's Encrypt `shortlived`: обычный профиль не выдаёт сертификаты на IP. Срок такого сертификата — **160 часов**; ежедневный таймер проверяет необходимость продления. Для acme.sh используется интервал продления 3 дня. Профиль сохраняется и при автоматическом продлении. Подробности: [профили Let's Encrypt](https://letsencrypt.org/docs/profiles/), [профили и интервал продления acme.sh](https://github.com/acmesh-official/acme.sh/wiki/Profile-selection).

```bash
curl --proto '=https' --tlsv1.2 -fsSL https://github.com/balamutik/familychat-keyserver/releases/latest/download/install.sh | sudo bash -s -- \
  --domain PUBLIC_IP --email admin@example.com \
  --client acme.sh --challenge standalone --port 8443
```

Замените `PUBLIC_IP` публичным адресом вашего сервера и укажите свой email. Для IP поддерживаются `standalone` и `webroot`; порт 80 должен быть доступен извне, а порт 8443 используется самим сервером ключей. Установщик проверяет поддержку необходимых параметров ACME-клиента до создания ключей. Для certbot нужна версия с поддержкой IP (5.4+); если пакет дистрибутива старый, выберите `acme.sh` либо обновите certbot по официальной инструкции. Для IPv6 существующая конфигурация Docker и сеть сервера также должны обеспечивать доступ по IPv6.

### Повторный запуск после ошибки сертификата

Если установка остановилась на выпуске сертификата и `deploy.json` ещё не создан, повторите ту же команду установки из актуального релиза с тем же адресом и каталогом. Исправленный установщик создаёт закрытый каталог конфигурации acme.sh **до** регистрации и выпуска. Уже имеющиеся `state/state.json` и секрет билетов используются повторно: ключи не генерируются заново. **Не удаляйте `/opt/familychat-keyserver` или его `state` для повторной установки.** Если был указан импорт существующих ключей, повторите и параметры импорта.

Если `deploy.json` уже существует, используйте обновление ниже, затем `sudo /opt/familychat-keyserver/app/scripts/renew.sh`. Для получения сертификата на IP при HTTP-01 доступ к порту 80 нужен и для последующих продлений.

### Когда порт 80 занят: webroot

Укажите каталог, который **уже** отдаётся существующим веб-сервером по адресу `http://keys.example.com/.well-known/acme-challenge/...`. Его маршрутизацию настраивает администратор существующего веб-сервера; установщик её не меняет.

```bash
curl --proto '=https' --tlsv1.2 -fsSL https://github.com/balamutik/familychat-keyserver/releases/latest/download/install.sh | sudo bash -s -- \
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
curl --proto '=https' --tlsv1.2 -fsSL https://github.com/balamutik/familychat-keyserver/releases/latest/download/install.sh | sudo bash -s -- \
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
curl --proto '=https' --tlsv1.2 -fsSL https://github.com/balamutik/familychat-keyserver/releases/latest/download/install.sh | sudo bash -s -- \
  --domain keys.example.com --email admin@example.com \
  --client certbot --challenge dns \
  --certbot-dns-args /root/familychat-certbot-dns.json
```

Параметры зависят от установленного DNS-плагина. Файл credentials, указанный отдельным аргументом `--dns-…-credentials`, копируется в каталог установки и включается в резервную копию.

## Перенос уже работающего FamilyChat — сохранить историю

### Оба сервера уже установлены: подключение двумя командами

Начиная с **v1.0.5** установщик переносит исходную пару ключей чата в отдельно установленный **ещё не используемый** сервер ключей и подключает чат автоматически. Переписка продолжает использовать прежний ключ. VPS должны иметь доступ к GitHub; с VPS ключей нужен обычный SSH-доступ к VPS чата и пользователь с `sudo`. Основной чат должен быть установлен релизным установщиком в `/opt/familychat` и поддерживать отдельный сервер ключей. Обновлять установщик на VPS отдельной командой не требуется.

**1. На VPS чата:**

```bash
curl --proto '=https' --tlsv1.2 -fsSL https://github.com/balamutik/familychat-keyserver/releases/latest/download/install.sh | sudo bash -s -- prepare-chat
```

Первая команда подготовит закрытый временный пакет для текущего SSH-пользователя и выведет готовую вторую команду с адресом VPS чата. При запуске из-под root имя SSH-пользователя будет запрошено; Enter выбирает `root`. Можно указать `--ssh-user USER` и, для нестандартной установки, `--chat-root /путь`. В версии v1.0.6 исправлен ввод из терминала при запуске от root через `curl | sudo bash`. Если подготовка не выполнена, сообщение указывает этап и безопасную причину ошибки без содержимого ключей.

**2. На VPS сервера ключей:**

```bash
curl --proto '=https' --tlsv1.2 -fsSL https://github.com/balamutik/familychat-keyserver/releases/latest/download/install.sh | sudo bash -s -- connect-chat
```

Введите `пользователь@IP_чата`, либо выполните готовую команду, выведенную на первом VPS. Проверка SSH-ключа узла, пароль SSH и пароль `sudo` запрашиваются в терминале, в том числе при запуске через `curl | sudo bash`. Нестандартные параметры: `--chat USER@HOST --ssh-port 2222 --ssh-identity /root/.ssh/id_ed25519`; каталог сервера ключей — `--install-dir /opt/familychat-keyserver`. Ключ SSH должен быть доступен пользователю root, запускающему команду.

Подключение сохраняет закрытые резервные копии, проверяет пару ключей, перезапускает службу ключей и API чата с ожиданием готовности и перезагружает nginx. При подтверждённой ошибке применения прежние настройки восстанавливаются на обоих VPS. При обрыве SSH повторите **вторую команду**: сохранённый журнал и подтверждение позволяют продолжить без повторной смены ключей и секрета билетов. Изменённые вручную настройки автоматически не перезаписываются.

После успеха временные `payload.json` с парой ключей и `connection.json` удаляются из `~/.familychat-keyserver-link` на VPS чата. Исходные файлы `secrets/content-*-key.txt` сохраняются до проверки старой истории на клиентах. Их удаление вместе с прежними резервными копиями — отдельный шаг администратора после проверки; до этого закрытый ключ ещё присутствует на основном VPS. Не удаляйте исходные ключи до подтверждённого переключения.

### Ручной перенос при установке нового сервера ключей

**Не создавайте новую пару ключей для существующей истории.** Перед переключением сохраните согласованную резервную копию основного приложения и его текущих секретов.

1. На основном сервере найдите `secrets/content-public-key.txt` и `secrets/content-private-key.txt` действующей установки. В них находится та пара, отпечаток которой записан в PostgreSQL. Для старых установок вместо пары может использоваться `encryption_keys/key.json` из прежнего тома ключей.
2. Перенесите исходные файлы защищённым каналом на сервер ключей; права на них должны быть `0600` или `0400`. Не передавайте содержимое через сообщения или параметры командной строки.
3. Выполните установку с **импортом**:

```bash
curl --proto '=https' --tlsv1.2 -fsSL https://github.com/balamutik/familychat-keyserver/releases/latest/download/install.sh | sudo bash -s -- \
  --domain keys.example.com --email admin@example.com \
  --client certbot --challenge standalone \
  --import-public /root/import/content-public-key.txt \
  --import-private /root/import/content-private-key.txt
```

Для прежнего JSON:

```bash
curl --proto '=https' --tlsv1.2 -fsSL https://github.com/balamutik/familychat-keyserver/releases/latest/download/install.sh | sudo bash -s -- \
  --domain keys.example.com --email admin@example.com \
  --client certbot --challenge standalone \
  --import-json /root/import/key.json
```

Импорт проверяет соответствие половин ключа и SHA-256 отпечатка. Конфликт с уже созданным состоянием завершается ошибкой; подмены и автоматической ротации нет. Резервную копию старого ключа сохраняйте отдельно; перенос не меняет ключ для исторических данных.

### Если оба сервера уже установлены с разными ключами

Сообщение `Новый ключ не совпадает с текущим` означает, что нужно перенести **исходные ключи чата на сервер ключей**. Существующий чат и его БД сохраняются. Для нового keyserver, который ещё не подключён к чату, в версии **v1.0.3+** есть отдельная команда `import-keys`. Она проверяет пару в отдельном каталоге, сохраняет закрытую резервную копию прежнего состояния и переключает только службу ключей. При ошибке запуска восстанавливает прежнее состояние и запускает службу с ним. Сертификат, ACME, адрес и порт сохраняются.

1. На сервере чатов подготовьте закрытые копии исходной пары и перенесите их по SSH. Замените `SSH_USER@KEYSERVER` на пользователя и адрес VPS сервера ключей:

```bash
mkdir -p -m 700 "$HOME/familychat-key-import"
sudo install -o "$(id -u)" -g "$(id -g)" -m 600 \
  /opt/familychat/secrets/content-public-key.txt \
  /opt/familychat/secrets/content-private-key.txt \
  "$HOME/familychat-key-import/"
scp -r "$HOME/familychat-key-import" SSH_USER@KEYSERVER:
```

2. На сервере ключей обновите установщик и импортируйте пару:

```bash
curl --proto '=https' --tlsv1.2 -fsSL https://github.com/balamutik/familychat-keyserver/releases/latest/download/install.sh | sudo bash -s -- update
sudo python3 /opt/familychat-keyserver/app/scripts/manage.py import-keys \
  --import-public "$HOME/familychat-key-import/content-public-key.txt" \
  --import-private "$HOME/familychat-key-import/content-private-key.txt" \
  --replace-unused-state
sudo install -o "$(id -u)" -g "$(id -g)" -m 600 \
  /opt/familychat-keyserver/export/main-server.json "$HOME/main-server.json"
```

Параметр `--replace-unused-state` явно разрешает заменить отдельную пару ещё не подключённого keyserver. Не используйте его для ротации ключей другого действующего чата. Если импортируется уже установленная пара, команда ничего не заменяет и сохраняет прежний секрет билетов без перезапуска. Для старого JSON вместо двух параметров используйте `--import-json /закрытый/путь/key.json`. Файлы импорта должны находиться вне заменяемых каталогов `state/` и `export/`.

3. На сервере чатов заново скачайте **обновлённый** файл подключения:

```bash
scp SSH_USER@KEYSERVER:main-server.json "$HOME/main-server.json"
chmod 600 "$HOME/main-server.json"
sudo familychat configure-key-server --key-service-config "$HOME/main-server.json"
sudo familychat status
```

Резервная копия прежнего keyserver сохраняется в `/opt/familychat-keyserver/backups/before-key-import-*.tar.gz` с правами `0600`. При неудаче автоматического восстановления команда выводит путь к резервной копии и каталогу восстановления; сохраните их. После успешного подключения проверьте старые сообщения и вложения, затем перенесите прежние приватные копии и резервные копии за пределы основного VPS по правилам ниже. Команда не удаляет исходные файлы импорта или данные основного сервера.

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

Обновление до последнего опубликованного релиза:

```bash
curl --proto '=https' --tlsv1.2 -fsSL https://github.com/balamutik/familychat-keyserver/releases/latest/download/install.sh | sudo bash -s -- update
```

Обновление до определённой версии:

```bash
curl --proto '=https' --tlsv1.2 -fsSL https://github.com/balamutik/familychat-keyserver/releases/download/v1.0.3/install.sh | sudo bash -s -- v1.0.3 update
```

Для нестандартного каталога добавьте `--install-dir /opt/your-keyserver`. Скрипт проверяет новый комплект, создаёт закрытую резервную копию, загружает неизменяемый образ и пересоздаёт только службу `keyserver` своего Compose-проекта. Состояние ключей, секрет билетов, TLS, ACME и DNS-настройки сохраняются. Команда `init` при обновлении не вызывается; ротации ключей нет. До обновления дождитесь завершения резервной копии; при ошибке не удаляйте состояние и не запускайте новую установку.

Установка и обновление **из локальных исходников** также поддерживаются: скопируйте чистый checkout этого репозитория на сервер и выполните `sudo ./scripts/install.sh ...` либо `sudo ./scripts/update.sh`. Тогда используется локальная Docker-сборка. `update.sh` из установленного релизного `app` повторно загружает **тот же закреплённый образ**; для перехода на новый релиз используйте публичную команду выше. TLS-сертификат перечитывается при новых соединениях без перезапуска процесса; при неполной замене пары продолжает работать последний корректный сертификат.

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

Восстановление на чистой машине: остановите только контейнер ключей, распакуйте архив в `/opt/familychat-keyserver` с сохранением прав, установите выбранный ACME-клиент и Docker, затем выполните публичную команду обновления с нужной версией; она вернёт релизный комплект в `app` и проверьте readiness. Каталог `state` и его файл должны принадлежать UID/GID `10001:10001`, иметь права `0700/0600`; `tls` также должен читаться этим UID. Если изменился домен/порт или пути DNS, приведите их в `deploy.json` и `service.env` к новой машине, перевыпустите сертификат и заново экспортируйте файл подключения с сохранённым состоянием.

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
# Проверка релизного комплекта с тестовым digest без запуска контейнеров:
python3 scripts/package-release.py --version v1.0.0 --image "ghcr.io/balamutik/familychat-keyserver@sha256:$(printf 'a%.0s' {1..64})" --output /tmp/keyserver-release
python3 scripts/tests/validate_compose.py /tmp/keyserver-release/familychat-keyserver.tar.gz
```

Публикация: workflow `.github/workflows/release.yml` запускается по тегу `vX.Y.Z`, тестирует сервис и установщик, собирает образ для amd64/arm64 и выпускает три файла: `install.sh`, `familychat-keyserver.tar.gz`, `SHA256SUMS`. Все используемые Actions закреплены SHA коммитов. Перед публикацией файлов проверяется доступ к образу **без Docker-авторизации**. При первой публикации владелец должен сделать GHCR package публичным в GitHub; если проверка остановит job, смените видимость и повторите запуск. Выпущенные версии не заменяются: для изменения нужен новый тег.
