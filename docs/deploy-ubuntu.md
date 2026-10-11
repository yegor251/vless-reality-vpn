# Раскатка на VPS (Ubuntu) — runbook

Сценарий: код лежит на GitHub, VPS с Ubuntu 22.04/24.04 (x86_64), деплой под root
(или через `sudo -i`). Домен не нужен. Порт — 443/tcp.

Заменяйте `<VPS_IP>` на адрес сервера и `<github-user>` на свой аккаунт.

## 0. Локально: выгрузка на GitHub

```bash
cd ~/PycharmProjects/vpn
git init
git add .
git commit -m "VLESS+REALITY server: core + tooling + tests"
git remote add origin git@github.com:<github-user>/vpn.git
git branch -M main
git push -u origin main
```

`.gitignore` уже настроен: конфиги с реальными ключами (`deploy/server.json`,
`test/server-*-reality.json`) и `.venv` не попадут в репозиторий.
**Приватный ключ REALITY живёт только на VPS в `/etc/vpn/server.json`.**

## 1. Подготовка VPS

```bash
apt update && apt upgrade -y
apt install -y git curl ca-certificates ufw python3 python3-venv

# время: должно быть NTP synchronized: yes (иначе REALITY-auth будет падать)
timedatectl status

# BBR — заметно ускоряет проксирование
printf 'net.core.default_qdisc=fq\nnet.ipv4.tcp_congestion_control=bbr\n' > /etc/sysctl.d/99-bbr.conf
sysctl --system

# файрвол: только ssh и 443
ufw allow 22/tcp
ufw allow 443/tcp
ufw enable
```

Если у хостера есть своя security group — откройте там 443/tcp тоже.

## 2. Go 1.27 (apt-версия старая, ставим официальную)

```bash
ARCH=$(dpkg --print-architecture)
GO_VER=1.27.1   # проверьте актуальный 1.27.x на https://go.dev/dl
curl -LO "https://go.dev/dl/go${GO_VER}.linux-${ARCH}.tar.gz"
rm -rf /usr/local/go && tar -C /usr/local -xzf "go${GO_VER}.linux-${ARCH}.tar.gz"
echo 'export PATH=$PATH:/usr/local/go/bin' > /etc/profile.d/go.sh
source /etc/profile.d/go.sh
go version    # go1.27.x
```

## 3. Код и сборка

```bash
git clone https://github.com/<github-user>/vpn.git /opt/vpn
cd /opt/vpn/core
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /usr/local/bin/vpn-server ./cmd/vpn-server
/usr/local/bin/vpn-server -h 2>&1 | head -2   # бинарь живой
```

## 4. Конфиг и ключи (генерируются НА сервере)

```bash
python3 -m venv /opt/vpn/.venv
/opt/vpn/.venv/bin/pip install -q cryptography

# проверка camouflage-цели (нужен TLS 1.3)
/opt/vpn/.venv/bin/python /opt/vpn/tools/vpnctl.py probe --dest www.apple.com:443

# генерация конфига + vless:// ссылки
mkdir -p /etc/vpn
/opt/vpn/.venv/bin/python /opt/vpn/tools/vpnctl.py init \
    --host <VPS_IP> \
    --dest www.apple.com:443 --sni www.apple.com \
    --out /etc/vpn/server.json
```

**Сохраните выведенную `vless://...` ссылку** — это ключ подключения для клиентов.

Требования к dest: TLS 1.3, не RU-домен, желательно географически рядом с VPS.
Альтернативы apple: крупные зарубежные сайты с TLS 1.3 (проверяйте `probe`).

## 5. systemd и запуск

```bash
cp /opt/vpn/deploy/vpn-server.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now vpn-server
systemctl status vpn-server --no-pager   # active (running)
journalctl -u vpn-server -n 20 --no-pager
```

Юнит: DynamicUser (без root), CAP_NET_BIND_SERVICE для 443, strict-изоляция ФС.

## 6. Проверка

```bash
# С ЛЮБОЙ машины — маскировка: должен ответить настоящий apple.com (HTTP 200)
curl -sI --resolve www.apple.com:443:<VPS_IP> https://www.apple.com/ | head -1

# На сервере — логи при подключении клиента: "reality established" затем "-> host:port"
journalctl -u vpn-server -f
```

Затем импортируйте `vless://`-ссылку в клиент (v2rayNG: + из буфера обмена;
v2rayN: Сервер → Импорт из буфера) и проверьте внешний IP, например
`curl --socks5-hostname 127.0.0.1:10808 https://api.ipify.org` — должен показать `<VPS_IP>`.

## 7. Эксплуатация

```bash
# добавить устройство/человека: новая ссылка (перезапуск обязателен)
/opt/vpn/.venv/bin/python /opt/vpn/tools/vpnctl.py add-user \
    --config /etc/vpn/server.json --host <VPS_IP> --name phone
systemctl restart vpn-server

# обновление кода
cd /opt/vpn && git pull
cd core && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /usr/local/bin/vpn-server ./cmd/vpn-server
systemctl restart vpn-server

# логи
journalctl -u vpn-server -f
```

Альтернатива — Docker: `apt install docker.io docker-compose-v2`, положить
`server.json` в `deploy/`, затем `cd deploy && docker compose up -d --build`.

## 8. Траблшутинг

| Симптом | Причина | Что делать |
|---|---|---|
| `curl --resolve` — connection refused | порт закрыт / сервис упал | `systemctl status vpn-server`, security group хостера, `ss -tlnp | grep 443` |
| curl отдаёт 200, клиент не подключается | время, ключи, fingerprint | `timedatectl` на VPS; сверить `pbk`/`sid` в ссылке с `server.json`; у клиента `fp=chrome` |
| в логах `reality auth failed` при рабочем клиенте | рассинхрон часов (>300 c) | `timedatectl status`, включить NTP: `timedatectl set-ntp true` |
| в логах `dest oracle failed` | dest недоступен с VPS | `vpnctl probe --dest ...`, сменить dest |
| в логах `server name mismatch` | SNI клиента не в `server_names` | сверить sni в ссылке и конфиге |
| go build: ошибки версий/синтаксиса | Go < 1.27 | `go version`, переустановить шаг 2 |

## 9. Практики РФ

- VPS вне РФ; следить за волнами блокировок ASN (если IP-диапазон хостера забанили — переезд).
- На IP ничего кроме 443; ssh лучше перевесить на нестандартный порт после настройки.
- При подозрении на блокировку: сменить short_id (`vpnctl` + restart), при необходимости — IP/хостера.
- Домен не используется — блокировать нечего, всё ходит по IP с SNI dest.
