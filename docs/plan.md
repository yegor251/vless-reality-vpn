# VLESS + REALITY VPN — план и статус

Цель: собственный VPN-сервер (и опционально клиент) VLESS + REALITY для личного обхода блокировок.
Без биллинга/пользовательских панелей — только подключение и проксирование.

Runbook раскатки на Ubuntu VPS: [deploy-ubuntu.md](deploy-ubuntu.md).

Решение по языку: ядро (VLESS + REALITY) — Go; тулинг (ключи, конфиги, vless://-ссылки, e2e) — Python.
Причины: отсутствие в Python аналогов uTLS и библиотек для кастомного TLS 1.3 хендшейка;
в Go есть `golang.org/x/crypto`, `refraction-networking/utls` и два эталона (Xray-core, sing-box).

## Этапы

- [x] **M0 — эталон.** Xray-core установлен (`brew install xray`), исходники:
      `git clone --depth 1 https://github.com/XTLS/Xray-core /tmp/xray-ref` (при необходимости повторить);
      пакет `github.com/xtls/reality` — `git clone --depth 1 https://github.com/XTLS/REALITY /tmp/reality-ref`.
- [x] **M1 — VLESS по голому TCP (Go).** Кодек, UUID-аутентификация, TCP-проксирование.
      Интероп: Xray-клиент (SOCKS5 → VLESS outbound, security=none) ходит через наш сервер. `test/e2e.sh`.
- [x] **M2 — REALITY-сервер.** Полностью своё ядро (см. «REALITY-ядро» ниже), проверено `test/e2e.sh`:
      Xray 26.3.27 (fp=chrome) проксируется; пробер видит настоящий dest-сайт и сертификат;
      неверный short_id/SNI/мусор уходит в relay.
- [ ] **M3 — свой клиент (опционально).** SOCKS5 → VLESS+REALITY, uTLS Chrome fingerprint.
- [x] **M4 — Python-тулинг** (`tools/`, venv + `cryptography`/`pytest`): `vpnctl.py`
      (keys/init/add-user/link/probe), `link2xray.py` (линк → клиентский конфиг, для тестов),
      pytest-тесты. Проверено e2e: сервер на конфиге из `init` + клиент, собранный только из
      `vless://`-ссылки, проксирует трафик. Деплой: `deploy/` (Dockerfile, docker-compose.yml,
      systemd unit с DynamicUser+hardening, `deploy.sh user@host`). Compose-конфиг провалидирован;
      docker build и systemd на локальной машине не проверялись (демон выключен, macOS).
- [ ] **M5 — опционально.** UDP ASSOCIATE (2-байтовый length-prefix на пакет), flow Vision,
      ротация short_id, метрики.

## Wire-формат VLESS (сверено с исходниками Xray-core, `proxy/vless/encoding/`)

Запрос: `version(0x00) | UUID(16 байт raw) | addons_len | addons | command | port(2, BE) | addr_type | addr`
- command: TCP=0x01, UDP=0x02, MUX=0x03, Rvs=0x04 (MUX/Rvs не содержат addr/port)
- addr_type: IPv4=0x01 (4 байта), domain=0x02 (1 байт len + байты), IPv6=0x03 (16 байт)
- addons: protobuf `Addons` (Flow для Vision); без flow — addons_len=0

Ответ сервера: `0x00 0x00` (version + addons_len).

UDP-фрейминг: каждый пакет с префиксом длины 2 байта BE.

## REALITY-ядро (реализовано в `core/internal/reality/`, сверено с `github.com/xtls/reality`)

Механика:
- Клиент прячет аутентификацию в `session_id` (32 байта):
  `AES-256-GCM(HKDF-SHA256(X25519(TLS key_share, статический ключ сервера), salt=Random[:20], info="REALITY"))`
  над 16 байтами `{version[3], reserved, time BE32, short_id[8]}`; nonce = `Random[20:32]`,
  AAD = байты ClientHello **с обнулённым session_id**.
- Аутентификация требует наличия key_share X25519MLKEM768 (как в текущем эталоне); чистый x25519,
  идущий после гибрида, имеет приоритет для ECDH.
- При успехе сервер завершает TLS 1.3 **своим** мини-стеком (`tls13.go`): всегда подписывает
  CertificateVerify ключом ed25519, игнорируя предложенные клиентом схемы подписи, и предъявляет
  минимальный self-signed сертификат, в 64-байтовое поле подписи которого записан
  `HMAC-SHA512(authKey, ed25519 pubkey)` — по нему REALITY-клиент узнаёт «своего» сервера.
- При провале (мусор, чужой SNI, неверный short_id/ключ/время) — прозрачный relay на dest:
  пробер получает настоящий сайт. Dest используется и как оракул: на успешный путь сервер
  пересылает ClientHello и требует валидный TLS 1.3 ServerHello.

Отклонения от эталона (сознательные упрощения M2): свой ServerHello без зеркалирования длин
записей dest, нет фейковых post-handshake записей и rate-limit на fallback, fallback
последовательный; suite только AES-GCM (0x1301/0x1302). Ключи в конфигах — base64 RawURL
(как ждёт Xray); `cmd/keygen` генерирует пару.

Проверка: `cd core && go test ./...` (KAT RFC 8448, round-trip auth, интероп со stdlib-клиентом),
`test/e2e.sh` (M1 + M2 матрица).

## Структура

```
core/    Go-модуль (module vpn)
  cmd/vpn-server/      сервер
  cmd/keygen/          генератор x25519-пар
  internal/vless/      кодек + UUID
  internal/auth/       constant-time хранилище UUID
  internal/config/     JSON-конфиг
  internal/reality/    REALITY-ядро: ClientHello, auth, cert, мини-TLS 1.3
  internal/proxy/      обработка соединений
tools/   Python-тулинг (venv: cryptography, pytest)
  vpnctl.py            keys/init/add-user/link/probe
  link2xray.py         vless:// → клиентский конфиг Xray
test/    e2e-интероп с Xray (e2e.sh: фазы M1/M2/M4)
deploy/  Dockerfile, docker-compose.yml, vpn-server.service, deploy.sh
docs/    план
```

## Рабочий цикл (M4)

```
# 1. проверить, что dest подходит (TLS 1.3)
.venv/bin/python tools/vpnctl.py probe --dest www.apple.com:443
# 2. сгенерировать конфиг сервера + vless://-ссылки (host — публичный адрес VPS)
.venv/bin/python tools/vpnctl.py init --host <VPS_IP> --dest www.apple.com:443 --sni www.apple.com
# 3. задеплоить (или docker compose -f deploy/docker-compose.yml up -d)
deploy/deploy.sh root@<VPS_IP> deploy/server.json
# 4. импортировать ссылку в клиент (v2rayNG / v2rayN / Streisand / …)
```

Проверка после деплоя: с клиента `curl --socks5-hostname 127.0.0.1:1080 https://api.ipify.org`,
с посторонней машины `curl --resolve <sni>:443:<VPS_IP> https://<sni>/` должен показать настоящий dest-сайт.

## Практики для РФ (реализовать на M2)

- dest: TLS 1.3 + HTTP/2, не RU-домен, географически близко к серверу.
- Только 443/tcp на внешнем IP; ничего лишнего.
- short_id ротация; мониторинг блокировок (волны блокировок ASN у хостеров).
