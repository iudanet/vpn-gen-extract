# vpn-gen-extract

CLI-утилита: разбирает `vgc://` ссылку и печатает готовые конфиги для VPN-клиентов.

## Формат ссылки

Ссылка приходит в виде `https://<host>/vgc://<payload>`. Вся конфигурация зашита
в самой ссылке — обращаться к серверу не нужно:

```
payload → Base58 (алфавит bitcoin) → gzip → JSON
```

Base58 опознаётся по алфавиту: в нём нет символов `0`, `O`, `I` и `l`.

JSON содержит настройки сразу четырёх протоколов: `shadowsocks`, `protocol0`
(VLESS + Reality), `wireguard` и `cloak`.

## Установка

Готовые статические бинарники для Linux, Windows и macOS (amd64/arm64) лежат
в [Releases](https://github.com/iudanet/vpn-gen-extract/releases).

```bash
go build -o vpn-gen-extract ./cmd/vpn-gen-extract
```

## Релизы

Сборкой занимается GoReleaser: пуш тега `v*` запускает workflow, который
собирает все платформы и публикует архивы с `checksums.txt`.

```bash
git tag v0.1.0
git push origin v0.1.0
```

Проверить сборку локально, без публикации:

```bash
goreleaser release --snapshot --clean --skip=publish
```

Все бинарники собираются с `CGO_ENABLED=0`, поэтому статические: не зависят от
libc и одинаково работают на glibc, musl (Alpine) и в scratch-контейнере.

## Использование

```bash
# все протоколы разом
vpn-gen-extract 'https://host/vgc://B9CUGw...'
vpn-gen-extract -file url.txt

# один протокол — печатается голая ссылка, удобно для пайпов
vpn-gen-extract -only ss    -file url.txt
vpn-gen-extract -only vless -file url.txt

# сохранить в файл
vpn-gen-extract -only wireguard -file url.txt -out wg0.conf
vpn-gen-extract -only cloak     -file url.txt -out cloak.json
```

Флаги: `-file` (читать ссылку из файла), `-only` (`ss`/`outline`, `vless`,
`wireguard`/`wg`, `cloak`), `-out` (записать результат в файл), `-debug`
(подробный лог в stderr).

`-out` создаёт файл с правами `0600` — внутри приватные ключи. Файл
перезаписывается только после успешного разбора ссылки, поэтому битый ввод
не обнулит уже существующий конфиг.

## Что генерируется

| `-only` | Формат | Клиенты |
|---|---|---|
| `ss` | `ss://` (SIP002) с `/?outline=1&prefix=` | Outline, Hiddify, VPN4TV |
| `vless` | `vless://` с Reality | v2rayN, Hiddify, Streisand |
| `wireguard` | `.conf` для wg-quick | WireGuard, AmneziaWG |
| `cloak` | JSON | Cloak client |

## Про Outline prefix

`shadowsocks.outline.prefix` — байтовая строка, маскирующая первый пакет под
TLS ClientHello (`16 03 01 00 A8 01 01`). Ссылка всегда несёт путь `/` и маркер
`outline=1`, а сам префикс едет параметром `prefix=`.

Клиенты Outline (в том числе форки Hiddify — VPN4TV на телевизорах, sing-box
под капотом) читают значение `prefix` как UTF-8-строку, где каждая руна — один
байт префикса. Поэтому байт `0xA8` обязан уехать как UTF-8 `%C2%A8`: это делает
стандартный `url.Values.Encode()` в `internal/link`. Итоговый вид ссылки —
`ss://…/?outline=1&prefix=%16%03%01%00%C2%A8%01%01#…`.

## Безопасность

Ссылка содержит приватные ключи и пароли. Вывод утилиты — секрет: не коммитьте
`url.txt` и сгенерированные конфиги.

## Разработка

```bash
go test ./... -cover
golangci-lint run ./...
```

CI гоняет линтер и тесты на каждый push и PR. Релиз по тегу сначала проходит
тот же гейт и публикуется только после него.

## Лицензия

[MIT](LICENSE)
