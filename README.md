# Volfram

## Возможности

- **Протоколы:** VLESS (включая Reality), VMess, Trojan, Shadowsocks, Hysteria2, TUIC, AnyTLS, WireGuard, SOCKS, а на Windows ещё и NaiveProxy.
- **Подписки** в форматах base64, Clash/Mihomo YAML и JSON от sing-box и Xray. Обновляются сами раз в 6 часов.
- **Три режима маршрутизации:**
  - *Умный* — российские сайты идут напрямую, остальное через VPN;
  - *Глобальный* — весь трафик через VPN;
  - *Только заблокированное* — через VPN идут только сайты, заблокированные в РФ.
- **Свои списки доменов:** через VPN, напрямую или заблокировать.
- **Блокировка рекламы и трекеров** через фильтр AdGuard DNS.
- **Проверка пинга** всех серверов и сортировка по задержке.
- **Windows:** системный прокси или TUN-режим, значок в трее, автозапуск. Можно раздать прокси на другие устройства в сети по логину и паролю.
- **Android:** VPN для всего устройства или только локальный прокси, выбор приложений, которые идут через VPN.
- **Защита от утечек:** при переподключении трафик не уходит в обход VPN, IPv6 тоже идёт через туннель.

## Установка

Готовые `.exe` и `.apk` лежат в Releases.

- На Windows нужен WebView2. Обычно он уже установлен, а если нет — программа подскажет, где его скачать.
- Exe не подписан сертификатом, поэтому SmartScreen может предупредить при запуске: «Подробнее» → «Выполнить в любом случае».
- Для TUN-режима нужны права администратора. Volfram сам предложит перезапуститься с ними.

## Сборка

Нужны Go 1.27+, bash, curl, unzip, tar и zstd (Linux, macOS или WSL).

```sh
./scripts/fetch-cores.sh
./scripts/build-windows.sh
```

`fetch-cores.sh` скачивает sing-box 1.14.4, Xray-core 26.10.31, tun2socks 2.7.0 и наборы правил, проверяет SHA-256 бинарников и конвертирует фильтр AdGuard DNS в `rules/adguard-dns.srs`. Результат сборки — `dist/Volfram.exe`.

### Android

Нужны Android SDK (build-tools и platforms/android-35) и JDK 17+.

```sh
export ANDROID_HOME=$HOME/Android/Sdk
export KEYSTORE=$HOME/volfram.jks
export KEYSTORE_PASS=...
./android/build.sh
```

Если ключа по пути `KEYSTORE` нет, скрипт создаст новый. Результат — `dist/Volfram.apk`. Ключ лучше хранить отдельно и не добавлять в репозиторий: без него обновления не установятся поверх старой версии.

## Тесты

```sh
go test .
```

Полная проверка конфигов на настоящих ядрах:

```sh
SB=/path/to/sing-box XR=/path/to/xray RULES=$PWD/rules go test .
```

## Структура

- `*.go` — бэкенд, общий для Windows и Android (Android собирается с тегом `volframandroid`)
- `ui/` — интерфейс
- `android/` — Java-обёртка, ресурсы и скрипт сборки APK
- `res/`, `tools/mkres/` — иконки и ресурсы Windows
- `scripts/` — загрузка ядер и сборка под Windows

## Лицензии

У sing-box, Xray-core, tun2socks и наборов правил свои лицензии, подробности в их репозиториях. Фильтр AdGuard DNS распространяется под GPL-3.0, шрифты Golos Text и JetBrains Mono — под SIL Open Font License 1.1.

Нашли баг или есть идея — пишите в Issues.
