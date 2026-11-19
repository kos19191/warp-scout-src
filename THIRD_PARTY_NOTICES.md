# Сторонние материалы и лицензии

Код проекта распространяется по MIT (см. `LICENSE`). Ниже — всё, что лежит в репозитории или
подключается как зависимость и **не** покрывается MIT.

## 1. Справочные копии в `docs/vendor-reference/`

Эти файлы не компилируются, не линкуются и не входят в APK — это первоисточники, по которым
сверялся протокольный слой. Подробности и команды обновления — в
`docs/vendor-reference/README.md`.

| Файлы | Источник | Лицензия |
|---|---|---|
| `noise.c`, `send.c`, `recv.c`, `cookie.c`, `messages.h` | `drivers/net/wireguard/`, ядро Linux (torvalds/linux) | GPL-2.0, © Jason A. Donenfeld |
| `wg.html` | https://www.wireguard.com/protocol/ | CC BY-SA 4.0 |
| `xch.txt` | `draft-irtf-cfrg-xchacha` (IETF) | свободный документ IETF |
| `script.js`, `quic.js` | публичная страница генератора WARP (warp-generation.github.io) | публично доступно; взяты только параметры (пулы подсетей/портов, шаблоны конфигов) |

GPL-2.0 распространяется **только** на перечисленные файлы ядра и не «заражает» MIT-код проекта:
он не линкуется с ними и не является производной работой (использование как справочной
документации). Если вы переиспользуете этот репозиторий целиком, учитывайте смешанный состав.

## 2. Списки доменов и подсетей в `core/src/main/resources/rules/`

Снапшот собран из [haritos90/allow-domains](https://github.com/haritos90/allow-domains) —
форка [itdoginfo/allow-domains](https://github.com/itdoginfo/allow-domains) — на коммит
`eee7d6c` (19.11.2026). Лицензия форка — **MIT** (файл `LICENSE` апстрима). Сами списки — это
факты о доменах и адресах («этот домен принадлежит Discord»), они не являются объектом
авторского права, но ссылка и лицензия указаны, потому что мы копируем чужую подборку целиком.

Что именно скопировано и как обновляется — в `core/src/main/resources/rules/README.md`.
Скрипт `tools/gen_rules.py` пересобирает снапшот из тарбола апстрима одной командой и
записывает дату/коммит в `RuleCatalog.SNAPSHOT_DATE` / `SNAPSHOT_COMMIT`, чтобы в отчёте было
видно, насколько данные свежие.

## 3. Зависимости сборки

| Компонент | Где объявлена | Лицензия |
|---|---|---|
| BouncyCastle (`bcprov-jdk18on`) | `core/build.gradle.kts` — X25519 и ChaCha20-Poly1305 | Bouncy Castle License (MIT-подобная) |
| Kotlin stdlib, Kotlin Gradle plugin | `build.gradle.kts` | Apache-2.0 |
| Android Gradle Plugin, AndroidX (core-ktx, appcompat, constraintlayout, work-runtime), Material Components | `app/build.gradle.kts` | Apache-2.0 |

BLAKE2s реализован в проекте самостоятельно (`core/.../crypto/Blake2s.kt`); AES-GCM/AES-ECB и
HMAC-SHA256 берутся из стандартного JCA (`javax.crypto`), то есть из платформы Android/JDK.

## 4. Внешние проекты, на которые ссылается документация

`docs/vendor-reference/byedpi-android.md` описывает, как приложение стыкуется с
[ByeDPI](https://github.com/hufrea/byedpi) и [ByeDPIAndroid](https://github.com/dovecoteescapee/ByeDPIAndroid)
через локальный SOCKS5 (`127.0.0.1:1080`). **Ни их код, ни их бинарники в репозиторий не входят и в
APK не упаковываются** — это отдельное приложение, с которым WarpScout общается по сети. Лицензии и
условия использования — на страницах этих проектов.

## 5. Товарные знаки

Cloudflare, WARP, WireGuard, AmneziaVPN упомянуты как названия сервисов и протоколов. Проект
не аффилирован ни с Cloudflare, ни с командой WireGuard, ни с AmneziaVPN.
