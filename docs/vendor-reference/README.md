# Копии спецификаций и эталонных реализаций

Здесь лежат **только справочные материалы**, по которым писался протокольный слой
(`core/.../wg/`, `core/.../crypto/`, `core/.../junk/`). Лицензия MIT из корня репозитория
относится к коду проекта, а не к этим файлам.

| Файл | Откуда | Лицензия |
|---|---|---|
| `noise.c`, `send.c`, `recv.c`, `cookie.c`, `messages.h` | `drivers/net/wireguard/` из ядра Linux (`git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git`) | GPL-2.0, © Jason A. Donenfeld |
| `wg.html` | https://www.wireguard.com/protocol/ — описание handshake, layout'ов пакетов, cookie-цикла | CC BY-SA 4.0 (см. страницу) |
| `xch.txt` | текст `draft-irtf-cfrg-xchacha` (векторы для XChaCha20-Poly1305 и hChaCha20) | свободный документ IETF |
| `script.js`, `quic.js` | публичные страницы генератора WARP (https://warp-generation.github.io/) — шаблоны конфигов, пулы подсетей/портов, генерация QUIC-Initial | публично доступно; использовано как источник параметров, не как код проекта |

Наш код ни один из этих файлов не включает и не линкует: X25519/ChaCha20-Poly1305/BLAKE2s
реализованы заново (`core/.../crypto/`), а сверены — с CPython, OpenSSL и векторами из RFC.

Обновить копии:

```bash
base=https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/plain/drivers/net/wireguard
for f in noise.c send.c receive.c cookie.c messages.h; do
  curl -sSL -o docs/vendor-reference/${f/receive/recv} $base/$f
done
```
