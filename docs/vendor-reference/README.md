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

Наш код ни один из этих файлов не включает и не линкует:

* BLAKE2s реализован заново (`core/.../crypto/Blake2s.kt`) и сверен с `hashlib` из CPython;
* X25519 и ChaCha20-Poly1305 берутся из BouncyCastle (`bcprov-jdk18on`, MIT-подобная лицензия) и
  сверены с RFC 7748 §6.1 / OpenSSL и Appendix A.1 `draft-irtf-cfrg-xchacha`;
* AES-GCM/AES-ECB и HMAC-SHA256 — из стандартного JCA (`javax.crypto`).

Полный список сторонних материалов и их лицензий — в `THIRD_PARTY_NOTICES.md` в корне репозитория.

Обновить копии:

```bash
base=https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/plain/drivers/net/wireguard
for f in noise.c send.c receive.c cookie.c messages.h; do
  curl -sSL -o docs/vendor-reference/${f/receive/recv} $base/$f
done
```
