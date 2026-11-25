package dev.warpscout.core.proton

import java.io.ByteArrayOutputStream

/**
 * Обходной путь Proton (с 1.10.46) — «alternative routing» приложений Proton для стран с блокировками
 * (protoncore_android: DnsOverHttpsProviderRFC8484, Constants.ALTERNATIVE_API_SPKI_PINS).
 *
 * Зачем. Из России адреса Proton закрыты, а если выход WARP на московской площадке Cloudflare — их режут
 * и через туннель: скриншот 25.11, туннель работает, «Выход: RU», а у обоих адресов API «Unable to resolve
 * host … No address associated with hostname». Для таких сетей Proton держит посредников: TXT-запись
 * `d<base32 имени API>.protonpro.xyz` отдаёт их адреса, и те же запросы API уходят на `https://<адрес>/…`.
 * Запись спрашиваем через DNS-over-HTTPS — обычный DNS тоже режут. Сертификат посредника выписан не на его
 * адрес, поэтому имя не сверяем, а открытый ключ сертификата сверяем с закреплёнными — те же отпечатки,
 * что в приложениях Proton. На 25.11 запись для vpn-api.proton.me — CNAME vpn.protonpro.xyz и пять адресов
 * AWS во Франкфурте.
 */
object ProtonAlt {

    /** SHA-256 открытого ключа (SPKI) сертификатов посредников, base64 — ALTERNATIVE_API_SPKI_PINS Proton. */
    val PINS = listOf(
        "EU6TS9MO0L/GsDHvVc9D5fChYLNy5JdGYpJw0ccgetM=",
        "iKPIHPnDNqdkvOnTClQ8zQAIKG0XavaPkcEo0LBAABA=",
        "MSlVrBCdL0hKyczvgYVSRNm88RicyY04Q2y5qrBt0xA=",
        "C2UxW0T1Ckl9s+8cXfjXxlEqwAfPM4HiW2y3UdtBeCw=",
    )

    /**
     * DNS-over-HTTPS (RFC 8484). Первым — 1.1.1.1: через WARP он внутри Cloudflare, и записи protonpro.xyz
     * тоже обслуживает Cloudflare — ответ не выходит наружу даже с московской площадки. Дальше — те два,
     * что у Proton по умолчанию.
     */
    val DOH = listOf("https://1.1.1.1/dns-query", "https://dns.google/dns-query", "https://dns11.quad9.net/dns-query")

    const val TYPE_TXT = 16
    private const val SUFFIX = ".protonpro.xyz"
    private const val ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    private val HOST_RE = Regex("^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$")

    /** Имя записи для хоста API — как у Proton: «d» + base32 (RFC 4648, заглавные, без «=») + .protonpro.xyz. */
    fun queryName(host: String): String = "d" + base32(host.toByteArray(Charsets.UTF_8)) + SUFFIX

    /** Base32 по RFC 4648 — заглавными и без «=» в конце (так кодирует Proton). */
    fun base32(data: ByteArray): String {
        val sb = StringBuilder((data.size * 8 + 4) / 5)
        var buffer = 0
        var bits = 0
        for (b in data) {
            buffer = ((buffer shl 8) or (b.toInt() and 0xFF)) and 0xFFFF
            bits += 8
            while (bits >= 5) {
                sb.append(ALPHABET[(buffer shr (bits - 5)) and 31])
                bits -= 5
            }
        }
        if (bits > 0) sb.append(ALPHABET[(buffer shl (5 - bits)) and 31])
        return sb.toString()
    }

    /** DNS-запрос в «проводном» виде: id 0 (так советует RFC 8484), рекурсия, один вопрос класса IN. */
    fun encodeQuery(name: String, type: Int = TYPE_TXT): ByteArray {
        val out = ByteArrayOutputStream()
        out.write(byteArrayOf(0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0))
        for (label in name.trimEnd('.').split('.')) {
            val bytes = label.toByteArray(Charsets.US_ASCII)
            require(bytes.size in 1..63) { "метка DNS: «$label»" }
            out.write(bytes.size)
            out.write(bytes)
        }
        out.write(0)
        out.write(type shr 8)
        out.write(type and 0xFF)
        out.write(0)
        out.write(1)
        return out.toByteArray()
    }

    /** Запрос для GET …/dns-query?dns=… (base64url без «=»). */
    fun base64Url(data: ByteArray): String = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(data)

    /** Строки всех TXT-записей ответа (CNAME по дороге пропускаем). Ошибка DNS или мусор — пустой список. */
    fun txtRecords(msg: ByteArray): List<String> = runCatching { parseTxt(msg) }.getOrDefault(emptyList())

    /** Адрес посредника из строки TXT: IPv4 или имя хоста; всё прочее отбрасываем. */
    fun hostOf(txt: String): String? = txt.trim().trimEnd('.').takeIf { it.length <= 253 && HOST_RE.matches(it) }

    private fun parseTxt(m: ByteArray): List<String> {
        fun u8(i: Int): Int = m[i].toInt() and 0xFF
        fun u16(i: Int): Int = (u8(i) shl 8) or u8(i + 1)
        fun skipName(start: Int): Int {
            var i = start
            while (true) {
                val len = u8(i)
                when {
                    len == 0 -> return i + 1
                    (len and 0xC0) == 0xC0 -> return i + 2
                    else -> i += 1 + len
                }
            }
        }
        if (m.size < 12) return emptyList()
        if ((u8(2) and 0x80) == 0) return emptyList()   // это не ответ
        if ((u8(3) and 0x0F) != 0) return emptyList()   // RCODE: NXDOMAIN, SERVFAIL…
        val questions = u16(4)
        val answers = u16(6)
        var p = 12
        repeat(questions) { p = skipName(p) + 4 }
        val out = ArrayList<String>()
        repeat(answers) {
            p = skipName(p)
            val type = u16(p)
            val rdLen = u16(p + 8)
            val rd = p + 10
            if (rd + rdLen > m.size) return out
            if (type == TYPE_TXT) {
                var i = rd
                while (i < rd + rdLen) {
                    val n = u8(i)
                    if (i + 1 + n > rd + rdLen) break
                    out += String(m, i + 1, n, Charsets.UTF_8)
                    i += 1 + n
                }
            }
            p = rd + rdLen
        }
        return out
    }
}
