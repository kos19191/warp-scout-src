package dev.warpscout.core.telegram

import java.net.URLDecoder
import java.net.URLEncoder
import java.util.Base64

/**
 * Прокси MTProto для Telegram (с 1.10.49-beta4): ссылки tg://proxy и https://t.me/proxy из
 * публичных списков, секреты трёх видов и отбор разных кандидатов для проверки ([MtProxyChecker]).
 *
 * Секрет: 16 байт ключа (обычный), «dd» + ключ (со случайной добивкой) или «ee» + ключ + имя сайта
 * (Fake-TLS: соединение выглядит как HTTPS к этому сайту — фильтру его труднее узнать). В ссылках
 * секрет бывает шестнадцатеричным или base64url.
 *
 * Списки — те же, что у версии для компьютера (WilyScout Desktop), плюс проверенный список
 * SoliSpirit; у каждого — копия на jsDelivr: raw.githubusercontent.com бывает закрыт.
 */
object MtProxy {

    enum class Kind(val label: String, val priority: Int) {
        FAKE_TLS("Fake-TLS", 3),
        PADDED("dd", 2),
        CLASSIC("обычный", 1)
    }

    /** Разобранный секрет: вид, 16 байт ключа и имя сайта (у Fake-TLS). */
    class Secret(val kind: Kind, val key: ByteArray, val domain: String)

    /** Прокси из списка. [secret] — как в ссылке (её же и откроем в Telegram). */
    data class Entry(
        val server: String,
        val port: Int,
        val secret: String,
        val kind: Kind,
        val domain: String = "",
        val source: String = ""
    ) {
        val id: String get() = "${server.lowercase()}:$port"

        val tgLink: String get() = "tg://proxy?server=${enc(server)}&port=$port&secret=${enc(secret)}"

        val tmeLink: String get() = "https://t.me/proxy?server=${enc(server)}&port=$port&secret=${enc(secret)}"

        /** «Fake-TLS (google.com)». */
        val badge: String get() = if (domain.isNotBlank()) "${kind.label} ($domain)" else kind.label

        fun parsedSecret(): Secret? = parseSecret(secret)
    }

    class Feed(val name: String, val urls: List<String>)

    /** Обновляемые списки (раз в 15–60 минут): сначала raw.githubusercontent.com — свежее, потом копия jsDelivr. */
    val FEEDS: List<Feed> = listOf(
        Feed(
            "tgmtproxy",
            listOf(
                "https://raw.githubusercontent.com/tgmtproxy/telegram-mtproto-proxy-list/main/proxies.txt",
                "https://cdn.jsdelivr.net/gh/tgmtproxy/telegram-mtproto-proxy-list@main/proxies.txt"
            )
        ),
        Feed(
            "Free-Telegram-Proxy (Fake-TLS)",
            listOf(
                "https://raw.githubusercontent.com/aMyNaR/Free-Telegram-Proxy/main/faketls/tg.txt",
                "https://cdn.jsdelivr.net/gh/aMyNaR/Free-Telegram-Proxy@main/faketls/tg.txt"
            )
        ),
        Feed(
            "SoliSpirit (проверенные)",
            listOf(
                "https://raw.githubusercontent.com/SoliSpirit/mtproto/master/verified.txt",
                "https://cdn.jsdelivr.net/gh/SoliSpirit/mtproto@master/verified.txt"
            )
        )
    )

    private fun enc(s: String): String = URLEncoder.encode(s, "UTF-8")

    private val LINK = Regex("""(?:tg://proxy\?|https?://(?:www\.)?t\.me/proxy\?)([^\s"'<>]+)""", RegexOption.IGNORE_CASE)
    private val HEX = Regex("^[0-9a-fA-F]+$")
    private val B64 = Regex("^[A-Za-z0-9_\\-+/=]+$")
    private val HOST = Regex("^[A-Za-z0-9.-]{1,253}$")

    /** Ссылки прокси из текста списка; повторы (тот же адрес и порт) — один раз. */
    fun parse(text: String, source: String = ""): List<Entry> {
        val out = ArrayList<Entry>()
        val seen = HashSet<String>()
        for (m in LINK.findAll(text)) {
            val q = m.groupValues[1].trimEnd('.', ',', ';', ')', ']')
            val params = HashMap<String, String>()
            for (pair in q.split('&')) {
                val eq = pair.indexOf('=')
                if (eq <= 0) continue
                val k = pair.substring(0, eq).lowercase()
                val v = runCatching { URLDecoder.decode(pair.substring(eq + 1), "UTF-8") }.getOrDefault(pair.substring(eq + 1))
                params[k] = v.trim()
            }
            val server = params["server"].orEmpty().trimEnd('.')
            val port = params["port"]?.toIntOrNull() ?: continue
            val secret = params["secret"].orEmpty()
            if (server.isEmpty() || !HOST.matches(server) || port !in 1..65535) continue
            val parsed = parseSecret(secret) ?: continue
            val e = Entry(server, port, secret, parsed.kind, parsed.domain, source)
            if (seen.add(e.id)) out += e
        }
        return out
    }

    /** Секрет из ссылки: hex («ee…», «dd…», 32 знака) или base64url; null — не секрет MTProto. */
    fun parseSecret(s: String): Secret? {
        val t = s.trim()
        if (t.length < 22) return null
        val bytes: ByteArray = when {
            HEX.matches(t) && t.length % 2 == 0 -> ByteArray(t.length / 2) { i -> t.substring(i * 2, i * 2 + 2).toInt(16).toByte() }
            B64.matches(t) -> runCatching {
                Base64.getUrlDecoder().decode(t.replace('+', '-').replace('/', '_').trimEnd('='))
            }.getOrNull() ?: return null
            else -> return null
        }
        return when {
            bytes.size == 16 -> Secret(Kind.CLASSIC, bytes, "")
            bytes.size == 17 && (bytes[0].toInt() and 0xFF) == 0xdd -> Secret(Kind.PADDED, bytes.copyOfRange(1, 17), "")
            bytes.size > 17 && (bytes[0].toInt() and 0xFF) == 0xee -> {
                val domain = String(bytes, 17, bytes.size - 17, Charsets.ISO_8859_1)
                if (domain.isEmpty() || domain.length > 253 || !domain.all { it.code in 0x21..0x7e }) return null
                Secret(Kind.FAKE_TLS, bytes.copyOfRange(1, 17), domain)
            }
            else -> null
        }
    }

    /**
     * Кандидаты для проверки: Fake-TLS вперёд, порт 443 (и 8443) — выше, не больше двух с одной
     * подсети /24 или одного домена второго уровня: проверять клонов одного сервера незачем.
     */
    fun candidates(all: List<Entry>, limit: Int = 60): List<Entry> {
        val sorted = all.sortedWith(
            compareByDescending<Entry> { it.kind.priority }.thenByDescending { it.port == 443 || it.port == 8443 }
        )
        val out = ArrayList<Entry>()
        val groups = HashMap<String, Int>()
        val seen = HashSet<String>()
        for (e in sorted) {
            if (!seen.add(e.id)) continue
            val g = group(e.server)
            val used = groups[g] ?: 0
            if (used >= 2) continue
            groups[g] = used + 1
            out += e
            if (out.size >= limit) break
        }
        return out
    }

    private fun group(host: String): String {
        val parts = host.lowercase().split('.')
        if (parts.size == 4 && parts.all { p -> p.toIntOrNull()?.let { it in 0..255 } == true }) return parts.take(3).joinToString(".")
        return if (parts.size >= 2) parts.takeLast(2).joinToString(".") else host.lowercase()
    }
}
