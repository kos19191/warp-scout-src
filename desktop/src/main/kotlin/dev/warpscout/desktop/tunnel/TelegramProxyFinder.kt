package dev.warpscout.desktop.tunnel

import java.net.HttpURLConnection
import java.net.InetSocketAddress
import java.net.Socket
import java.net.URI
import java.net.URLDecoder
import java.net.URLEncoder
import java.util.concurrent.Callable
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

enum class MtProtoSecretKind(val label: String, val priority: Int) {
    FAKE_TLS("Fake-TLS", 3),
    RANDOM_PADDING("Random-Padding", 2),
    CLASSIC("Classic", 1)
}

data class TelegramProxyEntry(
    val server: String,
    val port: Int,
    val secret: String,
    val kind: MtProtoSecretKind,
    val maskDomain: String = "",
    val latencyMs: Long = -1L,
    val source: String = ""
) {
    val tgLink: String
        get() = "tg://proxy?server=${enc(server)}&port=$port&secret=${enc(secret)}"

    val tmeLink: String
        get() = "https://t.me/proxy?server=${enc(server)}&port=$port&secret=${enc(secret)}"

    val badge: String
        get() = if (maskDomain.isNotBlank()) "${kind.label} ($maskDomain)" else kind.label

    companion object {
        private fun enc(s: String): String = URLEncoder.encode(s, Charsets.UTF_8)

        fun socksTgLink(host: String = "127.0.0.1", port: Int = 1080): String =
            "tg://socks?server=${enc(host)}&port=$port"
    }
}

data class TelegramProxyScanResult(
    val proxies: List<TelegramProxyEntry>,
    val totalFetched: Int,
    val totalTested: Int,
    val sourcesUsed: List<String>,
    val error: String? = null
)

/**
 * Автоподбор и проверка живых бесплатных MTProto-прокси для Telegram.
 *
 * Загружает обновляемые каждые 15–60 минут публичные каталоги (с резервными зеркалами jsDelivr,
 * работающими даже при блокировке raw.githubusercontent.com), приоритезирует Fake-TLS (`ee...`)
 * прокси с маскировкой под реальные HTTPS-домены и измеряет реальную доступность/задержку
 * прямо с ПК пользователя.
 */
object TelegramProxyFinder {
    private const val USER_AGENT = "WilyScout-Desktop"

    data class FeedSource(val name: String, val urls: List<String>)

    val DEFAULT_FEEDS: List<FeedSource> = listOf(
        FeedSource(
            name = "Free-Telegram-Proxy (Fake-TLS)",
            urls = listOf(
                "https://cdn.jsdelivr.net/gh/aMyNaR/Free-Telegram-Proxy@main/faketls/tg.txt",
                "https://raw.githubusercontent.com/aMyNaR/Free-Telegram-Proxy/main/faketls/tg.txt"
            )
        ),
        FeedSource(
            name = "Free-Telegram-Proxy (Stable)",
            urls = listOf(
                "https://cdn.jsdelivr.net/gh/aMyNaR/Free-Telegram-Proxy@main/stable/tg.txt",
                "https://raw.githubusercontent.com/aMyNaR/Free-Telegram-Proxy/main/stable/tg.txt"
            )
        ),
        FeedSource(
            name = "tgmtproxy (Hourly)",
            urls = listOf(
                "https://cdn.jsdelivr.net/gh/tgmtproxy/telegram-mtproto-proxy-list@main/proxies.txt",
                "https://raw.githubusercontent.com/tgmtproxy/telegram-mtproto-proxy-list/main/proxies.txt"
            )
        )
    )

    /** Парсит ссылки `tg://proxy?...` и `https://t.me/proxy?...` из текстового фида. */
    fun parseFeedText(text: String, source: String = ""): List<TelegramProxyEntry> {
        val out = ArrayList<TelegramProxyEntry>()
        val seen = HashSet<String>()
        val rx = Regex("""(?:tg://proxy\?|https?://t\.me/proxy\?)([^\s"'<>]+)""", RegexOption.IGNORE_CASE)
        for (m in rx.findAll(text)) {
            val query = m.groupValues[1].trimEnd('.', ',', ';', ')')
            val params = parseQuery(query)
            val server = params["server"]?.trim()?.trimEnd('.').orEmpty()
            val port = params["port"]?.trim()?.toIntOrNull() ?: continue
            val secret = params["secret"]?.trim().orEmpty()
            if (server.isBlank() || port !in 1..65535 || secret.length < 32) continue
            if (!isValidSecret(secret)) continue
            val key = "${server.lowercase()}:$port"
            if (!seen.add(key)) continue
            val (kind, mask) = classifySecret(secret)
            out.add(
                TelegramProxyEntry(
                    server = server,
                    port = port,
                    secret = secret,
                    kind = kind,
                    maskDomain = mask,
                    source = source
                )
            )
        }
        return out
    }

    /**
     * Определяет тип секрета MTProto:
     *  • `ee` + 32 hex + hex-имя домена (Fake-TLS — маскировка под HTTPS/SNI);
     *  • `dd` + 32 hex (Random Padding);
     *  • 32 hex (Classic).
     */
    fun classifySecret(secret: String): Pair<MtProtoSecretKind, String> {
        val lower = secret.lowercase()
        if (lower.startsWith("ee") && lower.length > 34 && lower.length % 2 == 0) {
            val domainHex = lower.substring(34)
            val domain = decodeAsciiHex(domainHex)
            return MtProtoSecretKind.FAKE_TLS to domain
        }
        if (lower.startsWith("dd") && lower.length == 34) {
            return MtProtoSecretKind.RANDOM_PADDING to ""
        }
        return MtProtoSecretKind.CLASSIC to ""
    }

    /**
     * Отбирает разнообразных кандидатов для проверки: приоритет Fake-TLS, не больше 2 прокси
     * с одинаковым доменом верхнего уровня / /24-подсетью, чтобы не тратить тесты на клоны одного сервера.
     */
    fun pickDiverseCandidates(raw: List<TelegramProxyEntry>, limit: Int = 60): List<TelegramProxyEntry> {
        val sorted = raw.sortedWith(
            compareByDescending<TelegramProxyEntry> { it.kind.priority }
                .thenByDescending { it.port == 443 || it.port == 8443 }
        )
        val out = ArrayList<TelegramProxyEntry>(minOf(limit, sorted.size))
        val groupCounts = HashMap<String, Int>()
        val seenKeys = HashSet<String>()
        for (p in sorted) {
            val key = "${p.server.lowercase()}:${p.port}"
            if (!seenKeys.add(key)) continue
            val group = hostGroup(p.server)
            val used = groupCounts[group] ?: 0
            if (used >= 2) continue
            groupCounts[group] = used + 1
            out.add(p)
            if (out.size >= limit) break
        }
        return out
    }

    /** Загружает фиды, проверяет TCP-доступность и задержку с ПК пользователя и возвращает Топ-[topN]. */
    fun findBestProxies(
        feeds: List<FeedSource> = DEFAULT_FEEDS,
        maxCandidates: Int = 60,
        topN: Int = 8,
        connectTimeoutMs: Int = 1800,
        fetcher: (String) -> String? = ::httpGetText,
        prober: (TelegramProxyEntry, Int) -> Long = ::probeTcpLatencyMs,
        onProgress: (String) -> Unit = {}
    ): TelegramProxyScanResult {
        val all = ArrayList<TelegramProxyEntry>()
        val usedSources = ArrayList<String>()

        for (feed in feeds) {
            onProgress("Загружаю список ${feed.name}…")
            var body: String? = null
            for (u in feed.urls) {
                body = fetcher(u)
                if (!body.isNullOrBlank()) break
            }
            if (!body.isNullOrBlank()) {
                val parsed = parseFeedText(body, source = feed.name)
                if (parsed.isNotEmpty()) {
                    all.addAll(parsed)
                    usedSources.add(feed.name)
                }
            }
        }

        if (all.isEmpty()) {
            return TelegramProxyScanResult(
                proxies = emptyList(),
                totalFetched = 0,
                totalTested = 0,
                sourcesUsed = emptyList(),
                error = "Не удалось загрузить списки MTProto-прокси (проверьте интернет или включите туннель)"
            )
        }

        val candidates = pickDiverseCandidates(all, limit = maxCandidates)
        onProgress("Проверяю доступность ${candidates.size} MTProto-прокси (из ${all.size})…")

        val pool = Executors.newFixedThreadPool(minOf(24, candidates.size.coerceAtLeast(1))) { r ->
            Thread(r, "wilyscout-tgproxy-probe").apply { isDaemon = true }
        }
        val alive = try {
            val futures = candidates.map { entry ->
                pool.submit(Callable {
                    val rtt = prober(entry, connectTimeoutMs)
                    if (rtt >= 0L) entry.copy(latencyMs = rtt) else null
                })
            }
            futures.mapNotNull { runCatching { it.get(connectTimeoutMs + 2500L, TimeUnit.MILLISECONDS) }.getOrNull() }
        } finally {
            pool.shutdownNow()
        }

        val ranked = alive
            .sortedWith(
                compareByDescending<TelegramProxyEntry> { it.kind.priority }
                    .thenBy { it.latencyMs }
            )
            .take(topN)

        return TelegramProxyScanResult(
            proxies = ranked,
            totalFetched = all.size,
            totalTested = candidates.size,
            sourcesUsed = usedSources,
            error = if (ranked.isEmpty()) "Ни один из ${candidates.size} проверенных прокси не ответил" else null
        )
    }

    internal fun probeTcpLatencyMs(entry: TelegramProxyEntry, timeoutMs: Int): Long {
        val t0 = System.nanoTime()
        return runCatching {
            Socket().use { s ->
                s.connect(InetSocketAddress(entry.server, entry.port), timeoutMs)
                ((System.nanoTime() - t0) / 1_000_000L).coerceAtLeast(1L)
            }
        }.getOrDefault(-1L)
    }

    private fun hostGroup(host: String): String {
        val lower = host.lowercase()
        val parts = lower.split('.')
        if (parts.size == 4 && parts.all { it.toIntOrNull() in 0..255 }) {
            return "${parts[0]}.${parts[1]}.${parts[2]}"
        }
        return if (parts.size >= 2) "${parts[parts.size - 2]}.${parts[parts.size - 1]}" else lower
    }

    private fun isValidSecret(secret: String): Boolean {
        val clean = secret.trim()
        // Поддерживаем hex-секреты (32 / 34 / ee+hex) и base64url-секреты Fake-TLS.
        if (clean.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' }) {
            return clean.length >= 32 && clean.length % 2 == 0
        }
        return clean.length >= 22 && clean.all { it.isLetterOrDigit() || it == '-' || it == '_' || it == '=' }
    }

    private fun decodeAsciiHex(hex: String): String {
        if (hex.length < 4 || hex.length % 2 != 0) return ""
        val sb = StringBuilder(hex.length / 2)
        var i = 0
        while (i + 1 < hex.length) {
            val code = hex.substring(i, i + 2).toIntOrNull(16) ?: return ""
            if (code !in 0x20..0x7E) return ""
            sb.append(code.toChar())
            i += 2
        }
        val res = sb.toString().trim()
        return if ('.' in res && res.length <= 64) res else ""
    }

    private fun parseQuery(query: String): Map<String, String> {
        val out = HashMap<String, String>()
        for (pair in query.split('&')) {
            val eq = pair.indexOf('=')
            if (eq <= 0) continue
            val k = pair.substring(0, eq).lowercase()
            val v = runCatching { URLDecoder.decode(pair.substring(eq + 1), Charsets.UTF_8) }
                .getOrDefault(pair.substring(eq + 1))
            out[k] = v
        }
        return out
    }

    private fun httpGetText(url: String): String? = runCatching {
        val conn = (URI(url).toURL().openConnection() as HttpURLConnection).apply {
            connectTimeout = 6000
            readTimeout = 8000
            instanceFollowRedirects = true
            setRequestProperty("User-Agent", USER_AGENT)
        }
        try {
            if (conn.responseCode !in 200..299) return@runCatching null
            conn.inputStream.bufferedReader(Charsets.UTF_8).use { it.readText() }
        } finally {
            conn.disconnect()
        }
    }.getOrNull()
}
