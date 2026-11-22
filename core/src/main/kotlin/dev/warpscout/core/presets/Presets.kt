package dev.warpscout.core.presets

import dev.warpscout.core.model.ResourceCheck

/** Готовые наборы настроек — то, что обычно подбирают вручную в Telegram-ботах и на форуме. */
object Presets {

    /**
     * Набор DNS для конфига. [host] — имя сервиса: если задано, адреса берутся по нему (раз в
     * сутки и при выборе), а [servers] остаются запасом на случай, когда имя не разрешилось.
     * Так у «умных» DNS (они отдают адреса прокси для ChatGPT и Gemini) список не протухает:
     * их адреса меняются, а имя остаётся.
     */
    data class DnsPreset(val name: String, val servers: List<String>, val note: String, val host: String = "")

    // ВАЖНО: настройка хранит НОМЕР набора — новые добавляем только в конец, иначе у людей молча
    // сменится выбранный DNS.
    val DNS = listOf(
        DnsPreset("Cloudflare", listOf("1.1.1.1", "1.0.0.1", "2606:4700:4700::1111", "2606:4700:4700::1001"),
            "по умолчанию у генератора"),
        DnsPreset("Google", listOf("8.8.8.8", "8.8.4.4", "2001:4860:4860::8888", "2001:4860:4860::8844"), ""),
        DnsPreset("AdGuard", listOf("179.254.166.171", "164.5.224.81", "2a12:bec4:1bb0:27dd::2", "2a13:82c0:0:d::3"),
            "реклама + трекеры"),
        DnsPreset("Безмежа.У", listOf("143.20.64.55", "31.58.216.201"), "ChatGPT/Gemini, российский DoH-фолбэк",
            host = "dns.bezmezhau.com"),
        DnsPreset("GeoHide", listOf("5.175.161.3", "5.175.161.40", "37.221.93.141", "37.221.93.128",
            "45.13.237.213", "31.25.239.132", "143.20.64.192"), "ChatGPT/Gemini", host = "dns.geohide.ru"),
        DnsPreset("GeoDema", listOf("179.236.130.10", "179.236.130.11"), ""),
        // «Умные» DNS из списка NetFix: адреса только по имени — своих запасных у нас нет.
        DnsPreset("WLRus", emptyList(), "ChatGPT/Gemini · адрес по имени", host = "dns.wlrus.cfd"),
        DnsPreset("Comss", emptyList(), "ChatGPT/Gemini · адрес по имени", host = "dns.comss.one"),
        DnsPreset("Dagami", emptyList(), "ChatGPT/Gemini · адрес по имени", host = "dns.dagami.ru"),
    )

    /**
     * Домены, по которым строится split-tunnel (AllowedIPs). Резолвим их через DoH в момент генерации —
     * так список маршрутов не протухает, в отличие от «вечных» CSV с IP.
     */
    val SITE_DOMAINS: Map<String, List<String>> = linkedMapOf(
        "YouTube / Google" to listOf(
            "youtube.com", "www.youtube.com", "m.youtube.com", "youtube.googleapis.com",
            "i.ytimg.com", "s.ytimg.com", "yt3.googleusercontent.com", "googlevideo.com",
            "www.google.com", "apis.google.com", "dns.google"
        ),
        "Telegram" to listOf(
            "t.me", "telegram.org", "web.telegram.org", "api.telegram.org",
            "cdn5.telegram.org", "cdn1.telegram.org", "updates.telegram.org"
        ),
        "WhatsApp" to listOf(
            "web.whatsapp.com", "mmg.whatsapp.net", "g.whatsapp.net", "wa.me", "whatsapp.com"
        ),
        "Discord" to listOf(
            "discord.com", "discordapp.com", "gateway.discord.gg", "cdn.discordapp.com",
            "media-discordapp.com", "discord.gg"
        ),
        "ChatGPT" to listOf("chatgpt.com", "api.openai.com", "auth.openai.com", "files.oaiusercontent.com"),
        "Instagram/Meta" to listOf("instagram.com", "graph.instagram.com", "static.xx.fbcdn.net", "x.com", "api.x.com")
    )

    /** Стандартный набор проверок доступности («то, ради чего всё это»). */
    val RESOURCE_CHECKS: List<ResourceCheck> = listOf(
        ResourceCheck("WARP: контроль (в РФ работает без VPN)", "https://ru.wikipedia.org/wiki/Zapad",
            baselineExpected = true),
        ResourceCheck("Google (204)", "https://www.google.com/generate_204", 200..399),
        ResourceCheck("YouTube", "https://www.youtube.com/", 200..399),
        ResourceCheck("ChatGPT", "https://chatgpt.com/cdn-cgi/trace", 200..399),
        ResourceCheck("OpenAI API", "https://api.openai.com/v1/models", 200..499),
        ResourceCheck("Telegram web", "https://web.telegram.org/a/", 200..399),
        ResourceCheck("Discord", "https://discord.com/api/guilds", 200..499),
        ResourceCheck("WhatsApp web", "https://web.whatsapp.com/", 200..399),
        ResourceCheck("X", "https://x.com/", 200..399),
        ResourceCheck("Cloudflare trace", "https://www.cloudflare.com/cdn-cgi/trace", 200..299)
    )

    /**
     * Сервисы для настройки «Что проверять» и списка «Доступность» (с 1.10.30). Каждая проверка
     * отвечает на вопрос «работает ли сервис», а не «отвечает ли что-нибудь по этому имени»:
     *  • ChatGPT — какую страну видит сайт (trace Cloudflare): на сам адрес отвечает Cloudflare перед
     *    сайтом, а ChatGPT отказывает по стране, и раньше в списке стояло «открылся», хотя не
     *    открывался;
     *  • Telegram — подключение к его серверам: приложению нужны они, а не сайт;
     *  • остальные — загрузка настоящей страницы или API.
     *
     * ВАЖНО: настройка хранит id — их не менять, новые добавлять в конец.
     */
    val SERVICE_CHECKS: List<ResourceCheck> = listOf(
        ResourceCheck("YouTube", "https://www.youtube.com/", 200..399, id = "youtube", hint = "главная страница"),
        ResourceCheck(
            "Telegram", "tcp://149.154.167.51:443|149.154.175.53:443",
            id = "telegram", hint = "подключение к серверам Telegram"
        ),
        ResourceCheck("WhatsApp", "https://web.whatsapp.com/", 200..399, id = "whatsapp", hint = "веб-версия"),
        ResourceCheck(
            "ChatGPT", "https://chatgpt.com/cdn-cgi/trace", 200..299,
            id = "chatgpt", hint = "какую страну видит сайт",
            blockedCountries = dev.warpscout.core.net.SmartDnsCheck.UNSUPPORTED
        ),
        ResourceCheck("Instagram", "https://www.instagram.com/", 200..399, id = "instagram", hint = "главная страница"),
        ResourceCheck(
            "Discord", "https://discord.com/api/v9/gateway", 200..299, mustContain = "gateway",
            id = "discord", hint = "сервер Discord"
        ),
        ResourceCheck("X (Twitter)", "https://x.com/", 200..399, id = "x", hint = "главная страница"),
        ResourceCheck("Google", "https://www.google.com/generate_204", 200..299, id = "google", hint = "служебная страница")
    )

    /** Сколько своих сайтов проверять, не больше: каждая проверка — запрос и секунды ожидания. */
    const val CUSTOM_CHECKS_MAX = 20

    /**
     * Свои сайты из настроек: по строке (или через запятую) — имя `example.com` или адрес
     * `https://example.com/путь`. Всё после `#` — комментарий. Непонятное пропускается.
     */
    fun customChecks(text: String): List<ResourceCheck> = text
        .split('\n', ',', ';')
        .map { it.substringBefore('#').trim() }
        .filter { it.isNotEmpty() && !it.contains(' ') }
        .mapNotNull { raw ->
            val withScheme = if (raw.startsWith("https://", ignoreCase = true) || raw.startsWith("http://", ignoreCase = true)) {
                raw
            } else {
                "https://" + raw.trimEnd('/') + "/"
            }
            val scheme = withScheme.substringBefore("://").lowercase()
            val rest = withScheme.substringAfter("://")
            val authority = rest.substringBefore('/').substringBefore('?').substringBefore('#')
            val tail = rest.removePrefix(authority).ifEmpty { "/" }
            val hostTyped = authority.substringBeforeLast(':').takeIf { authority.count { it == ':' } == 1 } ?: authority
            val port = if (hostTyped.length < authority.length) authority.substring(hostTyped.length) else ""
            // Русские имена (сайт.рф) — в запрос идут в виде xn--…: иначе URI их не разбирает, и
            // сайт молча пропадал из списка. В списке остаётся имя так, как его написали.
            val ascii = runCatching { java.net.IDN.toASCII(hostTyped.lowercase()) }.getOrNull() ?: return@mapNotNull null
            val url = "$scheme://$ascii$port$tail"
            val host = runCatching { java.net.URI(url).host }.getOrNull()?.takeIf { it.isNotBlank() && it.contains('.') }
                ?: return@mapNotNull null
            ResourceCheck(hostTyped.lowercase(), url, 200..399, id = "custom:$host", hint = "свой сайт")
        }
        .distinctBy { it.url }
        .take(CUSTOM_CHECKS_MAX)

    /** Проверки, которые имеют смысл только внутри туннеля (через них и «видно», что WARP работает). */
    val TUNNEL_ONLY_CHECKS: List<ResourceCheck> = listOf(
        ResourceCheck("Кто я для Cloudflare", "https://cloudflare.com/cdn-cgi/trace", 200..299, mustContain = "warp=on"),
        ResourceCheck("IP-гео через туннель", "https://ipinfo.io/json", 200..299)
    )

    val KEEPALIVE_OPTIONS = listOf<Int?>(null, 15, 20, 25, 30)
    val MTU_OPTIONS = listOf(1280, 1420, 1400, 1360, 1200)
}
