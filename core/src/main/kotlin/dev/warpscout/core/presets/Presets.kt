package dev.warpscout.core.presets

import dev.warpscout.core.model.ResourceCheck

/** Готовые наборы настроек — то, что обычно подбирают вручную в Telegram-ботах и на форуме. */
object Presets {

    data class DnsPreset(val name: String, val servers: List<String>, val note: String)

    val DNS = listOf(
        DnsPreset("Cloudflare", listOf("1.1.1.1", "1.0.0.1", "2606:4700:4700::1111", "2606:4700:4700::1001"),
            "по умолчанию у генератора"),
        DnsPreset("Google", listOf("8.8.8.8", "8.8.4.4", "2001:4860:4860::8888", "2001:4860:4860::8844"), ""),
        DnsPreset("AdGuard", listOf("179.254.166.171", "164.5.224.81", "2a12:bec4:1bb0:27dd::2", "2a13:82c0:0:d::3"),
            "реклама + трекеры"),
        DnsPreset("Безмежа.У", listOf("143.20.64.55", "31.58.216.201"), "российский DoH-фолбэк"),
        DnsPreset("GeoHide", listOf("5.175.161.3", "5.175.161.40", "37.221.93.141", "37.221.93.128",
            "45.13.237.213", "31.25.239.132", "143.20.64.192"), ""),
        DnsPreset("GeoDema", listOf("179.236.130.10", "179.236.130.11"), "")
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
        ResourceCheck("WARP: контроль (в РФ работает без VPN)", "https://ya.ru/generate_204",
            200..399, baselineExpected = true),
        ResourceCheck("Google (204)", "https://www.google.com/generate_204", 200..399),
        ResourceCheck("YouTube", "https://www.youtube.com/", 200..399),
        ResourceCheck("ChatGPT", "https://chatgpt.com/cdn-cgi/trace", 200..399),
        ResourceCheck("OpenAI API", "https://api.openai.com/v1/models", 200..499),
        ResourceCheck("Telegram web", "https://web.telegram.org/a/", 200..399),
        ResourceCheck("Telegram DC2", "https://venus.web.telegram.org/apiw1", 200..499),
        ResourceCheck("Discord", "https://discord.com/api/guilds", 200..499),
        ResourceCheck("WhatsApp", "https://www.whatsapp.com/", 200..399),
        ResourceCheck("X", "https://x.com/", 200..399),
        ResourceCheck("Cloudflare trace", "https://www.cloudflare.com/cdn-cgi/trace", 200..299)
    )

    /** Проверки, которые имеют смысл только внутри туннеля (через них и «видно», что WARP работает). */
    val TUNNEL_ONLY_CHECKS: List<ResourceCheck> = listOf(
        ResourceCheck("Кто я для Cloudflare", "https://cloudflare.com/cdn-cgi/trace", 200..299, mustContain = "warp=on"),
        ResourceCheck("IP-гео через туннель", "https://ipinfo.io/json", 200..299)
    )

    val KEEPALIVE_OPTIONS = listOf<Int?>(null, 15, 20, 25, 30)
    val MTU_OPTIONS = listOf(1280, 1420, 1400, 1360, 1200)
}
