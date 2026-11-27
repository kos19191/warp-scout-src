package dev.warpscout.desktop.tunnel

import dev.warpscout.core.config.WgConf
import dev.warpscout.core.model.WarpConfig
import dev.warpscout.core.net.DohClient
import dev.warpscout.core.net.HttpClient
import java.io.InputStream
import java.io.OutputStream
import java.net.InetAddress
import java.util.concurrent.Callable
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

data class ProtonConfInfo(
    val config: WarpConfig,
    val isProton: Boolean,
    val serverLabel: String,
    val endpoint: String,
    val clientIpv4: String
)

enum class SecondExitPreset(
    val id: String,
    val title: String,
    val domains: String,
    val builtInCidrs: String = ""
) {
    ALL_FOREIGN(
        id = "all_foreign",
        title = "Весь зарубежный трафик",
        domains = "",
        // 0.0.0.0/0 внутри ExitRouter (с автоматическим вырезанием IP сервера ProtonVPN) направляет
        // весь зарубежный трафик из Wintun в ProtonVPN (при «Обходе РФ» российские сайты остаются напрямую!).
        builtInCidrs = "0.0.0.0/0"
    ),
    TELEGRAM(
        id = "telegram",
        title = "Telegram",
        domains = "telegram.org, web.telegram.org, t.me, core.telegram.org",
        // Официальные IPv4-подсети датацентров Telegram (https://core.telegram.org/resources/cidr.txt)
        // — работают мгновенно даже без DoH-резолвинга!
        builtInCidrs = listOf(
            "91.108.4.0/22",
            "91.108.8.0/22",
            "91.108.12.0/22",
            "91.108.16.0/22",
            "91.108.20.0/22",
            "91.108.56.0/22",
            "91.105.192.0/23",
            "95.161.64.0/20",
            "149.154.160.0/20",
            "185.76.151.0/24"
        ).joinToString(", ")
    ),
    AI(
        id = "ai",
        title = "ChatGPT / AI",
        domains = "chatgpt.com, chat.openai.com, openai.com, api.openai.com, auth.openai.com, auth0.openai.com, ab.chatgpt.com, ws.chatgpt.com, cdn.oaistatic.com, oaiusercontent.com, claude.ai, anthropic.com, gemini.google.com, aistudio.google.com"
    ),
    SOCIAL_MEDIA(
        id = "social",
        title = "YouTube / Discord / X",
        domains = "youtube.com, googlevideo.com, ytimg.com, discord.com, discord.gg, gateway.discord.gg, x.com, instagram.com"
    )
}

/**
 * Одна категория списков для кнопок выбора «Что отправлять через второй выход»
 * (1-в-1 с мобильным WilyScout: можно комбинировать любые категории одновременно).
 */
data class SecondExitCategory(
    val id: String,
    val title: String,
    val allowListId: String? = null,
    val builtInPrefixes: List<String> = emptyList(),
    val extraHosts: List<String> = emptyList(),
    val note: String = ""
)

data class ParsedCustomSites(
    val hosts: List<String>,
    val prefixes: List<String>
)

/**
 * Справочник списков и подсетей для WARP и Второго выхода (синхронизировано с мобильным WilyScout):
 *  • критичные поддомены ИИ-сервисов (`auth.openai.com`, `cdn.oaistatic.com`, `grok.com`, `x.ai`, `api.anthropic.com`…);
 *  • официальные IPv4-подсети Telegram (10 CIDR) и Google/YouTube AS15169 (`googlevideo.com`, 13 CIDR);
 *  • официальные IPv4-сети GitHub (чтобы обновления WilyScout и списки всегда были доступны);
 *  • умный парсер пользовательских сайтов (понимает `https://chatgpt.com/c/123`, `*.example.com`, CIDR и кириллицу).
 */
object SecondExitCatalog {
    const val ALL_FOREIGN_ID = "all-foreign"
    const val CHECK_HOST = "chatgpt.com"
    const val MAX_CIDRS = 3000

    /** Официальные IPv4-подсети датацентров Telegram (https://core.telegram.org/resources/cidr.txt). */
    val TELEGRAM_NETS_V4: List<String> = listOf(
        "91.108.4.0/22",
        "91.108.8.0/22",
        "91.108.12.0/22",
        "91.108.16.0/22",
        "91.108.20.0/22",
        "91.108.56.0/22",
        "91.105.192.0/23",
        "95.161.64.0/20",
        "149.154.160.0/20",
        "185.76.151.0/24"
    )

    /** Сети Google AS15169, с которых отдаётся видео YouTube (`rr3---sn-*.googlevideo.com`, 95% адресов). */
    val YOUTUBE_VIDEO_NETS_V4: List<String> = listOf(
        "64.233.160.0/19",
        "66.102.0.0/20",
        "72.14.192.0/18",
        "74.125.0.0/16",
        "108.177.0.0/17",
        "142.250.0.0/15",
        "172.217.0.0/16",
        "172.253.0.0/16",
        "173.194.0.0/16",
        "192.178.0.0/15",
        "209.85.128.0/17",
        "216.58.192.0/19",
        "216.239.32.0/19"
    )

    /** Сети GitHub (обновления WilyScout и списки allow-domains). */
    val GITHUB_NETS_V4: List<String> = listOf(
        "140.82.112.0/20",
        "143.55.64.0/20",
        "185.199.108.0/22",
        "192.30.252.0/22"
    )

    /** Критичные поддомены, без которых вход/API/CDN сервисов уходят мимо таблицы маршрутов. */
    val EXTRA_HOSTS: Map<String, List<String>> = mapOf(
        "openai" to listOf(
            "chatgpt.com", "openai.com", "auth.openai.com", "auth0.openai.com",
            "api.openai.com", "chat.openai.com", "platform.openai.com",
            "cdn.openai.com", "cdn.oaistatic.com", "auth-cdn.oaistatic.com",
            "files.oaiusercontent.com", "oaiusercontent.com",
            "ab.chatgpt.com", "ws.chatgpt.com", "sora.chatgpt.com", "videos.openai.com"
        ),
        "claude" to listOf(
            "claude.ai", "www.claude.ai", "anthropic.com", "www.anthropic.com",
            "api.anthropic.com", "console.anthropic.com", "statsig.anthropic.com",
            "a-cdn.anthropic.com", "s-cdn.anthropic.com", "assets-proxy.anthropic.com"
        ),
        "google-ai" to listOf(
            "gemini.google.com", "aistudio.google.com", "makersuite.google.com",
            "alkalimakersuite-pa.clients6.google.com", "generativelanguage.googleapis.com"
        ),
        "ru-ip-blocked" to listOf(
            "grok.com", "www.grok.com", "assets.grok.com",
            "x.ai", "accounts.x.ai", "auth.x.ai", "api.x.ai", "imagine-public.x.ai"
        )
    )

    /** Категории-кнопки Второго выхода (в порядке отображения в UI). */
    val CATEGORIES: List<SecondExitCategory> = listOf(
        SecondExitCategory(
            id = "openai",
            title = "ChatGPT / OpenAI",
            allowListId = "openai",
            extraHosts = EXTRA_HOSTS["openai"].orEmpty()
        ),
        SecondExitCategory(
            id = "claude",
            title = "Claude / Anthropic",
            allowListId = "claude",
            extraHosts = EXTRA_HOSTS["claude"].orEmpty()
        ),
        SecondExitCategory(
            id = "google-ai",
            title = "Gemini / Google AI",
            allowListId = "google-ai",
            extraHosts = EXTRA_HOSTS["google-ai"].orEmpty()
        ),
        SecondExitCategory(
            id = "ru-ip-blocked",
            title = "Закрытые для РФ (Grok…)",
            allowListId = "ru-ip-blocked",
            extraHosts = EXTRA_HOSTS["ru-ip-blocked"].orEmpty(),
            note = "Grok, Canva, Adobe, Atlassian и другие сервисы, блокирующие РФ-адреса"
        ),
        SecondExitCategory(
            id = "telegram",
            title = "Telegram",
            allowListId = "telegram",
            builtInPrefixes = TELEGRAM_NETS_V4,
            extraHosts = listOf("telegram.org", "web.telegram.org", "t.me")
        ),
        SecondExitCategory(
            id = "youtube",
            title = "YouTube",
            allowListId = "youtube",
            builtInPrefixes = YOUTUBE_VIDEO_NETS_V4,
            extraHosts = listOf("youtube.com", "www.youtube.com", "youtu.be", "ytimg.com")
        ),
        SecondExitCategory(
            id = "discord",
            title = "Discord",
            allowListId = "discord",
            extraHosts = listOf("discord.com", "discord.gg", "gateway.discord.gg", "cdn.discordapp.com")
        ),
        SecondExitCategory(
            id = "meta",
            title = "Meta (Insta / FB)",
            allowListId = "meta",
            extraHosts = listOf("instagram.com", "www.instagram.com", "facebook.com", "www.facebook.com")
        ),
        SecondExitCategory(
            id = "twitter",
            title = "X / Twitter",
            allowListId = "twitter",
            extraHosts = listOf("x.com", "twitter.com", "api.x.com")
        ),
        SecondExitCategory(
            id = "tiktok",
            title = "TikTok",
            allowListId = "tiktok",
            extraHosts = listOf("tiktok.com", "www.tiktok.com")
        )
    )

    val byId: Map<String, SecondExitCategory> = CATEGORIES.associateBy { it.id }

    /** По умолчанию — ровно как в мобильном WilyScout: ИИ-сервисы и сайты, закрытые для РФ-адресов. */
    val DEFAULT_LIST_IDS: List<String> = listOf("openai", "claude", "google-ai", "ru-ip-blocked")

    private val HOST_RE = Regex("""^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+([a-z]{2,63}|xn--[a-z0-9-]{1,59})$""")
    private val V4_RE = Regex("""^\d{1,3}(\.\d{1,3}){3}$""")

    /** Разбирает пользовательское поле «Свои сайты» (ссылки `https://...`, домены, IP, CIDR, кириллица). */
    fun parseCustomSites(text: String): ParsedCustomSites {
        val hosts = LinkedHashSet<String>()
        val prefixes = LinkedHashSet<String>()
        for (line in text.lines()) {
            val clean = line.substringBefore('#').trim()
            if (clean.isEmpty()) continue
            for (raw in clean.split(',', ';', ' ', '\t')) {
                val token = raw.trim()
                if (token.isEmpty()) continue
                val cidr = normalizeCidr(token)
                if (cidr != null) {
                    prefixes += cidr
                    continue
                }
                val host = extractHost(token)
                if (host != null) {
                    hosts += host
                    if (!host.startsWith("www.") && host.count { it == '.' } == 1) {
                        hosts += "www.$host"
                    }
                }
            }
        }
        return ParsedCustomSites(hosts.toList(), prefixes.toList())
    }

    internal fun extractHost(token: String): String? {
        var t = token.trim()
        if ("://" in t) t = t.substringAfter("://")
        t = t.substringBefore('/').substringBefore('?').substringBefore('#')
        if ('@' in t) t = t.substringAfter('@')
        if (t.count { it == ':' } == 1) {
            val port = t.substringAfter(':')
            if (port.isNotEmpty() && port.all { it.isDigit() }) t = t.substringBefore(':')
        }
        t = t.trim().trimEnd('.').removePrefix("*.").removePrefix(".").lowercase()
        if (t.isEmpty()) return null
        if (t.any { it.code > 127 }) {
            t = runCatching { java.net.IDN.toASCII(t, java.net.IDN.ALLOW_UNASSIGNED).lowercase() }.getOrNull() ?: return null
        }
        return t.takeIf { HOST_RE.matches(it) }
    }

    internal fun normalizeCidr(token: String): String? {
        var t = token.trim()
        if (t.startsWith("[") && "]" in t) t = t.substring(1, t.indexOf(']'))
        val slash = t.indexOf('/')
        val addr = if (slash >= 0) t.substring(0, slash) else t
        val bitsText = if (slash >= 0) t.substring(slash + 1) else ""
        if (V4_RE.matches(addr)) {
            val parts = addr.split('.').map { it.toIntOrNull() ?: return null }
            if (parts.any { it !in 0..255 }) return null
            val bits = if (bitsText.isEmpty()) 32 else bitsText.toIntOrNull()?.takeIf { it in 0..32 } ?: return null
            val range = CidrMath.parseIpv4Cidr("$addr/$bits") ?: return null
            return "${CidrMath.formatIpv4(range.start)}/$bits"
        }
        if (':' in addr && addr.all { it.isDigit() || it in 'a'..'f' || it in 'A'..'F' || it == ':' || it == '.' }) {
            val bytes = runCatching { InetAddress.getByName(addr).address }.getOrNull() ?: return null
            if (bytes.size != 16) return null
            val bits = if (bitsText.isEmpty()) 128 else bitsText.toIntOrNull()?.takeIf { it in 0..128 } ?: return null
            return "$addr/$bits"
        }
        return null
    }

    /** Прямой DoH-резолв через 1.1.1.1 (по IP, без SNI cloudflare-dns.com) с фолбэком на dns.google. */
    fun resolveFastDoh(host: String, includeIpv6: Boolean = false): List<String> {
        val cfIp = DohClient("https://1.1.1.1/dns-query", HttpClient(timeoutMs = 2500))
        val out = LinkedHashSet<String>()
        val a = runCatching { cfIp.resolveA(host) }.getOrNull()
        if (a != null) out.addAll(a)
        if (includeIpv6) {
            runCatching { cfIp.resolveAAAA(host) }.getOrNull()?.let { out.addAll(it) }
        }
        if (out.isNotEmpty() || a != null) return out.toList()

        val gg = DohClient(DohClient.GOOGLE, HttpClient(timeoutMs = 2500))
        runCatching { gg.resolveA(host) }.getOrNull()?.let { out.addAll(it) }
        if (includeIpv6) {
            runCatching { gg.resolveAAAA(host) }.getOrNull()?.let { out.addAll(it) }
        }
        return out.toList()
    }

    /**
     * Мульти-источниковый резолв для критичных доменов (chatgpt.com, openai.com, claude.ai, grok.com…):
     * объединяет ответы системного DNS Windows (ровно те IP, что видит Chrome!), Cloudflare 1.1.1.1 DoH
     * и Google dns.google DoH, чтобы ни один Cloudflare Anycast IP не выпал из таблицы Второго выхода.
     */
    fun resolveMultiSource(
        host: String,
        includeIpv6: Boolean = false,
        includeSystemDns: Boolean = true
    ): List<String> {
        val out = LinkedHashSet<String>()
        if (includeSystemDns) {
            runCatching {
                InetAddress.getAllByName(host).forEach { addr ->
                    val ip = addr.hostAddress?.substringBefore('%') ?: return@forEach
                    if (includeIpv6 || ':' !in ip) out.add(ip)
                }
            }
        }
        val cfIp = DohClient("https://1.1.1.1/dns-query", HttpClient(timeoutMs = 2500))
        runCatching { cfIp.resolveA(host) }.getOrNull()?.let { out.addAll(it) }
        if (includeIpv6) runCatching { cfIp.resolveAAAA(host) }.getOrNull()?.let { out.addAll(it) }

        val gg = DohClient(DohClient.GOOGLE, HttpClient(timeoutMs = 2500))
        runCatching { gg.resolveA(host) }.getOrNull()?.let { out.addAll(it) }
        if (includeIpv6) runCatching { gg.resolveAAAA(host) }.getOrNull()?.let { out.addAll(it) }

        return out.filter { includeIpv6 || ':' !in it }
    }

    /** Параллельный резолв списка доменов без протухания очереди при большом списке. */
    fun resolveBatch(
        hosts: List<String>,
        threads: Int = 16,
        resolver: (String) -> List<String>
    ): Map<String, List<String>> {
        val unique = hosts.distinct()
        if (unique.isEmpty()) return emptyMap()
        val ex = Executors.newFixedThreadPool(minOf(threads, unique.size).coerceAtLeast(1)) { r ->
            Thread(r, "ws-second-dns").apply { isDaemon = true }
        }
        return try {
            val futures = unique.associateWith { h ->
                ex.submit(Callable { runCatching { resolver(h) }.getOrDefault(emptyList()) })
            }
            futures.mapValues { (_, f) ->
                runCatching { f.get(45, TimeUnit.SECONDS) }.getOrDefault(emptyList())
            }
        } finally {
            ex.shutdownNow()
        }
    }
}

/**
 * Помощник для простого добавления ProtonVPN (и любых других WireGuard `.conf`):
 *  • распознаёт официальные конфиги ProtonVPN (`# NL-FREE#123`, `10.2.0.2`, `NetShield`, `Bouncing`);
 *  • даёт готовые пресеты маршрутов для Второго выхода (включая «Весь зарубежный трафик» и Telegram CIDR);
 *  • реализует 1:1 IPv4 NAT, TCP MSS clamping (RFC 1624) и ICMPv4 Fragmentation Needed (PMTU)
 *    для стабильной работы ProtonVPN как напрямую, так и в режиме Double-Hop поверх WARP.
 */
object ProtonVpnHelper {
    const val PROTON_WG_DOWNLOADS_URL = "https://account.protonvpn.com/downloads#wireguard-configuration"

    fun inspectConf(confText: String): ProtonConfInfo? {
        val parsed = WgConf.toWarpConfig("ProtonVPN", confText) ?: return null
        val lower = confText.lowercase()
        val isProton = ("netshield" in lower) ||
            ("bouncing" in lower) ||
            ("vpn accelerator" in lower) ||
            ("proton" in lower) ||
            (parsed.account.ipv4 == "10.2.0.2" && parsed.dns.contains("10.2.0.1"))

        val serverLabel = extractServerLabel(confText)
            ?: if (isProton) "ProtonVPN" else parsed.endpoint.host

        return ProtonConfInfo(
            config = parsed,
            isProton = isProton,
            serverLabel = serverLabel,
            endpoint = parsed.endpoint.render(),
            clientIpv4 = parsed.account.ipv4
        )
    }

    /** Извлекает имя сервера из комментариев ProtonVPN (например `# NL-FREE#123` или `# CA-FREE#20`). */
    internal fun extractServerLabel(confText: String): String? {
        val serverRx = Regex("""^\s*#\s*([A-Z]{2}(?:-[A-Z]{2})?(?:-FREE)?#\d+(?:-[A-Z0-9]+)?)\s*$""")
        var inPeer = false
        for (rawLine in confText.lineSequence()) {
            val line = rawLine.trim()
            if (line.equals("[Peer]", ignoreCase = true)) {
                inPeer = true
                continue
            }
            if (line.startsWith("[") && !line.equals("[Peer]", ignoreCase = true)) {
                inPeer = false
                continue
            }
            val m = serverRx.matchEntire(line)
            if (m != null) return m.groupValues[1]
            if (inPeer && line.startsWith("#")) {
                val cand = line.removePrefix("#").trim()
                if (cand.length in 2..32 && !cand.contains('=')) return cand
            }
        }
        return null
    }
}

/**
 * 1:1 IPv4 NAT + TCP MSS clamping + ICMPv4 PMTU для Второго выхода на одном Wintun-адаптере:
 *  • исходящие пакеты (Wintun → второй DataPlane): переписывает `src IP` с IP основного туннеля (`172.16.0.2`)
 *    на IP второго туннеля (`10.2.0.2` у ProtonVPN);
 *  • входящие пакеты (второй DataPlane → Wintun): переписывает `dst IP` обратно (`10.2.0.2` → `172.16.0.2`);
 *  • в Double-Hop режиме (WARP → ProtonVPN): зажимает TCP MSS до 1160 байт (и шлёт ICMP Type 3 Code 4 MTU=1200
 *    для негабаритных IPv4-пакетов), чтобы зашифрованные пакеты второго туннеля гарантированно
 *    помещались в MTU Wintun (1280) без фрагментации.
 */
object Ipv4Nat {
    /** Безопасный TCP MSS для Double-Hop (1160 + 40 IP/TCP + 60 WG2 = 1260 <= 1280 Wintun MTU). */
    const val DOUBLE_HOP_MAX_TCP_MSS = 1160

    /** Максимальный размер внутреннего IPv4-пакета в Double-Hop до шифрования вторым WireGuard. */
    const val DOUBLE_HOP_PMTU = 1200

    fun ipv4Bytes(ip: String): ByteArray? = runCatching {
        val b = InetAddress.getByName(ip.substringBefore('/').trim()).address
        if (b.size == 4) b else null
    }.getOrNull()

    /** Переписывает IPv4 source (offset 12) или destination (offset 16) на месте. Возвращает true, если пакет изменён. */
    fun rewriteIpv4Address(
        packet: ByteArray,
        offset: Int,
        length: Int,
        addrFieldOffset: Int,
        expectedOld: ByteArray,
        replacementNew: ByteArray
    ): Boolean {
        if (length < 20) return false
        val version = (packet[offset].toInt() ushr 4) and 0x0F
        if (version != 4) return false
        val ihl = (packet[offset].toInt() and 0x0F) * 4
        if (ihl < 20 || length < ihl) return false

        val fieldPos = offset + addrFieldOffset
        if (packet[fieldPos] != expectedOld[0] ||
            packet[fieldPos + 1] != expectedOld[1] ||
            packet[fieldPos + 2] != expectedOld[2] ||
            packet[fieldPos + 3] != expectedOld[3]
        ) {
            return false
        }

        val oldHi = u16(packet, fieldPos)
        val oldLo = u16(packet, fieldPos + 2)
        val newHi = u16(replacementNew, 0)
        val newLo = u16(replacementNew, 2)

        System.arraycopy(replacementNew, 0, packet, fieldPos, 4)

        // 1. Инкрементальное обновление IPv4 header checksum (байты 10..11).
        val oldIpSum = u16(packet, offset + 10)
        val newIpSum = updateChecksum16(updateChecksum16(oldIpSum, oldHi, newHi), oldLo, newLo)
        put16(packet, offset + 10, newIpSum)

        // 2. Обновление псевдо-заголовка L4 для TCP (proto 6) и UDP (proto 17).
        val proto = packet[offset + 9].toInt() and 0xFF
        val l4Pos = offset + ihl
        when (proto) {
            6 -> if (length >= ihl + 18) { // TCP checksum @ +16
                val oldTcp = u16(packet, l4Pos + 16)
                val newTcp = updateChecksum16(updateChecksum16(oldTcp, oldHi, newHi), oldLo, newLo)
                put16(packet, l4Pos + 16, newTcp)
            }
            17 -> if (length >= ihl + 8) { // UDP checksum @ +6 (0 в IPv4 означает «не используется»)
                val oldUdp = u16(packet, l4Pos + 6)
                if (oldUdp != 0) {
                    var newUdp = updateChecksum16(updateChecksum16(oldUdp, oldHi, newHi), oldLo, newLo)
                    if (newUdp == 0) newUdp = 0xFFFF
                    put16(packet, l4Pos + 6, newUdp)
                }
            }
        }
        return true
    }

    /**
     * Зажимает TCP опцию MSS (Kind=2, Len=4) на IPv4 TCP SYN / SYN-ACK пакетах до [maxMss]
     * с инкрементальным пересчётом TCP checksum (корректно для чётного и нечётного выравнивания).
     */
    fun clampTcpMss(packet: ByteArray, offset: Int, length: Int, maxMss: Int = DOUBLE_HOP_MAX_TCP_MSS): Boolean {
        if (maxMss <= 0 || length < 44) return false
        val version = (packet[offset].toInt() ushr 4) and 0x0F
        if (version != 4) return false
        val ihl = (packet[offset].toInt() and 0x0F) * 4
        if (ihl < 20 || length < ihl + 24) return false
        val proto = packet[offset + 9].toInt() and 0xFF
        if (proto != 6) return false

        val l4Pos = offset + ihl
        val flags = packet[l4Pos + 13].toInt() and 0xFF
        if ((flags and 0x02) == 0) return false // только SYN / SYN-ACK

        val tcpHeaderLen = ((packet[l4Pos + 12].toInt() ushr 4) and 0x0F) * 4
        if (tcpHeaderLen <= 20 || length < ihl + tcpHeaderLen) return false

        var pos = l4Pos + 20
        val end = l4Pos + tcpHeaderLen
        while (pos < end) {
            val kind = packet[pos].toInt() and 0xFF
            if (kind == 0) break // EOL
            if (kind == 1) { // NOP
                pos += 1
                continue
            }
            if (pos + 1 >= end) break
            val optLen = packet[pos + 1].toInt() and 0xFF
            if (optLen < 2 || pos + optLen > end) break
            if (kind == 2 && optLen == 4) {
                val valPos = pos + 2
                val curMss = u16(packet, valPos)
                if (curMss <= maxMss) return false

                val rel = valPos - l4Pos
                var tcpSum = u16(packet, l4Pos + 16)
                if (rel % 2 == 0) {
                    put16(packet, valPos, maxMss)
                    tcpSum = updateChecksum16(tcpSum, curMss, maxMss)
                } else {
                    // Нечётное смещение относительно начала TCP-заголовка: затрагивает 2 выровненных 16-битных слова.
                    val word1Pos = valPos - 1
                    val word2Pos = valPos + 1
                    val oldW1 = u16(packet, word1Pos)
                    val oldW2 = if (word2Pos + 1 < offset + length) u16(packet, word2Pos)
                    else ((packet[word2Pos].toInt() and 0xFF) shl 8)
                    put16(packet, valPos, maxMss)
                    val newW1 = u16(packet, word1Pos)
                    val newW2 = if (word2Pos + 1 < offset + length) u16(packet, word2Pos)
                    else ((packet[word2Pos].toInt() and 0xFF) shl 8)
                    tcpSum = updateChecksum16(updateChecksum16(tcpSum, oldW1, newW1), oldW2, newW2)
                }
                put16(packet, l4Pos + 16, tcpSum)
                return true
            }
            pos += optLen
        }
        return false
    }

    /**
     * Формирует стандартный ICMPv4 Type 3 Code 4 (Fragmentation Needed, Next-Hop MTU = [nextHopMtu])
     * в ответ на слишком большой исходящий IPv4-пакет в Double-Hop режиме.
     */
    fun buildIcmpFragNeeded(
        origPacket: ByteArray,
        offset: Int,
        length: Int,
        nextHopMtu: Int = DOUBLE_HOP_PMTU,
        gatewayIpv4: ByteArray = byteArrayOf(172.toByte(), 16, 0, 1)
    ): ByteArray? {
        if (length < 20) return null
        val version = (origPacket[offset].toInt() ushr 4) and 0x0F
        if (version != 4) return null
        val origIhl = (origPacket[offset].toInt() and 0x0F) * 4
        if (origIhl < 20 || length < origIhl) return null
        val origProto = origPacket[offset + 9].toInt() and 0xFF
        if (origProto == 1) return null // не отвечаем ICMP на ICMP

        val quotedLen = minOf(length, origIhl + 8)
        val totalLen = 20 + 8 + quotedLen
        val out = ByteArray(totalLen)

        // IPv4 header
        out[0] = 0x45
        out[1] = 0
        put16(out, 2, totalLen)
        put16(out, 4, 0)
        put16(out, 6, 0)
        out[8] = 64
        out[9] = 1 // ICMP
        // src = gatewayIpv4, dst = origPacket.src
        System.arraycopy(gatewayIpv4, 0, out, 12, 4)
        System.arraycopy(origPacket, offset + 12, out, 16, 4)
        put16(out, 10, checksum16(out, 0, 20))

        // ICMP header: Type=3 (Dest Unreachable), Code=4 (Frag Needed), Next-Hop MTU
        out[20] = 3
        out[21] = 4
        put16(out, 22, 0)
        put16(out, 24, 0)
        put16(out, 26, nextHopMtu)
        System.arraycopy(origPacket, offset, out, 28, quotedLen)
        put16(out, 22, checksum16(out, 20, 8 + quotedLen))
        return out
    }

    /** RFC 1624 инкрементальный пересчёт 16-битной контрольной суммы 1's complement. */
    internal fun updateChecksum16(oldSum: Int, oldWord: Int, newWord: Int): Int {
        var sum = (oldSum.inv() and 0xFFFF) + (oldWord.inv() and 0xFFFF) + (newWord and 0xFFFF)
        while ((sum ushr 16) != 0) {
            sum = (sum and 0xFFFF) + (sum ushr 16)
        }
        return sum.inv() and 0xFFFF
    }

    internal fun checksum16(buf: ByteArray, off: Int, len: Int): Int {
        var sum = 0
        var i = 0
        while (i + 1 < len) {
            sum += u16(buf, off + i)
            i += 2
        }
        if (i < len) {
            sum += (buf[off + i].toInt() and 0xFF) shl 8
        }
        while ((sum ushr 16) != 0) {
            sum = (sum and 0xFFFF) + (sum ushr 16)
        }
        return sum.inv() and 0xFFFF
    }

    private fun u16(b: ByteArray, pos: Int): Int =
        ((b[pos].toInt() and 0xFF) shl 8) or (b[pos + 1].toInt() and 0xFF)

    private fun put16(b: ByteArray, pos: Int, value: Int) {
        b[pos] = ((value ushr 8) and 0xFF).toByte()
        b[pos + 1] = (value and 0xFF).toByte()
    }
}

/**
 * Обёртка [InputStream] для второго DataPlane:
 *  • опционально проверяет PMTU (для Double-Hop поверх WARP) и шлёт ICMP Fragmentation Needed;
 *  • опционально зажимает TCP MSS на исходящих SYN;
 *  • опционально переписывает `src IP` (primary → secondary, 1:1 NAT).
 */
class NatRewriteInputStream(
    private val delegate: InputStream,
    private val primaryIpv4: ByteArray? = null,
    private val secondaryIpv4: ByteArray? = null,
    private val maxTcpMss: Int = 0,
    private val pmtuLimit: Int = 0,
    private val pmtuFeedbackOut: OutputStream? = null
) : InputStream() {
    private val needNat = primaryIpv4 != null && secondaryIpv4 != null && !primaryIpv4.contentEquals(secondaryIpv4)

    override fun read(): Int = delegate.read()

    override fun read(b: ByteArray, off: Int, len: Int): Int {
        while (true) {
            val n = delegate.read(b, off, len)
            if (n < 20) return n
            if (pmtuLimit > 0 && n > pmtuLimit) {
                val icmp = Ipv4Nat.buildIcmpFragNeeded(b, off, n, nextHopMtu = pmtuLimit)
                if (icmp != null) {
                    runCatching { pmtuFeedbackOut?.write(icmp) }
                    continue
                }
            }
            if (maxTcpMss > 0) {
                Ipv4Nat.clampTcpMss(b, off, n, maxTcpMss)
            }
            if (needNat) {
                Ipv4Nat.rewriteIpv4Address(
                    b, off, n,
                    addrFieldOffset = 12,
                    expectedOld = primaryIpv4!!,
                    replacementNew = secondaryIpv4!!
                )
            }
            return n
        }
    }

    override fun close() = delegate.close()
}

/**
 * Обёртка [OutputStream] для второго DataPlane:
 *  • опционально зажимает TCP MSS на входящих SYN-ACK;
 *  • опционально переписывает `dst IP` (secondary → primary) перед записью в Wintun.
 */
class NatRewriteOutputStream(
    private val delegate: OutputStream,
    private val primaryIpv4: ByteArray? = null,
    private val secondaryIpv4: ByteArray? = null,
    private val maxTcpMss: Int = 0
) : OutputStream() {
    private val needNat = primaryIpv4 != null && secondaryIpv4 != null && !primaryIpv4.contentEquals(secondaryIpv4)

    override fun write(b: Int) = delegate.write(b)

    override fun write(b: ByteArray, off: Int, len: Int) {
        if (len >= 20 && (needNat || maxTcpMss > 0)) {
            val copy = b.copyOfRange(off, off + len)
            if (maxTcpMss > 0) {
                Ipv4Nat.clampTcpMss(copy, 0, len, maxTcpMss)
            }
            if (needNat) {
                Ipv4Nat.rewriteIpv4Address(
                    copy, 0, len,
                    addrFieldOffset = 16,
                    expectedOld = secondaryIpv4!!,
                    replacementNew = primaryIpv4!!
                )
            }
            delegate.write(copy, 0, len)
        } else {
            delegate.write(b, off, len)
        }
    }

    override fun close() = delegate.close()
}
