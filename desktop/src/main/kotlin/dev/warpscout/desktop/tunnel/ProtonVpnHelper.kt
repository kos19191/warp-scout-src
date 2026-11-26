package dev.warpscout.desktop.tunnel

import dev.warpscout.core.config.WgConf
import dev.warpscout.core.model.WarpConfig
import java.io.InputStream
import java.io.OutputStream
import java.net.InetAddress

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
        domains = "chatgpt.com, openai.com, api.openai.com, auth.openai.com, claude.ai, gemini.google.com, aistudio.google.com"
    ),
    SOCIAL_MEDIA(
        id = "social",
        title = "YouTube / Discord / X",
        domains = "youtube.com, googlevideo.com, ytimg.com, discord.com, discord.gg, gateway.discord.gg, x.com, instagram.com"
    )
}

/**
 * Помощник для простого добавления ProtonVPN (и любых других WireGuard `.conf`):
 *  • распознаёт официальные конфиги ProtonVPN (`# NL-FREE#123`, `10.2.0.2`, `NetShield`, `Bouncing`);
 *  • даёт готовые пресеты маршрутов для Второго выхода (включая официальные CIDR Telegram без DoH);
 *  • реализует 1:1 IPv4 NAT (`Ipv4AddressRewriter`) с инкрементальным пересчётом IPv4/TCP/UDP checksums
 *    (RFC 1624), чтобы Второй выход с собственным внутренним IP (например `10.2.0.2` у ProtonVPN)
 *    корректно работал поверх Wintun-адаптера WARP (`172.16.0.2`).
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

    /** Извлекает имя сервера из комментариев ProtonVPN (например `# NL-FREE#123` или `# CH-DE#1`). */
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
 * 1:1 IPv4 NAT для Второго выхода на одном Wintun-адаптере:
 *  • исходящие пакеты (Wintun → второй DataPlane): переписывает `src IP` с IP основного туннеля (`172.16.0.2`)
 *    на IP второго туннеля (`10.2.0.2` у ProtonVPN);
 *  • входящие пакеты (второй DataPlane → Wintun): переписывает `dst IP` обратно (`10.2.0.2` → `172.16.0.2`).
 *
 * Контрольные суммы IPv4-заголовка, TCP и UDP (если ненулевая) пересчитываются инкрементально по RFC 1624.
 */
object Ipv4Nat {
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

    /** RFC 1624 инкрементальный пересчёт 16-битной контрольной суммы 1's complement. */
    internal fun updateChecksum16(oldSum: Int, oldWord: Int, newWord: Int): Int {
        var sum = (oldSum.inv() and 0xFFFF) + (oldWord.inv() and 0xFFFF) + (newWord and 0xFFFF)
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

/** Обёртка [InputStream] для второго DataPlane: переписывает `src IP` (primary → secondary). */
class NatRewriteInputStream(
    private val delegate: InputStream,
    private val primaryIpv4: ByteArray,
    private val secondaryIpv4: ByteArray
) : InputStream() {
    override fun read(): Int = delegate.read()

    override fun read(b: ByteArray, off: Int, len: Int): Int {
        val n = delegate.read(b, off, len)
        if (n >= 20) {
            Ipv4Nat.rewriteIpv4Address(b, off, n, addrFieldOffset = 12, expectedOld = primaryIpv4, replacementNew = secondaryIpv4)
        }
        return n
    }

    override fun close() = delegate.close()
}

/** Обёртка [OutputStream] для второго DataPlane: переписывает `dst IP` (secondary → primary) перед записью в Wintun. */
class NatRewriteOutputStream(
    private val delegate: OutputStream,
    private val primaryIpv4: ByteArray,
    private val secondaryIpv4: ByteArray
) : OutputStream() {
    override fun write(b: Int) = delegate.write(b)

    override fun write(b: ByteArray, off: Int, len: Int) {
        if (len >= 20) {
            val copy = b.copyOfRange(off, off + len)
            Ipv4Nat.rewriteIpv4Address(copy, 0, len, addrFieldOffset = 16, expectedOld = secondaryIpv4, replacementNew = primaryIpv4)
            delegate.write(copy, 0, len)
        } else {
            delegate.write(b, off, len)
        }
    }

    override fun close() = delegate.close()
}
