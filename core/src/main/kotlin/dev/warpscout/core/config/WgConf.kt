package dev.warpscout.core.config

import dev.warpscout.core.crypto.Crypto
import dev.warpscout.core.model.AddrFamily
import dev.warpscout.core.model.AwgParams
import dev.warpscout.core.model.Endpoint
import dev.warpscout.core.model.JunkChunk
import dev.warpscout.core.model.JunkProfile
import dev.warpscout.core.model.WarpAccount
import dev.warpscout.core.model.WarpConfig

/**
 * Парсер/сериализатор конфигов AmneziaWG («WireGuard .conf + AWG-параметры») — ровно тот формат,
 * который отдаёт warp-generation.github.io и который вы импортируете в Amnezia:
 *
 * ```
 * [Interface]
 * PrivateKey = …
 * Address = 172.16.0.2, 2606:…
 * DNS = 1.1.1.1, …
 * MTU = 1280
 * S1..S4 / Jc / Jmin / Jmax / H1..H4     ← мусорные пакеты AWG
 * I1 = <b 0x…><r 16>                      ← шаблон мусорного пакета (буквальные байты + случайные)
 * [Peer]
 * PublicKey / AllowedIPs / Endpoint / PersistentKeepalive
 * ```
 */
data class RawSection(val name: String, val entries: MutableList<Pair<String, String>> = mutableListOf()) {
    fun get(key: String): String? = entries.lastOrNull { it.first.equals(key, true) }?.second
    fun set(key: String, value: String) {
        val idx = entries.indexOfLast { it.first.equals(key, true) }
        if (idx >= 0) entries[idx] = key to value else entries.add(key to value)
    }

    fun remove(key: String) {
        entries.removeAll { it.first.equals(key, true) }
    }
}

data class RawConf(val preamble: List<String> = emptyList(), val sections: List<RawSection>) {
    fun section(name: String): RawSection? = sections.firstOrNull { it.name.equals(name, true) }
    val iface: RawSection get() = section("Interface") ?: RawSection("Interface")
    val peer: RawSection get() = section("Peer") ?: RawSection("Peer")
}

object WgConf {

    private val JUNK_KEYS = listOf("I1", "I2", "I3", "I4", "I5", "I6")
    private val AWG_INT_KEYS = listOf("Jc", "Jmin", "Jmax", "H1", "H2", "H3", "H4", "S1", "S2", "S3", "S4")

    fun parse(text: String): RawConf {
        val sections = mutableListOf<RawSection>()
        var current: RawSection? = null
        for (rawLine in text.lines()) {
            val line = rawLine.trim()
            if (line.isEmpty() || line.startsWith("#") || line.startsWith(";")) continue
            if (line.startsWith("[") && line.endsWith("]")) {
                current = RawSection(line.substring(1, line.length - 1)).also { sections.add(it) }
                continue
            }
            val eq = line.indexOf('=')
            if (eq <= 0) continue
            val key = line.substring(0, eq).trim()
            val value = line.substring(eq + 1).trim()
            if (current == null) current = RawSection("Interface").also { sections.add(it) }
            current.entries.add(key to value)
        }
        return RawConf(sections = sections)
    }

    fun render(raw: RawConf): String = buildString {
        for (s in raw.sections) {
            append('[').append(s.name).append("]\n")
            for ((k, v) in s.entries) append(k).append(" = ").append(v).append('\n')
            append('\n')
        }
    }.trimEnd() + "\n"

    /** `<b 0xdeadbeef><r 16>` → список чанков. Всё, что не распознано, считается литералом. */
    fun parseJunk(value: String): List<JunkChunk> {
        val out = mutableListOf<JunkChunk>()
        var i = 0
        val s = value.trim()
        while (i < s.length) {
            if (s[i] != '<') {
                val rest = s.substring(i).trim()
                if (rest.isNotEmpty()) out.add(JunkChunk.Literal(hexOrRaw(rest)))
                break
            }
            val close = s.indexOf('>', i)
            if (close < 0) {
                out.add(JunkChunk.Literal(hexOrRaw(s.substring(i).trim())))
                break
            }
            val body = s.substring(i + 1, close).trim()
            val parts = body.split(Regex("\\s+"), limit = 2)
            when (parts.firstOrNull()?.lowercase()) {
                "b" -> out.add(JunkChunk.Literal(Crypto.unHex(parts.getOrElse(1) { "00" })))
                "r" -> out.add(JunkChunk.RandomBytes(parts.getOrElse(1) { "0" }.toIntOrNull() ?: 0))
                else -> out.add(JunkChunk.Literal(hexOrRaw(body)))
            }
            i = close + 1
        }
        return out
    }

    private fun hexOrRaw(text: String): ByteArray =
        if (Regex("^0?[xX]?[0-9a-fA-F]+$").matches(text) && text.replace(Regex("^0[xX]"), "").length % 2 == 0) {
            Crypto.unHex(text.removePrefix("0x").removePrefix("0X"))
        } else {
            text.toByteArray()
        }

    fun renderJunk(chunks: List<JunkChunk>): String = JunkChunk.renderAll(chunks)

    /** Полный разбор конфига в доменную модель. Возвращает null, если не хватает ключей. */
    fun toWarpConfig(name: String, text: String): WarpConfig? {
        val raw = parse(text)
        val iface = raw.iface
        val peer = raw.peer
        val priv = iface.get("PrivateKey") ?: return null
        val pub = peer.get("PublicKey") ?: return null
        val addr = iface.get("Address")?.split(',')?.map { it.trim() }?.filter { it.isNotEmpty() } ?: emptyList()
        val endpoint = peer.get("Endpoint")?.let { parseEndpoint(it) } ?: Endpoint("engage.cloudflareclient.com", 2408, AddrFamily.HOSTNAME)

        fun intKey(k: String, def: Int) = iface.get(k)?.trim()?.toIntOrNull() ?: def
        val junkKeys = JUNK_KEYS.mapNotNull { k -> iface.get(k)?.let { k to parseJunk(it) } }
        val profile = JunkProfile(
            name = iface.get("AWGProfile") ?: "imported",
            i1 = junkKeys.firstOrNull { it.first == "I1" }?.second ?: emptyList(),
            i2 = junkKeys.firstOrNull { it.first == "I2" }?.second ?: emptyList(),
            awg = AwgParams(
                jc = intKey("Jc", 4), jmin = intKey("Jmin", 40), jmax = intKey("Jmax", 70),
                h1 = intKey("H1", 1), h2 = intKey("H2", 2), h3 = intKey("H3", 3), h4 = intKey("H4", 4),
                s1 = intKey("S1", 0), s2 = intKey("S2", 0), s3 = intKey("S3", 0), s4 = intKey("S4", 0),
                extra = iface.entries.filter { (k, _) ->
                    k !in AWG_INT_KEYS && k !in JUNK_KEYS &&
                        k !in listOf("PrivateKey", "Address", "DNS", "MTU", "FWMark", "Table")
                }.map { it.first to it.second }
            )
        )

        return WarpConfig(
            name = name,
            account = WarpAccount(
                privateB64 = priv,
                peerPublicB64 = pub,
                ipv4 = addr.firstOrNull()?.substringBefore('/') ?: "172.16.0.2",
                ipv6 = addr.drop(1).firstOrNull()?.substringBefore('/'),
                source = "imported"
            ),
            endpoint = endpoint,
            junk = profile,
            allowedIps = peer.get("AllowedIPs") ?: "0.0.0.0/0, ::/0",
            dns = iface.get("DNS")?.split(',')?.map { it.trim() }?.filter { it.isNotEmpty() } ?: emptyList(),
            mtu = intKey("MTU", 1280),
            // У AmneziaWG 3 интервал бывает диапазоном («25-35»): берём нижнюю границу (с 1.10.49-beta1).
            persistentKeepalive = peer.get("PersistentKeepalive")?.trim()?.substringBefore('-')?.trim()?.toIntOrNull(),
            enableIpv6Address = addr.size > 1
        )
    }

    fun parseEndpoint(value: String): Endpoint {
        val v = value.trim()
        val host: String
        val port: Int
        when {
            v.startsWith("[") -> {
                val close = v.indexOf(']')
                host = v.substring(1, close)
                port = v.substring(close + 1).removePrefix(":").trim().toIntOrNull() ?: 2408
            }
            else -> {
                val idx = v.lastIndexOf(':')
                if (idx < 0) { host = v; port = 2408 } else {
                    host = v.substring(0, idx)
                    port = v.substring(idx + 1).trim().toIntOrNull() ?: 2408
                }
            }
        }
        val family = if (host.contains(':')) AddrFamily.IPV6 else if (Regex("^\\d+\\.\\d+\\.\\d+\\.\\d+$").matches(host)) AddrFamily.IPV4 else AddrFamily.HOSTNAME
        return Endpoint(host, port, family)
    }

    /**
     * Сборка конфига под конкретного клиента. Порядок ключей — как у генератора, потому что
     * люди сравнивают глазами с тем, что отдаёт warp-generation.
     *
     * [ConfTarget.WIREGUARD] вырезает AWG-ключи: стоковый парсер на неизвестном ключе не
     * «предупреждает», а отказывается читать конфиг целиком. [ConfTarget.ROUTES] вообще не про
     * ключи — это то, что вставляют в поле маршрутов любого клиента.
     */
    fun render(cfg: WarpConfig, target: ConfTarget = ConfTarget.AMNEZIA): String = when (target) {
        ConfTarget.CLASH -> dev.warpscout.core.report.ConfigExport.clashYaml(cfg)
        ConfTarget.ROUTES -> renderRoutes(cfg)
        else -> render(cfg, junk = target.wantsJunk)
    }

    /** Только маршруты + список доменов комментарием: для «у меня уже есть WG, добавь маршруты». */
    fun renderRoutes(cfg: WarpConfig): String = buildString {
        appendLine("# WilyScout: каналы туннелирования для «${cfg.name}»")
        appendLine("# Сервер (Endpoint): ${cfg.endpoint.render()}")
        appendLine("# Домены здесь уже развёрнуты в IP: WireGuard не умеет правила по именам, только маршруты.")
        appendLine("# Собранные адреса устаревают (CDN меняет IP) — обнови списки, если что-то из этого перестало открываться.")
        appendLine()
        appendLine("AllowedIPs =")
        val parts = SplitRoutes.prefixesOf(cfg.allowedIps)
        parts.forEachIndexed { i, cidr ->
            append("    ").append(cidr).append(if (i == parts.lastIndex) "" else ",").append('\n')
        }
        appendLine()
        appendLine("# MTU = ${cfg.mtu}")
        appendLine("# PersistentKeepalive = ${cfg.persistentKeepalive ?: "нет (NAT-таймаут обычно 30..120)"}")
    }

    private fun render(cfg: WarpConfig, junk: Boolean): String = buildString {
        for (c in cfg.comments) append("# ").append(c).append('\n')
        append("[Interface]\n")
        append("PrivateKey = ").append(cfg.account.privateB64).append('\n')
        val address = buildList {
            add(cfg.account.ipv4)
            if (cfg.enableIpv6Address && cfg.account.ipv6 != null) add(cfg.account.ipv6!!)
        }.joinToString(", ")
        append("Address = ").append(address).append('\n')
        if (cfg.dns.isNotEmpty()) append("DNS = ").append(cfg.dns.joinToString(", ")).append('\n')
        append("MTU = ").append(cfg.mtu).append('\n')
        if (junk) {
            append(cfg.junk.awg.renderInterfaceLines().joinToString("\n")).append('\n')
            if (cfg.junk.i1.isNotEmpty()) append("I1 = ").append(renderJunk(cfg.junk.i1)).append('\n')
            if (cfg.junk.i2.isNotEmpty()) append("I2 = ").append(renderJunk(cfg.junk.i2)).append('\n')
        } else {
            append("# AWG-мусор (Jc/Jmin/H*/S*/I*) вырезан: стоковый WireGuard их не понимает.\n")
            append("# Если с этим конфигом endpoint молчит — нужен клиент с AmneziaWG (AWG).\n")
        }
        append("\n[Peer]\n")
        append("PublicKey = ").append(cfg.account.peerPublicB64).append('\n')
        append("AllowedIPs = ").append(cfg.allowedIps).append('\n')
        append("Endpoint = ").append(cfg.endpoint.render()).append('\n')
        cfg.persistentKeepalive?.let { append("PersistentKeepalive = ").append(it).append('\n') }
    }
}
