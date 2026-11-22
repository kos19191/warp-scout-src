package dev.warpscout.core.lists

/**
 * Свой список сайтов (с 1.10.31): поле «Сайты» на вкладке «Туннелирование» и «свои сайты» второго
 * выхода. Человек пишет как привык — домен, ссылку, адрес или подсеть, по одному в строке или
 * через запятую, — а туннелю нужны маршруты (CIDR).
 *
 * Правила:
 *  • ссылка → домен («https://chatgpt.com/c/123» → chatgpt.com), порт отбрасывается;
 *  • «*.example.com» и «.example.com» → example.com (маршруты всё равно по адресам);
 *  • кириллический домен → punycode (сайт.рф → xn--80aswg.xn--p1ai), иначе DoH его не найдёт;
 *  • адрес → /32 или /128; подсеть — как есть, но с обнулёнными битами узла: Android не принимает
 *    маршрут «1.2.3.4/24» (VpnService.Builder.addRoute бросает «Bad address»), и подсеть молча
 *    пропала бы из туннеля;
 *  • непонятное — в [Parsed.bad], чтобы экран мог сказать, что именно не принято.
 */
object SiteList {

    data class Parsed(
        /** Домены (в нижнем регистре, punycode), без повторов. */
        val hosts: List<String>,
        /** Адреса и подсети в виде CIDR, без повторов. */
        val prefixes: List<String>,
        /** Строки, которые не похожи ни на домен, ни на адрес. */
        val bad: List<String>,
    ) {
        val isEmpty: Boolean get() = hosts.isEmpty() && prefixes.isEmpty()
        val total: Int get() = hosts.size + prefixes.size
    }

    private val HOST_RE = Regex("""^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+([a-z]{2,63}|xn--[a-z0-9-]{1,59})$""")
    private val V4_RE = Regex("""^\d{1,3}(\.\d{1,3}){3}$""")

    fun parse(text: String): Parsed {
        val hosts = LinkedHashSet<String>()
        val prefixes = LinkedHashSet<String>()
        val bad = LinkedHashSet<String>()
        for (line in text.lines()) {
            val clean = line.substringBefore('#').trim()
            if (clean.isEmpty()) continue
            for (raw in clean.split(',', ';', ' ', '\t')) {
                val token = raw.trim()
                if (token.isEmpty()) continue
                val cidr = cidrOf(token)
                if (cidr != null) {
                    prefixes += cidr
                    continue
                }
                val host = hostOf(token)
                if (host != null) hosts += host else bad += token
            }
        }
        return Parsed(hosts.toList(), prefixes.toList(), bad.toList())
    }

    /** «example.com» → ещё и «www.example.com»: у сайта с www часто другие адреса CDN. */
    fun withWww(hosts: List<String>): List<String> {
        val out = LinkedHashSet<String>()
        for (h in hosts) {
            out += h
            if (!h.startsWith("www.") && h.count { it == '.' } == 1) out += "www.$h"
        }
        return out.toList()
    }

    /**
     * Маршруты: подсети как есть, домены — адресами из [resolved] (host → адреса, как отдаёт
     * `AllowListPlanner.resolveAll`).
     */
    fun cidrs(parsed: Parsed, resolved: Map<String, List<String>>): List<String> {
        val out = LinkedHashSet<String>(parsed.prefixes)
        for (ips in resolved.values) {
            for (ip in ips) {
                val c = cidrOf(ip.trim()) ?: continue
                out += c
            }
        }
        return out.toList()
    }

    /** Адрес или подсеть → нормальный CIDR; null — это не адрес. */
    fun cidrOf(token: String): String? {
        var t = token.trim()
        if (t.startsWith("[") && t.contains("]")) t = t.substring(1, t.indexOf(']'))
        val slash = t.indexOf('/')
        val addr = if (slash >= 0) t.substring(0, slash) else t
        val bitsText = if (slash >= 0) t.substring(slash + 1) else ""
        if (V4_RE.matches(addr)) {
            val parts = addr.split('.').map { it.toIntOrNull() ?: return null }
            if (parts.any { it !in 0..255 }) return null
            val bits = if (bitsText.isEmpty()) 32 else bitsText.toIntOrNull()?.takeIf { it in 0..32 } ?: return null
            val bytes = ByteArray(4) { parts[it].toByte() }
            mask(bytes, bits)
            return bytes.joinToString(".") { (it.toInt() and 0xFF).toString() } + "/$bits"
        }
        if (addr.contains(':') && addr.all { it.isDigit() || it in 'a'..'f' || it in 'A'..'F' || it == ':' || it == '.' }) {
            val bytes = runCatching { java.net.InetAddress.getByName(addr).address }.getOrNull() ?: return null
            if (bytes.size != 16) return null
            val bits = if (bitsText.isEmpty()) 128 else bitsText.toIntOrNull()?.takeIf { it in 0..128 } ?: return null
            mask(bytes, bits)
            val text = runCatching { java.net.InetAddress.getByAddress(bytes).hostAddress }.getOrNull() ?: return null
            return compactV6(text) + "/$bits"
        }
        return null
    }

    /** Домен из строки (ссылка, «домен:порт», «*.домен»); null — не похоже на домен. */
    fun hostOf(token: String): String? {
        var t = token.trim()
        if (t.contains("://")) t = t.substringAfter("://")
        t = t.substringBefore('/').substringBefore('?').substringBefore('#')
        if (t.contains('@')) t = t.substringAfter('@')
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

    private fun mask(bytes: ByteArray, bits: Int) {
        for (i in bytes.indices) {
            val keep = (bits - i * 8).coerceIn(0, 8)
            val m = if (keep == 8) 0xFF else (0xFF shl (8 - keep)) and 0xFF
            bytes[i] = (bytes[i].toInt() and m).toByte()
        }
    }

    /** Java пишет IPv6 полностью («2a00:0:0:0:0:0:0:1»): сжимаем самую длинную серию нулей до «::». */
    private fun compactV6(text: String): String {
        val groups = text.substringBefore('%').split(':').map { it.trimStart('0').ifEmpty { "0" } }
        if (groups.size != 8) return text.lowercase()
        var bestStart = -1
        var bestLen = 0
        var i = 0
        while (i < 8) {
            if (groups[i] == "0") {
                var j = i
                while (j < 8 && groups[j] == "0") j++
                if (j - i > bestLen && j - i > 1) {
                    bestStart = i
                    bestLen = j - i
                }
                i = j
            } else {
                i++
            }
        }
        if (bestStart < 0) return groups.joinToString(":").lowercase()
        val head = groups.subList(0, bestStart).joinToString(":")
        val tail = groups.subList(bestStart + bestLen, 8).joinToString(":")
        return "$head::$tail".lowercase()
    }
}
