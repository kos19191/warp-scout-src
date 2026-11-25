package dev.warpscout.desktop.tunnel

import java.math.BigInteger
import java.net.Inet6Address
import java.net.InetAddress

/**
 * Пресет раздельного туннелирования «Обход РФ»:
 *  • все зарубежные сети идут через туннель WARP (YouTube, Discord, Telegram, AI, зарубежные сайты, DNS 1.1.1.1);
 *  • все российские сети RIPE (8 690 IPv4 + 2 164 IPv6 блоков: Яндекс, VK, Сбер, Т-Банк, Альфа, ВТБ,
 *    Госуслуги, Ozon, Wildberries, Авито, Rutube, Кинопоиск, российские провайдеры) и локальная сеть
 *    (RFC1918, loopback, link-local) идут НАПРЯМУЮ мимо туннеля.
 *
 * Ресурсы `/routes/ru-ipv4.txt` и `/routes/ru-ipv6.txt` собраны из официальных распределений RIPE NCC.
 */
object RuBypassRoutes {

    private const val RU_V4_RESOURCE = "/routes/ru-ipv4.txt"
    private const val RU_V6_RESOURCE = "/routes/ru-ipv6.txt"
    private const val MAX_IPV4 = 0xFFFF_FFFFL

    /** Локальные и служебные IPv4-сети, которые всегда должны идти напрямую. */
    private val LAN_V4_CIDRS = listOf(
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.0.0.0/24",
        "192.0.2.0/24",
        "192.168.0.0/16",
        "198.18.0.0/15",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "224.0.0.0/4",
        "240.0.0.0/4"
    )

    val russianIpv4Cidrs: List<String> by lazy { loadResourceLines(RU_V4_RESOURCE) }
    val russianIpv6Cidrs: List<String> by lazy { loadResourceLines(RU_V6_RESOURCE) }

    /** Зарубежные IPv4-подсети = 0.0.0.0/0 \ (LAN ∪ RU). */
    val foreignIpv4Cidrs: List<String> by lazy {
        computeIpv4Complement(LAN_V4_CIDRS + russianIpv4Cidrs)
    }

    /** Зарубежные глобальные IPv6-подсети = 2000::/3 \ RU_v6. */
    val foreignIpv6Cidrs: List<String> by lazy {
        computeIpv6GlobalComplement(russianIpv6Cidrs)
    }

    private val foreignIpv4CsvOnly: String by lazy { foreignIpv4Cidrs.joinToString(", ") }
    private val foreignDualCsv: String by lazy { (foreignIpv4Cidrs + foreignIpv6Cidrs).joinToString(", ") }

    fun allowedIpsCsv(includeIpv6: Boolean): String =
        if (includeIpv6 && foreignIpv6Cidrs.isNotEmpty()) foreignDualCsv else foreignIpv4CsvOnly

    private val excludedV4Merged: List<CidrMath.Ipv4Range> by lazy {
        mergeIpv4Ranges((LAN_V4_CIDRS + russianIpv4Cidrs).mapNotNull { CidrMath.parseIpv4Cidr(it) })
    }

    /** Быстрая бинарная проверка: относится ли IPv4-адрес к РФ или локальной сети (идёт напрямую). */
    fun isRussianOrLanIpv4(ip: String): Boolean {
        val v = CidrMath.parseIpv4(ip) ?: return false
        var lo = 0
        var hi = excludedV4Merged.size - 1
        while (lo <= hi) {
            val mid = (lo + hi) ushr 1
            val r = excludedV4Merged[mid]
            when {
                v < r.start -> hi = mid - 1
                v > r.end -> lo = mid + 1
                else -> return true
            }
        }
        return false
    }

    internal fun computeIpv4Complement(excludedCidrs: List<String>): List<String> {
        val merged = mergeIpv4Ranges(excludedCidrs.mapNotNull { CidrMath.parseIpv4Cidr(it) })
        val out = ArrayList<String>(24_000)
        var cur = 0L
        for (r in merged) {
            if (cur < r.start) {
                out.addAll(CidrMath.rangeToCidrs(cur, r.start - 1L))
            }
            cur = r.end + 1L
        }
        if (cur <= MAX_IPV4) {
            out.addAll(CidrMath.rangeToCidrs(cur, MAX_IPV4))
        }
        return out
    }

    private fun mergeIpv4Ranges(ranges: List<CidrMath.Ipv4Range>): List<CidrMath.Ipv4Range> {
        if (ranges.isEmpty()) return emptyList()
        val sorted = ranges.sortedBy { it.start }
        val merged = ArrayList<CidrMath.Ipv4Range>(sorted.size)
        var curStart = sorted[0].start
        var curEnd = sorted[0].end
        for (i in 1 until sorted.size) {
            val next = sorted[i]
            if (next.start <= curEnd + 1L) {
                if (next.end > curEnd) curEnd = next.end
            } else {
                merged.add(CidrMath.Ipv4Range(curStart, curEnd))
                curStart = next.start
                curEnd = next.end
            }
        }
        merged.add(CidrMath.Ipv4Range(curStart, curEnd))
        return merged
    }

    internal fun computeIpv6GlobalComplement(excludedCidrs: List<String>): List<String> {
        // Глобальный unicast IPv6: 2000::/3 = [0x2000_0000... .. 0x3fff_ffff...]
        val globalStart = BigInteger("20000000000000000000000000000000", 16)
        val globalEnd = BigInteger("3fffffffffffffffffffffffffffffff", 16)
        val parsed = excludedCidrs.mapNotNull { parseIpv6Range(it) }
            .filter { it.second >= globalStart && it.first <= globalEnd }
            .map { (s, e) -> s.max(globalStart) to e.min(globalEnd) }
            .sortedBy { it.first }

        if (parsed.isEmpty()) return listOf("2000::/3")

        val merged = ArrayList<Pair<BigInteger, BigInteger>>(parsed.size)
        var curS = parsed[0].first
        var curE = parsed[0].second
        for (i in 1 until parsed.size) {
            val (ns, ne) = parsed[i]
            if (ns <= curE.add(BigInteger.ONE)) {
                if (ne > curE) curE = ne
            } else {
                merged.add(curS to curE)
                curS = ns
                curE = ne
            }
        }
        merged.add(curS to curE)

        val out = ArrayList<String>(14_000)
        var cur = globalStart
        for ((s, e) in merged) {
            if (cur < s) {
                appendIpv6RangeCidrs(cur, s.subtract(BigInteger.ONE), out)
            }
            cur = e.add(BigInteger.ONE)
        }
        if (cur <= globalEnd) {
            appendIpv6RangeCidrs(cur, globalEnd, out)
        }
        return out
    }

    private fun parseIpv6Range(cidr: String): Pair<BigInteger, BigInteger>? {
        val slash = cidr.indexOf('/')
        if (slash <= 0) return null
        val host = cidr.substring(0, slash).trim()
        val prefix = cidr.substring(slash + 1).trim().toIntOrNull() ?: return null
        if (prefix !in 0..128) return null
        val addr = runCatching { InetAddress.getByName(host) as? Inet6Address }.getOrNull() ?: return null
        val ip = BigInteger(1, addr.address)
        val hostBits = 128 - prefix
        val size = BigInteger.ONE.shiftLeft(hostBits)
        val start = ip.shiftRight(hostBits).shiftLeft(hostBits)
        val end = start.add(size).subtract(BigInteger.ONE)
        return start to end
    }

    private fun appendIpv6RangeCidrs(start: BigInteger, end: BigInteger, out: MutableList<String>) {
        var cur = start
        while (cur <= end) {
            val remaining = end.subtract(cur).add(BigInteger.ONE)
            val tz = if (cur == BigInteger.ZERO) 128 else cur.lowestSetBit.coerceAtMost(128)
            var bits = tz
            while (bits > 0 && BigInteger.ONE.shiftLeft(bits) > remaining) {
                bits--
            }
            val prefix = 128 - bits
            out.add("${formatIpv6(cur)}/$prefix")
            cur = cur.add(BigInteger.ONE.shiftLeft(bits))
        }
    }

    private fun formatIpv6(value: BigInteger): String {
        val raw = value.toByteArray()
        val bytes = ByteArray(16)
        val srcOff = (raw.size - 16).coerceAtLeast(0)
        val len = minOf(raw.size, 16)
        System.arraycopy(raw, srcOff, bytes, 16 - len, len)
        return InetAddress.getByAddress(bytes).hostAddress
    }

    private fun loadResourceLines(path: String): List<String> {
        val stream = RuBypassRoutes::class.java.getResourceAsStream(path) ?: return emptyList()
        return stream.bufferedReader(Charsets.UTF_8).useLines { lines ->
            lines.map { it.trim() }
                .filter { it.isNotEmpty() && !it.startsWith("#") && '/' in it }
                .toList()
        }
    }
}
