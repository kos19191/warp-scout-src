package dev.warpscout.core.net

import java.math.BigInteger

/**
 * Сеть в виде пары «начало диапазона + число хостовых бит».
 *
 * Зачем свой тип, а не `InetAddress`: WireGuard `AllowedIPs` — это список префиксов, и с ним нужно
 * делать две вещи, которых нет в стандартной библиотеке Android:
 *
 *  • **схлопывать** пересекающиеся и соседние сети (10 списков категорий дают десятки дублей,
 *    а `VpnService.addRoute()` на каждый маршрут — это время установки туннеля);
 *  • **считать** попадание адреса в набор (для проверок «маршрут на этот IP вообще есть?»).
 *
 * Всё на [BigInteger]: одинаково работает для IPv4 и IPv6, без зависимостей и без Android API.
 */
data class Cidr(val start: BigInteger, val hostBits: Int, val version: Int) {

    init {
        require(version == 4 || version == 6) { "version must be 4 or 6" }
    }

    val totalBits: Int get() = if (version == 4) 32 else 128

    /** Длина префикса: 0.0.0.0/0 → 0, ::/0 → 0. */
    val prefix: Int get() = totalBits - hostBits

    val size: BigInteger get() = BigInteger.ONE.shiftLeft(hostBits)

    val end: BigInteger get() = start + size - BigInteger.ONE

    fun contains(address: BigInteger): Boolean = address >= start && address <= end

    /** Приводит к канонической записи: младшие (хостовые) биты обнуляются. */
    fun normalized(): Cidr =
        if (hostBits == 0) this else Cidr(start.shiftRight(hostBits).shiftLeft(hostBits), hostBits, version)

    fun render(): String = "${addressString()}/$prefix"

    fun addressString(): String = if (version == 4) ipv4ToString(start) else ipv6ToString(start)

    override fun toString(): String = render()

    companion object {

        /** Разбор «1.2.3.4/24», «2a00::/32», «1.2.3.4» (без маски — /32 или /128). */
        fun parse(text: String): Cidr? {
            val s = text.trim().substringBefore('#').trim()
            if (s.isEmpty()) return null
            val slash = s.indexOf('/')
            val addrText = if (slash >= 0) s.substring(0, slash).trim() else s
            val prefixText = if (slash >= 0) s.substring(slash + 1).trim() else null
            return if (addrText.contains(':')) {
                val value = parseIpv6(addrText) ?: return null
                val bits = prefixText?.toIntOrNull() ?: 128
                if (bits !in 0..128) return null
                Cidr(value, 128 - bits, 6).normalized()
            } else {
                val value = parseIpv4(addrText) ?: return null
                val bits = prefixText?.toIntOrNull() ?: 32
                if (bits !in 0..32) return null
                Cidr(value, 32 - bits, 4).normalized()
            }
        }

        fun parseList(text: String): List<Cidr> =
            text.split(',', '\n', '\r', ' ', '\t', ';')
                .asSequence()
                .map { it.trim() }
                .filter { it.isNotEmpty() && !it.startsWith("#") }
                .mapNotNull { parse(it) }
                .toList()

        /** Объединение: убирает дубли и вложенности, схлопывает соседей в минимальный набор префиксов. */
        fun union(inputList: List<Cidr>): List<Cidr> {
            if (inputList.isEmpty()) return emptyList()
            val sorted = inputList.map { it.normalized() }
                .sortedWith(compareBy({ it.version }, { it.start }))
            val out = ArrayList<Cidr>()
            var i = 0
            while (i < sorted.size) {
                val version = sorted[i].version
                var start = sorted[i].start
                var end = sorted[i].end
                i++
                // Сливаем всё, что пересекается или приляпано вплотную (+1): так получается
                // минимальный набор префиксов, и VpnService не получает 2000 маршрутов вместо 300.
                while (i < sorted.size && sorted[i].version == version && sorted[i].start <= end + BigInteger.ONE) {
                    end = maxOf(end, sorted[i].end)
                    i++
                }
                out += summarize(start, end, version)
            }
            return out.sortedWith(compareBy({ it.version }, { it.start }))
        }

        /** Диапазон [start, end] → минимальный набор префиксов. */
        private fun summarize(start: BigInteger, end: BigInteger, version: Int): List<Cidr> {
            val totalBits = if (version == 4) 32 else 128
            val out = ArrayList<Cidr>()
            var s = start
            while (s <= end) {
                val available = end - s                       // максимум адресов: available + 1
                val maxHostBits = available.bitLength()       // ≤ 2^bitLength
                val aligned = if (s.signum() == 0) totalBits else s.lowestSetBit
                val hostBits = minOf(maxHostBits, aligned, totalBits)
                out += Cidr(s, hostBits, version)
                s += BigInteger.ONE.shiftLeft(hostBits)
            }
            return out
        }

        fun toCsv(list: List<Cidr>): String = list.joinToString(", ") { it.render() }

        fun parseIpv4(text: String): BigInteger? {
            val parts = text.trim().split('.')
            if (parts.size != 4) return null
            var value = BigInteger.ZERO
            for (p in parts) {
                val n = p.toIntOrNull() ?: return null
                if (n !in 0..255) return null
                value = value.shiftLeft(8).or(BigInteger.valueOf(n.toLong()))
            }
            return value
        }

        fun ipv4ToString(value: BigInteger): String {
            val v = value.toLong() and 0xFFFFFFFFL
            return listOf(24L, 16L, 8L, 0L).joinToString(".") { ((v shr it.toInt()) and 0xFF).toString() }
        }

        fun parseIpv6(text: String): BigInteger? {
            var s = text.trim()
            if (s.startsWith("[") && s.endsWith("]")) s = s.substring(1, s.length - 1)
            if (s.isEmpty()) return null
            // Хвост вида «1.2.3.4» внутри IPv6 (IPv4-mapped) — переводим в две группы.
            val lastColon = s.lastIndexOf(':')
            if (lastColon >= 0 && s.substring(lastColon + 1).contains('.')) {
                val v4 = parseIpv4(s.substring(lastColon + 1)) ?: return null
                val hi = v4.shiftRight(16).toInt()
                val lo = v4.and(BigInteger.valueOf(0xFFFF)).toInt()
                s = s.substring(0, lastColon + 1) + Integer.toHexString(hi) + ":" + Integer.toHexString(lo)
            }
            val doubleColon = s.indexOf("::")
            val groups: List<String>
            if (doubleColon >= 0) {
                if (s.indexOf("::", doubleColon + 1) >= 0) return null
                val head = s.substring(0, doubleColon)
                val tail = s.substring(doubleColon + 2)
                val headParts = if (head.isEmpty()) emptyList() else head.split(':')
                val tailParts = if (tail.isEmpty()) emptyList() else tail.split(':')
                val missing = 8 - headParts.size - tailParts.size
                if (missing < 1) return null
                groups = headParts + List(missing) { "0" } + tailParts
            } else {
                groups = s.split(':')
                if (groups.size != 8) return null
            }
            var value = BigInteger.ZERO
            for (g in groups) {
                if (g.isEmpty() || g.length > 4) return null
                val n = g.toIntOrNull(16) ?: return null
                value = value.shiftLeft(16).or(BigInteger.valueOf(n.toLong()))
            }
            return value
        }

        fun ipv6ToString(value: BigInteger): String {
            val groups = IntArray(8)
            var v = value
            val mask = BigInteger.valueOf(0xFFFF)
            for (i in 7 downTo 0) {
                groups[i] = v.and(mask).toInt()
                v = v.shiftRight(16)
            }
            // RFC 5952: сжимаем самый длинный ряд нулей (≥2 групп), первый по порядку.
            var bestStart = -1
            var bestLen = 0
            var i = 0
            while (i < 8) {
                if (groups[i] == 0) {
                    var j = i
                    while (j < 8 && groups[j] == 0) j++
                    if (j - i > bestLen) {
                        bestStart = i
                        bestLen = j - i
                    }
                    i = j
                } else {
                    i++
                }
            }
            val sb = StringBuilder()
            var k = 0
            while (k < 8) {
                if (k == bestStart && bestLen >= 2) {
                    sb.append("::")
                    k += bestLen
                    continue
                }
                if (sb.isNotEmpty() && !sb.endsWith(":")) sb.append(':')
                sb.append(Integer.toHexString(groups[k]))
                k++
            }
            return if (sb.isEmpty()) "::" else sb.toString()
        }
    }
}
