package dev.warpscout.desktop.tunnel

/**
 * Арифметика IPv4 CIDR для «Второго выхода».
 *
 * Когда основной туннель (WARP) настроен на весь трафик `0.0.0.0/0`, а поверх него
 * поднимается второй туннель (свой WireGuard/AmneziaWG VPS в нужной стране), адрес самого
 * VPS (`Endpoint`) нужно исключить из `AllowedIPs` основного туннеля — иначе его UDP-пакеты
 * завернутся внутрь WARP и получится петля маршрутизации.
 */
object CidrMath {

    data class Ipv4Range(val start: Long, val end: Long) {
        init {
            require(start in 0L..MAX_IP && end in start..MAX_IP)
        }
    }

    private const val MAX_IP = 0xFFFF_FFFFL

    fun parseIpv4(ip: String): Long? {
        val parts = ip.trim().split('.')
        if (parts.size != 4) return null
        var acc = 0L
        for (p in parts) {
            val octet = p.toIntOrNull() ?: return null
            if (octet !in 0..255) return null
            acc = (acc shl 8) or octet.toLong()
        }
        return acc
    }

    fun formatIpv4(ip: Long): String =
        "${(ip ushr 24) and 0xFF}.${(ip ushr 16) and 0xFF}.${(ip ushr 8) and 0xFF}.${ip and 0xFF}"

    fun parseIpv4Cidr(cidr: String): Ipv4Range? {
        val trimmed = cidr.trim()
        val slash = trimmed.indexOf('/')
        val host = if (slash < 0) trimmed else trimmed.substring(0, slash)
        val prefix = if (slash < 0) 32 else trimmed.substring(slash + 1).toIntOrNull() ?: return null
        if (prefix !in 0..32) return null
        val ip = parseIpv4(host) ?: return null
        val mask = if (prefix == 0) 0L else (MAX_IP shl (32 - prefix)) and MAX_IP
        val start = ip and mask
        val size = 1L shl (32 - prefix)
        val end = (start + size - 1L).coerceAtMost(MAX_IP)
        return Ipv4Range(start, end)
    }

    /** Разбивает произвольный диапазон [start..end] на минимальный набор IPv4 CIDR. */
    fun rangeToCidrs(start: Long, end: Long): List<String> {
        val out = ArrayList<String>()
        var cur = start
        while (cur <= end) {
            var maxSize = cur and -cur
            if (maxSize == 0L) maxSize = 1L shl 32
            val remaining = end - cur + 1L
            while (maxSize > remaining) maxSize = maxSize ushr 1
            var prefix = 32
            var s = maxSize
            while (s > 1L) {
                s = s ushr 1
                prefix--
            }
            out.add("${formatIpv4(cur)}/$prefix")
            cur += maxSize
        }
        return out
    }

    /**
     * Исключает конкретные IPv4-адреса из строки `AllowedIPs`.
     * IPv6-подсети и нераспознанные записи сохраняются без изменений.
     */
    fun excludeIpv4(allowedIpsCsv: String, excludeIps: List<String>): String {
        val excludes = excludeIps.mapNotNull { parseIpv4(it) }.distinct().sorted()
        if (excludes.isEmpty()) return allowedIpsCsv

        val tokens = allowedIpsCsv.split(',').map { it.trim() }.filter { it.isNotEmpty() }
        val result = LinkedHashSet<String>()

        for (token in tokens) {
            if (':' in token) {
                result.add(token)
                continue
            }
            val range = parseIpv4Cidr(token)
            if (range == null) {
                result.add(token)
                continue
            }
            val inside = excludes.filter { it in range.start..range.end }
            if (inside.isEmpty()) {
                result.add(token)
                continue
            }
            var cur = range.start
            for (ex in inside) {
                if (ex > cur) {
                    result.addAll(rangeToCidrs(cur, ex - 1L))
                }
                cur = ex + 1L
            }
            if (cur <= range.end) {
                result.addAll(rangeToCidrs(cur, range.end))
            }
        }
        return result.joinToString(", ")
    }
}
