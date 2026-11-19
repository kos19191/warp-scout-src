package dev.warpscout.core.net

import dev.warpscout.core.model.AddrFamily
import dev.warpscout.core.model.Endpoint
import java.util.Random

/**
 * Пул кандидатов «IP:порт», по которым мы сканируем.
 *
 * Источник знания о сетях и портах — официальная документация генератора:
 *   • https://help-guide.notion.site/Cloudflare-WARP-1f82684dab0d8024a1c8fec230f5e4e1
 *   • открытая часть генератора (warp-generation.github.io, script.js → generateRandomEndpoint)
 */
object WarpDefaults {

    /** Подсети AWG/WireGuard (Cloudflare). '*' заменяется на октет из [octetRange]. */
    val AWG_SUBNETS = listOf(
        "162.159.192.", "162.159.195.",
        "8.6.112.", "8.34.70.", "8.34.146.", "8.35.211.", "8.39.125.", "8.39.204.", "8.39.214.", "8.47.69.",
        "188.114.96.", "188.114.97.", "188.114.98.", "188.114.99."
    )

    /** Имена хостов, которые тоже стоит пробовать. */
    val AWG_HOSTNAMES = listOf("engage.cloudflareclient.com")

    /** Только с включённым Zero Trust (162.159.193.1–10). */
    val ZERO_TRUST_SUBNETS = listOf("162.159.193.")

    /** Порты AWG из документации (54 шт.). */
    val AWG_PORTS = listOf(
        500, 854, 859, 864, 878, 880, 890, 891, 894, 903, 908, 928, 934, 939, 942, 943, 945, 946, 955, 968,
        987, 988, 1002, 1010, 1014, 1018, 1070, 1074, 1180, 1387, 1701, 2408, 2506, 3138, 3476, 3581, 3854,
        4177, 4198, 4233, 4500, 5279, 5956, 7103, 7152, 7156, 7281, 7559, 8319, 8742, 8854, 8886
    )

    /** Порты MASQUE (WireGuard over HTTP/3 CONNECT-UDP). */
    val MASQUE_PORTS = listOf(443, 500, 1701, 4500, 4443, 8443, 8095)
    val MASQUE_SUBNETS = listOf("162.159.198.", "162.159.199.")

    /** Сгенерированный генератором диапазон октетов: 1..10 (не 0..255) — экономим на скане. */
    val DEFAULT_OCTET_RANGE = 1..10

    /** Публичные ключи Cloudflare WARP. */
    const val WARP_PEER_PUBLIC = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="
}

enum class PoolMode {
    /** По [samplesPerKey] случайных хостов на каждую пару (подсеть, порт) — быстрый и репрезентативный. */
    STRATIFIED,

    /** Полный перебор подсеть×октет×порт (много; для десктопа). */
    FULL,

    /** Только хостнеймы/поддомены из userList, по одному порту на строку. */
    EXPLICIT
}

data class EndpointSpec(
    val subnets: List<String> = WarpDefaults.AWG_SUBNETS,
    val hostnames: List<String> = WarpDefaults.AWG_HOSTNAMES,
    val ports: List<Int> = WarpDefaults.AWG_PORTS,
    val octetRange: IntRange = WarpDefaults.DEFAULT_OCTET_RANGE,
    val mode: PoolMode = PoolMode.STRATIFIED,
    val samplesPerKey: Int = 2,
    val maxEndpoints: Int = 400,
    val seed: Long = 20261119L
)

object EndpointPool {

    fun build(spec: EndpointSpec): List<Endpoint> {
        val rnd = Random(spec.seed)
        val out = LinkedHashSet<Endpoint>()
        val octets = spec.octetRange.filter { it in 0..255 }

        if (spec.mode == PoolMode.STRATIFIED) {
            // Детерминированно, но «перемешанно»: для каждой подсети и порта берём samplesPerKey октетов.
            for (prefix in spec.subnets) {
                val chosen = if (octets.isEmpty()) listOf(1) else
                    octets.shuffled(rnd).take(spec.samplesPerKey).sorted()
                for (port in spec.ports) {
                    for (o in chosen) {
                        out.add(Endpoint(prefix + o, port))
                        if (out.size >= spec.maxEndpoints) return out.toList()
                    }
                }
            }
            for (h in spec.hostnames) {
                for (port in spec.ports.take(spec.samplesPerKey)) {
                    out.add(Endpoint(h, port, AddrFamily.HOSTNAME))
                    if (out.size >= spec.maxEndpoints) return out.toList()
                }
            }
            return out.toList()
        }

        if (spec.mode == PoolMode.FULL) {
            for (prefix in spec.subnets) {
                for (o in if (octets.isEmpty()) listOf(1) else octets) {
                    for (port in spec.ports) {
                        out.add(Endpoint(prefix + o, port))
                        if (out.size >= spec.maxEndpoints) return out.toList()
                    }
                }
            }
            return out.toList()
        }

        for (line in spec.hostnames) for (e in parseOne(line)) out.add(e)
        for (prefix in spec.subnets) for (p in spec.ports) for (o in octets.take(1)) out.add(Endpoint(prefix + o, p))
        return out.toList().take(spec.maxEndpoints)
    }

    /**
     * Разбор пользовательского списка: по строке на конечную точку.
     * Поддерживается `1.2.3.4:500`, `host:port`, `162.159.192.*:943` (звёздочка → 1..10),
     * диапазоны `188.114.96.1-10:443`, комментарии через #.
     */
    fun parseList(text: String): List<Endpoint> {
        val out = LinkedHashSet<Endpoint>()
        for (rawLine in text.lines()) {
            val line = rawLine.substringBefore('#').substringBefore("//").trim()
            if (line.isEmpty()) continue
            for (part in line.split(',', ' ')) {
                if (part.isBlank()) continue
                out.addAll(parseRange(part.trim()))
            }
        }
        return out.toList()
    }

    fun parseOne(line: String): List<Endpoint> = parseRange(line.trim())

    private fun parseRange(token: String): List<Endpoint> {
        val sep = token.lastIndexOf(':')
        if (sep < 0) return emptyList()
        val hostPart = token.substring(0, sep)
        val portPart = token.substring(sep + 1).trim()
        val ports = if (portPart == "*") WarpDefaults.AWG_PORTS else listOfNotNull(portPart.toIntOrNull())

        fun hostsWithOctets(): List<String> = when {
            hostPart.contains('*') -> {
                val base = hostPart.trimEnd('*')
                (1..10).map { base + it }
            }
            hostPart.contains('-') -> {
                val idx = hostPart.lastIndexOf('.')
                val base = hostPart.substring(0, idx + 1)
                val range = hostPart.substring(idx + 1).split('-')
                val a = range.getOrNull(0)?.toIntOrNull() ?: 1
                val b = range.getOrNull(1)?.toIntOrNull() ?: a
                (a..maxOf(a, b)).map { base + it }
            }
            else -> listOf(hostPart)
        }

        return hostsWithOctets().flatMap { h ->
            ports.map { p ->
                val family = when {
                    h.contains(':') -> AddrFamily.IPV6
                    Regex("^\\d+\\.\\d+\\.\\d+\\.\\d+$").matches(h) -> AddrFamily.IPV4
                    else -> AddrFamily.HOSTNAME
                }
                Endpoint(h, p, family)
            }
        }
    }
}
