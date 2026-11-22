package dev.warpscout.core.config

import dev.warpscout.core.model.WarpConfig

/**
 * Под какого клиента компилировать конфиг. Выбор не косметический: AmneziaWG понимает ключи
 * `Jc/Jmin/Jmax/H1..H4/S1..S4/I1..I4`, а стоковый WireGuard на них падает при разборе — и наоборот,
 * без мусорных пакетов AWG endpoint'ы, которые режут по первому же `type=1` пакету, перестают
 * отвечать. Отсюда и «подо что компилируем»: под VPN-клиент с AWG или под голый WG.
 */
enum class ConfTarget(val title: String, val note: String, val extension: String) {
    /** Amnezia / AmneziaWG: full AWG (джанк-пакеты + SNI-маска). */
    AMNEZIA(
        title = "AmneziaWG (VPN)",
        note = "Полный AWG: Jc/Jmin/Jmax/H*/S*/I1..I2. Нужен, если провайдер режет голый WireGuard.",
        extension = "conf"
    ),

    /** Стоковый WireGuard: только то, что описано в spec, иначе конфиг не импортируется. */
    WIREGUARD(
        title = "Обычный WireGuard",
        note = "Только PrivateKey/Address/DNS/MTU + Peer. Мусорные пакеты вырезаются: их " +
            "стоковый клиент не понимает (и не умеет), поэтому часть endpoint'ов с ним ляжет.",
        extension = "conf"
    ),

    /** Clash/Mihomo/sing-box-style YAML — для тех, кто собирает конфиг сам. */
    CLASH(
        title = "Clash YAML",
        note = "Для Clash/Mihomo: прокси + amnezia-wg-option блоком, маршруты берутся из allowed-ips.",
        extension = "yaml"
    ),

    /**
     * Only routes/channels — конфиг без ключей: список подсетей для AllowedIPs и домены.
     * Нужен, когда WG уже настроен, и надо лишь сказать «что туннелировать».
     */
    ROUTES(
        title = "Только каналы (routes)",
        note = "Не конфиг, а то, что вставить в AllowedIPs/роуты клиента: WG сам по себе не умеет " +
            "«туннелировать по домену», поэтому домены уже развёрнуты в /32 и /128.",
        extension = "txt"
    );

    /** AmneziaWG-специфичные строки, которые в голом WG надо вырезать. */
    val wantsJunk: Boolean get() = this == AMNEZIA
}

/** Готовые пресеты «что туннелировать». WG не умеет правила по доменам, поэтому только CIDR. */
data class RoutePreset(val id: String, val title: String, val domains: List<String>, val note: String = "")

/**
 * Сборка AllowedIPs из доменных групп.
 *
 * WireGuard — это маршруты по IP. Никакого «туннелировать youtube.com» в формате конфига нет:
 * есть `AllowedIPs = 1.2.3.4/32, ...`. Значит домены надо развёртывать в адреса, и делать это надо
 * не системным резолвером (в РФ он отравлен), а DoH — иначе мы замёртим маршрут до адреса, который
 * провайдер и так уже подменил.
 */
object SplitRoutes {

    /** Сколько адресов максимум класть в AllowedIPs: больше — и клиент тупит, и конфиг не читается. */
    const val MAX_PREFIXES = 900

    data class Plan(
        val allowedIps: String,
        val prefixes: List<String>,
        val unresolved: List<String>,
        val viaDoh: Boolean
    ) {
        val isEmpty: Boolean get() = prefixes.isEmpty()

        /** Что показать в UI: коротко и по-русски. */
        fun summary(): String {
            if (isEmpty) return "маршрутов нет: список доменов пуст или ничего не разрешилось"
            val v6 = prefixes.count { ':' in it }
            val v4 = prefixes.size - v6
            val tail = if (unresolved.isEmpty()) ""
            else ", не разрешилось: ${unresolved.size} (${unresolved.take(3).joinToString(", ")})"
            return "${prefixes.size} маршрутов: v4 $v4, v6 $v6$tail"
        }
    }

    /**
     * @param resolver host → список адресов; обычно `DohClient.resolveA` + `resolveAAAA`,
     *                 либо системный резолвер как фолбэк.
     */
    fun build(
        domains: List<String>,
        resolver: (String) -> List<String>,
        fullTunnel: Boolean = false,
        extra: List<String> = emptyList()
    ): Plan {
        if (fullTunnel) {
            return Plan("0.0.0.0/0, ::/0", listOf("0.0.0.0/0", "::/0"), emptyList(), false)
        }
        val prefixes = LinkedHashSet<String>()
        val unresolved = LinkedHashSet<String>()
        for (raw in domains.map { it.trim().removePrefix(".").removePrefix("*.").lowercase() }.filter { it.isNotEmpty() }) {
            val addrs = runCatching { resolver(raw) }.getOrDefault(emptyList())
            if (addrs.isEmpty()) {
                unresolved.add(raw)
                continue
            }
            for (a in addrs) {
                if (a.contains(':')) prefixes.add("$a/128")
                else if (Regex("""^\d+\.\d+\.\d+\.\d+$""").matches(a)) prefixes.add("$a/32")
            }
        }
        // CIDR из внешних списков добавляем как есть (они уже в нужном формате)
        for (e in extra) {
            val v = e.trim()
            if (v.contains('/')) prefixes.add(v)
        }
        val list = prefixes.toList().take(MAX_PREFIXES)
        return Plan(list.joinToString(", "), list, unresolved.toList(), true)
    }

    /** Обратная задача: из конфига вытащить маршруты (для «показать, что реально попадёт в туннель»). */
    fun prefixesOf(allowedIps: String): List<String> =
        allowedIps.split(',').map { it.trim() }.filter { it.isNotEmpty() && it.contains('/') }

    /**
     * DNS-серверы конфига — в маршруты туннеля, если маршруты раздельные.
     *
     * Зачем. При «весь трафик» DNS и так идёт через туннель. А в режиме «только нужные сайты»
     * адрес DNS (1.1.1.1, 8.8.8.8…) в маршруты обычно не входит — запросы идут мимо туннеля, и с
     * августа 2026 их ответы подменяет оператор (об этом пишут и в NetFix): сайт «из списка»
     * получает чужой адрес, и маршрут к нему уже не помогает. Маршрут /32 (/128) к самому DNS
     * отправляет запросы внутрь туннеля, где подменять их некому.
     *
     * Уже покрытые адреса и полный туннель не трогаем: строка возвращается как была.
     */
    fun withDns(allowedIps: String, dns: List<String>): String {
        val prefixes = prefixesOf(allowedIps)
        if (prefixes.isEmpty()) return allowedIps
        val v4All = prefixes.any { it.replace(" ", "") == "0.0.0.0/0" }
        val v6All = prefixes.any { it.replace(" ", "") == "::/0" }
        val add = ArrayList<String>()
        for (raw in dns) {
            val ip = raw.trim()
            if (ip.isEmpty()) continue
            if (ip.contains(':')) {
                if (v6All || prefixes.any { it.substringBefore('/').trim().equals(ip, ignoreCase = true) }) continue
                add += "$ip/128"
            } else {
                val addr = v4ToInt(ip) ?: continue
                if (v4All || prefixes.any { coversV4(it, addr) }) continue
                add += "$ip/32"
            }
        }
        if (add.isEmpty()) return allowedIps
        return (prefixes + add).distinct().joinToString(", ")
    }

    /** «a.b.c.d» → число; null — не IPv4. */
    private fun v4ToInt(ip: String): Int? {
        val parts = ip.split('.')
        if (parts.size != 4) return null
        var out = 0
        for (p in parts) {
            val b = p.trim().toIntOrNull() ?: return null
            if (b !in 0..255) return null
            out = (out shl 8) or b
        }
        return out
    }

    /** Префикс IPv4 «сеть/длина» накрывает адрес. */
    private fun coversV4(prefix: String, addr: Int): Boolean {
        val net = prefix.substringBefore('/').trim()
        if (net.contains(':')) return false
        val bits = prefix.substringAfter('/', "").trim().toIntOrNull() ?: return false
        if (bits !in 0..32) return false
        val base = v4ToInt(net) ?: return false
        if (bits == 0) return true
        val mask = -1 shl (32 - bits)
        return (base and mask) == (addr and mask)
    }
}
