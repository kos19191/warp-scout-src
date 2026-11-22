package dev.warpscout.core.lists

import dev.warpscout.core.config.SplitRoutes
import dev.warpscout.core.net.DohClient
import java.util.concurrent.Executors

/**
 * Превращает наборы доменов/подсетей в то, что понимает WireGuard: список CIDR для `AllowedIPs`.
 *
 * Правила, которые тут зашиты, взяты из реальности, а не из фантазии:
 *
 *  • подсети из `Subnets/IPv4/NN-name.lst` берём как есть — они актуальнее любого кеша резолвинга, и их
 *    отдаёт сам проект (для Telegram без них вообще смысла нет: клиенты ходят по IP);
 *  • домены резолвим только DoH и только ограниченным числом: `java.net.InetAddress` в РФ отдаёт
 *    отравленные адреса, а без лимита мы бы сделали тысячи запросов;
 *  • всё, что относится к стороне DIRECT (банки, сайты, банящие дата-центры), в AllowedIPs НЕ
 *    попадает: WG-конфиг не умеет «исключить», он умеет только «включить», поэтому исключение
 *    выражается отсутствием маршрута;
 *  • если в списке есть `0.0.0.0/0` — это «туннелировать всё», и тогда резолвинг не нужен вовсе.
 */
data class TunnelPlan(
    /** CIDR, которые попадут в AllowedIPs. */
    val include: List<String>,
    /** Что мы сознательно оставляем снаружи туннеля — для человека, не для конфига. */
    val excludeNote: List<String>,
    /** Итоговая строчка AllowedIPs. */
    val allowedIps: String,
    val unresolved: List<String>,
    val fullTunnel: Boolean,
    /** Кто сколько дал маршрутов: «YouTube: 42», чтобы в UI было видно, откуда что взялось. */
    val perList: Map<String, Int>
) {
    fun summary(): String {
        val v6 = include.count { ':' in it }
        return when {
            fullTunnel -> "весь трафик (0.0.0.0/0, ::/0)"
            include.isEmpty() -> "маршрутов нет: списки не загружены или ничего не разрешилось"
            else -> "${include.size} маршрутов (v4 ${include.size - v6}, v6 $v6)" +
                if (unresolved.isEmpty()) "" else ", не разрешилось ${unresolved.size}"
        }
    }
}

object AllowListPlanner {

    /** Сколько доменов максимум резолвим на весь план: больше — долго и бессмысленно. Подсети в этот лимит не входят. */
    const val DEFAULT_MAX_DOMAINS = 220

    /**
     * @param block  списки, которые туннелируем
     * @param direct списки, которые должны идти мимо туннеля (в AllowedIPs их нет)
     * @param resolver host → адреса; по умолчанию — Cloudflare DoH с фолбэком на Google
     */
    fun plan(
        block: List<AllowList>,
        direct: List<AllowList>,
        parsed: Map<String, AllowLists.Parsed>,
        fullTunnel: Boolean = false,
        maxDomains: Int = DEFAULT_MAX_DOMAINS,
        resolver: ((String) -> List<String>)? = null
    ): TunnelPlan {
        if (fullTunnel) {
            return TunnelPlan(
                include = listOf("0.0.0.0/0", "::/0"),
                excludeNote = emptyList(),
                allowedIps = "0.0.0.0/0, ::/0",
                unresolved = emptyList(),
                fullTunnel = true,
                perList = emptyMap()
            )
        }

        val resolve: (String) -> List<String> = resolver ?: { host -> dohResolve(host) }
        val include = LinkedHashSet<String>()
        val unresolved = LinkedHashSet<String>()
        val perList = LinkedHashMap<String, Int>()
        var budget = maxDomains.coerceAtLeast(0)

        for (list in block) {
            val p = parsed[list.id] ?: continue
            val before = include.size
            // Подсети — даром: они уже в списке, их не надо резолвить, и в бюджет доменов не входят.
            include.addAll(p.prefixes)
            // И подсети, без которых сервис из списка не работает (видео YouTube, см. EXTRA_PREFIXES).
            AllowLists.EXTRA_PREFIXES[list.id]?.let { include.addAll(it) }
            val room = budget.coerceAtMost(p.domains.size).coerceAtLeast(0)
            if (budget > 0 && room > 0) {
                val picked = p.domains.take(room)
                budget -= room
                val addrs = resolveAll(picked, resolve)
                for ((domain, ips) in addrs) {
                    if (ips.isEmpty()) unresolved.add(domain)
                    ips.forEach { a ->
                        if (a.contains(':')) include.add("$a/128")
                        else if (Regex("""^\d+\.\d+\.\d+\.\d+$""").matches(a)) include.add("$a/32")
                    }
                }
            }
            perList[list.title] = include.size - before
        }

        // «Снаружи» — это не запись в конфиге, а то, чего в конфиге нет. Но показать их полезно:
        // пользователь должен видеть, что банк он через туннель не погонит, и почему.
        val excludeNote = direct.flatMap { p -> parsed[p.id]?.let { d -> d.domains.take(6) } ?: emptyList() }
            .distinct().take(12)

        val prefixes = include.toList()
        return TunnelPlan(
            include = prefixes,
            excludeNote = excludeNote,
            allowedIps = if (prefixes.isEmpty()) "0.0.0.0/0, ::/0" else prefixes.joinToString(", "),
            unresolved = unresolved.toList(),
            fullTunnel = prefixes.isEmpty(),
            perList = perList
        )
    }

    /**
     * Один DoH-запрос на тип записи: Cloudflare, при пустом ответе — Google. Системный резолвер не
     * используем принципиально: в РФ он отдаёт подменённые адреса, и мы бы замаршрутизировали трафик
     * на IP, который провайдер и так подсунул.
     */
    fun dohResolve(host: String): List<String> {
        val cf = DohClient(DohClient.CLOUDFLARE)
        val a = runCatching { cf.resolveA(host) }.getOrNull()
        val v6 = runCatching { cf.resolveAAAA(host) }.getOrNull()
        val fromCf = (a ?: emptyList()) + (v6 ?: emptyList())
        if (fromCf.isNotEmpty() || a != null) return fromCf
        val gg = DohClient(DohClient.GOOGLE)
        return (runCatching { gg.resolveA(host) }.getOrNull() ?: emptyList()) +
            (runCatching { gg.resolveAAAA(host) }.getOrNull() ?: emptyList())
    }

    /** Пакетный резолвинг одним пулом потоков: 200 доменов должны занимать секунды, а не минуты. */
    fun resolveAll(
        hosts: List<String>,
        resolve: (String) -> List<String> = { dohResolve(it) },
        threads: Int = 16
    ): Map<String, List<String>> {
        if (hosts.isEmpty()) return emptyMap()
        val ex = Executors.newFixedThreadPool(minOf(threads, hosts.size).coerceAtLeast(1)) { r ->
            Thread(r, "warpscout-resolve").apply { isDaemon = true }
        }
        return try {
            hosts.associateWith { h -> ex.submit(java.util.concurrent.Callable { runCatching { resolve(h) }.getOrDefault(emptyList()) }) }
                .mapValues { (_, f) ->
                    runCatching { f.get(15, java.util.concurrent.TimeUnit.SECONDS) }.getOrDefault(emptyList())
                }
        } finally {
            ex.shutdownNow()
        }
    }

    /** Готовый план → конфиг-строка (чтобы UI мог показать «вот что пойдёт в AllowedIPs»). */
    fun renderAllowedIps(plan: TunnelPlan, max: Int = SplitRoutes.MAX_PREFIXES): String =
        plan.include.take(max).joinToString(",\n    ")
}
