package dev.warpscout.core.presets

import dev.warpscout.core.net.Cidr
import dev.warpscout.core.net.RuleData

/**
 * Что именно гнать через туннель.
 *
 * Здесь важное ограничение, из-за которого всё так устроено: **WireGuard маршрутизирует только
 * по IP**. Доменов в `AllowedIPs` не бывает — поэтому в режимах «только выбранные категории» мы
 * берём подсети из снапшота `allow-domains`, а для категорий без подсетей (YouTube, OpenAI, Claude…)
 * домены резолвятся в момент генерации через DoH и добавляются как /32-маршруты
 * ([SplitTunnel.build] принимает их готовыми в `extraCidrs` — ядро остаётся офлайновым).
 */
enum class SplitMode(val title: String, val hint: String) {
    FULL("Всё через туннель", "0.0.0.0/0 — весь трафик идёт через WARP"),
    ALL_EXCEPT_RU("Всё, кроме РФ", "туннель для зарубежных сетей, российские — напрямую"),
    ONLY_SELECTED("Только выбранные категории", "маршруты только для отмеченных сервисов"),
    ONLY_BLOCKED_IN_RU("Только заблокированное в РФ", "все подсети из списков allow-domains"),
    CUSTOM("Свой список AllowedIPs", "как вписали, так и будет");
}

data class SplitPlan(
    val mode: SplitMode,
    /** Готовое значение для `AllowedIPs = …` в конфиге. */
    val allowedIps: String,
    val prefixesV4: Int,
    val prefixesV6: Int,
    /** Категории, из которых построен план (для отчёта). */
    val categories: List<String> = emptyList(),
    /** Что важно знать пользователю: почему маршрутов столько, что не влезло, где подвох. */
    val notes: List<String> = emptyList()
) {
    val total: Int get() = prefixesV4 + prefixesV6

    val summary: String
        get() = when {
            allowedIps.isBlank() -> "маршрутов нет"
            prefixesV4 == 1 && prefixesV6 == 0 && allowedIps.startsWith("0.0.0.0/0") -> "весь трафик"
            else -> "$total маршрут(ов): $prefixesV4 IPv4" + if (prefixesV6 > 0) " + $prefixesV6 IPv6" else ""
        }
}

object SplitTunnel {

    /** Больше этого числа префиксов туннель поднимается заметно дольше — предупреждаем. */
    const val PREFIX_WARN = 1500

    /** Маршрут на публичный DoH-резолвер: без него в режимах с частичным туннелем DNS утекает мимо. */
    private const val DNS_V4 = "1.1.1.1/32"
    private const val DNS_V6 = "2606:4700:4700::1111/128"

    fun build(
        mode: SplitMode,
        selected: Collection<String> = RuleCatalog.DEFAULT_SELECTED,
        custom: String = "",
        ipv6: Boolean = true,
        /** Резолвнутые через DoH адреса доменов выбранных категорий. */
        extraCidrs: List<Cidr> = emptyList(),
        includeDnsRoute: Boolean = true
    ): SplitPlan {
        val ids = selected.filter { RuleCatalog.BY_ID.containsKey(it) }
        return when (mode) {
            SplitMode.FULL -> SplitPlan(
                mode = mode,
                allowedIps = if (ipv6) "0.0.0.0/0, ::/0" else "0.0.0.0/0",
                prefixesV4 = 1, prefixesV6 = if (ipv6) 1 else 0,
                notes = listOf("Весь трафик идёт через туннель — split-tunnel выключен.")
            )

            SplitMode.ALL_EXCEPT_RU -> {
                val nets = Cidr.union(RoutePresets.BYPASS_WHITELIST.mapNotNull { Cidr.parse(it) })
                    .filter { ipv6 || it.version == 4 }
                plan(mode, nets, ids, ipv6, includeDnsRoute,
                    baseNote = "Через туннель идут зарубежные сети из белого списка, российские — напрямую.")
            }

            SplitMode.ONLY_SELECTED -> {
                val fromRules = Cidr.union(ids.flatMap { RuleData.cidrs(it, 4) + RuleData.cidrs(it, 6) })
                val nets = Cidr.union(fromRules + extraCidrs).filter { ipv6 || it.version == 4 }
                if (nets.isEmpty()) {
                    val notes = mutableListOf(
                        "У выбранных категорий нет подсетей, а домены не разрешились — " +
                            "чтобы не оставить пользователя без туннеля, включён режим «всё через туннель»."
                    )
                    SplitPlan(SplitMode.FULL, if (ipv6) "0.0.0.0/0, ::/0" else "0.0.0.0/0",
                        prefixesV4 = 1, prefixesV6 = if (ipv6) 1 else 0, categories = ids, notes = notes)
                } else {
                    plan(mode, nets, ids, ipv6, includeDnsRoute)
                }
            }

            SplitMode.ONLY_BLOCKED_IN_RU -> {
                val fromRules = Cidr.union(
                    RuleData.unionCidrs(4) + RuleData.unionCidrs(6) +
                        ids.flatMap { RuleData.cidrs(it, 4) + RuleData.cidrs(it, 6) }
                )
                val nets = Cidr.union(fromRules + extraCidrs).filter { ipv6 || it.version == 4 }
                plan(mode, nets, ids, ipv6, includeDnsRoute,
                    baseNote = "Маршруты — объединение всех подсетей allow-domains (что режут в РФ) плюс выбранные категории.")
            }

            SplitMode.CUSTOM -> {
                val nets = Cidr.union(Cidr.parseList(custom)).filter { ipv6 || it.version == 4 }
                if (nets.isEmpty()) {
                    SplitPlan(SplitMode.FULL, if (ipv6) "0.0.0.0/0, ::/0" else "0.0.0.0/0",
                        prefixesV4 = 1, prefixesV6 = if (ipv6) 1 else 0,
                        notes = listOf("Свой список пуст или не разобрался — включён режим «всё через туннель»."))
                } else {
                    plan(mode, nets, ids, ipv6, includeDnsRoute)
                }
            }
        }
    }

    private fun plan(
        mode: SplitMode,
        nets: List<Cidr>,
        categories: List<String>,
        ipv6: Boolean,
        includeDnsRoute: Boolean,
        baseNote: String? = null
    ): SplitPlan {
        val notes = ArrayList<String>()
        baseNote?.let { notes += it }

        var all = nets
        val dnsTarget = Cidr.parseIpv4("1.1.1.1")
        if (includeDnsRoute && dnsTarget != null && all.none { it.version == 4 && it.contains(dnsTarget) }) {
            val dns = listOfNotNull(Cidr.parse(DNS_V4), if (ipv6) Cidr.parse(DNS_V6) else null)
            all = Cidr.union(all + dns)
            notes += "Добавлен маршрут на 1.1.1.1 — иначе DNS в частичном туннеле уходил бы мимо."
        }

        val v4 = all.filter { it.version == 4 }
        val v6 = all.filter { it.version == 6 }
        if (v4.isEmpty() && v6.isNotEmpty()) notes += "Маршруты только IPv6 — включите IPv6 в настройках."
        if (v4.isEmpty() && v6.isEmpty()) notes += "Маршрутов не осталось."

        if (v4.size + v6.size > PREFIX_WARN) {
            notes += "Маршрутов ${v4.size + v6.size} — туннель будет подниматься дольше обычного. " +
                "Обычно помогает режим с меньшим числом категорий."
        }
        if (categories.isNotEmpty()) {
            notes += "Категории: " + categories.mapNotNull { RuleCatalog.BY_ID[it]?.title }.joinToString(", ")
        }
        notes += "Данные: ${RuleData.snapshotSummary()}."
        return SplitPlan(
            mode = mode,
            allowedIps = Cidr.toCsv(all),
            prefixesV4 = v4.size,
            prefixesV6 = v6.size,
            categories = categories,
            notes = notes
        )
    }
}
