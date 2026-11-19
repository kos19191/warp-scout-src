package dev.warpscout.core.presets

import dev.warpscout.core.model.ResourceCheck
import dev.warpscout.core.net.RuleData

/**
 * Набор проверок доступности, построенный по спискам allow-domains.
 *
 * Логика простая и, главное, симметричная: если мы выбрали категорию, то и проверять надо именно
 * её — иначе «подбор под Telegram, проверенный по Google» выглядит успешным ровно до того момента,
 * когда пользователь открывает Telegram.
 *
 * Две стороны блокировки разведены явно:
 *  • [RuleCatalog.Kind.RU_BLOCKED] — режут в РФ, туннель обязан открыть: недоступность = плохой кандидат;
 *  • [RuleCatalog.Kind.BLOCKS_RU] — сайт сам закрыт для РФ-адресов или для дата-центров
 *    (`blockedByTarget = true`): даже рабочий WARP его не откроет, значит это не аргумент против
 *    кандидата, а справочная строка в отчёте;
 *  • [RuleCatalog.Kind.INFRA] — служебные диапазоны, по ним проверок не строим.
 */
object ResourceChecks {

    /** Контрольная точка: сайт, который в РФ открывается и без VPN. */
    fun control(): ResourceCheck = ResourceCheck(
        name = "контроль: сайт, доступный без VPN",
        url = "https://ru.wikipedia.org/wiki/Zapad",
        baselineExpected = true
    )

    /**
     * По одной проверке на категорию (по умолчанию), плюс контрольная точка.
     * Порядок стабильный — по номеру категории, чтобы отчёты сравнивались между запусками.
     */
    fun forCategories(
        ids: Collection<String> = RuleCatalog.DEFAULT_SELECTED,
        perCategory: Int = 1,
        includeControl: Boolean = true,
        includeBlockedByTarget: Boolean = true
    ): List<ResourceCheck> {
        val out = ArrayList<ResourceCheck>()
        if (includeControl) out += control()
        for (cat in RuleCatalog.ALL.sortedBy { it.number }) {
            if (cat.id !in ids) continue
            if (cat.kind == RuleCatalog.Kind.INFRA) continue
            if (cat.kind == RuleCatalog.Kind.BLOCKS_RU && !includeBlockedByTarget) continue
            val domains = cat.checkDomains.ifEmpty { RuleData.domains(cat.id).take(perCategory) }
            for (domain in domains.take(perCategory)) {
                out += ResourceCheck(
                    name = "${cat.title}: $domain",
                    url = "https://$domain/",
                    // 403/451 у таких сайтов — нормальный ответ: нас узнали и закрыли.
                    expectStatus = if (cat.kind == RuleCatalog.Kind.BLOCKS_RU) 200..499 else 200..399,
                    blockedByTarget = cat.kind == RuleCatalog.Kind.BLOCKS_RU
                )
            }
        }
        return out
    }

    /** Только те проверки, которые влияют на балл (без контрольной точки и без «нас блокируют»). */
    fun scored(checks: List<ResourceCheck>): List<ResourceCheck> =
        checks.filter { !it.baselineExpected && !it.blockedByTarget }
}
