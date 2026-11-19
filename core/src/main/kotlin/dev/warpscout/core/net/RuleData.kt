package dev.warpscout.core.net

import dev.warpscout.core.presets.RuleCatalog
import java.util.concurrent.ConcurrentHashMap

/**
 * Доступ к снапшоту списков [allow-domains](https://github.com/haritos90/allow-domains),
 * вшитому в ресурсы ядра (`core/src/main/resources/rules/`).
 *
 * Почему снапшот, а не загрузка по сети: конфиг нужен в момент, когда сеть уже может быть
 * «сломана» — именно из-за блокировок приложение и запускают. Снапшот обновляется скриптом
 * `tools/gen_rules.py` (см. его шапку) и попадает и в APK, и в CLI без отдельной логики.
 *
 * Ресурсы читаются через classloader, поэтому одинаково работают в JVM (CLI, тесты) и в Android
 * (библиотека `:core` пакуется в APK).
 */
object RuleData {

    private const val DIR = "/rules/"

    private val cidrCache = ConcurrentHashMap<String, List<Cidr>>()
    private val textCache = ConcurrentHashMap<String, List<String>>()

    /** Подсети категории. [version] — 4 или 6. */
    fun cidrs(id: String, version: Int = 4): List<Cidr> =
        cidrCache.getOrPut("$id.v$version") {
            lines("$id.v$version.lst").mapNotNull { Cidr.parse(it) }
        }

    /** Домены категории — для DoH-резолва и для проверок доступности. */
    fun domains(id: String): List<String> = textCache.getOrPut("$id.domains") { lines("$id.domains.lst") }

    /** Объединение всех подсетей апстрима (`Subnets/IPv4|IPv6/all.lst`). */
    fun unionCidrs(version: Int = 4): List<Cidr> =
        cidrCache.getOrPut("union.v$version") { lines("union.v$version.lst").mapNotNull { Cidr.parse(it) } }

    /** Подсети категорий, объединённые и схлопнутые. */
    fun cidrsOf(ids: Collection<String>, version: Int = 4): List<Cidr> =
        Cidr.union(ids.flatMap { cidrs(it, version) })

    /** Есть ли у категории хоть какие-то подсети (иначе её можно только резолвить по DoH). */
    fun hasSubnets(id: String): Boolean =
        RuleCatalog.BY_ID[id]?.hasSubnets ?: (cidrs(id, 4).isNotEmpty() || cidrs(id, 6).isNotEmpty())

    /** Для отчёта и шапки настроек. */
    fun snapshotSummary(): String =
        "allow-domains ${RuleCatalog.SNAPSHOT_DATE}" +
            (if (RuleCatalog.SNAPSHOT_COMMIT.isNotEmpty()) " @${RuleCatalog.SNAPSHOT_COMMIT.take(7)}" else "")

    private fun lines(name: String): List<String> {
        val stream = RuleData::class.java.getResourceAsStream(DIR + name) ?: return emptyList()
        return stream.bufferedReader(Charsets.UTF_8).use { reader ->
            reader.readLines()
                .map { it.trim() }
                .filter { it.isNotEmpty() && !it.startsWith("#") && !it.startsWith(";") }
        }
    }
}
