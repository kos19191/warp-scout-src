package dev.warpscout.app

import android.content.Context
import dev.warpscout.core.config.ConfTarget
import dev.warpscout.core.config.SplitRoutes
import dev.warpscout.core.config.WgConf
import dev.warpscout.core.lists.AllowList
import dev.warpscout.core.lists.AllowLists
import dev.warpscout.core.lists.AllowListPlanner
import dev.warpscout.core.lists.FileListStore
import dev.warpscout.core.lists.TunnelPlan
import dev.warpscout.core.model.Endpoint
import dev.warpscout.core.model.JunkProfile
import dev.warpscout.core.model.WarpConfig
import dev.warpscout.core.net.HttpClient
import dev.warpscout.core.report.ConfigExport
import java.io.File

/**
 * Финальная сборка конфига под выбранный клиент.
 *
 * Порядок именно такой: сначала ядро отдаёт «лучший» конфиг, потом сюда применяются ручные
 * пожелания пользователя — сервер и каналы. Так «выбрал сервер вручную» не расходится с тем, что
 * реально лежит в файле и что поднимает собственный туннель.
 */
object ConfigComposer {

    /** Сервер, указанный пользователем (`host:port`), или null — брать подобранный. */
    fun pinnedEndpoint(prefs: Prefs): Endpoint? = prefs.pinnedEndpoint.takeIf { it.isNotBlank() }?.let { line ->
        runCatching { WgConf.parseEndpoint(if (line.contains(':')) line else "$line:2408") }.getOrNull()
    }

    fun applyPrefs(base: WarpConfig, prefs: Prefs, junkPool: List<JunkProfile>): WarpConfig {
        val ep = pinnedEndpoint(prefs)
        val junk = prefs.pinnedJunk.takeIf { it.isNotBlank() }
            ?.let { name -> junkPool.firstOrNull { it.name == name } }
        val withServer = if (ep != null && ep != base.endpoint) {
            base.copy(endpoint = ep, comments = base.comments + "сервер выбран вручную: ${ep.render()}")
        } else {
            base
        }
        val withJunk = if (junk != null && junk.name != withServer.junk.name) {
            withServer.copy(junk = junk, comments = withServer.comments + "профиль шума выбран вручную: ${junk.name}")
        } else {
            withServer
        }
        val allowed = prefs.allowedIps()
        val routesChanged = allowed.trim() != withJunk.allowedIps.trim()
        val note = if (routesChanged && prefs.routesMode != 0) {
            withJunk.comments + "каналы: ${prefs.routesModeName()} (${SplitRoutes.prefixesOf(allowed).size} маршрутов)"
        } else {
            withJunk.comments
        }
        return withJunk.copy(allowedIps = allowed, comments = note)
    }

    fun target(prefs: Prefs): ConfTarget = prefs.confTargetEnum()

    /** Текст «как его просили»: .conf с AWG, .conf без AWG, Clash YAML или только маршруты. */
    fun render(cfg: WarpConfig, prefs: Prefs): String = when (val t = target(prefs)) {
        ConfTarget.CLASH -> ConfigExport.clashYaml(cfg)
        ConfTarget.ROUTES -> WgConf.renderRoutes(cfg)
        else -> WgConf.render(cfg, t)
    }

    fun fileName(cfg: WarpConfig, prefs: Prefs): String = ConfigExport.filename(cfg, target(prefs))

    /** Что сказать под кнопкой экспорта. */
    fun explain(cfg: WarpConfig, prefs: Prefs): String {
        val t = target(prefs)
        val server = pinnedEndpoint(prefs)?.let { "сервер вручную $it" } ?: "сервер из подбора"
        val routes = when (prefs.routesMode) {
            0 -> "весь трафик"
            else -> "${SplitRoutes.prefixesOf(cfg.allowedIps).size} маршрутов (${prefs.routesModeName()})"
        }
        return "${t.title} · $server · $routes"
    }
}

/**
 * Загрузка и сборка маршрутов из allow-domains. Отдельный класс, потому что тут есть сеть и файл,
 * а и то и другое нужно и кнопке «Обновить списки», и авто-обновлению в WorkManager.
 */
class AllowListsRepo(context: Context) {

    private val store = FileListStore(File(context.filesDir, "allowlists"))
    private val http = HttpClient(8000)

    fun store(): FileListStore = store

    fun cached(): Map<String, AllowLists.Cached> = AllowLists.loadAll(store)

    /** Скачивает выбранные списки. Возвращает, что обновилось; ошибки не исключение, а строчка в UI. */
    fun refresh(ids: List<String>, log: (String) -> Unit): Result<Int> = runCatching {
        var updated = 0
        for (id in ids) {
            val list = AllowLists.byId[id] ?: continue
            log("списки: тяну ${list.id} …")
            val parts = AllowLists.fetch({ url -> runCatching { http.get(url, maxBytes = 4 * 1024 * 1024).body }.getOrNull() }, list)
            if (parts.isEmpty()) {
                log("списки: ${list.id} не скачался — остаётся старый кеш")
                continue
            }
            store.write(list.id, AllowLists.merge(parts))
            updated++
        }
        updated
    }

    /**
     * Собирает AllowedIPs и кладёт в Prefs. [fullTunnel] — «туннелировать всё», тогда резолвинг не нужен.
     */
    fun buildPlan(prefs: Prefs, log: (String) -> Unit): TunnelPlanResult {
        val cache = cached()
        val parsed = cache.mapValues { it.value.parsed }
        val block = prefs.allowBlockIds.mapNotNull { AllowLists.byId[it] }.ifEmpty {
            AllowLists.DEFAULT_BLOCK_IDS.mapNotNull { AllowLists.byId[it] }
        }
        val direct = prefs.allowDirectIds.mapNotNull { AllowLists.byId[it] }
        log("маршруты: ${block.size} списков «туннелируем», ${direct.size} «держим напрямую», резолвим DoH…")
        val plan = AllowListPlanner.plan(
            block = block,
            direct = direct,
            parsed = parsed,
            fullTunnel = false,
            maxDomains = prefs.routeDomainBudget
        )
        return TunnelPlanResult(plan, block, direct, cache)
    }

    /** Сохраняет план в Prefs (текстом) и возвращает сводку для UI. */
    fun savePlan(prefs: Prefs, plan: TunnelPlan): String {
        prefs.allowedIpsText = plan.allowedIps
        prefs.routesGeneratedAt = System.currentTimeMillis()
        return plan.summary()
    }

    /**
     * Устарели ли списки: нет кеша вообще или самый свежий скачан давно. Фоновому подбору этого
     * достаточно — он не должен тянуть 25 файлов каждые 6 часов, но и молча маршрутизировать по
     * месячной давности спискам тоже не должен.
     */
    fun isStale(maxAgeDays: Long = 7L, now: Long = System.currentTimeMillis()): Boolean {
        val newest = cached().values.maxOfOrNull { it.fetchedAt } ?: return true
        return now - newest > maxAgeDays * 86_400_000L
    }

    /** Какие списки стоит подтянуть: отмеченные пользователем + дефолт для «держать напрямую». */
    fun wantedIds(prefs: Prefs): List<String> =
        ((prefs.allowBlockIds + prefs.allowDirectIds + AllowLists.DEFAULT_BLOCK_IDS).toList())

    fun freshness(id: String): String {
        val list = AllowLists.byId[id] ?: return "нет такого списка"
        return AllowLists.freshness(AllowLists.readCache(store, list))
    }
}

/** Всё, что UI хочет знать о собранном плане маршрутов. */
data class TunnelPlanResult(
    val plan: dev.warpscout.core.lists.TunnelPlan,
    val block: List<AllowList>,
    val direct: List<AllowList>,
    val cache: Map<String, AllowLists.Cached>
) {
    fun missing(): List<AllowList> = block.filter { cache[it.id] == null }

    fun summary(): String = buildString {
        append(plan.summary())
        val miss = missing()
        if (miss.isNotEmpty()) append(" · не скачано: ").append(miss.joinToString(", ") { it.id })
        val directOnly = direct.mapNotNull { cache[it.id]?.parsed?.domains?.size }
        if (directOnly.isNotEmpty()) append(" · мимо туннеля оставляем ${directOnly.sum()} доменов")
    }
}
