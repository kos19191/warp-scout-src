package dev.warpscout.app

import android.content.Context
import dev.warpscout.core.lists.AllowListPlanner
import dev.warpscout.core.lists.AllowLists
import dev.warpscout.core.lists.SiteList
import dev.warpscout.core.net.CfTrace

/**
 * Сайты второго выхода — сами (с 1.10.31).
 *
 * Раньше адреса для второго выхода нужно было вписать руками («подсети»), а домены развернуть
 * кнопкой. Человек не понимал, что туда писать (журнал 22.11 21:17: девять правок подряд, ни одна не
 * применена). Теперь сайты берутся из списков allow-domains — тех, что не работают с российских
 * адресов (сервисы сами отказывают России, а у WARP выход российский), — плюс свои сайты. Адреса
 * собираются через DoH и обновляются раз в сутки; таблицу сервис меняет на лету.
 *
 * Проверка выхода — запрос `chatgpt.com/cdn-cgi/trace`: chatgpt.com всегда идёт через второй выход
 * (его адреса добавляются в любом случае), а ответ Cloudflare говорит, из какой страны пришёл запрос.
 */
object SecondRoutes {

    /** Списки по умолчанию: всё, что отказывает российским адресам, и ИИ-сервисы. */
    val SOURCES: List<String> = listOf("ru-ip-blocked", "openai", "claude", "google-ai")
    val DEFAULT_SOURCES: Set<String> = SOURCES.toSet()

    /** По нему проверяется страна второго выхода; его адреса идут во второй выход всегда. */
    const val CHECK_HOST = "chatgpt.com"
    const val CHECK_URL = "https://chatgpt.com/cdn-cgi/trace"

    /** Адресов не больше этого: таблица и маршруты остаются лёгкими. */
    const val MAX_CIDRS = 3000

    /** Раз в сутки — достаточно: адреса сайтов меняются редко. */
    const val STALE_MS = 24L * 3_600_000L

    /** Списки старше недели перед сборкой скачиваются заново. */
    private const val LIST_STALE_MS = 7L * 86_400_000L

    data class Result(val cidrs: List<String>, val sites: Int, val unresolved: Int, val missing: List<String>) {
        fun note(): String = "сайтов $sites → адресов ${cidrs.size}" +
            (if (unresolved > 0) ", не найдено $unresolved" else "") +
            (if (missing.isNotEmpty()) ", не скачано: ${missing.joinToString(", ")}" else "")
    }

    /** Что собирали — по этой подписи видно, что выбор поменялся и адреса пора собрать заново. */
    fun signature(prefs: Prefs): String =
        prefs.secondSources.sorted().joinToString(",") + "|" + prefs.secondDomains.trim()

    /** Пора ли собирать: выбор поменялся, адресов нет или они старше суток. */
    fun needsBuild(prefs: Prefs, now: Long = System.currentTimeMillis()): Boolean =
        prefs.secondExitOn && prefs.secondConf.isNotBlank() &&
            (prefs.secondCidrs.isBlank() || signature(prefs) != prefs.secondBuiltSig ||
                now - prefs.secondRoutesAt > STALE_MS)

    /**
     * Собрать адреса: скачать нужные списки (нет в кеше или старше недели), домены → адреса через
     * DoH. Долго (секунды–минута) и с сетью — звать не из UI-потока.
     */
    fun build(context: Context, prefs: Prefs, log: (String) -> Unit): Result {
        val repo = AllowListsRepo(context)
        val ids = prefs.secondSources.filter { AllowLists.byId[it] != null }.sortedBy { SOURCES.indexOf(it) }
        val now = System.currentTimeMillis()
        val before = repo.cached()
        val need = ids.filter { id -> before[id]?.let { now - it.fetchedAt > LIST_STALE_MS } ?: true }
        if (need.isNotEmpty()) repo.refresh(need, log)
        val cache = repo.cached()
        val missing = ids.filter { cache[it] == null }
        // Сначала — chatgpt.com (по нему проверяется выход) и свои сайты: при обрезке по MAX_CIDRS
        // они должны остаться, а не уступить место хвосту большого списка.
        val own = SiteList.parse(prefs.secondDomains)
        val ownHosts = LinkedHashSet<String>().apply {
            add(CHECK_HOST)
            addAll(SiteList.withWww(own.hosts))
        }
        val listHosts = LinkedHashSet<String>()
        val listPrefixes = LinkedHashSet<String>()
        ids.forEach { id ->
            cache[id]?.parsed?.let { parsed ->
                listHosts += parsed.domains
                // Подсети из списков — через cidrOf: Android не принимает маршрут с битами узла.
                parsed.prefixes.forEach { p -> SiteList.cidrOf(p)?.let { listPrefixes += it } }
            }
        }
        listHosts.removeAll(ownHosts)
        val all = ownHosts.toList() + listHosts.toList()
        log("второй выход: разворачиваю ${all.size} сайтов в адреса через DoH…")
        val resolved = AllowListPlanner.resolveAll(all)
        val first = SiteList.cidrs(
            SiteList.Parsed(emptyList(), own.prefixes, emptyList()),
            resolved.filterKeys { it in ownHosts }
        )
        val rest = SiteList.cidrs(
            SiteList.Parsed(emptyList(), listPrefixes.toList(), emptyList()),
            resolved.filterKeys { it !in ownHosts }
        )
        val cidrs = LinkedHashSet<String>().apply {
            addAll(first)
            addAll(rest)
        }.toList()
        val unresolved = resolved.count { it.value.isEmpty() }
        return Result(cidrs.take(MAX_CIDRS), all.size, unresolved, missing)
    }

    /** Сохранить сборку. true — адреса изменились (сервису есть что обновить). */
    fun save(prefs: Prefs, result: Result): Boolean {
        // Ни одного адреса (DoH не ответил) — сборкой это не считаем: прежние адреса остаются,
        // а следующая попытка будет при первом удобном случае, а не через сутки.
        if (result.cidrs.isEmpty()) {
            prefs.secondRoutesNote = "адреса не нашлись (" + result.note() + ")"
            return false
        }
        val text = result.cidrs.joinToString(", ")
        val changed = text != prefs.secondCidrs
        if (changed) prefs.secondCidrs = text
        prefs.secondRoutesAt = System.currentTimeMillis()
        prefs.secondRoutesNote = result.note()
        prefs.secondBuiltSig = signature(prefs)
        return changed
    }

    /**
     * Из какой страны выходит второй выход: запрос через туннель к chatgpt.com (его адреса —
     * во втором выходе). Строка для [Prefs.secondCheck]: «DE|адрес|время» или «!|причина|время».
     */
    fun checkExit(): String {
        val now = System.currentTimeMillis()
        val result = runCatching {
            val conn = java.net.URL(CHECK_URL).openConnection() as java.net.HttpURLConnection
            conn.connectTimeout = 7000
            conn.readTimeout = 7000
            conn.instanceFollowRedirects = false
            try {
                conn.inputStream.bufferedReader().use { it.readText().take(4096) }
            } finally {
                runCatching { conn.disconnect() }
            }
        }
        val trace = CfTrace.parse(result.getOrNull())
        return when {
            trace != null && trace.loc.isNotBlank() -> "${trace.loc}|${trace.ip}|$now"
            else -> "!|" + (result.exceptionOrNull()?.javaClass?.simpleName ?: "ответ не похож на Cloudflare") + "|$now"
        }
    }
}
