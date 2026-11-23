package dev.warpscout.app

import android.content.Context
import android.os.Build
import dev.warpscout.core.lists.AllowListPlanner
import dev.warpscout.core.lists.AllowLists
import dev.warpscout.core.lists.SiteList
import dev.warpscout.core.net.CfTrace
import dev.warpscout.core.net.ExitCheck
import dev.warpscout.core.tunnel.ExitRouter

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
 * С 1.10.32 — на адрес, который точно лежит в таблице второго выхода, и с честным разбором ответа
 * (см. ExitCheck): «ушло через WARP» больше не выдаётся за «свой сервер в России».
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

    /**
     * Правила сборки: поменялись — адреса собираются заново при первом удобном случае, не дожидаясь
     * суток (см. [rulesChanged]). В подпись выбора они не входят: иначе экран писал бы «выбор сайтов
     * поменялся», хотя человек ничего не трогал. 1 — 1.10.35: поддомены сервисов (AllowLists.EXTRA_HOSTS);
     * 2 — 1.10.38: Grok (grok.com, x.ai — xAI отказывает российским адресам).
     */
    const val RULES = 2

    /** Адреса собраны прежними правилами — пора собрать заново. */
    fun rulesChanged(prefs: Prefs): Boolean = prefs.secondRules != RULES

    /** Что собирали — по этой подписи видно, что выбор поменялся и адреса пора собрать заново. */
    fun signature(prefs: Prefs): String =
        prefs.secondSources.sorted().joinToString(",") + "|" + prefs.secondDomains.trim()

    /** Пора ли собирать: выбор поменялся, адресов нет или они старше суток. */
    fun needsBuild(prefs: Prefs, now: Long = System.currentTimeMillis()): Boolean =
        prefs.secondExitOn && prefs.secondConf.isNotBlank() &&
            (prefs.secondCidrs.isBlank() || signature(prefs) != prefs.secondBuiltSig ||
                rulesChanged(prefs) || now - prefs.secondRoutesAt > STALE_MS)

    /**
     * Собрать адреса: скачать нужные списки (нет в кеше или старше недели), домены → адреса через
     * DoH. Долго (секунды–минута) и с сетью — звать не из UI-потока. [progress] (с 1.10.32) —
     * «адреса найдены у N из M сайтов», из потоков DoH: по нему кнопка показывает, что работа идёт.
     * Он стоит перед [log]: прежние вызовы `build(…) { строка -> … }` отдают лямбду последнему
     * параметру — журналу, как и раньше.
     */
    fun build(context: Context, prefs: Prefs, progress: ((Int, Int) -> Unit)? = null, log: (String) -> Unit): Result {
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
        // Поддомены сервисов, которых нет в списках (с 1.10.35, см. AllowLists.EXTRA_HOSTS): вход в
        // ChatGPT — auth.openai.com, а в списке только openai.com, и вход уходил через WARP.
        val extraHosts = LinkedHashSet<String>()
        ids.forEach { id -> AllowLists.EXTRA_HOSTS[id]?.let { extraHosts += it } }
        extraHosts.removeAll(ownHosts)
        extraHosts.removeAll(listHosts)
        val all = ownHosts.toList() + listHosts.toList() + extraHosts.toList()
        log("второй выход: разворачиваю ${all.size} сайтов в адреса через DoH…")
        val resolved = AllowListPlanner.resolveAll(all, progress = progress)
        // Поддомены сервисов — вместе со своими сайтами, в начало: при обрезке по MAX_CIDRS вход в
        // ChatGPT не должен уступить место хвосту большого списка.
        val first = SiteList.cidrs(
            SiteList.Parsed(emptyList(), own.prefixes, emptyList()),
            resolved.filterKeys { it in ownHosts || it in extraHosts }
        )
        val rest = SiteList.cidrs(
            SiteList.Parsed(emptyList(), listPrefixes.toList(), emptyList()),
            resolved.filterKeys { it !in ownHosts && it !in extraHosts }
        )
        val cidrs = LinkedHashSet<String>().apply {
            addAll(first)
            addAll(rest)
        }.toList()
        // Поддомены, которых нет в DNS, — не ошибка списка: в «не найдено» их не считаем.
        val unresolved = resolved.count { it.value.isEmpty() && it.key !in extraHosts }
        return Result(cidrs.take(MAX_CIDRS), all.size - extraHosts.size, unresolved, missing)
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
        prefs.secondRules = RULES
        return changed
    }

    /**
     * Из какой страны выходит второй выход (с 1.10.32 — точно): запрос через туннель к chatgpt.com,
     * но на тот его адрес, что лежит в таблице второго выхода, и с именем сайта в TLS. В 1.10.31
     * адрес выбирала система: не совпал с собранными — запрос шёл через WARP, и экран писал «свой
     * сервер отвечает из России». Строка для [Prefs.secondCheck] — см. ExitCheck.Result.
     * С сетью и до 7 с — не из UI-потока.
     */
    fun checkExit(context: Context, prefs: Prefs): String {
        val now = System.currentTimeMillis()
        val router = ExitRouter.of(ExitRouter.parse(prefs.secondCidrs))
        if (router.isEmpty) return ExitCheck.Result(ExitCheck.FAIL, "адресов второго выхода нет", now).encode()
        // Адрес chatgpt.com — сначала как его видит телефон, потом через DoH (так собирались адреса).
        val system = runCatching {
            java.net.InetAddress.getAllByName(CHECK_HOST).mapNotNull { it.hostAddress }
        }.getOrDefault(emptyList())
        val ip = ExitCheck.pickRouted(system, router)
            ?: ExitCheck.pickRouted(runCatching { AllowListPlanner.dohResolve(CHECK_HOST) }.getOrDefault(emptyList()), router)
            ?: return ExitCheck.Result(ExitCheck.FAIL, "адрес $CHECK_HOST не попал во второй выход — обновите адреса", now).encode()
        // Адрес в таблице есть, но не в маршрутах туннеля (раздельный режим, адреса собраны после
        // подключения): запрос ушёл бы мимо туннеля. Так и говорим — нужно переподключение.
        if (vpnCovers(context, ip) == false) return ExitCheck.Result(ExitCheck.NOT_ROUTED, ip, now).encode()
        val t0 = android.os.SystemClock.elapsedRealtime()
        val body = runCatching {
            ExitCheck.fetchTrace(
                ip, CHECK_HOST, 7000, "WarpScout/${BuildConfig.VERSION_NAME}",
                verify = { host, session -> javax.net.ssl.HttpsURLConnection.getDefaultHostnameVerifier().verify(host, session) }
            )
        }
        val ms = (android.os.SystemClock.elapsedRealtime() - t0).toInt()
        val error = body.exceptionOrNull()?.let { (it.message ?: it.javaClass.simpleName).take(90) }
        return ExitCheck.verdict(CfTrace.parse(body.getOrNull()), error, now, ms).encode()
    }

    /**
     * Маршруты работающего VPN (только обычные, unicast); null — VPN не найден или Android их не
     * отдал. В раздельном режиме адреса второго выхода попадают в маршруты только при подключении:
     * собранные позже ждут переподключения.
     */
    private fun vpnRoutes(context: Context): List<android.net.RouteInfo>? = runCatching {
        val cm = context.getSystemService(android.net.ConnectivityManager::class.java) ?: return null
        @Suppress("DEPRECATION")
        val vpn = cm.allNetworks.firstOrNull { n ->
            cm.getNetworkCapabilities(n)?.hasTransport(android.net.NetworkCapabilities.TRANSPORT_VPN) == true
        } ?: return null
        cm.getLinkProperties(vpn)?.routes.orEmpty()
            .filter { r -> Build.VERSION.SDK_INT < 29 || r.type == android.net.RouteInfo.RTN_UNICAST }
            .ifEmpty { null }
    }.getOrNull()

    /** Адрес-запись («104.18.32.47», «1.2.3.0/24») → InetAddress без DNS; null — не адрес. */
    private fun addressOf(text: String): java.net.InetAddress? {
        val host = text.substringBefore('/').trim()
        // Сначала — что это запись адреса: ipBytes на имени сайта пошёл бы в DNS.
        if (!ExitCheck.isIpLiteral(host)) return null
        val bytes = ExitRouter.ipBytes(host) ?: return null
        return runCatching { java.net.InetAddress.getByAddress(bytes) }.getOrNull()
    }

    /** Входит ли адрес в маршруты VPN: true / false; null — не узнать (VPN не найден). */
    fun vpnCovers(context: Context, ip: String): Boolean? {
        val routes = vpnRoutes(context) ?: return null
        val addr = addressOf(ip) ?: return null
        return routes.any { runCatching { it.matches(addr) }.getOrDefault(false) }
    }

    /** Сколько адресов из [cidrs] не входит в маршруты VPN; null — не узнать. Маршруты берутся один раз. */
    fun uncovered(context: Context, cidrs: Collection<String>): Int? {
        val routes = vpnRoutes(context) ?: return null
        return cidrs.count { cidr ->
            val addr = addressOf(cidr) ?: return@count false
            routes.none { runCatching { it.matches(addr) }.getOrDefault(false) }
        }
    }
}
