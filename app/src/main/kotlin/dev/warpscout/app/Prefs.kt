package dev.warpscout.app

import android.content.Context
import dev.warpscout.core.junk.JunkLibrary
import dev.warpscout.core.model.JunkProfile
import dev.warpscout.core.net.EndpointPool
import dev.warpscout.core.net.EndpointSpec
import dev.warpscout.core.net.NetSettings
import dev.warpscout.core.net.PoolMode
import dev.warpscout.core.presets.Presets
import dev.warpscout.core.presets.RoutePresets
import dev.warpscout.core.state.ServiceSettings
import dev.warpscout.core.tune.TuningSpec

/**
 * Всё, что пользователь настроил в интерфейсе. Хранится в SharedPreferences; приватный ключ
 * сюда не попадает — для него есть [KeyVault] (AndroidKeyStore).
 */
class Prefs(private val context: Context) {

    private val sp = context.getSharedPreferences("warpscout", Context.MODE_PRIVATE)

    init {
        // Раньше был один переключатель «split-tunnel: whitelist» (ключ «whitelist», по умолчанию
        // включён). Он стал 4-позиционным режимом + списочным режимом — мигрируем молча, чтобы у
        // обновившихся людей поведение не поменялось: включённый whitelist = пресет маршрутов.
        if (!sp.getBoolean("routesMigrated", false)) {
            val edit = sp.edit().putBoolean("routesMigrated", true)
            val wasWhitelist = if (sp.contains("whitelist")) sp.getBoolean("whitelist", true) else true
            if (wasWhitelist && sp.getInt("routesMode", 0) == 0) edit.putInt("routesMode", 1)
            edit.remove("whitelist").apply()
        }
    }
    private val junkNames = JunkLibrary.defaultPool().map { it.name }

    var hostsText: String
        get() = sp.getString("hosts", "") ?: ""
        set(v) = sp.edit().putString("hosts", v).apply()

    /** «500-510, 2408» — пусто = порты генератора. */
    var portsText: String
        get() = sp.getString("ports", "") ?: ""
        set(v) = sp.edit().putString("ports", v).apply()

    var endpointCount: Int
        get() = sp.getInt("count", 120)
        set(v) = sp.edit().putInt("count", v.coerceIn(4, 4000)).apply()

    var dnsIndex: Int
        get() = sp.getInt("dns", 0)
        set(v) = sp.edit().putInt("dns", v).apply()

    var keepalive: Int
        get() = sp.getInt("keepalive", 25)
        set(v) = sp.edit().putInt("keepalive", v.coerceIn(0, 120)).apply()

    var mtu: Int
        get() = sp.getInt("mtu", 1280)
        set(v) = sp.edit().putInt("mtu", v.coerceIn(576, 1420)).apply()

    var enableIpv6: Boolean
        get() = sp.getBoolean("ipv6", true)
        set(v) = sp.edit().putBoolean("ipv6", v).apply()

    var checkResources: Boolean
        get() = sp.getBoolean("resources", true)
        set(v) = sp.edit().putBoolean("resources", v).apply()

    var verifyInTunnel: Boolean
        get() = sp.getBoolean("tunnel_verify", false)
        set(v) = sp.edit().putBoolean("tunnel_verify", v).apply()

    /** Включённые профили шума (по именам из [JunkLibrary]). */
    var enabledJunk: Set<String>
        get() = sp.getStringSet("junk", junkNames.toSet()) ?: junkNames.toSet()
        set(v) = sp.edit().putStringSet("junk", v).apply()

    var scheduleOn: Boolean
        get() = sp.getBoolean("schedule", false)
        set(v) = sp.edit().putBoolean("schedule", v).apply()

    /** С какой пары «адрес:порт» начинать перебор: ротация между попытками подключения. */
    var endpointCursor: Int
        get() = sp.getInt("endpointCursor", 0)
        set(v) = sp.edit().putInt("endpointCursor", v).apply()

    /** Второй выход: свой сервер (WireGuard/AmneziaWG) для выбранных подсетей. */
    var secondExitOn: Boolean
        get() = sp.getBoolean("secondExitOn", false)
        set(v) {
            sp.edit().putBoolean("secondExitOn", v).apply()
            pushToService()
        }

    /** Конфиг второго выхода: текст [Interface]/[Peer] от своего сервера. */
    var secondConf: String
        get() = sp.getString("secondConf", "").orEmpty()
        set(v) {
            sp.edit().putString("secondConf", v).apply()
            pushToService()
        }

    /** Домены, которые должны идти через второй выход (для человека и для повторного сбора IP). */
    var secondDomains: String
        get() = sp.getString("secondDomains", "").orEmpty()
        set(v) = sp.edit().putString("secondDomains", v).apply()

    /** Развёрнутые в CIDR адреса этих доменов — ровно их и раскладывает ExitRouter. */
    var secondCidrs: String
        get() = sp.getString("secondCidrs", "").orEmpty()
        set(v) {
            sp.edit().putString("secondCidrs", v).apply()
            pushToService()
        }

    /** Период фонового подбора в часах: 0 — выключено. */
    var scheduleHours: Int
        get() = sp.getInt("scheduleHours", 6).coerceIn(0, 24)
        set(v) = sp.edit().putInt("scheduleHours", v.coerceIn(0, 24)).apply()

    /**
     * Все настройки разом — для бекапа. Приватный ключ из [KeyVault] сюда не входит (он в
     * AndroidKeyStore), но текст рабочего конфига содержит свой ключ, поэтому поднять туннель
     * из восстановленного бекапа можно и на другом устройстве.
     */
    fun snapshot(): Map<String, *> = sp.all

    /** Восстановление из бекапа: пишем только известные типы, мусор игнорируем. */
    fun restoreAll(values: Map<String, Any?>) {
        val edit = sp.edit()
        values.forEach { (key, value) ->
            when (value) {
                is String -> edit.putString(key, value)
                is Int -> edit.putInt(key, value)
                is Long -> edit.putLong(key, value)
                is Boolean -> edit.putBoolean(key, value)
                is Float -> edit.putFloat(key, value)
                is Set<*> -> edit.putStringSet(key, value.map { it.toString() }.toSet())
            }
        }
        edit.apply()
        pushToService()
    }

    /** .conf, импортированный вручную: используется, если генератор недоступен. */
    var manualConf: String
        get() = sp.getString("manual_conf", "") ?: ""
        set(v) = sp.edit().putString("manual_conf", v).apply()

    var concurrency: Int
        get() = sp.getInt("concurrency", 48)
        set(v) = sp.edit().putInt("concurrency", v.coerceIn(4, 256)).apply()

    var attempts: Int
        get() = sp.getInt("attempts", 3)
        set(v) = sp.edit().putInt("attempts", v.coerceIn(1, 8)).apply()

    var timeoutMs: Int
        get() = sp.getInt("timeout", 1200)
        set(v) = sp.edit().putInt("timeout", v.coerceIn(300, 8000)).apply()

    /** 0 — пул генератора, 1 — только MASQUE, 2 — полный перебор. Выбирается кнопками в UI. */
    var poolMode: Int
        get() = sp.getInt("poolMode", POOL_DEFAULT)
        set(v) = sp.edit().putInt("poolMode", v.coerceIn(0, 2)).apply()

    /** Поднимать/переподнимать собственный туннель сразу после подбора (сборка tunnel). */
    // ---- экспорт: под кого компилируем, какой сервер, какие каналы ----

    /** 0 = AmneziaWG, 1 = обычный WireGuard, 2 = Clash YAML, 3 = только маршруты. */
    var confTarget: Int
        get() = sp.getInt("confTarget", 0)
        set(v) = sp.edit().putInt("confTarget", v.coerceIn(0, 3)).apply()

    /** «Сервер» вручную: `host:port`. Пусто — берём лучший по итогам подбора. */
    var pinnedEndpoint: String
        get() = sp.getString("pinnedEndpoint", "").orEmpty().trim()
        set(v) = sp.edit().putString("pinnedEndpoint", v.trim()).apply()

    /** Профиль шума для выбранного сервера (пусто = тот, что у лучшего кандидата). */
    var pinnedJunk: String
        get() = sp.getString("pinnedJunk", "").orEmpty().trim()
        set(v) = sp.edit().putString("pinnedJunk", v.trim()).apply()

    /** 0 = весь трафик, 1 = встроенный whitelist-пресет, 2 = по спискам allow-domains, 3 = вручную. */
    var routesMode: Int
        get() = sp.getInt("routesMode", 0)
        set(v) = sp.edit().putInt("routesMode", v.coerceIn(0, 3)).apply()

    /** Готовый AllowedIPs: сгенерированный из списков или вписанный руками (режимы 2 и 3). */
    var allowedIpsText: String
        get() = sp.getString("allowedIps", "").orEmpty()
        set(v) = sp.edit().putString("allowedIps", v.trim()).apply()

    var routesGeneratedAt: Long
        get() = sp.getLong("routesGeneratedAt", 0L)
        set(v) = sp.edit().putLong("routesGeneratedAt", v).apply()

    /** Категории allow-domains: что туннелируем и что сознательно оставляем снаружи. */
    /**
     * Разделение трафика ПО ПРИЛОЖЕНИЯМ (как в Amnezia): 0 — всё через туннель,
     * 1 — только отмеченные, 2 — все, кроме отмеченных.
     */
    var appsMode: Int
        get() = sp.getInt("appsMode", APPS_ALL)
        set(v) {
            sp.edit().putInt("appsMode", v).apply()
            pushToService()
        }

    /** Пакеты, выбранные в режимах «только» и «кроме» (один список на оба режима). */
    var appsSelected: Set<String>
        get() = sp.getStringSet("appsSelected", emptySet()).orEmpty()
        set(v) {
            sp.edit().putStringSet("appsSelected", v).apply()
            pushToService()
        }

    var allowBlockIds: Set<String>
        get() = sp.getStringSet("allowBlock", null) ?: dev.warpscout.core.lists.AllowLists.DEFAULT_BLOCK_IDS.toSet()
        set(v) = sp.edit().putStringSet("allowBlock", v).apply()

    var allowDirectIds: Set<String>
        get() = sp.getStringSet("allowDirect", null)
            ?: dev.warpscout.core.lists.AllowLists.bySide(dev.warpscout.core.lists.ListSide.DIRECT)
                .map { it.id }.toSet()
        set(v) = sp.edit().putStringSet("allowDirect", v).apply()

    /** Сколько доменов максимум разворачиваем в маршруты (DoH-запросов будет в два раза больше). */
    var routeDomainBudget: Int
        get() = sp.getInt("routeBudget", 220)
        set(v) = sp.edit().putInt("routeBudget", v.coerceIn(0, 1200)).apply()

    /** true — в подбор добавляются проверки по загруженным спискам (и «заблокированное», и «_ru-side_»). */
    var checkByLists: Boolean
        get() = sp.getBoolean("checkByLists", false)
        set(v) = sp.edit().putBoolean("checkByLists", v).apply()

    /** Адрес SOCKS5-прокси ByeDPI ('' = не использовать). */
    var byedpiProxy: String
        get() = sp.getString("byedpiProxy", "") ?: ""
        set(v) = sp.edit().putString("byedpiProxy", v.trim()).apply()

    /** true — базовые замеры во время подбора идут через ByeDPI, а не напрямую. */
    var tuneViaByedpi: Boolean
        get() = sp.getBoolean("tuneViaByedpi", false)
        set(v) = sp.edit().putBoolean("tuneViaByedpi", v).apply()

    var autoApply: Boolean
        get() = sp.getBoolean("autoApply", false)
        set(v) = sp.edit().putBoolean("autoApply", v).apply()

    /** Когда последний раз заканчивался подбор — чтобы на экране было видно «это свежий конфиг». */
    var lastTunedAt: Long
        get() = sp.getLong("lastTunedAt", 0L)
        set(v) = sp.edit().putLong("lastTunedAt", v).apply()

    /**
     * Последний конфиг, которым поднимали туннель (текст WireGuard/AmneziaWG). Нужен плитке
     * быстрых настроек: она подключает «то же, что в прошлый раз», не собирая конфиг заново.
     */
    /** Последняя точка входа, которая реально поднялась: её пробуем раньше «сегодняшней». */
    var lastEndpoint: String
        get() = sp.getString("lastEndpoint", "").orEmpty()
        set(v) = sp.edit().putString("lastEndpoint", v).apply()

    /** Регион выхода, определённый последним подключением (colo · страна · адрес). */
    var lastExitRegion: String
        get() = sp.getString("lastExitRegion", "").orEmpty()
        set(v) = sp.edit().putString("lastExitRegion", v).apply()

    var lastConfigText: String
        get() = sp.getString("lastConfigText", "").orEmpty()
        set(v) = sp.edit().putString("lastConfigText", v).apply()

    var lastTunedEndpoint: String
        get() = sp.getString("lastTunedEndpoint", "").orEmpty()
        set(v) = sp.edit().putString("lastTunedEndpoint", v).apply()

    var lastTunedScore: Int
        get() = sp.getInt("lastTunedScore", 0)
        set(v) = sp.edit().putInt("lastTunedScore", v).apply()

    /** Когда endpoint реально сменился: «новый конфиг» ≠ «тот же, просто перепроверен». */
    var lastChangedAt: Long
        get() = sp.getLong("lastChangedAt", 0L)
        set(v) = sp.edit().putLong("lastChangedAt", v).apply()

    val junkPool: List<JunkProfile>
        get() = JunkLibrary.defaultPool().filter { it.name in enabledJunk }
            .ifEmpty { listOf(JunkLibrary.none()) }

    /**
     * Что именно сканить.
     *
     *  • поле «IP или подсети» пустое — берём пул самого генератора (подсети Cloudflare × порты);
     *  • строки вида `1.2.3.4:500`, `engage.cloudflareclient.com:443`, `188.114.96.1-10:443`,
     *    `8.6.112.*:943` — сканируем ровно их (режим EXPLICIT, звёздочка и диапазоны разбираются ядром);
     *  • строка без порта — к ней применяются порты из второго поля (или все 52 порта AWG, если поле
     *    портов пустое).
     */
    fun endpointSpec(): EndpointSpec {
        val lines = hostsText.split('\n', ',').map { it.substringBefore('#').trim() }.filter { it.isNotEmpty() }
        val ports = portsText.split(',', ' ', '\n').mapNotNull { it.trim().toIntOrNull() }
        val seed = System.currentTimeMillis() / (24L * 3600_000L)   // один и тот же пул в течение суток
        val mode = when (poolMode) {
            POOL_MASQUE -> PoolMode.STRATIFIED
            POOL_FULL -> PoolMode.FULL
            else -> if (endpointCount >= 900) PoolMode.FULL else PoolMode.STRATIFIED
        }
        val base = when (poolMode) {
            POOL_MASQUE -> EndpointSpec(
                subnets = dev.warpscout.core.net.WarpDefaults.MASQUE_SUBNETS,
                ports = if (ports.isEmpty()) dev.warpscout.core.net.WarpDefaults.MASQUE_PORTS else ports,
                mode = mode, maxEndpoints = endpointCount, seed = seed
            )
            POOL_FULL -> EndpointSpec(mode = PoolMode.FULL, maxEndpoints = endpointCount, seed = seed)
            else -> EndpointSpec(
                ports = if (ports.isEmpty()) dev.warpscout.core.net.WarpDefaults.AWG_PORTS else ports,
                mode = mode, maxEndpoints = endpointCount, seed = seed
            )
        }
        if (lines.isEmpty()) return base
        // Набран свой список: он важнее режима (режим тогда только про «сколько» и про FULL/STRATIFIED).
        val explicit = lines.flatMap { line ->
            val p = if (line.contains(':')) null else ports
            when {
                line.contains(':') -> listOf(line)
                p != null && p.isNotEmpty() -> p.map { "$line:$it" }
                else -> listOf("$line:*")
            }
        }
        return base.copy(subnets = emptyList(), hostnames = explicit, mode = PoolMode.EXPLICIT,
            maxEndpoints = maxOf(endpointCount, explicit.size))
    }

    fun confTargetEnum(): dev.warpscout.core.config.ConfTarget =
        dev.warpscout.core.config.ConfTarget.values()[confTarget.coerceIn(0, 3)]

    fun routesModeName(): String = when (routesMode) {
        1 -> "whitelist-пресет"
        2 -> "по спискам allow-domains"
        3 -> "вручную"
        else -> "весь трафик"
    }

    /**
     * Что реально попадёт в `AllowedIPs`.
     *
     * Режим 2 берёт уже собранный план (его генерирует кнопка «Собрать маршруты»: домены
     * разворачиваются в /32 и /128 через DoH, потому что WireGuard не умеет правила по именам).
     * Если плана нет — честно возвращаем «весь трафик», а не пустой конфиг, в котором ничего не едет.
     */
    fun allowedIps(): String {
        val plan = allowedIpsText
        val raw = when (routesMode) {
            1 -> dev.warpscout.core.presets.RoutePresets.BYPASS_WHITELIST_CSV
            2 -> plan.ifBlank { "0.0.0.0/0, ::/0" }
            3 -> plan.ifBlank { "0.0.0.0/0, ::/0" }
            else -> "0.0.0.0/0, ::/0"
        }
        if (enableIpv6) return raw
        // Без IPv6-адреса в туннеле маршрут ::/0 — чёрная дыра: браузер радостно выбирает IPv6
        // и половина сайтов «не открывается», хотя туннель поднят. Поэтому при выключенном IPv6
        // v6-маршруты не выпускаем вовсе.
        val v4 = raw.split(',').map { it.trim() }.filter { it.isNotEmpty() && !it.contains(':') }
        return if (v4.isEmpty()) "0.0.0.0/0" else v4.joinToString(", ")
    }

    /** Проверки по спискам: берём кеш `.lst` и превращаем в canary-запросы. */
    fun listChecks(limitPerList: Int = 3): List<dev.warpscout.core.model.ResourceCheck> {
        if (!checkByLists) return emptyList()
        val store = allowListStore()
        val picked = dev.warpscout.core.lists.AllowLists.loadAll(store)
        val out = mutableListOf<dev.warpscout.core.model.ResourceCheck>()
        for (list in dev.warpscout.core.lists.AllowLists.ALL) {
            val wantIds = if (list.side == dev.warpscout.core.lists.ListSide.BLOCK) allowBlockIds else allowDirectIds
            if (list.id !in wantIds) continue
            val cached = picked[list.id] ?: continue
            out += dev.warpscout.core.lists.AllowLists.checksFor(list, cached.parsed, limitPerList)
        }
        return out
    }

    /**
     * Донести «сервисные» настройки до процесса туннеля. SharedPreferences между процессами
     * расходятся (у каждого своя копия в памяти), поэтому сервис читает отдельный снимок в файле,
     * который переписывается здесь при каждом изменении.
     */
    private fun pushToService() {
        dev.warpscout.app.status.ServiceSettingsStore.write(
            context,
            ServiceSettings(
                secondExitOn = secondExitOn,
                secondConf = secondConf,
                secondCidrs = secondCidrs,
                appsMode = appsMode,
                appsSelected = appsSelected.toList().sorted(),
            )
        )
    }

    /** Куда класть скачанные списки. */
    fun allowListStore(): dev.warpscout.core.lists.FileListStore =
        dev.warpscout.core.lists.FileListStore(java.io.File(context.filesDir, "allowlists"))

    /** Как объяснить пользователю, что он сейчас выбрал. */
    fun poolModeName(): String = when (poolMode) {
        POOL_MASQUE -> "Только MASQUE"
        POOL_FULL -> "Полный перебор"
        else -> "Пул генератора"
    }

    fun tuningSpec(): TuningSpec = TuningSpec(
        endpointSpec = endpointSpec(),
        junkProfiles = junkPool,
        net = NetSettings(attempts = attempts, timeoutMs = timeoutMs, concurrency = concurrency),
        resources = if (checkResources) Presets.RESOURCE_CHECKS + listChecks() else emptyList(),
        dns = Presets.DNS[dnsIndex.coerceIn(0, Presets.DNS.size - 1)].servers,
        mtu = mtu,
        allowedIps = allowedIps(),
        keepalive = keepalive.takeIf { it > 0 },
        enableIpv6Address = enableIpv6,
        checkBaselineResources = checkResources,
        verifyThroughTunnel = verifyInTunnel,
        tunnelSettleMs = 8000
    )

    companion object {
        const val POOL_DEFAULT = 0

        // Значения берутся из общей модели: сервис и интерфейс не должны разойтись в нумерации.
        const val APPS_ALL = ServiceSettings.APPS_ALL
        const val APPS_ONLY = ServiceSettings.APPS_ONLY
        const val APPS_EXCEPT = ServiceSettings.APPS_EXCEPT
        const val POOL_MASQUE = 1
        const val POOL_FULL = 2

        const val MIRROR_NOTE = "Ключи берутся из публичного генератора (warp-api.cfd); вводить PrivateKey не нужно."
    }
}
