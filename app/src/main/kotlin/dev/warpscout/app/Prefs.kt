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
        // 1.10.30: проверка доступности через туннель при подборе включается один раз для всех —
        // так решил человек («по кнопке и при подборе»). Раньше переключатель сохранялся
        // выключенным при каждом подборе, и одна смена умолчания до обновившихся не дошла бы.
        if (!sp.getBoolean("availMigrated", false)) {
            sp.edit().putBoolean("availMigrated", true).putBoolean("tunnel_verify", true).apply()
        }
        // 1.10.40: шум «как Chrome» (JunkLibrary.chrome) — новый профиль. Набор включённых профилей
        // хранится, как только настройки сохранили хоть раз, и новое имя в него само не попадёт: подбор
        // его бы не проверял. Добавляем один раз; снять галочку можно, как с любого профиля.
        if (!sp.getBoolean("junkChromeAdded", false)) {
            val edit = sp.edit().putBoolean("junkChromeAdded", true)
            sp.getStringSet("junk", null)?.let { stored ->
                edit.putStringSet("junk", HashSet(stored).apply { add(JunkLibrary.chrome().name) })
            }
            edit.apply()
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

    /** Адреса выбранного DNS для конфига: найденные по имени и запасные (см. [DnsBook]). */
    fun dnsServers(): List<String> = DnsBook.servers(context, dnsIndex)

    var keepalive: Int
        get() = sp.getInt("keepalive", 25)
        set(v) = sp.edit().putInt("keepalive", v.coerceIn(0, 120)).apply()

    var mtu: Int
        get() = sp.getInt("mtu", 1280)
        set(v) = sp.edit().putInt("mtu", v.coerceIn(576, 1420)).apply()

    var enableIpv6: Boolean
        get() = sp.getBoolean("ipv6", true)
        set(v) {
            sp.edit().putBoolean("ipv6", v).apply()
            // Маршруты сервис берёт из снимка (с 1.10.33) — снимок следует за настройкой.
            pushToService()
        }

    var checkResources: Boolean
        get() = sp.getBoolean("resources", true)
        set(v) = sp.edit().putBoolean("resources", v).apply()

    /**
     * При подборе проверять доступность через туннель у трёх лучших точек. С 1.10.30 включено по
     * умолчанию: так выбрал человек («по кнопке и при подборе»), и только так список «Доступность»
     * показывает то, что откроется через туннель, а не без VPN.
     */
    var verifyInTunnel: Boolean
        get() = sp.getBoolean("tunnel_verify", true)
        set(v) = sp.edit().putBoolean("tunnel_verify", v).apply()

    /** Какие сервисы проверять (коды из Presets.SERVICE_CHECKS, с 1.10.30). По умолчанию — все. */
    var availServices: Set<String>
        get() = sp.getStringSet("availServices", null)?.toSet() ?: Presets.SERVICE_CHECKS.map { it.id }.toSet()
        set(v) = sp.edit().putStringSet("availServices", v.toSet()).apply()

    /** Свои сайты для проверки доступности: по одному в строке (с 1.10.30). */
    var availCustom: String
        get() = sp.getString("availCustom", "").orEmpty()
        set(v) = sp.edit().putString("availCustom", v).apply()

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

    /**
     * Какие списки «не работает с российских адресов» идут через второй выход (с 1.10.31). Сайты
     * берутся из них сами — вписывать их руками не нужно; свои сайты — в [secondDomains].
     */
    var secondSources: Set<String>
        get() = sp.getStringSet("secondSources", null) ?: SecondRoutes.DEFAULT_SOURCES
        set(v) = sp.edit().putStringSet("secondSources", v).apply()

    /** Когда адреса второго выхода собраны в последний раз (мс; 0 — ещё ни разу). */
    var secondRoutesAt: Long
        get() = sp.getLong("secondRoutesAt", 0L)
        set(v) = sp.edit().putLong("secondRoutesAt", v).apply()

    /** Сводка последней сборки для экрана: «сайтов 489 → адресов 1520». */
    var secondRoutesNote: String
        get() = sp.getString("secondRoutesNote", "").orEmpty()
        set(v) = sp.edit().putString("secondRoutesNote", v).apply()

    /** Что собирали: списки и свои сайты. Изменились — адреса пора собрать заново. */
    var secondBuiltSig: String
        get() = sp.getString("secondBuiltSig", "").orEmpty()
        set(v) = sp.edit().putString("secondBuiltSig", v).apply()

    /** Какими правилами собраны адреса второго выхода (см. SecondRoutes.RULES; 0 — до 1.10.35). */
    var secondRules: Int
        get() = sp.getInt("secondRules", 0)
        set(v) = sp.edit().putInt("secondRules", v).apply()

    /** Второй выход внутри WARP (по умолчанию) или напрямую — см. ServiceSettings.secondViaWarp. */
    var secondViaWarp: Boolean
        get() = sp.getBoolean("secondViaWarp", true)
        set(v) {
            sp.edit().putBoolean("secondViaWarp", v).apply()
            pushToService()
        }

    /** Последняя проверка выхода: «DE|1.2.3.4|время» или «!|причина|время». */
    var secondCheck: String
        get() = sp.getString("secondCheck", "").orEmpty()
        set(v) = sp.edit().putString("secondCheck", v).apply()

    /**
     * Proton VPN Free (с 1.10.31): страна второго выхода — код («NL»), пусто — любая, ближние
     * первыми. Сервер в этой стране приложение выбирает само (см. SecondProton).
     */
    var secondProtonCountry: String
        get() = sp.getString("secondProtonCountry", "").orEmpty()
        set(v) {
            sp.edit().putString("secondProtonCountry", v).apply()
            pushToService()
        }

    /** Сервер Proton, на котором второй выход работал последним: с него и начинается перебор. */
    var secondProtonLast: String
        get() = sp.getString("secondProtonLast", "").orEmpty()
        set(v) {
            if (v == secondProtonLast) return
            sp.edit().putString("secondProtonLast", v).apply()
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

    /**
     * Сброс по умолчанию (с 1.10.32): все настройки — как после установки. commit, а не apply: сразу
     * после сброса экран создаётся заново и должен прочитать уже пустые настройки. Разовые переносы
     * из init (маршруты, проверка через туннель) отработают снова при следующем создании Prefs —
     * ровно как при первом запуске.
     */
    fun clearAll() {
        sp.edit().clear().commit()
        pushToService()
    }

    /**
     * Восстановление из бекапа: настройки становятся такими, как в копии («будут заменены» — так и
     * написано в вопросе). До 1.10.40 значения дописывались поверх текущих, и на свежей установке её
     * отметки разовых переносов (init) оставались: копия из прошлой версии не получала, например, шум
     * «как Chrome». Теперь сначала всё стирается, а переносы отрабатывают при следующем создании Prefs
     * (Backup.restoreText создаёт его сразу). commit, а не apply: экран тут же читает настройки заново.
     * Пишем только известные типы, мусор игнорируем.
     */
    fun restoreAll(values: Map<String, Any?>) {
        val edit = sp.edit().clear()
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
        edit.commit()
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
        set(v) {
            sp.edit().putInt("routesMode", v.coerceIn(0, 3)).apply()
            // Маршруты сервис берёт из снимка (с 1.10.33) — снимок следует за настройкой.
            pushToService()
        }

    /** Готовый AllowedIPs: сгенерированный из списков или вписанный руками (режимы 2 и 3). */
    var allowedIpsText: String
        get() = sp.getString("allowedIps", "").orEmpty()
        set(v) {
            sp.edit().putString("allowedIps", v.trim()).apply()
            // Маршруты сервис берёт из снимка (с 1.10.33) — снимок следует за настройкой.
            pushToService()
        }

    /**
     * «Сайты» вкладки «Туннелирование» (с 1.10.31): домены, адреса и подсети — как вписаны.
     * Режим маршрутов 3 («только мои сайты») пускает через туннель ровно их.
     */
    var tunnelSites: String
        get() = sp.getString("tunnelSites", "").orEmpty()
        set(v) {
            sp.edit().putString("tunnelSites", v).apply()
            // Маршруты сервис берёт из снимка (с 1.10.33) — снимок следует за настройкой.
            pushToService()
        }

    /** Адреса этих сайтов (CIDR через запятую), развёрнутые через DoH. */
    var tunnelSitesCidrs: String
        get() = sp.getString("tunnelSitesCidrs", "").orEmpty()
        set(v) {
            sp.edit().putString("tunnelSitesCidrs", v.trim()).apply()
            // Маршруты сервис берёт из снимка (с 1.10.33) — снимок следует за настройкой.
            pushToService()
        }

    /** Текст поля на момент сборки: поле правили — адреса пора собрать заново. */
    var tunnelSitesSig: String
        get() = sp.getString("tunnelSitesSig", "").orEmpty()
        set(v) = sp.edit().putString("tunnelSitesSig", v).apply()

    var tunnelSitesAt: Long
        get() = sp.getLong("tunnelSitesAt", 0L)
        set(v) = sp.edit().putLong("tunnelSitesAt", v).apply()

    var routesGeneratedAt: Long
        get() = sp.getLong("routesGeneratedAt", 0L)
        set(v) = sp.edit().putLong("routesGeneratedAt", v).apply()

    /** Какие списки были отмечены, когда собирались маршруты (с 1.10.31): поменяли — собрать заново. */
    var listsBuiltSig: String
        get() = sp.getString("listsBuiltSig", "").orEmpty()
        set(v) = sp.edit().putString("listsBuiltSig", v).apply()

    /**
     * Какие списки отмечены и по каким правилам собраны маршруты — по подписи видно, что выбор
     * или правила поменялись после сборки ([listsBuiltSig] — подпись на момент сборки). Версия
     * правил — с 1.10.33: сети Google для видео YouTube из 1.10.31 не дошли до телефона, потому что
     * маршруты пересобирались только при смене отметок.
     */
    fun listsSignature(): String =
        "v${dev.warpscout.core.lists.AllowListPlanner.VERSION};" +
            (allowBlockIds.sorted() + listOf("|") + allowDirectIds.sorted()).joinToString(",")

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
    /**
     * Набор по умолчанию (Telegram, Instagram, YouTube, Facebook, X — см. DefaultApps) уже
     * применён: «только выбранные» включаются один раз, а не при каждом запуске (с 1.10.31).
     */
    var appsDefaultsDone: Boolean
        get() = sp.getBoolean("appsDefaultsV1", false)
        set(v) = sp.edit().putBoolean("appsDefaultsV1", v).apply()

    /** Приложения из набора по умолчанию, с которых человек сам снял галочку: обратно не ставим. */
    var appsUnticked: Set<String>
        get() = sp.getStringSet("appsUnticked", emptySet()).orEmpty()
        set(v) = sp.edit().putStringSet("appsUnticked", v.toSet()).apply()

    var appsSelected: Set<String>
        get() = sp.getStringSet("appsSelected", emptySet()).orEmpty()
        set(v) {
            sp.edit().putStringSet("appsSelected", v).apply()
            pushToService()
        }

    /**
     * Выход по приложениям (с 1.10.39, см. AppExit): пакет → «Всегда WARP» или «Второй выход».
     * Приложения без записи — «Само», по адресам. Хранится строками «пакет|правило».
     */
    var appExits: Map<String, Int>
        get() = dev.warpscout.core.tunnel.AppExit.decodeAll(sp.getStringSet("appExits", emptySet()).orEmpty())
        set(v) {
            sp.edit().putStringSet("appExits", dev.warpscout.core.tunnel.AppExit.encodeAll(v).toSet()).apply()
            pushToService()
        }

    /**
     * Правила, которые действуют сейчас: второй выход включён и Android 10+ (раньше система не
     * говорит VPN, чьё соединение). Выключили второй выход — правила хранятся, но не действуют: иначе
     * приложение со «Вторым выходом» шло бы через туннель, а кнопки в его строке не видно.
     */
    fun appExitsActive(): Map<String, Int> =
        if (secondExitOn && android.os.Build.VERSION.SDK_INT >= 29) appExits else emptyMap()

    /** Приложения с выходом «Второй выход» — целиком через второй выход. */
    fun secondExitApps(): Set<String> =
        appExitsActive().filterValues { it == dev.warpscout.core.tunnel.AppExit.SECOND }.keys

    var allowBlockIds: Set<String>
        get() = sp.getStringSet("allowBlock", null) ?: dev.warpscout.core.lists.AllowLists.DEFAULT_BLOCK_IDS.toSet()
        set(v) {
            sp.edit().putStringSet("allowBlock", v).apply()
            // Список YouTube решает, добавлять ли сети Google для видео (с 1.10.33, см. youtubeTunneled).
            pushToService()
        }

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

    var autoApply: Boolean
        get() = sp.getBoolean("autoApply", false)
        set(v) = sp.edit().putBoolean("autoApply", v).apply()

    /** Когда последний раз заканчивался подбор — чтобы на экране было видно «это свежий конфиг». */
    var lastTunedAt: Long
        get() = sp.getLong("lastTunedAt", 0L)
        set(v) = sp.edit().putLong("lastTunedAt", v).apply()

    /** Последняя точка входа, которая реально поднялась: её пробуем раньше «сегодняшней». */
    /**
     * Очередь точек входа из последнего подключения — её читает процесс туннеля, чтобы после
     * смены сети перейти на следующую точку самому, не ожидая нажатия «Подключить».
     */
    var failoverQueue: List<String>
        get() = (sp.getString("failoverQueue", "") ?: "")
            .split('\n')
            .map { it.trim() }
            .filter { it.isNotEmpty() }
        set(v) = sp.edit().putString("failoverQueue", v.distinct().take(12).joinToString("\n")).apply()

    var lastEndpoint: String
        get() = sp.getString("lastEndpoint", "").orEmpty()
        set(v) = sp.edit().putString("lastEndpoint", v).apply()

    /**
     * Резервная точка, выбранная человеком в «Резервном» (host:port; пусто — не выбрана). Её же
     * получает сервис: если текущая точка замолчит, он перейдёт на неё первой.
     *
     * С 1.10.28 это резервная для Wi-Fi (и любой немобильной сети), а для мобильной — своя,
     * [backupMobile]. Прежнее единственное значение остаётся здесь: выбирали его чаще всего дома.
     */
    var backupEndpoint: String
        get() = sp.getString("backupEndpoint", "").orEmpty()
        set(v) {
            sp.edit().putString("backupEndpoint", v.trim()).apply()
            pushToService()
        }

    /** Резервная точка для мобильной сети (см. [backupEndpoint]). */
    var backupMobile: String
        get() = sp.getString("backupMobile", "").orEmpty()
        set(v) {
            sp.edit().putString("backupMobile", v.trim()).apply()
            pushToService()
        }

    /** Резервная точка группы сетей (`ConfigShortlist.GROUP_WIFI` / `GROUP_MOBILE`). */
    fun backupFor(group: String): String =
        if (group == ConfigShortlist.GROUP_MOBILE) backupMobile else backupEndpoint

    /**
     * Отметить резервную для группы сетей. Только запоминает: туннель не трогается — переход
     * сейчас делает отдельная кнопка «Перейти сейчас».
     */
    fun setBackupFor(group: String, endpoint: String) {
        if (group == ConfigShortlist.GROUP_MOBILE) backupMobile = endpoint else backupEndpoint = endpoint
    }

    // ---------------------------------------------- переключатели новых функций
    //
    // Каждую новую автоматику можно выключить, не дожидаясь новой версии: если на каком-то
    // телефоне или сети она ведёт себя плохо, человек сам решает, без неё лучше или с ней.
    // По умолчанию всё включено. Читает их сервис — поэтому каждая запись уходит в его снимок.

    /** Поднимать туннель самому после перезагрузки телефона и обновления приложения. */
    var featAutoStart: Boolean
        get() = sp.getBoolean("featAutoStart", true)
        set(v) {
            sp.edit().putBoolean("featAutoStart", v).apply()
            pushToService()
        }

    /** Проверка связи дважды не прошла — переподключаться. */
    var featLinkReconnect: Boolean
        get() = sp.getBoolean("featLinkReconnect", true)
        set(v) {
            sp.edit().putBoolean("featLinkReconnect", v).apply()
            pushToService()
        }

    /** Короткий замер скорости после подключения (он же ловит «заморозку»). */
    var featSpeedAuto: Boolean
        get() = sp.getBoolean("featSpeedAuto", true)
        set(v) {
            sp.edit().putBoolean("featSpeedAuto", v).apply()
            pushToService()
        }

    /** Загрузка дважды «замёрзла» — переходить на другую точку. */
    var featFreezeReconnect: Boolean
        get() = sp.getBoolean("featFreezeReconnect", true)
        set(v) {
            sp.edit().putBoolean("featFreezeReconnect", v).apply()
            pushToService()
        }

    /** В раздельном режиме отправлять DNS-запросы через туннель. */
    var featDnsInTunnel: Boolean
        get() = sp.getBoolean("featDnsInTunnel", true)
        set(v) {
            sp.edit().putBoolean("featDnsInTunnel", v).apply()
            pushToService()
        }

    /**
     * Искать точку с выходом за рубежом, если выход WARP на этой сети — в России (с 1.10.34): на
     * зарядке с погашенным экраном, не чаще раза в сутки на сеть, туннель гаснет примерно на минуту.
     */
    var featAbroadSearch: Boolean
        get() = sp.getBoolean("featAbroadSearch", true)
        set(v) {
            sp.edit().putBoolean("featAbroadSearch", v).apply()
            pushToService()
        }

    /**
     * «Браузер — только к нужным сайтам» (с 1.10.35, так решил человек 23.11): браузер среди
     * выбранных приложений идёт через туннель только к сайтам второго выхода, своим сайтам и
     * отмеченным спискам; выбранные приложения известных сервисов — целиком (см. [routeParts]).
     */
    var featBrowserSites: Boolean
        get() = sp.getBoolean("featBrowserSites", true)
        set(v) {
            sp.edit().putBoolean("featBrowserSites", v).apply()
            pushToService()
        }

    /**
     * Сети выбранных приложений (с 1.10.35): списки их сервисов (AppServices), собранные в адреса —
     * подсети из списков и адреса доменов через DoH. Собираются при «Сохранить и применить»
     * (см. [appNetsReady]), подпись — [appNetsSignature].
     */
    var appNetsText: String
        get() = sp.getString("appNetsText", "").orEmpty()
        set(v) = sp.edit().putString("appNetsText", v.trim()).apply()

    var appNetsSig: String
        get() = sp.getString("appNetsSig", "").orEmpty()
        set(v) = sp.edit().putString("appNetsSig", v).apply()

    var appNetsAt: Long
        get() = sp.getLong("appNetsAt", 0L)
        set(v) = sp.edit().putLong("appNetsAt", v).apply()

    /**
     * Предлагать второй выход для Telegram, если через Москву медиа тормозит (с 1.10.36 — вопросом,
     * см. TelegramChoice; ключ прежний, с 1.10.34, — выбор человека переживает обновление).
     */
    var featTgSecond: Boolean
        get() = sp.getBoolean("featTgSecond", true)
        set(v) {
            sp.edit().putBoolean("featTgSecond", v).apply()
            pushToService()
        }

    /** Перед переключением на выбранную точку спрашивать её пробой (рабочий туннель не трогая). */
    var featProbeBeforeSwitch: Boolean
        get() = sp.getBoolean("featProbeBeforeSwitch", true)
        set(v) = sp.edit().putBoolean("featProbeBeforeSwitch", v).apply()

    /**
     * Вид главного экрана: [UI_SIMPLE] — одна кнопка, запасная точка и проверка связи;
     * [UI_ADVANCED] — все вкладки, как раньше; [UI_DEFAULT] — ещё не выбирали, решает сборка
     * (tunnel открывается упрощённым, scout — расширенным).
     */
    var uiMode: Int
        get() = sp.getInt("uiMode", UI_DEFAULT)
        set(v) = sp.edit().putInt("uiMode", v).apply()

    /** Упрощённый ли экран сейчас: выбор человека, а без него — то, что задано сборкой. */
    fun simpleUi(): Boolean = when (uiMode) {
        UI_SIMPLE -> true
        UI_ADVANCED -> false
        else -> BuildConfig.DEFAULT_SIMPLE
    }

    /** Тема: [THEME_SYSTEM] — как в системе, [THEME_LIGHT] — светлая, [THEME_DARK] — тёмная. */
    var themeMode: Int
        get() = sp.getInt("themeMode", THEME_SYSTEM).coerceIn(THEME_SYSTEM, THEME_DARK)
        set(v) = sp.edit().putInt("themeMode", v.coerceIn(THEME_SYSTEM, THEME_DARK)).apply()

    /** Регион выхода, определённый последним подключением (colo · страна · адрес). */
    var lastExitRegion: String
        get() = sp.getString("lastExitRegion", "").orEmpty()
        set(v) = sp.edit().putString("lastExitRegion", v).apply()

    /**
     * Какой конфиг из тройки сейчас работает (`host:port|шум`). Отдельно от [lastConfigText]:
     * текст последнего конфига зависит от выбранного клиента (Amnezia/WireGuard/Clash), и сравнивать
     * его с записью в списке напрямую нельзя — активная строка переставала бы подсвечиваться.
     */
    var shortlistActive: String
        get() = sp.getString("shortlistActive", "").orEmpty()
        set(v) = sp.edit().putString("shortlistActive", v).apply()

    /**
     * Последний конфиг, которым поднимали туннель (текст WireGuard/AmneziaWG). Нужен плитке
     * быстрых настроек: она подключает «то же, что в прошлый раз», не собирая конфиг заново.
     */
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

    fun routesModeName(): String = context.getString(
        when {
            runCatching { browserSitesActive() }.getOrDefault(false) -> R.string.routes_mode_browser
            routesMode == 1 -> R.string.routes_mode_preset
            routesMode == 2 -> R.string.routes_mode_lists
            routesMode == 3 -> R.string.routes_mode_manual
            else -> R.string.routes_mode_all
        }
    )

    // ------------------------------------------------ браузер — только к нужным сайтам (с 1.10.35)
    //
    // Android решает сначала по приложению, потом по адресам, и адреса у туннеля общие для всех
    // выбранных приложений. Поэтому «браузер — только к сайтам, Telegram — целиком» выражается так:
    // маршруты = нужные сайты + сети выбранных приложений. Telegram, Instagram, YouTube ходят только в
    // свои сети и идут целиком; браузеру из этих маршрутов достаются только сайты (и сайты тех же
    // сервисов: youtube.com, instagram.com — маршруты общие). Сайты второго выхода сервис добавляет
    // в маршруты сам. Приложения без известного сервиса при неполных маршрутах идут только к сайтам —
    // экран об этом предупреждает (так решил человек 23.11).

    /**
     * Чьи сети нужны маршрутам: выбранные приложения в режиме «только выбранные» и (с 1.10.39)
     * приложения с выходом «Второй выход» в любом режиме — они идут через туннель целиком.
     */
    fun appsForNets(): Set<String> = (if (appsMode == APPS_ONLY) appsSelected else emptySet()) + secondExitApps()

    /** Списки сервисов этих приложений. */
    fun appNetsLists(): List<String> = dev.warpscout.core.lists.AppServices.listsFor(appsForNets())

    /** Подпись сетей приложений: правила сборки и списки. Изменилась — собрать заново. */
    fun appNetsSignature(): String =
        "v${dev.warpscout.core.lists.AllowListPlanner.VERSION};" + appNetsLists().sorted().joinToString(",")

    /** Сети выбранных приложений собраны под нынешний выбор (или собирать нечего). */
    fun appNetsReady(): Boolean = appNetsLists().isEmpty() || (appNetsText.isNotBlank() && appNetsSig == appNetsSignature())

    /** Выбранные браузеры (только в режиме «только выбранные»). */
    fun selectedBrowsers(): List<String> =
        if (appsMode == APPS_ONLY) Browsers.among(context, appsSelected) else emptyList()

    /** Выбранные приложения, сетей которых мы не знаем (не браузеры и не известные сервисы). */
    fun unknownSelectedApps(): List<String> {
        if (appsMode != APPS_ONLY) return emptyList()
        return appsSelected.filter { pkg ->
            dev.warpscout.core.lists.AppServices.serviceOf(pkg) == null && !Browsers.isBrowser(context, pkg)
        }.sorted()
    }

    /**
     * Браузер должен идти только к нужным сайтам: переключатель включён, «только выбранные», среди
     * них есть браузер, а сайты — «все» или «всё, кроме российских сетей» (иначе маршруты и так
     * неполные: там браузер уже идёт только к выбранным сайтам).
     */
    fun browserSitesWanted(): Boolean =
        featBrowserSites && appsMode == APPS_ONLY && (routesMode == 0 || routesMode == 1) && selectedBrowsers().isNotEmpty()

    /**
     * То же, и сети выбранных приложений собраны. Пока не собраны — по-старому (браузер целиком):
     * иначе Telegram и YouTube остались бы без своих сетей.
     */
    fun browserSitesActive(): Boolean = browserSitesWanted() && appNetsReady()

    /** Маршруты по спискам собраны под нынешние отметки. */
    fun listsReady(): Boolean = allowedIpsText.isNotBlank() && listsBuiltSig == listsSignature()

    /**
     * Что реально попадёт в `AllowedIPs`.
     *
     * Режим 2 берёт уже собранный план (его собирают «Сохранить и применить» и «Обновить списки»:
     * домены разворачиваются в /32 и /128 через DoH, потому что WireGuard не умеет правила по именам).
     * Если плана нет — честно возвращаем «весь трафик», а не пустой конфиг, в котором ничего не едет.
     */
    /**
     * До 1.10.31 режим «вручную» брал AllowedIPs из поля CIDR (allowedIpsText). Теперь это «мои
     * сайты»: прежний список переносится туда один раз. В нём были только адреса и подсети —
     * маршруты готовы без сети, и туннель после обновления ведёт себя как раньше.
     */
    fun migrateManualRoutes() {
        if (routesMode != 3 || tunnelSites.isNotBlank() || allowedIpsText.isBlank()) return
        val text = allowedIpsText.split(',', '\n').map { it.trim() }.filter { it.isNotEmpty() }.joinToString("\n")
        tunnelSites = text
        val parsed = dev.warpscout.core.lists.SiteList.parse(text)
        if (parsed.hosts.isEmpty() && parsed.prefixes.isNotEmpty()) {
            tunnelSitesCidrs = dev.warpscout.core.lists.SiteList.cidrs(parsed, emptyMap()).joinToString(", ")
            tunnelSitesSig = text.trim()
            tunnelSitesAt = System.currentTimeMillis()
        }
    }

    fun allowedIps(): String {
        val parts = routeParts()
        return onlyUsable(parts.all())
    }

    /**
     * Маршруты по режиму «Туннелирования» и сети Google для видео YouTube, которых в них нет.
     *
     * Сети Google (с 1.10.33) добавляются здесь, при подключении, а не только при сборке маршрутов:
     * маршруты, собранные прежней версией, их не содержали, а пересобираются они только по
     * «Сохранить и применить». Журнал 23.11: в режиме «сайты из списков» страница и превью YouTube
     * грузились, а видео шло мимо туннеля — по LTE, где его замедляет оператор, — и вставало.
     */
    private fun routeParts(): dev.warpscout.core.config.TunnelRoutes.Parts {
        val browser = runCatching { browserSitesActive() }.getOrDefault(false)
        // «Мои сайты» (с 1.10.31) — их адреса; до первой сборки — весь трафик. Прежний ручной
        // список переносится сам (см. migrateManualRoutes) — и здесь тоже: туннель может
        // подняться после обновления раньше, чем откроют экран (автозапуск, плитка).
        val own = if (routesMode == 3) tunnelSitesCidrs.ifBlank { migrateManualRoutes(); tunnelSitesCidrs } else tunnelSitesCidrs
        // Для браузера — только списки, собранные под нынешние отметки: устаревшие могли включать
        // то, с чего галочку уже сняли.
        val lists = if (browser && !listsReady()) "" else allowedIpsText
        // Сети выбранных приложений (с 1.10.35): Telegram, Instagram, YouTube идут целиком, даже
        // когда сайты выбраны не все. С 1.10.39 — и приложений с выходом «Второй выход».
        val appNets = if (appNetsLists().isNotEmpty() && appNetsReady()) appNetsText else ""
        return dev.warpscout.core.config.TunnelRoutes.compose(
            mode = routesMode,
            browser = browser,
            lists = lists,
            own = own,
            preset = dev.warpscout.core.presets.RoutePresets.BYPASS_WHITELIST_CSV,
            appNets = appNets,
            youtube = youtubeTunneled(),
        )
    }

    /**
     * Без IPv6-адреса в туннеле маршрут ::/0 — чёрная дыра: браузер радостно выбирает IPv6 и
     * половина сайтов «не открывается», хотя туннель поднят. Поэтому при выключенном IPv6
     * v6-маршруты не выпускаем вовсе.
     */
    private fun onlyUsable(routes: String): String {
        if (enableIpv6) return routes
        val v4 = routes.split(',').map { it.trim() }.filter { it.isNotEmpty() && !it.contains(':') }
        return if (v4.isEmpty()) "0.0.0.0/0" else v4.joinToString(", ")
    }

    /**
     * Идёт ли YouTube через туннель при маршрутах «только часть сайтов» (с 1.10.33): отмечен список
     * YouTube, среди выбранных приложений есть YouTube или его клиент, или он есть в «моих сайтах».
     * Тогда к маршрутам добавляются сети Google, откуда идёт видео: адреса видеосерверов выдаются
     * под каждое видео, и заранее в список их не внести.
     */
    fun youtubeTunneled(): Boolean {
        val lists = dev.warpscout.core.lists.AllowLists
        if (routesMode == 2 || runCatching { browserSitesActive() }.getOrDefault(false)) {
            // Пустой выбор списков сборка понимает как набор по умолчанию (см. ConfigComposer.buildPlan).
            val block = allowBlockIds.filter { lists.byId.containsKey(it) }.ifEmpty { lists.DEFAULT_BLOCK_IDS }
            if ("youtube" in block) return true
        }
        if (appsMode == APPS_ONLY && appsSelected.any { DefaultApps.isYoutube(it) }) return true
        if (routesMode == 3 && YOUTUBE_SITE.containsMatchIn(tunnelSites)) return true
        return false
    }

    /**
     * Маршруты словами — строка в журнал сервиса при каждом подъёме (с 1.10.33): по ней видно, в
     * каком режиме поднялся туннель и добавились ли сети Google для видео YouTube.
     */
    fun routesNote(): String {
        val parts = routeParts()
        val split = dev.warpscout.core.config.SplitRoutes
        val name = routesModeName()
        val full = split.prefixesOf(parts.base).any { it == "0.0.0.0/0" }
        val usable = { list: List<String> -> list.count { enableIpv6 || !it.contains(':') } }
        val base = when {
            parts.browser -> name + ": " + usable(split.prefixesOf(parts.base))
            routesMode == 0 && browserSitesWanted() -> "$name — браузер пока целиком: сети выбранных приложений ещё не собраны"
            routesMode == 0 -> name
            full && (routesMode == 2 || routesMode == 3) -> "$name — адреса ещё не собраны, пока весь трафик"
            else -> name + ": " + usable(split.prefixesOf(parts.base))
        }
        val apps = usable(parts.apps)
        val withApps = if (apps > 0) {
            val titles = dev.warpscout.core.lists.AppServices.titlesFor(appsSelected).joinToString(", ")
            "$base + сети выбранных приложений ($titles): $apps"
        } else {
            base
        }
        val added = usable(parts.video)
        return if (added > 0) "$withApps + сети Google для видео YouTube: $added" else withApps
    }

    /**
     * Что проверять (с 1.10.30): отмеченные сервисы, свои сайты и, если включено, проверки по
     * скачанным спискам. Один и тот же список — для подбора и для «Проверить сейчас».
     */
    fun availabilityChecks(): List<dev.warpscout.core.model.ResourceCheck> {
        val chosen = availServices
        return Presets.SERVICE_CHECKS.filter { it.id in chosen } +
            Presets.customChecks(availCustom) +
            runCatching { listChecks() }.getOrDefault(emptyList())
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
        // Снимок собирается из настроек, и сборка маршрутов сама может записать настройку (перенос
        // ручного списка, см. migrateManualRoutes) — повторный вход пропускаем: внешний вызов
        // запишет снимок уже с перенесёнными значениями.
        if (pushing) return
        pushing = true
        try {
            dev.warpscout.app.status.ServiceSettingsStore.write(context, serviceSettings())
        } finally {
            pushing = false
        }
    }

    /** Идёт запись снимка для сервиса (см. pushToService). */
    private var pushing = false

    /**
     * Снимок для сервиса — в одном месте. Раньше он собирался здесь и ещё раз в
     * `ServiceSettingsStore.syncFromPrefs`, и новое поле легко было добавить только в одну копию.
     */
    fun serviceSettings(): ServiceSettings {
        // Тройки подбора для каждой сети — сервис перебирает их сам, когда текущая точка замолчит.
        val shortlist = runCatching { ConfigShortlist.load(context) }.getOrDefault(emptyList())
        fun endpointsOf(group: String): List<String> = shortlist
            .filter { ConfigShortlist.group(it.network) == group }
            .map { it.endpoint.trim() }
            .filter { it.isNotEmpty() }
            .distinct()
        return ServiceSettings(
            secondExitOn = secondExitOn,
            secondConf = secondConf,
            secondCidrs = secondCidrs,
            appsMode = appsMode,
            appsSelected = appsSelected.toList().sorted(),
            failover = failoverQueue,
            backup = backupEndpoint,
            backupMobile = backupMobile,
            listWifi = endpointsOf(ConfigShortlist.GROUP_WIFI),
            listMobile = endpointsOf(ConfigShortlist.GROUP_MOBILE),
            autoStart = featAutoStart,
            linkReconnect = featLinkReconnect,
            speedAuto = featSpeedAuto,
            freezeReconnect = featFreezeReconnect,
            dnsInTunnel = featDnsInTunnel,
            secondViaWarp = secondViaWarp,
            // Proton Free: серверы по порядку перебора; пусто — один сервер из конфига.
            secondPeers = runCatching { SecondProton.candidates(context, this) }.getOrDefault(emptyList()),
            // Маршруты «Туннелирования» (с 1.10.33): сервис ставит их любому конфигу при подъёме —
            // и точке из подбора, и сохранённому для автоподъёма.
            routes = runCatching { allowedIps() }.getOrDefault(""),
            routesNote = runCatching { routesNote() }.getOrDefault(""),
            abroadSearch = featAbroadSearch,
            tgSecond = featTgSecond,
            // Выход по приложениям (с 1.10.39): сервис читает его при подъёме туннеля. Только
            // действующие правила — при выключенном втором выходе их нет.
            appExits = dev.warpscout.core.tunnel.AppExit.encodeAll(appExitsActive()),
        )
    }

    /** Куда класть скачанные списки. */
    fun allowListStore(): dev.warpscout.core.lists.FileListStore =
        dev.warpscout.core.lists.FileListStore(java.io.File(context.filesDir, "allowlists"))

    /** Как объяснить пользователю, что он сейчас выбрал. */
    fun poolModeName(): String = context.getString(
        when (poolMode) {
            POOL_MASQUE -> R.string.pool_mode_masque
            POOL_FULL -> R.string.pool_mode_full
            else -> R.string.pool_mode_default
        }
    )

    fun tuningSpec(): TuningSpec = TuningSpec(
        endpointSpec = endpointSpec(),
        junkProfiles = junkPool,
        net = NetSettings(attempts = attempts, timeoutMs = timeoutMs, concurrency = concurrency),
        // С 1.10.30 — отмеченное в «Что проверять». Проверки без VPN и через туннель включаются
        // отдельно, поэтому список нужен, если включена хоть одна из них.
        resources = if (checkResources || verifyInTunnel) availabilityChecks() else emptyList(),
        // Адреса выбранного DNS — с учётом найденных по имени (см. DnsBook): у «умных» DNS они
        // меняются, а без адресов набор подставил бы пустой список.
        dns = dnsServers(),
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

        /** Вид экрана ещё не выбирали — решает сборка (BuildConfig.DEFAULT_SIMPLE). */
        const val UI_DEFAULT = 0
        const val UI_SIMPLE = 1
        const val UI_ADVANCED = 2

        const val THEME_SYSTEM = 0
        const val THEME_LIGHT = 1
        const val THEME_DARK = 2

        const val MIRROR_NOTE = "Ключи берутся из публичного генератора (warp-api.cfd); вводить PrivateKey не нужно."

        /** YouTube среди «моих сайтов» (с 1.10.33, см. youtubeTunneled). */
        private val YOUTUBE_SITE = Regex("(?i)youtube|youtu\\.be|googlevideo|ytimg")
    }
}
