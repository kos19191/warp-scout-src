package dev.warpscout.desktop.engine

import dev.warpscout.core.config.ConfTarget
import dev.warpscout.core.config.WgConf
import dev.warpscout.core.junk.JunkLibrary
import dev.warpscout.core.keys.AccountStore
import dev.warpscout.core.keys.KeySource
import dev.warpscout.core.lists.AllowListPlanner
import dev.warpscout.core.lists.AllowLists
import dev.warpscout.core.lists.FileListStore
import dev.warpscout.core.lists.ListSide
import dev.warpscout.core.model.JunkProfile
import dev.warpscout.core.model.ResourceResult
import dev.warpscout.core.model.WarpConfig
import dev.warpscout.core.net.DnsCheck
import dev.warpscout.core.net.DnsInspector
import dev.warpscout.core.net.EndpointPool
import dev.warpscout.core.net.EndpointSpec
import dev.warpscout.core.net.HttpClient
import dev.warpscout.core.net.NetSettings
import dev.warpscout.core.net.PoolMode
import dev.warpscout.core.net.ResourceProber
import dev.warpscout.core.net.TlsProber
import dev.warpscout.core.net.WarpDefaults
import dev.warpscout.core.net.WgProber
import dev.warpscout.core.presets.Presets
import dev.warpscout.core.report.Report
import dev.warpscout.core.tune.AutoTuner
import dev.warpscout.core.tune.CachedStart
import dev.warpscout.core.tune.ProgressSink
import dev.warpscout.core.tune.Shortlist
import dev.warpscout.core.tune.TuningSpec
import dev.warpscout.desktop.storage.DesktopPoolMode
import dev.warpscout.desktop.storage.DesktopSettings
import dev.warpscout.desktop.storage.DesktopStore
import dev.warpscout.desktop.storage.ShortlistEntry
import dev.warpscout.desktop.storage.TunnelBackendMode
import dev.warpscout.desktop.tunnel.CommandRunner
import dev.warpscout.desktop.tunnel.EngineInfo
import dev.warpscout.desktop.tunnel.EngineKind
import dev.warpscout.desktop.tunnel.EngineLocator
import dev.warpscout.desktop.tunnel.NativeWintunTunnelManager
import dev.warpscout.desktop.tunnel.ProcessCommandRunner
import dev.warpscout.desktop.tunnel.SecondExitSpec
import dev.warpscout.desktop.tunnel.SpeedTestResult
import dev.warpscout.desktop.tunnel.TraceAndSpeed
import dev.warpscout.desktop.tunnel.TunnelPhase
import dev.warpscout.desktop.tunnel.TunnelSnapshot
import dev.warpscout.desktop.tunnel.WindowsAutostart
import dev.warpscout.desktop.tunnel.WindowsTunnelManager
import dev.warpscout.desktop.tunnel.WintunLoader
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import java.io.File
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

enum class LogLevel { INFO, OK, WARN, ERROR }

data class LogEntry(
    val timestampMs: Long,
    val level: LogLevel,
    val message: String
)

data class DesktopUiState(
    val settings: DesktopSettings = DesktopSettings(),
    val tunnel: TunnelSnapshot = TunnelSnapshot(),
    val wintunReady: Boolean = false,
    val engine: EngineInfo = EngineInfo(EngineKind.NONE, null, null, "Проверка…"),
    val isElevated: Boolean = false,
    val shortlist: List<ShortlistEntry> = emptyList(),
    val activeConfText: String? = null,

    // Состояние подбора
    val scanning: Boolean = false,
    val scanDone: Int = 0,
    val scanTotal: Int = 0,
    val scanStep: String = "",

    // Результаты проверок
    val checkingResources: Boolean = false,
    val resourceResults: List<ResourceResult> = emptyList(),
    val dnsChecks: List<DnsCheck> = emptyList(),
    val speedTesting: Boolean = false,
    val speedResult: SpeedTestResult? = null,

    // Списки allow-domains и Второй выход
    val listsBusy: Boolean = false,
    val listsStatus: String = "",
    val cachedListStamps: Map<String, Long> = emptyMap(),
    val secondExitBusy: Boolean = false,
    val secondExitStatus: String = "",

    // Уведомление-баннер на текущем экране
    val banner: String? = null,
    val bannerIsError: Boolean = false,

    // Журнал
    val logs: List<LogEntry> = emptyList()
) {
    val hasConfig: Boolean get() = !activeConfText.isNullOrBlank() || shortlist.isNotEmpty()
    val effectivePhase: TunnelPhase get() = if (scanning) TunnelPhase.SCANNING else tunnel.phase
    val tunnelBackendReady: Boolean
        get() = when (settings.backendMode) {
            TunnelBackendMode.BUILTIN_WINTUN -> wintunReady
            TunnelBackendMode.EXTERNAL_AWG -> engine.available
        }
    val backendTitle: String
        get() = when (settings.backendMode) {
            TunnelBackendMode.BUILTIN_WINTUN -> "Встроенный туннель (Wintun)"
            TunnelBackendMode.EXTERNAL_AWG -> engine.kind.title
        }
}

class DesktopController(
    val store: DesktopStore,
    private val runner: CommandRunner = ProcessCommandRunner(),
    private val autoConnectRequested: Boolean = false,
    private val onTrayNotify: (title: String, message: String) -> Unit = { _, _ -> },
    private val onRelaunchElevated: (extraArgs: List<String>) -> Boolean = { false }
) {
    private val _state = MutableStateFlow(DesktopUiState())
    val state: StateFlow<DesktopUiState> = _state.asStateFlow()

    private val worker = Executors.newSingleThreadExecutor { r ->
        Thread(r, "warpscout-worker").apply { isDaemon = true }
    }
    private val auxWorker = Executors.newFixedThreadPool(2) { r ->
        Thread(r, "warpscout-aux").apply { isDaemon = true }
    }
    private val scheduler = Executors.newSingleThreadScheduledExecutor { r ->
        Thread(r, "warpscout-schedule").apply { isDaemon = true }
    }

    private val scanCancel = AtomicBoolean(false)
    private var scheduledTune: ScheduledFuture<*>? = null

    val listStore = FileListStore(store.paths.listsDir)

    /** Встроенный туннель (по умолчанию): ядро :core (DataPlane + ExitRouter) поверх wintun.dll. */
    val nativeTunnel = NativeWintunTunnelManager(
        nativeDir = store.paths.nativeDir,
        runner = runner,
        onState = { snap ->
            if (_state.value.settings.backendMode == TunnelBackendMode.BUILTIN_WINTUN) {
                _state.update { it.copy(tunnel = snap) }
            }
        },
        onLog = { msg -> appendLog(msg) }
    )

    /** Опциональный внешний движок AmneziaWG (если пользователь выбрал его в Настройках). */
    val externalAwgTunnel = WindowsTunnelManager(
        tunnelsDir = store.paths.tunnelsDir,
        runner = runner,
        onState = { snap ->
            if (_state.value.settings.backendMode == TunnelBackendMode.EXTERNAL_AWG) {
                _state.update { it.copy(tunnel = snap) }
            }
        },
        onLog = { msg -> appendLog(msg) },
        autoElevateUac = { _state.value.settings.autoElevateUac }
    )

    private val isBuiltinMode: Boolean
        get() = _state.value.settings.backendMode == TunnelBackendMode.BUILTIN_WINTUN

    private val currentTunnelUp: Boolean
        get() = if (isBuiltinMode) nativeTunnel.snapshot.isUp else externalAwgTunnel.snapshot.isUp

    private val currentActiveEndpoint: String
        get() = if (isBuiltinMode) nativeTunnel.snapshot.activeEndpoint else externalAwgTunnel.snapshot.activeEndpoint

    init {
        val loaded = store.loadSettings()
        val shortlist = store.loadShortlist()
        val activeConf = store.loadActiveConfigText() ?: shortlist.getOrNull(loaded.activeShortlistIndex)?.confText
        val stamps = AllowLists.cachedIds(listStore)

        _state.update {
            it.copy(
                settings = loaded,
                shortlist = shortlist,
                activeConfText = activeConf,
                cachedListStamps = stamps
            )
        }

        appendLog("WarpScout Desktop запущен (каталог данных: ${store.paths.root.absolutePath})")
        refreshEngineAndPrivileges()
        rescheduleBackgroundTune(loaded)

        if (autoConnectRequested) {
            appendLog("Запуск с автоподключением (--autoconnect)…")
            if (activeConf != null) connectActive() else runScan(autoConnectAfter = true)
        } else if (loaded.autoConnectOnStart && activeConf != null) {
            appendLog("Автоподключение при запуске включено — поднимаю туннель…")
            connectActive()
        }
    }

    fun refreshEngineAndPrivileges() {
        auxWorker.execute {
            val s = _state.value.settings
            val wintunOk = WintunLoader.isAvailable(store.paths.nativeDir)
            val engine = EngineLocator.locate(customPath = s.customEnginePath, runner = runner)
            val elevated = runCatching { runner.isElevated() }.getOrDefault(false)
            _state.update { it.copy(wintunReady = wintunOk, engine = engine, isElevated = elevated) }

            val modeInfo = when (s.backendMode) {
                TunnelBackendMode.BUILTIN_WINTUN ->
                    if (wintunOk) "Встроенный туннель WarpScout (Wintun готов)"
                    else "Встроенный туннель (wintun.dll не найден в bin/)"
                TunnelBackendMode.EXTERNAL_AWG ->
                    if (engine.available) "Внешний движок: ${engine.kind.title} (${engine.sourceLabel})"
                    else "Внешний движок AmneziaWG не найден"
            }
            appendLog(
                "$modeInfo${if (elevated) " · права администратора" else ""}",
                if ((s.backendMode == TunnelBackendMode.BUILTIN_WINTUN && wintunOk) || engine.available) LogLevel.OK else LogLevel.WARN
            )
        }
    }

    /** Перезапускает WarpScout с правами администратора (UAC) и сразу подключается. */
    fun relaunchAsAdministrator(autoConnect: Boolean = true) {
        val args = if (autoConnect) listOf("--autoconnect") else emptyList()
        val ok = onRelaunchElevated(args)
        if (!ok) {
            showBanner("Запрос прав администратора отменён или недоступен. Запустите WarpScout.exe правой кнопкой → «От имени администратора».", isError = true)
        }
    }

    fun clearBanner() {
        _state.update { it.copy(banner = null, bannerIsError = false) }
    }

    fun showBanner(text: String, isError: Boolean = false) {
        _state.update { it.copy(banner = text, bannerIsError = isError) }
    }

    fun updateSettings(transform: (DesktopSettings) -> DesktopSettings) {
        val prev = _state.value.settings
        val next = transform(prev)
        store.saveSettings(next)
        _state.update { it.copy(settings = next) }

        if (prev.backendMode != next.backendMode) {
            worker.execute {
                if (nativeTunnel.snapshot.isUp) nativeTunnel.disconnect("Смена движка туннеля")
                if (externalAwgTunnel.snapshot.isUp) externalAwgTunnel.disconnect("Смена движка туннеля")
            }
            refreshEngineAndPrivileges()
        } else if (prev.customEnginePath != next.customEnginePath) {
            refreshEngineAndPrivileges()
        }

        if (prev.autostartWindows != next.autostartWindows) {
            auxWorker.execute {
                val res = WindowsAutostart.setEnabled(next.autostartWindows, runner)
                if (res.ok) {
                    appendLog(if (next.autostartWindows) "Автозапуск с Windows включён" else "Автозапуск с Windows выключен", LogLevel.OK)
                } else {
                    appendLog("Не удалось изменить автозапуск: ${res.combined}", LogLevel.WARN)
                    showBanner("Не удалось изменить автозапуск: ${res.combined}", isError = true)
                }
            }
        }
        if (prev.autoScheduleHours != next.autoScheduleHours || prev.autoApplyScheduled != next.autoApplyScheduled) {
            rescheduleBackgroundTune(next)
        }
    }

    /** Главная одна кнопка на экране «Главная» и в трее. */
    fun onPrimaryButtonClick() {
        clearBanner()
        val s = _state.value
        when {
            s.scanning -> {
                cancelScan()
            }
            s.tunnel.isBusy -> {
                nativeTunnel.requestCancel()
                externalAwgTunnel.requestCancel()
                worker.execute {
                    if (isBuiltinMode) nativeTunnel.disconnect("Подключение отменено")
                    else externalAwgTunnel.disconnect("Подключение отменено")
                }
            }
            s.tunnel.isUp -> {
                disconnect()
            }
            !s.hasConfig -> {
                showBanner("Конфигурации ещё нет — подбираю рабочую точку и подключусь сам")
                runScan(autoConnectAfter = true)
            }
            else -> {
                connectActive()
            }
        }
    }

    fun connectActive() {
        val s = _state.value
        val confText = s.activeConfText ?: s.shortlist.firstOrNull()?.confText
        if (confText.isNullOrBlank()) {
            runScan(autoConnectAfter = true)
            return
        }
        val parsed = WgConf.toWarpConfig("WarpScout-Active", confText)
        if (parsed == null) {
            showBanner("Сохранённый конфиг повреждён — запускаю новый подбор", isError = true)
            runScan(autoConnectAfter = true)
            return
        }
        val appliedPrimary = applyCurrentNetworkSettings(parsed, s.settings)
        val fallbacks = s.shortlist
            .mapNotNull { WgConf.toWarpConfig("Shortlist", it.confText) }
            .map { applyCurrentNetworkSettings(it, s.settings) }
            .filter { it.endpoint != appliedPrimary.endpoint || it.junk.name != appliedPrimary.junk.name }

        val secondExit = buildSecondExitSpec(s.settings)
        worker.execute {
            if (s.settings.backendMode == TunnelBackendMode.BUILTIN_WINTUN) {
                val elevated = runCatching { runner.isElevated() }.getOrDefault(false)
                _state.update { it.copy(isElevated = elevated) }
                if (!elevated && s.settings.autoElevateUac && WindowsAutostart.isWindows()) {
                    appendLog("Запрашиваю права администратора (UAC) для запуска встроенного туннеля…")
                    if (onRelaunchElevated(listOf("--autoconnect"))) {
                        return@execute
                    }
                }
                val ok = nativeTunnel.connect(appliedPrimary, fallbacks, secondExit)
                if (ok) {
                    store.saveActiveConfigText(WgConf.render(appliedPrimary))
                    _state.update { it.copy(activeConfText = WgConf.render(appliedPrimary)) }
                    onTrayNotify("WarpScout подключён", "Точка: ${nativeTunnel.snapshot.activeEndpoint}")
                }
            } else {
                val engine = resolveFreshEngine()
                val ok = externalAwgTunnel.connect(engine, appliedPrimary, fallbacks, secondExit)
                if (ok) {
                    store.saveActiveConfigText(WgConf.render(appliedPrimary))
                    _state.update { it.copy(activeConfText = WgConf.render(appliedPrimary)) }
                    onTrayNotify("WarpScout подключён", "Точка: ${externalAwgTunnel.snapshot.activeEndpoint}")
                }
            }
        }
    }

    fun disconnect() {
        worker.execute {
            if (isBuiltinMode) nativeTunnel.disconnect("Туннель выключен пользователем")
            else externalAwgTunnel.disconnect("Туннель выключен пользователем")
        }
    }

    fun switchToNextEndpoint() {
        worker.execute {
            val ok = if (isBuiltinMode) nativeTunnel.switchToNextEndpoint() else externalAwgTunnel.switchToNextEndpoint()
            if (ok) {
                onTrayNotify("WarpScout", "Сменил точку на $currentActiveEndpoint")
            } else {
                showBanner("Не удалось сменить точку — попробуйте запустить подбор", isError = true)
            }
        }
    }

    fun switchToShortlist(index: Int) {
        val s = _state.value
        val entry = s.shortlist.getOrNull(index) ?: return
        val parsed = WgConf.toWarpConfig("Top3-${index + 1}", entry.confText)
        if (parsed == null) {
            showBanner("Выбранный конфиг повреждён", isError = true)
            return
        }
        updateSettings { it.copy(activeShortlistIndex = index) }
        store.saveActiveConfigText(entry.confText)
        _state.update { it.copy(activeConfText = entry.confText) }
        appendLog("Выбрана точка #${index + 1}: ${entry.endpoint} (${entry.junkName})")
        connectActive()
    }

    fun clearShortlist() {
        store.saveShortlist(emptyList())
        _state.update { it.copy(shortlist = emptyList()) }
        showBanner("Список лучших конфигов очищен")
        appendLog("Список Топ-3 очищен")
    }

    fun cancelScan() {
        scanCancel.set(true)
        appendLog("Останавливаю подбор по запросу пользователя…", LogLevel.WARN)
    }

    /** Полный цикл подбора через `AutoTuner` из `:core`. */
    fun runScan(autoConnectAfter: Boolean = false, silentBackground: Boolean = false) {
        if (_state.value.scanning) {
            if (!silentBackground) showBanner("Подбор уже идёт — дождитесь результата")
            return
        }
        scanCancel.set(false)
        _state.update {
            it.copy(
                scanning = true,
                scanDone = 0,
                scanTotal = 0,
                scanStep = "Подготовка пула точек и ключей…"
            )
        }

        worker.execute {
            val startedMs = System.currentTimeMillis()
            val wasUp = currentTunnelUp
            try {
                if (wasUp && !silentBackground) {
                    appendLog("Приостанавливаю текущий туннель на время чистого сканирования…")
                    if (isBuiltinMode) nativeTunnel.disconnect("Приостановлен на время подбора")
                    else externalAwgTunnel.disconnect("Приостановлен на время подбора")
                }

                val settings = _state.value.settings
                val engine = resolveFreshEngine()
                val spec = buildTuningSpec(settings)
                val keySource = KeySource(store = AccountStore.file(store.paths.accountCacheFile.absolutePath))

                // Проверяем топ-3 изнутри туннеля (встроенного Wintun или внешнего AmneziaWG).
                val verifier = if (settings.verifyThroughTunnel && (!wasUp || !silentBackground)) {
                    when (settings.backendMode) {
                        TunnelBackendMode.BUILTIN_WINTUN -> nativeTunnel.createVerifier()
                        TunnelBackendMode.EXTERNAL_AWG -> if (engine.available) externalAwgTunnel.createVerifier(engine) else null
                    }
                } else null

                val tuner = AutoTuner(
                    keySource = keySource,
                    wgProber = WgProber(spec.net),
                    tlsProber = TlsProber(spec.net),
                    resources = ResourceProber(HttpClient(timeoutMs = 7000)),
                    tunnel = verifier
                )

                val sink = object : ProgressSink {
                    override fun log(message: String) = appendLog(message)
                    override fun progress(done: Int, total: Int, current: String) {
                        _state.update { it.copy(scanDone = done, scanTotal = total, scanStep = current) }
                    }
                    override fun isCancelled(): Boolean = scanCancel.get()
                }

                appendLog("Старт подбора: пул ${settings.poolMode.title}, точек до ${spec.endpointSpec.maxEndpoints}, профилей шума: ${spec.junkProfiles.size}")
                val result = tuner.run(spec, sink)
                val durSec = ((System.currentTimeMillis() - startedMs) / 1000L).toInt().coerceAtLeast(1)

                if (scanCancel.get()) {
                    appendLog("Подбор остановлен пользователем", LogLevel.WARN)
                    _state.update { it.copy(scanning = false, scanStep = "Остановлено") }
                    if (wasUp && !silentBackground) connectActive()
                    return@execute
                }

                runCatching { Report.writeAll(result.report, store.paths.reportsDir) }

                val picked = Shortlist.pick(result.report.candidates)
                val nowMs = System.currentTimeMillis()
                val newShortlist = picked.map { c ->
                    ShortlistEntry(
                        endpoint = c.config.endpoint.render(),
                        junkName = c.junk.name,
                        score = c.score,
                        resourcesOk = c.resourcesOk,
                        resourcesTotal = c.resourcesTotal,
                        checkedAtMs = nowMs,
                        confText = WgConf.render(c.config)
                    )
                }

                val bestConfText = result.configText ?: newShortlist.firstOrNull()?.confText
                val bestEndpoint = result.best?.endpoint?.render().orEmpty()
                val bestJunk = result.best?.junk?.name.orEmpty()

                if (newShortlist.isNotEmpty()) {
                    store.saveShortlist(newShortlist)
                }
                if (!bestConfText.isNullOrBlank()) {
                    store.saveActiveConfigText(bestConfText)
                }

                val summary = if (result.best != null) {
                    val b = result.report.best
                    val resPart = if (b != null && b.resourcesTotal > 0) " · открылось ${b.resourcesOk}/${b.resourcesTotal}" else ""
                    "$bestEndpoint · $bestJunk · ${b?.score ?: 0} б.$resPart"
                } else {
                    "Живых точек не нашлось"
                }

                updateSettings {
                    it.copy(
                        activeShortlistIndex = 0,
                        lastTuneAtMs = nowMs,
                        lastTuneDurationSec = durSec,
                        lastTuneEndpoint = bestEndpoint,
                        lastTuneJunk = bestJunk,
                        lastTuneSummary = summary,
                        lastAccountSource = result.accountSource
                    )
                }

                _state.update {
                    it.copy(
                        scanning = false,
                        scanStep = "Готово",
                        shortlist = if (newShortlist.isNotEmpty()) newShortlist else it.shortlist,
                        activeConfText = bestConfText ?: it.activeConfText,
                        resourceResults = if (result.report.resources.isNotEmpty()) result.report.resources else it.resourceResults
                    )
                }

                if (result.best == null) {
                    appendLog("Подбор завершён: живых точек не нашлось", LogLevel.WARN)
                    if (!silentBackground) showBanner("Живых точек не нашлось — попробуйте увеличить число точек или сменить режим пула", isError = true)
                    return@execute
                }

                appendLog("Подбор завершён за ${Formatters.duration(durSec.toLong())}: $summary", LogLevel.OK)
                if (!silentBackground) {
                    showBanner("Найдена лучшая точка: $summary")
                } else {
                    onTrayNotify("Фоновый подбор завершён", summary)
                }

                val shouldConnect = autoConnectAfter || (wasUp && !silentBackground) || (silentBackground && settings.autoApplyScheduled)
                if (shouldConnect && bestConfText != null) {
                    connectActive()
                }
            } catch (e: Exception) {
                appendLog("Ошибка подбора: ${e.javaClass.simpleName}: ${e.message}", LogLevel.ERROR)
                _state.update { it.copy(scanning = false, scanStep = "Ошибка") }
                if (!silentBackground) showBanner("Ошибка подбора: ${e.message}", isError = true)
            }
        }
    }

    /** Проверка реальной доступности сайтов + сверка системного DNS с DoH. */
    fun runSiteAndDnsCheck() {
        if (_state.value.checkingResources) return
        _state.update { it.copy(checkingResources = true) }
        auxWorker.execute {
            try {
                appendLog("Проверяю доступность сайтов и DNS…")
                val checks = buildList {
                    addAll(Presets.RESOURCE_CHECKS)
                    if (currentTunnelUp) addAll(Presets.TUNNEL_ONLY_CHECKS)
                }
                val prober = ResourceProber(HttpClient(timeoutMs = 7000))
                val results = prober.checkAll(checks)
                val dns = runCatching {
                    DnsInspector().check(listOf("youtube.com", "discord.com", "chatgpt.com", "telegram.org"))
                }.getOrDefault(emptyList())

                val okCount = results.count { it.ok }
                val poisoned = dns.count { it.suspicious }
                appendLog(
                    "Проверка сайтов: открылось $okCount из ${results.size}" +
                        if (poisoned > 0) " · внимание: обнаружена подмена DNS ($poisoned домена)" else " · DNS чистый",
                    if (poisoned > 0) LogLevel.WARN else LogLevel.OK
                )
                _state.update {
                    it.copy(
                        checkingResources = false,
                        resourceResults = results,
                        dnsChecks = dns
                    )
                }
            } catch (e: Exception) {
                appendLog("Ошибка проверки ресурсов: ${e.message}", LogLevel.ERROR)
                _state.update { it.copy(checkingResources = false) }
            }
        }
    }

    /** Замер скорости через `speed.cloudflare.com`. */
    fun runSpeedTest() {
        if (_state.value.speedTesting) return
        _state.update { it.copy(speedTesting = true, speedResult = null) }
        auxWorker.execute {
            appendLog("Замеряю скорость через speed.cloudflare.com (10 МБ)…")
            val res = TraceAndSpeed.measureSpeed()
            if (res.ok) {
                appendLog(String.format("Скорость: %.1f Мбит/с · задержка %d мс", res.downloadMbps, res.latencyMs), LogLevel.OK)
            } else {
                appendLog("Замер скорости не удался: ${res.error}", LogLevel.WARN)
            }
            _state.update { it.copy(speedTesting = false, speedResult = res) }
        }
    }

    /** Скачивание свежих списков `allow-domains` с GitHub. */
    fun refreshAllowLists() {
        if (_state.value.listsBusy) return
        _state.update { it.copy(listsBusy = true, listsStatus = "Скачиваю списки allow-domains…") }
        auxWorker.execute {
            try {
                val http = HttpClient(timeoutMs = 10_000, followRedirects = true)
                val fetcher: (String) -> String? = { url ->
                    runCatching {
                        val r = http.get(url, maxBytes = 1024 * 1024)
                        if (r.status in 200..299) r.body else null
                    }.getOrNull()
                }
                val s = _state.value.settings
                val targetIds = (s.selectedBlockListIds + s.selectedDirectListIds).distinct()
                val lists = targetIds.mapNotNull { AllowLists.byId[it] }.ifEmpty { AllowLists.bySide(ListSide.BLOCK) }
                var ok = 0
                for (list in lists) {
                    val parts = AllowLists.fetch(fetcher, list)
                    val merged = AllowLists.merge(parts)
                    if (merged.isNotBlank()) {
                        listStore.write(list.id, merged)
                        ok++
                    }
                }
                val stamps = AllowLists.cachedIds(listStore)
                val msg = "Списки обновлены: $ok из ${lists.size}"
                appendLog(msg, if (ok > 0) LogLevel.OK else LogLevel.WARN)
                _state.update { it.copy(listsBusy = false, listsStatus = msg, cachedListStamps = stamps) }
            } catch (e: Exception) {
                val msg = "Ошибка загрузки списков: ${e.message}"
                appendLog(msg, LogLevel.ERROR)
                _state.update { it.copy(listsBusy = false, listsStatus = msg) }
            }
        }
    }

    /** Сборка `AllowedIPs` из скачанных списков через DoH. */
    fun buildAllowListRoutes() {
        if (_state.value.listsBusy) return
        _state.update { it.copy(listsBusy = true, listsStatus = "Разворачиваю домены списков в CIDR через DoH…") }
        auxWorker.execute {
            try {
                val s = _state.value.settings
                val block = s.selectedBlockListIds.mapNotNull { AllowLists.byId[it] }
                val direct = s.selectedDirectListIds.mapNotNull { AllowLists.byId[it] }
                val cached = AllowLists.loadAll(listStore)
                val parsed = cached.mapValues { it.value.parsed }
                if (parsed.isEmpty()) {
                    val msg = "Кеш списков пуст — сначала нажмите «Скачать списки»"
                    _state.update { it.copy(listsBusy = false, listsStatus = msg) }
                    return@execute
                }
                val plan = AllowListPlanner.plan(block = block, direct = direct, parsed = parsed, fullTunnel = false)
                updateSettings { it.copy(builtAllowedIps = plan.allowedIps) }
                val msg = "Маршруты собраны: ${plan.summary()}"
                appendLog(msg, LogLevel.OK)
                _state.update { it.copy(listsBusy = false, listsStatus = msg) }
            } catch (e: Exception) {
                val msg = "Ошибка сборки маршрутов: ${e.message}"
                appendLog(msg, LogLevel.ERROR)
                _state.update { it.copy(listsBusy = false, listsStatus = msg) }
            }
        }
    }

    /** Разворачивает домены «Второго выхода» в `/32` и `/128` адреса через DoH. */
    fun resolveSecondExitDomains() {
        if (_state.value.secondExitBusy) return
        val domains = _state.value.settings.secondExitDomains
            .split(',', '\n', '\r', ';', ' ', '\t')
            .map { it.trim().removePrefix("*.").removePrefix(".").lowercase() }
            .filter { it.isNotEmpty() && '.' in it }
            .distinct()
        if (domains.isEmpty()) {
            _state.update { it.copy(secondExitStatus = "Список доменов пуст") }
            return
        }
        _state.update { it.copy(secondExitBusy = true, secondExitStatus = "Разворачиваю ${domains.size} доменов через DoH…") }
        auxWorker.execute {
            try {
                val resolved = AllowListPlanner.resolveAll(domains)
                val cidrs = LinkedHashSet<String>()
                var unresolvedCount = 0
                for ((_, ips) in resolved) {
                    if (ips.isEmpty()) unresolvedCount++
                    for (ip in ips) {
                        if (':' in ip) cidrs.add("$ip/128")
                        else if (Regex("""^\d+\.\d+\.\d+\.\d+$""").matches(ip)) cidrs.add("$ip/32")
                    }
                }
                val csv = cidrs.joinToString(", ")
                updateSettings { it.copy(secondExitCidrs = csv) }
                val msg = if (cidrs.isEmpty()) "Адреса не найдены (проверьте интернет)"
                else "Найдено подсетей: ${cidrs.size} (доменов: ${domains.size}" +
                    if (unresolvedCount > 0) ", не разрешилось: $unresolvedCount)" else ")"
                appendLog("Второй выход: $msg", if (cidrs.isNotEmpty()) LogLevel.OK else LogLevel.WARN)
                _state.update { it.copy(secondExitBusy = false, secondExitStatus = msg) }
            } catch (e: Exception) {
                val msg = "Ошибка DoH: ${e.message}"
                appendLog(msg, LogLevel.ERROR)
                _state.update { it.copy(secondExitBusy = false, secondExitStatus = msg) }
            }
        }
    }

    /** Применяет изменённые настройки маршрутов/сети и переподключает туннель, если он был поднят. */
    fun applySettingsAndReconnect() {
        if (currentTunnelUp) {
            appendLog("Настройки изменены — переподключаю туннель…")
            showBanner("Настройки сохранены — переподключаю туннель")
            connectActive()
        } else {
            showBanner("Настройки сохранены — применятся при следующем подключении")
        }
    }

    fun renderExportText(target: ConfTarget = _state.value.settings.exportTarget): String? {
        val raw = _state.value.activeConfText ?: return null
        val parsed = WgConf.toWarpConfig("WarpScout", raw) ?: return null
        val applied = applyCurrentNetworkSettings(parsed, _state.value.settings)
        return WgConf.render(applied, target)
    }

    fun importConfigText(text: String): Boolean {
        val parsed = WgConf.toWarpConfig("Imported", text)
        if (parsed == null) {
            showBanner("Не удалось прочитать конфиг: нужны [Interface] PrivateKey и [Peer] PublicKey", isError = true)
            return false
        }
        val rendered = WgConf.render(parsed)
        store.saveActiveConfigText(rendered)
        val entry = ShortlistEntry(
            endpoint = parsed.endpoint.render(),
            junkName = parsed.junk.name,
            score = 0,
            checkedAtMs = System.currentTimeMillis(),
            confText = rendered
        )
        val updatedList = (listOf(entry) + _state.value.shortlist.filterNot { it.endpoint == entry.endpoint }).take(3)
        store.saveShortlist(updatedList)
        updateSettings { it.copy(activeShortlistIndex = 0) }
        _state.update { it.copy(activeConfText = rendered, shortlist = updatedList) }
        appendLog("Импортирован конфиг: ${parsed.endpoint.render()} (${parsed.junk.name})", LogLevel.OK)
        showBanner("Конфиг импортирован: ${parsed.endpoint.render()}")
        return true
    }

    fun saveBackup(file: File): Boolean = try {
        val summary = store.exportBackup(file)
        appendLog("Резервная копия сохранена: ${file.absolutePath}", LogLevel.OK)
        showBanner("Бекап сохранён: ${summary.file.name}")
        true
    } catch (e: Exception) {
        appendLog("Ошибка сохранения бекапа: ${e.message}", LogLevel.ERROR)
        showBanner("Бекап не сохранился: ${e.message}", isError = true)
        false
    }

    fun restoreBackup(file: File): Boolean = try {
        val res = store.importBackup(file)
        _state.update {
            it.copy(
                settings = res.settings,
                shortlist = res.shortlist,
                activeConfText = res.activeConf ?: it.activeConfText
            )
        }
        rescheduleBackgroundTune(res.settings)
        appendLog("Восстановлено из ${file.name}: настроек — ${res.restoredFields}", LogLevel.OK)
        showBanner("Восстановлено из ${file.name}. Переподключите туннель для применения.")
        true
    } catch (e: Exception) {
        appendLog("Ошибка восстановления бекапа: ${e.message}", LogLevel.ERROR)
        showBanner("Ошибка восстановления: ${e.message}", isError = true)
        false
    }

    fun clearLogs() {
        _state.update { it.copy(logs = emptyList()) }
        runCatching { store.paths.logFile.writeText("") }
    }

    fun exportLogsText(): String = _state.value.logs.joinToString("\n") {
        "[${Formatters.timeOf(it.timestampMs)}] [${it.level.name}] ${it.message}"
    }

    fun shutdown(disconnectTunnel: Boolean = _state.value.settings.disconnectOnExit) {
        scheduledTune?.cancel(false)
        scanCancel.set(true)
        if (nativeTunnel.snapshot.isUp) {
            nativeTunnel.disconnect("Туннель остановлен при закрытии приложения")
        }
        if (disconnectTunnel && externalAwgTunnel.snapshot.isUp) {
            externalAwgTunnel.disconnect("Туннель остановлен при закрытии приложения")
        }
        nativeTunnel.shutdown()
        externalAwgTunnel.shutdown()
        scheduler.shutdownNow()
        worker.shutdownNow()
        auxWorker.shutdownNow()
    }

    // ---------------------------------------------------------------- helpers

    private fun resolveFreshEngine(): EngineInfo {
        val wintunOk = WintunLoader.isAvailable(store.paths.nativeDir)
        val engine = EngineLocator.locate(_state.value.settings.customEnginePath, runner = runner)
        val elevated = runCatching { runner.isElevated() }.getOrDefault(false)
        _state.update { it.copy(wintunReady = wintunOk, engine = engine, isElevated = elevated) }
        return engine
    }

    private fun buildSecondExitSpec(s: DesktopSettings): SecondExitSpec = SecondExitSpec(
        enabled = s.secondExitEnabled,
        confText = s.secondExitConf,
        cidrsCsv = s.secondExitCidrs
    )

    private fun applyCurrentNetworkSettings(cfg: WarpConfig, s: DesktopSettings): WarpConfig = cfg.copy(
        dns = s.effectiveDns(),
        mtu = s.mtu,
        persistentKeepalive = s.keepalive.takeIf { it > 0 },
        allowedIps = s.effectiveAllowedIps(),
        enableIpv6Address = s.enableIpv6
    )

    private fun buildTuningSpec(s: DesktopSettings): TuningSpec {
        val ports = parsePorts(s.customPortsText)
        val endpointSpec = when (s.poolMode) {
            DesktopPoolMode.DEFAULT -> EndpointSpec(
                subnets = WarpDefaults.AWG_SUBNETS,
                hostnames = WarpDefaults.AWG_HOSTNAMES,
                ports = ports.ifEmpty { WarpDefaults.AWG_PORTS },
                mode = PoolMode.STRATIFIED,
                maxEndpoints = s.endpointCount
            )
            DesktopPoolMode.MASQUE -> EndpointSpec(
                subnets = WarpDefaults.MASQUE_SUBNETS + WarpDefaults.AWG_SUBNETS.take(2),
                hostnames = WarpDefaults.AWG_HOSTNAMES,
                ports = ports.ifEmpty { WarpDefaults.MASQUE_PORTS },
                mode = PoolMode.STRATIFIED,
                maxEndpoints = s.endpointCount
            )
            DesktopPoolMode.FULL -> EndpointSpec(
                subnets = WarpDefaults.AWG_SUBNETS,
                hostnames = WarpDefaults.AWG_HOSTNAMES,
                ports = ports.ifEmpty { WarpDefaults.AWG_PORTS },
                mode = PoolMode.FULL,
                maxEndpoints = s.endpointCount.coerceAtLeast(400)
            )
            DesktopPoolMode.CUSTOM -> {
                val parsed = EndpointPool.parseList(s.customHostsText)
                EndpointSpec(
                    subnets = emptyList(),
                    hostnames = parsed.map { it.render() },
                    ports = ports.ifEmpty { WarpDefaults.AWG_PORTS },
                    mode = PoolMode.EXPLICIT,
                    maxEndpoints = parsed.size.coerceAtLeast(1)
                )
            }
        }

        val profiles = buildList<JunkProfile> {
            if (s.includeNoneJunk) add(JunkLibrary.none())
            if (s.includeTlsJunk) add(JunkLibrary.tlsFixed())
            if (s.includeQuicJunk) {
                JunkLibrary.SNI_DOMAINS.take(s.sniCount.coerceIn(1, 10)).forEachIndexed { idx, sni ->
                    add(JunkLibrary.quic(sni, level = 3, seed = 7L + idx))
                }
            }
            if (s.includeSipJunk) add(JunkLibrary.sip())
        }.ifEmpty { JunkLibrary.defaultPool(sniCount = s.sniCount) }

        val cachedStart = s.lastTuneEndpoint.takeIf { it.isNotBlank() }?.let { epStr ->
            runCatching { CachedStart(WgConf.parseEndpoint(epStr), s.lastTuneJunk) }.getOrNull()
        }

        return TuningSpec(
            endpointSpec = endpointSpec,
            junkProfiles = profiles,
            net = NetSettings(attempts = 3, timeoutMs = 1200, concurrency = 64),
            resources = if (s.checkResources) Presets.RESOURCE_CHECKS else emptyList(),
            dns = s.effectiveDns(),
            mtu = s.mtu,
            allowedIps = s.effectiveAllowedIps(),
            keepalive = s.keepalive.takeIf { it > 0 },
            enableIpv6Address = s.enableIpv6,
            checkBaselineResources = s.checkResources,
            verifyThroughTunnel = s.verifyThroughTunnel,
            cachedStart = cachedStart
        )
    }

    private fun parsePorts(raw: String): List<Int> {
        if (raw.isBlank()) return emptyList()
        val out = LinkedHashSet<Int>()
        for (token in raw.split(',', ';', ' ', '\n', '\r', '\t')) {
            val t = token.trim()
            if (t.isEmpty()) continue
            if ('-' in t || '–' in t) {
                val parts = t.split('-', '–')
                val a = parts.getOrNull(0)?.trim()?.toIntOrNull()
                val b = parts.getOrNull(1)?.trim()?.toIntOrNull()
                if (a != null && b != null && a in 1..65535 && b in a..65535) {
                    for (p in a..minOf(b, a + 200)) out.add(p)
                }
            } else {
                t.toIntOrNull()?.takeIf { it in 1..65535 }?.let { out.add(it) }
            }
        }
        return out.toList()
    }

    private fun rescheduleBackgroundTune(s: DesktopSettings) {
        scheduledTune?.cancel(false)
        scheduledTune = null
        if (s.autoScheduleHours <= 0) return
        val hours = s.autoScheduleHours.toLong()
        scheduledTune = scheduler.scheduleAtFixedRate(
            {
                if (!_state.value.scanning) {
                    appendLog("Запуск планового фонового подбора (каждые $hours ч)…")
                    runScan(autoConnectAfter = false, silentBackground = true)
                }
            },
            hours,
            hours,
            TimeUnit.HOURS
        )
    }

    private fun appendLog(message: String, level: LogLevel = LogLevel.INFO) {
        val entry = LogEntry(System.currentTimeMillis(), level, message)
        _state.update { cur ->
            val next = (cur.logs + entry).takeLast(1500)
            cur.copy(logs = next)
        }
        runCatching {
            store.paths.logsDir.mkdirs()
            store.paths.logFile.appendText("[${Formatters.timeOf(entry.timestampMs)}] [${level.name}] $message\n", Charsets.UTF_8)
        }
    }
}
