package dev.warpscout.app

import android.content.Context
import android.os.Handler
import android.os.Looper
import dev.warpscout.app.status.TunnelStatusBus
import dev.warpscout.core.config.WgConf
import dev.warpscout.core.keys.KeySource
import dev.warpscout.core.keys.KeySourceConfig
import dev.warpscout.core.model.WarpConfig
import dev.warpscout.core.net.HttpClient
import dev.warpscout.core.net.ResourceProber
import dev.warpscout.core.net.TlsProber
import dev.warpscout.core.net.WgProber
import dev.warpscout.core.report.Report
import dev.warpscout.core.tune.AutoTuner
import dev.warpscout.core.tune.ProgressSink
import dev.warpscout.core.tune.TuningResult
import dev.warpscout.core.tune.Shortlist
import dev.warpscout.core.tune.TuningSpec
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Двигатель подбора: бегает [AutoTuner] на отдельном потоке, складывает отчёт и конфиг
 * во внутреннее хранилище и отдаёт результат в UI. Никаких разрешений на сеть запрашивать
 * не нужно — INTERNET у приложения есть всегда.
 */
class Engine(private val context: Context) {

    companion object {
        /** Режимы подбора (см. [start]). */
        const val SCAN_CURRENT = 0
        const val SCAN_MOBILE = 1
        const val SCAN_BOTH = 2

        @Volatile
        private var shared: Engine? = null

        /**
         * Один движок на процесс. Раньше у каждого экрана был свой: после поворота, смены темы или
         * возврата в приложение экран создавался заново вместе с новым — пустым — движком, а прежний
         * подбор продолжал идти в старом. «Остановить подбор» останавливало пустой движок, и подбор
         * «не останавливался». Контекст — приложения, чтобы не держать закрытый экран.
         */
        fun shared(context: Context): Engine =
            shared ?: synchronized(this) {
                shared ?: Engine(context.applicationContext).also { shared = it }
            }
    }

    private val executor = Executors.newSingleThreadExecutor { r -> Thread(r, "warpscout-engine") }
    private val cancelled = AtomicBoolean(false)

    @Volatile
    var running: Boolean = false
        private set

    @Volatile
    var last: TuningResult? = null
        private set

    /**
     * Подбор сам поднял туннель на найденной точке (авто-применение). Тогда возвращать прежний
     * не нужно: работает более свежий, только что проверенный.
     */
    @Volatile
    private var tunnelBackUp = false

    /** Файл конфига, который Engine записал последним (UI отдаёт его по «Поделиться»). */
    @Volatile
    var storedConfigFile: java.io.File? = null
        private set

    fun cancel() {
        cancelled.set(true)
    }

    /**
     * [allowAutoApply] — можно ли поднять туннель по галочке «авто-применение». Фоновый подбор
     * передаёт false, если туннель последним выключил сам человек: «выключил руками» значит, что
     * ничто не включает его само, и подбор по расписанию тоже.
     */
    fun start(
        spec: TuningSpec,
        manual: WarpConfig?,
        sink: ProgressSink,
        allowAutoApply: Boolean = true,
        /**
         * Что подбирать: [SCAN_CURRENT] — текущую сеть (как всегда), [SCAN_MOBILE] — только
         * мобильную, не уходя с Wi-Fi, [SCAN_BOTH] — текущую, а потом мобильную.
         */
        mode: Int = SCAN_CURRENT,
        onDone: (TuningResult?, String?) -> Unit
    ) {
        if (running) {
            onDone(null, "Подбор уже выполняется")
            return
        }
        val main = Handler(Looper.getMainLooper())
        val guard = context.applicationContext
        running = true
        cancelled.set(false)
        // Пока идёт подбор, процесс держится foreground-сервисом: иначе сворачивание экрана
        // отдаёт процесс системе на растерзание и скан обрывается молча.
        ScanGuard.start(guard)
        // Прогресс дублируем в уведомление — по нему видно, что подбор жив, когда приложение свёрнуто.
        val watched = object : ProgressSink {
            override fun log(message: String) {
                ScanGuard.update(guard, message)
                sink.log(message)
            }

            override fun progress(done: Int, total: Int, current: String) {
                ScanGuard.update(guard, if (total > 0) "$done из $total · $current" else current)
                sink.progress(done, total, current)
            }

            override fun isCancelled(): Boolean = cancelled.get() || sink.isCancelled()
        }
        executor.execute {
            // Туннель, который подбор погасил сам (см. runOnce, шаг 1), обязан вернуться к концу
            // подбора — чем бы тот ни кончился. Раньше runOnce поднимал его только при найденной
            // лучшей точке, поэтому при ошибке (нет сети, все зеркала недоступны), отмене или
            // «живых точек нет» человек оставался без интернета до ручного нажатия.
            // Подбор из интерфейса гасит туннель ещё до старта — тот случай возвращает MainActivity.
            val before = TunnelFactory.create(guard)
            runCatching { TunnelStatusBus.refresh(guard) }
            val wasUp = runCatching { before.supported && before.isUp }.getOrDefault(false)
            val previousText = if (wasUp) previousTunnelText(guard) else ""
            tunnelBackUp = false
            val outcome = runCatching {
                when (mode) {
                    SCAN_MOBILE -> runMobileOnce(spec, watched)
                    SCAN_BOTH -> {
                        val currentNet = runOnce(spec, manual, watched, allowAutoApply)
                        // Мобильная — вторым проходом: только если первый не остановили.
                        if (!watched.isCancelled()) {
                            runCatching { runMobileOnce(spec, watched) }
                                .onFailure { watched.log("подбор для мобильной сети: " + describe(it)) }
                        }
                        currentNet
                    }
                    else -> runOnce(spec, manual, watched, allowAutoApply)
                }
            }
            if (wasUp && !tunnelBackUp) restoreTunnel(before, previousText, watched)
            ScanGuard.stop(guard)
            main.post {
                running = false
                onDone(outcome.getOrNull(), outcome.exceptionOrNull()?.let { describe(it) })
            }
        }
    }

    /** Для WorkManager: тот же цикл, но синхронно. */
    fun runBlocking(
        spec: TuningSpec,
        manual: WarpConfig?,
        sink: ProgressSink,
        limitMs: Long,
        allowAutoApply: Boolean = true
    ): TuningResult? {
        val latch = CountDownLatch(1)
        var result: TuningResult? = null
        start(spec, manual, sink, allowAutoApply, onDone = { r, _ -> result = r; latch.countDown() })
        latch.await(limitMs, TimeUnit.MILLISECONDS)
        return result
    }

    private fun runOnce(
        spec: TuningSpec,
        manual: WarpConfig?,
        sink: ProgressSink,
        allowAutoApply: Boolean
    ): TuningResult? {
        val prefs = Prefs(context)
        val tunnel = TunnelFactory.create(context)

        // 1) Базовые замеры имеют смысл только «на чистой сети»: свой туннель гасим, чужие — обходим.
        val wasUp = tunnel.isUp
        if (wasUp) {
            tunnel.stop()
            sink.log("базовые замеры: собственный туннель приостановлен")
        }
        val haveClean = CleanNetwork.prepare(context)
        sink.log(CleanNetwork.statusLine(context))
        if (haveClean) CleanNetwork.bind(context)
        val factories = CleanNetwork.factories()
        val tuned = factories?.let { (udp, tcp) ->
            spec.copy(net = spec.net.copy(udpFactory = udp, tcpFactory = tcp))
        } ?: spec

        // Замеры идут напрямую: настройки внешнего SOCKS5-обхода в интерфейсе нет, а «включено, но
        // не настроено» — худший вид настройки: подбор молча мерил бы не то, что видит пользователь.
        val withProxy = tuned
        val resourceHttp = HttpClient(6000)

        val vault = KeyVault(context)
        val keySource = KeySource(
            http = HttpClient(timeoutMs = 4000),
            store = vault.accountStore(),
            config = KeySourceConfig(),
            manual = manual?.account
        )
        val tuner = AutoTuner(
            keySource = keySource,
            wgProber = WgProber(withProxy.net),
            tlsProber = TlsProber(withProxy.net),
            resources = ResourceProber(resourceHttp),
            tunnel = tunnel.verifier()
        )
        // Быстрый старт: если на этой же сети недавно нашлась рабочая точка, проверяем сначала
        // только её (секунды вместо минут и без разогрева радио на весь скан). Не подтвердится —
        // подбор сам уйдёт в полный проход по пулу.
        val withCache = withProxy.copy(cachedStart = TuningCache.cachedStart(context, withProxy.junkProfiles))
        val result = try {
            tuner.run(withCache, sink)
        } finally {
            CleanNetwork.unbind(context)
        }
        // Остановленный подбор — это не результат. Раньше недосчитанный прогон шёл дальше как
        // обычный: записывал отчёт и тройку замен из случайного куска пула и по галочке даже
        // поднимал туннель на «лучшей» точке — после «Остановить подбор» человек видел, что
        // подбор продолжает работать. Прежний туннель вернёт вызывающий (см. start).
        if (sink.isCancelled()) {
            sink.log("подбор остановлен — результат не сохраняю и не применяю")
            return null
        }
        last = result
        runCatching { Report.writeAll(result.report, ConfigFiles.dir(context, "reports"), "warpscout") }
        if (result.best == null) {
            // Годных точек нет (молчат или «рукопожатие есть, данных нет»). Раньше лучшей всё равно
            // объявлялась молчащая точка с 60 баллами: её конфиг записывался, тройка из мёртвых
            // точек затирала рабочую, и подключение перебирало заведомо мёртвое (журнал 22.11 16:32).
            sink.log("годных точек нет — конфиг, кеш и очередь остаются прежними")
        }

        // Конфиг пользователю отдаём уже «под него»: выбранный сервер, выбранный шум, выбранные
        // каналы и выбранный клиент. Иначе «я же выбрал WireGuard» расходится с файлом на диске.
        val exportable = result.best?.let { ConfigComposer.applyPrefs(it, prefs, prefs.junkPool) }
        val exportText = exportable?.let { ConfigComposer.render(it, prefs) }
        if (exportable != null && exportText != null) {
            val file = runCatching {
                val dir = ConfigFiles.dir(context, "configs")
                val out = java.io.File(dir, ConfigComposer.fileName(exportable, prefs))
                out.writeText(exportText)
                out
            }.getOrNull()
            if (file != null) {
                storedConfigFile = file
                sink.log("конфиг записан: ${file.name} · ${ConfigComposer.explain(exportable, prefs)}")
            }
        }

        // 2) Помечаем результат: «когда проверяли» и «конфиг реально новый или тот же».
        val now = System.currentTimeMillis()
        prefs.lastTunedAt = now
        result.best?.let { cfg ->
            runCatching { TuningCache.save(context, cfg.endpoint, cfg.junk.name) }
            val prev = prefs.lastTunedEndpoint
            val rendered = cfg.endpoint.render()
            if (rendered != prev) {
                prefs.lastChangedAt = now
                prefs.lastTunedEndpoint = rendered
                prefs.lastTunedScore = result.report.best?.score ?: 0
                sink.log("новый конфиг: endpoint $rendered (прежний: ${prev.ifBlank { "ещё не было подобранного" }})")
            }
        }

        // 2b) Топ-3: не только победитель, но и две готовые замены. Сеть режет адреса выборочно и
        // без предупреждения — «переключиться на второй» должно быть нажатием, а не новым сканом.
        saveShortlist(result, TuningCache.transportOf(context), handshakeOnly = false, sink = sink)

        // 3) Авто-применение: либо по галочке, либо восстанавливаем только что остановленный туннель.
        val best = result.best
        if (best != null && tunnel.supported) {
            val allowed = runCatching { android.net.VpnService.prepare(context) == null }.getOrDefault(false)
            val autoApply = prefs.autoApply && allowAutoApply
            if (prefs.autoApply && !allowAutoApply && !wasUp) {
                sink.log("авто-применение пропущено: туннель выключен вручную — сам его не включаю")
            }
            when {
                autoApply && !allowed ->
                    sink.log("авто-применение пропущено: нет разрешения на VPN — открой приложение и нажми «Туннель»")
                autoApply || wasUp -> {
                    val withRoutes = ConfigComposer.applyPrefs(best, prefs, prefs.junkPool)
                    val up = runCatching { tunnel.startAndAwait(withRoutes, 25000) }.getOrDefault(false)
                    if (up) {
                        tunnelBackUp = true
                        // «Подключить последнее» должно поднимать именно то, что работает сейчас.
                        prefs.lastConfigText = runCatching { WgConf.render(withRoutes) }
                            .getOrDefault(prefs.lastConfigText)
                        prefs.lastEndpoint = withRoutes.endpoint.render()
                        prefs.shortlistActive = withRoutes.endpoint.render() + "|" + withRoutes.junk.name
                        sink.log("туннель поднят на подобранном конфиге: ${withRoutes.endpoint.render()}")
                    } else {
                        val why = tunnel.lastError() ?: tunnel.status
                        sink.log("туннель не поднялся: $why")
                        TunnelTrouble.advise(tunnel.debugDump()).forEach {
                            sink.log("  почему: ${context.getString(it.titleRes)} — ${context.getString(it.whatToDoRes)}")
                        }
                    }
                }
            }
        }
        return result
    }

    /**
     * Тройка лучших для переключения — в список своей сети (тройка другой сети остаётся).
     * Сервису — сразу: он перебирает эту тройку сам, когда текущая точка замолчит.
     */
    private fun saveShortlist(result: TuningResult, network: String, handshakeOnly: Boolean, sink: ProgressSink) {
        val prefs = Prefs(context)
        runCatching {
            val picked = Shortlist.pick(result.report.candidates)
            val savedAt = System.currentTimeMillis()
            val entries = picked.mapNotNull { cand ->
                val composed = ConfigComposer.applyPrefs(cand.config, prefs, prefs.junkPool)
                // Ручной сервер из настроек свёл бы всю тройку в один адрес, и список замен стал бы
                // бесполезным: три строки, которые падают вместе. В тройке остаётся адрес подбора —
                // именно он и есть альтернатива текущей точке.
                val restoreEndpoint = if (composed.endpoint != cand.config.endpoint) {
                    composed.copy(endpoint = cand.config.endpoint)
                } else {
                    composed
                }
                val text = ConfigComposer.render(restoreEndpoint, prefs)
                if (text.isBlank()) return@mapNotNull null
                ConfigShortlist.Entry(
                    endpoint = restoreEndpoint.endpoint.render(),
                    junk = restoreEndpoint.junk.name,
                    score = cand.score,
                    resourcesOk = cand.resourcesOk,
                    resourcesTotal = cand.resourcesTotal,
                    configText = text,
                    savedAt = savedAt,
                    network = network,
                    speedKbps = cand.speedKbps,
                    handshakeOnly = handshakeOnly,
                    dataMs = cand.stats.dataMs?.toInt() ?: -1
                )
            }.distinctBy { it.endpoint + "|" + it.junk }
            if (entries.isEmpty()) {
                sink.log("очередь не обновлена: в этом подборе нет точек, через которые идут данные")
            }
            if (entries.isNotEmpty()) {
                ConfigShortlist.save(context, entries)
                val where = if (ConfigShortlist.group(network) == ConfigShortlist.GROUP_MOBILE) "мобильной сети" else "Wi-Fi"
                sink.log("топ-${entries.size} для $where: " + entries.joinToString { it.endpoint })
                runCatching { dev.warpscout.app.status.ServiceSettingsStore.syncFromPrefs(context) }
            }
        }.onFailure { t -> sink.log("тройка лучших не сохранилась: " + describe(t)) }
    }

    /**
     * Подбор для мобильной сети, не уходя с Wi-Fi: пробы рукопожатием через мобильную сеть,
     * которую система держит поднятой по нашему запросу (см. CellularNetwork).
     *
     * Свой туннель на это время гасим и потом возвращаем: пробы идут тем же ключом, и удачное
     * рукопожатие с мобильного адреса увело бы сессию работающего туннеля к себе — WireGuard
     * «переезжает» на адрес, с которого пришло последнее рукопожатие.
     */
    private fun runMobileOnce(spec: TuningSpec, sink: ProgressSink): TuningResult? {
        val tunnel = TunnelFactory.create(context)
        val wasUp = runCatching { tunnel.supported && tunnel.isUp }.getOrDefault(false)
        val previousText = if (wasUp) previousTunnelText(context) else ""
        if (wasUp) {
            tunnel.stop()
            runCatching { tunnel.waitStopped(3000) }
            sink.log("подбор для мобильной сети: собственный туннель приостановлен")
        }
        try {
            if (!CellularNetwork.maybeAvailable(context)) {
                sink.log("подбор для мобильной сети пропущен: SIM-карта не готова")
                return null
            }
            val cell = CellularNetwork.acquire(context)
            if (cell == null) {
                sink.log("подбор для мобильной сети пропущен: система не дала мобильную сеть (выключены мобильные данные?)")
                return null
            }
            try {
                sink.log("мобильная сеть получена: ${CellularNetwork.describe(context)} — проверяю точки через неё, не уходя с Wi-Fi")
                val (udp, tcp) = CellularNetwork.factories(cell.first)
                val tuned = spec.copy(
                    net = spec.net.copy(udpFactory = udp, tcpFactory = tcp),
                    resources = emptyList(),
                    checkBaselineResources = false,
                    verifyThroughTunnel = false,
                    cachedStart = null
                )
                val vault = KeyVault(context)
                val keySource = KeySource(
                    http = HttpClient(timeoutMs = 4000),
                    store = vault.accountStore(),
                    config = KeySourceConfig(),
                    manual = null
                )
                val tuner = AutoTuner(
                    keySource = keySource,
                    wgProber = WgProber(tuned.net),
                    tlsProber = TlsProber(tuned.net),
                    resources = ResourceProber(HttpClient(6000)),
                    tunnel = null
                )
                val result = tuner.run(tuned, sink)
                if (sink.isCancelled()) {
                    sink.log("подбор для мобильной сети остановлен — результат не сохраняю")
                    return null
                }
                saveShortlist(result, ConfigShortlist.GROUP_MOBILE, handshakeOnly = true, sink = sink)
                return result
            } finally {
                CellularNetwork.release(context, cell.second)
            }
        } finally {
            if (wasUp) restoreTunnel(tunnel, previousText, sink)
        }
    }

    /**
     * Текст конфига, которым туннель работает прямо сейчас.
     *
     * Ключи, маршруты и профиль шума — из сохранённого текста. Точку берём из снимка сервиса:
     * после аварии он сам переходит на следующую, и в сохранённом тексте остаётся уже мёртвый
     * адрес. Вернуть «прежний туннель» на мёртвую точку — значит не вернуть его вовсе.
     */
    private fun previousTunnelText(ctx: Context): String {
        val text = runCatching { Prefs(ctx).lastConfigText }.getOrDefault("")
        if (text.isBlank()) return text
        val live = runCatching { TunnelStatusBus.snapshot(ctx).endpoint }.getOrDefault("").trim()
        if (live.isEmpty() || live.any { it.isWhitespace() }) return text
        return text.lineSequence().joinToString("\n") { line ->
            if (line.trimStart().startsWith("Endpoint") && '=' in line) "Endpoint = $live" else line
        }
    }

    /**
     * Вернуть туннель, который работал до подбора.
     *
     * Вызывается, когда подбор закончился, а сам туннель не поднял (ошибка, отмена, «живых
     * точек нет»).
     */
    private fun restoreTunnel(tunnel: TunnelController, previousText: String, sink: ProgressSink) {
        runCatching {
            // Снимок состояния пишет процесс туннеля — перечитываем сами. Сессия, которую проверка
            // «изнутри» только что попросила закрыться, ещё может числиться живой: ждём её конца.
            // Если же туннель и правда работает (человек нажал «Подключить» сам) — не трогаем.
            runCatching { TunnelStatusBus.refresh(context) }
            if (tunnel.isUp && !tunnel.waitStopped(3000)) return
            if (previousText.isBlank()) {
                sink.log("вернуть туннель нечем: сохранённого конфига нет")
                return
            }
            val cfg = WgConf.toWarpConfig("возврат", previousText)
            if (cfg == null) {
                sink.log("вернуть туннель нечем: сохранённый конфиг не разбирается")
                return
            }
            sink.log("подбор не оставил туннель — возвращаю прежний: ${cfg.endpoint.render()}")
            if (tunnel.startAndAwait(cfg, 25000)) {
                TunnelDebug.ok("туннель снова поднят после подбора: ${cfg.endpoint.render()}")
            } else {
                val why = tunnel.lastError() ?: tunnel.status
                TunnelDebug.error("туннель не вернулся после подбора: $why")
                sink.log("туннель не вернулся: $why")
            }
        }.onFailure { t -> sink.log("возврат туннеля: " + describe(t)) }
    }

    private fun describe(e: Throwable): String {
        val msg = buildString {
            append(e.javaClass.simpleName)
            e.message?.let { append(": ").append(it.take(220)) }
            (e.cause as? KeySource.AllMirrorsFailed)?.let { append(" (все зеркала генератора недоступны — попробуйте позже или импортируйте .conf вручную)") }
        }
        return msg
    }
}
