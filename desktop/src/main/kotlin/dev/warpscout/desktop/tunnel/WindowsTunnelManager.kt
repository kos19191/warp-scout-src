package dev.warpscout.desktop.tunnel

import dev.warpscout.core.config.ConfTarget
import dev.warpscout.core.config.WgConf
import dev.warpscout.core.model.AddrFamily
import dev.warpscout.core.model.Endpoint
import dev.warpscout.core.model.ResourceCheck
import dev.warpscout.core.model.ResourceResult
import dev.warpscout.core.model.WarpConfig
import dev.warpscout.core.net.HttpClient
import dev.warpscout.core.net.ResourceProber
import dev.warpscout.core.tune.TunnelVerifier
import java.io.File
import java.net.InetAddress
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

enum class TunnelPhase(val title: String) {
    OFF("Выключен"),
    SCANNING("Идёт подбор…"),
    CONNECTING("Подключение…"),
    CONNECTED("Подключён"),
    RECONNECTING("Переподключение…"),
    ERROR("Ошибка")
}

data class SecondExitSpec(
    val enabled: Boolean = false,
    val confText: String = "",
    val cidrsCsv: String = ""
) {
    val activeCandidate: Boolean get() = enabled && confText.isNotBlank() && cidrsCsv.isNotBlank()
}

data class TunnelSnapshot(
    val phase: TunnelPhase = TunnelPhase.OFF,
    val activeEndpoint: String = "",
    val activeJunk: String = "",
    val exitInfo: ExitInfo = ExitInfo(),
    val rxBytes: Long = 0L,
    val txBytes: Long = 0L,
    val rxSpeedBps: Long = 0L,
    val txSpeedBps: Long = 0L,
    val connectedSinceMs: Long = 0L,
    val handshakeAgeSec: Long = -1L,
    val secondExitActive: Boolean = false,
    val secondExitServer: String = "",
    val statusMessage: String = "Туннель выключен",
    val lastError: String? = null,
    val advice: String? = null,
    val needsElevation: Boolean = false,
    val attemptIndex: Int = 0,
    val attemptTotal: Int = 0
) {
    val isUp: Boolean get() = phase == TunnelPhase.CONNECTED
    val isBusy: Boolean get() = phase == TunnelPhase.CONNECTING || phase == TunnelPhase.RECONNECTING || phase == TunnelPhase.SCANNING
}

/**
 * Управляет AmneziaWG-туннелем на Windows через системные службы (`amneziawg.exe /installtunnelservice`)
 * и мониторинг (`awg.exe show <name> dump`).
 *
 * Поддерживает:
 *  • автопереключение при отказе точки (до 6 точек подряд);
 *  • мониторинг здоровья сессии и автоматический failover при зависании/обрыве;
 *  • «Второй выход» (второй одновременный туннель для отдельных доменов/CIDR с безопасным исключением
 *    endpoint'а из маршрутов WARP и мягким фолбэком в WARP при падении второго сервера);
 *  • реализацию [TunnelVerifier] для проверки реальной доступности сайтов из-под туннеля в AutoTuner.
 */
class WindowsTunnelManager(
    private val tunnelsDir: File,
    private val runner: CommandRunner = ProcessCommandRunner(),
    private val onState: (TunnelSnapshot) -> Unit = {},
    private val onLog: (String) -> Unit = {},
    private val exitProber: () -> ExitInfo = { TraceAndSpeed.probeExitInfo() },
    private val handshakeWaitMs: Long = 9000L,
    private val handshakePollMs: Long = 600L,
    private val healthPollMs: Long = 4000L,
    private val autoElevateUac: () -> Boolean = { true }
) {
    companion object {
        const val PRIMARY_TUNNEL = "warpscout"
        const val SECOND_EXIT_TUNNEL = "warpscout_exit2"
        const val PROBE_TUNNEL = "warpscout_probe"
        const val MAX_FAILOVER_QUEUE = 6
        const val STALL_HANDSHAKE_AGE_SEC = 210L
        const val STALL_NO_RX_MS = 20_000L
        const val COOLDOWN_MS = 5 * 60_000L

        /** Запасные проверенные точки Cloudflare, если пользовательский список исчерпан. */
        val FALLBACK_ENDPOINTS: List<Endpoint> = listOf(
            Endpoint("162.159.192.1", 2408),
            Endpoint("162.159.195.1", 2408),
            Endpoint("188.114.96.1", 2408),
            Endpoint("188.114.97.1", 943),
            Endpoint("engage.cloudflareclient.com", 2408, AddrFamily.HOSTNAME)
        )
    }

    @Volatile
    var snapshot: TunnelSnapshot = TunnelSnapshot()
        private set

    @Volatile
    private var currentEngine: EngineInfo = EngineInfo(EngineKind.NONE, null, null, "")

    @Volatile
    private var activeQueue: List<WarpConfig> = emptyList()

    @Volatile
    private var activeQueueIndex: Int = 0

    @Volatile
    private var activeSecondExit: SecondExitSpec = SecondExitSpec()

    private val cancelRequested = AtomicBoolean(false)
    private val reconnecting = AtomicBoolean(false)
    private var consecutiveAutoSwitches = 0
    private var cooldownUntilMs = 0L

    // Состояние для расчёта скорости и детектора зависшей сессии.
    private var prevRxBytes = 0L
    private var prevTxBytes = 0L
    private var prevSampleMs = 0L
    private var txWithoutRxSinceMs = 0L

    private val scheduler = Executors.newSingleThreadScheduledExecutor { r ->
        Thread(r, "warpscout-health").apply { isDaemon = true }
    }
    private var healthTask: ScheduledFuture<*>? = null

    private fun update(transform: (TunnelSnapshot) -> TunnelSnapshot) {
        val next = transform(snapshot)
        snapshot = next
        onState(next)
    }

    /**
     * Поднимает туннель, пробуя до [MAX_FAILOVER_QUEUE] точек из [primary] + [fallbacks].
     * Возвращает `true`, если handshake подтверждён и туннель поднят.
     */
    @Synchronized
    fun connect(
        engine: EngineInfo,
        primary: WarpConfig,
        fallbacks: List<WarpConfig> = emptyList(),
        secondExit: SecondExitSpec = SecondExitSpec()
    ): Boolean {
        cancelRequested.set(false)
        currentEngine = engine
        activeSecondExit = secondExit
        consecutiveAutoSwitches = 0
        cooldownUntilMs = 0L

        if (!engine.available || engine.tunnelExe == null) {
            val msg = "Движок AmneziaWG не найден — установите AmneziaWG или укажите путь в Настройках"
            onLog(msg)
            update {
                it.copy(
                    phase = TunnelPhase.ERROR,
                    statusMessage = "AmneziaWG не найден",
                    lastError = msg,
                    advice = "Установите AmneziaWG для Windows (кнопка «Скачать AmneziaWG» в Настройках) и нажмите «Включить туннель» снова."
                )
            }
            return false
        }

        val queue = buildQueue(primary, fallbacks)
        activeQueue = queue
        activeQueueIndex = 0
        stopHealthMonitor()

        return tryQueueFrom(0, engine, secondExit, isFailover = false)
    }

    /** Переключается на следующую точку из очереди («Другая точка входа»). */
    @Synchronized
    fun switchToNextEndpoint(): Boolean {
        if (activeQueue.size <= 1 || !currentEngine.available) {
            onLog("В очереди нет запасных точек для переключения")
            return false
        }
        val nextIdx = (activeQueueIndex + 1) % activeQueue.size
        onLog("Смена точки входа → ${activeQueue[nextIdx].endpoint.render()}")
        stopHealthMonitor()
        return tryQueueFrom(nextIdx, currentEngine, activeSecondExit, isFailover = true)
    }

    @Synchronized
    fun disconnect(reason: String = "Туннель выключен") {
        cancelRequested.set(true)
        stopHealthMonitor()
        if (currentEngine.available) {
            uninstallService(currentEngine, SECOND_EXIT_TUNNEL)
            uninstallService(currentEngine, PRIMARY_TUNNEL)
        }
        resetCounters()
        onLog(reason)
        update {
            TunnelSnapshot(
                phase = TunnelPhase.OFF,
                statusMessage = reason
            )
        }
    }

    fun requestCancel() {
        cancelRequested.set(true)
    }

    fun shutdown() {
        stopHealthMonitor()
        scheduler.shutdownNow()
    }

    /**
     * Создаёт [TunnelVerifier] для [dev.warpscout.core.tune.AutoTuner]:
     * поднимает временный туннель `warpscout_probe`, ждёт handshake + settleMs,
     * проверяет список сайтов и аккуратно удаляет службу.
     */
    fun createVerifier(engine: EngineInfo): TunnelVerifier? {
        if (!engine.available || engine.tunnelExe == null) return null
        return object : TunnelVerifier {
            override val title: String = "AmneziaWG (${engine.kind.title})"

            override fun verify(config: WarpConfig, checks: List<ResourceCheck>, settleMs: Int): List<ResourceResult> {
                val rendered = renderPrimaryConfig(config, engine, SecondExitSpec())
                val confFile = writeTunnelConf(PROBE_TUNNEL, rendered)
                uninstallService(engine, PROBE_TUNNEL)
                try {
                    val installed = installService(engine, confFile)
                    if (!installed.ok) {
                        onLog("проверка изнутри: не удалось поднять ${config.endpoint.render()} (${installed.combined.take(120)})")
                        return emptyList()
                    }
                    val hsOk = waitForHandshake(engine, PROBE_TUNNEL, timeoutMs = minOf(handshakeWaitMs, 6500L))
                    if (!hsOk) {
                        onLog("проверка изнутри: нет handshake от ${config.endpoint.render()}")
                        return emptyList()
                    }
                    if (settleMs > 0) {
                        runCatching { Thread.sleep(minOf(settleMs.toLong(), 2500L)) }
                    }
                    val prober = ResourceProber(HttpClient(timeoutMs = 6000))
                    return prober.checkAll(checks)
                } finally {
                    uninstallService(engine, PROBE_TUNNEL)
                }
            }

            override fun stop() {
                uninstallService(engine, PROBE_TUNNEL)
            }
        }
    }

    // ---------------------------------------------------------------- внутренняя логика

    private fun tryQueueFrom(
        startIdx: Int,
        engine: EngineInfo,
        secondExit: SecondExitSpec,
        isFailover: Boolean
    ): Boolean {
        val total = activeQueue.size
        for (offset in 0 until total) {
            if (cancelRequested.get()) {
                uninstallService(engine, SECOND_EXIT_TUNNEL)
                uninstallService(engine, PRIMARY_TUNNEL)
                update { TunnelSnapshot(phase = TunnelPhase.OFF, statusMessage = "Подключение отменено") }
                return false
            }
            val idx = (startIdx + offset) % total
            val cfg = activeQueue[idx]
            activeQueueIndex = idx

            update {
                it.copy(
                    phase = if (isFailover) TunnelPhase.RECONNECTING else TunnelPhase.CONNECTING,
                    activeEndpoint = cfg.endpoint.render(),
                    activeJunk = cfg.junk.name,
                    statusMessage = "Пробую точку ${offset + 1} из $total: ${cfg.endpoint.render()} (${cfg.junk.name})…",
                    lastError = null,
                    advice = null,
                    attemptIndex = offset + 1,
                    attemptTotal = total
                )
            }
            onLog("Поднимаю туннель (${offset + 1}/$total): ${cfg.endpoint.render()} · шум ${cfg.junk.name}")

            uninstallService(engine, SECOND_EXIT_TUNNEL)
            uninstallService(engine, PRIMARY_TUNNEL)

            val rendered = renderPrimaryConfig(cfg, engine, secondExit)
            val confFile = writeTunnelConf(PRIMARY_TUNNEL, rendered)
            val res = installService(engine, confFile)
            if (!res.ok) {
                val err = res.combined.ifBlank { "код выхода ${res.exitCode}" }
                onLog("Ошибка запуска службы туннеля: $err")
                if (isElevationError(err)) {
                    update {
                        it.copy(
                            phase = TunnelPhase.ERROR,
                            statusMessage = "Нужны права администратора",
                            lastError = err,
                            advice = "Подтвердите запрос UAC или запустите WarpScout от имени администратора: создание виртуального сетевого адаптера Windows требует повышенных прав."
                        )
                    }
                    return false
                }
                continue
            }

            val hsOk = waitForHandshake(engine, PRIMARY_TUNNEL, handshakeWaitMs)
            if (!hsOk) {
                onLog("Точка ${cfg.endpoint.render()} не ответила на handshake за ${handshakeWaitMs / 1000} с — пробую следующую")
                uninstallService(engine, PRIMARY_TUNNEL)
                continue
            }

            // Основной туннель поднят!
            resetCounters()
            val nowMs = System.currentTimeMillis()
            val peer = queryPeer(engine, PRIMARY_TUNNEL)
            onLog("Туннель поднят: ${cfg.endpoint.render()} · шум ${cfg.junk.name}")

            // Поднимаем Второй выход, если включён.
            val (secondUp, secondServer) = startSecondExitIfConfigured(engine, secondExit)

            update {
                it.copy(
                    phase = TunnelPhase.CONNECTED,
                    activeEndpoint = cfg.endpoint.render(),
                    activeJunk = cfg.junk.name,
                    rxBytes = peer?.rxBytes ?: 0L,
                    txBytes = peer?.txBytes ?: 0L,
                    rxSpeedBps = 0L,
                    txSpeedBps = 0L,
                    connectedSinceMs = nowMs,
                    handshakeAgeSec = peer?.handshakeAgeSec() ?: 0L,
                    secondExitActive = secondUp,
                    secondExitServer = secondServer,
                    statusMessage = "Туннель работает: ${cfg.endpoint.render()}",
                    lastError = null,
                    advice = null
                )
            }

            // Асинхронно определяем регион выхода и признак warp=on, чтобы не тормозить отклик кнопки.
            scheduler.execute {
                val info = runCatching { exitProber() }.getOrDefault(ExitInfo())
                if (snapshot.isUp && snapshot.activeEndpoint == cfg.endpoint.render()) {
                    onLog("Регион выхода: ${info.regionLabel()} · warp=${if (info.warpOn) "on" else "off"}${if (info.ip.isNotBlank()) " · IP ${info.ip}" else ""}")
                    update { cur ->
                        cur.copy(
                            exitInfo = info,
                            statusMessage = buildString {
                                append("Подключён · ${info.regionLabel()}")
                                if (info.warpOn) append(" · warp=on")
                            }
                        )
                    }
                }
            }

            startHealthMonitor()
            return true
        }

        val failMsg = "Не удалось поднять туннель ни на одной из $total точек"
        onLog(failMsg)
        update {
            it.copy(
                phase = TunnelPhase.ERROR,
                statusMessage = "Туннель не поднялся",
                lastError = failMsg,
                advice = "Провайдер мог закрыть старые адреса или профиль шума. Нажмите «Сканировать и подобрать», чтобы найти свежие рабочие точки."
            )
        }
        return false
    }

    private fun startSecondExitIfConfigured(engine: EngineInfo, spec: SecondExitSpec): Pair<Boolean, String> {
        if (!spec.activeCandidate) return false to ""
        val parsed = WgConf.toWarpConfig("second-exit", spec.confText)
        if (parsed == null) {
            onLog("Второй выход: конфиг не содержит PrivateKey/PublicKey — пропущен (весь трафик идёт через WARP)")
            return false to ""
        }
        val secondConf = parsed.copy(
            allowedIps = spec.cidrsCsv,
            // Не переписываем системный DNS вторым туннелем — DNS уже идёт через основной туннель.
            dns = emptyList()
        )
        val target = if (engine.supportsAwg) ConfTarget.AMNEZIA else ConfTarget.WIREGUARD
        val rendered = WgConf.render(secondConf, target)
        val file = writeTunnelConf(SECOND_EXIT_TUNNEL, rendered)
        onLog("Второй выход: поднимаю ${parsed.endpoint.render()} для выделенных доменов…")
        val res = installService(engine, file)
        if (!res.ok) {
            onLog("Второй выход не запустился (${res.combined.take(120)}) — его маршруты возвращены в WARP")
            uninstallService(engine, SECOND_EXIT_TUNNEL)
            return false to ""
        }
        val hsOk = waitForHandshake(engine, SECOND_EXIT_TUNNEL, minOf(handshakeWaitMs, 6500L))
        if (!hsOk) {
            onLog("Второй выход (${parsed.endpoint.render()}) не ответил на handshake — откатываю его маршруты в WARP")
            uninstallService(engine, SECOND_EXIT_TUNNEL)
            return false to ""
        }
        onLog("Второй выход активен: ${parsed.endpoint.render()}")
        return true to parsed.endpoint.render()
    }

    /** Собирает текст `.conf` для основного туннеля с учётом движка и исключения endpoint'а второго выхода. */
    internal fun renderPrimaryConfig(cfg: WarpConfig, engine: EngineInfo, secondExit: SecondExitSpec): String {
        var effectiveAllowed = cfg.allowedIps
        if (secondExit.activeCandidate) {
            val second = WgConf.toWarpConfig("second-exit", secondExit.confText)
            if (second != null) {
                val ipsToExclude = resolveIpv4s(second.endpoint.host)
                if (ipsToExclude.isNotEmpty()) {
                    effectiveAllowed = CidrMath.excludeIpv4(effectiveAllowed, ipsToExclude)
                }
            }
        }
        val adjusted = cfg.copy(allowedIps = effectiveAllowed)
        val target = if (engine.supportsAwg) ConfTarget.AMNEZIA else ConfTarget.WIREGUARD
        return WgConf.render(adjusted, target)
    }

    private fun resolveIpv4s(host: String): List<String> {
        if (CidrMath.parseIpv4(host) != null) return listOf(host)
        return runCatching {
            InetAddress.getAllByName(host)
                .mapNotNull { it.hostAddress }
                .filter { CidrMath.parseIpv4(it) != null }
                .distinct()
        }.getOrDefault(emptyList())
    }

    private fun buildQueue(primary: WarpConfig, fallbacks: List<WarpConfig>): List<WarpConfig> {
        val seen = LinkedHashSet<String>()
        val out = ArrayList<WarpConfig>(MAX_FAILOVER_QUEUE)
        fun addIfNew(cfg: WarpConfig) {
            if (out.size >= MAX_FAILOVER_QUEUE) return
            val key = "${cfg.endpoint.render()}|${cfg.junk.name}"
            if (seen.add(key)) out.add(cfg)
        }
        addIfNew(primary)
        fallbacks.forEach { addIfNew(it) }
        for (ep in FALLBACK_ENDPOINTS) {
            addIfNew(primary.copy(name = "WARP-Fallback ${ep.render()}", endpoint = ep))
        }
        return out
    }

    private fun writeTunnelConf(name: String, content: String): File {
        tunnelsDir.mkdirs()
        val f = File(tunnelsDir, "$name.conf")
        f.writeText(content, Charsets.UTF_8)
        return f
    }

    private fun installService(engine: EngineInfo, confFile: File): CommandResult {
        val exe = engine.tunnelExe ?: return CommandResult(-1, "", "нет исполняемого файла движка")
        val args = listOf("/installtunnelservice", confFile.absolutePath)
        return if (runner.isElevated()) {
            runner.run(listOf(exe.absolutePath) + args, timeoutMs = 20_000L)
        } else if (autoElevateUac()) {
            runner.runElevated(exe.absolutePath, args, timeoutMs = 25_000L)
        } else {
            CommandResult(-1, "", "Access is denied: требуются права администратора")
        }
    }

    private fun uninstallService(engine: EngineInfo, name: String): CommandResult {
        val exe = engine.tunnelExe ?: return CommandResult(0, "", "")
        val args = listOf("/uninstalltunnelservice", name)
        return if (runner.isElevated()) {
            runner.run(listOf(exe.absolutePath) + args, timeoutMs = 15_000L)
        } else if (autoElevateUac()) {
            runner.runElevated(exe.absolutePath, args, timeoutMs = 20_000L)
        } else {
            CommandResult(0, "", "")
        }
    }

    private fun queryPeer(engine: EngineInfo, name: String): TunnelPeerStats? {
        val cli = engine.cliExe ?: return null
        val res = runner.run(listOf(cli.absolutePath, "show", name, "dump"), timeoutMs = 4000L)
        if (!res.ok) return null
        return AwgDumpParser.parseFirstPeer(res.stdout)
    }

    private fun isServiceRunning(engine: EngineInfo, name: String): Boolean {
        val svc = engine.serviceNameFor(name)
        val res = runner.run(listOf("sc.exe", "query", svc), timeoutMs = 4000L)
        return res.ok && "RUNNING" in res.stdout.uppercase()
    }

    private fun waitForHandshake(engine: EngineInfo, name: String, timeoutMs: Long): Boolean {
        val deadline = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < deadline && !cancelRequested.get()) {
            val peer = queryPeer(engine, name)
            if (peer != null && peer.hasHandshake) return true
            if (engine.cliExe == null && isServiceRunning(engine, name)) return true
            runCatching { Thread.sleep(handshakePollMs) }
        }
        return false
    }

    private fun startHealthMonitor() {
        stopHealthMonitor()
        healthTask = scheduler.scheduleAtFixedRate(
            { runCatching { pollHealth() } },
            healthPollMs,
            healthPollMs,
            TimeUnit.MILLISECONDS
        )
    }

    private fun stopHealthMonitor() {
        healthTask?.cancel(false)
        healthTask = null
    }

    private fun resetCounters() {
        prevRxBytes = 0L
        prevTxBytes = 0L
        prevSampleMs = 0L
        txWithoutRxSinceMs = 0L
    }

    internal fun pollHealth() {
        if (!snapshot.isUp || cancelRequested.get() || reconnecting.get()) return
        val engine = currentEngine
        if (!engine.available) return

        val nowMs = System.currentTimeMillis()
        val peer = queryPeer(engine, PRIMARY_TUNNEL)

        if (peer == null) {
            if (engine.cliExe != null || !isServiceRunning(engine, PRIMARY_TUNNEL)) {
                onLog("Служба туннеля перестала отвечать — запускаю автопереподключение")
                triggerAutoFailover()
            }
            return
        }

        val dtMs = if (prevSampleMs > 0L) (nowMs - prevSampleMs).coerceAtLeast(1L) else healthPollMs
        val dRx = (peer.rxBytes - prevRxBytes).coerceAtLeast(0L)
        val dTx = (peer.txBytes - prevTxBytes).coerceAtLeast(0L)
        val rxSpeed = if (prevSampleMs > 0L) dRx * 1000L / dtMs else 0L
        val txSpeed = if (prevSampleMs > 0L) dTx * 1000L / dtMs else 0L

        if (dRx > 0L) {
            txWithoutRxSinceMs = 0L
        } else if (dTx > 0L && txWithoutRxSinceMs == 0L) {
            txWithoutRxSinceMs = nowMs
        }

        prevRxBytes = peer.rxBytes
        prevTxBytes = peer.txBytes
        prevSampleMs = nowMs

        val hsAge = peer.handshakeAgeSec(nowMs / 1000L)
        update {
            it.copy(
                rxBytes = peer.rxBytes,
                txBytes = peer.txBytes,
                rxSpeedBps = rxSpeed,
                txSpeedBps = txSpeed,
                handshakeAgeSec = hsAge
            )
        }

        // Детектор «мёртвой сессии»: трафик уходит, ответов нет >= 20 с и handshake протух (> 210 с).
        val stalled = txWithoutRxSinceMs > 0L &&
            (nowMs - txWithoutRxSinceMs) >= STALL_NO_RX_MS &&
            hsAge > STALL_HANDSHAKE_AGE_SEC
        if (stalled) {
            onLog("Сессия зависла (handshake ${hsAge} с назад, входящего трафика нет) — меняю точку входа")
            triggerAutoFailover()
        }
    }

    private fun triggerAutoFailover() {
        val now = System.currentTimeMillis()
        if (now < cooldownUntilMs) return
        if (!reconnecting.compareAndSet(false, true)) return
        scheduler.execute {
            try {
                if (consecutiveAutoSwitches >= MAX_FAILOVER_QUEUE) {
                    cooldownUntilMs = System.currentTimeMillis() + COOLDOWN_MS
                    consecutiveAutoSwitches = 0
                    onLog("Достигнут лимит $MAX_FAILOVER_QUEUE переключений подряд — пауза 5 минут перед следующей попыткой")
                    return@execute
                }
                consecutiveAutoSwitches++
                val nextIdx = if (activeQueue.isEmpty()) 0 else (activeQueueIndex + 1) % activeQueue.size
                if (activeQueue.isNotEmpty()) {
                    tryQueueFrom(nextIdx, currentEngine, activeSecondExit, isFailover = true)
                }
            } finally {
                reconnecting.set(false)
            }
        }
    }

    private fun isElevationError(err: String): Boolean {
        val l = err.lowercase()
        return "access is denied" in l ||
            "отказано в доступе" in l ||
            "elevation" in l ||
            "cancelled by the user" in l ||
            "отменена пользователем" in l ||
            "требуются права администратора" in l
    }
}
