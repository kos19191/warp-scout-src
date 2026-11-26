package dev.warpscout.desktop.tunnel

import dev.warpscout.core.config.WgConf
import dev.warpscout.core.junk.JunkLibrary
import dev.warpscout.core.model.Endpoint
import dev.warpscout.core.model.ResourceCheck
import dev.warpscout.core.model.ResourceResult
import dev.warpscout.core.model.WarpConfig
import dev.warpscout.core.net.HttpClient
import dev.warpscout.core.net.NetSettings
import dev.warpscout.core.net.ResourceProber
import dev.warpscout.core.tune.TunnelVerifier
import dev.warpscout.core.tunnel.DataPlane
import dev.warpscout.core.tunnel.ExitRouter
import dev.warpscout.core.tunnel.PacketQueueIn
import dev.warpscout.core.tunnel.SharedPacketOut
import dev.warpscout.core.tunnel.SocketUdpChannel
import dev.warpscout.core.tunnel.TunDispatcher
import dev.warpscout.core.tunnel.UdpChannel
import java.io.File
import java.net.DatagramSocket
import java.net.InetAddress
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Собственный встроенный туннель WarpScout для Windows — без установки AmneziaWG и сторонних VPN.
 *
 * Архитектура 1-в-1 с Android `WarpVpnService`:
 *  • виртуальный сетевой адаптер создаётся напрямую через встроенную подписанную `wintun.dll`;
 *  • шифрование, WireGuard/AmneziaWG handshake, мусорные пакеты, keepalive, пересогласование сессии
 *    (rekey) и детектор зависаний (`StallDetector`) выполняются нашим ядром [DataPlane] из `:core`;
 *  • «Второй выход» работает внутри того же адаптера через [ExitRouter] + [TunDispatcher] + второй
 *    [DataPlane] — при отказе второго сервера трафик мгновенно и без разрыва возвращается в WARP;
 *  • системные маршруты (`0.0.0.0/1 + 128.0.0.0/1`) накатываются ТОЛЬКО после подтверждённого
 *    криптографического handshake, а до IP точек добавляются `/32` bypass-маршруты через физический
 *    шлюз — петля маршрутизации и «сломанный интернет» исключены.
 */
class NativeWintunTunnelManager(
    private val nativeDir: File,
    private val runner: CommandRunner = ProcessCommandRunner(),
    netConfig: WindowsNetConfigurator? = null,
    private val tunFactory: (String) -> TunDevice = { name -> WintunDevice.open(name, nativeDir) },
    private val udpFactory: (Endpoint) -> UdpChannel = { ep -> SocketUdpChannel(DatagramSocket(), ep, timeoutMs = 1500) },
    private val onState: (TunnelSnapshot) -> Unit = {},
    private val onLog: (String) -> Unit = {},
    private val exitProber: () -> ExitInfo = { TraceAndSpeed.probeExitInfo() },
    private val handshakeWaitMs: Long = 8000L,
    private val statsPollMs: Long = 1500L,
    private val requireElevationCheck: Boolean = true,
    private val skipNetConfig: Boolean = false
) {
    private val netConfig: WindowsNetConfigurator = netConfig ?: WindowsNetConfigurator(runner, onLog = onLog)

    companion object {
        const val ADAPTER_NAME = "WilyScout"
        const val PROBE_ADAPTER_NAME = "WilyScoutProbe"
        const val MAX_FAILOVER_QUEUE = WindowsTunnelManager.MAX_FAILOVER_QUEUE
        const val COOLDOWN_MS = WindowsTunnelManager.COOLDOWN_MS
    }

    @Volatile
    var snapshot: TunnelSnapshot = TunnelSnapshot()
        private set

    /** Фактически подключённая конфигурация (включая сработавшую резервную точку). */
    @Volatile
    var activeConfig: WarpConfig? = null
        private set

    @Volatile
    private var activeQueue: List<WarpConfig> = emptyList()

    @Volatile
    private var activeQueueIndex: Int = 0

    @Volatile
    private var activeSecondExit: SecondExitSpec = SecondExitSpec()

    // Текущие активные ресурсы туннеля.
    @Volatile
    private var activeTun: TunDevice? = null

    @Volatile
    private var activeDispatcher: TunDispatcher? = null

    @Volatile
    private var primaryPlane: DataPlane? = null

    @Volatile
    private var secondaryPlane: DataPlane? = null

    @Volatile
    private var physicalGateway: PhysicalGateway? = null

    private val bypassRoutesAdded = LinkedHashSet<String>()
    private val cancelRequested = AtomicBoolean(false)
    private val reconnecting = AtomicBoolean(false)
    private var consecutiveAutoSwitches = 0
    private var cooldownUntilMs = 0L

    private var prevRxBytes = 0L
    private var prevTxBytes = 0L
    private var prevSampleMs = 0L

    private val scheduler = Executors.newSingleThreadScheduledExecutor { r ->
        Thread(r, "warpscout-wintun-stats").apply { isDaemon = true }
    }
    private var statsTask: ScheduledFuture<*>? = null

    private fun update(transform: (TunnelSnapshot) -> TunnelSnapshot) {
        val next = transform(snapshot)
        snapshot = next
        onState(next)
    }

    fun isDriverReady(): Boolean = WintunLoader.isAvailable(nativeDir)

    /** Последний определённый физический шлюз и локальный IPv4 (до наката маршрутов Wintun). */
    fun currentPhysicalGateway(): PhysicalGateway? = physicalGateway

    @Synchronized
    fun connect(
        primary: WarpConfig,
        fallbacks: List<WarpConfig> = emptyList(),
        secondExit: SecondExitSpec = SecondExitSpec()
    ): Boolean {
        cancelRequested.set(false)
        activeSecondExit = secondExit
        consecutiveAutoSwitches = 0
        cooldownUntilMs = 0L

        if (requireElevationCheck && !runner.isElevated()) {
            val msg = "Для создания виртуального адаптера Wintun требуются права администратора"
            onLog(msg)
            update {
                it.copy(
                    phase = TunnelPhase.ERROR,
                    statusMessage = "Нужны права администратора",
                    lastError = msg,
                    advice = "Нажмите «Перезапустить от администратора» — Windows запросит подтверждение UAC, после чего WilyScout сразу поднимет встроенный туннель без сторонних программ.",
                    needsElevation = true
                )
            }
            return false
        }

        val queue = buildQueue(primary, fallbacks)
        activeQueue = queue
        activeQueueIndex = 0
        stopStatsPoller()
        teardownActiveSession()

        if (!skipNetConfig) {
            physicalGateway = netConfig.detectPhysicalGateway()
            if (physicalGateway != null) {
                onLog("Физический шлюз: ${physicalGateway!!.nextHop} (интерфейс #${physicalGateway!!.interfaceIndex})")
            } else {
                onLog("Предупреждение: не удалось определить физический шлюз по умолчанию")
            }
        }

        return tryQueueFrom(0, secondExit, isFailover = false)
    }

    @Synchronized
    fun switchToNextEndpoint(): Boolean {
        if (activeQueue.size <= 1) {
            onLog("В очереди нет запасных точек для переключения")
            return false
        }
        val nextIdx = (activeQueueIndex + 1) % activeQueue.size
        onLog("Смена точки входа → ${activeQueue[nextIdx].endpoint.render()}")
        stopStatsPoller()
        teardownActiveSession()
        return tryQueueFrom(nextIdx, activeSecondExit, isFailover = true)
    }

    @Synchronized
    fun disconnect(reason: String = "Туннель выключен") {
        cancelRequested.set(true)
        stopStatsPoller()
        teardownActiveSession()
        cleanupAllBypassRoutes()
        if (!skipNetConfig) {
            runCatching { netConfig.flushDns() }
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
        stopStatsPoller()
        teardownActiveSession()
        cleanupAllBypassRoutes()
        scheduler.shutdownNow()
    }

    /**
     * [TunnelVerifier] для [dev.warpscout.core.tune.AutoTuner] на базе нашего встроенного туннеля:
     * проверяет топ-3 кандидата изнутри реального туннеля Wintun без внешних программ.
     */
    fun createVerifier(): TunnelVerifier? {
        if (requireElevationCheck && !runner.isElevated()) return null
        if (!skipNetConfig && !isDriverReady()) return null
        return object : TunnelVerifier {
            override val title: String = "Встроенный туннель WilyScout (Wintun)"

            @Volatile
            private var probeTun: TunDevice? = null

            @Volatile
            private var probePlane: DataPlane? = null

            override fun verify(config: WarpConfig, checks: List<ResourceCheck>, settleMs: Int): List<ResourceResult> {
                val gw = if (!skipNetConfig) netConfig.detectPhysicalGateway() else null
                val bypassIps = resolveIpv4s(config.endpoint.host)
                val added = if (!skipNetConfig) netConfig.addBypassHostRoutes(bypassIps, gw) else emptyList()
                var tun: TunDevice? = null
                var plane: DataPlane? = null
                try {
                    tun = tunFactory(PROBE_ADAPTER_NAME)
                    probeTun = tun
                    if (!skipNetConfig) {
                        val cfgRes = netConfig.configureAdapter(
                            adapterName = PROBE_ADAPTER_NAME,
                            ipv4 = config.account.ipv4,
                            ipv6 = null, // Проверка изнутри идёт по IPv4 (0.0.0.0/1 + 128.0.0.0/1) — не вешаем лишний IPv6 без маршрутов.
                            mtu = config.mtu,
                            dnsServers = config.dns,
                            adapterLuid = tun.adapterLuid
                        )
                        if (!cfgRes.ok) {
                            onLog("проверка изнутри: ошибка настройки адаптера (${cfgRes.combined.take(120)})")
                            return emptyList()
                        }
                    }

                    val upLatch = CountDownLatch(1)
                    val udp = udpFactory(config.endpoint)
                    plane = DataPlane(
                        udp = udp,
                        tunInput = tun.input,
                        tunOutput = tun.output,
                        config = config,
                        settings = NetSettings(attempts = 3, timeoutMs = 1500),
                        onTunnelUp = { upLatch.countDown() },
                        log = { }
                    )
                    probePlane = plane
                    val runnerThread = Thread({ plane.run() }, "ws-probe-plane").apply { isDaemon = true; start() }
                    val ok = upLatch.await(minOf(handshakeWaitMs, 6500L), TimeUnit.MILLISECONDS)
                    if (!ok || !plane.handshakeOk) {
                        onLog("проверка изнутри: нет handshake от ${config.endpoint.render()}")
                        return emptyList()
                    }
                    if (!skipNetConfig) {
                        // Для короткой проверки кандидатов достаточно 2 маршрутов (0.0.0.0/1 + 128.0.0.0/1)
                        // с обязательным вырезанием IP самой точки, чтобы исключить петлю маршрутизации.
                        netConfig.applyRoutes(
                            adapterName = PROBE_ADAPTER_NAME,
                            allowedIpsCsv = "0.0.0.0/0",
                            enableIpv6 = false,
                            adapterLuid = tun.adapterLuid,
                            excludeIpv4s = bypassIps
                        )
                    }
                    if (settleMs > 0) {
                        runCatching { Thread.sleep(minOf(settleMs.toLong(), 1500L)) }
                    }
                    // Быстрый тест «идут ли вообще данные сквозь туннель» (~4 с вместо 30–40 с таймаутов
                    // по всем 10 сайтам, если DPI пропускает handshake, но глушит транспорт).
                    var probeColo = ""
                    if (!skipNetConfig) {
                        val quickTrace = runCatching {
                            HttpClient(timeoutMs = 3500).get("https://1.1.1.1/cdn-cgi/trace")
                        }.getOrNull()
                        if (quickTrace != null && quickTrace.status in 200..299) {
                            probeColo = TraceAndSpeed.parseCloudflareTrace(quickTrace.body)["colo"].orEmpty().uppercase()
                        }
                        val hasData = (quickTrace != null && quickTrace.status in 200..299) || plane.bytesDown > 128L
                        if (!hasData) {
                            onLog("проверка изнутри: ${config.endpoint.render()} · ${config.junk.name} — handshake прошёл, но трафик не идёт (0 Б)")
                            return checks.map { ResourceResult(check = it, ok = false, errorClass = "no_tunnel_traffic") }
                        }
                    }
                    val prober = ResourceProber(HttpClient(timeoutMs = 5500))
                    val rawResults = prober.checkAll(checks)
                    val isRuColo = probeColo in TraceAndSpeed.RU_COLOS
                    val results = if (isRuColo) {
                        // Выход через российский дата-центр Cloudflare (DME/LED/OVB) часто режется ТСПУ:
                        // снимаем «бесплатные» очки контроля/Cloudflare/Google-204, чтобы узел РФ
                        // никогда не проходил порог 75–80% и не мешал поиску зарубежного узла (FRA/ARN/HEL).
                        rawResults.map { r ->
                            if (r.check.baselineExpected ||
                                r.check.url.contains("cloudflare.com/cdn-cgi/trace") ||
                                r.check.url.contains("google.com/generate_204")
                            ) {
                                r.copy(ok = false, errorClass = "ru_colo_$probeColo")
                            } else r
                        }
                    } else {
                        rawResults
                    }
                    val failedNames = results.filterNot { it.ok }.map { it.check.name }
                    val coloNote = when {
                        probeColo.isBlank() -> ""
                        isRuColo -> " · выход $probeColo (узел РФ!)"
                        else -> " · выход $probeColo"
                    }
                    val failNote = if (failedNames.isEmpty()) " · все доступны" else " · не открылись: ${failedNames.take(5).joinToString(", ")}"
                    onLog("проверка изнутри: ${config.endpoint.render()} · ${config.junk.name}$coloNote$failNote")
                    return results
                } catch (e: Exception) {
                    onLog("проверка изнутри (${config.endpoint.render()}): ${e.message}")
                    return emptyList()
                } finally {
                    runCatching { plane?.stop() }
                    runCatching { tun?.close() }
                    probePlane = null
                    probeTun = null
                    if (added.isNotEmpty() && !skipNetConfig) {
                        netConfig.removeBypassHostRoutes(added, gw)
                    }
                }
            }

            override fun stop() {
                runCatching { probePlane?.stop() }
                runCatching { probeTun?.close() }
            }
        }
    }

    // ---------------------------------------------------------------- внутренняя логика

    private fun tryQueueFrom(
        startIdx: Int,
        secondExit: SecondExitSpec,
        isFailover: Boolean
    ): Boolean {
        val total = activeQueue.size
        val secondParsed = if (secondExit.activeCandidate) {
            WgConf.toWarpConfig("second-exit", secondExit.confText)
        } else null
        val secondCidrs = if (secondParsed != null) ExitRouter.parse(secondExit.cidrsCsv) else emptyList()
        val exitRouter = if (secondParsed != null && secondCidrs.isNotEmpty()) ExitRouter.of(secondCidrs) else ExitRouter.EMPTY

        for (offset in 0 until total) {
            if (cancelRequested.get()) {
                teardownActiveSession()
                cleanupAllBypassRoutes()
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
                    needsElevation = false,
                    attemptIndex = offset + 1,
                    attemptTotal = total
                )
            }
            onLog("Поднимаю встроенный туннель (${offset + 1}/$total): ${cfg.endpoint.render()} · шум ${cfg.junk.name}")

            teardownActiveSession()

            // 1. Определяем IP текущей точки WARP (и Второго выхода) и добавляем /32 bypass-маршруты через физический шлюз.
            val bypassTargets = buildList {
                addAll(resolveIpv4s(cfg.endpoint.host))
                if (secondParsed != null) addAll(resolveIpv4s(secondParsed.endpoint.host))
            }
            if (!skipNetConfig) {
                val added = netConfig.addBypassHostRoutes(bypassTargets, physicalGateway)
                bypassRoutesAdded.addAll(added)
            }

            // 2. Открываем Wintun-адаптер и настраиваем IP/MTU/DNS (маршруты пока НЕ трогаем!).
            val tun = try {
                tunFactory(ADAPTER_NAME)
            } catch (e: Exception) {
                val msg = e.message ?: e.javaClass.simpleName
                onLog("Ошибка открытия Wintun-адаптера: $msg")
                val elev = "администратор" in msg.lowercase() || "access" in msg.lowercase() || "код windows 5" in msg.lowercase()
                update {
                    it.copy(
                        phase = TunnelPhase.ERROR,
                        statusMessage = if (elev) "Нужны права администратора" else "Ошибка адаптера Wintun",
                        lastError = msg,
                        advice = if (elev) "Перезапустите WilyScout от имени администратора для создания сетевого адаптера."
                        else "Проверьте, что драйвер wintun.dll не заблокирован антивирусом.",
                        needsElevation = elev
                    )
                }
                return false
            }
            activeTun = tun

            val useIpv6 = !skipNetConfig && netConfig.shouldEnableIpv6(cfg.allowedIps, cfg.enableIpv6Address)
            if (!skipNetConfig) {
                val cfgRes = netConfig.configureAdapter(
                    adapterName = ADAPTER_NAME,
                    ipv4 = cfg.account.ipv4,
                    ipv6 = if (useIpv6) cfg.account.ipv6 else null,
                    mtu = cfg.mtu,
                    dnsServers = cfg.dns,
                    adapterLuid = tun.adapterLuid
                )
                if (!cfgRes.ok) {
                    val err = cfgRes.combined.ifBlank { "код ${cfgRes.exitCode}" }
                    onLog("Ошибка настройки интерфейса Wintun: $err")
                    teardownActiveSession()
                    continue
                }
            }

            // 3. Подключаем DataPlane (один выход или два выхода через ExitRouter + TunDispatcher).
            val upLatch = CountDownLatch(1)
            val fatalTriggered = AtomicBoolean(false)
            val useSecondExit = !exitRouter.isEmpty && secondParsed != null

            val lane0: PacketQueueIn?
            val lane1: PacketQueueIn?
            val tunInForPrimary = if (useSecondExit) {
                lane0 = PacketQueueIn("warp")
                lane1 = PacketQueueIn("second-exit")
                lane0
            } else {
                lane0 = null
                lane1 = null
                tun.input
            }
            val tunOutShared = if (useSecondExit) SharedPacketOut(tun.output) else tun.output

            val udpPrimary = try {
                udpFactory(cfg.endpoint)
            } catch (e: Exception) {
                onLog("Ошибка UDP-сокета до ${cfg.endpoint.render()}: ${e.message}")
                teardownActiveSession()
                continue
            }

            val plane1 = DataPlane(
                udp = udpPrimary,
                tunInput = tunInForPrimary,
                tunOutput = tunOutShared,
                config = cfg,
                settings = NetSettings(attempts = 4, timeoutMs = 1500),
                onTunnelUp = { upLatch.countDown() },
                screenOn = { true }, // На ПК экран не усыпляет радиомодем.
                log = { msg -> onLog("[WARP] $msg") },
                onFatal = { reason ->
                    if (fatalTriggered.compareAndSet(false, true) && !cancelRequested.get()) {
                        onLog("Сбой активной сессии: $reason — переключаю точку входа")
                        triggerAutoFailover()
                    }
                }
            )
            primaryPlane = plane1

            val planeThread = Thread({
                plane1.run()
                upLatch.countDown()
            }, "ws-desktop-plane1").apply { isDaemon = true; start() }

            // Ждём подтверждённого WireGuard/AWG handshake ДО включения маршрутов!
            val signaled = runCatching { upLatch.await(handshakeWaitMs, TimeUnit.MILLISECONDS) }.getOrDefault(false)
            if (!signaled || !plane1.handshakeOk || cancelRequested.get()) {
                val why = plane1.failureReason ?: "нет ответа за ${handshakeWaitMs / 1000} с"
                onLog("Точка ${cfg.endpoint.render()} не поднялась ($why) — пробую следующую")
                teardownActiveSession()
                runCatching { planeThread.join(600) }
                continue
            }

            // 4. Если настроен Второй выход — запускаем TunDispatcher и второй DataPlane на том же адаптере!
            var secondUp = false
            var secondServer = ""
            if (useSecondExit && secondParsed != null && lane0 != null && lane1 != null) {
                val dispatcher = TunDispatcher(
                    tun = tun.input,
                    router = exitRouter,
                    lanes = listOf(lane0, lane1),
                    log = { msg -> onLog("[маршрутизатор] $msg") }
                )
                activeDispatcher = dispatcher
                Thread(dispatcher, "ws-desktop-dispatch").apply { isDaemon = true; start() }

                val secondLatch = CountDownLatch(1)
                val udp2 = runCatching { udpFactory(secondParsed.endpoint) }.getOrNull()
                if (udp2 != null) {
                    val plane2 = DataPlane(
                        udp = udp2,
                        tunInput = lane1,
                        tunOutput = tunOutShared,
                        config = secondParsed,
                        settings = NetSettings(attempts = 3, timeoutMs = 1500),
                        onTunnelUp = { secondLatch.countDown() },
                        screenOn = { true },
                        log = { msg -> onLog("[Второй выход] $msg") },
                        onFatal = { reason ->
                            onLog("Второй выход отключился ($reason) — трафик возвращён в WARP")
                            runCatching { lane1.close() }
                            update { it.copy(secondExitActive = false, secondExitServer = "") }
                        }
                    )
                    secondaryPlane = plane2
                    Thread({
                        val ok2 = plane2.run()
                        secondLatch.countDown()
                        if (!ok2) {
                            runCatching { lane1.close() }
                        }
                    }, "ws-desktop-plane2").apply { isDaemon = true; start() }

                    val hs2 = runCatching { secondLatch.await(minOf(handshakeWaitMs, 6000L), TimeUnit.MILLISECONDS) }.getOrDefault(false)
                    if (hs2 && plane2.handshakeOk) {
                        secondUp = true
                        secondServer = secondParsed.endpoint.render()
                        onLog("Второй выход активен: $secondServer (${exitRouter.size} подсетей)")
                    } else {
                        onLog("Второй выход (${secondParsed.endpoint.render()}) не ответил — маршруты идут через WARP")
                        runCatching { plane2.stop() }
                        runCatching { lane1.close() }
                        secondaryPlane = null
                    }
                } else {
                    runCatching { lane1.close() }
                }
            }

            // 5. Handshake подтверждён — накатываем маршруты туннеля на Wintun-адаптер!
            // Обязательно вырезаем IP точек (bypassTargets) из маршрутов Wintun — петля невозможна.
            if (!skipNetConfig) {
                val routeRes = netConfig.applyRoutes(
                    adapterName = ADAPTER_NAME,
                    allowedIpsCsv = cfg.allowedIps,
                    extraCidrs = if (secondUp) exitRouter.cidrs else emptyList(),
                    enableIpv6 = useIpv6,
                    adapterLuid = tun.adapterLuid,
                    excludeIpv4s = bypassTargets
                )
                if (!routeRes.ok) {
                    onLog("Предупреждение при установке маршрутов: ${routeRes.combined.take(160)}")
                }
            }

            resetCounters()
            activeConfig = cfg
            val nowMs = System.currentTimeMillis()
            onLog("Встроенный туннель поднят: ${cfg.endpoint.render()} · шум ${cfg.junk.name}")

            update {
                it.copy(
                    phase = TunnelPhase.CONNECTED,
                    activeEndpoint = cfg.endpoint.render(),
                    activeJunk = cfg.junk.name,
                    rxBytes = plane1.bytesDown,
                    txBytes = plane1.bytesUp,
                    rxSpeedBps = 0L,
                    txSpeedBps = 0L,
                    connectedSinceMs = nowMs,
                    handshakeAgeSec = 0L,
                    secondExitActive = secondUp,
                    secondExitServer = secondServer,
                    statusMessage = "Туннель работает: ${cfg.endpoint.render()}",
                    lastError = null,
                    advice = null,
                    needsElevation = false
                )
            }

            // Асинхронно определяем регион выхода и warp=on.
            // Если handshake прошёл, но трафик полностью заблокирован DPI (warp=off и 0 входящих байт),
            // сразу переключаемся на следующую точку (~5 с вместо 45 с ожидания StallDetector).
            scheduler.execute {
                val info = runCatching { exitProber() }.getOrDefault(ExitInfo())
                if (snapshot.isUp && snapshot.activeEndpoint == cfg.endpoint.render() && !cancelRequested.get()) {
                    onLog("Регион выхода: ${info.regionLabel()} · warp=${if (info.warpOn) "on" else "off"}${if (info.ip.isNotBlank()) " · IP ${info.ip}" else ""}")
                    if (info.isRussianColo) {
                        onLog("Внимание: трафик выходит через российский узел Cloudflare (${info.colo}) — часть сервисов (Telegram и др.) может ограничиваться. Попробуйте переключить точку (Топ-3) на зарубежный узел (ARN/HEL/FRA).")
                    }
                    update { cur ->
                        cur.copy(
                            exitInfo = info,
                            statusMessage = buildString {
                                append("Подключён · ${info.regionLabel()}")
                                if (info.warpOn) append(" · warp=on")
                            }
                        )
                    }
                    val noTraffic = !info.warpOn && info.ip.isBlank() && plane1.bytesDown < 128L
                    if (noTraffic && !skipNetConfig && activeQueue.size > 1) {
                        onLog("Точка ${cfg.endpoint.render()} (${cfg.junk.name}) не пропускает трафик (warp=off, получено ${plane1.bytesDown} Б) — переключаю на следующую")
                        triggerAutoFailover()
                    }
                }
            }

            startStatsPoller()
            return true
        }

        val failMsg = "Не удалось поднять встроенный туннель ни на одной из $total точек"
        onLog(failMsg)
        cleanupAllBypassRoutes()
        update {
            it.copy(
                phase = TunnelPhase.ERROR,
                statusMessage = "Туннель не поднялся",
                lastError = failMsg,
                advice = "Провайдер мог закрыть старые адреса или профиль шума. Нажмите «Подобрать и подключить», чтобы найти свежие рабочие точки.",
                needsElevation = false
            )
        }
        return false
    }

    private fun teardownActiveSession() {
        activeConfig = null
        runCatching { activeDispatcher?.stop() }
        activeDispatcher = null
        runCatching { secondaryPlane?.stop() }
        secondaryPlane = null
        runCatching { primaryPlane?.stop() }
        primaryPlane = null
        runCatching { activeTun?.close() }
        activeTun = null
    }

    private fun cleanupAllBypassRoutes() {
        if (bypassRoutesAdded.isEmpty()) return
        val copy = bypassRoutesAdded.toList()
        bypassRoutesAdded.clear()
        if (!skipNetConfig) {
            netConfig.removeBypassHostRoutes(copy, physicalGateway)
        }
    }

    private fun startStatsPoller() {
        stopStatsPoller()
        statsTask = scheduler.scheduleAtFixedRate(
            { runCatching { pollStats() } },
            statsPollMs,
            statsPollMs,
            TimeUnit.MILLISECONDS
        )
    }

    private fun stopStatsPoller() {
        statsTask?.cancel(false)
        statsTask = null
    }

    private fun resetCounters() {
        prevRxBytes = 0L
        prevTxBytes = 0L
        prevSampleMs = 0L
    }

    internal fun pollStats() {
        if (!snapshot.isUp) return
        val p1 = primaryPlane ?: return
        val p2 = secondaryPlane
        val rx = p1.bytesDown + (p2?.bytesDown ?: 0L)
        val tx = p1.bytesUp + (p2?.bytesUp ?: 0L)
        val nowMs = System.currentTimeMillis()
        val dtMs = if (prevSampleMs > 0L) (nowMs - prevSampleMs).coerceAtLeast(1L) else statsPollMs
        val rxSpeed = if (prevSampleMs > 0L) (rx - prevRxBytes).coerceAtLeast(0L) * 1000L / dtMs else 0L
        val txSpeed = if (prevSampleMs > 0L) (tx - prevTxBytes).coerceAtLeast(0L) * 1000L / dtMs else 0L
        prevRxBytes = rx
        prevTxBytes = tx
        prevSampleMs = nowMs

        update {
            it.copy(
                rxBytes = rx,
                txBytes = tx,
                rxSpeedBps = rxSpeed,
                txSpeedBps = txSpeed,
                handshakeAgeSec = p1.sessionAgeMs() / 1000L
            )
        }
    }

    private fun triggerAutoFailover() {
        if (cancelRequested.get()) return
        val now = System.currentTimeMillis()
        if (now < cooldownUntilMs) return
        if (!reconnecting.compareAndSet(false, true)) return
        scheduler.execute {
            try {
                if (cancelRequested.get()) return@execute
                if (consecutiveAutoSwitches >= MAX_FAILOVER_QUEUE) {
                    cooldownUntilMs = System.currentTimeMillis() + COOLDOWN_MS
                    consecutiveAutoSwitches = 0
                    onLog("Достигнут лимит $MAX_FAILOVER_QUEUE переключений подряд — пауза 5 минут")
                    return@execute
                }
                consecutiveAutoSwitches++
                stopStatsPoller()
                teardownActiveSession()
                if (cancelRequested.get()) return@execute
                val nextIdx = if (activeQueue.isEmpty()) 0 else (activeQueueIndex + 1) % activeQueue.size
                if (activeQueue.isNotEmpty()) {
                    tryQueueFrom(nextIdx, activeSecondExit, isFailover = true)
                }
            } finally {
                reconnecting.set(false)
            }
        }
    }

    internal fun buildQueue(primary: WarpConfig, fallbacks: List<WarpConfig>): List<WarpConfig> {
        val seen = LinkedHashSet<String>()
        val out = ArrayList<WarpConfig>(MAX_FAILOVER_QUEUE)
        fun addIfNew(cfg: WarpConfig) {
            if (out.size >= MAX_FAILOVER_QUEUE) return
            val key = "${cfg.endpoint.render()}|${cfg.junk.name}"
            if (seen.add(key)) out.add(cfg)
        }
        addIfNew(primary)

        // Сначала добавляем запасные точки с ДРУГИМ профилем шума: если DPI зарезал `none`,
        // автопереключение сразу перейдёт на `sip-invite`/`quic:*`/`tls-fixed`, а не на второй `none`.
        val diffJunk = fallbacks.filter { it.junk.name != primary.junk.name }
        val sameJunk = fallbacks.filter { it.junk.name == primary.junk.name }
        diffJunk.forEach { addIfNew(it) }
        sameJunk.forEach { addIfNew(it) }

        // Аварийные запасные точки: если основной профиль был без маскировки (`none`),
        // чередуем маскировку (sip-invite / tls-fixed), чтобы failover мог обойти DPI.
        val emergencyJunks = if (primary.junk.name == "none") {
            listOf(JunkLibrary.sip(), JunkLibrary.tlsFixed(), JunkLibrary.quic("deepseek.com", level = 3, seed = 7L))
        } else {
            listOf(primary.junk, JunkLibrary.sip(), JunkLibrary.tlsFixed())
        }
        WindowsTunnelManager.FALLBACK_ENDPOINTS.forEachIndexed { idx, ep ->
            val j = emergencyJunks[idx % emergencyJunks.size]
            addIfNew(primary.copy(name = "WARP-Fallback ${ep.render()}", endpoint = ep, junk = j))
        }
        return out
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
}
