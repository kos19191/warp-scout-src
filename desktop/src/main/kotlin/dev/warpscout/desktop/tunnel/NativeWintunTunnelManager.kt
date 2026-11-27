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
import dev.warpscout.core.tunnel.IpPacket
import dev.warpscout.core.tunnel.PacketQueueIn
import dev.warpscout.core.tunnel.SharedPacketOut
import dev.warpscout.core.tunnel.SocketUdpChannel
import dev.warpscout.core.tunnel.UdpChannel
import java.io.File
import java.io.InputStream
import java.net.DatagramSocket
import java.net.InetAddress
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference

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
    private var activeDispatcher: DynamicTunDispatcher? = null

    private val activeExitRouterRef = AtomicReference<ExitRouter>(ExitRouter.EMPTY)

    @Volatile
    private var activeSecondBypassIps: List<String> = emptyList()

    @Volatile
    private var activeSecondHasIpv6: Boolean = false

    @Volatile
    private var activeSecondAllForeign: Boolean = false

    @Volatile
    private var activeSecondSyncHosts: List<String> = emptyList()

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
        val secondBypassIps = if (secondParsed != null) resolveIpv4s(secondParsed.endpoint.host) else emptyList()
        val rawSecondCidrs = if (secondParsed != null) ExitRouter.parse(secondExit.cidrsCsv) else emptyList()
        val isAllForeignSecond = rawSecondCidrs.any { it.trim() == "0.0.0.0/0" }
        val secondHasIpv6 = secondParsed != null && !secondParsed.account.ipv6.isNullOrBlank()
        // Защита от петли в Double-Hop и защита от отправки IPv6 в IPv4-only второй туннель (ProtonVPN):
        //  1. Если у второго выхода нет IPv6 — фильтруем IPv6 CIDR.
        //  2. Всегда вырезаем IP самого сервера второго выхода из ExitRouter, чтобы даже с 0.0.0.0/0
        //     UDP-пакеты к серверу второго выхода шли в lane0 (WARP), а не зацикливались в lane1.
        val sanitizedSecondCidrs = if (secondParsed != null && rawSecondCidrs.isNotEmpty()) {
            val filtered = rawSecondCidrs.filter { secondHasIpv6 || ':' !in it }
            val afterExclude = if (secondBypassIps.isNotEmpty()) {
                ExitRouter.parse(CidrMath.excludeIpv4(filtered.joinToString(", "), secondBypassIps))
            } else {
                filtered
            }
            afterExclude
        } else {
            emptyList()
        }
        val exitRouter = if (secondParsed != null && sanitizedSecondCidrs.isNotEmpty()) {
            ExitRouter.of(sanitizedSecondCidrs)
        } else {
            ExitRouter.EMPTY
        }
        // При пресете «Весь зарубежный трафик» (0.0.0.0/0) не прокидываем 0.0.0.0/0 в extraCidrs Wintun,
        // чтобы режим «Обход РФ» сохранялся: российские сайты идут напрямую, зарубежные — в Wintun → Второй выход.
        val secondExtraRouteCidrs = if (isAllForeignSecond) emptyList() else exitRouter.cidrs

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

            // 1. Определяем IP текущей точки WARP (и Второго выхода, если пробуем напрямую) и добавляем /32 bypass-маршруты через физический шлюз.
            val warpBypassIps = resolveIpv4s(cfg.endpoint.host)
            val initialBypassTargets = if (secondExit.preferViaWarp) {
                warpBypassIps.distinct()
            } else {
                (warpBypassIps + secondBypassIps).distinct()
            }
            if (!skipNetConfig) {
                val added = netConfig.addBypassHostRoutes(initialBypassTargets, physicalGateway)
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

            val useSecondExit = !exitRouter.isEmpty && secondParsed != null
            // Если Второй выход работает только по IPv4 (например ProtonVPN 10.2.0.2/32), отключаем IPv6
            // на Wintun-адаптере, чтобы браузер не уходил на ChatGPT/AI по IPv6 через WARP в обход Второго выхода.
            val disableIpv6ForSecond = useSecondExit && !secondHasIpv6
            val useIpv6 = !skipNetConfig && !disableIpv6ForSecond && netConfig.shouldEnableIpv6(cfg.allowedIps, cfg.enableIpv6Address)
            if (disableIpv6ForSecond) {
                onLog("[Второй выход] Сервер только IPv4 — отключаю IPv6 на адаптере, чтобы исключить утечку в WARP")
            }
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
            //    Сначала пробуем прямой WireGuard; если ТСПУ режет UDP 51820 — автоматически переключаемся
            //    на Double-Hop поверх уже работающего WARP (с TCP MSS clamping 1160 и ICMP PMTU 1200).
            var secondUp = false
            var secondViaWarp = false
            var secondServer = ""
            var secondError = ""
            var routesApplied = false
            if (useSecondExit && secondParsed != null && lane0 != null && lane1 != null) {
                activeExitRouterRef.set(exitRouter)
                activeSecondBypassIps = secondBypassIps
                activeSecondHasIpv6 = secondHasIpv6
                activeSecondAllForeign = isAllForeignSecond
                activeSecondSyncHosts = secondExit.syncHosts
                val dispatcher = DynamicTunDispatcher(
                    tun = tun.input,
                    routerRef = activeExitRouterRef,
                    lanes = listOf(lane0, lane1),
                    log = { msg -> onLog("[маршрутизатор] $msg") }
                )
                activeDispatcher = dispatcher
                Thread(dispatcher, "ws-desktop-dispatch").apply { isDaemon = true; start() }

                val primaryIpBytes = Ipv4Nat.ipv4Bytes(cfg.account.ipv4)
                val secondaryIpBytes = Ipv4Nat.ipv4Bytes(secondParsed.account.ipv4)
                val needNat = primaryIpBytes != null && secondaryIpBytes != null && !primaryIpBytes.contentEquals(secondaryIpBytes)
                if (needNat) {
                    onLog("[Второй выход] 1:1 IPv4 NAT активен (${cfg.account.ipv4} ↔ ${secondParsed.account.ipv4})")
                }

                fun launchSecondAttempt(viaWarp: Boolean, timeoutMs: Long): Boolean {
                    val latch = CountDownLatch(1)
                    val udp2 = runCatching { udpFactory(secondParsed.endpoint) }.getOrNull() ?: return false
                    val maxMss = if (viaWarp) Ipv4Nat.DOUBLE_HOP_MAX_TCP_MSS else 0
                    val pmtu = if (viaWarp) Ipv4Nat.DOUBLE_HOP_PMTU else 0
                    val secondIn = if (needNat || viaWarp) {
                        NatRewriteInputStream(
                            delegate = lane1,
                            primaryIpv4 = primaryIpBytes,
                            secondaryIpv4 = secondaryIpBytes,
                            maxTcpMss = maxMss,
                            pmtuLimit = pmtu,
                            pmtuFeedbackOut = if (viaWarp) tunOutShared else null
                        )
                    } else lane1
                    val secondOut = if (needNat || viaWarp) {
                        NatRewriteOutputStream(
                            delegate = tunOutShared,
                            primaryIpv4 = primaryIpBytes,
                            secondaryIpv4 = secondaryIpBytes,
                            maxTcpMss = maxMss
                        )
                    } else tunOutShared

                    val plane2 = DataPlane(
                        udp = udp2,
                        tunInput = secondIn,
                        tunOutput = secondOut,
                        config = secondParsed,
                        settings = NetSettings(attempts = 3, timeoutMs = 1300),
                        onTunnelUp = { latch.countDown() },
                        screenOn = { true },
                        log = { msg -> onLog("[Второй выход] $msg") },
                        onFatal = { reason ->
                            onLog("Второй выход отключился ($reason) — трафик возвращён в WARP")
                            runCatching { lane1.close() }
                            update {
                                it.copy(
                                    secondExitActive = false,
                                    secondExitServer = "",
                                    secondExitViaWarp = false,
                                    secondExitError = "Сессия прервалась ($reason)"
                                )
                            }
                        }
                    )
                    secondaryPlane = plane2
                    val attemptThread = Thread({
                        plane2.run()
                        latch.countDown()
                    }, if (viaWarp) "ws-desktop-plane2-warp" else "ws-desktop-plane2-direct").apply {
                        isDaemon = true
                        start()
                    }

                    val hsOk = runCatching { latch.await(timeoutMs, TimeUnit.MILLISECONDS) }.getOrDefault(false)
                    if (hsOk && plane2.handshakeOk) {
                        return true
                    }
                    runCatching { plane2.stop() }
                    runCatching { attemptThread.join(400) }
                    if (secondaryPlane === plane2) secondaryPlane = null
                    return false
                }

                // Попытка 1: если пользователь НЕ включил «сразу через WARP», пробуем прямой WireGuard (3.5 с).
                val directOk = if (secondExit.preferViaWarp) {
                    false
                } else {
                    launchSecondAttempt(viaWarp = false, timeoutMs = minOf(handshakeWaitMs, 3500L))
                }
                if (directOk) {
                    secondUp = true
                    secondViaWarp = false
                    secondServer = secondParsed.endpoint.render()
                    onLog("Второй выход активен напрямую: $secondServer (${exitRouter.size} подсетей)")
                } else if (!cancelRequested.get()) {
                    // Double-Hop поверх уже работающего AmneziaWG/WARP (обход блокировки ТСПУ на UDP 51820!).
                    if (secondExit.preferViaWarp) {
                        onLog("[Второй выход] Подключаюсь к ${secondParsed.endpoint.render()} поверх WARP (Double-Hop · обход ТСПУ)…")
                    } else {
                        onLog("[Второй выход] Прямой WireGuard к ${secondParsed.endpoint.render()} не ответил (вероятно, блокировка ТСПУ) — запускаю поверх WARP (Double-Hop)…")
                    }
                    if (!skipNetConfig) {
                        if (!secondExit.preferViaWarp && secondBypassIps.isNotEmpty()) {
                            netConfig.removeBypassHostRoutes(secondBypassIps, physicalGateway)
                            bypassRoutesAdded.removeAll(secondBypassIps.toSet())
                        }
                        val routeRes = netConfig.applyRoutes(
                            adapterName = ADAPTER_NAME,
                            allowedIpsCsv = cfg.allowedIps,
                            extraCidrs = (secondExtraRouteCidrs + secondBypassIps.map { "$it/32" }).distinct(),
                            enableIpv6 = useIpv6,
                            adapterLuid = tun.adapterLuid,
                            excludeIpv4s = warpBypassIps
                        )
                        routesApplied = true
                        if (!routeRes.ok) {
                            onLog("Предупреждение при установке маршрутов Double-Hop: ${routeRes.combined.take(160)}")
                        }
                    }

                    val warpHopOk = launchSecondAttempt(viaWarp = true, timeoutMs = minOf(handshakeWaitMs, 6500L))
                    if (warpHopOk) {
                        secondUp = true
                        secondViaWarp = true
                        secondServer = secondParsed.endpoint.render()
                        onLog("Второй выход активен поверх WARP (Double-Hop): $secondServer (${exitRouter.size} подсетей, MSS=${Ipv4Nat.DOUBLE_HOP_MAX_TCP_MSS})")
                    } else {
                        secondError = if (secondExit.preferViaWarp) {
                            "Сервер ${secondParsed.endpoint.render()} не ответил через WARP — проверьте ключи или скачайте новый .conf"
                        } else {
                            "Сервер ${secondParsed.endpoint.render()} не ответил ни напрямую, ни через WARP — проверьте ключи или скачайте новый .conf"
                        }
                        onLog("Второй выход (${secondParsed.endpoint.render()}) не ответил поверх WARP — маршруты идут через WARP")
                        runCatching { lane1.close() }
                    }
                } else {
                    runCatching { lane1.close() }
                }
            }

            // 5. Handshake подтверждён — накатываем маршруты туннеля на Wintun-адаптер (если ещё не накатили для Double-Hop)!
            if (!skipNetConfig && !routesApplied) {
                val routeRes = netConfig.applyRoutes(
                    adapterName = ADAPTER_NAME,
                    allowedIpsCsv = cfg.allowedIps,
                    extraCidrs = if (secondUp) secondExtraRouteCidrs else emptyList(),
                    enableIpv6 = useIpv6,
                    adapterLuid = tun.adapterLuid,
                    excludeIpv4s = if (secondUp && !secondViaWarp) initialBypassTargets else warpBypassIps
                )
                if (!routeRes.ok) {
                    onLog("Предупреждение при установке маршрутов: ${routeRes.combined.take(160)}")
                }
            }
            if (!skipNetConfig) {
                runCatching { netConfig.flushDns() }
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
                    secondExitViaWarp = secondViaWarp,
                    secondExitError = secondError,
                    secondExitCheckOk = null,
                    secondExitCheckText = if (secondUp) "Проверяю выход (chatgpt.com)…" else "",
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

            // Если Второй выход активен — сразу в отдельном потоке синхронизируем свежие IP из системного DNS
            // внутри поднятого туннеля (чтобы chatgpt.com/openai.com 100% совпадали с DNS браузера!) и проверяем выход.
            if (secondUp && !skipNetConfig) {
                Thread({
                    runCatching { Thread.sleep(250L) }
                    if (snapshot.isUp && snapshot.secondExitActive && !cancelRequested.get()) {
                        syncAndCheckSecondExit()
                    }
                }, "ws-second-verify").apply { isDaemon = true; start() }
            }
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

    /**
     * Добавляет новые CIDR в живой [ExitRouter] Второго выхода без переподключения туннеля
     * (с автоматическим вырезанием IP сервера Второго выхода для защиты от петли).
     * Возвращает фактически добавленные новые CIDR.
     */
    internal fun addCidrsToLiveRouter(newCidrs: Collection<String>): List<String> {
        if (newCidrs.isEmpty()) return emptyList()
        val cur = activeExitRouterRef.get()
        val existingSet = cur.cidrs.toHashSet()
        val filtered = newCidrs
            .map { it.trim() }
            .filter { it.isNotEmpty() && (activeSecondHasIpv6 || ':' !in it) }
            .distinct()
        val safe = if (activeSecondBypassIps.isNotEmpty()) {
            ExitRouter.parse(CidrMath.excludeIpv4(filtered.joinToString(", "), activeSecondBypassIps))
        } else {
            filtered
        }
        val toAdd = safe.filter { it !in existingSet }
        if (toAdd.isEmpty()) return emptyList()
        val merged = ExitRouter.of((cur.cidrs + toAdd).distinct())
        activeExitRouterRef.set(merged)
        return toAdd
    }

    /**
     * Синхронизирует DNS ключевых доменов Второго выхода прямо изнутри работающего туннеля
     * (системный DNS Windows + 1.1.1.1 DoH + dns.google DoH) и проверяет реальный выход
     * через `https://chatgpt.com/cdn-cgi/trace`.
     */
    fun syncAndCheckSecondExit(
        extraHosts: List<String> = emptyList(),
        onNewCidrs: (List<String>) -> Unit = {}
    ): Boolean {
        if (!snapshot.isUp || !snapshot.secondExitActive) return false
        update { it.copy(secondExitCheckText = "Синхронизирую DNS и проверяю chatgpt.com…") }

        // 1. Если не выбран «Весь зарубежный трафик», освежаем IP ключевых доменов из системного DNS + DoH.
        val addedAll = LinkedHashSet<String>()
        var chatgptIps = emptyList<String>()
        if (!activeSecondAllForeign) {
            val targets = (activeSecondSyncHosts + extraHosts + SecondExitCatalog.CHECK_HOST)
                .map { it.trim().lowercase() }
                .filter { it.isNotEmpty() && '.' in it }
                .distinct()
                .take(80)
            val resolved = SecondExitCatalog.resolveBatch(targets, threads = 12) { host ->
                SecondExitCatalog.resolveMultiSource(
                    host = host,
                    includeIpv6 = activeSecondHasIpv6,
                    includeSystemDns = true
                )
            }
            chatgptIps = resolved[SecondExitCatalog.CHECK_HOST].orEmpty()
            val candidateCidrs = LinkedHashSet<String>()
            for (ips in resolved.values) {
                for (ip in ips) {
                    val cidr = SecondExitCatalog.normalizeCidr(ip) ?: continue
                    if (activeSecondHasIpv6 || ':' !in cidr) candidateCidrs.add(cidr)
                }
            }
            val added = addCidrsToLiveRouter(candidateCidrs)
            addedAll.addAll(added)
            if (added.isNotEmpty()) {
                val cgNote = if (chatgptIps.isNotEmpty()) " (chatgpt.com → ${chatgptIps.take(4).joinToString(", ")})" else ""
                onLog("[Второй выход] Синхронизация DNS внутри туннеля: добавлено ${added.size} свежих IP$cgNote (всего в таблице: ${activeExitRouterRef.get().size})")
                if (!skipNetConfig) runCatching { netConfig.flushDns() }
                onNewCidrs(added)
            } else if (chatgptIps.isNotEmpty()) {
                val r = activeExitRouterRef.get()
                val matched = chatgptIps.count { ip -> ExitRouter.ipBytes(ip)?.let { r.route(it) == 1 } == true }
                onLog("[Второй выход] DNS-сверка: chatgpt.com → ${chatgptIps.take(4).joinToString(", ")} (в таблице: $matched/${chatgptIps.size})")
            }
        }

        if (skipNetConfig) return true

        // 2. Реальная проверка выхода через https://chatgpt.com/cdn-cgi/trace (до 2 попыток: если 1-я ушла в WARP,
        //    добавляем точный системный IP chatgpt.com на лету и повторяем).
        for (attempt in 1..2) {
            val t0 = System.currentTimeMillis()
            val resp = runCatching {
                HttpClient(timeoutMs = 5500).get("https://${SecondExitCatalog.CHECK_HOST}/cdn-cgi/trace")
            }.getOrNull()
            val ms = (System.currentTimeMillis() - t0).coerceAtLeast(1L)

            if (resp == null || resp.status !in 200..299) {
                val errNote = if (resp == null) "таймаут / нет ответа (${ms} мс)" else "HTTP ${resp.status}"
                onLog("[Второй выход] Проверка chatgpt.com: $errNote (пакетов через 2-й выход: ${activeDispatcher?.sentSecondary ?: 0})")
                update {
                    it.copy(
                        secondExitCheckOk = false,
                        secondExitCheckText = "chatgpt.com не ответил: $errNote"
                    )
                }
                return false
            }

            val trace = TraceAndSpeed.parseCloudflareTrace(resp.body)
            val ip = trace["ip"].orEmpty()
            val loc = trace["loc"].orEmpty().uppercase()
            val colo = trace["colo"].orEmpty().uppercase()
            val warpOn = trace["warp"].equals("on", ignoreCase = true) || trace["warp"].equals("plus", ignoreCase = true)

            if (!warpOn && ip.isNotBlank()) {
                val place = buildString {
                    if (loc.isNotBlank()) append(loc)
                    if (colo.isNotBlank()) append(if (isNotEmpty()) " ($colo)" else colo)
                    if (isEmpty()) append("2-й выход")
                }
                val text = "chatgpt.com → $place · IP $ip (${ms} мс)"
                onLog("[Второй выход] Проверка chatgpt.com: ОК · $text · warp=off (пакетов через 2-й выход: ${activeDispatcher?.sentSecondary ?: 0})")
                update {
                    it.copy(
                        secondExitCheckOk = true,
                        secondExitCheckText = text
                    )
                }
                return true
            }

            // Запрос ушёл через WARP! Добираем системные IP chatgpt.com и пробуем ещё раз.
            val sysIps = resolveIpv4s(SecondExitCatalog.CHECK_HOST)
            if (attempt == 1 && !activeSecondAllForeign && sysIps.isNotEmpty()) {
                val addedRetry = addCidrsToLiveRouter(sysIps.map { "$it/32" })
                if (addedRetry.isNotEmpty()) {
                    addedAll.addAll(addedRetry)
                    onNewCidrs(addedRetry)
                    onLog("[Второй выход] chatgpt.com на 1-й проверке ушёл в WARP — добавил ${addedRetry.joinToString(", ")} в таблицу, повторяю проверку…")
                    continue
                }
            }

            val warnText = "chatgpt.com ушёл в WARP ($ip) — выберите «Весь зарубежный трафик» или нажмите «Проверить выход»"
            onLog(
                "[Второй выход] Проверка chatgpt.com: ушло через WARP (IP=$ip, loc=$loc, sysIps=${sysIps.joinToString(",")}, " +
                    "пакетов во 2-й выход=${activeDispatcher?.sentSecondary ?: 0}, таблица=${activeExitRouterRef.get().size})"
            )
            update {
                it.copy(
                    secondExitCheckOk = false,
                    secondExitCheckText = warnText
                )
            }
            return false
        }
        return false
    }
}

/**
 * Диспетчер пакетов Wintun с горячей заменой таблицы [ExitRouter] через [AtomicReference],
 * чтобы новые IP из системного DNS добавлялись во Второй выход на лету без переподключения туннеля.
 */
internal class DynamicTunDispatcher(
    private val tun: InputStream,
    private val routerRef: AtomicReference<ExitRouter>,
    private val lanes: List<PacketQueueIn>,
    private val log: (String) -> Unit = {}
) : Runnable {

    @Volatile
    private var stopped = false

    @Volatile
    var sentPrimary: Long = 0L
        private set

    @Volatile
    var sentSecondary: Long = 0L
        private set

    @Volatile
    var dropped: Long = 0L
        private set

    fun stop() {
        stopped = true
        lanes.forEach { runCatching { it.close() } }
    }

    override fun run() {
        val buf = ByteArray(65535)
        while (!stopped) {
            val n = try {
                tun.read(buf)
            } catch (_: Exception) {
                -1
            }
            if (n <= 0) break
            val packet = buf.copyOf(n)
            val dst = IpPacket.dst(packet)
            if (dst == null) {
                dropped++
                continue
            }
            val wanted = routerRef.get().route(dst)
            val lane = when {
                wanted !in lanes.indices -> 0
                lanes[wanted].isClosed() -> 0
                else -> wanted
            }
            if (lane in lanes.indices) {
                lanes[lane].offer(packet)
                if (lane == 0) sentPrimary++ else sentSecondary++
            } else {
                dropped++
            }
        }
        lanes.forEach { runCatching { it.close() } }
        log("диспетчер tun остановлен (WARP: $sentPrimary, 2-й выход: $sentSecondary)")
    }
}
