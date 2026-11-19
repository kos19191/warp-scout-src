package dev.warpscout.app.tunnel

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import androidx.core.app.NotificationCompat
import dev.warpscout.app.Prefs
import dev.warpscout.app.R
import dev.warpscout.app.TunnelDebug
import dev.warpscout.core.config.SplitRoutes
import dev.warpscout.core.config.WgConf
import dev.warpscout.core.model.WarpConfig
import dev.warpscout.core.net.NetSettings
import dev.warpscout.core.tunnel.DataPlane
import dev.warpscout.core.tunnel.ExitRouter
import dev.warpscout.core.tunnel.PacketQueueIn
import dev.warpscout.core.tunnel.SharedPacketOut
import dev.warpscout.core.tunnel.TunDispatcher
import dev.warpscout.core.tunnel.SocketUdpChannel
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.net.DatagramSocket
import java.net.InetSocketAddress
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/**
 * Собственный туннель: VpnService + data plane из `:core` (handshake AWG, transport-пакеты,
 * keepalive, счётчики). Чужой бэкенд не нужен: AWG отличается от WireGuard только мусором перед
 * инициацией, а его отправляет тот же [DataPlane].
 *
 * Существует только во flavor'е `tunnel` (см. app/src/tunnel/AndroidManifest.xml).
 */
class WarpVpnService : VpnService() {

    private var plane: DataPlane? = null
    /** Второй выход (другой сервер): свой data plane и сокет, если включён. */
    private var plane2: DataPlane? = null
    private var worker2: Thread? = null
    private var secondSocket: DatagramSocket? = null
    /** Разделитель пакетов между выходами: tun читает только он. */
    private var dispatcher: TunDispatcher? = null
    private var tun: ParcelFileDescriptor? = null
    private var worker: Thread? = null
    private var udpSocket: DatagramSocket? = null
    private val stopped = java.util.concurrent.atomic.AtomicBoolean(false)

    /**
     * Номер попытки подъёма. Поток подъёма, который начался до «Отключить», обязан увидеть, что
     * его эпоха устарела, и выйти, не трогая tun/сокет/plane: иначе он закрывал бы файловые
     * дескрипторы уже следующей сессии — ровно то, из-за чего «после выключения больше не включается».
     */
    private val epoch = java.util.concurrent.atomic.AtomicInteger(0)

    /** Идёт подъём или уже работает — второй запуск (плитка, кнопка, шторка) игнорируем. */
    @Volatile
    private var starting = false

    /** Текст конфига, которым поднят туннель: по нему же переподнимаем после смены сети. */
    @Volatile
    private var lastConfigText: String? = null
    @Volatile
    private var lastStartId: Int = 0

    /**
     * Слежение за «настоящей» сетью (без VPN). Раньше это жило в MainActivity — и в фоне, когда
     * экран погашен или активити уничтожена, не работало вовсе: переключение Wi-Fi ↔ мобильные
     * оставляло мёртвый UDP-сокет, туннель молчал, а замочек в шторке продолжал висеть.
     * Теперь наблюдатель живёт в сервисе — он существует всё время работы туннеля.
     */
    private var netCallback: android.net.ConnectivityManager.NetworkCallback? = null

    /** Сеть, через которую поднимали туннель: с ней сравниваем, чтобы не перезапускаться зря. */
    @Volatile
    private var baselineNetwork: android.net.Network? = null

    /** Сеть менялась — значит, туннель нужно переподнять, даже если новой сети пока нет. */
    @Volatile
    private var networkChanged = false

    @Volatile
    private var lastNetRestartAt: Long = 0L

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            shutdown()
            // stopSelf обязателен: без него экземпляр живёт дальше со своим состоянием, и следующий
            // запуск может прийти в него же (см. эпоху выше и сброс stopped в startVpn).
            runCatching { stopSelf() }
            return START_NOT_STICKY
        }
        if (starting || plane != null) {
            // Повторное нажатие «Подключить» (кнопка, плитка быстрых настроек) не должно
            // поднимать второй туннель поверх первого — только напомнить, что уже работаем.
            TunnelState.status = "туннель уже поднимается или работает"
            postNotification(TunnelState.status)
            return START_REDELIVER_INTENT
        }
        val text = intent?.getStringExtra(EXTRA_CONF)
        if (text.isNullOrBlank()) {
            TunnelState.status = "нет конфигурации — запуск пропущен"
            stopSelf()
            return START_NOT_STICKY
        }
        lastConfigText = text
        lastStartId = startId
        // Раньше здесь был startVpn(text) напрямую, и onStartCommand блокировался на 12 с, ожидая
        // handshake. Главный поток сервиса — он же главный поток приложения: UI в это время висел,
        // и выглядело это ровно как «туннель запускается, потом без ошибок ничего не происходит».
        Thread({ startVpn(text, startId) }, "warpscout-vpn-boot").apply { isDaemon = true }.start()
        return START_REDELIVER_INTENT
    }

    override fun onDestroy() {
        shutdown()
        super.onDestroy()
    }

    private fun startVpn(text: String, startId: Int) {
        val myEpoch = epoch.incrementAndGet()
        fun alive() = myEpoch == epoch.get() && !stopped.get()
        // Выход из устаревшей попытки обязан снять свои флаги, иначе сервис навсегда останется
        // «занятым»: следующий старт получит «уже поднимается» и не сделает ничего. Именно это
        // выглядело как «немного работает, потом больше не подключается».
        fun abandon() {
            if (myEpoch == epoch.get() && !stopped.get()) {
                starting = false
                TunnelState.busy = false
            }
        }
        starting = true
        // Экземпляр сервиса переиспользуется: без сброса флага «остановлен» второй подъём после
        // «Отключить» жил бы с чужим состоянием (watchdog и статусы считали бы себя остановленными).
        stopped.set(false)
        TunnelState.busy = true
        TunnelState.up = false
        TunnelState.error = null
        TunnelState.gaveUp = false
        TunnelState.startedAt = System.currentTimeMillis()
        TunnelDebug.reset()
        createChannel()
        postNotification("Поднимаю туннель…")

        watchNetwork()
        TunnelDebug.stage("конфиг получен (${text.toByteArray().size} байт)")
        val cfg = runCatching { WgConf.toWarpConfig("WARP", text) }.getOrNull()
        if (cfg == null) {
            fail("конфиг не разбирается: нет PrivateKey или PublicKey", startId)
            return
        }
        TunnelState.endpoint = cfg.endpoint.render()
        TunnelDebug.stage("сервер ${cfg.endpoint.render()}, шум ${cfg.junk.name}, MTU ${cfg.mtu}")

        val socket = try {
            // soTimeout = 1500: ровно столько ждём один ответ handshake; attempts в NetSettings умножает это.
            DatagramSocket(null).apply { reuseAddress = true; soTimeout = 1500 }
        } catch (e: Exception) {
            fail("сокет: ${e.javaClass.simpleName} ${e.message}", startId)
            return
        }
        // Без protect() пакеты туннеля попадут в сам туннель — трафик замкнётся по кругу.
        val protected = runCatching { protect(socket) }.getOrDefault(false)
        if (!protected) {
            runCatching { socket.close() }
            fail("protect() отказал — туннель не поднят во избежание петли", startId)
            return
        }
        runCatching { socket.connect(InetSocketAddress(cfg.endpoint.host, cfg.endpoint.port)) }
            .onFailure { runCatching { socket.close() }; fail("connect(): ${it.message}", startId); return }
        TunnelDebug.stage("UDP-сокет создан и защищён")
        if (!alive()) {
            // Пока поднимались, пользователь нажал «Отключить» (или пошла следующая попытка).
            runCatching { socket.close() }
            abandon()
            return
        }

        // Второй выход: другой сервер для выбранных подсетей (страна/провайдер на выбор).
        // Внутри WARP выбрать регион нельзя, поэтому «регион для сайта» = второй туннель рядом.
        val secondCfg = secondConfig()
        val router = secondCfg?.let { ExitRouter.of(ExitRouter.parse(Prefs(this).secondCidrs)) }
            ?.takeIf { !it.isEmpty } ?: ExitRouter.EMPTY
        val multiExit = secondCfg != null && !router.isEmpty

        val builder = builderFor(cfg)
        if (multiExit) {
            // В split-режиме подсети второго выхода должны попадать в tun, иначе они уйдут мимо.
            router.cidrs.forEach { cidr ->
                val host = cidr.substringBefore('/').trim()
                val bits = cidr.substringAfter('/', "").trim().toIntOrNull()
                if (host.isNotEmpty() && bits != null) runCatching { builder.addRoute(host, bits) }
            }
            TunnelDebug.stage("второй выход: ${router.size} подсетей, сервер ${secondCfg?.endpoint?.render()}")
        }

        val pfd = try {
            builder.establish()
        } catch (e: Exception) {
            runCatching { socket.close() }
            fail("tun: ${e.javaClass.simpleName} ${e.message?.take(140)}", startId)
            return
        }
        if (pfd == null) {
            runCatching { socket.close() }
            fail("VpnService не выдал tun (обычно уже работает другой VPN)", startId)
            return
        }
        if (!alive()) {
            // tun уже выдан, но эта попытка устарела: закрываем, иначе интерфейс останется чужим.
            runCatching { pfd.close() }
            runCatching { socket.close() }
            abandon()
            return
        }
        tun = pfd
        udpSocket = socket
        val routes = SplitRoutes.prefixesOf(cfg.allowedIps)
        TunnelDebug.stage("tun получен: ${routes.size} маршрутов, blocking=${isFullTunnel(cfg)}")

        val handshake = CountDownLatch(1)

        // Со вторым выходом tun читает диспетчер, а каждый data plane читает свою очередь.
        // Без второго выхода — ровно прежнее поведение (прямые потоки), регрессии быть не должно.
        val secondSock = if (multiExit && secondCfg != null) openSecondSocket(secondCfg) else null
        val rawIn = FileInputStream(pfd.fileDescriptor)
        val rawOut = FileOutputStream(pfd.fileDescriptor)
        val lanes = if (secondSock != null) listOf(PacketQueueIn("основной"), PacketQueueIn("второй")) else emptyList()
        val tunOut: OutputStream = if (lanes.isEmpty()) rawOut else SharedPacketOut(rawOut)
        val tunIn: InputStream = if (lanes.isEmpty()) rawIn else lanes[0]
        if (lanes.isNotEmpty()) {
            val dispatcher = TunDispatcher(rawIn, router, lanes) { line -> TunnelDebug.stage(line) }
            this.dispatcher = dispatcher
            Thread(dispatcher, "warpscout-tun-split").apply { isDaemon = true; start() }
        }

        val plane = DataPlane(
            udp = SocketUdpChannel(socket, cfg.endpoint, 1500),
            tunInput = tunIn,
            tunOutput = tunOut,
            config = cfg,
            // Пять инициаций с интервалом 400 мс: первая же обычно отвечает за доли секунды,
            // а если датаграмм потерялся — следующая уходит не через 1.5 с, а почти сразу.
            settings = NetSettings(
                attempts = 5, timeoutMs = 1000, retryEveryMs = 400, junkPacketsBeforeHandshake = 1
            ),
            // Сокет перестал отправлять — сеть ушла без уведомления от системы. Переподнимаем.
            onFatal = { reason -> restartAfterNetworkChange(reason) },
            log = { line ->
                TunnelState.status = line
                when {
                    line.contains("туннель поднят") -> {
                        TunnelState.up = true
                        handshake.countDown()
                        TunnelDebug.ok(line)
                        postNotification("Туннель активен: ${cfg.endpoint.render()}")
                    }
                    // Пересогласование сессии — штатное событие раз в две минуты, но именно его
                    // отсутствие раньше выглядело как «туннель есть, интернета нет».
                    line.startsWith("rekey") || line.contains("cookie") -> {
                        TunnelDebug.ok(line)
                    }
                    line.startsWith("попытка") -> {
                        TunnelDebug.noteAttempt(line)
                    }
                    line.contains("не прошёл") -> TunnelDebug.error(line, "endpoint молчит или ключи не подошли")
                    else -> TunnelDebug.stage(line)
                }
                TunnelDebug.bytesUp = planeBytesUp()
            }
        )
        this.plane = plane
        worker = Thread {
            val ok = runCatching { plane.run() }.getOrDefault(false)
            TunnelDebug.bytesUp = plane.bytesUp
            TunnelDebug.bytesDown = plane.bytesDown
            TunnelState.up = false
            when {
                stopped.get() -> TunnelState.status = "туннель остановлен"
                !ok -> {
                    val why = plane.failureReason ?: "endpoint молчит"
                    fail(
                        if (plane.handshakeOk) "туннель закрылся во время работы"
                        else "handshake не прошёл (${plane.attemptCount} попыток): $why",
                        startId
                    )
                }
                else -> {
                    TunnelState.status = "туннель закрыт (пира не стало)"
                    TunnelDebug.stage("туннель закрыт: прошло ${plane.bytesUp} байт вверх, ${plane.bytesDown} вниз")
                    stopSelfSafely()
                }
            }
        }.apply { isDaemon = true; name = "warpscout-vpn"; start() }

        // Второй выход запускаем сразу после основного: он независим (своя сессия, свой rekey),
        // и его падение не должно ронять туннель — трафик просто продолжит идти через WARP.
        val secondary = if (lanes.size > 1 && secondCfg != null && secondSock != null) {
            DataPlane(
                udp = SocketUdpChannel(secondSock, secondCfg.endpoint, 1500),
                tunInput = lanes[1],
                tunOutput = tunOut,
                config = secondCfg,
                settings = NetSettings(attempts = 3, timeoutMs = 1000, retryEveryMs = 500, junkPacketsBeforeHandshake = 1),
                log = { line ->
                    when {
                        line.contains("туннель поднят") ->
                            TunnelDebug.ok("второй выход поднят: ${secondCfg.endpoint.render()}")
                        line.contains("не прошёл") || line.contains("невозможен") ->
                            TunnelDebug.error("второй выход: $line", "проверь второй конфиг и его endpoint")
                        else -> TunnelDebug.stage("второй: $line")
                    }
                }
            )
        } else {
            null
        }
        if (secondary != null) {
            plane2 = secondary
            secondSocket = secondSock
            val lane2 = lanes.getOrNull(1)
            worker2 = Thread {
                val ok2 = runCatching { secondary.run() }.getOrDefault(false)
                // Очередь закрываем: диспетчер увидит это и вернёт подсети в основной туннель.
                runCatching { lane2?.close() }
                TunnelDebug.stage(
                    "второй выход остановлен: ${if (ok2) "закрыт" else "аварийно"}, " +
                        "прошло ${secondary.bytesUp} вверх / ${secondary.bytesDown} вниз"
                )
            }.apply { isDaemon = true; name = "warpscout-vpn-2"; start() }
        }

        // Handshake ждём НЕ здесь (мы и так на отдельном потоке, а главному потоку делать нечего):
        // ждёт [dev.warpscout.app.VpnTunnelController.startAndAwait], опрашивая TunnelState.
        // Тут только страховка: если за 25 с туннель не поднялся — сами себя снимаем и объясняем почему.
        Thread {
            val waited = runCatching { handshake.await(25, TimeUnit.SECONDS) }.getOrDefault(false)
            if (!waited && !stopped.get() && !TunnelState.up) {
                fail("таймаут: за 25 с handshake не завершился", startId)
            } else if (waited) {
                watchTraffic(startId)
            }
        }.apply { isDaemon = true; name = "warpscout-vpn-watch"; start() }
    }

    /**
     * «Туннель поднят, а интернета нет» — отдельный диагноз: if up, но счётчики нулевые, значит
     * маршруты не совпали (split-tunnel) или пира не шлёт трафик. Молча это оставлять нельзя.
     */
    private fun watchTraffic(startId: Int) {
        val deadline = System.currentTimeMillis() + 8000
        while (System.currentTimeMillis() < deadline && !stopped.get()) {
            val p = plane
            if (p != null && (p.bytesUp > 0 || p.bytesDown > 0)) {
                TunnelDebug.ok("трафик пошёл: вверх ${p.bytesUp}, вниз ${p.bytesDown} байт")
                TunnelDebug.bytesUp = p.bytesUp
                TunnelDebug.bytesDown = p.bytesDown
                return
            }
            Thread.sleep(500)
        }
        if (!stopped.get() && TunnelState.up) {
            val p = plane
            if (p != null && p.bytesUp == 0L && p.bytesDown == 0L) {
                TunnelDebug.error(
                    "туннель поднят, но ноль пакетов за 8 с",
                    "проверь AllowedIPs: в split-tunnel через WARP идут только перечисленные сети"
                )
                postNotification("Туннель поднят, трафик не идёт")
            }
        }
    }

    /** Конфиг второго выхода из настроек (null — выключен или пустой). */
    private fun secondConfig(): WarpConfig? {
        val prefs = Prefs(this)
        if (!prefs.secondExitOn) return null
        val text = prefs.secondConf
        if (text.isBlank()) return null
        return runCatching { WgConf.toWarpConfig("второй выход", text) }.getOrNull()
    }

    /** Отдельный защищённый сокет для второго выхода: свой protect() обязателен, иначе петля. */
    private fun openSecondSocket(cfg: WarpConfig): DatagramSocket? {
        val socket = runCatching {
            DatagramSocket(null).apply { reuseAddress = true; soTimeout = 1500 }
        }.getOrNull() ?: return null
        if (!runCatching { protect(socket) }.getOrDefault(false)) {
            runCatching { socket.close() }
            TunnelDebug.error("второй выход: protect() отказал", "второй туннель не поднят, трафик идёт через WARP")
            return null
        }
        val connected = runCatching {
            socket.connect(InetSocketAddress(cfg.endpoint.host, cfg.endpoint.port))
        }.isSuccess
        if (!connected) {
            runCatching { socket.close() }
            TunnelDebug.error("второй выход: connect() не удался", "проверь endpoint второго конфига")
            return null
        }
        return socket
    }

    private fun isFullTunnel(cfg: WarpConfig): Boolean =
        SplitRoutes.prefixesOf(cfg.allowedIps).any { it == "0.0.0.0/0" || it == "::/0" }

    private fun planeBytesUp(): Long = plane?.bytesUp ?: 0L

    /** Единственная точка «мы сдались»: статус + журнал + аккуратная остановка. */
    private fun fail(reason: String, startId: Int) {
        starting = false
        TunnelState.busy = false
        TunnelState.status = reason
        TunnelState.error = reason
        TunnelState.gaveUp = true
        TunnelDebug.error(reason)
        runCatching {
            TunnelDebug.writeToFile(File(filesDir, "tunnel-debug.log"))
        }
        stopSelfSafely()
    }

    private fun stopSelfSafely() {
        runCatching { stopSelf() }
    }

    private fun builderFor(cfg: WarpConfig): Builder {
        val builder = Builder()
            .setSession("WarpScout")
            .setMtu(cfg.mtu.coerceIn(576, 1420))
            // setBlocking(true) = «всё, что не попало в маршруты, ЗАПРЕТИТЬ». При split-tunnel это
            // убило бы весь российский трафик (его в AllowedIPs нет намеренно), поэтому блокируем
            // только когда туннель и правда полный.
            .setBlocking(isFullTunnel(cfg))
        runCatching { builder.setMetered(false) }   // иначе часть телефонов режет фоновый трафик в туннеле
        runCatching { builder.addAddress(cfg.account.ipv4.substringBefore('/'), 32) }
        val v6 = cfg.account.ipv6?.takeIf { cfg.enableIpv6Address && it.isNotBlank() }
        if (v6 != null) runCatching { builder.addAddress(v6.substringBefore('/'), 128) }
        cfg.dns.forEach { if (it.isNotBlank()) runCatching { builder.addDnsServer(it.trim()) } }
        cfg.allowedIps.split(',').map { it.trim() }.filter { it.contains('/') }.forEach { cidr ->
            // IPv6-маршрут без IPv6-адреса на интерфейсе — чёрная дыра (пакеты уходят в tun и
            // пропадают). Проверено на живом запросе: с таким маршрутом Telegram и браузер
            // «открывались наполовину». Поэтому v6-маршруты добавляем только с адресом.
            if (cidr.contains(':') && v6 == null) return@forEach
            val parts = cidr.split('/')
            val bits = parts[1].trim().toIntOrNull() ?: return@forEach
            runCatching { builder.addRoute(parts[0].trim(), bits) }
        }
        applyAppSplit(builder)
        return builder
    }

    /**
     * Разделение по приложениям. Amnezia делает то же самое: в режиме «только выбранные»
     * в туннель попадают лишь отмеченные пакеты, в режиме «всё, кроме выбранных» — наоборот.
     *
     * Пустой список не должен означать «ничего не туннелировать»: если пользователь выбрал
     * «только выбранные», но ничего не отметил, честнее пустить всё и сказать об этом в журнале,
     * чем оставить телефон без интернета и без объяснений.
     */
    private fun applyAppSplit(builder: Builder) {
        val prefs = Prefs(this)
        val selected = prefs.appsSelected.filter { it != packageName }
        when (prefs.appsMode) {
            Prefs.APPS_ONLY -> {
                if (selected.isEmpty()) {
                    TunnelDebug.stage("приложения: режим «только выбранные», но список пуст — идут все")
                } else {
                    selected.forEach { runCatching { builder.addAllowedApplication(it) } }
                    TunnelDebug.stage("приложения: только выбранные (${selected.size})")
                }
            }

            Prefs.APPS_EXCEPT -> {
                if (selected.isEmpty()) {
                    TunnelDebug.stage("приложения: все через туннель (исключений нет)")
                } else {
                    selected.forEach { runCatching { builder.addDisallowedApplication(it) } }
                    TunnelDebug.stage("приложения: все, кроме выбранных (${selected.size})")
                }
            }

            else -> TunnelDebug.stage("приложения: все через туннель")
        }
    }

    private fun postNotification(text: String) {
        // startForeground обязаны быть вызваны в течение ~5 с после startForegroundService, а теперь
        // весь путь у нас на worker-потоке — поэтому просто кидаем задачу на главный (он свободен).
        if (Thread.currentThread() !== mainLooperThread) {
            android.os.Handler(android.os.Looper.getMainLooper()).post { postNotificationNow(text) }
            return
        }
        postNotificationNow(text)
    }

    private val mainLooperThread: Thread get() = android.os.Looper.getMainLooper().thread

    private fun postNotificationNow(text: String) {
        createChannel()
        val open = android.app.PendingIntent.getActivity(
            this, 0,
            Intent(this, dev.warpscout.app.MainActivity::class.java)
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
            android.app.PendingIntent.FLAG_UPDATE_CURRENT or android.app.PendingIntent.FLAG_IMMUTABLE
        )
        val stopPi = android.app.PendingIntent.getService(
            this, 1,
            Intent(this, WarpVpnService::class.java).apply { action = ACTION_STOP },
            android.app.PendingIntent.FLAG_UPDATE_CURRENT or android.app.PendingIntent.FLAG_IMMUTABLE
        )
        val n = NotificationCompat.Builder(this, CHANNEL)
            .setContentTitle(getString(R.string.app_name))
            .setContentText(text)
            // Пустая иконка: значок приложения в строке состояния не появляется (см. ic_stat_blank).
            .setSmallIcon(R.drawable.ic_stat_blank)
            .setOngoing(true)
            .setSilent(true)
            .setShowWhen(false)
            .setPriority(NotificationCompat.PRIORITY_MIN)
            .setVisibility(NotificationCompat.VISIBILITY_SECRET)
            .setContentIntent(open)
            .addAction(0, getString(R.string.notif_stop), stopPi)
            .build()
        // Тип сервиса — specialUse (см. манифест): «vpn» приложению недоступен. На 34+
        // тип передаём явно, иначе летит MissingForegroundServiceTypeException.
        val started = if (Build.VERSION.SDK_INT >= 34) {
            runCatching { startForeground(NOTIF_ID, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE) }
                .recoverCatching { startForeground(NOTIF_ID, n) }
        } else {
            runCatching { startForeground(NOTIF_ID, n) }
        }
        if (started.isFailure) TunnelState.status = "startForeground отказал: ${started.exceptionOrNull()?.message}"
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            runCatching { notifyManager().notify(NOTIF_ID, n) }
        }
        refreshTile()
    }

    /** Плитка быстрых настроек показывает не своё «я», а реальное состояние сервиса. */
    private fun refreshTile() = runCatching {
        android.service.quicksettings.TileService.requestListeningState(
            this, android.content.ComponentName(this, TunnelTileService::class.java)
        )
    }

    private fun createChannel() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return
        val mgr = notifyManager()
        // Важность канала нельзя понизить после создания — поэтому новый id и удаление старого.
        // IMPORTANCE_MIN: уведомление сворачивается в самый низ шторки и молчит.
        mgr.createNotificationChannel(
            NotificationChannel(CHANNEL, getString(R.string.notif_channel), NotificationManager.IMPORTANCE_MIN).apply {
                setShowBadge(false)
                enableVibration(false)
                setSound(null, null)
                lockscreenVisibility = Notification.VISIBILITY_SECRET
            }
        )
        runCatching { mgr.deleteNotificationChannel(LEGACY_CHANNEL) }
    }

    private fun notifyManager(): NotificationManager =
        getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager

    private fun shutdown() {
        // Эпоха растёт первой: любой поток подъёма сразу становится недействительным.
        epoch.incrementAndGet()
        TunnelState.busy = false
        if (!stopped.compareAndSet(false, true)) return
        starting = false
        TunnelState.up = false
        TunnelState.status = "туннель остановлен"
        unwatchNetwork()
        closeAll()
        runCatching { stopForeground(STOP_FOREGROUND_REMOVE) }
    }

    /** Закрыть сокеты, tun и оба data plane — без решения «останавливаемся навсегда». */
    private fun closeAll() {
        runCatching { dispatcher?.stop() }
        dispatcher = null
        runCatching { plane2?.stop() }
        plane2 = null
        runCatching { secondSocket?.close() }
        secondSocket = null
        runCatching { worker2?.join(500) }
        worker2 = null
        runCatching { plane?.stop() }
        plane = null
        // Поток закрыт → читающий его цикл выйдет сам; join только из чужого потока.
        val w = worker
        if (w != null && w !== Thread.currentThread()) runCatching { w.join(1000) }
        worker = null
        runCatching { udpSocket?.close() }
        udpSocket = null
        runCatching { tun?.close() }
        tun = null
    }

    // ------------------------------------------------------------ смена сети

    /**
     * Следим за сетью, у которой нет флага VPN (то есть за настоящей: Wi-Fi или мобильной).
     *
     * `registerDefaultNetworkCallback` здесь не годится: при поднятом туннеле «сеть по умолчанию» —
     * это сам туннель, и смена Wi-Fi ↔ LTE его не трогает. Поэтому просим сеть с
     * `NET_CAPABILITY_NOT_VPN` и сравниваем с той, на которой поднимались.
     */
    private fun watchNetwork() {
        if (netCallback != null) return
        val cm = runCatching { getSystemService(android.net.ConnectivityManager::class.java) }.getOrNull()
            ?: return
        val request = runCatching {
            android.net.NetworkRequest.Builder()
                .addCapability(android.net.NetworkCapabilities.NET_CAPABILITY_INTERNET)
                .addCapability(android.net.NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
                .build()
        }.getOrNull() ?: return
        val cb = object : android.net.ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: android.net.Network) {
                val base = baselineNetwork
                if (base == null) {
                    baselineNetwork = network
                    TunnelDebug.stage("сеть туннеля: ${describeNetwork(network)}")
                    if (networkChanged) {
                        // Сети не было (или сменилась, пока её не было) — поднимаем заново.
                        restartAfterNetworkChange("сеть появилась: ${describeNetwork(network)}")
                    }
                    return
                }
                if (network == base) return
                baselineNetwork = network
                networkChanged = true
                restartAfterNetworkChange("новая сеть: ${describeNetwork(network)}")
            }

            override fun onLost(network: android.net.Network) {
                if (network != baselineNetwork) return
                baselineNetwork = null
                networkChanged = true
                TunnelState.up = false
                TunnelState.status = "сеть пропала — жду новую"
                postNotification(TunnelState.status)
                TunnelDebug.stage("сеть пропала (${describeNetwork(network)}): старый UDP-сокет мёртв")
                // Если новая сеть не появится, tun нельзя оставлять: приложения будут отправлять
                // трафик в туннель, из которого ничего не выходит (чёрная дыра, «интернета нет»).
                Thread({
                    runCatching { Thread.sleep(45_000) }
                    if (stopped.get() || baselineNetwork != null) return@Thread
                    TunnelDebug.stage("45 секунд без сети — снимаю туннель, чтобы трафик не уходил в пустоту")
                    TunnelState.status = "нет сети — туннель снят"
                    postNotification(TunnelState.status)
                    epoch.incrementAndGet()
                    stopped.set(true)
                    starting = false
                    TunnelState.up = false
                    TunnelState.busy = false
                    closeAll()
                    stopped.set(false)
                }, "warpscout-net-watchdog").apply { isDaemon = true }.start()
            }
        }
        val ok = runCatching { cm.registerNetworkCallback(request, cb) }.isSuccess
        if (ok) netCallback = cb else TunnelDebug.stage("не удалось следить за сетью: нет разрешения?")
    }

    private fun unwatchNetwork() {
        val cb = netCallback ?: return
        netCallback = null
        runCatching {
            getSystemService(android.net.ConnectivityManager::class.java)?.unregisterNetworkCallback(cb)
        }
    }

    private fun describeNetwork(network: android.net.Network): String = runCatching {
        val cm = getSystemService(android.net.ConnectivityManager::class.java)
        val caps = cm?.getNetworkCapabilities(network)
        val kind = when {
            caps == null -> "сеть"
            caps.hasTransport(android.net.NetworkCapabilities.TRANSPORT_WIFI) -> "Wi-Fi"
            caps.hasTransport(android.net.NetworkCapabilities.TRANSPORT_CELLULAR) -> "мобильная"
            caps.hasTransport(android.net.NetworkCapabilities.TRANSPORT_ETHERNET) -> "Ethernet"
            else -> "сеть"
        }
        "$kind ${network}"
    }.getOrDefault("сеть")

    /**
     * Переподнять туннель на новой сети. Полный цикл закрытия/открытия здесь обязателен: старый
     * UDP-сокет привязан к прежнему маршруту, и после смены сети каждый `sendto` падает с
     * ENETUNREACH — «туннель есть, а трафика нет», при этом замочек в шторке висит активным.
     */
    private fun restartAfterNetworkChange(why: String) {
        val now = System.currentTimeMillis()
        synchronized(this) {
            // Переключение сети приходит пачкой событий: перезапускаемся не чаще раза в 4 секунды.
            if (now - lastNetRestartAt < 4_000L) return
            lastNetRestartAt = now
        }
        Thread({
            val text = lastConfigText ?: return@Thread
            TunnelDebug.stage("$why — переподключаю туннель")
            TunnelState.status = "переподключаюсь после смены сети"
            postNotification(TunnelState.status)
            val myEpoch = epoch.incrementAndGet()
            stopped.set(true)
            TunnelState.up = false
            starting = false
            TunnelState.busy = false
            closeAll()
            // Небольшая пауза: системе нужно поднять маршрут по новой сети, иначе сокет снова
            // привяжется к несуществующему пути.
            runCatching { Thread.sleep(400) }
            // Пока спали, пользователь мог нажать «Отключить»: тогда переподнимать нечего.
            if (epoch.get() != myEpoch) return@Thread
            stopped.set(false)
            networkChanged = false
            baselineNetwork = null
            startVpn(text, lastStartId)
        }, "warpscout-net-restart").apply { isDaemon = true }.start()
    }

    companion object {
        const val ACTION_START = "dev.warpscout.app.tunnel.START"
        const val ACTION_STOP = "dev.warpscout.app.tunnel.STOP"
        const val EXTRA_CONF = "conf"
        private const val CHANNEL = "warpscout.tunnel.quiet"
        private const val LEGACY_CHANNEL = "warpscout.tunnel"
        private const val NOTIF_ID = 4200

        fun start(context: Context, config: WarpConfig) = startWithText(context, WgConf.render(config))

        /**
         * Запуск готовым текстом конфига. Нужен плитке быстрых настроек: она не собирает конфиг
         * заново, а берёт последний использованный ([Prefs.lastConfigText]) — то есть ровно то,
         * что в последний раз реально работало.
         */
        fun startWithText(context: Context, text: String) {
            val intent = Intent(context, WarpVpnService::class.java).apply {
                action = ACTION_START
                putExtra(EXTRA_CONF, text)
            }
            runCatching { context.startForegroundService(intent) }
                .onFailure { TunnelState.status = "сервис не запустился: ${it.message}" }
        }

        /** Сервис сдался (ошибка/таймаут) — ждать больше нечего. */
        fun gaveUp(): Boolean = TunnelState.gaveUp

        /** Причина, по которой сдался. */
        fun failureReason(): String? = TunnelState.error

        fun stop(context: Context) {
            runCatching {
                context.startService(Intent(context, WarpVpnService::class.java).apply { action = ACTION_STOP })
            }
        }

        /** Ждём, пока сервис реально освободится: следующий старт иначе упрётся в «уже поднимается». */
        fun waitDown(timeoutMs: Int): Boolean {
            val deadline = System.currentTimeMillis() + timeoutMs
            while (System.currentTimeMillis() < deadline) {
                if (!TunnelState.busy) return true
                Thread.sleep(50)
            }
            return !TunnelState.busy
        }

        /** Поднять и дождаться handshake (для проверки ресурсов из-под туннеля). */
        fun startAndWait(context: Context, config: WarpConfig, timeoutMs: Int): Boolean {
            start(context, config)
            val deadline = System.currentTimeMillis() + timeoutMs.coerceAtLeast(2000)
            while (System.currentTimeMillis() < deadline) {
                if (TunnelState.up) return true
                Thread.sleep(200)
            }
            stop(context)
            return false
        }
    }
}
