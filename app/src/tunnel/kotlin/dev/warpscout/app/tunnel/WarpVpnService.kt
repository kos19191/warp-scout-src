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
import dev.warpscout.app.R
import dev.warpscout.app.TunnelDebug
import dev.warpscout.core.config.SplitRoutes
import dev.warpscout.core.config.WgConf
import dev.warpscout.core.model.WarpConfig
import dev.warpscout.core.net.NetSettings
import dev.warpscout.core.tunnel.DataPlane
import dev.warpscout.core.tunnel.SocketUdpChannel
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
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
    private var tun: ParcelFileDescriptor? = null
    private var worker: Thread? = null
    private var udpSocket: DatagramSocket? = null
    private val stopped = java.util.concurrent.atomic.AtomicBoolean(false)

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            shutdown()
            return START_NOT_STICKY
        }
        val text = intent?.getStringExtra(EXTRA_CONF)
        if (text.isNullOrBlank()) {
            TunnelState.status = "нет конфигурации — запуск пропущен"
            stopSelf()
            return START_NOT_STICKY
        }
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
        TunnelState.error = null
        TunnelState.gaveUp = false
        TunnelState.startedAt = System.currentTimeMillis()
        TunnelDebug.reset()
        createChannel()
        postNotification("Поднимаю туннель…")

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

        val pfd = try {
            builderFor(cfg).establish()
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
        tun = pfd
        udpSocket = socket
        val routes = SplitRoutes.prefixesOf(cfg.allowedIps)
        TunnelDebug.stage("tun получен: ${routes.size} маршрутов, blocking=${isFullTunnel(cfg)}")

        val handshake = CountDownLatch(1)
        val plane = DataPlane(
            udp = SocketUdpChannel(socket, cfg.endpoint, 1500),
            tunInput = FileInputStream(pfd.fileDescriptor),
            tunOutput = FileOutputStream(pfd.fileDescriptor),
            config = cfg,
            settings = NetSettings(attempts = 3, timeoutMs = 1500, junkPacketsBeforeHandshake = 1),
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

    private fun isFullTunnel(cfg: WarpConfig): Boolean =
        SplitRoutes.prefixesOf(cfg.allowedIps).any { it == "0.0.0.0/0" || it == "::/0" }

    private fun planeBytesUp(): Long = plane?.bytesUp ?: 0L

    /** Единственная точка «мы сдались»: статус + журнал + аккуратная остановка. */
    private fun fail(reason: String, startId: Int) {
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
            val parts = cidr.split('/')
            val bits = parts[1].trim().toIntOrNull() ?: return@forEach
            runCatching { builder.addRoute(parts[0].trim(), bits) }
        }
        return builder
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
        val n = NotificationCompat.Builder(this, CHANNEL)
            .setContentTitle(getString(R.string.app_name))
            .setContentText(text)
            .setSmallIcon(android.R.drawable.stat_sys_data_bluetooth)
            .setOngoing(true)
            .setPriority(NotificationCompat.PRIORITY_LOW)
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
    }

    private fun createChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            notifyManager().createNotificationChannel(
                NotificationChannel(CHANNEL, "WarpScout: туннель", NotificationManager.IMPORTANCE_LOW)
            )
        }
    }

    private fun notifyManager(): NotificationManager =
        getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager

    private fun shutdown() {
        if (!stopped.compareAndSet(false, true)) return
        TunnelState.up = false
        TunnelState.status = "туннель остановлен"
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
        runCatching { stopForeground(STOP_FOREGROUND_REMOVE) }
    }

    companion object {
        const val ACTION_START = "dev.warpscout.app.tunnel.START"
        const val ACTION_STOP = "dev.warpscout.app.tunnel.STOP"
        const val EXTRA_CONF = "conf"
        private const val CHANNEL = "warpscout.tunnel"
        private const val NOTIF_ID = 4200

        fun start(context: Context, config: WarpConfig) {
            val intent = Intent(context, WarpVpnService::class.java).apply {
                action = ACTION_START
                putExtra(EXTRA_CONF, WgConf.render(config))
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
