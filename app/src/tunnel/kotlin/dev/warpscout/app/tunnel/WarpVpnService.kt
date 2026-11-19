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
import dev.warpscout.core.config.WgConf
import dev.warpscout.core.model.WarpConfig
import dev.warpscout.core.net.NetSettings
import dev.warpscout.core.tunnel.DataPlane
import dev.warpscout.core.tunnel.SocketUdpChannel
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
        startVpn(text)
        return START_STICKY
    }

    override fun onDestroy() {
        shutdown()
        super.onDestroy()
    }

    private fun startVpn(text: String) {
        createChannel()
        postNotification("Поднимаю туннель…")

        val cfg = runCatching { WgConf.toWarpConfig("WARP", text) }.getOrNull()
        if (cfg == null) {
            TunnelState.status = "конфиг не разбирается"
            stopSelf()
            return
        }
        TunnelState.endpoint = cfg.endpoint.render()

        val socket = try {
            DatagramSocket().apply {
                soTimeout = 1500
                connect(InetSocketAddress(cfg.endpoint.host, cfg.endpoint.port))
            }
        } catch (e: Exception) {
            TunnelState.status = "сокет: ${e.message}"
            stopSelf()
            return
        }
        if (!runCatching { protect(socket) }.getOrDefault(false)) {
            // Без protect() пакеты туннеля попадут в сам туннель — трафик замкнётся по кругу.
            TunnelState.status = "protect() отказал — туннель не поднят во избежание петли"
            runCatching { socket.close() }
            stopSelf()
            return
        }

        val pfd = try {
            builderFor(cfg).establish()
        } catch (e: Exception) {
            TunnelState.status = "tun: ${e.message}"
            runCatching { socket.close() }
            stopSelf()
            return
        }
        if (pfd == null) {
            TunnelState.status = "VpnService не выдал tun"
            runCatching { socket.close() }
            stopSelf()
            return
        }
        tun = pfd

        val handshake = CountDownLatch(1)
        val plane = DataPlane(
            udp = SocketUdpChannel(socket, cfg.endpoint, 1500),
            tunInput = FileInputStream(pfd.fileDescriptor),
            tunOutput = FileOutputStream(pfd.fileDescriptor),
            config = cfg,
            settings = NetSettings(attempts = 3, timeoutMs = 1500, junkPacketsBeforeHandshake = 1),
            log = { line ->
                TunnelState.status = line
                if (line.contains("туннель поднят")) {
                    TunnelState.up = true
                    handshake.countDown()
                    postNotification("Туннель активен: ${cfg.endpoint.render()}")
                }
            }
        )
        this.plane = plane
        worker = Thread {
            val ok = runCatching { plane.run() }.getOrDefault(false)
            TunnelState.up = false
            if (!ok && !stopped.get()) TunnelState.status = "handshake не прошёл — endpoint молчит"
            else if (stopped.get()) TunnelState.status = "туннель остановлен"
            else TunnelState.status = "туннель закрыт (пира не стало)"
            stopSelf()
        }.apply { isDaemon = true; name = "warpscout-vpn"; start() }

        // Ждём handshake, чтобы UI/верификатор не начали проверять ресурсы в пустоту.
        runCatching { handshake.await(12, TimeUnit.SECONDS) }
    }

    private fun builderFor(cfg: WarpConfig): Builder {
        val builder = Builder()
            .setSession("WarpScout")
            .setMtu(cfg.mtu.coerceIn(576, 1420))
            .setBlocking(true)
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
