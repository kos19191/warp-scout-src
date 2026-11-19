package dev.warpscout.app.tunnel

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import androidx.core.app.NotificationCompat
import dev.warpscout.app.R
import dev.warpscout.core.config.ConfigTarget
import dev.warpscout.core.config.WgConf
import dev.warpscout.core.model.WarpConfig
import dev.warpscout.core.net.NetSettings
import dev.warpscout.core.tunnel.DataPlane
import dev.warpscout.core.tunnel.SocketUdpChannel
import dev.warpscout.core.tunnel.TunnelDiagnostics
import dev.warpscout.core.tunnel.TunnelDiagnostics.Stage
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.DatagramSocket
import java.net.InetSocketAddress
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Собственный туннель: VpnService + data plane из `:core` (handshake AWG, transport-пакеты,
 * keepalive, счётчики). Чужой бэкенд не нужен: AWG отличается от WireGuard только мусором перед
 * инициацией, а его отправляет тот же [DataPlane].
 *
 * Существует только во flavor'е `tunnel` (см. app/src/tunnel/AndroidManifest.xml).
 *
 * Что изменилось после разбора «запускается и молчит»:
 *  • всё поднятие идёт в отдельном потоке: `onStartCommand` живёт в main-потоке, и ожидание
 *    handshake (до 12 с) подвешивало UI целиком;
 *  • каждая причина падения фиксируется кодом (`E_TUN`, `E_PROTECT`, …) и **не затирается**
 *    остановкой сервиса;
 *  • журнал этапов доступен из UI ([TunnelDiagnostics.dump]);
 *  • есть `onRevoke()` и `setUnderlyingNetworks()`: отзыв разрешения и переключение Wi-Fi↔LTE
 *    больше не оставляют «мёртвый, но включённый» туннель;
 *  • счётчики трафика обновляются раз в секунду, чтобы «активен» можно было проверить глазами.
 */
class WarpVpnService : VpnService() {

    private var plane: DataPlane? = null
    private var tun: ParcelFileDescriptor? = null
    private var tunnelThread: Thread? = null
    private var ticker: Thread? = null

    private val running = AtomicBoolean(false)
    private val stopping = AtomicBoolean(false)

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            shutdown("остановлено пользователем")
            return START_NOT_STICKY
        }
        val text = intent?.getStringExtra(EXTRA_CONF)
        if (text.isNullOrBlank()) {
            fail(Stage.CONFIG, "E_CONFIG", "в интенте нет конфигурации")
            stopSelf()
            return START_NOT_STICKY
        }
        if (!running.compareAndSet(false, true)) {
            // Повторный старт во время поднятия — не ошибка, просто не плодим второй туннель.
            TunnelDiagnostics.log(Stage.START, "сервис уже поднимается — повторный старт проигнорирован")
            return START_NOT_STICKY
        }
        stopping.set(false)
        TunnelDiagnostics.clear()
        TunnelState.reset()
        TunnelState.set(Stage.START, "поднимаю туннель…")
        createChannel()
        postNotification("Поднимаю туннель…")
        tunnelThread = Thread({ runTunnel(text) }, "warpscout-tunnel").apply {
            isDaemon = true
            start()
        }
        return START_NOT_STICKY
    }

    // ------------------------------------------------------------------ поднятие

    private fun runTunnel(text: String) {
        var socket: DatagramSocket? = null
        try {
            val cfg = runCatching { WgConf.toWarpConfig("WARP", text) }.getOrNull()
            if (cfg == null) {
                fail(Stage.CONFIG, "E_CONFIG", "конфигурация не разбирается (нет PrivateKey/PublicKey)")
                return
            }
            TunnelState.endpoint = cfg.endpoint.render()
            TunnelDiagnostics.log(Stage.CONFIG, "endpoint ${cfg.endpoint.render()}, mtu ${cfg.mtu}, allowed-ips ${cfg.allowedIps.take(80)}")

            socket = try {
                DatagramSocket().apply {
                    soTimeout = 1500
                    connect(InetSocketAddress(cfg.endpoint.host, cfg.endpoint.port))
                }
            } catch (e: Exception) {
                fail(Stage.SOCKET, "E_SOCKET", "сокет до ${cfg.endpoint.render()}: ${e.message}")
                return
            }
            TunnelDiagnostics.log(Stage.SOCKET, "UDP-сокет готов")

            if (!runCatching { protect(socket) }.getOrDefault(false)) {
                // Без protect() пакеты туннеля попадут в сам туннель — трафик замкнётся по кругу.
                fail(Stage.PROTECT, "E_PROTECT", "protect() отказал — туннель не поднимаю, иначе петля")
                return
            }
            TunnelDiagnostics.log(Stage.PROTECT, "protect() выдан")

            val pfd = try {
                builderFor(cfg).establish()
            } catch (e: Exception) {
                fail(Stage.TUN, "E_TUN", "establish(): ${e.javaClass.simpleName}: ${e.message}")
                return
            }
            if (pfd == null) {
                fail(Stage.TUN, "E_TUN", "VpnService не выдал tun (нет разрешения на VPN?)")
                return
            }
            tun = pfd
            bindUnderlyingNetwork()
            TunnelDiagnostics.log(
                Stage.TUN,
                "tun: fd=${pfd.fd}, адрес ${cfg.account.ipv4}, DNS ${cfg.dns.joinToString(",")}, " +
                    "маршрутов ${cfg.allowedIps.split(',').count { it.contains('/') }}"
            )

            val dataPlane = DataPlane(
                udp = SocketUdpChannel(socket, cfg.endpoint, 1500),
                tunInput = FileInputStream(pfd.fileDescriptor),
                tunOutput = FileOutputStream(pfd.fileDescriptor),
                config = cfg,
                settings = NetSettings(attempts = 3, timeoutMs = 1500, junkPacketsBeforeHandshake = 1),
                log = { line -> onPlaneLog(line) }
            )
            plane = dataPlane
            startTicker()

            val ok = runCatching { dataPlane.run() }.getOrElse { e ->
                fail(Stage.TRANSPORT, "E_CRASH", "${e.javaClass.simpleName}: ${e.message}")
                false
            }
            if (ok) {
                TunnelDiagnostics.log(Stage.STOP, "передача завершилась (пир перестал отвечать)")
                if (!stopping.get()) TunnelState.stopped("туннель закрыт: пир перестал отвечать")
            } else if (!stopping.get() && TunnelState.error == null) {
                fail(Stage.HANDSHAKE, "E_HANDSHAKE", "handshake не прошёл — endpoint молчит или режет UDP")
            }
        } finally {
            runCatching { socket?.close() }
            shutdown(if (stopping.get()) "туннель остановлен" else "туннель остановлен после ошибки")
        }
    }

    private fun onPlaneLog(line: String) {
        when {
            line.contains("туннель поднят") -> {
                TunnelState.started()
                TunnelState.set(Stage.TRANSPORT, "туннель поднят — трафик пошёл")
                postNotification("Туннель активен: ${TunnelState.endpoint}")
            }

            line.contains("handshake") || line.contains("попытка") || line.contains("cookie") ->
                TunnelState.set(Stage.HANDSHAKE, line)

            else -> TunnelState.set(Stage.TRANSPORT, line)
        }
    }

    /** Раз в секунду перекладываем счётчики data plane в состояние: видно, что трафик реально идёт. */
    private fun startTicker() {
        ticker = Thread({
            while (running.get() && !stopping.get()) {
                val p = plane
                if (p != null) {
                    TunnelState.bytesUp = p.bytesUp
                    TunnelState.bytesDown = p.bytesDown
                }
                runCatching { Thread.sleep(1000) }
            }
        }, "warpscout-tunnel-stats").apply {
            isDaemon = true
            start()
        }
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

    /** Привязка к текущей сети: без неё после Wi-Fi↔LTE туннель умирает молча. */
    private fun bindUnderlyingNetwork() {
        runCatching {
            val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
            val network = cm.activeNetwork
            if (network != null) {
                setUnderlyingNetworks(arrayOf(network))
                TunnelDiagnostics.log(Stage.TUN, "underlying network: $network")
            } else {
                setUnderlyingNetworks(null)
            }
        }.onFailure {
            TunnelDiagnostics.log(Stage.TUN, "underlying network не привязан: ${it.message}")
        }
    }

    // ------------------------------------------------------------------ сервис

    override fun onRevoke() {
        TunnelDiagnostics.log(Stage.REVOKE, "система отозвала разрешение на VPN")
        fail(Stage.REVOKE, "E_REVOKE", "VPN отозван системой (или включён другой VPN)")
        shutdown("туннель отозван системой")
        super.onRevoke()
    }

    override fun onDestroy() {
        shutdown("сервис уничтожен")
        super.onDestroy()
    }

    private fun fail(stage: Stage, code: String, message: String) {
        TunnelState.fail(stage, code, message)
        postNotification("$code: $message")
    }

    private fun shutdown(reason: String) {
        stopping.set(true)
        if (!running.getAndSet(false)) {
            // Уже остановлены — только гасим хвосты, статус с ошибкой не трогаем.
            runCatching { tun?.close() }
            tun = null
            return
        }
        runCatching { plane?.stop() }
        plane = null
        val t = tunnelThread
        if (t != null && t !== Thread.currentThread()) runCatching { t.join(800) }
        runCatching { ticker?.interrupt() }
        ticker = null
        runCatching { tun?.close() }
        tun = null
        TunnelState.stopped(reason)
        runCatching { stopForeground(STOP_FOREGROUND_REMOVE) }
        runCatching { stopSelf() }
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
        if (started.isFailure) {
            TunnelDiagnostics.fail(Stage.START, "E_FGS", "startForeground: ${started.exceptionOrNull()?.message}")
        }
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

    companion object {
        const val ACTION_START = "dev.warpscout.app.tunnel.START"
        const val ACTION_STOP = "dev.warpscout.app.tunnel.STOP"
        const val EXTRA_CONF = "conf"
        private const val CHANNEL = "warpscout.tunnel"
        private const val NOTIF_ID = 4200

        fun start(context: Context, config: WarpConfig) {
            val intent = Intent(context, WarpVpnService::class.java).apply {
                action = ACTION_START
                // Внутри туннеля нужен полный конфиг: формат экспорта на работу data plane не влияет.
                putExtra(EXTRA_CONF, WgConf.render(config, ConfigTarget.AMNEZIAWG))
            }
            runCatching { context.startForegroundService(intent) }
                .onFailure { TunnelState.fail(Stage.START, "E_FGS", "сервис не запустился: ${it.message}") }
        }

        fun stop(context: Context) {
            val intent = Intent(context, WarpVpnService::class.java).apply { action = ACTION_STOP }
            // С Android 12 startService из фона может быть запрещён — тогда просто снимаем сервис,
            // onDestroy всё равно сделает shutdown().
            val asked = runCatching { context.startService(intent) }.isSuccess
            if (!asked) {
                runCatching { context.stopService(Intent(context, WarpVpnService::class.java)) }
            }
        }

        /** Поднять и дождаться handshake (для проверки ресурсов из-под туннеля). */
        fun startAndWait(context: Context, config: WarpConfig, timeoutMs: Int): Boolean {
            start(context, config)
            val deadline = System.currentTimeMillis() + timeoutMs.coerceAtLeast(2000)
            while (System.currentTimeMillis() < deadline) {
                if (TunnelState.up) return true
                if (TunnelState.error != null) return false
                Thread.sleep(150)
            }
            stop(context)
            return false
        }
    }
}
