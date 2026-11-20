package dev.warpscout.app

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat

/**
 * Держит подбор «в foreground», пока он идёт.
 *
 * Сам подбор живёт в процессе приложения. Стоит свернуть экран — процесс становится фоновым, и
 * Android вправе убить его в любой момент: скан обрывался молча, а пользователь видел, что
 * «ничего не произошло». Foreground-сервис делает процесс защищённым ровно на время подбора, а по
 * завершении сразу останавливается — висящих уведомлений не остаётся.
 *
 * Сервис ничего не решает: ни как подбирать, ни что применять. Он только держит процесс и
 * показывает, на каком шаге подбор, чтобы приложение можно было свернуть.
 */
object ScanGuard {

    private const val CHANNEL = "warpscout.scan"
    private const val ID = 4242

    /** Последняя строка прогресса: её показывает и сервис при старте, и обновления. */
    @Volatile
    private var latest: String = ""

    @Volatile
    private var lastUpdateAt: Long = 0L

    fun start(context: Context) {
        val app = context.applicationContext
        latest = app.getString(R.string.scan_notif_text)
        runCatching {
            ContextCompat.startForegroundService(app, Intent(app, ScanGuardService::class.java))
        }
        // Отказ (например, Android 12+ не разрешает начинать foreground из фона) не должен ломать
        // подбор: без защиты процессом он работает как раньше, просто может прерваться при сворачивании.
    }

    /** Прогресс в уведомление. Обновляем не чаще раза в секунду: дёргать панель на каждый лог — расход. */
    fun update(context: Context, text: String) {
        val app = context.applicationContext
        val line = text.trim().take(90)
        if (line.isEmpty()) return
        latest = line
        val now = System.currentTimeMillis()
        if (now - lastUpdateAt < 800) return
        lastUpdateAt = now
        runCatching {
            NotificationManagerCompat.from(app).notify(ID, build(app, line))
        }
    }

    fun stop(context: Context) {
        val app = context.applicationContext
        runCatching { app.stopService(Intent(app, ScanGuardService::class.java)) }
        runCatching { NotificationManagerCompat.from(app).cancel(ID) }
    }

    /** Текущая строка прогресса (для сервиса, который подхватывает её при старте). */
    internal fun progressText(): String = latest

    internal fun build(context: Context, text: String): android.app.Notification {
        ensureChannel(context)
        return NotificationCompat.Builder(context, CHANNEL)
            .setSmallIcon(R.drawable.ic_tile_tunnel)
            .setContentTitle(context.getString(R.string.scan_notif_title))
            .setContentText(text)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setSilent(true)
            .setPriority(NotificationCompat.PRIORITY_MIN)
            .setShowWhen(false)
            .build()
    }

    internal fun ensureChannel(context: Context) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return
        val mgr = context.getSystemService(NotificationManager::class.java) ?: return
        if (mgr.getNotificationChannel(CHANNEL) != null) return
        mgr.createNotificationChannel(
            NotificationChannel(CHANNEL, context.getString(R.string.scan_notif_channel), NotificationManager.IMPORTANCE_MIN).apply {
                setShowBadge(false)
                enableLights(false)
                enableVibration(false)
                setSound(null, null)
            }
        )
    }
}

/** Пустая оболочка вокруг [ScanGuard.build]: тип сервиса объявлен в манифесте. */
class ScanGuardService : Service() {

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val text = ScanGuard.progressText().ifEmpty { getString(R.string.scan_notif_text) }
        val notification = ScanGuard.build(this, text)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            startForeground(
                NOTIFICATION_ID,
                notification,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC
            )
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }
        return START_NOT_STICKY
    }

    override fun onDestroy() {
        stopForeground(STOP_FOREGROUND_REMOVE)
        super.onDestroy()
    }

    private companion object {
        const val NOTIFICATION_ID = 4242
    }
}
