package dev.warpscout.app.status

import android.app.ActivityManager
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.Build
import android.util.Log
import dev.warpscout.app.TunnelDebug
import dev.warpscout.core.state.TunnelStatus
import java.io.File
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Состояние туннеля между процессами.
 *
 * Туннель живёт в своём процессе (`android:process=":vpn"`): падение интерфейса больше не роняет
 * VPN. Платить за это приходится тем, что общий объект в памяти невозможен — поэтому процесс
 * сервиса пишет маленький снимок в файл и рассылает короткое уведомление, а процесс интерфейса
 * читает снимок и раздаёт его тем, кто спрашивает.
 *
 * Правила, без которых это ломается:
 *  - **один писатель**. Файл пишет только процесс сервиса, иначе два снимка перетирают друг друга
 *    и интерфейс показывает то, чего нет;
 *  - **запись атомарная** (временный файл + переименование): читатель никогда не увидит половину
 *    JSON;
 *  - **понятная смерть**. Если сервис убили (не наш `stopSelf`, а OOM или системный kill),
 *    снимок останется «туннель работает». Поэтому в снимке есть время записи, а сервис раз в
 *    10 секунд пишет «сердцебиение»; если время давно не обновлялось, интерфейс проверяет,
 *    жив ли процесс сервиса, и не врёт про состояние.
 */
object TunnelStatusBus {

    /** Уведомление «снимок обновился». Рассылается внутри приложения, наружу не видно. */
    const val ACTION_STATUS = "dev.warpscout.app.STATUS_CHANGED"

    /** Имя файла со снимком состояния. */
    private const val SNAPSHOT = "tunnel-status.json"

    /** Снимок старше этого — повод проверить, жив ли сервис (при живом приходит сердцебиение). */
    private const val STALE_MS = 30_000L

    /** Проверка «процесс сервиса жив» не чаще раза в 2 секунды: она системная и не бесплатная. */
    private const val LIVENESS_THROTTLE_MS = 2_000L

    private const val TAG = "WarpScout/status"

    @Volatile
    private var current: TunnelStatus = TunnelStatus()

    @Volatile
    private var loaded: Boolean = false

    @Volatile
    private var lastLivenessAt: Long = 0L

    private val installed = AtomicBoolean(false)
    private val listeners = CopyOnWriteArrayList<(TunnelStatus) -> Unit>()

    fun snapshotFile(context: Context): File = File(context.applicationContext.filesDir, SNAPSHOT)

    /**
     * Подключить процесс интерфейса к снимку: прочитать текущий и слушать обновления.
     * Повторный вызов безопасен — приёмник регистрируется один раз на процесс.
     */
    fun install(context: Context) {
        val app = context.applicationContext
        if (installed.compareAndSet(false, true)) {
            val receiver = object : BroadcastReceiver() {
                override fun onReceive(receiverContext: Context?, intent: Intent?) = applySnapshot(app, read(app))
            }
            val filter = IntentFilter(ACTION_STATUS)
            runCatching {
                if (Build.VERSION.SDK_INT >= 33) {
                    app.registerReceiver(receiver, filter, Context.RECEIVER_NOT_EXPORTED)
                } else {
                    @Suppress("UnspecifiedRegisterReceiverFlag")
                    app.registerReceiver(receiver, filter)
                }
            }.onFailure { Log.w(TAG, "не удалось подписаться на состояние туннеля: ${it.message}") }
        }
        refresh(app)
    }

    /**
     * Подписаться на обновления. Слушателю сразу отдаётся последний известный снимок — иначе
     * интерфейс, открытый при уже поднятом туннеле, показывал бы «не запускался».
     */
    fun addListener(listener: (TunnelStatus) -> Unit) {
        listeners.add(listener)
        if (loaded) runCatching { listener(current) }
    }

    /**
     * Текущее состояние для интерфейса. Скрывает «мёртвый» снимок: если сервис молчит дольше
     * [STALE_MS] и его процесса нет, показываем «не запущен», а не «работает».
     */
    fun snapshot(context: Context): TunnelStatus {
        val status = current
        if (!status.up && !status.busy) return status
        val fresh = status.updatedAt > 0 && System.currentTimeMillis() - status.updatedAt < STALE_MS
        if (fresh) return status
        val now = System.currentTimeMillis()
        if (now - lastLivenessAt < LIVENESS_THROTTLE_MS) return current
        lastLivenessAt = now
        if (serviceProcessRunning(context) == false) {
            val dead = status.copy(up = false, busy = false, gaveUp = false, error = status.error, status = "туннель не запущен")
            current = dead
            return dead
        }
        return status
    }

    /** Перечитать снимок с диска (после возврата в приложение или по кнопке «обновить»). */
    fun refresh(context: Context) = applySnapshot(context.applicationContext, read(context))

    /**
     * Записать снимок и разослать уведомление. Вызывается **только** из процесса сервиса
     * (см. [dev.warpscout.app.tunnel.TunnelStatusPublisher]).
     */
    fun publish(context: Context, status: TunnelStatus) {
        val app = context.applicationContext
        val stamped = status.copy(updatedAt = System.currentTimeMillis())
        current = stamped
        loaded = true
        val file = snapshotFile(app)
        runCatching {
            file.parentFile?.mkdirs()
            val tmp = File(file.parentFile, file.name + ".tmp")
            tmp.writeText(stamped.toJson())
            // rename поверх существующего файла атомарен: читатель видит либо старый, либо новый.
            if (!tmp.renameTo(file)) {
                file.delete()
                if (!tmp.renameTo(file)) tmp.copyTo(file, overwrite = true)
            }
        }.onFailure { Log.w(TAG, "снимок состояния не записан: ${it.message}") }
        runCatching { app.sendBroadcast(Intent(ACTION_STATUS).setPackage(app.packageName)) }
    }

    /** Прочитать снимок с диска; null — если его нет или он битый. */
    fun read(context: Context): TunnelStatus? {
        val file = snapshotFile(context)
        if (!file.exists()) return null
        return TunnelStatus.fromJson(runCatching { file.readText() }.getOrNull())
    }

    private fun applySnapshot(context: Context, status: TunnelStatus?) {
        val fresh = status ?: return
        if (loaded && fresh.updatedAt == current.updatedAt) return
        current = fresh
        loaded = true
        // Журнал: часть полей живёт в снимке (счётчики, последняя ошибка), их надо отразить,
        // иначе интерфейс покажет нулевой трафик при работающем туннеле.
        runCatching { TunnelDebug.mirror(fresh) }
        listeners.forEach { listener -> runCatching { listener(fresh) } }
    }

    /**
     * Работает ли хоть один сервис приложения в отдельном процессе. `null` — если система
     * не дала ответа (тогда лучше верить снимку, чем показывать «не запущен» на живом туннеле).
     */
    @Suppress("DEPRECATION")
    private fun serviceProcessRunning(context: Context): Boolean? {
        val manager = runCatching {
            context.getSystemService(Context.ACTIVITY_SERVICE) as? ActivityManager
        }.getOrNull() ?: return null
        // Начиная с Android 8 метод возвращает только сервисы своего приложения — для нас это
        // ровно то, что нужно, поэтому устаревший API здесь уместнее привязки к сервису.
        val running = runCatching { manager.getRunningServices(Int.MAX_VALUE) }.getOrNull() ?: return null
        val self = context.packageName
        return running.any { info -> info.service.packageName == self && info.processName != self }
    }
}
