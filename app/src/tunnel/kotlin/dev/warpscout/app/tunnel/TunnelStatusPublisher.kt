package dev.warpscout.app.tunnel

import android.content.Context
import dev.warpscout.app.status.TunnelStatusBus
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Публикация состояния из процесса сервиса в снимок, который читает интерфейс.
 *
 * Состояние меняется пачками: одна подписка на rekey даёт несколько записей подряд, каждый этап
 * handshake — ещё одну. Писать файл и рассылать уведомление на каждую запись незачем, поэтому
 * публикация склеивается (не чаще четырёх раз в секунду), а срочное — «поднят», «сдался»,
 * ошибка — уходит сразу.
 *
 * Пока туннель жив, раз в 10 секунд уходит «сердцебиение». По нему интерфейс отличает «сервис
 * работает, просто ничего не меняется» от «сервис убит системой, а снимок остался». Само по себе
 * сердцебиение почти ничего не стоит: это запись трёхсот байт в файл, радио не просыпается.
 */
object TunnelStatusPublisher {

    /** Минимальный интервал между публикациями: пачка записей уходит одним снимком. */
    private const val MIN_GAP_MS = 250L

    /** Как часто напоминать о себе, пока туннель работает. */
    private const val HEARTBEAT_MS = 10_000L

    private val lock = Object()
    private val started = AtomicBoolean(false)

    private var pending = false
    private var urgent = false

    @Volatile
    private var lastPublishAt = 0L

    @Volatile
    private var app: Context? = null

    /** Запускается один раз из процесса сервиса (см. `WarpVpnService.onCreate`). */
    fun start(context: Context) {
        app = context.applicationContext
        if (!started.compareAndSet(false, true)) return
        Thread({ loop() }, "warpscout-status").apply { isDaemon = true }.start()
        request(urgent = true)
    }

    /**
     * Попросить опубликовать состояние. В процессе интерфейса ничего не делает: публикует только
     * тот, кто владеет туннелем, иначе два снимка затрут друг друга.
     */
    fun request(urgent: Boolean) {
        if (!started.get()) return
        synchronized(lock) {
            pending = true
            if (urgent) this.urgent = true
            lock.notifyAll()
        }
    }

    /** Опубликовать немедленно, не дожидаясь склейки: при остановке процесс может умереть сразу. */
    fun flush() {
        if (!started.get()) return
        synchronized(lock) {
            pending = false
            urgent = false
        }
        publish(force = true)
    }

    private fun loop() {
        while (true) {
            var forceNow = false
            var heartbeat = false
            var skip = false
            synchronized(lock) {
                if (!pending) {
                    val wait = heartbeatWait()
                    if (wait > 0L) runCatching { lock.wait(wait) }
                    if (!pending) {
                        // Проснулись по сердцебиению. Если туннель уже не работает — ждём события.
                        if (TunnelState.isAlive()) heartbeat = true else skip = true
                    }
                }
                if (!skip) {
                    forceNow = urgent
                    pending = false
                    urgent = false
                }
            }
            if (skip) continue
            publish(force = forceNow || heartbeat)
        }
    }

    /**
     * Сколько ждать до следующего сердцебиения; 0 — ждать события бесконечно (туннель не поднят,
     * будить процесс незачем).
     */
    private fun heartbeatWait(): Long {
        if (!TunnelState.isAlive()) return 0L
        val sinceLast = System.currentTimeMillis() - lastPublishAt
        return (HEARTBEAT_MS - sinceLast).coerceIn(100L, HEARTBEAT_MS)
    }

    private fun publish(force: Boolean) {
        val context = app ?: return
        if (!force) {
            val gap = System.currentTimeMillis() - lastPublishAt
            if (gap in 0 until MIN_GAP_MS) {
                // Пока склеиваем пачку, состояние может измениться ещё раз — снимок будет свежее.
                runCatching { Thread.sleep(MIN_GAP_MS - gap) }
            }
        }
        lastPublishAt = System.currentTimeMillis()
        TunnelStatusBus.publish(context, TunnelState.snapshot())
    }
}
