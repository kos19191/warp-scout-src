package dev.warpscout.app.tunnel

import dev.warpscout.app.TunnelDebug
import dev.warpscout.core.state.TunnelStatus

/**
 * Состояние туннеля.
 *
 * Живёт в двух процессах и ведёт себя по-разному:
 *  - **в процессе сервиса** это единственный источник правды: каждое изменение публикуется в общий
 *    снимок ([dev.warpscout.app.status.TunnelStatusBus]), по нему интерфейс и плитка узнают, что
 *    происходит;
 *  - **в процессе интерфейса** те же поля — зеркало снимка: их заполняет приёмник, а записи
 *    отсюда никуда не уходят (публиковать может только владелец состояния, иначе два снимка
 *    затрут друг друга).
 *
 * Читать эти поля можно откуда угодно: они `@Volatile`, а решение «кто хозяин» принимает
 * [TunnelStatusPublisher] — он запущен только в процессе сервиса.
 */
object TunnelState {

    @Volatile
    var up: Boolean = false
        set(v) {
            if (field == v) return
            field = v
            publishNow(urgent = true)
        }

    /** Текущий этап человеческим языком — именно это видно в кнопке и в статусе. */
    @Volatile
    var status: String = ""
        set(v) {
            if (field == v) return
            field = v
            publishNow(urgent = false)
        }

    @Volatile
    var endpoint: String = ""
        set(v) {
            if (field == v) return
            field = v
            publishNow(urgent = false)
        }

    /** Причина отказа, если он был. UI показывает её вместо «ничего не произошло». */
    @Volatile
    var error: String? = null
        set(v) {
            if (field == v) return
            field = v
            publishNow(urgent = true)
        }

    /** Сервис сам сдался (таймаут/ошибка) — ждать больше нечего. */
    @Volatile
    var gaveUp: Boolean = false
        set(v) {
            if (field == v) return
            field = v
            publishNow(urgent = true)
        }

    /** Когда последняя попытка стартовала: UI по этому отличает «не запускался» от «висит». */
    @Volatile
    var startedAt: Long = 0L
        set(v) {
            if (field == v) return
            field = v
            publishNow(urgent = false)
        }

    /**
     * Сервис занят: поднимается или уже работает. По этому флагу контроллер ждёт, пока прошлая
     * сессия действительно завершится, прежде чем стартовать новую — иначе два подъёма идут
     * одновременно и второй упирается в «уже поднимается».
     */
    @Volatile
    var busy: Boolean = false
        set(v) {
            if (field == v) return
            field = v
            publishNow(urgent = true)
        }

    /** true — прямо сейчас идёт установка или работа: по нему публикуется «сердцебиение». */
    fun isAlive(): Boolean = up || busy

    /**
     * Снимок для другого процесса: поля состояния плюс то, что интерфейсу нужно для карточки
     * (счётчики и последняя ошибка живут в журнале).
     */
    fun snapshot(): TunnelStatus = TunnelStatus(
        up = up,
        status = status,
        endpoint = endpoint.ifBlank { TunnelDebug.endpoint },
        error = error,
        gaveUp = gaveUp,
        busy = busy,
        startedAt = startedAt,
        bytesUp = TunnelDebug.bytesUp,
        bytesDown = TunnelDebug.bytesDown,
        handshakeAttempts = TunnelDebug.handshakeAttempts,
        lastError = TunnelDebug.lastError,
        lastStageMs = TunnelDebug.lastStageMs,
        touched = TunnelDebug.touched,
    )

    /** Заполнить поля из снимка, полученного из другого процесса (процесс интерфейса). */
    fun applySnapshot(snapshot: TunnelStatus) {
        mirroring = true
        try {
            up = snapshot.up
            status = snapshot.status
            endpoint = snapshot.endpoint
            error = snapshot.error
            gaveUp = snapshot.gaveUp
            busy = snapshot.busy
            startedAt = snapshot.startedAt
        } finally {
            mirroring = false
        }
    }

    /**
     * Забыть результат прошлой попытки перед новой. Без этого интерфейс успевает увидеть старые
     * «сдался» и «туннель работает» из прежнего снимка и делает вывод по устаревшим данным —
     * ровно то, из-за чего подключение «не удалось», хотя оно шло.
     */
    fun forgetAttempt() {
        up = false
        error = null
        gaveUp = false
    }

    /** true — поля заполняются из снимка другого процесса, публиковать их обратно не нужно. */
    @Volatile
    private var mirroring: Boolean = false

    private fun publishNow(urgent: Boolean) {
        if (!mirroring) TunnelStatusPublisher.request(urgent)
    }
}
