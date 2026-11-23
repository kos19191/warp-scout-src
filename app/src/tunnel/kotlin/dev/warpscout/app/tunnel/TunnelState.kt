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
     * Машинная фаза (см. `TunnelStatus.PHASE_*`): по ней интерфейс решает, что показать, не
     * разбирая русский текст статуса.
     */
    @Volatile
    var phase: Int = TunnelStatus.PHASE_IDLE
        set(v) {
            if (field == v) return
            field = v
            publishNow(urgent = true)
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

    /**
     * Туннель нужен: был старт и не было «Выключить». Пока это так, сервис переподключается сам,
     * даже когда туннель лежит и ждёт повтора, — и кнопка с плиткой предлагают «Выключить».
     */
    @Volatile
    var wanted: Boolean = false
        set(v) {
            if (field == v) return
            field = v
            publishNow(urgent = true)
        }

    /** Последним туннель выключил сам человек: после этого ничто не включает его само. */
    @Volatile
    var stoppedByUser: Boolean = false
        set(v) {
            if (field == v) return
            field = v
            publishNow(urgent = true)
        }

    /**
     * Когда человек последний раз выключил туннель (0 — не выключал). Новый старт её не сбрасывает:
     * по ней перебор точек в интерфейсе замечает выключение плиткой или из уведомления, даже если
     * следом успел уйти старт следующей точки.
     */
    @Volatile
    var stoppedByUserAt: Long = 0L
        set(v) {
            if (field == v) return
            field = v
            publishNow(urgent = true)
        }

    /**
     * Ответ на проверку точки рядом с работающим туннелем: «номер|адрес:порт|итог|мс»
     * (см. `TunnelStatus.probe`). Срочно: интерфейс ждёт его, держа палец над переключением.
     */
    @Volatile
    var probe: String = ""
        set(v) {
            if (field == v) return
            field = v
            publishNow(urgent = true)
        }

    /**
     * Рукопожатие прошло, сервис проверяет, идут ли данные (с этого момента; 0 — не проверяет).
     * Срочно: перебор точек в интерфейсе по нему продлевает ожидание попытки (см. `TunnelStatus.dataCheckAt`).
     */
    @Volatile
    var dataCheckAt: Long = 0L
        set(v) {
            if (field == v) return
            field = v
            publishNow(urgent = true)
        }

    /** Метки дозора для текущей сети (см. `TunnelStatus.marks`). */
    @Volatile
    var marks: String = ""
        set(v) {
            if (field == v) return
            field = v
            publishNow(urgent = false)
        }

    /** Второй выход в этой сессии (`TunnelStatus.SECOND_*`, с 1.10.31). */
    @Volatile
    var second: Int = TunnelStatus.SECOND_OFF
        set(v) {
            if (field == v) return
            field = v
            publishNow(urgent = true)
        }

    /** Сервер второго выхода (автопоиск Proton Free, с 1.10.31): «NL-FREE#12»; пусто — из конфига. */
    @Volatile
    var secondPeer: String = ""
        set(v) {
            if (field == v) return
            field = v
            publishNow(urgent = false)
        }

    /**
     * Итог проверки связи через туннель (см. `TunnelStatus.linkWeb` и соседние поля). Пишется
     * одним вызовом [setLink], чтобы снимок не ушёл с половиной полей от прошлой проверки.
     */
    @Volatile
    var linkAt: Long = 0L
        private set
    @Volatile
    var linkWeb: Int = TunnelStatus.LINK_UNKNOWN
        private set
    @Volatile
    var linkMs: Int = -1
        private set
    @Volatile
    var linkTg: Int = TunnelStatus.LINK_UNKNOWN
        private set
    @Volatile
    var linkTgMs: Int = -1
        private set
    @Volatile
    var linkExit: String = ""
        private set

    /**
     * Проверка медиа Telegram (с 1.10.34, см. `TunnelStatus.tgMedia`): пишется одним вызовом
     * [setTgMedia] — вывод и скорость от одной загрузки.
     */
    @Volatile
    var tgMedia: Int = 0
        private set
    @Volatile
    var tgMediaKbps: Int = -1
        private set
    @Volatile
    var tgMediaAt: Long = 0L
        private set

    fun setTgMedia(at: Long, verdict: Int, kbps: Int) {
        tgMediaAt = at
        tgMedia = verdict
        tgMediaKbps = kbps
        publishNow(urgent = true)
    }

    /** Telegram сейчас идёт через второй выход (выход WARP — в России; с 1.10.34). */
    @Volatile
    var tgSecond: Boolean = false
        set(v) {
            if (field == v) return
            field = v
            publishNow(urgent = true)
        }

    fun setLink(at: Long, web: Int, webMs: Int, tg: Int, tgMs: Int, exit: String) {
        linkAt = at
        linkWeb = web
        linkMs = webMs
        linkTg = tg
        linkTgMs = tgMs
        linkExit = exit
        publishNow(urgent = true)
    }

    /**
     * Замер скорости через туннель (см. `TunnelStatus.speedState` и соседние поля). Как и проверка
     * связи, пишется одним вызовом [setSpeed]: снимок не должен уйти с числом от одного замера и
     * итогом от другого.
     */
    @Volatile
    var speedAt: Long = 0L
        private set
    @Volatile
    var speedState: Int = TunnelStatus.SPEED_UNKNOWN
        private set
    @Volatile
    var speedKbps: Int = -1
        private set
    @Volatile
    var speedPingMs: Int = -1
        private set
    @Volatile
    var speedBytes: Long = 0L
        private set
    @Volatile
    var speedFull: Boolean = false
        private set
    @Volatile
    var speedRunningSince: Long = 0L
        private set

    fun setSpeed(at: Long, state: Int, kbps: Int, pingMs: Int, bytes: Long, full: Boolean) {
        speedAt = at
        speedState = state
        speedKbps = kbps
        speedPingMs = pingMs
        speedBytes = bytes
        speedFull = full
        speedRunningSince = 0L
        publishNow(urgent = true)
    }

    /** Замер начался (экран пишет «замеряю…») или закончился ничем (0). */
    fun setSpeedRunning(since: Long) {
        if (speedRunningSince == since) return
        speedRunningSince = since
        publishNow(urgent = true)
    }

    /** Новая сессия — число от прошлой точки к ней не относится. */
    fun clearSpeed() {
        if (speedAt == 0L && speedRunningSince == 0L && speedState == TunnelStatus.SPEED_UNKNOWN) return
        speedAt = 0L
        speedState = TunnelStatus.SPEED_UNKNOWN
        speedKbps = -1
        speedPingMs = -1
        speedBytes = 0L
        speedFull = false
        speedRunningSince = 0L
        publishNow(urgent = false)
    }

    /** Новая сессия — прежний итог проверки связи к ней не относится. */
    fun clearLink() {
        if (tgMediaAt != 0L || tgMedia != 0) setTgMedia(0L, 0, -1)
        if (linkAt == 0L && linkWeb == TunnelStatus.LINK_UNKNOWN && linkTg == TunnelStatus.LINK_UNKNOWN) return
        setLink(0L, TunnelStatus.LINK_UNKNOWN, -1, TunnelStatus.LINK_UNKNOWN, -1, "")
    }

    /**
     * true — сервис чем-то занят (поднимается, работает или ждёт повтора): по нему публикуется
     * «сердцебиение». Ожидание повтора — тоже жизнь: без сердцебиения снимок за пару минут
     * «протухал», и интерфейс шёл проверять, не умер ли сервис.
     */
    fun isAlive(): Boolean = up || busy || wanted

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
        phase = phase,
        wanted = wanted,
        stoppedByUser = stoppedByUser,
        stoppedByUserAt = stoppedByUserAt,
        probe = probe,
        marks = marks,
        linkAt = linkAt,
        linkWeb = linkWeb,
        linkMs = linkMs,
        linkTg = linkTg,
        linkTgMs = linkTgMs,
        linkExit = linkExit,
        speedAt = speedAt,
        speedState = speedState,
        speedKbps = speedKbps,
        speedPingMs = speedPingMs,
        speedBytes = speedBytes,
        speedFull = speedFull,
        speedRunningSince = speedRunningSince,
        dataCheckAt = dataCheckAt,
        second = second,
        secondPeer = secondPeer,
        tgMedia = tgMedia,
        tgMediaKbps = tgMediaKbps,
        tgMediaAt = tgMediaAt,
        tgSecond = tgSecond,
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
            phase = snapshot.phase
            wanted = snapshot.wanted
            stoppedByUser = snapshot.stoppedByUser
            stoppedByUserAt = snapshot.stoppedByUserAt
            probe = snapshot.probe
            marks = snapshot.marks
            setLink(snapshot.linkAt, snapshot.linkWeb, snapshot.linkMs, snapshot.linkTg, snapshot.linkTgMs, snapshot.linkExit)
            speedAt = snapshot.speedAt
            speedState = snapshot.speedState
            speedKbps = snapshot.speedKbps
            speedPingMs = snapshot.speedPingMs
            speedBytes = snapshot.speedBytes
            speedFull = snapshot.speedFull
            speedRunningSince = snapshot.speedRunningSince
            dataCheckAt = snapshot.dataCheckAt
            second = snapshot.second
            secondPeer = snapshot.secondPeer
            setTgMedia(snapshot.tgMediaAt, snapshot.tgMedia, snapshot.tgMediaKbps)
            tgSecond = snapshot.tgSecond
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
        dataCheckAt = 0L
        phase = TunnelStatus.PHASE_STARTING
    }

    /**
     * Подключить процесс интерфейса к снимку сервиса. Вызывается из контроллера и плитки;
     * слушатель регистрируется ровно один раз на процесс — активность пересоздаётся при каждом
     * повороте экрана, и добавлять зеркало каждый раз значило бы копить слушатели.
     */
    fun installMirror(context: android.content.Context) {
        dev.warpscout.app.status.TunnelStatusBus.install(context)
        if (mirrorInstalled.compareAndSet(false, true)) {
            dev.warpscout.app.status.TunnelStatusBus.addListener { status -> applySnapshot(status) }
        }
    }

    private val mirrorInstalled = java.util.concurrent.atomic.AtomicBoolean(false)

    /** true — поля заполняются из снимка другого процесса, публиковать их обратно не нужно. */
    @Volatile
    private var mirroring: Boolean = false

    private fun publishNow(urgent: Boolean) {
        if (!mirroring) TunnelStatusPublisher.request(urgent)
    }
}
