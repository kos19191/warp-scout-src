package dev.warpscout.app.tunnel

/** Общее состояние туннеля: читают UI и верификатор, пишет — сервис. */
object TunnelState {
    @Volatile
    var up: Boolean = false

    /** Текущий этап человеческим языком — именно это видно в кнопке и в статусе. */
    @Volatile
    var status: String = ""

    @Volatile
    var endpoint: String = ""

    /** Причина отказа, если он был. UI показывает её вместо «ничего не произошло». */
    @Volatile
    var error: String? = null

    /** Сервис сам сдался (таймаут/ошибка) — ждать больше нечего. */
    @Volatile
    var gaveUp: Boolean = false

    /** Когда последняя попытка стартовала: UI по этому отличает «не запускался» от «висит». */
    @Volatile
    var startedAt: Long = 0L
}
