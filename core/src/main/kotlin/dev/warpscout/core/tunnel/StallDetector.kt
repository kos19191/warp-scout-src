package dev.warpscout.core.tunnel

/**
 * Решение «сессия мертва, хотя формально поднята».
 *
 * Зачем отдельно от [DataPlane]: ошибка здесь дороже ошибки в любом другом месте. Слишком
 * чувствительное правило рвёт рабочий туннель (пользователь видит «переподключаюсь» на ровном
 * месте), слишком грубое — оставляет мёртвое соединение на минуты. Поэтому правило живёт чистой
 * функцией и проверяется в SelfCheck сценариями, а не подбирается на глаз.
 *
 * Логика: считаем, что соединение мертво, только если **пользовательский трафик идёт** и на него
 * **ни одного ответа**. Пока трафик стоит, судить не о чем: молчащий туннель без трафика — это
 * норма (все приложения спят). Успешное пересогласование сессии тоже считается ответом.
 */
object StallDetector {

    /** Сколько ждём ответа, прежде чем признать сессию мёртвой. */
    const val WINDOW_MS = 45_000L

    /** Сколько пакетов должно уйти без единого ответа: единичные UDP-датаграммы ответа не ждут. */
    const val MIN_PACKETS = 50

    /**
     * @param now текущее время, мс
     * @param lastRxAt когда последний раз что-то пришло с сервера (0 — не приходило ни разу)
     * @param burstStartAt когда начался текущий поток исходящих пакетов без ответа (0 — трафика нет)
     * @param sentPackets сколько пакетов ушло с начала этого потока
     */
    fun isStalled(
        now: Long,
        lastRxAt: Long,
        burstStartAt: Long,
        sentPackets: Int,
        windowMs: Long = WINDOW_MS,
        minPackets: Int = MIN_PACKETS,
    ): Boolean {
        if (sentPackets < minPackets) return false
        if (burstStartAt <= 0L) return false
        // Отсчёт от последнего события: либо ответ сервера, либо начало потока — что позже.
        val anchor = maxOf(lastRxAt, burstStartAt)
        if (anchor <= 0L) return false
        return now - anchor >= windowMs
    }

    /** Человеческое объяснение для журнала: по нему видно, что именно решило дело. */
    fun explain(now: Long, lastRxAt: Long, burstStartAt: Long, sentPackets: Int): String {
        val anchor = maxOf(lastRxAt, burstStartAt)
        val silent = if (anchor <= 0L) 0L else (now - anchor) / 1000
        return "сессия молчит: $sentPackets пакетов отправлено, ответа нет $silent с"
    }
}
