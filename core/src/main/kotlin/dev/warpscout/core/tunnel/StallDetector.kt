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

    /**
     * Сколько ждём, прежде чем заподозрить неладное и проверить связь по-настоящему.
     *
     * Зачем второй, «мягкий» порог. [isStalled] требует 50 пакетов без ответа: так он не путает
     * мёртвую сессию с одиночными UDP-датаграммами, но и не видит приложение, которое шлёт мало.
     * Telegram, потерявший соединение, пытается заново редкими пакетами — пятьдесят штук за 45 с
     * не набирается, и туннель часами числился «подключённым», хотя Telegram не работал.
     * Подозрение само туннель не рвёт: сервис по нему делает проверку связи (запрос через туннель),
     * и только её провал ведёт к переподключению.
     */
    const val SUSPECT_MS = 15_000L

    /** Сколько пакетов должно уйти без ответа, чтобы заподозрить. Живой сервер отвечает раньше. */
    const val SUSPECT_PACKETS = 8

    /** Пора проверить связь: ушло [SUSPECT_PACKETS] пакетов и [SUSPECT_MS] нет ни одного ответа. */
    fun isSuspect(now: Long, lastRxAt: Long, burstStartAt: Long, sentPackets: Int): Boolean =
        isStalled(now, lastRxAt, burstStartAt, sentPackets, SUSPECT_MS, SUSPECT_PACKETS)

    /**
     * Свежая сессия, по которой ещё не пришло ни байта данных (с 1.10.44-beta3; включает вызывающий —
     * для второго выхода). Журнал 24.11, 14:47: бесплатный сервер Proton (NL-FREE#125) принял рукопожатие,
     * а на 392 пакета не ответил ничем, и 45 с — пока не сработало общее правило — TikTok стоял без
     * интернета, а сравнение Telegram решило, что второй выход «не быстрее». Живой сервер на первые же
     * соединения (TCP SYN) отвечает за доли секунды, поэтому, пока данных не было вовсе, ждём меньше.
     */
    const val FRESH_WINDOW_MS = 15_000L

    /** Сколько пакетов должно уйти по свежей сессии без единого ответа. */
    const val FRESH_MIN_PACKETS = 20

    /** Свежая сессия не пропускает данные: [FRESH_MIN_PACKETS] пакетов и [FRESH_WINDOW_MS] без ответа. */
    fun isFreshDead(now: Long, lastRxAt: Long, burstStartAt: Long, sentPackets: Int): Boolean =
        isStalled(now, lastRxAt, burstStartAt, sentPackets, FRESH_WINDOW_MS, FRESH_MIN_PACKETS)

    /** Строка в журнал для [isFreshDead]. */
    fun explainFresh(now: Long, lastRxAt: Long, burstStartAt: Long, sentPackets: Int): String {
        val anchor = maxOf(lastRxAt, burstStartAt)
        val silent = if (anchor <= 0L) 0L else (now - anchor) / 1000
        return "сервер принял рукопожатие, но данных не пропускает: $sentPackets пакетов отправлено, ответа нет $silent с"
    }

    /** Человеческое объяснение для журнала: по нему видно, что именно решило дело. */
    fun explain(now: Long, lastRxAt: Long, burstStartAt: Long, sentPackets: Int): String {
        val anchor = maxOf(lastRxAt, burstStartAt)
        val silent = if (anchor <= 0L) 0L else (now - anchor) / 1000
        return "сессия молчит: $sentPackets пакетов отправлено, ответа нет $silent с"
    }
}
