package dev.warpscout.core.tunnel

/**
 * Сколько держать паузу между keepalive-пакетами.
 *
 * Каждый keepalive — это пробуждение радиомодуля, и после него модем ещё несколько секунд висит в
 * активном состоянии. На мобильной сети, где телефон лежит с погашенным экраном, интервал 25 секунд
 * означает, что радио практически не спит: именно так «подключённый, но ничего не делающий» туннель
 * съедает проценты батареи в час.
 *
 * Почему не отключить совсем: NAT-таблица в мобильной сети забывает про UDP-поток за минуту-две, и
 * сервер перестаёт достучаться до клиента первым. Поэтому в активном состоянии держим минуту, а
 * когда телефон лежит и трафика нет — полторы: соединение остаётся живым, а модем успевает уснуть
 * между пакетами.
 *
 * Верхняя граница 120 секунд: дольше держать бессмысленно — сессия всё равно требует
 * пересогласования до 180 секунд (жёсткий предел протокола), и NAT за это время её забудет.
 */
object Keepalive {

    /** Нижняя граница, пока телефон в руках или трафик идёт. */
    const val ACTIVE_FLOOR_MS = 60_000L

    /** Нижняя граница, когда экран погашен и трафика нет давно. */
    const val IDLE_SCREEN_OFF_FLOOR_MS = 90_000L

    /** Сколько тишины считать «трафика нет». */
    const val IDLE_AFTER_MS = 120_000L

    /** Дольше держать сессию без пересогласования всё равно не даст протокол. */
    const val MAX_MS = 120_000L

    /**
     * @param configuredSeconds что стоит в конфиге (`PersistentKeepalive`), 0 — keepalive выключен
     * @param idleMs сколько уже нет пользовательского трафика
     * @param screenOn включён ли экран
     */
    fun intervalMs(configuredSeconds: Int, idleMs: Long, screenOn: Boolean): Long {
        if (configuredSeconds <= 0) return Long.MAX_VALUE
        val configured = configuredSeconds.toLong() * 1000L
        val idle = idleMs >= IDLE_AFTER_MS
        val floor = if (!screenOn && idle) IDLE_SCREEN_OFF_FLOOR_MS else ACTIVE_FLOOR_MS
        // Пользователь может попросить реже — уважаем; чаще нижней границы — нет.
        return maxOf(configured, floor).coerceAtMost(MAX_MS)
    }

    /** Что происходит с интервалом — для журнала, чтобы расход объяснялся, а не угадывался. */
    fun describe(intervalMs: Long, screenOn: Boolean, idleMs: Long): String = when {
        intervalMs == Long.MAX_VALUE -> "keepalive выключен"
        !screenOn && idleMs >= IDLE_AFTER_MS -> "экран погашен, трафика нет ${idleMs / 1000} с — keepalive ${intervalMs / 1000} с"
        else -> "keepalive ${intervalMs / 1000} с"
    }
}
