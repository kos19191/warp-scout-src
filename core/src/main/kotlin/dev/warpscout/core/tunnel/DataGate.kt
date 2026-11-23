package dev.warpscout.core.tunnel

/**
 * Решение «идут ли данные» сразу после рукопожатия — для сервиса туннеля (с 1.10.30).
 *
 * Зачем. До 1.10.30 сервис объявлял туннель рабочим по первому же ответу через туннель. А сеть
 * человека пропускала рукопожатие и первые 60–200 байт, после чего замолкала (журнал 22.11,
 * 19:04:45: «данные идут: ответ за 82 мс», «туннель поднят», а через 28 с проверка связи — «нет
 * ответа»). Так шло по кругу полчаса: каждая точка без шума «поднималась» и через полминуты
 * объявлялась мёртвой.
 *
 * Теперь рабочим туннель считается, только когда данные идут и через [lateMs] после начала:
 * пришёл ответ на пробу, отправленную после этого момента, или приложения получили что-то вниз
 * уже после него. Первый ответ без позднего — «пошли и встали» ([Verdict.FROZEN]).
 *
 * Сам класс не шлёт пакетов и не смотрит на часы: сервис раз в несколько десятков миллисекунд
 * зовёт [step] с прошедшим временем и счётчиками data plane и делает то, что тот скажет. Так
 * правило проверяется в самопроверке без сети и без Android.
 */
class DataGate(
    private val probeAtMs: LongArray = PROBE_AT_MS,
    private val lateMs: Long = LATE_MS,
    /** Всё окно проверки, мс: после него без позднего ответа — [Verdict.FROZEN] или [Verdict.NO_DATA]. */
    val windowMs: Long = WINDOW_MS
) {
    enum class Step { SEND_PROBE, WAIT, DONE }

    enum class Verdict {
        /** Данные идут и после первых полутора секунд. */
        FLOWING,

        /** Первый ответ был, позднего — нет: сеть пропускает начало и режет остальное. */
        FROZEN,

        /** Ни ответа, ни байта вниз за всё окно. */
        NO_DATA
    }

    private var sent = 0
    private var firstAt = -1L
    private var lateRepliesBase = -1
    private var lateBytesBase = -1L

    /** Итог; null — проверка ещё идёт. */
    var verdict: Verdict? = null
        private set

    /** Когда пришёл первый ответ (или первый байт вниз), мс от начала; -1 — не приходил. */
    val firstMs: Long get() = firstAt

    /** Сколько проб уже отправлено. */
    val probesSent: Int get() = sent

    /**
     * Очередной шаг. [sinceMs] — сколько прошло с конца рукопожатия, [replies] — сколько ответов
     * на пробы пришло всего, [bytesDown] — сколько байт приложений пришло вниз всего.
     */
    fun step(sinceMs: Long, replies: Int, bytesDown: Long): Step {
        if (verdict != null) return Step.DONE
        if (firstAt < 0 && (replies > 0 || bytesDown > 0L)) firstAt = sinceMs
        // Отметка «сколько байт вниз было к поздней поре»: рост после неё — данные идут и сейчас.
        if (sinceMs >= lateMs && lateBytesBase < 0) lateBytesBase = bytesDown
        val lateReply = lateRepliesBase >= 0 && replies > lateRepliesBase
        val lateBytes = lateBytesBase >= 0 && bytesDown > lateBytesBase
        if (lateReply || lateBytes) {
            verdict = Verdict.FLOWING
            return Step.DONE
        }
        if (sent < probeAtMs.size && sinceMs >= probeAtMs[sent]) {
            // Первая поздняя проба: ответы, пришедшие после неё, — свидетельство «данные идут сейчас».
            if (probeAtMs[sent] >= lateMs && lateRepliesBase < 0) lateRepliesBase = replies
            sent++
            return Step.SEND_PROBE
        }
        if (sinceMs >= windowMs) {
            verdict = if (firstAt >= 0) Verdict.FROZEN else Verdict.NO_DATA
            return Step.DONE
        }
        return Step.WAIT
    }

    companion object {
        /** Когда слать пробы, мс от конца рукопожатия: две ранние (потеря одной — не приговор) и две поздние. */
        val PROBE_AT_MS = longArrayOf(0L, 900L, 1_600L, 2_600L)

        /** С этого момента ответ — свидетельство «данные не встали». */
        const val LATE_MS = 1_500L

        /** Всё окно проверки: последняя проба плюс время на ответ. */
        const val WINDOW_MS = 4_000L

        /** Медленная связь (H+, H, 3G, EDGE — с 1.10.40): поздние пробы на 3 и 4,5 с, окно 8 с. */
        val SLOW_PROBE_AT_MS = longArrayOf(0L, 1_500L, 3_000L, 4_500L)
        const val SLOW_LATE_MS = 2_500L
        const val SLOW_WINDOW_MS = 8_000L

        /**
         * Проверка для медленной мобильной связи. На H/H+ под нагрузкой ответ идёт секундами, и
         * обычное окно (поздняя проба на 2,6 с, конец — 4 с) объявляло «пошли и встали» туннелю, по
         * которому данные шли, только медленно. Правило то же — «данные идут и после начала», — шкала
         * вдвое длиннее.
         */
        fun forSlowNetwork(): DataGate = DataGate(SLOW_PROBE_AT_MS, SLOW_LATE_MS, SLOW_WINDOW_MS)
    }
}
