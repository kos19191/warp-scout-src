package dev.warpscout.core.net

/**
 * Пускать ли Telegram через второй выход (с 1.10.36): предлагает приложение, решает человек.
 *
 * Зачем. С 1.10.34 Telegram уходил во второй выход сразу, как только WARP выходил через Москву, —
 * без всякой проверки скорости. А режут Telegram в Москве не всегда: человек написал (23.11), что
 * через Москву было нормально, а во втором выходе (сервер в Мексике) — «прямо тяжело». Решил
 * (23.11): спрашивать, и только когда это поможет, —
 *  • по умолчанию Telegram идёт через Москву (напрямую через WARP);
 *  • проверка медиа через Москву показала «тормозит» или «встаёт» — та же загрузка через второй
 *    выход; заметно лучше — вопрос с цифрами: «Переключить» / «Оставить»;
 *  • ответ — на сутки для этой сети ([VALID_MS]); без ответа вопрос не повторяется [ASK_GAP_MS];
 *  • второй выход стал медленнее Москвы — Telegram сам возвращается через Москву.
 *
 * Здесь — правила и формат памяти (строки «сеть|решение|время»); хранит её приложение.
 */
object TelegramChoice {

    /** «Переключить»: Telegram — через второй выход, пока он быстрее Москвы. */
    const val SECOND = "second"

    /** «Оставить»: Telegram — через Москву, сутки не спрашиваем. */
    const val STAY = "stay"

    /** Спросили, ответа нет: не спрашиваем снова [ASK_GAP_MS]. */
    const val ASKED = "asked"

    /** Сколько действует ответ. */
    const val VALID_MS = 24L * 3_600_000L

    /** Через сколько можно спросить снова, если на вопрос не ответили. */
    const val ASK_GAP_MS = 3L * 3_600_000L

    /** Сколько сетей помним: старые записи уходят. */
    const val MAX_NETS = 32

    data class Mark(val net: String, val choice: String, val at: Long)

    fun parse(text: String): List<Mark> = text.lineSequence().mapNotNull { line ->
        val p = line.trim().split('|')
        if (p.size != 3) return@mapNotNull null
        val net = p[0].trim()
        val choice = p[1].trim()
        val at = p[2].trim().toLongOrNull() ?: return@mapNotNull null
        if (net.isEmpty() || choice !in setOf(SECOND, STAY, ASKED)) return@mapNotNull null
        Mark(net, choice, at)
    }.toList()

    fun render(marks: List<Mark>): String =
        marks.joinToString("") { "${it.net.replace('|', '/')}|${it.choice}|${it.at}\n" }

    /** Запись для сети заменяет прежнюю; сетей — не больше [MAX_NETS] (старые уходят). */
    fun put(marks: List<Mark>, mark: Mark): List<Mark> =
        (marks.filter { it.net != mark.net } + mark).takeLast(MAX_NETS)

    /** Действующее решение для сети: [SECOND] и [STAY] — сутки, [ASKED] — [ASK_GAP_MS]; пусто — нет. */
    fun choiceOf(marks: List<Mark>, net: String, now: Long): String {
        if (net.isBlank()) return ""
        val m = marks.lastOrNull { it.net == net } ?: return ""
        val ttl = if (m.choice == ASKED) ASK_GAP_MS else VALID_MS
        return if (now - m.at in 0 until ttl) m.choice else ""
    }

    /** Ранг загрузки: без остановок лучше, чем медленно, медленно лучше, чем «встаёт»; не пошла — −1. */
    fun rank(verdict: Int): Int = when (verdict) {
        TelegramMedia.OK -> 2
        TelegramMedia.SLOW -> 1
        TelegramMedia.STALL -> 0
        else -> -1
    }

    /**
     * Через Москву плохо — есть смысл сравнить со вторым выходом: тормозит, встаёт или загрузка не
     * пошла вовсе (при работающем соединении с Telegram — проверка медиа идёт только тогда).
     */
    fun poor(verdict: Int): Boolean =
        verdict == TelegramMedia.SLOW || verdict == TelegramMedia.STALL || verdict == TelegramMedia.FAIL

    /**
     * Второй выход заметно лучше Москвы: через Москву плохо ([poor]), а через второй выход —
     * вывод лучше, или тот же, но в полтора раза быстрее и хотя бы на 300 Кбит/с. Второй выход сам
     * встаёт или не грузит — не лучше.
     */
    fun secondHelps(moscowVerdict: Int, moscowKbps: Int, secondVerdict: Int, secondKbps: Int): Boolean {
        if (!poor(moscowVerdict)) return false
        val m = rank(moscowVerdict)
        val s = rank(secondVerdict)
        if (s < 1) return false
        if (s != m) return s > m
        val mk = moscowKbps.coerceAtLeast(0)
        return secondKbps >= maxOf(mk * 3 / 2, mk + 300)
    }

    /**
     * Второй выход медленнее Москвы — Telegram возвращается через Москву: у второго выхода вывод
     * хуже (не грузит, встаёт), или тот же, но он медленнее Москвы на 20 % и больше. Москва сама
     * не грузит — не возвращаемся: сравнивать не с чем.
     */
    fun secondWorse(moscowVerdict: Int, moscowKbps: Int, secondVerdict: Int, secondKbps: Int): Boolean {
        val m = rank(moscowVerdict)
        val s = rank(secondVerdict)
        if (m < 0) return false
        if (s != m) return s < m
        return secondKbps.coerceAtLeast(0).toLong() * 10 < moscowKbps.coerceAtLeast(0).toLong() * 8
    }

    /** Коротко, для вопроса: «4,1 Мбит/с», «300 Кбит/с, медленно», «2,0 Мбит/с, рывками», «встаёт». */
    fun short(verdict: Int, kbps: Int): String = when (verdict) {
        TelegramMedia.OK -> SpeedTest.human(kbps)
        TelegramMedia.SLOW ->
            if (kbps in 0 until TelegramMedia.SLOW_KBPS) "${SpeedTest.human(kbps)}, медленно" else "${SpeedTest.human(kbps)}, рывками"
        TelegramMedia.STALL -> "встаёт посреди загрузки"
        TelegramMedia.FAIL -> "не грузится"
        else -> "не проверено"
    }
}
