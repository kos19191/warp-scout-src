package dev.warpscout.core.tune

/**
 * Что на какой сети было с каким шумом (с 1.10.30): «пошли и встали», «данных нет», «идут».
 *
 * Зачем. Журнал 22.11: на Wi-Fi человека чистый WireGuard (шум «none») отвечал на рукопожатие и на
 * первый запрос, а дальше молчал — на любой точке. С TLS-маской та же точка работала 12 часов. Но
 * сервис помечал мёртвой точку, а не шум, перебирал точки с тем же «none» и через полчаса
 * подбирал новые — снова с «none». Книга помнит про шум: на этой сети «none» замерзает — значит,
 * следующую попытку сервис сделает с маской, а подбор не станет тратить на «none» время.
 *
 * Чистая логика без файлов и Android — хранение в приложении (NoiseMemory). Записи старше
 * [TTL_MS] не учитываются: сеть могут перенастроить, и тогда «none» снова стоит проверить.
 */
object NoiseBook {

    /** Данные пошли и встали (первый ответ есть, позднего нет). */
    const val FROZE = 'F'

    /** Рукопожатие есть, данных нет совсем. */
    const val NO_DATA = 'N'

    /** Данные идут и после первых секунд. */
    const val WORKED = 'W'

    /** Подбор: с этим шумом данные встают, а с другим на тех же точках идут. */
    const val TUNER = 'T'

    /** Сколько помнить, мс: трое суток. */
    const val TTL_MS = 3L * 24 * 3600 * 1000

    /** Предел числа записей: свежие вытесняют давние. */
    const val MAX_EVENTS = 300

    /** Шум «без шума» — чистый WireGuard. */
    const val PLAIN = "none"

    data class Event(val net: String, val noise: String, val kind: Char, val endpoint: String, val at: Long)

    /** Строка файла: `сеть|шум|вид|точка|время`. Битые строки пропускаются. */
    fun parse(text: String): List<Event> = text.lineSequence().mapNotNull { line ->
        val p = line.split('|')
        if (p.size < 5) return@mapNotNull null
        val kind = p[2].trim().singleOrNull() ?: return@mapNotNull null
        val at = p[4].trim().toLongOrNull() ?: return@mapNotNull null
        val net = p[0].trim()
        val noise = p[1].trim()
        if (net.isEmpty() || noise.isEmpty() || kind !in listOf(FROZE, NO_DATA, WORKED, TUNER)) null
        else Event(net, noise, kind, p[3].trim(), at)
    }.toList()

    fun render(events: List<Event>): String =
        events.joinToString("") { e -> "${clean(e.net)}|${clean(e.noise)}|${e.kind}|${clean(e.endpoint)}|${e.at}\n" }

    private fun clean(s: String): String = s.replace('|', '/').replace('\n', ' ').trim()

    /** Добавить запись: давние (старше [TTL_MS]) и лишние сверх [MAX_EVENTS] уходят. */
    fun add(events: List<Event>, e: Event): List<Event> =
        (events.filter { e.at - it.at in 0..TTL_MS } + e).takeLast(MAX_EVENTS)

    /**
     * Шум, который на сети [net] считается замерзающим. Учитываются записи после последнего «идут»
     * этого шума на этой сети:
     *  • подбор сказал «встают» ([TUNER]) — сразу;
     *  • «пошли и встали» ([FROZE]) у чистого WireGuard — сразу: ровно так DPI режет опознанный
     *    WireGuard, а мёртвая точка первого ответа не дала бы; у шума-маски — на двух разных точках
     *    (на одной это может быть сама точка);
     *  • «данных нет» ([NO_DATA]) — на двух разных точках.
     */
    fun frozen(events: List<Event>, net: String, now: Long): Set<String> {
        if (net.isBlank()) return emptySet()
        val mine = events.filter { it.net == net && now - it.at in 0..TTL_MS }
        val out = HashSet<String>()
        for ((noise, list) in mine.groupBy { it.noise }) {
            val lastWorked = list.filter { it.kind == WORKED }.maxOfOrNull { it.at } ?: Long.MIN_VALUE
            val after = list.filter { it.kind != WORKED && it.at > lastWorked }
            fun points(kind: Char) = after.filter { it.kind == kind }.map { it.endpoint }.distinct().size
            val froze = points(FROZE)
            val bad = after.any { it.kind == TUNER } ||
                (noise == PLAIN && froze >= 1) ||
                froze >= 2 ||
                points(NO_DATA) >= 2 ||
                froze + points(NO_DATA) >= 3
            if (bad) out += noise
        }
        return out
    }

    /** Шум, с которым данные на этой сети шли последними, — если он с тех пор не замерзает. */
    fun preferred(events: List<Event>, net: String, now: Long): String? {
        if (net.isBlank()) return null
        val last = events.filter { it.net == net && it.kind == WORKED && now - it.at in 0..TTL_MS }
            .maxByOrNull { it.at }?.noise ?: return null
        return last.takeIf { it !in frozen(events, net, now) }
    }

    /**
     * Чем заменить шум [current] на сети [net]: null — менять не нужно (он не замерзает) или не на
     * что (замерзает всё из [order]). Первым — шум, с которым здесь уже шли данные, потом [order].
     */
    fun replacement(events: List<Event>, net: String, current: String, order: List<String>, now: Long): String? {
        val bad = frozen(events, net, now)
        if (current !in bad) return null
        val pref = preferred(events, net, now)
        return (listOfNotNull(pref) + order).firstOrNull { it != current && it !in bad }
    }
}
