package dev.warpscout.core.tune

import dev.warpscout.core.model.Candidate

/**
 * Отбор тройки лучших кандидатов для быстрого переключения.
 *
 * Победитель подбора — один, но сеть режет адреса выборочно: точка, которая открылась сейчас, к
 * вечеру может перестать пропускать handshake. Повторный скан — минуты и разогрев радио, поэтому
 * пользователю нужны готовые замены, и они уже есть в отчёте: второе и третье места.
 *
 * Главное правило отбора — **разные точки входа**. Три варианта с одного адреса и разным профилем
 * шума выглядят как выбор, а на деле падают вместе: если сеть зарезала адрес, ей всё равно, что мы
 * положили в мусорные пакеты. Поэтому сначала берём по одному кандидату с разных endpoint'ов, и
 * только потом добираем оставшиеся места другими профилями шума на уже выбранных адресах.
 *
 * Ранжирование — как в [AutoTuner.finish]: сначала «сколько реально открылось изнутри туннеля»
 * (это факт), потом сетевой балл (это оценка).
 */
object Shortlist {

    /** Три — предел полезного: больше вариантов превращает быстрое переключение во второй список. */
    const val LIMIT = 3

    /** Годится ли кандидат в очередь (см. [Candidate.usable]). */
    fun usable(c: Candidate): Boolean = c.usable

    fun pick(candidates: List<Candidate>, limit: Int = LIMIT): List<Candidate> {
        if (limit <= 0 || candidates.isEmpty()) return emptyList()
        // Мёртвых и «рукопожатие есть, данных нет» не предлагаем вовсе — даже когда других нет.
        // Раньше при пустом списке живых в тройку шли молчащие точки (журнал 22.11 16:32: три точки
        // по 60 баллов, ни одна не ответила), подключение перебирало заведомо мёртвое, а прежняя
        // рабочая тройка затиралась. Пустой итог означает «тройку не трогать».
        val pool = candidates.filter { usable(it) }.sortedWith(rank())

        val result = ArrayList<Candidate>(limit)
        val endpoints = HashSet<String>()
        for (c in pool) {
            if (result.size >= limit) break
            if (endpoints.add(c.config.endpoint.render())) result += c
        }
        if (result.size < limit) {
            val seen = result.mapTo(HashSet()) { key(it) }
            for (c in pool) {
                if (result.size >= limit) break
                if (seen.add(key(c))) result += c
            }
        }
        return result
    }

    /**
     * Тот же порядок, что у победителя подбора: проверенное изнутри важнее непроверенного, дальше
     * число открытых сайтов, дальше балл. Без этого на первое место мог попасть кандидат, который
     * отвечает на handshake, но не пускает трафик.
     */
    private fun rank(): Comparator<Candidate> =
        compareByDescending<Candidate> { it.resourcesTotal > 0 }
            .thenByDescending { opened(it) }
            .thenByDescending { dev.warpscout.core.net.ExitSite.rank(it.site) }
            // Ответ через туннель пришёл — выше тех, у кого данные не проверяли (старые отчёты).
            .thenByDescending { it.stats.dataReplies > 0 }
            // Одинаково открывшиеся — по ступени скорости через туннель (см. SpeedTest.bucket).
            .thenByDescending { dev.warpscout.core.net.SpeedTest.bucket(it.speedKbps) }
            .thenByDescending { it.score }

    /**
     * Порядок проверенных изнутри — общий для победителя подбора и первой строки тройки: сколько
     * открылось → где выход → ступень скорости → балл.
     */
    fun verifiedOrder(): Comparator<Candidate> =
        compareByDescending<Candidate> { opened(it) }
            .thenByDescending { dev.warpscout.core.net.ExitSite.rank(it.site) }
            .thenByDescending { dev.warpscout.core.net.SpeedTest.bucket(it.speedKbps) }
            .thenByDescending { it.score }

    /**
     * Сколько открылось изнутри, и выход за рубежом — как ещё один открывшийся сайт (с 1.10.34).
     * Через российскую площадку Cloudflare медиа Telegram и часть сайтов режут фильтры (журнал
     * 23.11), а проверка «открылось» этого почти не видит: соединение с Telegram открывается.
     * Поэтому при равенстве или разнице в один сайт первой идёт точка с выходом за рубежом, а
     * точка, через которую открылось заметно больше, остаётся первой и с выходом через Москву.
     */
    fun opened(c: Candidate): Int =
        if (c.resourcesTotal > 0 && dev.warpscout.core.net.ExitSite.isAbroad(c.site)) c.resourcesOk + 1 else c.resourcesOk

    private fun key(c: Candidate): String = c.config.endpoint.render() + "|" + c.config.junk.name
}
