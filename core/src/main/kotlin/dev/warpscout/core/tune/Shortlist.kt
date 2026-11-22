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

    fun pick(candidates: List<Candidate>, limit: Int = LIMIT): List<Candidate> {
        if (limit <= 0 || candidates.isEmpty()) return emptyList()
        // Мёртвых не предлагаем: «переключиться» должно вести на что-то, что хотя бы ответило.
        val alive = candidates.filter { it.stats.replies > 0 || it.resourcesOk > 0 }
        val pool = (if (alive.isNotEmpty()) alive else candidates).sortedWith(rank())

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
            .thenByDescending { it.resourcesOk }
            // Одинаково открывшиеся — по ступени скорости через туннель (см. SpeedTest.bucket).
            .thenByDescending { dev.warpscout.core.net.SpeedTest.bucket(it.speedKbps) }
            .thenByDescending { it.score }

    private fun key(c: Candidate): String = c.config.endpoint.render() + "|" + c.config.junk.name
}
