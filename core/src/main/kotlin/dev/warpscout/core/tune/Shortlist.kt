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
        // Кандидатов, проверенных изнутри туннеля с результатом 0/N (доказанно не пропускают трафик,
        // например чистый WireGuard под DPI), исключаем, пока есть рабочие или непроверенные варианты.
        val alive = candidates.filter { it.stats.replies > 0 || it.resourcesOk > 0 }
        val notBroken = alive.filterNot { isProvenBroken(it) }
        val pool = (when {
            notBroken.isNotEmpty() -> notBroken
            alive.isNotEmpty() -> alive
            else -> candidates
        }).sortedWith(rank())

        val result = ArrayList<Candidate>(limit)
        val endpoints = HashSet<String>()
        val subnets = HashSet<String>()
        // Внутри каждого уровня надёжности сначала берём разные /24-подсети (разные дата-центры
        // Cloudflare, например 162.159.192.x ARN + 188.114.97.x HEL), затем разные IP:порт.
        for (tier in listOf(2, 1, 0)) {
            if (result.size >= limit) break
            val tierPool = pool.filter { verifyTier(it) == tier }
            for (c in tierPool) {
                if (result.size >= limit) break
                val sub = AutoTuner.subnet24Of(c.config.endpoint.host)
                if (sub !in subnets && endpoints.add(c.config.endpoint.render())) {
                    subnets.add(sub)
                    result += c
                }
            }
            for (c in tierPool) {
                if (result.size >= limit) break
                if (endpoints.add(c.config.endpoint.render())) result += c
            }
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
     * Трёхуровневый приоритет:
     *  • 2 — проверен изнутри туннеля и реально открыл ресурсы (`ok > 0`);
     *  • 1 — не проверялся изнутри (`total == 0`), но ответил на handshake;
     *  • 0 — проверен изнутри и доказанно не пропустил ни одного ресурса (`0/N`).
     *
     * Раньше проверялось только `resourcesTotal > 0`, из-за чего доказанно мёртвые `0/10`
     * обгоняли рабочие непроверенные варианты и попадали на 1–2 места.
     */
    private fun verifyTier(c: Candidate): Int = when {
        c.resourcesTotal > 0 && c.resourcesOk > 0 -> 2
        c.resourcesTotal == 0 -> 1
        else -> 0
    }

    private fun isProvenBroken(c: Candidate): Boolean =
        c.resourcesTotal > 0 && c.resourcesOk <= 0

    private fun rank(): Comparator<Candidate> =
        compareByDescending<Candidate> { verifyTier(it) }
            .thenByDescending { it.resourcesOk }
            .thenByDescending { it.score }

    private fun key(c: Candidate): String = c.config.endpoint.render() + "|" + c.config.junk.name
}
