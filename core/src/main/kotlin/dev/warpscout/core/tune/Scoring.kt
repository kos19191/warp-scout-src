package dev.warpscout.core.tune

import dev.warpscout.core.model.EndpointStats
import dev.warpscout.core.model.ScoreParts
import dev.warpscout.core.model.Verdict

/**
 * Скоринг кандидатов. Специально простой и объяснимый: в отчёте видно, из чего сложился балл,
 * а веса можно крутить под себя. Max ≈ 1750.
 *
 *  • confirmed      — главный признак: WireGuard реально ответил на НАШ handshake (1000)
 *                     или прислал cookie (700, сервер жив, но под нагрузкой);
 *  • tls            — для MASQUE-портов подтверждённый TLS — тоже сильный сигнал (600);
 *  • latency        — лучший RTT;
 *  • stability      — доля потерянных попыток;
 *  • jitter         — разброс;
 *  • junk_survival  — handshake дошёл, даже когда перед ним летел мусор профиля (значит DPI его не режет);
 *  • resource_bonus — сколько целевых сайтов открылось через эту конфигурацию (когда проверяли туннелем);
 *  • penalty        — закрытый порт / не разрешился хост.
 */
data class Weights(
    val handshakeOk: Int = 1000,
    val cookieReply: Int = 700,
    val tlsOk: Int = 600,
    val silent: Int = 60,
    val latencyBands: List<Pair<Double, Int>> = listOf(
        25.0 to 300, 50.0 to 260, 80.0 to 210, 120.0 to 150, 200.0 to 90, 400.0 to 40, Double.MAX_VALUE to 10
    ),
    val stableBands: List<Pair<Double, Int>> = listOf(
        0.0 to 200, 20.0 to 150, 40.0 to 90, 70.0 to 40, Double.MAX_VALUE to 0
    ),
    val jitterBands: List<Pair<Double, Int>> = listOf(
        8.0 to 100, 20.0 to 70, 50.0 to 35, Double.MAX_VALUE to 10
    ),
    val junkSurvived: Int = 150,
    val junkBlocked: Int = 150,
    val closedPenalty: Int = 500,
    val dnsPenalty: Int = 800,
    val perResourceOk: Int = 60
)

object Scoring {

    private fun band(value: Double, bands: List<Pair<Double, Int>>): Int =
        bands.firstOrNull { value <= it.first }?.second ?: 0

    fun evaluate(
        stats: EndpointStats,
        junkSurvived: Boolean?,
        resourcesOk: Int = 0,
        resourcesTotal: Int = 0,
        weights: Weights = Weights()
    ): ScoreParts {
        val confirmed = when (stats.bestVerdict) {
            Verdict.HANDSHAKE_OK -> weights.handshakeOk
            Verdict.COOKIE_REPLY -> weights.cookieReply
            Verdict.TLS_OK -> weights.tlsOk
            Verdict.UDP_SILENT -> weights.silent
            else -> 0
        }
        val latency = stats.minRtt?.let { band(it, weights.latencyBands) } ?: 0
        val stability = band(stats.lossPct, weights.stableBands)
        val jitter = stats.jitterMs?.let { band(it, weights.jitterBands) } ?: 0
        val junk = when (junkSurvived) {
            true -> weights.junkSurvived
            false -> -weights.junkBlocked
            null -> 0
        }
        val resource = if (resourcesTotal > 0) resourcesOk * weights.perResourceOk else 0
        val penalty = when {
            stats.samples.all { it.verdict == Verdict.UDP_CLOSED } -> weights.closedPenalty
            stats.samples.any { it.verdict == Verdict.DNS_FAIL } -> weights.dnsPenalty
            else -> 0
        }
        return ScoreParts(
            confirmed = maxOf(0, confirmed),
            latency = latency,
            stability = if (confirmed > 0) stability else stability / 2,
            jitter = jitter,
            junkSurvival = junk,
            resourceBonus = resource,
            penalty = penalty
        )
    }
}
