package dev.warpscout.core.junk

import dev.warpscout.core.crypto.Crypto
import dev.warpscout.core.model.AwgParams
import dev.warpscout.core.model.JunkChunk
import dev.warpscout.core.model.JunkKind
import dev.warpscout.core.model.JunkProfile

/**
 * Библиотека профилей «шума» (AWG I1/I2). Это то, что в РФ приходится постоянно перенастраивать:
 * провайдер выучивает конкретные байтовые паттерны и начинает их резать — приложение перебирает
 * профили и выбирает тот, который проходит.
 */
object JunkLibrary {

    /** Домены для SNI в QUIC-маске — тот же белый список, что использует генератор. */
    val SNI_DOMAINS = listOf(
        "akbars.ru", "babyblog.ru", "deepseek.com", "dnevnik.ru", "edimdoma.ru", "is74.ru", "ivi.ru",
        "kopilkaurokov.ru", "naked-science.ru", "nplus1.ru", "obrazovaka.ru", "pypi.org", "sdamgia.ru",
        "skyeng.ru", "uchi.ru", "videouroki.net", "yaklass.ru", "youdo.com", "youla.ru", "zakon.ru",
        "zdorovie.ru", "zdorovieinfo.ru", "znaika.ru", "zoon.ru"
    )

    /** Фиксированный TLS-like шаблон — «1 вариант» генератора (точный байт-на-байт, см. JunkTemplates). */
    val TLS_LITERAL_HEX: String get() = JunkTemplates.TLS_FIXED_HEX

    fun none() = JunkProfile("none", emptyList(), emptyList(), AwgParams(jc = 0), JunkKind.NONE,
        "без мусорных пакетов — чистый WireGuard")

    fun tlsFixed() = JunkProfile(
        "tls-fixed", JunkTemplateChunks.tlsFixed(), emptyList(),
        AwgParams(), JunkKind.TLS, "фиксированный TLS-like шаблон (1 вариант генератора)"
    )

    fun sip() = JunkProfile(
        "sip-invite", JunkTemplateChunks.sipI1(), JunkTemplateChunks.sipI2(),
        AwgParams(), JunkKind.SIP, "SIP INVITE / 100 Trying (3 вариант генератора)"
    )

    /** QUIC-маска под конкретный SNI; level 1..4 — насколько «обрезанный» ClientHello. */
    fun quic(sni: String, level: Int = 3, seed: Long? = null, awg: AwgParams = AwgParams()) = JunkProfile(
        name = "quic:$sni",
        i1 = QuicMask.buildTemplate(sni, level, seed),
        i2 = emptyList(),
        awg = awg,
        kind = JunkKind.QUIC,
        note = "QUIC Initial + ClientHello(SNI=$sni), уровень $level"
    )

    /** Простой HTTP-шаблон — иногда помогает, когда DPI режет «похожее на TLS» в нестандартном порту. */
    fun httpGet(host: String = "www.gstatic.com") = JunkProfile(
        "http-get",
        listOf(JunkChunk.Literal("GET /generate_204 HTTP/1.1\r\nHost: $host\r\nUser-Agent: Mozilla/5.0\r\n\r\n".toByteArray())),
        emptyList(), AwgParams(jc = 2, jmin = 20, jmax = 60), JunkKind.HTTP, "HTTP-подобный шум"
    )

    /**
     * Набор профилей для автоподбора: «нет шума» + фиксированный TLS + QUIC под несколько SNI из
     * белого списка + SIP. Порядок такой, чтобы дешёвые/типовые проверялись первыми.
     */
    fun defaultPool(sniCount: Int = 3, level: Int = 3, seed: Long = 7L): List<JunkProfile> {
        val snis = SNI_DOMAINS.take(sniCount.coerceAtLeast(1))
        return buildList {
            add(tlsFixed())
            for ((i, sni) in snis.withIndex()) add(quic(sni, level, seed + i))
            add(sip())
        }
    }
}
