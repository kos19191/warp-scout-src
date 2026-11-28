package dev.warpscout.core.junk

import dev.warpscout.core.crypto.Crypto
import dev.warpscout.core.model.AwgParams
import dev.warpscout.core.model.JunkChunk
import dev.warpscout.core.model.JunkKind
import dev.warpscout.core.model.JunkProfile
import dev.warpscout.core.junk.SniSettings

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

    /**
     * Имя сайта в пакете «как Chrome» (с 1.10.40): то же, что в конфиге, который на сети человека «прям
     * хорошо работает со всеми ресурсами» (23.11), — российский сайт, который фильтры пропускают.
     */
    const val CHROME_SNI = "apteka.ru"

    /** Зерно пакета «как Chrome»: те же байты на всех телефонах и во всех версиях с этим генератором. */
    private const val CHROME_SEED = 1_250L

    private val chromeCache = java.util.concurrent.ConcurrentHashMap<String, JunkProfile>()

    /**
     * Пакет «как Chrome» (с 1.10.40, см. [ChromeQuic]): первый пакет QUIC к [sni] целиком, 1250 байт, одним
     * литералом — так он и уходит перед каждой инициацией (шлётся первый кусок шаблона). Собирается один
     * раз: [defaultPool] и [nameOf] зовут часто, а шифровать 1250 байт каждый раз незачем.
     */
    fun chrome(sni: String = CHROME_SNI): JunkProfile = chromeCache.getOrPut(sni) {
        JunkProfile(
            name = "chrome:$sni",
            i1 = listOf(JunkChunk.Literal(ChromeQuic.packet(sni, CHROME_SEED + sni.hashCode()))),
            i2 = emptyList(),
            awg = AwgParams(),
            kind = JunkKind.QUIC,
            note = "как Chrome: первый пакет QUIC к $sni, ${ChromeQuic.SIZE} байт"
        )
    }

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
     * Набор профилей для автоподбора: «нет шума» + фиксированный TLS + «как Chrome» + QUIC под несколько
     * SNI из белого списка + SIP. Порядок такой, чтобы дешёвые/типовые проверялись первыми.
     */
    fun defaultPool(sniCount: Int = 3, level: Int = 3, seed: Long = 7L): List<JunkProfile> {
        return defaultPoolRemote(SniSettings.Default, sniCount, level, seed)
    }

    /** Версия defaultPool с SNI из удалённого источника (SniSource). При ошибке сети — fallback на локальный список. */
    fun defaultPoolRemote(settings: SniSettings = SniSettings.Default, sniCount: Int = 3, level: Int = 3, seed: Long = 7L): List<JunkProfile> {
        // defaultPool() должен быть детерминированным: nameOf() сравнивает шаблоны профиля с библиотечными,
        // и если набор quic-профилей плавает (rotate/shuffle), сопоставление ломается. Рандомная ротация
        // нужна только в sniPool() для AutoTuner — здесь берём домены в фиксированном порядке.
        val cfg = SniSource.load(settings)
        val snis = cfg.domains.sorted().take(sniCount.coerceAtLeast(1).coerceAtMost(cfg.domains.size))
        return buildList {
            // «Без шума» — такой же участник сравнения, как остальные: на части сетей DPI не трогает
            // WireGuard вообще, и тогда любая маскировка только мешает. Раньше этот вариант
            // проверялся лишь для лучшей точки одной запасной конфигурацией.
            add(this@JunkLibrary.none())
            add(tlsFixed())
            // «Как Chrome» (с 1.10.40): настоящий первый пакет QUIC, а не обрезок, — подбор сравнивает
            // его с остальными на каждой из лучших точек.
            add(chrome())
            for ((i, sni) in snis.withIndex()) add(quic(sni, level, seed + i))
            add(sip())
        }
    }

    /**
     * Порядок, в котором сервис пробует шум, когда рукопожатие проходит, а данные — нет (с 1.10.30).
     * С 1.10.40 первым — «как Chrome»: с таким пакетом конфиг человека на его сети «прям хорошо работает
     * со всеми ресурсами» (23.11). Вторым — фиксированный TLS: он держал туннель 12 часов подряд (журнал
     * 22.11, 01:21–13:06), когда чистый WireGuard не поднимался ни разу. «Без шума» — последним. Шум, с
     * которым на этой сети уже шли данные, сервис берёт раньше этого порядка (см. NoiseMemory).
     */
    fun serviceOrder(): List<JunkProfile> {
        val pool = defaultPool()
        val quic = pool.filter { it.kind == JunkKind.QUIC && it.name.startsWith("quic:") }
        return buildList {
            add(chrome())
            add(tlsFixed())
            quic.firstOrNull()?.let { add(it) }
            add(sip())
            addAll(quic.drop(1))
            add(this@JunkLibrary.none())
        }.distinctBy { it.name }
    }

    /**
     * Профиль библиотеки по имени («tls-fixed», «quic:akbars.ru», «none»…) — тот же, что даёт
     * [defaultPool] (те же шаблоны и зерно), чтобы шум из памяти совпадал с проверенным подбором.
     */
    fun byName(name: String): JunkProfile? {
        val n = name.trim()
        if (n.isEmpty()) return null
        if (n == "none") return none()
        defaultPool().firstOrNull { it.name == n }?.let { return it }
        // «Как Chrome» к другому сайту — тем же генератором (имя сайта — после «chrome:»). Только латиница,
        // цифры, точка и дефис: в ClientHello имя идёт ASCII, кириллица превратилась бы в «?».
        if (n.startsWith("chrome:")) {
            val sni = n.removePrefix("chrome:")
            if (sni.isNotEmpty() && sni.length < 200 &&
                sni.all { it in 'a'..'z' || it in 'A'..'Z' || it in '0'..'9' || it == '.' || it == '-' }
            ) {
                return runCatching { chrome(sni) }.getOrNull()
            }
        }
        // Остальные SNI из списка: зерно — как в defaultPool при большем числе доменов.
        return defaultPool(sniCount = SNI_DOMAINS.size).firstOrNull { it.name == n }
            ?: listOf(tlsFixed(), sip(), httpGet()).firstOrNull { it.name == n }
    }

    /**
     * Имя шума по самим пакетам. Профиль, разобранный из текста конфига, называется «imported» —
     * имя в .conf не пишется. По имени же сервис и память сетей решают, какой шум уже пробовали и
     * какой здесь замерзает, поэтому сравниваем шаблоны: совпал с библиотечным — его имя.
     */
    fun nameOf(profile: JunkProfile): String {
        if (profile.isEmpty) return "none"
        val key = JunkChunk.renderAll(profile.i1 + profile.i2)
        val known = defaultPool() + listOf(httpGet())
        return known.firstOrNull { !it.isEmpty && JunkChunk.renderAll(it.i1 + it.i2) == key }?.name ?: profile.name
    }
}
