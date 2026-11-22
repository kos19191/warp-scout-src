package dev.warpscout.core.model

/** Что-то, куда мы шлём пакеты: IPv4, IPv6 или домен. */
enum class AddrFamily { IPV4, IPV6, HOSTNAME }

data class Endpoint(
    val host: String,
    val port: Int,
    val family: AddrFamily = if (host.contains(':')) AddrFamily.IPV6 else AddrFamily.IPV4
) {
    init {
        require(port in 1..65535) { "порт вне диапазона: $port" }
        require(host.isNotBlank()) { "пустой хост" }
    }

    fun render(): String = if (family == AddrFamily.IPV6) "[$host]:$port" else "$host:$port"
    override fun toString(): String = render()
}

/** Вердикт одной проверки конечной точки. Порядок важен: чем выше — тем увереннее «работает». */
enum class Verdict {
    /** Получен и криптографически проверен handshake response → endpoint жив И наш ключ принят. */
    HANDSHAKE_OK,

    /** Получен cookie reply → сервер WireGuard жив (наш MAC1 признан валидным), под нагрузкой. */
    COOKIE_REPLY,

    /** TLS/HTTP3-рукопожатие прошло (актуально для MASQUE-портов 443/8443/…). */
    TLS_OK,

    /** UDP не ответил, но и ICMP unreachable не пришёл → вероятно работает, но не доказано. */
    UDP_SILENT,

    /** Пришёл ICMP port unreachable (ECONNREFUSED) → порт закрыт. */
    UDP_CLOSED,

    /** Домен не разрешился. */
    DNS_FAIL,

    /** Локальная ошибка сокета/права/таймаут на резолвере и т.п. */
    ERROR;

    /**
     * Сила вердикта: порядок объявления — от сильнейшего к слабейшему, поэтому
     * «лучший» = с НАИМЕНЬШИМ rank. Сравнения везде идут по нему.
     */
    val rank: Int get() = ordinal

    companion object {
        fun bestOf(a: Verdict, b: Verdict): Verdict = if (a.rank <= b.rank) a else b
    }
}

enum class NetworkVia { DEFAULT, UNDERLAY, TUNNEL }

/** Одна попытка пробы (один пакет → ожидание ответа). */
data class ProbeSample(
    val endpoint: Endpoint,
    val verdict: Verdict,
    val rttMs: Double? = null,
    val attempt: Int = 0,
    val profile: String = "none",
    val note: String = "",
    /**
     * После рукопожатия проверяли, идут ли данные: DNS-запрос внутри сессии (см.
     * [dev.warpscout.core.tunnel.DataProbe]). Рукопожатие само по себе ничего не обещает — в журнале
     * 22.11 точка отвечала на него за 200 мс, а данных через неё не шло ни байта.
     */
    val dataTried: Boolean = false,
    /** За сколько пришёл ответ на этот запрос, мс; null — не пришёл (или не проверяли). */
    val dataMs: Double? = null,
    /**
     * Данные пошли и встали: на первый запрос ответ пришёл, а на запросы через полторы секунды и
     * позже — нет. Так сеть режет «опознанный» туннель: пропускает рукопожатие и первые пакеты, а
     * дальше молчит (журнал 22.11 19:04–19:10: «данные идут: ответ за 82 мс», а приложениям за 8 с
     * не пришло ни байта и проверка связи провалилась на каждой точке без шума).
     */
    val dataFrozen: Boolean = false,
    /** Данные идут и через полторы секунды после начала: поздние запросы тоже получили ответ. */
    val dataSustained: Boolean = false
)

/** Агрегированная статистика по конечной точке. */
data class EndpointStats(
    val endpoint: Endpoint,
    val samples: List<ProbeSample>,
    val bestVerdict: Verdict,
    val replies: Int,
    val attempts: Int
) {
    val rtts: List<Double> get() = samples.mapNotNull { it.rttMs }.sorted()
    val lossPct: Double get() = if (attempts == 0) 100.0 else 100.0 * (attempts - replies) / attempts
    val medianRtt: Double? get() = rtts.getOrNull(rtts.size / 2)
    val meanRtt: Double? get() = rtts.takeIf { it.isNotEmpty() }?.average()
    val minRtt: Double? get() = rtts.firstOrNull()

    /** Сколько раз после рукопожатия проверяли данные (0 — не проверяли вовсе). */
    val dataTried: Int get() = samples.count { it.dataTried }

    /** Сколько раз ответ через туннель пришёл. */
    val dataReplies: Int get() = samples.count { it.dataMs != null }

    /** Лучшее время ответа через туннель, мс (null — ответа не было или не проверяли). */
    val dataMs: Double? get() = samples.mapNotNull { it.dataMs }.minOrNull()

    /**
     * Данные встали через секунду-другую (см. [ProbeSample.dataFrozen]) и ни одна долгая проверка
     * этой точки с этим шумом не показала обратного.
     */
    val dataFrozen: Boolean get() = samples.any { it.dataFrozen } && samples.none { it.dataSustained }

    /** Долгая проверка показала: данные идут и через полторы секунды после начала. */
    val dataSustained: Boolean get() = samples.any { it.dataSustained }

    /**
     * Рукопожатие было, а данные не пошли: ровно «вверх есть, вниз 0». С 1.10.30 сюда же — «пошли и
     * встали»: для человека это тот же нерабочий туннель, только обман длится на секунду дольше.
     */
    val dataBlocked: Boolean get() = dataTried > 0 && (dataReplies == 0 || dataFrozen)

    /** Джиттер = среднее отклонение от медианы (в мс). */
    val jitterMs: Double?
        get() {
            val m = medianRtt ?: return null
            if (rtts.size < 3) return null   // по 1-2 замерам джиттер не оцениваем
            return rtts.sumOf { kotlin.math.abs(it - m) } / rtts.size
        }
}

/** Мусорный пакет AWG: либо фиксированные байты, либо случайные. Ровно то, что пишется в I1/I2. */
sealed class JunkChunk {
    abstract val size: Int
    data class Literal(val bytes: ByteArray) : JunkChunk() {
        override val size: Int get() = bytes.size
        override fun equals(other: Any?) = other is Literal && bytes.contentEquals(other.bytes)
        override fun hashCode() = bytes.contentHashCode()
    }

    data class RandomBytes(override val size: Int) : JunkChunk()

    /** В виде, который понимает AmneziaWG: `<b 0x…>` / `<r N>`. */
    fun render(): String = when (this) {
        is Literal -> "<b 0x${dev.warpscout.core.crypto.Crypto.hex(bytes)}>"
        is RandomBytes -> "<r $size>"
    }

    fun materialize(random: java.security.SecureRandom): ByteArray = when (this) {
        is Literal -> bytes
        is RandomBytes -> ByteArray(size).also { random.nextBytes(it) }
    }

    companion object {
        fun renderAll(chunks: List<JunkChunk>): String = chunks.joinToString("") { it.render() }
    }
}

/** Параметры AWG (AmneziaWG). По умолчанию — ровно то, что отдаёт warp-generation.github.io. */
data class AwgParams(
    val jc: Int = 4,
    val jmin: Int = 40,
    val jmax: Int = 70,
    val h1: Int = 1,
    val h2: Int = 2,
    val h3: Int = 3,
    val h4: Int = 4,
    val s1: Int = 0,
    val s2: Int = 0,
    val s3: Int = 0,
    val s4: Int = 0,
    /** AWG 3.0/3.1: ContentPaddingAddition, RekeyAfterTime, RandomTrailers, DisableCookies и т.п. */
    val extra: List<Pair<String, String>> = emptyList()
) {
    fun renderInterfaceLines(): List<String> = buildList {
        add("S1 = $s1"); add("S2 = $s2"); add("S3 = $s3"); add("S4 = $s4")
        add("Jc = $jc"); add("Jmin = $jmin"); add("Jmax = $jmax")
        add("H1 = $h1"); add("H2 = $h2"); add("H3 = $h3"); add("H4 = $h4")
        for ((k, v) in extra) add("$k = $v")
    }
}

/** Профиль «шума»: какие шаблоны мусорных пакетов и с какими параметрами AWG использовать. */
data class JunkProfile(
    val name: String,
    val i1: List<JunkChunk>,
    val i2: List<JunkChunk> = emptyList(),
    val awg: AwgParams = AwgParams(),
    val kind: JunkKind = JunkKind.TLS,
    val note: String = ""
) {
    val isEmpty: Boolean get() = i1.isEmpty() && i2.isEmpty()
}

enum class JunkKind { NONE, TLS, QUIC, SIP, HTTP, CUSTOM }

/** Ключи аккаунта WARP: то, что выдаёт генератор (или то, что у вас уже есть). */
data class WarpAccount(
    val privateB64: String,
    val peerPublicB64: String,
    val ipv4: String = "172.16.0.2",
    val ipv6: String? = null,
    val source: String = "manual"
)

/** Готовая конфигурация, которую можно положить в Amnezia. */
data class WarpConfig(
    val name: String,
    val account: WarpAccount,
    val endpoint: Endpoint,
    val junk: JunkProfile,
    val allowedIps: String = "0.0.0.0/0, ::/0",
    val dns: List<String> = listOf("1.1.1.1", "1.0.0.1", "2606:4700:4700::1111", "2606:4700:4700::1001"),
    val mtu: Int = 1280,
    val persistentKeepalive: Int? = null,
    val enableIpv6Address: Boolean = true,
    val comments: List<String> = emptyList()
)

data class ResourceCheck(
    val name: String,
    val url: String,
    val expectStatus: IntRange = 200..399,
    val method: String = "GET",
    val mustContain: String? = null,
    val timeoutMs: Int = 8000,
    /** true — ресурс должен работать без VPN (контрольная точка: если падает и она, проблема не в блокировке). */
    val baselineExpected: Boolean = false
)

data class ResourceResult(
    val check: ResourceCheck,
    val ok: Boolean,
    val status: Int? = null,
    val elapsedMs: Long = 0,
    val errorClass: String? = null,
    val via: NetworkVia = NetworkVia.DEFAULT,
    val bytes: Int = 0
)

/** Оценка кандидата: из чего сложился балл — отчёт должен быть объяснимым. */
data class ScoreParts(
    val confirmed: Int = 0,
    val latency: Int = 0,
    val stability: Int = 0,
    val jitter: Int = 0,
    val junkSurvival: Int = 0,
    val resourceBonus: Int = 0,
    val penalty: Int = 0,
    /**
     * Данные после рукопожатия: плюс, если ответ через туннель пришёл, большой минус, если нет
     * (см. [dev.warpscout.core.tune.Weights.dataBlocked]), ноль — не проверяли.
     */
    val dataPath: Int = 0,
    /**
     * Маскировка: минус варианту без шума (чистый WireGuard), плюс — данным, которые идут и после
     * первых секунд. С 1.10.30: «без шума» выигрывал подбор за подбором на одном пинге, а на сети
     * человека он замерзает через секунду — работала только маскировка (журнал 22.11).
     */
    val masking: Int = 0
) {
    val total: Int get() = confirmed + latency + stability + jitter + junkSurvival + resourceBonus - penalty + dataPath + masking
    fun asMap(): Map<String, Int> = linkedMapOf(
        "confirmed" to confirmed,
        "latency" to latency,
        "stability" to stability,
        "jitter" to jitter,
        "junk_survival" to junkSurvival,
        "resource_bonus" to resourceBonus,
        "penalty" to -penalty,
        "data_path" to dataPath,
        "masking" to masking
    )
}

data class Candidate(
    val config: WarpConfig,
    val stats: EndpointStats,
    val parts: ScoreParts,
    val junkProbes: List<ProbeSample> = emptyList(),
    /**
     * Сколько целевых ресурсов реально открылось из-под ЭТОГО туннеля.
     * -1 — изнутри не проверяли (сборка без туннеля или не попал в топ проверяемых).
     */
    val resourcesOk: Int = -1,
    /** Сколько ресурсов проверяли (0 — не проверяли). */
    val resourcesTotal: Int = 0,
    /**
     * Скорость загрузки через туннель этого кандидата, Кбит/с (-1 — не мерили). Из двух точек,
     * открывших одинаково много сайтов, лучше та, через которую быстрее качается: «открылось» не
     * отличает 50 Мбит/с от 300 Кбит/с.
     */
    val speedKbps: Int = -1
) {
    val score: Int get() = parts.total
    val junk: dev.warpscout.core.model.JunkProfile get() = config.junk

    /**
     * Годится в очередь: сервер ответил, и данные через него пошли (или их не проверяли — старые
     * отчёты), либо изнутри туннеля открылся хоть один сайт. «Рукопожатие есть, данных нет» и
     * молчащие точки — нет: подключение к ним кончается «вверх есть, вниз 0».
     */
    val usable: Boolean get() = resourcesOk > 0 || (stats.replies > 0 && !stats.dataBlocked)
}

data class TuningReport(
    val startedAt: String,
    val finishedAt: String,
    val profileName: String,
    val candidates: List<Candidate>,
    val resources: List<ResourceResult>,
    val endpointsTested: Int,
    val notes: List<String> = emptyList(),
    /**
     * Профили шума, на которых данные пошли и встали (по одной записи на каждую такую точку). По
     * ним приложение запоминает, что на этой сети такой шум не годится (см. NoiseMemory).
     */
    val frozenProfiles: List<String> = emptyList()
) {
    /**
     * Лучший из годных (см. [Candidate.usable]). Раньше — просто максимум балла, и при «живых 0»
     * лучшим становилась молчащая точка с 60 баллами: её конфиг записывался как подобранный.
     */
    val best: Candidate? get() = candidates.filter { it.usable }.maxByOrNull { it.score }
}
