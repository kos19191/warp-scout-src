package dev.warpscout.core.tune

import dev.warpscout.core.crypto.Crypto
import dev.warpscout.core.junk.JunkLibrary
import dev.warpscout.core.model.JunkProfile
import dev.warpscout.core.keys.KeySource
import dev.warpscout.core.model.Candidate
import dev.warpscout.core.model.Endpoint
import dev.warpscout.core.model.EndpointStats
import dev.warpscout.core.model.ProbeSample
import dev.warpscout.core.model.ResourceCheck
import dev.warpscout.core.model.ResourceResult
import dev.warpscout.core.model.TuningReport
import dev.warpscout.core.model.Verdict
import dev.warpscout.core.model.WarpConfig
import dev.warpscout.core.net.EndpointPool
import dev.warpscout.core.net.EndpointSpec
import dev.warpscout.core.net.NetSettings
import dev.warpscout.core.net.PoolMode
import dev.warpscout.core.net.ResourceProber
import dev.warpscout.core.net.TlsProber
import dev.warpscout.core.net.WgProber
import dev.warpscout.core.presets.Presets
import dev.warpscout.core.config.WgConf
import java.time.LocalDateTime
import java.time.format.DateTimeFormatter

/** Куда приложение пишет «что происходит». В Android это живой лог на экране, в CLI — stdout. */
interface ProgressSink {
    fun log(message: String)
    fun progress(done: Int, total: Int, current: String) {}
    fun isCancelled(): Boolean = false

    companion object {
        val NOOP = object : ProgressSink {
            override fun log(message: String) {}
        }
        val STDOUT = object : ProgressSink {
            override fun log(message: String) = println(message)
            override fun progress(done: Int, total: Int, current: String) {
                println("[$done/$total] $current")
            }
        }
    }
}

/**
 * Реализация «подключиться и проверить изнутри туннеля». Есть только в сборке с туннелем
 * (VpnService + amneziawg-go); в «scout»-сборке равна null и проверка ресурсов идёт по обычному пути.
 */
interface TunnelVerifier {
    val title: String
    /** Поднять туннель по конфигу, дождаться handshake, прогнать проверки, вернуть результаты, остановить. */
    fun verify(config: WarpConfig, checks: List<ResourceCheck>, settleMs: Int): List<ResourceResult>

    /**
     * То же, но с отменой: одна проверка изнутри — это подъём туннеля и до десятка запросов, то есть
     * десятки секунд. Без отмены «Остановить подбор» ждало их до конца. Реализация, которая умеет
     * прерываться, переопределяет этот вариант; остальные работают как раньше.
     */
    fun verify(
        config: WarpConfig,
        checks: List<ResourceCheck>,
        settleMs: Int,
        isCancelled: () -> Boolean
    ): List<ResourceResult> = verify(config, checks, settleMs)

    /**
     * Скорость загрузки через туннель, измеренная последним [verify], Кбит/с (-1 — не мерили).
     * Отдельным методом, а не полем результата: проверки ресурсов — это список «открылось или
     * нет», а скорость — одно число на кандидата. Реализации без замера ничего не меняют.
     */
    fun lastSpeedKbps(): Int = -1

    fun stop() {}
}

data class TuningSpec(
    val endpointSpec: EndpointSpec = EndpointSpec(),
    val junkProfiles: List<JunkProfile> = JunkLibrary.defaultPool(),
    val net: NetSettings = NetSettings(attempts = 3, timeoutMs = 1200, concurrency = 64),
    val resources: List<ResourceCheck> = Presets.RESOURCE_CHECKS,
    val dns: List<String> = Presets.DNS.first().servers,
    val mtu: Int = 1280,
    val allowedIps: String = "0.0.0.0/0, ::/0",
    val keepalive: Int? = 25,
    val enableIpv6Address: Boolean = true,
    /** Сколько точек проверять подробно (с профилями шума и лишними попытками). */
    val refineTop: Int = 10,
    val checkBaselineResources: Boolean = true,
    val verifyThroughTunnel: Boolean = true,
    val tunnelSettleMs: Int = 6000,
    val namePrefix: String = "WARP-Auto",
    /**
     * Прошлая удачная конфигурация (сеть та же, свежая). Если задана, подбор сначала проверяет
     * только её и прежнюю очередь: несколько точек вместо пула — секунды вместо минут.
     */
    val cachedStart: CachedStart? = null,
    /**
     * После рукопожатия проверять, идут ли данные (DNS-запрос внутри сессии, см.
     * [dev.warpscout.core.tunnel.DataProbe]). Без этого «живой» значило «ответил на рукопожатие», и в
     * очередь попадали точки, через которые не идёт ни байта (журнал 22.11: «вверх 5542, вниз 0»).
     */
    val dataProbe: Boolean = true,
    /**
     * Точки, которые подробно проверяются в любом случае, если ответили в первом проходе: прежняя
     * очередь. Иначе полный подбор после неудачного быстрого старта мог потерять рабочую точку,
     * которой просто не оказалось в пуле.
     */
    val priority: List<Endpoint> = emptyList(),
    /**
     * Профили шума, которые на этой сети замерзают (данные идут секунду и встают): их подбор не
     * проверяет вовсе. Список ведёт приложение по прошлым подборам и подключениям (NoiseMemory).
     */
    val excludeJunk: Set<String> = emptySet(),
    /**
     * Сколько лучших точек проверить долгой пробой данных (см. [WgProber.probeSustained]): идут
     * ли данные и через полторы секунды. 0 — не проверять.
     */
    val sustainTop: Int = 4,
    /** Длина долгой пробы, мс. */
    val sustainMs: Int = WgProber.SUSTAIN_DEFAULT_MS,
    /**
     * Искать выход за рубежом (с 1.10.34): на этой сети последний выход был в России, а поиска не
     * было больше суток. Быстрый старт тогда не принимается, если сохранённые точки выходят через
     * Россию, — иначе подбор раз за разом подтверждал бы московские точки и не смотрел остальные.
     */
    val seekAbroad: Boolean = false
)

/**
 * Сохранённая удачная точка и прежняя очередь этой сети: их проверяют первыми, но по тем же
 * правилам, что и свежие.
 */
data class CachedStart(
    val endpoint: Endpoint,
    val junkName: String = "",
    /** Остальные точки прежней очереди этой сети (без [endpoint]). */
    val queue: List<Endpoint> = emptyList(),
    /** Профили шума точек очереди — имена из [JunkLibrary]. */
    val queueJunk: List<String> = emptyList()
)

/**
 * Сколько годных точек должен найти быстрый старт, чтобы обойтись без полного подбора: лучшая и
 * хотя бы одна запасная. Одна точка без запасных не стоит экономии на скане — раньше быстрый
 * старт подтверждал одну сохранённую точку и затирал ею всю тройку (журнал 22.11 16:35).
 */
private const val QUICK_MIN_POINTS = 2

class TuningResult(
    val report: TuningReport,
    val best: WarpConfig?,
    val configText: String?,
    val accountSource: String
)

/**
 * Основной конвейер:
 *
 *   1. берём ключи (генератор → кеш → ручной);
 *   2. строим пул endpoint'ов (подсети × порты, детерминированно по seed);
 *   3. быстрый UDP-скан handshake-инициацией — отсекаем мёртвые и чёрные дыры;
 *   4. топ-N проверяем подробно: сколько попыток, какой RTT/джиттер, и главное —
 *      проходит ли handshake с мусором каждого профиля (это и есть «доступность относительно конфигурации»);
 *   5. MASQUE-подмножество проверяем TLS'ом (там ответ настоящий, не гадание);
 *   6. считаем баллы, собираем конфигурации, прогоняем проверки ресурсов (при наличии туннеля — изнутри);
 *   7. отдаём отчёт + лучший конфиг.
 */
class AutoTuner(
    private val keySource: KeySource,
    private val wgProber: WgProber,
    private val tlsProber: TlsProber = TlsProber(NetSettings()),
    private val resources: ResourceProber = ResourceProber(),
    private val tunnel: TunnelVerifier? = null,
    private val weights: Weights = Weights()
) {

    private val tsFmt = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")

    fun run(spec: TuningSpec = TuningSpec(), progress: ProgressSink = ProgressSink.NOOP): TuningResult {
        val started = LocalDateTime.now()
        val notes = mutableListOf<String>()

        val account = try {
            keySource.account()
        } catch (e: Exception) {
            notes += "Ключи не получены (${e.message?.take(140)}); беру запасной аккаунт из примеров генератора."
            dev.warpscout.core.model.WarpAccount(
                privateB64 = "",
                peerPublicB64 = dev.warpscout.core.net.WarpDefaults.WARP_PEER_PUBLIC,
                source = "none"
            )
        }

        if (account.privateB64.isBlank() || !KeySource.looksLikeCurve25519(account.privateB64)) {
            notes += "Приватного ключа нет/он не Curve25519 — точный handshake недоступен, переключаемся на эвристики UDP/TLS."
            return runHeuristicOnly(spec, progress, started, notes, account)
        }
        val peerPublic = Crypto.unBase64(account.peerPublicB64)

        // Сохранённую конфигурацию пробуем первой: проверить одну точку — секунды, полный
        // скан пула — минуты и заметный расход батареи. Не подтвердилась — честно идём в полный подбор.
        val cached = spec.cachedStart
        if (cached != null) {
            speculativeStart(spec, cached, progress)?.let { narrow ->
                // Заметки быстрой попытки — отдельная копия: если она провалится, полный подбор не
                // должен рассказывать пользователю про точки, которые он даже не проверял.
                val quickNotes = notes.toMutableList()
                quickNotes += "Быстрый старт: сохранённые точки проверены заново, полный скан не понадобился."
                val quick = tuneWith(narrow, progress, started, quickNotes, account, peerPublic)
                val usable = quick.report.candidates.filter { it.usable }
                    .map { it.config.endpoint.render() }
                    .distinct()
                val confirmed = quick.best != null && cachedConfirmed(quick, cached)
                // Выход лучшей из сохранённых — в России, а искать заграницу пора (см. seekAbroad):
                // быстрый старт не принимаем, смотрим весь пул.
                val quickSite = quick.report.candidates.firstOrNull { it.config.endpoint == quick.best?.endpoint }?.site
                val wantAbroad = spec.seekAbroad && dev.warpscout.core.net.ExitSite.isRussian(quickSite)
                if (confirmed && usable.size >= QUICK_MIN_POINTS && !wantAbroad) return quick
                // Остановили во время быстрого старта — полный подбор не начинаем. Раньше он
                // начинался именно здесь: быстрая проверка «не подтвердилась» (её прервали), и
                // «Остановить подбор» запускало полный скан пула вместо остановки.
                if (progress.isCancelled()) return quick
                progress.log(
                    when {
                        confirmed && wantAbroad ->
                            "сохранённые точки работают, но выходят через ${dev.warpscout.core.net.ExitSite.describe(quickSite)} — " +
                                "ищу выход за рубежом полным подбором"
                        confirmed -> "сохранённая точка работает, но рабочих точек ${usable.size} — мало для очереди, полный подбор"
                        else -> "сохранённая конфигурация не подтвердилась — полный подбор"
                    }
                )
                // Прежние точки полный подбор проверит подробно первыми (если они ответят).
                val prior = (listOf(cached.endpoint) + cached.queue).distinct()
                return tuneWith(spec.copy(priority = spec.priority + prior), progress, started, notes, account, peerPublic)
            }
        }

        return tuneWith(spec, progress, started, notes, account, peerPublic)
    }

    /**
     * Пул, суженный до сохранённой точки и её профиля шума. Всё остальное (проверки ресурсов,
     * изнутри туннеля тоже) остаётся общим с полным подбором: сохранённая конфигурация
     * принимается по тем же правилам, что и свежая, иначе кеш мог бы протащить нерабочее.
     */
    private fun speculativeStart(spec: TuningSpec, cached: CachedStart, progress: ProgressSink): TuningSpec? {
        val ep = cached.endpoint
        // IPv6 в разборе списка пока не поддержан — быстрый старт не для него, полный подбор работает.
        if (ep.host.isBlank() || ep.port !in 1..65535 || ep.host.contains(':')) return null
        // Вся прежняя очередь этой сети, а не одна точка: проверить три точки — те же секунды, а
        // итогом быстрого старта становится тройка, а не одна строка без запасных.
        val points = (listOf(ep) + cached.queue)
            .filter { it.host.isNotBlank() && !it.host.contains(':') && it.port in 1..65535 }
            .distinctBy { it.render() }
            .take(Shortlist.LIMIT + 1)
        val names = (listOf(cached.junkName) + cached.queueJunk).filter { it.isNotBlank() }.toSet()
        // Замерзающий на этой сети шум не проверяем и в быстром старте: иначе он снова «подтвердился»
        // бы одним ответом и затёр очередь (журнал 22.11: быстрый старт брал точки с шумом none).
        val allowed = spec.junkProfiles.filter { it.name !in spec.excludeJunk }.ifEmpty { spec.junkProfiles }
        val saved = allowed.filter { it.name in names }
        // Сохранённая очередь целиком «без шума» (так её оставил 1.10.29) — рядом всегда проверяем и
        // TLS-маску: только сравнение двух вариантов на тех же точках показывает, что чистый
        // WireGuard здесь замерзает, а с маской данные идут. Без пары долгая проверка увидела бы
        // «встало у всех» и не доверилась бы себе, и быстрый старт снова подтвердил бы «none».
        val masked = allowed.firstOrNull { it.name == JunkLibrary.tlsFixed().name }
            ?: allowed.firstOrNull { !it.isEmpty }
        val profiles = when {
            saved.isNotEmpty() && saved.all { it.isEmpty } && masked != null -> saved + masked
            // Сохранённый шум весь замерзает на этой сети — те же точки проверяем с маской, а не
            // со всем пулом шума: быстрый старт должен остаться быстрым.
            saved.isEmpty() && names.isNotEmpty() && masked != null -> listOf(masked)
            else -> saved
        }
        progress.log(
            "быстрый старт: проверяю сохранённые точки — " + points.joinToString { it.render() } +
                (if (profiles.isNotEmpty()) " · шум " + profiles.joinToString { it.name } else "")
        )
        return spec.copy(
            endpointSpec = EndpointSpec(
                mode = PoolMode.EXPLICIT,
                subnets = emptyList(),
                hostnames = points.map { "${it.host}:${it.port}" },
                maxEndpoints = points.size
            ),
            junkProfiles = profiles.ifEmpty { allowed },
            refineTop = points.size,
            priority = emptyList(),
            // Быстрый старт должен остаться быстрым: долгой пробой — две лучшие точки (плюс лучшие
            // варианты с шумом и без), а не четыре.
            sustainTop = spec.sustainTop.coerceAtMost(2)
        )
    }

    /**
     * Подтвердилась ли сохранённая точка (см. [CachedPoint]): хотя бы с одним профилем шума ответила
     * на рукопожатие и — если проверяли — пропустила данные.
     */
    private fun cachedConfirmed(result: TuningResult, cached: CachedStart): Boolean =
        result.report.candidates
            .filter { it.config.endpoint == cached.endpoint }
            // Годный — значит и не «данные пошли и встали» (с 1.10.30 это видно долгой пробой).
            .any { cand ->
                cand.usable && CachedPoint.confirmed(
                    cand.stats.replies, cand.resourcesTotal, cand.resourcesOk,
                    cand.stats.dataTried, cand.stats.dataReplies
                )
            }

    /**
     * Сам подбор: пул endpoint'ов → скан → подробные пробы по профилям шума → проверки ресурсов.
     *
     * Отдельным методом — чтобы «быстрый старт» гонял тот же конвейер, а не его упрощённую
     * копию: две реализации одной проверки неизбежно расходятся.
     */
    private fun tuneWith(
        spec: TuningSpec,
        progress: ProgressSink,
        started: LocalDateTime,
        notes: MutableList<String>,
        account: dev.warpscout.core.model.WarpAccount,
        peerPublic: ByteArray
    ): TuningResult {
    val peerPublic = Crypto.unBase64(account.peerPublicB64)
    // Прежняя очередь — в пул первой: её точек может не быть в выборке пула.
    val endpoints = (spec.priority.filter { !it.host.contains(':') } + EndpointPool.build(spec.endpointSpec)).distinct()
    progress.log("Ключи: ${account.source}; кандидатов: ${endpoints.size}")

    // --- фаза 1: быстрый скан -------------------------------------------------------
    val coarse = wgProber.scan(endpoints, account, peerPublic, junk = null, isCancelled = { progress.isCancelled() }) { d, t, _ ->
        if (d % 25 == 0 || d == t) progress.progress(d, t, "первичный UDP-скан")
    }
    if (progress.isCancelled()) return finish(spec, started, notes, emptyList(), emptyList(), account, progress, endpoints.size)

    // rank у вердикта растёт по мере «ухудшения», поэтому лучший — с минимальным rank
    val ranked = coarse.sortedWith(
        compareBy<EndpointStats> { it.bestVerdict.rank }
            .thenBy { it.minRtt ?: Double.MAX_VALUE }
            .thenBy { it.lossPct }
    )
    val alive = ranked.filter { it.bestVerdict in setOf(Verdict.HANDSHAKE_OK, Verdict.COOKIE_REPLY) }
    notes += "Живых (подтверждённый handshake/cookie): ${alive.size} из ${ranked.size}"

    // Ответившие точки прежней очереди проверяются подробно в любом случае — первыми.
    val prior = spec.priority.mapTo(HashSet()) { it.render() }
    val pool = if (alive.size >= 2) alive else ranked
    val refineLimit = maxOf(3, spec.refineTop)
    // С 1.10.34 половина мест — лучшему адресу каждой подсети: площадка выхода зависит от подсети
    // (журнал 22.11 на Wi-Fi: 162.159.192.x — HEL, 188.114.97.1 — FRA), а десять самых быстрых
    // адресов часто оказывались из двух-трёх подсетей с одним и тем же выходом через Москву.
    val bySubnet = pool.distinctBy { subnetOf(it.endpoint) }.take(refineLimit / 2)
    val refineCandidates = (alive.filter { it.endpoint.render() in prior } + bySubnet + pool)
        .distinctBy { it.endpoint.render() }
        .take(refineLimit)

    // --- фаза 2: подробно, по профилям шума ---------------------------------------
    // Шум, который на этой сети замерзает (знает приложение по прошлым подборам и подключениям),
    // не проверяем: одна проба данных его не разоблачает, а место в очереди он займёт.
    val activeProfiles = spec.junkProfiles.filter { it.name !in spec.excludeJunk }.ifEmpty { spec.junkProfiles }
    val skipped = spec.junkProfiles.filter { it.name in spec.excludeJunk }.map { it.name }
    if (skipped.isNotEmpty() && activeProfiles.size < spec.junkProfiles.size) {
        val line = "На этой сети замерзает шум: ${skipped.joinToString(", ")} — не проверяю его"
        notes += line
        progress.log(line)
    }
    val perProfile = LinkedHashMap<Endpoint, MutableMap<String, EndpointStats>>()
    val totalWork = refineCandidates.size * activeProfiles.size
    var done = 0
    // Площадка выхода — одна на адрес (зависит от адреса и сети, а не от шума): спрашиваем, пока не
    // узнали, и не больше трёх раз на адрес — если резолвер её не называет, проба не тратит время.
    val siteByHost = HashMap<String, String>()
    val siteTries = HashMap<String, Int>()
    for (stats in refineCandidates) {
        for (profile in activeProfiles) {
            if (progress.isCancelled()) break
            val host = stats.endpoint.host
            val ask = spec.dataProbe && host !in siteByHost && (siteTries[host] ?: 0) < 3
            val refined = wgProber.probe(
                stats.endpoint, account, peerPublic, profile, dataProbe = spec.dataProbe, askSite = ask
            ).stats
            if (ask && refined.dataReplies > 0) siteTries[host] = (siteTries[host] ?: 0) + 1
            refined.site?.let { siteByHost[host] = it }
            perProfile.getOrPut(stats.endpoint) { LinkedHashMap() }[profile.name] = refined
            done++
            val dataMark = when {
                refined.dataTried == 0 -> ""
                refined.dataReplies > 0 -> " · данные ✓"
                else -> " · данных нет"
            }
            progress.progress(done, totalWork, "${stats.endpoint.render()} · ${profile.name} · ${refined.bestVerdict}$dataMark")
        }
    }
    if (spec.dataProbe) {
        // Итог проверки данных — в журнал подбора: по нему видно, режет ли сеть сам туннель.
        val tried = perProfile.values.flatMap { it.values }.filter { it.dataTried > 0 }
        if (tried.isNotEmpty()) {
            val passed = tried.count { it.dataReplies > 0 }
            val line = "Данные через туннель: пошли у $passed из ${tried.size} вариантов «точка + шум»" +
                (if (passed == 0) " — рукопожатие проходит, а данные нет: сеть режет сам туннель" else "")
            notes += line
            progress.log(line)
        }
    }
    if (siteByHost.isNotEmpty()) {
        // Где выходят точки: по этой строке видно, есть ли на этой сети выход не через Россию.
        val counts = siteByHost.values.groupingBy { it }.eachCount().entries
            .sortedWith(compareByDescending<Map.Entry<String, Int>> { dev.warpscout.core.net.ExitSite.rank(it.key) }.thenByDescending { it.value })
        val allRussian = siteByHost.values.all { dev.warpscout.core.net.ExitSite.isRussian(it) }
        val line = "Выход WARP по точкам: " + counts.joinToString(", ") {
            "${dev.warpscout.core.net.ExitSite.describe(it.key)} — ${it.value}"
        } + (if (allRussian) " — все в России: там медиа Telegram и часть сайтов режут фильтры" else "")
        notes += line
        progress.log(line)
    }

    // --- фаза 3: MASQUE/TLS, если подсеть задана ------------------------------------
    val tlsResults: Map<Endpoint, ProbeSample> = if (!progress.isCancelled() &&
        spec.endpointSpec.ports.contains(443) &&
        spec.endpointSpec.subnets.any { it.startsWith("162.159.19") }
    ) {
        refineCandidates.take(4).associate { it.endpoint to tlsProber.probe(it.endpoint) }
    } else emptyMap()

    // --- кандидаты: endpoint × профиль ----------------------------------------------
    val candidates = ArrayList<Candidate>()
    for ((endpoint, profiles) in perProfile) {
        for ((profileName, stats) in profiles) {
            val profile = activeProfiles.firstOrNull { it.name == profileName } ?: continue
            val survived = stats.replies > 0
            val tlsSample = tlsResults[endpoint]
            val effectiveStats = if (tlsSample != null && tlsSample.verdict == Verdict.TLS_OK) {
                EndpointStats(endpoint, stats.samples + tlsSample, Verdict.TLS_OK, stats.replies, stats.attempts)
            } else stats
            val site = siteByHost[endpoint.host]
            val parts = Scoring.evaluate(effectiveStats, survived, 0, 0, weights, plain = profile.isEmpty, site = site)
            candidates.add(
                Candidate(
                    config = buildConfig(spec, account, endpoint, profile, parts.total),
                    stats = effectiveStats,
                    parts = parts,
                    junkProbes = stats.samples,
                    site = site
                )
            )
        }
    }
    // добавляем «просто лучший endpoint без шума» — иногда честный WG проходит лучше AWG. С проверкой
    // данных — нет: у этого варианта только рукопожатие первого прохода, а «без шума» и так есть
    // среди профилей второго прохода, уже с проверкой данных.
    if (!spec.dataProbe) ranked.firstOrNull()?.let { top ->
        candidates.add(
            Candidate(
                buildConfig(spec, account, top.endpoint, JunkLibrary.none(), 0),
                top,
                Scoring.evaluate(top, null, 0, 0, weights, plain = true),
                top.samples
            )
        )
    }

    // --- фаза 2б: не встают ли данные через секунду ---------------------------------
    val frozenNames = ArrayList<String>()
    if (spec.dataProbe && spec.sustainTop > 0 && !progress.isCancelled()) {
        sustainCheck(spec, candidates, account, peerPublic, progress, notes, frozenNames)
    }

    val ordered = candidates.sortedByDescending { it.score }

    // --- ресурсы ---------------------------------------------------------------------
    // После «Остановить подбор» ни замеров ресурсов, ни проверки изнутри: это ещё минута работы.
    val resourceResults = if (!progress.isCancelled() && spec.checkBaselineResources && spec.resources.isNotEmpty()) {
        progress.log("Проверяю доступность ресурсов без туннеля (это база сравнения)…")
        resources.checkAll(spec.resources)
    } else emptyList()

    var finalList = ordered
    if (!progress.isCancelled() && spec.verifyThroughTunnel && tunnel != null && ordered.isNotEmpty() && spec.resources.isNotEmpty()) {
        progress.log("Проверяю топ-${minOf(3, ordered.size)} кандидатов внутри туннеля…")
        val verified = ArrayList<Candidate>()
        val tv: TunnelVerifier = tunnel
        for (cand in ordered.take(minOf(3, ordered.size))) {
            if (progress.isCancelled()) break
            val results = runCatching {
                tv.verify(cand.config, spec.resources, spec.tunnelSettleMs) { progress.isCancelled() }
            }
                .getOrElse {
                    notes += "Туннель не поднялся (${it.javaClass.simpleName}) — пропускаю проверку изнутри."
                    emptyList()
                }
            val ok = results.count { it.ok }
            // Скорость через туннель этого кандидата: её мерит проверяющий сразу после сайтов.
            val speed = if (results.isEmpty()) -1 else runCatching { tv.lastSpeedKbps() }.getOrDefault(-1)
            progress.log(
                "  ${cand.config.endpoint.render()} · ${cand.junk.name} → ${ok}/${spec.resources.size} ресурсов" +
                    (if (speed > 0) " · ${dev.warpscout.core.net.SpeedTest.human(speed)}" else "") +
                    (cand.site?.let { " · выход ${dev.warpscout.core.net.ExitSite.describe(it)}" } ?: "")
            )
            val parts = Scoring.evaluate(
                cand.stats, cand.stats.replies > 0, ok, spec.resources.size, weights, plain = cand.junk.isEmpty, site = cand.site
            )
            verified.add(
                cand.copy(
                    parts = parts,
                    resourcesOk = ok,
                    resourcesTotal = spec.resources.size,
                    speedKbps = speed,
                    resourceResults = results,
                    config = cand.config.copy(name = "${spec.namePrefix}-${ok}of${spec.resources.size}")
                )
            )
        }
        // Проверенные изнутри важнее непроверенных: «открылось 7 из 9 сайтов» — это факт, а
        // сетевой балл — только догадка. Раньше списки перемешивались по баллу, и победить
        // мог кандидат, который отвечал на handshake, но не пускал трафик. Среди одинаково
        // открывшихся выше тот, через кого быстрее качается (ступенями, см. SpeedTest.bucket).
        finalList = verified.sortedWith(verifiedOrder()) +
            ordered.drop(verified.size).sortedByDescending { it.score }
    } else if (tunnel == null && spec.verifyThroughTunnel) {
        notes += "Сборка без встроенного туннеля: проверка «изнутри» пропущена, отранжировано по сетевым пробам."
    }

    return finish(spec, started, notes, finalList, resourceResults, account, progress, endpoints.size, frozen = frozenNames)
    }

    /**
     * Долгая проба данных для лучших вариантов (с 1.10.30): идут ли данные и через полторы
     * секунды после рукопожатия. Варианты, у которых данные встали, получают «данных нет» и в
     * очередь не попадают. Если без шума данные встают, а с шумом идут — это свойство сети, а не
     * точки: варианты без шума убираются из выбора совсем.
     *
     * Журнал 22.11: подбор 19:03 нашёл «данные идут» у 57 из 60 вариантов и выбрал чистый
     * WireGuard; на деле через него за 8 с не пришло приложениям ни байта, и сервис полчаса
     * переключался по кругу между точками без шума.
     */
    private fun sustainCheck(
        spec: TuningSpec,
        candidates: MutableList<Candidate>,
        account: dev.warpscout.core.model.WarpAccount,
        peerPublic: ByteArray,
        progress: ProgressSink,
        notes: MutableList<String>,
        frozenNames: MutableList<String>
    ) {
        val targets = sustainTargets(candidates, spec.sustainTop)
        if (targets.isEmpty()) return
        progress.log("Проверяю, не встают ли данные через секунду: вариантов ${targets.size}…")
        val before = candidates.toList()
        val sustainedBy = HashMap<String, Int>()
        val frozenBy = HashMap<String, Int>()
        for ((i, cand) in targets.withIndex()) {
            if (progress.isCancelled()) break
            val label = "${cand.config.endpoint.render()} · ${cand.junk.name}"
            progress.progress(i, targets.size, "проверка на заморозку · $label")
            val sample = runCatching {
                wgProber.probeSustained(
                    cand.config.endpoint, account, peerPublic, cand.junk.takeIf { !it.isEmpty }, spec.sustainMs
                )
            }.getOrNull() ?: continue
            if (!sample.dataTried) {
                // Рукопожатие на этот раз не прошло: одна потеря — не приговор, вариант не трогаем.
                progress.log("  ? $label — рукопожатие не повторилось (${sample.note.take(60)})")
                continue
            }
            val stats = cand.stats.copy(samples = cand.stats.samples + sample)
            val parts = Scoring.evaluate(stats, stats.replies > 0, 0, 0, weights, plain = cand.junk.isEmpty, site = cand.site)
            val idx = candidates.indexOf(cand)
            if (idx >= 0) candidates[idx] = cand.copy(stats = stats, parts = parts)
            val ok = sample.dataSustained
            val counter = if (ok) sustainedBy else frozenBy
            counter[cand.junk.name] = (counter[cand.junk.name] ?: 0) + 1
            progress.log(
                "  ${if (ok) "✓" else "✗"} $label — ${sample.note}" +
                    (cand.site?.let { " · выход ${dev.warpscout.core.net.ExitSite.describe(it)}" } ?: "")
            )
        }
        progress.progress(targets.size, targets.size, "проверка на заморозку")
        val sustained = sustainedBy.values.sum()
        val frozen = frozenBy.values.sum()
        val summary = "Долгая проверка данных: идут у $sustained, встали у $frozen"
        notes += summary
        progress.log(summary)
        if (sustained == 0) {
            if (frozen > 0) {
                // Встало у всех: это либо сеть, которая режет вообще всё, либо сбой самой проверки.
                // Очередь из-за неё не опустошаем — остаётся итог обычной проверки, а ложь (если она
                // есть) поймает проверка данных при подключении.
                candidates.clear()
                candidates.addAll(before)
                val line = "Данные встали у всех проверенных вариантов — не доверяю долгой проверке, " +
                    "оставляю итог обычной"
                notes += line
                progress.log(line)
            }
            return
        }
        // Шум, с которым данные вставали и ни разу не пошли, когда с другим шумом шли: это свойство
        // сети, а не точки. Такие варианты из очереди убираем, а имена отдаём приложению — оно
        // запомнит их для этой сети (NoiseMemory) и в следующий раз проверять их не будет.
        val badNoise = frozenBy.keys.filter { (sustainedBy[it] ?: 0) == 0 }.sorted()
        if (badNoise.isNotEmpty()) {
            val removed = candidates.count { it.junk.name in badNoise }
            candidates.removeAll { it.junk.name in badNoise }
            frozenNames += badNoise
            val line = "С шумом ${badNoise.joinToString(", ")} данные встают через секунду, с другим идут — " +
                "такие варианты ($removed) в очередь не беру"
            notes += line
            progress.log(line)
        }
    }

    /**
     * Кого проверять долгой пробой: лучший вариант каждой из [top] лучших точек, плюс лучший
     * вариант без шума и лучший с шумом — чтобы узнать, как сеть обходится с каждым из них.
     */
    private fun sustainTargets(candidates: List<Candidate>, top: Int): List<Candidate> {
        val usable = candidates.filter { it.usable }.sortedByDescending { it.score }
        val perPoint = usable.distinctBy { it.config.endpoint.render() }.take(top)
        val plain = usable.firstOrNull { it.junk.isEmpty }
        val masked = usable.firstOrNull { !it.junk.isEmpty }
        return (perPoint + listOfNotNull(plain, masked))
            .distinctBy { it.config.endpoint.render() + "|" + it.junk.name }
    }

    /**
     * Порядок проверенных изнутри: сколько открылось (выход за рубежом — как ещё один открывшийся
     * сайт, с 1.10.34) → где выход → ступень скорости через туннель → балл. Один и тот же для списка
     * и победителя (см. [Shortlist]), иначе «лучший» и первая строка топ-3 расходились бы.
     */
    private fun verifiedOrder(): Comparator<Candidate> = Shortlist.verifiedOrder()

    /** Когда приватного ключа нет: только «закрыт/открыт» и TLS. Честно помечаем низкую уверенность. */
    private fun runHeuristicOnly(
        spec: TuningSpec,
        progress: ProgressSink,
        started: java.time.LocalDateTime,
        notes: MutableList<String>,
        account: dev.warpscout.core.model.WarpAccount
    ): TuningResult {
        val endpoints = EndpointPool.build(spec.endpointSpec).take(60)
        progress.log("Эвристический режим: ${endpoints.size} endpoint'ов, TLS+UDP")
        // По одной точке за раз, поэтому отмену проверяем перед каждой: иначе 60 точек по TLS+UDP
        // досчитывались бы минуты после «Остановить подбор».
        val results = endpoints.asSequence().takeWhile { !progress.isCancelled() }.map { ep ->
            val tls = tlsProber.probe(ep)
            val peerPub = runCatching { Crypto.unBase64(account.peerPublicB64) }.getOrElse { ByteArray(32) }
            val udp = wgProber.probe(ep, account, peerPub, null).stats
            val stats = EndpointStats(ep, udp.samples + tls, Verdict.bestOf(udp.bestVerdict, tls.verdict),
                udp.replies + (if (tls.verdict == Verdict.TLS_OK) 1 else 0), udp.attempts + 1)
            val parts = Scoring.evaluate(stats, null, 0, 0, weights)
            Candidate(buildConfig(spec, account, ep, JunkLibrary.tlsFixed(), parts.total), stats, parts)
        }.toList().sortedByDescending { it.score }
        // Здесь рукопожатий нет вовсе (нет ключа) — это догадка по TLS/UDP, и годность по ответу
        // сервера к ней не применима.
        return finish(spec, started, notes, results, emptyList(), account, progress, endpoints.size, requireUsable = false)
    }

    private fun buildConfig(
        spec: TuningSpec,
        account: dev.warpscout.core.model.WarpAccount,
        endpoint: Endpoint,
        junk: JunkProfile,
        score: Int
    ): WarpConfig = WarpConfig(
        name = "${spec.namePrefix} ${endpoint.render()} ${junk.name} ($score)",
        account = account,
        endpoint = endpoint,
        junk = junk,
        allowedIps = spec.allowedIps,
        dns = spec.dns,
        mtu = spec.mtu,
        persistentKeepalive = spec.keepalive,
        enableIpv6Address = spec.enableIpv6Address,
        comments = listOf("сгенерировано WARP Scout", "профиль шума: ${junk.name}", "балл: $score")
    )

    private fun finish(
        spec: TuningSpec,
        started: LocalDateTime,
        notes: MutableList<String>,
        candidates: List<Candidate>,
        resources: List<ResourceResult>,
        account: dev.warpscout.core.model.WarpAccount,
        progress: ProgressSink,
        endpointsTested: Int = 0,
        /** Профили шума, на которых данные встали (см. [TuningReport.frozenProfiles]). */
        frozen: List<String> = emptyList(),
        /**
         * Победитель — только из годных (см. [Candidate.usable]). Раньше при «живых 0 из 120»
         * победителем становилась молчащая точка с 60 баллами: её конфиг записывался, тройка из
         * молчащих точек затирала рабочую, а подключение перебирало мёртвое (журнал 22.11 16:32).
         */
        requireUsable: Boolean = true
    ): TuningResult {
        val report = TuningReport(
            startedAt = started.format(tsFmt),
            finishedAt = LocalDateTime.now().format(tsFmt),
            profileName = spec.endpointSpec.name(),
            candidates = candidates,
            resources = resources,
            endpointsTested = endpointsTested,
            notes = notes,
            frozenProfiles = frozen
        )
        // Победитель: сначала «сколько реально открылось», потом балл. Если изнутри ничего не
        // проверяли — обычный максимум балла.
        val pool = if (requireUsable) candidates.filter { it.usable } else candidates
        val verifiedAny = pool.filter { it.resourcesTotal > 0 }
        val best = if (verifiedAny.any { it.resourcesOk > 0 }) {
            verifiedAny.sortedWith(verifiedOrder()).firstOrNull()
        } else {
            pool.maxByOrNull { it.score }
        }
        val text = best?.let { WgConf.render(it.config) }
        progress.log(
            if (best == null) when {
                candidates.isEmpty() -> "Готово: ни один кандидат не набрал баллов."
                candidates.any { it.stats.replies > 0 } ->
                    "Готово: рукопожатие у части точек есть, но данные не пошли ни через одну — прежние конфиг и очередь не трогаю."
                else -> "Готово: ни одна точка не ответила — прежние конфиг и очередь не трогаю."
            }
            else buildString {
                append("Лучший: ${best.config.endpoint.render()} · ${best.junk.name} · ${best.score} балла")
                best.stats.dataMs?.let { append(" · данные через туннель ${it.toLong()} мс") }
                if (best.resourcesTotal > 0) append(" · изнутри открылось ${best.resourcesOk}/${best.resourcesTotal}")
                if (best.speedKbps > 0) append(" · ${dev.warpscout.core.net.SpeedTest.human(best.speedKbps)}")
                best.site?.let { append(" · выход ${dev.warpscout.core.net.ExitSite.describe(it)}") }
            }
        )
        // Лучший выходит через Россию — честно говорим, есть ли другие варианты на этой сети.
        if (best != null && dev.warpscout.core.net.ExitSite.isRussian(best.site)) {
            val abroad = pool.filter { dev.warpscout.core.net.ExitSite.isAbroad(it.site) }
                .map { it.config.endpoint.render() }.distinct()
            progress.log(
                if (abroad.isEmpty()) {
                    "Точек с выходом за рубежом на этой сети не нашлось — выход через " +
                        "${dev.warpscout.core.net.ExitSite.city(best.site)}: медиа Telegram может тормозить"
                } else {
                    "С выходом за рубежом есть ${abroad.take(3).joinToString(", ")}, но через них открылось меньше — " +
                        "выбрал выход через ${dev.warpscout.core.net.ExitSite.city(best.site)}"
                }
            )
        }
        // Явно говорим, что профили шума сравнивались: это и есть ответ на «какой метод эффективнее».
        val profilesSeen = candidates.map { it.junk.name }.distinct()
        if (profilesSeen.size > 1) {
            progress.log(
                "Сравнил профилей шума: ${profilesSeen.size} (${profilesSeen.joinToString(", ")}) — " +
                    "победил ${best?.junk?.name ?: "—"}"
            )
        }
        return TuningResult(report, best?.config, text, account.source)
    }
}

/** Подсеть адреса для разнообразия подбора: «8.34.70.3» → «8.34.70»; не IPv4 — сам адрес. */
private fun subnetOf(endpoint: Endpoint): String {
    val host = endpoint.host
    val parts = host.split('.')
    return if (parts.size == 4 && parts.all { p -> p.isNotEmpty() && p.all { it.isDigit() } }) parts.take(3).joinToString(".") else host
}

private fun EndpointSpec.name(): String =
    "pool[${subnets.size} подсетей × ${ports.size} портов, ${mode.name.lowercase()}, seed=$seed]"
