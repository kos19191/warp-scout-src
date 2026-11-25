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
     * только её: одна точка вместо пула — секунды вместо минут и без разогрева радио на весь скан.
     */
    val cachedStart: CachedStart? = null
)

/** Сохранённая удачная точка: её проверяют первой, но по тем же правилам, что и свежую. */
data class CachedStart(val endpoint: Endpoint, val junkName: String = "")

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
                quickNotes += "Быстрый старт: сохранённая конфигурация проверена заново, полный скан не понадобился."
                val quick = tuneWith(narrow, progress, started, quickNotes, account, peerPublic)
                if (quick.best != null && cachedConfirmed(quick, cached)) return quick
                progress.log("сохранённая конфигурация не подтвердилась — полный подбор")
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
        val profiles = spec.junkProfiles.filter { it.name == cached.junkName }
        // IPv6 в разборе списка пока не поддержан — быстрый старт не для него, полный подбор работает.
        if (ep.host.isBlank() || ep.port !in 1..65535 || ep.host.contains(':')) return null
        progress.log("быстрый старт: проверяю сохранённую конфигурацию ${ep.render()}" +
            (profiles.firstOrNull()?.let { " · ${it.name}" } ?: ""))
        return spec.copy(
            endpointSpec = EndpointSpec(
                mode = PoolMode.EXPLICIT,
                subnets = emptyList(),
                hostnames = listOf("${ep.host}:${ep.port}"),
                maxEndpoints = 1
            ),
            junkProfiles = profiles.ifEmpty { spec.junkProfiles },
            refineTop = 1
        )
    }

    /** Есть ли в отчёте сохранённая точка и подтвердилась ли она (см. [CachedPoint]). */
    private fun cachedConfirmed(result: TuningResult, cached: CachedStart): Boolean {
        val cand = result.report.candidates.firstOrNull { it.config.endpoint == cached.endpoint } ?: return false
        return CachedPoint.confirmed(cand.stats.replies, cand.resourcesTotal, cand.resourcesOk)
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
    val endpoints = EndpointPool.build(spec.endpointSpec)
    progress.log("Ключи: ${account.source}; кандидатов: ${endpoints.size}")

    // --- фаза 1: быстрый скан -------------------------------------------------------
    val coarse = wgProber.scan(endpoints, account, peerPublic, junk = null) { d, t, _ ->
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

    val refineCandidates = (if (alive.size >= 2) alive else ranked).take(maxOf(3, spec.refineTop))

    // --- фаза 2: подробно, по профилям шума ---------------------------------------
    val perProfile = LinkedHashMap<Endpoint, MutableMap<String, EndpointStats>>()
    val totalWork = refineCandidates.size * spec.junkProfiles.size
    var done = 0
    for (stats in refineCandidates) {
        for (profile in spec.junkProfiles) {
            if (progress.isCancelled()) break
            val refined = wgProber.probe(stats.endpoint, account, peerPublic, profile).stats
            perProfile.getOrPut(stats.endpoint) { LinkedHashMap() }[profile.name] = refined
            done++
            progress.progress(done, totalWork, "${stats.endpoint.render()} · ${profile.name} · ${refined.bestVerdict}")
        }
    }

    // --- фаза 3: MASQUE/TLS, если подсеть задана ------------------------------------
    val tlsResults: Map<Endpoint, ProbeSample> = if (spec.endpointSpec.ports.contains(443) &&
        spec.endpointSpec.subnets.any { it.startsWith("162.159.19") }
    ) {
        refineCandidates.take(4).associate { it.endpoint to tlsProber.probe(it.endpoint) }
    } else emptyMap()

    // --- кандидаты: endpoint × профиль ----------------------------------------------
    val candidates = ArrayList<Candidate>()
    for ((endpoint, profiles) in perProfile) {
        for ((profileName, stats) in profiles) {
            val profile = spec.junkProfiles.firstOrNull { it.name == profileName } ?: continue
            val survived = stats.replies > 0
            val tlsSample = tlsResults[endpoint]
            val effectiveStats = if (tlsSample != null && tlsSample.verdict == Verdict.TLS_OK) {
                EndpointStats(endpoint, stats.samples + tlsSample, Verdict.TLS_OK, stats.replies, stats.attempts)
            } else stats
            val parts = Scoring.evaluate(effectiveStats, survived, 0, 0, weights)
            candidates.add(
                Candidate(
                    config = buildConfig(spec, account, endpoint, profile, parts.total),
                    stats = effectiveStats,
                    parts = parts,
                    junkProbes = stats.samples
                )
            )
        }
    }
    // добавляем «просто лучший endpoint без шума» — иногда честный WG проходит лучше AWG
    ranked.firstOrNull()?.let { top ->
        candidates.add(
            Candidate(
                buildConfig(spec, account, top.endpoint, JunkLibrary.none(), 0),
                top,
                Scoring.evaluate(top, null, 0, 0, weights),
                top.samples
            )
        )
    }

    val ordered = candidates.sortedByDescending { it.score }

    // --- ресурсы ---------------------------------------------------------------------
    val resourceResults = if (spec.checkBaselineResources && spec.resources.isNotEmpty()) {
        progress.log("Проверяю доступность ресурсов без туннеля (это база сравнения)…")
        resources.checkAll(spec.resources)
    } else emptyList()

    var finalList = ordered
    if (spec.verifyThroughTunnel && tunnel != null && ordered.isNotEmpty() && spec.resources.isNotEmpty()) {
        val toVerify = selectForVerification(ordered, maxCount = 6)
        progress.log("Проверяю до ${toVerify.size} разнообразных кандидатов внутри туннеля…")
        val verified = ArrayList<Candidate>()
        val verifiedKeys = HashSet<String>()
        val tv: TunnelVerifier = tunnel
        var strongCount = 0
        val strongThreshold = ((spec.resources.size * 8) + 9) / 10 // ≥80% ресурсов (например 8/10)
        for (cand in toVerify) {
            if (progress.isCancelled()) break
            // Останавливаемся досрочно только если уже нашли ≥2 по-настоящему сильных узла (≥80% сайтов),
            // а не на посредственных 6/10 (как бывает при выходе через российский узел DME).
            if (strongCount >= 3 || (verified.size >= 3 && strongCount >= 2)) break
            val results = runCatching { tv.verify(cand.config, spec.resources, spec.tunnelSettleMs) }
                .getOrElse {
                    notes += "Туннель не поднялся (${it.javaClass.simpleName}) — пропускаю проверку изнутри."
                    emptyList()
                }
            val ok = results.count { it.ok }
            if (ok >= strongThreshold) strongCount++
            progress.log("  ${cand.config.endpoint.render()} · ${cand.junk.name} → ${ok}/${spec.resources.size} ресурсов")
            val parts = Scoring.evaluate(cand.stats, cand.stats.replies > 0, ok, spec.resources.size, weights)
            verifiedKeys.add(candidateKey(cand))
            verified.add(
                cand.copy(
                    parts = parts,
                    resourcesOk = ok,
                    resourcesTotal = spec.resources.size,
                    config = cand.config.copy(name = "${spec.namePrefix}-${ok}of${spec.resources.size}")
                )
            )
        }
        // Трёхуровневый порядок: сначала доказанно рабочие (ok > 0), затем непроверенные,
        // и в самом конце — проверенные с 0/N (доказанно зарезанные DPI после handshake).
        val workingVerified = verified
            .filter { it.resourcesOk > 0 }
            .sortedWith(compareByDescending<Candidate> { it.resourcesOk }.thenByDescending { it.score })
        val failedVerified = verified
            .filter { it.resourcesOk <= 0 }
            .sortedByDescending { it.score }
        val unverified = ordered
            .filterNot { candidateKey(it) in verifiedKeys }
            .sortedByDescending { it.score }
        finalList = workingVerified + unverified + failedVerified
    } else if (tunnel == null && spec.verifyThroughTunnel) {
        notes += "Сборка без встроенного туннеля: проверка «изнутри» пропущена, отранжировано по сетевым пробам."
    }

    return finish(spec, started, notes, finalList, resourceResults, account, progress, endpoints.size)
    }

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
        val results = endpoints.map { ep ->
            val tls = tlsProber.probe(ep)
            val peerPub = runCatching { Crypto.unBase64(account.peerPublicB64) }.getOrElse { ByteArray(32) }
            val udp = wgProber.probe(ep, account, peerPub, null).stats
            val stats = EndpointStats(ep, udp.samples + tls, Verdict.bestOf(udp.bestVerdict, tls.verdict),
                udp.replies + (if (tls.verdict == Verdict.TLS_OK) 1 else 0), udp.attempts + 1)
            val parts = Scoring.evaluate(stats, null, 0, 0, weights)
            Candidate(buildConfig(spec, account, ep, JunkLibrary.tlsFixed(), parts.total), stats, parts)
        }.sortedByDescending { it.score }
        return finish(spec, started, notes, results, emptyList(), account, progress, endpoints.size)
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
        endpointsTested: Int = 0
    ): TuningResult {
        val report = TuningReport(
            startedAt = started.format(tsFmt),
            finishedAt = LocalDateTime.now().format(tsFmt),
            profileName = spec.endpointSpec.name(),
            candidates = candidates,
            resources = resources,
            endpointsTested = endpointsTested,
            notes = notes
        )
        // Победитель: сначала доказанно рабочие изнутри (ok > 0), затем непроверенные живые,
        // и только в крайнем случае (если все проверены и дали 0/N) — максимум балла.
        val verifiedWorking = candidates.filter { it.resourcesTotal > 0 && it.resourcesOk > 0 }
        val unverified = candidates.filter { it.resourcesTotal == 0 }
        val best = when {
            verifiedWorking.isNotEmpty() -> verifiedWorking.sortedWith(
                compareByDescending<Candidate> { it.resourcesOk }.thenByDescending { it.score }
            ).firstOrNull()
            unverified.isNotEmpty() -> unverified.maxByOrNull { it.score }
            else -> candidates.maxByOrNull { it.score }
        }
        val text = best?.let { WgConf.render(it.config) }
        progress.log(
            if (best == null) "Готово: ни один кандидат не набрал баллов."
            else buildString {
                append("Лучший: ${best.config.endpoint.render()} · ${best.junk.name} · ${best.score} балла")
                if (best.resourcesTotal > 0) append(" · изнутри открылось ${best.resourcesOk}/${best.resourcesTotal}")
            }
        )
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

    companion object {
        internal fun candidateKey(c: Candidate): String =
            c.config.endpoint.render() + "|" + c.junk.name

        fun subnet24Of(host: String): String {
            val parts = host.split('.')
            return if (parts.size == 4) "${parts[0]}.${parts[1]}.${parts[2]}" else host
        }

        /**
         * Отбирает разнообразную выборку для проверки изнутри туннеля:
         *  1) по одному лучшему кандидату каждого вида маскировки (сначала замаскированные профили
         *     SIP/QUIC/TLS/HTTP, затем `none`), предпочитая РАЗНЫЕ `/24`-подсети (разные дата-центры
         *     Cloudflare, например `162.159.192.x` → ARN вместо двух `162.159.195.x` → DME);
         *  2) оставшиеся слоты добираем лучшими кандидатами из ещё не проверенных `/24`-подсетей
         *     (разных узлов выхода), затем просто разных `IP:порт`;
         *  3) при малом числе точек (например, быстрый старт из 1 точки) добираем по баллу.
         */
        fun selectForVerification(ordered: List<Candidate>, maxCount: Int = 6): List<Candidate> {
            if (maxCount <= 0 || ordered.isEmpty()) return emptyList()
            val out = ArrayList<Candidate>(minOf(maxCount, ordered.size))
            val pickedKeys = HashSet<String>()
            val pickedEndpoints = HashSet<String>()
            val pickedSubnets = HashSet<String>()

            fun tryAdd(c: Candidate, requireNewSubnet: Boolean, requireNewEndpoint: Boolean): Boolean {
                if (out.size >= maxCount) return false
                val ep = c.config.endpoint.render()
                val sub = subnet24Of(c.config.endpoint.host)
                if (requireNewSubnet && sub in pickedSubnets) return false
                if (requireNewEndpoint && ep in pickedEndpoints) return false
                if (!pickedKeys.add(candidateKey(c))) return false
                pickedEndpoints.add(ep)
                pickedSubnets.add(sub)
                out.add(c)
                return true
            }

            // Шаг 1: по одному лучшему представителю каждого вида маскировки (сначала с обфускацией, потом none),
            // но СТРОГО из разных /24-подсетей (чтобы один московский PoP не съедал слоты до проверки зарубежных).
            val distinctKinds = ordered.map { it.junk.kind }.distinct()
                .sortedBy { if (it == dev.warpscout.core.model.JunkKind.NONE) 1 else 0 }
            val coveredKinds = HashSet<dev.warpscout.core.model.JunkKind>()
            for (kind in distinctKinds) {
                val ofKind = ordered.filter { it.junk.kind == kind }
                if (ofKind.firstOrNull { tryAdd(it, requireNewSubnet = true, requireNewEndpoint = true) } != null) {
                    coveredKinds.add(kind)
                }
            }

            // Шаг 2: добираем ещё не проверенные /24-подсети (приоритет замаскированным профилям).
            val obfuscatedFirst = ordered.sortedBy { if (it.junk.kind == dev.warpscout.core.model.JunkKind.NONE) 1 else 0 }
            for (c in obfuscatedFirst) {
                if (out.size >= maxCount) break
                if (tryAdd(c, requireNewSubnet = true, requireNewEndpoint = true)) {
                    coveredKinds.add(c.junk.kind)
                }
            }

            // Шаг 3: добираем ещё не охваченные виды маскировки (если они нашлись только в уже взятых /24).
            for (kind in distinctKinds) {
                if (out.size >= maxCount) break
                if (kind in coveredKinds) continue
                val ofKind = ordered.filter { it.junk.kind == kind }
                val added = ofKind.firstOrNull { tryAdd(it, requireNewSubnet = false, requireNewEndpoint = true) } != null ||
                    ofKind.firstOrNull { tryAdd(it, requireNewSubnet = false, requireNewEndpoint = false) } != null
                if (added) coveredKinds.add(kind)
            }

            // Шаг 4: добираем разные endpoint'ы с максимальным баллом.
            for (c in ordered) {
                if (out.size >= maxCount) break
                tryAdd(c, requireNewSubnet = false, requireNewEndpoint = true)
            }

            // Шаг 5: если уникальных endpoint'ов меньше maxCount — добираем оставшихся по баллу.
            for (c in ordered) {
                if (out.size >= maxCount) break
                tryAdd(c, requireNewSubnet = false, requireNewEndpoint = false)
            }
            return out
        }
    }
}

private fun EndpointSpec.name(): String =
    "pool[${subnets.size} подсетей × ${ports.size} портов, ${mode.name.lowercase()}, seed=$seed]"
