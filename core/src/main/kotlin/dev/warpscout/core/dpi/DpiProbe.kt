package dev.warpscout.core.dpi

import dev.warpscout.core.model.Endpoint
import dev.warpscout.core.net.DefaultFactories
import dev.warpscout.core.net.TcpSocketFactory
import java.io.ByteArrayOutputStream
import java.io.EOFException
import java.io.IOException
import java.net.ConnectException
import java.net.Inet4Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.NoRouteToHostException
import java.net.Socket
import java.net.SocketTimeoutException
import java.nio.ByteBuffer
import java.util.concurrent.Callable
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLEngine
import javax.net.ssl.SSLEngineResult
import javax.net.ssl.SSLException
import javax.net.ssl.SSLHandshakeException

/**
 * Сайт для проверки «режут DPI или адрес». [speed] — сравнивать скорость приёмов и тогда, когда сайт
 * открывается как есть (замедление YouTube — это не блокировка: страница открывается, но медленно).
 * [control] — контрольный сайт: не открылся он — сеть не работает, и итогу верить нельзя.
 */
data class DpiTarget(
    val id: String,
    val name: String,
    val host: String,
    val path: String = "/",
    val speed: Boolean = false,
    val control: Boolean = false
)

object DpiTargets {
    /**
     * YouTube — главная страница (большая, по ней видна скорость), сервер видео и картинки: фильтр
     * может резать их по-разному. Discord — блокировка 2024 года, Instagram и X — давние блокировки
     * (обычно по адресам: для сравнения). Cloudflare — 256 КБ одним ответом: видно, обрывает ли сеть
     * соединения с зарубежными хостингами после ~16 КБ. Google — контроль.
     */
    val DEFAULT: List<DpiTarget> = listOf(
        DpiTarget("youtube", "YouTube", "www.youtube.com", "/", speed = true),
        DpiTarget("googlevideo", "Видео YouTube", "redirector.googlevideo.com", "/report_mapping"),
        DpiTarget("ytimg", "Картинки YouTube", "i.ytimg.com", "/vi/jNQXAC9IVRw/hqdefault.jpg"),
        DpiTarget("discord", "Discord", "discord.com", "/api/v9/gateway"),
        DpiTarget("instagram", "Instagram", "www.instagram.com", "/"),
        DpiTarget("x", "X (Twitter)", "x.com", "/"),
        DpiTarget("cloudflare", "Сайты за Cloudflare", "speed.cloudflare.com", "/__down?bytes=262144"),
        DpiTarget("google", "Google (контроль)", "www.google.com", "/generate_204", control = true)
    )
}

/** Докуда дошла попытка: имя → подключение → приветствие TLS → рукопожатие → ответ на запрос. */
enum class DpiStage { DNS, CONNECT, HELLO, TLS, DATA, DONE, SKIPPED }

/**
 * Одна попытка открыть сайт одним приёмом. [ok] — рукопожатие TLS прошло и сервер ответил на запрос
 * (любым кодом: 403 от сайта — тоже «фильтр пропустил»). [stalled] — данные шли и встали.
 */
data class DpiAttempt(
    val trick: DpiTrick,
    val ok: Boolean,
    val stage: DpiStage,
    val reason: String = "",
    val connectMs: Long = -1,
    val helloMs: Long = -1,
    val bytesIn: Long = 0,
    val status: Int = 0,
    val kbps: Int = -1,
    val stalled: Boolean = false
) {
    fun short(): String = when {
        stage == DpiStage.SKIPPED -> "${trick.title} — не проверить ($reason)"
        ok -> "${trick.title} ✓" + (if (kbps > 0) " ${DpiReport.speed(kbps)}" else "")
        else -> "${trick.title} ✗ $reason"
    }
}

enum class DpiVerdict {
    /** Открывается как есть. */
    OPEN,
    /** Открывается и как есть, но с приёмом заметно быстрее: замедляют по имени сайта. */
    FASTER,
    /** Как есть не открывается, с приёмом — да: режет DPI, обход поможет. */
    BYPASS,
    /** Данные идут и встают (~16 КБ), приёмы не помогают. */
    STALL,
    /** Режет на приветствии TLS, и эти приёмы не помогают. */
    DPI,
    /** Не отвечает даже на подключение: блокировка по адресу. */
    IP,
    /** Не узнать адрес. */
    DNS,
    /** Проверка не успела или не запускалась. */
    NONE
}

data class DpiTargetResult(
    val target: DpiTarget,
    val address: String,
    val dnsNote: String,
    val attempts: List<DpiAttempt>,
    val verdict: DpiVerdict,
    val helpers: List<DpiTrick>
) {
    val plain: DpiAttempt? get() = attempts.firstOrNull { it.trick == DpiTrick.PLAIN }

    /** Открывается (как есть или с приёмом). */
    val reachable: Boolean get() = verdict == DpiVerdict.OPEN || verdict == DpiVerdict.FASTER || verdict == DpiVerdict.BYPASS

    /** Итог по сайту — одна строка по-русски. */
    fun text(): String {
        val p = plain
        val names = helpers.joinToString(", ") { "«${it.title}»" }
        return when (verdict) {
            DpiVerdict.OPEN -> "открыт напрямую" + (p?.kbps?.takeIf { it > 0 }?.let { " · ${DpiReport.speed(it)}" } ?: "")
            DpiVerdict.FASTER -> {
                val best = attempts.filter { it.ok && it.trick in helpers }.maxByOrNull { it.kbps }
                "открыт, но медленно (${p?.kbps?.let { DpiReport.speed(it) } ?: "?"}); с приёмом " +
                    "«${best?.trick?.title}» — ${best?.kbps?.let { DpiReport.speed(it) } ?: "?"}: замедляют по имени сайта"
            }
            DpiVerdict.BYPASS -> "режет DPI (${p?.reason ?: "не открылся"}) — открывается с приёмами: $names"
            DpiVerdict.STALL -> "данные встают после ~${(p?.bytesIn ?: 0) / 1024} КБ — так режут зарубежные хостинги; приёмы не помогают"
            DpiVerdict.DPI -> "режет DPI (${p?.reason ?: "?"}); эти приёмы не помогают"
            DpiVerdict.IP -> "не отвечает на подключение (${p?.reason ?: "?"}) — блокировка по адресу, обход DPI не поможет"
            DpiVerdict.DNS -> "адрес не узнать: ${dnsNote.ifBlank { "DNS не ответил" }}"
            DpiVerdict.NONE -> p?.reason?.ifBlank { null } ?: "проверка не успела"
        }
    }

    /** Строка для журнала: адрес, все попытки и итог. */
    fun journal(): String =
        "${target.name} (${target.host}" + (if (address.isNotBlank()) " → $address" else "") + ")" +
            (if (dnsNote.isNotBlank()) " [$dnsNote]" else "") + ": " +
            (if (attempts.isEmpty()) "—" else attempts.joinToString(" · ") { it.short() }) +
            " ⇒ " + text()
}

/**
 * Итог проверки на одной сети. [ttl] — получилось ли менять TTL (без этого нет «перестановки»).
 */
class DpiReport(
    val at: Long,
    val network: String,
    val results: List<DpiTargetResult>,
    val tookMs: Long,
    val ttl: Boolean
) {
    /** Контрольный сайт открылся (или его нет в списке): итогу можно верить. */
    val controlOk: Boolean
        get() = results.filter { it.target.control }.all { it.reachable }

    /** Приёмы по числу сайтов, которым помогли (закрытые и замедленные), лучшие первыми. */
    fun bestTricks(): List<Pair<DpiTrick, Int>> {
        val counts = LinkedHashMap<DpiTrick, Int>()
        for (r in results) {
            if (r.verdict != DpiVerdict.BYPASS && r.verdict != DpiVerdict.FASTER) continue
            r.helpers.forEach { counts[it] = (counts[it] ?: 0) + 1 }
        }
        // При равенстве — приём проще (раньше в списке): разрез надёжнее перестановки.
        return counts.entries.sortedWith(compareByDescending<Map.Entry<DpiTrick, Int>> { it.value }.thenBy { it.key.ordinal })
            .map { it.key to it.value }
    }

    /** Короткий итог для экрана и журнала. */
    fun summary(): String {
        if (results.isEmpty()) return "Проверка не дала результатов."
        if (!controlOk) {
            return "Контрольный сайт не открылся — сеть не работает или не удалось выйти мимо туннеля. " +
                "Итогу не верь: проверь интернет (или выключи туннель) и повтори."
        }
        val parts = ArrayList<String>()
        val bypass = results.filter { it.verdict == DpiVerdict.BYPASS }
        val faster = results.filter { it.verdict == DpiVerdict.FASTER }
        val ip = results.filter { it.verdict == DpiVerdict.IP }
        val hard = results.filter { it.verdict == DpiVerdict.DPI || it.verdict == DpiVerdict.STALL || it.verdict == DpiVerdict.DNS }
        val open = results.filter { it.verdict == DpiVerdict.OPEN && !it.target.control }
        val best = bestTricks().firstOrNull()
        if (bypass.isNotEmpty() || faster.isNotEmpty()) {
            parts += "Обход DPI поможет: " + (bypass + faster).joinToString(", ") { it.target.name } +
                (best?.let { " — лучше всего «${it.first.title}»" } ?: "") + "."
        } else {
            parts += "Обход DPI на этой сети ничего не открывает."
        }
        if (ip.isNotEmpty()) parts += "По адресу (нужен VPN): " + ip.joinToString(", ") { it.target.name } + "."
        if (hard.isNotEmpty()) parts += "Не помогают эти приёмы: " + hard.joinToString(", ") { it.target.name } + "."
        if (open.isNotEmpty()) parts += "Открыто и так: " + open.joinToString(", ") { it.target.name } + "."
        if (!ttl) parts += "Перестановку проверить не удалось: система не дала поменять TTL."
        return parts.joinToString(" ")
    }

    /** Строки для журнала: шапка, по строке на сайт, итог и параметры для ByeDPI. */
    fun journalLines(): List<String> {
        val out = ArrayList<String>()
        out += "DPI: проверка на сети ${network.ifBlank { "?" }} · ${tookMs / 1000} с · TTL " + (if (ttl) "меняется" else "не меняется")
        results.forEach { out += "DPI · " + it.journal() }
        out += "DPI: итог — " + summary()
        bestTricks().firstOrNull()?.let { (trick, n) ->
            out += "DPI: для ByeDPI на этой сети — ${trick.byedpi} (помог: $n)"
        }
        return out
    }

    companion object {
        fun speed(kbps: Int): String =
            if (kbps >= 1000) String.format(java.util.Locale.US, "%.1f Мбит/с", kbps / 1000.0) else "$kbps кбит/с"
    }
}

/**
 * «Режут DPI или адрес» — сам, без ByeDPI и без root (с 1.10.49-beta2).
 *
 * Каждый сайт открывается по-честному: подключение TCP, рукопожатие TLS с проверкой сертификата и
 * запрос страницы. Сначала как есть, потом — если не открылся (или для [DpiTarget.speed] — всегда) —
 * с приёмами [DpiTrick]: первый пакет (ClientHello) уходит так, как его отправил бы ByeDPI. Всё
 * остальное соединение — обычное. Поэтому «открылось с приёмом» значит ровно то, что обход DPI на
 * этой сети этот сайт откроет.
 *
 * Сокеты — из [tcp] (в приложении — на настоящей сети, мимо туннеля), имена — через [resolve]
 * (DNS этой сети) и, если тот не отдал адрес или отдал заглушку, через [fallbackResolve].
 * «Перестановке» нужен [ttl]; без него она честно помечается «не проверить».
 */
class DpiProbe(
    private val tcp: TcpSocketFactory = DefaultFactories.tcp,
    private val resolve: (String) -> List<InetAddress> = { InetAddress.getAllByName(it).toList() },
    private val fallbackResolve: ((String) -> List<InetAddress>)? = null,
    private val ttl: SocketTtl? = null,
    private val sslContext: SSLContext? = null,
    val connectTimeoutMs: Int = 4000,
    val helloTimeoutMs: Int = 4000,
    val idleTimeoutMs: Int = 4000,
    val maxBytes: Int = 320 * 1024,
    val maxDataMs: Long = 6000,
    private val port: Int = 443,
    /** Пускать на локальные адреса (только для самопроверки: там сервер — на 127.0.0.1). */
    private val allowLocal: Boolean = false
) {

    /** Доступ к TTL исходящих пакетов сокета (в Android — через setsockopt). */
    interface SocketTtl {
        /** Текущий TTL; null — не узнать (тогда вернём [DEFAULT_TTL]). */
        fun get(socket: Socket): Int?

        /** Поставить TTL; false — система не дала. */
        fun set(socket: Socket, ttl: Int): Boolean
    }

    private class TrickUnsupported(message: String) : IOException(message)

    /** Проверить все [targets] параллельно. [progress] зовётся из рабочих потоков. */
    fun run(
        targets: List<DpiTarget> = DpiTargets.DEFAULT,
        network: String = "",
        progress: (String) -> Unit = {},
        cancelled: () -> Boolean = { false },
        threads: Int = 4,
        deadlineMs: Long = 180_000
    ): DpiReport {
        val t0 = System.currentTimeMillis()
        val pool = Executors.newFixedThreadPool(threads.coerceIn(1, 8)) { r ->
            Thread(r, "warpscout-dpi").apply { isDaemon = true }
        }
        try {
            val futures = targets.map { t -> pool.submit(Callable { check(t, progress, cancelled) }) }
            val results = futures.mapIndexed { i, f ->
                val left = deadlineMs - (System.currentTimeMillis() - t0)
                runCatching { f.get(left.coerceAtLeast(1), TimeUnit.MILLISECONDS) }.getOrElse {
                    f.cancel(true)
                    DpiTargetResult(
                        targets[i], "", "",
                        listOf(DpiAttempt(DpiTrick.PLAIN, false, DpiStage.SKIPPED, "проверка не успела")),
                        DpiVerdict.NONE, emptyList()
                    )
                }
            }
            val ttlWorks = ttl != null && results.flatMap { it.attempts }
                .none { it.trick.needsTtl && it.stage == DpiStage.SKIPPED }
            return DpiReport(t0, network, results, System.currentTimeMillis() - t0, ttlWorks)
        } finally {
            pool.shutdownNow()
        }
    }

    /** Один сайт: адрес, «как есть», при надобности — приёмы, итог. */
    fun check(target: DpiTarget, progress: (String) -> Unit = {}, cancelled: () -> Boolean = { false }): DpiTargetResult {
        val (addresses, dnsNote) = addressesOf(target.host)
        if (addresses.isEmpty()) {
            return DpiTargetResult(target, "", dnsNote, emptyList(), DpiVerdict.DNS, emptyList())
        }
        val attempts = ArrayList<DpiAttempt>()
        progress("${target.name}: как есть")
        var addr = addresses.first()
        var plain = attempt(target, addr, DpiTrick.PLAIN)
        // Не подключилось — ещё раз, другим адресом, если он есть: «блокировка по адресу» не должна
        // держаться на одной потерянной попытке.
        if (plain.stage == DpiStage.CONNECT && !cancelled()) {
            addresses.getOrNull(1)?.let { addr = it }
            plain = attempt(target, addr, DpiTrick.PLAIN)
        }
        attempts += plain
        val tryTricks = plain.stage != DpiStage.CONNECT && (!plain.ok || target.speed)
        if (tryTricks) {
            for (trick in DpiTrick.BYPASS) {
                if (cancelled()) break
                progress("${target.name}: ${trick.title}")
                attempts += attempt(target, addr, trick)
            }
        }
        var (verdict, helpers) = classify(target, attempts)
        // «С приёмом быстрее» — сначала ещё раз как есть: первое соединение бывает медленнее
        // следующих (разгон TCP, холодный сервер), и вывод «замедляют» не должен держаться на нём.
        if (verdict == DpiVerdict.FASTER && !cancelled()) {
            progress("${target.name}: как есть, повтор")
            val again = attempt(target, addr, DpiTrick.PLAIN)
            if (again.ok && again.kbps > plain.kbps) {
                attempts[0] = again
                val re = classify(target, attempts)
                verdict = re.first
                helpers = re.second
            }
        }
        return DpiTargetResult(target, addr.hostAddress ?: "", dnsNote, attempts, verdict, helpers)
    }

    /** Адреса сайта: IPv4 первыми; заглушки DNS (0.0.0.0, 127.*, частные сети) — не адреса. */
    internal fun addressesOf(host: String): Pair<List<InetAddress>, String> {
        val sys = runCatching { resolve(host) }.getOrElse { emptyList() }
        val bogus: (InetAddress) -> Boolean = { a -> if (allowLocal) a.isAnyLocalAddress else bogus(a) }
        val good = sys.filter { !bogus(it) }.sortedBy { if (it is Inet4Address) 0 else 1 }
        if (good.isNotEmpty()) return good to ""
        val stub = sys.firstOrNull { bogus(it) }
        val note = if (stub != null) "DNS сети отдал заглушку ${stub.hostAddress}" else "DNS сети не отдал адрес"
        val fb = fallbackResolve?.let { f -> runCatching { f(host) }.getOrElse { emptyList() } }.orEmpty()
            .filter { !bogus(it) }.sortedBy { if (it is Inet4Address) 0 else 1 }
        return if (fb.isNotEmpty()) fb to "$note — взят адрес от публичного DNS" else emptyList<InetAddress>() to note
    }

    /** Одна попытка: подключение, TLS (первый пакет — по приёму [trick]), запрос страницы. */
    fun attempt(target: DpiTarget, address: InetAddress, trick: DpiTrick): DpiAttempt {
        if (trick.needsTtl && ttl == null) return DpiAttempt(trick, false, DpiStage.SKIPPED, "нет доступа к TTL")
        val started = System.nanoTime()
        var stage = DpiStage.CONNECT
        var connectMs = -1L
        var helloAt = 0L
        var sock: Socket? = null
        var pump: TlsPump? = null
        try {
            val ctx = sslContext ?: SSLContext.getDefault()
            val s = tcp.create(Endpoint(address.hostAddress ?: target.host, port))
            sock = s
            s.tcpNoDelay = true
            s.connect(InetSocketAddress(address, port), connectTimeoutMs)
            connectMs = msSince(started)
            s.soTimeout = helloTimeoutMs
            stage = DpiStage.HELLO
            val engine = ctx.createSSLEngine(target.host, port)
            engine.useClientMode = true
            engine.sslParameters = engine.sslParameters.also { p ->
                p.serverNames = listOf(SNIHostName(target.host))
                p.endpointIdentificationAlgorithm = "HTTPS"
            }
            val tls = TlsPump(engine, s)
            pump = tls
            tls.handshake(
                first = { bytes ->
                    sendFirst(s, bytes, trick)
                    helloAt = System.nanoTime()
                },
                onServerByte = { if (stage == DpiStage.HELLO) stage = DpiStage.TLS }
            )
            stage = DpiStage.DATA
            s.soTimeout = idleTimeoutMs
            val request = ("GET ${target.path} HTTP/1.1\r\nHost: ${target.host}\r\nUser-Agent: $USER_AGENT\r\n" +
                "Accept: */*\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n").toByteArray(Charsets.US_ASCII)
            tls.httpGet(request, maxBytes.toLong(), maxDataMs)
            val ok = tls.status > 0
            return DpiAttempt(
                trick, ok, if (ok) DpiStage.DONE else DpiStage.DATA,
                if (ok) "" else "сервер не ответил на запрос",
                connectMs, helloMsOf(helloAt, tls), tls.rawIn, tls.status, tls.kbps()
            )
        } catch (e: TrickUnsupported) {
            return DpiAttempt(trick, false, DpiStage.SKIPPED, e.message ?: "не поддерживается")
        } catch (e: InterruptedException) {
            Thread.currentThread().interrupt()
            return DpiAttempt(trick, false, DpiStage.SKIPPED, "остановлено")
        } catch (e: Exception) {
            val p = pump
            val stalled = stage == DpiStage.DATA && e is SocketTimeoutException
            val reason = if (stalled) {
                if (p != null && p.status > 0) "встало после ${p.rawIn / 1024} КБ (тишина ${idleTimeoutMs / 1000} с)"
                else "на запрос нет ответа (тишина ${idleTimeoutMs / 1000} с)"
            } else reasonOf(e, stage)
            return DpiAttempt(
                trick, false, stage, reason, connectMs,
                if (p != null) helloMsOf(helloAt, p) else -1, p?.rawIn ?: 0, p?.status ?: 0, -1, stalled
            )
        } finally {
            runCatching { sock?.close() }
        }
    }

    private fun helloMsOf(helloAt: Long, p: TlsPump): Long =
        if (helloAt == 0L || p.firstByteAt == 0L) -1 else ((p.firstByteAt - helloAt) / 1_000_000).coerceAtLeast(0)

    /** Первый пакет — кусками по плану приёма. Паузы — чтобы куски ушли разными пакетами TCP. */
    private fun sendFirst(s: Socket, hello: ByteArray, trick: DpiTrick) {
        val out = s.getOutputStream()
        val pieces = TlsHello.plan(trick, hello)
        pieces.forEachIndexed { i, p ->
            if (p.lowTtl) {
                val t = ttl ?: throw TrickUnsupported("нет доступа к TTL")
                val normal = runCatching { t.get(s) }.getOrNull()?.takeIf { it in 2..255 } ?: DEFAULT_TTL
                if (!runCatching { t.set(s, 1) }.getOrDefault(false)) throw TrickUnsupported("система не дала поменять TTL")
                try {
                    out.write(p.bytes)
                    out.flush()
                    // Кусок должен уйти с TTL 1 до того, как вернём обычный: ядро может придержать
                    // мелкую запись на миллисекунды (autocork), и тогда он ушёл бы с обычным TTL.
                    Thread.sleep(LOW_TTL_HOLD_MS)
                } finally {
                    runCatching { t.set(s, normal) }
                }
            } else {
                out.write(p.bytes)
                out.flush()
            }
            if (p.oobAfter) {
                try {
                    s.sendUrgentData(TlsHello.OOB_BYTE)
                } catch (e: IOException) {
                    throw TrickUnsupported("срочный байт не отправляется: ${e.message ?: e.javaClass.simpleName}")
                }
            }
            if (i < pieces.size - 1) Thread.sleep(PIECE_GAP_MS)
        }
    }

    private fun reasonOf(e: Throwable, stage: DpiStage): String {
        val msg = (e.message ?: "").lowercase()
        val cert = generateSequence(e) { it.cause }.any { c ->
            c is java.security.cert.CertificateException || c is java.security.cert.CertPathValidatorException ||
                (c.message ?: "").lowercase().let { m -> "certificate" in m || "trust anchor" in m || "hostname" in m }
        }
        return when {
            e is SocketTimeoutException -> when (stage) {
                DpiStage.CONNECT -> "нет ответа на подключение (${connectTimeoutMs / 1000} с)"
                DpiStage.HELLO -> "тишина после приветствия TLS (${helloTimeoutMs / 1000} с)"
                DpiStage.TLS -> "рукопожатие TLS встало"
                else -> "тишина"
            }
            e is ConnectException && "refused" in msg -> "отказ в подключении"
            e is NoRouteToHostException || "unreachable" in msg -> "нет маршрута до сервера"
            "reset" in msg || "broken pipe" in msg || "aborted" in msg ->
                if (stage == DpiStage.HELLO) "сброс после приветствия TLS" else "сброс соединения"
            e is EOFException -> if (stage == DpiStage.HELLO) "сервер закрыл соединение сразу после приветствия" else "соединение закрыто"
            e is SSLHandshakeException && cert -> "сертификат не прошёл проверку — подмена?"
            e is SSLException -> "ошибка TLS: " + (e.message ?: e.javaClass.simpleName).take(90)
            else -> e.javaClass.simpleName + (e.message?.let { ": " + it.take(90) } ?: "")
        }
    }

    companion object {
        const val DEFAULT_TTL = 64

        /** Сколько держать TTL 1 после отправки куска (см. [sendFirst]). */
        const val LOW_TTL_HOLD_MS = 20L

        /** Пауза между кусками первого пакета: иначе ядро может склеить их в один пакет. */
        const val PIECE_GAP_MS = 15L

        /** Скорость считаем, только если пришло хотя бы столько: на мелочи она — шум. */
        const val SPEED_MIN_BYTES = 64 * 1024L

        /** Медленнее — «как есть медленно» (см. [classify]). */
        const val SLOW_KBPS = 1000

        /** Приём «быстрее», только если с ним не медленнее этого. */
        const val FAST_KBPS = 1500

        const val USER_AGENT =
            "Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0 Mobile Safari/537.36"

        private fun msSince(t: Long): Long = (System.nanoTime() - t) / 1_000_000

        /** Заглушки DNS и адреса, по которым сайт точно не живёт. */
        fun bogus(a: InetAddress): Boolean =
            a.isAnyLocalAddress || a.isLoopbackAddress || a.isSiteLocalAddress || a.isLinkLocalAddress || a.isMulticastAddress

        /**
         * Итог по попыткам. Приём «помог», если открыл сайт, который как есть не открылся; для
         * [DpiTarget.speed] — ещё и если как есть сайт качался медленнее [SLOW_KBPS], а с приёмом —
         * втрое быстрее и не медленнее [FAST_KBPS]. Пороги грубые нарочно: замедление YouTube — это
         * сотни килобит против мегабит, а разброс между соединениями бывает и вдвое (проверено).
         */
        fun classify(target: DpiTarget, attempts: List<DpiAttempt>): Pair<DpiVerdict, List<DpiTrick>> {
            val plain = attempts.firstOrNull { it.trick == DpiTrick.PLAIN }
                ?: return DpiVerdict.NONE to emptyList()
            val tricks = attempts.filter { it.trick != DpiTrick.PLAIN }
            if (plain.ok) {
                if (target.speed && plain.kbps in 1 until SLOW_KBPS) {
                    val faster = tricks.filter { it.ok && it.kbps >= plain.kbps * 3 && it.kbps >= FAST_KBPS }
                    if (faster.isNotEmpty()) return DpiVerdict.FASTER to faster.sortedByDescending { it.kbps }.map { it.trick }
                }
                return DpiVerdict.OPEN to emptyList()
            }
            if (plain.stage == DpiStage.SKIPPED) return DpiVerdict.NONE to emptyList()
            if (plain.stage == DpiStage.CONNECT) return DpiVerdict.IP to emptyList()
            val helpers = tricks.filter { it.ok }.map { it.trick }
            if (helpers.isNotEmpty()) return DpiVerdict.BYPASS to helpers
            return (if (plain.stalled && plain.status > 0) DpiVerdict.STALL else DpiVerdict.DPI) to emptyList()
        }
    }
}

/**
 * TLS поверх обычного сокета через SSLEngine: так первый пакет (ClientHello) проходит через наши
 * руки и уходит кусками по приёму, а дальше всё как у обычного HTTPS — с проверкой сертификата.
 */
private class TlsPump(private val engine: SSLEngine, sock: Socket) {
    private val input = sock.getInputStream()
    private val output = sock.getOutputStream()
    private var netIn: ByteBuffer = ByteBuffer.allocate(engine.session.packetBufferSize + 4096)
    private var netOut: ByteBuffer = ByteBuffer.allocate(engine.session.packetBufferSize + 4096)
    private var appIn: ByteBuffer = ByteBuffer.allocate(engine.session.applicationBufferSize + 4096)
    private val readBuf = ByteArray(32 * 1024)
    private val empty: ByteBuffer = ByteBuffer.allocate(0)

    /** Сколько байт пришло от сервера (TCP, вместе с рукопожатием). */
    var rawIn = 0L
        private set
    var firstByteAt = 0L
        private set
    private var lastByteAt = 0L
    private var onByte: (() -> Unit)? = null

    // Ответ HTTP.
    var status = 0
        private set
    private val head = ByteArrayOutputStream()
    private var last4 = 0
    private var headerDone = false
    private var contentLength = -1L
    private var chunked = false
    private var body = 0L
    private val tail = ArrayDeque<Byte>()
    private var complete = false
    private var dataStartRaw = 0L
    private var dataStartAt = 0L
    private var replyRaw = -1L
    private var replyAt = 0L

    private fun grow(b: ByteBuffer): ByteBuffer {
        val n = ByteBuffer.allocate(b.capacity() * 2)
        b.flip()
        n.put(b)
        return n
    }

    /** Дочитать из сокета в netIn (режим записи); -1 — конец потока. */
    private fun fill(): Int {
        if (!netIn.hasRemaining()) netIn = grow(netIn)
        val n = input.read(readBuf, 0, minOf(readBuf.size, netIn.remaining()))
        if (n > 0) {
            netIn.put(readBuf, 0, n)
            rawIn += n
            val now = System.nanoTime()
            if (firstByteAt == 0L) firstByteAt = now
            lastByteAt = now
            onByte?.invoke()
            // Первый кусок ответа на запрос: скорость считаем от него, а не от запроса — иначе в
            // неё попадает время, пока сервер думает (на мелких страницах это половина замера).
            if (dataStartAt != 0L && replyRaw < 0) {
                replyRaw = rawIn
                replyAt = now
            }
        }
        return n
    }

    private fun runTasks() {
        while (true) {
            val task = engine.delegatedTask ?: break
            task.run()
        }
    }

    private fun wrapAndSend(src: ByteBuffer, first: ((ByteArray) -> Unit)?): SSLEngineResult {
        while (true) {
            netOut.clear()
            val r = engine.wrap(src, netOut)
            if (r.status == SSLEngineResult.Status.BUFFER_OVERFLOW) {
                netOut = ByteBuffer.allocate(netOut.capacity() * 2)
                continue
            }
            netOut.flip()
            if (netOut.hasRemaining()) {
                val bytes = ByteArray(netOut.remaining())
                netOut.get(bytes)
                if (first != null) first(bytes) else {
                    output.write(bytes)
                    output.flush()
                }
            }
            return r
        }
    }

    private fun unwrapOnce(): SSLEngineResult {
        netIn.flip()
        try {
            return engine.unwrap(netIn, appIn)
        } finally {
            netIn.compact()
        }
    }

    /** Рукопожатие. [first] получает первый пакет (ClientHello) вместо прямой записи в сокет. */
    fun handshake(first: (ByteArray) -> Unit, onServerByte: () -> Unit) {
        onByte = onServerByte
        engine.beginHandshake()
        var firstSent = false
        var hs = engine.handshakeStatus
        var guard = 0
        while (true) {
            if (++guard > 20_000) throw SSLException("рукопожатие не сходится")
            when {
                hs == SSLEngineResult.HandshakeStatus.NEED_WRAP -> {
                    val r = wrapAndSend(empty, if (firstSent) null else first)
                    // «Первый пакет ушёл» — только когда wrap и правда что-то выдал: иначе ClientHello
                    // из следующего вызова ушёл бы мимо приёма (у Conscrypt пустой wrap бывает).
                    if (r.bytesProduced() > 0) firstSent = true
                    if (r.status == SSLEngineResult.Status.CLOSED) throw SSLException("TLS закрыт при отправке")
                    hs = r.handshakeStatus
                }
                // NEED_UNWRAP_AGAIN (Java 9+) — по имени: на старых Android такой константы нет.
                hs == SSLEngineResult.HandshakeStatus.NEED_UNWRAP || hs.name == "NEED_UNWRAP_AGAIN" -> {
                    val r = unwrapOnce()
                    when (r.status) {
                        SSLEngineResult.Status.BUFFER_UNDERFLOW -> {
                            if (fill() < 0) throw EOFException("сервер закрыл соединение")
                            hs = engine.handshakeStatus
                        }
                        SSLEngineResult.Status.BUFFER_OVERFLOW -> {
                            appIn = grow(appIn)
                            hs = engine.handshakeStatus
                        }
                        SSLEngineResult.Status.CLOSED -> throw SSLException("сервер закрыл TLS")
                        else -> hs = r.handshakeStatus
                    }
                }
                hs == SSLEngineResult.HandshakeStatus.NEED_TASK -> {
                    runTasks()
                    hs = engine.handshakeStatus
                }
                hs == SSLEngineResult.HandshakeStatus.FINISHED || hs == SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING -> {
                    // Данные, пришедшие вместе с концом рукопожатия, остаются в netIn — их прочтёт httpGet.
                    appIn.clear()
                    onByte = null
                    return
                }
                else -> hs = engine.handshakeStatus
            }
        }
    }

    /** Запрос и чтение ответа: до конца ответа, [maxBytes] от сервера или [maxMs]. */
    fun httpGet(request: ByteArray, maxBytes: Long, maxMs: Long) {
        val src = ByteBuffer.wrap(request)
        var guard = 0
        while (src.hasRemaining()) {
            if (++guard > 1000) throw SSLException("запрос не уходит")
            val r = wrapAndSend(src, null)
            if (r.status == SSLEngineResult.Status.CLOSED) throw SSLException("TLS закрыт до запроса")
            if (r.handshakeStatus == SSLEngineResult.HandshakeStatus.NEED_TASK) runTasks()
        }
        dataStartRaw = rawIn
        dataStartAt = System.nanoTime()
        val deadline = dataStartAt + maxMs * 1_000_000
        while (!complete) {
            if (rawIn - dataStartRaw >= maxBytes) return
            if (System.nanoTime() > deadline) return
            val r = unwrapOnce()
            when (r.status) {
                SSLEngineResult.Status.OK -> {
                    consumeApp()
                    when (r.handshakeStatus) {
                        SSLEngineResult.HandshakeStatus.NEED_TASK -> runTasks()
                        SSLEngineResult.HandshakeStatus.NEED_WRAP -> wrapAndSend(empty, null)
                        else -> {}
                    }
                }
                SSLEngineResult.Status.BUFFER_UNDERFLOW -> if (fill() < 0) return
                SSLEngineResult.Status.BUFFER_OVERFLOW -> appIn = grow(appIn)
                SSLEngineResult.Status.CLOSED -> {
                    consumeApp()
                    return
                }
                else -> return
            }
        }
    }

    /** Скорость приёма ответа, кбит/с; −1 — пришло слишком мало, чтобы мерить. */
    fun kbps(): Int {
        if (replyRaw < 0) return -1
        val bytes = rawIn - replyRaw
        if (bytes < DpiProbe.SPEED_MIN_BYTES || lastByteAt <= replyAt) return -1
        val ms = ((lastByteAt - replyAt) / 1_000_000).coerceAtLeast(1)
        return (bytes * 8 / ms).toInt()
    }

    private fun consumeApp() {
        appIn.flip()
        val n = appIn.remaining()
        if (n > 0) {
            val bytes = ByteArray(n)
            appIn.get(bytes)
            onBody(bytes)
        }
        appIn.clear()
    }

    private fun onBody(b: ByteArray) {
        var off = 0
        if (!headerDone) {
            // Заголовок копим до пустой строки (последние 4 байта — «\r\n\r\n»); длиннее 64 КБ не
            // бывает — дальше считаем телом.
            while (off < b.size && !headerDone) {
                val v = b[off].toInt() and 0xFF
                head.write(v)
                off++
                last4 = (last4 shl 8) or v
                if (last4 == 0x0D0A0D0A || head.size() > 65_536) parseHead(String(head.toByteArray(), Charsets.ISO_8859_1))
            }
            if (!headerDone) return
        }
        val n = b.size - off
        if (n <= 0) return
        body += n
        if (chunked) {
            for (i in off until b.size) {
                tail.addLast(b[i])
                if (tail.size > 5) tail.removeFirst()
            }
            if (tail.size == 5 && String(tail.toByteArray(), Charsets.ISO_8859_1) == "0\r\n\r\n") complete = true
        }
        if (contentLength >= 0 && body >= contentLength) complete = true
    }

    private fun parseHead(text: String) {
        headerDone = true
        val lines = text.split("\r\n")
        status = lines.firstOrNull()?.split(' ')?.getOrNull(1)?.toIntOrNull() ?: 0
        for (line in lines.drop(1)) {
            val i = line.indexOf(':')
            if (i <= 0) continue
            val name = line.substring(0, i).trim().lowercase()
            val value = line.substring(i + 1).trim()
            if (name == "content-length") contentLength = value.toLongOrNull() ?: -1
            if (name == "transfer-encoding" && value.lowercase().contains("chunked")) chunked = true
        }
        if (status == 204 || status == 304 || status in 100..199 || contentLength == 0L) complete = true
    }
}
