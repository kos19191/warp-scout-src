package dev.warpscout.core.tunnel

import dev.warpscout.core.model.Candidate
import dev.warpscout.core.model.TuningReport
import dev.warpscout.core.net.ExitSite
import dev.warpscout.core.net.SmartDnsCheck
import dev.warpscout.core.net.SpeedTest
import dev.warpscout.core.net.TelegramMedia
import java.io.BufferedInputStream
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketTimeoutException
import java.net.URI
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLPeerUnverifiedException
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

/**
 * Эксперимент «Приложения по точкам и автовыбор выхода» (с 1.10.43; переключатель в «Автоматике»,
 * по умолчанию выключен).
 *
 * Зачем. Человек спросил 24.11: «можно ли, чтобы при сканировании точек он ещё ранжировал доступность
 * приложений… и в зависимости от того, что мы открываем, точка менялась на более лучшую для
 * приложения». Менять точку под открытое приложение нельзя: какое приложение открыто, Android говорит
 * только с доступом к истории использования (его убрали в 1.10.32 — Samsung назвал приложение
 * опасным), а смена точки рвёт живые соединения всех приложений. Да и точки с одним городом выхода
 * для приложений почти одинаковы: после Cloudflare трафик идёт одним путём. Разница бывает между
 * выходами — WARP и второй выход. Поэтому два шага:
 *
 *  1. [byPointText] — в отчёте подбора: как каждый сервис открылся через каждую из проверенных точек
 *     (подбор и так проверяет их изнутри туннеля), с честным «≈ одинаково», если разница — в пределах
 *     разброса одного запроса ([withinNoise]);
 *  2. автовыбор выхода: для приложений с выходом «Само» сервис сам сравнивает их сервис через WARP и
 *     через второй выход ([PROBES], [fetch]) и ведёт приложение туда, где сервис работает ([decide]) —
 *     правилом на лету и только для новых соединений (см. AppExitTable.setAuto). Telegram — как
 *     раньше, своей проверкой медиа (TelegramChoice).
 */
object AppAuto {

    // ------------------------------------------------------------------ что меряем

    /**
     * Замер сервиса: адрес, который отвечает так же, как само приложение. [blockedCountries] — сервис
     * отказывает по стране выхода, а сам адрес отвечает всем (trace Cloudflare): тогда «работает» —
     * это страна в ответе не из списка.
     */
    data class Probe(val service: String, val url: String, val blockedCountries: Set<String> = emptySet())

    /** Названия — как в AppServices: по ним сервис находит приложения. */
    val PROBES: List<Probe> = listOf(
        Probe("YouTube", "https://www.youtube.com/"),
        Probe("Instagram", "https://www.instagram.com/"),
        Probe("Facebook", "https://www.facebook.com/"),
        Probe("WhatsApp", "https://web.whatsapp.com/"),
        Probe("X", "https://x.com/"),
        Probe("Discord", "https://discord.com/api/v9/gateway"),
        Probe("ChatGPT", "https://chatgpt.com/cdn-cgi/trace", SmartDnsCheck.UNSUPPORTED),
        Probe("Claude", "https://claude.ai/cdn-cgi/trace", SmartDnsCheck.UNSUPPORTED),
        Probe("TikTok", "https://www.tiktok.com/"),
    )

    fun probeFor(service: String): Probe? = PROBES.firstOrNull { it.service.equals(service, ignoreCase = true) }

    /** Сервис под автовыбором: есть замер, и это не Telegram (у него своя проверка медиа и свой вопрос). */
    fun covers(service: String): Boolean = !service.equals("Telegram", ignoreCase = true) && probeFor(service) != null

    /** Как часто мерить: как медиа Telegram — раз в 30 минут при включённом экране. */
    const val GAP_MS = 30 * 60_000L

    /** Файл итога в filesDir: пишет сервис (процесс туннеля), читает экран. */
    const val STATUS_FILE = "app-auto.txt"

    // ------------------------------------------------------------------ замер

    /**
     * Итог одного замера. [ok] — сервис ответил как надо; [kbps] — скорость (−1 — ответ слишком
     * короткий, тогда сравниваем по [ms]); [ms] — всё целиком: соединение, TLS, ответ; [unknown] —
     * замер не показателен (адрес вне туннеля, имя не разрешилось), по нему не решаем.
     */
    data class Measure(
        val ok: Boolean,
        val kbps: Int,
        val ms: Long,
        val note: String = "",
        val unknown: Boolean = false,
    )

    /** Сколько читаем: на скорость хватает, а трафика — копейки (меряем раз в 30 минут). */
    const val PROBE_BYTES = 96 * 1024
    const val PROBE_MAX_MS = 6_000L
    const val CONNECT_MS = 5_000
    const val READ_MS = 4_000

    /** Короче этого скорость не считаем — сравниваем по времени. */
    const val MIN_SPEED_BYTES = 32 * 1024

    const val MAX_HOPS = 5

    /** Открыть соединение с [ip] для имени [host]: в приложении — [tlsOpener], в SelfCheck — простой TCP. */
    fun interface Opener {
        fun open(ip: String, host: String, port: Int, timeoutMs: Int): Socket
    }

    /**
     * TLS поверх своего сокета. Сокет привязывается к локальному порту ДО соединения, и [prepare]
     * получает этот порт: сервис закрепляет по нему соединение замера за выходом (см.
     * TunDispatcher.pin) — самый первый пакет, SYN, уже идёт нужным путём. Имя — в SNI и сверяется с
     * сертификатом (цепочку проверяет системное хранилище).
     */
    fun tlsOpener(prepare: (localPort: Int, ip: String, port: Int) -> Unit): Opener = Opener { ip, host, port, timeoutMs ->
        val raw = Socket()
        try {
            raw.bind(InetSocketAddress(0))
            prepare(raw.localPort, ip, port)
            raw.connect(InetSocketAddress(InetAddress.getByName(ip), port), timeoutMs)
            raw.soTimeout = timeoutMs
            val ssl = (SSLSocketFactory.getDefault() as SSLSocketFactory).createSocket(raw, host, port, true) as SSLSocket
            val params = ssl.sslParameters
            params.serverNames = listOf(SNIHostName(host))
            params.endpointIdentificationAlgorithm = "HTTPS"
            ssl.sslParameters = params
            ssl.startHandshake()
            if (!TelegramMedia.certMatches(ssl.session, host)) {
                runCatching { ssl.close() }
                throw SSLPeerUnverifiedException("сертификат не для $host")
            }
            ssl
        } catch (e: Exception) {
            runCatching { raw.close() }
            throw e
        }
    }

    /**
     * GET [probe] по IPv4 своим сокетом ([opener]): так замер идёт ровно тем путём, который ему
     * назначили, — системный HTTP выбрал бы IPv6 или другой адрес имени. Перенаправления проходим
     * сами. [resolve] — адреса имени (в приложении — системный DNS через туннель); [inTunnel] —
     * адрес идёт через туннель: нет — замер про туннель ничего не скажет ([Measure.unknown]).
     */
    fun fetch(
        probe: Probe,
        resolve: (String) -> List<String>,
        inTunnel: (String) -> Boolean,
        opener: Opener,
        maxBytes: Int = PROBE_BYTES,
        maxMs: Long = PROBE_MAX_MS,
        readTimeoutMs: Int = READ_MS,
        now: () -> Long = System::currentTimeMillis,
    ): Measure {
        val started = now()
        fun took(): Long = (now() - started).coerceAtLeast(0L)
        val scheme = runCatching { URI(probe.url).scheme.orEmpty().lowercase() }.getOrDefault("")
        var current = probe.url
        for (hop in 0 until MAX_HOPS) {
            val t = Target.of(current) ?: return Measure(false, -1, took(), "адрес не разобран", unknown = true)
            if (t.scheme != scheme) return Measure(false, -1, took(), "перенаправление на ${t.scheme}", unknown = true)
            val ip = runCatching { resolve(t.host) }.getOrDefault(emptyList())
                .map { it.trim() }
                .firstOrNull { isV4(it) }
                ?: return Measure(false, -1, took(), "${t.host} не разрешился в адрес IPv4", unknown = true)
            if (!inTunnel(ip)) return Measure(false, -1, took(), "${t.host} ($ip) идёт мимо туннеля", unknown = true)
            val socket = try {
                opener.open(ip, t.host, t.port, CONNECT_MS)
            } catch (e: Exception) {
                return Measure(false, -1, took(), "соединение с ${t.host}: ${brief(e)}")
            }
            try {
                socket.soTimeout = readTimeoutMs
                val out = socket.getOutputStream()
                out.write(request(t).toByteArray(Charsets.ISO_8859_1))
                out.flush()
                val input = BufferedInputStream(socket.getInputStream(), 16 * 1024)
                val head = readHead(input) ?: return Measure(false, -1, took(), "ответ не HTTP")
                if (head.code in 300..399) {
                    val location = head.headers["location"].orEmpty().trim()
                    if (location.isEmpty()) return Measure(false, -1, took(), "перенаправление без адреса", unknown = true)
                    current = runCatching { URI(current).resolve(location).toString() }.getOrNull()
                        ?: return Measure(false, -1, took(), "перенаправление не разобрано", unknown = true)
                    continue
                }
                if (head.code !in 200..299) return Measure(false, -1, took(), "HTTP ${head.code}")
                if (head.code == 204) return Measure(true, -1, took(), "HTTP 204")
                val expected = head.headers["content-length"]?.trim()?.toLongOrNull()?.takeIf { it >= 0L }
                val body = readBody(input, expected, maxBytes, maxMs, now)
                if (body.bytes <= 0L && expected != 0L) return Measure(false, -1, took(), "пустой ответ")
                if (body.cut && body.bytes < body.limit / 2) {
                    return Measure(false, -1, took(), "данные встали посреди ответа (${body.bytes / 1024} КБ)")
                }
                if (probe.blockedCountries.isNotEmpty()) {
                    val loc = Regex("""(?m)^loc=([A-Z]{2})\s*$""").find(body.text)?.groupValues?.get(1).orEmpty()
                    if (loc.isEmpty()) return Measure(false, -1, took(), "страна в ответе не видна", unknown = true)
                    if (loc in probe.blockedCountries) return Measure(false, -1, took(), "страна $loc — сервис отказывает")
                    return Measure(true, -1, took(), "страна $loc")
                }
                val kbps = if (body.bytes >= MIN_SPEED_BYTES) TelegramMedia.kbps(body.bytes, body.ms) else -1
                return Measure(true, kbps, took(), "${body.bytes / 1024} КБ")
            } catch (e: SocketTimeoutException) {
                return Measure(false, -1, took(), "нет ответа за ${readTimeoutMs / 1000} с")
            } catch (e: IOException) {
                return Measure(false, -1, took(), "ответ оборвался: ${e.javaClass.simpleName}")
            } finally {
                runCatching { socket.close() }
            }
        }
        return Measure(false, -1, took(), "слишком много перенаправлений", unknown = true)
    }

    private fun request(t: Target): String =
        "GET ${t.path} HTTP/1.1\r\n" +
            "Host: ${t.hostHeader}\r\n" +
            "User-Agent: Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Mobile Safari/537.36\r\n" +
            "Accept: text/html,application/json,*/*\r\n" +
            "Accept-Encoding: identity\r\n" +
            "Connection: close\r\n\r\n"

    private fun brief(e: Exception): String = (e.javaClass.simpleName + " " + e.message.orEmpty()).trim().take(70)

    private fun isV4(ip: String): Boolean {
        val p = ip.split('.')
        return p.size == 4 && p.all { part -> part.toIntOrNull()?.let { it in 0..255 } == true }
    }

    private class Head(val code: Int, val headers: Map<String, String>)

    /** Заголовки до пустой строки (не больше 32 КБ); null — это не HTTP. */
    private fun readHead(input: InputStream): Head? {
        val bytes = ByteArrayOutputStream()
        var tail = 0
        while (bytes.size() < 32 * 1024) {
            val b = input.read()
            if (b < 0) break
            bytes.write(b)
            tail = (tail shl 8) or b
            if (tail == 0x0D0A0D0A) break
        }
        val lines = bytes.toString("ISO-8859-1").split("\r\n")
        val status = lines.firstOrNull().orEmpty()
        if (!status.startsWith("HTTP/")) return null
        val code = status.split(' ').getOrNull(1)?.toIntOrNull() ?: return null
        val headers = HashMap<String, String>()
        for (line in lines.drop(1)) {
            val i = line.indexOf(':')
            if (i <= 0) continue
            headers[line.substring(0, i).trim().lowercase()] = line.substring(i + 1).trim()
        }
        return Head(code, headers)
    }

    private class Body(val bytes: Long, val ms: Long, val text: String, val cut: Boolean, val limit: Long)

    /** Тело: сколько пришло и за сколько (от первого куска), начало текстом (для trace), оборвалось ли. */
    private fun readBody(input: InputStream, expected: Long?, maxBytes: Int, maxMs: Long, now: () -> Long): Body {
        val limit = if (expected != null) minOf(expected, maxBytes.toLong()) else maxBytes.toLong()
        val buf = ByteArray(16 * 1024)
        val text = ByteArrayOutputStream()
        val start = now()
        var last = start
        var total = 0L
        var cut = false
        while (total < limit) {
            val want = minOf(buf.size.toLong(), limit - total).toInt()
            val n = try {
                input.read(buf, 0, want)
            } catch (e: SocketTimeoutException) {
                cut = true
                break
            } catch (e: IOException) {
                cut = true
                break
            }
            if (n < 0) {
                // Конец без обещанной длины (Connection: close) — это и есть весь ответ.
                if (expected != null && total < limit) cut = true
                break
            }
            if (text.size() < 4096) text.write(buf, 0, minOf(n, 4096 - text.size()))
            total += n
            last = now()
            if (last - start >= maxMs) break
        }
        return Body(total, (last - start).coerceAtLeast(1L), text.toString("ISO-8859-1"), cut, limit)
    }

    /** Куда и что запрашивать. */
    private class Target(val scheme: String, val host: String, val port: Int, val path: String, val hostHeader: String) {
        companion object {
            fun of(url: String): Target? = runCatching {
                val u = URI(url)
                val scheme = u.scheme.orEmpty().lowercase()
                if (scheme != "https" && scheme != "http") return@runCatching null
                val host = u.host.orEmpty()
                if (host.isEmpty()) return@runCatching null
                val default = if (scheme == "https") 443 else 80
                val port = if (u.port > 0) u.port else default
                val path = u.rawPath.orEmpty().ifEmpty { "/" } + (u.rawQuery?.let { "?$it" } ?: "")
                Target(scheme, host, port, path, if (port == default) host else "$host:$port")
            }.getOrNull()
        }
    }

    // ------------------------------------------------------------------ решение

    /**
     * Куда вести приложение: [AppExit.AUTO] — как обычно, по адресам (почти всё — через WARP);
     * [AppExit.SECOND] — целиком через второй выход. [current] — что решили прошлым замером.
     *
     *  • замер не показателен — оставляем как было;
     *  • открывается только одним путём — им;
     *  • не открывается никак — как обычно: второй выход не помогает;
     *  • открывается обоими — WARP (он быстрее и без лимитов), а второй выход — только если через WARP
     *    заметно хуже ([secondMuchBetter]); вернуться — когда WARP догнал ([warpCatchesUp]). Пороги
     *    разные, чтобы приложение не скакало между выходами от замера к замеру.
     */
    fun decide(warp: Measure, second: Measure, current: Int): Int {
        if (warp.unknown || second.unknown) return current
        if (warp.ok && !second.ok) return AppExit.AUTO
        if (!warp.ok && second.ok) return AppExit.SECOND
        if (!warp.ok) return AppExit.AUTO
        return if (current == AppExit.SECOND) {
            if (warpCatchesUp(warp, second)) AppExit.AUTO else AppExit.SECOND
        } else {
            if (secondMuchBetter(warp, second)) AppExit.SECOND else AppExit.AUTO
        }
    }

    /** Через второй выход вдвое быстрее и хотя бы на мегабит (или ответ вдвое быстрее и на полторы секунды). */
    fun secondMuchBetter(warp: Measure, second: Measure): Boolean {
        if (warp.kbps > 0 && second.kbps > 0) return second.kbps >= maxOf(warp.kbps * 2, warp.kbps + 1_000)
        return second.ms * 2 <= warp.ms && warp.ms - second.ms >= 1_500
    }

    /** WARP не хуже второго выхода больше чем на пятую часть (по скорости) или на четверть (по времени). */
    fun warpCatchesUp(warp: Measure, second: Measure): Boolean {
        if (warp.kbps > 0 && second.kbps > 0) return warp.kbps.toLong() * 5 >= second.kbps.toLong() * 4
        return warp.ms * 4 <= second.ms * 5
    }

    /** Почему так решили — для журнала и экрана. */
    fun why(warp: Measure, second: Measure, exit: Int): String = when {
        warp.unknown || second.unknown -> "замер не показателен — оставляю как было"
        exit == AppExit.SECOND && !warp.ok -> "через WARP не открывается"
        exit == AppExit.SECOND -> "через WARP заметно медленнее"
        !warp.ok && !second.ok -> "не открывается ни так, ни так"
        else -> "через WARP работает"
    }

    /** «✓ 8,1 Мбит/с», «✓ 640 мс», «✗ HTTP 403», «не проверено (…)». */
    fun describe(m: Measure): String = when {
        m.unknown -> "не проверено" + if (m.note.isNotBlank()) " (${m.note})" else ""
        !m.ok -> "✗" + if (m.note.isNotBlank()) " ${m.note}" else ""
        m.kbps > 0 -> "✓ ${SpeedTest.human(m.kbps)}"
        else -> "✓ ${m.ms} мс"
    }

    fun exitName(exit: Int): String = if (exit == AppExit.SECOND) "второй выход" else "WARP"

    // ------------------------------------------------------------------ итог для экрана

    /** Строка итога: сервис, что решили, оба замера, почему. */
    data class Row(val service: String, val exit: Int, val warp: Measure, val second: Measure, val why: String)

    /**
     * Итог последнего замера: когда, площадка выхода WARP («DME»), как зовут второй выход («второй
     * выход (США)»), строки по сервисам и [note] — почему замера не было (второй выход не поднят,
     * мерить нечего).
     */
    data class Status(
        val at: Long,
        val site: String,
        val secondLabel: String,
        val rows: List<Row>,
        val note: String = "",
    ) {
        fun encode(): String = buildString {
            append(HEADER).append('|').append(at).append('|').append(clean(site)).append('|')
                .append(clean(secondLabel)).append('|').append(clean(note)).append('\n')
            for (r in rows) {
                append(clean(r.service)).append('|').append(r.exit).append('|')
                append(measure(r.warp)).append('|').append(measure(r.second)).append('|')
                append(clean(r.why)).append('\n')
            }
        }

        companion object {
            private const val HEADER = "v1"

            private fun clean(s: String): String = s.replace('|', '/').replace('\n', ' ').replace('\r', ' ').trim()

            private fun measure(m: Measure): String =
                "${if (m.ok) 1 else 0}|${m.kbps}|${m.ms}|${if (m.unknown) 1 else 0}|${clean(m.note)}"

            private fun measureOf(p: List<String>, from: Int): Measure = Measure(
                ok = p[from] == "1",
                kbps = p[from + 1].toIntOrNull() ?: -1,
                ms = p[from + 2].toLongOrNull() ?: 0L,
                unknown = p[from + 3] == "1",
                note = p[from + 4],
            )

            /** Разбор файла; кривой или чужой версии — null. */
            fun decode(text: String?): Status? = runCatching {
                val lines = text.orEmpty().split('\n').filter { it.isNotBlank() }
                val head = lines.firstOrNull()?.split('|') ?: return@runCatching null
                if (head.size < 5 || head[0] != HEADER) return@runCatching null
                val rows = lines.drop(1).mapNotNull { line ->
                    val p = line.split('|')
                    if (p.size < 13) return@mapNotNull null
                    Row(p[0], p[1].toIntOrNull() ?: AppExit.AUTO, measureOf(p, 2), measureOf(p, 7), p[12])
                }
                Status(head[1].toLongOrNull() ?: 0L, head[2], head[3], rows, head[4])
            }.getOrNull()
        }
    }

    /** Итог словами, по строке: шапка, пояснение, сервисы. */
    fun statusLines(s: Status): List<String> {
        val out = ArrayList<String>()
        out += buildString {
            append("замер ").append(hhmm(s.at))
            if (s.site.isNotBlank()) append(" · WARP через ").append(ExitSite.cityAcc(s.site).ifBlank { s.site })
            if (s.secondLabel.isNotBlank()) append(" · ").append(s.secondLabel)
        }
        if (s.note.isNotBlank()) out += s.note
        s.rows.forEach { r ->
            out += "${r.service}: WARP ${describe(r.warp)} · второй выход ${describe(r.second)} → ${exitName(r.exit)}" +
                if (r.why.isNotBlank()) " (${r.why})" else ""
        }
        return out
    }

    private fun hhmm(at: Long): String =
        if (at <= 0L) "—" else java.text.SimpleDateFormat("HH:mm", java.util.Locale.getDefault()).format(java.util.Date(at))

    // ------------------------------------------------------------------ шаг 1: приложения по точкам

    /** Ячейка «сервис × точка»: открылся ли и за сколько. */
    data class Cell(val ok: Boolean, val ms: Long)

    /**
     * Сервис по точкам: ячейки по порядку точек (null — у этой точки его не проверяли), лучшие точки
     * (индексы; пусто — не открылся нигде) и [same] — разницы нет (всюду открылся в пределах разброса
     * или нигде).
     */
    data class ServiceByPoint(val service: String, val cells: List<Cell?>, val best: List<Int>, val same: Boolean)

    /**
     * Разница меньше этого — разброс одного запроса, а не свойство точки: четверть секунды или
     * половина лучшего времени. Подбор делает по одному запросу на сервис, и время одного запроса
     * скачет сильнее, чем отличаются точки с одним городом выхода.
     */
    fun withinNoise(ms: Long, bestMs: Long): Boolean = ms <= bestMs + maxOf(250L, bestMs / 2)

    /**
     * Точки, проверенные изнутри (до [maxPoints], в порядке подбора), и сервисы по ним: «Что
     * проверять» и свои сайты — у проверок по спискам id пустой, их здесь нет (это не приложения).
     */
    fun byPoint(report: TuningReport, maxPoints: Int = 3): Pair<List<Candidate>, List<ServiceByPoint>> {
        val points = report.candidates.filter { it.resourceResults.isNotEmpty() }.take(maxPoints)
        val checks = LinkedHashMap<String, String>()
        points.forEach { p -> p.resourceResults.forEach { r -> if (r.check.id.isNotBlank()) checks.putIfAbsent(r.check.url, r.check.name) } }
        val rows = checks.map { (url, name) ->
            val cells = points.map { p -> p.resourceResults.firstOrNull { it.check.url == url }?.let { Cell(it.ok, it.elapsedMs) } }
            val opened = cells.mapIndexedNotNull { i, c -> if (c != null && c.ok) i to c.ms else null }
            val bestMs = opened.minOfOrNull { it.second }
            val best = if (bestMs == null) emptyList() else opened.filter { withinNoise(it.second, bestMs) }.map { it.first }
            val measured = cells.count { it != null }
            ServiceByPoint(name, cells, best, same = best.isEmpty() || best.size == measured)
        }
        return points to rows
    }

    private val MARKS = listOf("①", "②", "③", "④", "⑤")

    /**
     * Раздел отчёта подбора «Приложения по точкам» (Markdown, как весь отчёт). [second] — итог
     * последнего замера автовыбора: если свежий (до трёх часов), добавляем строку про второй выход.
     */
    fun byPointText(report: TuningReport, second: Status? = null, now: Long = System.currentTimeMillis()): String {
        val (points, rows) = byPoint(report)
        return buildString {
            appendLine("## Приложения по точкам (эксперимент)")
            appendLine()
            when {
                points.isEmpty() -> appendLine(
                    "Изнутри туннеля точки не проверялись — сравнивать нечего: включи «При подборе проверять через туннель " +
                        "трёх лучших точек» в «Что проверять»."
                )
                rows.isEmpty() -> appendLine("В «Что проверять» не отмечено ни одного сервиса — сравнивать нечего.")
                points.size < 2 -> appendLine("Изнутри туннеля проверена одна точка — сравнивать не с чем.")
                else -> {
                    appendLine(
                        "Точки: " + points.mapIndexed { i, c ->
                            "${MARKS[i]} ${c.config.endpoint.render()}" + (c.site?.let { " (${ExitSite.city(it).ifBlank { it }})" } ?: "")
                        }.joinToString(" · ")
                    )
                    appendLine()
                    rows.forEach { r ->
                        val cells = r.cells.mapIndexed { i, c ->
                            MARKS[i] + " " + when {
                                c == null -> "—"
                                c.ok -> "✓ ${c.ms} мс"
                                else -> "✗"
                            }
                        }.joinToString(" · ")
                        val verdict = when {
                            r.best.isEmpty() -> "не открылся ни через одну"
                            r.same -> "≈ одинаково"
                            else -> "лучше " + r.best.joinToString(", ") { MARKS[it] }
                        }
                        appendLine("- ${r.service}: $cells → $verdict")
                    }
                }
            }
            if (second != null && second.rows.isNotEmpty() && now - second.at in 0..3 * 3_600_000L) {
                appendLine(
                    "- ${second.secondLabel.ifBlank { "второй выход" }} (замер ${hhmm(second.at)}): " +
                        second.rows.joinToString(" · ") { "${it.service} ${describe(it.second)}" }
                )
            }
            if (points.size >= 2 && rows.isNotEmpty()) {
                appendLine()
                val diff = rows.filter { !it.same && it.best.isNotEmpty() }
                val connected = report.best?.config?.endpoint?.render()
                if (diff.isEmpty()) {
                    appendLine(
                        "Итог: разницы между точками нет — точку под приложение выбирать незачем. Разница бывает " +
                            "между выходами (WARP и второй выход) — её ловит автовыбор выхода."
                    )
                } else {
                    appendLine(
                        "Итог: разница есть — " + diff.joinToString(", ") { r -> "${r.service} (лучше ${r.best.joinToString(", ") { MARKS[it] }})" } +
                            ". " + (connected?.let { "Туннель подключается к $it; " } ?: "") +
                            "если эти сервисы важнее, точку можно выбрать вручную из отчёта."
                    )
                }
            }
        }
    }
}
