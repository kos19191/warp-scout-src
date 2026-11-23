package dev.warpscout.core.net

import java.io.BufferedInputStream
import java.io.IOException
import java.io.InputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketTimeoutException
import java.net.URI
import java.security.cert.X509Certificate
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLPeerUnverifiedException
import javax.net.ssl.SSLSession
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

/**
 * Честная проверка Telegram (с 1.10.34): не только «соединение открылось», но и «данные идут
 * ровно». Здесь правила без сети — сеть делает сервис (WarpVpnService.runTelegramMedia).
 *
 * Зачем. Журнал 23.11: проверка связи писала «Telegram ✓ 120 мс», а медиа грузилось «через раз и
 * рывками». Проверка была TCP-соединением с сервером Telegram, а фильтры на московской площадке
 * Cloudflare соединение пропускают и режут уже поток: скорость падает до десятков килобайт в
 * секунду или данные встают посреди файла. Небольшая загрузка с серверов Telegram (до 256 КБ, с
 * отметками времени каждого куска) видит и то, и другое.
 *
 * Загрузка ([fetch]) идёт по IPv4 и своим сокетом, а не через HttpURLConnection: Telegram ходит по
 * IPv4, пока он есть, и фильтры режут именно IPv4 (по IPv6 через ту же площадку медиа проходит). В
 * туннеле IPv6 включён по умолчанию, и системный HTTP выбрал бы IPv6 — проверка писала бы «медиа ✓»,
 * пока сам Telegram тормозит.
 */
object TelegramMedia {

    /**
     * IPv4-сети Telegram (haritos90/allow-domains, Subnets/IPv4/04-telegram.lst, ноябрь 2026). Они же
     * идут во второй выход, когда WARP выходит через Россию (см. WarpVpnService.applyTelegramRoute).
     * IPv6 не берём: свой сервер второго выхода и Proton Free часто без IPv6, а Telegram сам ходит по
     * IPv4, пока IPv4 есть.
     */
    val NETS_V4: List<String> = listOf(
        "91.105.192.0/23", "91.108.4.0/22", "91.108.8.0/21", "91.108.16.0/21",
        "91.108.56.0/22", "95.161.64.0/20", "149.154.160.0/20", "185.76.151.0/24"
    )

    /**
     * Что загружаем: официальный APK Telegram для Android (telegram.org, ~70 МБ). Читаем только
     * начало ([PROBE_BYTES]) и закрываем соединение. Сервер — в сетях Telegram (149.154.160.0/20);
     * если перенаправит за их пределы, вывод о медиа не делаем (см. [NOT_TELEGRAM]).
     */
    const val PROBE_URL = "https://telegram.org/dl/android/apk"

    /** Сколько читаем: хватает и на скорость, и на «встало посреди». */
    const val PROBE_BYTES = 256 * 1024

    /** Дольше этого читать не нужно — скорость уже видна. */
    const val PROBE_MAX_MS = 6_000L

    /** Пауза в потоке дольше этого — «встало». */
    const val STALL_MS = 2_500L

    /** Пауза дольше этого — «рывками». */
    const val JERK_MS = 1_200L

    /** Медленнее этого (Кбит/с) — «тормозит»: фото в полэкрана грузилось бы секундами. */
    const val SLOW_KBPS = 1_000

    /** Не проверяли (или проверка не показательна). */
    const val UNKNOWN = 0
    /** Данные идут ровно и быстро. */
    const val OK = 1
    /** Идут, но медленно или рывками. */
    const val SLOW = 2
    /** Пошли и встали. */
    const val STALL = 3
    /** Ни байта: сервер не ответил на загрузку. */
    const val FAIL = 4
    /** Загрузка ушла не на сервер Telegram — о медиа Telegram она ничего не говорит. */
    const val NOT_TELEGRAM = 5

    /** Адрес IPv4 в сетях Telegram. */
    fun isTelegramIp(ip: String?): Boolean {
        val v = ipv4(ip) ?: return false
        return NETS_V4.any { inPrefix(v, it) }
    }

    /**
     * Вывод по загрузке: [bytes] прочитано за [elapsedMs] от первого байта, самая долгая пауза между
     * кусками — [maxGapMs], [complete] — дочитали до цели (или до конца файла).
     */
    fun verdict(bytes: Long, elapsedMs: Long, maxGapMs: Long, complete: Boolean): Int {
        if (bytes <= 0L) return FAIL
        if (!complete && maxGapMs >= STALL_MS) return STALL
        val kbps = kbps(bytes, elapsedMs)
        if (kbps in 0 until SLOW_KBPS) return SLOW
        if (maxGapMs >= JERK_MS) return SLOW
        return OK
    }

    /** Скорость в Кбит/с; −1 — не посчитать. */
    fun kbps(bytes: Long, elapsedMs: Long): Int {
        if (bytes <= 0L) return -1
        val ms = elapsedMs.coerceAtLeast(1L)
        return (bytes * 8L / ms).coerceAtMost(Int.MAX_VALUE.toLong()).toInt()
    }

    /** Самый короткий ответ, по которому ещё можно судить о скорости. */
    const val MIN_BYTES = 32 * 1024

    /** Сколько перенаправлений проходим. */
    const val MAX_HOPS = 5

    /** Сколько ждём соединения (TCP и TLS). */
    const val CONNECT_MS = 5_000

    /**
     * Итог загрузки: вывод ([OK], [SLOW], …), скорость в Кбит/с (−1 — не посчитать), самая долгая
     * пауза между кусками, сколько прочитано, с какого адреса (пусто — до соединения не дошло) и
     * пояснение для журнала.
     */
    data class Fetch(
        val verdict: Int,
        val kbps: Int,
        val maxGapMs: Long,
        val bytes: Long,
        val ip: String,
        val note: String
    )

    /** Открыть соединение с адресом [ip] для имени [host]: в приложении — [TLS], в SelfCheck — простой TCP. */
    fun interface Connector {
        fun open(ip: String, host: String, port: Int, timeoutMs: Int): Socket
    }

    /**
     * TLS поверх обычного сокета (через туннель, если процесс в нём): соединяемся именно с адресом
     * IPv4, имя передаём в SNI и сверяем с сертификатом (цепочку проверяет системное хранилище).
     */
    val TLS: Connector = Connector { ip, host, port, timeoutMs ->
        val raw = Socket()
        try {
            raw.connect(InetSocketAddress(InetAddress.getByName(ip), port), timeoutMs)
            raw.soTimeout = timeoutMs
            val ssl = (SSLSocketFactory.getDefault() as SSLSocketFactory).createSocket(raw, host, port, true) as SSLSocket
            val params = ssl.sslParameters
            params.serverNames = listOf(SNIHostName(host))
            params.endpointIdentificationAlgorithm = "HTTPS"
            ssl.sslParameters = params
            ssl.startHandshake()
            if (!certMatches(ssl.session, host)) {
                runCatching { ssl.close() }
                throw SSLPeerUnverifiedException("сертификат не для $host")
            }
            ssl
        } catch (e: Exception) {
            runCatching { raw.close() }
            throw e
        }
    }

    /** Имя [host] есть в сертификате сервера (subjectAltName; «*.» — ровно один уровень). */
    fun certMatches(session: SSLSession, host: String): Boolean {
        val cert = runCatching { session.peerCertificates.firstOrNull() as? X509Certificate }.getOrNull() ?: return false
        val names = runCatching { cert.subjectAlternativeNames }.getOrNull().orEmpty()
            .filter { (it.getOrNull(0) as? Int) == 2 }
            .mapNotNull { it.getOrNull(1) as? String }
        return names.any { nameMatches(it, host) }
    }

    /** «telegram.org» подходит к «telegram.org», «a.telegram.org» — к «*.telegram.org», «a.b.telegram.org» — нет. */
    fun nameMatches(pattern: String, host: String): Boolean {
        val p = pattern.trim().lowercase().trimEnd('.')
        val h = host.trim().lowercase().trimEnd('.')
        if (p.isEmpty() || h.isEmpty()) return false
        if (!p.startsWith("*.")) return p == h
        val suffix = p.substring(1)
        if (!h.endsWith(suffix)) return false
        val label = h.substring(0, h.length - suffix.length)
        return label.isNotEmpty() && '.' !in label
    }

    /**
     * Загрузка начала файла [url] с проверкой, что сервер — в сетях Telegram ([accept]); перенаправления
     * (до [MAX_HOPS]) проходим сами и каждый раз проверяем адрес заново: ушли за пределы сетей Telegram —
     * [NOT_TELEGRAM], о медиа Telegram такая загрузка ничего не скажет. [resolve] — адреса имени (в
     * приложении — системный DNS через туннель). Пауза дольше [readTimeoutMs] посреди тела — «встало».
     */
    fun fetch(
        url: String = PROBE_URL,
        resolve: (String) -> List<String>,
        connector: Connector = TLS,
        accept: (String) -> Boolean = ::isTelegramIp,
        readTimeoutMs: Int = (STALL_MS + 500).toInt(),
        maxBytes: Int = PROBE_BYTES,
        maxMs: Long = PROBE_MAX_MS,
        now: () -> Long = System::currentTimeMillis
    ): Fetch {
        var current = url
        val scheme = runCatching { URI(url).scheme.orEmpty().lowercase() }.getOrDefault("")
        for (hop in 0 until MAX_HOPS) {
            val target = Target.of(current) ?: return Fetch(UNKNOWN, -1, 0L, 0L, "", "адрес не разобран: ${current.take(60)}")
            if (target.scheme != scheme) return Fetch(UNKNOWN, -1, 0L, 0L, "", "перенаправление на ${target.scheme}")
            val v4 = runCatching { resolve(target.host) }.getOrDefault(emptyList())
                .map { it.trim() }
                .filter { ipv4(it) != null }
                .distinct()
            if (v4.isEmpty()) return Fetch(FAIL, -1, 0L, 0L, "", "${target.host} не разрешился в адрес IPv4")
            val ip = v4.firstOrNull(accept) ?: return Fetch(NOT_TELEGRAM, -1, 0L, 0L, v4.first(), "${target.host} → ${v4.first()}")
            val socket = try {
                connector.open(ip, target.host, target.port, CONNECT_MS)
            } catch (e: Exception) {
                return Fetch(FAIL, -1, 0L, 0L, ip, "соединение с ${target.host}: ${e.javaClass.simpleName} ${e.message.orEmpty().take(50)}")
            }
            try {
                socket.soTimeout = readTimeoutMs
                val request = "GET ${target.path} HTTP/1.1\r\n" +
                    "Host: ${target.hostHeader}\r\n" +
                    "User-Agent: WarpScout\r\n" +
                    "Accept: */*\r\n" +
                    "Accept-Encoding: identity\r\n" +
                    "Range: bytes=0-${maxBytes - 1}\r\n" +
                    "Connection: close\r\n\r\n"
                val input = try {
                    val out = socket.getOutputStream()
                    out.write(request.toByteArray(Charsets.ISO_8859_1))
                    out.flush()
                    BufferedInputStream(socket.getInputStream(), 16 * 1024)
                } catch (e: IOException) {
                    return Fetch(FAIL, -1, 0L, 0L, ip, "запрос не ушёл: ${e.javaClass.simpleName}")
                }
                val parsed: Head? = try {
                    readHead(input)
                } catch (e: SocketTimeoutException) {
                    return Fetch(FAIL, -1, 0L, 0L, ip, "нет ответа от ${target.host} за ${readTimeoutMs / 1000.0} с")
                } catch (e: IOException) {
                    return Fetch(FAIL, -1, 0L, 0L, ip, "ответ оборвался: ${e.javaClass.simpleName}")
                }
                val head = parsed ?: return Fetch(FAIL, -1, 0L, 0L, ip, "ответ не HTTP")
                if (head.code in 300..399) {
                    val location = head.headers["location"].orEmpty().trim()
                    if (location.isEmpty()) return Fetch(UNKNOWN, -1, 0L, 0L, ip, "перенаправление без адреса")
                    current = runCatching { URI(current).resolve(location).toString() }.getOrNull()
                        ?: return Fetch(UNKNOWN, -1, 0L, 0L, ip, "перенаправление не разобрано")
                    continue
                }
                if (head.code !in 200..299) return Fetch(FAIL, -1, 0L, 0L, ip, "HTTP ${head.code} от ${target.host}")
                val expected = head.headers["content-length"]?.trim()?.toLongOrNull()?.takeIf { it > 0L }
                return readBody(input, expected, maxBytes.toLong(), maxMs, now, ip, target.host)
            } finally {
                runCatching { socket.close() }
            }
        }
        return Fetch(UNKNOWN, -1, 0L, 0L, "", "слишком много перенаправлений")
    }

    /** Тело ответа: время каждого куска, самая долгая пауза, вывод. */
    private fun readBody(
        input: InputStream,
        expected: Long?,
        maxBytes: Long,
        maxMs: Long,
        now: () -> Long,
        ip: String,
        host: String
    ): Fetch {
        val limit = if (expected != null) minOf(expected, maxBytes) else maxBytes
        val buf = ByteArray(16 * 1024)
        val start = now()
        var last = start
        var total = 0L
        var maxGap = 0L
        var eof = false
        var cut = false
        while (total < limit) {
            val want = minOf(buf.size.toLong(), limit - total).toInt()
            val n = try {
                input.read(buf, 0, want)
            } catch (e: SocketTimeoutException) {
                // Тишина дольше таймаута чтения — это и есть «встало».
                maxGap = maxOf(maxGap, now() - last)
                cut = true
                break
            } catch (e: IOException) {
                // Соединение оборвали посреди тела — для человека то же «встало».
                maxGap = maxOf(maxGap, STALL_MS)
                cut = true
                break
            }
            val t = now()
            if (n < 0) {
                eof = true
                break
            }
            maxGap = maxOf(maxGap, t - last)
            last = t
            total += n
            if (t - start >= maxMs) break
        }
        // Конец тела без обещанной длины (Connection: close) — это и есть весь ответ.
        val complete = total >= limit || (eof && expected == null)
        if (eof && !complete) cut = true
        val ms = (last - start).coerceAtLeast(1L)
        val speed = kbps(total, ms)
        val verdict = when {
            total <= 0L -> FAIL
            cut && total < limit / 2 -> STALL
            complete && total < MIN_BYTES -> UNKNOWN
            else -> verdict(total, ms, maxGap, complete || total >= limit / 2)
        }
        val note = "${total / 1024} КБ с $host ($ip)" +
            if (verdict == UNKNOWN) " — ответ слишком короткий, скорость не посчитать" else ""
        return Fetch(verdict, if (total > 0L) speed else -1, maxGap, total, ip, note)
    }

    /** Статус и заголовки ответа (имена — строчными). */
    private class Head(val code: Int, val headers: Map<String, String>)

    /** Читаем заголовки до пустой строки (не больше 32 КБ); null — это не HTTP. */
    private fun readHead(input: InputStream): Head? {
        val bytes = java.io.ByteArrayOutputStream()
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

    /** Итог словами — для журнала. */
    fun describe(verdict: Int, kbps: Int, maxGapMs: Long): String = when (verdict) {
        OK -> "медиа ✓ ${SpeedTest.human(kbps)}"
        SLOW -> if (kbps in 0 until SLOW_KBPS) {
            "медиа тормозит: ${SpeedTest.human(kbps)}"
        } else {
            "медиа рывками: пауза ${maxGapMs / 100 / 10.0} с при ${SpeedTest.human(kbps)}"
        }
        STALL -> "медиа встаёт: данные остановились посреди загрузки"
        FAIL -> "медиа ✗ загрузка не пошла"
        NOT_TELEGRAM -> "медиа не проверено: загрузка ушла не на сервер Telegram"
        else -> "медиа не проверено"
    }

    private fun ipv4(ip: String?): Long? {
        val p = ip.orEmpty().trim().split('.')
        if (p.size != 4) return null
        var v = 0L
        for (part in p) {
            val n = part.toIntOrNull() ?: return null
            if (n !in 0..255) return null
            v = (v shl 8) or n.toLong()
        }
        return v
    }

    private fun inPrefix(ip: Long, cidr: String): Boolean {
        val base = ipv4(cidr.substringBefore('/')) ?: return false
        val bits = cidr.substringAfter('/', "").toIntOrNull()?.takeIf { it in 0..32 } ?: return false
        if (bits == 0) return true
        val mask = (0xFFFFFFFFL shl (32 - bits)) and 0xFFFFFFFFL
        return (ip and mask) == (base and mask)
    }
}
