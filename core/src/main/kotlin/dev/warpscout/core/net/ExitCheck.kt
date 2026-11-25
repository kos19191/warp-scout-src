package dev.warpscout.core.net

import dev.warpscout.core.tunnel.ExitRouter
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.net.InetSocketAddress
import java.net.Socket
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLSession
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

/**
 * Проверка второго выхода (с 1.10.32): из какой страны на самом деле выходит запрос к сайту,
 * который должен идти через свой сервер.
 *
 * Зачем отдельно. В 1.10.31 проверка просто открывала `https://chatgpt.com/cdn-cgi/trace`: адрес
 * сайта выбирала система. Если он не совпадал с теми, что собраны для второго выхода (Cloudflare
 * отдаёт разные адреса), запрос уходил через WARP или мимо туннеля, и экран писал «второй выход
 * отвечает из России» — вина приписывалась своему серверу, хотя до него запрос не доходил. Поле
 * `warp` в ответе не смотрели вовсе. Человек (22.11) так и написал: «не понял, как работает и
 * работает ли».
 *
 * Теперь запрос идёт на адрес, который точно лежит в таблице второго выхода ([pickRouted]), с
 * правильным именем сайта в TLS ([fetchTrace]), а ответ разбирается честно ([verdict]): ушло через
 * WARP — так и пишем, а не «Россия».
 */
object ExitCheck {

    /** Проверка не прошла: [Result.detail] — причина словами. */
    const val FAIL = "!"

    /** Ответ пришёл через WARP: второй выход запрос не принял. */
    const val VIA_WARP = "W"

    /** Адрес сайта не входит в маршруты туннеля: новые адреса заработают после переподключения. */
    const val NOT_ROUTED = "R"

    /**
     * Итог. [code] — страна выхода («NL»), «RU» или [FAIL] / [VIA_WARP] / [NOT_ROUTED];
     * [detail] — адрес выхода или причина; [ms] — сколько шёл ответ (-1 — неизвестно).
     */
    data class Result(val code: String, val detail: String, val at: Long, val ms: Int = -1) {
        /** Выход в другой стране — то, ради чего второй выход и нужен. */
        val ok: Boolean get() = isCountry(code) && code != "RU"

        /** Строка для настроек: «NL|1.2.3.4|время|мс» (поле мс — с 1.10.32, старые строки без него). */
        fun encode(): String =
            listOf(code, detail.replace('|', '/').replace('\n', ' '), at.toString()).joinToString("|") +
                if (ms >= 0) "|$ms" else ""
    }

    private fun isCountry(code: String) = code.length == 2 && code.all { it in 'A'..'Z' }

    /**
     * Страна второго выхода для строки «где мы» под кнопкой (с 1.10.40): «мобильная · вход … · выход RU
     * · второй выход NL». null — второй выход в этой сессии не поднят (тогда о нём не пишем: «если
     * второго нет, просто не пиши», 23.11); "" — поднят, а страна неизвестна. Страна — по имени сервера
     * Proton [peer] («NL-FREE#121» → NL): оно всегда про тот сервер, что работает сейчас. Свой сервер
     * ([peer] пустой) — по последней проверке второго выхода [check]: адрес у него один, страна та же.
     */
    fun secondCountry(up: Boolean, peer: String, check: Result?): String? {
        if (!up) return null
        val byName = peer.trim().substringBefore('-').uppercase()
        if (isCountry(byName)) return byName
        return check?.code?.takeIf { isCountry(it) }.orEmpty()
    }

    /** Разобрать строку из настроек (и прежнего формата «DE|адрес|время»). null — проверки не было. */
    fun decode(text: String?): Result? {
        val parts = text.orEmpty().split('|')
        if (parts.size < 3) return null
        val at = parts[2].trim().toLongOrNull() ?: return null
        val code = parts[0].trim()
        if (code.isEmpty()) return null
        return Result(code, parts[1].trim(), at, parts.getOrNull(3)?.trim()?.toIntOrNull() ?: -1)
    }

    /** Вердикт по ответу trace. [error] — почему ответа нет (если его нет). */
    fun verdict(trace: CfTrace?, error: String?, at: Long, ms: Int = -1): Result = when {
        trace == null -> Result(FAIL, error?.takeIf { it.isNotBlank() } ?: "ответ не похож на Cloudflare", at)
        trace.viaWarp -> Result(VIA_WARP, trace.ip, at, ms)
        !isCountry(trace.loc.uppercase()) -> Result(FAIL, "в ответе нет страны", at)
        else -> Result(trace.loc.uppercase(), trace.ip, at, ms)
    }

    /**
     * Из адресов сайта — тот, что идёт во второй выход по таблице [router]. IPv4 — первым: у
     * второго выхода может не быть IPv6. null — ни один адрес в таблицу не попал.
     */
    fun pickRouted(addresses: List<String>, router: ExitRouter): String? {
        val routed = addresses.map { it.trim() }.filter { a ->
            // Только записи адресов: ExitRouter.ipBytes на имени сайта пошёл бы в DNS.
            isIpLiteral(a) && ExitRouter.ipBytes(a)?.let { router.route(it) == 1 } == true
        }
        return routed.firstOrNull { ':' !in it } ?: routed.firstOrNull()
    }

    /**
     * Все адреса сайта, что идут во второй выход по таблице [router] (с 1.10.44-beta3): IPv4 — первыми,
     * без повторов, не больше [limit]. Проверка пробует их по очереди: журнал 24.11, 14:50 — первый
     * подходящий адрес chatgpt.com (8.6.112.0) через второй выход не ответил, и проверка написала «нет
     * ответа», хотя через минуту по другому адресу всё работало.
     */
    fun routedAll(addresses: List<String>, router: ExitRouter, limit: Int = 3): List<String> {
        val routed = addresses.map { it.trim() }.filter { a ->
            isIpLiteral(a) && ExitRouter.ipBytes(a)?.let { router.route(it) == 1 } == true
        }.distinct()
        return (routed.filter { ':' !in it } + routed.filter { ':' in it }).take(limit)
    }

    private val V4 = Regex("^\\d{1,3}(\\.\\d{1,3}){3}$")

    /** Запись адреса IPv4 или IPv6 (а не имя сайта): такую можно разбирать, не спрашивая DNS. */
    fun isIpLiteral(a: String): Boolean =
        V4.matches(a) || (':' in a && a.all { it.isDigit() || it in 'a'..'f' || it in 'A'..'F' || it == ':' || it == '.' })

    /** Ответ HTTP: код (-1 — не HTTP) и тело. */
    data class HttpReply(val code: Int, val body: String)

    /**
     * Разобрать сырой ответ HTTP/1.x. Просим HTTP/1.0, поэтому тело обычно идёт как есть; если
     * сервер всё же ответил по частям (chunked), склеиваем их.
     */
    fun parseHttp(raw: ByteArray): HttpReply {
        val text = String(raw, Charsets.ISO_8859_1)
        val headEnd = text.indexOf("\r\n\r\n").takeIf { it >= 0 } ?: return HttpReply(-1, "")
        val head = text.substring(0, headEnd).split("\r\n")
        val status = head.firstOrNull().orEmpty()
        if (!status.startsWith("HTTP/")) return HttpReply(-1, "")
        val code = status.split(' ').getOrNull(1)?.toIntOrNull() ?: return HttpReply(-1, "")
        val chunked = head.drop(1).any { line ->
            line.substringBefore(':').trim().equals("Transfer-Encoding", ignoreCase = true) &&
                line.substringAfter(':').contains("chunked", ignoreCase = true)
        }
        val bodyBytes = raw.copyOfRange(headEnd + 4, raw.size)
        val body = if (chunked) dechunk(bodyBytes) else bodyBytes
        return HttpReply(code, String(body, Charsets.UTF_8))
    }

    private fun dechunk(data: ByteArray): ByteArray {
        val out = ByteArrayOutputStream()
        var pos = 0
        while (pos < data.size) {
            var lineEnd = pos
            while (lineEnd + 1 < data.size && !(data[lineEnd] == '\r'.code.toByte() && data[lineEnd + 1] == '\n'.code.toByte())) lineEnd++
            if (lineEnd + 1 >= data.size) break
            val size = String(data, pos, lineEnd - pos, Charsets.ISO_8859_1).substringBefore(';').trim().toIntOrNull(16) ?: break
            if (size <= 0) break
            val start = lineEnd + 2
            val end = minOf(start + size, data.size)
            out.write(data, start, end - start)
            pos = end + 2
        }
        return out.toByteArray()
    }

    /**
     * `GET /cdn-cgi/trace` на адрес [ip] с именем [host] в TLS (SNI) и в заголовке Host: запрос
     * идёт ровно туда, куда нужно проверить, а сертификат проверяется по имени сайта. [verify] —
     * проверка имени платформой (на Android — стандартная HostnameVerifier); сверх неё имя проверяет
     * и сама TLS (endpointIdentificationAlgorithm = HTTPS). Возвращает тело ответа; ошибка —
     * исключением с понятным текстом.
     */
    fun fetchTrace(
        ip: String,
        host: String,
        timeoutMs: Int = 7000,
        userAgent: String = "WilyScout",
        verify: ((String, SSLSession) -> Boolean)? = null,
        socket: () -> Socket = { Socket() },
    ): String {
        val raw = socket()
        try {
            raw.soTimeout = timeoutMs
            raw.connect(InetSocketAddress(ip, 443), timeoutMs)
            val factory = SSLSocketFactory.getDefault() as SSLSocketFactory
            val tls = factory.createSocket(raw, host, 443, true) as SSLSocket
            tls.use { s ->
                s.soTimeout = timeoutMs
                val params = s.sslParameters
                params.serverNames = listOf(SNIHostName(host))
                params.endpointIdentificationAlgorithm = "HTTPS"
                s.sslParameters = params
                s.startHandshake()
                if (verify != null && !verify(host, s.session)) throw IOException("сертификат не для $host")
                val request = "GET /cdn-cgi/trace HTTP/1.0\r\n" +
                    "Host: $host\r\n" +
                    "User-Agent: $userAgent\r\n" +
                    "Accept: text/plain\r\n" +
                    "Cache-Control: no-cache\r\n" +
                    "Connection: close\r\n\r\n"
                s.outputStream.apply {
                    write(request.toByteArray(Charsets.ISO_8859_1))
                    flush()
                }
                val buf = ByteArrayOutputStream()
                val chunk = ByteArray(4096)
                s.inputStream.use { input ->
                    while (buf.size() < 16 * 1024) {
                        val n = input.read(chunk)
                        if (n < 0) break
                        buf.write(chunk, 0, n)
                    }
                }
                val reply = parseHttp(buf.toByteArray())
                if (reply.code !in 200..299) throw IOException(if (reply.code < 0) "ответ не HTTP" else "HTTP ${reply.code}")
                return reply.body
            }
        } finally {
            runCatching { raw.close() }
        }
    }
}
