package dev.warpscout.core.net

import dev.warpscout.core.json.JsonVal
import dev.warpscout.core.json.parseJson
import dev.warpscout.core.model.ResourceCheck
import dev.warpscout.core.model.ResourceResult
import java.io.BufferedReader
import java.net.HttpURLConnection
import java.net.InetAddress
import java.net.SocketTimeoutException
import java.net.URI
import java.net.UnknownHostException
import javax.net.ssl.HostnameVerifier
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLException

/**
 * HTTP(S)-пробы ресурсов и DNS-проверки.
 *
 * Смысл: «доступен/недоступен» в РФ бывает трёх видов — отравленный DNS, RST/TCP-блокировка,
 * блокировка по IP. Различать их можно только сравнивая обычный резолвер с DoH и сравнивая
 * ответ «до» и «после» подключения. Отчёт в приложении строится ровно на этом.
 */
class HttpClient(
    private val timeoutMs: Int = 8000,
    private val followRedirects: Boolean = false,
    /** Локальный SOCKS5 (ByeDPI в режиме прокси). null — ходить напрямую, как раньше. */
    private val proxy: Socks5Endpoint? = null
) {

    data class Response(val status: Int, val body: String, val bytes: Int, val elapsedMs: Long, val headers: Map<String, String>)

    fun get(url: String, headers: Map<String, String> = emptyMap(), maxBytes: Int = 64 * 1024): Response {
        val t0 = System.nanoTime()
        val proxyAddr = proxy?.takeIf { it.configured }?.let { java.net.InetSocketAddress(it.host, it.port) }
        val urlConn = if (proxyAddr != null) URI(url).toURL().openConnection(java.net.Proxy(java.net.Proxy.Type.SOCKS, proxyAddr))
            else URI(url).toURL().openConnection()
        val conn = (urlConn as HttpURLConnection).apply {
            this.connectTimeout = timeoutMs
            readTimeout = timeoutMs
            this.instanceFollowRedirects = followRedirects
            requestMethod = "GET"
            setRequestProperty("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/124 Mobile Safari/537.36")
            setRequestProperty("Accept", "*/*")
            for ((k, v) in headers) setRequestProperty(k, v)
        }
        try {
            val status = conn.responseCode
            val stream = runCatching { conn.inputStream }.getOrElse { conn.errorStream }
            var total = 0
            val sb = StringBuilder()
            if (stream != null) {
                stream.use { input ->
                    val buf = ByteArray(8 * 1024)
                    while (true) {
                        val n = input.read(buf)
                        if (n < 0) break
                        total += n
                        if (sb.length < maxBytes) sb.append(String(buf, 0, n, Charsets.UTF_8))
                        if (total >= maxBytes) break
                    }
                }
            }
            val headers = conn.headerFields.entries
                .filter { it.key != null }
                .associate { (k, v) -> k.lowercase() to v.joinToString(" ") }
            return Response(status, sb.toString(), total, (System.nanoTime() - t0) / 1_000_000, headers)
        } finally {
            runCatching { conn.disconnect() }
        }
    }
}

/** Простой DNS-over-HTTPS клиент (JSON API Cloudflare/Google). */
class DohClient(private val endpoint: String = "https://cloudflare-dns.com/dns-query", private val http: HttpClient = HttpClient(4000)) {

    /** Возвращает список адресов или null, если DoH недоступен. */
    fun resolveA(domain: String): List<String>? = resolve(domain, "A")

    fun resolveAAAA(domain: String): List<String>? = resolve(domain, "AAAA")

    private fun resolve(domain: String, type: String): List<String>? = try {
        val resp = http.get("$endpoint?name=$domain&type=$type", mapOf("Accept" to "application/dns-json"))
        if (resp.status != 200) null else parseAnswers(resp.body)
    } catch (e: Exception) {
        null
    }

    private fun parseAnswers(body: String): List<String> {
        val obj = parseJson(body) as? JsonVal.Obj ?: return emptyList()
        val answers = obj.arr("Answer")?.items ?: return emptyList()
        return answers.mapNotNull { (it as? JsonVal.Obj)?.str("data") }
    }

    companion object {
        const val CLOUDFLARE = "https://cloudflare-dns.com/dns-query"
        const val GOOGLE = "https://dns.google/resolve"
    }
}

enum class DnsVerdict { SAME, DIFFERENT, UNAVAILABLE }

data class DnsCheck(val domain: String, val system: List<String>, val cloudflareDoH: List<String>, val googleDoH: List<String>, val verdict: DnsVerdict) {
    val suspicious: Boolean get() = verdict == DnsVerdict.DIFFERENT
}

class DnsInspector(
    private val cf: DohClient = DohClient(DohClient.CLOUDFLARE),
    private val gg: DohClient = DohClient(DohClient.GOOGLE)
) {
    /**
     * Сверяет системный резолвер с двумя независимыми DoH. Если системный отдаёт адреса, которых нет
     * ни в одном DoH — это отравленный DNS (типично для РФ), и тогда «сайт не открывается» лечится
     * не сменой endpoint'а, а правильными DNS в конфиге.
     */
    fun check(domains: List<String>): List<DnsCheck> = domains.map { d ->
        val sys = runCatching { InetAddress.getAllByName(d).map { it.hostAddress } }.getOrElse { emptyList() }
        val a = cf.resolveA(d)
        val b = gg.resolveA(d)
        val verdict = when {
            a == null && b == null -> DnsVerdict.UNAVAILABLE
            sys.isEmpty() -> DnsVerdict.DIFFERENT
            else -> {
                val trusted = (a ?: emptyList()) + (b ?: emptyList())
                if (trusted.isEmpty() || sys.any { it !in trusted }) DnsVerdict.DIFFERENT else DnsVerdict.SAME
            }
        }
        DnsCheck(d, sys, a ?: emptyList(), b ?: emptyList(), verdict)
    }
}

/** Проверка доступности конкретного ресурса (то, ради чего всё затевалось). */
class ResourceProber(private val http: HttpClient = HttpClient()) {

    fun check(rc: ResourceCheck, viaNote: String = "default"): ResourceResult {
        val started = System.currentTimeMillis()
        val via = if (viaNote == "tunnel") dev.warpscout.core.model.NetworkVia.TUNNEL else dev.warpscout.core.model.NetworkVia.DEFAULT
        // Приложение, а не сайт (Telegram): достучаться до его серверов (с 1.10.30).
        if (rc.url.startsWith(TCP_PREFIX)) return tcpCheck(rc, started).copy(via = via)
        return try {
            val resp = http.get(rc.url, maxBytes = 256 * 1024)
            val verdict = judge(rc, resp.status, resp.body)
            ResourceResult(
                check = rc,
                ok = verdict.ok,
                status = resp.status,
                elapsedMs = System.currentTimeMillis() - started,
                errorClass = verdict.errorClass,
                bytes = resp.bytes,
                detail = verdict.detail
            )
        } catch (e: Exception) {
            ResourceResult(
                check = rc,
                ok = false,
                status = null,
                elapsedMs = System.currentTimeMillis() - started,
                errorClass = classify(e),
                bytes = 0
            )
        }.copy(via = via)
    }

    fun checkAll(checks: List<ResourceCheck>, parallelism: Int = 6): List<ResourceResult> {
        val pool = java.util.concurrent.Executors.newFixedThreadPool(parallelism.coerceIn(1, 16))
        try {
            return checks.map { c -> pool.submit(java.util.concurrent.Callable { check(c) }) }
                .map { runCatching { it.get() }.getOrThrow() }
        } finally {
            pool.shutdownNow()
        }
    }

    /**
     * Прогнать проверки параллельно, но не больше шести разом (с 1.10.30): по одной восемь
     * сервисов и свои сайты ждали бы друг друга до минуты. Порядок результатов — как в списке;
     * отмена — между ответами; недождавшиеся — «нет ответа». Общая для проверки через туннель при
     * подборе и для «Проверить сейчас».
     */
    fun checkParallel(
        checks: List<ResourceCheck>,
        viaNote: String,
        isCancelled: () -> Boolean = { false }
    ): List<ResourceResult> {
        if (checks.isEmpty()) return emptyList()
        val via = if (viaNote == "tunnel") dev.warpscout.core.model.NetworkVia.TUNNEL else dev.warpscout.core.model.NetworkVia.DEFAULT
        val pool = java.util.concurrent.Executors.newFixedThreadPool(checks.size.coerceIn(1, 6))
        try {
            val futures = checks.map { c -> pool.submit(java.util.concurrent.Callable { check(c, viaNote) }) }
            val out = ArrayList<ResourceResult>(checks.size)
            for ((i, f) in futures.withIndex()) {
                if (isCancelled()) break
                val limit = (checks[i].timeoutMs.toLong() * 3).coerceIn(5_000L, 40_000L)
                out += runCatching { f.get(limit, java.util.concurrent.TimeUnit.MILLISECONDS) }.getOrElse {
                    ResourceResult(check = checks[i], ok = false, errorClass = "timeout", via = via)
                }
            }
            return out
        } finally {
            pool.shutdownNow()
        }
    }

    /**
     * Подключение к серверам приложения: `tcp://адрес:порт|адрес:порт` — годится любой. Через туннель
     * это честный ответ «серверы доступны»: соединение устанавливается по ту сторону WARP, а не
     * подтверждается самим телефоном.
     */
    private fun tcpCheck(rc: ResourceCheck, started: Long): ResourceResult {
        val targets = rc.url.removePrefix(TCP_PREFIX).split('|').map { it.trim() }.filter { it.isNotEmpty() }
        var lastError = "no_target"
        for (t in targets) {
            val host = t.substringBeforeLast(':')
            val port = t.substringAfterLast(':', "443").toIntOrNull() ?: 443
            try {
                java.net.Socket().use { s -> s.connect(java.net.InetSocketAddress(host, port), rc.timeoutMs.coerceIn(1_000, 10_000)) }
                return ResourceResult(check = rc, ok = true, elapsedMs = System.currentTimeMillis() - started)
            } catch (e: Exception) {
                lastError = classify(e)
            }
        }
        return ResourceResult(check = rc, ok = false, elapsedMs = System.currentTimeMillis() - started, errorClass = lastError)
    }

    private fun classify(e: Throwable): String = when {
        e is UnknownHostException -> "dns_fail"
        e is SocketTimeoutException -> "timeout"
        e is java.net.ConnectException -> "refused"
        e is java.net.NoRouteToHostException -> "no_route"
        e is SSLException -> "tls_fail"
        e is java.io.IOException -> "io_error"
        else -> e.javaClass.simpleName.lowercase()
    }

    /** Решение по ответу сервера: годится ли, почему нет и что показать человеку. */
    data class Judgement(val ok: Boolean, val errorClass: String?, val detail: String)

    companion object {
        const val TCP_PREFIX = "tcp://"

        /**
         * Чистое решение по ответу — без сети, его проверяет самопроверка ядра. С 1.10.30 для
         * сервисов с запретом по странам (ChatGPT) ответ trace Cloudflare разбирается: «ответил» ещё
         * не значит «пустит» — важно, какую страну видит сайт.
         */
        fun judge(rc: ResourceCheck, status: Int, body: String): Judgement {
            if (status !in rc.expectStatus) return Judgement(false, "http_$status", "")
            if (rc.mustContain != null && !body.contains(rc.mustContain, ignoreCase = true)) {
                return Judgement(false, "content_mismatch", "")
            }
            if (rc.blockedCountries.isNotEmpty()) {
                val loc = Regex("""(?m)^loc=([A-Z]{2})\s*$""").find(body)?.groupValues?.get(1).orEmpty()
                if (loc.isEmpty()) return Judgement(false, "no_country", "")
                if (loc in rc.blockedCountries) return Judgement(false, "region:$loc", loc)
                return Judgement(true, null, loc)
            }
            return Judgement(true, null, "")
        }

        /** Итог проверки словами — для списка «Доступность» и журнала. */
        fun describe(r: ResourceResult): String {
            if (r.ok) {
                val head = if (r.elapsedMs > 0) "открылся, ${r.elapsedMs} мс" else "открылся"
                // detail — страна, которую видит сайт (ChatGPT): «открылся · сайт видит страну NL».
                return if (r.detail.isBlank()) head else "$head · сайт видит страну ${r.detail}"
            }
            val e = r.errorClass.orEmpty()
            return when {
                e.startsWith("region:") -> "сайт видит страну ${e.removePrefix("region:")} — её сервис не обслуживает"
                e == "no_country" -> "сайт ответил без страны — проверить не удалось"
                e == "timeout" -> "нет ответа (истекло время ожидания)"
                e == "dns_fail" -> "имя не нашлось (DNS)"
                e == "refused" -> "соединение отклонено"
                e == "no_route" -> "нет маршрута до сервера"
                e == "tls_fail" -> "защищённое соединение оборвано — похоже на блокировку"
                e == "io_error" -> "соединение оборвалось"
                e == "content_mismatch" -> "ответил не тот сервер (заглушка?)"
                e == "tunnel_not_started" -> "туннель для проверки не поднялся"
                e == "no_target" -> "не задан адрес проверки"
                e == "http_403" -> "сервер отказал (403)"
                e.startsWith("http_") -> "сервер ответил кодом ${e.removePrefix("http_")}"
                e.isBlank() -> "нет ответа"
                else -> e
            }
        }
    }
}

/** Замер скорости через speed.cloudflare.com — удобно показать в отчёте «до/после». */
class ThroughputProbe(private val timeoutMs: Int = 15000) {

    data class Result(val mbps: Double, val bytes: Int, val elapsedMs: Long, val error: String?)

    fun measure(bytes: Int = 2_000_000, url: String = "http://speed.cloudflare.com/__down"): Result {
        val t0 = System.currentTimeMillis()
        return try {
            val conn = (URI("$url?bytes=$bytes").toURL().openConnection() as HttpURLConnection).apply {
                connectTimeout = timeoutMs
                readTimeout = timeoutMs
                instanceFollowRedirects = true
            }
            var total = 0
            conn.inputStream.use { input ->
                val buf = ByteArray(32 * 1024)
                while (true) {
                    val n = input.read(buf)
                    if (n < 0) break
                    total += n
                    if (total >= bytes) break
                }
            }
            val ms = (System.currentTimeMillis() - t0).coerceAtLeast(1)
            Result(total * 8.0 / 1_000_000.0 * 1000.0 / ms, total, ms, null)
        } catch (e: Exception) {
            Result(0.0, 0, System.currentTimeMillis() - t0, e.javaClass.simpleName)
        }
    }
}
