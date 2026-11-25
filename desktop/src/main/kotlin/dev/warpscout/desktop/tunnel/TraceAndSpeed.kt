package dev.warpscout.desktop.tunnel

import dev.warpscout.core.json.JsonVal
import dev.warpscout.core.json.parseJson
import dev.warpscout.core.net.HttpClient
import java.net.HttpURLConnection
import java.net.URI

data class ExitInfo(
    val colo: String = "",
    val loc: String = "",
    val ip: String = "",
    val warpOn: Boolean = false,
    val city: String = "",
    val country: String = "",
    val org: String = ""
) {
    /** Краткая метка региона выхода: например «HEL · RU» или «AMS · NL». */
    fun regionLabel(): String {
        val parts = buildList {
            if (colo.isNotBlank()) add(colo)
            val cc = country.ifBlank { loc }
            if (cc.isNotBlank()) add(cc)
            if (city.isNotBlank() && city != colo) add(city)
        }
        return if (parts.isEmpty()) "не определён" else parts.joinToString(" · ")
    }
}

data class SpeedTestResult(
    val downloadMbps: Double,
    val latencyMs: Long,
    val bytesDownloaded: Long,
    val elapsedMs: Long,
    val error: String? = null
) {
    val ok: Boolean get() = error == null && downloadMbps > 0.0
}

object TraceAndSpeed {

    /** Разбор key=value ответа `https://www.cloudflare.com/cdn-cgi/trace`. */
    fun parseCloudflareTrace(body: String): Map<String, String> =
        body.lineSequence()
            .map { it.trim() }
            .filter { '=' in it }
            .associate { line ->
                val idx = line.indexOf('=')
                line.substring(0, idx).trim() to line.substring(idx + 1).trim()
            }

    /** Разбор `https://ipinfo.io/json`. */
    fun parseIpInfo(body: String): Triple<String, String, String> {
        val obj = runCatching { parseJson(body) as? JsonVal.Obj }.getOrNull() ?: return Triple("", "", "")
        return Triple(
            obj.str("city").orEmpty(),
            obj.str("country").orEmpty(),
            obj.str("org").orEmpty()
        )
    }

    /** Определяет регион выхода WARP, признак `warp=on` и внешний IP. */
    fun probeExitInfo(http: HttpClient = HttpClient(timeoutMs = 4500)): ExitInfo {
        val traceMap = runCatching {
            val r = http.get("https://www.cloudflare.com/cdn-cgi/trace")
            if (r.status in 200..299) parseCloudflareTrace(r.body) else emptyMap()
        }.getOrDefault(emptyMap())

        // Если даже cloudflare/trace не ответил — не тратим ещё 5–10 секунд на ipinfo.io.
        val ipInfo = if (traceMap.isNotEmpty()) {
            runCatching {
                val r = http.get("https://ipinfo.io/json")
                if (r.status in 200..299) parseIpInfo(r.body) else Triple("", "", "")
            }.getOrDefault(Triple("", "", ""))
        } else {
            Triple("", "", "")
        }

        val warp = traceMap["warp"].orEmpty().equals("on", ignoreCase = true) ||
            traceMap["warp"].orEmpty().equals("plus", ignoreCase = true)

        return ExitInfo(
            colo = traceMap["colo"].orEmpty(),
            loc = traceMap["loc"].orEmpty(),
            ip = traceMap["ip"].orEmpty(),
            warpOn = warp,
            city = ipInfo.first,
            country = ipInfo.second,
            org = ipInfo.third
        )
    }

    /** Замер скорости загрузки через `speed.cloudflare.com` (10 МБ) и задержки до Cloudflare. */
    fun measureSpeed(bytesToFetch: Long = 10_000_000L, timeoutMs: Int = 12_000): SpeedTestResult {
        val latency = runCatching {
            val t0 = System.nanoTime()
            HttpClient(timeoutMs = 4000).get("https://www.cloudflare.com/cdn-cgi/trace")
            (System.nanoTime() - t0) / 1_000_000L
        }.getOrDefault(0L)

        return try {
            val url = "https://speed.cloudflare.com/__down?bytes=$bytesToFetch"
            val conn = (URI(url).toURL().openConnection() as HttpURLConnection).apply {
                connectTimeout = timeoutMs
                readTimeout = timeoutMs
                requestMethod = "GET"
                setRequestProperty("User-Agent", "WarpScout-Desktop")
            }
            val t0 = System.nanoTime()
            var total = 0L
            try {
                if (conn.responseCode !in 200..299) {
                    return SpeedTestResult(0.0, latency, 0L, 0L, "HTTP ${conn.responseCode}")
                }
                conn.inputStream.use { input ->
                    val buf = ByteArray(32 * 1024)
                    while (true) {
                        val n = input.read(buf)
                        if (n < 0) break
                        total += n
                    }
                }
            } finally {
                runCatching { conn.disconnect() }
            }
            val elapsedMs = ((System.nanoTime() - t0) / 1_000_000L).coerceAtLeast(1L)
            val mbps = (total * 8.0) / (elapsedMs / 1000.0) / 1_000_000.0
            SpeedTestResult(
                downloadMbps = mbps,
                latencyMs = latency,
                bytesDownloaded = total,
                elapsedMs = elapsedMs
            )
        } catch (e: Exception) {
            SpeedTestResult(0.0, latency, 0L, 0L, "${e.javaClass.simpleName}: ${e.message}")
        }
    }
}
