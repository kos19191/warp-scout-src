package dev.warpscout.core.dpi

import dev.warpscout.core.model.ResourceCheck
import dev.warpscout.core.net.HttpClient
import dev.warpscout.core.net.Socks5Endpoint
import java.net.URI

/**
 * «Это режет DPI или режут IP?» — сравнение одних и тех же запросов напрямую и через локальный
 * SOCKS5 (ByeDPI/GoodbyDPI), то есть до и после обхода DPI.
 *
 * Почему так, а не «повторить трюки GoodbyDPI у себя»: GoodbyDPI/ByeDPI меняют сами TCP-пакеты
 * (фрагментация заголовка, фейные сегменты, TTL, рассинхрон SEQ). В обычном Android-сокете такого
 * языка нет: `Socket` не даёт ни фрагментировать TCP, ни поставить TTL, ни отправить фейный сегмент —
 * это уровень ядра/`raw socket` (root) или userspace-стек, как у ByeDPI (он и есть userspace-стек,
 * а Android-приложение вокруг него лишь поднимает tun + SOCKS5). Поэтому правильное поведение
 * приложения — не копировать трюки, а **использовать** уже сделанный обход и честно измерить, что он
 * меняет. Отсюда и вердикты ниже.
 */
enum class DpiOutcome {
    /** Открыто и так, и через прокси: блокировки нет, трогать ничего не надо. */
    OPEN_BOTH,

    /** Лежит напрямую, открывается через ByeDPI → блокировка похожа на DPI-эвристики, а не на IP. */
    OPEN_ONLY_VIA_PROXY,

    /** Напрямую работает, через ByeDPI нет → мешают настройки обхода (обычно frag/split/fake). */
    OPEN_ONLY_DIRECT,

    /** Не открывается ни так, ни так → это IP/маршрутная блокировка, лечится WARP-обходом. */
    BLOCKED_BOTH,

    /** Прокси не отвечает — сравнение несерьёзно, надо сначала поднять ByeDPI в режим прокси. */
    PROXY_UNREACHABLE
}

data class DpiRow(
    val name: String,
    val url: String,
    val direct: String,
    val viaProxy: String,
    val directOk: Boolean,
    val proxyOk: Boolean,
    val outcome: DpiOutcome
)

data class DpiComparison(
    val proxy: Socks5Endpoint,
    val rows: List<DpiRow>,
    /** Что вернул сам прокси на CONNECT первой пробы — для диагностики «порт не тот». */
    val proxyError: String? = null
) {
    val usable: Boolean get() = rows.isNotEmpty() && rows.none { it.outcome == DpiOutcome.PROXY_UNREACHABLE }

    val dpiShaped: Int get() = rows.count { it.outcome == DpiOutcome.OPEN_ONLY_VIA_PROXY }
    val ipShaped: Int get() = rows.count { it.outcome == DpiOutcome.BLOCKED_BOTH }
    val cleanCount: Int get() = rows.count { it.outcome == DpiOutcome.OPEN_BOTH }

    /** Главный вывод одним предложением — его показываем в UI и пишем в отчёт. */
    fun headline(): String = when {
        rows.isEmpty() -> "нечего сравнивать: список ресурсов пуст"
        !usable -> "ByeDPI не отвечает на ${proxy.render()}: $proxyError. " +
            "В приложении ByeDPI включи «режим прокси» (SOCKS5), а не режим VPN — два VPN одновременно Android не даёт."
        dpiShaped > 0 && ipShaped == 0 ->
            "DPI-блокировки: $dpiShaped из ${rows.size} ресурсов оживают через ByeDPI → чинится настройками обхода, endpoint WARP тут не при чём"
        ipShaped > 0 && dpiShaped == 0 ->
            "через ByeDPI всё равно лежат: $ipShaped из ${rows.size} → это блокировка по IP/маршруту, нужен подобранный endpoint WARP"
        ipShaped > 0 && dpiShaped > 0 ->
            "смешанный случай: $dpiShaped ресурсов чинит ByeDPI, $ipShaped — только WARP; нужны оба слоя"
        else -> "блокировок не видно: ${cleanCount}/${rows.size} ресурсов открыты и напрямую, и через прокси"
    }

    fun renderText(): String = buildString {
        appendLine("Сравнение «напрямую vs через ${proxy.render()}»")
        appendLine()
        rows.forEach { r ->
            appendLine("${verdictMark(r.outcome)} ${r.name}")
            appendLine("      url:      ${r.url}")
            appendLine("      напрямую: ${r.direct}")
            appendLine("      через SOCKS5: ${r.viaProxy}")
        }
        appendLine()
        appendLine("вывод: ${headline()}")
    }

    private fun verdictMark(o: DpiOutcome): String = when (o) {
        DpiOutcome.OPEN_BOTH -> "[OK]      "
        DpiOutcome.OPEN_ONLY_VIA_PROXY -> "[DPI]     "
        DpiOutcome.OPEN_ONLY_DIRECT -> "[PROXY-BAD]"
        DpiOutcome.BLOCKED_BOTH -> "[IP]      "
        DpiOutcome.PROXY_UNREACHABLE -> "[NO-PROXY]"
    }
}

class DpiComparator(
    private val timeoutMs: Int = 6000,
    private val connectTimeoutMs: Int = 3000
) {

    fun compare(
        checks: List<ResourceCheck>,
        proxy: Socks5Endpoint,
        httpClient: HttpClient = HttpClient(timeoutMs)
    ): DpiComparison {
        if (!proxy.configured) {
            return DpiComparison(proxy, emptyList(), "адрес прокси не задан")
        }
        // Сначала дёшево проверяем сам порт прокси: если к нему нельзя подключиться, любое
        // «не открыто через SOCKS5» было бы враньё про блокировки, а не про выключенный ByeDPI.
        val handshake = runCatching {
            java.net.Socket().apply { connect(java.net.InetSocketAddress(proxy.host, proxy.port), connectTimeoutMs); close() }
        }.exceptionOrNull()
        if (handshake != null) {
            val why = "${handshake.javaClass.simpleName}: ${handshake.message?.take(80)}"
            return DpiComparison(
                proxy,
                checks.map { DpiRow(it.name, it.url, "—", "прокси недоступен", false, false, DpiOutcome.PROXY_UNREACHABLE) },
                why
            )
        }
        val direct = HttpClient(timeoutMs)
        val viaProxy = HttpClient(timeoutMs, proxy = proxy)
        val rows = checks.map { rc ->
            val a = probe(direct, rc)
            val b = probe(viaProxy, rc)
            val outcome = when {
                a.ok && b.ok -> DpiOutcome.OPEN_BOTH
                !a.ok && b.ok -> DpiOutcome.OPEN_ONLY_VIA_PROXY
                a.ok && !b.ok -> DpiOutcome.OPEN_ONLY_DIRECT
                else -> DpiOutcome.BLOCKED_BOTH
            }
            DpiRow(rc.name, rc.url, a.render(), b.render(), a.ok, b.ok, outcome)
        }
        val firstProxyErr = rows.firstOrNull { it.outcome == DpiOutcome.PROXY_UNREACHABLE }?.viaProxy
        return DpiComparison(proxy, rows, firstProxyErr)
    }

    /** Только «прокси жив?», без перебора ресурсов — дешёвая проверка перед долгим сравнением. */
    fun proxyAlive(proxy: Socks5Endpoint, target: String = "http://connectivitycheck.gstatic.com/generate_204"): Boolean =
        runCatching { HttpClient(connectTimeoutMs, proxy = proxy).get(target, maxBytes = 1024) }.isSuccess

    private class Probe(val ok: Boolean, val status: Int?, val error: String?, val ms: Long) {
        fun render(): String = when {
            ok -> "OK $status (${ms} мс)"
            error != null -> "$error (${ms} мс)"
            else -> "HTTP $status (${ms} мс)"
        }
    }

    private fun probe(http: HttpClient, rc: ResourceCheck): Probe {
        val t0 = System.currentTimeMillis()
        if (runCatching { URI(rc.url).host }.getOrNull().isNullOrBlank()) return Probe(false, null, "bad_url", 0)
        return try {
            val resp = http.get(rc.url, maxBytes = 64 * 1024)
            val ok = resp.status in rc.expectStatus &&
                (rc.mustContain == null || resp.body.contains(rc.mustContain, ignoreCase = true))
            Probe(ok, resp.status, null, System.currentTimeMillis() - t0)
        } catch (e: Exception) {
            // Отказ CONNECT («цель не прошла») — это результат пробы, а не «прокси умер».
            Probe(false, null, describe(e), System.currentTimeMillis() - t0)
        }
    }

    private fun describe(e: Throwable): String {
        val msg = e.message?.take(120)
        return when {
            e is java.net.SocketTimeoutException -> "timeout" + (msg?.let { " ($it)" }.orEmpty())
            e is java.net.UnknownHostException -> "dns_fail"
            e is java.net.ConnectException -> "refused${msg?.let { " ($it)" }.orEmpty()}"
            e is java.io.IOException && msg.isNullOrBlank() -> e.javaClass.simpleName
            e is java.io.IOException -> "io_error ($msg)"
            else -> "${e.javaClass.simpleName}${msg?.let { " ($it)" }.orEmpty()}"
        }
    }
}
