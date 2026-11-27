package dev.warpscout.netdiag

import android.content.Context
import java.util.concurrent.Callable
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger

class DiagEngine(private val context: Context) {

    data class Progress(
        val done: Int,
        val total: Int,
        val currentLabel: String
    ) {
        val percent: Int get() = if (total <= 0) 0 else ((done * 100) / total).coerceIn(0, 100)
    }

    fun runFullScan(
        cancelled: AtomicBoolean,
        onProgress: (Progress) -> Unit
    ): FullDiagReport {
        val tStart = System.currentTimeMillis()
        val dnsTargets = listOf(
            "telegram.org",
            "web.telegram.org",
            "whatsapp.com",
            "www.instagram.com",
            "www.facebook.com",
            "www.youtube.com",
            "googlevideo.com"
        )

        data class ProbeSpec(
            val group: ServiceGroup,
            val label: String,
            val host: String,
            val port: Int = 443,
            val useTls: Boolean = (port == 443),
            val path: String? = if (port == 443) "/" else null,
            val maxBytes: Int = 32 * 1024
        )

        val endpointSpecs = listOf(
            // Базовый контроль
            ProbeSpec(ServiceGroup.BASELINE, "Яндекс (контроль РФ)", "ya.ru", 443, true, "/", 16 * 1024),
            ProbeSpec(ServiceGroup.BASELINE, "VK (контроль РФ)", "vk.com", 443, true, "/", 16 * 1024),
            ProbeSpec(ServiceGroup.BASELINE, "Cloudflare 1.1.1.1", "1.1.1.1", 443, true, "/cdn-cgi/trace", 4096),
            ProbeSpec(ServiceGroup.BASELINE, "Google 204", "connectivitycheck.gstatic.com", 443, true, "/generate_204", 1024),

            // Telegram
            ProbeSpec(ServiceGroup.TELEGRAM, "Telegram сайт", "telegram.org", 443, true, "/", 32 * 1024),
            ProbeSpec(ServiceGroup.TELEGRAM, "Telegram Web", "web.telegram.org", 443, true, "/", 32 * 1024),
            ProbeSpec(ServiceGroup.TELEGRAM, "Telegram Bot API", "api.telegram.org", 443, true, "/", 8192),
            ProbeSpec(ServiceGroup.TELEGRAM, "Telegram t.me", "t.me", 443, true, "/", 16 * 1024),
            ProbeSpec(ServiceGroup.TELEGRAM, "Telegram CDN медиа", "cdn4.telegram-cdn.org", 443, true, "/", 16 * 1024),
            ProbeSpec(ServiceGroup.TELEGRAM, "Telegram DC1 (TCP 443)", "149.154.175.53", 443, false, null),
            ProbeSpec(ServiceGroup.TELEGRAM, "Telegram DC2 EU (TCP 443)", "149.154.167.51", 443, false, null),
            ProbeSpec(ServiceGroup.TELEGRAM, "Telegram DC4 EU (TCP 443)", "149.154.167.91", 443, false, null),
            ProbeSpec(ServiceGroup.TELEGRAM, "Telegram DC5 (TCP 443)", "91.108.56.130", 443, false, null),

            // Meta (WhatsApp / Instagram / Facebook)
            ProbeSpec(ServiceGroup.META, "WhatsApp Web", "web.whatsapp.com", 443, true, "/", 32 * 1024),
            ProbeSpec(ServiceGroup.META, "WhatsApp чат (TLS 443)", "g.whatsapp.net", 443, true, null),
            ProbeSpec(ServiceGroup.META, "WhatsApp чат (TCP 5222)", "g.whatsapp.net", 5222, false, null),
            ProbeSpec(ServiceGroup.META, "WhatsApp медиа (TLS 443)", "mmg.whatsapp.net", 443, true, null),
            ProbeSpec(ServiceGroup.META, "Instagram сайт", "www.instagram.com", 443, true, "/", 32 * 1024),
            ProbeSpec(ServiceGroup.META, "Instagram API", "i.instagram.com", 443, true, "/", 16 * 1024),
            ProbeSpec(ServiceGroup.META, "Instagram CDN медиа (TLS)", "scontent.cdninstagram.com", 443, true, null),
            ProbeSpec(ServiceGroup.META, "Facebook сайт", "www.facebook.com", 443, true, "/", 32 * 1024),
            ProbeSpec(ServiceGroup.META, "Facebook Graph API", "graph.facebook.com", 443, true, "/", 8192),
            ProbeSpec(ServiceGroup.META, "Facebook CDN статика (TLS)", "static.xx.fbcdn.net", 443, true, null),

            // YouTube / Google Video
            ProbeSpec(ServiceGroup.YOUTUBE, "YouTube (64 КБ тест)", "www.youtube.com", 443, true, "/", 64 * 1024),
            ProbeSpec(ServiceGroup.YOUTUBE, "YouTube Mobile (64 КБ)", "m.youtube.com", 443, true, "/", 64 * 1024),
            ProbeSpec(ServiceGroup.YOUTUBE, "YouTube API (youtubei)", "youtubei.googleapis.com", 443, true, "/", 16 * 1024),
            ProbeSpec(ServiceGroup.YOUTUBE, "YouTube превью (ytimg)", "i.ytimg.com", 443, true, "/", 16 * 1024),
            ProbeSpec(ServiceGroup.YOUTUBE, "YouTube redirector", "redirector.googlevideo.com", 443, true, "/", 8192),
            ProbeSpec(ServiceGroup.YOUTUBE, "YouTube googlevideo (TLS)", "manifest.googlevideo.com", 443, true, null)
        )

        val udpTasks: List<Pair<String, () -> UdpProbeResult>> = listOf(
            "DNS UDP 1.1.1.1:53" to { NetProbes.probeDnsUdp53("DNS UDP Cloudflare", "1.1.1.1") },
            "DNS UDP 8.8.8.8:53" to { NetProbes.probeDnsUdp53("DNS UDP Google", "8.8.8.8") },
            "STUN UDP 19302" to { NetProbes.probeStunUdp() },
            "QUIC UDP 443 (YouTube)" to { NetProbes.probeQuicUdp443("YouTube QUIC", "www.youtube.com") },
            "QUIC UDP 443 (Cloudflare)" to { NetProbes.probeQuicUdp443("Cloudflare QUIC", "1.1.1.1") },
            "QUIC UDP 443 (Instagram)" to { NetProbes.probeQuicUdp443("Instagram QUIC", "www.instagram.com") },
            "QUIC UDP 443 (WhatsApp)" to { NetProbes.probeQuicUdp443("WhatsApp QUIC", "web.whatsapp.com") }
        )

        val totalSteps = 2 + dnsTargets.size + endpointSpecs.size + udpTasks.size
        val completed = AtomicInteger(0)
        fun tick(label: String) {
            onProgress(Progress(completed.incrementAndGet(), totalSteps, label))
        }

        // Шаг 1: сбор сведений о Wi-Fi / Android-сети
        onProgress(Progress(0, totalSteps, "Сбор параметров Wi-Fi, DNS и маршрутов…"))
        var env = AndroidNetworkCollector.collect(context)
        tick("Параметры Wi-Fi и интерфейсов собраны")

        // Шаг 2: внешний выход + IPv6
        if (!cancelled.get()) {
            val (trace, traceErr) = NetProbes.probeCloudflareTrace()
            val extV6 = NetProbes.probeExternalIpv6()
            env = env.copy(externalTrace = trace, externalTraceError = traceErr, externalIpv6 = extV6)
        }
        tick("Проверка внешнего IP и IPv6 завершена")

        val pool = Executors.newFixedThreadPool(6) { r ->
            Thread(r, "wilydiag-worker").apply { isDaemon = true }
        }
        return try {
            // Шаг 3: DNS сравнение (параллельно)
            val dnsFutures = dnsTargets.map { host ->
                pool.submit(Callable {
                    if (cancelled.get()) return@Callable null
                    val res = NetProbes.compareDns(host)
                    tick("DNS: $host")
                    res
                })
            }
            val dnsResults = dnsFutures.mapNotNull { runCatching { it.get() }.getOrNull() }

            // Шаг 4: TCP/TLS/HTTPS проверка сервисов (параллельно)
            val epFutures = endpointSpecs.map { spec ->
                pool.submit(Callable {
                    if (cancelled.get()) return@Callable null
                    val res = NetProbes.probeEndpoint(
                        group = spec.group,
                        label = spec.label,
                        host = spec.host,
                        port = spec.port,
                        useTls = spec.useTls,
                        path = spec.path,
                        maxBodyBytes = spec.maxBytes
                    )
                    tick(spec.label)
                    res
                })
            }
            val endpointResults = epFutures.mapNotNull { runCatching { it.get() }.getOrNull() }

            // Шаг 5: UDP / QUIC / STUN / DNS 53 (параллельно)
            val udpFutures = udpTasks.map { (name, fn) ->
                pool.submit(Callable {
                    if (cancelled.get()) return@Callable null
                    val res = fn()
                    tick(name)
                    res
                })
            }
            val udpResults = udpFutures.mapNotNull { runCatching { it.get() }.getOrNull() }

            FullDiagReport(
                appVersion = BuildConfig.VERSION_NAME,
                durationMs = (System.currentTimeMillis() - tStart).coerceAtLeast(1L),
                env = env,
                dnsChecks = dnsResults,
                endpointProbes = endpointResults,
                udpProbes = udpResults
            )
        } finally {
            pool.shutdownNow()
        }
    }
}
