package dev.warpscout.netdiag

import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

data class NetworkEnvInfo(
    val timestampIso: String,
    val deviceModel: String,
    val androidVersion: String,
    val transports: List<String>,
    val validated: Boolean,
    val metered: Boolean,
    val vpnActive: Boolean,
    val downstreamKbps: Int,
    val upstreamKbps: Int,
    val wifiSummary: String,
    val interfaceName: String,
    val mtu: Int,
    val ipv4Addresses: List<String>,
    val ipv6Addresses: List<String>,
    val dnsServers: List<String>,
    val privateDnsActive: Boolean,
    val privateDnsServer: String,
    val httpProxy: String,
    val routes: List<String>,
    val allInterfaces: List<String>,
    val externalTrace: Map<String, String> = emptyMap(),
    val externalTraceError: String? = null,
    val externalIpv6: String? = null
)

data class DnsCompareResult(
    val host: String,
    val systemIps: List<String>,
    val systemMs: Long,
    val systemError: String? = null,
    val dohCfIps: List<String> = emptyList(),
    val dohCfMs: Long = 0L,
    val dohCfError: String? = null,
    val dohGoogleIps: List<String> = emptyList(),
    val dohGoogleMs: Long = 0L,
    val dohGoogleError: String? = null
) {
    val looksPoisonedOrBlocked: Boolean
        get() {
            val sysV4 = systemIps.filter { ':' !in it }
            val cfV4 = dohCfIps.filter { ':' !in it }
            if (sysV4.any { isBogusOrSinkholeIpv4(it) }) return true
            if (sysV4.isEmpty() && cfV4.isNotEmpty()) return true
            return false
        }

    val diffNote: String
        get() {
            val sysV4 = systemIps.filter { ':' !in it }
            val cfV4 = dohCfIps.filter { ':' !in it }
            return when {
                sysV4.any { isBogusOrSinkholeIpv4(it) } -> "ПОДМЕНА / ЗАГЛУШКА DNS!"
                sysV4.isEmpty() && cfV4.isNotEmpty() -> "Системный DNS не ответил, DoH 1.1.1.1 работает"
                sysV4.isEmpty() && cfV4.isEmpty() -> "Ни один DNS не вернул IPv4"
                cfV4.isNotEmpty() && sysV4.none { it in cfV4 } -> "IP системного DNS отличаются от 1.1.1.1 (CDN/Anycast или перехват)"
                else -> "OK"
            }
        }

    companion object {
        fun isBogusOrSinkholeIpv4(ip: String): Boolean {
            return ip == "0.0.0.0" ||
                ip.startsWith("127.") ||
                ip.startsWith("10.") ||
                ip.startsWith("192.168.") ||
                ip.startsWith("169.254.") ||
                ip.startsWith("198.18.") ||
                ip.startsWith("198.19.")
        }
    }
}

enum class ServiceGroup(val title: String) {
    BASELINE("База (контроль РФ и мир)"),
    TELEGRAM("Telegram"),
    META("Meta (WhatsApp / Instagram / Facebook)"),
    YOUTUBE("YouTube / Google Video")
}

data class EndpointProbeResult(
    val group: ServiceGroup,
    val label: String,
    val host: String,
    val port: Int,
    val path: String? = null,
    val resolvedIp: String? = null,
    val dnsMs: Long = 0L,
    val tcpOk: Boolean = false,
    val tcpMs: Long = 0L,
    val tlsTried: Boolean = false,
    val tlsOk: Boolean = false,
    val tlsMs: Long = 0L,
    val tlsProtocol: String? = null,
    val certSubject: String? = null,
    val httpCode: Int? = null,
    val bytesRead: Int = 0,
    val downloadMs: Long = 0L,
    val stageFailed: String? = null,
    val error: String? = null
) {
    val ok: Boolean
        get() = when {
            path != null -> tcpOk && (!tlsTried || tlsOk) && httpCode != null && stageFailed == null
            tlsTried -> tcpOk && tlsOk && stageFailed == null
            else -> tcpOk && stageFailed == null
        }

    /** ТСПУ часто рвёт поток после ~16 КБ (от 10 до 22 КБ прочитано, затем таймаут/сброс). */
    val looksLike16KbThrottle: Boolean
        get() = stageFailed == "BODY" && bytesRead in 4_096..26_000
}

data class UdpProbeResult(
    val label: String,
    val target: String,
    val protocol: String,
    val ok: Boolean,
    val rttMs: Long,
    val detail: String
)

data class FullDiagReport(
    val appVersion: String,
    val durationMs: Long,
    val env: NetworkEnvInfo,
    val dnsChecks: List<DnsCompareResult>,
    val endpointProbes: List<EndpointProbeResult>,
    val udpProbes: List<UdpProbeResult>
) {
    fun buildAutoFindings(): List<String> {
        val out = ArrayList<String>()

        if (env.vpnActive) {
            out += "На телефоне АКТИВЕН VPN-туннель — результаты отражают работу поверх VPN (для проверки чистого Wi-Fi повторите с выключенным VPN)."
        }
        if (env.privateDnsActive) {
            val srv = env.privateDnsServer.ifBlank { "авто/системный" }
            out += "Включён Private DNS (DoT: $srv) — телефон обходит DNS роутера. Если на роутере настроен обход по доменам, Private DNS на Android часто мешает ему работать."
        }
        if (env.ipv6Addresses.isNotEmpty()) {
            val v6State = if (env.externalIpv6 != null) "выход в интернет по IPv6 есть (${env.externalIpv6})" else "локальный/провайдерский IPv6 выдан, но внешний IPv6 не отвечает (возможны подвисания Happy Eyeballs!)"
            out += "На интерфейсе есть IPv6 (${env.ipv6Addresses.size} адр.): $v6State. Если обход настроен только для IPv4, IPv6 на Wi-Fi нужно отключить."
        }
        if (env.httpProxy.isNotBlank() && env.httpProxy != "нет") {
            out += "В настройках Wi-Fi задан HTTP-прокси: ${env.httpProxy} — часть приложений (Telegram/YouTube/UDP) может его игнорировать или ломаться."
        }

        val poisonedDns = dnsChecks.filter { it.looksPoisonedOrBlocked }
        if (poisonedDns.isNotEmpty()) {
            val names = poisonedDns.joinToString(", ") { it.host }
            out += "ПРОБЛЕМА DNS: системный DNS не резолвит или подменяет адреса для: $names (при этом DoH 1.1.1.1 видит их)."
        }

        for (group in listOf(ServiceGroup.TELEGRAM, ServiceGroup.META, ServiceGroup.YOUTUBE)) {
            val items = endpointProbes.filter { it.group == group }
            if (items.isEmpty()) continue
            val passed = items.count { it.ok }
            val failed = items.filter { !it.ok }
            val throttle16k = failed.filter { it.looksLike16KbThrottle }
            val tlsFails = failed.filter { it.tcpOk && it.tlsTried && !it.tlsOk }
            val tcpFails = failed.filter { !it.tcpOk && it.stageFailed == "TCP" }
            val dnsFails = failed.filter { it.stageFailed == "DNS" }

            val verdict = buildString {
                append("${group.title}: работает $passed/${items.size}")
                if (failed.isEmpty()) {
                    append(" — всё доступно.")
                } else {
                    append(". Проблемы: ")
                    val parts = ArrayList<String>()
                    if (dnsFails.isNotEmpty()) parts += "DNS (${dnsFails.size})"
                    if (tcpFails.isNotEmpty()) parts += "TCP-бан/таймаут (${tcpFails.size})"
                    if (tlsFails.isNotEmpty()) parts += "TLS/SNI сброс DPI (${tlsFails.size})"
                    if (throttle16k.isNotEmpty()) parts += "обрыв на ~16 КБ / ТСПУ-троттлинг (${throttle16k.size})"
                    val other = failed.size - dnsFails.size - tcpFails.size - tlsFails.size - throttle16k.size
                    if (other > 0) parts += "HTTP/чтение ($other)"
                    append(parts.joinToString(", "))
                    append(".")
                }
            }
            out += verdict
        }

        val quicProbes = udpProbes.filter { it.protocol == "QUIC" }
        if (quicProbes.isNotEmpty()) {
            val quicOk = quicProbes.count { it.ok }
            if (quicOk == 0) {
                out += "QUIC (UDP 443) НЕ проходит (0/${quicProbes.size}) — YouTube и Instagram на Android будут долго думать перед откатом на TCP."
            } else if (quicOk < quicProbes.size) {
                val blocked = quicProbes.filter { !it.ok }.joinToString(", ") { it.label }
                out += "QUIC (UDP 443) частично режется ($quicOk/${quicProbes.size}); не ответили: $blocked."
            }
        }

        val stun = udpProbes.firstOrNull { it.protocol == "STUN" }
        if (stun != null && !stun.ok) {
            out += "STUN UDP 19302 не прошёл — Wi-Fi роутер или провайдер режет исходящий UDP (звонки Telegram/WhatsApp и VPN могут не работать)."
        }

        if (out.isEmpty()) {
            out += "Явных блокировок и сетевых аномалий не обнаружено."
        }
        return out
    }

    fun renderTxt(): String = buildString {
        appendLine("========================================================================")
        appendLine("  WilyDiag v$appVersion — Диагностический отчёт сети Android")
        appendLine("  Время: ${env.timestampIso}  |  Длительность проверки: ${durationMs / 1000.0} с")
        appendLine("========================================================================")
        appendLine()

        appendLine("[1] КРАТКИЕ ВЫВОДЫ (АВТОАНАЛИЗ)")
        appendLine("------------------------------------------------------------------------")
        buildAutoFindings().forEachIndexed { idx, line ->
            appendLine(" ${idx + 1}. $line")
        }
        appendLine()

        appendLine("[2] УСТРОЙСТВО, WI-FI И СЕТЕВОЙ СТЕК ANDROID")
        appendLine("------------------------------------------------------------------------")
        appendLine("Устройство       : ${env.deviceModel} (Android ${env.androidVersion})")
        appendLine("Транспорт        : ${env.transports.ifEmpty { listOf("нет сети") }.joinToString(", ")}")
        appendLine("Состояние сети   : validated=${env.validated}, metered=${env.metered}, vpnActive=${env.vpnActive}")
        appendLine("Оценка канала ОС : down=${env.downstreamKbps} кбит/с, up=${env.upstreamKbps} кбит/с")
        appendLine("Wi-Fi            : ${env.wifiSummary}")
        appendLine("Интерфейс / MTU  : ${env.interfaceName.ifBlank { "?" }} / MTU=${if (env.mtu > 0) env.mtu else "по умолчанию"}")
        appendLine("IPv4 адреса      : ${env.ipv4Addresses.ifEmpty { listOf("нет") }.joinToString(", ")}")
        appendLine("IPv6 адреса      : ${env.ipv6Addresses.ifEmpty { listOf("нет") }.joinToString(", ")}")
        appendLine("Системные DNS    : ${env.dnsServers.ifEmpty { listOf("нет") }.joinToString(", ")}")
        appendLine("Private DNS (DoT): active=${env.privateDnsActive}, server=${env.privateDnsServer.ifBlank { "-" }}")
        appendLine("HTTP-прокси      : ${env.httpProxy.ifBlank { "нет" }}")
        if (env.externalTrace.isNotEmpty()) {
            val ip = env.externalTrace["ip"].orEmpty()
            val loc = env.externalTrace["loc"].orEmpty()
            val colo = env.externalTrace["colo"].orEmpty()
            val warp = env.externalTrace["warp"].orEmpty()
            val tls = env.externalTrace["tls"].orEmpty()
            appendLine("Внешний выход    : IP=$ip, loc=$loc, colo=$colo, warp=$warp, tls=$tls")
        } else if (env.externalTraceError != null) {
            appendLine("Внешний выход    : ошибка (${env.externalTraceError})")
        }
        appendLine("Внешний IPv6     : ${env.externalIpv6 ?: "недоступен / отсутствует"}")
        appendLine("Маршруты ОС      : ${env.routes.take(12).ifEmpty { listOf("нет") }.joinToString(" ; ")}")
        if (env.allInterfaces.isNotEmpty()) {
            appendLine("Активные адаптеры:")
            env.allInterfaces.forEach { appendLine("   - $it") }
        }
        appendLine()

        appendLine("[3] СРАВНЕНИЕ DNS (Системный DNS vs DoH 1.1.1.1 vs DoH dns.google)")
        appendLine("------------------------------------------------------------------------")
        for (d in dnsChecks) {
            val sysStr = if (d.systemIps.isNotEmpty()) "${d.systemIps.joinToString(",")} (${d.systemMs}мс)" else "ОШИБКА: ${d.systemError ?: "пусто"} (${d.systemMs}мс)"
            val cfStr = if (d.dohCfIps.isNotEmpty()) "${d.dohCfIps.joinToString(",")} (${d.dohCfMs}мс)" else "ОШИБКА: ${d.dohCfError ?: "пусто"}"
            val ggStr = if (d.dohGoogleIps.isNotEmpty()) "${d.dohGoogleIps.joinToString(",")} (${d.dohGoogleMs}мс)" else "ОШИБКА: ${d.dohGoogleError ?: "пусто"}"
            appendLine("• ${d.host}  [${d.diffNote}]")
            appendLine("    System : $sysStr")
            appendLine("    1.1.1.1: $cfStr")
            appendLine("    Google : $ggStr")
        }
        appendLine()

        var sectionNum = 4
        for (group in ServiceGroup.values()) {
            val items = endpointProbes.filter { it.group == group }
            if (items.isEmpty()) continue
            val okCount = items.count { it.ok }
            appendLine("[$sectionNum] ${group.title.uppercase(Locale.ROOT)} ($okCount/${items.size} OK)")
            appendLine("------------------------------------------------------------------------")
            for (p in items) {
                val mark = if (p.ok) "OK  " else "FAIL"
                val target = "${p.host}:${p.port}${p.path ?: ""}"
                val ipPart = p.resolvedIp?.let { " [$it]" } ?: ""
                appendLine("$mark | ${p.label} | $target$ipPart")
                val details = ArrayList<String>()
                if (p.dnsMs > 0) details += "DNS=${p.dnsMs}мс"
                if (p.tcpOk) details += "TCP=${p.tcpMs}мс" else if (p.stageFailed == "TCP") details += "TCP=FAIL(${p.tcpMs}мс)"
                if (p.tlsTried) {
                    if (p.tlsOk) {
                        details += "TLS=${p.tlsMs}мс(${p.tlsProtocol ?: "?"})"
                    } else {
                        details += "TLS=FAIL(${p.tlsMs}мс)"
                    }
                }
                if (p.httpCode != null) details += "HTTP=${p.httpCode}"
                if (p.bytesRead > 0 || p.downloadMs > 0) {
                    val kb = String.format(Locale.US, "%.1fКБ", p.bytesRead / 1024.0)
                    details += "читано=$kb за ${p.downloadMs}мс"
                }
                if (p.looksLike16KbThrottle) details += "⚠ ПОХОЖЕ НА ТСПУ-ОБРЫВ ~16КБ"
                if (!p.certSubject.isNullOrBlank()) details += "CN=${p.certSubject}"
                appendLine("      ${details.joinToString(" | ")}")
                if (!p.error.isNullOrBlank()) {
                    appendLine("      Ошибка [${p.stageFailed ?: "?"}]: ${p.error}")
                }
            }
            appendLine()
            sectionNum++
        }

        appendLine("[$sectionNum] UDP, QUIC (UDP 443), DNS UDP 53, STUN И VPN-ПОРТЫ")
        appendLine("------------------------------------------------------------------------")
        for (u in udpProbes) {
            val mark = if (u.ok) "OK  " else "FAIL"
            appendLine("$mark | ${u.protocol.padEnd(5)} | ${u.label} (${u.target}) | ${u.rttMs}мс | ${u.detail}")
        }
        appendLine()
        appendLine("=== Конец отчёта WilyDiag ===")
    }

    fun renderShortSummary(): String = buildString {
        appendLine("Итог проверки (${String.format(Locale.US, "%.1f", durationMs / 1000.0)} с):")
        appendLine()
        buildAutoFindings().forEach { appendLine("• $it") }
        appendLine()
        for (g in listOf(ServiceGroup.BASELINE, ServiceGroup.TELEGRAM, ServiceGroup.META, ServiceGroup.YOUTUBE)) {
            val list = endpointProbes.filter { it.group == g }
            if (list.isEmpty()) continue
            val ok = list.count { it.ok }
            appendLine("${g.title}: $ok/${list.size}")
            list.filter { !it.ok }.forEach { f ->
                val why = f.stageFailed ?: "ERR"
                val extra = if (f.looksLike16KbThrottle) " (~${f.bytesRead / 1024}КБ обрыв)" else ""
                appendLine("  ✗ ${f.label} ($why$extra): ${f.error?.take(90) ?: ""}")
            }
        }
        val quic = udpProbes.filter { it.protocol == "QUIC" }
        if (quic.isNotEmpty()) {
            appendLine("QUIC UDP 443: ${quic.count { it.ok }}/${quic.size}")
        }
        val stun = udpProbes.firstOrNull { it.protocol == "STUN" }
        if (stun != null) {
            appendLine("STUN UDP: ${if (stun.ok) "OK (${stun.detail})" else "FAIL (${stun.detail})"}")
        }
    }

    companion object {
        fun nowIso(): String = SimpleDateFormat("yyyy-MM-dd HH:mm:ss Z", Locale.US).format(Date())
        fun fileTimestamp(): String = SimpleDateFormat("yyyyMMdd-HHmmss", Locale.US).format(Date())
    }
}
