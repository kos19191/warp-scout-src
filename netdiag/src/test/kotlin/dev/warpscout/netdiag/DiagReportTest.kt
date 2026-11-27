package dev.warpscout.netdiag

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class DiagReportTest {

    @Test
    fun parsesDohJsonARecordsOnly() {
        val sample = """
            {"Status":0,"Answer":[
              {"name":"youtube.com","type":5,"TTL":60,"data":"alias.youtube.com"},
              {"name":"youtube.com","type":1,"TTL":60,"data":"142.250.74.206"},
              {"name":"youtube.com","type":1,"TTL":60,"data":"142.250.74.238"}
            ]}
        """.trimIndent()
        assertEquals(listOf("142.250.74.206", "142.250.74.238"), NetProbes.parseDohAJson(sample))
    }

    @Test
    fun buildsValidDnsStunAndQuicPackets() {
        val dns = NetProbes.buildDnsQueryPacket(0x1234, "example.com")
        assertTrue(dns.size >= 29)
        assertEquals(0x12, dns[0].toInt() and 0xFF)
        assertEquals(0x34, dns[1].toInt() and 0xFF)

        val txId = ByteArray(12) { (it + 1).toByte() }
        val stunReq = NetProbes.buildStunBindingRequest(txId)
        assertEquals(20, stunReq.size)
        assertEquals(0x21, stunReq[4].toInt() and 0xFF)

        // Синтетический STUN response с XOR-MAPPED-ADDRESS для 1.2.3.4:54321
        val resp = ByteArray(32)
        resp[0] = 0x01; resp[1] = 0x01
        resp[20] = 0x00; resp[21] = 0x20 // XOR-MAPPED-ADDRESS
        resp[22] = 0x00; resp[23] = 0x08
        resp[24] = 0x00; resp[25] = 0x01 // IPv4
        val xPort = 54321 xor 0x2112
        resp[26] = ((xPort ushr 8) and 0xFF).toByte()
        resp[27] = (xPort and 0xFF).toByte()
        resp[28] = (1 xor 0x21).toByte()
        resp[29] = (2 xor 0x12).toByte()
        resp[30] = (3 xor 0xA4).toByte()
        resp[31] = (4 xor 0x42).toByte()
        assertEquals("1.2.3.4:54321", NetProbes.parseStunXorMappedAddress(resp, resp.size))

        val quic = NetProbes.buildQuicVersionProbePacket()
        assertEquals(1200, quic.size)
        assertEquals(0xC0, quic[0].toInt() and 0xFF)
    }

    @Test
    fun detectsPoisonedDns16KbThrottleAndRendersReport() {
        val env = NetworkEnvInfo(
            timestampIso = "2026-11-25 12:00:00 +0300",
            deviceModel = "Samsung S24",
            androidVersion = "14 (API 34)",
            transports = listOf("WIFI"),
            validated = true,
            metered = false,
            vpnActive = false,
            downstreamKbps = 150000,
            upstreamKbps = 50000,
            wifiSummary = "SSID=HomeWiFi, сигнал=-52 дБм, линк=866 Мбит/с, 5180 МГц (5 ГГц)",
            interfaceName = "wlan0",
            mtu = 1500,
            ipv4Addresses = listOf("192.168.1.42/24"),
            ipv6Addresses = listOf("2a00:1234::5/64"),
            dnsServers = listOf("192.168.1.1"),
            privateDnsActive = true,
            privateDnsServer = "dns.google",
            httpProxy = "нет",
            routes = listOf("0.0.0.0/0 -> 192.168.1.1 (wlan0)"),
            allInterfaces = listOf("wlan0 (MTU=1500): 192.168.1.42")
        )
        val dns = listOf(
            DnsCompareResult(
                host = "www.instagram.com",
                systemIps = listOf("127.0.0.1"),
                systemMs = 8,
                dohCfIps = listOf("157.240.20.174"),
                dohCfMs = 45
            )
        )
        assertTrue(dns.first().looksPoisonedOrBlocked)

        val probes = listOf(
            EndpointProbeResult(
                group = ServiceGroup.YOUTUBE,
                label = "YouTube (64 КБ тест)",
                host = "www.youtube.com",
                port = 443,
                path = "/",
                resolvedIp = "142.250.74.206",
                tcpOk = true,
                tcpMs = 30,
                tlsTried = true,
                tlsOk = true,
                tlsMs = 80,
                httpCode = 200,
                bytesRead = 16384,
                downloadMs = 4001,
                stageFailed = "BODY",
                error = "SocketTimeoutException: Read timed out"
            ),
            EndpointProbeResult(
                group = ServiceGroup.TELEGRAM,
                label = "Telegram DC2 EU",
                host = "149.154.167.51",
                port = 443,
                tcpOk = true,
                tcpMs = 42
            )
        )
        assertTrue(probes[0].looksLike16KbThrottle)
        assertFalse(probes[0].ok)
        assertTrue(probes[1].ok)

        val report = FullDiagReport(
            appVersion = "1.0.0",
            durationMs = 12300,
            env = env,
            dnsChecks = dns,
            endpointProbes = probes,
            udpProbes = listOf(
                UdpProbeResult("YouTube QUIC", "www.youtube.com:443", "QUIC", false, 2500, "SocketTimeoutException")
            )
        )

        val findings = report.buildAutoFindings().joinToString("\n")
        assertTrue(findings.contains("Private DNS"))
        assertTrue(findings.contains("IPv6"))
        assertTrue(findings.contains("ПРОБЛЕМА DNS"))
        assertTrue(findings.contains("16 КБ"))
        assertTrue(findings.contains("QUIC"))

        val txt = report.renderTxt()
        assertTrue(txt.contains("WilyDiag v1.0.0"))
        assertTrue(txt.contains("www.instagram.com"))
        assertTrue(txt.contains("ТСПУ-ОБРЫВ ~16КБ"))
    }
}
