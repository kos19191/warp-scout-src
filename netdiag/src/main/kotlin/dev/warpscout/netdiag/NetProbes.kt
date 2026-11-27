package dev.warpscout.netdiag

import java.io.BufferedInputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.HttpURLConnection
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.URL
import java.security.SecureRandom
import java.security.cert.X509Certificate
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

object NetProbes {

    private val random = SecureRandom()
    private val IPV4_RE = Regex("""^\d{1,3}(\.\d{1,3}){3}$""")
    private val DOH_DATA_RE = Regex(""""type"\s*:\s*1\b[^}]*?"data"\s*:\s*"(\d{1,3}(?:\.\d{1,3}){3})"""")

    /**
     * Пошаговый зонд: DNS → TCP → TLS (с SNI) → HTTP GET + чтение до [maxBodyBytes].
     * Чётко разделяет: DNS-ошибку, TCP-бан/таймаут, TLS/SNI сброс DPI и обрыв потока (~16 КБ ТСПУ).
     */
    fun probeEndpoint(
        group: ServiceGroup,
        label: String,
        host: String,
        port: Int = 443,
        useTls: Boolean = (port == 443),
        sniHost: String? = if (IPV4_RE.matches(host)) null else host,
        path: String? = if (port == 443 || port == 80) "/" else null,
        maxBodyBytes: Int = 32 * 1024,
        connectTimeoutMs: Int = 3500,
        readTimeoutMs: Int = 4000
    ): EndpointProbeResult {
        // 1. DNS
        val tDns = System.currentTimeMillis()
        val targetAddr: InetAddress = try {
            if (IPV4_RE.matches(host)) {
                InetAddress.getByName(host)
            } else {
                val all = InetAddress.getAllByName(host)
                all.firstOrNull { it is Inet4Address } ?: all.first()
            }
        } catch (e: Exception) {
            return EndpointProbeResult(
                group = group,
                label = label,
                host = host,
                port = port,
                path = path,
                dnsMs = (System.currentTimeMillis() - tDns).coerceAtLeast(1L),
                tlsTried = useTls,
                stageFailed = "DNS",
                error = formatException(e)
            )
        }
        val dnsMs = if (IPV4_RE.matches(host)) 0L else (System.currentTimeMillis() - tDns).coerceAtLeast(1L)
        val ipStr = targetAddr.hostAddress ?: host

        // 2. TCP
        val rawSocket = Socket()
        val tTcp = System.currentTimeMillis()
        try {
            rawSocket.connect(InetSocketAddress(targetAddr, port), connectTimeoutMs)
            rawSocket.soTimeout = readTimeoutMs
        } catch (e: Exception) {
            runCatching { rawSocket.close() }
            return EndpointProbeResult(
                group = group,
                label = label,
                host = host,
                port = port,
                path = path,
                resolvedIp = ipStr,
                dnsMs = dnsMs,
                tcpOk = false,
                tcpMs = (System.currentTimeMillis() - tTcp).coerceAtLeast(1L),
                tlsTried = useTls,
                stageFailed = "TCP",
                error = formatException(e)
            )
        }
        val tcpMs = (System.currentTimeMillis() - tTcp).coerceAtLeast(1L)

        // 3. TLS (если требуется)
        var activeSocket: Socket = rawSocket
        var tlsOk = false
        var tlsMs = 0L
        var tlsProtocol: String? = null
        var certSubject: String? = null
        if (useTls) {
            val tTls = System.currentTimeMillis()
            try {
                val factory = SSLSocketFactory.getDefault() as SSLSocketFactory
                val ssl = factory.createSocket(rawSocket, sniHost ?: host, port, true) as SSLSocket
                ssl.soTimeout = readTimeoutMs
                if (!sniHost.isNullOrBlank() && !IPV4_RE.matches(sniHost)) {
                    val params = ssl.sslParameters
                    params.serverNames = listOf(SNIHostName(sniHost))
                    ssl.sslParameters = params
                }
                ssl.startHandshake()
                tlsMs = (System.currentTimeMillis() - tTls).coerceAtLeast(1L)
                tlsOk = true
                tlsProtocol = ssl.session?.protocol
                val cert = runCatching { ssl.session?.peerCertificates?.firstOrNull() as? X509Certificate }.getOrNull()
                certSubject = cert?.subjectX500Principal?.name?.take(80)
                activeSocket = ssl
            } catch (e: Exception) {
                tlsMs = (System.currentTimeMillis() - tTls).coerceAtLeast(1L)
                runCatching { rawSocket.close() }
                return EndpointProbeResult(
                    group = group,
                    label = label,
                    host = host,
                    port = port,
                    path = path,
                    resolvedIp = ipStr,
                    dnsMs = dnsMs,
                    tcpOk = true,
                    tcpMs = tcpMs,
                    tlsTried = true,
                    tlsOk = false,
                    tlsMs = tlsMs,
                    stageFailed = "TLS",
                    error = formatException(e)
                )
            }
        }

        // Если нужен только TCP/TLS (например, Telegram DC или WhatsApp 5222) — закрываем и возвращаем ОК.
        if (path == null) {
            runCatching { activeSocket.close() }
            return EndpointProbeResult(
                group = group,
                label = label,
                host = host,
                port = port,
                path = null,
                resolvedIp = ipStr,
                dnsMs = dnsMs,
                tcpOk = true,
                tcpMs = tcpMs,
                tlsTried = useTls,
                tlsOk = tlsOk,
                tlsMs = tlsMs,
                tlsProtocol = tlsProtocol,
                certSubject = certSubject
            )
        }

        // 4. HTTP GET + чтение до maxBodyBytes (ловим 16KB ТСПУ-дроп / таймаут чтения)
        val tDl = System.currentTimeMillis()
        var httpCode: Int? = null
        var totalRead = 0
        try {
            val hostHeader = sniHost ?: host
            val req = buildString {
                append("GET $path HTTP/1.1\r\n")
                append("Host: $hostHeader\r\n")
                append("User-Agent: Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 Chrome/126.0 Mobile Safari/537.36\r\n")
                append("Accept: */*\r\n")
                append("Accept-Encoding: identity\r\n")
                append("Connection: close\r\n\r\n")
            }
            val out = activeSocket.getOutputStream()
            out.write(req.toByteArray(Charsets.US_ASCII))
            out.flush()

            val inp = BufferedInputStream(activeSocket.getInputStream(), 8192)
            val statusLine = readLineAscii(inp)
            if (statusLine.isNullOrBlank()) {
                return EndpointProbeResult(
                    group = group,
                    label = label,
                    host = host,
                    port = port,
                    path = path,
                    resolvedIp = ipStr,
                    dnsMs = dnsMs,
                    tcpOk = true,
                    tcpMs = tcpMs,
                    tlsTried = useTls,
                    tlsOk = tlsOk,
                    tlsMs = tlsMs,
                    tlsProtocol = tlsProtocol,
                    certSubject = certSubject,
                    downloadMs = (System.currentTimeMillis() - tDl).coerceAtLeast(1L),
                    stageFailed = "HTTP",
                    error = "Сервер закрыл соединение без HTTP-ответа (EOF)"
                )
            }
            val parts = statusLine.split(' ')
            httpCode = parts.getOrNull(1)?.toIntOrNull()

            // Пропускаем HTTP-заголовки
            while (true) {
                val h = readLineAscii(inp) ?: break
                if (h.isEmpty()) break
            }

            // Читаем тело до maxBodyBytes (если код 204 — тело пустое и EOF нормален)
            val buf = ByteArray(4096)
            while (totalRead < maxBodyBytes) {
                val n = inp.read(buf, 0, minOf(buf.size, maxBodyBytes - totalRead))
                if (n <= 0) break
                totalRead += n
            }

            return EndpointProbeResult(
                group = group,
                label = label,
                host = host,
                port = port,
                path = path,
                resolvedIp = ipStr,
                dnsMs = dnsMs,
                tcpOk = true,
                tcpMs = tcpMs,
                tlsTried = useTls,
                tlsOk = tlsOk,
                tlsMs = tlsMs,
                tlsProtocol = tlsProtocol,
                certSubject = certSubject,
                httpCode = httpCode,
                bytesRead = totalRead,
                downloadMs = (System.currentTimeMillis() - tDl).coerceAtLeast(1L)
            )
        } catch (e: Exception) {
            return EndpointProbeResult(
                group = group,
                label = label,
                host = host,
                port = port,
                path = path,
                resolvedIp = ipStr,
                dnsMs = dnsMs,
                tcpOk = true,
                tcpMs = tcpMs,
                tlsTried = useTls,
                tlsOk = tlsOk,
                tlsMs = tlsMs,
                tlsProtocol = tlsProtocol,
                certSubject = certSubject,
                httpCode = httpCode,
                bytesRead = totalRead,
                downloadMs = (System.currentTimeMillis() - tDl).coerceAtLeast(1L),
                stageFailed = if (httpCode == null) "HTTP" else "BODY",
                error = formatException(e)
            )
        } finally {
            runCatching { activeSocket.close() }
        }
    }

    /** Сравнение системного DNS с DoH 1.1.1.1 и DoH dns.google. */
    fun compareDns(host: String): DnsCompareResult {
        val tSys = System.currentTimeMillis()
        var sysIps = emptyList<String>()
        var sysErr: String? = null
        try {
            sysIps = InetAddress.getAllByName(host)
                .mapNotNull { it.hostAddress?.substringBefore('%') }
                .distinct()
        } catch (e: Exception) {
            sysErr = formatException(e)
        }
        val sysMs = (System.currentTimeMillis() - tSys).coerceAtLeast(1L)

        val (cfIps, cfMs, cfErr) = queryDoh("https://1.1.1.1/dns-query?name=$host&type=A")
        val (ggIps, ggMs, ggErr) = queryDoh("https://dns.google/resolve?name=$host&type=A")

        return DnsCompareResult(
            host = host,
            systemIps = sysIps,
            systemMs = sysMs,
            systemError = sysErr,
            dohCfIps = cfIps,
            dohCfMs = cfMs,
            dohCfError = cfErr,
            dohGoogleIps = ggIps,
            dohGoogleMs = ggMs,
            dohGoogleError = ggErr
        )
    }

    internal fun queryDoh(urlStr: String, timeoutMs: Int = 3000): Triple<List<String>, Long, String?> {
        val t0 = System.currentTimeMillis()
        var conn: HttpURLConnection? = null
        return try {
            conn = (URL(urlStr).openConnection() as HttpURLConnection).apply {
                requestMethod = "GET"
                connectTimeout = timeoutMs
                readTimeout = timeoutMs
                setRequestProperty("Accept", "application/dns-json")
                setRequestProperty("User-Agent", "WilyDiag/1.0")
            }
            val code = conn.responseCode
            val body = (if (code in 200..299) conn.inputStream else conn.errorStream)
                ?.bufferedReader(Charsets.UTF_8)?.use { it.readText() }.orEmpty()
            val ms = (System.currentTimeMillis() - t0).coerceAtLeast(1L)
            if (code !in 200..299) {
                Triple(emptyList(), ms, "HTTP $code")
            } else {
                Triple(parseDohAJson(body), ms, null)
            }
        } catch (e: Exception) {
            Triple(emptyList(), (System.currentTimeMillis() - t0).coerceAtLeast(1L), formatException(e))
        } finally {
            conn?.disconnect()
        }
    }

    internal fun parseDohAJson(json: String): List<String> =
        DOH_DATA_RE.findAll(json).map { it.groupValues[1] }.distinct().toList()

    /** Внешний выход (IP, страна, colo, warp=on/off) через Cloudflare trace. */
    fun probeCloudflareTrace(): Pair<Map<String, String>, String?> {
        val urls = listOf(
            "https://1.1.1.1/cdn-cgi/trace",
            "https://cloudflare.com/cdn-cgi/trace"
        )
        var lastErr: String? = null
        for (u in urls) {
            var conn: HttpURLConnection? = null
            try {
                conn = (URL(u).openConnection() as HttpURLConnection).apply {
                    connectTimeout = 3500
                    readTimeout = 3500
                    setRequestProperty("User-Agent", "WilyDiag/1.0")
                }
                if (conn.responseCode in 200..299) {
                    val text = conn.inputStream.bufferedReader().use { it.readText() }
                    val map = LinkedHashMap<String, String>()
                    text.lines().forEach { line ->
                        val idx = line.indexOf('=')
                        if (idx > 0) map[line.substring(0, idx).trim()] = line.substring(idx + 1).trim()
                    }
                    if (map.isNotEmpty()) return map to null
                } else {
                    lastErr = "HTTP ${conn.responseCode} ($u)"
                }
            } catch (e: Exception) {
                lastErr = "${formatException(e)} ($u)"
            } finally {
                conn?.disconnect()
            }
        }
        return emptyMap<String, String>() to lastErr
    }

    /** Проверка реального внешнего IPv6-доступа (прямой TCP 443 к 2606:4700:4700::1111). */
    fun probeExternalIpv6(): String? {
        val sock = Socket()
        return try {
            val addr = InetAddress.getByName("2606:4700:4700::1111")
            if (addr !is Inet6Address) return null
            sock.connect(InetSocketAddress(addr, 443), 2500)
            val local = sock.localAddress?.hostAddress?.substringBefore('%')
            local ?: "доступен (TCP 443 OK)"
        } catch (_: Exception) {
            null
        } finally {
            runCatching { sock.close() }
        }
    }

    /** Реальный DNS A-запрос по UDP 53 (проверяет, проходит ли открытый UDP 53). */
    fun probeDnsUdp53(label: String, serverIp: String, domain: String = "example.com"): UdpProbeResult {
        val t0 = System.currentTimeMillis()
        val txId = random.nextInt(0x10000)
        val req = buildDnsQueryPacket(txId, domain)
        val sock = DatagramSocket()
        return try {
            sock.soTimeout = 2500
            sock.send(DatagramPacket(req, req.size, InetAddress.getByName(serverIp), 53))
            val rx = ByteArray(512)
            val pkt = DatagramPacket(rx, rx.size)
            sock.receive(pkt)
            val rtt = (System.currentTimeMillis() - t0).coerceAtLeast(1L)
            val rxId = ((rx[0].toInt() and 0xFF) shl 8) or (rx[1].toInt() and 0xFF)
            val rcode = rx[3].toInt() and 0x0F
            val anCount = ((rx[6].toInt() and 0xFF) shl 8) or (rx[7].toInt() and 0xFF)
            val ok = pkt.length >= 12 && rxId == txId && rcode == 0
            UdpProbeResult(label, "$serverIp:53", "DNS", ok, rtt, "ответ ${pkt.length} Б, rcode=$rcode, answers=$anCount")
        } catch (e: Exception) {
            UdpProbeResult(label, "$serverIp:53", "DNS", false, (System.currentTimeMillis() - t0).coerceAtLeast(1L), formatException(e))
        } finally {
            runCatching { sock.close() }
        }
    }

    /** RFC 5389 STUN Binding Request по UDP (проверяет проходимость UDP и внешний NAT IP:порт). */
    fun probeStunUdp(host: String = "stun.l.google.com", port: Int = 19302): UdpProbeResult {
        val t0 = System.currentTimeMillis()
        val txId = ByteArray(12).also { random.nextBytes(it) }
        val req = buildStunBindingRequest(txId)
        val sock = DatagramSocket()
        return try {
            sock.soTimeout = 3000
            val ip = InetAddress.getAllByName(host).firstOrNull { it is Inet4Address } ?: InetAddress.getByName(host)
            sock.send(DatagramPacket(req, req.size, ip, port))
            val rx = ByteArray(512)
            val pkt = DatagramPacket(rx, rx.size)
            sock.receive(pkt)
            val rtt = (System.currentTimeMillis() - t0).coerceAtLeast(1L)
            val mapped = parseStunXorMappedAddress(rx, pkt.length)
            if (mapped != null) {
                UdpProbeResult("STUN (Google)", "$host:$port", "STUN", true, rtt, "внешний UDP NAT: $mapped")
            } else {
                UdpProbeResult("STUN (Google)", "$host:$port", "STUN", pkt.length >= 20, rtt, "ответ ${pkt.length} Б")
            }
        } catch (e: Exception) {
            UdpProbeResult("STUN (Google)", "$host:$port", "STUN", false, (System.currentTimeMillis() - t0).coerceAtLeast(1L), formatException(e))
        } finally {
            runCatching { sock.close() }
        }
    }

    /**
     * QUIC Version Negotiation probe (RFC 9000): 1200-байтный UDP-пакет на порт 443 с grease-версией `0x0a0a0a0a`.
     * Живой QUIC-сервер (YouTube, Cloudflare, Meta) обязан ответить пакетом Version Negotiation.
     * Если ответа нет — QUIC UDP 443 блокируется провайдером/ТСПУ или роутером.
     */
    fun probeQuicUdp443(label: String, host: String): UdpProbeResult {
        val t0 = System.currentTimeMillis()
        val req = buildQuicVersionProbePacket()
        val sock = DatagramSocket()
        return try {
            sock.soTimeout = 2500
            val ip = if (IPV4_RE.matches(host)) {
                InetAddress.getByName(host)
            } else {
                InetAddress.getAllByName(host).firstOrNull { it is Inet4Address } ?: InetAddress.getByName(host)
            }
            sock.send(DatagramPacket(req, req.size, ip, 443))
            val rx = ByteArray(1500)
            val pkt = DatagramPacket(rx, rx.size)
            sock.receive(pkt)
            val rtt = (System.currentTimeMillis() - t0).coerceAtLeast(1L)
            val isLongHeader = pkt.length >= 7 && (rx[0].toInt() and 0x80) != 0
            val ver = if (pkt.length >= 5) {
                ((rx[1].toInt() and 0xFF) shl 24) or
                    ((rx[2].toInt() and 0xFF) shl 16) or
                    ((rx[3].toInt() and 0xFF) shl 8) or
                    (rx[4].toInt() and 0xFF)
            } else -1
            val note = if (isLongHeader && ver == 0) {
                "QUIC Version Negotiation (${pkt.length} Б, IP ${ip.hostAddress})"
            } else {
                "UDP 443 ответил (${pkt.length} Б, IP ${ip.hostAddress})"
            }
            UdpProbeResult(label, "$host:443", "QUIC", true, rtt, note)
        } catch (e: Exception) {
            UdpProbeResult(label, "$host:443", "QUIC", false, (System.currentTimeMillis() - t0).coerceAtLeast(1L), formatException(e))
        } finally {
            runCatching { sock.close() }
        }
    }

    internal fun buildDnsQueryPacket(txId: Int, domain: String): ByteArray {
        val out = ArrayList<Byte>(64)
        out.add(((txId ushr 8) and 0xFF).toByte())
        out.add((txId and 0xFF).toByte())
        // Flags: standard query, RD=1 (0x0100)
        out.add(0x01); out.add(0x00)
        // QDCOUNT=1, ANCOUNT=0, NSCOUNT=0, ARCOUNT=0
        out.add(0x00); out.add(0x01)
        repeat(6) { out.add(0x00) }
        for (part in domain.trim('.').split('.')) {
            val bytes = part.toByteArray(Charsets.US_ASCII)
            out.add(bytes.size.toByte())
            bytes.forEach { out.add(it) }
        }
        out.add(0x00) // root
        out.add(0x00); out.add(0x01) // QTYPE = A
        out.add(0x00); out.add(0x01) // QCLASS = IN
        return out.toByteArray()
    }

    internal fun buildStunBindingRequest(txId12: ByteArray): ByteArray {
        require(txId12.size == 12)
        val buf = ByteArray(20)
        buf[0] = 0x00; buf[1] = 0x01 // Binding Request
        buf[2] = 0x00; buf[3] = 0x00 // Length = 0
        // Magic cookie: 0x2112A442
        buf[4] = 0x21; buf[5] = 0x12; buf[6] = 0xA4.toByte(); buf[7] = 0x42
        txId12.copyInto(buf, 8)
        return buf
    }

    internal fun parseStunXorMappedAddress(buf: ByteArray, len: Int): String? {
        if (len < 20) return null
        val cookie = byteArrayOf(0x21, 0x12, 0xA4.toByte(), 0x42)
        var off = 20
        while (off + 4 <= len) {
            val attrType = ((buf[off].toInt() and 0xFF) shl 8) or (buf[off + 1].toInt() and 0xFF)
            val attrLen = ((buf[off + 2].toInt() and 0xFF) shl 8) or (buf[off + 3].toInt() and 0xFF)
            off += 4
            if (off + attrLen > len) break
            if (attrType == 0x0020 && attrLen >= 8 && (buf[off + 1].toInt() and 0xFF) == 0x01) {
                val xPort = (((buf[off + 2].toInt() and 0xFF) shl 8) or (buf[off + 3].toInt() and 0xFF)) xor 0x2112
                val ip = (0..3).joinToString(".") { i ->
                    ((buf[off + 4 + i].toInt() and 0xFF) xor (cookie[i].toInt() and 0xFF)).toString()
                }
                return "$ip:$xPort"
            }
            if (attrType == 0x0001 && attrLen >= 8 && (buf[off + 1].toInt() and 0xFF) == 0x01) {
                val port = ((buf[off + 2].toInt() and 0xFF) shl 8) or (buf[off + 3].toInt() and 0xFF)
                val ip = (0..3).joinToString(".") { i -> (buf[off + 4 + i].toInt() and 0xFF).toString() }
                return "$ip:$port"
            }
            off += (attrLen + 3) and 3.inv()
        }
        return null
    }

    internal fun buildQuicVersionProbePacket(): ByteArray {
        val pkt = ByteArray(1200)
        pkt[0] = 0xC0.toByte() // Long header, Initial
        // Grease version (RFC 9000): 0x0a0a0a0a -> forces Version Negotiation reply
        pkt[1] = 0x0A; pkt[2] = 0x0A; pkt[3] = 0x0A; pkt[4] = 0x0A
        pkt[5] = 8 // DCID len = 8
        for (i in 0 until 8) pkt[6 + i] = (0x11 + i).toByte()
        pkt[14] = 8 // SCID len = 8
        for (i in 0 until 8) pkt[15 + i] = (0x21 + i).toByte()
        return pkt
    }

    private fun readLineAscii(inp: BufferedInputStream): String? {
        val sb = StringBuilder(64)
        var prev = -1
        var any = false
        while (true) {
            val b = inp.read()
            if (b == -1) return if (any) sb.toString() else null
            any = true
            if (b == '\n'.code) {
                if (prev == '\r'.code && sb.isNotEmpty()) sb.setLength(sb.length - 1)
                return sb.toString()
            }
            sb.append(b.toChar())
            prev = b
            if (sb.length > 4096) return sb.toString()
        }
    }

    private fun formatException(e: Exception): String {
        val cls = e.javaClass.simpleName
        val msg = e.message?.trim().orEmpty()
        return if (msg.isEmpty()) cls else "$cls: ${msg.take(140)}"
    }
}
