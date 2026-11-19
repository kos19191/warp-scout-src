package dev.warpscout.core.net

import dev.warpscout.core.crypto.Crypto
import dev.warpscout.core.model.Endpoint
import dev.warpscout.core.model.EndpointStats
import dev.warpscout.core.model.JunkProfile
import dev.warpscout.core.model.ProbeSample
import dev.warpscout.core.model.Verdict
import dev.warpscout.core.model.WarpAccount
import dev.warpscout.core.wg.Wg
import java.net.ConnectException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.NoRouteToHostException
import java.net.Socket
import java.net.SocketException
import java.net.SocketTimeoutException
import java.net.UnknownHostException
import java.util.concurrent.Callable
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicInteger

/**
 * Создание сокетов вынесено в фабрики: в приложении на Android мы привязываем сокет к конкретной
 * сети (ConnectivityManager#Network), чтобы уметь измерять «без VPN» даже когда туннель уже поднят,
 * и наоборот — мерить внутри туннеля. В CLI/на десктопе фабрики по умолчанию.
 */
fun interface UdpSocketFactory {
    fun create(endpoint: Endpoint): DatagramSocket
}

fun interface TcpSocketFactory {
    fun create(endpoint: Endpoint): Socket
}

object DefaultFactories {
    val udp = UdpSocketFactory { DatagramSocket(null).apply {
        // connect() обязателен: только на connected-сокете Linux/Android отдаёт ICMP «port unreachable»
        // как SocketException, а это для нас единственный способ отличить закрытый порт от чёрной дыры.
        reuseAddress = true
    } }
    val tcp = TcpSocketFactory { Socket() }
}

data class NetSettings(
    val attempts: Int = 4,
    val timeoutMs: Int = 1200,
    val connectTimeoutMs: Int = 4000,
    val concurrency: Int = 48,
    val betweenAttemptsMs: Int = 60,
    val junkPacketsBeforeHandshake: Int = 1,
    val udpFactory: UdpSocketFactory = DefaultFactories.udp,
    val tcpFactory: TcpSocketFactory = DefaultFactories.tcp,
    /**
     * Локальный SOCKS5 (по умолчанию — то, что поднимает ByeDPI for Android). Ставится только для
     * TCP-проб: UDP-хэндшейк WireGuard через SOCKS5 не пушится, а вот TLS-пробы MASQUE и HTTP-замеры
     * ресурсов через него идут и показывают, что изменит обход DPI.
     */
    val socks5: Socks5Endpoint? = null
)

/** Результат пробы одной конечной точки. */
data class WgProbeResult(val stats: EndpointStats, val accepted: Boolean, val replyTypes: List<Int>)

/**
 * Проба «это живой WireGuard/AmneziaWG-сервер, и он принимает НАШ ключ».
 *
 * Отправка: [мусорные пакеты выбранного профиля] → handshake initiation (148 байт).
 * Ответ:   handshake response (92) — проверяем receiver_index, MAC1 и AEAD-тег;
 *          cookie reply (60) — тоже признак живого сервера.
 * Молчание/ICMP — отличаем друг от друга по ECONNREFUSED на connected UDP-сокете.
 */
class WgProber(private val settings: NetSettings) {

    fun probe(
        endpoint: Endpoint,
        account: WarpAccount,
        peerPublic: ByteArray,
        junk: JunkProfile? = null
    ): WgProbeResult {
        val samples = ArrayList<ProbeSample>()
        val replyTypes = mutableListOf<Int>()
        var accepted = false

        val address = try {
            InetAddress.getByName(endpoint.host)
        } catch (e: UnknownHostException) {
            return WgProbeResult(
                EndpointStats(endpoint, listOf(
                    ProbeSample(endpoint, Verdict.DNS_FAIL, note = "не разрешился ${endpoint.host}")
                ), Verdict.DNS_FAIL, 0, settings.attempts), false, replyTypes
            )
        }

        val localPriv = Crypto.unBase64(account.privateB64)
        val localPub = Crypto.publicOf(localPriv)
        val socket = try {
            settings.udpFactory.create(endpoint).apply {
                soTimeout = settings.timeoutMs
                connect(InetSocketAddress(address, endpoint.port))
            }
        } catch (e: Exception) {
            return WgProbeResult(
                EndpointStats(endpoint, listOf(ProbeSample(endpoint, Verdict.ERROR, note = "сокет: ${e.message}")),
                    Verdict.ERROR, 0, settings.attempts), false, replyTypes
            )
        }

        try {
            for (attempt in 0 until settings.attempts) {
                val initiation = Wg.buildInitiation(localPriv, localPub, peerPublic, Crypto.random.nextInt())
                val t0 = System.nanoTime()
                try {
                    if (junk != null && !junk.isEmpty && settings.junkPacketsBeforeHandshake > 0) {
                        val chunks = junk.i1 + junk.i2
                        if (chunks.isNotEmpty()) {
                            for (i in 0 until settings.junkPacketsBeforeHandshake) {
                                val bytes = chunks[i % chunks.size].materialize(Crypto.random)
                                if (bytes.isNotEmpty()) socket.send(DatagramPacket(bytes, bytes.size))
                                val spread = (junk.awg.jmax - junk.awg.jmin).coerceAtLeast(0)
                                Thread.sleep((junk.awg.jmin + Crypto.random.nextInt(spread + 1)).toLong())
                            }
                        }
                    }
                    socket.send(DatagramPacket(initiation.packet, initiation.packet.size))

                    val buf = ByteArray(2048)
                    val pkt = DatagramPacket(buf, buf.size)
                    socket.receive(pkt)
                    val rtt = (System.nanoTime() - t0) / 1e6
                    val data = pkt.data.copyOfRange(0, pkt.length)
                    val type = if (data.size >= 4) Crypto.readLe32(data, 0) else -1
                    replyTypes.add(type)
                    val reply = Wg.consumeResponse(data, initiation, peerPublic)
                    var verdict = when (reply.kind) {
                        Wg.ResponseKind.HANDSHAKE_RESPONSE -> { accepted = true; Verdict.HANDSHAKE_OK }
                        Wg.ResponseKind.COOKIE_REPLY -> { accepted = true; Verdict.COOKIE_REPLY }
                        Wg.ResponseKind.MISMATCH -> Verdict.UDP_SILENT
                        Wg.ResponseKind.MALFORMED -> Verdict.UDP_SILENT
                    }
                    var note = "type=$type len=${data.size} ${reply.kind}"
                    if (reply.kind == Wg.ResponseKind.COOKIE_REPLY && reply.cookie != null) {
                        // Сервер перегружен и требует cookie. Повторяем инициацию с mac2 =
                        // MAC(cookie) — если и тогда придёт валидный ответ, endpoint точно живой.
                        val retry = Wg.buildInitiation(
                            localPriv, localPub, peerPublic, Crypto.random.nextInt(), lastCookie = reply.cookie
                        )
                        val ok = runCatching {
                            socket.send(DatagramPacket(retry.packet, retry.packet.size))
                            val pkt2 = DatagramPacket(ByteArray(2048), 2048)
                            socket.receive(pkt2)
                            Wg.consumeResponse(pkt2.data.copyOfRange(0, pkt2.length), retry, peerPublic)
                                .kind == Wg.ResponseKind.HANDSHAKE_RESPONSE
                        }.getOrDefault(false)
                        if (ok) {
                            accepted = true; verdict = Verdict.HANDSHAKE_OK; note += " +cookie-retry"
                        }
                    }
                    samples.add(ProbeSample(endpoint, verdict, rtt, attempt, junk?.name ?: "none", note = note))
                } catch (e: SocketTimeoutException) {
                    samples.add(ProbeSample(endpoint, Verdict.UDP_SILENT, null, attempt, junk?.name ?: "none",
                        note = "нет ответа ${settings.timeoutMs}мс"))
                } catch (e: Exception) {
                    val closed = e is ConnectException || e is NoRouteToHostException ||
                        (e is SocketException && e.message?.contains("ECONNREFUSED") == true) ||
                        (e.message?.contains("Connection refused", true) == true) ||
                        (e.message?.contains("unreachable", true) == true)
                    samples.add(ProbeSample(endpoint, if (closed) Verdict.UDP_CLOSED else Verdict.ERROR,
                        null, attempt, junk?.name ?: "none", note = e.javaClass.simpleName + ": " + e.message))
                }
                if (attempt < settings.attempts - 1 && settings.betweenAttemptsMs > 0) {
                    Thread.sleep(settings.betweenAttemptsMs.toLong())
                }
            }
        } finally {
            runCatching { socket.close() }
        }

        val replies = samples.count { it.verdict in setOf(Verdict.HANDSHAKE_OK, Verdict.COOKIE_REPLY, Verdict.TLS_OK) }
        val best = samples.minByOrNull { it.verdict.rank }?.verdict ?: Verdict.ERROR
        return WgProbeResult(EndpointStats(endpoint, samples, best, replies, samples.size), accepted, replyTypes)
    }

    /** Параллельный скан по пулу конечных точек. */
    fun scan(
        endpoints: List<Endpoint>,
        account: WarpAccount,
        peerPublic: ByteArray,
        junk: JunkProfile? = null,
        onProgress: ((done: Int, total: Int, EndpointStats) -> Unit)? = null
    ): List<EndpointStats> {
        val pool = Executors.newFixedThreadPool(settings.concurrency.coerceIn(1, 256))
        val done = AtomicInteger(0)
        try {
            val futures = endpoints.map { ep ->
                pool.submit(Callable {
                    val res = probe(ep, account, peerPublic, junk)
                    onProgress?.invoke(done.incrementAndGet(), endpoints.size, res.stats)
                    res.stats
                })
            }
            return futures.mapNotNull { runCatching { it.get() }.getOrNull() }
        } finally {
            pool.shutdownNow()
        }
    }
}

/**
 * TLS/TCP-проба. Нужна в основном для MASQUE (QUIC/HTTP/3 поверх 443/8443/…): там сервер честно
 * отвечает на TLS ClientHello, и это надёжнее любого UDP-гадания.
 */
class TlsProber(private val settings: NetSettings) {

    fun probe(endpoint: Endpoint, sni: String = endpoint.host, alpn: List<String> = listOf("h3", "h2")): ProbeSample {
        val t0 = System.nanoTime()
        var sock: Socket? = null
        return try {
            sock = settings.socks5?.takeIf { it.configured }?.let {
                // Сокет уже соединён (SOCKS5 CONNECT сделан), поэтому ниже не коннектимся второй раз.
                Socks5.connect(it, endpoint.host, endpoint.port, settings.connectTimeoutMs, settings.tcpFactory)
            } ?: settings.tcpFactory.create(endpoint).apply {
                connect(InetSocketAddress(endpoint.host, endpoint.port), settings.connectTimeoutMs)
            }
            val ctx = javax.net.ssl.SSLContext.getInstance("TLS")
            ctx.init(null, arrayOf(TrustAll), null)
            val ssl = ctx.socketFactory.createSocket(sock, sni, endpoint.port, true) as javax.net.ssl.SSLSocket
            sock = ssl
            // ALPN h3/h2 ставим аккуратно: на части Android-провайдеров setApplicationProtocols нет.
            runCatching {
                val params = ssl.sslParameters
                params.applicationProtocols = alpn.toTypedArray()
                ssl.sslParameters = params
            }
            ssl.soTimeout = settings.connectTimeoutMs
            ssl.startHandshake()
            val session = ssl.session
            ProbeSample(endpoint, Verdict.TLS_OK, (System.nanoTime() - t0) / 1e6, 0, "tls",
                note = "proto=${session?.protocol} cipher=${session?.cipherSuite?.take(18)}")
        } catch (e: SocketTimeoutException) {
            ProbeSample(endpoint, Verdict.UDP_SILENT, (System.nanoTime() - t0) / 1e6, 0, "tls", "таймаут TCP")
        } catch (e: ConnectException) {
            ProbeSample(endpoint, Verdict.UDP_CLOSED, (System.nanoTime() - t0) / 1e6, 0, "tls", "refused")
        } catch (e: UnknownHostException) {
            ProbeSample(endpoint, Verdict.DNS_FAIL, null, 0, "tls", "DNS: ${e.message}")
        } catch (e: Exception) {
            ProbeSample(endpoint, Verdict.ERROR, (System.nanoTime() - t0) / 1e6, 0, "tls",
                "${e.javaClass.simpleName}: ${e.message?.take(80)}")
        } finally {
            runCatching { sock?.close() }
        }
    }

    private val TrustAll = object : javax.net.ssl.X509TrustManager {
        override fun checkClientTrusted(chain: Array<java.security.cert.X509Certificate>?, authType: String?) {}
        override fun checkServerTrusted(chain: Array<java.security.cert.X509Certificate>?, authType: String?) {}
        override fun getAcceptedIssuers(): Array<java.security.cert.X509Certificate> = arrayOf()
    }
}
