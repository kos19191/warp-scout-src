package dev.warpscout.core.tunnel

import dev.warpscout.core.model.Endpoint
import dev.warpscout.core.net.NetSettings
import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.EOFException
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketTimeoutException
import java.net.UnknownHostException
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.X509TrustManager
import javax.security.cert.X509Certificate

/**
 * TCP/TLS-канал, реализующий [UdpChannel] — поэтому им можно заменить UDP-сокет в [DataPlane]
 * и гонять WireGuard-пакеты через TCP 443 с TLS-маскировкой.
 *
 * Зачем. В режиме белых списков сеть режет не сигнатуры, а сам факт UDP к иностранным IP.
 * TCP 443 к домену из белого списка (госуслуги, банки, поиск) проходит — поэтому оборачиваем
 * каждый пакет WireGuard в TLS-сессию с whitelisted SNI. Снаружи это выглядит как обычный
 * HTTPS к разрешённому сайту, а внутри — полноценный WireGuard-туннель.
 *
 * Фрейминг: каждая датаграмма уходит как 2 байта длины (big-endian) + данные. Это позволяет
 * читать сообщения потоково, не зная заранее их размера.
 *
 * TLS: доверяем любому сертификату (как [TlsProber]), SNI берём из конфига или подставляем
 * whitelisted домен. ALPN не ставим — хотим выглядеть как обычный TLS-клиент, а не HTTP/2.
 */
class TcpChannel(
    private val endpoint: Endpoint,
    private val sni: String,
    private val settings: NetSettings = NetSettings(),
    connectTimeoutMs: Int = 8000,
    readTimeoutMs: Int = 5000,
    private val log: (String) -> Unit = {}
) : UdpChannel {

    private var sock: Socket? = null
    private var ssl: javax.net.ssl.SSLSocket? = null
    private var inStream: BufferedInputStream? = null
    private var outStream: BufferedOutputStream? = null
    @Volatile
    private var closed = false

    init {
        connect(connectTimeoutMs)
    }

    private fun connect(timeoutMs: Int) {
        val address = try {
            java.net.InetAddress.getByName(endpoint.host)
        } catch (e: UnknownHostException) {
            throw IllegalStateException("Не удалось разрешить ${endpoint.host}: ${e.message}")
        }
        sock = settings.tcpFactory.create(endpoint).apply {
            connect(InetSocketAddress(address, endpoint.port), timeoutMs)
            soTimeout = readTimeoutMs
            tcpNoDelay = true
        }

        val ctx = SSLContext.getInstance("TLS")
        ctx.init(null, arrayOf(TrustAll), null)
        ssl = ctx.socketFactory.createSocket(sock!!, sni, endpoint.port, true) as SSLSocket
        sock = ssl
        ssl.soTimeout = readTimeoutMs

        // Не ставим ALPN — выглядим как обычный TLS-клиент, не как браузер.
        runCatching {
            val params = ssl!!.sslParameters
            // applicationProtocols доступен не на всех Android, поэтому обёртка.
            params.applicationProtocols = arrayOf()
            ssl!!.sslParameters = params
        }

        ssl!!.startHandshake()

        inStream = BufferedInputStream(ssl!!.inputStream, 8192)
        outStream = BufferedOutputStream(ssl!!.outputStream, 8192)
        log("TCP-канал подключён: $endpoint (SNI=$sni), TLS ${ssl!!.session.protocol}")
    }

    override fun send(packet: ByteArray) {
        if (closed || outStream == null) throw IllegalStateException("Канал закрыт")
        if (packet.size > 65535) throw IllegalArgumentException("Пакет слишком велик для TCP-фрейма: ${packet.size}")
        // 2 байта длины (big-endian) + данные.
        outStream!!.write(packet.size shr 8 and 0xFF)
        outStream!!.write(packet.size and 0xFF)
        outStream!!.write(packet)
        outStream!!.flush()
    }

    override fun receive(): ByteArray? {
        if (closed || inStream == null) return null
        return try {
            val lenHi = inStream!!.read()
            if (lenHi == -1) return null // конец потока
            val lenLo = inStream!!.read()
            if (lenLo == -1) throw EOFException("Обрезан заголовок длины")
            val len = (lenHi shl 8) or (lenLo and 0xFF)
            if (len <= 0 || len > 65535) throw EOFException("Некорректная длина фрейма: $len")
            val buf = ByteArray(len)
            var read = 0
            while (read < len) {
                val n = inStream!!.read(buf, read, len - read)
                if (n == -1) throw EOFException("Конец потока посередине фрейма")
                read += n
            }
            buf
        } catch (e: SocketTimeoutException) {
            null // таймаут — нет данных, это нормально
        } catch (e: EOFException) {
            null // сторона закрыла соединение
        } catch (e: Exception) {
            if (!closed) log("Ошибка чтения TCP: ${e.javaClass.simpleName}: ${e.message}")
            null
        }
    }

    override fun close() {
        if (closed) return
        closed = true
        runCatching { outStream?.close() }
        runCatching { inStream?.close() }
        runCatching { sock?.close() }
        sock = null
        ssl = null
        inStream = null
        outStream = null
    }

    private val TrustAll = object : X509TrustManager {
        override fun checkClientTrusted(chain: Array<X509Certificate>?, authType: String?) {}
        override fun checkServerTrusted(chain: Array<X509Certificate>?, authType: String?) {}
        override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
    }
}

/**
 * MASQUE-транспорт: WireGuard-over-TCP через whitelisted SNI.
 *
 * Подбирает endpoint из пула MASQUE (162.159.198/199.*, порты 443/8443/4443/8095)
 * и whitelisted SNI из SniSource. Возвращает [TcpChannel], готовый к передаче в [DataPlane].
 *
 * Использование:
 *   val channel = MasqueTransport.open(settings, sniSource, log)
 *   val plane = DataPlane(channel, tunInput, tunOutput, config)
 */
object MasqueTransport {

    /** Подсети MASQUE — те же, что в [WarpDefaults.MASQUE_SUBNETS]. */
    private val MASQUE_SUBNETS = listOf("162.159.198.", "162.159.199.")
    private val MASQUE_PORTS = listOf(443, 8443, 4443, 8095)

    /**
     * Открывает TCP/TLS-канал к первому ответившему MASQUE-endpoint.
     *
     * @param settings настройки сети;
     * @param sniSource источник SNI-доменов;
     * @param maxAttempts сколько endpoint'ов перебирать (по умолчанию все);
     * @param log куда писать прогресс;
     * @return открытый канал или null, если ни один endpoint не ответил.
     */
    fun open(
        settings: NetSettings = NetSettings(),
        sni: String,
        maxAttempts: Int = 8,
        log: (String) -> Unit = {}
    ): TcpChannel? {
        val endpoints = buildEndpoints().take(maxAttempts)
        for (ep in endpoints) {
            log("MASQUE: пробуем $ep (SNI=$sni)…")
            return try {
                TcpChannel(ep, sni, settings, log = log)
            } catch (e: Exception) {
                log("MASQUE: $ep не répondu: ${e.message?.take(100)}")
                null
            }
        }
        log("MASQUE: ни один endpoint не ответил")
        return null
    }

    private fun buildEndpoints(): List<Endpoint> {
        val out = mutableListOf<Endpoint>()
        for (subnet in MASQUE_SUBNETS) {
            for (octet in 1..10) {
                for (port in MASQUE_PORTS) {
                    out += Endpoint("$subnet$octet", port)
                }
            }
        }
        return out
    }
}
