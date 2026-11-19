package dev.warpscout.core.tunnel

import dev.warpscout.core.crypto.Crypto
import dev.warpscout.core.model.JunkProfile
import dev.warpscout.core.model.Endpoint
import dev.warpscout.core.model.WarpConfig
import dev.warpscout.core.net.NetSettings
import dev.warpscout.core.wg.Wg
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetSocketAddress
import java.io.InputStream
import java.io.OutputStream

/**
 * UDP-канал, через который туннель ходит наружу. В Android реализация обязана вызвать
 * `VpnService.protect(socket)` до подключения — иначе пакеты туннеля попадут в сам туннель.
 */
interface UdpChannel {
    fun send(packet: ByteArray)

    /** `null` — таймаут ожидания. */
    fun receive(): ByteArray?

    fun close()
}

/** Обычный connected-datagram-сокет (используется CLI и тестами). */
class SocketUdpChannel(
    private val socket: DatagramSocket,
    private val endpoint: Endpoint,
    private val timeoutMs: Int = 1500
) : UdpChannel {

    init {
        if (!socket.isConnected) socket.connect(InetSocketAddress(endpoint.host, endpoint.port))
        socket.soTimeout = timeoutMs
    }

    override fun send(packet: ByteArray) {
        socket.send(DatagramPacket(packet, packet.size))
    }

    override fun receive(): ByteArray? {
        val buf = ByteArray(64 * 1024)
        val pkt = DatagramPacket(buf, buf.size)
        return try {
            socket.receive(pkt)
            buf.copyOfRange(0, pkt.length)
        } catch (e: Exception) {
            null
        }
    }

    override fun close() {
        runCatching { socket.close() }
    }
}

/**
 * Двусторонний поток между tun-устройством (InputStream/OutputStream) и UDP-сокетом:
 * WireGuard transport-пакеты в обе стороны, keepalive, счётчики, защита от повторов.
 *
 * Это тот самый «собственный туннель»: никакого чужого бэкенда не нужно — AWG отличается от
 * WireGuard только handshake-мусором перед инициацией, а он обрабатывается здесь же.
 */
class DataPlane(
    private val udp: UdpChannel,
    private val tunInput: InputStream,
    private val tunOutput: OutputStream,
    private val config: WarpConfig,
    private val settings: NetSettings = NetSettings(),
    private val log: (String) -> Unit = {}
) {

    @Volatile
    private var stopped = false

    /** Итог handshake: false — туннель не поднялся (эндпоинт молчит или ключи не подошли). */
    var handshakeOk: Boolean = false
        private set

    /** Сколько байт прошло в каждую сторону (для статистики в уведомлении). */
    @Volatile
    var bytesUp: Long = 0L
        private set
    @Volatile
    var bytesDown: Long = 0L
        private set

    private val lock = Any()
    private var session: Wg.Session? = null
    private var peerIndex: Int = 0
    private var localIndex: Int = 0

    fun stop() {
        stopped = true
        runCatching { udp.close() }
        runCatching { tunInput.close() }
        runCatching { tunOutput.close() }
    }

    /** @return true, если handshake удался и хотя бы один цикл передачи прошёл. */
    fun run(): Boolean {
        if (!handshake()) {
            log("handshake не прошёл — туннель не поднят")
            return false
        }
        handshakeOk = true
        log("handshake OK, туннель поднят")

        val reader = Thread({ tunToUdp() }, "warpscout-tun-out")
        reader.isDaemon = true
        reader.start()
        udpToTun()
        reader.join(1000)
        return true
    }

    // ------------------------------------------------------------- handshake

    private fun handshake(): Boolean {
        val localPriv = runCatching { Crypto.unBase64(config.account.privateB64) }.getOrNull() ?: return false
        if (localPriv.size != Wg.KEY_LEN) return false
        val localPub = Crypto.publicOf(localPriv)
        val peerPub = runCatching { Crypto.unBase64(config.account.peerPublicB64) }.getOrNull() ?: return false

        val junk: JunkProfile? = config.junk.takeIf { !it.isEmpty }
        var attempt = 0
        while (!stopped && attempt < maxOf(1, settings.attempts)) {
            attempt++
            val initiation = Wg.buildInitiation(localPriv, localPub, peerPub, Crypto.random.nextInt())
            localIndex = initiation.state.senderIndex
            if (junk != null) {
                val chunks = junk.i1 + junk.i2
                if (chunks.isNotEmpty()) {
                    for (i in 0 until settings.junkPacketsBeforeHandshake) {
                        val bytes = chunks[i % chunks.size].materialize(Crypto.random)
                        if (bytes.isNotEmpty()) runCatching { udp.send(bytes) }
                    }
                }
            }
            udp.send(initiation.packet)

            val deadline = System.currentTimeMillis() + settings.timeoutMs
            var reply: ByteArray? = null
            while (reply == null && !stopped && System.currentTimeMillis() < deadline) {
                val pkt = udp.receive() ?: continue
                val type = if (pkt.size >= 4) Crypto.readLe32(pkt, 0) else -1
                if (type == Wg.TYPE_INITIATION || type == Wg.TYPE_TRANSPORT) continue   // не наш пакет
                reply = pkt
            }
            if (reply == null) {
                log("попытка $attempt: ответа нет (${settings.timeoutMs} мс)")
                continue
            }
            val res = Wg.consumeResponse(reply, initiation, peerPub)
            when (res.kind) {
                Wg.ResponseKind.HANDSHAKE_RESPONSE -> {
                    val s = res.session ?: continue
                    val idx = res.peerSenderIndex ?: continue
                    session = s
                    peerIndex = idx
                    return true
                }
                Wg.ResponseKind.COOKIE_REPLY -> {
                    val cookie = res.cookie
                    if (cookie == null) {
                        log("cookie reply, но cookie не расшифровался")
                        continue
                    }
                    log("сервер требует cookie — повторяю инициацию")
                    val retry = Wg.buildInitiation(localPriv, localPub, peerPub, Crypto.random.nextInt(), lastCookie = cookie)
                    localIndex = retry.state.senderIndex
                    udp.send(retry.packet)
                    val deadline2 = System.currentTimeMillis() + settings.timeoutMs
                    var reply2: ByteArray? = null
                    while (reply2 == null && !stopped && System.currentTimeMillis() < deadline2) {
                        val p2 = udp.receive() ?: continue
                        if (p2.size >= 4 && Crypto.readLe32(p2, 0) == Wg.TYPE_RESPONSE) reply2 = p2
                    }
                    if (reply2 == null) {
                        log("после cookie ответа нет")
                        continue
                    }
                    val res2 = Wg.consumeResponse(reply2, retry, peerPub)
                    val s2 = res2.session ?: continue
                    val idx2 = res2.peerSenderIndex ?: continue
                    session = s2
                    peerIndex = idx2
                    return true
                }
                else -> log("попытка $attempt: ${res.kind}")
            }
        }
        return false
    }

    // --------------------------------------------------------------- пересылка

    private fun tunToUdp() {
        val mtu = config.mtu.coerceIn(576, 1420)
        val buf = ByteArray(mtu)
        while (!stopped) {
            val n = try {
                tunInput.read(buf)
            } catch (e: Exception) {
                -1
            }
            if (n < 0) break
            if (n == 0) continue
            val payload = buf.copyOf(n)
            val packet: ByteArray? = synchronized(lock) {
                val s = session
                if (s == null) null else {
                    val (pkt, next) = Wg.buildTransport(peerIndex, s, payload)
                    session = next
                    pkt
                }
            }
            if (packet == null) break
            try {
                udp.send(packet)
                bytesUp += n
            } catch (e: Exception) {
                if (!stopped) log("отправка: ${e.javaClass.simpleName}")
                break
            }
        }
        stopped = true
    }

    private fun udpToTun() {
        var lastOut = System.currentTimeMillis()
        while (!stopped) {
            val pkt = udp.receive()
            if (pkt != null) {
                val plain = synchronized(lock) {
                    val s = session ?: return@synchronized null
                    val opened = Wg.openTransport(pkt, localIndex, s) ?: return@synchronized null
                    session = opened.second
                    opened.first
                }
                if (plain != null && plain.isNotEmpty()) {
                    try {
                        tunOutput.write(plain)
                        tunOutput.flush()
                        bytesDown += plain.size
                        lastOut = System.currentTimeMillis()
                    } catch (e: Exception) {
                        if (!stopped) log("в tun: ${e.javaClass.simpleName}")
                        break
                    }
                }
            }
            val ka = config.persistentKeepalive
            if (ka != null && ka > 0) {
                val idle = System.currentTimeMillis() - lastOut
                if (idle >= ka * 1000L) {
                    val keep = synchronized(lock) {
                        val s = session ?: return@synchronized null
                        val (pkt2, next) = Wg.buildTransport(peerIndex, s, ByteArray(0))
                        session = next
                        pkt2
                    }
                    keep?.let { runCatching { udp.send(it) } }
                    lastOut = System.currentTimeMillis()
                }
            }
        }
    }

}
