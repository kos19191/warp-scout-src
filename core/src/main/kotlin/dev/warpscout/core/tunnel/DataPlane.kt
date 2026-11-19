package dev.warpscout.core.tunnel

import dev.warpscout.core.crypto.Crypto
import dev.warpscout.core.model.Endpoint
import dev.warpscout.core.model.JunkProfile
import dev.warpscout.core.model.WarpConfig
import dev.warpscout.core.net.NetSettings
import dev.warpscout.core.wg.Wg
import java.io.InputStream
import java.io.OutputStream
import java.net.DatagramSocket
import java.net.InetSocketAddress
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit

/** Куда отправлять собранные пакеты и откуда брать входящие (сокет, туннель, пара сокетов в тестах). */
interface UdpChannel {
    fun send(packet: ByteArray)
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
        socket.send(java.net.DatagramPacket(packet, packet.size))
    }

    override fun receive(): ByteArray? = try {
        val buf = ByteArray(65536)
        val p = java.net.DatagramPacket(buf, buf.size)
        socket.receive(p)
        p.data.copyOfRange(0, p.length)
    } catch (e: java.net.SocketTimeoutException) {
        null
    }

    override fun close() {
        runCatching { socket.close() }
    }
}

/**
 * Двусторонний поток между tun-устройством (InputStream/OutputStream) и UDP-сокетом:
 * WireGuard transport-пакеты в обе стороны, **пересогласование сессии**, keepalive, счётчики,
 * защита от повторов.
 *
 * Про rekey — это была главная причина «работает 3–5 минут, потом Telegram пишет Соединение…».
 * WireGuard-сессия не вечная: ядро само пересогласовывает её через `REKEY_AFTER_TIME` (120 с),
 * а через `REJECT_AFTER_TIME` (180 с) отбрасывает. Раньше handshake делался один раз при старте,
 * дальше сессия умирала молча: keepalive уходил в никуда, ответный handshake-пакет (тип 2) в
 * транспортном цикле отбрасывался как «не наш», и туннель «оставался поднятым» без данных.
 *
 * Теперь: один читатель сокета на всё, handshake-ответы уходят в очередь ожидающего
 * пересогласования, таймер в 120 с инициирует rekey и повторяет его каждые 5 с, пока не получится.
 * Старая сессия живёт до подтверждения новой, поэтому TCP-соединения не рвутся.
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
    @Volatile
    var handshakeOk: Boolean = false
        private set

    /** Сколько попыток инициации реально ушло в сеть — без этого «тихий» отказ не объяснить. */
    @Volatile
    var attemptCount: Int = 0
        private set

    /** Почему handshake не состоялся (null — причина не задокументирована, например пользователь остановил). */
    @Volatile
    var failureReason: String? = null
        private set

    /** Сколько раз сессия успешно пересогласовывалась после старта. */
    @Volatile
    var rekeyCount: Int = 0
        private set

    /** Последняя неудача rekey — для журнала туннеля («сессия не восстанавливается»). */
    @Volatile
    var lastRekeyFailure: String? = null
        private set

    /** Сколько байт прошло в каждую сторону (для статистики в уведомлении). */
    @Volatile
    var bytesUp: Long = 0L
        private set

    @Volatile
    var bytesDown: Long = 0L
        private set

    @Volatile
    private var sessionStartedAt: Long = 0L

    @Volatile
    private var lastOutboundAt: Long = 0L

    private val lock = Any()
    private var session: Wg.Session? = null
    private var peerIndex: Int = 0
    private var localIndex: Int = 0

    /** Ответы на наши инициации (тип 2/3): один читатель — сюда, ожидающий — оттуда. */
    private val handshakeInbox = LinkedBlockingQueue<ByteArray>(16)

    private val localPriv: ByteArray? by lazy {
        runCatching { Crypto.unBase64(config.account.privateB64) }.getOrNull()
            ?.takeIf { it.size == Wg.KEY_LEN }
    }
    private val localPub: ByteArray? by lazy { localPriv?.let { Crypto.publicOf(it) } }
    private val peerPub: ByteArray? by lazy {
        runCatching { Crypto.unBase64(config.account.peerPublicB64) }.getOrNull()
            ?.takeIf { it.size == Wg.KEY_LEN }
    }

    fun stop() {
        stopped = true
        runCatching { udp.close() }
        runCatching { tunInput.close() }
        runCatching { tunOutput.close() }
    }

    /** Возраст текущей сессии: по нему видно, жива ли она вообще. */
    fun sessionAgeMs(): Long = if (sessionStartedAt == 0L) 0 else System.currentTimeMillis() - sessionStartedAt

    /** @return true, если handshake удался и передача шла (поток завершается при stop()). */
    fun run(): Boolean {
        if (localPriv == null || localPub == null) return fail("PrivateKey не разбирается как base64 или короче ${Wg.KEY_LEN} байт")
        if (peerPub == null) return fail("PublicKey пира не разбирается как base64 или короче ${Wg.KEY_LEN} байт")

        // Читатель стартует ДО handshake: теперь он один на всё — и транспорт, и ответы на rekey.
        val reader = Thread({ readerLoop() }, "warpscout-tunnel-in").apply { isDaemon = true; start() }

        if (!negotiate(initial = true)) {
            log("handshake не прошёл — туннель не поднят")
            stop()
            reader.join(1000)
            return false
        }
        handshakeOk = true
        log("handshake OK, туннель поднят")

        val timers = Thread({ timerLoop() }, "warpscout-tunnel-timers").apply { isDaemon = true; start() }
        val sender = Thread({ tunToUdp() }, "warpscout-tunnel-out").apply { isDaemon = true; start() }

        reader.join()
        sender.join(1000)
        timers.interrupt()
        return true
    }

    // --------------------------------------------------------------- читатель

    private fun readerLoop() {
        while (!stopped) {
            // Закрытие сокета при stop() — штатный выход, а не ошибка: ловим и уходим.
            val pkt = try {
                udp.receive()
            } catch (e: Exception) {
                if (!stopped) log("чтение сокета: ${e.javaClass.simpleName}: ${e.message}")
                return
            } ?: continue
            if (pkt.isEmpty()) continue
            val type = if (pkt.size >= 4) Crypto.readLe32(pkt, 0) else -1
            when (type) {
                // Ответ на инициацию (в том числе на rekey) или cookie reply — отдаём ожидающему.
                Wg.TYPE_RESPONSE, Wg.TYPE_COOKIE -> handshakeInbox.offer(pkt)
                Wg.TYPE_TRANSPORT -> deliver(pkt)
                else -> Unit // junk/чужое: молча игнорируем, иначе журнал забьётся мусором
            }
        }
    }

    private fun deliver(pkt: ByteArray) {
        val plain = synchronized(lock) {
            val s = session ?: return
            val idx = localIndex
            val opened = Wg.openTransport(pkt, idx, s) ?: return
            session = opened.second
            opened.first
        }
        if (plain.isEmpty()) return
        try {
            tunOutput.write(plain)
            tunOutput.flush()
            bytesDown += plain.size
        } catch (e: Exception) {
            if (!stopped) log("в tun: ${e.javaClass.simpleName}: ${e.message}")
            stop()
        }
    }

    // ------------------------------------------------------------- handshake

    /**
     * Одна итерация пересогласования: инициация → (cookie) → ответ, с дедлайном.
     * Вызывается и при старте, и таймером для rekey — код один, поэтому rekey не может «отстать»
     * от основного пути по обработке cookie или мусора.
     */
    private fun negotiate(initial: Boolean): Boolean {
        val priv = localPriv ?: return fail("нет приватного ключа")
        val pub = localPub ?: return fail("нет публичного ключа")
        val peer = peerPub ?: return fail("нет ключа пира")
        val junk: JunkProfile? = config.junk.takeIf { !it.isEmpty }
        val attempts = maxOf(1, settings.attempts)

        var attempt = 0
        while (!stopped && attempt < attempts) {
            attempt++
            attemptCount = attempt
            var initiation = Wg.buildInitiation(priv, pub, peer, Crypto.random.nextInt())
            if (junk != null) sendJunk(junk)
            udp.send(initiation.packet)

            val deadline = System.currentTimeMillis() + settings.timeoutMs
            while (!stopped && System.currentTimeMillis() < deadline) {
                val remaining = (deadline - System.currentTimeMillis()).coerceAtLeast(1)
                val reply = handshakeInbox.poll(remaining, TimeUnit.MILLISECONDS) ?: continue
                val res = Wg.consumeResponse(reply, initiation, peer)
                when (res.kind) {
                    Wg.ResponseKind.HANDSHAKE_RESPONSE -> {
                        val s = res.session
                        val idx = res.peerSenderIndex
                        if (s == null || idx == null) continue
                        install(s, idx, initiation.state.senderIndex, initial)
                        return true
                    }

                    Wg.ResponseKind.COOKIE_REPLY -> {
                        val cookie = res.cookie
                        if (cookie == null) {
                            log("cookie reply, но cookie не расшифровался")
                            continue
                        }
                        log("сервер требует cookie — повторяю инициацию")
                        initiation = Wg.buildInitiation(priv, pub, peer, Crypto.random.nextInt(), lastCookie = cookie)
                        if (junk != null) sendJunk(junk)
                        udp.send(initiation.packet)
                    }

                    // Ответ на другую (просроченную) инициацию — не наш, ждём дальше.
                    Wg.ResponseKind.MISMATCH -> continue
                    else -> continue
                }
            }
            if (!stopped) {
                failureReason = "сервер молчит: $attempt ${if (attempt == 1) "попытка" else "попыток"} " +
                    "по ${settings.timeoutMs} мс без ответа"
                log("попытка $attempt: ответа нет (${settings.timeoutMs} мс)")
            }
        }
        return false
    }

    private fun sendJunk(junk: JunkProfile) {
        val chunks = junk.i1 + junk.i2
        if (chunks.isEmpty()) return
        for (i in 0 until settings.junkPacketsBeforeHandshake) {
            val bytes = chunks[i % chunks.size].materialize(Crypto.random)
            if (bytes.isNotEmpty()) runCatching { udp.send(bytes) }
        }
    }

    private fun install(s: Wg.Session, peer: Int, local: Int, initial: Boolean) {
        synchronized(lock) {
            session = s
            peerIndex = peer
            localIndex = local
            sessionStartedAt = System.currentTimeMillis()
        }
        handshakeInbox.clear() // чужие/старые ответы больше не нужны
        // WireGuard подтверждает новую сессию первым transport-пакетом; пустой keepalive делает это
        // сразу, не дожидаясь, пока пользователь что-нибудь отправит (иначе сервер может продолжать
        // считать активной старую сессию, а мы уже шифруем новой — и данные «теряются»).
        sendKeepalive()
        if (!initial) {
            rekeyCount++
            lastRekeyFailure = null
            log("rekey OK: сессия обновлена (${rekeyCount}-й раз)")
        }
    }

    // ---------------------------------------------------------------- таймеры

    /**
     * Rekey и keepalive. Отдельный поток, потому что пересогласование занимает до нескольких
     * секунд и не должно останавливать пересылку.
     */
    private fun timerLoop() {
        var lastAttemptAt = 0L
        var warnedExpiry = false
        while (!stopped) {
            runCatching { Thread.sleep(200) }
            if (stopped) return
            val now = System.currentTimeMillis()
            val age = if (sessionStartedAt == 0L) 0 else now - sessionStartedAt
            val keepaliveSeconds = config.persistentKeepalive ?: 0

            if (age >= settings.rekeyAfterMs && now - lastAttemptAt >= settings.rekeyRetryMs) {
                lastAttemptAt = now
                if (age >= 180_000 && !warnedExpiry) {
                    warnedExpiry = true
                    log("сессия старше 180 с — сервер её уже мог выбросить, пересогласовываю")
                }
                if (!negotiate(initial = false)) {
                    lastRekeyFailure = failureReason ?: "rekey не удался"
                    log("rekey не удался: ${lastRekeyFailure}")
                } else {
                    warnedExpiry = false
                }
                continue
            }

            // Keepalive по PersistentKeepalive: пустой transport-пакет держит NAT и сессию живой.
            if (keepaliveSeconds > 0 && now - lastOutboundAt >= keepaliveSeconds * 1000L) {
                sendKeepalive()
            }
        }
    }

    private fun sendKeepalive() {
        val pkt = synchronized(lock) {
            val s = session ?: return
            val (bytes, next) = Wg.buildTransport(peerIndex, s, ByteArray(0))
            session = next
            bytes
        }
        runCatching { udp.send(pkt) }
        lastOutboundAt = System.currentTimeMillis()
    }

    // --------------------------------------------------------------- пересылка

    private fun fail(reason: String): Boolean {
        failureReason = reason
        log("handshake невозможен: $reason")
        return false
    }

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
            if (packet == null) {
                // Сессии нет (только что стартовали или идёт rekey) — пакет теряем, но туннель живой.
                runCatching { Thread.sleep(20) }
                continue
            }
            try {
                udp.send(packet)
                bytesUp += n
                lastOutboundAt = System.currentTimeMillis()
            } catch (e: Exception) {
                if (!stopped) log("отправка: ${e.javaClass.simpleName}: ${e.message}")
                break
            }
        }
        // tun закрылся — значит, сервис останавливают: гасим и читателя с таймерами.
        stopped = true
    }
}
