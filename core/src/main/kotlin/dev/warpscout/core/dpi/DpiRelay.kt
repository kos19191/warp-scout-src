package dev.warpscout.core.dpi

import dev.warpscout.core.tunnel.FlowKey
import dev.warpscout.core.tunnel.PacketTap
import java.io.EOFException
import java.io.IOException
import java.net.ConnectException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.NoRouteToHostException
import java.net.Socket
import java.net.SocketTimeoutException
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.ThreadLocalRandom
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

/**
 * Обход DPI в туннеле (с 1.10.49-beta3): YouTube и X — напрямую через провайдера с приёмом ByeDPI,
 * а не через WARP.
 *
 * Пакеты приложений приходят в tun целиком, поэтому приём обхода (разрезать первый пакет, срочный
 * байт, TTL 1) можно сделать только своим концом TCP: соединение приложения к адресу:443 туннель
 * принимает сам (отвечает SYN-ACK от имени сервера), читает первое сообщение TLS и по имени сайта в
 * нём решает:
 *
 *  • сайт из плана этой сети ([DpiPlan]: YouTube, X) — новый сокет мимо туннеля к тому же адресу, и
 *    первое сообщение уходит кусками по приёму ([TrickSender]). Сервер ответил — дальше байты просто
 *    перекладываются в обе стороны;
 *  • напрямую не открылось (адрес молчит, сброс, тишина после приветствия) — то же сообщение уходит
 *    через туннель, как раньше: приложение этого не замечает, только ждёт на пару секунд дольше;
 *    адрес запоминается, и следующие соединения к нему идут через туннель сразу (а не разбираются);
 *  • другой сайт этого приложения (реклама, вход в аккаунт) — через туннель.
 *
 * Разбираются только соединения выбранных приложений ([apps]) к порту 443: остальной трафик идёт
 * мимо, как шёл. QUIC (UDP 443) этих приложений закрывается ответом «порт закрыт»: QUIC шифрует имя
 * сайта по-другому, и приёмы к нему не применить, — приложение тут же переходит на TCP.
 *
 * Свой конец TCP — минимальный: окно без масштабирования, без SACK и меток времени (своё SYN-ACK их
 * не предлагает — значит, по RFC их нет и у приложения), повтор неподтверждённого «назад на N».
 * Пакеты в tun теряются редко: это не сеть, а ядро того же телефона.
 */
class DpiRelay(
    private val tunOut: (ByteArray) -> Unit,
    private val owner: (Int, InetSocketAddress, InetSocketAddress) -> Int,
    private val apps: Map<Int, App>,
    plan: DpiPlan,
    private val direct: Connector,
    private val tunnel: Connector,
    private val ttl: DpiProbe.SocketTtl? = null,
    mtu: Int = 1280,
    private val log: (String) -> Unit = {},
    private val families: List<DpiFamily> = DpiFamilies.ALL,
    private val clock: () -> Long = System::currentTimeMillis,
    private val timing: Timing = Timing(),
    /** Фейк (с 1.10.49-beta4, см. [FakeSender]); null — приёмы с фейком напрямую не открываются. */
    private val fake: FakeSender? = null,
    /** Внешняя сеть имеет рабочий IPv6; при отсутствии соединения идут через туннель без DPI-разбора. */
    directV6: Boolean = true
) : PacketTap {

    /** Приложение, чьи соединения разбираем: название (для журнала) и сервис ([DpiService.id]). */
    class App(val name: String, val service: String)

    /** Откуда берутся сокеты: мимо туннеля (с protect) и через него (обычный сокет процесса). */
    interface Connector {
        /**
         * Подключённый сокет к [address]:[port] за [timeoutMs]. [uid] — чьё это соединение (выход по
         * приложениям); [bound] — зовётся со своим портом сокета до подключения.
         */
        fun connect(address: InetAddress, port: Int, timeoutMs: Int, uid: Int, bound: (Int) -> Unit): Socket

        /** Соединение закрыто: снять закрепление за выходом, если оно было. */
        fun release(localPort: Int, address: InetAddress, port: Int) {}
    }

    class Timing(
        /** Подключение мимо туннеля: дольше — адрес закрыт (так ТСПУ режет по адресу — молча). */
        val directConnectMs: Int = 2500,
        /** Ответ сервера на первое сообщение: тишина дольше — приём не помог. */
        val replyMs: Int = 3500,
        val tunnelConnectMs: Int = 12_000,
        /** Сколько ждать первое сообщение TLS: приложения открывают соединения заранее. */
        val helloWaitMs: Long = 30_000,
        val idleMs: Long = 10 * 60_000L,
        /** Адрес, который напрямую не открылся, — столько через туннель сразу. */
        val penaltyMs: Long = 20 * 60_000L,
        /** Сервис, которому подряд не помог приём, — столько целиком через туннель. */
        val familyPenaltyMs: Long = 10 * 60_000L,
        val rtoMinMs: Long = 250,
        val rtoMaxMs: Long = 4000,
        val tickMs: Long = 100
    )

    private enum class St { SYN_RCVD, OPEN, CLOSED }

    private inner class Flow(
        val key: FlowKey,
        val v6: Boolean,
        val appIp: ByteArray,
        val appPort: Int,
        val srvIp: ByteArray,
        val srvPort: Int,
        val srvAddr: InetAddress,
        val uid: Int,
        val app: App,
        val irs: Int,
        val iss: Int,
        val mss: Int
    ) {
        val lock = ReentrantLock()
        val upData = lock.newCondition()
        val downSpace = lock.newCondition()
        var state = St.SYN_RCVD

        // От приложения к серверу.
        var rcvNxt = irs + 1
        val up = ByteRing(UP_CAP)
        var appFin = false
        var upShut = false
        var advWnd = 0

        // От сервера к приложению: в [down] лежит всё с sndUna, отправленное — до sndNxt.
        var sndUna = iss + 1
        var sndNxt = iss + 1
        var sndMax = iss + 1
        val down = ByteRing(DOWN_CAP)
        var appWnd = 0
        var srvEof = false
        var finSent = false
        var finEver = false
        var finSeq = 0
        var finAcked = false

        var lastSendAt = 0L
        var rto = timing.rtoMinMs
        var retries = 0
        var lastSeen = clock()
        var synAckAt = 0L
        var synAckTries = 0
        var probeAt = 0L

        @Volatile
        var sock: Socket? = null
        var ownPort = -1
        var route = Route.NONE
        var family: DpiFamily? = null
        var sni = ""
        var bytesUp = 0L
        var bytesDown = 0L
    }

    private enum class Route { NONE, DIRECT, TUNNEL, FALLBACK }

    @Volatile
    private var stopped = false

    @Volatile
    var plan: DpiPlan = plan
        set(value) {
            field = value
            planGen.incrementAndGet()
        }

    private val planGen = AtomicInteger(0)

    /** Выключается также при обнаружении отсутствующего IPv6-маршрута напрямую. */
    @Volatile
    private var v6Direct = directV6

    private val mss4 = (mtu - 40).coerceIn(536, 1460)
    private val mss6 = (mtu - 60).coerceIn(536, 1440)
    private val ipId = AtomicInteger(ThreadLocalRandom.current().nextInt(0x10000))

    private val flows = ConcurrentHashMap<FlowKey, Flow>()

    /**
     * Недавно закрытые соединения → когда: запоздавшие пакеты приложения по ним (последний ACK, сброс)
     * выбрасываем, а не отдаём в WARP — серверу на том конце они ни к чему.
     */
    private val recentClosed = ConcurrentHashMap<FlowKey, Long>()

    /** Свои порты сокетов через туннель: их SYN — наши, разбирать их нельзя (иначе петля). */
    private val ownPorts = ConcurrentHashMap.newKeySet<Int>()

    /** Решения про QUIC по соединениям (только поток диспетчера). */
    private val quic = object : LinkedHashMap<FlowKey, Boolean>(64, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<FlowKey, Boolean>?): Boolean = size > 512
    }
    private var quicGen = -1

    /** Адрес → до какого времени идти через туннель (напрямую не открылся). */
    private val badIp = ConcurrentHashMap<String, Long>()

    /** Сервис → до какого времени целиком через туннель; подряд неудач напрямую. */
    private val badFamily = ConcurrentHashMap<String, Long>()
    private val familyFails = ConcurrentHashMap<String, Int>()
    private val familyOk = ConcurrentHashMap.newKeySet<String>()

    /** Группа сайтов → группа стратегии (`--auto`), которой открылось в последний раз: с неё и начинаем. */
    private val goodGroup = ConcurrentHashMap<String, Int>()

    private val pool: ExecutorService = Executors.newCachedThreadPool { r ->
        Thread(r, "warpscout-dpi-relay").apply { isDaemon = true }
    }

    private val timer = Thread({ timerLoop() }, "warpscout-dpi-timer").apply { isDaemon = true }

    /** Разбудить таймер: появилось соединение (без соединений он спит, не будя телефон). */
    private val wake = java.util.concurrent.LinkedBlockingQueue<Boolean>()

    // ------------------------------------------------------------------------------- счётчики

    val opened = AtomicLong()
    val viaDirect = AtomicLong()
    val viaTunnel = AtomicLong()
    val fallbacks = AtomicLong()
    val failed = AtomicLong()
    val quicBlocked = AtomicLong()
    val retransmits = AtomicLong()
    val bytesDirectDown = AtomicLong()
    val bytesDirectUp = AtomicLong()
    val bytesTunnelDown = AtomicLong()
    private val directBy = ConcurrentHashMap<String, AtomicLong>()

    @Volatile
    var lookups = 0L
        private set

    @Volatile
    var lookupMisses = 0L
        private set

    private val said = AtomicInteger(0)
    private var ownerSaid = false
    private var fullSaid = false

    init {
        timer.start()
    }

    /** Сколько соединений разбирается сейчас. */
    val active: Int get() = flows.size

    // --------------------------------------------------------------------------- пакеты из tun

    override fun take(packet: ByteArray, len: Int): Boolean {
        if (stopped || len < 20 || len > packet.size) return false
        val p = plan
        if (p.isEmpty) return false
        val ihl: Int
        val proto: Int
        when ((packet[0].toInt() ushr 4) and 0x0F) {
            4 -> {
                ihl = (packet[0].toInt() and 0x0F) * 4
                proto = packet[9].toInt() and 0xFF
                if ((((packet[6].toInt() and 0x1F) shl 8) or (packet[7].toInt() and 0xFF)) != 0) return false
            }

            6 -> {
                if (len < 40) return false
                ihl = 40
                proto = packet[6].toInt() and 0xFF
            }

            else -> return false
        }
        if (ihl < 20 || len < ihl + 4) return false
        if (TcpPacket.u16(packet, ihl + 2) != PORT) return false
        return when (proto) {
            6 -> takeTcp(packet, len, p)
            17 -> takeUdp(packet, len, p)
            else -> false
        }
    }

    private fun takeTcp(packet: ByteArray, len: Int, p: DpiPlan): Boolean {
        val key = FlowKey.of(packet, len) ?: return false
        val f = flows[key]
        if (f != null) {
            // Наше соединение: битый пакет выбрасываем, в выходы его отдавать нельзя.
            TcpPacket.parse(packet, len)?.let { onSegment(f, it) }
            return true
        }
        if (!TcpPacket.isSynTo(packet, len, PORT)) {
            val closedAt = recentClosed[key] ?: return false
            return clock() - closedAt < LINGER_MS
        }
        if (key.sport in ownPorts) return false
        // Без внешнего IPv6 такие соединения должны идти обычным путём через туннель.
        if (!v6Direct && ((packet[0].toInt() ushr 4) and 0x0F) == 6) return false
        val dst = key.dst
        val until = badIp[ipText(dst)]
        if (until != null && clock() < until) return false
        if (flows.size >= MAX_FLOWS) {
            if (!fullSaid) {
                fullSaid = true
                say("обход DPI: разбираю уже $MAX_FLOWS соединений — новые идут через туннель, как раньше")
            }
            return false
        }
        val uid = ownerOf(6, key)
        val app = apps[uid] ?: return false
        if (!serviceActive(p, app.service)) return false
        val s = TcpPacket.parse(packet, len) ?: return false
        val v6 = s.v6
        val ourMss = if (v6) mss6 else mss4
        val mss = if (s.mss > 0) minOf(s.mss, ourMss) else 536
        val srvAddr = runCatching { InetAddress.getByAddress(s.dst) }.getOrNull() ?: return false
        val flow = Flow(
            key, v6, s.src, s.sport, s.dst, s.dport, srvAddr, uid, app,
            irs = s.seq, iss = ThreadLocalRandom.current().nextInt(), mss = mss
        )
        flows[key] = flow
        opened.incrementAndGet()
        flow.lock.withLock { sendSynAck(flow) }
        if (wake.isEmpty()) wake.offer(true)
        return true
    }

    private fun takeUdp(packet: ByteArray, len: Int, p: DpiPlan): Boolean {
        val gen = planGen.get()
        if (gen != quicGen) {
            quic.clear()
            quicGen = gen
        }
        val key = FlowKey.of(packet, len) ?: return false
        val block = quic[key] ?: run {
            val app = apps[ownerOf(17, key)]
            (app != null && serviceActive(p, app.service)).also { quic[key] = it }
        }
        if (!block) return false
        quicBlocked.incrementAndGet()
        TcpPacket.portUnreachable(packet, len)?.let { emit(it) }
        return true
    }

    private fun ownerOf(proto: Int, key: FlowKey): Int {
        val uid = try {
            owner(proto, key.local, key.remote)
        } catch (e: Exception) {
            -1
        }
        lookups++
        if (uid < 0) {
            lookupMisses++
            if (!ownerSaid && lookups >= 20 && lookupMisses == lookups) {
                ownerSaid = true
                say("обход DPI: система не называет, чьи соединения, — разбирать нечего, всё идёт через туннель")
            }
        }
        return uid
    }

    /**
     * Разбирать ли соединения приложений сервиса: в плане есть его главная группа сайтов (страница,
     * видео), и она не наказана неудачами. Только картинки — не повод (см. [DpiFamily.primary]).
     */
    private fun serviceActive(p: DpiPlan, service: String): Boolean =
        families.any { it.service == service && it.primary && p.trickFor(it.id) != null && !familyBlocked(it.id) }

    private fun familyBlocked(id: String): Boolean {
        val until = badFamily[id] ?: return false
        if (clock() < until) return true
        badFamily.remove(id)
        familyFails.remove(id)
        return false
    }

    // ------------------------------------------------------------------------------ свой TCP

    private fun upWindow(f: Flow): Int = minOf(0xFFFF, f.up.free())

    /** Номер нашего следующего байта для подтверждений: после FIN — за ним. */
    private fun ackSeq(f: Flow): Int = if (f.finSent) f.finSeq + 1 else f.sndNxt

    private fun segment(f: Flow, seq: Int, flags: Int, mss: Int = 0, dataLen: Int = 0, fill: ((ByteArray, Int) -> Unit)? = null): ByteArray {
        val w = upWindow(f)
        f.advWnd = w
        return TcpPacket.build(
            f.v6, f.srvIp, f.appIp, f.srvPort, f.appPort, seq, f.rcvNxt, flags, w,
            mss = mss, ipId = ipId.incrementAndGet(), dataLen = dataLen, fill = fill
        )
    }

    private fun emit(pkt: ByteArray) {
        try {
            tunOut(pkt)
        } catch (e: Exception) {
            // tun закрыт (остановка) — пакет теряется, TCP повторит или соединение закроется само.
        }
    }

    private fun sendSynAck(f: Flow) {
        f.synAckAt = clock()
        emit(segment(f, f.iss, TcpPacket.SYN or TcpPacket.ACK, mss = f.mss))
    }

    private fun sendAck(f: Flow) = emit(segment(f, ackSeq(f), TcpPacket.ACK))

    private fun onSegment(f: Flow, s: TcpPacket.Seg) {
        var startUp = false
        f.lock.withLock {
            if (f.state == St.CLOSED) return
            f.lastSeen = clock()
            if (s.has(TcpPacket.RST)) {
                closeLocked(f, rst = false)
                return
            }
            if (f.state == St.SYN_RCVD) {
                if (s.has(TcpPacket.SYN)) {
                    if (s.seq == f.irs) sendSynAck(f)
                    return
                }
                if (!s.has(TcpPacket.ACK) || s.ack != f.iss + 1) return
                f.state = St.OPEN
                f.appWnd = s.window
                startUp = true
            } else if (s.has(TcpPacket.SYN)) {
                sendAck(f)
                return
            }
            if (s.has(TcpPacket.ACK)) onAck(f, s.ack, s.window)
            if (s.dataLen > 0 || s.has(TcpPacket.FIN)) onData(f, s)
            maybeDone(f)
        }
        if (startUp) {
            try {
                pool.execute { upstream(f) }
            } catch (e: Exception) {
                closeFlow(f, rst = true)
            }
        }
    }

    private fun onAck(f: Flow, ack: Int, wnd: Int) {
        val top = if (f.finEver) f.finSeq + 1 else f.sndMax
        val acked = ack - f.sndUna
        if (acked > 0 && ack - top <= 0) {
            val data = minOf(acked, f.down.size)
            f.down.drop(data)
            f.sndUna += data
            if (f.sndNxt - f.sndUna < 0) f.sndNxt = f.sndUna
            if (f.finEver && ack == f.finSeq + 1) {
                f.finAcked = true
                f.finSent = true
            }
            f.retries = 0
            f.rto = timing.rtoMinMs
            f.lastSendAt = clock()
            f.downSpace.signalAll()
        }
        f.appWnd = wnd
        pump(f)
    }

    private fun onData(f: Flow, s: TcpPacket.Seg) {
        if (f.appFin) {
            sendAck(f)
            return
        }
        var off = s.dataOff
        var len = s.dataLen
        val behind = f.rcvNxt - s.seq
        if (behind > 0) {
            if (behind >= len) {
                // Повтор уже принятого (или прежнего FIN) — только подтвердить.
                sendAck(f)
                return
            }
            off += behind
            len -= behind
        } else if (behind < 0) {
            // Не по порядку: выбрасываем, подтверждение повтором скажет, что ждём.
            sendAck(f)
            return
        }
        val n = if (len > 0) f.up.write(s.data, off, len) else 0
        f.rcvNxt += n
        if (n > 0) f.upData.signalAll()
        if (s.has(TcpPacket.FIN) && n == len) {
            f.appFin = true
            f.rcvNxt += 1
            f.upData.signalAll()
        }
        sendAck(f)
    }

    /** Отправить приложению, сколько позволяет его окно. */
    private fun pump(f: Flow) {
        if (f.state != St.OPEN) return
        var sent = false
        while (true) {
            val inFlight = f.sndNxt - f.sndUna
            val unsent = f.down.size - inFlight
            val usable = f.appWnd - inFlight
            if (unsent <= 0 || usable <= 0) break
            val n = minOf(unsent, usable, f.mss)
            val off = inFlight
            emit(segment(f, f.sndNxt, TcpPacket.ACK or TcpPacket.PSH, dataLen = n) { b, at -> f.down.peek(b, at, off, n) })
            f.sndNxt += n
            if (f.sndNxt - f.sndMax > 0) f.sndMax = f.sndNxt
            sent = true
        }
        if (f.srvEof && !f.finSent && f.down.size == f.sndNxt - f.sndUna) {
            f.finSeq = f.sndNxt
            f.finSent = true
            f.finEver = true
            emit(segment(f, f.finSeq, TcpPacket.FIN or TcpPacket.ACK))
            sent = true
        }
        if (sent) f.lastSendAt = clock()
    }

    /** Окно освободилось заметно — сказать приложению, иначе оно ждёт своего таймера. */
    private fun windowUpdate(f: Flow) {
        val w = upWindow(f)
        if (w - f.advWnd >= minOf(UP_CAP / 4, 8 * f.mss)) sendAck(f)
    }

    private fun maybeDone(f: Flow) {
        if (f.state == St.OPEN && f.appFin && f.upShut && f.srvEof && f.finAcked) closeLocked(f, rst = false)
    }

    private fun closeFlow(f: Flow, rst: Boolean) = f.lock.withLock { closeLocked(f, rst) }

    private fun closeLocked(f: Flow, rst: Boolean) {
        if (f.state == St.CLOSED) return
        if (rst) emit(segment(f, ackSeq(f), TcpPacket.RST or TcpPacket.ACK))
        f.state = St.CLOSED
        f.upData.signalAll()
        f.downSpace.signalAll()
        flows.remove(f.key, f)
        recentClosed[f.key] = clock()
        val s = f.sock
        f.sock = null
        runCatching { s?.close() }
        releasePort(f)
        when (f.route) {
            Route.DIRECT -> {
                bytesDirectDown.addAndGet(f.bytesDown)
                bytesDirectUp.addAndGet(f.bytesUp)
            }

            Route.TUNNEL, Route.FALLBACK -> bytesTunnelDown.addAndGet(f.bytesDown)
            Route.NONE -> {}
        }
    }

    /** Свой порт сокета через туннель больше не наш: убрать из списка и снять закрепление. */
    private fun releasePort(f: Flow) {
        val port = f.ownPort
        if (port <= 0) return
        ownPorts.remove(port)
        runCatching { tunnel.release(port, f.srvAddr, f.srvPort) }
    }

    // ------------------------------------------------------------------- путь до сервера

    private fun upstream(f: Flow) {
        try {
            val hello = waitHello(f) ?: return
            val sni = if (hello.isNotEmpty()) TlsHello.findSni(hello)?.name.orEmpty() else ""
            val fam = if (sni.isNotEmpty()) DpiFamilies.ofHost(sni, families) else null
            val trick = fam?.let { plan.trickFor(it.id) }
            f.sni = sni
            f.family = fam
            var sock: Socket? = null
            var first: ByteArray? = null
            var route = Route.TUNNEL
            if (hello.isNotEmpty() && fam != null && trick != null && !familyBlocked(fam.id)) {
                val r = tryGroups(f, hello, trick, fam)
                if (r != null) {
                    sock = r.first
                    first = r.second
                    route = Route.DIRECT
                } else {
                    route = Route.FALLBACK
                }
            }
            if (f.lock.withLock { f.state == St.CLOSED }) {
                runCatching { sock?.close() }
                return
            }
            if (sock == null) {
                sock = tunnel.connect(f.srvAddr, f.srvPort, timing.tunnelConnectMs, f.uid) { port ->
                    ownPorts.add(port)
                    f.lock.withLock { f.ownPort = port }
                }
                runCatching { sock.tcpNoDelay = true }
                if (hello.isNotEmpty()) {
                    sock.getOutputStream().write(hello)
                    sock.getOutputStream().flush()
                }
            }
            val s: Socket = sock
            val owned = f.lock.withLock {
                if (f.state == St.CLOSED) {
                    false
                } else {
                    f.sock = s
                    f.route = route
                    if (hello.isNotEmpty()) f.up.drop(hello.size)
                    if (route == Route.DIRECT) f.bytesUp += hello.size
                    windowUpdate(f)
                    true
                }
            }
            if (!owned) {
                runCatching { s.close() }
                releasePort(f)
                return
            }
            when (route) {
                Route.DIRECT -> {
                    viaDirect.incrementAndGet()
                    fam?.let { directBy.getOrPut(it.id) { AtomicLong() }.incrementAndGet() }
                }

                Route.FALLBACK -> fallbacks.incrementAndGet()
                else -> viaTunnel.incrementAndGet()
            }
            pool.execute { downstream(f, s, first) }
            writerLoop(f, s)
        } catch (e: InterruptedException) {
            closeFlow(f, rst = true)
        } catch (e: Exception) {
            val open = f.lock.withLock { f.state != St.CLOSED }
            if (open) {
                if (f.route == Route.NONE) {
                    failed.incrementAndGet()
                    sayLimited("обход DPI: ${f.app.name} — ${hostOf(f)}: ни напрямую, ни через туннель не подключился (${shortReason(e)})")
                }
                closeFlow(f, rst = true)
            }
        }
    }

    /**
     * Первая запись TLS целиком (копия, из очереди не забирается). Пустой массив — первым пришло не
     * TLS или его не дождались: тогда соединение идёт через туннель как есть. null — приложение
     * закрыло соединение, ничего не отправив (так бывает у параллельных попыток подключения): идти
     * никуда не нужно.
     */
    private fun waitHello(f: Flow): ByteArray? {
        val deadline = clock() + timing.helloWaitMs
        f.lock.withLock {
            while (true) {
                if (f.state == St.CLOSED) return null
                val size = f.up.size
                if (size >= 5) {
                    if (f.up.byteAt(0) != 0x16) return ByteArray(0)
                    val need = 5 + ((f.up.byteAt(3) shl 8) or f.up.byteAt(4))
                    if (need > UP_CAP) return ByteArray(0)
                    if (size >= need) return ByteArray(need).also { f.up.peek(it, 0, 0, need) }
                }
                if (f.appFin) {
                    if (size == 0) {
                        // Приложение уже закрыло своё: сброс, чтобы его сокет не ждал нашего FIN.
                        closeLocked(f, rst = true)
                        return null
                    }
                    return ByteArray(0)
                }
                val left = deadline - clock()
                if (left <= 0) return ByteArray(0)
                f.upData.await(minOf(left, 1000L), TimeUnit.MILLISECONDS)
            }
        }
    }

    /**
     * Группы стратегии по очереди (`--auto`, с 1.10.49-beta4): начиная с той, что открыла эту группу
     * сайтов в прошлый раз; каждая — новым соединением. Ни одна не открыла — null.
     */
    private fun tryGroups(f: Flow, hello: ByteArray, trick: DpiTrick, fam: DpiFamily): Pair<Socket, ByteArray>? {
        val n = trick.strategy.groups.size.coerceAtLeast(1)
        val first = (goodGroup[fam.id] ?: 0).coerceIn(0, n - 1)
        for (k in 0 until n) {
            val g = (first + k) % n
            if (k > 0 && f.lock.withLock { f.state == St.CLOSED }) return null
            val r = tryDirect(f, hello, trick, fam, g, last = k == n - 1)
            if (r != null) {
                if (n > 1) goodGroup[fam.id] = g
                return r
            }
            // Адрес молчит на подключение — дальше группы не помогут.
            if (lastConnectFailed.get() == true) break
        }
        return null
    }

    /** Последняя попытка напрямую не подключилась (а не «приём не помог»). */
    private val lastConnectFailed = ThreadLocal<Boolean>()

    /** Напрямую с приёмом: сокет и первые байты ответа; null — не открылось (причина — в журнале). */
    private fun tryDirect(f: Flow, hello: ByteArray, trick: DpiTrick, fam: DpiFamily, group: Int = 0, last: Boolean = true): Pair<Socket, ByteArray>? {
        var s: Socket? = null
        var stage = 0
        lastConnectFailed.set(false)
        try {
            val sock = direct.connect(f.srvAddr, f.srvPort, timing.directConnectMs, f.uid) {}
            s = sock
            stage = 1
            runCatching { sock.tcpNoDelay = true }
            sock.soTimeout = trick.strategy.timeoutMs.takeIf { it > 0 } ?: timing.replyMs
            TrickSender.send(sock, hello, trick, ttl, fake, group)
            stage = 2
            val buf = ByteArray(16 * 1024)
            val n = sock.getInputStream().read(buf)
            if (n <= 0) throw EOFException("сервер закрыл соединение сразу после приветствия")
            // Запись «alert» вместо ответа: приём сломал приветствие для этого сервера.
            if ((buf[0].toInt() and 0xFF) == 0x15) throw IOException("сервер ответил ошибкой TLS")
            // Ответ на чужое приветствие: до сервера дошёл фейк (TTL велик) — соединение уже не наше.
            if (DpiDesync.sidMismatch(hello, buf, n)) throw IOException("до сервера дошёл фейк — TTL велик")
            sock.soTimeout = 0
            directOk(f, fam, trick)
            return sock to buf.copyOf(n)
        } catch (e: InterruptedException) {
            runCatching { s?.close() }
            throw e
        } catch (e: Exception) {
            runCatching { s?.close() }
            if (stage == 0) lastConnectFailed.set(true)
            // Нет маршрута для IPv6 — внешнего IPv6 у сети нет, это не ошибка DPI. Отключаем разбор IPv6.
            if (f.v6 && stage == 0 && noRoute(e)) {
                noDirectV6(e)
                return null
            }
            // Неудача группы, за которой есть следующая, — не неудача приёма: в журнал и в счёт — только последняя.
            if (last || stage == 0) directFailed(f, fam, trick, stage, e)
            return null
        }
    }

    private fun noRoute(e: Throwable): Boolean {
        val msg = (e.message ?: "").lowercase()
        return e is NoRouteToHostException || "unreachable" in msg || "enetunreach" in msg || "ehostunreach" in msg
    }

    private fun noDirectV6(e: Throwable) {
        if (!v6Direct) return
        v6Direct = false
        say("обход DPI: у этой сети нет IPv6 напрямую (${shortReason(e)}) — соединения по IPv6 дальше не разбираю, они идут через туннель, как раньше")
    }

    private fun directOk(f: Flow, fam: DpiFamily, trick: DpiTrick) {
        familyFails.remove(fam.id)
        if (familyOk.add(fam.id)) {
            say("обход DPI: ${fam.title} — открылся напрямую с приёмом ${DpiPlan.trickLabel(trick)} (${hostOf(f)}, ${f.app.name})")
        }
    }

    private fun directFailed(f: Flow, fam: DpiFamily, trick: DpiTrick, stage: Int, e: Exception) {
        val why = when {
            e is TrickSender.Unsupported -> "приём не работает на этом телефоне: ${e.message}"
            e is SocketTimeoutException && stage == 0 -> "нет ответа на подключение — похоже на блокировку по адресу"
            e is SocketTimeoutException -> "тишина после приветствия — приём ${DpiPlan.trickLabel(trick)} не помог"
            else -> shortReason(e)
        }
        val now = clock()
        badIp[ipText(f.srvIp)] = now + timing.penaltyMs
        val fails = (familyFails[fam.id] ?: 0) + 1
        familyFails[fam.id] = fails
        val giveUp = e is TrickSender.Unsupported || (fails >= FAMILY_FAILS && fam.id !in familyOk)
        if (giveUp && badFamily.put(fam.id, now + timing.familyPenaltyMs) == null) {
            say(
                "обход DPI: ${fam.title} — напрямую не открывается ($why); ${timing.familyPenaltyMs / 60_000} мин " +
                    "весь ${fam.title} идёт через туннель, как раньше"
            )
        } else {
            sayLimited(
                "обход DPI: ${fam.title} — ${hostOf(f)} напрямую не открылся ($why) — это соединение через туннель, " +
                    "адрес ${timing.penaltyMs / 60_000} мин тоже"
            )
        }
    }

    /** Следующий кусок для сервера: байт сколько взято, −1 — приложение закончило, −2 — соединение закрыто. */
    private fun nextUp(f: Flow, buf: ByteArray): Int = f.lock.withLock {
        while (f.up.size == 0 && !f.appFin && f.state != St.CLOSED) f.upData.await(1, TimeUnit.SECONDS)
        when {
            f.state == St.CLOSED -> -2
            f.up.size == 0 -> -1
            else -> f.up.read(buf, 0, buf.size).also { n ->
                f.bytesUp += n
                windowUpdate(f)
            }
        }
    }

    private fun writerLoop(f: Flow, s: Socket) {
        val out = s.getOutputStream()
        val buf = ByteArray(16 * 1024)
        while (true) {
            val n = nextUp(f, buf)
            if (n == -2) return
            if (n < 0) {
                runCatching { s.shutdownOutput() }
                f.lock.withLock {
                    f.upShut = true
                    maybeDone(f)
                }
                return
            }
            out.write(buf, 0, n)
            out.flush()
        }
    }

    private fun downstream(f: Flow, s: Socket, first: ByteArray?) {
        try {
            if (first != null) push(f, first, first.size)
            val inp = s.getInputStream()
            val buf = ByteArray(16 * 1024)
            while (true) {
                val room = f.lock.withLock {
                    while (f.down.free() == 0 && f.state != St.CLOSED) f.downSpace.await(1, TimeUnit.SECONDS)
                    if (f.state == St.CLOSED) -1 else f.down.free()
                }
                if (room < 0) return
                val n = inp.read(buf, 0, minOf(buf.size, room))
                if (n < 0) {
                    f.lock.withLock {
                        f.srvEof = true
                        pump(f)
                        maybeDone(f)
                    }
                    return
                }
                push(f, buf, n)
            }
        } catch (e: Exception) {
            closeFlow(f, rst = true)
        }
    }

    private fun push(f: Flow, b: ByteArray, n: Int) {
        f.lock.withLock {
            if (f.state == St.CLOSED) return
            val k = f.down.write(b, 0, n)
            f.bytesDown += k
            pump(f)
        }
    }

    // ------------------------------------------------------------------------------- таймер

    /**
     * Таймер: повторы, проба окна, тишина. Часто (раз в [Timing.tickMs]) — только пока есть что повторять;
     * соединения молчат — раз в секунду; соединений нет — спит до первого (батарея: туннель живёт сутками).
     */
    private fun timerLoop() {
        var fast = true
        while (!stopped) {
            try {
                when {
                    flows.isEmpty() -> wake.poll(60, TimeUnit.SECONDS)
                    fast -> Thread.sleep(timing.tickMs)
                    else -> wake.poll(IDLE_TICK_MS, TimeUnit.MILLISECONDS)
                }
            } catch (e: InterruptedException) {
                return
            }
            wake.clear()
            fast = runCatching { tick() }.getOrDefault(true)
        }
    }

    /** Один проход таймера; true — есть что повторять (следующий проход — скоро). */
    private fun tick(): Boolean {
        val now = clock()
        var busy = false
        for (f in flows.values) {
            f.lock.withLock {
                if (f.state == St.CLOSED) return@withLock
                if (f.state == St.SYN_RCVD || f.sndNxt != f.sndUna || (f.finSent && !f.finAcked) || (f.appWnd == 0 && f.down.size > 0)) {
                    busy = true
                }
                if (now - f.lastSeen > timing.idleMs) {
                    closeLocked(f, rst = true)
                    return@withLock
                }
                when (f.state) {
                    St.SYN_RCVD -> if (now - f.synAckAt >= 1000L * (f.synAckTries + 1)) {
                        if (++f.synAckTries > 4) closeLocked(f, rst = false) else sendSynAck(f)
                    }

                    St.OPEN -> {
                        val inFlight = f.sndNxt != f.sndUna
                        val finPending = f.finSent && !f.finAcked
                        if ((inFlight || finPending) && now - f.lastSendAt >= f.rto) {
                            f.sndNxt = f.sndUna
                            if (finPending) f.finSent = false
                            if (f.appWnd == 0) {
                                // Окно приложения закрыто — это не потеря: пробуем окно, не считая повторов.
                                emit(segment(f, f.sndUna - 1, TcpPacket.ACK))
                                f.lastSendAt = now
                            } else {
                                if (++f.retries > MAX_RETRIES) {
                                    closeLocked(f, rst = true)
                                    return@withLock
                                }
                                retransmits.incrementAndGet()
                                f.rto = minOf(f.rto * 2, timing.rtoMaxMs)
                                pump(f)
                                f.lastSendAt = now
                            }
                        } else if (!inFlight && f.appWnd == 0 && f.down.size > 0 && now - f.probeAt >= 1000) {
                            f.probeAt = now
                            emit(segment(f, f.sndUna - 1, TcpPacket.ACK))
                        }
                    }

                    St.CLOSED -> {}
                }
            }
        }
        if (badIp.size > 256) badIp.entries.removeIf { it.value < now }
        if (recentClosed.size > 256) recentClosed.entries.removeIf { now - it.value >= LINGER_MS }
        return busy
    }

    // ---------------------------------------------------------------------------- журнал

    private fun say(line: String) = runCatching { log(line) }

    private fun sayLimited(line: String) {
        val n = said.incrementAndGet()
        if (n <= SAY_LIMIT) say(line)
        if (n == SAY_LIMIT) say("обход DPI: дальше неудачи не пишу по одной — итог будет при отключении")
    }

    private fun hostOf(f: Flow): String {
        val ip = f.srvAddr.hostAddress ?: "?"
        return if (f.sni.isNotEmpty()) "${f.sni} → $ip" else ip
    }

    private fun shortReason(e: Throwable): String {
        val msg = (e.message ?: "").lowercase()
        return when {
            e is SocketTimeoutException -> "нет ответа"
            e is ConnectException && "refused" in msg -> "отказ в подключении"
            e is NoRouteToHostException || "unreachable" in msg -> "нет маршрута до сервера"
            "reset" in msg || "broken pipe" in msg || "aborted" in msg -> "сброс соединения"
            e is EOFException -> e.message ?: "соединение закрыто"
            else -> (e.message?.take(80) ?: e.javaClass.simpleName)
        }
    }

    /** Строка для журнала: что разбирается и сколько. */
    fun summary(): String {
        val by = directBy.entries.filter { it.value.get() > 0 }
            .joinToString(", ") { (id, n) -> "${DpiFamilies.byId(id, families)?.title ?: id} ${n.get()}" }
        return "обход DPI за сессию: соединений ${opened.get()} — напрямую ${viaDirect.get()}" +
            (if (by.isNotEmpty()) " ($by)" else "") +
            ", через туннель ${viaTunnel.get() + fallbacks.get()}" +
            (if (fallbacks.get() > 0) " (из них напрямую не открылись: ${fallbacks.get()})" else "") +
            (if (failed.get() > 0) ", не подключились никак: ${failed.get()}" else "") +
            "; принято напрямую ${mb(bytesDirectDown.get())}, через туннель ${mb(bytesTunnelDown.get())}" +
            (if (quicBlocked.get() > 0) "; QUIC закрыт: ${quicBlocked.get()} пакетов" else "") +
            (if (retransmits.get() > 0) "; повторов ${retransmits.get()}" else "")
    }

    override fun close() = stop()

    /** Остановить: все разбираемые соединения закрываются (приложениям — сброс). */
    fun stop() {
        if (stopped) return
        stopped = true
        timer.interrupt()
        for (f in flows.values.toList()) closeFlow(f, rst = true)
        pool.shutdownNow()
    }

    companion object {
        const val PORT = 443
        const val UP_CAP = 32 * 1024
        const val DOWN_CAP = 128 * 1024
        const val MAX_FLOWS = 64
        const val MAX_RETRIES = 8

        /** Проход таймера, когда повторять нечего: только тишину проверить. */
        const val IDLE_TICK_MS = 1000L

        /** Сколько после закрытия выбрасывать запоздавшие пакеты соединения. */
        const val LINGER_MS = 30_000L

        /** Подряд неудач напрямую, после которых сервис уходит в туннель (если напрямую ни разу не открылся). */
        const val FAMILY_FAILS = 4
        const val SAY_LIMIT = 12

        fun ipText(ip: ByteArray): String = runCatching { InetAddress.getByAddress(ip).hostAddress }.getOrNull() ?: ""

        fun mb(bytes: Long): String = when {
            bytes >= 1024L * 1024 -> String.format(java.util.Locale.US, "%.1f МБ", bytes / 1048576.0)
            bytes >= 1024 -> "${bytes / 1024} КБ"
            else -> "$bytes Б"
        }
    }
}
