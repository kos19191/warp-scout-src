package dev.warpscout.core.test

import dev.warpscout.core.dpi.ByteRing
import dev.warpscout.core.dpi.DpiAttempt
import dev.warpscout.core.dpi.DpiFamilies
import dev.warpscout.core.dpi.DpiFamily
import dev.warpscout.core.dpi.DpiPlan
import dev.warpscout.core.dpi.DpiRelay
import dev.warpscout.core.dpi.DpiReport
import dev.warpscout.core.dpi.DpiStage
import dev.warpscout.core.dpi.DpiTarget
import dev.warpscout.core.dpi.DpiTargetResult
import dev.warpscout.core.dpi.DpiTargets
import dev.warpscout.core.dpi.DpiTrick
import dev.warpscout.core.dpi.DpiVerdict
import dev.warpscout.core.dpi.GoogleVideo
import dev.warpscout.core.dpi.TcpPacket
import dev.warpscout.core.dpi.TlsHello
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.nio.ByteBuffer
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLContext

/**
 * Самопроверка обхода DPI в туннеле (1.10.49-beta3) — без интернета и без tun.
 *
 *  • пакеты TCP/ICMP собираются с правильными суммами и разбираются обратно, IPv4 и IPv6;
 *  • план по итогу проверки: на Tele2 (журнал 26.11) YouTube — «разрез», X — «лишний байт»;
 *  • имя узла видео по ответу редиректора — как у conv.py (lennylxx/ipv6-hosts);
 *  • «приложение» из пакетов говорит со своим концом TCP туннеля, а сервер — настоящий сокет на
 *    127.0.0.1 за «эмулятором DPI» (сброс, если имя сайта целиком в первом пакете): соединение
 *    открывается с приёмом напрямую, 200 КБ уходят и возвращаются, закрытие — по FIN с обеих сторон;
 *  • напрямую молчит — то же соединение через «туннель», адрес дальше не разбирается;
 *  • чужое приложение и чужой сайт — мимо; QUIC выбранного приложения — «порт закрыт».
 */
class DpiRelayChecks(private val check: (String, Boolean, String) -> Unit) {

    private fun ok(name: String, condition: Boolean, detail: String = "") = check(name, condition, detail)

    fun run() {
        packetChecks()
        ringChecks()
        familyAndPlanChecks()
        videoNameChecks()
        relayChecks()
    }

    // ------------------------------------------------------------------------------ пакеты

    private val appIp4 = byteArrayOf(172.toByte(), 16, 0, 2)
    private val srvIp4 = byteArrayOf(203.toByte(), 0, 113, 10)
    private val appIp6 = InetAddress.getByName("2606:4700:110:8a36::2").address
    private val srvIp6 = InetAddress.getByName("2a00:1450:4010:c05::5d").address

    private fun packetChecks() {
        val data = ByteArray(300) { (it * 7).toByte() }
        val p4 = TcpPacket.build(false, appIp4, srvIp4, 40001, 443, 1000, 2000, TcpPacket.ACK or TcpPacket.PSH, 4096, ipId = 7, dataLen = data.size) { b, at ->
            System.arraycopy(data, 0, b, at, data.size)
        }
        val s4 = TcpPacket.parse(p4)
        ok(
            "обход DPI: пакет TCP по IPv4 — суммы IP и TCP сходятся, разбор возвращает то же",
            TcpPacket.checksumOk(p4) && s4 != null && s4.sport == 40001 && s4.dport == 443 && s4.seq == 1000 &&
                s4.ack == 2000 && s4.window == 4096 && s4.dataLen == 300 && s4.has(TcpPacket.PSH) &&
                s4.data.copyOfRange(s4.dataOff, s4.dataOff + s4.dataLen).contentEquals(data)
        )
        val syn6 = TcpPacket.build(true, appIp6, srvIp6, 50000, 443, -5, 0, TcpPacket.SYN, 65535, mss = 1220)
        val s6 = TcpPacket.parse(syn6)
        ok(
            "обход DPI: SYN по IPv6 с MSS — сумма сходится, MSS и номер читаются",
            TcpPacket.checksumOk(syn6) && s6 != null && s6.v6 && s6.mss == 1220 && s6.seq == -5 && s6.has(TcpPacket.SYN) &&
                TcpPacket.isSynTo(syn6, syn6.size, 443) && !TcpPacket.isSynTo(p4, p4.size, 443)
        )
        val broken = p4.copyOf().also { it[it.size - 1] = (it[it.size - 1] + 1).toByte() }
        ok("обход DPI: испорченный байт — сумма не сходится", !TcpPacket.checksumOk(broken))

        val udp = udpPacket(appIp4, srvIp4, 50123, 443, 200)
        val icmp = TcpPacket.portUnreachable(udp)
        ok(
            "обход DPI: «порт закрыт» на QUIC — ICMP от адресата к приложению, сумма сходится, внутри заголовок исходного",
            icmp != null && icmp[9].toInt() == 1 && icmp[20].toInt() == 3 && icmp[21].toInt() == 3 &&
                icmp.copyOfRange(12, 16).contentEquals(srvIp4) && icmp.copyOfRange(16, 20).contentEquals(appIp4) &&
                icmpSumOk(icmp, 20) && icmp.copyOfRange(28, 56).contentEquals(udp.copyOfRange(0, 28)) &&
                TcpPacket.isUdpTo(udp, udp.size, 443)
        )
        val udp6 = udpPacket6(appIp6, srvIp6, 50124, 443, 120)
        val icmp6 = TcpPacket.portUnreachable(udp6)
        ok(
            "обход DPI: «порт закрыт» по IPv6 — ICMPv6 с правильной суммой",
            icmp6 != null && icmp6[6].toInt() == 58 && icmp6[40].toInt() == 1 && icmp6[41].toInt() == 4 && icmp6SumOk(icmp6)
        )
        var thrown = 0
        val rnd = java.util.Random(77)
        repeat(3000) {
            val b = ByteArray(1 + rnd.nextInt(120)).also { rnd.nextBytes(it) }
            if (it % 2 == 0) b[0] = 0x45
            try {
                TcpPacket.parse(b)
                TcpPacket.portUnreachable(b)
                TcpPacket.isSynTo(b, b.size, 443)
            } catch (e: Exception) {
                thrown++
            }
        }
        ok("обход DPI: 3000 случайных пакетов — разбор без исключений", thrown == 0, "исключений: $thrown")
    }

    private fun udpPacket(src: ByteArray, dst: ByteArray, sport: Int, dport: Int, payload: Int): ByteArray {
        val p = ByteArray(28 + payload)
        p[0] = 0x45
        p[2] = ((28 + payload) ushr 8).toByte(); p[3] = (28 + payload).toByte()
        p[8] = 64; p[9] = 17
        System.arraycopy(src, 0, p, 12, 4); System.arraycopy(dst, 0, p, 16, 4)
        p[20] = (sport ushr 8).toByte(); p[21] = sport.toByte(); p[22] = (dport ushr 8).toByte(); p[23] = dport.toByte()
        p[24] = ((8 + payload) ushr 8).toByte(); p[25] = (8 + payload).toByte()
        return p
    }

    private fun udpPacket6(src: ByteArray, dst: ByteArray, sport: Int, dport: Int, payload: Int): ByteArray {
        val p = ByteArray(48 + payload)
        p[0] = 0x60
        p[4] = ((8 + payload) ushr 8).toByte(); p[5] = (8 + payload).toByte()
        p[6] = 17; p[7] = 64
        System.arraycopy(src, 0, p, 8, 16); System.arraycopy(dst, 0, p, 24, 16)
        p[40] = (sport ushr 8).toByte(); p[41] = sport.toByte(); p[42] = (dport ushr 8).toByte(); p[43] = dport.toByte()
        p[44] = ((8 + payload) ushr 8).toByte(); p[45] = (8 + payload).toByte()
        return p
    }

    private fun sum16(b: ByteArray, off: Int, len: Int, initial: Long = 0): Long {
        var s = initial
        var i = off
        while (i + 1 < off + len) {
            s += ((b[i].toInt() and 0xFF) shl 8) or (b[i + 1].toInt() and 0xFF); i += 2
        }
        if (i < off + len) s += (b[i].toInt() and 0xFF) shl 8
        return s
    }

    private fun folded(s0: Long): Int {
        var s = s0
        while ((s ushr 16) != 0L) s = (s and 0xFFFF) + (s ushr 16)
        return s.toInt()
    }

    private fun icmpSumOk(p: ByteArray, off: Int): Boolean = folded(sum16(p, off, p.size - off)) == 0xFFFF

    private fun icmp6SumOk(p: ByteArray): Boolean {
        val len = p.size - 40
        val pseudo = sum16(p, 8, 32) + (len ushr 16) + (len and 0xFFFF) + 58
        return folded(sum16(p, 40, len, pseudo)) == 0xFFFF
    }

    private fun ringChecks() {
        val r = ByteRing(10)
        r.write(byteArrayOf(1, 2, 3, 4, 5, 6, 7), 0, 7)
        r.drop(5)
        val wrote = r.write(byteArrayOf(8, 9, 10, 11, 12, 13, 14, 15, 16), 0, 9)
        val peek = ByteArray(3).also { r.peek(it, 0, 2, 3) }
        val all = ByteArray(r.size).also { r.read(it, 0, it.size) }
        ok(
            "обход DPI: кольцевой буфер — через край, сколько влезло, по порядку",
            wrote == 8 && peek.contentEquals(byteArrayOf(8, 9, 10)) &&
                all.contentEquals(byteArrayOf(6, 7, 8, 9, 10, 11, 12, 13, 14, 15)) && r.size == 0, "влезло $wrote"
        )
    }

    // ---------------------------------------------------------------------- сервисы и план

    private fun att(trick: DpiTrick, ok: Boolean, stage: DpiStage = if (ok) DpiStage.DONE else DpiStage.HELLO, kbps: Int = -1) =
        DpiAttempt(trick, ok, stage, if (ok) "" else "тишина после приветствия TLS (4 с)", status = if (ok) 200 else 0, kbps = kbps)

    private fun res(id: String, verdict: DpiVerdict, helpers: List<DpiTrick> = emptyList(), control: Boolean = false, attempts: List<DpiAttempt>? = null) =
        DpiTargetResult(
            DpiTargets.DEFAULT.firstOrNull { it.id == id } ?: DpiTarget(id, id, "$id.example", control = control),
            "1.2.3.4", "", attempts ?: listOf(att(DpiTrick.PLAIN, verdict == DpiVerdict.OPEN)), verdict, helpers
        )

    private fun familyAndPlanChecks() {
        val yt = listOf(
            "www.youtube.com", "youtube.com", "rr3---sn-8ph2xajvh-v8ce.googlevideo.com", "i.ytimg.com",
            "yt3.ggpht.com", "youtubei.googleapis.com", "m.youtube.com."
        )
        val x = listOf("x.com", "api.x.com", "pbs.twimg.com", "video.twimg.com", "t.co", "api.twitter.com")
        val none = listOf("www.google.com", "notyoutube.com", "youtube.com.evil.example", "googleapis.com", "twitter.co", "")
        ok(
            "обход DPI: имена YouTube и X узнаются, чужие и похожие — нет",
            yt.all { DpiFamilies.ofHost(it) == DpiFamilies.YOUTUBE } && x.all { DpiFamilies.ofHost(it) == DpiFamilies.X } &&
                none.all { DpiFamilies.ofHost(it) == null },
            none.filter { DpiFamilies.ofHost(it) != null }.joinToString()
        )
        ok(
            "обход DPI: приложения YouTube и X — в своих сервисах",
            "com.google.android.youtube" in DpiFamilies.YOUTUBE.packages && "com.twitter.android" in DpiFamilies.X.packages
        )
        val all5 = listOf(DpiTrick.SPLIT, DpiTrick.TLSREC, DpiTrick.DISORDER, DpiTrick.DISORDER_TLSREC, DpiTrick.OOB)
        val tele2 = DpiReport(
            0, "мобильная · t2",
            listOf(
                res("youtube", DpiVerdict.BYPASS, all5),
                res("googlevideo", DpiVerdict.OPEN),
                res("ytimg", DpiVerdict.OPEN),
                res("discord", DpiVerdict.OPEN),
                res("instagram", DpiVerdict.IP),
                res("x", DpiVerdict.BYPASS, listOf(DpiTrick.OOB)),
                res("cloudflare", DpiVerdict.OPEN),
                res("google", DpiVerdict.OPEN, control = true)
            ),
            22_000, true
        )
        val plan = DpiPlan.of(tele2)
        ok(
            "обход DPI: план по проверке на Tele2 (26.11) — YouTube «разрез», X «лишний байт (OOB)», Instagram нет",
            plan.trickFor("youtube") == DpiTrick.SPLIT && plan.trickFor("x") == DpiTrick.OOB && plan.tricks.size == 2, plan.encode()
        )
        ok(
            "обход DPI: план хранится строкой и читается обратно; мусор и «как есть» пропускаются",
            DpiPlan.decode(plan.encode()) == plan && plan.encode() == "youtube=split,x=oob" &&
                DpiPlan.decode("youtube=tlsrec,foo=oob,x=bad,x=plain,,=").encode() == "youtube=tlsrec" && DpiPlan.decode(null).isEmpty
        )
        ok("обход DPI: описание плана для журнала", plan.describe() == "YouTube — «разрез», X (Twitter) — «лишний байт (OOB)»", plan.describe())
        val video = DpiReport(
            0, "Wi-Fi",
            listOf(
                res("youtube", DpiVerdict.BYPASS, listOf(DpiTrick.TLSREC, DpiTrick.OOB)),
                res("ytvideo", DpiVerdict.BYPASS, listOf(DpiTrick.OOB)),
                res("google", DpiVerdict.OPEN, control = true)
            ),
            1000, true
        )
        ok(
            "обход DPI: приём для сервиса — тот, что помог и странице, и серверу видео",
            DpiPlan.of(video).trickFor("youtube") == DpiTrick.OOB, DpiPlan.of(video).encode()
        )
        val entries = listOf(DpiPlan.entry("мобильная·25020", plan), DpiPlan.entry("Wi-Fi·192.168.1.1", DpiPlan(mapOf("x" to DpiTrick.TLSREC))))
        ok(
            "обход DPI: план — по ключу сети: Tele2 своё, домашний Wi-Fi своё, чужая сеть — ничего",
            DpiPlan.forNetwork(entries, "мобильная·25020") == plan &&
                DpiPlan.forNetwork(entries, "Wi-Fi·192.168.1.1").encode() == "x=tlsrec" &&
                DpiPlan.forNetwork(entries, "Wi-Fi·10.0.0.1").isEmpty && DpiPlan.forNetwork(entries, "").isEmpty
        )
        val st = dev.warpscout.core.state.ServiceSettings(dpiBypass = false, dpiPlans = entries)
        val back = dev.warpscout.core.state.ServiceSettings.fromJson(st.toJson())
        val old = dev.warpscout.core.state.ServiceSettings.fromJson("{\"ver\":1,\"secondExitOn\":true}")
        ok(
            "обход DPI: переключатель и планы доходят до сервиса; снимок прежней версии — обход включён, планов нет",
            back?.dpiBypass == false && back.dpiPlans == entries && old?.dpiBypass == true && old.dpiPlans.isEmpty()
        )
        val untrusted = DpiReport(0, "?", listOf(res("youtube", DpiVerdict.BYPASS, all5), res("google", DpiVerdict.IP, control = true)), 1000, true)
        val openOnly = DpiReport(0, "?", listOf(res("youtube", DpiVerdict.OPEN), res("x", DpiVerdict.DPI), res("google", DpiVerdict.OPEN, control = true)), 1000, true)
        ok(
            "обход DPI: контроль не открылся, всё открыто или приёмы не помогают — план пустой",
            DpiPlan.of(untrusted).isEmpty && DpiPlan.of(openOnly).isEmpty
        )
        val speedRow = res(
            "youtube", DpiVerdict.BYPASS, listOf(DpiTrick.SPLIT, DpiTrick.OOB),
            attempts = listOf(att(DpiTrick.PLAIN, false), att(DpiTrick.SPLIT, true, kbps = 3100), att(DpiTrick.OOB, true))
        )
        ok(
            "DPI: скорость страницы с приёмом видна в итоге",
            speedRow.text().contains("«разрез» 3.1 Мбит/с") && speedRow.text().contains("«лишний байт (OOB)»"), speedRow.text()
        )
    }

    private fun videoNameChecks() {
        ok(
            "DPI: кластер видео из ответа редиректора",
            GoogleVideo.clusterOf("85.249.22.12 => vimpelcom-iar2 (85.249.20.0/22)") == "vimpelcom-iar2" &&
                GoogleVideo.clusterOf("<html>что-то не то</html>") == null
        )
        // Ожидаемое — от самого conv.py (lennylxx/ipv6-hosts), а не от нашей реализации; первое — ещё
        // и настоящий узел из обсуждения zapret (rr7---sn-8ph2xajvh-v8ce, Новосибирск).
        val cases = mapOf(
            "vimpelcom-ovb1" to "8ph2xajvh-v8ce",
            "vimpelcom-iar2" to "8ph2xajvh-p5gl",
            "tele2-led1" to "uxax1-axqe",
            "fra16s48" to "4g5ednzr"
        )
        val wrong = cases.filter { (c, sn) -> GoogleVideo.snOf(c) != sn }
        ok("DPI: имя узла видео по кластеру — как у conv.py", wrong.isEmpty(), wrong.keys.joinToString { "$it → ${GoogleVideo.snOf(it)}" })
        ok(
            "DPI: узлы кластера — rr1, rr2, r1; странное имя — без узлов",
            GoogleVideo.hostsOf("vimpelcom-ovb1").firstOrNull() == "rr1---sn-8ph2xajvh-v8ce.googlevideo.com" &&
                GoogleVideo.hostsOf("a-b-c").isEmpty() && GoogleVideo.hostsOf("weird name").isEmpty()
        )
        ok(
            "DPI: в проверке — настоящий сервер видео YouTube, а редиректор назван редиректором",
            DpiTargets.DEFAULT.any { it.id == DpiTargets.VIDEO_ID && it.host.isBlank() } &&
                DpiTargets.DEFAULT.first { it.id == "googlevideo" }.name.startsWith("Редиректор")
        )
    }

    // ------------------------------------------------------------------- свой конец TCP

    /** Сервер на 127.0.0.1: принимает в отдельных потоках. */
    private class Srv(private val handler: (Socket) -> Unit) {
        val socket = ServerSocket(0, 50, InetAddress.getByName("127.0.0.1"))
        val accepted = AtomicInteger()

        init {
            Thread({
                while (!socket.isClosed) {
                    val c = runCatching { socket.accept() }.getOrNull() ?: break
                    accepted.incrementAndGet()
                    Thread({ runCatching { handler(c) }; runCatching { c.close() } }, "relay-test-conn").apply { isDaemon = true }.start()
                }
            }, "relay-test-accept").apply { isDaemon = true }.start()
        }

        val port: Int get() = socket.localPort
        fun close() = runCatching { socket.close() }
    }

    /**
     * «Сервер TLS» для проверки: первое сообщение (ClientHello — одной записью или несколькими, как после
     * «двух записей») целиком — ответ записью handshake, дальше эхо всего, что пришло, до конца потока.
     * [dpi] — «эмулятор DPI» перед ним: имя dpi.test целиком в первом пакете — сброс. Приём в проверке —
     * «две записи»: он не зависит от того, как ядро нарежет запись на пакеты, и проверка не мигает.
     */
    private fun tlsEcho(c: Socket, dpi: Boolean) {
        c.soTimeout = 8000
        val inp = c.getInputStream()
        val out = c.getOutputStream()
        val buf = ByteArray(32 * 1024)
        val n = inp.read(buf)
        if (n <= 0) return
        if (dpi && TlsHello.findSni(buf.copyOf(n))?.name == "dpi.test") {
            c.setSoLinger(true, 0)
            return
        }
        val hello = ByteArrayOutputStream()
        hello.write(buf, 0, n)
        // Конец ClientHello: записи handshake подряд, пока их тела не наберут длину сообщения.
        fun end(): Int {
            val b = hello.toByteArray()
            var p = 0
            var body = 0
            var msg = -1
            while (p + 5 <= b.size && b[p] == 0x16.toByte()) {
                val len = ((b[p + 3].toInt() and 0xFF) shl 8) or (b[p + 4].toInt() and 0xFF)
                if (p + 5 + len > b.size) return -1
                if (msg < 0) {
                    if (len < 4) return -1
                    msg = 4 + (((b[p + 6].toInt() and 0xFF) shl 16) or ((b[p + 7].toInt() and 0xFF) shl 8) or (b[p + 8].toInt() and 0xFF))
                }
                body += len
                p += 5 + len
                if (body >= msg) return p
            }
            return -1
        }
        while (end() < 0) {
            val k = inp.read(buf)
            if (k < 0) return
            hello.write(buf, 0, k)
        }
        out.write(byteArrayOf(0x16, 0x03, 0x03, 0x00, 0x02, 0x02, 0x00))
        val extra = hello.toByteArray().let { it.copyOfRange(end(), it.size) }
        if (extra.isNotEmpty()) out.write(extra)
        out.flush()
        while (true) {
            val k = inp.read(buf)
            if (k < 0) break
            out.write(buf, 0, k)
            out.flush()
        }
        c.shutdownOutput()
    }

    private fun clientHello(host: String): ByteArray {
        val ctx = SSLContext.getInstance("TLS")
        ctx.init(null, null, null)
        val e = ctx.createSSLEngine(host, 443)
        e.useClientMode = true
        e.sslParameters = e.sslParameters.also { it.serverNames = listOf(SNIHostName(host)) }
        e.beginHandshake()
        val out = ByteBuffer.allocate(e.session.packetBufferSize)
        e.wrap(ByteBuffer.allocate(0), out)
        out.flip()
        return ByteArray(out.remaining()).also { out.get(it) }
    }

    /** Подключатель к своему серверу вместо настоящего адреса. */
    private class LocalConnector(@Volatile var port: Int) : DpiRelay.Connector {
        val calls = AtomicInteger()
        val released = AtomicInteger()
        override fun connect(address: InetAddress, port: Int, timeoutMs: Int, uid: Int, bound: (Int) -> Unit): Socket {
            calls.incrementAndGet()
            val s = Socket()
            s.bind(InetSocketAddress(InetAddress.getByName("127.0.0.1"), 0))
            bound(s.localPort)
            s.connect(InetSocketAddress(InetAddress.getByName("127.0.0.1"), this.port), timeoutMs)
            return s
        }

        override fun release(localPort: Int, address: InetAddress, port: Int) {
            released.incrementAndGet()
        }
    }

    /**
     * «Приложение» из пакетов: одно соединение TCP к [srvIp]:443, как его видит tun. Проверяет каждую
     * сумму пакетов от туннеля, подтверждает данные по порядку, уважает окно туннеля.
     */
    private inner class SimApp(
        val relay: DpiRelay,
        val q: LinkedBlockingQueue<ByteArray>,
        val sport: Int,
        val srvIp: ByteArray = srvIp4,
        val window: Int = 65535
    ) {
        val appIp = appIp4
        var sndNxt = 7_000_000
        var rcvNxt = 0
        var peerAck = 0
        var peerWnd = 0
        var synAck = false
        var fin = false
        var rst = false
        var badSums = 0
        var foreign = 0
        var dropNextData = 0
        val got = ByteArrayOutputStream()

        fun pkt(flags: Int, data: ByteArray = ByteArray(0), off: Int = 0, len: Int = data.size, seq: Int = sndNxt, mss: Int = 0): ByteArray =
            TcpPacket.build(false, appIp, srvIp, sport, 443, seq, rcvNxt, flags, window, mss = mss, dataLen = len) { b, at ->
                System.arraycopy(data, off, b, at, len)
            }

        fun syn(): Boolean {
            val p = pkt(TcpPacket.SYN, mss = 1240)
            sndNxt += 1
            return relay.take(p, p.size)
        }

        fun ack(): Boolean = pkt(TcpPacket.ACK).let { relay.take(it, it.size) }

        fun send(data: ByteArray, off: Int = 0, len: Int = data.size, fin: Boolean = false): Boolean {
            val p = pkt(TcpPacket.ACK or TcpPacket.PSH or (if (fin) TcpPacket.FIN else 0), data, off, len)
            sndNxt += len + (if (fin) 1 else 0)
            return relay.take(p, p.size)
        }

        fun finish(): Boolean = pkt(TcpPacket.FIN or TcpPacket.ACK).let { sndNxt += 1; relay.take(it, it.size) }

        fun reset(): Boolean = pkt(TcpPacket.RST or TcpPacket.ACK).let { relay.take(it, it.size) }

        /** Разобрать пакеты от туннеля, пока [until] не станет true или не выйдет [ms]. */
        fun pumpUntil(ms: Long, until: () -> Boolean): Boolean {
            val deadline = System.currentTimeMillis() + ms
            while (!until()) {
                val left = deadline - System.currentTimeMillis()
                if (left <= 0) return false
                val p = q.poll(minOf(left, 50L), TimeUnit.MILLISECONDS) ?: continue
                handle(p)
            }
            return true
        }

        fun handle(p: ByteArray) {
            if (!TcpPacket.checksumOk(p)) {
                badSums++
                return
            }
            val s = TcpPacket.parse(p) ?: return
            if (s.dport != sport) {
                foreign++
                return
            }
            if (s.has(TcpPacket.RST)) {
                rst = true
                return
            }
            if (s.has(TcpPacket.SYN)) {
                synAck = s.has(TcpPacket.ACK) && s.ack == sndNxt
                rcvNxt = s.seq + 1
                peerAck = s.ack
                peerWnd = s.window
                return
            }
            if (s.has(TcpPacket.ACK) && s.ack - peerAck >= 0) {
                peerAck = s.ack
                peerWnd = s.window
            } else if (s.has(TcpPacket.ACK) && s.ack == peerAck) {
                peerWnd = s.window
            }
            if (s.dataLen > 0) {
                if (dropNextData > 0) {
                    dropNextData--
                    return
                }
                if (s.seq == rcvNxt) {
                    got.write(s.data, s.dataOff, s.dataLen)
                    rcvNxt += s.dataLen
                }
                ack()
            }
            // FIN — по порядку: данные этого пакета (если были) уже приняты, rcvNxt стоит за ними.
            if (s.has(TcpPacket.FIN) && s.seq + s.dataLen == rcvNxt) {
                rcvNxt += 1
                fin = true
                ack()
            }
        }

        /** Отправить [data] сегментами по 1200 байт, не больше окна туннеля. */
        fun sendAll(data: ByteArray, ms: Long): Boolean {
            var off = 0
            val deadline = System.currentTimeMillis() + ms
            while (off < data.size) {
                if (System.currentTimeMillis() > deadline) return false
                val inFlight = sndNxt - peerAck
                val room = peerWnd - inFlight
                if (room <= 0) {
                    val p = q.poll(50, TimeUnit.MILLISECONDS)
                    if (p != null) handle(p)
                    continue
                }
                val n = minOf(1200, room, data.size - off)
                send(data, off, n)
                off += n
                while (true) handle(q.poll() ?: break)
            }
            return true
        }
    }

    private fun relayChecks() {
        val tlsDpi = Srv { tlsEcho(it, dpi = true) }
        val tlsPlain = Srv { tlsEcho(it, dpi = false) }
        val silent = Srv { c -> c.soTimeout = 3000; runCatching { c.getInputStream().read(ByteArray(4096)); Thread.sleep(2500) } }
        val testFamily = DpiFamily("test", "Тест", listOf("dpi.test"), listOf("dpi"), listOf("test.app"))
        val q = LinkedBlockingQueue<ByteArray>()
        val direct = LocalConnector(tlsDpi.port)
        val tunnel = LocalConnector(tlsPlain.port)
        val uids = HashMap<Int, Int>() // свой порт «приложения» → uid
        val owner: (Int, InetSocketAddress, InetSocketAddress) -> Int = { _, local, _ -> uids[local.port] ?: -1 }
        val logs = java.util.Collections.synchronizedList(ArrayList<String>())
        val timing = DpiRelay.Timing(directConnectMs = 1000, replyMs = 500, tunnelConnectMs = 2000, helloWaitMs = 3000, rtoMinMs = 150, rtoMaxMs = 600, tickMs = 30)
        val relay = DpiRelay(
            tunOut = { q.offer(it) }, owner = owner, apps = mapOf(10123 to DpiRelay.App("Тест", "test")),
            plan = DpiPlan(mapOf("test" to DpiTrick.TLSREC)), direct = direct, tunnel = tunnel, ttl = null,
            mtu = 1280, log = { logs += it }, families = listOf(testFamily), timing = timing
        )
        try {
            // 1. Сайт из плана: напрямую с «двумя записями» через «эмулятор DPI», 200 КБ туда и обратно, FIN.
            uids[40001] = 10123
            val app = SimApp(relay, q, 40001, window = 20_000)
            val took = app.syn()
            val synOk = app.pumpUntil(2000) { app.synAck }
            app.ack()
            val hello = clientHello("dpi.test")
            app.send(hello, 0, 100)
            app.send(hello, 100, hello.size - 100)
            val replied = app.pumpUntil(4000) { app.got.size() >= 7 }
            val reply = app.got.toByteArray()
            ok(
                "обход DPI: SYN выбранного приложения к :443 забран, SYN-ACK от имени сервера с правильной суммой",
                took && synOk && app.badSums == 0, "забран=$took syn-ack=$synOk плохих сумм=${app.badSums}"
            )
            ok(
                "обход DPI: имя сайта из плана — напрямую с приёмом, «эмулятор DPI» пропустил, сервер ответил",
                replied && reply.size >= 7 && reply[0] == 0x16.toByte() && direct.calls.get() == 1 && tunnel.calls.get() == 0 &&
                    relay.viaDirect.get() == 1L,
                "ответ ${reply.size} Б, напрямую ${direct.calls.get()}, через туннель ${tunnel.calls.get()}; ${logs.joinToString(" | ")}"
            )
            val body = ByteArray(200_000) { ((it * 31) xor (it ushr 8)).toByte() }
            val sent = app.sendAll(body, 15_000)
            val echoed = app.pumpUntil(15_000) { app.got.size() >= 7 + body.size }
            val back = app.got.toByteArray()
            ok(
                "обход DPI: 200 КБ к серверу и обратно — по окнам (у «приложения» 20 КБ), байт в байт",
                sent && echoed && back.size == 7 + body.size && back.copyOfRange(7, back.size).contentEquals(body) && app.badSums == 0,
                "отправлено=$sent вернулось ${back.size - 7} из ${body.size}, плохих сумм ${app.badSums}"
            )
            app.finish()
            val closed = app.pumpUntil(5000) { app.fin } && waitFor(3000) { relay.active == 0 }
            ok("обход DPI: закрытие — FIN от приложения, FIN от сервера, соединение забыто", closed, "fin=${app.fin} активных ${relay.active}")
            val late = app.pkt(TcpPacket.ACK)
            ok("обход DPI: запоздавший пакет закрытого соединения выброшен, а не отдан в WARP", relay.take(late, late.size))
            ok(
                "обход DPI: журнал — «открылся напрямую с приёмом «две записи TLS»»",
                logs.any { it.contains("открылся напрямую с приёмом «две записи TLS»") }, logs.joinToString(" | ")
            )

            // 2. Потеря пакета: первый кусок данных от туннеля «теряется» — туннель повторяет сам.
            uids[40002] = 10123
            val lossy = SimApp(relay, q, 40002)
            lossy.syn(); lossy.pumpUntil(2000) { lossy.synAck }; lossy.ack()
            lossy.dropNextData = 1
            lossy.send(hello, 0, hello.size)
            val recovered = lossy.pumpUntil(4000) { lossy.got.size() >= 7 }
            ok(
                "обход DPI: потерянный пакет к приложению повторяется по таймеру",
                recovered && relay.retransmits.get() >= 1, "получено ${lossy.got.size()} Б, повторов ${relay.retransmits.get()}"
            )
            lossy.reset()
            ok("обход DPI: сброс от приложения — соединение забыто, сокет закрыт", waitFor(2000) { relay.active == 0 }, "активных ${relay.active}")

            // 3. Чужое приложение — мимо, пакетов от туннеля нет.
            q.clear()
            uids[40003] = 999
            val other = SimApp(relay, q, 40003)
            val tookOther = other.syn()
            ok("обход DPI: SYN другого приложения не забирается (идёт в WARP, как раньше)", !tookOther && q.poll(200, TimeUnit.MILLISECONDS) == null)

            // 4. Чужой сайт у выбранного приложения — через «туннель», без попытки напрямую.
            uids[40004] = 10123
            val foreignSite = SimApp(relay, q, 40004)
            foreignSite.syn(); foreignSite.pumpUntil(2000) { foreignSite.synAck }; foreignSite.ack()
            foreignSite.send(clientHello("other.test"))
            val viaTunnel = foreignSite.pumpUntil(4000) { foreignSite.got.size() >= 7 }
            ok(
                "обход DPI: другой сайт выбранного приложения — через туннель, напрямую не пробуется",
                viaTunnel && direct.calls.get() == 2 && tunnel.calls.get() == 1, "напрямую ${direct.calls.get()}, через туннель ${tunnel.calls.get()}"
            )
            foreignSite.finish()
            foreignSite.pumpUntil(3000) { foreignSite.fin }
            ok("обход DPI: закреплённый порт сокета через туннель снят после закрытия", waitFor(2000) { tunnel.released.get() >= 1 }, "снято ${tunnel.released.get()}")

            // 5. Параллельная попытка: приложение закрыло, ничего не отправив, — никуда не подключаемся.
            uids[40005] = 10123
            val racer = SimApp(relay, q, 40005)
            racer.syn(); racer.pumpUntil(2000) { racer.synAck }; racer.ack(); racer.finish()
            val racerReset = racer.pumpUntil(2000) { racer.rst }
            ok(
                "обход DPI: соединение без данных (параллельная попытка) закрыто сбросом, к серверу не подключались",
                racerReset && waitFor(2000) { relay.active == 0 } && direct.calls.get() == 2 && tunnel.calls.get() == 1,
                "сброс=$racerReset активных ${relay.active}, напрямую ${direct.calls.get()}, через туннель ${tunnel.calls.get()}"
            )

            // 6. Напрямую тишина после приветствия — то же соединение через туннель; адрес запомнен.
            direct.port = silent.port
            uids[40006] = 10123
            val blocked = SimApp(relay, q, 40006)
            blocked.syn(); blocked.pumpUntil(2000) { blocked.synAck }; blocked.ack()
            blocked.send(hello)
            val fellBack = blocked.pumpUntil(5000) { blocked.got.size() >= 7 }
            ok(
                "обход DPI: напрямую тишина — то же приветствие через туннель, приложение получает ответ",
                fellBack && relay.fallbacks.get() == 1L && blocked.got.toByteArray()[0] == 0x16.toByte(),
                "получено ${blocked.got.size()} Б, запасных ${relay.fallbacks.get()}; ${logs.lastOrNull()}"
            )
            uids[40007] = 10123
            val again = SimApp(relay, q, 40007)
            ok("обход DPI: адрес, где напрямую не открылось, дальше не разбирается — сразу в туннель", !again.syn())
            blocked.reset()

            // 7. QUIC выбранного приложения — «порт закрыт», чужого — мимо.
            q.clear()
            uids[50123] = 10123
            uids[50124] = 999
            val quicMine = udpPacket(appIp4, byteArrayOf(203.toByte(), 0, 113, 77), 50123, 443, 1200)
            val quicOther = udpPacket(appIp4, byteArrayOf(203.toByte(), 0, 113, 77), 50124, 443, 1200)
            val tookQuic = relay.take(quicMine, quicMine.size)
            val icmp = q.poll(200, TimeUnit.MILLISECONDS)
            val tookOtherQuic = relay.take(quicOther, quicOther.size)
            ok(
                "обход DPI: QUIC выбранного приложения закрыт («порт закрыт» — сразу перейдёт на TCP), чужой — мимо",
                tookQuic && icmp != null && icmp[9].toInt() == 1 && !tookOtherQuic && relay.quicBlocked.get() == 1L
            )
            ok(
                "обход DPI: итог сессии для журнала — напрямую 2, через туннель 2 (из них запасной путь 1), QUIC",
                relay.viaDirect.get() == 2L && relay.summary().contains("напрямую 2 (Тест 2)") &&
                    relay.summary().contains("через туннель 2 (из них напрямую не открылись: 1)") && relay.summary().contains("QUIC закрыт"),
                relay.summary()
            )

            // 8. План пустой — туннель ничего не разбирает.
            relay.plan = DpiPlan.EMPTY
            uids[40008] = 10123
            val idle = SimApp(relay, q, 40008, srvIp = byteArrayOf(203.toByte(), 0, 113, 99))
            ok("обход DPI: план пустой — ничего не забирается", !idle.syn() && !relay.take(quicMine, quicMine.size))
        } finally {
            relay.stop()
            tlsDpi.close()
            tlsPlain.close()
            silent.close()
        }
    }

    private fun waitFor(ms: Long, cond: () -> Boolean): Boolean {
        val deadline = System.currentTimeMillis() + ms
        while (System.currentTimeMillis() < deadline) {
            if (cond()) return true
            Thread.sleep(20)
        }
        return cond()
    }

    @Suppress("unused")
    private fun readAll(inp: InputStream): ByteArray = inp.readBytes()
}
