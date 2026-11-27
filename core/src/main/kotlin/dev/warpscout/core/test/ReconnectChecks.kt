package dev.warpscout.core.test

import dev.warpscout.core.dpi.DpiFamily
import dev.warpscout.core.dpi.DpiPlan
import dev.warpscout.core.dpi.DpiRelay
import dev.warpscout.core.dpi.DpiTrick
import dev.warpscout.core.dpi.TcpPacket
import dev.warpscout.core.tunnel.ExitRouter
import dev.warpscout.core.tunnel.PacketQueueIn
import dev.warpscout.core.tunnel.SecondRetry
import dev.warpscout.core.tunnel.TcpGuard
import dev.warpscout.core.tunnel.TunDispatcher
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.net.InetAddress
import java.net.Socket

/**
 * Самопроверка 1.10.50-beta1: переключение сети и сим-карт без зависших соединений.
 *
 *  • после переподключения прежние соединения TCP сбрасываются приложению сегментом RST с тем номером,
 *    которого оно ждёт (IPv4 и IPv6, отложенное подтверждение, «challenge ACK», соединение без ответа
 *    на SYN), а новые — нет;
 *  • прежнее соединение, по которому приложение шлёт, а ответа 4 с нет, хотя туннель пакеты получает, —
 *    тоже сброс; при мёртвом туннеле и в проверочном подъёме — нет;
 *  • второй выход на паузе: диспетчер шлёт в WARP, очередь не закрыта; повторы — 1, 2, 5, 10, 15 мин;
 *  • закрепление соединения за выходом — и по IPv6;
 *  • обход DPI: без IPv6 у сети соединения по IPv6 не разбираются.
 */
class ReconnectChecks(private val check: (String, Boolean, String) -> Unit) {

    private fun ok(name: String, condition: Boolean, detail: String = "") = check(name, condition, detail)

    fun run() {
        guardChecks()
        guardReactiveChecks()
        guardStreamChecks()
        laneChecks()
        pinChecks()
        relayV6Checks()
    }

    private val app4 = byteArrayOf(172.toByte(), 16, 0, 2)
    private val srv4 = byteArrayOf(149.toByte(), 154.toByte(), 167.toByte(), 51)
    private val app6 = InetAddress.getByName("2606:4700:110:8d8a::2").address
    private val srv6 = InetAddress.getByName("2001:67c:4e8:f004::9").address

    private fun pkt(
        v6: Boolean, fromApp: Boolean, appPort: Int, seq: Int, ack: Int, flags: Int, data: Int = 0, srvPort: Int = 443,
    ): ByteArray {
        val a = if (v6) app6 else app4
        val s = if (v6) srv6 else srv4
        return if (fromApp) {
            TcpPacket.build(v6, a, s, appPort, srvPort, seq, ack, flags, 65535, dataLen = data) { b, at -> for (i in 0 until data) b[at + i] = i.toByte() }
        } else {
            TcpPacket.build(v6, s, a, srvPort, appPort, seq, ack, flags, 65535, dataLen = data) { b, at -> for (i in 0 until data) b[at + i] = i.toByte() }
        }
    }

    /** Соединение от SYN до обмена данными: приложение послало 100 байт, сервер — 50 и подтвердил. */
    private fun handshake(g: TcpGuard, clock: LongArray, v6: Boolean, port: Int) {
        val ack = TcpPacket.ACK
        clock[0] += 10; up(g, pkt(v6, true, port, 1000, 0, TcpPacket.SYN))
        clock[0] += 10; down(g, pkt(v6, false, port, 5000, 1001, TcpPacket.SYN or ack))
        clock[0] += 10; up(g, pkt(v6, true, port, 1001, 5001, ack))
        clock[0] += 10; up(g, pkt(v6, true, port, 1001, 5001, ack or TcpPacket.PSH, data = 100))
        clock[0] += 10; down(g, pkt(v6, false, port, 5001, 1101, ack or TcpPacket.PSH, data = 50))
        clock[0] += 10; up(g, pkt(v6, true, port, 1101, 5051, ack))
    }

    private fun up(g: TcpGuard, p: ByteArray): Boolean = g.up(p, 0, p.size)
    private fun down(g: TcpGuard, p: ByteArray) = g.down(p, 0, p.size)

    private fun guardChecks() {
        val clock = longArrayOf(1_000L)
        val out = ArrayList<ByteArray>()
        val g = TcpGuard({ clock[0] })
        g.sessionBegin({ out += it }, resetting = true)
        handshake(g, clock, v6 = false, port = 40001)
        // Новая сессия (переподключение).
        clock[0] = 10_000L
        g.sessionBegin({ out += it }, resetting = true)
        clock[0] = 10_500L
        ok("сброс соединений: к подъёму никто не ждал ответа — при той же сети сбрасывать нечего", g.staleFlows(all = false).isEmpty())
        val all = g.staleFlows(all = true)
        ok("сброс соединений: сеть сменилась — прежнее соединение в списке", all.size == 1 && all[0].appPort == 40001, "в списке ${all.size}")
        val n = g.reset(all)
        val rst = out.singleOrNull()?.let { TcpPacket.parse(it) }
        ok(
            "сброс соединений: RST|ACK от имени сервера, номер — ровно тот, которого ждёт приложение, суммы сходятся",
            n == 1 && rst != null && rst.has(TcpPacket.RST) && rst.has(TcpPacket.ACK) && rst.seq == 5051 && rst.ack == 1101 &&
                rst.sport == 443 && rst.dport == 40001 && rst.src.contentEquals(srv4) && rst.dst.contentEquals(app4) &&
                TcpPacket.checksumOk(out[0]),
            "сброшено $n, пакетов ${out.size}, seq=${rst?.seq} ack=${rst?.ack}"
        )
        // «Challenge ACK»: номер не совпал — приложение подтверждает свой, отвечаем вторым сбросом с ним.
        out.clear()
        clock[0] = 10_600L
        val dropped = up(g, pkt(false, true, 40001, 1101, 5060, TcpPacket.ACK))
        val second = out.singleOrNull()?.let { TcpPacket.parse(it) }
        ok(
            "сброс соединений: на «challenge ACK» — второй сброс с номером из него, сам ACK наружу не уходит",
            dropped && second != null && second.has(TcpPacket.RST) && second.seq == 5060,
            "выброшен=$dropped seq=${second?.seq}"
        )
        out.clear()
        val data = up(g, pkt(false, true, 40001, 1101, 5060, TcpPacket.ACK or TcpPacket.PSH, data = 20))
        ok("сброс соединений: данные сброшенного соединения выбрасываются, лишних сбросов нет", data && out.isEmpty())
        // Новое соединение после подъёма — не трогаем.
        clock[0] = 10_700L
        up(g, pkt(false, true, 40002, 3000, 0, TcpPacket.SYN))
        ok("сброс соединений: новое соединение (SYN после подъёма) не сбрасывается", g.staleFlows(all = true).none { it.appPort == 40002 })
        // То же сочетание портов, новый SYN после сброса — новое соединение.
        clock[0] = 10_800L
        val again = up(g, pkt(false, true, 40001, 9000, 0, TcpPacket.SYN))
        ok("сброс соединений: SYN на порту сброшенного — новое соединение, пропускаем", !again)

        // Отложенное подтверждение: сервер прислал ещё, приложение не успело подтвердить — два сброса.
        val clock2 = longArrayOf(1_000L)
        val out2 = ArrayList<ByteArray>()
        val g2 = TcpGuard({ clock2[0] })
        g2.sessionBegin({ out2 += it }, resetting = true)
        handshake(g2, clock2, v6 = false, port = 40010)
        clock2[0] += 10; down(g2, pkt(false, false, 40010, 5051, 1101, TcpPacket.ACK or TcpPacket.PSH, data = 100))
        clock2[0] = 20_000L
        g2.sessionBegin({ out2 += it }, resetting = true)
        g2.reset(g2.staleFlows(all = true))
        val seqs = out2.mapNotNull { TcpPacket.parse(it)?.seq }
        ok("сброс соединений: подтверждение отложено — сбросы с обоими номерами (5051 и 5151)", seqs == listOf(5051, 5151), "номера $seqs")

        // Только SYN, ответа не было: сброс принимается по полю ACK = SYN + 1.
        val clock3 = longArrayOf(1_000L)
        val out3 = ArrayList<ByteArray>()
        val g3 = TcpGuard({ clock3[0] })
        g3.sessionBegin({ out3 += it }, resetting = true)
        up(g3, pkt(false, true, 40020, 7000, 0, TcpPacket.SYN))
        clock3[0] = 5_000L
        g3.sessionBegin({ out3 += it }, resetting = true)
        val waiting = g3.staleFlows(all = false)
        g3.reset(waiting)
        val synRst = out3.singleOrNull()?.let { TcpPacket.parse(it) }
        ok(
            "сброс соединений: SYN без ответа к подъёму — «ждало ответа», сброс с ACK = SYN + 1",
            waiting.size == 1 && synRst != null && synRst.has(TcpPacket.RST) && synRst.ack == 7001,
            "ждали ${waiting.size}, ack=${synRst?.ack}"
        )

        // IPv6.
        val clock6 = longArrayOf(1_000L)
        val out6 = ArrayList<ByteArray>()
        val g6 = TcpGuard({ clock6[0] })
        g6.sessionBegin({ out6 += it }, resetting = true)
        handshake(g6, clock6, v6 = true, port = 50001)
        clock6[0] = 30_000L
        g6.sessionBegin({ out6 += it }, resetting = true)
        g6.reset(g6.staleFlows(all = true))
        val r6 = out6.singleOrNull()?.let { TcpPacket.parse(it) }
        ok(
            "сброс соединений: IPv6 — сброс с заголовком IPv6, адреса и сумма верны",
            r6 != null && r6.v6 && r6.seq == 5051 && r6.src.contentEquals(srv6) && r6.dst.contentEquals(app6) && TcpPacket.checksumOk(out6[0]),
            "seq=${r6?.seq} v6=${r6?.v6}"
        )

        // Закрытое соединение (FIN с обеих сторон) не сбрасываем.
        val clockF = longArrayOf(1_000L)
        val outF = ArrayList<ByteArray>()
        val gF = TcpGuard({ clockF[0] })
        gF.sessionBegin({ outF += it }, resetting = true)
        handshake(gF, clockF, v6 = false, port = 40030)
        clockF[0] += 10; up(gF, pkt(false, true, 40030, 1101, 5051, TcpPacket.FIN or TcpPacket.ACK))
        clockF[0] += 10; down(gF, pkt(false, false, 40030, 5051, 1102, TcpPacket.FIN or TcpPacket.ACK))
        clockF[0] = 40_000L
        gF.sessionBegin({ outF += it }, resetting = true)
        ok("сброс соединений: закрытое с обеих сторон соединение забыто, сбрасывать нечего", gF.staleFlows(all = true).isEmpty())

        // Проверочный подъём подбора: только следим.
        val clockQ = longArrayOf(1_000L)
        val outQ = ArrayList<ByteArray>()
        val gQ = TcpGuard({ clockQ[0] })
        gQ.sessionBegin({ outQ += it }, resetting = true)
        handshake(gQ, clockQ, v6 = false, port = 40040)
        clockQ[0] = 50_000L
        gQ.sessionBegin({ outQ += it }, resetting = false)
        ok("сброс соединений: в проверочном подъёме подбора ничего не сбрасывается", gQ.reset(gQ.staleFlows(all = true)) == 0 && outQ.isEmpty())

        // Прежнюю сессию закрывают в фоне, а новая уже началась: её конец новую не трогает (с 1.10.50-beta1).
        val clockE = longArrayOf(1_000L)
        val oldOut = ArrayList<ByteArray>()
        val newOut = ArrayList<ByteArray>()
        val gE = TcpGuard({ clockE[0] })
        val first = gE.sessionBegin({ oldOut += it }, resetting = true)
        handshake(gE, clockE, v6 = false, port = 40050)
        clockE[0] = 60_000L
        val next = gE.sessionBegin({ newOut += it }, resetting = true)
        gE.sessionEnd(first)
        val kept = gE.reset(gE.staleFlows(all = true))
        ok(
            "сброс соединений: конец прежней сессии (закрывали в фоне) не выключает сбросы в новой",
            next != first && kept == 1 && newOut.size == 1 && oldOut.isEmpty(),
            "сброшено $kept, в новый tun ${newOut.size}, в прежний ${oldOut.size}"
        )
        gE.sessionEnd(next)
        clockE[0] = 70_000L
        up(gE, pkt(false, true, 40051, 7000, 0, TcpPacket.SYN))
        clockE[0] = 80_000L
        gE.sessionBegin(null, resetting = true)
        ok("сброс соединений: tun сессии закрыт — сбрасывать некуда, ничего не пишем", gE.reset(gE.staleFlows(all = true)) == 0 && newOut.size == 1)
    }

    private fun guardReactiveChecks() {
        val clock = longArrayOf(1_000L)
        val out = ArrayList<ByteArray>()
        val g = TcpGuard({ clock[0] })
        var said = 0
        g.onReactive = { said++ }
        g.sessionBegin({ out += it }, resetting = true)
        handshake(g, clock, v6 = false, port = 41001)
        handshake(g, clock, v6 = false, port = 41002)
        clock[0] = 100_000L
        g.sessionBegin({ out += it }, resetting = true)
        // Сеть та же: прежнее соединение 41001 — приложение шлёт, сервер молчит.
        clock[0] = 101_000L
        ok("сброс по ходу: первая отправка после подъёма — не повод", !up(g, pkt(false, true, 41001, 1101, 5051, TcpPacket.ACK or TcpPacket.PSH, data = 30)))
        // Туннель живой: другому соединению ответы идут.
        clock[0] = 102_000L
        down(g, pkt(false, false, 41002, 5051, 1101, TcpPacket.ACK or TcpPacket.PSH, data = 10))
        clock[0] = 103_000L
        ok("сброс по ходу: прошло 2 с — ещё ждём", !up(g, pkt(false, true, 41001, 1101, 5051, TcpPacket.ACK or TcpPacket.PSH, data = 30)) && out.isEmpty())
        clock[0] = 105_200L
        val reset = up(g, pkt(false, true, 41001, 1101, 5051, TcpPacket.ACK or TcpPacket.PSH, data = 30))
        val r = out.lastOrNull()?.let { TcpPacket.parse(it) }
        ok(
            "сброс по ходу: прежнее соединение молчит 4 с, а туннель пакеты получает — сброс, пакет наружу не уходит",
            reset && r != null && r.has(TcpPacket.RST) && r.dport == 41001 && said == 1 && g.reactiveResets.get() == 1L,
            "сброс=$reset сообщено=$said"
        )

        // Туннель мёртв (вниз ничего): не сбрасываем — виноват туннель, не соединение.
        val clockD = longArrayOf(1_000L)
        val outD = ArrayList<ByteArray>()
        val gD = TcpGuard({ clockD[0] })
        gD.sessionBegin({ outD += it }, resetting = true)
        handshake(gD, clockD, v6 = false, port = 42001)
        clockD[0] = 100_000L
        gD.sessionBegin({ outD += it }, resetting = true)
        clockD[0] = 101_000L
        up(gD, pkt(false, true, 42001, 1101, 5051, TcpPacket.ACK or TcpPacket.PSH, data = 30))
        clockD[0] = 108_000L
        ok("сброс по ходу: туннель ничего не получает — соединение не сбрасываем", !up(gD, pkt(false, true, 42001, 1101, 5051, TcpPacket.ACK or TcpPacket.PSH, data = 30)) && outD.isEmpty())

        // Новое соединение после подъёма молчит — не наше дело.
        val clockN = longArrayOf(1_000L)
        val outN = ArrayList<ByteArray>()
        val gN = TcpGuard({ clockN[0] })
        gN.sessionBegin({ outN += it }, resetting = true)
        clockN[0] = 2_000L
        up(gN, pkt(false, true, 43001, 100, 0, TcpPacket.SYN))
        handshake(gN, clockN, v6 = false, port = 43002)
        clockN[0] = 9_000L
        down(gN, pkt(false, false, 43002, 5051, 1101, TcpPacket.ACK))
        clockN[0] = 9_500L
        ok("сброс по ходу: новое соединение без ответа не трогаем", !up(gN, pkt(false, true, 43001, 100, 0, TcpPacket.SYN)) && outN.isEmpty())

        // Ждало ответа к подъёму (обрыв на старой сети): при той же сети — в списке на сброс сразу.
        val clockS = longArrayOf(1_000L)
        val gS = TcpGuard({ clockS[0] })
        gS.sessionBegin({ }, resetting = true)
        handshake(gS, clockS, v6 = false, port = 44001)
        clockS[0] = 50_000L
        up(gS, pkt(false, true, 44001, 1101, 5051, TcpPacket.ACK or TcpPacket.PSH, data = 40))
        clockS[0] = 50_500L
        gS.sessionBegin({ }, resetting = true)
        clockS[0] = 52_000L
        ok("сброс соединений: зависло на обрыве (ждало ответа 2 с) — в списке и при той же сети", gS.staleFlows(all = false).size == 1)
    }

    /** Чтение «tun» по пакету за раз, как у настоящего tun. */
    private class PacketStream(packets: List<ByteArray>) : InputStream() {
        private val q = ArrayDeque(packets)
        override fun read(): Int = -1
        override fun read(b: ByteArray, off: Int, len: Int): Int {
            val p = q.removeFirstOrNull() ?: return -1
            System.arraycopy(p, 0, b, off, p.size)
            return p.size
        }
    }

    private fun guardStreamChecks() {
        val clock = longArrayOf(1_000L)
        val out = ArrayList<ByteArray>()
        val g = TcpGuard({ clock[0] })
        g.sessionBegin({ out += it }, resetting = true)
        handshake(g, clock, v6 = false, port = 45001)
        clock[0] = 60_000L
        g.sessionBegin({ out += it }, resetting = true)
        g.reset(g.staleFlows(all = true))
        val dead = pkt(false, true, 45001, 1101, 5051, TcpPacket.ACK or TcpPacket.PSH, data = 10)
        val fresh = pkt(false, true, 45002, 1, 0, TcpPacket.SYN)
        val stream = g.In(PacketStream(listOf(dead, fresh)))
        val buf = ByteArray(2048)
        val n = stream.read(buf, 0, buf.size)
        ok(
            "обёртка tun: пакет сброшенного соединения пропущен, следующий отдан как есть",
            n == fresh.size && buf.copyOf(n).contentEquals(fresh), "прочитано $n из ${fresh.size}"
        )
        val sink = ByteArrayOutputStream()
        val w = g.Out(sink)
        val reply = pkt(false, false, 45002, 777, 2, TcpPacket.SYN or TcpPacket.ACK)
        w.write(reply, 0, reply.size)
        ok("обёртка tun: запись проходит байт в байт", sink.toByteArray().contentEquals(reply))
    }

    private fun laneChecks() {
        val q = PacketQueueIn("второй")
        q.offer(ByteArray(40))
        q.paused = true
        ok("второй выход на паузе: пакеты — в WARP (очередь «не годится»), но не закрыта", !q.usable() && !q.isClosed())
        q.paused = false
        ok("второй выход снова работает: очередь годится", q.usable())
        q.close()
        ok("закрытая очередь не годится", !q.usable() && q.isClosed())
        ok(
            "повторы второго выхода: 1, 2, 5, 10, дальше 15 мин",
            (1..6).map { SecondRetry.delayMs(it) / 60_000L } == listOf(1L, 2L, 5L, 10L, 15L, 15L),
            (1..6).joinToString { "${SecondRetry.delayMs(it) / 60_000L}" }
        )
    }

    private fun pinChecks() {
        val d = TunDispatcher(ByteArrayInputStream(ByteArray(0)), ExitRouter.EMPTY, listOf(PacketQueueIn("а"), PacketQueueIn("б")))
        val google6 = InetAddress.getByName("2001:4860:4845:400::")
        d.pinAddr(40100, google6, 443, 0)
        val p6 = TcpPacket.build(true, app6, google6.address, 40100, 443, 1, 0, TcpPacket.SYN, 65535)
        val other6 = TcpPacket.build(true, app6, google6.address, 40101, 443, 1, 0, TcpPacket.SYN, 65535)
        ok("закрепление за выходом: IPv6 — своё соединение в WARP, чужой порт — нет", d.pinnedLane(p6, p6.size) == 0 && d.pinnedLane(other6, other6.size) == -1)
        val v4 = InetAddress.getByName("142.250.74.110")
        d.pinAddr(40102, v4, 443, 1)
        val p4 = TcpPacket.build(false, app4, v4.address, 40102, 443, 1, 0, TcpPacket.SYN, 65535)
        ok("закрепление за выходом: IPv4 через тот же вызов — как у замеров", d.pinnedLane(p4, p4.size) == 1)
        d.unpinAddr(40100, google6, 443)
        ok("закрепление за выходом: снято — пакет снова по общим правилам", d.pinnedLane(p6, p6.size) == -1)
    }

    private fun relayV6Checks() {
        val family = DpiFamily("test", "Тест", listOf("dpi.test"), listOf("dpi"), service = "test")
        val never = object : DpiRelay.Connector {
            override fun connect(address: InetAddress, port: Int, timeoutMs: Int, uid: Int, bound: (Int) -> Unit): Socket =
                throw java.io.IOException("в проверке не подключаемся")
        }
        fun relay(directV6: Boolean, sink: MutableList<ByteArray>) = DpiRelay(
            tunOut = { sink += it }, owner = { _, _, _ -> 10123 }, apps = mapOf(10123 to DpiRelay.App("Тест", "test")),
            plan = DpiPlan(mapOf("test" to DpiTrick.TLSREC)), direct = never, tunnel = never, ttl = null,
            families = listOf(family), directV6 = directV6
        )
        val syn6 = TcpPacket.build(true, app6, srv6, 50100, 443, 1, 0, TcpPacket.SYN, 65535, mss = 1220)
        val syn4 = TcpPacket.build(false, app4, srv4, 40200, 443, 1, 0, TcpPacket.SYN, 65535, mss = 1240)
        val sinkA = java.util.Collections.synchronizedList(ArrayList<ByteArray>())
        val noV6 = relay(directV6 = false, sinkA)
        try {
            ok("обход DPI: у сети нет IPv6 — SYN по IPv6 не разбираем, он идёт через туннель сам", !noV6.take(syn6, syn6.size))
            ok("обход DPI: у сети нет IPv6 — IPv4 разбираем как раньше", noV6.take(syn4, syn4.size))
        } finally {
            noV6.stop()
        }
        val sinkB = java.util.Collections.synchronizedList(ArrayList<ByteArray>())
        val withV6 = relay(directV6 = true, sinkB)
        try {
            ok("обход DPI: у сети есть IPv6 — SYN по IPv6 разбираем", withV6.take(syn6, syn6.size))
        } finally {
            withV6.stop()
        }
    }
}
