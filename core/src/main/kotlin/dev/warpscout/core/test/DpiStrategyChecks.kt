package dev.warpscout.core.test

import dev.warpscout.core.dpi.DpiAttempt
import dev.warpscout.core.dpi.DpiDesync
import dev.warpscout.core.dpi.DpiFamilies
import dev.warpscout.core.dpi.DpiPlan
import dev.warpscout.core.dpi.DpiProbe
import dev.warpscout.core.dpi.DpiReport
import dev.warpscout.core.dpi.DpiStage
import dev.warpscout.core.dpi.DpiStrategy
import dev.warpscout.core.dpi.DpiTarget
import dev.warpscout.core.dpi.DpiTargetResult
import dev.warpscout.core.dpi.DpiTargets
import dev.warpscout.core.dpi.DpiTrick
import dev.warpscout.core.dpi.DpiVerdict
import dev.warpscout.core.dpi.FakeSender
import dev.warpscout.core.dpi.TlsHello
import dev.warpscout.core.dpi.TrickSender
import java.io.ByteArrayOutputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.nio.ByteBuffer
import java.util.Random
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLContext

/**
 * Самопроверка стратегий ByeDPI (1.10.49-beta4) — без интернета:
 *
 *  • разбор строки ByeDPI: длинные и короткие ключи, склейка «-s1+s», позиции «1:3:5», «0+sm»,
 *    «-1», группы --auto; неизвестное — ошибка, ненужное телефону — пропуск с объяснением;
 *  • куски первого сообщения — как у desync.c ByeDPI: склейка без срочных байтов — то, что получит
 *    сервер, позиции повторов, TTL у перестановок, записи TLS по --tlsrec;
 *  • фейк: подделка той же длины, имя другое (фильтр видит чужой сайт), random и session_id —
 *    случайные; сервер, который ответил на фейк, узнаётся по session_id (как ssl_err у ByeDPI);
 *  • план: Tele2 26.11 10:53 — страница и видео YouTube через туннель (приёмы их не открыли),
 *    картинки отдельно, X и Discord — OOB; выбор человека поверх плана; старые планы beta3 не в ходу.
 */
class DpiStrategyChecks(private val check: (String, Boolean, String) -> Unit) {

    private fun ok(name: String, condition: Boolean, detail: String = "") = check(name, condition, detail)

    fun run() {
        parseChecks()
        desyncChecks()
        fakeChecks()
        senderChecks()
        planChecks()
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

    private fun u16(b: ByteArray, i: Int): Int = ((b[i].toInt() and 0xFF) shl 8) or (b[i + 1].toInt() and 0xFF)

    // ------------------------------------------------------------------------------- разбор

    private fun parseChecks() {
        val d = DpiStrategy.of("--split 1+s --disorder 3+s --tlsrec 1+s --auto=torst --fake -1 --ttl 5").describe()
        ok(
            "стратегия: словами для экрана — «разрез 1+s, перестановка 3+s, запись TLS 1+s; если не вышло (torst): фейк -1 (TTL 5)»",
            d == "разрез 1+s, перестановка 3+s, запись TLS 1+s; если не вышло (torst): фейк -1 (TTL 5)", d
        )
        val a = DpiStrategy.parse("--split 1+s --disorder 3+s").strategy
        val b = DpiStrategy.parse("-s1+s -d3+s").strategy
        fun shape(s: DpiStrategy?): String = s?.groups?.joinToString(" | ") { g -> g.parts.joinToString(" ") { "${it.mode.flag} ${it.pos}" } }.orEmpty()
        ok(
            "стратегия: «--split 1+s --disorder 3+s» и «-s1+s -d3+s» — одно и то же",
            a != null && shape(a) == "--split 1+s --disorder 3+s" && shape(a) == shape(b), "${shape(a)} / ${shape(b)}"
        )
        val f = DpiStrategy.parse("-f-1 -t5").strategy
        ok(
            "стратегия: «-f-1 -t5» — фейк до последнего байта, TTL 5",
            f != null && f.groups.size == 1 && f.groups[0].parts.single().mode == DpiStrategy.Mode.FAKE &&
                f.groups[0].parts.single().pos.offset == -1L && f.groups[0].fakeTtl == 5 && f.needsFake && f.needsTtl
        )
        val eq = DpiStrategy.parse("--fake=-1 --ttl=3 --fake-sni=ya.ru").strategy
        ok("стратегия: «--ключ=значение» и --fake-sni", eq != null && eq.groups[0].fakeTtl == 3 && eq.groups[0].fakeSni == listOf("ya.ru"))
        val auto = DpiStrategy.parse("ciadpi --tlsrec 1+s --auto=torst --oob 3+s --timeout 2.5").strategy
        ok(
            "стратегия: «ciadpi … --auto=torst …» — две группы, вторая по сбою; имя программы не мешает",
            auto != null && auto.groups.size == 2 && auto.groups[1].trigger == "torst" && auto.groups[0].tlsrec.size == 1 &&
                auto.groups[1].parts.single().mode == DpiStrategy.Mode.OOB && auto.timeoutMs == 2500,
            auto?.groups?.size.toString()
        )
        val limited = DpiStrategy.parse("--hosts list.txt --split 1 -p 1080 --md5sig --udp-fake 1")
        ok(
            "стратегия: ненужное телефону (--hosts, порт, --md5sig, --udp-fake) — пропущено с объяснением",
            limited.strategy != null && limited.error == null && limited.notes.size >= 4 &&
                limited.notes.any { it.contains("--md5sig") } && limited.notes.any { it.contains("--udp-fake") },
            limited.notes.joinToString(" | ")
        )
        val bad = listOf("--split", "--bogus 1", "split 1", "--split 1+x", "--ttl 300", "-s1:0", "--auto=whatever", "--tlsrec 70000", "")
        val badOut = bad.filter { DpiStrategy.parse(it).error == null }
        ok("стратегия: неизвестный ключ, кривая позиция, TTL 300, пустая строка — ошибка", badOut.isEmpty(), badOut.joinToString(" ; "))
        val pos = mapOf(
            "1+s" to "1+s", "0+sm" to "0+sm", "1:3:5" to "1:3:5", "-1" to "-1", "0x10" to "16", "+s" to "0+s", "2+se" to "2+se",
            "010" to "8", "5+n" to "5", "3+ne" to "3+ne"
        )
        val posBad = pos.filter { (src, want) ->
            DpiStrategy.parse("--split $src").strategy?.groups?.firstOrNull()?.parts?.firstOrNull()?.pos?.toString() != want
        }
        ok("стратегия: позиции ByeDPI — 1+s, 0+sm, 1:3:5, -1, 0x10, 010 (восьмеричное), +s", posBad.isEmpty(), posBad.keys.joinToString())
        val builtinsOk = DpiTrick.BUILTIN.all { !it.strategy.isPlain && it.strategy.notes.isEmpty() }
        ok("стратегия: все встроенные приёмы разбираются без пропусков", builtinsOk, DpiTrick.BUILTIN.joinToString { "${it.id}=${it.strategy.isPlain}" })
        val custom = DpiTrick.custom("  --fake -1   --ttl 6 ")
        ok(
            "стратегия: своя — из строки; пустая и «ничего не делающая» — не своя",
            custom != null && custom.isCustom && custom.needsFake && custom.byedpi == "--fake -1 --ttl 6" &&
                DpiTrick.custom("") == null && DpiTrick.custom("--hosts x.txt") == null && DpiTrick.custom("--bogus") == null
        )
        ok(
            "стратегия: склеенные короткие ключи «-Sd1» = «-S -d 1»",
            DpiStrategy.parse("-Sd1").strategy?.groups?.firstOrNull()?.parts?.singleOrNull()?.mode == DpiStrategy.Mode.DISORDER
        )
    }

    // ------------------------------------------------------------------------------- куски

    private fun desyncChecks() {
        val hello = clientHello("www.youtube.com")
        val sni = TlsHello.findSni(hello)!!
        val rnd = Random(77)
        var mismatch = 0
        val bad = ArrayList<String>()
        for (t in DpiTrick.BUILTIN) {
            val g = t.strategy.groups.first()
            val p = DpiDesync.plan(hello, g, rnd)
            val joined = TlsHello.joined(p.pieces)
            val expectedSize = hello.size + 5 * (if (g.tlsrec.isEmpty()) 0 else g.tlsrec.size)
            if (!joined.contentEquals(p.sent) || p.sent.size != expectedSize) {
                mismatch++
                bad += t.id
            }
        }
        ok("стратегия: у каждого встроенного приёма склейка кусков — ровно то, что получит сервер", mismatch == 0, bad.joinToString())

        val rep = DpiDesync.plan(hello, DpiStrategy.of("--split 1:3:5").groups[0], rnd).pieces.map { it.bytes.size }
        ok("стратегия: «--split 1:3:5» — разрезы на 1, 6 и 11 (как в README ByeDPI)", rep.take(3) == listOf(1, 5, 5), rep.toString())
        val dis = DpiDesync.plan(hello, DpiStrategy.of("--disorder 1:4:1").groups[0], rnd).pieces
        ok(
            "стратегия: повторы перестановки — TTL 1 у первого и третьего, обычный у второго и четвёртого (как desync.c)",
            dis.size == 5 && dis.take(4).map { it.lowTtl } == listOf(true, false, true, false) && !dis[4].lowTtl
        )
        val mid = DpiDesync.plan(hello, DpiStrategy.of("--split 0+sm").groups[0], rnd).pieces
        ok("стратегия: «0+sm» — разрез ровно в середине имени", mid.first().bytes.size == sni.offset + sni.length / 2, "${mid.first().bytes.size}")

        val rec2 = DpiDesync.plan(hello, DpiStrategy.of("--tlsrec 1+s --tlsrec 5+s").groups[0], rnd).sent
        val l1 = u16(rec2, 3)
        val h2 = 5 + l1
        val l2 = u16(rec2, h2 + 3)
        val h3 = h2 + 5 + l2
        val l3 = u16(rec2, h3 + 3)
        val body = hello.copyOfRange(5, TlsHello.recordEnd(hello))
        val joinedBody = rec2.copyOfRange(5, 5 + l1) + rec2.copyOfRange(h2 + 5, h2 + 5 + l2) + rec2.copyOfRange(h3 + 5, h3 + 5 + l3)
        ok(
            "стратегия: «--tlsrec 1+s --tlsrec 5+s» — три записи, тела склеиваются в исходное; разрезы на 1+s и 5+s",
            rec2.size == hello.size + 10 && joinedBody.contentEquals(body) && l1 == sni.offset + 1 - 5 && l2 == 4,
            "l1=$l1 l2=$l2 l3=$l3"
        )
        val rec3 = DpiDesync.plan(hello, DpiStrategy.of("--tlsrec 3").groups[0], rnd).sent
        ok("стратегия: «--tlsrec 3» без флага — от начала тела записи (как tamp у ByeDPI)", u16(rec3, 3) == 3, "первое тело ${u16(rec3, 3)}")
        val oob0 = DpiDesync.plan(hello, DpiStrategy.of("--oob 0").groups[0], rnd).pieces
        ok("стратегия: «--oob 0» — срочный байт самым первым", oob0.first().bytes.isEmpty() && oob0.first().oobAfter)
        val minor = DpiDesync.plan(hello, DpiStrategy.of("--tlsminor 1 --split 1").groups[0], rnd).sent
        ok("стратегия: «--tlsminor 1» — третий байт записи", minor[2] == 1.toByte() && minor.size == hello.size)

        // Случайные стратегии на случайных «приветствиях» — без исключений, склейка сходится.
        val r = Random(4242)
        val modes = listOf("--split", "--disorder", "--oob", "--disoob", "--fake", "--tlsrec")
        val posv = listOf("1", "1+s", "3+s", "-1", "0+sm", "2:3:2", "+se", "5", "-10", "0+sr", "1+h", "0+nm")
        var thrown = 0
        var wrong = 0
        repeat(1500) { i ->
            val args = (0 until 1 + r.nextInt(5)).joinToString(" ") { modes[r.nextInt(modes.size)] + " " + posv[r.nextInt(posv.size)] } +
                (if (r.nextBoolean()) " --tlsminor 2" else "")
            val st = DpiStrategy.parse(args).strategy ?: return@repeat
            val h = if (i % 3 == 0) hello else ByteArray(1 + r.nextInt(700)).also { b ->
                r.nextBytes(b)
                if (i % 2 == 0 && b.size > 6) { b[0] = 0x16; b[1] = 3; b[2] = 1; b[5] = 1 }
            }
            try {
                val p = DpiDesync.plan(h, st.groups[0], r)
                if (!TlsHello.joined(p.pieces).contentEquals(p.sent)) wrong++
            } catch (e: Exception) {
                thrown++
            }
        }
        ok("стратегия: 1500 случайных стратегий на случайных приветствиях — без исключений, склейка сходится", thrown == 0 && wrong == 0, "исключений $thrown, расхождений $wrong")
    }

    // ------------------------------------------------------------------------------- фейк

    /** ServerHello: TLS 1.3 (supported_versions) или 1.2, с эхом [sid]. */
    private fun serverHello(sid: ByteArray, tls13: Boolean): ByteArray {
        val ext = ByteArrayOutputStream()
        if (tls13) {
            ext.write(byteArrayOf(0x00, 0x2b, 0x00, 0x02, 0x03, 0x04))
            ext.write(byteArrayOf(0x00, 0x33, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20))
            ext.write(ByteArray(32) { 7 })
        } else {
            ext.write(byteArrayOf(0xff.toByte(), 0x01, 0x00, 0x01, 0x00))
        }
        val e = ext.toByteArray()
        val hs = ByteArrayOutputStream()
        hs.write(byteArrayOf(0x03, 0x03))
        hs.write(ByteArray(32) { 9 })
        hs.write(sid.size)
        hs.write(sid)
        hs.write(byteArrayOf(0x13, 0x01, 0x00))
        hs.write(e.size ushr 8); hs.write(e.size and 0xFF)
        hs.write(e)
        val body = hs.toByteArray()
        val msg = byteArrayOf(0x02, 0x00, (body.size ushr 8).toByte(), body.size.toByte()) + body
        return byteArrayOf(0x16, 0x03, 0x03, (msg.size ushr 8).toByte(), msg.size.toByte()) + msg
    }

    private fun fakeChecks() {
        val hello = clientHello("www.youtube.com")
        val sni = TlsHello.findSni(hello)!!
        val p = DpiDesync.plan(hello, DpiStrategy.of("--fake -1 --ttl 5").groups[0], Random(5))
        val first = p.pieces.first()
        val fake = first.fake
        val decoyName = fake?.let { TlsHello.findSni(it + hello.copyOfRange(it.size, hello.size))?.name }
        ok(
            "фейк: «--fake -1» — подделка до последнего байта с TTL 5, настоящий последний байт отдельно",
            p.pieces.size == 2 && fake != null && fake.size == hello.size - 1 && first.fakeTtl == 5 &&
                first.bytes.contentEquals(hello.copyOf(hello.size - 1)) && p.pieces[1].bytes.size == 1 && p.pieces[1].fake == null
        )
        ok(
            "фейк: в подделке другое имя той же длины — фильтр видит чужой сайт, разметка та же",
            decoyName != null && decoyName != sni.name && decoyName.length == sni.length && fake != null &&
                !String(fake, Charsets.ISO_8859_1).contains("youtube") && u16(fake, 3) == u16(hello, 3),
            "имя в фейке: $decoyName"
        )
        ok(
            "фейк: random и session_id подделки — свои, не как у настоящего",
            fake != null && !fake.copyOfRange(11, 43).contentEquals(hello.copyOfRange(11, 43)) &&
                !fake.copyOfRange(44, 76).contentEquals(hello.copyOfRange(44, 76))
        )
        val names = (5..40).map { DpiDesync.decoyName(it, rnd = Random(it.toLong())) }
        ok(
            "фейк: имя-подмена любой длины — ровно той длины, латиница и точки, без пустых меток",
            names.withIndex().all { (i, n) -> n.length == i + 5 && n.all { it in 'a'..'z' || it in '0'..'9' || it == '.' } && !n.contains("..") && !n.startsWith(".") },
            names.joinToString()
        )
        val user = DpiDesync.decoyName(15, listOf("www.??????.com"), Random(1))
        ok("фейк: --fake-sni с «?» — свои буквы, длина подгоняется", user.length == 15 && user.endsWith(".com") && !user.contains('?'), user)
        val sid = hello.copyOfRange(44, 44 + (hello[43].toInt() and 0xFF))
        val other = ByteArray(sid.size) { (it * 3 + 1).toByte() }
        ok(
            "фейк: сервер ответил на наше приветствие (session_id тот же) — всё в порядке",
            !DpiDesync.sidMismatch(hello, serverHello(sid, true))
        )
        ok(
            "фейк: TLS 1.3 с чужим session_id — до сервера дошёл фейк (как ssl_err у ByeDPI)",
            DpiDesync.sidMismatch(hello, serverHello(other, true))
        )
        ok(
            "фейк: TLS 1.2 и обрывок ответа так не проверить — не считаем неудачей",
            !DpiDesync.sidMismatch(hello, serverHello(other, false)) && !DpiDesync.sidMismatch(hello, serverHello(other, true).copyOf(40))
        )
    }

    // -------------------------------------------------------------------- отправка с фейком

    private fun senderChecks() {
        val hello = clientHello("dpi.test")
        val server = ServerSocket(0, 5, InetAddress.getByName("127.0.0.1"))
        try {
            val got = ByteArrayOutputStream()
            val reader = Thread {
                runCatching {
                    server.accept().use { c ->
                        c.soTimeout = 3000
                        val buf = ByteArray(4096)
                        while (got.size() < hello.size) {
                            val n = c.getInputStream().read(buf)
                            if (n < 0) break
                            synchronized(got) { got.write(buf, 0, n) }
                        }
                    }
                }
            }.apply { isDaemon = true; start() }
            val calls = ArrayList<String>()
            // «Ядро» в проверке: фейк до сервера не дошёл — пришло настоящее (так и будет при верном TTL).
            val fakeSender = object : FakeSender {
                override fun send(socket: Socket, fake: ByteArray, real: ByteArray, ttl: Int, normalTtl: Int) {
                    calls += "fake ${fake.size}/${real.size} ttl=$ttl normal=$normalTtl differs=${!fake.contentEquals(real)}"
                    socket.getOutputStream().write(real)
                    socket.getOutputStream().flush()
                }
            }
            val ttl = object : DpiProbe.SocketTtl {
                override fun get(socket: Socket): Int? = null
                override fun set(socket: Socket, ttl: Int): Boolean = true
            }
            Socket().use { s ->
                s.connect(InetSocketAddress(InetAddress.getByName("127.0.0.1"), server.localPort), 2000)
                TrickSender.send(s, hello, DpiTrick.FAKE5, ttl, fakeSender)
                reader.join(3000)
            }
            ok(
                "фейк: отправка — подделка той же длины с TTL 5, обычный TTL 64 после; сервер получил настоящее приветствие",
                calls.size == 1 && calls[0] == "fake ${hello.size - 1}/${hello.size - 1} ttl=5 normal=64 differs=true" &&
                    synchronized(got) { got.toByteArray() }.contentEquals(hello),
                calls.joinToString() + " получено ${got.size()} из ${hello.size}"
            )
            val noFake = runCatching {
                Socket().use { s ->
                    s.connect(InetSocketAddress(InetAddress.getByName("127.0.0.1"), server.localPort), 2000)
                    TrickSender.send(s, hello, DpiTrick.FAKE5, ttl, null)
                }
            }.exceptionOrNull()
            ok("фейк: без поддержки фейка — «не поддерживается», а не тихая отправка как есть", noFake is TrickSender.Unsupported, "$noFake")
        } finally {
            runCatching { server.close() }
        }
    }

    // --------------------------------------------------------------------------------- план

    private fun att(trick: DpiTrick, ok: Boolean) =
        DpiAttempt(trick, ok, if (ok) DpiStage.DONE else DpiStage.HELLO, if (ok) "" else "тишина после приветствия TLS (4 с)", status = if (ok) 200 else 0)

    private fun res(id: String, verdict: DpiVerdict, helpers: List<DpiTrick> = emptyList(), control: Boolean = false) =
        DpiTargetResult(
            DpiTargets.DEFAULT.firstOrNull { it.id == id } ?: DpiTarget(id, id, "$id.example", control = control),
            "1.2.3.4", "", listOf(att(DpiTrick.PLAIN, verdict == DpiVerdict.OPEN)), verdict, helpers
        )

    private fun planChecks() {
        // Журнал 26.11 10:53 (beta3, Tele2): страница и редиректор — ничем, узел видео не узнать,
        // картинки — перестановкой и OOB, Discord и X — только OOB.
        val evening = DpiReport(
            0, "мобильная · t2",
            listOf(
                res("youtube", DpiVerdict.DPI),
                res(DpiTargets.VIDEO_ID, DpiVerdict.DNS),
                res("googlevideo", DpiVerdict.DPI),
                res("ytimg", DpiVerdict.BYPASS, listOf(DpiTrick.DISORDER, DpiTrick.DISORDER_TLSREC, DpiTrick.OOB)),
                res("discord", DpiVerdict.BYPASS, listOf(DpiTrick.OOB)),
                res("instagram", DpiVerdict.IP),
                res("x", DpiVerdict.BYPASS, listOf(DpiTrick.OOB)),
                res("cloudflare", DpiVerdict.OPEN),
                res("google", DpiVerdict.OPEN, control = true)
            ),
            46_000, true
        )
        val plan = DpiPlan.of(evening)
        ok(
            "обход DPI: Tele2 10:53 — страница и видео YouTube через туннель, картинки отдельно, X и Discord — OOB",
            plan.trickFor("youtube") == null && plan.trickFor("ytvideo") == null && plan.trickFor("ytimg") == DpiTrick.DISORDER &&
                plan.trickFor("x") == DpiTrick.OOB && plan.trickFor("discord") == DpiTrick.OOB,
            plan.encode()
        )
        ok(
            "обход DPI: ради одних картинок приложение YouTube не разбирается (QUIC ему не закрывается), X и Discord — да",
            !plan.coversService("youtube") && plan.coversService("x") && plan.coversService("discord")
        )
        val videoOnly = DpiReport(
            0, "Wi-Fi",
            listOf(
                res("youtube", DpiVerdict.OPEN), res(DpiTargets.VIDEO_ID, DpiVerdict.BYPASS, listOf(DpiTrick.FAKE5)),
                res("googlevideo", DpiVerdict.DPI), res("google", DpiVerdict.OPEN, control = true)
            ),
            1000, true
        )
        ok(
            "обход DPI: у видео решает настоящий узел, а не редиректор (его приложение почти не трогает)",
            DpiPlan.of(videoOnly).trickFor("ytvideo") == DpiTrick.FAKE5 && DpiPlan.of(videoOnly).coversService("youtube"),
            DpiPlan.of(videoOnly).encode()
        )
        val custom = DpiTrick.custom("--split 1+s --disorder 3+s")
        val eff = DpiPlan.effective(plan, DpiPlan.AUTO, mapOf("youtube" to "fake5", "discord" to DpiPlan.OFF), custom)
        ok(
            "обход DPI: выбор человека поверх проверки — YouTube «фейк (TTL 5)» целиком, Discord не обходить, X по проверке",
            eff.trickFor("youtube") == DpiTrick.FAKE5 && eff.trickFor("ytvideo") == DpiTrick.FAKE5 && eff.trickFor("ytimg") == DpiTrick.FAKE5 &&
                eff.trickFor("x") == DpiTrick.OOB && eff.trickFor("discord") == null,
            eff.encode()
        )
        val all = DpiPlan.effective(DpiPlan.EMPTY, "custom", emptyMap(), custom)
        val noCustom = DpiPlan.effective(DpiPlan.EMPTY, "custom", emptyMap(), null)
        val off = DpiPlan.effective(plan, DpiPlan.OFF, mapOf("x" to "auto"), custom)
        ok(
            "обход DPI: общая «своя» — для всех групп; своей нет — ничего; общая «не обходить», но X «по проверке» — только X",
            DpiFamilies.ALL.all { all.trickFor(it.id) == custom } && noCustom.isEmpty && off.tricks.keys == setOf("x"),
            "${all.encode()} / ${off.encode()}"
        )
        val old = listOf("мобильная·25020\tyoutube=disorder,x=oob")
        val fresh = listOf(DpiPlan.entry("мобильная·25020", plan))
        ok(
            "обход DPI: план beta3 (подобран по картинкам) не применяется — нужна новая проверка; план beta4 читается",
            DpiPlan.forNetwork(old, "мобильная·25020").isEmpty && DpiPlan.forNetwork(fresh, "мобильная·25020") == plan &&
                fresh[0].contains("\tv2:"),
            fresh[0]
        )
        val withCustom = DpiPlan(mapOf("x" to custom!!))
        ok(
            "обход DPI: в плане своя стратегия хранится как «custom» и берётся из настроек",
            DpiPlan.decode(withCustom.encode(), custom = custom) == withCustom && DpiPlan.decode(withCustom.encode()).isEmpty &&
                withCustom.describe().contains("«своя» (--split 1+s --disorder 3+s)"),
            withCustom.describe()
        )
        val st = dev.warpscout.core.state.ServiceSettings(dpiStrategy = "oob", dpiOverrides = listOf("youtube=fake5"), dpiCustom = "-s1+s")
        val back = dev.warpscout.core.state.ServiceSettings.fromJson(st.toJson())
        val older = dev.warpscout.core.state.ServiceSettings.fromJson("{\"ver\":1,\"dpiBypass\":true}")
        ok(
            "обход DPI: общая стратегия, выбор сервисов и своя строка доходят до сервиса; снимок beta3 — «по проверке»",
            back?.dpiStrategy == "oob" && back.dpiOverrides == listOf("youtube=fake5") && back.dpiCustom == "-s1+s" &&
                older?.dpiStrategy == "auto" && older.dpiOverrides.isEmpty() && older.dpiCustom.isEmpty()
        )
        ok(
            "обход DPI: выбор словами — «по проверке сети», «не обходить», «фейк (TTL 5)», своя",
            DpiPlan.describeChoice("auto", null) == "по проверке сети" && DpiPlan.describeChoice("off", null) == "не обходить" &&
                DpiPlan.describeChoice("fake5", null) == "«фейк (TTL 5)»" && DpiPlan.describeChoice("custom", custom).startsWith("своя (") &&
                DpiPlan.parseOverrides(listOf("youtube=oob", "x=", "=oob", "discord=off")) == mapOf("youtube" to "oob", "discord" to "off")
        )
    }
}
