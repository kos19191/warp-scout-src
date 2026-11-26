package dev.warpscout.core.test

import dev.warpscout.core.dpi.DpiAttempt
import dev.warpscout.core.dpi.DpiProbe
import dev.warpscout.core.dpi.DpiReport
import dev.warpscout.core.dpi.DpiStage
import dev.warpscout.core.dpi.DpiTarget
import dev.warpscout.core.dpi.DpiTargetResult
import dev.warpscout.core.dpi.DpiTrick
import dev.warpscout.core.dpi.DpiVerdict
import dev.warpscout.core.dpi.TlsHello
import java.io.ByteArrayInputStream
import java.io.InputStream
import java.io.OutputStream
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.nio.ByteBuffer
import java.security.KeyStore
import java.util.Base64
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLServerSocket
import javax.net.ssl.TrustManagerFactory

/**
 * Самопроверка «режут DPI или адрес» (1.10.49-beta2) — целиком без интернета.
 *
 *  • ClientHello — настоящий, от Java: в нём ищется имя сайта, он режется и делится на две записи;
 *  • итоги — по придуманным попыткам, включая случай из песочницы (2,7 против 7,8 Мбит/с — разброс,
 *    а не «замедляют»);
 *  • свой сервер TLS на 127.0.0.1 с сертификатом для dpi.test: каждый приём должен собираться
 *    сервером в обычное соединение, данные — читаться, обрыв после 20 КБ — называться обрывом;
 *  • «эмулятор DPI» перед сервером: рвёт соединение (RST), если видит имя сайта целиком в первом
 *    пакете. Как есть — сброс, с приёмами — открывается: итог «режет DPI, обход поможет».
 */
class DpiChecks(private val check: (String, Boolean, String) -> Unit) {

    private fun ok(name: String, condition: Boolean, detail: String = "") = check(name, condition, detail)

    fun run() {
        helloChecks()
        verdictChecks()
        dnsChecks()
        localServerChecks()
    }

    private fun u16(b: ByteArray, i: Int): Int = ((b[i].toInt() and 0xFF) shl 8) or (b[i + 1].toInt() and 0xFF)

    /** Первый пакет клиента TLS — каким его шлёт Java (SunJSSE), с именем [host]. */
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

    private fun helloChecks() {
        val hello = clientHello("www.youtube.com")
        val sni = TlsHello.findSni(hello)
        ok("DPI: имя сайта найдено в ClientHello", sni?.name == "www.youtube.com", "найдено: ${sni?.name}")
        ok(
            "DPI: смещение имени указывает ровно на байты имени",
            sni != null && String(hello, sni.offset, sni.length, Charsets.US_ASCII) == "www.youtube.com"
        )
        val cut = TlsHello.cutPos(hello)
        ok("DPI: разрез — первый байт имени плюс один (1+s, как у ByeDPI)", sni != null && cut == sni.offset + 1, "разрез $cut")

        val two = TlsHello.splitRecord(hello, cut)
        val len1 = u16(two, 3)
        val h2 = 5 + len1
        val len2 = u16(two, h2 + 3)
        val body = hello.copyOfRange(5, TlsHello.recordEnd(hello))
        val joinedBody = two.copyOfRange(5, 5 + len1) + two.copyOfRange(h2 + 5, h2 + 5 + len2)
        ok(
            "DPI: две записи — оба заголовка handshake той же версии",
            two[0] == 0x16.toByte() && two[h2] == 0x16.toByte() && two[1] == hello[1] && two[h2 + 2] == hello[2]
        )
        ok("DPI: две записи — тела склеиваются в исходное сообщение", joinedBody.contentEquals(body))
        ok("DPI: две записи — длиннее ровно на заголовок (5 байт)", two.size == hello.size + 5)
        ok(
            "DPI: две записи — имя сайта разорвано заголовком второй записи",
            !String(two, Charsets.ISO_8859_1).contains("www.youtube.com") && TlsHello.findSni(two) == null
        )

        for (t in DpiTrick.entries) {
            val expected = if (t == DpiTrick.TLSREC || t == DpiTrick.DISORDER_TLSREC) two else hello
            ok(
                "DPI: приём «${t.title}» — сервер получает " + (if (expected === two) "две записи" else "исходный ClientHello"),
                TlsHello.joined(TlsHello.plan(t, hello)).contentEquals(expected)
            )
        }
        val split = TlsHello.plan(DpiTrick.SPLIT, hello)
        ok(
            "DPI: разрез — два куска, первый кончается на первой букве имени",
            split.size == 2 && split[0].bytes.size == cut && !String(split[0].bytes, Charsets.ISO_8859_1).contains("ww.youtube")
        )
        val dis = TlsHello.plan(DpiTrick.DISORDER, hello)
        ok(
            "DPI: перестановка — первый байт с TTL 1, остальное обычным",
            dis.size == 2 && dis[0].bytes.size == 1 && dis[0].lowTtl && !dis[1].lowTtl
        )
        val oob = TlsHello.plan(DpiTrick.OOB, hello)
        ok(
            "DPI: OOB — срочный байт сразу за куском с первой буквой имени",
            oob.size == 2 && oob[0].oobAfter && !oob[1].oobAfter && oob[0].bytes.size == cut
        )

        // Мусор, обрезанное и случайное — без имени и без исключений.
        val rnd = java.util.Random(4919)
        var thrown = 0
        var found = 0
        repeat(3000) { i ->
            val n = 1 + rnd.nextInt(600)
            val b = ByteArray(n).also { rnd.nextBytes(it) }
            if (i % 2 == 0 && n > 6) { b[0] = 0x16; b[1] = 3; b[2] = 1; b[5] = 1 }
            try {
                if (TlsHello.findSni(b) != null) found++
                TlsHello.plan(DpiTrick.entries[i % DpiTrick.entries.size], b)
            } catch (e: Exception) {
                thrown++
            }
        }
        ok("DPI: 3000 случайных «приветствий» — разбор и приёмы без исключений", thrown == 0, "исключений: $thrown")
        ok(
            "DPI: обрезанный ClientHello и пустой массив — имени нет",
            TlsHello.findSni(hello.copyOf(60)) == null && TlsHello.findSni(ByteArray(0)) == null &&
                TlsHello.findSni(hello.copyOf(sni?.offset?.plus(3) ?: 0)) == null
        )
    }

    private fun att(
        trick: DpiTrick, ok: Boolean, stage: DpiStage = if (ok) DpiStage.DONE else DpiStage.HELLO,
        kbps: Int = -1, stalled: Boolean = false, status: Int = if (ok) 200 else 0, bytes: Long = 0
    ) = DpiAttempt(trick, ok, stage, if (ok) "" else if (stage == DpiStage.CONNECT) "нет ответа на подключение (4 с)" else "сброс после приветствия TLS",
        bytesIn = bytes, status = status, kbps = kbps, stalled = stalled)

    private fun verdictChecks() {
        val t = DpiTarget("t", "Сайт", "t.example")
        val ts = DpiTarget("s", "YouTube", "s.example", speed = true)
        fun v(target: DpiTarget, vararg a: DpiAttempt) = DpiProbe.classify(target, a.toList())

        ok("DPI: итог — открылся как есть", v(t, att(DpiTrick.PLAIN, true)).first == DpiVerdict.OPEN)
        ok("DPI: итог — не подключился — блокировка по адресу", v(t, att(DpiTrick.PLAIN, false, DpiStage.CONNECT)).first == DpiVerdict.IP)
        val byp = v(t, att(DpiTrick.PLAIN, false), att(DpiTrick.SPLIT, true), att(DpiTrick.TLSREC, false), att(DpiTrick.OOB, true))
        ok(
            "DPI: итог — как есть сброс, с разрезом и OOB открылся — режет DPI, помогают разрез и OOB",
            byp.first == DpiVerdict.BYPASS && byp.second == listOf(DpiTrick.SPLIT, DpiTrick.OOB), "$byp"
        )
        ok(
            "DPI: итог — сброс и ни один приём не помог — «приёмы не помогают»",
            v(t, att(DpiTrick.PLAIN, false), att(DpiTrick.SPLIT, false), att(DpiTrick.TLSREC, false)).first == DpiVerdict.DPI
        )
        ok(
            "DPI: итог — данные встали после ~16 КБ и с приёмами тоже — «встаёт», а не «режет DPI»",
            v(
                t, att(DpiTrick.PLAIN, false, DpiStage.DATA, stalled = true, status = 200, bytes = 17_000),
                att(DpiTrick.SPLIT, false, DpiStage.DATA, stalled = true, status = 200)
            ).first == DpiVerdict.STALL
        )
        val slow = v(ts, att(DpiTrick.PLAIN, true, kbps = 300), att(DpiTrick.SPLIT, true, kbps = 4000), att(DpiTrick.OOB, true, kbps = 600))
        ok(
            "DPI: итог — YouTube 300 кбит/с как есть и 4 Мбит/с с разрезом — замедляют по имени",
            slow.first == DpiVerdict.FASTER && slow.second == listOf(DpiTrick.SPLIT), "$slow"
        )
        ok(
            "DPI: итог — 2,7 против 7,8 Мбит/с — разброс между соединениями, не «замедляют» (песочница)",
            v(ts, att(DpiTrick.PLAIN, true, kbps = 2700), att(DpiTrick.OOB, true, kbps = 7800)).first == DpiVerdict.OPEN
        )
        ok(
            "DPI: итог — выигрыш меньше втрое — не «замедляют»",
            v(ts, att(DpiTrick.PLAIN, true, kbps = 600), att(DpiTrick.SPLIT, true, kbps = 1700)).first == DpiVerdict.OPEN
        )

        fun res(id: String, name: String, verdict: DpiVerdict, helpers: List<DpiTrick> = emptyList(), control: Boolean = false) =
            DpiTargetResult(DpiTarget(id, name, "$id.example", control = control), "1.2.3.4", "", listOf(att(DpiTrick.PLAIN, verdict == DpiVerdict.OPEN)), verdict, helpers)
        val good = DpiReport(
            0, "Wi-Fi·192.168.1.1",
            listOf(
                res("yt", "YouTube", DpiVerdict.BYPASS, listOf(DpiTrick.SPLIT, DpiTrick.DISORDER)),
                res("dc", "Discord", DpiVerdict.BYPASS, listOf(DpiTrick.DISORDER)),
                res("ig", "Instagram", DpiVerdict.IP),
                res("g", "Google (контроль)", DpiVerdict.OPEN, control = true)
            ),
            30_000, true
        )
        ok("DPI: лучший приём — тот, что помог большему числу сайтов", good.bestTricks().firstOrNull()?.first == DpiTrick.DISORDER, "${good.bestTricks()}")
        val sum = good.summary()
        ok(
            "DPI: итог для экрана — что откроет обход и что только через VPN",
            sum.contains("Обход DPI поможет: YouTube, Discord") && sum.contains("По адресу (нужен VPN): Instagram") &&
                sum.contains("«перестановка»"), sum
        )
        ok(
            "DPI: в журнале — параметры для ByeDPI",
            good.journalLines().any { it.contains("для ByeDPI на этой сети — --disorder 1 (помог: 2)") }, good.journalLines().last()
        )
        val dead = DpiReport(0, "?", listOf(res("yt", "YouTube", DpiVerdict.DPI), res("g", "Google (контроль)", DpiVerdict.IP, control = true)), 1000, true)
        ok("DPI: контроль не открылся — итогу не верим и так и пишем", dead.summary().startsWith("Контрольный сайт не открылся"), dead.summary())
    }

    private fun dnsChecks() {
        val stub = DpiProbe(resolve = { listOf(InetAddress.getByName("0.0.0.0")) }).addressesOf("x.example")
        ok("DPI: DNS отдал 0.0.0.0 — это заглушка, а не адрес", stub.first.isEmpty() && stub.second.contains("заглушку 0.0.0.0"), stub.second)
        val fb = DpiProbe(
            resolve = { listOf(InetAddress.getByName("10.10.34.35")) },
            fallbackResolve = { listOf(InetAddress.getByName("93.184.215.14")) }
        ).addressesOf("x.example")
        ok(
            "DPI: заглушка DNS провайдера — адрес берётся у публичного DNS",
            fb.first.firstOrNull()?.hostAddress == "93.184.215.14" && fb.second.contains("публичного DNS"), fb.second
        )
        val order = DpiProbe(
            resolve = { listOf(InetAddress.getByName("2606:4700::1111"), InetAddress.getByName("104.16.1.1")) }
        ).addressesOf("x.example")
        ok("DPI: IPv4 раньше IPv6", order.first.firstOrNull()?.hostAddress == "104.16.1.1")
        val none = DpiProbe(resolve = { throw java.net.UnknownHostException("x") }).check(DpiTarget("x", "X", "x.example"))
        ok("DPI: имя не разрешилось — итог «адрес не узнать», без попыток", none.verdict == DpiVerdict.DNS && none.attempts.isEmpty())
        ok(
            "DPI: заглушки — 127.*, 10.*, 192.168.*, 0.0.0.0; обычный адрес — нет",
            listOf("127.0.0.1", "10.1.2.3", "192.168.1.1", "0.0.0.0").all { DpiProbe.bogus(InetAddress.getByName(it)) } &&
                !DpiProbe.bogus(InetAddress.getByName("142.250.74.14"))
        )
    }

    // ------------------------------------------------------------ свой сервер TLS и «эмулятор DPI»

    private class Server(val socket: ServerSocket, private val handler: (Socket) -> Unit) {
        init {
            Thread({
                while (!socket.isClosed) {
                    val c = runCatching { socket.accept() }.getOrNull() ?: break
                    Thread({ runCatching { handler(c) }; runCatching { c.close() } }, "dpi-test-conn").apply { isDaemon = true }.start()
                }
            }, "dpi-test-accept").apply { isDaemon = true }.start()
        }

        val port: Int get() = socket.localPort
        fun close() = runCatching { socket.close() }
    }

    private fun readLine(inp: InputStream): String? {
        val sb = StringBuilder()
        while (true) {
            val c = inp.read()
            if (c < 0) return if (sb.isEmpty()) null else sb.toString()
            if (c == '\n'.code) return sb.toString().trimEnd('\r')
            sb.append(c.toChar())
        }
    }

    /** Простой HTTPS-сервер: /ok — 70 000 байт, /chunked — частями без закрытия, /stall — 20 КБ и тишина. */
    private fun serveHttp(c: Socket) {
        c.soTimeout = 5000
        val inp = java.io.BufferedInputStream(c.getInputStream())
        val out = c.getOutputStream()
        val first = readLine(inp) ?: return
        while (true) {
            val l = readLine(inp) ?: break
            if (l.isEmpty()) break
        }
        when (first.split(' ').getOrNull(1)) {
            "/ok" -> {
                out.write("HTTP/1.1 200 OK\r\nContent-Length: 70000\r\nConnection: close\r\n\r\n".toByteArray())
                out.write(ByteArray(70_000) { (it % 251).toByte() })
                out.flush()
            }
            "/chunked" -> {
                out.write("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".toByteArray())
                repeat(3) {
                    out.write("1000\r\n".toByteArray())
                    out.write(ByteArray(4096))
                    out.write("\r\n".toByteArray())
                }
                out.write("0\r\n\r\n".toByteArray())
                out.flush()
                Thread.sleep(6000) // конец ответа — по последнему куску, а не по закрытию
            }
            "/stall" -> {
                out.write("HTTP/1.1 200 OK\r\nContent-Length: 100000\r\n\r\n".toByteArray())
                out.write(ByteArray(20_000))
                out.flush()
                Thread.sleep(3000)
            }
            else -> {
                out.write("HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".toByteArray())
                out.flush()
            }
        }
    }

    private fun pump(from: InputStream, to: OutputStream, onEnd: () -> Unit) {
        Thread({
            val buf = ByteArray(16384)
            try {
                while (true) {
                    val n = from.read(buf)
                    if (n < 0) break
                    to.write(buf, 0, n)
                    to.flush()
                }
            } catch (_: Exception) {
            } finally {
                onEnd()
            }
        }, "dpi-test-pump").apply { isDaemon = true }.start()
    }

    private fun localServerChecks() {
        val pass = PASSWORD.toCharArray()
        val ks = KeyStore.getInstance("PKCS12")
        ks.load(ByteArrayInputStream(Base64.getDecoder().decode(KEYSTORE)), pass)
        val kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm())
        kmf.init(ks, pass)
        val serverCtx = SSLContext.getInstance("TLS")
        serverCtx.init(kmf.keyManagers, null, null)
        val tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
        tmf.init(ks)
        val clientCtx = SSLContext.getInstance("TLS")
        clientCtx.init(null, tmf.trustManagers, null)
        val lo = InetAddress.getByName("127.0.0.1")

        val tls = Server(serverCtx.serverSocketFactory.createServerSocket(0, 50, lo) as SSLServerSocket) { serveHttp(it) }
        val calls = ArrayList<Int>()
        val fakeTtl = object : DpiProbe.SocketTtl {
            override fun get(socket: Socket): Int = 64
            override fun set(socket: Socket, ttl: Int): Boolean {
                synchronized(calls) { calls += ttl }
                return true
            }
        }
        fun probe(port: Int, ttl: DpiProbe.SocketTtl? = null, idleMs: Int = 1000) = DpiProbe(
            resolve = { listOf(lo) }, ttl = ttl, sslContext = clientCtx,
            connectTimeoutMs = 2000, helloTimeoutMs = 2000, idleTimeoutMs = idleMs, port = port, allowLocal = true
        )
        try {
            val p = probe(tls.port)
            val okT = DpiTarget("ok", "Тест", "dpi.test", "/ok")
            val plain = p.attempt(okT, lo, DpiTrick.PLAIN)
            ok(
                "DPI: свой сервер TLS — как есть: рукопожатие, сертификат dpi.test и 70 КБ ответа",
                plain.ok && plain.status == 200 && plain.bytesIn >= 70_000 && plain.stage == DpiStage.DONE, plain.toString()
            )
            for (t in listOf(DpiTrick.SPLIT, DpiTrick.TLSREC, DpiTrick.OOB)) {
                val a = p.attempt(okT, lo, t)
                ok("DPI: свой сервер TLS — «${t.title}» сервер собирает в обычное соединение", a.ok && a.status == 200, a.short())
            }
            val noTtl = p.attempt(okT, lo, DpiTrick.DISORDER)
            ok("DPI: перестановка без доступа к TTL — честно «не проверить»", noTtl.stage == DpiStage.SKIPPED && noTtl.reason.contains("TTL"), noTtl.short())
            val d = probe(tls.port, fakeTtl).attempt(okT, lo, DpiTrick.DISORDER)
            ok(
                "DPI: перестановка — первый кусок с TTL 1, затем TTL обратно 64",
                d.ok && synchronized(calls) { calls.toList() } == listOf(1, 64), "вызовы: $calls; ${d.short()}"
            )
            val wrongName = p.attempt(DpiTarget("bad", "Чужое имя", "other.test", "/ok"), lo, DpiTrick.PLAIN)
            ok(
                "DPI: сертификат на другое имя — «подмена?», а не «открылся»",
                !wrongName.ok && wrongName.reason.contains("сертификат"), wrongName.short()
            )
            // Сервер после последней части молчит 6 с, тишина у проверки — 4 с: не узнай она конец
            // ответа по части «0», попытка кончилась бы через 4 с «встало».
            val t0 = System.nanoTime()
            val chunked = probe(tls.port, idleMs = 4000).attempt(DpiTarget("ch", "Частями", "dpi.test", "/chunked"), lo, DpiTrick.PLAIN)
            val chunkedMs = (System.nanoTime() - t0) / 1_000_000
            ok(
                "DPI: ответ частями — конец по последней части, без ожидания тишины",
                chunked.ok && !chunked.stalled && chunkedMs < 3000, "${chunked.short()} · $chunkedMs мс"
            )
            val stall = p.attempt(DpiTarget("st", "Обрыв", "dpi.test", "/stall"), lo, DpiTrick.PLAIN)
            ok(
                "DPI: 20 КБ и тишина — «встало после N КБ», а не «открылся»",
                !stall.ok && stall.stalled && stall.reason.contains("встало после"), stall.short()
            )

            // Закрытый порт — «блокировка по адресу».
            val closed = ServerSocket(0, 1, lo).let { s -> val port = s.localPort; s.close(); port }
            val refused = probe(closed).check(DpiTarget("ip", "Закрытый порт", "dpi.test", "/ok"))
            ok(
                "DPI: подключение отвергнуто — блокировка по адресу, приёмы не пробуются",
                refused.verdict == DpiVerdict.IP && refused.attempts.size == 1, refused.journal()
            )

            // «Эмулятор DPI»: видит имя целиком в первом пакете — RST; иначе пропускает к серверу.
            val dpi = Server(ServerSocket(0, 50, lo)) { c ->
                c.soTimeout = 4000
                val buf = ByteArray(16384)
                val n = c.getInputStream().read(buf)
                if (n <= 0) return@Server
                val first = buf.copyOf(n)
                if (TlsHello.findSni(first)?.name == "dpi.test") {
                    c.setSoLinger(true, 0) // закрыть со сбросом — как ТСПУ
                    return@Server
                }
                val up = Socket(lo, tls.port)
                up.getOutputStream().write(first)
                val done = java.util.concurrent.CountDownLatch(2)
                pump(c.getInputStream(), up.getOutputStream()) { done.countDown(); runCatching { up.shutdownOutput() } }
                pump(up.getInputStream(), c.getOutputStream()) { done.countDown(); runCatching { c.shutdownOutput() } }
                done.await(6, java.util.concurrent.TimeUnit.SECONDS)
                runCatching { up.close() }
            }
            try {
                val res = probe(dpi.port, fakeTtl).check(DpiTarget("dpi", "За эмулятором DPI", "dpi.test", "/ok"))
                val pl = res.plain
                ok(
                    "DPI: эмулятор DPI — как есть сброс после приветствия",
                    pl != null && !pl.ok && pl.stage == DpiStage.HELLO && pl.reason.contains("сброс"), pl?.short() ?: "нет попытки"
                )
                ok(
                    "DPI: эмулятор DPI — с двумя записями TLS открывается, итог «режет DPI, обход поможет»",
                    res.verdict == DpiVerdict.BYPASS && DpiTrick.TLSREC in res.helpers, res.journal()
                )
            } finally {
                dpi.close()
            }
        } finally {
            tls.close()
        }
    }

    companion object {
        private const val PASSWORD = "dpitest"

        /**
         * PKCS12: самоподписанный EC-сертификат для dpi.test (SAN), действует с 2020 по 2074 год —
         * чтобы самопроверка не «протухла» и не зависела от часов сборочной машины. Сделан keytool:
         * -genkeypair -keyalg EC -groupname secp256r1 -ext SAN=dns:dpi.test -startdate 2020/01/01.
         */
        private val KEYSTORE: String =
            "MIID+gIBAzCCA6QGCSqGSIb3DQEHAaCCA5UEggORMIIDjTCCASQGCSqGSIb3DQEHAaCCARUEggERMIIBDTCCAQkGCyqGSIb3DQEM" +
            "CgECoIG9MIG6MGYGCSqGSIb3DQEFDTBZMDgGCSqGSIb3DQEFDDArBBSGJT+a5vzC8zXMTGIPMK836lsobgICJxACASAwDAYIKoZI" +
            "hvcNAgkFADAdBglghkgBZQMEASoEEHm7qZxrM6ztOKUfUyxrkAAEUAi6JG5pjyq2KnJX/ZZTFgC6ASQ0XQiLP7+93DPGv1JNm7Il" +
            "sJ1/jp92nxM3pn8UTSvxd2LBvpvD3QsW6nkQk0Q6xerMVNs5tYWRjNVS6Ui5MTowFQYJKoZIhvcNAQkUMQgeBgBkAHAAaTAhBgkq" +
            "hkiG9w0BCRUxFAQSVGltZSAxNzk1NjU1MzMwNDQzMIICYQYJKoZIhvcNAQcGoIICUjCCAk4CAQAwggJHBgkqhkiG9w0BBwEwZgYJ" +
            "KoZIhvcNAQUNMFkwOAYJKoZIhvcNAQUMMCsEFO2AAY0nz8aWp/c4vwn/vWy88XbyAgInEAIBIDAMBggqhkiG9w0CCQUAMB0GCWCG" +
            "SAFlAwQBKgQQwCDMxHeTWJNDr0/V9kKgtYCCAdCjaGfhYhURacWGvK3KL+AJi2YiwcH2bAxsZRpTSq1C8e/FRufPPN66qe5dzoDI" +
            "2CJAf2pBCoJ9U1ppNgMb9rVLeicMkTpFgcMoHSeSkl9hzUY4D1dg/PWWlXw+FoiIWbd7y3HdSLAVHqukEcgxy+1+ZJli/zN9MLnK" +
            "q3xH7nqrouhJ4GlrC2Ste3n0xiy2nV9crTlOfDgAwnvnrH2R/kErL+fUQBIdbRy/bHAwAETKEMNxQ/5JCdSPtorgSVBqhToSgEyX" +
            "dnqSmtlc05yUV4qR+1tJykR1xLsBrfG+DN/QgoF8u2fdXw5rlKh5BbgXC5ymbwbAvn0H2OEOjyXSp+dhnpAqOEQYBYDTPQFjrzMf" +
            "9/bIm5NsMCCHdbDXq0rzdBueUkNqVeAK9dFcxrKlyswyOUc0DZkgr6rmkZ30fQ18KdJl7lWKc1JSIAYd/Uun5zq4va03RWSNz98q" +
            "dLtjQF35xEPY59toPvrqk/yuADSxZyC78VcGQROXctfWcLwaBJidCeyiAaxPMeagU6xBXUgBMj/E4f6F7mCfjaUR0jUSwKJzit5S" +
            "SPiQE5HDvTt5JXxt3SONZU1rPLlO8DTLmTdKOHXpxnvY/Eu1PA9qA4I5mzBNMDEwDQYJYIZIAWUDBAIBBQAEIDTmOIumVD0CtilM" +
            "fl5p0/xL79T+Gpfz1k88ZhSiewqvBBSpRBVNtfuxOmCI/elLKh4wztuW3wICJxA="
    }
}
