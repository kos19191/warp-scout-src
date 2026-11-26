package dev.warpscout.core.test

import dev.warpscout.core.dpi.TlsHello
import dev.warpscout.core.telegram.MtProxy
import dev.warpscout.core.telegram.MtProxyChecker
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.Random

/**
 * Самопроверка прокси MTProto (1.10.49-beta4) — без интернета, против своего «MTProxy» на 127.0.0.1:
 * разбор ссылок и секретов, отбор кандидатов, приветствие Fake-TLS (517 байт, подпись секретом,
 * время), проверка до ответа «Telegram» (obfuscated2 + req_pq_multi → resPQ) для всех трёх видов
 * секрета; чужой ключ, молчащий прокси и закрытый порт — честно ниже.
 */
class MtProxyChecks(private val check: (String, Boolean, String) -> Unit) {

    private fun ok(name: String, condition: Boolean, detail: String = "") = check(name, condition, detail)

    fun run() {
        parseChecks()
        helloChecks()
        liveChecks()
    }

    private fun hex(b: ByteArray): String = b.joinToString("") { "%02x".format(it.toInt() and 0xFF) }

    private val key = ByteArray(16) { (it * 17 + 3).toByte() }

    private fun parseChecks() {
        val eeHex = "ee" + hex(key) + hex("www.google.com".toByteArray())
        val eeB64 = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(byteArrayOf(0xee.toByte()) + key + "ya.ru".toByteArray())
        val text = """
            # список
            tg://proxy?server=1.2.3.4&port=443&secret=$eeHex
            https://t.me/proxy?server=proxy.example.org&port=8443&secret=dd${hex(key)}
            https://t.me/proxy?server=5.6.7.8&port=2096&secret=${hex(key)}
            tg://proxy?server=9.9.9.9&port=443&secret=$eeB64
            tg://proxy?server=1.2.3.4&port=443&secret=$eeHex
            tg://proxy?server=bad host&port=443&secret=$eeHex
            tg://proxy?server=2.2.2.2&port=99999&secret=$eeHex
            tg://proxy?server=3.3.3.3&port=443&secret=zz
        """.trimIndent()
        val list = MtProxy.parse(text, "проверка")
        ok(
            "Telegram: ссылки tg:// и t.me из списка — 4 прокси, повтор и мусор отброшены",
            list.size == 4 && list.map { it.kind } == listOf(MtProxy.Kind.FAKE_TLS, MtProxy.Kind.PADDED, MtProxy.Kind.CLASSIC, MtProxy.Kind.FAKE_TLS),
            list.joinToString { "${it.id} ${it.kind}" }
        )
        ok(
            "Telegram: секрет Fake-TLS — домен и ключ (hex и base64url)",
            list[0].domain == "www.google.com" && list[3].domain == "ya.ru" && list[3].parsedSecret()?.key?.contentEquals(key) == true &&
                list[1].parsedSecret()?.key?.contentEquals(key) == true
        )
        ok(
            "Telegram: ссылка для кнопки «Добавить в Telegram» — tg://proxy с теми же полями",
            list[0].tgLink == "tg://proxy?server=1.2.3.4&port=443&secret=$eeHex" && list[0].tmeLink.startsWith("https://t.me/proxy?server=1.2.3.4&port=443&secret=")
        )
        val many = (1..10).map { i -> MtProxy.Entry("10.0.0.$i", 443, eeHex, MtProxy.Kind.FAKE_TLS, "www.google.com") } +
            (1..5).map { i -> MtProxy.Entry("s$i.same.example", 443, eeHex, MtProxy.Kind.FAKE_TLS) } +
            listOf(MtProxy.Entry("11.0.0.1", 443, hex(key), MtProxy.Kind.CLASSIC), MtProxy.Entry("12.0.0.1", 8888, eeHex, MtProxy.Kind.FAKE_TLS))
        val cands = MtProxy.candidates(many, limit = 10)
        ok(
            "Telegram: кандидаты — не больше двух с одной подсети и домена, Fake-TLS вперёд",
            cands.count { it.server.startsWith("10.0.0.") } == 2 && cands.count { it.server.endsWith("same.example") } == 2 &&
                cands.last().kind == MtProxy.Kind.CLASSIC && cands.size == 6,
            cands.joinToString { it.id }
        )
    }

    private fun helloChecks() {
        val now = 1_764_000_000_000L
        val c = MtProxyChecker({ _, _, _ -> throw IllegalStateException() }, clock = { now }, rnd = Random(1))
        val hello = c.clientHello("www.google.com", key)
        val sni = TlsHello.findSni(hello)
        ok("Telegram: приветствие Fake-TLS — 517 байт, имя — домен секрета", hello.size == 517 && sni?.name == "www.google.com", "${hello.size} ${sni?.name}")
        val random = hello.copyOfRange(11, 43)
        val zero = hello.copyOf().also { for (i in 11 until 43) it[i] = 0 }
        val d = MtProxyChecker.hmac(key, zero)
        val ts = ByteBuffer.wrap(ByteArray(4) { i -> (d[28 + i].toInt() xor random[28 + i].toInt()).toByte() }).order(ByteOrder.LITTLE_ENDIAN).int
        ok(
            "Telegram: random приветствия — HMAC-SHA256 секретом, в последних 4 байтах — время (как у tdlib)",
            random.copyOf(28).contentEquals(d.copyOf(28)) && ts.toLong() == now / 1000, "время $ts"
        )
        val other = MtProxyChecker.hmac(ByteArray(16), zero)
        ok("Telegram: чужой ключ подпись не сходится", !random.copyOf(28).contentEquals(other.copyOf(28)))
    }

    // ------------------------------------------------------------------ свой MTProxy для проверки

    /** «MTProxy» на 127.0.0.1: Fake-TLS по tdlib, obfuscated2 по документации Telegram, на req_pq — resPQ. */
    private class FakeProxy(
        val key: ByteArray,
        val tls: Boolean,
        val signKey: ByteArray = key,
        val answer: Boolean = true
    ) {
        val socket = ServerSocket(0, 10, InetAddress.getByName("127.0.0.1"))
        @Volatile var seenDc = -1
        @Volatile var seenTag = 0
        @Volatile var error = ""

        init {
            Thread({
                while (!socket.isClosed) {
                    val c = runCatching { socket.accept() }.getOrNull() ?: break
                    Thread({ runCatching { handle(c) }.onFailure { error = it.toString() }; runCatching { c.close() } }, "mtproxy-test").apply { isDaemon = true }.start()
                }
            }, "mtproxy-test-accept").apply { isDaemon = true }.start()
        }

        val port: Int get() = socket.localPort
        fun close() = runCatching { socket.close() }

        private fun u16(b: ByteArray, i: Int) = ((b[i].toInt() and 0xFF) shl 8) or (b[i + 1].toInt() and 0xFF)

        private fun handle(c: Socket) {
            c.soTimeout = 5000
            val inp = c.getInputStream()
            val out = c.getOutputStream()
            var stream: (Int) -> ByteArray = { n -> MtProxyChecker.readFully(inp, n) }
            if (tls) {
                val h = MtProxyChecker.readFully(inp, 5)
                val hello = h + MtProxyChecker.readFully(inp, u16(h, 3))
                val random = hello.copyOfRange(11, 43)
                val zero = hello.copyOf().also { for (i in 11 until 43) it[i] = 0 }
                val d = MtProxyChecker.hmac(key, zero)
                if (!random.copyOf(28).contentEquals(d.copyOf(28))) {
                    error = "подпись приветствия не сошлась"
                    return
                }
                val sidLen = hello[43].toInt() and 0xFF
                val sid = hello.copyOfRange(44, 44 + sidLen)
                val ext = byteArrayOf(0x00, 0x2b, 0x00, 0x02, 0x03, 0x04, 0x00, 0x33, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20) + ByteArray(32) { 5 }
                val body = byteArrayOf(0x03, 0x03) + ByteArray(32) + byteArrayOf(sidLen.toByte()) + sid +
                    byteArrayOf(0x13, 0x01, 0x00, (ext.size ushr 8).toByte(), ext.size.toByte()) + ext
                val msg = byteArrayOf(0x02, 0x00, (body.size ushr 8).toByte(), body.size.toByte()) + body
                val filler = ByteArray(77) { (it * 7).toByte() }
                val resp = byteArrayOf(0x16, 0x03, 0x03, (msg.size ushr 8).toByte(), msg.size.toByte()) + msg +
                    MtProxyChecker.CCS + byteArrayOf(0x17, 0x03, 0x03, 0x00, filler.size.toByte()) + filler
                val sign = MtProxyChecker.hmac(signKey, random + resp)
                System.arraycopy(sign, 0, resp, 11, 32)
                out.write(resp)
                out.flush()
                var pending = ByteArray(0)
                stream = { n ->
                    while (pending.size < n) {
                        val rh = MtProxyChecker.readFully(inp, 5)
                        val rb = MtProxyChecker.readFully(inp, u16(rh, 3))
                        if ((rh[0].toInt() and 0xFF) == 0x17) pending += rb
                    }
                    pending.copyOf(n).also { pending = pending.copyOfRange(n, pending.size) }
                }
            }
            val init = stream(64)
            val rev = init.reversedArray()
            val dec = MtProxyChecker.Obfs.ctr(MtProxyChecker.Obfs.sha256(init.copyOfRange(8, 40) + key), init.copyOfRange(40, 56))
            val enc = MtProxyChecker.Obfs.ctr(MtProxyChecker.Obfs.sha256(rev.copyOfRange(8, 40) + key), rev.copyOfRange(40, 56))
            val plain = ByteBuffer.wrap(dec.update(init)).order(ByteOrder.LITTLE_ENDIAN)
            seenTag = plain.getInt(56)
            seenDc = plain.getShort(60).toInt()
            val len = ByteBuffer.wrap(dec.update(stream(4))).order(ByteOrder.LITTLE_ENDIAN).int
            val m = ByteBuffer.wrap(dec.update(stream(len))).order(ByteOrder.LITTLE_ENDIAN)
            if (m.getLong(0) != 0L || m.getInt(20) != MtProxyChecker.REQ_PQ_MULTI) {
                error = "не req_pq_multi"
                return
            }
            val nonce = ByteArray(16).also { m.position(24); m.get(it) }
            if (!answer) {
                Thread.sleep(6000)
                return
            }
            val data = ByteBuffer.allocate(4 + 16 + 16 + 12 + 16).order(ByteOrder.LITTLE_ENDIAN)
                .putInt(MtProxyChecker.RES_PQ).put(nonce).put(ByteArray(16) { 1 })
                .put(8).put(ByteArray(8) { 2 }).put(ByteArray(3))
                .putInt(0x1cb5c415).putInt(1).putLong(0x0123456789abcdefL).array()
            val reply = ByteBuffer.allocate(20 + data.size).order(ByteOrder.LITTLE_ENDIAN).putLong(0).putLong(m.getLong(8) + 1).putInt(data.size).put(data).array()
            val frame = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(reply.size).array() + reply
            val encd = enc.update(frame)
            if (tls) {
                out.write(byteArrayOf(0x17, 0x03, 0x03, (encd.size ushr 8).toByte(), encd.size.toByte()))
            }
            out.write(encd)
            out.flush()
        }
    }

    private fun liveChecks() {
        val connect: (String, Int, Int) -> Socket = { _, port, t ->
            Socket().apply { connect(InetSocketAddress(InetAddress.getByName("127.0.0.1"), port), t) }
        }
        val checker = MtProxyChecker(connect, replyMs = 2500)
        val ee = "ee" + hex(key) + hex("www.google.com".toByteArray())
        val proxies = listOf(
            Triple("Fake-TLS", FakeProxy(key, tls = true), ee),
            Triple("dd", FakeProxy(key, tls = false), "dd" + hex(key)),
            Triple("обычный", FakeProxy(key, tls = false), hex(key))
        )
        try {
            for ((label, srv, secret) in proxies) {
                val e = MtProxy.Entry("127.0.0.1", srv.port, secret, MtProxy.parseSecret(secret)!!.kind)
                val r = checker.check(e)
                val tag = if (label == "обычный") MtProxyChecker.TAG_INTERMEDIATE else MtProxyChecker.TAG_PADDED
                ok(
                    "Telegram: прокси $label — до ответа Telegram (obfuscated2, req_pq → resPQ), сервер 2",
                    r.level == MtProxyChecker.Level.TELEGRAM && srv.seenDc == 2 && srv.seenTag == tag,
                    "${r.level} ${r.note} dc=${srv.seenDc} ${srv.error}"
                )
            }
            val wrong = FakeProxy(key, tls = true, signKey = ByteArray(16) { 9 })
            val silent = FakeProxy(key, tls = true, answer = false)
            try {
                val rw = checker.check(MtProxy.Entry("127.0.0.1", wrong.port, ee, MtProxy.Kind.FAKE_TLS))
                ok("Telegram: ответ TLS подписан чужим ключом — не MTProxy этого секрета (только «порт открыт»)", rw.level == MtProxyChecker.Level.TCP, "${rw.level} ${rw.note}")
                val rs = checker.check(MtProxy.Entry("127.0.0.1", silent.port, ee, MtProxy.Kind.FAKE_TLS))
                ok("Telegram: рукопожатие прошло, а Telegram через прокси молчит — «рукопожатие», не «работает»", rs.level == MtProxyChecker.Level.HANDSHAKE, "${rs.level} ${rs.note}")
            } finally {
                wrong.close()
                silent.close()
            }
            val dead = ServerSocket(0, 1, InetAddress.getByName("127.0.0.1")).let { s -> s.localPort.also { s.close() } }
            val rd = checker.check(MtProxy.Entry("127.0.0.1", dead, ee, MtProxy.Kind.FAKE_TLS))
            ok("Telegram: закрытый порт — «не подключается»", rd.level == MtProxyChecker.Level.NONE && rd.note.startsWith("не подключается"), rd.note)
        } finally {
            proxies.forEach { it.second.close() }
        }
    }

    @Suppress("unused")
    private fun drain(inp: InputStream): ByteArray = ByteArrayOutputStream().also { o -> inp.copyTo(o) }.toByteArray()
}
