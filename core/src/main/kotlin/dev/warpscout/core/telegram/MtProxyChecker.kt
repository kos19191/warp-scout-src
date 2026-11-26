package dev.warpscout.core.telegram

import java.io.ByteArrayOutputStream
import java.io.EOFException
import java.io.InputStream
import java.net.Socket
import java.net.SocketTimeoutException
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Проверка прокси MTProto по-настоящему (с 1.10.49-beta4): не «порт открыт», а то, что сделает
 * Telegram.
 *
 *  1. [Level.TCP] — подключение (время — пинг).
 *  2. [Level.HANDSHAKE] — у Fake-TLS: приветствие TLS с подписью HMAC-SHA256 секретом (как у tdlib)
 *     и ответ сервера, подписанный тем же секретом: это MTProxy с этим ключом, а не чужой сайт.
 *  3. [Level.TELEGRAM] — через прокси до сервера Telegram: заголовок obfuscated2 (ключи — SHA-256
 *     от его байтов и секрета), запрос req_pq_multi и ответ resPQ с нашим nonce. Прокси жив и
 *     пускает к Telegram.
 *
 * Протокол — по документации Telegram (mtproto-transports, «transport obfuscation») и tdlib
 * (TlsInit); самопроверка гоняет его против своего сервера. Вручную 26.11 проверено против
 * mtprotoproxy (alexbers) с поддельным сервером Telegram: все три вида секрета — TELEGRAM, чужой ключ — TCP.
 */
class MtProxyChecker(
    /** Сокет к адресу прокси (в приложении — мимо туннеля); бросает при неудаче. */
    private val connect: (host: String, port: Int, timeoutMs: Int) -> Socket,
    private val clock: () -> Long = System::currentTimeMillis,
    private val rnd: java.util.Random = SecureRandom(),
    val connectMs: Int = 3000,
    val replyMs: Int = 4000,
    /** Какой сервер Telegram просить у прокси: 2 — самый обычный. */
    val dc: Int = 2
) {
    enum class Level { NONE, TCP, HANDSHAKE, TELEGRAM }

    data class Result(val entry: MtProxy.Entry, val level: Level, val pingMs: Long, val note: String) {
        val works: Boolean get() = level == Level.TELEGRAM
    }

    fun check(e: MtProxy.Entry): Result {
        val secret = e.parsedSecret() ?: return Result(e, Level.NONE, -1, "секрет не разобрать")
        val t0 = System.nanoTime()
        val s = try {
            connect(e.server, e.port, connectMs)
        } catch (x: Exception) {
            return Result(e, Level.NONE, -1, "не подключается: ${reason(x)}")
        }
        val ping = ((System.nanoTime() - t0) / 1_000_000).coerceAtLeast(1)
        return try {
            s.soTimeout = replyMs
            s.tcpNoDelay = true
            val inp = s.getInputStream()
            val out = s.getOutputStream()
            if (secret.kind == MtProxy.Kind.FAKE_TLS) {
                val hello = clientHello(secret.domain, secret.key)
                out.write(hello)
                out.flush()
                val resp = try {
                    readServerHello(inp)
                } catch (x: Exception) {
                    return Result(e, Level.TCP, ping, "на приветствие TLS нет ответа MTProxy (${reason(x)})")
                }
                if (!serverHelloOk(resp, hello.copyOfRange(11, 43), secret.key)) {
                    return Result(e, Level.TCP, ping, "ответ TLS не подписан секретом — не MTProxy или чужой ключ")
                }
            }
            val tag = if (secret.kind == MtProxy.Kind.CLASSIC) TAG_INTERMEDIATE else TAG_PADDED
            val obfs = Obfs(secret.key, tag, dc, rnd)
            val nonce = ByteArray(16).also { rnd.nextBytes(it) }
            val frame = frame(reqPq(nonce, msgId()), padded = tag == TAG_PADDED)
            val payload = obfs.header + obfs.encrypt(frame)
            if (secret.kind == MtProxy.Kind.FAKE_TLS) {
                out.write(CCS)
                out.write(appRecord(payload))
            } else {
                out.write(payload)
            }
            out.flush()
            val records = if (secret.kind == MtProxy.Kind.FAKE_TLS) RecordReader(inp) else null
            val reader: (Int) -> ByteArray = { n -> obfs.decrypt(records?.read(n) ?: readFully(inp, n)) }
            val ok = try {
                resPqOk(reader, nonce)
            } catch (x: Exception) {
                return Result(e, if (secret.kind == MtProxy.Kind.FAKE_TLS) Level.HANDSHAKE else Level.TCP, ping, "Telegram через прокси не ответил (${reason(x)})")
            }
            if (ok) Result(e, Level.TELEGRAM, ping, "Telegram ответил через прокси")
            else Result(e, if (secret.kind == MtProxy.Kind.FAKE_TLS) Level.HANDSHAKE else Level.TCP, ping, "ответ через прокси — не от Telegram")
        } catch (x: Exception) {
            Result(e, Level.TCP, ping, reason(x))
        } finally {
            runCatching { s.close() }
        }
    }

    // --------------------------------------------------------------------------- Fake-TLS

    private fun grease(): Int = GREASE[rnd.nextInt(GREASE.size)]

    /**
     * ClientHello как у Telegram (tdlib, под Chrome): 517 байт с добивкой, имя — домен секрета,
     * random — HMAC-SHA256(ключ, приветствие с нулевым random), последние 4 байта XOR время.
     */
    fun clientHello(domain: String, key: ByteArray): ByteArray {
        val name = domain.toByteArray(Charsets.US_ASCII)
        val ext = ByteArrayOutputStream()
        fun u16(o: ByteArrayOutputStream, v: Int) { o.write((v ushr 8) and 0xFF); o.write(v and 0xFF) }
        fun extension(type: Int, data: ByteArray) { u16(ext, type); u16(ext, data.size); ext.write(data) }
        val g1 = grease()
        val g2 = grease().let { if (it == g1) it xor 0x1010 else it }
        extension(g1, ByteArray(0))
        extension(0x0000, ByteArrayOutputStream().also { o -> u16(o, name.size + 3); o.write(0); u16(o, name.size); o.write(name) }.toByteArray())
        extension(0x0017, ByteArray(0))
        extension(0xff01, byteArrayOf(0))
        extension(0x000a, ByteArrayOutputStream().also { o -> u16(o, 8); u16(o, grease()); u16(o, 0x001d); u16(o, 0x0017); u16(o, 0x0018) }.toByteArray())
        extension(0x000b, byteArrayOf(1, 0))
        extension(0x0023, ByteArray(0))
        extension(0x0010, byteArrayOf(0, 12, 2, 'h'.code.toByte(), '2'.code.toByte(), 8) + "http/1.1".toByteArray(Charsets.US_ASCII))
        extension(0x0005, byteArrayOf(1, 0, 0, 0, 0))
        extension(0x000d, ByteArrayOutputStream().also { o ->
            val algs = intArrayOf(0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601)
            u16(o, algs.size * 2); algs.forEach { u16(o, it) }
        }.toByteArray())
        extension(0x0012, ByteArray(0))
        extension(0x0033, ByteArrayOutputStream().also { o ->
            u16(o, 5 + 36); u16(o, grease()); u16(o, 1); o.write(0)
            u16(o, 0x001d); u16(o, 32); o.write(ByteArray(32).also { rnd.nextBytes(it) })
        }.toByteArray())
        extension(0x002d, byteArrayOf(1, 1))
        extension(0x002b, ByteArrayOutputStream().also { o -> o.write(6); u16(o, grease()); u16(o, 0x0304); u16(o, 0x0303) }.toByteArray())
        extension(0x001b, byteArrayOf(2, 0, 2))
        extension(g2, byteArrayOf(0))

        val body = ByteArrayOutputStream()
        u16(body, 0x0303)
        body.write(ByteArray(32))                       // random — потом подпись
        body.write(32); body.write(ByteArray(32).also { rnd.nextBytes(it) })
        val suites = intArrayOf(grease(), 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035)
        u16(body, suites.size * 2); suites.forEach { u16(body, it) }
        body.write(1); body.write(0)
        // Добивка до 517 байт записи, как у Telegram: 5 (запись) + 4 (сообщение) + тело + 2 (длина расширений).
        val noPad = 5 + 4 + body.size() + 2 + ext.size()
        val padLen = 517 - noPad - 4
        if (padLen >= 0) extension(0x0015, ByteArray(padLen))
        val exts = ext.toByteArray()
        u16(body, exts.size)
        body.write(exts)
        val hs = body.toByteArray()
        val rec = ByteArrayOutputStream()
        rec.write(0x16); u16(rec, 0x0301)
        u16(rec, hs.size + 4)
        rec.write(0x01); rec.write((hs.size ushr 16) and 0xFF); u16(rec, hs.size and 0xFFFF)
        rec.write(hs)
        val hello = rec.toByteArray()
        val digest = hmac(key, hello)
        val t = (clock() / 1000).toInt()
        for (i in 0 until 4) digest[28 + i] = (digest[28 + i].toInt() xor (t ushr (8 * i))).toByte()
        System.arraycopy(digest, 0, hello, 11, 32)
        return hello
    }

    /** Ответ сервера: запись ServerHello, ChangeCipherSpec и первая запись данных (как ждёт tdlib). */
    private fun readServerHello(inp: InputStream): ByteArray {
        val out = ByteArrayOutputStream()
        val h1 = readFully(inp, 5)
        if ((h1[0].toInt() and 0xFF) != 0x16 || (h1[1].toInt() and 0xFF) != 0x03 || (h1[2].toInt() and 0xFF) != 0x03) {
            throw EOFException("первая запись — не ServerHello")
        }
        out.write(h1)
        out.write(readFully(inp, len(h1, 3)))
        val h2 = readFully(inp, 11)
        if (!h2.copyOf(9).contentEquals(CCS + byteArrayOf(0x17, 0x03, 0x03))) throw EOFException("за ServerHello нет ChangeCipherSpec и данных")
        out.write(h2)
        out.write(readFully(inp, len(h2, 9)))
        return out.toByteArray()
    }

    private fun serverHelloOk(resp: ByteArray, clientRandom: ByteArray, key: ByteArray): Boolean {
        if (resp.size < 43) return false
        val got = resp.copyOfRange(11, 43)
        val zero = resp.copyOf()
        for (i in 11 until 43) zero[i] = 0
        val want = hmac(key, clientRandom + zero)
        return MessageDigest.isEqual(got, want)
    }

    private fun appRecord(payload: ByteArray): ByteArray {
        val out = ByteArrayOutputStream()
        var off = 0
        while (off < payload.size) {
            val n = minOf(MAX_RECORD, payload.size - off)
            out.write(0x17); out.write(0x03); out.write(0x03); out.write(n ushr 8); out.write(n and 0xFF)
            out.write(payload, off, n)
            off += n
        }
        return out.toByteArray()
    }

    /** Данные из записей TLS (17 03 03): их тела подряд. */
    private class RecordReader(private val inp: InputStream) {
        private var pending = ByteArray(0)

        fun read(n: Int): ByteArray {
            while (pending.size < n) {
                val h = readFully(inp, 5)
                val type = h[0].toInt() and 0xFF
                val body = readFully(inp, len(h, 3))
                if (type == 0x14) continue
                if (type != 0x17) throw EOFException("запись TLS не того вида: $type")
                pending += body
            }
            val out = pending.copyOf(n)
            pending = pending.copyOfRange(n, pending.size)
            return out
        }
    }

    // -------------------------------------------------------------------------- obfuscated2

    /** Заголовок obfuscated2 и шифры в обе стороны (AES-256-CTR, ключи — SHA-256 с секретом). */
    class Obfs(secret: ByteArray, tag: Int, dc: Int, rnd: java.util.Random) {
        val header: ByteArray
        private val enc: Cipher
        private val dec: Cipher

        init {
            val init = initBytes(rnd, tag, dc)
            val rev = init.reversedArray()
            enc = ctr(sha256(init.copyOfRange(8, 40) + secret), init.copyOfRange(40, 56))
            dec = ctr(sha256(rev.copyOfRange(8, 40) + secret), rev.copyOfRange(40, 56))
            val encrypted = enc.update(init)
            header = init.copyOf()
            System.arraycopy(encrypted, 56, header, 56, 8)
        }

        fun encrypt(b: ByteArray): ByteArray = enc.update(b)
        fun decrypt(b: ByteArray): ByteArray = dec.update(b)

        companion object {
            /** Первые 4 байта, которые нельзя: начала HTTP, TLS и метки других транспортов. */
            private val FORBIDDEN = setOf(0x44414548, 0x54534f50, 0x20544547, 0x4954504f, 0xdddddddd.toInt(), 0xeeeeeeee.toInt(), 0x02010316)

            fun initBytes(rnd: java.util.Random, tag: Int, dc: Int): ByteArray {
                while (true) {
                    val b = ByteArray(64).also { rnd.nextBytes(it) }
                    if ((b[0].toInt() and 0xFF) == 0xef) continue
                    val bb = ByteBuffer.wrap(b).order(ByteOrder.LITTLE_ENDIAN)
                    if (bb.getInt(0) in FORBIDDEN || bb.getInt(4) == 0) continue
                    bb.putInt(56, tag)
                    bb.putShort(60, dc.toShort())
                    return b
                }
            }

            fun ctr(key: ByteArray, iv: ByteArray): Cipher =
                Cipher.getInstance("AES/CTR/NoPadding").apply { init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), IvParameterSpec(iv)) }

            fun sha256(b: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(b)
        }
    }

    // ------------------------------------------------------------------------------- MTProto

    private fun msgId(): Long {
        val ms = clock()
        return ((ms / 1000) shl 32) or (((ms % 1000) * 4294967L) and 0xFFFFFFFCL)
    }

    /** Незашифрованное сообщение req_pq_multi (auth_key_id = 0). */
    fun reqPq(nonce: ByteArray, msgId: Long): ByteArray =
        ByteBuffer.allocate(40).order(ByteOrder.LITTLE_ENDIAN).putLong(0).putLong(msgId).putInt(20)
            .putInt(REQ_PQ_MULTI).put(nonce).array()

    /** Кадр intermediate: длина (LE) и сообщение; padded — ещё 0–15 случайных байт (длина с ними). */
    private fun frame(msg: ByteArray, padded: Boolean): ByteArray {
        val pad = if (padded) ByteArray(rnd.nextInt(16)).also { rnd.nextBytes(it) } else ByteArray(0)
        return ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(msg.size + pad.size).array() + msg + pad
    }

    /** Ответ — resPQ с нашим nonce. */
    private fun resPqOk(read: (Int) -> ByteArray, nonce: ByteArray): Boolean {
        val len = ByteBuffer.wrap(read(4)).order(ByteOrder.LITTLE_ENDIAN).int
        if (len < 0) throw EOFException("Telegram ответил ошибкой ${len}")
        if (len < 40 || len > 4096) return false
        val msg = ByteBuffer.wrap(read(len)).order(ByteOrder.LITTLE_ENDIAN)
        if (msg.getLong(0) != 0L) return false
        val dataLen = msg.getInt(16)
        if (dataLen < 20 || 20 + dataLen > len) return false
        if (msg.getInt(20) != RES_PQ) return false
        val got = ByteArray(16)
        msg.position(24)
        msg.get(got)
        return got.contentEquals(nonce)
    }

    companion object {
        const val TAG_INTERMEDIATE = 0xeeeeeeee.toInt()
        const val TAG_PADDED = 0xdddddddd.toInt()
        const val REQ_PQ_MULTI = 0xbe7e8ef1.toInt()
        const val RES_PQ = 0x05162463
        private const val MAX_RECORD = 16384
        val CCS = byteArrayOf(0x14, 0x03, 0x03, 0x00, 0x01, 0x01)
        private val GREASE = intArrayOf(0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa)

        fun hmac(key: ByteArray, data: ByteArray): ByteArray =
            Mac.getInstance("HmacSHA256").apply { init(SecretKeySpec(key, "HmacSHA256")) }.doFinal(data)

        private fun len(b: ByteArray, at: Int): Int = ((b[at].toInt() and 0xFF) shl 8) or (b[at + 1].toInt() and 0xFF)

        fun readFully(inp: InputStream, n: Int): ByteArray {
            val b = ByteArray(n)
            var off = 0
            while (off < n) {
                val k = inp.read(b, off, n - off)
                if (k < 0) throw EOFException("соединение закрыто")
                off += k
            }
            return b
        }

        fun reason(e: Throwable): String {
            val m = (e.message ?: "").lowercase()
            return when {
                e is SocketTimeoutException -> "тишина"
                "refused" in m -> "отказ в подключении"
                "reset" in m -> "сброс"
                "unreachable" in m || "no route" in m -> "нет маршрута"
                e is EOFException -> e.message ?: "соединение закрыто"
                e is java.net.UnknownHostException -> "имя не находится"
                else -> e.message?.take(80) ?: e.javaClass.simpleName
            }
        }
    }
}
