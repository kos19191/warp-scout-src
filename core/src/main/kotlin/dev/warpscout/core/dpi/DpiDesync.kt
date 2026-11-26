package dev.warpscout.core.dpi

import java.util.Random

/**
 * Как первое сообщение TLS уходит по группе стратегии [DpiStrategy] (с 1.10.49-beta4): порт
 * desync.c и packets.c из ByeDPI (MIT), только без сети — на выходе куски [TlsHello.Piece],
 * отправляет их [TrickSender].
 *
 * Порядок как у ByeDPI: сначала «подделка» самого сообщения (`--tlsminor`, `--tlsrec` — сервер их
 * примет: это всё ещё правильный TLS), потом куски по позициям в порядке ключей. Позиции имени
 * сайта (`+s`) считаются по исходному сообщению — у ByeDPI так же (он запоминает их до `--tlsrec`).
 * Позиция меньше предыдущей — дальше не режем, остаток уходит целиком (у ByeDPI — «split cancel»).
 *
 * Фейк (`--fake`) — настоящее приветствие с другим именем той же длины и случайными random,
 * session_id и ключами (как `--fake-tls-mod rand,orig --fake-sni …`): длины и разметка те же,
 * значит те же и номера байтов TCP, а фильтр видит чужой сайт.
 */
object DpiDesync {

    /** Что получит сервер ([sent] — после `--tlsrec`/`--tlsminor`) и какими кусками это уходит. */
    class Plan(val sent: ByteArray, val pieces: List<TlsHello.Piece>)

    /** Имя сайта в исходном сообщении: смещение и длина (у ByeDPI — proto_info). */
    private class Info(val tls: Boolean, val hostPos: Int, val hostLen: Int)

    /**
     * Чем подменяется имя в фейке, если в стратегии нет `--fake-sni`: сайты, которые фильтр точно
     * пропускает. Имя подгоняется под длину настоящего (поддомен спереди): так не меняются длины.
     */
    val DECOYS: List<String> = listOf(
        "vk.com", "ya.ru", "ok.ru", "mail.ru", "dzen.ru", "yandex.ru", "rutube.ru", "ozon.ru", "avito.ru", "gosuslugi.ru"
    )

    private fun u8(b: ByteArray, i: Int): Int = b[i].toInt() and 0xFF
    private fun u16(b: ByteArray, i: Int): Int = (u8(b, i) shl 8) or u8(b, i + 1)

    fun isClientHello(b: ByteArray, n: Int = b.size): Boolean =
        n > 5 && n <= b.size && u8(b, 0) == 0x16 && u8(b, 1) == 0x03 && u8(b, 5) == 0x01

    private fun info(hello: ByteArray): Info {
        val tls = isClientHello(hello)
        val sni = if (tls) TlsHello.findSni(hello) else null
        return Info(tls, sni?.offset ?: 0, sni?.length ?: 0)
    }

    /** gen_offset ByeDPI: позиция в байтах; −1 — нужна позиция имени, а имени нет. */
    private fun offset(p: DpiStrategy.Pos, n: Int, lp: Int, info: Info, rnd: Random): Long {
        if (p.sni || p.host) {
            if (info.hostPos <= 0 || (p.sni && !info.tls)) return -1
            var pos = p.offset + info.hostPos
            when {
                p.end -> pos += info.hostLen
                p.mid -> pos += info.hostLen / 2
                p.rand -> pos += rnd.nextInt(maxOf(1, info.hostLen))
            }
            return pos
        }
        return when {
            p.rand -> p.offset + lp + rnd.nextInt(maxOf(1, n - lp))
            p.mid -> p.offset + n / 2
            p.offset < 0 || p.end -> p.offset + n
            else -> p.offset
        }
    }

    /** Разрез записи: запись с [lp], тело до разреза — [rel] байт, всё тело было [rsz]. */
    private class RecOp(val lp: Int, val rel: Int, val rsz: Int)

    /** part_tls ByeDPI: на месте разреза — новый заголовок записи (+5 байт). */
    private fun splitAt(buf: ByteArray, op: RecOp): ByteArray {
        val out = ByteArray(buf.size + 5)
        val cut = op.lp + 5 + op.rel
        System.arraycopy(buf, 0, out, 0, cut)
        out[cut] = buf[op.lp]
        out[cut + 1] = buf[op.lp + 1]
        out[cut + 2] = buf[op.lp + 2]
        val second = op.rsz - op.rel
        out[cut + 3] = (second ushr 8).toByte()
        out[cut + 4] = second.toByte()
        System.arraycopy(buf, cut, out, cut + 5, buf.size - cut)
        out[op.lp + 3] = (op.rel ushr 8).toByte()
        out[op.lp + 4] = op.rel.toByte()
        return out
    }

    /** `--tlsrec` по ByeDPI (tamp): позиции с флагом или отрицательные — от начала тела записи. */
    private fun tlsrec(hello: ByteArray, recs: List<DpiStrategy.Pos>, info: Info, rnd: Random): Pair<ByteArray, List<RecOp>> {
        var buf = hello
        val ops = ArrayList<RecOp>()
        var lp = 0
        var rc = 0
        loop@ for (part in recs) {
            for (k in 0 until maxOf(1, part.repeats)) {
                val base = offset(part, buf.size - rc * 5, lp, info, rnd)
                if (base < 0 && (part.sni || part.host)) break@loop
                var pos = rc * 5L + base
                if (part.offset < 0 || part.flagged) pos -= 5
                pos += part.skip * k
                if (pos < lp) break@loop
                val rel = pos - lp
                val remaining = buf.size - lp
                if (remaining < 3 || rel < 0 || rel + 5 > remaining) break@loop
                val rsz = u16(buf, lp + 3)
                if (rsz < rel) break@loop
                val op = RecOp(lp, rel.toInt(), rsz)
                buf = splitAt(buf, op)
                ops += op
                rc++
                lp = (pos + 5).toInt()
            }
        }
        return buf to ops
    }

    /**
     * Куски первого сообщения [hello] по группе [g]. Склейка кусков без срочных байтов — ровно
     * [Plan.sent]: то, что получит сервер.
     */
    fun plan(hello: ByteArray, g: DpiStrategy.Group, rnd: Random = Random()): Plan {
        if (hello.isEmpty()) return Plan(hello, emptyList())
        val info = info(hello)
        var buf = hello.copyOf()
        var decoy: ByteArray? = if (g.needsFake) decoyOf(hello, g.fakeSni, rnd) else null
        if (g.tlsminor >= 0 && isClientHello(buf)) {
            buf[2] = g.tlsminor.toByte()
            decoy?.set(2, g.tlsminor.toByte())
        }
        if (g.tlsrec.isNotEmpty() && isClientHello(buf)) {
            val (b, ops) = tlsrec(buf, g.tlsrec, info, rnd)
            buf = b
            decoy = decoy?.let { d -> ops.fold(d) { acc, op -> splitAt(acc, op) } }
        }
        val n = buf.size
        val pieces = ArrayList<TlsHello.Piece>()
        var lp = 0
        loop@ for (part in g.parts) {
            for (k in 0 until maxOf(1, part.pos.repeats)) {
                val base = offset(part.pos, n, lp, info, rnd)
                if (base < 0 && (part.pos.sni || part.pos.host)) break@loop
                val pos = base + part.pos.skip * k
                if (pos < 0 || pos < lp) break@loop
                val end = minOf(pos, n.toLong()).toInt()
                val bytes = buf.copyOfRange(lp, end)
                // Повторы перестановки: у ByeDPI TTL 1 — у чётных (первый, третий…), у остальных — обычный.
                val low = k % 2 == 0
                when (part.mode) {
                    DpiStrategy.Mode.SPLIT -> if (bytes.isNotEmpty()) pieces += TlsHello.Piece(bytes)
                    DpiStrategy.Mode.DISORDER -> if (bytes.isNotEmpty()) pieces += TlsHello.Piece(bytes, lowTtl = low)
                    DpiStrategy.Mode.OOB -> pieces += TlsHello.Piece(bytes, oobAfter = true)
                    DpiStrategy.Mode.DISOOB -> pieces += TlsHello.Piece(bytes, lowTtl = low, oobAfter = true)
                    // Фейк у ByeDPI — с начала поддельного сообщения, длиной с отрезаемый кусок.
                    DpiStrategy.Mode.FAKE -> if (bytes.isNotEmpty()) {
                        val d = decoy ?: buf
                        pieces += TlsHello.Piece(bytes, fake = d.copyOfRange(0, bytes.size), fakeTtl = g.fakeTtl)
                    }
                }
                lp = end
            }
        }
        if (lp < n) pieces += TlsHello.Piece(buf.copyOfRange(lp, n))
        return Plan(buf, pieces)
    }

    // ------------------------------------------------------------------------------------ фейк

    /** Поддельное приветствие: то же, но имя — [decoyName] той же длины, random/session_id/ключи — случайные. */
    fun decoyOf(hello: ByteArray, names: List<String> = emptyList(), rnd: Random = Random()): ByteArray {
        val d = hello.copyOf()
        val sni = if (isClientHello(hello)) TlsHello.findSni(hello) else null
        if (sni != null) {
            val name = decoyName(sni.length, names, rnd).toByteArray(Charsets.US_ASCII)
            if (name.size == sni.length) System.arraycopy(name, 0, d, sni.offset, sni.length)
        }
        randomize(d, rnd)
        return d
    }

    /** Имя ровно из [len] символов: из [user] (с `?`, `#`, `*`) или [DECOYS], с поддоменом спереди. */
    fun decoyName(len: Int, user: List<String> = emptyList(), rnd: Random = Random()): String {
        if (len <= 0) return ""
        val pool = user.map { pattern(it, rnd) }.filter { it.isNotEmpty() }.ifEmpty { DECOYS }
        val fit = pool.filter { it.length <= len }
        if (fit.isEmpty()) return letters(len, rnd)
        val base = fit[rnd.nextInt(fit.size)]
        return when (val extra = len - base.length) {
            0 -> base
            // На один символ длиннее — буква в начало первой метки (точку с поддоменом не вставить).
            1 -> letters(1, rnd) + base
            else -> labels(extra - 1, rnd) + "." + base
        }
    }

    private const val ALNUM = "abcdefghijklmnopqrstuvwxyz0123456789"

    private fun letters(n: Int, rnd: Random): String =
        String(CharArray(n) { i -> if (i == 0) ('a' + rnd.nextInt(26)) else ALNUM[rnd.nextInt(ALNUM.length)] })

    /** Поддомены суммарной длины [n]: метки не длиннее 60 символов, без пустых. */
    private fun labels(n: Int, rnd: Random): String {
        if (n <= 60) return letters(n, rnd)
        // «метка.остаток»: остаток не короче 1, иначе метка короче.
        val head = if (n - 61 >= 1) 60 else n - 2
        return letters(head, rnd) + "." + labels(n - head - 1, rnd)
    }

    private fun pattern(s: String, rnd: Random): String = s.lowercase().map { c ->
        when (c) {
            '?' -> 'a' + rnd.nextInt(26)
            '#' -> '0' + rnd.nextInt(10)
            '*' -> ALNUM[rnd.nextInt(ALNUM.length)]
            else -> c
        }
    }.joinToString("").trim('.')

    /** randomize_tls ByeDPI: random, session_id и ключи key_share — случайные. */
    private fun randomize(b: ByteArray, rnd: Random) {
        if (!isClientHello(b) || b.size < 44) return
        val sidLen = u8(b, 43)
        if (b.size < 44 + sidLen + 2) return
        fill(b, 11, 32, rnd)
        fill(b, 44, sidLen, rnd)
        val ks = extOffset(b, b.size, 0x0033, extBlock(b, b.size))
        if (ks < 0 || ks + 6 >= b.size) return
        val ksSize = u16(b, ks + 2)
        if (ks + 4 + ksSize > b.size) return
        var g = ks + 4 + 2
        while (g + 4 < ks + 4 + ksSize) {
            val gSize = u16(b, g + 2)
            if (g + 4 + gSize > b.size) return
            fill(b, g + 4, gSize, rnd)
            g += 4 + gSize
        }
    }

    private fun fill(b: ByteArray, from: Int, len: Int, rnd: Random) {
        for (i in from until minOf(b.size, from + len)) b[i] = rnd.nextInt(256).toByte()
    }

    /** find_ext_block ByeDPI: начало расширений ClientHello (поле длины); −1 — нет. */
    private fun extBlock(b: ByteArray, size: Int): Int {
        if (size < 44) return -1
        val sidLen = u8(b, 43)
        if (size < 44 + sidLen + 2) return -1
        val cip = u16(b, 44 + sidLen)
        val skip = 44 + sidLen + 2 + cip + 2
        return if (skip > size) -1 else skip
    }

    /** find_tls_ext_offset ByeDPI: где расширение [type] (его заголовок); −1 — нет. */
    private fun extOffset(b: ByteArray, size0: Int, type: Int, skip0: Int): Int {
        if (skip0 < 0) return -1
        var size = minOf(size0, b.size)
        if (size <= skip0 + 2) return -1
        val extLen = u16(b, skip0)
        var skip = skip0 + 2
        if (extLen < size - skip) size = extLen + skip
        while (skip + 4 < size) {
            if (u16(b, skip) == type) return skip
            skip += u16(b, skip + 2) + 4
        }
        return -1
    }

    /**
     * neq_tls_sid ByeDPI: ответ — ServerHello TLS 1.3 (есть supported_versions), а session_id в нём
     * не наш. Так бывает, когда до сервера дошёл фейк (TTL велик): он ответил чужому приветствию.
     * TLS 1.2 так не проверить — тогда false.
     */
    fun sidMismatch(hello: ByteArray, resp: ByteArray, respLen: Int = resp.size): Boolean {
        val n = minOf(respLen, resp.size)
        if (hello.size < 75 || n < 75) return false
        if (!isClientHello(hello) || u8(resp, 0) != 0x16 || u8(resp, 1) != 0x03) return false
        val sidLen = u8(hello, 43)
        if (44 + sidLen > hello.size || 44 + sidLen > n) return false
        if (extOffset(resp, n, 0x2b, 44 + sidLen + 3) < 0) return false
        if (u8(hello, 43) != u8(resp, 43)) return true
        for (i in 0 until sidLen) if (hello[44 + i] != resp[44 + i]) return true
        return false
    }
}
