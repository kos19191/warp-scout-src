package dev.warpscout.core.dpi

/**
 * Пакеты TCP в tun — разбор и сборка (с 1.10.49-beta3, для обхода DPI в туннеле, см. [DpiRelay]).
 *
 * Только то, что нужно своему концу TCP: IPv4 (без фрагментов) и IPv6 без заголовков расширения,
 * опция MSS, контрольные суммы. Окно без масштабирования, без SACK и меток времени: своё SYN-ACK их
 * не предлагает, и по RFC 7323 приложение тогда их не включает тоже.
 */
object TcpPacket {
    const val FIN = 0x01
    const val SYN = 0x02
    const val RST = 0x04
    const val PSH = 0x08
    const val ACK = 0x10

    /** Сегмент из tun. [data] — весь пакет; полезная нагрузка — [dataOff] … [dataOff] + [dataLen]. */
    class Seg(
        val v6: Boolean,
        val src: ByteArray,
        val dst: ByteArray,
        val sport: Int,
        val dport: Int,
        val seq: Int,
        val ack: Int,
        val flags: Int,
        val window: Int,
        /** Опция MSS из SYN; −1 — её нет. */
        val mss: Int,
        val data: ByteArray,
        val dataOff: Int,
        val dataLen: Int
    ) {
        fun has(flag: Int): Boolean = (flags and flag) != 0
    }

    internal fun u16(b: ByteArray, i: Int): Int = ((b[i].toInt() and 0xFF) shl 8) or (b[i + 1].toInt() and 0xFF)

    internal fun s32(b: ByteArray, i: Int): Int =
        ((b[i].toInt() and 0xFF) shl 24) or ((b[i + 1].toInt() and 0xFF) shl 16) or
            ((b[i + 2].toInt() and 0xFF) shl 8) or (b[i + 3].toInt() and 0xFF)

    internal fun put16(b: ByteArray, i: Int, v: Int) {
        b[i] = (v ushr 8).toByte()
        b[i + 1] = v.toByte()
    }

    internal fun put32(b: ByteArray, i: Int, v: Int) {
        b[i] = (v ushr 24).toByte()
        b[i + 1] = (v ushr 16).toByte()
        b[i + 2] = (v ushr 8).toByte()
        b[i + 3] = v.toByte()
    }

    /** TCP-сегмент из IP-пакета; null — не TCP, фрагмент или пакет битый. */
    fun parse(p: ByteArray, len: Int = p.size): Seg? {
        val size = minOf(len, p.size)
        if (size < 20) return null
        when ((p[0].toInt() ushr 4) and 0x0F) {
            4 -> {
                val ihl = (p[0].toInt() and 0x0F) * 4
                if (ihl < 20 || size < ihl + 20) return null
                if ((p[9].toInt() and 0xFF) != 6) return null
                // Флаг «есть ещё фрагменты» или смещение — не целый сегмент: не наш.
                if ((((p[6].toInt() and 0x3F) shl 8) or (p[7].toInt() and 0xFF)) != 0) return null
                val total = minOf(size, u16(p, 2))
                if (total < ihl + 20) return null
                return tcp(false, p, ihl, total, p.copyOfRange(12, 16), p.copyOfRange(16, 20))
            }

            6 -> {
                if (size < 60) return null
                if ((p[6].toInt() and 0xFF) != 6) return null
                val total = minOf(size, 40 + u16(p, 4))
                if (total < 60) return null
                return tcp(true, p, 40, total, p.copyOfRange(8, 24), p.copyOfRange(24, 40))
            }
        }
        return null
    }

    private fun tcp(v6: Boolean, p: ByteArray, off: Int, total: Int, src: ByteArray, dst: ByteArray): Seg? {
        val doff = ((p[off + 12].toInt() ushr 4) and 0x0F) * 4
        if (doff < 20 || off + doff > total) return null
        var mss = -1
        var i = off + 20
        val end = off + doff
        while (i < end) {
            val kind = p[i].toInt() and 0xFF
            if (kind == 0) break
            if (kind == 1) {
                i++
                continue
            }
            if (i + 1 >= end) break
            val l = p[i + 1].toInt() and 0xFF
            if (l < 2 || i + l > end) break
            if (kind == 2 && l == 4) mss = u16(p, i + 2)
            i += l
        }
        return Seg(
            v6, src, dst, u16(p, off), u16(p, off + 2), s32(p, off + 4), s32(p, off + 8),
            p[off + 13].toInt() and 0xFF, u16(p, off + 14), mss, p, off + doff, total - off - doff
        )
    }

    /** Сумма 16-битных слов (для контрольных сумм IP/TCP/ICMP). */
    internal fun sum16(b: ByteArray, off: Int, len: Int, initial: Long = 0L): Long {
        var s = initial
        var i = off
        val end = off + len
        while (i + 1 < end) {
            s += ((b[i].toInt() and 0xFF) shl 8) or (b[i + 1].toInt() and 0xFF)
            i += 2
        }
        if (i < end) s += (b[i].toInt() and 0xFF) shl 8
        return s
    }

    internal fun fold(sum: Long): Int {
        var s = sum
        while ((s ushr 16) != 0L) s = (s and 0xFFFF) + (s ushr 16)
        return (s.inv() and 0xFFFF).toInt()
    }

    /** Сумма псевдозаголовка: адреса, протокол и длина сегмента. */
    private fun pseudo(v6: Boolean, b: ByteArray, proto: Int, segLen: Int): Long =
        if (v6) {
            sum16(b, 8, 32) + (segLen ushr 16) + (segLen and 0xFFFF) + proto
        } else {
            sum16(b, 12, 8) + proto + segLen
        }

    /** Контрольная сумма TCP пакета, собранного целиком (поле суммы — нули). */
    internal fun tcpChecksum(pkt: ByteArray, v6: Boolean, tcpOff: Int, tcpLen: Int): Int =
        fold(pseudo(v6, pkt, 6, tcpLen) + sum16(pkt, tcpOff, tcpLen))

    /** Сумма пакета сходится (для проверок): IPv4 — заголовок и TCP, IPv6 — TCP. */
    fun checksumOk(pkt: ByteArray): Boolean {
        val v6 = (pkt[0].toInt() ushr 4) == 6
        val ipLen = if (v6) 40 else (pkt[0].toInt() and 0x0F) * 4
        if (!v6 && fold(sum16(pkt, 0, ipLen)) != 0) return false
        val tcpLen = if (v6) u16(pkt, 4) else u16(pkt, 2) - ipLen
        return fold(pseudo(v6, pkt, 6, tcpLen) + sum16(pkt, ipLen, tcpLen)) == 0
    }

    /**
     * Сегмент от имени [src]:[sport] к [dst]:[dport]. [mss] > 0 — с опцией MSS (только для SYN-ACK).
     * Полезную нагрузку [dataLen] байт кладёт [fill] — прямо в пакет, без лишней копии.
     */
    fun build(
        v6: Boolean,
        src: ByteArray,
        dst: ByteArray,
        sport: Int,
        dport: Int,
        seq: Int,
        ack: Int,
        flags: Int,
        window: Int,
        mss: Int = 0,
        ipId: Int = 0,
        dataLen: Int = 0,
        fill: ((ByteArray, Int) -> Unit)? = null
    ): ByteArray {
        val opt = if (mss > 0) 4 else 0
        val tcpLen = 20 + opt + dataLen
        val ipLen = if (v6) 40 else 20
        val pkt = ByteArray(ipLen + tcpLen)
        if (v6) {
            pkt[0] = 0x60
            put16(pkt, 4, tcpLen)
            pkt[6] = 6
            pkt[7] = 64
            System.arraycopy(src, 0, pkt, 8, 16)
            System.arraycopy(dst, 0, pkt, 24, 16)
        } else {
            pkt[0] = 0x45
            put16(pkt, 2, ipLen + tcpLen)
            put16(pkt, 4, ipId and 0xFFFF)
            pkt[6] = 0x40 // DF
            pkt[8] = 64
            pkt[9] = 6
            System.arraycopy(src, 0, pkt, 12, 4)
            System.arraycopy(dst, 0, pkt, 16, 4)
            put16(pkt, 10, fold(sum16(pkt, 0, 20)))
        }
        val t = ipLen
        put16(pkt, t, sport)
        put16(pkt, t + 2, dport)
        put32(pkt, t + 4, seq)
        put32(pkt, t + 8, ack)
        pkt[t + 12] = (((20 + opt) / 4) shl 4).toByte()
        pkt[t + 13] = flags.toByte()
        put16(pkt, t + 14, window.coerceIn(0, 0xFFFF))
        if (opt > 0) {
            pkt[t + 20] = 2
            pkt[t + 21] = 4
            put16(pkt, t + 22, mss)
        }
        if (dataLen > 0) fill?.invoke(pkt, t + 20 + opt)
        put16(pkt, t + 16, tcpChecksum(pkt, v6, t, tcpLen))
        return pkt
    }

    /**
     * «Порт закрыт» (ICMP) в ответ на пакет [p] — от имени его адресата. Так приложение сразу узнаёт,
     * что QUIC не пройдёт, и переходит на TCP, а не ждёт таймаута. null — не IP или пакет короткий.
     */
    fun portUnreachable(p: ByteArray, len: Int = p.size): ByteArray? {
        val size = minOf(len, p.size)
        if (size < 20) return null
        return when ((p[0].toInt() ushr 4) and 0x0F) {
            4 -> {
                val ihl = (p[0].toInt() and 0x0F) * 4
                if (ihl < 20 || size < ihl + 8) return null
                val quote = minOf(size, ihl + 8)
                val icmpLen = 8 + quote
                val out = ByteArray(20 + icmpLen)
                out[0] = 0x45
                put16(out, 2, 20 + icmpLen)
                out[8] = 64
                out[9] = 1
                System.arraycopy(p, 16, out, 12, 4) // от адресата исходного пакета
                System.arraycopy(p, 12, out, 16, 4) // к его отправителю
                put16(out, 10, fold(sum16(out, 0, 20)))
                out[20] = 3 // destination unreachable
                out[21] = 3 // port unreachable
                System.arraycopy(p, 0, out, 28, quote)
                put16(out, 22, fold(sum16(out, 20, icmpLen)))
                out
            }

            6 -> {
                if (size < 48) return null
                val quote = minOf(size, 1280 - 48)
                val icmpLen = 8 + quote
                val out = ByteArray(40 + icmpLen)
                out[0] = 0x60
                put16(out, 4, icmpLen)
                out[6] = 58
                out[7] = 64
                System.arraycopy(p, 24, out, 8, 16)
                System.arraycopy(p, 8, out, 24, 16)
                out[40] = 1 // destination unreachable
                out[41] = 4 // port unreachable
                System.arraycopy(p, 0, out, 48, quote)
                put16(out, 42, fold(pseudo(true, out, 58, icmpLen) + sum16(out, 40, icmpLen)))
                out
            }

            else -> null
        }
    }

    /** Пакет — TCP с SYN без ACK к порту [port] (новое соединение). Без разбора и копий. */
    fun isSynTo(p: ByteArray, len: Int, port: Int): Boolean {
        val off = l4Offset(p, len, 6) ?: return false
        if (len < off + 14) return false
        val flags = p[off + 13].toInt() and 0xFF
        return (flags and SYN) != 0 && (flags and ACK) == 0 && u16(p, off + 2) == port
    }

    /** Пакет — UDP к порту [port] (QUIC — к 443). */
    fun isUdpTo(p: ByteArray, len: Int, port: Int): Boolean {
        val off = l4Offset(p, len, 17) ?: return false
        return len >= off + 4 && u16(p, off + 2) == port
    }

    /** Смещение заголовка протокола [proto] в целом (не фрагменте) пакете; null — другой протокол. */
    private fun l4Offset(p: ByteArray, len: Int, proto: Int): Int? {
        if (len < 20 || len > p.size) return null
        return when ((p[0].toInt() ushr 4) and 0x0F) {
            4 -> {
                val ihl = (p[0].toInt() and 0x0F) * 4
                if (ihl < 20 || (p[9].toInt() and 0xFF) != proto) return null
                if ((((p[6].toInt() and 0x1F) shl 8) or (p[7].toInt() and 0xFF)) != 0) return null
                ihl
            }

            6 -> if (len >= 44 && (p[6].toInt() and 0xFF) == proto) 40 else null
            else -> null
        }
    }
}

/** Кольцевой буфер байтов: очередь «от приложения к серверу» и «от сервера к приложению». */
class ByteRing(val capacity: Int) {
    private val buf = ByteArray(capacity)
    private var head = 0

    var size: Int = 0
        private set

    fun free(): Int = capacity - size

    /** Дописать до [len] байт; сколько поместилось. */
    fun write(src: ByteArray, off: Int, len: Int): Int {
        val n = minOf(len, free())
        var tail = (head + size) % capacity
        var done = 0
        while (done < n) {
            val chunk = minOf(n - done, capacity - tail)
            System.arraycopy(src, off + done, buf, tail, chunk)
            done += chunk
            tail = (tail + chunk) % capacity
        }
        size += n
        return n
    }

    /** Скопировать [len] байт, начиная с [from] от начала очереди, не забирая их. */
    fun peek(dst: ByteArray, dstOff: Int, from: Int, len: Int) {
        require(from >= 0 && len >= 0 && from + len <= size) { "за пределами очереди: $from+$len > $size" }
        var pos = (head + from) % capacity
        var done = 0
        while (done < len) {
            val chunk = minOf(len - done, capacity - pos)
            System.arraycopy(buf, pos, dst, dstOff + done, chunk)
            done += chunk
            pos = (pos + chunk) % capacity
        }
    }

    /** Забрать до [len] байт в [dst]; сколько забрано. */
    fun read(dst: ByteArray, off: Int, len: Int): Int {
        val n = minOf(len, size)
        peek(dst, off, 0, n)
        drop(n)
        return n
    }

    fun drop(n: Int) {
        val k = minOf(n, size)
        head = (head + k) % capacity
        size -= k
        if (size == 0) head = 0
    }

    /** Байт по смещению от начала (для разбора заголовка записи TLS). */
    fun byteAt(i: Int): Int = buf[(head + i) % capacity].toInt() and 0xFF
}
