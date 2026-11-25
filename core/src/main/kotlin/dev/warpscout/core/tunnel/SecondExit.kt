package dev.warpscout.core.tunnel

import dev.warpscout.core.config.WgConf
import dev.warpscout.core.crypto.Crypto
import dev.warpscout.core.wg.Wg
import java.io.OutputStream
import java.security.SecureRandom
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit

/**
 * Второй выход (свой сервер для отдельных сайтов): всё, что нужно, чтобы он работал с обычным
 * сервером, а не только «на бумаге».
 *
 * До 1.10.31 пакеты уходили во второй туннель как есть — с адресом WARP (172.16.0.2) в поле
 * «отправитель». Сервер WireGuard принимает от клиента только адреса, которые сам ему выдал
 * (10.8.0.2 и т. п.), поэтому такие пакеты молча отбрасывал: второй выход поднимался, а сайты через
 * него не открывались. Здесь:
 *  • [ExitNat] — подмена адреса туда и обратно с пересчётом контрольных сумм;
 *  • [InnerUdpChannel] — второй туннель внутри основного (WARP): провайдер видит только WARP,
 *    а «голый» WireGuard до своего сервера в России часто режут;
 *  • [AwgChannel] — серверы AmneziaWG (свои типы пакетов H1–H4 и случайные байты S1–S4);
 *  • [Icmp6Reject] — быстрый отказ по IPv6, если у второго сервера IPv6 нет: приложение сразу
 *    идёт по IPv4 через второй выход, а не через WARP с российским адресом.
 */
object PacketMath {

    fun u16(b: ByteArray, off: Int): Int = ((b[off].toInt() and 0xFF) shl 8) or (b[off + 1].toInt() and 0xFF)

    fun put16(b: ByteArray, off: Int, v: Int) {
        b[off] = (v ushr 8).toByte()
        b[off + 1] = v.toByte()
    }

    /** Сумма 16-битных слов (дополнение до единицы, без свёртки и инверсии). */
    fun sum(b: ByteArray, off: Int, len: Int, initial: Long = 0L): Long {
        var s = initial
        var i = off
        val end = off + len
        while (i + 1 < end) {
            s += u16(b, i)
            i += 2
        }
        if (i < end) s += ((b[i].toInt() and 0xFF) shl 8).toLong()
        return s
    }

    fun fold(sum: Long): Int {
        var s = sum
        while (s ushr 16 != 0L) s = (s and 0xFFFF) + (s ushr 16)
        return s.toInt()
    }

    /** Контрольная сумма нового пакета. */
    fun checksum(b: ByteArray, off: Int, len: Int, initial: Long = 0L): Int =
        fold(sum(b, off, len, initial)).inv() and 0xFFFF

    /**
     * Поправить сумму по месту после замены слов [old] на [new] (RFC 1624: HC' = ~(~HC + ~m + m')).
     * Пересчитывать весь пакет ради смены адреса незачем: меняется пара слов.
     */
    fun adjust(b: ByteArray, at: Int, old: ByteArray, new: ByteArray, udp: Boolean = false) {
        var s = (u16(b, at).inv() and 0xFFFF).toLong()
        var i = 0
        while (i + 1 < old.size) {
            s += (u16(old, i).inv() and 0xFFFF).toLong()
            s += u16(new, i).toLong()
            i += 2
        }
        var r = fold(s).inv() and 0xFFFF
        // В UDP поверх IPv4 ноль значит «суммы нет»: настоящий ноль пишется как 0xFFFF.
        if (udp && r == 0) r = 0xFFFF
        put16(b, at, r)
    }

    fun same(b: ByteArray, off: Int, addr: ByteArray): Boolean {
        if (off + addr.size > b.size) return false
        for (i in addr.indices) if (b[off + i] != addr[i]) return false
        return true
    }

    /** Адрес из текста («10.8.0.2/32» → 4 байта). Только литерал: имя не резолвим. */
    fun addrOf(text: String?): ByteArray? {
        val host = text?.trim()?.substringBefore('/')?.trim().orEmpty()
        if (host.isEmpty()) return null
        if (host.contains(':')) {
            if (!host.all { it.isDigit() || it in 'a'..'f' || it in 'A'..'F' || it == ':' || it == '.' }) return null
        } else {
            val parts = host.split('.')
            if (parts.size != 4 || parts.any { p -> p.toIntOrNull()?.let { it !in 0..255 } != false }) return null
        }
        return runCatching { java.net.InetAddress.getByName(host).address }.getOrNull()
    }
}

/**
 * Подмена адреса для второго выхода: у tun адрес WARP, у второго сервера — свой.
 *
 * [outbound] — пакет из tun во второй выход: отправитель «адрес tun» → «адрес второго конфига».
 * [inbound] — ответ второго выхода в tun: получатель «адрес второго конфига» → «адрес tun».
 * Контрольные суммы поправляются: IPv4-заголовок, TCP, UDP, ICMPv6 (у них в сумме есть адреса).
 */
class ExitNat(
    private val inner4: ByteArray?,
    private val outer4: ByteArray?,
    private val inner6: ByteArray?,
    private val outer6: ByteArray?,
) {
    /** IPv4 через второй выход возможен (адреса известны с обеих сторон). */
    val v4: Boolean get() = inner4 != null && outer4 != null

    /** IPv6 через второй выход возможен: у второго сервера есть IPv6-адрес, у tun — тоже. */
    val v6: Boolean get() = inner6 != null && outer6 != null

    /** false — этот пакет во второй выход отправить нельзя (нет адреса его версии IP). */
    fun outbound(p: ByteArray, len: Int = p.size): Boolean = rewrite(p, len, outbound = true)

    fun inbound(p: ByteArray, len: Int = p.size): Boolean = rewrite(p, len, outbound = false)

    private fun rewrite(p: ByteArray, len: Int, outbound: Boolean): Boolean {
        if (len < 1 || len > p.size) return false
        return when ((p[0].toInt() ushr 4) and 0x0F) {
            4 -> rewrite4(p, len, outbound)
            6 -> rewrite6(p, len, outbound)
            else -> false
        }
    }

    private fun rewrite4(p: ByteArray, len: Int, outbound: Boolean): Boolean {
        val from = (if (outbound) inner4 else outer4) ?: return false
        val to = (if (outbound) outer4 else inner4) ?: return false
        if (len < 20) return false
        val ihl = (p[0].toInt() and 0x0F) * 4
        if (ihl < 20 || len < ihl) return false
        val at = if (outbound) 12 else 16
        // Чужой адрес (не наш поток) или адреса совпадают — пакет как есть.
        if (!PacketMath.same(p, at, from) || from.contentEquals(to)) return true
        PacketMath.adjust(p, 10, from, to)
        // Во фрагментах, кроме первого, заголовка TCP/UDP нет — там правится только IP.
        if ((PacketMath.u16(p, 6) and 0x1FFF) == 0) {
            when (p[9].toInt() and 0xFF) {
                6 -> if (len >= ihl + 18) PacketMath.adjust(p, ihl + 16, from, to)
                17 -> if (len >= ihl + 8 && PacketMath.u16(p, ihl + 6) != 0) {
                    PacketMath.adjust(p, ihl + 6, from, to, udp = true)
                }
            }
        }
        System.arraycopy(to, 0, p, at, 4)
        return true
    }

    private fun rewrite6(p: ByteArray, len: Int, outbound: Boolean): Boolean {
        val from = (if (outbound) inner6 else outer6) ?: return false
        val to = (if (outbound) outer6 else inner6) ?: return false
        if (len < 40) return false
        val at = if (outbound) 8 else 24
        if (!PacketMath.same(p, at, from) || from.contentEquals(to)) return true
        var next = p[6].toInt() and 0xFF
        var off = 40
        var tail = false
        var guard = 0
        // Заголовки расширений (hop-by-hop, routing, destination options, фрагмент) — пропускаем.
        while (guard++ < 8) {
            when (next) {
                0, 43, 60 -> {
                    if (len < off + 8) return false
                    val size = ((p[off + 1].toInt() and 0xFF) + 1) * 8
                    next = p[off].toInt() and 0xFF
                    off += size
                }
                44 -> {
                    if (len < off + 8) return false
                    if ((PacketMath.u16(p, off + 2) ushr 3) != 0) tail = true
                    next = p[off].toInt() and 0xFF
                    off += 8
                }
                else -> break
            }
        }
        if (!tail) {
            when (next) {
                6 -> if (len >= off + 18) PacketMath.adjust(p, off + 16, from, to)
                17 -> if (len >= off + 8) PacketMath.adjust(p, off + 6, from, to, udp = true)
                58 -> if (len >= off + 4) PacketMath.adjust(p, off + 2, from, to)
            }
        }
        System.arraycopy(to, 0, p, at, 16)
        return true
    }

    /**
     * Ограничить MSS в SYN и SYN-ACK. Второй выход внутри основного туннеля: его пакеты плюс заголовки
     * обёртки должны влезать в MTU основного, иначе большие TCP-сегменты потерялись бы.
     */
    fun clampMss(p: ByteArray, len: Int, maxMss: Int) {
        if (maxMss <= 0 || len < 1 || len > p.size) return
        val l4 = when ((p[0].toInt() ushr 4) and 0x0F) {
            4 -> {
                val ihl = (p[0].toInt() and 0x0F) * 4
                if (ihl < 20 || len < ihl + 20 || (p[9].toInt() and 0xFF) != 6) return
                if ((PacketMath.u16(p, 6) and 0x1FFF) != 0) return
                ihl
            }
            6 -> {
                if (len < 60 || (p[6].toInt() and 0xFF) != 6) return
                40
            }
            else -> return
        }
        if ((p[l4 + 13].toInt() and 0x02) == 0) return
        val dataOff = ((p[l4 + 12].toInt() ushr 4) and 0x0F) * 4
        if (dataOff < 20 || len < l4 + dataOff) return
        var i = l4 + 20
        val end = l4 + dataOff
        while (i < end) {
            val kind = p[i].toInt() and 0xFF
            if (kind == 0) return
            if (kind == 1) {
                i++
                continue
            }
            if (i + 1 >= end) return
            val olen = p[i + 1].toInt() and 0xFF
            if (olen < 2 || i + olen > end) return
            if (kind == 2 && olen == 4) {
                val pos = i + 2
                if (PacketMath.u16(p, pos) <= maxMss) return
                // Сумма считается словами от начала TCP-заголовка (он всегда на чётном месте):
                // если поле MSS стоит на нечётном месте, оно задевает два слова.
                val base = pos and 1.inv()
                val span = if (pos == base) 2 else 4
                if (base + span > p.size) return
                val old = p.copyOfRange(base, base + span)
                PacketMath.put16(p, pos, maxMss)
                val new = p.copyOfRange(base, base + span)
                PacketMath.adjust(p, l4 + 16, old, new)
                return
            }
            i += olen
        }
    }

    companion object {
        /**
         * NAT из адресов tun и текста второго конфига (строка Address). Адреса берём по виду, а не по
         * порядку: в конфиге IPv6 может стоять и первым.
         */
        fun of(tun4: String?, tun6: String?, secondConf: String): ExitNat {
            val addrs = WgConf.parse(secondConf).iface.get("Address").orEmpty()
                .split(',').map { it.trim() }.filter { it.isNotEmpty() }
            val outer4 = addrs.firstOrNull { !it.contains(':') }?.let { PacketMath.addrOf(it) }
            val outer6 = addrs.firstOrNull { it.contains(':') }?.let { PacketMath.addrOf(it) }
            return ExitNat(PacketMath.addrOf(tun4), outer4, PacketMath.addrOf(tun6), outer6)
        }
    }
}

/**
 * Второй туннель внутри основного: UDP-датаграммы второго WireGuard уходят не в сеть напрямую,
 * а IP-пакетами в основной туннель (WARP). Провайдер видит только WARP — а WARP у вас уже работает.
 *
 * [send] заворачивает датаграмму в IPv4/UDP (адрес tun → адрес второго сервера) и отдаёт её
 * основному выходу через [inject]. Ответы сервера приходят из основного туннеля обычными пакетами:
 * их забирает [accept] (см. [TapPacketOut]) и возвращает через [receive].
 */
class InnerUdpChannel(
    private val inject: (ByteArray) -> Unit,
    private val localIp: ByteArray,
    private val remoteIp: ByteArray,
    private val remotePort: Int,
    /** Сколько байт влезает в основной туннель за раз (его MTU): больше — режем на фрагменты IPv4. */
    private val maxPacket: Int,
    private val timeoutMs: Long = 1500L,
    random: java.util.Random = SecureRandom(),
) : UdpChannel {

    val localPort: Int = 20000 + random.nextInt(40000)
    private val inbox = LinkedBlockingQueue<ByteArray>(4096)
    private var ipId = random.nextInt(0x10000)

    @Volatile
    private var closed = false

    @Volatile
    var bytesIn: Long = 0L
        private set

    override fun send(packet: ByteArray) {
        if (closed) throw java.io.IOException("канал второго выхода закрыт")
        for (p in packets(packet)) inject(p)
    }

    override fun receive(): ByteArray? {
        if (closed) throw java.io.IOException("канал второго выхода закрыт")
        return inbox.poll(timeoutMs, TimeUnit.MILLISECONDS)
    }

    override fun close() {
        closed = true
        inbox.clear()
    }

    /**
     * Пакет из основного туннеля — ответ нашего сервера? Тогда забираем полезную нагрузку себе и
     * возвращаем true: в tun такой пакет писать нельзя (система ответила бы «порт закрыт»).
     */
    fun accept(p: ByteArray, len: Int = p.size): Boolean {
        if (closed || len < 28 || len > p.size) return false
        if (((p[0].toInt() ushr 4) and 0x0F) != 4 || (p[9].toInt() and 0xFF) != 17) return false
        val ihl = (p[0].toInt() and 0x0F) * 4
        if (ihl < 20 || len < ihl + 8) return false
        if (!PacketMath.same(p, 12, remoteIp) || !PacketMath.same(p, 16, localIp)) return false
        if (PacketMath.u16(p, ihl) != remotePort || PacketMath.u16(p, ihl + 2) != localPort) return false
        // Фрагменты не собираем: WireGuard такой обрывок всё равно не расшифрует. Но и в tun его не пускаем.
        if ((PacketMath.u16(p, 6) and 0x3FFF) != 0) return true
        val total = minOf(PacketMath.u16(p, 2), len)
        val end = minOf(total, ihl + PacketMath.u16(p, ihl + 4))
        if (end <= ihl + 8) return true
        val payload = p.copyOfRange(ihl + 8, end)
        bytesIn += payload.size
        inbox.offer(payload)
        return true
    }

    /** Датаграмма → один IPv4/UDP-пакет или несколько фрагментов, если не влезает в [maxPacket]. */
    fun packets(payload: ByteArray): List<ByteArray> {
        val udpLen = 8 + payload.size
        val udp = ByteArray(udpLen)
        PacketMath.put16(udp, 0, localPort)
        PacketMath.put16(udp, 2, remotePort)
        PacketMath.put16(udp, 4, udpLen)
        System.arraycopy(payload, 0, udp, 8, payload.size)
        var pseudo = PacketMath.sum(localIp, 0, 4) + PacketMath.sum(remoteIp, 0, 4) + 17L + udpLen
        pseudo = PacketMath.sum(udp, 0, udpLen, pseudo)
        var sum = PacketMath.fold(pseudo).inv() and 0xFFFF
        if (sum == 0) sum = 0xFFFF
        PacketMath.put16(udp, 6, sum)

        val id = (ipId++) and 0xFFFF
        val room = (maxPacket.coerceIn(576, 65535) - 20)
        if (udpLen <= room) return listOf(ip(udp, 0, udpLen, id, 0, more = false))
        val step = room and 7.inv()
        val out = ArrayList<ByteArray>()
        var off = 0
        while (off < udpLen) {
            val n = minOf(step, udpLen - off)
            out += ip(udp, off, n, id, off / 8, more = off + n < udpLen)
            off += n
        }
        return out
    }

    private fun ip(data: ByteArray, off: Int, n: Int, id: Int, frag8: Int, more: Boolean): ByteArray {
        val p = ByteArray(20 + n)
        p[0] = 0x45
        PacketMath.put16(p, 2, 20 + n)
        PacketMath.put16(p, 4, id)
        PacketMath.put16(p, 6, (if (more) 0x2000 else 0) or (frag8 and 0x1FFF))
        p[8] = 64
        p[9] = 17
        System.arraycopy(localIp, 0, p, 12, 4)
        System.arraycopy(remoteIp, 0, p, 16, 4)
        PacketMath.put16(p, 10, PacketMath.checksum(p, 0, 20))
        System.arraycopy(data, off, p, 20, n)
        return p
    }
}

/**
 * Выход основного туннеля в tun с отводом: пакеты, которые забрал [tap] (ответы второго сервера,
 * идущего внутри основного туннеля), в tun не пишутся.
 */
class TapPacketOut(
    private val out: OutputStream,
    private val tap: (ByteArray, Int) -> Boolean,
) : OutputStream() {

    override fun write(b: Int) = write(byteArrayOf(b.toByte()), 0, 1)

    override fun write(b: ByteArray, off: Int, len: Int) {
        val p = if (off == 0) b else b.copyOfRange(off, off + len)
        if (runCatching { tap(p, len) }.getOrDefault(false)) return
        out.write(p, 0, len)
    }

    override fun flush() = out.flush()

    override fun close() {
        // Дескриптор tun закрывает сервис, а не один из выходов.
    }
}

/**
 * Вход второго туннеля из tun: пакеты, которые диспетчер отправил во второй выход, получают адрес
 * отправителя из второго конфига. Пакет, который туда отправить нельзя (IPv6, а у второго сервера
 * IPv6 нет), не теряется молча: системе сразу уходит отказ ([Icmp6Reject]), и приложение повторяет
 * по IPv4 — уже через второй выход.
 */
class NatPacketIn(
    private val inner: java.io.InputStream,
    private val nat: ExitNat,
    private val maxMss: Int = 0,
    private val reject: (ByteArray) -> Unit = {},
) : java.io.InputStream() {

    @Volatile
    var rejected: Long = 0L
        private set

    override fun read(): Int {
        val one = ByteArray(1)
        val n = read(one, 0, 1)
        return if (n <= 0) -1 else one[0].toInt() and 0xFF
    }

    override fun read(b: ByteArray, off: Int, len: Int): Int {
        while (true) {
            val n = inner.read(b, off, len)
            if (n <= 0) return n
            val p = if (off == 0) b else b.copyOfRange(off, off + n)
            if (nat.outbound(p, n)) {
                if (maxMss > 0) nat.clampMss(p, n, maxMss)
                if (off != 0) System.arraycopy(p, 0, b, off, n)
                return n
            }
            rejected++
            Icmp6Reject.build(p, n)?.let { runCatching { reject(it) } }
        }
    }

    override fun close() = inner.close()
}

/** Выход второго туннеля в tun: в ответах адрес второго сервера меняется обратно на адрес tun. */
class NatPacketOut(
    private val out: OutputStream,
    private val nat: ExitNat,
    private val maxMss: Int = 0,
) : OutputStream() {

    override fun write(b: Int) = write(byteArrayOf(b.toByte()), 0, 1)

    override fun write(b: ByteArray, off: Int, len: Int) {
        val p = if (off == 0) b else b.copyOfRange(off, off + len)
        if (maxMss > 0) nat.clampMss(p, len, maxMss)
        nat.inbound(p, len)
        out.write(p, 0, len)
    }

    override fun flush() = out.flush()

    override fun close() {
        // См. TapPacketOut.close.
    }
}

/**
 * Отказ по IPv6 «запрещено» (ICMPv6, тип 1, код 1). Нужен, когда у второго сервера нет IPv6:
 * без него приложение пошло бы к сайту по IPv6 через WARP (сайт увидел бы Россию) или ждало бы
 * таймаута. С отказом система сразу сообщает приложению об ошибке, и оно идёт по IPv4.
 */
object Icmp6Reject {

    fun build(orig: ByteArray, len: Int): ByteArray? {
        if (len < 40 || len > orig.size || ((orig[0].toInt() ushr 4) and 0x0F) != 6) return null
        // На ICMPv6 ошибкой не отвечаем: так не бывает петель «ошибка на ошибку».
        if ((orig[6].toInt() and 0xFF) == 58) return null
        val quote = minOf(len, 1280 - 48)
        val body = 8 + quote
        val out = ByteArray(40 + body)
        out[0] = 0x60
        PacketMath.put16(out, 4, body)
        out[6] = 58
        out[7] = 64
        System.arraycopy(orig, 24, out, 8, 16)
        System.arraycopy(orig, 8, out, 24, 16)
        out[40] = 1
        out[41] = 1
        System.arraycopy(orig, 0, out, 48, quote)
        val pseudo = PacketMath.sum(out, 8, 32) + body + 58L
        PacketMath.put16(out, 42, PacketMath.checksum(out, 40, body, pseudo))
        return out
    }
}

/**
 * AmneziaWG поверх нашего WireGuard — для второго выхода (свой сервер AmneziaWG).
 *
 * Что умеет, по версиям AmneziaWG (как в amneziawg-go, device/send.go и receive.go):
 * - 1.0: свои номера типов пакетов H1–H4, случайные байты перед инициацией и ответом (S1, S2) и Jc
 *   пакетов шума размером Jmin–Jmax перед каждой инициацией;
 * - 1.5: пакеты-«подписи» I1–I5 перед шумом ([AwgObf]; с 1.10.49-beta1);
 * - 2: H1–H4 — диапазоны «от-до» (номер выбирается случайно на каждый пакет), S3 — перед cookie,
 *   S4 — перед пакетами данных;
 * - 3 (3.1 у AmneziaVPN 5.1+; с 1.10.49-beta1): HeaderProtectionKey — заголовок каждого пакета
 *   закрыт ChaCha20 (у рукопожатия — всё сообщение, у данных — 16 байт заголовка), nonce — первые
 *   12 байт пакета, то есть случайные байты S1–S4; RandomTrailers — случайный «хвост» после
 *   сообщений рукопожатия. ContentPaddingAddition, DisableCookies и таймеры (RekeyAfterTime и др.)
 *   клиенту менять не нужно: дополнительную набивку внутри шифра сервер принимает и без неё, cookie
 *   шлёт сервер, а наши таймеры — обычные таймеры WireGuard, они в пределах серверных.
 *
 * Сделано обёрткой над каналом, а не правкой самого WireGuard: основной туннель (WARP) работает с
 * обычными типами, и эта обёртка его не касается — она включается только для второго выхода и только
 * если в его конфиге есть параметры AmneziaWG. mac1 считается по байтам вместе с типом, поэтому после
 * замены типа он пересчитывается (см. [Wg.remac1]).
 */
class AwgChannel(
    private val inner: UdpChannel,
    private val p: Params,
    private val localPublic: ByteArray,
    private val remotePublic: ByteArray,
    private val random: java.util.Random = SecureRandom(),
) : UdpChannel {

    /** Параметры AmneziaWG; диапазоны — беззнаковые 32-битные. */
    class Params(
        val h1: LongRange, val h2: LongRange, val h3: LongRange, val h4: LongRange,
        val s1: Int = 0, val s2: Int = 0, val s3: Int = 0, val s4: Int = 0,
        val jc: Int = 0, val jmin: Int = 0, val jmax: Int = 0,
        /** I1–I5: пакеты-«подписи» перед каждой инициацией (пустые и битые сюда не попадают). */
        val ipackets: List<AwgObf.Chain> = emptyList(),
        /** HeaderProtectionKey (AmneziaWG 3): 32 байта ключа ChaCha20. */
        val headerKey: ByteArray? = null,
        /** RandomTrailers (AmneziaWG 3): «хвосты» после сообщений рукопожатия. */
        val randomTrailers: Boolean = false,
        /** Параметры AmneziaWG 3, которые клиенту применять не нужно (для журнала). */
        val notApplied: List<String> = emptyList(),
        /** Что в конфиге не разобралось (для журнала): битые I1–I5, ключ защиты заголовков. */
        val problems: List<String> = emptyList(),
    ) {
        /** Обычный WireGuard (без своих типов, добавок, шума и защиты): обёртка не нужна. */
        val isPlain: Boolean
            get() = h1 == 1L..1L && h2 == 2L..2L && h3 == 3L..3L && h4 == 4L..4L &&
                s1 == 0 && s2 == 0 && s3 == 0 && s4 == 0 && jc == 0 &&
                ipackets.isEmpty() && headerKey == null && !randomTrailers

        /** Версия AmneziaWG по набору параметров — для журнала и экрана. */
        val version: String
            get() = when {
                headerKey != null || randomTrailers -> "3"
                s3 != 0 || s4 != 0 || listOf(h1, h2, h3, h4).any { it.first != it.last } -> "2"
                ipackets.isNotEmpty() -> "1.5"
                else -> "1"
            }

        fun describe(): String = "AmneziaWG $version: H1=${r(h1)} H2=${r(h2)} H3=${r(h3)} H4=${r(h4)} S1=$s1 S2=$s2" +
            (if (s3 != 0 || s4 != 0) " S3=$s3 S4=$s4" else "") + (if (jc > 0) " Jc=$jc" else "") +
            (if (ipackets.isNotEmpty()) " · подписи I1–I5: ${ipackets.size}" else "") +
            (if (headerKey != null) " · защита заголовков" else "") +
            (if (randomTrailers) " · хвосты" else "") +
            (if (notApplied.isNotEmpty()) " · не нужны клиенту: ${notApplied.joinToString(", ")}" else "") +
            (if (problems.isNotEmpty()) " · не разобралось: ${problems.joinToString("; ")}" else "")

        private fun r(x: LongRange) = if (x.first == x.last) "${x.first}" else "${x.first}-${x.last}"
    }

    /**
     * Наибольший отправленный пакет данных — от него длина «хвостов» (у amneziawg-go это udpWindow
     * пира: начинается с 500 байт и растёт с пакетами данных).
     */
    @Volatile
    private var udpWindow = DEFAULT_UDP_WINDOW

    override fun send(packet: ByteArray) {
        val type = if (packet.size >= 4) u32(packet, 0) else -1L
        when {
            type == Wg.TYPE_INITIATION.toLong() && packet.size == Wg.INITIATION_LEN -> {
                // Порядок как у amneziawg-go: подписи I1–I5, потом Jc пакетов шума, потом инициация.
                for (chain in p.ipackets) runCatching { inner.send(chain.build(random)) }
                repeat(p.jc.coerceIn(0, 16)) {
                    val lo = p.jmin.coerceIn(1, 1280)
                    val hi = p.jmax.coerceIn(lo, 1280)
                    val junk = ByteArray(lo + random.nextInt(hi - lo + 1)).also { random.nextBytes(it) }
                    runCatching { inner.send(junk) }
                }
                val msg = packet.copyOf()
                Crypto.le32(pick(p.h1).toInt()).copyInto(msg, 0)
                Wg.remac1(msg, remotePublic)
                inner.send(frame(p.s1, msg, wholeMessage = true, trailer = true))
            }
            type == Wg.TYPE_RESPONSE.toLong() && packet.size == Wg.RESPONSE_LEN -> {
                val msg = packet.copyOf()
                Crypto.le32(pick(p.h2).toInt()).copyInto(msg, 0)
                Wg.remac1(msg, remotePublic)
                inner.send(frame(p.s2, msg, wholeMessage = true, trailer = true))
            }
            type == Wg.TYPE_TRANSPORT.toLong() && packet.size >= 32 -> {
                val msg = packet.copyOf()
                Crypto.le32(pick(p.h4).toInt()).copyInto(msg, 0)
                val out = frame(p.s4, msg, wholeMessage = false, trailer = false)
                if (out.size > udpWindow) udpWindow = out.size
                inner.send(out)
            }
            else -> inner.send(packet)
        }
    }

    /**
     * Пакет как у amneziawg-go: [S случайных байт][сообщение][хвост]. С ключом защиты заголовков
     * сообщение (у данных — первые 16 байт: тип, индекс, номер) складывается XOR с потоком ChaCha20;
     * nonce — первые 12 байт пакета до этого XOR (у amneziawg-go — `crypt[:12]`; при S ≥ 12 это сами
     * случайные байты, и сервер берёт те же 12 байт из пришедшего пакета).
     */
    private fun frame(pad: Int, msg: ByteArray, wholeMessage: Boolean, trailer: Boolean): ByteArray {
        val n = pad.coerceAtLeast(0)
        val size = n + msg.size
        val window = udpWindow
        val tail = if (trailer && p.randomTrailers && window > size) random.nextInt(window - size) else 0
        val out = ByteArray(size + tail)
        if (n > 0) ByteArray(n).also { random.nextBytes(it) }.copyInto(out, 0)
        msg.copyInto(out, n)
        p.headerKey?.let { key ->
            val nonce = out.copyOfRange(0, NONCE)
            Crypto.chacha20Xor(key, nonce, out, n, if (wholeMessage) msg.size else HEADER)
        }
        if (tail > 0) ByteArray(tail).also { random.nextBytes(it) }.copyInto(out, size)
        return out
    }

    override fun receive(): ByteArray? {
        val pkt = inner.receive() ?: return null
        if (pkt.size < 32) return pkt
        val key = p.headerKey
        // Защита заголовков: тип открывается первыми 4 байтами потока ChaCha20 (nonce — первые 12
        // байт пакета), остальное сообщение — следующими. Так же разбирает и amneziawg-go.
        val nonce = if (key != null) pkt.copyOfRange(0, NONCE) else null
        val mask = if (key != null && nonce != null) {
            ByteArray(4).also { Crypto.chacha20Xor(key, nonce, it, 0, 4) }.let { u32(it, 0) }
        } else 0L
        fun typeAt(pad: Int): Long = u32(pkt, pad) xor mask
        fun fits(pad: Int, len: Int) = pkt.size == pad + len || (p.randomTrailers && pkt.size > pad + len)

        if (fits(p.s2, Wg.RESPONSE_LEN) && typeAt(p.s2) in p.h2) {
            val msg = pkt.copyOfRange(p.s2, p.s2 + Wg.RESPONSE_LEN)
            if (key != null && nonce != null) Crypto.chacha20Xor(key, nonce, msg, 0, msg.size)
            Crypto.le32(Wg.TYPE_RESPONSE).copyInto(msg, 0)
            Wg.remac1(msg, localPublic)
            return msg
        }
        if (fits(p.s3, Wg.COOKIE_MSG_LEN) && typeAt(p.s3) in p.h3) {
            val msg = pkt.copyOfRange(p.s3, p.s3 + Wg.COOKIE_MSG_LEN)
            if (key != null && nonce != null) Crypto.chacha20Xor(key, nonce, msg, 0, msg.size)
            Crypto.le32(Wg.TYPE_COOKIE).copyInto(msg, 0)
            return msg
        }
        if (pkt.size >= p.s4 + 32 && typeAt(p.s4) in p.h4) {
            val msg = pkt.copyOfRange(p.s4, pkt.size)
            if (key != null && nonce != null) Crypto.chacha20Xor(key, nonce, msg, 0, HEADER)
            Crypto.le32(Wg.TYPE_TRANSPORT).copyInto(msg, 0)
            return msg
        }
        return pkt
    }

    override fun close() = inner.close()

    private fun pick(r: LongRange): Long {
        val span = r.last - r.first
        if (span <= 0L) return r.first
        return r.first + (random.nextLong() ushr 1) % (span + 1)
    }

    private fun u32(b: ByteArray, off: Int): Long = Crypto.readLe32(b, off).toLong() and 0xFFFFFFFFL

    companion object {
        /** Начальное окно для «хвостов», как DefaultUdpWindow у amneziawg-go. */
        const val DEFAULT_UDP_WINDOW = 500
        private const val NONCE = 12
        private const val HEADER = 16

        /** Параметры AmneziaWG 3, которые сервер учитывает сам; клиенту их применять не нужно. */
        private val NOT_APPLIED = listOf(
            "ContentPaddingAddition", "DisableCookies", "RekeyAfterTime", "RekeyTimeout",
            "RejectAfterTime", "KeepaliveTimeout", "MaxHandshakeAttempts",
        )

        /** Параметры из текста конфига; null — обычный WireGuard (обёртка не нужна) или не разобралось. */
        fun paramsOf(conf: String): Params? {
            val iface = runCatching { WgConf.parse(conf).iface }.getOrNull() ?: return null
            fun range(key: String, def: Long): LongRange? {
                val raw = iface.get(key)?.trim().orEmpty()
                if (raw.isEmpty()) return def..def
                val a = raw.substringBefore('-').trim().toLongOrNull() ?: return null
                val b = if (raw.contains('-')) raw.substringAfter('-').trim().toLongOrNull() ?: return null else a
                if (a < 0 || b < a || b > 0xFFFFFFFFL) return null
                return a..b
            }
            fun int(key: String): Int = iface.get(key)?.trim()?.toIntOrNull()?.coerceIn(0, 65535) ?: 0
            val problems = ArrayList<String>()
            val ipackets = (1..5).mapNotNull { k ->
                val spec = iface.get("I$k")?.trim().orEmpty()
                if (spec.isEmpty()) return@mapNotNull null
                runCatching { AwgObf.parse(spec) }.getOrElse { t ->
                    problems += "I$k: ${t.message}"
                    null
                }
            }
            val headerKey = iface.get("HeaderProtectionKey")?.trim()?.takeIf { it.isNotEmpty() }?.let { raw ->
                headerKeyOf(raw) ?: run {
                    problems += "HeaderProtectionKey: нужен ключ 32 байта (base64 или hex)"
                    null
                }
            }
            val trailers = iface.get("RandomTrailers")?.trim()?.lowercase() in setOf("on", "true", "1", "yes")
            val params = Params(
                h1 = range("H1", 1) ?: return null,
                h2 = range("H2", 2) ?: return null,
                h3 = range("H3", 3) ?: return null,
                h4 = range("H4", 4) ?: return null,
                s1 = int("S1"), s2 = int("S2"), s3 = int("S3"), s4 = int("S4"),
                jc = int("Jc"), jmin = int("Jmin"), jmax = int("Jmax"),
                ipackets = ipackets,
                headerKey = headerKey,
                randomTrailers = trailers,
                notApplied = NOT_APPLIED.filter { !iface.get(it)?.trim().isNullOrEmpty() },
                problems = problems,
            )
            return params.takeIf { !it.isPlain }
        }

        private fun headerKeyOf(raw: String): ByteArray? {
            val hex = raw.removePrefix("0x")
            if (hex.length == 64 && hex.all { Character.digit(it, 16) >= 0 }) return Crypto.unHex(hex)
            return runCatching { Crypto.unBase64(raw) }.getOrNull()?.takeIf { it.size == 32 }
        }
    }
}
