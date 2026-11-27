package dev.warpscout.core.tunnel

import dev.warpscout.core.dpi.TcpPacket
import java.io.InputStream
import java.io.OutputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong

/**
 * Зависшие соединения после переподключения (с 1.10.50-beta1).
 *
 * Зачем. Журнал 26.11, 21:15: телефон переключился с Tele2 на МегаФон, туннель поднялся заново за 6 с, а
 * Telegram «прям тяжело» включался. После переподключения у WARP новая сессия: другой адрес телефона,
 * другая площадка (Стокгольм → Франкфурт) и другой адрес выхода (104.28.212.78 → 104.28.244.74). Для
 * серверов старые соединения TCP теперь приходят с чужого адреса, ответы им не доходят — а приложение
 * этого не знает: интерфейс VPN тот же (с 1.10.50-beta1 он при переподключении не пропадает), сетевых
 * событий нет, и Telegram ждёт своего таймаута — десятки секунд.
 *
 * Что делаем. Следим за соединениями TCP в tun (адреса, порты, номера) и после переподключения
 * сбрасываем приложению зависшие: сегмент RST от имени сервера с тем номером, которого ждёт приложение
 * (RFC 5961: сброс принимается только при точном совпадении; не совпал — приложение пришлёт «challenge
 * ACK» с нужным номером, и мы ответим вторым сбросом). Приложение сразу видит «соединение сброшено» и
 * открывает новое — уже через новую сессию:
 *  • сеть сменилась — все прежние соединения (кроме тех, что сервис решит оставить: второй выход);
 *  • сеть та же — те, что к подъёму уже ждали ответа ([staleFlows] с all = false);
 *  • и дальше: по прежнему соединению приложение шлёт данные, а в ответ за [staleMs] ни пакета, хотя
 *    туннель другие пакеты получает, — тоже сброс (см. [up]).
 * Новые соединения (начатые после [sessionBegin]) не трогаем никогда.
 *
 * Пакеты от приложений видит [In] (обёртка чтения tun), к приложениям — [Out] (обёртка записи).
 * Один экземпляр живёт весь процесс: соединения переживают смену сессии, ради этого всё и затевалось.
 */
class TcpGuard(
    private val clock: () -> Long = System::currentTimeMillis,
    /** Сколько ждать ответа по прежнему соединению, прежде чем сбросить его. */
    @Volatile var staleMs: Long = STALE_MS,
) {

    /** Соединение приложения: адрес и порт приложения, сервера, номера в обе стороны. */
    class Flow internal constructor(
        val v6: Boolean,
        val app: ByteArray,
        val appPort: Int,
        val srv: ByteArray,
        val srvPort: Int,
        /** Когда видели SYN; 0 — начала не видели (соединение старше нас). */
        val created: Long,
    ) {
        /** Следующий номер от приложения (seq + данные + SYN/FIN). */
        @Volatile internal var appNext = 0
        @Volatile internal var appKnown = false

        /** Последний номер подтверждения от приложения — столько оно ждёт от сервера. */
        @Volatile internal var appAck = 0
        @Volatile internal var ackKnown = false

        /** Следующий номер от сервера (по пакетам к приложению). */
        @Volatile internal var srvNext = 0
        @Volatile internal var srvKnown = false

        @Volatile var lastUp = 0L
            internal set
        @Volatile var lastDown = 0L
            internal set

        /** С какой минуты приложение ждёт ответа (послало данные, от сервера после этого ничего); 0 — не ждёт. */
        @Volatile internal var waitSince = 0L

        /** Когда сбросили мы; 0 — не сбрасывали. */
        @Volatile internal var resetAt = 0L

        @Volatile internal var finUp = false
        @Volatile internal var finDown = false

        val appAddress: InetSocketAddress get() = InetSocketAddress(InetAddress.getByAddress(app), appPort)
        val srvAddress: InetSocketAddress get() = InetSocketAddress(InetAddress.getByAddress(srv), srvPort)

        /** «149.154.167.51:443» — для журнала. */
        fun describe(): String {
            val host = runCatching { InetAddress.getByAddress(srv).hostAddress }.getOrNull() ?: "?"
            return if (v6) "[$host]:$srvPort" else "$host:$srvPort"
        }
    }

    private data class Key(val v6: Boolean, val a: Long, val b: Long, val c: Long, val d: Long, val ports: Int)

    private class Parsed(
        val v6: Boolean,
        val srcOff: Int,
        val dstOff: Int,
        val sport: Int,
        val dport: Int,
        val seq: Int,
        val ack: Int,
        val flags: Int,
        val payload: Int,
    )

    private val flows = ConcurrentHashMap<Key, Flow>()

    /** Начало текущей сессии туннеля (см. [sessionBegin]); 0 — сессий ещё не было. */
    @Volatile
    var sessionStart = 0L
        private set

    /** Куда писать сбросы — в tun текущей сессии. null — некуда (туннеля нет). */
    @Volatile
    private var output: ((ByteArray) -> Unit)? = null

    /** Сбрасывать ли сейчас (в проверочных подъёмах подбора — нет: только следим). */
    @Volatile
    private var resetting = false

    /** Последний пакет к приложениям — любой: по нему видно, что туннель вообще что-то получает. */
    @Volatile
    private var lastAnyDown = 0L

    /** Пакеты, которые пишем сами (сбросы): [Out] их не разбирает. */
    private val emitting = ThreadLocal<Boolean>()

    /** Сброс по ходу сессии (см. [up]) — сервис пишет в журнал, кого и почему. */
    @Volatile
    var onReactive: ((Flow) -> Unit)? = null

    val resets = AtomicLong()
    val reactiveResets = AtomicLong()

    /** Сколько соединений помним сейчас. */
    val size: Int get() = flows.size

    // ---------------------------------------------------------------------------- сессии

    /** Номер текущей сессии (см. [sessionBegin]); 0 — сессии нет. */
    private var sessionId = 0L
    private var sessionSeq = 0L
    private val sessionLock = Any()

    /**
     * Новый tun (новая сессия): всё, что видели до этой минуты, — «прежние» соединения. [out] — запись в
     * tun этой сессии; [resetting] = false — только следить (проверочный подъём подбора). Возвращает номер
     * сессии — для [sessionEnd].
     */
    fun sessionBegin(out: ((ByteArray) -> Unit)?, resetting: Boolean): Long = synchronized(sessionLock) {
        sessionStart = clock()
        output = out
        this.resetting = resetting
        sessionSeq++
        sessionId = sessionSeq
        sessionId
    }

    /**
     * Туннеля сессии [id] больше нет: писать сбросы некуда. Уже началась другая (прежнюю закрывали в фоне,
     * а новая успела подняться) — её не трогаем. [id] = 0 — закончить любую.
     */
    fun sessionEnd(id: Long = 0L) = synchronized(sessionLock) {
        if (id != 0L && id != sessionId) return@synchronized
        output = null
        sessionId = 0L
    }

    /**
     * Прежние соединения, которые пора сбросить: [all] — все живые (сеть сменилась), иначе только те,
     * что уже ждали ответа хотя бы [STALL_AT_UP_MS]. Закрытые и давно молчащие заодно забываем.
     */
    fun staleFlows(all: Boolean): List<Flow> {
        val now = clock()
        val start = sessionStart
        val out = ArrayList<Flow>()
        for ((k, f) in flows) {
            if (f.resetAt > 0L) continue
            if (start > 0L && f.created >= start) continue
            if (f.finUp && f.finDown) {
                flows.remove(k, f)
                continue
            }
            if (now - maxOf(f.lastUp, f.lastDown) > FORGET_MS) {
                flows.remove(k, f)
                continue
            }
            val waiting = f.waitSince > 0L && now - f.waitSince >= STALL_AT_UP_MS
            if (all || waiting) out += f
        }
        return out
    }

    /** Сбросить соединения [list]: сколько сброшено. */
    fun reset(list: List<Flow>): Int {
        if (!resetting) return 0
        var n = 0
        for (f in list) if (resetFlow(f)) n++
        return n
    }

    // ------------------------------------------------------------------------- пакеты

    /**
     * Пакет от приложения (прочитан из tun). true — пакет не отдавать в выходы: это соединение мы уже
     * сбросили (или сбрасываем прямо сейчас).
     */
    fun up(p: ByteArray, off: Int, len: Int): Boolean {
        val s = parse(p, off, len) ?: return false
        val now = clock()
        val key = keyOf(s.v6, p, s.srcOff, s.dstOff, s.sport, s.dport)
        val synOnly = (s.flags and TcpPacket.SYN) != 0 && (s.flags and TcpPacket.ACK) == 0
        val rst = (s.flags and TcpPacket.RST) != 0
        var f = flows[key]
        if (f != null && f.resetAt > 0L) {
            when {
                // То же сочетание портов, но новое соединение — забываем сброшенное.
                synOnly -> {
                    flows.remove(key, f)
                    f = null
                }
                now - f.resetAt < RESET_HOLD_MS -> {
                    // «Challenge ACK» (RFC 5961): сброс не совпал с ожидаемым номером, и приложение
                    // подтвердило, чего ждёт, — второй сброс ровно с этим номером.
                    if (!rst && (s.flags and TcpPacket.ACK) != 0 && s.payload == 0 &&
                        (s.flags and (TcpPacket.SYN or TcpPacket.FIN)) == 0
                    ) {
                        emitRst(f, s.ack)
                    }
                    return true
                }
                else -> {
                    flows.remove(key, f)
                    return false
                }
            }
        }
        // SYN по сочетанию портов уже закрытого (или чужого по номеру) соединения — это новое соединение.
        if (f != null && synOnly && (f.finUp || f.finDown || f.created == 0L || (f.appKnown && s.seq + 1 != f.appNext))) {
            flows.remove(key, f)
            f = null
        }
        if (f == null) {
            if (rst) return false
            if (flows.size >= MAX_FLOWS) prune(now)
            val n = if (s.v6) 16 else 4
            val fresh = Flow(
                s.v6, p.copyOfRange(s.srcOff, s.srcOff + n), s.sport, p.copyOfRange(s.dstOff, s.dstOff + n), s.dport,
                created = if (synOnly) now else 0L
            )
            f = flows.putIfAbsent(key, fresh) ?: fresh
        }
        f.lastUp = now
        if (rst) {
            flows.remove(key, f)
            return false
        }
        val adv = s.payload + (if ((s.flags and TcpPacket.SYN) != 0) 1 else 0) + (if ((s.flags and TcpPacket.FIN) != 0) 1 else 0)
        val end = s.seq + adv
        if (!f.appKnown || after(end, f.appNext)) {
            f.appNext = end
            f.appKnown = true
        }
        if ((s.flags and TcpPacket.ACK) != 0) {
            f.appAck = s.ack
            f.ackKnown = true
        }
        if ((s.flags and TcpPacket.FIN) != 0) f.finUp = true
        if (adv > 0 && f.waitSince == 0L) f.waitSince = now
        // Прежнее соединение, по которому приложение шлёт, а сервер молчит, пока туннель другие пакеты
        // получает: сессия у сервера уже не та — сбрасываем, приложение откроет новое.
        val start = sessionStart
        if (resetting && start > 0L && f.created < start && f.waitSince > 0L && !(f.finUp && f.finDown)) {
            val since = maxOf(f.waitSince, start)
            if (now - since >= staleMs && lastAnyDown > since && resetFlow(f)) {
                reactiveResets.incrementAndGet()
                runCatching { onReactive?.invoke(f) }
                return true
            }
        }
        return false
    }

    /** Пакет к приложению (пишется в tun). */
    fun down(p: ByteArray, off: Int, len: Int) {
        if (emitting.get() == true) return
        val now = clock()
        lastAnyDown = now
        val s = parse(p, off, len) ?: return
        val key = keyOf(s.v6, p, s.dstOff, s.srcOff, s.dport, s.sport)
        val f = flows[key] ?: return
        f.lastDown = now
        f.waitSince = 0L
        if ((s.flags and TcpPacket.RST) != 0) {
            flows.remove(key, f)
            return
        }
        val adv = s.payload + (if ((s.flags and TcpPacket.SYN) != 0) 1 else 0) + (if ((s.flags and TcpPacket.FIN) != 0) 1 else 0)
        val end = s.seq + adv
        if (!f.srvKnown || after(end, f.srvNext)) {
            f.srvNext = end
            f.srvKnown = true
        }
        if ((s.flags and TcpPacket.FIN) != 0) f.finDown = true
    }

    // ------------------------------------------------------------------------- сброс

    private fun resetFlow(f: Flow): Boolean {
        val out = output ?: return false
        if (f.resetAt > 0L) return false
        f.resetAt = clock()
        // Номер, которого ждёт приложение: его последнее подтверждение, а если после него сервер успел
        // прислать ещё (подтверждение отложено) — конец присланного. Не видели ни того, ни другого
        // (только SYN) — номер не важен: сброс в ответ на SYN принимается по полю ACK.
        val seqs = LinkedHashSet<Int>(4)
        if (f.ackKnown) seqs += f.appAck
        if (f.srvKnown) seqs += f.srvNext
        if (seqs.isEmpty()) seqs += 0
        for (seq in seqs) emit(out, f, seq)
        resets.incrementAndGet()
        return true
    }

    private fun emitRst(f: Flow, seq: Int) {
        val out = output ?: return
        emit(out, f, seq)
    }

    private fun emit(out: (ByteArray) -> Unit, f: Flow, seq: Int) {
        val pkt = TcpPacket.build(
            f.v6, f.srv, f.app, f.srvPort, f.appPort, seq, f.appNext, TcpPacket.RST or TcpPacket.ACK, 0
        )
        emitting.set(true)
        try {
            out(pkt)
        } catch (e: Exception) {
            // tun закрыт — сбрасывать уже нечего.
        } finally {
            emitting.set(false)
        }
    }

    private fun prune(now: Long) {
        flows.entries.removeIf { (_, f) ->
            (f.finUp && f.finDown) || now - maxOf(f.lastUp, f.lastDown) > PRUNE_IDLE_MS ||
                (f.resetAt > 0L && now - f.resetAt > RESET_HOLD_MS)
        }
        if (flows.size < MAX_FLOWS) return
        // Всё ещё много — забываем самые давние.
        flows.entries.sortedBy { maxOf(it.value.lastUp, it.value.lastDown) }
            .take(flows.size - MAX_FLOWS * 3 / 4)
            .forEach { flows.remove(it.key, it.value) }
    }

    // ----------------------------------------------------------------------- обёртки tun

    /** Чтение tun: каждый пакет — через [up]; пакеты сброшенных соединений не выходят наружу. */
    inner class In(private val raw: InputStream) : InputStream() {
        override fun read(): Int {
            val one = ByteArray(1)
            val n = read(one, 0, 1)
            return if (n <= 0) -1 else one[0].toInt() and 0xFF
        }

        override fun read(b: ByteArray, off: Int, len: Int): Int {
            while (true) {
                val n = raw.read(b, off, len)
                if (n <= 0) return n
                val drop = try {
                    up(b, off, n)
                } catch (e: Exception) {
                    false
                }
                if (!drop) return n
            }
        }

        override fun available(): Int = raw.available()

        override fun close() = raw.close()
    }

    /** Запись в tun: каждый пакет — через [down]. */
    inner class Out(private val raw: OutputStream) : OutputStream() {
        override fun write(b: Int) = raw.write(b)

        override fun write(b: ByteArray, off: Int, len: Int) {
            try {
                down(b, off, len)
            } catch (e: Exception) {
                // разбор не должен мешать записи
            }
            raw.write(b, off, len)
        }

        override fun flush() = raw.flush()

        override fun close() = raw.close()
    }

    // ---------------------------------------------------------------------------- разбор

    private fun parse(p: ByteArray, off: Int, len: Int): Parsed? {
        if (len < 20 || off < 0 || off + len > p.size) return null
        val ipLen: Int
        val total: Int
        val srcOff: Int
        val dstOff: Int
        val v6: Boolean
        when ((p[off].toInt() ushr 4) and 0x0F) {
            4 -> {
                ipLen = (p[off].toInt() and 0x0F) * 4
                if (ipLen < 20 || (p[off + 9].toInt() and 0xFF) != 6) return null
                // Не первый фрагмент — заголовка TCP в нём нет.
                if ((((p[off + 6].toInt() and 0x1F) shl 8) or (p[off + 7].toInt() and 0xFF)) != 0) return null
                total = minOf(len, u16(p, off + 2))
                srcOff = off + 12
                dstOff = off + 16
                v6 = false
            }

            6 -> {
                ipLen = 40
                if (len < 60 || (p[off + 6].toInt() and 0xFF) != 6) return null
                total = minOf(len, 40 + u16(p, off + 4))
                srcOff = off + 8
                dstOff = off + 24
                v6 = true
            }

            else -> return null
        }
        if (total < ipLen + 20) return null
        val t = off + ipLen
        val doff = ((p[t + 12].toInt() ushr 4) and 0x0F) * 4
        if (doff < 20 || ipLen + doff > total) return null
        return Parsed(
            v6, srcOff, dstOff, u16(p, t), u16(p, t + 2), s32(p, t + 4), s32(p, t + 8),
            p[t + 13].toInt() and 0xFF, total - ipLen - doff
        )
    }

    private fun keyOf(v6: Boolean, p: ByteArray, appOff: Int, srvOff: Int, appPort: Int, srvPort: Int): Key =
        if (v6) {
            Key(true, s64(p, appOff), s64(p, appOff + 8), s64(p, srvOff), s64(p, srvOff + 8), (appPort shl 16) or srvPort)
        } else {
            Key(false, s32(p, appOff).toLong() and 0xFFFFFFFFL, s32(p, srvOff).toLong() and 0xFFFFFFFFL, 0L, 0L, (appPort shl 16) or srvPort)
        }

    companion object {
        /** Ответа по прежнему соединению нет столько — сбрасываем. */
        const val STALE_MS = 4_000L

        /** К подъёму сессии соединение ждало ответа столько — зависло на обрыве, сбрасываем сразу. */
        const val STALL_AT_UP_MS = 1_500L

        /** Сколько после сброса глотаем пакеты соединения и отвечаем на «challenge ACK». */
        const val RESET_HOLD_MS = 10_000L

        /** Соединение молчит дольше — забываем при ближайшем просмотре. */
        const val FORGET_MS = 30 * 60_000L

        /** При переполнении забываем молчащие дольше этого. */
        const val PRUNE_IDLE_MS = 10 * 60_000L

        const val MAX_FLOWS = 2048

        /** a «после» b в пространстве номеров TCP (по модулю 2³²). */
        internal fun after(a: Int, b: Int): Boolean = a - b > 0

        private fun u16(b: ByteArray, i: Int): Int = ((b[i].toInt() and 0xFF) shl 8) or (b[i + 1].toInt() and 0xFF)

        private fun s32(b: ByteArray, i: Int): Int =
            ((b[i].toInt() and 0xFF) shl 24) or ((b[i + 1].toInt() and 0xFF) shl 16) or
                ((b[i + 2].toInt() and 0xFF) shl 8) or (b[i + 3].toInt() and 0xFF)

        private fun s64(b: ByteArray, i: Int): Long =
            (s32(b, i).toLong() shl 32) or (s32(b, i + 4).toLong() and 0xFFFFFFFFL)
    }
}
