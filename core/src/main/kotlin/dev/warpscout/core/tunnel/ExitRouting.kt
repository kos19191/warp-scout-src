package dev.warpscout.core.tunnel

import java.io.InputStream
import java.io.OutputStream
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit

/**
 * Второй выход: «эти IP — через другой сервер, остальное — через основной».
 *
 * Зачем: WARP anycast, страну выхода выбрать нельзя. Единственный честный способ получить
 * «ChatGPT через Германию, а всё остальное через WARP» — держать **два туннеля одновременно**
 * (в одном tun-интерфейсе) и раскладывать пакеты по адресу назначения. Таблица ниже и есть
 * это правило: подсети (полученные из доменов через DoH) → номер выхода.
 *
 * 0 — основной выход (WARP), 1 — второй.
 */
class ExitRouter private constructor(
    private val v4ByLen: Map<Int, Set<Int>>,
    private val v6Exact: Set<String>,
    /** Исходные CIDR'ы — нужны сервису, чтобы добавить маршруты в tun (в split-режиме). */
    val cidrs: List<String>
) {

    val size: Int get() = v4ByLen.values.sumOf { it.size } + v6Exact.size
    val isEmpty: Boolean get() = size == 0

    /** Куда отправить пакет с таким адресом назначения (сырые байты: 4 или 16). */
    fun route(dst: ByteArray): Int {
        if (dst.size == 4) {
            val ip = u32(dst, 0)
            for (len in 32 downTo 1) {
                val set = v4ByLen[len] ?: continue
                if (set.contains(ip ushr (32 - len))) return 1
            }
            // /0 отдельно: сдвиг на 32 в Java не сдвигает, поэтому проверяем самим фактом наличия.
            if (v4ByLen[0]?.isNotEmpty() == true) return 1
            return 0
        }
        if (dst.size == 16) {
            return if (v6Exact.contains(hex16(dst, 0))) 1 else 0
        }
        return 0
    }

    companion object {

        val EMPTY: ExitRouter = ExitRouter(emptyMap(), emptySet(), emptyList())

        /** Разбор строки «1.2.3.0/24, 5.6.7.8/32» или списка строк. */
        fun parse(text: String): List<String> = text
            .split(',', '\n', '\r', ';', ' ', '\t')
            .map { it.trim() }
            .filter { it.isNotEmpty() }

        fun of(cidrs: List<String>): ExitRouter {
            val v4 = HashMap<Int, MutableSet<Int>>()
            val v6 = HashSet<String>()
            val kept = ArrayList<String>()
            cidrs.forEach { raw ->
                val item = raw.trim()
                if (item.isEmpty() || '/' !in item) return@forEach
                val host = item.substringBefore('/')
                val len = item.substringAfter('/').toIntOrNull() ?: return@forEach
                val bytes = ipBytes(host) ?: return@forEach
                when (bytes.size) {
                    4 -> {
                        if (len !in 0..32) return@forEach
                        val ip = u32(bytes, 0)
                        // Храним ровно старшие len бит — по ним и сравниваем при маршрутизации.
                        v4.getOrPut(len) { HashSet() }.add(if (len == 0) 0 else ip ushr (32 - len))
                        kept += item
                    }

                    16 -> {
                        // Для доменных адресов хватает точного совпадения: DoH отдаёт /128.
                        if (len != 128) return@forEach
                        v6.add(hex16(bytes, 0))
                        kept += item
                    }
                }
            }
            return ExitRouter(v4, v6, kept)
        }

        private fun u32(b: ByteArray, off: Int): Int =
            ((b[off].toInt() and 0xFF) shl 24) or
                ((b[off + 1].toInt() and 0xFF) shl 16) or
                ((b[off + 2].toInt() and 0xFF) shl 8) or
                (b[off + 3].toInt() and 0xFF)

        private fun hex16(b: ByteArray, off: Int): String {
            val sb = StringBuilder(32)
            for (i in 0 until 16) sb.append(String.format("%02x", b[off + i]))
            return sb.toString()
        }

        /** Строковый IP → байты (IPv4 или IPv6). null — если не разобралось. */
        fun ipBytes(text: String): ByteArray? = runCatching {
            val addr = java.net.InetAddress.getByName(text)
            addr.address
        }.getOrNull()
    }
}

/** Минимальный разбор IP-пакета из tun: нужен только адрес назначения. */
object IpPacket {

    /** 4 — IPv4, 6 — IPv6, 0 — не IP. */
    fun version(raw: ByteArray): Int = if (raw.isEmpty()) 0 else (raw[0].toInt() shr 4) and 0x0F

    fun dst(raw: ByteArray): ByteArray? = when (version(raw)) {
        4 -> if (raw.size < 20) null else raw.copyOfRange(16, 20)
        6 -> if (raw.size < 40) null else raw.copyOfRange(24, 40)
        else -> null
    }

    fun protocol(raw: ByteArray): Int = when (version(raw)) {
        4 -> if (raw.size > 9) raw[9].toInt() and 0xFF else -1
        6 -> if (raw.size > 6) raw[6].toInt() and 0xFF else -1
        else -> -1
    }
}

/**
 * Очередь пакетов, которую [DataPlane] читает как обычный поток. Нужна, чтобы два data plane
 * (два выхода) могли жить на одном tun: читает tun только диспетчер, а пакеты раскладывает по
 * очередям согласно [ExitRouter].
 */
class PacketQueueIn(private val name: String) : InputStream() {

    private val queue = LinkedBlockingQueue<ByteArray>()
    @Volatile
    private var closed = false

    fun offer(packet: ByteArray) {
        if (!closed) queue.offer(packet)
    }

    /** Очередь закрыта — выход больше не обслуживается (диспетчер тогда вернётся к основному). */
    fun isClosed(): Boolean = closed

    override fun read(): Int {
        val buf = ByteArray(1)
        val n = read(buf, 0, 1)
        return if (n <= 0) -1 else buf[0].toInt() and 0xFF
    }

    override fun read(b: ByteArray, off: Int, len: Int): Int {
        while (true) {
            if (closed && queue.isEmpty()) return -1
            val packet = queue.poll(250, TimeUnit.MILLISECONDS) ?: continue
            val n = minOf(len, packet.size)
            System.arraycopy(packet, 0, b, off, n)
            return n
        }
    }

    override fun close() {
        closed = true
    }

    /**
     * Отдельный читатель очереди (с 1.10.31): его закрытие не закрывает саму очередь. Второй выход
     * меняет сервер (автопоиск Proton Free) — data plane прежнего сервера при остановке закрывает
     * свой вход, и без этого очередь закрылась бы вместе с ним: диспетчер вернул бы сайты второго
     * выхода в WARP на время смены сервера.
     */
    fun view(): InputStream = object : InputStream() {
        @Volatile
        private var viewClosed = false

        override fun read(): Int {
            val buf = ByteArray(1)
            val n = read(buf, 0, 1)
            return if (n <= 0) -1 else buf[0].toInt() and 0xFF
        }

        override fun read(b: ByteArray, off: Int, len: Int): Int {
            while (true) {
                if (viewClosed || (closed && queue.isEmpty())) return -1
                val packet = queue.poll(250, TimeUnit.MILLISECONDS) ?: continue
                // Вид закрыли, пока ждали: пакет теряется (TCP повторит), очередь — нет.
                if (viewClosed) return -1
                val n = minOf(len, packet.size)
                System.arraycopy(packet, 0, b, off, n)
                return n
            }
        }

        override fun close() {
            viewClosed = true
        }
    }

    override fun toString(): String = "PacketQueueIn($name)"
}

/** Один выход в tun для нескольких data plane: записи не должны перемешиваться. */
class SharedPacketOut(private val out: OutputStream) : OutputStream() {

    override fun write(b: Int) = write(byteArrayOf(b.toByte()), 0, 1)

    override fun write(b: ByteArray, off: Int, len: Int) {
        synchronized(this) { out.write(b, off, len) }
    }

    override fun close() {
        // Реальный дескриптор закрывает сервис, а не один из выходов.
    }
}

/**
 * Читает tun и раскладывает пакеты: адрес назначения → [ExitRouter] → очередь нужного выхода.
 * Пакеты, для которых выхода нет, отбрасываются (их не должно быть: маршруты в tun добавляются).
 */
class TunDispatcher(
    private val tun: InputStream,
    router: ExitRouter,
    private val lanes: List<PacketQueueIn>,
    /**
     * Ждать данных в tun (см. `DataPlane.tunReady`). Дескриптор tun неблокирующий: пустое чтение
     * возвращает 0, и раньше диспетчер принимал его за конец потока и останавливался сразу после
     * запуска — второй выход в раздельном режиме молча не работал.
     */
    private val tunReady: ((Long) -> Boolean)? = null,
    private val log: (String) -> Unit = {}
) : Runnable {

    @Volatile
    private var stopped = false

    /**
     * Таблица «адрес → выход». Меняется на лету (с 1.10.31): адреса сайтов второго выхода
     * обновляются раз в сутки, и ради новой таблицы рвать работающий туннель незачем.
     */
    @Volatile
    var router: ExitRouter = router

    var sentPrimary: Long = 0L
        private set
    var sentSecondary: Long = 0L
        private set
    var dropped: Long = 0L
        private set

    fun stop() {
        stopped = true
        lanes.forEach { runCatching { it.close() } }
    }

    override fun run() {
        val buf = ByteArray(65535)
        while (!stopped) {
            val n = try {
                tun.read(buf)
            } catch (e: Exception) {
                -1
            }
            if (n < 0) break
            if (n == 0) {
                // Пусто — ждём пакет, а не выходим: 0 у неблокирующего tun значит «пока нечего».
                val waitTun = tunReady
                if (waitTun == null || !runCatching { waitTun(5_000L) }.getOrDefault(false)) {
                    if (!stopped) runCatching { Thread.sleep(20) }
                }
                continue
            }
            val packet = buf.copyOf(n)
            val dst = IpPacket.dst(packet)
            if (dst == null) {
                dropped++
                continue
            }
            val wanted = router.route(dst)
            // Если второй выход отказал (сессию не поднял или умер), его подсети не теряются:
            // трафик возвращается в основной туннель — регион будет не тот, зато сайт работает.
            val lane = when {
                wanted !in lanes.indices -> 0
                lanes[wanted].isClosed() -> 0
                else -> wanted
            }
            if (lane in lanes.indices) {
                lanes[lane].offer(packet)
                if (lane == 0) sentPrimary++ else sentSecondary++
            } else {
                dropped++
            }
        }
        lanes.forEach { runCatching { it.close() } }
        log("диспетчер tun остановлен")
    }
}
