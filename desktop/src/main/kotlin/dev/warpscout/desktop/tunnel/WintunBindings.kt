package dev.warpscout.desktop.tunnel

import com.sun.jna.Library
import com.sun.jna.Native
import com.sun.jna.Pointer
import com.sun.jna.WString
import com.sun.jna.platform.win32.Guid
import com.sun.jna.platform.win32.Kernel32
import com.sun.jna.platform.win32.WinNT
import com.sun.jna.ptr.IntByReference
import com.sun.jna.ptr.LongByReference
import java.io.File
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Абстракция виртуального TUN-устройства (пакетные потоки `InputStream`/`OutputStream`).
 * На Windows реализуется через [WintunDevice], в тестах — через парные очереди в памяти.
 */
interface TunDevice : AutoCloseable {
    val adapterName: String
    val input: InputStream
    val output: OutputStream
}

/** Прямые JNA-привязки к официальной библиотеке `wintun.dll` (https://www.wintun.net). */
interface WintunApi : Library {
    fun WintunCreateAdapter(name: WString, tunnelType: WString, requestedGuid: Guid.GUID?): Pointer?
    fun WintunOpenAdapter(name: WString): Pointer?
    fun WintunCloseAdapter(adapter: Pointer)
    fun WintunGetAdapterLUID(adapter: Pointer, luid: LongByReference)
    fun WintunGetRunningDriverVersion(): Int
    fun WintunStartSession(adapter: Pointer, capacity: Int): Pointer?
    fun WintunEndSession(session: Pointer)
    fun WintunGetReadWaitEvent(session: Pointer): Pointer?
    fun WintunReceivePacket(session: Pointer, packetSize: IntByReference): Pointer?
    fun WintunReleaseReceivePacket(session: Pointer, packet: Pointer)
    fun WintunAllocateSendPacket(session: Pointer, packetSize: Int): Pointer?
    fun WintunSendPacket(session: Pointer, packet: Pointer)
}

/**
 * Поиск и извлечение встроенного драйвера `wintun.dll`.
 *
 * Порядок поиска:
 *  1. `bin/wintun.dll` или `wintun.dll` рядом с `WarpScout.exe` / рабочим каталогом;
 *  2. встроенный ресурс `/native/win32-x86-64/wintun.dll` внутри сборки (автоматически
 *     извлекается в `%APPDATA%\WarpScout\native\wintun.dll`).
 */
object WintunLoader {

    private const val RESOURCE_PATH = "/native/win32-x86-64/wintun.dll"

    @Volatile
    private var cachedApi: WintunApi? = null

    fun findOrExtractDll(nativeCacheDir: File, appDir: File = File(System.getProperty("user.dir") ?: ".")): File? {
        val jpackageDir = System.getProperty("jpackage.app-path")?.let { File(it).parentFile }
        val candidates = listOfNotNull(
            jpackageDir?.let { File(it, "bin/wintun.dll") },
            jpackageDir?.let { File(it, "wintun.dll") },
            File(appDir, "bin/wintun.dll"),
            File(appDir, "wintun.dll")
        )
        for (f in candidates) {
            if (f.isFile && f.length() > 10_000L) return f
        }

        // Извлекаем встроенный wintun.dll из ресурсов приложения.
        val stream = WintunLoader::class.java.getResourceAsStream(RESOURCE_PATH) ?: return null
        return runCatching {
            nativeCacheDir.mkdirs()
            val target = File(nativeCacheDir, "wintun.dll")
            val bytes = stream.use { it.readBytes() }
            if (bytes.size < 10_000) return@runCatching null
            if (!target.exists() || target.length() != bytes.size.toLong()) {
                target.writeBytes(bytes)
            }
            target
        }.getOrNull()
    }

    fun isAvailable(nativeCacheDir: File): Boolean =
        findOrExtractDll(nativeCacheDir) != null

    @Synchronized
    fun load(nativeCacheDir: File): WintunApi {
        cachedApi?.let { return it }
        val dll = findOrExtractDll(nativeCacheDir)
            ?: throw IllegalStateException("Встроенный драйвер wintun.dll не найден в сборке")
        val api = Native.load(dll.absolutePath, WintunApi::class.java)
        cachedApi = api
        return api
    }
}

/**
 * Реальное TUN-устройство Windows поверх `wintun.dll`.
 *
 * Потоки `input` и `output` — строго пакетные:
 *  • один `input.read(buf)` возвращает ровно один IP-пакет из кольцевого буфера Wintun;
 *  • один `output.write(buf, off, len)` отправляет ровно один IP-пакет в Wintun.
 * Это напрямую совпадает с ожиданиями `DataPlane` и `TunDispatcher` из `:core`.
 */
class WintunDevice private constructor(
    override val adapterName: String,
    private val api: WintunApi,
    private val adapter: Pointer,
    private val session: Pointer,
    private val readEvent: WinNT.HANDLE?
) : TunDevice {

    private val closed = AtomicBoolean(false)
    private val writeLock = Any()

    override val input: InputStream = object : InputStream() {
        private val sizeRef = IntByReference()

        override fun read(): Int {
            val one = ByteArray(1)
            val n = read(one, 0, 1)
            return if (n <= 0) -1 else one[0].toInt() and 0xFF
        }

        override fun read(b: ByteArray, off: Int, len: Int): Int {
            while (!closed.get()) {
                val pktPtr = api.WintunReceivePacket(session, sizeRef)
                if (pktPtr != null) {
                    return try {
                        val pktLen = sizeRef.value
                        val copyLen = minOf(pktLen, len)
                        if (copyLen > 0) {
                            pktPtr.read(0L, b, off, copyLen)
                        }
                        copyLen
                    } finally {
                        api.WintunReleaseReceivePacket(session, pktPtr)
                    }
                }
                val err = Native.getLastError()
                when (err) {
                    ERROR_NO_MORE_ITEMS -> {
                        if (readEvent != null) {
                            Kernel32.INSTANCE.WaitForSingleObject(readEvent, 200)
                        } else {
                            runCatching { Thread.sleep(5) }
                        }
                    }
                    ERROR_HANDLE_EOF, ERROR_DEVICE_NOT_CONNECTED, ERROR_OPERATION_ABORTED -> return -1
                    else -> {
                        if (closed.get()) return -1
                        runCatching { Thread.sleep(10) }
                    }
                }
            }
            return -1
        }

        override fun close() {
            this@WintunDevice.close()
        }
    }

    override val output: OutputStream = object : OutputStream() {
        override fun write(b: Int) = write(byteArrayOf(b.toByte()), 0, 1)

        override fun write(b: ByteArray, off: Int, len: Int) {
            if (closed.get()) throw IOException("Wintun-сессия закрыта")
            if (len <= 0) return
            synchronized(writeLock) {
                if (closed.get()) throw IOException("Wintun-сессия закрыта")
                val sendPtr = api.WintunAllocateSendPacket(session, len)
                if (sendPtr == null) {
                    val err = Native.getLastError()
                    if (err == ERROR_BUFFER_OVERFLOW) {
                        // Кольцевой буфер временно заполнен — дропаем пакет, как делает обычный NIC.
                        return
                    }
                    throw IOException("WintunAllocateSendPacket error=$err")
                }
                sendPtr.write(0L, b, off, len)
                api.WintunSendPacket(session, sendPtr)
            }
        }

        override fun close() {
            this@WintunDevice.close()
        }
    }

    fun adapterLuid(): Long {
        val ref = LongByReference()
        api.WintunGetAdapterLUID(adapter, ref)
        return ref.value
    }

    override fun close() {
        if (!closed.compareAndSet(false, true)) return
        synchronized(writeLock) {
            runCatching { api.WintunEndSession(session) }
            runCatching { api.WintunCloseAdapter(adapter) }
        }
    }

    companion object {
        private const val RING_CAPACITY = 0x400000 // 4 МБ — быстрый кольцевой буфер Wintun.
        private const val ERROR_NO_MORE_ITEMS = 259
        private const val ERROR_HANDLE_EOF = 38
        private const val ERROR_BUFFER_OVERFLOW = 111
        private const val ERROR_OPERATION_ABORTED = 995
        private const val ERROR_DEVICE_NOT_CONNECTED = 1167

        /** Постоянный GUID адаптера WarpScout, чтобы Windows не плодила «WarpScout 2, 3…». */
        private val ADAPTER_GUID = Guid.GUID("{E47A3C19-9D81-4B27-A6F4-8215D3C04E71}")

        fun open(name: String, nativeCacheDir: File): WintunDevice {
            val api = WintunLoader.load(nativeCacheDir)
            // Если от предыдущего падения остался старый адаптер — аккуратно переиспользуем или пересоздаём.
            val existing = runCatching { api.WintunOpenAdapter(WString(name)) }.getOrNull()
            if (existing != null) {
                runCatching { api.WintunCloseAdapter(existing) }
            }
            val adapter = api.WintunCreateAdapter(WString(name), WString("WarpScout"), ADAPTER_GUID)
                ?: throw IOException(
                    "Не удалось создать Wintun-адаптер (код Windows ${Native.getLastError()}). " +
                        "Для создания виртуального сетевого адаптера требуются права администратора."
                )
            val session = api.WintunStartSession(adapter, RING_CAPACITY)
            if (session == null) {
                val err = Native.getLastError()
                runCatching { api.WintunCloseAdapter(adapter) }
                throw IOException("Не удалось запустить Wintun-сессию (код Windows $err)")
            }
            val eventPtr = api.WintunGetReadWaitEvent(session)
            val eventHandle = eventPtr?.let { WinNT.HANDLE(it) }
            return WintunDevice(name, api, adapter, session, eventHandle)
        }
    }
}
