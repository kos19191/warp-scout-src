package dev.warpscout.desktop.tunnel

import com.sun.jna.Library
import com.sun.jna.Native
import com.sun.jna.Pointer
import com.sun.jna.platform.win32.Advapi32Util
import com.sun.jna.platform.win32.WinReg
import dev.warpscout.core.dpi.DpiComparison
import dev.warpscout.core.dpi.DpiComparator
import dev.warpscout.core.model.ResourceCheck
import dev.warpscout.core.net.Socks5Endpoint
import java.io.File
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

/** Готовая проверенная стратегия обхода DPI для ByeDPI (`ciadpi.exe`) на Windows. */
data class ByeDpiPreset(
    val id: String,
    val title: String,
    val subtitle: String,
    val args: List<String>
)

data class ByeDpiSnapshot(
    val running: Boolean = false,
    val available: Boolean = false,
    val binaryPath: String? = null,
    val host: String = "127.0.0.1",
    val port: Int = 1080,
    val presetId: String = ByeDpiPresets.DEFAULT_ID,
    val presetTitle: String = ByeDpiPresets.byId(ByeDpiPresets.DEFAULT_ID).title,
    val systemProxyEnabled: Boolean = false,
    val statusMessage: String = "ByeDPI выключен",
    val lastError: String? = null
) {
    val socksAddress: String get() = "$host:$port"
}

object ByeDpiPresets {
    const val DEFAULT_ID = "auto-universal"
    const val CUSTOM_ID = "custom"

    /**
     * Проверенные Windows-совместимые стратегии `ciadpi.exe` (без Linux-only `--md5sig`).
     * Автоматический режим `--auto=torst` сначала пускает трафик без искажений и включает
     * обход только для доменов, где ТСПУ рвёт соединение (RST/таймаут), кэшируя выбор.
     */
    val BUILTIN: List<ByeDpiPreset> = listOf(
        ByeDpiPreset(
            id = "auto-universal",
            title = "Универсальный РФ",
            subtitle = "Автоподбор при RST/таймауте: disorder+tlsrec → oob → split + UDP fake",
            args = listOf(
                "--auto=torst", "--timeout", "3",
                "--disorder", "1", "--tlsrec", "1+s", "--udp-fake", "1",
                "--auto=torst", "--oob", "1+s",
                "--auto=torst", "--split", "1+s"
            )
        ),
        ByeDpiPreset(
            id = "disorder-tlsrec",
            title = "TLS + Disorder",
            subtitle = "Разбиение TLS-записи и перестановка сегментов по SNI (YouTube / Discord)",
            args = listOf("--disorder", "1", "--tlsrec", "1+s", "--udp-fake", "1")
        ),
        ByeDpiPreset(
            id = "disorder-fake",
            title = "Fake + Disorder",
            subtitle = "Фейковый пакет с TTL=8 + disorder (рекомендовано ByeDPI для Windows)",
            args = listOf("--disorder", "1", "--fake", "-1", "--ttl", "8", "--udp-fake", "1")
        ),
        ByeDpiPreset(
            id = "oob-split",
            title = "OOB + Split",
            subtitle = "Внеканальный байт URG и разбиение в середине SNI",
            args = listOf("--oob", "1+s", "--split", "2+s", "--tlsrec", "1+s")
        ),
        ByeDpiPreset(
            id = CUSTOM_ID,
            title = "Свои аргументы",
            subtitle = "Произвольные флаги ciadpi (без -i / -p, они подставляются автоматически)",
            args = emptyList()
        )
    )

    val TUNABLE: List<ByeDpiPreset> = BUILTIN.filter { it.id != CUSTOM_ID }

    fun byId(id: String): ByeDpiPreset =
        BUILTIN.firstOrNull { it.id == id } ?: BUILTIN.first()

    /** Разбирает строку пользовательских флагов с поддержкой одинарных/двойных кавычек. */
    fun tokenizeArgs(raw: String): List<String> {
        val out = ArrayList<String>()
        val cur = StringBuilder()
        var quote: Char? = null
        var i = 0
        while (i < raw.length) {
            val ch = raw[i]
            when {
                quote != null -> {
                    if (ch == quote) quote = null else cur.append(ch)
                }
                ch == '"' || ch == '\'' -> quote = ch
                ch.isWhitespace() -> {
                    if (cur.isNotEmpty()) {
                        out.add(cur.toString())
                        cur.clear()
                    }
                }
                else -> cur.append(ch)
            }
            i++
        }
        if (cur.isNotEmpty()) out.add(cur.toString())
        return out
    }

    /** Собирает полный список аргументов для запуска `ciadpi.exe`. */
    fun buildCommand(
        binary: File,
        host: String,
        port: Int,
        presetId: String,
        customArgs: String = ""
    ): List<String> {
        val extra = if (presetId == CUSTOM_ID) {
            tokenizeArgs(customArgs).ifEmpty { byId(DEFAULT_ID).args }
        } else {
            byId(presetId).args
        }
        return buildList {
            add(binary.absolutePath)
            add("-i")
            add(host)
            add("-p")
            add(port.coerceIn(1024, 65535).toString())
            addAll(extra)
        }
    }
}

/** Поиск и извлечение встроенного бинарника `ciadpi.exe` (ByeDPI). */
object ByeDpiLocator {
    private const val RESOURCE_PATH = "/native/win32-x86-64/ciadpi.exe"

    fun findOrExtract(
        nativeCacheDir: File,
        appDir: File = File(System.getProperty("user.dir") ?: ".")
    ): File? {
        val jpackageDir = System.getProperty("jpackage.app-path")?.let { File(it).parentFile }
        val candidates = listOfNotNull(
            jpackageDir?.let { File(it, "bin/ciadpi.exe") },
            jpackageDir?.let { File(it, "ciadpi.exe") },
            File(appDir, "bin/ciadpi.exe"),
            File(appDir, "ciadpi.exe"),
            File(nativeCacheDir, "ciadpi.exe")
        )
        for (f in candidates) {
            if (f.isFile && f.length() > 10_000L) return f
        }

        val stream = ByeDpiLocator::class.java.getResourceAsStream(RESOURCE_PATH) ?: return null
        return runCatching {
            nativeCacheDir.mkdirs()
            val target = File(nativeCacheDir, "ciadpi.exe")
            val bytes = stream.use { it.readBytes() }
            if (bytes.size < 10_000) return@runCatching null
            if (!target.exists() || target.length() != bytes.size.toLong()) {
                target.writeBytes(bytes)
            }
            target
        }.getOrNull()
    }
}

/**
 * Безопасное включение/выключение системного SOCKS5-прокси Windows (HKCU Internet Settings)
 * с обязательным сохранением и восстановлением прежних значений пользователя.
 */
object WindowsSystemProxy {
    private const val REG_PATH = "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings"
    private const val INTERNET_OPTION_SETTINGS_CHANGED = 39
    private const val INTERNET_OPTION_REFRESH = 37

    /** Исключения: локальная сеть и российские домены всегда идут напрямую, минуя прокси. */
    const val DEFAULT_BYPASS =
        "localhost;127.*;10.*;172.16.*;192.168.*;*.ru;*.рф;*.su;*.local;<local>"

    private interface WinInet : Library {
        fun InternetSetOptionW(hInternet: Pointer?, dwOption: Int, lpBuffer: Pointer?, dwBufferLength: Int): Boolean
    }

    private data class SavedProxy(
        val proxyEnable: Int?,
        val proxyServer: String?,
        val proxyOverride: String?
    )

    @Volatile
    private var saved: SavedProxy? = null

    @Volatile
    private var appliedByUs: Boolean = false

    @Synchronized
    fun enableSocks(host: String, port: Int, bypass: String = DEFAULT_BYPASS): Boolean {
        if (!WindowsAutostart.isWindows()) return false
        return runCatching {
            if (!appliedByUs) {
                saved = SavedProxy(
                    proxyEnable = readInt(REG_PATH, "ProxyEnable"),
                    proxyServer = readStr(REG_PATH, "ProxyServer"),
                    proxyOverride = readStr(REG_PATH, "ProxyOverride")
                )
            }
            Advapi32Util.registrySetIntValue(WinReg.HKEY_CURRENT_USER, REG_PATH, "ProxyEnable", 1)
            Advapi32Util.registrySetStringValue(WinReg.HKEY_CURRENT_USER, REG_PATH, "ProxyServer", "socks=$host:$port")
            Advapi32Util.registrySetStringValue(WinReg.HKEY_CURRENT_USER, REG_PATH, "ProxyOverride", bypass)
            appliedByUs = true
            notifySystem()
            true
        }.getOrDefault(false)
    }

    @Synchronized
    fun restore(): Boolean {
        if (!appliedByUs || !WindowsAutostart.isWindows()) return false
        return runCatching {
            val prev = saved
            if (prev?.proxyEnable != null) {
                Advapi32Util.registrySetIntValue(WinReg.HKEY_CURRENT_USER, REG_PATH, "ProxyEnable", prev.proxyEnable)
            } else {
                Advapi32Util.registrySetIntValue(WinReg.HKEY_CURRENT_USER, REG_PATH, "ProxyEnable", 0)
            }
            if (prev?.proxyServer != null) {
                Advapi32Util.registrySetStringValue(WinReg.HKEY_CURRENT_USER, REG_PATH, "ProxyServer", prev.proxyServer)
            } else {
                runCatching { Advapi32Util.registryDeleteValue(WinReg.HKEY_CURRENT_USER, REG_PATH, "ProxyServer") }
            }
            if (prev?.proxyOverride != null) {
                Advapi32Util.registrySetStringValue(WinReg.HKEY_CURRENT_USER, REG_PATH, "ProxyOverride", prev.proxyOverride)
            }
            appliedByUs = false
            saved = null
            notifySystem()
            true
        }.getOrDefault(false)
    }

    private fun readInt(path: String, key: String): Int? = runCatching {
        if (Advapi32Util.registryValueExists(WinReg.HKEY_CURRENT_USER, path, key)) {
            Advapi32Util.registryGetIntValue(WinReg.HKEY_CURRENT_USER, path, key)
        } else null
    }.getOrNull()

    private fun readStr(path: String, key: String): String? = runCatching {
        if (Advapi32Util.registryValueExists(WinReg.HKEY_CURRENT_USER, path, key)) {
            Advapi32Util.registryGetStringValue(WinReg.HKEY_CURRENT_USER, path, key)
        } else null
    }.getOrNull()

    private fun notifySystem() {
        runCatching {
            val wininet = Native.load("wininet", WinInet::class.java)
            wininet.InternetSetOptionW(null, INTERNET_OPTION_SETTINGS_CHANGED, null, 0)
            wininet.InternetSetOptionW(null, INTERNET_OPTION_REFRESH, null, 0)
        }
    }
}

data class ByeDpiTuneResult(
    val bestPresetId: String,
    val bestPresetTitle: String,
    val bestFixedCount: Int,
    val totalChecks: Int,
    val summary: String,
    val comparison: DpiComparison? = null
)

/**
 * Встроенный менеджер обхода DPI на базе `ciadpi.exe` (ByeDPI).
 *
 * Работает полностью в userspace (без драйверов WinDivert), поднимает локальный SOCKS5-прокси
 * `127.0.0.1:<port>`, опционально включает системный прокси Windows (с исключением РФ-доменов и LAN)
 * и умеет через `:core` [DpiComparator] автоматически подбирать лучшую стратегию под провайдера.
 */
class ByeDpiManager(
    private val nativeDir: File,
    private val onState: (ByeDpiSnapshot) -> Unit = {},
    private val onLog: (String) -> Unit = {},
    private val binaryResolver: () -> File? = { ByeDpiLocator.findOrExtract(nativeDir) }
) {
    @Volatile
    var snapshot: ByeDpiSnapshot = ByeDpiSnapshot()
        private set

    init {
        refreshAvailability()
    }

    @Volatile
    private var process: Process? = null

    private val stopping = AtomicBoolean(false)

    private fun update(transform: (ByeDpiSnapshot) -> ByeDpiSnapshot) {
        val next = transform(snapshot)
        snapshot = next
        onState(next)
    }

    fun refreshAvailability(): ByeDpiSnapshot {
        val bin = binaryResolver()
        val next = snapshot.copy(
            available = bin != null,
            binaryPath = bin?.absolutePath
        )
        snapshot = next
        return next
    }

    @Synchronized
    fun start(
        presetId: String,
        port: Int = 1080,
        customArgs: String = "",
        enableSystemProxy: Boolean = false
    ): Boolean {
        stopInternal(logStop = false)
        val bin = binaryResolver()
        if (bin == null || !bin.isFile) {
            val msg = "Файл ciadpi.exe не найден (нужна Windows-сборка WarpScout или bin/ciadpi.exe)"
            onLog(msg)
            update {
                it.copy(
                    running = false,
                    available = false,
                    binaryPath = null,
                    statusMessage = "ciadpi.exe не найден",
                    lastError = msg
                )
            }
            return false
        }

        val cleanPort = port.coerceIn(1024, 65535)
        val preset = ByeDpiPresets.byId(presetId)
        val cmd = ByeDpiPresets.buildCommand(bin, "127.0.0.1", cleanPort, preset.id, customArgs)
        stopping.set(false)

        return try {
            val proc = ProcessBuilder(cmd)
                .directory(bin.parentFile)
                .redirectErrorStream(true)
                .start()
            process = proc

            // Читаем stdout/stderr в фоне, чтобы процесс не заблокировался на переполненном буфере.
            Thread({
                runCatching {
                    proc.inputStream.bufferedReader(Charsets.UTF_8).forEachLine { line ->
                        val t = line.trim()
                        if (t.isNotEmpty()) onLog("[ByeDPI] $t")
                    }
                }
                val code = runCatching { proc.waitFor() }.getOrDefault(-1)
                if (!stopping.get() && process === proc) {
                    WindowsSystemProxy.restore()
                    onLog("ByeDPI неожиданно завершился (код $code)")
                    update {
                        it.copy(
                            running = false,
                            systemProxyEnabled = false,
                            statusMessage = "ByeDPI остановился (код $code)",
                            lastError = "Процесс ciadpi.exe завершился с кодом $code"
                        )
                    }
                }
            }, "warpscout-byedpi-out").apply { isDaemon = true; start() }

            val ready = waitPortOpen("127.0.0.1", cleanPort, timeoutMs = 2500L)
            if (!ready || !proc.isAlive) {
                runCatching { proc.destroyForcibly() }
                process = null
                val msg = "ByeDPI не открыл порт 127.0.0.1:$cleanPort (возможно, порт занят другой программой)"
                onLog(msg)
                update {
                    it.copy(
                        running = false,
                        available = true,
                        binaryPath = bin.absolutePath,
                        systemProxyEnabled = false,
                        statusMessage = "Ошибка запуска ByeDPI",
                        lastError = msg
                    )
                }
                return false
            }

            val sysProxyOk = if (enableSystemProxy) {
                val ok = WindowsSystemProxy.enableSocks("127.0.0.1", cleanPort)
                if (ok) onLog("Системный SOCKS5-прокси Windows включён: 127.0.0.1:$cleanPort (РФ и LAN — напрямую)")
                else onLog("Не удалось включить системный прокси Windows — используйте SOCKS5 127.0.0.1:$cleanPort вручную")
                ok
            } else {
                WindowsSystemProxy.restore()
                false
            }

            onLog("ByeDPI запущен: 127.0.0.1:$cleanPort · стратегия «${preset.title}»")
            update {
                it.copy(
                    running = true,
                    available = true,
                    binaryPath = bin.absolutePath,
                    host = "127.0.0.1",
                    port = cleanPort,
                    presetId = preset.id,
                    presetTitle = preset.title,
                    systemProxyEnabled = sysProxyOk,
                    statusMessage = "ByeDPI работает · 127.0.0.1:$cleanPort (${preset.title})",
                    lastError = null
                )
            }
            true
        } catch (e: Exception) {
            val msg = "Не удалось запустить ciadpi.exe: ${e.message ?: e.javaClass.simpleName}"
            onLog(msg)
            update {
                it.copy(
                    running = false,
                    available = true,
                    binaryPath = bin.absolutePath,
                    systemProxyEnabled = false,
                    statusMessage = "Ошибка запуска ByeDPI",
                    lastError = msg
                )
            }
            false
        }
    }

    @Synchronized
    fun setSystemProxy(enabled: Boolean): Boolean {
        val snap = snapshot
        if (!snap.running) {
            WindowsSystemProxy.restore()
            update { it.copy(systemProxyEnabled = false) }
            return false
        }
        val ok = if (enabled) {
            WindowsSystemProxy.enableSocks(snap.host, snap.port)
        } else {
            WindowsSystemProxy.restore()
            false
        }
        update { it.copy(systemProxyEnabled = ok) }
        onLog(
            if (ok) "Системный прокси Windows включён: socks=${snap.socksAddress}"
            else "Системный прокси Windows восстановлен (выключен)"
        )
        return ok
    }

    @Synchronized
    fun stop(reason: String = "ByeDPI выключен") {
        stopInternal(logStop = true, reason = reason)
    }

    private fun stopInternal(logStop: Boolean, reason: String = "ByeDPI выключен") {
        stopping.set(true)
        val wasRunning = process != null || snapshot.running
        val proc = process
        process = null
        if (proc != null) {
            runCatching {
                proc.destroy()
                if (!proc.waitFor(1200, TimeUnit.MILLISECONDS)) {
                    proc.destroyForcibly()
                }
            }
        }
        WindowsSystemProxy.restore()
        if (wasRunning && logStop) onLog(reason)
        update {
            it.copy(
                running = false,
                systemProxyEnabled = false,
                statusMessage = reason,
                lastError = null
            )
        }
    }

    /**
     * Автоподбор лучшей DPI-стратегии для текущего провайдера через `:core` [DpiComparator].
     * Прогоняет все встроенные стратегии на временных портах и выбирает ту, через которую
     * открывается максимум заблокированных ресурсов.
     */
    fun autoTuneStrategy(
        checks: List<ResourceCheck>,
        baseProbePort: Int = 1091,
        onProgress: (String) -> Unit = {}
    ): ByeDpiTuneResult? {
        val bin = binaryResolver() ?: return null
        if (!bin.isFile || checks.isEmpty()) return null

        val comparator = DpiComparator(timeoutMs = 5000, connectTimeoutMs = 2000)
        var bestPreset = ByeDpiPresets.TUNABLE.first()
        var bestScore = -1
        var bestComp: DpiComparison? = null

        ByeDpiPresets.TUNABLE.forEachIndexed { idx, preset ->
            val probePort = (baseProbePort + idx).coerceIn(1024, 65000)
            onProgress("Проверяю стратегию ${idx + 1}/${ByeDpiPresets.TUNABLE.size}: ${preset.title}…")
            val cmd = ByeDpiPresets.buildCommand(bin, "127.0.0.1", probePort, preset.id)
            val proc = runCatching {
                ProcessBuilder(cmd).directory(bin.parentFile).redirectErrorStream(true).start()
            }.getOrNull() ?: return@forEachIndexed

            try {
                if (!waitPortOpen("127.0.0.1", probePort, timeoutMs = 2000L)) {
                    onLog("ByeDPI-подбор: «${preset.title}» не открыл порт $probePort")
                    return@forEachIndexed
                }
                val cmp = comparator.compare(checks, Socks5Endpoint("127.0.0.1", probePort))
                val proxyOkCount = cmp.rows.count { it.proxyOk }
                onLog("ByeDPI-подбор: «${preset.title}» → открыто $proxyOkCount/${cmp.rows.size} (ожило через DPI: ${cmp.dpiShaped})")
                val score = cmp.dpiShaped * 10 + proxyOkCount
                if (score > bestScore) {
                    bestScore = score
                    bestPreset = preset
                    bestComp = cmp
                }
            } finally {
                runCatching {
                    proc.destroy()
                    if (!proc.waitFor(800, TimeUnit.MILLISECONDS)) proc.destroyForcibly()
                }
            }
        }

        val comp = bestComp ?: return null
        val okCount = comp.rows.count { it.proxyOk }
        val summary = "Лучшая стратегия: «${bestPreset.title}» — открыто $okCount/${comp.rows.size} (DPI оживил ${comp.dpiShaped})"
        return ByeDpiTuneResult(
            bestPresetId = bestPreset.id,
            bestPresetTitle = bestPreset.title,
            bestFixedCount = comp.dpiShaped,
            totalChecks = comp.rows.size,
            summary = summary,
            comparison = comp
        )
    }

    fun shutdown() {
        stopInternal(logStop = false)
    }

    private fun waitPortOpen(host: String, port: Int, timeoutMs: Long): Boolean {
        val deadline = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < deadline) {
            val ok = runCatching {
                Socket().use { s ->
                    s.connect(InetSocketAddress(host, port), 250)
                    true
                }
            }.getOrDefault(false)
            if (ok) return true
            runCatching { Thread.sleep(80) }
        }
        return false
    }
}
