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
import java.io.BufferedReader
import java.io.File
import java.io.InputStreamReader
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

/** Готовая проверенная стратегия обхода DPI для ByeDPI (`ciadpi.exe`) на Windows. */
data class ByeDpiPreset(
    val id: String,
    val title: String,
    val subtitle: String,
    val args: List<String>
)

/** Определённая текущая сеть (Wi-Fi SSID и/или физический шлюз) для запоминания стратегии. */
data class NetworkIdentity(
    val key: String,
    val label: String,
    val ssid: String = "",
    val gatewayIp: String = "",
    val sourceIp: String = "",
    val interfaceIndex: Int = 0
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
    val pacUrl: String? = null,
    val pacDomainsCount: Int = 0,
    val bindConnIp: String? = null,
    val statusMessage: String = "ByeDPI выключен",
    val lastError: String? = null
) {
    val socksAddress: String get() = "$host:$port"
}

object ByeDpiPresets {
    const val DEFAULT_ID = "win-auto"
    const val CUSTOM_ID = "custom"

    /**
     * Стратегии `ciadpi.exe`, адаптированные под TCP-стек Windows (без Linux-only `--md5sig` и `--drop-sack`).
     *
     * На Windows повторная отправка потерянных сегментов работает иначе, чем в Linux, поэтому
     * документация ByeDPI рекомендует связки `--split 1+s --disorder 3+s` и `--disorder 1 --fake -1`.
     */
    val BUILTIN: List<ByeDpiPreset> = listOf(
        ByeDpiPreset(
            id = "win-auto",
            title = "Авто Windows",
            subtitle = "Автоподбор при RST/таймауте: split+disorder (Win) → disorder+fake → oob+split",
            args = listOf(
                "--auto=torst", "--timeout", "3",
                "--split", "1+s", "--disorder", "3+s", "--tlsrec", "1+s", "--udp-fake", "1",
                "--auto=torst", "--disorder", "1", "--fake", "-1", "--ttl", "8", "--udp-fake", "1",
                "--auto=torst", "--oob", "1+s", "--split", "1+s"
            )
        ),
        ByeDpiPreset(
            id = "win-split-disorder",
            title = "Split + Disorder (Win)",
            subtitle = "Рекомендация ByeDPI для Windows: --split 1+s --disorder 3+s (без fake-TTL)",
            args = listOf("--split", "1+s", "--disorder", "3+s", "--udp-fake", "1")
        ),
        ByeDpiPreset(
            id = "win-disorder-fake",
            title = "Disorder + Fake (Win)",
            subtitle = "Рекомендация ByeDPI для Windows: --disorder 1 --fake -1 --ttl 8",
            args = listOf("--disorder", "1", "--fake", "-1", "--ttl", "8", "--udp-fake", "1")
        ),
        ByeDpiPreset(
            id = "win-tlsrec-split",
            title = "TLS Record + Split",
            subtitle = "Разбиение TLS-записи + Windows split/disorder по SNI (YouTube / Discord)",
            args = listOf("--tlsrec", "1+s", "--split", "1+s", "--disorder", "3+s", "--udp-fake", "1")
        ),
        ByeDpiPreset(
            id = "win-oob-split",
            title = "OOB + Split",
            subtitle = "Внеканальный байт URG + split (резерв, если disorder/fake режутся)",
            args = listOf("--oob", "1+s", "--split", "1+s", "--tlsrec", "1+s")
        ),
        ByeDpiPreset(
            id = CUSTOM_ID,
            title = "Свои аргументы",
            subtitle = "Произвольные флаги ciadpi (-i / -p подставляются сами; -I можно переопределить)",
            args = emptyList()
        )
    )

    val TUNABLE: List<ByeDpiPreset> = BUILTIN.filter { it.id != CUSTOM_ID }

    /** Совместимость со старыми ID стратегий из v1.10.28. */
    private val LEGACY_MAP: Map<String, String> = mapOf(
        "auto-universal" to "win-auto",
        "disorder-tlsrec" to "win-tlsrec-split",
        "disorder-fake" to "win-disorder-fake",
        "oob-split" to "win-oob-split"
    )

    fun normalizeId(id: String): String = LEGACY_MAP[id] ?: id

    fun byId(id: String): ByeDpiPreset {
        val norm = normalizeId(id)
        return BUILTIN.firstOrNull { it.id == norm } ?: BUILTIN.first()
    }

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

    /**
     * Собирает полный список аргументов для запуска `ciadpi.exe`.
     *
     * Если передан [bindConnIp] (локальный IPv4 физического адаптера, например `192.168.1.42`)
     * и пользователь сам не указал `-I` / `--conn-ip`, добавляются флаги `-I <bindConnIp> -X`:
     * исходящие соединения ByeDPI привязываются к физической сетевой карте и идут мимо Wintun,
     * а `-X` (`--no-ipv6`) не даёт `getaddrinfo` вернуть AAAA-запись при IPv4-привязке.
     */
    fun buildCommand(
        binary: File,
        host: String,
        port: Int,
        presetId: String,
        customArgs: String = "",
        bindConnIp: String? = null
    ): List<String> {
        val normId = normalizeId(presetId)
        val extra = if (normId == CUSTOM_ID) {
            tokenizeArgs(customArgs).ifEmpty { byId(DEFAULT_ID).args }
        } else {
            byId(normId).args
        }
        val cleanBindIp = bindConnIp?.trim()?.takeIf { CidrMath.parseIpv4(it) != null && !it.startsWith("127.") }
        val userHasConnIp = extra.any { it == "-I" || it == "--conn-ip" || it.startsWith("--conn-ip=") }
        val userHasNoIpv6 = extra.any { it == "-X" || it == "--no-ipv6" }

        return buildList {
            add(binary.absolutePath)
            add("-i")
            add(host)
            add("-p")
            add(port.coerceIn(1024, 65535).toString())
            if (cleanBindIp != null && !userHasConnIp) {
                add("-I")
                add(cleanBindIp)
                if (!userHasNoIpv6) {
                    add("-X")
                }
            }
            addAll(extra)
        }
    }
}

/**
 * Генератор PAC-файла автонастройки прокси (`FindProxyForURL`) для совместной работы ByeDPI и WARP:
 *  • домены из списка (YouTube, googlevideo, ytimg, Discord…) идут через `SOCKS5 127.0.0.1:<port>; DIRECT`;
 *  • всё остальное идёт `DIRECT` (российские сайты напрямую, зарубежные — в WARP по маршрутам);
 *  • явный `SOCKS5` (Chrome/Edge резолвят имена через сам прокси, а не как SOCKS4 по системному DNS);
 *  • при падении `ciadpi.exe` или убийстве процесса браузер сам откатывается на `DIRECT`.
 */
object ByeDpiPac {
    val DEFAULT_DOMAINS: List<String> = listOf(
        "youtube.com",
        "youtu.be",
        "googlevideo.com",
        "ytimg.com",
        "ggpht.com",
        "youtube-nocookie.com",
        "youtubei.googleapis.com",
        "yt.be",
        "discord.com",
        "discord.gg",
        "discordapp.com",
        "discordapp.net",
        "discord.media",
        "discordcdn.com",
        "discordstatus.com"
    )

    val DEFAULT_DOMAINS_TEXT: String = DEFAULT_DOMAINS.joinToString(", ")

    fun parseDomains(raw: String): List<String> {
        val parsed = raw
            .split(',', ';', '\n', '\r', ' ', '\t')
            .map { token ->
                token.trim()
                    .lowercase()
                    .removePrefix("https://")
                    .removePrefix("http://")
                    .substringBefore('/')
                    .removePrefix("*.")
                    .removePrefix(".")
            }
            .filter { it.isNotEmpty() && '.' in it && it.all { ch -> ch.isLetterOrDigit() || ch == '.' || ch == '-' } }
            .distinct()
        return parsed.ifEmpty { DEFAULT_DOMAINS }
    }

    fun renderPac(socksHost: String, socksPort: Int, domains: List<String>): String {
        val cleanDomains = domains.map { it.trim().lowercase() }.filter { it.isNotEmpty() }.distinct().ifEmpty { DEFAULT_DOMAINS }
        val jsList = cleanDomains.joinToString(",\n    ") { "\"${escapeJs(it)}\"" }
        return """
            // WarpScout PAC (auto-generated) — ByeDPI SOCKS5 for selected domains, DIRECT for everything else.
            function FindProxyForURL(url, host) {
              if (!host || isPlainHostName(host)) return "DIRECT";
              var h = host.toLowerCase();
              var domains = [
                $jsList
              ];
              for (var i = 0; i < domains.length; i++) {
                var d = domains[i];
                if (h === d || shExpMatch(h, "*." + d)) {
                  return "SOCKS5 $socksHost:$socksPort; DIRECT";
                }
              }
              return "DIRECT";
            }
        """.trimIndent() + "\n"
    }

    private fun escapeJs(s: String): String =
        s.replace("\\", "\\\\").replace("\"", "\\\"")
}

/**
 * Лёгкий локальный HTTP-сервер на `127.0.0.1` без внешних зависимостей и без модуля `jdk.httpserver`.
 * Раздаёт `/warpscout.pac` для Windows WinINet / Chrome / Edge (`file://` PAC в Windows 10/11 отключён).
 * При аварийном завершении WarpScout порт закрывается, и браузеры автоматически откатываются на `DIRECT`.
 */
class LocalPacServer {
    @Volatile
    private var serverSocket: ServerSocket? = null

    @Volatile
    private var pacBytes: ByteArray = ByteArray(0)

    @Volatile
    var url: String? = null
        private set

    private val running = AtomicBoolean(false)
    private var acceptThread: Thread? = null
    private var workers: ExecutorService? = null

    @Synchronized
    fun start(pacScript: String): String? {
        pacBytes = pacScript.toByteArray(Charsets.UTF_8)
        if (running.get() && serverSocket?.isClosed == false && url != null) {
            return url
        }
        stop()
        return try {
            val ss = ServerSocket()
            ss.reuseAddress = true
            ss.bind(InetSocketAddress(InetAddress.getByName("127.0.0.1"), 0))
            val localPort = ss.localPort
            val pacUrl = "http://127.0.0.1:$localPort/warpscout.pac"
            serverSocket = ss
            url = pacUrl
            running.set(true)

            val pool = Executors.newFixedThreadPool(2) { r ->
                Thread(r, "warpscout-pac-http").apply { isDaemon = true }
            }
            workers = pool

            acceptThread = Thread({
                while (running.get() && !ss.isClosed) {
                    val client = runCatching { ss.accept() }.getOrNull() ?: break
                    runCatching {
                        pool.execute { handleClient(client) }
                    }.onFailure {
                        runCatching { client.close() }
                    }
                }
            }, "warpscout-pac-accept").apply {
                isDaemon = true
                start()
            }
            pacUrl
        } catch (_: Exception) {
            stop()
            null
        }
    }

    fun updateScript(pacScript: String) {
        pacBytes = pacScript.toByteArray(Charsets.UTF_8)
    }

    @Synchronized
    fun stop() {
        running.set(false)
        url = null
        runCatching { serverSocket?.close() }
        serverSocket = null
        runCatching { workers?.shutdownNow() }
        workers = null
        acceptThread = null
    }

    private fun handleClient(socket: Socket) {
        socket.use { s ->
            runCatching {
                s.soTimeout = 1500
                val reader = BufferedReader(InputStreamReader(s.getInputStream(), Charsets.ISO_8859_1))
                // Вычитываем заголовки HTTP-запроса до пустой строки.
                var lines = 0
                while (lines < 32) {
                    val line = reader.readLine() ?: break
                    if (line.isEmpty()) break
                    lines++
                }
                val body = pacBytes
                val header = buildString {
                    append("HTTP/1.1 200 OK\r\n")
                    append("Content-Type: application/x-ns-proxy-autoconfig; charset=utf-8\r\n")
                    append("Content-Length: ").append(body.size).append("\r\n")
                    append("Cache-Control: no-store, no-cache, must-revalidate\r\n")
                    append("Connection: close\r\n\r\n")
                }.toByteArray(Charsets.ISO_8859_1)
                val out = s.getOutputStream()
                out.write(header)
                out.write(body)
                out.flush()
            }
        }
    }
}

/** Определение текущей сети (Wi-Fi SSID и/или физический шлюз) для привязки стратегии ByeDPI к сети. */
object NetworkIdentityDetector {
    fun detect(
        gateway: PhysicalGateway?,
        runner: CommandRunner = ProcessCommandRunner()
    ): NetworkIdentity? {
        val ssid = if (WindowsAutostart.isWindows()) detectWindowsWifiSsid(runner) else ""
        val gwIp = gateway?.nextHop?.takeIf { it.isNotBlank() && it != "0.0.0.0" }.orEmpty()
        val srcIp = gateway?.sourceIp?.takeIf { it.isNotBlank() && !it.startsWith("172.16.0.") }.orEmpty()
        val ifIdx = gateway?.interfaceIndex ?: 0

        if (ssid.isBlank() && gwIp.isBlank() && srcIp.isBlank()) return null

        val subnet = ipv4Subnet24(srcIp)
        val key = when {
            ssid.isNotBlank() && gwIp.isNotBlank() -> "wifi:$ssid|$gwIp"
            ssid.isNotBlank() -> "wifi:$ssid"
            gwIp.isNotBlank() && subnet.isNotBlank() -> "gw:$gwIp|$subnet"
            gwIp.isNotBlank() -> "gw:$gwIp|if:$ifIdx"
            else -> "ip:$subnet|if:$ifIdx"
        }
        val label = when {
            ssid.isNotBlank() && gwIp.isNotBlank() -> "Wi-Fi «$ssid» ($gwIp)"
            ssid.isNotBlank() -> "Wi-Fi «$ssid»"
            gwIp.isNotBlank() -> "Сеть $gwIp"
            else -> "Сеть $srcIp"
        }
        return NetworkIdentity(
            key = key,
            label = label,
            ssid = ssid,
            gatewayIp = gwIp,
            sourceIp = srcIp,
            interfaceIndex = ifIdx
        )
    }

    internal fun detectWindowsWifiSsid(runner: CommandRunner): String {
        val res = runCatching {
            runner.run(listOf("netsh.exe", "wlan", "show", "interfaces"), timeoutMs = 2500L)
        }.getOrNull() ?: return ""
        if (!res.ok) return ""
        return parseNetshWifiSsid(res.stdout)
    }

    /**
     * Извлекает имя подключённой Wi-Fi сети (SSID) из вывода `netsh wlan show interfaces`
     * на любой локали Windows (EN/RU): поле `SSID` одинаково на всех языках, BSSID игнорируется.
     */
    fun parseNetshWifiSsid(output: String): String {
        var connected = false
        var ssid = ""
        for (rawLine in output.lineSequence()) {
            val line = rawLine.trim()
            if (line.isEmpty()) continue
            val colon = line.indexOf(':')
            if (colon <= 0) continue
            val key = line.substring(0, colon).trim()
            val value = line.substring(colon + 1).trim()
            val keyLower = key.lowercase()
            if (keyLower == "state" || keyLower == "состояние") {
                connected = value.lowercase().let {
                    it.contains("connected") && !it.contains("disconnected") ||
                        (it.contains("подключ") && !it.contains("отключ"))
                }
            } else if (key.equals("SSID", ignoreCase = true)) {
                if (value.isNotBlank()) ssid = value
            }
        }
        return if (connected && ssid.isNotBlank()) ssid else ""
    }

    private fun ipv4Subnet24(ip: String): String {
        val parts = ip.split('.')
        return if (parts.size == 4) "${parts[0]}.${parts[1]}.${parts[2]}.0/24" else ""
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
 * Безопасное включение/выключение автонастройки прокси Windows (PAC-файл через `AutoConfigURL`)
 * в `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`.
 *
 * Почему PAC вместо глобального `ProxyServer=socks=...`:
 *  1. Браузеры (Chrome, Edge) понимают `SOCKS5` в PAC именно как SOCKS5 (с резолвом домена на стороне прокси),
 *     а не как SOCKS4 с системным DNS.
 *  2. Маршрутизация идёт по имени домена (YouTube/Discord → ByeDPI, остальное → DIRECT / WARP).
 *  3. Если `ciadpi.exe` упал или WarpScout закрыли через Диспетчер задач, браузер автоматически откатывается на `DIRECT`.
 */
object WindowsSystemProxy {
    private const val REG_PATH = "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings"
    private const val INTERNET_OPTION_SETTINGS_CHANGED = 39
    private const val INTERNET_OPTION_REFRESH = 37
    private const val OUR_PAC_SUFFIX = "/warpscout.pac"

    private interface WinInet : Library {
        fun InternetSetOptionW(hInternet: Pointer?, dwOption: Int, lpBuffer: Pointer?, dwBufferLength: Int): Boolean
    }

    private data class SavedProxy(
        val autoConfigUrl: String?,
        val proxyEnable: Int?,
        val proxyServer: String?
    )

    @Volatile
    private var saved: SavedProxy? = null

    @Volatile
    private var appliedByUs: Boolean = false

    /**
     * Подчищает «осиротевшие» настройки WarpScout в реестре после аварийного завершения процесса
     * (например, закрытия через Диспетчер задач), не трогая чужие прокси пользователя.
     */
    @Synchronized
    fun cleanupStaleIfOurs(): Boolean {
        if (appliedByUs || !WindowsAutostart.isWindows()) return false
        return runCatching {
            var changed = false
            val existingPac = readStr(REG_PATH, "AutoConfigURL")
            if (existingPac != null && isOurPacUrl(existingPac)) {
                runCatching { Advapi32Util.registryDeleteValue(WinReg.HKEY_CURRENT_USER, REG_PATH, "AutoConfigURL") }
                changed = true
            }
            // Подчищаем и старый глобальный `socks=127.0.0.1:...` от прошлой версии v1.10.28, если остался висеть.
            val existingProxy = readStr(REG_PATH, "ProxyServer")
            val existingEnable = readInt(REG_PATH, "ProxyEnable")
            if (existingEnable == 1 && existingProxy != null && existingProxy.startsWith("socks=127.0.0.1:")) {
                Advapi32Util.registrySetIntValue(WinReg.HKEY_CURRENT_USER, REG_PATH, "ProxyEnable", 0)
                runCatching { Advapi32Util.registryDeleteValue(WinReg.HKEY_CURRENT_USER, REG_PATH, "ProxyServer") }
                changed = true
            }
            if (changed) notifySystem()
            changed
        }.getOrDefault(false)
    }

    @Synchronized
    fun enablePac(pacUrl: String): Boolean {
        if (!WindowsAutostart.isWindows()) return false
        return runCatching {
            if (!appliedByUs) {
                val curPac = readStr(REG_PATH, "AutoConfigURL")?.takeUnless { isOurPacUrl(it) }
                val curEnable = readInt(REG_PATH, "ProxyEnable")
                val curServer = readStr(REG_PATH, "ProxyServer")
                saved = SavedProxy(
                    autoConfigUrl = curPac,
                    proxyEnable = curEnable,
                    proxyServer = curServer
                )
            }
            // Если остался наш старый глобальный `socks=127.0.0.1:...`, выключаем его, чтобы работал именно PAC.
            val curServer = readStr(REG_PATH, "ProxyServer")
            if (curServer != null && curServer.startsWith("socks=127.0.0.1:")) {
                Advapi32Util.registrySetIntValue(WinReg.HKEY_CURRENT_USER, REG_PATH, "ProxyEnable", 0)
                runCatching { Advapi32Util.registryDeleteValue(WinReg.HKEY_CURRENT_USER, REG_PATH, "ProxyServer") }
            }
            Advapi32Util.registrySetStringValue(WinReg.HKEY_CURRENT_USER, REG_PATH, "AutoConfigURL", pacUrl)
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
            if (prev?.autoConfigUrl != null && !isOurPacUrl(prev.autoConfigUrl)) {
                Advapi32Util.registrySetStringValue(WinReg.HKEY_CURRENT_USER, REG_PATH, "AutoConfigURL", prev.autoConfigUrl)
            } else {
                runCatching { Advapi32Util.registryDeleteValue(WinReg.HKEY_CURRENT_USER, REG_PATH, "AutoConfigURL") }
            }
            appliedByUs = false
            saved = null
            notifySystem()
            true
        }.getOrDefault(false)
    }

    internal fun isOurPacUrl(url: String): Boolean =
        url.startsWith("http://127.0.0.1:") && url.endsWith(OUR_PAC_SUFFIX)

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
 * Работает полностью в userspace (без драйверов WinDivert):
 *  • поднимает локальный SOCKS5-прокси `127.0.0.1:<port>`;
 *  • при включённом обходе туннеля привязывает исходящие соединения к IP физического адаптера
 *    (`-I <physicalIp> -X`), чтобы трафик ByeDPI шёл мимо Wintun;
 *  • опционально настраивает системный PAC-файл (`AutoConfigURL` на локальный HTTP-сервер),
 *    отправляя YouTube/Discord в `SOCKS5 127.0.0.1:<port>; DIRECT`, а всё остальное — `DIRECT` (в WARP);
 *  • подбирает лучшую Windows-стратегию через `:core` [DpiComparator].
 */
class ByeDpiManager(
    private val nativeDir: File,
    private val pacExportFile: File? = null,
    private val onState: (ByeDpiSnapshot) -> Unit = {},
    private val onLog: (String) -> Unit = {},
    private val binaryResolver: () -> File? = { ByeDpiLocator.findOrExtract(nativeDir) },
    private val physicalIpResolver: () -> String? = { null }
) {
    @Volatile
    var snapshot: ByeDpiSnapshot = ByeDpiSnapshot()
        private set

    private val pacServer = LocalPacServer()

    @Volatile
    private var activePacDomains: List<String> = ByeDpiPac.DEFAULT_DOMAINS

    init {
        if (WindowsSystemProxy.cleanupStaleIfOurs()) {
            onLog("Очищена оставшаяся после прошлого запуска запись PAC/прокси Windows")
        }
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
        enableSystemProxy: Boolean = false,
        bypassTunnel: Boolean = true,
        pacDomainsText: String = ByeDpiPac.DEFAULT_DOMAINS_TEXT
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
        val bindIp = if (bypassTunnel) {
            physicalIpResolver()?.trim()?.takeIf { CidrMath.parseIpv4(it) != null && !it.startsWith("172.16.0.") }
        } else null
        val cmd = ByeDpiPresets.buildCommand(
            binary = bin,
            host = "127.0.0.1",
            port = cleanPort,
            presetId = preset.id,
            customArgs = customArgs,
            bindConnIp = bindIp
        )
        activePacDomains = ByeDpiPac.parseDomains(pacDomainsText)
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
                    pacServer.stop()
                    WindowsSystemProxy.restore()
                    onLog("ByeDPI неожиданно завершился (код $code)")
                    update {
                        it.copy(
                            running = false,
                            systemProxyEnabled = false,
                            pacUrl = null,
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
                        pacUrl = null,
                        bindConnIp = null,
                        statusMessage = "Ошибка запуска ByeDPI",
                        lastError = msg
                    )
                }
                return false
            }

            var appliedPacUrl: String? = null
            val sysProxyOk = if (enableSystemProxy) {
                val pacScript = ByeDpiPac.renderPac("127.0.0.1", cleanPort, activePacDomains)
                writePacDebugCopy(pacScript)
                val url = pacServer.start(pacScript)
                val ok = url != null && WindowsSystemProxy.enablePac(url)
                if (ok) {
                    appliedPacUrl = url
                    onLog("Автонастройка прокси Windows (PAC) включена: $url (доменов: ${activePacDomains.size}, остальные → DIRECT/WARP)")
                } else {
                    pacServer.stop()
                    onLog("Не удалось включить PAC-прокси Windows — используйте SOCKS5 127.0.0.1:$cleanPort вручную")
                }
                ok
            } else {
                pacServer.stop()
                WindowsSystemProxy.restore()
                false
            }

            val bindNote = if (bindIp != null) " · исходящий IP $bindIp (мимо туннеля)" else ""
            onLog("ByeDPI запущен: 127.0.0.1:$cleanPort · стратегия «${preset.title}»$bindNote")
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
                    pacUrl = appliedPacUrl,
                    pacDomainsCount = activePacDomains.size,
                    bindConnIp = bindIp,
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
                    pacUrl = null,
                    bindConnIp = null,
                    statusMessage = "Ошибка запуска ByeDPI",
                    lastError = msg
                )
            }
            false
        }
    }

    @Synchronized
    fun setSystemProxy(enabled: Boolean, pacDomainsText: String = ByeDpiPac.DEFAULT_DOMAINS_TEXT): Boolean {
        activePacDomains = ByeDpiPac.parseDomains(pacDomainsText)
        val snap = snapshot
        if (!snap.running) {
            pacServer.stop()
            WindowsSystemProxy.restore()
            update { it.copy(systemProxyEnabled = false, pacUrl = null) }
            return false
        }
        var appliedPacUrl: String? = null
        val ok = if (enabled) {
            val pacScript = ByeDpiPac.renderPac(snap.host, snap.port, activePacDomains)
            writePacDebugCopy(pacScript)
            val url = pacServer.start(pacScript)
            val regOk = url != null && WindowsSystemProxy.enablePac(url)
            if (regOk) appliedPacUrl = url else pacServer.stop()
            regOk
        } else {
            pacServer.stop()
            WindowsSystemProxy.restore()
            false
        }
        update {
            it.copy(
                systemProxyEnabled = ok,
                pacUrl = appliedPacUrl,
                pacDomainsCount = activePacDomains.size
            )
        }
        onLog(
            if (ok) "PAC-прокси Windows включён: $appliedPacUrl (доменов: ${activePacDomains.size}, остальное → DIRECT)"
            else "PAC-прокси Windows выключен (настройки восстановлены)"
        )
        return ok
    }

    /** Обновляет список доменов в активном PAC-сервере без перезапуска `ciadpi.exe`. */
    @Synchronized
    fun updatePacDomains(pacDomainsText: String) {
        activePacDomains = ByeDpiPac.parseDomains(pacDomainsText)
        val snap = snapshot
        if (snap.running && snap.systemProxyEnabled) {
            val pacScript = ByeDpiPac.renderPac(snap.host, snap.port, activePacDomains)
            writePacDebugCopy(pacScript)
            pacServer.updateScript(pacScript)
            update { it.copy(pacDomainsCount = activePacDomains.size) }
        }
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
        pacServer.stop()
        WindowsSystemProxy.restore()
        if (wasRunning && logStop) onLog(reason)
        update {
            it.copy(
                running = false,
                systemProxyEnabled = false,
                pacUrl = null,
                bindConnIp = null,
                statusMessage = reason,
                lastError = null
            )
        }
    }

    /**
     * Автоподбор лучшей Windows-стратегии для текущего провайдера через `:core` [DpiComparator].
     * Прогоняет все встроенные стратегии на временных портах (с привязкой `-I <physicalIp>`, если включён обход туннеля)
     * и выбирает ту, через которую открывается максимум заблокированных ресурсов.
     */
    fun autoTuneStrategy(
        checks: List<ResourceCheck>,
        baseProbePort: Int = 1091,
        bypassTunnel: Boolean = true,
        onProgress: (String) -> Unit = {}
    ): ByeDpiTuneResult? {
        val bin = binaryResolver() ?: return null
        if (!bin.isFile || checks.isEmpty()) return null

        val bindIp = if (bypassTunnel) {
            physicalIpResolver()?.trim()?.takeIf { CidrMath.parseIpv4(it) != null && !it.startsWith("172.16.0.") }
        } else null
        if (bindIp != null) {
            onLog("ByeDPI-подбор: привязка исходящих соединений к $bindIp (мимо туннеля)")
        }

        val comparator = DpiComparator(timeoutMs = 5000, connectTimeoutMs = 2000)
        var bestPreset = ByeDpiPresets.TUNABLE.first()
        var bestScore = -1
        var bestComp: DpiComparison? = null

        ByeDpiPresets.TUNABLE.forEachIndexed { idx, preset ->
            val probePort = (baseProbePort + idx).coerceIn(1024, 65000)
            onProgress("Проверяю стратегию ${idx + 1}/${ByeDpiPresets.TUNABLE.size}: ${preset.title}…")
            val cmd = ByeDpiPresets.buildCommand(
                binary = bin,
                host = "127.0.0.1",
                port = probePort,
                presetId = preset.id,
                bindConnIp = bindIp
            )
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

    private fun writePacDebugCopy(pacScript: String) {
        val file = pacExportFile ?: return
        runCatching {
            file.parentFile?.mkdirs()
            file.writeText(pacScript, Charsets.UTF_8)
        }
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
