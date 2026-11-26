package dev.warpscout.desktop.tunnel

import com.sun.jna.platform.win32.Advapi32Util
import com.sun.jna.platform.win32.Shell32
import com.sun.jna.platform.win32.WinReg
import java.io.File

data class TelegramLaunchSpec(
    val exePath: String,
    val workDir: String? = null,
    val source: String = ""
)

data class TelegramOpenResult(
    val opened: Boolean,
    val message: String,
    val launchedVia: String = ""
)

/**
 * Надёжное открытие `tg://proxy?...` и `tg://socks?...` напрямую в Telegram Desktop на Windows
 * (включая обычную установку, портативную сборку, форки вроде AyuGram/64Gram/Kotatogram и Microsoft Store),
 * минуя браузер (чтобы никогда не открывалась пустая вкладка).
 */
object TelegramOpener {
    private val KNOWN_CLIENT_EXES = listOf(
        "telegram.exe",
        "ayugram.exe",
        "64gram.exe",
        "kotatogram.exe",
        "unigram.exe"
    )

    fun isWindows(): Boolean = "win" in System.getProperty("os.name").orEmpty().lowercase()

    /**
     * Парсит команду из реестра Windows (`HKCU\Software\Classes\tg\shell\open\command`), например:
     * `"C:\Users\User\AppData\Roaming\Telegram Desktop\Telegram.exe" -workdir "C:/Users/User/..." -- "%1"`
     */
    internal fun parseRegistryCommand(commandLine: String): TelegramLaunchSpec? {
        val tokens = splitCommandTokens(commandLine)
        if (tokens.isEmpty()) return null
        val exe = tokens[0].trim()
        if (!exe.lowercase().endsWith(".exe")) return null

        var workDir: String? = null
        var i = 1
        while (i < tokens.size) {
            if (tokens[i].equals("-workdir", ignoreCase = true) && i + 1 < tokens.size) {
                val cand = tokens[i + 1].trim()
                if (cand.isNotBlank() && cand != "%1") {
                    workDir = cand
                }
                i += 2
            } else {
                i++
            }
        }
        return TelegramLaunchSpec(exePath = exe, workDir = workDir, source = "registry")
    }

    /** Разбивает командную строку Windows на токены с учётом кавычек. */
    internal fun splitCommandTokens(cmd: String): List<String> {
        val out = ArrayList<String>()
        val cur = StringBuilder()
        var inQuotes = false
        for (ch in cmd) {
            when {
                ch == '"' -> inQuotes = !inQuotes
                ch.isWhitespace() && !inQuotes -> {
                    if (cur.isNotEmpty()) {
                        out.add(cur.toString())
                        cur.setLength(0)
                    }
                }
                else -> cur.append(ch)
            }
        }
        if (cur.isNotEmpty()) out.add(cur.toString())
        return out
    }

    /** Собирает аргументы запуска для передачи deep-link `tg://...` прямо в клиент Telegram. */
    internal fun buildLaunchArgs(spec: TelegramLaunchSpec, tgUrl: String): List<String> = buildList {
        add(spec.exePath)
        if (!spec.workDir.isNullOrBlank()) {
            add("-workdir")
            add(spec.workDir)
        }
        add("--")
        add(tgUrl)
    }

    /** Ищет установленный или уже запущенный клиент Telegram на Windows. */
    fun findTelegramClient(
        runningExePaths: List<String> = detectRunningTelegramExes(),
        registryCommand: String? = readRegistryTgCommand(),
        standardCandidates: List<File> = defaultInstallCandidates(),
        fileExists: (String) -> Boolean = { File(it).isFile }
    ): TelegramLaunchSpec? {
        val regSpec = registryCommand?.let(::parseRegistryCommand)

        // 1. Уже запущенный процесс (идеально для портативного Telegram в любой папке).
        for (running in runningExePaths) {
            if (running.isBlank() || !fileExists(running)) continue
            val matchedWorkDir = if (regSpec != null && pathsEqual(regSpec.exePath, running)) regSpec.workDir else null
            return TelegramLaunchSpec(exePath = running, workDir = matchedWorkDir, source = "running")
        }

        // 2. Команда протокола tg:// из реестра Windows (сохраняет точный -workdir).
        if (regSpec != null && fileExists(regSpec.exePath)) {
            return regSpec
        }

        // 3. Стандартные пути установки Telegram Desktop на Windows.
        for (cand in standardCandidates) {
            val path = cand.absolutePath
            if (fileExists(path)) {
                val matchedWorkDir = if (regSpec != null && pathsEqual(regSpec.exePath, path)) regSpec.workDir else null
                return TelegramLaunchSpec(exePath = path, workDir = matchedWorkDir, source = "standard")
            }
        }
        return null
    }

    /**
     * Открывает `tg://proxy?...` или `tg://socks?...` напрямую в Telegram Desktop без запуска браузера.
     */
    fun openTgLink(
        tgUrl: String,
        specOverride: TelegramLaunchSpec? = null,
        processStarter: (List<String>, File?) -> Boolean = ::startProcessDirect,
        shellFallback: (String) -> Boolean = ::openViaWindowsShellIfRegistered
    ): TelegramOpenResult {
        if (!tgUrl.startsWith("tg://", ignoreCase = true)) {
            return TelegramOpenResult(false, "Ожидалась ссылка tg://…")
        }

        if (!isWindows()) {
            val ok = runCatching {
                ProcessBuilder("xdg-open", tgUrl).start()
                true
            }.getOrDefault(false)
            return if (ok) {
                TelegramOpenResult(true, "Ссылка передана в Telegram", launchedVia = "xdg-open")
            } else {
                TelegramOpenResult(false, "Не удалось открыть ссылку tg:// на этой ОС")
            }
        }

        val spec = specOverride ?: findTelegramClient()
        if (spec != null) {
            val args = buildLaunchArgs(spec, tgUrl)
            val workDirFile = File(spec.exePath).parentFile?.takeIf { it.isDirectory }
            if (processStarter(args, workDirFile)) {
                val exeName = File(spec.exePath).name
                return TelegramOpenResult(
                    opened = true,
                    message = "Передано в $exeName — подтвердите добавление прокси в окне Telegram",
                    launchedVia = exeName
                )
            }
        }

        // Запасной путь только если tg:// зарегистрирован в системе (например, Telegram из Microsoft Store / MSIX).
        if (shellFallback(tgUrl)) {
            return TelegramOpenResult(
                opened = true,
                message = "Ссылка передана в системный обработчик Telegram (tg://)",
                launchedVia = "shell-tg"
            )
        }

        return TelegramOpenResult(
            opened = false,
            message = "Telegram Desktop не найден на ПК (если он портативный — сначала откройте Telegram и нажмите кнопку снова; ссылка скопирована в буфер)"
        )
    }

    private fun startProcessDirect(args: List<String>, workingDir: File?): Boolean = runCatching {
        val pb = ProcessBuilder(args)
        if (workingDir != null) pb.directory(workingDir)
        pb.start()
        true
    }.getOrDefault(false)

    private fun detectRunningTelegramExes(): List<String> = runCatching {
        ProcessHandle.allProcesses()
            .map { it.info().command().orElse(null) }
            .filter { cmd ->
                if (cmd.isNullOrBlank()) false
                else {
                    val name = File(cmd).name.lowercase()
                    name in KNOWN_CLIENT_EXES
                }
            }
            .distinct()
            .toList()
    }.getOrDefault(emptyList())

    private fun readRegistryTgCommand(): String? {
        if (!isWindows()) return null
        val candidates = listOf(
            WinReg.HKEY_CURRENT_USER to "Software\\Classes\\tg\\shell\\open\\command",
            WinReg.HKEY_CLASSES_ROOT to "tg\\shell\\open\\command",
            WinReg.HKEY_LOCAL_MACHINE to "SOFTWARE\\Classes\\tg\\shell\\open\\command"
        )
        for ((root, path) in candidates) {
            val v = runCatching {
                if (Advapi32Util.registryValueExists(root, path, "")) {
                    Advapi32Util.registryGetStringValue(root, path, "")
                } else null
            }.getOrNull()
            if (!v.isNullOrBlank()) return v
        }
        return null
    }

    private fun isTgProtocolRegistered(): Boolean {
        if (!isWindows()) return false
        val roots = listOf(
            WinReg.HKEY_CURRENT_USER to "Software\\Classes\\tg",
            WinReg.HKEY_CLASSES_ROOT to "tg",
            WinReg.HKEY_LOCAL_MACHINE to "SOFTWARE\\Classes\\tg"
        )
        return roots.any { (root, path) ->
            runCatching { Advapi32Util.registryKeyExists(root, path) }.getOrDefault(false)
        }
    }

    private fun openViaWindowsShellIfRegistered(tgUrl: String): Boolean {
        if (!isTgProtocolRegistered()) return false
        return runCatching {
            val res = Shell32.INSTANCE.ShellExecute(null, "open", tgUrl, null, null, 1)
            // Согласно Win32 API ShellExecute возвращает HINSTANCE/INT_PTR > 32 при успехе.
            (res?.toLong() ?: 0L) > 32L
        }.getOrDefault(false)
    }

    private fun defaultInstallCandidates(): List<File> {
        val out = ArrayList<File>()
        val appData = System.getenv("APPDATA")?.takeIf { it.isNotBlank() }
        val localAppData = System.getenv("LOCALAPPDATA")?.takeIf { it.isNotBlank() }
        val userProfile = System.getenv("USERPROFILE")?.takeIf { it.isNotBlank() } ?: System.getProperty("user.home")
        val progFiles = System.getenv("ProgramFiles")?.takeIf { it.isNotBlank() } ?: """C:\Program Files"""
        val progFiles86 = System.getenv("ProgramFiles(x86)")?.takeIf { it.isNotBlank() } ?: """C:\Program Files (x86)"""

        if (appData != null) {
            out.add(File(appData, """Telegram Desktop\Telegram.exe"""))
            out.add(File(appData, """AyuGram Desktop\AyuGram.exe"""))
        }
        if (localAppData != null) {
            out.add(File(localAppData, """Telegram Desktop\Telegram.exe"""))
            out.add(File(localAppData, """Programs\Telegram Desktop\Telegram.exe"""))
        }
        if (!userProfile.isNullOrBlank()) {
            out.add(File(userProfile, """Desktop\Telegram\Telegram.exe"""))
            out.add(File(userProfile, """Downloads\Telegram\Telegram.exe"""))
        }
        out.add(File(progFiles, """Telegram Desktop\Telegram.exe"""))
        out.add(File(progFiles86, """Telegram Desktop\Telegram.exe"""))
        return out
    }

    private fun pathsEqual(a: String, b: String): Boolean =
        a.replace('/', '\\').trimEnd('\\').equals(b.replace('/', '\\').trimEnd('\\'), ignoreCase = true)
}
