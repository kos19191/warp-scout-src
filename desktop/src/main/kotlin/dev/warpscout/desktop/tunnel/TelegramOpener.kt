package dev.warpscout.desktop.tunnel

import com.sun.jna.Native
import com.sun.jna.platform.win32.Advapi32Util
import com.sun.jna.platform.win32.Shell32
import com.sun.jna.platform.win32.User32
import com.sun.jna.platform.win32.WinDef
import com.sun.jna.platform.win32.WinReg
import com.sun.jna.platform.win32.WinUser
import com.sun.jna.ptr.IntByReference
import com.sun.jna.win32.StdCallLibrary
import java.io.File
import java.util.concurrent.TimeUnit

data class TelegramLaunchSpec(
    val exePath: String,
    val workDir: String? = null,
    val source: String = "",
    val runningPid: Long? = null,
    val isStoreApp: Boolean = false
)

data class TelegramOpenResult(
    val opened: Boolean,
    val message: String,
    val launchedVia: String = "",
    val detail: String = ""
)

/**
 * Надёжное открытие `tg://proxy?...` и `tg://socks?...` напрямую в Telegram Desktop на Windows
 * (обычная установка, портативная сборка, форки вроде AyuGram/64Gram/Kotatogram и Microsoft Store),
 * минуя браузер и вынося окно Telegram на передний план поверх повышенного (UAC) окна WilyScout.
 */
object TelegramOpener {
    private val KNOWN_CLIENT_EXES = listOf(
        "telegram.exe",
        "ayugram.exe",
        "64gram.exe",
        "kotatogram.exe",
        "unigram.exe"
    )

    private const val ASFW_ANY = -1
    private const val SW_RESTORE = 9

    private interface User32Extra : StdCallLibrary {
        fun AllowSetForegroundWindow(dwProcessId: Int): Boolean
    }

    private val user32Extra: User32Extra? by lazy {
        if (!isWindows()) null
        else runCatching { Native.load("user32", User32Extra::class.java) }.getOrNull()
    }

    fun isWindows(): Boolean = "win" in System.getProperty("os.name").orEmpty().lowercase()

    fun isKnownTelegramExe(path: String): Boolean {
        val name = path.substringAfterLast('\\').substringAfterLast('/').lowercase()
        return name in KNOWN_CLIENT_EXES
    }

    fun isWindowsStorePath(path: String): Boolean =
        "\\windowsapps\\" in path.replace('/', '\\').lowercase()

    /**
     * Нормализует `-workdir` для Telegram Desktop:
     * заменяет `\` на `/`, чтобы Java `ProcessBuilder` на Windows никогда не превратил
     * завершающий обратный слэш в экранированную кавычку `\"`, ломающую аргумент `-- tg://...`.
     */
    internal fun normalizeWorkDir(raw: String?): String? {
        val trimmed = raw?.trim()?.trim('"') ?: return null
        if (trimmed.isBlank()) return null
        val slash = trimmed.replace('\\', '/')
        return if (slash.endsWith("/")) slash else "$slash/"
    }

    /**
     * Парсит команду из реестра Windows (`HKCU\Software\Classes\tg\shell\open\command`),
     * принимая ТОЛЬКО реальные клиенты Telegram (и никогда — браузеры вроде chrome.exe / msedge.exe).
     */
    internal fun parseRegistryCommand(commandLine: String): TelegramLaunchSpec? {
        val tokens = splitCommandTokens(commandLine)
        if (tokens.isEmpty()) return null
        val exe = tokens[0].trim()
        if (!isKnownTelegramExe(exe)) return null

        var workDir: String? = null
        var i = 1
        while (i < tokens.size) {
            if (tokens[i].equals("-workdir", ignoreCase = true) && i + 1 < tokens.size) {
                val cand = tokens[i + 1].trim()
                if (cand.isNotBlank() && cand != "%1") {
                    workDir = normalizeWorkDir(cand)
                }
                i += 2
            } else {
                i++
            }
        }
        return TelegramLaunchSpec(
            exePath = exe,
            workDir = workDir,
            source = "registry",
            isStoreApp = isWindowsStorePath(exe)
        )
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
        val wd = normalizeWorkDir(spec.workDir)
        if (!wd.isNullOrBlank()) {
            add("-workdir")
            add(wd)
        }
        add("--")
        add(tgUrl)
    }

    data class RunningProcess(val pid: Long, val exePath: String)

    /** Ищет установленный или уже запущенный клиент Telegram на Windows. */
    fun findTelegramClient(
        customExePath: String = "",
        runningProcesses: List<RunningProcess> = detectRunningTelegramProcesses(),
        registryCommand: String? = readRegistryTgCommand(),
        standardCandidates: List<File> = defaultInstallCandidates(),
        fileExists: (String) -> Boolean = { File(it).isFile }
    ): TelegramLaunchSpec? {
        val regSpec = registryCommand?.let(::parseRegistryCommand)

        // 0. Пользовательский путь к Telegram.exe (если указан вручную).
        val manual = customExePath.trim().trim('"')
        if (manual.isNotBlank() && fileExists(manual)) {
            val runningMatch = runningProcesses.firstOrNull { pathsEqual(it.exePath, manual) }
            val matchedWorkDir = if (regSpec != null && pathsEqual(regSpec.exePath, manual)) regSpec.workDir else null
            return TelegramLaunchSpec(
                exePath = manual,
                workDir = matchedWorkDir,
                source = "custom",
                runningPid = runningMatch?.pid,
                isStoreApp = isWindowsStorePath(manual)
            )
        }

        // 1. Уже запущенный процесс (идеально для портативного Telegram в любой папке и для поднятия окна).
        for (proc in runningProcesses) {
            if (proc.exePath.isBlank()) continue
            val store = isWindowsStorePath(proc.exePath)
            if (!store && !fileExists(proc.exePath)) continue
            val matchedWorkDir = if (regSpec != null && pathsEqual(regSpec.exePath, proc.exePath)) regSpec.workDir else null
            return TelegramLaunchSpec(
                exePath = proc.exePath,
                workDir = matchedWorkDir,
                source = "running",
                runningPid = proc.pid,
                isStoreApp = store
            )
        }

        // 2. Команда протокола tg:// из реестра Windows (сохраняет точный -workdir).
        if (regSpec != null && (regSpec.isStoreApp || fileExists(regSpec.exePath))) {
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
        customExePath: String = "",
        specOverride: TelegramLaunchSpec? = null,
        processStarter: (List<String>, File?) -> Pair<Boolean, String> = ::startProcessAndCheck,
        shellFallback: (String) -> Boolean = ::openViaWindowsShellIfTgHandlerValid,
        foregroundBumper: (Long?) -> Unit = ::bringTelegramToFront
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

        // Разрешаем окну Telegram выпрыгнуть поверх повышенного (Admin) окна WilyScout.
        runCatching { user32Extra?.AllowSetForegroundWindow(ASFW_ANY) }

        val spec = specOverride ?: findTelegramClient(customExePath = customExePath)
        val attemptDetails = ArrayList<String>()

        if (spec != null && !spec.isStoreApp) {
            val args = buildLaunchArgs(spec, tgUrl)
            val workDirFile = File(spec.exePath).parentFile?.takeIf { it.isDirectory }
            val (ok, detail) = processStarter(args, workDirFile)
            attemptDetails.add("direct(${spec.source}:${spec.exePath}) -> $detail")
            if (ok) {
                foregroundBumper(spec.runningPid)
                val exeName = File(spec.exePath).name
                return TelegramOpenResult(
                    opened = true,
                    message = "Передано в $exeName — подтвердите подключение прокси в окне Telegram",
                    launchedVia = exeName,
                    detail = attemptDetails.joinToString("; ")
                )
            }
        } else if (spec != null && spec.isStoreApp) {
            attemptDetails.add("store-app(${spec.exePath}) -> shell")
        }

        // Для Microsoft Store (WindowsApps) или если прямой запуск не сработал — пробуем Win32 ShellExecute,
        // НО только если в реестре tg:// привязан НЕ к браузеру!
        if (shellFallback(tgUrl)) {
            foregroundBumper(spec?.runningPid)
            return TelegramOpenResult(
                opened = true,
                message = "Ссылка передана в Telegram (через обработчик tg://) — подтвердите прокси в окне Telegram",
                launchedVia = "shell-tg",
                detail = (attemptDetails + "ShellExecute=ok").joinToString("; ")
            )
        }

        val reason = if (spec == null) {
            "Telegram.exe не найден — укажите его кнопкой «Указать Telegram.exe» (или откройте портативный Telegram); ссылка скопирована в буфер"
        } else {
            "Не удалось передать ссылку в ${File(spec.exePath).name} — ссылка скопирована в буфер (вставьте её в «Избранное» Telegram)"
        }
        return TelegramOpenResult(
            opened = false,
            message = reason,
            detail = (attemptDetails + "ShellExecute=skipped/failed").joinToString("; ")
        )
    }

    /**
     * Запускает `Telegram.exe -- tg://...` и проверяет в течение 350 мс, что процесс не упал
     * мгновенно с ненулевым кодом ошибки (например Access Denied или неверные флаги).
     * Если Telegram уже запущен, новый экземпляр быстро отдаёт ссылку по IPC и выходит с кодом 0 — это успех.
     */
    private fun startProcessAndCheck(args: List<String>, workingDir: File?): Pair<Boolean, String> = runCatching {
        val pb = ProcessBuilder(args)
        if (workingDir != null) pb.directory(workingDir)
        val proc = pb.start()
        val exitedQuickly = proc.waitFor(350L, TimeUnit.MILLISECONDS)
        if (!exitedQuickly) {
            true to "started(alive)"
        } else {
            val code = proc.exitValue()
            if (code == 0) true to "ipc-forwarded(exit=0)"
            else false to "exit=$code"
        }
    }.getOrElse { e ->
        false to "${e.javaClass.simpleName}:${e.message}"
    }

    /** Выносит уже открытое окно Telegram Desktop на передний план, чтобы диалог прокси был сразу виден. */
    private fun bringTelegramToFront(pid: Long?) {
        if (!isWindows() || pid == null || pid <= 0L) return
        runCatching {
            val user32 = User32.INSTANCE
            user32Extra?.AllowSetForegroundWindow(pid.toInt())
            val targetWindows = ArrayList<WinDef.HWND>()
            user32.EnumWindows(
                WinUser.WNDENUMPROC { hwnd, _ ->
                    val ref = IntByReference()
                    user32.GetWindowThreadProcessId(hwnd, ref)
                    if (ref.value.toLong() == pid && user32.IsWindowVisible(hwnd)) {
                        val buf = CharArray(256)
                        val len = user32.GetWindowText(hwnd, buf, buf.size)
                        if (len > 0) {
                            targetWindows.add(hwnd)
                        }
                    }
                    true
                },
                null
            )
            val hwnd = targetWindows.firstOrNull() ?: return@runCatching
            user32.ShowWindow(hwnd, SW_RESTORE)
            user32.SetForegroundWindow(hwnd)
        }
    }

    private fun detectRunningTelegramProcesses(): List<RunningProcess> = runCatching {
        ProcessHandle.allProcesses()
            .map { handle ->
                val cmd = handle.info().command().orElse(null)
                if (cmd.isNullOrBlank() || !isKnownTelegramExe(cmd)) null
                else RunningProcess(handle.pid(), cmd)
            }
            .filter { it != null }
            .map { it!! }
            .toList()
    }.getOrDefault(emptyList())

    private fun readRegistryTgCommand(): String? {
        if (!isWindows()) return null
        val candidates = ArrayList<Pair<WinReg.HKEY, String>>()

        // 1. Проверяем UserChoice ProgId (Windows 10/11), если пользователь выбирал обработчик tg://.
        val progId = runCatching {
            val path = "Software\\Microsoft\\Windows\\Shell\\Associations\\UrlAssociations\\tg\\UserChoice"
            if (Advapi32Util.registryValueExists(WinReg.HKEY_CURRENT_USER, path, "ProgId")) {
                Advapi32Util.registryGetStringValue(WinReg.HKEY_CURRENT_USER, path, "ProgId")
            } else null
        }.getOrNull()
        if (!progId.isNullOrBlank()) {
            candidates.add(WinReg.HKEY_CURRENT_USER to "Software\\Classes\\$progId\\shell\\open\\command")
            candidates.add(WinReg.HKEY_CLASSES_ROOT to "$progId\\shell\\open\\command")
        }

        candidates.add(WinReg.HKEY_CURRENT_USER to "Software\\Classes\\tg\\shell\\open\\command")
        candidates.add(WinReg.HKEY_CLASSES_ROOT to "tg\\shell\\open\\command")
        candidates.add(WinReg.HKEY_LOCAL_MACHINE to "SOFTWARE\\Classes\\tg\\shell\\open\\command")

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

    /**
     * Вызывает ShellExecute для `tg://` только когда протокол зарегистрирован в Windows
     * и НЕ привязан к веб-браузеру (чтобы исключить открытие пустой вкладки браузера).
     */
    private fun openViaWindowsShellIfTgHandlerValid(tgUrl: String): Boolean {
        if (!isWindows()) return false
        val regCmd = readRegistryTgCommand()
        if (!regCmd.isNullOrBlank()) {
            val lower = regCmd.lowercase()
            val isBrowser = listOf("chrome.exe", "msedge.exe", "firefox.exe", "browser.exe", "opera.exe", "brave.exe", "vivaldi.exe")
                .any { it in lower }
            if (isBrowser) return false
        } else {
            val hasDelegate = runCatching {
                Advapi32Util.registryKeyExists(WinReg.HKEY_CURRENT_USER, "Software\\Classes\\tg") ||
                    Advapi32Util.registryKeyExists(WinReg.HKEY_CLASSES_ROOT, "tg")
            }.getOrDefault(false)
            if (!hasDelegate) return false
        }
        return runCatching {
            val res = Shell32.INSTANCE.ShellExecute(null, "open", tgUrl, null, null, 1)
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
            out.add(File(userProfile, """Desktop\Telegram Desktop\Telegram.exe"""))
            out.add(File(userProfile, """Desktop\Telegram\Telegram.exe"""))
            out.add(File(userProfile, """Downloads\Telegram Desktop\Telegram.exe"""))
            out.add(File(userProfile, """Downloads\Telegram\Telegram.exe"""))
        }
        out.add(File("""C:\Telegram\Telegram.exe"""))
        out.add(File("""D:\Telegram\Telegram.exe"""))
        out.add(File("""D:\Telegram Desktop\Telegram.exe"""))
        out.add(File(progFiles, """Telegram Desktop\Telegram.exe"""))
        out.add(File(progFiles86, """Telegram Desktop\Telegram.exe"""))
        return out
    }

    private fun pathsEqual(a: String, b: String): Boolean =
        a.replace('/', '\\').trimEnd('\\').equals(b.replace('/', '\\').trimEnd('\\'), ignoreCase = true)
}
