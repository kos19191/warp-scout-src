package dev.warpscout.desktop.tunnel

import java.io.File
import java.util.concurrent.TimeUnit

data class CommandResult(
    val exitCode: Int,
    val stdout: String,
    val stderr: String,
    val timedOut: Boolean = false
) {
    val ok: Boolean get() = exitCode == 0 && !timedOut
    val combined: String get() = listOf(stdout, stderr).filter { it.isNotBlank() }.joinToString("\n").trim()
}

/** Абстракция запуска системных команд — нужна для модульного тестирования без Windows. */
interface CommandRunner {
    fun run(command: List<String>, timeoutMs: Long = 15_000L): CommandResult
    fun isElevated(): Boolean
    fun runElevated(executable: String, args: List<String>, timeoutMs: Long = 20_000L): CommandResult
}

class ProcessCommandRunner : CommandRunner {

    override fun run(command: List<String>, timeoutMs: Long): CommandResult {
        if (command.isEmpty()) return CommandResult(-1, "", "пустая команда")
        return try {
            val pb = ProcessBuilder(command)
            pb.redirectErrorStream(false)
            val proc = pb.start()
            val outFuture = StringBuilder()
            val errFuture = StringBuilder()
            val tOut = Thread {
                runCatching { proc.inputStream.bufferedReader(Charsets.UTF_8).use { outFuture.append(it.readText()) } }
            }.apply { isDaemon = true; start() }
            val tErr = Thread {
                runCatching { proc.errorStream.bufferedReader(Charsets.UTF_8).use { errFuture.append(it.readText()) } }
            }.apply { isDaemon = true; start() }

            val finished = proc.waitFor(timeoutMs, TimeUnit.MILLISECONDS)
            if (!finished) {
                proc.destroyForcibly()
                return CommandResult(-1, outFuture.toString(), "таймаут выполнения команды (${timeoutMs} мс)", timedOut = true)
            }
            tOut.join(1000)
            tErr.join(1000)
            CommandResult(proc.exitValue(), outFuture.toString().trim(), errFuture.toString().trim())
        } catch (e: Exception) {
            CommandResult(-1, "", "${e.javaClass.simpleName}: ${e.message}")
        }
    }

    override fun isElevated(): Boolean {
        val os = System.getProperty("os.name").orEmpty().lowercase()
        if ("win" !in os) return System.getProperty("user.name") == "root"
        // `net session` завершается с кодом 0 только в повышенном (Administrator) процессе.
        val res = run(listOf("cmd.exe", "/c", "net session >nul 2>&1"), timeoutMs = 4000L)
        return res.ok
    }

    override fun runElevated(executable: String, args: List<String>, timeoutMs: Long): CommandResult {
        if (isElevated()) {
            return run(listOf(executable) + args, timeoutMs)
        }
        val os = System.getProperty("os.name").orEmpty().lowercase()
        if ("win" !in os) {
            return CommandResult(-1, "", "требуются права администратора (root)")
        }
        // Безопасное экранирование аргументов для PowerShell Start-Process -Verb RunAs.
        val escapedExe = executable.replace("'", "''")
        val argListPs = if (args.isEmpty()) "@()" else {
            args.joinToString(", ", "@(", ")") { a -> "'${a.replace("'", "''")}'" }
        }
        val script = "\$p = Start-Process -FilePath '$escapedExe' -ArgumentList $argListPs -Verb RunAs -WindowStyle Hidden -Wait -PassThru; exit \$p.ExitCode"
        return run(
            listOf("powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script),
            timeoutMs = timeoutMs
        )
    }
}

/** Управление автозапуском приложения в реестре Windows (HKCU — прав администратора не требует). */
object WindowsAutostart {
    private const val REG_KEY = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
    private const val VALUE_NAME = "WarpScout"

    fun isWindows(): Boolean = "win" in System.getProperty("os.name").orEmpty().lowercase()

    fun setEnabled(enabled: Boolean, runner: CommandRunner = ProcessCommandRunner()): CommandResult {
        if (!isWindows()) return CommandResult(0, "не Windows", "")
        return if (enabled) {
            val launchCmd = resolveLaunchCommand()
                ?: return CommandResult(-1, "", "не удалось определить путь к WarpScout.exe")
            runner.run(
                listOf("reg.exe", "add", REG_KEY, "/v", VALUE_NAME, "/t", "REG_SZ", "/d", "\"$launchCmd\" --minimized", "/f"),
                timeoutMs = 5000L
            )
        } else {
            val res = runner.run(
                listOf("reg.exe", "delete", REG_KEY, "/v", VALUE_NAME, "/f"),
                timeoutMs = 5000L
            )
            // Если записи уже нет — это не ошибка.
            if (res.ok || "unable to find" in res.combined.lowercase() || "не удается найти" in res.combined.lowercase()) {
                CommandResult(0, "автозапуск отключён", "")
            } else res
        }
    }

    fun isEnabled(runner: CommandRunner = ProcessCommandRunner()): Boolean {
        if (!isWindows()) return false
        return runner.run(listOf("reg.exe", "query", REG_KEY, "/v", VALUE_NAME), timeoutMs = 4000L).ok
    }

    private fun resolveLaunchCommand(): String? {
        val jpackageApp = System.getProperty("jpackage.app-path")?.takeIf { it.isNotBlank() }
        if (jpackageApp != null && File(jpackageApp).exists()) return jpackageApp
        val cmd = ProcessHandle.current().info().command().orElse(null)
        if (cmd != null && cmd.lowercase().endsWith("warpscout.exe") && File(cmd).exists()) return cmd
        val localExe = File(System.getProperty("user.dir") ?: ".", "WarpScout.exe")
        if (localExe.exists()) return localExe.absolutePath
        return cmd
    }
}
