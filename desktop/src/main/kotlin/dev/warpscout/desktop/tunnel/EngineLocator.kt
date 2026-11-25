package dev.warpscout.desktop.tunnel

import java.io.File

enum class EngineKind(val title: String, val supportsAwg: Boolean) {
    AMNEZIA_WG("AmneziaWG", true),
    WIREGUARD("WireGuard (без AWG-шума)", false),
    NONE("Не найден", false)
}

/** Найденный системный или встроенный движок туннеля на Windows. */
data class EngineInfo(
    val kind: EngineKind,
    val tunnelExe: File?,
    val cliExe: File?,
    val sourceLabel: String
) {
    val available: Boolean get() = kind != EngineKind.NONE && tunnelExe != null
    val supportsAwg: Boolean get() = kind.supportsAwg

    /** Имя службы Windows, которую создаёт `/installtunnelservice`. */
    fun serviceNameFor(tunnelName: String): String = when (kind) {
        EngineKind.AMNEZIA_WG -> "AmneziaWGTunnel\$$tunnelName"
        EngineKind.WIREGUARD -> "WireGuardTunnel\$$tunnelName"
        EngineKind.NONE -> tunnelName
    }
}

/**
 * Ищет `amneziawg.exe` + `awg.exe` (или запасной `wireguard.exe` + `wg.exe`):
 *   1. путь, указанный пользователем в настройках;
 *   2. папка `bin/` рядом с приложением (портативный комплект);
 *   3. стандартные каталоги установки Windows (`Program Files\AmneziaWG`, `%LOCALAPPDATA%`);
 *   4. системный `PATH`;
 *   5. запасной вариант — официальный WireGuard (если профиль шума `none`).
 */
object EngineLocator {

    const val AMNEZIAWG_RELEASES_URL = "https://github.com/amnezia-vpn/amneziawg-windows-client/releases"

    fun locate(
        customPath: String = "",
        appDir: File = File(System.getProperty("user.dir") ?: "."),
        runner: CommandRunner = ProcessCommandRunner()
    ): EngineInfo {
        // 1. Явно указанный путь в настройках (файл или папка).
        if (customPath.isNotBlank()) {
            inspectPath(File(customPath.trim()), "из настроек")?.let { return it }
        }

        // 2. Встроенная папка bin/ рядом с приложением или jpackage-каталогом.
        val jpackageDir = System.getProperty("jpackage.app-path")?.let { File(it).parentFile }
        val localDirs = listOfNotNull(
            File(appDir, "bin"),
            appDir,
            jpackageDir?.let { File(it, "bin") },
            jpackageDir
        ).distinct()
        for (dir in localDirs) {
            inspectDirectory(dir, "встроенный (${dir.name})", preferAwg = true)?.let { return it }
        }

        // 3. Стандартные пути установки AmneziaWG на Windows.
        val programFiles = System.getenv("ProgramFiles") ?: "C:\\Program Files"
        val programFiles86 = System.getenv("ProgramFiles(x86)") ?: "C:\\Program Files (x86)"
        val localAppData = System.getenv("LOCALAPPDATA") ?: ""
        val awgDirs = buildList {
            add(File(programFiles, "AmneziaWG"))
            add(File(programFiles86, "AmneziaWG"))
            if (localAppData.isNotBlank()) {
                add(File(localAppData, "Programs\\AmneziaWG"))
                add(File(localAppData, "AmneziaWG"))
            }
        }
        for (dir in awgDirs) {
            inspectDirectory(dir, "системный (${dir.absolutePath})", preferAwg = true)?.let { return it }
        }

        // 4. Поиск amneziawg.exe через PATH (`where`).
        whereOnPath("amneziawg.exe", runner)?.let { exe ->
            val cli = File(exe.parentFile, "awg.exe").takeIf { it.isFile } ?: whereOnPath("awg.exe", runner)
            return EngineInfo(EngineKind.AMNEZIA_WG, exe, cli, "из PATH (${exe.parent})")
        }

        // 5. Фолбэк на стандартный WireGuard (работает с профилем шума `none`).
        val wgDirs = listOf(File(programFiles, "WireGuard"), File(programFiles86, "WireGuard"))
        for (dir in wgDirs) {
            inspectDirectory(dir, "системный WireGuard (${dir.absolutePath})", preferAwg = false)?.let { return it }
        }
        whereOnPath("wireguard.exe", runner)?.let { exe ->
            val cli = File(exe.parentFile, "wg.exe").takeIf { it.isFile } ?: whereOnPath("wg.exe", runner)
            return EngineInfo(EngineKind.WIREGUARD, exe, cli, "из PATH (${exe.parent})")
        }

        return EngineInfo(EngineKind.NONE, null, null, "AmneziaWG не установлен")
    }

    internal fun inspectPath(path: File, label: String): EngineInfo? {
        if (!path.exists()) return null
        if (path.isDirectory) return inspectDirectory(path, label, preferAwg = true)
            ?: inspectDirectory(path, label, preferAwg = false)
        val lower = path.name.lowercase()
        val parent = path.parentFile ?: File(".")
        return when {
            lower == "amneziawg.exe" -> EngineInfo(
                EngineKind.AMNEZIA_WG,
                path,
                File(parent, "awg.exe").takeIf { it.isFile },
                label
            )
            lower == "awg.exe" -> {
                val tunnel = File(parent, "amneziawg.exe").takeIf { it.isFile } ?: return null
                EngineInfo(EngineKind.AMNEZIA_WG, tunnel, path, label)
            }
            lower == "wireguard.exe" -> EngineInfo(
                EngineKind.WIREGUARD,
                path,
                File(parent, "wg.exe").takeIf { it.isFile },
                label
            )
            else -> null
        }
    }

    internal fun inspectDirectory(dir: File, label: String, preferAwg: Boolean): EngineInfo? {
        if (!dir.isDirectory) return null
        if (preferAwg) {
            val awg = File(dir, "amneziawg.exe")
            if (awg.isFile) {
                val cli = File(dir, "awg.exe").takeIf { it.isFile }
                return EngineInfo(EngineKind.AMNEZIA_WG, awg, cli, label)
            }
        } else {
            val wg = File(dir, "wireguard.exe")
            if (wg.isFile) {
                val cli = File(dir, "wg.exe").takeIf { it.isFile }
                return EngineInfo(EngineKind.WIREGUARD, wg, cli, label)
            }
        }
        return null
    }

    private fun whereOnPath(exeName: String, runner: CommandRunner): File? {
        if (!WindowsAutostart.isWindows()) return null
        val res = runner.run(listOf("where.exe", exeName), timeoutMs = 3000L)
        if (!res.ok) return null
        val first = res.stdout.lineSequence().map { it.trim() }.firstOrNull { it.isNotEmpty() } ?: return null
        return File(first).takeIf { it.isFile }
    }
}
