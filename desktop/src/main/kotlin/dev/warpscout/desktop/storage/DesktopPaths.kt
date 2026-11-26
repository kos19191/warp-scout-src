package dev.warpscout.desktop.storage

import java.io.File

/**
 * Каталоги данных WarpScout Desktop.
 *
 * По умолчанию на Windows: `%APPDATA%\WarpScout`.
 * Если рядом с приложением лежит файл `portable` или `portable.txt`, все данные
 * хранятся рядом в `./data` — удобно для портативного архива на флешке.
 */
class DesktopPaths(val root: File) {

    val tunnelsDir: File get() = File(root, "tunnels")
    val nativeDir: File get() = File(root, "native")
    val listsDir: File get() = File(root, "lists")
    val reportsDir: File get() = File(root, "reports")
    val backupsDir: File get() = File(root, "backups")
    val updatesDir: File get() = File(root, "updates")
    val logsDir: File get() = File(root, "logs")

    val settingsFile: File get() = File(root, "settings.json")
    val shortlistFile: File get() = File(root, "shortlist.json")
    val activeConfFile: File get() = File(root, "active.conf")
    val accountCacheFile: File get() = File(root, "account-cache.json")
    val logFile: File get() = File(logsDir, "warpscout.log")
    val lockFile: File get() = File(root, "instance.lock")

    fun ensureDirs() {
        listOf(root, tunnelsDir, nativeDir, listsDir, reportsDir, backupsDir, logsDir).forEach { it.mkdirs() }
    }

    companion object {
        fun resolveDefault(): DesktopPaths {
            val cwd = File(System.getProperty("user.dir") ?: ".")
            if (File(cwd, "portable").exists() || File(cwd, "portable.txt").exists()) {
                return DesktopPaths(File(cwd, "data")).also { it.ensureDirs() }
            }
            val os = System.getProperty("os.name").orEmpty().lowercase()
            val (base, legacy) = when {
                "win" in os -> {
                    val appData = System.getenv("APPDATA")?.takeIf { it.isNotBlank() }
                    val rootDir = if (appData != null) File(appData) else File(System.getProperty("user.home"), "AppData/Roaming")
                    File(rootDir, "WilyScout") to File(rootDir, "WarpScout")
                }
                "mac" in os -> {
                    val rootDir = File(System.getProperty("user.home"), "Library/Application Support")
                    File(rootDir, "WilyScout") to File(rootDir, "WarpScout")
                }
                else -> {
                    val xdg = System.getenv("XDG_CONFIG_HOME")?.takeIf { it.isNotBlank() }
                    val rootDir = if (xdg != null) File(xdg) else File(System.getProperty("user.home"), ".config")
                    File(rootDir, "wilyscout") to File(rootDir, "warpscout")
                }
            }
            val paths = DesktopPaths(base).also { it.ensureDirs() }
            migrateLegacyDataIfNeeded(legacy, paths)
            return paths
        }

        /** Мягкий перенос настроек, Топ-3 и аккаунта WARP из старого каталога WarpScout при первом запуске WilyScout. */
        internal fun migrateLegacyDataIfNeeded(legacyRoot: File, target: DesktopPaths) {
            if (!legacyRoot.isDirectory || target.settingsFile.exists()) return
            for (name in listOf("settings.json", "shortlist.json", "active.conf", "account-cache.json")) {
                val src = File(legacyRoot, name)
                val dst = File(target.root, name)
                if (src.isFile && !dst.exists()) {
                    runCatching { src.copyTo(dst, overwrite = false) }
                }
            }
        }
    }
}
