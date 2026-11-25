package dev.warpscout.desktop.update

import dev.warpscout.core.json.JsonVal
import dev.warpscout.core.json.parseJson
import dev.warpscout.desktop.tunnel.WindowsAutostart
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.HttpURLConnection
import java.net.URI
import java.security.MessageDigest
import java.time.Instant
import java.util.Properties

data class BuildInfo(
    val version: String = "1.10.25",
    val buildTimeUtc: String = "",
    val commitSha: String = "local",
    val githubRepo: String = "kos19191/warp-scout-src"
) {
    val buildTimeEpochMs: Long
        get() = runCatching { Instant.parse(buildTimeUtc).toEpochMilli() }.getOrDefault(0L)

    companion object {
        val current: BuildInfo by lazy { load() }

        fun load(): BuildInfo {
            val stream = BuildInfo::class.java.getResourceAsStream("/warpscout-build.properties")
                ?: return BuildInfo()
            return runCatching {
                val props = Properties()
                stream.use { props.load(it.reader(Charsets.UTF_8)) }
                BuildInfo(
                    version = props.getProperty("version", "1.10.25").trim(),
                    buildTimeUtc = props.getProperty("buildTimeUtc", "").trim(),
                    commitSha = props.getProperty("commitSha", "local").trim(),
                    githubRepo = props.getProperty("githubRepo", "kos19191/warp-scout-src").trim()
                )
            }.getOrDefault(BuildInfo())
        }
    }
}

enum class InstallKind(val title: String) {
    MSI("Установщик MSI"),
    PORTABLE("Портативная сборка (ZIP)")
}

data class ReleaseAsset(
    val name: String,
    val downloadUrl: String,
    val sizeBytes: Long,
    val updatedAtUtc: String
) {
    val updatedAtEpochMs: Long
        get() = runCatching { Instant.parse(updatedAtUtc).toEpochMilli() }.getOrDefault(0L)
}

data class ReleaseInfo(
    val tagName: String,
    val title: String,
    val htmlUrl: String,
    val prerelease: Boolean,
    val publishedAtUtc: String,
    val version: String,
    val msiAsset: ReleaseAsset?,
    val portableAsset: ReleaseAsset?,
    val checksumsAsset: ReleaseAsset?,
    val notes: String = ""
) {
    val primaryAssetEpochMs: Long
        get() = maxOf(
            msiAsset?.updatedAtEpochMs ?: 0L,
            portableAsset?.updatedAtEpochMs ?: 0L,
            runCatching { Instant.parse(publishedAtUtc).toEpochMilli() }.getOrDefault(0L)
        )

    fun assetFor(kind: InstallKind): ReleaseAsset? = when (kind) {
        InstallKind.MSI -> msiAsset ?: portableAsset
        InstallKind.PORTABLE -> portableAsset ?: msiAsset
    }
}

data class UpdateCheckResult(
    val ok: Boolean,
    val updateAvailable: Boolean,
    val release: ReleaseInfo? = null,
    val message: String = "",
    val error: String? = null
)

data class UpdateDownloadResult(
    val ok: Boolean,
    val file: File? = null,
    val isMsi: Boolean = true,
    val sha256Verified: Boolean = false,
    val error: String? = null
)

/**
 * Проверка, скачивание с проверкой SHA-256 и самообновление WarpScout Desktop из GitHub Releases.
 *
 * Поддерживает и обычные тегированные релизы (`v1.10.26`), и скользящий пререлиз
 * `desktop-windows-preview` (сравнение по времени сборки ассета, если номер версии совпадает).
 */
object AppUpdater {

    /**
     * Запас по времени (5 минут) при сравнении `updated_at` ассета с временем сборки JAR:
     * GitHub Actions собирает MSI и загружает его в релиз примерно на 2–4 минуты позже `generateBuildInfo`,
     * поэтому собственная свежеустановленная сборка не должна предлагать обновиться на саму себя.
     */
    internal const val ROLLING_BUILD_MARGIN_MS = 5 * 60_000L
    private const val USER_AGENT = "WarpScout-Desktop-Updater"

    fun releasesPageUrl(repo: String = BuildInfo.current.githubRepo): String =
        "https://github.com/$repo/releases"

    fun detectInstallKind(): InstallKind {
        val exePath = System.getProperty("jpackage.app-path")?.trim().orEmpty()
        if (exePath.isBlank()) return InstallKind.MSI
        val normalized = exePath.replace('/', '\\').lowercase()
        return if ("\\program files\\" in normalized || "\\program files (x86)\\" in normalized) {
            InstallKind.MSI
        } else {
            InstallKind.PORTABLE
        }
    }

    fun currentExeFile(): File? =
        System.getProperty("jpackage.app-path")?.takeIf { it.isNotBlank() }?.let { File(it) }?.takeIf { it.isFile }

    fun checkForUpdate(
        current: BuildInfo = BuildInfo.current,
        includePrereleases: Boolean = true,
        fetcher: (String) -> String? = ::httpGetText
    ): UpdateCheckResult {
        val apiUrl = "https://api.github.com/repos/${current.githubRepo}/releases?per_page=10"
        val body = fetcher(apiUrl)
            ?: return UpdateCheckResult(
                ok = false,
                updateAvailable = false,
                error = "Не удалось связаться с GitHub Releases (проверьте интернет или включите туннель)"
            )

        val releases = parseReleasesJson(body)
            .filter { it.msiAsset != null || it.portableAsset != null }
            .filter { includePrereleases || !it.prerelease }

        if (releases.isEmpty()) {
            return UpdateCheckResult(
                ok = true,
                updateAvailable = false,
                message = "Подходящих Windows-релизов на GitHub не найдено"
            )
        }

        // Выбираем лучший релиз: с наибольшей версией, а при равной версии — самый свежий по времени файла.
        val best = releases.maxWithOrNull(
            Comparator<ReleaseInfo> { a, b ->
                val vc = compareVersions(a.version, b.version)
                if (vc != 0) vc else a.primaryAssetEpochMs.compareTo(b.primaryAssetEpochMs)
            }
        )!!

        val newer = isNewer(best, current)
        val msg = if (newer) {
            val tagPart = if (best.prerelease) " (${best.tagName})" else ""
            "Доступна новая версия ${best.version}$tagPart"
        } else {
            "У вас установлена актуальная версия ${current.version}"
        }
        return UpdateCheckResult(
            ok = true,
            updateAvailable = newer,
            release = best,
            message = msg
        )
    }

    /** Проверяет, новее ли удалённый релиз текущей сборки (по SemVer, а при равной версии — по дате ассета). */
    fun isNewer(remote: ReleaseInfo, current: BuildInfo): Boolean {
        val vc = compareVersions(remote.version, current.version)
        if (vc > 0) return true
        if (vc < 0) return false
        val localMs = current.buildTimeEpochMs
        val remoteMs = remote.primaryAssetEpochMs
        if (localMs <= 0L || remoteMs <= 0L) return false
        return remoteMs > localMs + ROLLING_BUILD_MARGIN_MS
    }

    /** Сравнение версий вида `1.10.25`, `v1.10.24`, `1.11.0-preview`. */
    fun compareVersions(a: String, b: String): Int {
        val pa = parseVersionParts(a)
        val pb = parseVersionParts(b)
        val maxLen = maxOf(pa.size, pb.size)
        for (i in 0 until maxLen) {
            val va = pa.getOrElse(i) { 0 }
            val vb = pb.getOrElse(i) { 0 }
            if (va != vb) return va.compareTo(vb)
        }
        return 0
    }

    private fun parseVersionParts(raw: String): List<Int> {
        val m = Regex("""(\d+(?:\.\d+)+)""").find(raw) ?: return listOf(0)
        return m.groupValues[1].split('.').mapNotNull { it.toIntOrNull() }
    }

    fun parseReleasesJson(json: String): List<ReleaseInfo> {
        val root = runCatching { parseJson(json) }.getOrNull() ?: return emptyList()
        val items = when (root) {
            is JsonVal.Arr -> root.items
            is JsonVal.Obj -> listOf(root)
            else -> emptyList()
        }
        return items.mapNotNull { item ->
            val obj = item as? JsonVal.Obj ?: return@mapNotNull null
            if (obj.bool("draft") == true) return@mapNotNull null
            val tag = obj.str("tag_name").orEmpty().trim()
            if (tag.isEmpty()) return@mapNotNull null
            val title = obj.str("name").orEmpty().ifBlank { tag }
            val htmlUrl = obj.str("html_url").orEmpty()
            val prerelease = obj.bool("prerelease") ?: false
            val publishedAt = obj.str("published_at").orEmpty()
            val notes = obj.str("body").orEmpty()

            val assets = obj.arr("assets")?.items.orEmpty().mapNotNull { a ->
                val ao = a as? JsonVal.Obj ?: return@mapNotNull null
                val name = ao.str("name").orEmpty()
                val url = ao.str("browser_download_url").orEmpty()
                if (name.isBlank() || url.isBlank()) return@mapNotNull null
                ReleaseAsset(
                    name = name,
                    downloadUrl = url,
                    sizeBytes = ao.num("size")?.toLong() ?: 0L,
                    updatedAtUtc = ao.str("updated_at").orEmpty().ifBlank { publishedAt }
                )
            }

            val msi = assets.firstOrNull { it.name.endsWith(".msi", ignoreCase = true) }
            val zip = assets.firstOrNull {
                it.name.endsWith(".zip", ignoreCase = true) && "portable" in it.name.lowercase()
            } ?: assets.firstOrNull { it.name.endsWith(".zip", ignoreCase = true) }
            val sums = assets.firstOrNull { it.name.equals("SHA256SUMS.txt", ignoreCase = true) }

            val version = extractVersion(msi?.name, zip?.name, title, tag)

            ReleaseInfo(
                tagName = tag,
                title = title,
                htmlUrl = htmlUrl,
                prerelease = prerelease,
                publishedAtUtc = publishedAt,
                version = version,
                msiAsset = msi,
                portableAsset = zip,
                checksumsAsset = sums,
                notes = notes
            )
        }
    }

    private fun extractVersion(vararg candidates: String?): String {
        val rx = Regex("""(\d+\.\d+(?:\.\d+)*)""")
        for (c in candidates) {
            if (c.isNullOrBlank()) continue
            val m = rx.find(c)
            if (m != null) return m.groupValues[1]
        }
        return "0.0.0"
    }

    fun parseSha256Sums(content: String): Map<String, String> {
        val out = LinkedHashMap<String, String>()
        for (line in content.lineSequence()) {
            val trimmed = line.trim()
            if (trimmed.isEmpty() || trimmed.startsWith("#")) continue
            val parts = trimmed.split(Regex("""\s+"""), limit = 2)
            if (parts.size == 2 && parts[0].length == 64) {
                val fileName = parts[1].trim().removePrefix("*")
                out[fileName] = parts[0].lowercase()
            }
        }
        return out
    }

    fun computeSha256(file: File): String {
        val md = MessageDigest.getInstance("SHA-256")
        FileInputStream(file).use { input ->
            val buf = ByteArray(64 * 1024)
            while (true) {
                val n = input.read(buf)
                if (n < 0) break
                md.update(buf, 0, n)
            }
        }
        return md.digest().joinToString("") { "%02x".format(it) }
    }

    fun downloadUpdate(
        release: ReleaseInfo,
        installKind: InstallKind,
        destDir: File,
        onProgress: (downloadedBytes: Long, totalBytes: Long) -> Unit = { _, _ -> }
    ): UpdateDownloadResult {
        val asset = release.assetFor(installKind)
            ?: return UpdateDownloadResult(false, error = "В релизе нет файла для Windows")
        val isMsi = asset.name.endsWith(".msi", ignoreCase = true)

        destDir.mkdirs()
        val target = File(destDir, asset.name)
        val tmp = File(destDir, "${asset.name}.part")

        val downloadErr = downloadFileWithRedirects(
            url = asset.downloadUrl,
            targetFile = tmp,
            expectedSize = asset.sizeBytes,
            onProgress = onProgress
        )
        if (downloadErr != null) {
            tmp.delete()
            return UpdateDownloadResult(false, error = downloadErr)
        }

        // Проверяем SHA-256, если в релизе опубликован SHA256SUMS.txt.
        var verified = false
        val sumsAsset = release.checksumsAsset
        if (sumsAsset != null) {
            val sumsText = httpGetText(sumsAsset.downloadUrl, timeoutMs = 15_000)
            if (sumsText != null) {
                val expected = parseSha256Sums(sumsText)[asset.name]
                if (expected != null) {
                    val actual = computeSha256(tmp)
                    if (!actual.equals(expected, ignoreCase = true)) {
                        tmp.delete()
                        return UpdateDownloadResult(
                            ok = false,
                            error = "Контрольная сумма SHA-256 не совпала (файл повреждён при загрузке)"
                        )
                    }
                    verified = true
                }
            }
        }

        if (target.exists()) target.delete()
        if (!tmp.renameTo(target)) {
            runCatching { tmp.copyTo(target, overwrite = true) }.onFailure {
                tmp.delete()
                return UpdateDownloadResult(false, error = "Не удалось сохранить файл обновления: ${it.message}")
            }
            tmp.delete()
        }

        return UpdateDownloadResult(
            ok = true,
            file = target,
            isMsi = isMsi,
            sha256Verified = verified
        )
    }

    /**
     * Запускает фоновый PowerShell-скрипт установки обновления (ждёт завершения текущего процесса,
     * ставит MSI или распаковывает Portable ZIP поверх текущей папки и запускает обновлённый WarpScout.exe).
     */
    fun launchInstallerScript(
        downloadedFile: File,
        isMsi: Boolean,
        sameVersion: Boolean,
        updatesDir: File,
        currentExe: File? = currentExeFile()
    ): Boolean {
        if (!WindowsAutostart.isWindows()) return false
        updatesDir.mkdirs()
        val scriptFile = File(updatesDir, "apply-update.ps1")
        val currentPid = ProcessHandle.current().pid()

        val psPath = { f: File -> f.absolutePath.replace("'", "''") }
        val script = if (isMsi) {
            val defaultExe = currentExe?.absolutePath ?: """C:\Program Files\WarpScout\WarpScout.exe"""
            val escapedDefaultExe = defaultExe.replace("'", "''")
            val msiEsc = psPath(downloadedFile)
            buildString {
                appendLine("\$ErrorActionPreference = 'Continue'")
                appendLine("for (\$i = 0; \$i -lt 40; \$i++) {")
                appendLine("  if (-not (Get-Process -Id $currentPid -ErrorAction SilentlyContinue)) { break }")
                appendLine("  Start-Sleep -Milliseconds 250")
                appendLine("}")
                appendLine("Start-Sleep -Milliseconds 500")
                if (sameVersion) {
                    // Скользящее обновление preview с тем же номером версии: принудительно обновляем файлы.
                    appendLine("\$p = Start-Process -FilePath 'msiexec.exe' -ArgumentList @('/i', '$msiEsc', 'REINSTALL=ALL', 'REINSTALLMODE=vomus', '/qb', '/norestart') -Wait -PassThru")
                    appendLine("if (\$p.ExitCode -ne 0 -and \$p.ExitCode -ne 3010) {")
                    appendLine("  Start-Process -FilePath 'msiexec.exe' -ArgumentList @('/i', '$msiEsc', '/qb', '/norestart') -Wait -PassThru | Out-Null")
                    appendLine("}")
                } else {
                    appendLine("\$p = Start-Process -FilePath 'msiexec.exe' -ArgumentList @('/i', '$msiEsc', '/qb', '/norestart') -Wait -PassThru")
                    appendLine("if (\$p.ExitCode -eq 1638) {")
                    appendLine("  Start-Process -FilePath 'msiexec.exe' -ArgumentList @('/i', '$msiEsc', 'REINSTALL=ALL', 'REINSTALLMODE=vomus', '/qb', '/norestart') -Wait -PassThru | Out-Null")
                    appendLine("}")
                }
                appendLine("\$candidates = @('$escapedDefaultExe', 'C:\\Program Files\\WarpScout\\WarpScout.exe')")
                appendLine("\$launchExe = \$candidates | Where-Object { Test-Path \$_ } | Select-Object -First 1")
                appendLine("if (\$launchExe) { Start-Process -FilePath \$launchExe }")
            }
        } else {
            val appDir = currentExe?.parentFile ?: return false
            val appDirEsc = psPath(appDir)
            val exeEsc = psPath(currentExe)
            val zipEsc = psPath(downloadedFile)
            val stageEsc = psPath(File(updatesDir, "stage"))
            buildString {
                appendLine("\$ErrorActionPreference = 'Stop'")
                appendLine("for (\$i = 0; \$i -lt 40; \$i++) {")
                appendLine("  if (-not (Get-Process -Id $currentPid -ErrorAction SilentlyContinue)) { break }")
                appendLine("  Start-Sleep -Milliseconds 250")
                appendLine("}")
                appendLine("Start-Sleep -Milliseconds 600")
                appendLine("if (Test-Path '$stageEsc') { Remove-Item -Recurse -Force '$stageEsc' }")
                appendLine("Expand-Archive -Path '$zipEsc' -DestinationPath '$stageEsc' -Force")
                appendLine("Copy-Item -Path '$stageEsc\\*' -Destination '$appDirEsc' -Recurse -Force")
                appendLine("Remove-Item -Recurse -Force '$stageEsc' -ErrorAction SilentlyContinue")
                appendLine("if (Test-Path '$exeEsc') { Start-Process -FilePath '$exeEsc' }")
            }
        }

        return runCatching {
            scriptFile.writeText(script, Charsets.UTF_8)
            ProcessBuilder(
                "powershell.exe",
                "-NoProfile",
                "-ExecutionPolicy", "Bypass",
                "-WindowStyle", "Hidden",
                "-File", scriptFile.absolutePath
            ).start()
            true
        }.getOrDefault(false)
    }

    private fun openWithRedirects(url: String, timeoutMs: Int, accept: String): HttpURLConnection {
        var currentUrl = url
        repeat(6) {
            val conn = (URI(currentUrl).toURL().openConnection() as HttpURLConnection).apply {
                instanceFollowRedirects = false
                connectTimeout = timeoutMs
                readTimeout = timeoutMs
                requestMethod = "GET"
                setRequestProperty("User-Agent", USER_AGENT)
                setRequestProperty("Accept", accept)
            }
            val code = conn.responseCode
            if (code in 300..399) {
                val loc = conn.getHeaderField("Location")
                conn.disconnect()
                if (loc.isNullOrBlank()) throw IllegalStateException("Пустой redirect для $currentUrl")
                currentUrl = URI(currentUrl).resolve(loc).toString()
            } else {
                return conn
            }
        }
        throw IllegalStateException("Слишком много перенаправлений: $url")
    }

    private fun httpGetText(url: String, timeoutMs: Int = 10_000): String? = runCatching {
        val conn = openWithRedirects(url, timeoutMs, "application/vnd.github+json")
        try {
            if (conn.responseCode !in 200..299) return@runCatching null
            conn.inputStream.bufferedReader(Charsets.UTF_8).use { it.readText() }
        } finally {
            conn.disconnect()
        }
    }.getOrNull()

    private fun downloadFileWithRedirects(
        url: String,
        targetFile: File,
        expectedSize: Long,
        onProgress: (Long, Long) -> Unit
    ): String? {
        return try {
            val conn = openWithRedirects(url, timeoutMs = 25_000, accept = "application/octet-stream")
            try {
                if (conn.responseCode !in 200..299) {
                    return "GitHub вернул HTTP ${conn.responseCode}"
                }
                val total = conn.contentLengthLong.takeIf { it > 0L } ?: expectedSize
                var downloaded = 0L
                var lastNotify = 0L
                conn.inputStream.use { input ->
                    FileOutputStream(targetFile).use { output ->
                        val buf = ByteArray(64 * 1024)
                        while (true) {
                            val n = input.read(buf)
                            if (n < 0) break
                            output.write(buf, 0, n)
                            downloaded += n
                            val now = System.currentTimeMillis()
                            if (now - lastNotify >= 150L || (total > 0L && downloaded >= total)) {
                                lastNotify = now
                                onProgress(downloaded, total)
                            }
                        }
                    }
                }
                if (downloaded < 1024L) {
                    "Загруженный файл слишком мал ($downloaded Б)"
                } else {
                    onProgress(downloaded, total.coerceAtLeast(downloaded))
                    null
                }
            } finally {
                conn.disconnect()
            }
        } catch (e: Exception) {
            "${e.javaClass.simpleName}: ${e.message}"
        }
    }
}
