package dev.warpscout.desktop.update

import dev.warpscout.desktop.tunnel.ProcessCommandRunner
import dev.warpscout.desktop.tunnel.WindowsAutostart
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.io.File
import java.io.FileOutputStream
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

class AppUpdaterTest {

    @Test
    fun `BuildInfo loads generated warpscout-build properties`() {
        val info = BuildInfo.load()
        assertTrue(info.version.matches(Regex("""\d+\.\d+\.\d+""")), "Unexpected version: ${info.version}")
        assertTrue(info.buildTimeEpochMs > 0L, "Expected valid ISO buildTimeUtc, got: ${info.buildTimeUtc}")
        assertEquals("kos19191/warp-scout-src", info.githubRepo)
    }

    @Test
    fun `compareVersions and rolling preview timestamp comparison work accurately`() {
        assertTrue(AppUpdater.compareVersions("1.10.26", "1.10.25") > 0)
        assertTrue(AppUpdater.compareVersions("v1.11.0", "1.10.99") > 0)
        assertEquals(0, AppUpdater.compareVersions("v1.10.25", "1.10.25"))
        assertTrue(AppUpdater.compareVersions("1.10.24", "1.10.25") < 0)

        val current = BuildInfo(version = "1.10.25", buildTimeUtc = "2026-11-25T13:00:00Z")
        val sameBuildPreview = ReleaseInfo(
            tagName = "desktop-windows-preview",
            title = "WarpScout Desktop 1.10.25 (Windows)",
            htmlUrl = "https://github.com/kos19191/warp-scout-src/releases/tag/desktop-windows-preview",
            prerelease = true,
            publishedAtUtc = "2026-11-25T13:03:00Z",
            version = "1.10.25",
            msiAsset = ReleaseAsset("WarpScout-1.10.25-windows-x64.msi", "https://example/msi", 100L, "2026-11-25T13:03:00Z"),
            portableAsset = null,
            checksumsAsset = null
        )
        assertFalse(AppUpdater.isNewer(sameBuildPreview, current), "Freshly published own build within 5 min must not trigger self-update")

        val newerPreview = sameBuildPreview.copy(
            msiAsset = sameBuildPreview.msiAsset!!.copy(updatedAtUtc = "2026-11-25T13:15:00Z")
        )
        assertTrue(AppUpdater.isNewer(newerPreview, current), "Later rolling preview rebuild must be detected as update")

        val newerStable = sameBuildPreview.copy(tagName = "v1.10.26", prerelease = false, version = "1.10.26")
        assertTrue(AppUpdater.isNewer(newerStable, current), "Higher SemVer release must be detected as update")
    }

    @Test
    fun `parseReleasesJson and checkForUpdate select best Windows release and respect prerelease flag`() {
        val sampleJson = """
            [
              {
                "tag_name": "desktop-windows-preview",
                "name": "WarpScout Desktop 1.10.26 (Windows)",
                "html_url": "https://github.com/kos19191/warp-scout-src/releases/tag/desktop-windows-preview",
                "draft": false,
                "prerelease": true,
                "published_at": "2026-11-25T14:00:00Z",
                "assets": [
                  {
                    "name": "WarpScout-1.10.26-windows-x64.msi",
                    "browser_download_url": "https://github.com/kos19191/warp-scout-src/releases/download/desktop-windows-preview/WarpScout-1.10.26-windows-x64.msi",
                    "size": 108000000,
                    "updated_at": "2026-11-25T14:05:00Z"
                  },
                  {
                    "name": "WarpScout-1.10.26-windows-x64-portable.zip",
                    "browser_download_url": "https://github.com/kos19191/warp-scout-src/releases/download/desktop-windows-preview/WarpScout-1.10.26-windows-x64-portable.zip",
                    "size": 107500000,
                    "updated_at": "2026-11-25T14:05:00Z"
                  },
                  {
                    "name": "SHA256SUMS.txt",
                    "browser_download_url": "https://github.com/kos19191/warp-scout-src/releases/download/desktop-windows-preview/SHA256SUMS.txt",
                    "size": 211,
                    "updated_at": "2026-11-25T14:05:00Z"
                  }
                ]
              },
              {
                "tag_name": "v1.10.24",
                "name": "WarpScout 1.10.24",
                "html_url": "https://github.com/kos19191/warp-scout-src/releases/tag/v1.10.24",
                "draft": false,
                "prerelease": false,
                "published_at": "2026-11-24T10:00:00Z",
                "assets": [
                  {
                    "name": "WarpScout-1.10.24-windows-x64.msi",
                    "browser_download_url": "https://example/old.msi",
                    "size": 100000000,
                    "updated_at": "2026-11-24T10:00:00Z"
                  }
                ]
              }
            ]
        """.trimIndent()

        val current = BuildInfo(version = "1.10.25", buildTimeUtc = "2026-11-25T13:00:00Z")
        val withPre = AppUpdater.checkForUpdate(current, includePrereleases = true) { sampleJson }
        assertTrue(withPre.ok)
        assertTrue(withPre.updateAvailable)
        assertEquals("1.10.26", withPre.release?.version)
        assertNotNull(withPre.release?.msiAsset)
        assertNotNull(withPre.release?.portableAsset)
        assertNotNull(withPre.release?.checksumsAsset)

        val stableOnly = AppUpdater.checkForUpdate(current, includePrereleases = false) { sampleJson }
        assertTrue(stableOnly.ok)
        assertFalse(stableOnly.updateAvailable, "Stable v1.10.24 is older than current 1.10.25")
    }

    @Test
    fun `SHA-256 parsing and file verification match`(@TempDir tempDir: File) {
        val f = File(tempDir, "WarpScout-1.10.25-windows-x64.msi")
        f.writeText("warpscout-update-payload", Charsets.UTF_8)
        val digest = AppUpdater.computeSha256(f)
        val sums = AppUpdater.parseSha256Sums("$digest  WarpScout-1.10.25-windows-x64.msi\n")
        assertEquals(digest, sums["WarpScout-1.10.25-windows-x64.msi"])
    }

    @Test
    fun `picks newest asset when rolling release contains multiple versions`() {
        val json = """
            [
              {
                "tag_name": "desktop-windows-preview",
                "name": "WarpScout Desktop 1.10.27 (Windows)",
                "prerelease": true,
                "draft": false,
                "published_at": "2026-11-25T16:00:00Z",
                "html_url": "https://github.com/kos19191/warp-scout-src/releases/tag/desktop-windows-preview",
                "assets": [
                  {
                    "name": "WarpScout-1.10.25-windows-x64.msi",
                    "browser_download_url": "https://example.invalid/old.msi",
                    "size": 100,
                    "updated_at": "2026-11-25T12:00:00Z"
                  },
                  {
                    "name": "WarpScout-1.10.27-windows-x64.msi",
                    "browser_download_url": "https://example.invalid/new.msi",
                    "size": 200,
                    "updated_at": "2026-11-25T16:00:00Z"
                  }
                ]
              }
            ]
        """.trimIndent()
        val parsed = AppUpdater.parseReleasesJson(json)
        assertEquals("WarpScout-1.10.27-windows-x64.msi", parsed.single().msiAsset?.name)
    }

    @Test
    fun `buildUpdateScript writes UTF-8 BOM and quotes MSI paths safely for spaces and Cyrillic`(@TempDir tempDir: File) {
        val updatesDir = File(tempDir, "Пользователь Тест/updates").apply { mkdirs() }
        val msiFile = File(updatesDir, "WarpScout-1.10.30-windows-x64.msi")
        val exeFile = File(tempDir, "Program Files/WarpScout/WarpScout.exe")

        val script = AppUpdater.buildUpdateScript(
            downloadedFile = msiFile,
            isMsi = true,
            sameVersion = false,
            updatesDir = updatesDir,
            currentPid = 12345L,
            currentExe = exeFile,
            launchAfter = true
        )
        assertTrue(script.contains("/i `\"\$msiPath`\" /qb! /norestart /l*v `\"\$msiLog`\""))
        assertTrue(script.contains("finally {"))
        assertTrue(script.contains("Start-Process -FilePath \$launchExe -WorkingDirectory \$workDir"))

        val scriptFile = File(updatesDir, "apply-update.ps1")
        AppUpdater.writeScriptWithUtf8Bom(scriptFile, script)
        val raw = scriptFile.readBytes()
        assertTrue(raw.size > 3)
        assertEquals(0xEF.toByte(), raw[0], "PowerShell 5.1 requires UTF-8 BOM for Cyrillic paths")
        assertEquals(0xBB.toByte(), raw[1])
        assertEquals(0xBF.toByte(), raw[2])
    }

    @Test
    fun `consumeLastUpdateError reads once and deletes error marker`(@TempDir tempDir: File) {
        assertNull(AppUpdater.consumeLastUpdateError(tempDir))
        val marker = File(tempDir, "update-error.txt")
        marker.writeText("MSI-установщик завершился с кодом 1603", Charsets.UTF_8)
        assertEquals("MSI-установщик завершился с кодом 1603", AppUpdater.consumeLastUpdateError(tempDir))
        assertFalse(marker.exists())
        assertNull(AppUpdater.consumeLastUpdateError(tempDir))
    }

    @Test
    fun `portable update script runs end-to-end on real Windows with Cyrillic and spaces in path`(@TempDir tempDir: File) {
        assumeTrue(WindowsAutostart.isWindows(), "Windows-only PowerShell/robocopy updater verification")

        val appDir = File(tempDir, "Папка Пользователя/WarpScout App").apply { mkdirs() }
        val updatesDir = File(tempDir, "Данные Пользователя/updates").apply { mkdirs() }
        val appSub = File(appDir, "app").apply { mkdirs() }

        // Старая версия приложения + личный файл пользователя в корне.
        val exe = File(appDir, "WarpScout.exe").apply { writeText("old-exe-v1.10.29") }
        val oldJar = File(appSub, "desktop-1.10.29.jar").apply { writeText("old-jar") }
        val userNotes = File(appDir, "user-notes.txt").apply { writeText("keep-me") }

        // Новый Portable ZIP.
        val zipFile = File(updatesDir, "WarpScout-1.10.30-windows-x64-portable.zip")
        ZipOutputStream(FileOutputStream(zipFile)).use { zos ->
            zos.putNextEntry(ZipEntry("WarpScout.exe"))
            zos.write("new-exe-v1.10.30".toByteArray(Charsets.UTF_8))
            zos.closeEntry()

            zos.putNextEntry(ZipEntry("app/desktop-1.10.30.jar"))
            zos.write("new-jar".toByteArray(Charsets.UTF_8))
            zos.closeEntry()
        }

        val script = AppUpdater.buildUpdateScript(
            downloadedFile = zipFile,
            isMsi = false,
            sameVersion = false,
            updatesDir = updatesDir,
            currentPid = 0L,
            currentExe = exe,
            launchAfter = false
        )
        val scriptFile = File(updatesDir, "apply-update.ps1")
        AppUpdater.writeScriptWithUtf8Bom(scriptFile, script)

        val res = ProcessCommandRunner().run(
            listOf(
                "powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy", "Bypass",
                "-File", scriptFile.absolutePath
            ),
            timeoutMs = 30_000L
        )
        val logText = File(updatesDir, "update.log").takeIf { it.isFile }?.readText(Charsets.UTF_8).orEmpty()
        assertTrue(res.ok, "apply-update.ps1 failed (rc=${res.exitCode}): ${res.combined}\nLOG:\n$logText")
        assertNull(AppUpdater.consumeLastUpdateError(updatesDir), "Unexpected update error; LOG:\n$logText")

        assertEquals("new-exe-v1.10.30", exe.readText(Charsets.UTF_8), "WarpScout.exe must be replaced")
        assertTrue(File(appSub, "desktop-1.10.30.jar").isFile, "New jar must be installed")
        assertFalse(oldJar.exists(), "Stale old jar in app/ must be removed by robocopy /MIR")
        assertTrue(userNotes.isFile && userNotes.readText() == "keep-me", "User files in root must be preserved")
    }
}
