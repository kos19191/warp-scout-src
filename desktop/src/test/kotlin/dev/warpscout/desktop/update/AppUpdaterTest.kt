package dev.warpscout.desktop.update

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.io.File

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
}
