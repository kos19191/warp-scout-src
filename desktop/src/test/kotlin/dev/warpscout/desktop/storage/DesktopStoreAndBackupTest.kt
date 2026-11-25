package dev.warpscout.desktop.storage

import dev.warpscout.core.config.ConfTarget
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.io.File

class DesktopStoreAndBackupTest {

    @Test
    fun `roundtrips settings shortlist and backup restore`(@TempDir tmp: File) {
        val storeA = DesktopStore(DesktopPaths(File(tmp, "appA")))
        val custom = DesktopSettings(
            theme = ThemeMode.LIGHT,
            minimizeToTrayOnClose = false,
            autostartWindows = true,
            endpointCount = 320,
            mtu = 1360,
            keepalive = 20,
            enableIpv6 = false,
            routeMode = RouteMode.LISTS,
            selectedBlockListIds = listOf("youtube", "openai"),
            builtAllowedIps = "1.1.1.1/32, 8.8.8.8/32",
            secondExitEnabled = true,
            secondExitDomains = "chatgpt.com, openai.com",
            secondExitCidrs = "104.18.32.47/32",
            exportTarget = ConfTarget.CLASH,
            lastTuneEndpoint = "162.159.192.1:2408",
            lastTuneJunk = "quic:ivi.ru"
        )
        storeA.saveSettings(custom)
        val loaded = storeA.loadSettings()
        assertEquals(custom, loaded)

        val shortlist = listOf(
            ShortlistEntry("162.159.192.1:2408", "quic:ivi.ru", 95, 8, 9, 1700000000000L, "[Interface]\nPrivateKey = A\n[Peer]\nPublicKey = B\n"),
            ShortlistEntry("188.114.96.2:943", "tls-fixed", 82, 7, 9, 1700000000000L, "[Interface]\nPrivateKey = A\n[Peer]\nPublicKey = B\n")
        )
        storeA.saveShortlist(shortlist)
        storeA.saveActiveConfigText(shortlist.first().confText)

        assertEquals(shortlist, storeA.loadShortlist())

        val backupFile = File(tmp, "backup.json")
        val summary = storeA.exportBackup(backupFile)
        assertTrue(backupFile.exists())
        assertEquals(2, summary.shortlistCount)
        assertTrue(summary.hasActiveConfig)

        // Восстановление в полностью чистый каталог.
        val storeB = DesktopStore(DesktopPaths(File(tmp, "appB")))
        val restored = storeB.importBackup(backupFile)
        assertEquals(custom, restored.settings)
        assertEquals(shortlist, restored.shortlist)
        assertEquals(shortlist.first().confText, storeB.loadActiveConfigText())
    }
}
