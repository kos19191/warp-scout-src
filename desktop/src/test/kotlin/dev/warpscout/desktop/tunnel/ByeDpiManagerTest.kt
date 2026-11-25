package dev.warpscout.desktop.tunnel

import dev.warpscout.desktop.storage.DesktopSettings
import dev.warpscout.desktop.storage.DesktopStore
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.io.File

class ByeDpiManagerTest {

    @Test
    fun `presets build Windows-safe commands without Linux-only md5sig`() {
        val fakeBin = File("/tmp/ciadpi.exe")
        for (preset in ByeDpiPresets.TUNABLE) {
            val cmd = ByeDpiPresets.buildCommand(fakeBin, "127.0.0.1", 1080, preset.id)
            assertEquals(fakeBin.absolutePath, cmd[0])
            assertTrue("-i" in cmd && "127.0.0.1" in cmd)
            assertTrue("-p" in cmd && "1080" in cmd)
            assertFalse(cmd.any { it.contains("md5sig") }, "Windows presets must not use Linux-only --md5sig")
        }
    }

    @Test
    fun `tokenizeArgs splits flags and preserves quoted values`() {
        val args = ByeDpiPresets.tokenizeArgs("""--disorder 1 --fake-data=":GET / HTTP/1.1" --tlsrec '1+s'""")
        assertEquals(listOf("--disorder", "1", "--fake-data=:GET / HTTP/1.1", "--tlsrec", "1+s"), args)

        val cmd = ByeDpiPresets.buildCommand(File("/tmp/ciadpi.exe"), "127.0.0.1", 1085, ByeDpiPresets.CUSTOM_ID, "--split 2+s")
        assertTrue("1085" in cmd)
        assertTrue("--split" in cmd && "2+s" in cmd)
    }

    @Test
    fun `manager handles missing binary cleanly without crashing`(@TempDir tempDir: File) {
        val mgr = ByeDpiManager(
            nativeDir = tempDir,
            binaryResolver = { null }
        )
        assertFalse(mgr.snapshot.available)
        assertFalse(mgr.start(ByeDpiPresets.DEFAULT_ID, port = 1080))
        assertFalse(mgr.snapshot.running)
        assertTrue(!mgr.snapshot.lastError.isNullOrBlank())
        mgr.shutdown()
    }

    @Test
    fun `system proxy bypass excludes Russian domains and LAN`() {
        assertTrue("*.ru" in WindowsSystemProxy.DEFAULT_BYPASS)
        assertTrue("*.рф" in WindowsSystemProxy.DEFAULT_BYPASS)
        assertTrue("192.168.*" in WindowsSystemProxy.DEFAULT_BYPASS)
        assertTrue("<local>" in WindowsSystemProxy.DEFAULT_BYPASS)
    }

    @Test
    fun `DesktopStore persists ByeDPI settings round-trip`() {
        val orig = DesktopSettings(
            byeDpiPresetId = "disorder-fake",
            byeDpiPort = 1088,
            byeDpiCustomArgs = "--oob 1+s",
            byeDpiSystemProxy = true
        )
        val restored = DesktopStore.settingsFromJson(DesktopStore.settingsToJson(orig))
        assertEquals("disorder-fake", restored.byeDpiPresetId)
        assertEquals(1088, restored.byeDpiPort)
        assertEquals("--oob 1+s", restored.byeDpiCustomArgs)
        assertTrue(restored.byeDpiSystemProxy)
    }
}
