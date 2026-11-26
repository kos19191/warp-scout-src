package dev.warpscout.desktop.tunnel

import dev.warpscout.desktop.storage.DesktopSettings
import dev.warpscout.desktop.storage.DesktopStore
import dev.warpscout.desktop.storage.NetworkDpiProfile
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.io.File
import java.net.HttpURLConnection
import java.net.URL

class ByeDpiManagerTest {

    @Test
    fun `presets use Windows-recommended strategies without Linux-only flags`() {
        val fakeBin = File("/tmp/ciadpi.exe")
        val allArgs = ByeDpiPresets.TUNABLE.map { it.id to ByeDpiPresets.buildCommand(fakeBin, "127.0.0.1", 1080, it.id) }
        for ((id, cmd) in allArgs) {
            assertEquals(fakeBin.absolutePath, cmd[0])
            assertTrue("-i" in cmd && "127.0.0.1" in cmd, "Preset $id missing -i 127.0.0.1")
            assertTrue("-p" in cmd && "1080" in cmd, "Preset $id missing -p 1080")
            assertFalse(cmd.any { it.contains("md5sig") || it.contains("drop-sack") }, "Windows preset $id must not use Linux-only flags")
        }

        val splitDisorder = ByeDpiPresets.byId("win-split-disorder").args.joinToString(" ")
        assertTrue(splitDisorder.contains("--split 1+s --disorder 3+s"), "Missing Windows-recommended --split 1+s --disorder 3+s")

        val disorderFake = ByeDpiPresets.byId("win-disorder-fake").args.joinToString(" ")
        assertTrue(disorderFake.contains("--disorder 1 --fake -1"), "Missing Windows-recommended --disorder 1 --fake -1")

        // Совместимость со старыми ID стратегий из v1.10.28.
        assertEquals("win-auto", ByeDpiPresets.byId("auto-universal").id)
        assertEquals("win-disorder-fake", ByeDpiPresets.byId("disorder-fake").id)
    }

    @Test
    fun `buildCommand binds physical IP via -I and -X to bypass Wintun tunnel`() {
        val fakeBin = File("/tmp/ciadpi.exe")
        val cmd = ByeDpiPresets.buildCommand(
            binary = fakeBin,
            host = "127.0.0.1",
            port = 1080,
            presetId = "win-split-disorder",
            bindConnIp = "192.168.1.42"
        )
        val idxI = cmd.indexOf("-I")
        assertTrue(idxI >= 0 && cmd.getOrNull(idxI + 1) == "192.168.1.42", "Expected -I 192.168.1.42 in $cmd")
        assertTrue("-X" in cmd, "Expected -X (--no-ipv6) alongside IPv4 -I binding in $cmd")

        // Если пользователь сам передал -I в своих аргументах — не дублируем.
        val customCmd = ByeDpiPresets.buildCommand(
            binary = fakeBin,
            host = "127.0.0.1",
            port = 1080,
            presetId = ByeDpiPresets.CUSTOM_ID,
            customArgs = "-I 10.0.0.5 --split 1+s",
            bindConnIp = "192.168.1.42"
        )
        assertEquals(1, customCmd.count { it == "-I" })
        assertTrue("10.0.0.5" in customCmd)
        assertFalse("192.168.1.42" in customCmd)
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
    fun `PAC script explicitly uses SOCKS5 with DIRECT fallback for YouTube and Discord`() {
        val domains = ByeDpiPac.parseDomains("https://YouTube.com/watch, *.googlevideo.com, ytimg.com, discord.com")
        assertEquals(listOf("youtube.com", "googlevideo.com", "ytimg.com", "discord.com"), domains)

        val pac = ByeDpiPac.renderPac("127.0.0.1", 1080, domains)
        assertTrue(pac.contains("function FindProxyForURL(url, host)"))
        assertTrue(pac.contains("\"SOCKS5 127.0.0.1:1080; DIRECT\""))
        assertTrue(pac.contains("\"youtube.com\""))
        assertTrue(pac.contains("\"googlevideo.com\""))
        assertTrue(pac.contains("\"discord.com\""))
        assertTrue(pac.trimEnd().endsWith("}"))
    }

    @Test
    fun `LocalPacServer serves valid PAC over HTTP on 127_0_0_1`() {
        val server = LocalPacServer()
        try {
            val pac = ByeDpiPac.renderPac("127.0.0.1", 1080, ByeDpiPac.DEFAULT_DOMAINS)
            val urlStr = server.start(pac)
            assertNotNull(urlStr)
            assertTrue(WindowsSystemProxy.isOurPacUrl(urlStr!!))

            val conn = (URL(urlStr).openConnection() as HttpURLConnection).apply {
                connectTimeout = 2000
                readTimeout = 2000
            }
            assertEquals(200, conn.responseCode)
            assertTrue(conn.contentType.contains("proxy-autoconfig"))
            val body = conn.inputStream.bufferedReader(Charsets.UTF_8).readText()
            assertEquals(pac, body)
        } finally {
            server.stop()
        }
    }

    @Test
    fun `NetworkIdentityDetector parses EN and RU netsh Wi-Fi output and builds distinct network keys`() {
        val enOut = """
            There is 1 interface on the system:
                Name                   : Wi-Fi
                State                  : connected
                SSID                   : HomeFiber5G
                BSSID                  : aa:bb:cc:dd:ee:ff
        """.trimIndent()
        assertEquals("HomeFiber5G", NetworkIdentityDetector.parseNetshWifiSsid(enOut))

        val ruOut = """
            В системе имеется 1 интерфейс:
                Имя                    : Беспроводная сеть
                Состояние              : подключено
                SSID                   : iPhone_Hotspot
                BSSID                  : 11:22:33:44:55:66
        """.trimIndent()
        assertEquals("iPhone_Hotspot", NetworkIdentityDetector.parseNetshWifiSsid(ruOut))

        val disconnectedOut = """
                State                  : disconnected
                SSID                   : OldWifi
        """.trimIndent()
        assertEquals("", NetworkIdentityDetector.parseNetshWifiSsid(disconnectedOut))

        val fakeRunner = object : CommandRunner {
            override fun run(command: List<String>, timeoutMs: Long): CommandResult =
                CommandResult(0, enOut, "")
            override fun isElevated(): Boolean = true
            override fun runElevated(executable: String, args: List<String>, timeoutMs: Long): CommandResult =
                CommandResult(0, "", "")
        }
        val homeNet = NetworkIdentityDetector.detect(
            PhysicalGateway("192.168.1.1", 15, 0L, "192.168.1.42"),
            runner = fakeRunner
        )
        assertNotNull(homeNet)
        assertEquals("192.168.1.1", homeNet!!.gatewayIp)
        assertEquals("192.168.1.42", homeNet.sourceIp)
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
    fun `DesktopStore persists ByeDPI settings including PAC domains and per-network profiles`() {
        val orig = DesktopSettings(
            byeDpiPresetId = "win-split-disorder",
            byeDpiPort = 1088,
            byeDpiCustomArgs = "--oob 1+s",
            byeDpiSystemProxy = true,
            byeDpiBypassTunnel = true,
            byeDpiPacDomains = "youtube.com, googlevideo.com, discord.com",
            byeDpiNetworkProfiles = mapOf(
                "wifi:Home|192.168.1.1" to NetworkDpiProfile(
                    networkKey = "wifi:Home|192.168.1.1",
                    networkLabel = "Wi-Fi «Home» (192.168.1.1)",
                    presetId = "win-split-disorder",
                    fixedCount = 4,
                    totalChecks = 10,
                    testedAtMs = 1_700_000_000_000L
                ),
                "wifi:LTE|172.20.10.1" to NetworkDpiProfile(
                    networkKey = "wifi:LTE|172.20.10.1",
                    networkLabel = "Wi-Fi «LTE» (172.20.10.1)",
                    presetId = "win-disorder-fake",
                    fixedCount = 5,
                    totalChecks = 10,
                    testedAtMs = 1_700_000_100_000L
                )
            )
        )
        val restored = DesktopStore.settingsFromJson(DesktopStore.settingsToJson(orig))
        assertEquals("win-split-disorder", restored.byeDpiPresetId)
        assertEquals(1088, restored.byeDpiPort)
        assertEquals("--oob 1+s", restored.byeDpiCustomArgs)
        assertTrue(restored.byeDpiSystemProxy)
        assertTrue(restored.byeDpiBypassTunnel)
        assertEquals("youtube.com, googlevideo.com, discord.com", restored.byeDpiPacDomains)
        assertEquals(2, restored.byeDpiNetworkProfiles.size)
        assertEquals("win-disorder-fake", restored.byeDpiNetworkProfiles["wifi:LTE|172.20.10.1"]?.presetId)
    }
}
