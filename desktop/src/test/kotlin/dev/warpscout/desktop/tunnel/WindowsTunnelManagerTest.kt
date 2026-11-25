package dev.warpscout.desktop.tunnel

import dev.warpscout.core.junk.JunkLibrary
import dev.warpscout.core.model.Endpoint
import dev.warpscout.core.model.WarpAccount
import dev.warpscout.core.model.WarpConfig
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.io.File

class WindowsTunnelManagerTest {

    private class FakeRunner(
        var elevated: Boolean = true,
        val handler: (List<String>) -> CommandResult
    ) : CommandRunner {
        val commands = mutableListOf<List<String>>()
        override fun run(command: List<String>, timeoutMs: Long): CommandResult {
            commands.add(command)
            return handler(command)
        }
        override fun isElevated(): Boolean = elevated
        override fun runElevated(executable: String, args: List<String>, timeoutMs: Long): CommandResult =
            run(listOf(executable) + args, timeoutMs)
    }

    private fun sampleConfig(host: String, port: Int): WarpConfig = WarpConfig(
        name = "Test-$host",
        account = WarpAccount(
            privateB64 = "cGxhY2Vob2xkZXJQcml2S2V5MTIzNDU2Nzg5MDEyMzQ=",
            peerPublicB64 = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
            ipv4 = "172.16.0.2",
            ipv6 = "2606:4700:110::2"
        ),
        endpoint = Endpoint(host, port),
        junk = JunkLibrary.tlsFixed()
    )

    private fun fakeEngine(dir: File): EngineInfo {
        val exe = File(dir, "amneziawg.exe").apply { writeText("stub") }
        val cli = File(dir, "awg.exe").apply { writeText("stub") }
        return EngineInfo(EngineKind.AMNEZIA_WG, exe, cli, "test")
    }

    @Test
    fun `fails over from unresponsive first point to second working point`(@TempDir tmp: File) {
        val engine = fakeEngine(tmp)
        var currentEndpoint = ""
        val runner = FakeRunner { cmd ->
            when {
                "/installtunnelservice" in cmd -> {
                    val conf = File(cmd.last()).readText()
                    currentEndpoint = conf.lineSequence().firstOrNull { it.startsWith("Endpoint = ") }
                        ?.removePrefix("Endpoint = ")?.trim().orEmpty()
                    CommandResult(0, "ok", "")
                }
                "/uninstalltunnelservice" in cmd -> CommandResult(0, "ok", "")
                cmd.contains("dump") -> {
                    // Первая точка молчит (handshake = 0), вторая отвечает!
                    val hs = if (currentEndpoint == "162.159.192.2:943") System.currentTimeMillis() / 1000L else 0L
                    CommandResult(0, "priv\tpub\t51820\toff\npeer\t(none)\t$currentEndpoint\t0.0.0.0/0\t$hs\t1024\t512\t25", "")
                }
                else -> CommandResult(0, "", "")
            }
        }

        val mgr = WindowsTunnelManager(
            tunnelsDir = File(tmp, "tunnels"),
            runner = runner,
            exitProber = { ExitInfo(colo = "HEL", loc = "FI", ip = "104.28.1.1", warpOn = true) },
            handshakeWaitMs = 400L,
            handshakePollMs = 50L,
            healthPollMs = 60_000L
        )

        val ok = mgr.connect(
            engine = engine,
            primary = sampleConfig("162.159.192.1", 2408),
            fallbacks = listOf(sampleConfig("162.159.192.2", 943))
        )

        assertTrue(ok)
        assertEquals(TunnelPhase.CONNECTED, mgr.snapshot.phase)
        assertEquals("162.159.192.2:943", mgr.snapshot.activeEndpoint)

        mgr.disconnect()
        assertEquals(TunnelPhase.OFF, mgr.snapshot.phase)
        mgr.shutdown()
    }

    @Test
    fun `second exit excludes its endpoint from primary AllowedIPs and falls back safely if handshake fails`(@TempDir tmp: File) {
        val engine = fakeEngine(tmp)
        var primaryConfRendered = ""
        val runner = FakeRunner { cmd ->
            when {
                "/installtunnelservice" in cmd -> {
                    val file = File(cmd.last())
                    if (file.name == "${WindowsTunnelManager.PRIMARY_TUNNEL}.conf") {
                        primaryConfRendered = file.readText()
                    }
                    CommandResult(0, "ok", "")
                }
                "/uninstalltunnelservice" in cmd -> CommandResult(0, "ok", "")
                cmd.contains("dump") -> {
                    val tunnelName = cmd[cmd.indexOf("show") + 1]
                    val hs = if (tunnelName == WindowsTunnelManager.PRIMARY_TUNNEL) System.currentTimeMillis() / 1000L else 0L
                    CommandResult(0, "priv\tpub\t51820\toff\npeer\t(none)\t162.159.192.1:2408\t0.0.0.0/0\t$hs\t2048\t512\t25", "")
                }
                else -> CommandResult(0, "", "")
            }
        }

        val mgr = WindowsTunnelManager(
            tunnelsDir = File(tmp, "tunnels"),
            runner = runner,
            exitProber = { ExitInfo(colo = "AMS", loc = "NL", warpOn = true) },
            handshakeWaitMs = 300L,
            handshakePollMs = 50L,
            healthPollMs = 60_000L
        )

        val secondExit = SecondExitSpec(
            enabled = true,
            confText = """
                [Interface]
                PrivateKey = cGxhY2Vob2xkZXJQcml2S2V5MTIzNDU2Nzg5MDEyMzQ=
                Address = 10.7.0.2/32
                [Peer]
                PublicKey = bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=
                Endpoint = 198.51.100.77:51820
            """.trimIndent(),
            cidrsCsv = "104.18.32.47/32"
        )

        val ok = mgr.connect(engine, sampleConfig("162.159.192.1", 2408), secondExit = secondExit)
        assertTrue(ok, "основной туннель должен остаться поднятым")
        assertFalse(mgr.snapshot.secondExitActive, "второй выход без handshake должен откатиться в WARP")
        assertFalse("AllowedIPs = 0.0.0.0/0" in primaryConfRendered, "IP второго выхода должен быть исключён из 0.0.0.0/0")
        assertTrue("::/0" in primaryConfRendered)

        mgr.disconnect()
        mgr.shutdown()
    }

    @Test
    fun `engine locator finds amneziawg and wireguard fallback in directory`(@TempDir tmp: File) {
        val awgDir = File(tmp, "awg").apply { mkdirs() }
        File(awgDir, "amneziawg.exe").writeText("bin")
        File(awgDir, "awg.exe").writeText("cli")

        val foundAwg = EngineLocator.locate(customPath = awgDir.absolutePath, appDir = tmp)
        assertEquals(EngineKind.AMNEZIA_WG, foundAwg.kind)
        assertTrue(foundAwg.supportsAwg)
        assertEquals("AmneziaWGTunnel\$warpscout", foundAwg.serviceNameFor("warpscout"))

        val wgDir = File(tmp, "wg").apply { mkdirs() }
        File(wgDir, "wireguard.exe").writeText("bin")
        val foundWg = EngineLocator.locate(customPath = wgDir.absolutePath, appDir = tmp)
        assertEquals(EngineKind.WIREGUARD, foundWg.kind)
        assertFalse(foundWg.supportsAwg)
    }
}
