package dev.warpscout.desktop.tunnel

import dev.warpscout.desktop.storage.DesktopPaths
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.io.File

class TelegramProxyFinderTest {

    @Test
    fun `parseFeedText parses tg and tme links and decodes Fake-TLS domain`() {
        val sample = """
            # comment
            tg://proxy?server=85.17.89.193&port=443&secret=ee76f6583e6b509d946c56287a9ca59dc362726f7773696e672e79616e6465782e636f6d
            https://t.me/proxy?server=zephyr.tealbriar.xyz&port=8443&secret=eed8e23b55798e53b64877d42e6ef94a3f64726976652e676f6f676c652e636f6d
            tg://proxy?server=91.221.190.198&port=443&secret=dd104462821249bd7ac519130220c25d09
            tg://proxy?server=77.238.241.225&port=8880&secret=79e344818749bd7ac519130220c25d09
            tg://proxy?server=85.17.89.193&port=443&secret=ee76f6583e6b509d946c56287a9ca59dc362726f7773696e672e79616e6465782e636f6d
        """.trimIndent()

        val parsed = TelegramProxyFinder.parseFeedText(sample, source = "test")
        assertEquals(4, parsed.size, "Дубликат server:port должен быть отфильтрован")

        val first = parsed[0]
        assertEquals("85.17.89.193", first.server)
        assertEquals(443, first.port)
        assertEquals(MtProtoSecretKind.FAKE_TLS, first.kind)
        assertEquals("browsing.yandex.com", first.maskDomain)
        assertTrue(first.tgLink.startsWith("tg://proxy?server=85.17.89.193&port=443&secret=ee"))
        assertTrue(first.tmeLink.startsWith("https://t.me/proxy?server=85.17.89.193&port=443&secret=ee"))

        val second = parsed[1]
        assertEquals(MtProtoSecretKind.FAKE_TLS, second.kind)
        assertEquals("drive.google.com", second.maskDomain)

        assertEquals(MtProtoSecretKind.RANDOM_PADDING, parsed[2].kind)
        assertEquals(MtProtoSecretKind.CLASSIC, parsed[3].kind)
    }

    @Test
    fun `pickDiverseCandidates caps clones per host group and prefers Fake-TLS`() {
        val raw = listOf(
            TelegramProxyEntry("a.tealbriar.xyz", 8443, "ee" + "a".repeat(32) + "676f6f676c652e636f6d", MtProtoSecretKind.FAKE_TLS),
            TelegramProxyEntry("b.tealbriar.xyz", 8443, "ee" + "a".repeat(32) + "676f6f676c652e636f6d", MtProtoSecretKind.FAKE_TLS),
            TelegramProxyEntry("c.tealbriar.xyz", 8443, "ee" + "a".repeat(32) + "676f6f676c652e636f6d", MtProtoSecretKind.FAKE_TLS),
            TelegramProxyEntry("d.other.example", 443, "dd" + "b".repeat(32), MtProtoSecretKind.RANDOM_PADDING),
            TelegramProxyEntry("e.third.example", 443, "ee" + "c".repeat(32) + "676f6f676c652e636f6d", MtProtoSecretKind.FAKE_TLS)
        )

        val picked = TelegramProxyFinder.pickDiverseCandidates(raw, limit = 10)
        assertEquals(4, picked.size, "Не больше 2 прокси на один базовый домен tealbriar.xyz")
        assertEquals(MtProtoSecretKind.FAKE_TLS, picked.first().kind)
        assertEquals("d.other.example", picked.last().server)
    }

    @Test
    fun `findBestProxies uses mirror fallback and ranks Fake-TLS by lowest latency`() {
        val feeds = listOf(
            TelegramProxyFinder.FeedSource(
                name = "mock",
                urls = listOf("https://blocked.example/list.txt", "https://mirror.example/list.txt")
            )
        )
        val feedBody = """
            tg://proxy?server=slow.fake.example&port=443&secret=ee11111111111111111111111111111111676f6f676c652e636f6d
            tg://proxy?server=fast.fake.example&port=443&secret=ee22222222222222222222222222222222676f6f676c652e636f6d
            tg://proxy?server=dead.fake.example&port=443&secret=ee33333333333333333333333333333333676f6f676c652e636f6d
            tg://proxy?server=superfast.classic.example&port=443&secret=44444444444444444444444444444444
        """.trimIndent()

        val result = TelegramProxyFinder.findBestProxies(
            feeds = feeds,
            fetcher = { url -> if ("mirror" in url) feedBody else null },
            prober = { entry, _ ->
                when (entry.server) {
                    "slow.fake.example" -> 210L
                    "fast.fake.example" -> 55L
                    "dead.fake.example" -> -1L
                    "superfast.classic.example" -> 20L
                    else -> -1L
                }
            }
        )

        assertNull(result.error)
        assertEquals(3, result.proxies.size)
        assertEquals("fast.fake.example", result.proxies[0].server)
        assertEquals(55L, result.proxies[0].latencyMs)
        assertEquals("slow.fake.example", result.proxies[1].server)
        assertEquals("superfast.classic.example", result.proxies[2].server)
    }

    @Test
    fun `DesktopPaths migrates legacy WarpScout data into WilyScout once`(@TempDir tempDir: File) {
        val legacy = File(tempDir, "WarpScout").apply { mkdirs() }
        File(legacy, "settings.json").writeText("""{"theme":"DARK"}""")
        File(legacy, "shortlist.json").writeText("""[]""")
        File(legacy, "active.conf").writeText("[Interface]")

        val target = DesktopPaths(File(tempDir, "WilyScout")).also { it.ensureDirs() }
        DesktopPaths.migrateLegacyDataIfNeeded(legacy, target)

        assertTrue(target.settingsFile.exists())
        assertEquals("""{"theme":"DARK"}""", target.settingsFile.readText())
        assertTrue(target.shortlistFile.exists())
        assertTrue(target.activeConfFile.exists())

        // Повторный вызов не перезаписывает уже изменённые настройки WilyScout.
        target.settingsFile.writeText("""{"theme":"LIGHT"}""")
        DesktopPaths.migrateLegacyDataIfNeeded(legacy, target)
        assertEquals("""{"theme":"LIGHT"}""", target.settingsFile.readText())
        assertFalse(File(target.root, "nonexistent.json").exists())
    }

    @Test
    fun `TelegramOpener parses registry command with Cyrillic paths and normalizes workdir`() {
        val regCmd = """"C:\Users\Администратор\AppData\Roaming\Telegram Desktop\Telegram.exe" -workdir "C:\Users\Администратор\AppData\Roaming\Telegram Desktop\" -- "%1""""
        val spec = TelegramOpener.parseRegistryCommand(regCmd)
        assertEquals("""C:\Users\Администратор\AppData\Roaming\Telegram Desktop\Telegram.exe""", spec?.exePath)
        assertEquals("""C:/Users/Администратор/AppData/Roaming/Telegram Desktop/""", spec?.workDir)
        assertFalse(spec?.isStoreApp ?: true)

        val tgUrl = "tg://proxy?server=1.2.3.4&port=443&secret=ee123456"
        val args = TelegramOpener.buildLaunchArgs(spec!!, tgUrl)
        assertEquals(
            listOf(
                """C:\Users\Администратор\AppData\Roaming\Telegram Desktop\Telegram.exe""",
                "-workdir",
                """C:/Users/Администратор/AppData/Roaming/Telegram Desktop/""",
                "--",
                tgUrl
            ),
            args
        )

        // Браузер в реестре tg:// должен игнорироваться.
        val browserCmd = """"C:\Program Files\Google\Chrome\Application\chrome.exe" -- "%1""""
        assertNull(TelegramOpener.parseRegistryCommand(browserCmd))
    }

    @Test
    fun `TelegramOpener prefers running portable Telegram and marks WindowsApps store client`() {
        val portableExe = """D:\Portable\Telegram\Telegram.exe"""
        val regCmd = """"C:\Users\User\AppData\Roaming\Telegram Desktop\Telegram.exe" -workdir "C:/Users/User/TD/" -- "%1""""
        val spec = TelegramOpener.findTelegramClient(
            runningProcesses = listOf(TelegramOpener.RunningProcess(4242L, portableExe)),
            registryCommand = regCmd,
            standardCandidates = emptyList(),
            fileExists = { true }
        )
        assertEquals(portableExe, spec?.exePath)
        assertEquals(4242L, spec?.runningPid)
        assertNull(spec?.workDir, "Портативный процесс не должен получать чужой -workdir из реестра")
        assertEquals("running", spec?.source)

        val storeExe = """C:\Program Files\WindowsApps\TelegramMessengerLLP.TelegramDesktop_5.0.0\Telegram.exe"""
        assertTrue(TelegramOpener.isWindowsStorePath(storeExe))
        val storeSpec = TelegramOpener.findTelegramClient(
            runningProcesses = listOf(TelegramOpener.RunningProcess(999L, storeExe)),
            registryCommand = null,
            standardCandidates = emptyList(),
            fileExists = { false }
        )
        assertTrue(storeSpec?.isStoreApp == true)
    }

    @Test
    fun `TelegramOpener rejects non-tg urls and falls back cleanly on missing or failed launch`() {
        val bad = TelegramOpener.openTgLink("https://t.me/proxy?server=1.2.3.4")
        assertFalse(bad.opened)

        if (TelegramOpener.isWindows()) {
            val missing = TelegramOpener.openTgLink(
                tgUrl = "tg://socks?server=127.0.0.1&port=1080",
                specOverride = null,
                processStarter = { _, _ -> false to "not-called" },
                shellFallback = { false },
                foregroundBumper = {}
            )
            assertFalse(missing.opened)

            var shellCalled = false
            val storeRes = TelegramOpener.openTgLink(
                tgUrl = "tg://proxy?server=1.2.3.4&port=443&secret=ee1234",
                specOverride = TelegramLaunchSpec(
                    exePath = """C:\Program Files\WindowsApps\TelegramMessengerLLP.TelegramDesktop\Telegram.exe""",
                    isStoreApp = true
                ),
                processStarter = { _, _ -> error("Store app must not be launched directly via ProcessBuilder") },
                shellFallback = {
                    shellCalled = true
                    true
                },
                foregroundBumper = {}
            )
            assertTrue(shellCalled)
            assertTrue(storeRes.opened)
        }
    }
}
