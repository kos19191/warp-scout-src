package dev.warpscout.desktop.tunnel

import com.sun.jna.Memory
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.Test

class WindowsIpHelperTest {

    @Test
    fun `MIB_IPFORWARD_ROW2 byte offsets match real Windows iphlpapi InitializeIpForwardEntry`() {
        assumeTrue(WindowsAutostart.isWindows(), "Windows-only Win32 iphlpapi.dll layout verification")
        val api = WindowsIpHelper.loadApi()
        val buf = Memory(WindowsIpHelper.ROW_SIZE.toLong())
        buf.clear()

        api.InitializeIpForwardEntry(buf)

        // Windows SDK: InitializeIpForwardEntry выставляет ValidLifetime, PreferredLifetime и Metric в 0xFFFFFFFF (-1).
        assertEquals(-1, buf.getInt(WindowsIpHelper.OFF_VALID_LIFETIME), "ValidLifetime offset mismatch")
        assertEquals(-1, buf.getInt(WindowsIpHelper.OFF_PREFERRED_LIFETIME), "PreferredLifetime offset mismatch")
        assertEquals(-1, buf.getInt(WindowsIpHelper.OFF_METRIC), "Metric offset mismatch")
    }

    @Test
    fun `GetBestRoute2 resolves real physical gateway on Windows without PowerShell`() {
        assumeTrue(WindowsAutostart.isWindows(), "Windows-only Win32 GetBestRoute2 verification")
        val gw = WindowsIpHelper.getBestIpv4Route("1.1.1.1")
        assertNotNull(gw, "GetBestRoute2 should return active Windows default route")
        assertTrue(gw!!.interfaceLuid != 0L || gw.interfaceIndex > 0)
        assertNotNull(CidrMath.parseIpv4(gw.nextHop), "NextHop must be valid IPv4: ${gw.nextHop}")
        assertNotNull(CidrMath.parseIpv4(gw.sourceIp), "GetBestRoute2 must return physical adapter sourceIp: '${gw.sourceIp}'")
        if (gw.interfaceLuid != 0L) {
            val idx = WindowsIpHelper.luidToIndex(gw.interfaceLuid)
            assertEquals(gw.interfaceIndex, idx, "ConvertInterfaceLuidToIndex must match GetBestRoute2 interfaceIndex")
        }
    }

    @Test
    fun `MIB_UNICASTIPADDRESS_ROW byte offsets match real Windows iphlpapi InitializeUnicastIpAddressEntry`() {
        assumeTrue(WindowsAutostart.isWindows(), "Windows-only Win32 MIB_UNICASTIPADDRESS_ROW verification")
        val api = WindowsIpHelper.loadApi()
        val buf = Memory(WindowsIpHelper.UNICAST_ROW_SIZE.toLong())
        buf.clear()

        api.InitializeUnicastIpAddressEntry(buf)

        // Windows SDK: InitializeUnicastIpAddressEntry ставит PrefixOrigin/SuffixOrigin = 16 (Unchanged),
        // Valid/PreferredLifetime = 0xFFFFFFFF (-1), OnLinkPrefixLength = 0xFF (-1).
        assertEquals(16, buf.getInt(WindowsIpHelper.OFF_UNI_PREFIX_ORIGIN), "PrefixOrigin offset mismatch")
        assertEquals(16, buf.getInt(WindowsIpHelper.OFF_UNI_SUFFIX_ORIGIN), "SuffixOrigin offset mismatch")
        assertEquals(-1, buf.getInt(WindowsIpHelper.OFF_UNI_VALID_LIFETIME), "ValidLifetime offset mismatch")
        assertEquals(-1, buf.getInt(WindowsIpHelper.OFF_UNI_PREFERRED_LIFETIME), "PreferredLifetime offset mismatch")
        assertEquals((-1).toByte(), buf.getByte(WindowsIpHelper.OFF_UNI_PREFIX_LEN), "OnLinkPrefixLength offset mismatch")
    }

    @Test
    fun `MIB_IPINTERFACE_ROW offsets match real Windows iphlpapi GetIpInterfaceEntry`() {
        assumeTrue(WindowsAutostart.isWindows(), "Windows-only Win32 MIB_IPINTERFACE_ROW verification")
        val gw = WindowsIpHelper.getBestIpv4Route("1.1.1.1")
        assertNotNull(gw, "GetBestRoute2 should return active route")
        assertTrue(gw!!.interfaceLuid != 0L, "Expected non-zero interfaceLuid")

        val cfg = WindowsIpHelper.getInterfaceConfig(gw.interfaceLuid, isIpv6 = false)
        assertTrue(cfg.ok, "GetIpInterfaceEntry failed with Win32 rc=${cfg.win32Error}")
        assertTrue(cfg.mtu in 1200..9216, "Unexpected NlMtu=${cfg.mtu} (offset mismatch?)")
        assertTrue(cfg.metric in 0..10_000, "Unexpected Metric=${cfg.metric} (offset mismatch?)")

        // Сверяем прочитанный NlMtu с PowerShell Get-NetIPInterface.
        val ps = ProcessCommandRunner().run(
            listOf(
                "powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
                "(Get-NetIPInterface -InterfaceIndex ${gw.interfaceIndex} -AddressFamily IPv4).NlMtu"
            ),
            timeoutMs = 8000L
        )
        if (ps.ok) {
            val psMtu = ps.stdout.trim().toIntOrNull()
            if (psMtu != null) {
                assertEquals(psMtu, cfg.mtu, "MIB_IPINTERFACE_ROW NlMtu offset must match Get-NetIPInterface")
            }
        }
    }
}
