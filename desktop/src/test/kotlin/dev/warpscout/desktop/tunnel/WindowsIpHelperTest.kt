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

        // Windows SDK: InitializeUnicastIpAddressEntry ставит Valid/PreferredLifetime = 0xFFFFFFFF (-1),
        // OnLinkPrefixLength = 0xFF (-1), DadState = IpDadStatePreferred (4).
        assertEquals(-1, buf.getInt(WindowsIpHelper.OFF_UNI_VALID_LIFETIME), "ValidLifetime offset mismatch")
        assertEquals(-1, buf.getInt(WindowsIpHelper.OFF_UNI_PREFERRED_LIFETIME), "PreferredLifetime offset mismatch")
        assertEquals((-1).toByte(), buf.getByte(WindowsIpHelper.OFF_UNI_PREFIX_LEN), "OnLinkPrefixLength offset mismatch")
        assertEquals(4, buf.getInt(WindowsIpHelper.OFF_UNI_DAD_STATE), "DadState offset mismatch")
    }
}
