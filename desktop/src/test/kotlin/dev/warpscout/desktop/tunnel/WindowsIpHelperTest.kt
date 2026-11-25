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
    }
}
