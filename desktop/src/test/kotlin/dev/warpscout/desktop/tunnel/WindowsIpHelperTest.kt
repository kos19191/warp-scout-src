package dev.warpscout.desktop.tunnel

import com.sun.jna.Memory
import org.junit.jupiter.api.Assertions.assertEquals
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
}
