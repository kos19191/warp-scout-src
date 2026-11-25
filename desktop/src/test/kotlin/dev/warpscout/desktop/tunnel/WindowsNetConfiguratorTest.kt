package dev.warpscout.desktop.tunnel

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class WindowsNetConfiguratorTest {

    @Test
    fun `parses valid gateway output and rejects invalid lines`() {
        val gw = WindowsNetConfigurator.parseGatewayOutput("192.168.1.1|12\n")
        assertEquals(PhysicalGateway("192.168.1.1", 12), gw)

        assertNull(WindowsNetConfigurator.parseGatewayOutput(""))
        assertNull(WindowsNetConfigurator.parseGatewayOutput("192.168.1.1|not-a-number"))
        assertNull(WindowsNetConfigurator.parseGatewayOutput("bad-ip|12"))
        assertNull(WindowsNetConfigurator.parseGatewayOutput("192.168.1.1|0"))
    }

    @Test
    fun `expands default routes into split halves to keep physical gateway intact`() {
        val routesV4Only = WindowsNetConfigurator.expandSafeRoutes(
            allowedIpsCsv = "0.0.0.0/0, ::/0",
            extraCidrs = listOf("1.2.3.4/32"),
            enableIpv6 = false
        )
        assertEquals(listOf("0.0.0.0/1", "128.0.0.0/1", "1.2.3.4/32"), routesV4Only)

        val routesDual = WindowsNetConfigurator.expandSafeRoutes(
            allowedIpsCsv = "0.0.0.0/0, ::/0",
            extraCidrs = emptyList(),
            enableIpv6 = true
        )
        assertEquals(listOf("0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1"), routesDual)
    }

    @Test
    fun `adds and cleans up bypass host routes for endpoints`() {
        val calls = mutableListOf<List<String>>()
        val fakeRunner = object : CommandRunner {
            override fun run(command: List<String>, timeoutMs: Long, workingDir: java.io.File?): CommandResult {
                calls += command
                return CommandResult(0, "", "")
            }

            override fun runElevated(executable: String, arguments: List<String>, timeoutMs: Long): CommandResult =
                CommandResult(0, "", "")

            override fun isElevated(): Boolean = true
        }
        val cfg = WindowsNetConfigurator(fakeRunner)
        val gw = PhysicalGateway("10.0.0.1", 7)

        val added = cfg.addBypassHostRoutes(listOf("162.159.192.1", "162.159.192.1", "not-ip", "188.114.97.2"), gw)
        assertEquals(listOf("162.159.192.1", "188.114.97.2"), added)
        assertTrue(calls.any { it == listOf("route.exe", "ADD", "162.159.192.1", "MASK", "255.255.255.255", "10.0.0.1", "METRIC", "5", "IF", "7") })
        assertTrue(calls.any { it == listOf("route.exe", "ADD", "188.114.97.2", "MASK", "255.255.255.255", "10.0.0.1", "METRIC", "5", "IF", "7") })

        calls.clear()
        cfg.removeBypassHostRoutes(added)
        assertEquals(
            listOf(
                listOf("route.exe", "DELETE", "162.159.192.1"),
                listOf("route.exe", "DELETE", "188.114.97.2")
            ),
            calls
        )
    }
}
