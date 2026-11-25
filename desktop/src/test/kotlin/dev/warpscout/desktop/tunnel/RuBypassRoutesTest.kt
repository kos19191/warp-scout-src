package dev.warpscout.desktop.tunnel

import dev.warpscout.desktop.storage.DesktopSettings
import dev.warpscout.desktop.storage.RouteMode
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.math.BigInteger
import java.net.Inet6Address
import java.net.InetAddress

class RuBypassRoutesTest {

    @Test
    fun `default route mode is RF bypass preset`() {
        val defaults = DesktopSettings()
        assertEquals(RouteMode.PRESET, defaults.routeMode)
    }

    @Test
    fun `russian services and LAN bypass tunnel while foreign services go through tunnel`() {
        assertTrue(RuBypassRoutes.russianIpv4Cidrs.size in 80..250, "Compact RU IPv4 list expected, got ${RuBypassRoutes.russianIpv4Cidrs.size}")
        assertTrue(
            RuBypassRoutes.foreignIpv4Cidrs.size in 400..1_500,
            "Foreign IPv4 route count must stay compact (<1500) to avoid overloading Windows netprofm/BFE, got ${RuBypassRoutes.foreignIpv4Cidrs.size}"
        )

        val foreignRanges = RuBypassRoutes.foreignIpv4Cidrs.mapNotNull { CidrMath.parseIpv4Cidr(it) }
        fun inForeign(ip: String): Boolean {
            val v = CidrMath.parseIpv4(ip) ?: return false
            var lo = 0
            var hi = foreignRanges.size - 1
            while (lo <= hi) {
                val mid = (lo + hi) ushr 1
                val r = foreignRanges[mid]
                when {
                    v < r.start -> hi = mid - 1
                    v > r.end -> lo = mid + 1
                    else -> return true
                }
            }
            return false
        }

        val russianAndLan = listOf(
            "5.255.255.77",   // Yandex
            "77.88.55.242",   // Yandex
            "87.240.132.78",  // VK
            "94.100.180.200", // Mail.ru
            "194.54.14.131",  // Sberbank
            "91.194.226.10",  // T-Bank
            "213.59.254.8",   // Gosuslugi
            "185.71.67.1",    // Ozon
            "185.165.123.1",  // Wildberries
            "185.89.12.132",  // Avito
            "217.12.97.1",    // Alfa-Bank
            "195.208.131.1",  // VTB
            "192.168.1.1",    // LAN router
            "10.0.0.1",       // LAN
            "127.0.0.1"       // Loopback
        )
        for (ip in russianAndLan) {
            assertTrue(RuBypassRoutes.isRussianOrLanIpv4(ip), "$ip should be marked RU/LAN direct")
            assertFalse(inForeign(ip), "$ip must NOT be in foreign tunnel routes")
        }

        val foreign = listOf(
            "1.1.1.1",         // Cloudflare DNS
            "8.8.8.8",         // Google DNS
            "142.250.185.78",  // Google / YouTube
            "162.159.135.232", // Discord
            "149.154.167.99",  // Telegram
            "104.18.32.47"     // OpenAI / ChatGPT
        )
        for (ip in foreign) {
            assertFalse(RuBypassRoutes.isRussianOrLanIpv4(ip), "$ip should NOT be marked RU/LAN")
            assertTrue(inForeign(ip), "$ip MUST be routed through foreign tunnel")
        }
    }

    @Test
    fun `ipv6 complement excludes russian IPv6 and keeps foreign IPv6`() {
        assertTrue(RuBypassRoutes.russianIpv6Cidrs.size in 5..50, "Compact RU IPv6 list expected")
        val foreignV6 = RuBypassRoutes.foreignIpv6Cidrs
        assertTrue(foreignV6.size in 30..400, "Foreign IPv6 routes must stay compact, got ${foreignV6.size}")

        fun ipv6InList(ipStr: String, cidrs: List<String>): Boolean {
            val addr = InetAddress.getByName(ipStr) as Inet6Address
            val v = BigInteger(1, addr.address)
            return cidrs.any { cidr ->
                val slash = cidr.indexOf('/')
                val netAddr = InetAddress.getByName(cidr.substring(0, slash)) as Inet6Address
                val pfx = cidr.substring(slash + 1).toInt()
                val shift = 128 - pfx
                BigInteger(1, netAddr.address).shiftRight(shift) == v.shiftRight(shift)
            }
        }

        // Яндекс и VK IPv6 — напрямую
        assertFalse(ipv6InList("2a02:6b8::1", foreignV6), "Yandex IPv6 must bypass tunnel")
        assertFalse(ipv6InList("2a00:1148::1", foreignV6), "VK/Mail IPv6 must bypass tunnel")
        // Cloudflare DNS и Google IPv6 — в туннель
        assertTrue(ipv6InList("2606:4700:4700::1111", foreignV6), "Cloudflare IPv6 must go through tunnel")
        assertTrue(ipv6InList("2001:4860:4860::8888", foreignV6), "Google IPv6 must go through tunnel")
    }
}
