package dev.warpscout.desktop.tunnel

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class TraceParserTest {

    @Test
    fun `parses cloudflare trace and ipinfo`() {
        val trace = """
            fl=123f45
            h=www.cloudflare.com
            ip=104.28.198.12
            loc=FI
            colo=HEL
            warp=on
        """.trimIndent()
        val map = TraceAndSpeed.parseCloudflareTrace(trace)
        assertEquals("HEL", map["colo"])
        assertEquals("FI", map["loc"])
        assertEquals("on", map["warp"])

        val ipinfo = """{"ip":"104.28.198.12","city":"Helsinki","country":"FI","org":"AS13335 Cloudflare, Inc."}"""
        val (city, country, org) = TraceAndSpeed.parseIpInfo(ipinfo)
        assertEquals("Helsinki", city)
        assertEquals("FI", country)
        assertTrue("Cloudflare" in org)

        val exitInfo = ExitInfo(colo = "HEL", loc = "FI", ip = "104.28.198.12", warpOn = true, city = city, country = country, org = org)
        assertEquals("HEL · FI · Helsinki", exitInfo.regionLabel())
    }
}
