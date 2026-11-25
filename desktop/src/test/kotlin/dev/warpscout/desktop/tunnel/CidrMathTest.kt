package dev.warpscout.desktop.tunnel

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class CidrMathTest {

    @Test
    fun `exclude single IPv4 from full tunnel preserves IPv6 and excludes target IP`() {
        val target = "203.0.113.42"
        val out = CidrMath.excludeIpv4("0.0.0.0/0, ::/0", listOf(target))
        val cidrs = out.split(',').map { it.trim() }

        assertTrue("::/0" in cidrs, "IPv6 должен сохраниться")
        assertFalse("0.0.0.0/0" in cidrs, "полный 0.0.0.0/0 должен быть разбит")

        val targetNum = CidrMath.parseIpv4(target)!!
        val v4Ranges = cidrs.filter { ':' !in it }.map { CidrMath.parseIpv4Cidr(it)!! }

        // Целевой IP не входит ни в один CIDR.
        assertFalse(v4Ranges.any { targetNum in it.start..it.end })
        // Соседние адреса входят.
        assertTrue(v4Ranges.any { (targetNum - 1L) in it.start..it.end })
        assertTrue(v4Ranges.any { (targetNum + 1L) in it.start..it.end })
        // Суммарное покрытие = 2^32 - 1.
        val totalCovered = v4Ranges.sumOf { it.end - it.start + 1L }
        assertEquals((1L shl 32) - 1L, totalCovered)
    }

    @Test
    fun `exclude IP outside CIDR leaves CIDR untouched`() {
        val out = CidrMath.excludeIpv4("10.0.0.0/8, 172.16.0.0/12", listOf("203.0.113.5"))
        assertEquals("10.0.0.0/8, 172.16.0.0/12", out)
    }

    @Test
    fun `exclude boundary IPs does not overflow`() {
        val out = CidrMath.excludeIpv4("0.0.0.0/0", listOf("0.0.0.0", "255.255.255.255"))
        val ranges = out.split(',').map { CidrMath.parseIpv4Cidr(it.trim())!! }
        assertEquals((1L shl 32) - 2L, ranges.sumOf { it.end - it.start + 1L })
    }
}
