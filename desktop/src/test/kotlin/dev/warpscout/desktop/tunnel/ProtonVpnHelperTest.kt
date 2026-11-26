package dev.warpscout.desktop.tunnel

import dev.warpscout.core.tunnel.ExitRouter
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class ProtonVpnHelperTest {

    @Test
    fun `inspectConf recognizes official ProtonVPN WireGuard config`() {
        val conf = """
            [Interface]
            # Key for WilyScout
            # Bouncing = 4
            # NetShield = 1
            # Moderate NAT = off
            # NAT-PMP (Port Forwarding) = off
            # VPN Accelerator = on
            PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
            Address = 10.2.0.2/32
            DNS = 10.2.0.1

            [Peer]
            # NL-FREE#123
            PublicKey = BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=
            AllowedIPs = 0.0.0.0/0, ::/0
            Endpoint = 185.107.56.138:51820
        """.trimIndent()

        val info = ProtonVpnHelper.inspectConf(conf)
        assertNotNull(info)
        assertTrue(info!!.isProton)
        assertEquals("NL-FREE#123", info.serverLabel)
        assertEquals("185.107.56.138:51820", info.endpoint)
        assertEquals("10.2.0.2", info.clientIpv4)
    }

    @Test
    fun `SecondExitPreset TELEGRAM contains all official Telegram DC ranges`() {
        val cidrs = ExitRouter.parse(SecondExitPreset.TELEGRAM.builtInCidrs)
        val router = ExitRouter.of(cidrs)
        assertEquals(10, router.size)
        // DC2 149.154.167.50 -> route 1
        assertEquals(1, router.route(byteArrayOf(149.toByte(), 154.toByte(), 167.toByte(), 50)))
        // DC4 91.108.4.10 -> route 1
        assertEquals(1, router.route(byteArrayOf(91, 108, 4, 10)))
        // Посторонний IP 1.1.1.1 -> route 0 (WARP)
        assertEquals(0, router.route(byteArrayOf(1, 1, 1, 1)))
    }

    @Test
    fun `Ipv4Nat rewrites src and dst IPv4 and keeps IPv4 + TCP checksums valid`() {
        val primary = Ipv4Nat.ipv4Bytes("172.16.0.2")!!
        val secondary = Ipv4Nat.ipv4Bytes("10.2.0.2")!!
        val dst = Ipv4Nat.ipv4Bytes("149.154.167.50")!!

        // Собираем минимальный валидный IPv4 (20 Б) + TCP (20 Б) + payload (4 Б) пакет.
        val pkt = ByteArray(44)
        pkt[0] = 0x45 // IPv4, IHL=5 (20 bytes)
        pkt[2] = 0; pkt[3] = 44 // Total length
        pkt[8] = 64 // TTL
        pkt[9] = 6 // TCP
        System.arraycopy(primary, 0, pkt, 12, 4)
        System.arraycopy(dst, 0, pkt, 16, 4)
        val ipSumOrig = computeIpv4Checksum(pkt, 0, 20)
        pkt[10] = (ipSumOrig ushr 8).toByte()
        pkt[11] = (ipSumOrig and 0xFF).toByte()

        // TCP header
        pkt[20] = 0x10; pkt[21] = 0x20 // src port
        pkt[22] = 0x01; pkt[23] = 0xBB.toByte() // dst port 443
        pkt[32] = 0x50 // data offset = 5
        pkt[33] = 0x02 // SYN
        pkt[40] = 0xDE.toByte(); pkt[41] = 0xAD.toByte(); pkt[42] = 0xBE.toByte(); pkt[43] = 0xEF.toByte()
        val tcpSumOrig = computeTcpChecksum(pkt)
        pkt[36] = (tcpSumOrig ushr 8).toByte()
        pkt[37] = (tcpSumOrig and 0xFF).toByte()

        // 1. Исходящий NAT: src 172.16.0.2 -> 10.2.0.2
        assertTrue(Ipv4Nat.rewriteIpv4Address(pkt, 0, pkt.size, 12, primary, secondary))
        assertArrayEquals(secondary, pkt.copyOfRange(12, 16))
        assertEquals(0, computeIpv4Checksum(pkt, 0, 20), "IPv4 checksum должен сходиться после SNAT")
        assertEquals(0, computeTcpChecksum(pkt), "TCP checksum должен сходиться после SNAT")

        // 2. Обратный NAT: src/dst поменялись ролями (dst=10.2.0.2 -> 172.16.0.2)
        val reply = pkt.copyOf()
        System.arraycopy(dst, 0, reply, 12, 4)
        System.arraycopy(secondary, 0, reply, 16, 4)
        reply[10] = 0; reply[11] = 0
        val rIp = computeIpv4Checksum(reply, 0, 20)
        reply[10] = (rIp ushr 8).toByte(); reply[11] = (rIp and 0xFF).toByte()
        reply[36] = 0; reply[37] = 0
        val rTcp = computeTcpChecksum(reply)
        reply[36] = (rTcp ushr 8).toByte(); reply[37] = (rTcp and 0xFF).toByte()

        assertTrue(Ipv4Nat.rewriteIpv4Address(reply, 0, reply.size, 16, secondary, primary))
        assertArrayEquals(primary, reply.copyOfRange(16, 20))
        assertEquals(0, computeIpv4Checksum(reply, 0, 20), "IPv4 checksum должен сходиться после DNAT")
        assertEquals(0, computeTcpChecksum(reply), "TCP checksum должен сходиться после DNAT")
    }

    private fun computeIpv4Checksum(pkt: ByteArray, off: Int, len: Int): Int {
        var sum = 0
        var i = off
        while (i < off + len) {
            val w = ((pkt[i].toInt() and 0xFF) shl 8) or (pkt[i + 1].toInt() and 0xFF)
            sum += w
            i += 2
        }
        while ((sum ushr 16) != 0) sum = (sum and 0xFFFF) + (sum ushr 16)
        return sum.inv() and 0xFFFF
    }

    private fun computeTcpChecksum(pkt: ByteArray): Int {
        val tcpLen = pkt.size - 20
        var sum = 0
        // Pseudo-header: src IP + dst IP + proto + tcpLen
        for (i in listOf(12, 14, 16, 18)) {
            sum += ((pkt[i].toInt() and 0xFF) shl 8) or (pkt[i + 1].toInt() and 0xFF)
        }
        sum += 6
        sum += tcpLen
        var i = 20
        while (i + 1 < pkt.size) {
            sum += ((pkt[i].toInt() and 0xFF) shl 8) or (pkt[i + 1].toInt() and 0xFF)
            i += 2
        }
        if (i < pkt.size) sum += (pkt[i].toInt() and 0xFF) shl 8
        while ((sum ushr 16) != 0) sum = (sum and 0xFFFF) + (sum ushr 16)
        return sum.inv() and 0xFFFF
    }
}
