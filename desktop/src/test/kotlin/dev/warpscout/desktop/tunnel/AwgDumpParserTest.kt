package dev.warpscout.desktop.tunnel

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class AwgDumpParserTest {

    @Test
    fun `parses valid awg show dump output`() {
        val dump = """
            privKey==	pubKeyIface==	51820	off
            bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=	(none)	162.159.192.1:2408	0.0.0.0/0,::/0	1732500123	482910	92104	25
        """.trimIndent()

        val peer = AwgDumpParser.parseFirstPeer(dump)
        assertNotNull(peer)
        peer!!
        assertEquals("162.159.192.1:2408", peer.endpoint)
        assertEquals(1732500123L, peer.latestHandshakeEpochSec)
        assertTrue(peer.hasHandshake)
        assertEquals(482910L, peer.rxBytes)
        assertEquals(92104L, peer.txBytes)
        assertEquals(25, peer.keepaliveSec)
        assertEquals(77L, peer.handshakeAgeSec(1732500200L))
    }

    @Test
    fun `handles zero handshake and off keepalive`() {
        val dump = "priv\tpub\t0\toff\npeerPub\t(none)\t(none)\t0.0.0.0/0\t0\t0\t148\toff\n"
        val peer = AwgDumpParser.parseFirstPeer(dump)!!
        assertFalse(peer.hasHandshake)
        assertEquals("", peer.endpoint)
        assertEquals(0, peer.keepaliveSec)
        assertEquals(148L, peer.txBytes)
    }

    @Test
    fun `returns null on empty or header-only dump`() {
        assertNull(AwgDumpParser.parseFirstPeer(""))
        assertNull(AwgDumpParser.parseFirstPeer("priv\tpub\t51820\toff"))
    }
}
