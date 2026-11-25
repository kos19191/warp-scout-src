package dev.warpscout.desktop.tunnel

import dev.warpscout.core.crypto.Crypto
import dev.warpscout.core.model.Endpoint
import dev.warpscout.core.model.JunkKind
import dev.warpscout.core.model.JunkProfile
import dev.warpscout.core.model.WarpAccount
import dev.warpscout.core.model.WarpConfig
import dev.warpscout.core.test.WgResponder
import dev.warpscout.core.tunnel.UdpChannel
import dev.warpscout.core.wg.Wg
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.io.File
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.SocketTimeoutException
import java.util.Base64
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

class NativeWintunTunnelManagerTest {

    private class FakeCommandRunner(private val elevated: Boolean = true) : CommandRunner {
        override fun run(command: List<String>, timeoutMs: Long): CommandResult =
            CommandResult(0, "", "")

        override fun runElevated(executable: String, args: List<String>, timeoutMs: Long): CommandResult =
            CommandResult(0, "", "")

        override fun isElevated(): Boolean = elevated
    }

    private class InMemoryTunDevice(override val adapterName: String) : TunDevice {
        val inboundToPlane = LinkedBlockingQueue<ByteArray>()
        val outboundFromPlane = LinkedBlockingQueue<ByteArray>()
        val closed = AtomicBoolean(false)

        override val input: InputStream = object : InputStream() {
            override fun read(): Int = -1
            override fun read(b: ByteArray, off: Int, len: Int): Int {
                while (!closed.get()) {
                    val pkt = inboundToPlane.poll(50, TimeUnit.MILLISECONDS) ?: continue
                    val n = minOf(pkt.size, len)
                    pkt.copyInto(b, off, 0, n)
                    return n
                }
                return -1
            }
        }

        override val output: OutputStream = object : OutputStream() {
            override fun write(b: Int) {}
            override fun write(b: ByteArray, off: Int, len: Int) {
                if (closed.get()) throw IOException("closed")
                outboundFromPlane.offer(b.copyOfRange(off, off + len))
            }
        }

        override fun close() {
            closed.set(true)
        }
    }

    /**
     * In-memory WireGuard responder: на [aliveEndpoint] честно завершает Noise_IKpsk2 handshake
     * и возвращает эхо расшифрованного IP-пакета; на остальных точках молчит (имитирует дроп DPI).
     */
    private class ResponderUdpChannel(
        private val target: Endpoint,
        private val aliveEndpoint: Endpoint,
        private val serverPrivate: ByteArray
    ) : UdpChannel {
        private val rxQueue = LinkedBlockingQueue<ByteArray>()
        private val closed = AtomicBoolean(false)
        @Volatile private var serverSession: Wg.Session? = null
        @Volatile private var clientSenderIndex: Int = 0
        private val serverSenderIndex: Int = 0x42424242

        override fun send(packet: ByteArray) {
            if (closed.get() || target != aliveEndpoint) return
            if (packet.size == Wg.INITIATION_LEN && Crypto.readLe32(packet, 0) == Wg.TYPE_INITIATION) {
                clientSenderIndex = Crypto.readLe32(packet, 4)
                val (resp, sess) = WgResponder.respondWithSession(
                    initiation = packet,
                    serverPrivate = serverPrivate,
                    receiverIndex = clientSenderIndex,
                    senderIndex = serverSenderIndex
                )
                serverSession = sess
                rxQueue.offer(resp)
                return
            }
            val sess = serverSession ?: return
            val opened = Wg.openTransport(packet, serverSenderIndex, sess) ?: return
            val (plain, updatedRecv) = opened
            if (plain.isEmpty()) {
                serverSession = updatedRecv
                return
            }
            val (replyPkt, updatedSend) = Wg.buildTransport(clientSenderIndex, updatedRecv, plain)
            serverSession = updatedSend
            rxQueue.offer(replyPkt)
        }

        override fun receive(): ByteArray? {
            if (closed.get()) return null
            return rxQueue.poll(100L, TimeUnit.MILLISECONDS)
        }

        override fun close() {
            closed.set(true)
        }
    }

    private fun testConfig(endpoint: Endpoint, peerPublic: ByteArray): WarpConfig {
        val clientPriv = ByteArray(32) { (it + 11).toByte() }
        val b64 = Base64.getEncoder()
        return WarpConfig(
            name = "test-${endpoint.render()}",
            account = WarpAccount(
                privateB64 = b64.encodeToString(clientPriv),
                peerPublicB64 = b64.encodeToString(peerPublic),
                ipv4 = "172.16.0.2",
                ipv6 = null
            ),
            endpoint = endpoint,
            junk = JunkProfile(name = "none", i1 = emptyList(), kind = JunkKind.NONE),
            allowedIps = "0.0.0.0/0",
            dns = listOf("1.1.1.1"),
            mtu = 1280,
            enableIpv6Address = false
        )
    }

    @Test
    fun `fails over from dead endpoint to live endpoint and transfers encrypted packets`() {
        val serverPriv = ByteArray(32) { (it * 3 + 7).toByte() }
        val serverPub = Crypto.publicOf(serverPriv)
        val deadEp = Endpoint("162.159.192.1", 2408)
        val liveEp = Endpoint("162.159.192.2", 2408)
        val createdTuns = mutableListOf<InMemoryTunDevice>()
        val logs = mutableListOf<String>()

        val manager = NativeWintunTunnelManager(
            nativeDir = File(System.getProperty("java.io.tmpdir")),
            runner = FakeCommandRunner(elevated = true),
            tunFactory = { name -> InMemoryTunDevice(name).also { createdTuns += it } },
            udpFactory = { ep -> ResponderUdpChannel(ep, liveEp, serverPriv) },
            onLog = { logs += it },
            exitProber = { ExitInfo(ip = "1.2.3.4", colo = "FRA", country = "DE", warpOn = true) },
            handshakeWaitMs = 1_500L,
            statsPollMs = 500L,
            requireElevationCheck = false,
            skipNetConfig = true
        )

        try {
            val ok = manager.connect(
                primary = testConfig(deadEp, serverPub),
                fallbacks = listOf(testConfig(liveEp, serverPub))
            )

            assertTrue(ok, "expected failover to live endpoint; logs=$logs")
            assertEquals(TunnelPhase.CONNECTED, manager.snapshot.phase)
            assertEquals(liveEp.render(), manager.snapshot.activeEndpoint)
            assertFalse(manager.snapshot.needsElevation)

            val activeTun = createdTuns.last()
            // Шлём IPv4-пакет в TUN — должен пройти DataPlane → сервер → расшифроваться обратно в TUN.
            val sampleIpv4 = ByteArray(20).apply {
                this[0] = 0x45 // IPv4, IHL=5
                this[3] = 20
                this[12] = 172.toByte(); this[13] = 16; this[14] = 0; this[15] = 2
                this[16] = 1; this[17] = 1; this[18] = 1; this[19] = 1
            }
            activeTun.inboundToPlane.offer(sampleIpv4)
            val echoed = activeTun.outboundFromPlane.poll(2, TimeUnit.SECONDS)
            assertTrue(echoed != null && echoed.contentEquals(sampleIpv4), "expected encrypted round-trip echo")
        } finally {
            manager.disconnect()
            manager.shutdown()
        }

        assertTrue(createdTuns.all { it.closed.get() })
        assertEquals(TunnelPhase.OFF, manager.snapshot.phase)
    }

    @Test
    fun `reports needsElevation cleanly when process lacks administrator rights`() {
        val serverPriv = ByteArray(32) { (it + 1).toByte() }
        val serverPub = Crypto.publicOf(serverPriv)
        val manager = NativeWintunTunnelManager(
            nativeDir = File(System.getProperty("java.io.tmpdir")),
            runner = FakeCommandRunner(elevated = false),
            tunFactory = { error("must not open Wintun without elevation") },
            requireElevationCheck = true,
            skipNetConfig = true
        )

        try {
            val ok = manager.connect(testConfig(Endpoint("162.159.192.1", 2408), serverPub))
            assertFalse(ok)
            assertTrue(manager.snapshot.needsElevation)
            assertEquals(TunnelPhase.ERROR, manager.snapshot.phase)
        } finally {
            manager.shutdown()
        }
    }
}
