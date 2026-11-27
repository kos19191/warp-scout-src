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

    @Test
    fun `failover queue prioritizes obfuscated junk profile over duplicate none`() {
        val serverPub = Crypto.publicOf(ByteArray(32) { (it + 5).toByte() })
        val primaryNone = testConfig(Endpoint("162.159.192.10", 8886), serverPub)
        val fallbackNone = testConfig(Endpoint("162.159.195.6", 500), serverPub)
        val fallbackSip = testConfig(Endpoint("162.159.192.10", 880), serverPub).copy(
            junk = dev.warpscout.core.junk.JunkLibrary.sip()
        )
        val manager = NativeWintunTunnelManager(
            nativeDir = File(System.getProperty("java.io.tmpdir")),
            runner = FakeCommandRunner(elevated = true),
            requireElevationCheck = false,
            skipNetConfig = true
        )
        try {
            val q = manager.buildQueue(primaryNone, listOf(fallbackNone, fallbackSip))
            assertEquals("162.159.192.10:8886", q[0].endpoint.render())
            assertEquals("sip-invite", q[1].junk.name, "Second failover slot must switch away from none")
            assertEquals("162.159.192.10:880", q[1].endpoint.render())
            assertTrue(q.drop(1).any { it.junk.name != "none" }, "Emergency fallbacks must include obfuscation")
        } finally {
            manager.shutdown()
        }
    }

    @Test
    fun `Wg openTransport accepts out-of-order UDP packets via RFC 6479 window and rejects replays`() {
        val sendKey = ByteArray(32) { (it * 7 + 1).toByte() }
        val recvKey = ByteArray(32) { (it * 11 + 3).toByte() }
        var sender = Wg.Session(receiveKey = recvKey, sendKey = sendKey)
        var receiver = Wg.Session(receiveKey = sendKey, sendKey = recvKey)
        val idx = 0x11223344

        // Генерируем пакеты 0..5, доставляем в перемешанном порядке: 5, 2, 4, 0, 3, 1.
        val packets = (0..5).map { i ->
            val (pkt, next) = Wg.buildTransport(idx, sender, "msg-$i".toByteArray())
            sender = next
            i to pkt
        }.toMap()

        for (i in listOf(5, 2, 4, 0, 3, 1)) {
            val opened = Wg.openTransport(packets.getValue(i), idx, receiver)
            assertTrue(opened != null, "out-of-order packet $i must be accepted")
            assertEquals("msg-$i", String(opened!!.first))
            receiver = opened.second
        }

        // Любой повтор (и самого свежего, и старого) обязан отвергаться.
        for (i in listOf(5, 2, 0)) {
            assertEquals(null, Wg.openTransport(packets.getValue(i), idx, receiver), "duplicate $i must be rejected")
        }

        // Поддельный пакет с огромным счётчиком не должен сдвигать replay-окно.
        val forged = Wg.buildTransport(idx, Wg.Session(recvKey, ByteArray(32) { 9 }, sendCounter = 50_000L), "bad".toByteArray()).first
        assertEquals(null, Wg.openTransport(forged, idx, receiver))
        val (pkt6, _) = Wg.buildTransport(idx, sender, "msg-6".toByteArray())
        val opened6 = Wg.openTransport(pkt6, idx, receiver)
        assertTrue(opened6 != null && String(opened6.first) == "msg-6", "forged packet must not shift replay window")

        // Большой скачок через границу кольца (0 -> 5000): старые вне окна 2048 отвергаются, внутри окна принимаются.
        val win = Wg.ReplayWindow()
        win.mark(0L)
        win.mark(5000L)
        assertFalse(win.isAcceptable(2952L), "5000 - 2952 = 2048 -> outside window")
        assertTrue(win.isAcceptable(2953L), "5000 - 2953 = 2047 -> inside window")
        win.mark(2953L)
        assertFalse(win.isAcceptable(2953L), "replayed 2953 must be rejected")
        assertTrue(win.isAcceptable(4999L))
        win.mark(4999L)
        assertFalse(win.isAcceptable(4999L))
    }

    @Test
    fun `second exit automatically falls back to Double-Hop over WARP when direct WireGuard is blocked`() {
        val warpSrvPriv = ByteArray(32) { (it * 3 + 7).toByte() }
        val warpSrvPub = Crypto.publicOf(warpSrvPriv)
        val protonSrvPriv = ByteArray(32) { (it * 5 + 13).toByte() }
        val protonSrvPub = Crypto.publicOf(protonSrvPriv)
        val protonClientPriv = ByteArray(32) { (it * 7 + 19).toByte() }

        val warpEp = Endpoint("188.114.96.4", 854)
        val protonEp = Endpoint("217.138.213.2", 51820)
        val primaryCfg = testConfig(warpEp, warpSrvPub)

        val protonConfText = """
            [Interface]
            PrivateKey = ${Base64.getEncoder().encodeToString(protonClientPriv)}
            Address = 10.2.0.2/32
            DNS = 10.2.0.1

            [Peer]
            # CA-FREE#20
            PublicKey = ${Base64.getEncoder().encodeToString(protonSrvPub)}
            AllowedIPs = 0.0.0.0/0
            Endpoint = ${protonEp.render()}
        """.trimIndent()

        var protonAttempts = 0
        val manager = NativeWintunTunnelManager(
            nativeDir = File(System.getProperty("java.io.tmpdir")),
            runner = FakeCommandRunner(elevated = true),
            tunFactory = { name -> InMemoryTunDevice(name) },
            udpFactory = { ep ->
                when (ep) {
                    warpEp -> ResponderUdpChannel(ep, warpEp, warpSrvPriv)
                    protonEp -> {
                        protonAttempts++
                        if (protonAttempts == 1) {
                            // 1-я попытка (прямой WireGuard): имитируем блокировку ТСПУ (полная тишина).
                            ResponderUdpChannel(ep, Endpoint("0.0.0.0", 1), protonSrvPriv)
                        } else {
                            // 2-я попытка (Double-Hop поверх WARP): сервер ProtonVPN отвечает!
                            ResponderUdpChannel(ep, protonEp, protonSrvPriv)
                        }
                    }
                    else -> ResponderUdpChannel(ep, Endpoint("0.0.0.0", 1), warpSrvPriv)
                }
            },
            exitProber = { ExitInfo(ip = "217.138.213.2", colo = "YYZ", country = "CA", warpOn = false) },
            handshakeWaitMs = 2000L,
            statsPollMs = 5000L,
            requireElevationCheck = false,
            skipNetConfig = true
        )

        try {
            val ok = manager.connect(
                primary = primaryCfg,
                secondExit = SecondExitSpec(
                    enabled = true,
                    confText = protonConfText,
                    cidrsCsv = "0.0.0.0/0"
                )
            )
            assertTrue(ok, "Tunnel must connect")
            assertEquals(2, protonAttempts, "Must try direct first, then Double-Hop over WARP")
            assertTrue(manager.snapshot.secondExitActive, "Second exit must be active via Double-Hop")
            assertTrue(manager.snapshot.secondExitViaWarp, "secondExitViaWarp must be true")
            assertEquals(protonEp.render(), manager.snapshot.secondExitServer)
        } finally {
            manager.shutdown()
        }
    }
}
