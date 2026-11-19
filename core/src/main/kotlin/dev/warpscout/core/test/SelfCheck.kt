package dev.warpscout.core.test

import dev.warpscout.core.config.ConfTarget
import dev.warpscout.core.config.SplitRoutes
import dev.warpscout.core.config.WgConf
import dev.warpscout.core.lists.AllowList
import dev.warpscout.core.lists.AllowListPlanner
import dev.warpscout.core.lists.AllowLists
import dev.warpscout.core.lists.ListSide
import dev.warpscout.core.report.ConfigExport
import dev.warpscout.core.crypto.Blake2s
import dev.warpscout.core.crypto.Crypto
import dev.warpscout.core.junk.JunkLibrary
import dev.warpscout.core.junk.QuicMask
import dev.warpscout.core.keys.KeySource
import dev.warpscout.core.model.AwgParams
import dev.warpscout.core.model.Endpoint
import dev.warpscout.core.model.EndpointStats
import dev.warpscout.core.model.JunkChunk
import dev.warpscout.core.model.ProbeSample
import dev.warpscout.core.model.Verdict
import dev.warpscout.core.model.WarpConfig
import dev.warpscout.core.model.WarpAccount
import dev.warpscout.core.dpi.DpiComparator
import dev.warpscout.core.model.ResourceCheck
import dev.warpscout.core.net.EndpointPool
import dev.warpscout.core.net.EndpointSpec
import dev.warpscout.core.net.HttpClient
import dev.warpscout.core.net.NetSettings
import dev.warpscout.core.net.Socks5
import dev.warpscout.core.net.Socks5Endpoint
import dev.warpscout.core.net.PoolMode
import dev.warpscout.core.net.TlsProber
import dev.warpscout.core.net.WgProber
import dev.warpscout.core.presets.RoutePresets
import dev.warpscout.core.report.Report
import dev.warpscout.core.tune.Scoring
import dev.warpscout.core.tune.Weights
import dev.warpscout.core.wg.Wg

/**
 * Автономные проверки ядра. Запускаются и на десктопе (`warp-scout selftest`), и как unit-тесты
 * приложения — вся логика подобрана так, чтобы не требовать Android API.
 *
 *   ./gradlew :cli:run --args="selftest"            — офлайн-проверки (без сети)
 *   ./gradlew :cli:run --args="selftest --live"     — + сеть (генератор ключей, DoH, TLS, пробы)
 *   ./gradlew :cli:run --args="selftest --integration 127.0.0.1:34567"  — против tools/fake_warp_endpoint.py
 */
class SelfCheck(private val live: Boolean = false, private val integration: String? = null) {

    private var passed = 0
    private var failed = 0
    private val failures = mutableListOf<String>()

    fun run(): Int {
        section("криптография") {
            cryptoVectors()
            chachaCrossCheck()
        }
        section("wireguard handshake") {
            wgInitiationShape()
            wgHandshakeLoopback()
            dataPlaneLoopback()
            dataPlaneRekey()
        }
        section("junk-профили") {
            quicMaskRoundTrip()
            templateRendering()
        }
        section("конфиги") {
            confRoundTrip()
            sampleFiles()
        }
        section("пул endpoint'ов") {
            endpointPool()
        }
        section("скоринг и отчёт") {
            scoring()
            reportRendering()
        }
        section("socks5 / сравнение с ByeDPI") {
            socks5ByeDpiCompare()
        }
        section("списки allow-domains, маршруты, цели экспорта") {
            allowListsAndRoutes()
            confTargets()
        }
        if (live) {
            section("сеть: генератор/DoH/TLS") {
                liveNetwork()
            }
        }
        integration?.let { target ->
            section("сеть: integration с фейковым WARP-эндпоинтом") {
                liveIntegration(target)
            }
        }

        println()
        println("пройдено: $passed, провалено: $failed")
        failures.forEach { println("  ✗ $it") }
        return if (failed == 0) 0 else 1
    }

    // ------------------------------------------------------------------ helpers

    private fun section(name: String, block: () -> Unit) {
        println("— $name")
        runCatching(block).onFailure { reportFail("$name: исключение ${it.javaClass.simpleName}: ${it.message}") }
    }

    private fun check(name: String, condition: Boolean, detail: String = "") {
        if (condition) {
            passed++
            println("  ✓ $name")
        } else reportFail(name + if (detail.isEmpty()) "" else " — $detail")
    }

    private fun reportFail(msg: String) {
        failed++
        failures.add(msg)
        println("  ✗ $msg")
    }

    private fun expect(name: String, actual: Any?, expected: Any?) =
        check(name, actual?.toString() == expected?.toString(), "факт=$actual ожидалось=$expected")

    // ------------------------------------------------------------------- crypto

    private fun cryptoVectors() {
        // BLAKE2s: значения получены hashlib.blake2s (CPython), т.е. независимо от нашей реализации.
        expect("blake2s(пусто)", Crypto.hex(Blake2s.hash(ByteArray(0))),
            "69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9")
        expect("blake2s(\"abc\")", Crypto.hex(Blake2s.hash("abc".toByteArray())),
            "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982")
        expect("blake2s-128(\"abc\")", Crypto.hex(Blake2s.hash("abc".toByteArray(), 16)),
            "aa4938119b1dc7b87cbad0ffd200d0ae")
        val key = ByteArray(32) { it.toByte() }
        expect("blake2s keyed(\"abc\")", Crypto.hex(Blake2s(32, key).digest("abc".toByteArray())),
            "a281f725754969a702f6fe36fc591b7def866e4b70173ece402fc01c064d6b65")
        expect("hmac-blake2s(\"hello world\")", Crypto.hex(Blake2s.hmac(key, "hello world".toByteArray())),
            "ab8de334c780c9f8619f195f50dc4653044dc0a584c7398a3b89c2a8206ee1b6")
        expect("blake2s 1 МБ потоком = one-shot", run {
                val chunk = ByteArray(64 * 1024) { (it % 251).toByte() }
                val d = Blake2s(32)
                repeat(16) { d.update(chunk) }
                val out = ByteArray(32); d.finalize(out)
                val oneShot = Blake2s.hash(chunk + chunk + chunk + chunk + chunk + chunk + chunk + chunk +
                    chunk + chunk + chunk + chunk + chunk + chunk + chunk + chunk)
                Crypto.hex(out) == Crypto.hex(oneShot)
            }, true)

        // X25519: значения сверены с OpenSSL (python `cryptography`) — независимая реализация,
        // включая правильный clamp приватного ключа (BC/JDK/OpenSSL сходятся байт-в-байт).
        val a = Crypto.unHex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
        val b = Crypto.unHex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0f3")
        expect("x25519 pubkey A", Crypto.hex(Crypto.publicOf(a)),
            "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
        expect("x25519 pubkey B", Crypto.hex(Crypto.publicOf(b)),
            "ad8755450a97a734c552508acee9532b824f379522a085ac05e066e3d448fc31")
        expect("x25519 общий секрет", Crypto.hex(Crypto.dh(a, Crypto.publicOf(b))),
            "2623f1ec8c905e1519e2b3aa25bf07ba09c6ffea666da889be3c2ffd647d4a65")
        check("x25519 симметричность", Crypto.dh(a, Crypto.publicOf(b)).contentEquals(Crypto.dh(b, Crypto.publicOf(a))))

        // base64/hex
        val rnd = ByteArray(32) { (it * 7 + 3).toByte() }
        check("base64 roundtrip", Crypto.unBase64(Crypto.base64(rnd)).contentEquals(rnd))
        check("base64 == java.util", Crypto.base64(rnd) == java.util.Base64.getEncoder().encodeToString(rnd))
        check("hex roundtrip", Crypto.unHex(Crypto.hex(rnd)).contentEquals(rnd))
    }

    private fun chachaCrossCheck() {
        // Шифруем нашей реализацией (BouncyCastle), расшифровываем стандартным JCA — и наоборот.
        val key = ByteArray(32) { (it + 1).toByte() }
        val nonce = ByteArray(12) { (it * 3).toByte() }
        val aad = "wireguard".toByteArray()
        val pt = ByteArray(100) { (it * 5).toByte() }
        val ct = Crypto.chacha20Poly1305Seal(key, nonce, pt, aad)
        check("chachapoly: длина = plaintext+16", ct.size == pt.size + 16)

        val jca = javax.crypto.Cipher.getInstance("ChaCha20-Poly1305")
        jca.init(
            javax.crypto.Cipher.DECRYPT_MODE,
            javax.crypto.spec.SecretKeySpec(key, "ChaCha20-Poly1305"),
            javax.crypto.spec.IvParameterSpec(nonce)
        )
        jca.updateAAD(aad)
        check("chachapoly: JCA расшифровал наш текст", jca.doFinal(ct).contentEquals(pt))

        val jca2 = javax.crypto.Cipher.getInstance("ChaCha20-Poly1305")
        jca2.init(
            javax.crypto.Cipher.ENCRYPT_MODE,
            javax.crypto.spec.SecretKeySpec(key, "ChaCha20-Poly1305"),
            javax.crypto.spec.IvParameterSpec(nonce)
        )
        jca2.updateAAD(aad)
        val ours = Crypto.chacha20Poly1305Open(key, nonce, jca2.doFinal(pt), aad)
        check("chachapoly: наша расшифровка текста JCA", ours?.contentEquals(pt) == true)
        check("chachapoly: неверный AAD отвергается",
            Crypto.chacha20Poly1305Open(ct, key, nonce, "wrong".toByteArray()) == null)

        // RFC 8439 §2.8.2 — известный ответ AEAD ChaCha20-Poly1305.
        val rKey = Crypto.unHex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
        val rNonce = Crypto.unHex("070000004041424344454647")
        val rAad = Crypto.unHex("50515253c0c1c2c3c4c5c6c7")
        val rPt = ("Ladies and Gentlemen of the class of '99: If I could offer you only one tip for " +
            "the future, sunscreen would be it.").toByteArray()
        val expected = ("d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb" +
            "69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808" +
            "b4831d7bc3ff4def08e4b7a9de576d26586cec64b61161ae10b594f09e26a7e902ecbd0600691")
        expect("chachapoly RFC 8439 §2.8.2", Crypto.hex(Crypto.chacha20Poly1305Seal(rKey, rNonce, rPt, rAad)), expected)

        // HChaCha20 — вектор из draft-irtf-cfrg-xchacha §2.2.1
        expect("hchacha20 (§2.2.1)",
            Crypto.hex(Crypto.hChaCha20(ByteArray(32) { it.toByte() },
                Crypto.unHex("000000090000004a0000000031415927"))),
            "82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc")

        // AEAD_XChaCha20_Poly1305 — вектор Appendix A.1 того же черновика
        val xxKey = ByteArray(32) { (0x80 + it).toByte() }
        val xxNonce = ByteArray(24) { (0x40 + it).toByte() }
        val xxAad = Crypto.unHex("50515253c0c1c2c3c4c5c6c7")
        val xxExpected = ("bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb" +
            "731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b452" +
            "2f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9" +
            "21f9664c97637da9768812f615c68b13b52e" + "c0875924c1c7987947deafd8780acf49")
        expect("xchachapoly A.1 (seal)", Crypto.hex(Crypto.xChaCha20Poly1305Seal(xxKey, xxNonce, rPt, xxAad)), xxExpected)
        expect("xchachapoly A.1 (open)",
            Crypto.xChaCha20Poly1305Open(xxKey, xxNonce, Crypto.unHex(xxExpected), xxAad)?.let { String(it) }
                ?.substring(0, 20), rPt.toString(Charsets.ISO_8859_1).substring(0, 20))
        check("xchachapoly: битый tag отвергается",
            Crypto.xChaCha20Poly1305Open(xxKey, xxNonce,
                Crypto.unHex(xxExpected).also { it[40] = (it[40].toInt() xor 1).toByte() }, xxAad) == null)
    }

    // --------------------------------------------------------------- wireguard

    private fun wgInitiationShape() {
        val priv = ByteArray(32) { (it + 2).toByte() }.also { it[31] = 0 }
        val pub = Crypto.publicOf(priv)
        val peer = Crypto.publicOf(ByteArray(32) { (it * 3 + 1).toByte() }.also { a -> a[31] = 0 })
        val init = Wg.buildInitiation(priv, pub, peer, 0x11223344, ephPrivate = ByteArray(32) { 5 }.also { it[31] = 0 }, timestamp = ByteArray(12) { 7 })

        check("init: ровно 148 байт", init.packet.size == Wg.INITIATION_LEN, "длина ${init.packet.size}")
        expect("init: type = 1", Crypto.readLe32(init.packet, 0), 1)
        expect("init: sender index", Crypto.readLe32(init.packet, 4), 0x11223344)
        check("init: эфемерный ключ = pubkey",
            init.packet.copyOfRange(8, 40).contentEquals(Crypto.publicOf(ByteArray(32) { 5 }.also { it[31] = 0 })))
        // детерминизм: те же входы → те же байты
        val init2 = Wg.buildInitiation(priv, pub, peer, 0x11223344, ephPrivate = ByteArray(32) { 5 }.also { it[31] = 0 }, timestamp = ByteArray(12) { 7 })
        check("init: детерминирован при фиксированных ключах/метке", init.packet.contentEquals(init2.packet))
        // метка TAI64N входит в шифротекст, поэтому при другом timestamp всё меняется
        val init3 = Wg.buildInitiation(priv, pub, peer, 0x11223344, ephPrivate = ByteArray(32) { 5 }.also { it[31] = 0 }, timestamp = ByteArray(12) { 8 })
        check("init: метка времени влияет на пакет", !init.packet.contentEquals(init3.packet))
        expect("keyId() = первые 4 байта HASH(pub)", Wg.keyId(pub), Crypto.readLe32(Blake2s.hash(pub), 0))
    }

    /**
     * Полный круг: инициируем handshake, сами играем роль сервера (ровно по спецификации, в обратную
     * сторону), проверяем ответ и выводим ключи сессии. Если где-то ошиблись в цепочке HASH/HMAC/AEAD —
     * tag не сойдётся.
     */
    private fun wgHandshakeLoopback() {
        val clientPriv = ByteArray(32) { (it * 5 + 1).toByte() }.also { it[31] = 0 }
        val serverPriv = ByteArray(32) { (200 - it).toByte() }.also { it[31] = 0 }
        val clientPub = Crypto.publicOf(clientPriv)
        val serverPub = Crypto.publicOf(serverPriv)

        val init = Wg.buildInitiation(clientPriv, clientPub, serverPub, 0x0badf00d)
        val response = WgResponder.respond(init.packet, serverPriv, receiverIndex = Crypto.readLe32(init.packet, 4))
        check("resp: 92 байта", response.size == Wg.RESPONSE_LEN, "длина ${response.size}")

        val reply = Wg.consumeResponse(response, init)
        expect("resp: принят как HANDSHAKE_OK", reply.kind.toString(), "HANDSHAKE_RESPONSE")
        check("resp: есть ключи сессии", reply.session != null)

        // портим 1 байт — принять должно отказаться
        val broken = response.copyOf().also { it[50] = (it[50].toInt() xor 0x01).toByte() }
        expect("resp: битый пакет отвергнут", Wg.consumeResponse(broken, init).kind.toString(), "MISMATCH")
        // ответ от другого индекса — отвергается
        expect("resp: чужой receiver_index отвергнут",
            Wg.consumeResponse(response.copyOfRange(0, 8) + Crypto.le32(1) + response.copyOfRange(12, 92), init).kind.toString(),
            "MISMATCH")
        val keep = Wg.buildKeepalive(0x1234, reply.session!!)
        check("keepalive: 32 байта, type=4", keep.size == 32 && Crypto.readLe32(keep, 0) == 4)
        expect("resp: sender index сервера проброшен", reply.peerSenderIndex?.toString(), (0x5a5a5a5a).toString())

        // ---- транспорт: данные в обе стороны через ключи сессии
        val (respSrv, srvSession) = WgResponder.respondWithSession(init.packet, serverPriv)
        val cliSession = Wg.consumeResponse(respSrv, init).session!!
        val payload = "данные сквозь туннель".toByteArray()
        val (pkt, cliAfter) = Wg.buildTransport(0x5a5a5a5a, cliSession, payload)
        check("transport: длина = 32 + данные", pkt.size == 32 + payload.size, "длина ${pkt.size}")
        check("transport: type = 4", Crypto.readLe32(pkt, 0) == 4)
        val opened = Wg.openTransport(pkt, 0x5a5a5a5a, srvSession)
        check("transport: сервер расшифровал пакет", opened?.first?.contentEquals(payload) == true)
        check("transport: повтор отвергнут", opened?.let { Wg.openTransport(pkt, 0x5a5a5a5a, it.second) } == null)
        val srvAfter = opened!!.second
        val (back, _) = Wg.buildTransport(0x0badf00d, srvAfter, payload.reversedArray())
        val cliGot = Wg.openTransport(back, 0x0badf00d, cliAfter)
        check("transport: клиент расшифровал ответ", cliGot?.first?.contentEquals(payload.reversedArray()) == true)
        val bad = back.copyOf().also { it[20] = (it[20].toInt() xor 0x40).toByte() }
        check("transport: битый тег отвергнут", Wg.openTransport(bad, 0x0badf00d, cliAfter) == null)

        // ---- cookie reply: сервер «под нагрузкой»
        val cookie = ByteArray(16) { (it + 1).toByte() }
        val init2 = Wg.buildInitiation(clientPriv, clientPub, serverPub, 0x77)
        val msg = WgResponder.cookieReply(init2.packet, serverPriv, cookie)
        check("cookie: 64 байта", msg.size == 64, "длина ${msg.size}")
        val r3 = Wg.consumeResponse(msg, init2, serverPub)
        expect("cookie: распознан как COOKIE_REPLY", r3.kind.toString(), "COOKIE_REPLY")
        check("cookie: расшифрован XChaCha20-Poly1305", r3.cookie?.contentEquals(cookie) == true,
            "cookie=${r3.cookie?.let { Crypto.hex(it) }}")
        // без публичного ключа пира cookie не расшифровать — но вердикт всё равно верный
        check("cookie: без ключа пира cookie не расшифровывается", Wg.consumeResponse(msg, init2).cookie == null)
        // повторная инициация с mac2 = MAC(cookie) должна пройти серверную проверку
        val init3 = Wg.buildInitiation(clientPriv, clientPub, serverPub, 0x88, lastCookie = cookie)
        check("cookie: mac2 проходит проверку сервера", WgResponder.mac2Valid(init3.packet, cookie))
        check("cookie: mac2 не проходит без cookie", !WgResponder.mac2Valid(init2.packet, cookie))
        val resp3 = WgResponder.respond(init3.packet, serverPriv)
        expect("cookie: повторная инициация принята", Wg.consumeResponse(resp3, init3, serverPub).kind.toString(),
            "HANDSHAKE_RESPONSE")
    }

    // ------------------------------------------------------------------- junk

    private fun quicMaskRoundTrip() {
        val sni = "ivi.ru"
        val dcid = byteArrayOf(0x42)
        val ch = QuicMask.clientHelloSniOnly(sni, ByteArray(32) { (it + 1).toByte() })
        val (payload, _) = QuicMask.clientHelloToFrames(ch, 3)
        val packet = QuicMask.initial(dcid, payload)

        check("quic: пакет разумной длины", packet.size in 40..400, "размер ${packet.size}")
        // long header + version 1
        check("quic: это QUIC long header", (packet[0].toInt() and 0x80) != 0)
        expect("quic: version = 1 (в unprotected заголовке после снятия HP)",
            run {
                val unprotected = QuicMaskForTest.unprotect(packet, dcid)
                Crypto.hex(unprotected.copyOfRange(1, 5))
            }, "00000001")
        val clientHello = QuicMaskForTest.extractClientHello(packet, dcid)
        check("quic: CRYPTO-фреймы собираются обратно в ClientHello", clientHello.isNotEmpty() && clientHello[0] == 0x01.toByte())
        check("quic: SNI внутри ClientHello", String(clientHello, 0, clientHello.size, Charsets.ISO_8859_1).contains(sni))

        val tmpl = QuicMask.buildTemplate(sni, level = 3, seed = 11)
        check("quic: шаблон состоит из литерала", tmpl.isNotEmpty() && tmpl.first() is JunkChunk.Literal)
        val rendered = WgConf.renderJunk(tmpl)
        check("quic: шаблон рендерится в <b 0x…>", rendered.startsWith("<b 0x"), rendered.take(24))
        val reparsed = WgConf.parseJunk(rendered)
        check("quic: шаблон читается обратно", JunkChunk.renderAll(reparsed) == rendered)
    }

    private fun templateRendering() {
        val chunks = listOf(JunkChunk.Literal(byteArrayOf(0xde.toByte(), 0xad.toByte(), 0xbe.toByte(), 0xef.toByte())), JunkChunk.RandomBytes(16))
        expect("рендер чанков", JunkChunk.renderAll(chunks), "<b 0xdeadbeef><r 16>")
        val back = WgConf.parseJunk("<b 0xdeadbeef><r 16>")
        check("парсинг чанков", back.size == 2 && (back[1] as JunkChunk.RandomBytes).size == 16)
        val mat = chunks[1].materialize(Crypto.random)
        check("материализация случайного чанка", mat.size == 16 && mat.any { it != 0.toByte() })
    }

    // ------------------------------------------------------------------ конфиг

    private fun confRoundTrip() {
        val text = """
            [Interface]
            PrivateKey = 6KGXl3bW0YR6gxRxBDxI2sO1hCwSjFPHqZ4zXK+8YnM=
            Address = 172.16.0.2, 2606:4700:110:8b63:28c5:b72d:11d1:de72
            DNS = 1.1.1.1, 1.0.0.1
            MTU = 1280
            S1 = 0
            S2 = 0
            S3 = 0
            S4 = 0
            Jc = 4
            Jmin = 40
            Jmax = 70
            H1 = 1
            H2 = 2
            H3 = 3
            H4 = 4
            I1 = <b 0xdeadbeef><r 16>

            [Peer]
            PublicKey = bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=
            AllowedIPs = 0.0.0.0/0, ::/0
            Endpoint = 188.114.98.2:943
            PersistentKeepalive = 25
        """.trimIndent()

        val cfg = WgConf.toWarpConfig("тест", text)
        check("парсинг: конфиг прочитан", cfg != null)
        cfg!!
        expect("парсинг: endpoint", cfg.endpoint.render(), "188.114.98.2:943")
        expect("парсинг: mtu", cfg.mtu, 1280)
        expect("парсинг: keepalive", cfg.persistentKeepalive, 25)
        expect("парсинг: Jc", cfg.junk.awg.jc, 4)
        expect("парсинг: I1 → чанки", JunkChunk.renderAll(cfg.junk.i1), "<b 0xdeadbeef><r 16>")
        expect("парсинг: IPv6-адрес подхвачен", cfg.account.ipv6, "2606:4700:110:8b63:28c5:b72d:11d1:de72")

        val rendered = WgConf.render(cfg)
        val again = WgConf.toWarpConfig("тест2", rendered)!!
        expect("round-trip: endpoint", again.endpoint.render(), cfg.endpoint.render())
        expect("round-trip: I1", JunkChunk.renderAll(again.junk.i1), JunkChunk.renderAll(cfg.junk.i1))
        expect("round-trip: allowedIps", again.allowedIps, cfg.allowedIps)
        check("round-trip: блоки Interface/Peer на месте",
            rendered.contains("[Interface]") && rendered.contains("[Peer]"))

        // конфиг без приватного ключа — не валиден
        check("парсинг: конфиг без ключа отклонён", WgConf.toWarpConfig("x", "[Peer]\nPublicKey = y") == null)
        expect("парсинг: IPv6 endpoint", WgConf.parseEndpoint("[2606:4700:1::3]:1074").render(), "[2606:4700:1::3]:1074")
    }

    private fun sampleFiles() {
        val dir = listOf("samples", "../samples", "../../samples")
            .map { java.io.File(it) }
            .firstOrNull { it.isDirectory }
        if (dir == null) {
            println("    (каталог samples/ не найден — пропускаю)")
            return
        }
        val files: Array<java.io.File> = dir.listFiles { x: java.io.File -> x.name.endsWith(".conf") } ?: emptyArray()
        for (f in files) {
            val cfg = WgConf.toWarpConfig(f.name, f.readText())
            check("образец ${f.name} разбирается", cfg != null)
            if (cfg == null) continue
            check("образец ${f.name}: профиль шума непустой", !cfg.junk.isEmpty, "I1=${cfg.junk.i1.size} чанков")
            check("образец ${f.name}: публичный ключ Cloudflare",
                cfg.account.peerPublicB64 == "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=")
        }
    }

    // ------------------------------------------------------------ endpoint pool

    private fun endpointPool() {
        val a = EndpointPool.build(EndpointSpec(seed = 1))
        val b = EndpointPool.build(EndpointSpec(seed = 1))
        val c = EndpointPool.build(EndpointSpec(seed = 2))
        check("пул: детерминирован по seed", a == b)
        check("пул: seed меняет выборку", a != c)
        check("пул: respecting maxEndpoints", a.size <= 400 && a.isNotEmpty(), "размер ${a.size}")
        check("пул: все порты из списка генератора", a.all { it.port in dev.warpscout.core.net.WarpDefaults.AWG_PORTS })
        check("пул: хостнеймы не дублируются", a.map { it.render() }.distinct().size == a.size)

        val full = EndpointPool.build(EndpointSpec(subnets = listOf("10.0.0."), ports = listOf(500, 501), octetRange = 0..3, mode = PoolMode.FULL, maxEndpoints = 100))
        expect("пул: FULL перебор", full.size, 8)
        val parsed = EndpointPool.parseList("162.159.192.*:943\n188.114.96.1-4:443 # комментарий\nengage.cloudflareclient.com:2408")
        expect("парсинг: * → 10 хостов", parsed.count { it.host.startsWith("162.159.192.") }, 10)
        expect("парсинг: диапазон октетов", parsed.count { it.host.startsWith("188.114.96.") }, 4)
        expect("парсинг: явный хост", parsed.last().render(), "engage.cloudflareclient.com:2408")
        check("парсинг: мусор игнорируется", EndpointPool.parseList("\n# только комментарий\n").isEmpty())
        // EXPLICIT — режим, в который UI превращает набранный пользователем список
        val explicit = EndpointPool.build(
            EndpointSpec(
                subnets = emptyList(),
                hostnames = listOf("8.6.112.*:943", "188.114.96.1-3:443", "engage.example.com:2408"),
                mode = PoolMode.EXPLICIT,
                maxEndpoints = 100
            )
        )
        check(
            "пул: EXPLICIT сканит ровно то, что набрал пользователь",
            explicit.size == 14 && explicit.any { it.host == "8.6.112.1" && it.port == 943 } &&
                explicit.count { it.port == 443 } == 3 && explicit.last().render() == "engage.example.com:2408",
            "размер=${explicit.size}"
        )
        expect("роуты обхода белых списков", RoutePresets.BYPASS_WHITELIST.size, 56)
    }

    // ----------------------------------------------------------- scoring/report

    private fun scoring() {
        fun stats(verdict: Verdict, rtts: List<Double>, loss: Double, ep: Endpoint = Endpoint("1.2.3.4", 500)) =
            EndpointStats(
                ep,
                rtts.mapIndexed { i, r -> ProbeSample(ep, verdict, r, i) },
                verdict,
                replies = rtts.size,
                attempts = (rtts.size / (1 - loss / 100.0)).toInt().coerceAtLeast(rtts.size)
            )

        val good = Scoring.evaluate(stats(Verdict.HANDSHAKE_OK, listOf(20.0, 21.0, 22.0), 0.0), true, 0, 0, Weights())
        expect("скоринг: живой + быстрый + шум проходит", good.total, 1000 + 300 + 200 + 100 + 150)
        val dead = Scoring.evaluate(stats(Verdict.UDP_CLOSED, emptyList(), 100.0), null, 0, 0, Weights())
        expect("скоринг: закрытый порт", dead.total, -500)
        val silent = Scoring.evaluate(stats(Verdict.UDP_SILENT, listOf(300.0), 100.0), false, 0, 0, Weights())
        // 60 (silent) + 40 (rtt 300мс) + 0 (потери 100%) − 150 (шум не прошёл)
        expect("скоринг: тишина + шум зарезан", silent.total, 60 + 40 + 0 - 150)
        check("скоринг: живой всегда лучше тихого", good.total > silent.total)
        check("вердикт: лучший = сильнейший (rank, а не последний в списке)",
            Verdict.bestOf(Verdict.HANDSHAKE_OK, Verdict.UDP_SILENT) == Verdict.HANDSHAKE_OK &&
                Verdict.bestOf(Verdict.UDP_CLOSED, Verdict.ERROR) == Verdict.UDP_CLOSED &&
                Verdict.bestOf(Verdict.TLS_OK, Verdict.COOKIE_REPLY) == Verdict.COOKIE_REPLY)
        val mixed = EndpointStats(Endpoint("1.2.3.4", 500),
            listOf(ProbeSample(Endpoint("1.2.3.4", 500), Verdict.UDP_SILENT, null, 0, "none"),
                ProbeSample(Endpoint("1.2.3.4", 500), Verdict.HANDSHAKE_OK, 30.0, 1, "none")),
            Verdict.HANDSHAKE_OK, 1, 2)
        check("вердикт: один живой образец не тонет в тишине", mixed.bestVerdict == Verdict.HANDSHAKE_OK)
    }

    private fun reportRendering() {
        val cfg = dev.warpscout.core.model.WarpConfig(
            name = "тест",
            account = dev.warpscout.core.model.WarpAccount("a=".repeat(1), "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=", "172.16.0.2", "2606::1"),
            endpoint = Endpoint("188.114.98.2", 943),
            junk = dev.warpscout.core.junk.JunkLibrary.quic("ivi.ru", 3, 1),
            allowedIps = "0.0.0.0/0, ::/0"
        )
        val st = EndpointStats(cfg.endpoint, listOf(ProbeSample(cfg.endpoint, Verdict.HANDSHAKE_OK, 33.0, 0)), Verdict.HANDSHAKE_OK, 1, 1)
        val cand = dev.warpscout.core.model.Candidate(cfg, st, Scoring.evaluate(st, true), emptyList())
        val report = dev.warpscout.core.model.TuningReport("т", "т", "профиль", listOf(cand), emptyList(), 12, listOf("заметка <1>"))

        val json = Report.toJson(report, includeConfig = false)
        val parsed = dev.warpscout.core.json.parseJson(json) as dev.warpscout.core.json.JsonVal.Obj
        expect("отчёт JSON: читается обратно, candidates", (parsed.arr("candidates")?.items?.size), 1)
        expect("отчёт JSON: endpoint", parsed.arr("candidates")?.items?.firstOrNull()?.let { (it as dev.warpscout.core.json.JsonVal.Obj).str("endpoint") }, "188.114.98.2:943")
        expect("отчёт JSON: score", parsed.arr("candidates")?.items?.firstOrNull()?.let { (it as dev.warpscout.core.json.JsonVal.Obj).num("score")?.toInt() }, cand.score)
        val html = Report.toHtml(report)
        check("отчёт HTML: содержит endpoint и экранирует заметки",
            html.contains("188.114.98.2:943") && html.contains("&lt;1&gt;") && html.startsWith("<!doctype html"))
        check("отчёт CSV: строка на кандидата", Report.toCsv(report).trim().lines().size == 2)
        check("отчёт MD: таблица кандидатов", Report.toMarkdown(report).contains("188.114.98.2:943"))
        val conf = WgConf.render(cfg)
        check("конфиг: содержит AWG-параметры", conf.contains("Jc = 4") && conf.contains("I1 = <b 0x"))
        check("конфиг: Clash YAML собирается", dev.warpscout.core.report.ConfigExport.clashYaml(cfg).contains("amnezia-wg-option"))
    }

    // ---------------------------------------------------------------- live: сеть

    private fun liveNetwork() {
        val keys = KeySource()
        val acc = runCatching { keys.fetchFresh() }.getOrNull()
        check("ключи: генератор ответил", acc != null, "все зеркала недоступны")
        if (acc != null) {
            check("ключи: приватный похож на Curve25519", KeySource.looksLikeCurve25519(acc.privateB64), acc.privateB64)
            expect("ключи: публичный ключ пира", acc.peerPublicB64, "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=")
            println("    источник: ${acc.source}, v4=${acc.ipv4}, v6=${acc.ipv6}")
        }

        val dns = dev.warpscout.core.net.DnsInspector()
        val res = dns.check(listOf("youtube.com", "mesh.clouflare.invalid"))
        check("DNS: DoH-резолвер отвечает", res.any { it.cloudflareDoH.isNotEmpty() })
        res.forEach { println("    ${it.domain}: system=${it.system.take(2)} cf=${it.cloudflareDoH.take(2)} → ${it.verdict}") }

        val tls = TlsProber(NetSettings(connectTimeoutMs = 3000))
        val sample = listOf(Endpoint("1.1.1.1", 443), Endpoint("162.159.198.2", 443)).map { tls.probe(it, "www.google.com") }
        sample.forEach { println("    TLS ${it.endpoint.render()} → ${it.verdict} ${it.rttMs} ${it.note}") }
        check("TLS: хотя бы один эндпоинт отвечает (иначе сеть не для живых проверок)",
            sample.any { it.verdict == Verdict.TLS_OK })

        val resources = dev.warpscout.core.net.ResourceProber()
        val rr = resources.checkAll(dev.warpscout.core.presets.Presets.RESOURCE_CHECKS.take(4), 4)
        rr.forEach { println("    ${it.check.name}: ok=${it.ok} status=${it.status} err=${it.errorClass} ${it.elapsedMs}мс") }
        check("ресурсы: контроль-точка доступна", rr.firstOrNull()?.ok == true, "даже базовый сайт недоступен из этой сети")
    }

    /**
     * Туннельный data plane целиком: живой UDP-сокет, фейковый-peer отвечает по спецификации,
     * мы проверяем, что IP-пакет ушёл зашифрованным и вернулся обратно расшифрованным.
     */
    private fun dataPlaneLoopback() {
        val clientPriv = ByteArray(32) { (it * 3 + 7).toByte() }
        val serverPriv = ByteArray(32) { (it * 5 + 11).toByte() }
        val clientPub = Crypto.publicOf(clientPriv)
        val serverPub = Crypto.publicOf(serverPriv)

        val serverSock = java.net.DatagramSocket()
        val port = serverSock.localPort
        val opened = java.util.concurrent.CountDownLatch(1)
        var transported: ByteArray? = null
        var serverError: String? = null

        val serverThread = Thread {
            try {
                serverSock.soTimeout = 6000
                val p = java.net.DatagramPacket(ByteArray(2048), 2048)
                serverSock.receive(p)
                val init = p.data.copyOfRange(0, p.length)
                if (init.size != Wg.INITIATION_LEN) error("ожидал инициацию 148 байт, получил ${init.size}")
                val (resp, srvSession) = WgResponder.respondWithSession(init, serverPriv)
                serverSock.send(java.net.DatagramPacket(resp, resp.size, p.socketAddress))
                val ourIndex = Crypto.readLe32(init, 4)      // индекс клиента (ему и отвечаем)
                val serverIndex = 0x5a5a5a5a                  // наш индекс, нас им и вызывают
                // Клиент после установки сессии присылает пустой keepalive — это нормальный
                // WireGuard-трафик, а не пользовательский пакет: пропускаем пустые и ждём данные.
                var got: Pair<ByteArray, dev.warpscout.core.wg.Wg.Session>? = null
                var packets = 0
                while (got == null && packets < 5) {
                    packets++
                    val p2 = java.net.DatagramPacket(ByteArray(2048), 2048)
                    serverSock.receive(p2)
                    val pkt = p2.data.copyOfRange(0, p2.length)
                    val opened = Wg.openTransport(pkt, serverIndex, srvSession) ?: error("транспорт не расшифровался")
                    if (opened.first.isNotEmpty()) got = opened
                }
                val data = got ?: error("за 5 пакетов не пришло ни одного непустого transport")
                transported = data.first
                val (echo, _) = Wg.buildTransport(ourIndex, data.second, data.first)  // эхо клиенту
                serverSock.send(java.net.DatagramPacket(echo, echo.size, p.socketAddress))
                opened.countDown()
            } catch (e: Exception) {
                serverError = "${e.javaClass.simpleName}: ${e.message}"
                opened.countDown()
            } finally {
                runCatching { serverSock.close() }
            }
        }
        serverThread.isDaemon = true
        serverThread.start()

        val tunIn = QueueInputStream()
        val tunOut = QueueOutputStream()
        val clientSock = java.net.DatagramSocket().apply {
            connect(java.net.InetSocketAddress("127.0.0.1", port))
            soTimeout = 300
        }
        val config = dev.warpscout.core.model.WarpConfig(
            name = "loopback",
            account = dev.warpscout.core.model.WarpAccount(Crypto.base64(clientPriv), Crypto.base64(serverPub)),
            endpoint = Endpoint("127.0.0.1", port),
            junk = dev.warpscout.core.junk.JunkLibrary.none(),
            persistentKeepalive = null
        )
        val planeLog = StringBuilder()
        val plane = dev.warpscout.core.tunnel.DataPlane(
            dev.warpscout.core.tunnel.SocketUdpChannel(clientSock, Endpoint("127.0.0.1", port), 300),
            tunIn, tunOut, config,
            NetSettings(attempts = 2, timeoutMs = 1500)
        ) { line -> planeLog.append(line).append("; ") }
        val planeThread = Thread { plane.run() }
        planeThread.isDaemon = true
        planeThread.start()

        val ipPacket = ByteArray(48).also { b ->
            b[0] = 0x45; b[1] = 0
            java.net.Inet4Address.getByName("172.16.0.2")
            b[12] = 108.toByte(); b[13] = 64.toByte(); b[14] = 0; b[15] = 1
            b[16] = 1.toByte(); b[17] = 1; b[18] = 1; b[19] = 1
            for (i in 20 until 48) b[i] = (i % 251).toByte()
        }
        tunIn.offer(ipPacket)
        val finished = opened.await(8, java.util.concurrent.TimeUnit.SECONDS)
        check("data plane: handshake поднят", plane.handshakeOk)
        check("data plane: пакет дошёл до пира", finished && transported?.contentEquals(ipPacket) == true,
            serverError ?: "transport=${transported?.size}")
        if (serverError != null || transported == null) println("    plane log: $planeLog")
        val back = tunOut.poll(3000L)
        check("data plane: эхо вернулось в tun", back?.contentEquals(ipPacket) == true, "back=${back?.size}")
        // Инкременты живут в потоках пересылки: даём им доехать (иначе проверка флейкала бы).
        val counterDeadline = System.currentTimeMillis() + 1000
        while (System.currentTimeMillis() < counterDeadline &&
            (plane.bytesUp < ipPacket.size || plane.bytesDown == 0L)
        ) Thread.sleep(25)
        check(
            "data plane: счётчики учтены",
            plane.bytesUp == ipPacket.size.toLong() && plane.bytesDown == ipPacket.size.toLong(),
            "up=${plane.bytesUp} down=${plane.bytesDown} ожидалось=${ipPacket.size}"
        )
        plane.stop()
        planeThread.join(2000)
        serverThread.join(2000)
    }

    private fun liveIntegration(target: String) {
        val (host, portStr) = target.split(':')
        val endpoint = Endpoint(host, portStr.toInt())
        val priv = ByteArray(32) { (it + 3).toByte() }.also { it[31] = 0 }
        val account = dev.warpscout.core.model.WarpAccount(Crypto.base64(priv), Crypto.base64(Crypto.publicOf(priv)))
        val peerPriv = ByteArray(32) { (it * 2 + 1).toByte() }.also { it[31] = 0 }
        val prober = WgProber(NetSettings(attempts = 2, timeoutMs = 2500, betweenAttemptsMs = 50, concurrency = 2))
        val res = prober.probe(endpoint, account, Crypto.publicOf(peerPriv), dev.warpscout.core.junk.JunkLibrary.tlsFixed())
        expect("integration: фейковый сервер подтвердил handshake", res.stats.bestVerdict.toString(), "HANDSHAKE_OK")
        check("integration: RTT померен", (res.stats.minRtt ?: 0.0) > 0.0, "rtt=${res.stats.minRtt}")

        val closed = prober.probe(Endpoint("127.0.0.1", 1), account, Crypto.publicOf(peerPriv), null)
        // UDP_CLOSED — ICMP port unreachable; UDP_SILENT — молчит (тоже «не живой»);
        // ERROR — сокет не смог отправить/принять (в контейнерах ICMP отрезан). Все три означают
        // «порт не подтвердился», и именно это проверяется: закрытый порт НЕ выдаёт себя за живой.
        check("integration: закрытый порт отличается от «молчит»",
            closed.stats.bestVerdict in setOf(Verdict.UDP_CLOSED, Verdict.UDP_SILENT, Verdict.ERROR),
            "вердикт=${closed.stats.bestVerdict}, примечание=${closed.stats.samples.firstOrNull()?.note}")

        // Транспорт сквозь НЕЗАВИСИМУЮ реализацию (tools/fake_warp_endpoint.py) — причём не «ручной»
        // обмен пакетами, а настоящий DataPlane: мусор → инициация → cookie → сессия → эхо в tun.
        runCatching {
            val peerPub = Crypto.publicOf(peerPriv)
            val cfg = dev.warpscout.core.model.WarpConfig(
                name = "integration",
                account = dev.warpscout.core.model.WarpAccount(
                    privateB64 = Crypto.base64(priv),
                    peerPublicB64 = Crypto.base64(peerPub)
                ),
                endpoint = endpoint,
                junk = dev.warpscout.core.junk.JunkLibrary.tlsFixed(),
                persistentKeepalive = null
            )
            val tunIn = QueueInputStream()
            val tunOut = QueueOutputStream()
            val sock = java.net.DatagramSocket().apply {
                soTimeout = 800
                connect(java.net.InetSocketAddress(host, portStr.toInt()))
            }
            val planeLog = StringBuilder()
            val plane = dev.warpscout.core.tunnel.DataPlane(
                dev.warpscout.core.tunnel.SocketUdpChannel(sock, endpoint, 800),
                tunIn, tunOut, cfg,
                NetSettings(
                    attempts = 3, timeoutMs = 2500, betweenAttemptsMs = 120, junkPacketsBeforeHandshake = 1,
                    // Ускоренный rekey: проверяем само пересогласование, а не то, что 120 с проходят.
                    rekeyAfterMs = 900, rekeyRetryMs = 200
                )
            ) { line -> planeLog.append(line).append("; ") }
            val thread = Thread { plane.run() }.apply { isDaemon = true; start() }
            try {
                val until = System.currentTimeMillis() + 9000
                while (!plane.handshakeOk && System.currentTimeMillis() < until) Thread.sleep(50)
                check("integration: data plane поднял сессию", plane.handshakeOk, planeLog.toString())

                val ip = ByteArray(48).also { b ->
                    b[0] = 0x45; b[12] = 108.toByte(); b[13] = 64.toByte()
                    b[16] = 1.toByte(); b[17] = 1; b[18] = 1; b[19] = 1
                    for (i in 20 until 48) b[i] = (i % 251).toByte()
                }
                tunIn.offer(ip)
                val back = tunOut.poll(5000L)
                check("integration: пакет прошёл сквозь tun туда и обратно",
                    back?.contentEquals(ip) == true, "back=${back?.size} байт; $planeLog")
                var waited = 0
                while (waited < 1000 && (plane.bytesUp < ip.size || plane.bytesDown < ip.size)) {
                    Thread.sleep(25); waited += 25
                }
                check("integration: data plane посчитал трафик",
                    plane.bytesUp == ip.size.toLong() && plane.bytesDown == ip.size.toLong(),
                    "up=${plane.bytesUp} down=${plane.bytesDown}")

                // Ровно тот баг, из-за которого Telegram умирал через три минуты: сессия обязана
                // пересогласовываться САМА, без перезапуска сервиса.
                val rekeyUntil = System.currentTimeMillis() + 6000
                while (plane.rekeyCount < 1 && System.currentTimeMillis() < rekeyUntil) Thread.sleep(50)
                check("integration: сессия пересогласована автоматически", plane.rekeyCount >= 1,
                    "rekey=${plane.rekeyCount}; ${planeLog}")
            } finally {
                plane.stop()
                runCatching { sock.close() }
                runCatching { thread.join(1500) }
            }
        }.onFailure { reportFail("integration: data plane упал — ${it.javaClass.simpleName}: ${it.message}") }
    }

    /**
     * Пересогласование сессии (rekey). Это регрессия на «работает 3–5 минут, потом Telegram пишет
     * Соединение…»: WireGuard выбрасывает сессию через 180 с, а клиент обязан сам её обновить
     * (REKEY_AFTER_TIME = 120 с). Тут таймеры ускорены до 700 мс, сервер — локальный и независимый
     * (эхо через WgResponder), поэтому проверка идёт офлайн и без живого WARP.
     */
    private fun dataPlaneRekey() {
        val clientPriv = ByteArray(32) { (it * 3 + 17).toByte() }
        val serverPriv = ByteArray(32) { (it * 5 + 23).toByte() }
        val serverPub = Crypto.publicOf(serverPriv)
        val clientPub = Crypto.publicOf(clientPriv)

        val serverSock = java.net.DatagramSocket()
        val port = serverSock.localPort
        val serverStop = java.util.concurrent.atomic.AtomicBoolean(false)
        val handshakes = java.util.concurrent.atomic.AtomicInteger(0)
        var serverError: String? = null

        val serverThread = Thread {
            var session: dev.warpscout.core.wg.Wg.Session? = null
            var clientIndex = 0
            try {
                serverSock.soTimeout = 300
                val buf = ByteArray(65536)
                while (!serverStop.get()) {
                    val p = java.net.DatagramPacket(buf, buf.size)
                    try {
                        serverSock.receive(p)
                    } catch (e: java.net.SocketTimeoutException) {
                        continue
                    }
                    val pkt = p.data.copyOfRange(0, p.length)
                    val type = if (pkt.size >= 4) Crypto.readLe32(pkt, 0) else -1
                    when (type) {
                        Wg.TYPE_INITIATION -> {
                            if (pkt.size != Wg.INITIATION_LEN) continue
                            val (resp, srvSession) = WgResponder.respondWithSession(pkt, serverPriv)
                            session = srvSession
                            clientIndex = Crypto.readLe32(pkt, 4)
                            handshakes.incrementAndGet()
                            serverSock.send(java.net.DatagramPacket(resp, resp.size, p.socketAddress))
                        }

                        Wg.TYPE_TRANSPORT -> {
                            val s = session ?: continue
                            val got = Wg.openTransport(pkt, 0x5a5a5a5a, s) ?: continue
                            session = got.second
                            val (echo, next) = Wg.buildTransport(clientIndex, got.second, got.first)
                            session = next
                            serverSock.send(java.net.DatagramPacket(echo, echo.size, p.socketAddress))
                        }
                    }
                }
            } catch (e: Exception) {
                serverError = "${e.javaClass.simpleName}: ${e.message}"
            } finally {
                runCatching { serverSock.close() }
            }
        }
        serverThread.isDaemon = true
        serverThread.start()

        val tunIn = QueueInputStream()
        val tunOut = QueueOutputStream()
        val clientSock = java.net.DatagramSocket().apply {
            connect(java.net.InetSocketAddress("127.0.0.1", port))
            soTimeout = 300
        }
        val config = dev.warpscout.core.model.WarpConfig(
            name = "rekey",
            account = dev.warpscout.core.model.WarpAccount(Crypto.base64(clientPriv), Crypto.base64(serverPub)),
            endpoint = Endpoint("127.0.0.1", port),
            junk = dev.warpscout.core.junk.JunkLibrary.none(),
            persistentKeepalive = null
        )
        val planeLog = StringBuilder()
        val plane = dev.warpscout.core.tunnel.DataPlane(
            dev.warpscout.core.tunnel.SocketUdpChannel(clientSock, Endpoint("127.0.0.1", port), 300),
            tunIn, tunOut, config,
            NetSettings(attempts = 2, timeoutMs = 1200, rekeyAfterMs = 700, rekeyRetryMs = 150)
        ) { line -> planeLog.append(line).append("; ") }
        val planeThread = Thread { plane.run() }.apply { isDaemon = true; start() }

        try {
            val startDeadline = System.currentTimeMillis() + 4000
            while (!plane.handshakeOk && System.currentTimeMillis() < startDeadline) Thread.sleep(25)
            check("rekey: сессия поднялась", plane.handshakeOk, planeLog.toString())

            val rekeyDeadline = System.currentTimeMillis() + 6000
            while (plane.rekeyCount < 2 && System.currentTimeMillis() < rekeyDeadline) Thread.sleep(50)
            check(
                "rekey: сессия пересогласована сама (2 раза)",
                plane.rekeyCount >= 2,
                "rekey=${plane.rekeyCount}, инициаций на сервере=${handshakes.get()}, ${planeLog}"
            )

            // Данные должны ходить и ПОСЛЕ пересогласования — иначе «rekey есть, а трафика нет».
            val ipPacket = ByteArray(48).also { b ->
                b[0] = 0x45; b[12] = 108.toByte(); b[13] = 64.toByte()
                b[16] = 1.toByte(); b[17] = 1; b[18] = 1; b[19] = 1
                for (i in 20 until 48) b[i] = (i % 251).toByte()
            }
            tunIn.offer(ipPacket)
            val back = tunOut.poll(4000L)
            check("rekey: данные идут после пересогласования", back?.contentEquals(ipPacket) == true,
                serverError ?: "back=${back?.size}; ${planeLog}")
            check("rekey: возраст сессии обнулился", plane.sessionAgeMs() < 4000,
                "age=${plane.sessionAgeMs()}")
        } finally {
            plane.stop()
            runCatching { planeThread.join(1500) }
            serverStop.set(true)
            runCatching { serverSock.close() }
            runCatching { serverThread.join(1500) }
        }
    }

    // --------------------------------------------------- SOCKS5 / сравнение с ByeDPI

    private fun socks5ByeDpiCompare() {
        expect("socks5: разбор host:port", Socks5Endpoint.parse("127.0.0.1:1080")?.render(), "127.0.0.1:1080")
        expect("socks5: только порт = loopback", Socks5Endpoint.parse("1080")?.render(), "127.0.0.1:1080")
        expect("socks5: префикс схемы и скобки", Socks5Endpoint.parse("socks5://[::1]:1080")?.render(), "::1:1080")
        check("socks5: пусто → null", Socks5Endpoint.parse("   ") == null)
        check("socks5: мусор → null", Socks5Endpoint.parse("localhost") == null && Socks5Endpoint.parse("host:") == null)
        check("socks5: порт вне диапазона → null", Socks5Endpoint.parse("127.0.0.1:99999") == null)
        check("socks5: конфиг ByeDPI по умолчанию", Socks5Endpoint.BYEDPI_DEFAULT.render() == "127.0.0.1:1080")

        val origin = FakeHttpOrigin()
        val proxy = FakeSocks5Relay(origin.port)
        try {
            val target = "http://127.0.0.1:${origin.port}/"

            val sock = Socks5.connect(Socks5Endpoint("127.0.0.1", proxy.port), "127.0.0.1", origin.port, 3000)
            sock.getOutputStream().write("GET / HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n".toByteArray())
            val text = sock.getInputStream().readBytes().toString(Charsets.UTF_8)
            sock.close()
            check("socks5: байты прошли через прокси", text.contains("200 OK"), text.take(60).replace("\r\n", " "))
            expect("socks5: цель передана как IPv4 (ATYPE 1)", proxy.lastAtyp.toString(), "1")
            expect("socks5: порт цели в сетевом порядке", proxy.lastPort, origin.port)

            val viaProxy = HttpClient(3000, proxy = Socks5Endpoint("127.0.0.1", proxy.port))
            expect("HttpClient через SOCKS5: статус", viaProxy.get(target).status, 200)

            val cmp = DpiComparator(timeoutMs = 4000, connectTimeoutMs = 1500).compare(
                listOf(
                    ResourceCheck("открыто всегда", target),
                    // домен в зоне .invalid не резолвится никогда (RFC 6761) — «напрямую» обязано лечь,
                    // а наш фейковый прокси умеет подменять его на живой источник: ровно картина DPI-блокировки
                    ResourceCheck("лежит напрямую", "http://blocked.invalid:80/")
                ),
                Socks5Endpoint("127.0.0.1", proxy.port)
            )
            check("comparator: сравнение состоялось", cmp.usable, cmp.headline())
            expect("comparator: открыто и там и там", cmp.rows[0].outcome.name, "OPEN_BOTH")
            expect("comparator: оживает только через обход", cmp.rows[1].outcome.name, "OPEN_ONLY_VIA_PROXY")
            expect("comparator: счётчик DPI-образных", cmp.dpiShaped, 1)
            check("comparator: вывод по-русски и по делу",
                cmp.headline().contains("DPI") && cmp.renderText().contains("через SOCKS5"), cmp.headline())

            val dead = DpiComparator(1500, 800).compare(listOf(ResourceCheck("t", target)), Socks5Endpoint("127.0.0.1", 1))
            expect("comparator: мёртвый прокси → PROXY_UNREACHABLE", dead.rows.single().outcome.name, "PROXY_UNREACHABLE")
            check("comparator: при мёртвом прокси не врёт про блокировки",
                !dead.usable && dead.headline().contains("режим прокси"), dead.headline())

            val auth = FakeSocks5NeedsAuth()
            val err = runCatching {
                Socks5.connect(Socks5Endpoint("127.0.0.1", auth.port), "127.0.0.1", origin.port, 1500)
            }.exceptionOrNull()
            check("socks5: требование авторизации объясняется по-человечески",
                err?.message?.contains("аутентификац") == true, err?.message.orEmpty())
            auth.close()
        } finally {
            origin.close()
            proxy.close()
        }
    }

    // ------------------------------- списки allow-domains, маршруты, клиенты конфига

    private fun allowListsAndRoutes() {
        val sample = """
            # комментарий как в репозитории
            ; и такой тоже
            youtube.com
            .googlevideo.com
            *.youtu.be
            91.108.4.0/22
            2001:67c:4e8::/48
            DOMAIN-SUFFIX,discord.com
            IP-CIDR,149.154.160.0/20
            ||blocked.tld
            !excluded.tld
            мусорная строка
            no-dot-here
        """.trimIndent()
        val parsed = AllowLists.parse(sample)
        expect("списки: домены распознаны", parsed.domains.size, 6)
        expect("списки: подсети распознаны", parsed.prefixes.size, 3)
        check("списки: ведущая точка/звёздочка сняты", "youtu.be" in parsed.domains && "googlevideo.com" in parsed.domains)
        check("списки: surge/uBlock-форматы поняты",
            "discord.com" in parsed.domains && "blocked.tld" in parsed.domains && "excluded.tld" in parsed.domains)
        check("списки: CIDR из surge-строки понят", "149.154.160.0/20" in parsed.prefixes)
        check("списки: мусор и голые имена отвергнуты",
            parsed.domains.none { it.contains("мусор") } && parsed.domains.none { it == "no-dot-here" })

        // --- план маршрутов: подсети берём как есть, домены резолвим, бюджет соблюдаем
        val block = listOf(AllowList("t1", "Тест1", ListSide.BLOCK, "x"))
        val direct = listOf(AllowList("t2", "Тест2", ListSide.DIRECT, "y"))
        val maps = mapOf("t1" to parsed, "t2" to AllowLists.Parsed(listOf("alfabank.ru"), listOf("1.2.3.0/24")))
        val resolver: (String) -> List<String> = { host ->
            when (host) {
                "youtube.com" -> listOf("172.64.0.1", "2606:4700::1")
                "googlevideo.com" -> listOf("216.58.200.14")
                "youtu.be" -> emptyList()          // «не разрешилось» должно быть видно, а не проглочено
                else -> emptyList()
            }
        }
        val plan = AllowListPlanner.plan(block, direct, maps, fullTunnel = false, maxDomains = 6, resolver = resolver)
        check("маршруты: подсети из списка попали", "91.108.4.0/22" in plan.include && "2001:67c:4e8::/48" in plan.include)
        check("маршруты: домен развёрнут в /32 и /128",
            "172.64.0.1/32" in plan.include && "2606:4700::1/128" in plan.include)
        check("маршруты: не разрешилось записано, а не проигнорировано", "youtu.be" in plan.unresolved)
        check("маршруты: чужие домены (DIRECT) не попали в AllowedIPs",
            plan.include.none { it.startsWith("1.2.3.") } && plan.excludeNote.contains("alfabank.ru"))
        check("маршруты: allowedIps — это CIDR-список",
            plan.allowedIps.split(", ").toSet() == plan.include.toSet() && plan.allowedIps.contains("/32"),
            plan.allowedIps.take(120))
        // бюджет — на домены, а не на подсети: 1 подсеть + 1 домен в лимите 1
        val tight = AllowListPlanner.plan(block, direct, maps, fullTunnel = false, maxDomains = 1, resolver = resolver)
        check("маршруты: бюджет режет домены, но не подсети",
            tight.include.any { it == "91.108.4.0/22" } && tight.include.count { it.endsWith("/32") } <= 2,
            tight.include.take(6).joinToString())
        check("маршруты: сводка объяснимая", plan.summary().contains("маршрутов"), plan.summary())
        val full = AllowListPlanner.plan(block, direct, maps, fullTunnel = true)
        expect("маршруты: «весь трафик» = два default-маршрута", full.allowedIps, "0.0.0.0/0, ::/0")
        check("маршруты: пустой кеш не рождает битый конфиг",
            AllowListPlanner.plan(block, direct, emptyMap()).allowedIps == "0.0.0.0/0, ::/0")

        // --- SplitRoutes: общий лимит на число маршрутов
        val many = (1..1200).map { "h$it.example.com" }
        val capped = SplitRoutes.build(many, { listOf("203.0.113.7") })
        check("SplitRoutes: лимит маршрутов соблюдён",
            capped.prefixes.size <= SplitRoutes.MAX_PREFIXES, "получено ${capped.prefixes.size}")
        expect("SplitRoutes: fullTunnel короткое", SplitRoutes.build(many, { listOf("1.1.1.1") }, fullTunnel = true).allowedIps,
            "0.0.0.0/0, ::/0")
        expect("SplitRoutes: парсинг обратно", SplitRoutes.prefixesOf("0.0.0.0/0, ::/0").size, 2)

        // --- проверки «по обе стороны»: blocked-сторона и «не трогать»
        val checks = AllowLists.checksFor(AllowList("t1", "Тест1", ListSide.BLOCK, "x"), parsed, limit = 2)
        expect("списки: проверки построены", checks.size, 2)
        val directChecks = AllowLists.checksFor(AllowList("t2", "Тест2", ListSide.DIRECT, "y"),
            AllowLists.Parsed(listOf("alfabank.ru"), emptyList()), limit = 1)
        check("списки: «держать напрямую» помечено baselineExpected",
            directChecks.single().baselineExpected && !checks.first().baselineExpected)
        check("списки: статусы принимаем любые HTTP-ответы (403 — тоже «достучались»)",
            checks.first().expectStatus.last >= 400)

        // --- категории: обе стороны должны присутствовать и URL'ы должны быть пути из репозитория
        check("списки: есть BLOCK и DIRECT категории",
            AllowLists.bySide(ListSide.BLOCK).isNotEmpty() && AllowLists.bySide(ListSide.DIRECT).size >= 3)
        check("списки: путь собирется из RAW + относительного пути",
            AllowLists.url("Categories/01-youtube.lst") == "https://raw.githubusercontent.com/haritos90/allow-domains/main/Categories/01-youtube.lst")
        check("списки: telegram указан с подсетями (без них он не работает)",
            AllowLists.byId.getValue("telegram").hasSubnets)
        val fresh = AllowLists.freshnessOf(System.currentTimeMillis() - 3L * 3_600_000L)
        check("списки: свежесть по-человечески", fresh.contains("3 ч"), fresh)
    }

    private fun confTargets() {
        val acc = dev.warpscout.core.model.WarpAccount(
            privateB64 = "yHpLW0aFVZ0aGnJQpMhCqQYbKxwJmZ2eSbUvEjNnQ0=",
            peerPublicB64 = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
            ipv4 = "172.16.0.2", ipv6 = "2606:4700:110:8d5e:0:0:0:2", source = "test"
        )
        val cfg = WarpConfig(
            name = "test", account = acc, endpoint = Endpoint("188.114.96.3", 4500),
            junk = JunkLibrary.tlsFixed(),
            allowedIps = "0.0.0.0/0, ::/0", dns = listOf("1.1.1.1"), mtu = 1280, persistentKeepalive = 25
        )
        val amnezia = WgConf.render(cfg, ConfTarget.AMNEZIA)
        val stock = WgConf.render(cfg, ConfTarget.WIREGUARD)
        check("конфиг: AmneziaWG содержит AWG-ключи", amnezia.contains("Jc") || amnezia.contains("I1"), amnezia.take(80))
        check("конфиг: голый WG не содержит AWG-ключей",
            stock.lines().none { it.startsWith("Jc") || it.startsWith("Jmin") || it.startsWith("I1") || it.startsWith("H1") })
        check("конфиг: голый WG объясняет, что вырезано", stock.contains("стоковый"), stock.take(200))
        check("конфиг: общие обязательные поля на месте в обоих",
            listOf("PrivateKey", "Address", "PublicKey", "AllowedIPs", "Endpoint").all {
                amnezia.contains(it) && stock.contains(it)
            })
        val clash = WgConf.render(cfg, ConfTarget.CLASH)
        check("конфиг: Clash YAML — yaml, а не conf",
            clash.startsWith("proxies:") && clash.contains("amnezia-wg-option") && !clash.contains("[Interface]"))
        val routes = WgConf.render(cfg, ConfTarget.ROUTES)
        check("конфиг: режим «только маршруты» не содержит ключей",
            !routes.contains("PrivateKey") && routes.contains("AllowedIPs =") && routes.contains("0.0.0.0/0"))
        expect("конфиг: расширение по цели", ConfigExport.filename(cfg, ConfTarget.CLASH).substringAfterLast('.'), "yaml")
        expect("конфиг: расширение AmneziaWG", ConfigExport.filename(cfg, ConfTarget.AMNEZIA).substringAfterLast('.'), "conf")
        check("конфиг: имя файла различает цели",
            ConfigExport.filename(cfg, ConfTarget.AMNEZIA) != ConfigExport.filename(cfg, ConfTarget.WIREGUARD))
    }
}


/**
 * Мини-сервер WireGuard «на другой стороне» — ровно обратные операции из спецификации.
 * Нужен только чтобы проверить нашего же клиента; в проде не используется.
 */
object WgResponder {

    fun respond(initiation: ByteArray, serverPrivate: ByteArray, receiverIndex: Int? = null): ByteArray =
        respondWithSession(initiation, serverPrivate, receiverIndex).first

    /** Ответ + ключи сессии сервера (receiving = out1, sending = out2 — зеркально инициатору). */
    fun respondWithSession(
        initiation: ByteArray,
        serverPrivate: ByteArray,
        receiverIndex: Int? = null
    ): Pair<ByteArray, dev.warpscout.core.wg.Wg.Session> {
        val serverPublic = Crypto.publicOf(serverPrivate)
        var ck = Blake2s.hash("Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s".toByteArray())
        var h = Blake2s.hash(ck + "WireGuard v1 zx2c4 Jason@zx2c4.com".toByteArray())
        h = Blake2s.hash(h + serverPublic)

        val clientEph = initiation.copyOfRange(8, 40)
        h = Blake2s.hash(h + clientEph)

        var temp = Blake2s.hmac(ck, clientEph)
        ck = Blake2s.hmac(temp, byteArrayOf(0x01))
        temp = Blake2s.hmac(ck, Crypto.dh(serverPrivate, clientEph))
        ck = Blake2s.hmac(temp, byteArrayOf(0x01))
        var key = Blake2s.hmac(temp, ck + byteArrayOf(0x02))

        val encStatic = initiation.copyOfRange(40, 88)
        val clientStatic = Crypto.chacha20Poly1305Open(key, ByteArray(12), encStatic, h)
            ?: error("не расшифровался статический ключ клиента")
        h = Blake2s.hash(h + encStatic)

        temp = Blake2s.hmac(ck, Crypto.dh(serverPrivate, clientStatic))
        ck = Blake2s.hmac(temp, byteArrayOf(0x01))
        key = Blake2s.hmac(temp, ck + byteArrayOf(0x02))
        val encTs = initiation.copyOfRange(88, 116)
        val ts = Crypto.chacha20Poly1305Open(key, ByteArray(12), encTs, h) ?: error("не расшифровался timestamp")
        h = Blake2s.hash(h + encTs)
        require(ts.size == 12)

        // ---- собираем response: e, ee, se, psk
        val respEphPriv = ByteArray(32) { (it * 7 + 5).toByte() }.also { it[31] = 0 }
        val respEphPub = Crypto.publicOf(respEphPriv)
        val out = ByteArray(Wg.RESPONSE_LEN)
        Crypto.le32(Wg.TYPE_RESPONSE).copyInto(out, 0)
        val senderIndex = 0x5a5a5a5a
        Crypto.le32(senderIndex).copyInto(out, 4)
        Crypto.le32(receiverIndex ?: Crypto.readLe32(initiation, 4)).copyInto(out, 8)
        respEphPub.copyInto(out, 12)

        h = Blake2s.hash(h + respEphPub)
        temp = Blake2s.hmac(ck, respEphPub)
        ck = Blake2s.hmac(temp, byteArrayOf(0x01))
        temp = Blake2s.hmac(ck, Crypto.dh(respEphPriv, clientEph))
        ck = Blake2s.hmac(temp, byteArrayOf(0x01))
        temp = Blake2s.hmac(ck, Crypto.dh(respEphPriv, clientStatic))
        ck = Blake2s.hmac(temp, byteArrayOf(0x01))
        temp = Blake2s.hmac(ck, ByteArray(32))
        ck = Blake2s.hmac(temp, byteArrayOf(0x01))
        val temp2 = Blake2s.hmac(temp, ck + byteArrayOf(0x02))
        val k = Blake2s.hmac(temp, temp2 + byteArrayOf(0x03))
        h = Blake2s.hash(h + temp2)
        val encNothing = Crypto.chacha20Poly1305Seal(k, ByteArray(12), ByteArray(0), h)
        encNothing.copyInto(out, 44)
        h = Blake2s.hash(h + encNothing)

        val mac1Key = Blake2s.hash("mac1----".toByteArray() + clientStatic)
        Blake2s.mac(mac1Key, out.copyOfRange(0, 60)).copyInto(out, 60)
        // derive_keys(ck): out1 = HMAC(HMAC(ck, ""), 0x01), out2 = HMAC(temp, out1 || 0x02).
        // Инициатору — (sending=out1, receiving=out2), responder'у зеркально.
        val srvTemp = Blake2s.hmac(ck, ByteArray(0))
        val srvRecv = Blake2s.hmac(srvTemp, byteArrayOf(0x01))
        val srvSend = Blake2s.hmac(srvTemp, srvRecv + byteArrayOf(0x02))
        val serverSession = dev.warpscout.core.wg.Wg.Session(receiveKey = srvRecv, sendKey = srvSend)
        return out to serverSession
    }

    /**
     * Cookie reply (64 байта) как его шлёт ядро: type=3, receiver_index, nonce(24),
     * encrypted_cookie = XChaCha20Poly1305(BLAKE2s("cookie--" || pub_сервера), nonce, cookie, AAD = mac1 инициации).
     */
    fun cookieReply(initiation: ByteArray, serverPrivate: ByteArray, cookie: ByteArray = ByteArray(16) { (it + 1).toByte() }): ByteArray {
        val out = ByteArray(dev.warpscout.core.wg.Wg.COOKIE_MSG_LEN)
        Crypto.le32(3).copyInto(out, 0)
        Crypto.readLe32(initiation, 4).let { Crypto.le32(it).copyInto(out, 4) }
        val nonce = ByteArray(24).also { java.security.SecureRandom().nextBytes(it) }
        nonce.copyInto(out, 8)
        val key = Blake2s.hash("cookie--".toByteArray() + Crypto.publicOf(serverPrivate))
        Crypto.xChaCha20Poly1305Seal(key, nonce, cookie, initiation.copyOfRange(116, 132))
            .copyInto(out, 32)
        return out
    }

    /** Проверка mac2 (cookie) в инициации — ровно как wg_cookie_check в ядре. */
    fun mac2Valid(initiation: ByteArray, cookie: ByteArray): Boolean {
        val expected = Blake2s.mac(cookie, initiation.copyOfRange(0, 132))
        return expected.contentEquals(initiation.copyOfRange(132, 148))
    }
}

/** Поток-очередь: чтобы тестировать туннель без настоящего tun-устройства. */
private class QueueInputStream : java.io.InputStream() {
    private val q = java.util.concurrent.LinkedBlockingQueue<ByteArray>()

    @Volatile
    private var closed = false

    private var current: ByteArray? = null
    private var position = 0

    fun offer(b: ByteArray) {
        q.put(b)
    }

    override fun read(): Int {
        val b = ByteArray(1)
        val n = read(b, 0, 1)
        return if (n <= 0) -1 else b[0].toInt() and 0xff
    }

    override fun read(b: ByteArray, off: Int, len: Int): Int {
        var cur = current
        if (cur == null) {
            cur = q.poll(2, java.util.concurrent.TimeUnit.SECONDS) ?: return if (closed) -1 else 0
            current = cur
            position = 0
        }
        val n = minOf(len, cur.size - position)
        System.arraycopy(cur, position, b, off, n)
        position += n
        if (position >= cur.size) current = null
        return n
    }

    override fun close() {
        closed = true
    }
}

/** Второй конец — собирает то, что туннель пишет в tun. */
private class QueueOutputStream : java.io.OutputStream() {
    private val q = java.util.concurrent.LinkedBlockingQueue<ByteArray>()

    @Volatile
    private var closed = false

    fun poll(timeoutMs: Long): ByteArray? = q.poll(timeoutMs, java.util.concurrent.TimeUnit.MILLISECONDS)

    override fun write(b: ByteArray, off: Int, len: Int) {
        if (closed) throw java.io.IOException("поток закрыт")
        q.put(b.copyOfRange(off, off + len))
    }

    override fun write(b: Int) = write(byteArrayOf(b.toByte()), 0, 1)

    override fun flush() {}

    override fun close() {
        closed = true
    }
}


/**
 * Фейковый HTTP-источник для офлайн-проверок: на любой запрос отдаёт 200 с телом `ok`.
 * Нужен, чтобы проверить SOCKS5-путь без выхода в сеть.
 */
private class FakeHttpOrigin {
    private val srv = java.net.ServerSocket(0, 32, java.net.InetAddress.getByName("127.0.0.1"))
    val port: Int get() = srv.localPort
    @Volatile private var stopped = false

    init {
        daemon {
            while (!stopped) {
                val c = runCatching { srv.accept() }.getOrNull() ?: break
                daemon {
                    runCatching {
                        c.getInputStream().drainUntilHeaders()
                        val body = "ok"
                        val resp = "HTTP/1.1 200 OK\r\nContent-Length: ${body.length}\r\n" +
                            "Connection: close\r\n\r\n$body"
                        c.getOutputStream().apply {
                            write(resp.toByteArray(Charsets.UTF_8))
                            flush()
                        }
                    }
                    runCatching { c.close() }
                }
            }
        }
    }

    fun close() {
        stopped = true
        runCatching { srv.close() }
    }
}

/**
 * Фейковый SOCKS5: проверяет наш клиент по RFC 1928 и релееит трафик.
 * Домен `blocked.invalid` подменяет на [originPort] — так воспроизводится «напрямую лежит, через
 * обход DPI открывается», не трогая настоящую сеть.
 */
private class FakeSocks5Relay(private val originPort: Int) {
    private val srv = java.net.ServerSocket(0, 32, java.net.InetAddress.getByName("127.0.0.1"))
    val port: Int get() = srv.localPort
    @Volatile var lastAtyp: Int? = null
    @Volatile var lastPort: Int? = null
    @Volatile private var stopped = false

    init {
        daemon {
            while (!stopped) {
                val c = runCatching { srv.accept() }.getOrNull() ?: break
                daemon { serve(c) }
            }
        }
    }

    private fun serve(c: java.net.Socket) {
        runCatching {
            val input = c.getInputStream()
            val out = c.getOutputStream()
            val ver = input.read()
            val nmethods = input.read()
            repeat(nmethods.coerceAtLeast(0)) { input.read() }
            if (ver != 5) {
                c.close()
                return
            }
            out.write(byteArrayOf(5, 0))
            out.flush()

            require(input.read() == 5)
            val cmd = input.read()
            input.read()  // RSV
            val atyp = input.read()
            lastAtyp = atyp
            val host = when (atyp) {
                1 -> ByteArray(4).also { readInto(input, it) }.joinToString(".") { (it.toInt() and 0xFF).toString() }
                3 -> ByteArray(input.read()).also { readInto(input, it) }.toString(Charsets.UTF_8)
                4 -> {
                    val raw = ByteArray(16).also { readInto(input, it) }
                    raw.joinToString(":") { (it.toInt() and 0xFF).toString(16) }
                }
                else -> {
                    c.close()
                    return
                }
            }
            val portValue = ((input.read() and 0xFF) shl 8) or (input.read() and 0xFF)
            lastPort = portValue

            val denied = cmd != 1
            val mappedHost = if (host == "blocked.invalid") "127.0.0.1" else host
            val mappedPort = if (host == "blocked.invalid") originPort else portValue
            val upstream = if (denied) null else runCatching { java.net.Socket(mappedHost, mappedPort) }.getOrNull()
            if (upstream == null) {
                // 0x04 «host unreachable»: прокси жив, цели нет — клиент должен отличать это от «прокси умер»
                out.write(byteArrayOf(5, 4, 0, 1, 0, 0, 0, 0, 0, 0))
                out.flush()
                runCatching { c.close() }
                return
            }
            val bound = upstream.localPort
            out.write(byteArrayOf(5, 0, 0, 1, 127, 0, 0, 1, (bound shr 8).toByte(), (bound and 0xFF).toByte()))
            out.flush()
            val fromUpstream = upstream.getInputStream()
            val fromClient = c.getInputStream()
            val toClient = c.getOutputStream()
            val toUpstream = upstream.getOutputStream()
            // Направление важно: если перепутать, «прокси» вернёт клиенту его собственный запрос.
            val t1 = daemon { runCatching { fromUpstream.copyTo(toClient) } }
            val t2 = daemon { runCatching { fromClient.copyTo(toUpstream) } }
            t1.join(4000); t2.join(4000)
            runCatching { upstream.close() }
        }
        runCatching { c.close() }
    }

    fun close() {
        stopped = true
        runCatching { srv.close() }
    }
}

/** Прокси «как у взрослых с аутентификацией»: мы должны честно сказать, что сами такое не умеем. */
private class FakeSocks5NeedsAuth {
    private val srv = java.net.ServerSocket(0, 8, java.net.InetAddress.getByName("127.0.0.1"))
    val port: Int get() = srv.localPort
    @Volatile private var stopped = false

    init {
        daemon {
            while (!stopped) {
                val c = runCatching { srv.accept() }.getOrNull() ?: break
                daemon {
                    runCatching {
                        // читаем вручную: readNBytes появился в Android только с API 32, а нам нужен 26+
                        val input = c.getInputStream()
                        input.read(); input.read(); input.read()
                        c.getOutputStream().write(byteArrayOf(5, 0xFF.toByte()))
                        c.getOutputStream().flush()
                        Thread.sleep(50)
                    }
                    runCatching { c.close() }
                }
            }
        }
    }

    fun close() {
        stopped = true
        runCatching { srv.close() }
    }
}

/** readFully есть у DataInputStream, а у InputStream его нет — и на Android его не дождёшься. */
private fun readInto(input: java.io.InputStream, buf: ByteArray) {
    var got = 0
    while (got < buf.size) {
        val n = input.read(buf, got, buf.size - got)
        if (n < 0) {
            if (got == 0) throw java.io.EOFException("прокси закрыл поток до конца адреса")
            throw java.io.EOFException("прокси оборвался на " + got + "/" + buf.size + " байтах")
        }
        got += n
    }
}

private fun daemon(block: () -> Unit): Thread = Thread { block() }.apply { isDaemon = true; start() }

private fun java.io.InputStream.drainUntilHeaders(limit: Int = 16 * 1024) {
    var read = 0
    var tail = ""
    while (read < limit) {
        val b = this.read()
        if (b < 0) return
        read++
        tail = (tail + b.toChar()).takeLast(4)
        if (tail.endsWith("\r\n\r\n")) return
    }
}
