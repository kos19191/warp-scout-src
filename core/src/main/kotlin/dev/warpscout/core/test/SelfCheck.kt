package dev.warpscout.core.test

import dev.warpscout.core.config.ConfTarget
import dev.warpscout.core.config.SplitRoutes
import dev.warpscout.core.config.WgConf
import dev.warpscout.core.lists.AllowList
import dev.warpscout.core.lists.AllowListPlanner
import dev.warpscout.core.lists.AllowLists
import dev.warpscout.core.lists.ListSide
import dev.warpscout.core.report.ConfigExport
import dev.warpscout.core.tunnel.ExitRouter
import dev.warpscout.core.tunnel.Keepalive
import dev.warpscout.core.tunnel.StallDetector
import dev.warpscout.core.tune.CachedPoint
import dev.warpscout.core.tunnel.IpPacket
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
import dev.warpscout.core.state.ServiceSettings
import dev.warpscout.core.state.TunnelStatus
import dev.warpscout.core.model.Candidate
import dev.warpscout.core.tune.Scoring
import dev.warpscout.core.tune.Shortlist
import dev.warpscout.core.tune.Weights
import dev.warpscout.core.wg.Wg
import dev.warpscout.core.tune.NoiseBook
import dev.warpscout.core.tunnel.DataGate
import dev.warpscout.core.presets.Presets
import dev.warpscout.core.model.ResourceResult

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
            wgTimestamps()
            wgHandshakeLoopback()
            dataPlaneLoopback()
            dataPlaneRekey()
            dataPlaneRetryAfterLoss()
        }
        section("junk-профили") {
            quicMaskRoundTrip()
            templateRendering()
        }
        section("конфиги") {
            confRoundTrip()
            sampleFiles()
        }
        section("живость сессии по трафику") {
            stallDetection()
            deadPortFailsFast()
        }
        section("проверка связи и выбор точки") {
            linkCheckState()
        }
        section("быстрый старт подбора") {
            cachedPoint()
        }
        section("топ-3 конфига для переключения") {
            shortlistPick()
        }
        section("скорость через туннель, DNS и две тройки (1.10.28)") {
            speedAndDns()
        }
        section("данные после рукопожатия и очередь (1.10.29)") {
            dataProbeChecks()
        }
        section("заморозка данных и маскировка (1.10.30)") {
            sustainChecks()
            dataGateChecks()
            noiseBookChecks()
        }

        section("доступность сервисов (1.10.30)") {
            availabilityChecks()
        }
        section("расход батареи: интервал keepalive") {
            keepalivePolicy()
        }
        section("состояние сервиса между процессами") {
            serviceState()
        }
        section("пул endpoint'ов") {
            endpointPool()
        }
        section("отмена подбора") {
            scanCancel()
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

        // Повторное шифрование тем же nonce не должно бросать: экземпляр AEAD при шифровании
        // создаётся заново. На общем экземпляре BouncyCastle запрещает повтор nonce, а после
        // пересогласования счётчик начинается с нуля — это был бы случайный обрыв туннеля.
        val ctAgain = runCatching { Crypto.chacha20Poly1305Seal(key, nonce, pt, aad) }
        check(
            "chachapoly: шифрование с тем же nonce не падает",
            ctAgain.isSuccess && ctAgain.getOrNull()!!.contentEquals(ct),
            ctAgain.exceptionOrNull()?.message ?: "разные результаты"
        )

        // Шифрование «первые N байт буфера» — путь отправки из tun без копии пакета. Результат
        // обязан совпадать с шифрованием точной копии, иначе на проводе окажется мусор.
        val full = ByteArray(64) { (it * 7).toByte() }
        val partOfBuffer = Crypto.chacha20Poly1305Seal(key, nonce, full, Crypto.EMPTY_AAD, 40)
        val partCopied = Crypto.chacha20Poly1305Seal(key, nonce, full.copyOf(40), Crypto.EMPTY_AAD)
        check("chachapoly: часть буфера шифруется как копия части", partOfBuffer.contentEquals(partCopied))
        check("chachapoly: часть даёт длину N+16", partOfBuffer.size == 56, "${partOfBuffer.size}")
        val openedPart = Crypto.chacha20Poly1305Open(key, nonce, partOfBuffer, Crypto.EMPTY_AAD)
        check(
            "chachapoly: часть расшифровывается обратно",
            openedPart != null && openedPart.contentEquals(full.copyOf(40)),
            "раскрылось ${openedPart?.size} байт"
        )

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

    /**
     * Метка времени в инициации — ровно TAI64N из WireGuard. Сервер (ядро Linux, wireguard-go,
     * amneziawg-go) принимает инициацию, только если её метка больше прошлой принятой от этого
     * ключа, и сравнивает байты по порядку. До 1.10.26 метка шла младшим байтом вперёд: WARP её
     * не проверяет, а свой сервер второго выхода отвергал rekey как повтор.
     */
    private fun wgTimestamps() {
        expect("метка времени: эпоха Unix в TAI64N", Crypto.hex(Wg.tai64n(0)), "400000000000000a00000000")
        expect(
            "метка времени: секунды и наносекунды старшим байтом вперёд",
            Crypto.hex(Wg.tai64n(1_500)),
            "400000000000000b1dcd6500"
        )
        // Шаг 37 с прокручивает младший байт секунд десятки раз — на нём и ломалась прежняя метка.
        var earlier = Wg.tai64n(1_763_771_571_000)
        var notNewer = 0
        for (step in 1..2000) {
            val later = Wg.tai64n(1_763_771_571_000 + step * 37_000L)
            if (stampCompare(later, earlier) <= 0) notNewer++
            earlier = later
        }
        expect("метка времени: каждая следующая больше прежней по байтам (как сравнивает сервер)", notNewer, 0)
        var previousFresh = Wg.freshTai64n()
        var freshNotNewer = 0
        repeat(5000) {
            val fresh = Wg.freshTai64n()
            if (stampCompare(fresh, previousFresh) <= 0) freshNotNewer++
            previousFresh = fresh
        }
        expect("метка времени: инициации подряд (в одну миллисекунду) строго растут", freshNotNewer, 0)
    }

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

        // 1.10.29: предел пула не должен обрезать его на первой подсети (журнал 22.11 16:32: все 120
        // точек из 162.159.192.x, «живых 0», а 188.114.97.1:500 при этом отвечала).
        val spread = EndpointPool.build(EndpointSpec(maxEndpoints = 120, seed = 5))
        val subnetsSeen = spread.map { it.host.substringBeforeLast('.') + "." }.distinct()
        check(
            "пул: 120 точек покрывают все подсети, а не одну-две",
            subnetsSeen.size == dev.warpscout.core.net.WarpDefaults.AWG_SUBNETS.size,
            subnetsSeen.joinToString()
        )
        check(
            "пул: в каждой подсети есть порт 500",
            dev.warpscout.core.net.WarpDefaults.AWG_SUBNETS.all { pre -> spread.any { it.host.startsWith(pre) && it.port == 500 } }
        )
        check("пул: 120 точек — ровно 120", spread.size == 120, "размер ${spread.size}")
    }

    /**
     * 1.10.29: проверка данных после рукопожатия. Точка, которая отвечает на рукопожатие, но не
     * пропускает данные («вверх 5542, вниз 0» в журнале 22.11), не должна считаться рабочей — ни
     * в подборе, ни в очереди, ни при подключении.
     */
    private fun dataProbeChecks() {
        val probe = dev.warpscout.core.tunnel.DataProbe
        val src = probe.ipv4Of("172.16.0.2/32")
        check("проба данных: адрес туннеля разбирается", src?.toList() == listOf<Byte>(172.toByte(), 16, 0, 2))
        check("проба данных: IPv6 — не адрес для пробы", probe.ipv4Of("2606:4700::1") == null)
        val query = probe.dnsQuery(src ?: ByteArray(4), 40001, 0x1234)
        expect("проба данных: запрос — 60 байт", query.size, 60)
        expect("проба данных: сумма IP-заголовка сходится", probe.checksum(query, 0, 20, 0L), 0)
        fun w(b: ByteArray, o: Int) = (((b[o].toInt() and 0xff) shl 8) or (b[o + 1].toInt() and 0xff)).toLong()
        val udpLen = query.size - 20
        val pseudo = w(query, 12) + w(query, 14) + w(query, 16) + w(query, 18) + 17L + udpLen.toLong()
        expect("проба данных: сумма UDP сходится", probe.checksum(query, 20, udpLen, pseudo), 0)
        val reply = fakeDnsReply(query)
        check("проба данных: ответ узнаётся", reply != null && probe.isReply(reply, 40001, 0x1234))
        check("проба данных: чужой номер запроса — не наш ответ", reply != null && !probe.isReply(reply, 40001, 0x1235))
        check("проба данных: чужой порт — не наш ответ", reply != null && !probe.isReply(reply, 40002, 0x1234))
        check("проба данных: сам запрос ответом не считается", !probe.isReply(query, 40001, 0x1234))

        val clientPriv = ByteArray(32) { (it * 7 + 3).toByte() }
        val serverPriv = ByteArray(32) { (it * 11 + 5).toByte() }
        val serverPub = Crypto.publicOf(serverPriv)
        val account = WarpAccount(Crypto.base64(clientPriv), Crypto.base64(serverPub))
        val prober = WgProber(NetSettings(attempts = 2, timeoutMs = 800, betweenAttemptsMs = 0))

        // Сервер, который отвечает на DNS внутри сессии: точка рабочая.
        val dnsServer = LoopbackServer(serverPriv, answerData = { fakeDnsReply(it) }).start()
        try {
            val ok = prober.probe(Endpoint("127.0.0.1", dnsServer.port), account, serverPub, null, dataProbe = true)
            check(
                "проба данных: рукопожатие и ответ через сессию",
                ok.stats.replies > 0 && ok.stats.dataReplies > 0 && !ok.stats.dataBlocked,
                ok.stats.samples.joinToString { it.note }
            )
            check("проба данных: время ответа записано", ok.stats.dataMs != null)
            val plain = prober.probe(Endpoint("127.0.0.1", dnsServer.port), account, serverPub, null)
            check("проба данных: без флага — только рукопожатие, как раньше", plain.stats.dataTried == 0 && plain.stats.replies > 0)

            val h = startPlane(clientPriv, serverPub, dnsServer.port, NetSettings(attempts = 2, timeoutMs = 800))
            try {
                check("data plane: поднялся для пробы данных", h.awaitUp(3000), h.log.toString())
                check("data plane: проба данных ушла", h.plane.sendDataProbe())
                val until = System.currentTimeMillis() + 2000
                while (h.plane.probeReplies == 0 && System.currentTimeMillis() < until) Thread.sleep(20)
                check("data plane: ответ на пробу данных пришёл", h.plane.probeReplies > 0)
                check("data plane: ответ пробы не попал в tun", h.tunOut.poll(200L) == null)
                check("data plane: ответ пробы не считается трафиком приложений", h.plane.bytesDown == 0L)
            } finally {
                h.stop()
            }
        } finally {
            dnsServer.stop()
        }

        // Сервер отвечает на рукопожатие, а данные выбрасывает — ровно «вверх есть, вниз 0».
        val blackhole = LoopbackServer(serverPriv, answerData = { null }).start()
        try {
            val dead = prober.probe(Endpoint("127.0.0.1", blackhole.port), account, serverPub, null, dataProbe = true)
            check(
                "проба данных: «рукопожатие есть, данных нет» распознано",
                dead.stats.replies > 0 && dead.stats.dataBlocked,
                dead.stats.samples.joinToString { it.note }
            )
            val cfg = WarpConfig(
                name = "т", account = account, endpoint = Endpoint("127.0.0.1", blackhole.port), junk = JunkLibrary.none()
            )
            val blocked = Candidate(cfg, dead.stats, Scoring.evaluate(dead.stats, true))
            check("очередь: точка без данных в неё не попадает", !blocked.usable && Shortlist.pick(listOf(blocked)).isEmpty())
            val report = dev.warpscout.core.model.TuningReport("т", "т", "п", listOf(blocked), emptyList(), 1)
            check("отчёт: точка без данных не становится лучшей", report.best == null)
            check(
                "быстрый старт: точка без данных не подтверждается",
                !CachedPoint.confirmed(dead.stats.replies, 0, 0, dead.stats.dataTried, dead.stats.dataReplies)
            )
            val h = startPlane(clientPriv, serverPub, blackhole.port, NetSettings(attempts = 2, timeoutMs = 800))
            try {
                check("data plane: поднялся на точке без данных", h.awaitUp(3000), h.log.toString())
                h.plane.sendDataProbe()
                Thread.sleep(600)
                check("data plane: на точке без данных ответа на пробу нет", h.plane.probeReplies == 0)
            } finally {
                h.stop()
            }
        } finally {
            blackhole.stop()
        }

        // Балл: «рукопожатие есть, данных нет» ниже точки, через которую данные идут, при любом прочем.
        val ep = Endpoint("1.2.3.4", 500)
        val withData = EndpointStats(ep, listOf(ProbeSample(ep, Verdict.HANDSHAKE_OK, 300.0, 0, dataTried = true, dataMs = 310.0)), Verdict.HANDSHAKE_OK, 1, 3)
        val noData = EndpointStats(ep, listOf(
            ProbeSample(ep, Verdict.HANDSHAKE_OK, 10.0, 0, dataTried = true),
            ProbeSample(ep, Verdict.HANDSHAKE_OK, 11.0, 1, dataTried = true),
            ProbeSample(ep, Verdict.HANDSHAKE_OK, 12.0, 2)
        ), Verdict.HANDSHAKE_OK, 3, 3)
        check(
            "скоринг: медленная точка с данными выше быстрой без данных",
            Scoring.evaluate(withData, false).total > Scoring.evaluate(noData, true).total,
            "${Scoring.evaluate(withData, false).total} против ${Scoring.evaluate(noData, true).total}"
        )
        check("быстрый старт: данные пришли — подтверждается", CachedPoint.confirmed(1, 0, 0, 1, 1))
        expect(
            "снимок: начало проверки данных переживает JSON",
            TunnelStatus.fromJson(TunnelStatus(dataCheckAt = 1_758_000_000_777L).toJson())?.dataCheckAt,
            1_758_000_000_777L
        )
    }

    /**
     * 1.10.30: «данные пошли и встали» и маскировка. Журнал 22.11: на сети человека чистый WireGuard
     * отвечал на рукопожатие и на первый DNS-запрос, а дальше молчал — подбор выбирал его раз за
     * разом, хотя туннель держался только с шумом (tls-fixed — 12 часов подряд).
     */
    private fun sustainChecks() {
        val clientPriv = ByteArray(32) { (it * 7 + 3).toByte() }
        val serverPriv = ByteArray(32) { (it * 11 + 5).toByte() }
        val serverPub = Crypto.publicOf(serverPriv)
        val account = WarpAccount(Crypto.base64(clientPriv), Crypto.base64(serverPub))
        val prober = WgProber(NetSettings(attempts = 2, timeoutMs = 800, betweenAttemptsMs = 0))

        // Сервер отвечает на все запросы внутри сессии: данные идут и не встают.
        val steady = LoopbackServer(serverPriv, answerData = { fakeDnsReply(it) }).start()
        try {
            val ep = Endpoint("127.0.0.1", steady.port)
            val s1 = prober.probeSustained(ep, account, serverPub, null, 2_400)
            check(
                "долгая проба: данные идут и через полторы секунды",
                s1.dataTried && s1.dataSustained && !s1.dataFrozen && s1.dataMs != null,
                s1.note
            )
            val s2 = prober.probeSustained(ep, account, serverPub, JunkLibrary.tlsFixed(), 2_400)
            check("долгая проба: с шумом tls-fixed тоже", s2.dataSustained && s2.profile == "tls-fixed", s2.note)
            // Время ответа профиля с шумом — от инициации, без паузы после мусорного пакета
            // (Jmin = 40 мс): раньше любой шум проигрывал «none» по пингу на ровном месте.
            val masked = prober.probe(ep, account, serverPub, JunkLibrary.tlsFixed())
            val rtt = masked.stats.minRtt ?: 999.0
            check("пинг профиля с шумом не включает паузу после мусора", rtt < 38.0, "rtt=$rtt мс")
        } finally {
            steady.stop()
        }

        // Сервер отвечает только на первый пакет данных — ровно «пошли и встали».
        val answered = java.util.concurrent.atomic.AtomicInteger(0)
        val freezer = LoopbackServer(serverPriv, answerData = { q ->
            if (answered.incrementAndGet() <= 1) fakeDnsReply(q) else null
        }).start()
        try {
            val ep = Endpoint("127.0.0.1", freezer.port)
            val f = prober.probeSustained(ep, account, serverPub, null, 2_400)
            check(
                "долгая проба: «первый ответ есть, дальше тишина» — заморозка",
                f.dataTried && f.dataFrozen && !f.dataSustained && f.dataMs != null,
                f.note
            )
            val quick = ProbeSample(ep, Verdict.HANDSHAKE_OK, 20.0, 0, dataTried = true, dataMs = 21.0)
            val st = EndpointStats(ep, listOf(quick, f), Verdict.HANDSHAKE_OK, 1, 1)
            check("замёрзшая точка считается точкой без данных", st.dataFrozen && st.dataBlocked)
            val cfg = WarpConfig(name = "т", account = account, endpoint = ep, junk = JunkLibrary.none())
            val cand = Candidate(cfg, st, Scoring.evaluate(st, true, plain = true))
            check("замёрзшая точка в очередь не попадает", !cand.usable && Shortlist.pick(listOf(cand)).isEmpty())
            val okSample = ProbeSample(ep, Verdict.HANDSHAKE_OK, 20.0, 0, dataTried = true, dataMs = 21.0, dataSustained = true)
            val healed = EndpointStats(ep, listOf(quick, f, okSample), Verdict.HANDSHAKE_OK, 1, 1)
            check("долгая проба «идут» перевешивает прошлую заморозку", !healed.dataFrozen && !healed.dataBlocked)
        } finally {
            freezer.stop()
        }

        // Маскировка в баллах: при равных замерах вариант с шумом выше, а проверенный долгой пробой
        // шум выше быстрого «без шума».
        val ep2 = Endpoint("1.2.3.4", 500)
        fun st(ms: Double, sustained: Boolean = false) = EndpointStats(
            ep2,
            listOf(ProbeSample(ep2, Verdict.HANDSHAKE_OK, ms, 0, dataTried = true, dataMs = ms + 5, dataSustained = sustained)),
            Verdict.HANDSHAKE_OK, 3, 3
        )
        val plainScore = Scoring.evaluate(st(40.0), true, plain = true).total
        val maskedScore = Scoring.evaluate(st(40.0), true, plain = false).total
        check("маскировка: с шумом выше, чем без шума, при равных замерах", maskedScore > plainScore, "$maskedScore против $plainScore")
        val fastPlain = Scoring.evaluate(st(20.0), true, plain = true).total
        val slowMasked = Scoring.evaluate(st(150.0, sustained = true), true, plain = false).total
        check("маскировка: шум с долгой пробой выше быстрого «без шума»", slowMasked > fastPlain, "$slowMasked против $fastPlain")

        // Имя шума по самим пакетам: сервис и память сетей узнают профиль из текста конфига, где
        // имени нет (там он «imported»).
        for (p in JunkLibrary.defaultPool()) {
            expect("имя шума по пакетам: ${p.name}", JunkLibrary.nameOf(p.copy(name = "imported")), p.name)
            val cfg = WarpConfig(name = "т", account = account, endpoint = ep2, junk = p)
            val back = WgConf.toWarpConfig("т", WgConf.render(cfg))
            expect("имя шума переживает текст конфига: ${p.name}", back?.let { JunkLibrary.nameOf(it.junk) }, p.name)
            expect("профиль по имени: ${p.name}", JunkLibrary.byName(p.name)?.let { JunkChunk.renderAll(it.i1 + it.i2) }, JunkChunk.renderAll(p.i1 + p.i2))
        }
        expect("порядок шума в сервисе: первым tls-fixed", JunkLibrary.serviceOrder().firstOrNull()?.name, "tls-fixed")
        expect("порядок шума в сервисе: «без шума» последним", JunkLibrary.serviceOrder().lastOrNull()?.name, "none")
        check("неизвестный шум по имени — null", JunkLibrary.byName("нет-такого") == null)
    }

    /**
     * Проверка данных в сервисе (1.10.30): рабочим туннель считается, только если данные идут и
     * через полторы секунды. Моделируем сеть: проба, отправленная в момент t, получает ответ через
     * rtt мс, если сеть её пропускает.
     */
    private fun dataGateChecks() {
        fun runGate(
            replyIf: (Long) -> Boolean,
            rtt: Long = 80L,
            bytesAt: (Long) -> Long = { 0L }
        ): Pair<DataGate.Verdict?, Long> {
            val gate = DataGate()
            val sentAt = ArrayList<Long>()
            var t = 0L
            while (t <= 8_000L) {
                val replies = sentAt.count { s0 -> replyIf(s0) && t >= s0 + rtt }
                when (gate.step(t, replies, bytesAt(t))) {
                    DataGate.Step.SEND_PROBE -> sentAt += t
                    DataGate.Step.DONE -> return gate.verdict to t
                    DataGate.Step.WAIT -> t += 40L
                }
            }
            return gate.verdict to t
        }
        val flowing = runGate({ true })
        expect("проверка данных: данные идут — рабочий", flowing.first, DataGate.Verdict.FLOWING)
        check("проверка данных: рабочий — меньше чем за две секунды", flowing.second < 2_000L, "t=${flowing.second}")
        // Журнал 22.11 19:04:45: ответ на первую пробу пришёл, дальше — тишина.
        val frozen = runGate({ it < 500L })
        expect("проверка данных: «пошли и встали» — заморозка", frozen.first, DataGate.Verdict.FROZEN)
        expect("проверка данных: ни ответа — данных нет", runGate({ false }).first, DataGate.Verdict.NO_DATA)
        val apps = runGate({ false }, bytesAt = { it / 100L * 50L })
        expect("проверка данных: приложения получают байты и после 1,5 с — рабочий", apps.first, DataGate.Verdict.FLOWING)
        check("проверка данных: по байтам приложений — сразу после 1,5 с", apps.second in 1_500L..1_700L, "t=${apps.second}")
        // Журнал 22.11 18:53: «вверх 1091, вниз 60 байт» за полсекунды — и больше ничего.
        val bytesFrozen = runGate({ false }, bytesAt = { if (it >= 300L) 120L else 0L })
        expect("проверка данных: 120 байт в начале и тишина — заморозка", bytesFrozen.first, DataGate.Verdict.FROZEN)
        val slow = runGate({ true }, rtt = 1_200L)
        expect("проверка данных: медленная сеть (1,2 с на ответ) — рабочий", slow.first, DataGate.Verdict.FLOWING)
        check("проверка данных: укладывается в окно", flowing.second <= DataGate.WINDOW_MS && slow.second <= DataGate.WINDOW_MS)
    }

    /**
     * Доступность сервисов (1.10.30): ChatGPT «открылся» только если сайт видит обслуживаемую
     * страну; приложения проверяются подключением к их серверам; свои сайты разбираются из текста.
     */
    private fun availabilityChecks() {
        val chatgpt = Presets.SERVICE_CHECKS.firstOrNull { it.id == "chatgpt" }
        check("доступность: ChatGPT проверяется по стране", chatgpt != null && "RU" in chatgpt.blockedCountries)
        if (chatgpt != null) {
            val ru = dev.warpscout.core.net.ResourceProber.judge(chatgpt, 200, "fl=1f1\nip=1.2.3.4\nloc=RU\ncolo=ARN\n")
            check("доступность: ChatGPT видит RU — не открылся", !ru.ok && ru.errorClass == "region:RU", "${ru.errorClass}")
            val nl = dev.warpscout.core.net.ResourceProber.judge(chatgpt, 200, "ip=1.2.3.4\nloc=NL\ncolo=AMS\n")
            check("доступность: ChatGPT видит NL — открылся", nl.ok && nl.detail == "NL", nl.detail)
            val nlText = dev.warpscout.core.net.ResourceProber.describe(
                ResourceResult(chatgpt, ok = true, elapsedMs = 120, detail = nl.detail)
            )
            check("доступность: страна в строке словами", nlText.contains("страну NL"), nlText)
            val blocked = ResourceResult(chatgpt, ok = false, errorClass = "region:RU")
            check(
                "доступность: отказ по стране объяснён словами",
                dev.warpscout.core.net.ResourceProber.describe(blocked).contains("RU")
            )
            val noLoc = dev.warpscout.core.net.ResourceProber.judge(chatgpt, 200, "<html>заглушка</html>")
            check("доступность: ответ без страны — не «открылся»", !noLoc.ok)
            check("доступность: код 403 — не «открылся»", !dev.warpscout.core.net.ResourceProber.judge(chatgpt, 403, "loc=NL").ok)
        }
        val ids = Presets.SERVICE_CHECKS.map { it.id }
        expect("доступность: восемь сервисов", ids.size, 8)
        check("доступность: коды сервисов не повторяются", ids.toSet().size == ids.size && ids.none { it.isBlank() })
        val discord = Presets.SERVICE_CHECKS.first { it.id == "discord" }
        check(
            "доступность: чужой ответ вместо API — не «открылся»",
            !dev.warpscout.core.net.ResourceProber.judge(discord, 200, "<html>stub</html>").ok
        )

        val custom = Presets.customChecks("example.com\nhttps://a.example.org/путь # мой\nне сайт\n\nexample.com, локалхост")
        expect("свои сайты: разобраны два", custom.size, 2)
        expect("свои сайты: имя без адреса — https", custom.firstOrNull()?.url, "https://example.com/")
        expect("свои сайты: адрес как есть", custom.getOrNull(1)?.url, "https://a.example.org/путь")
        val idn = Presets.customChecks("сайт.рф\nhttps://Example.com:8443/a?b=1")
        expect("свои сайты: русское имя — в виде xn--", idn.firstOrNull()?.url, "https://xn--80aswg.xn--p1ai/")
        expect("свои сайты: русское имя в списке как написали", idn.firstOrNull()?.name, "сайт.рф")
        expect("свои сайты: порт и запрос сохранены", idn.getOrNull(1)?.url, "https://example.com:8443/a?b=1")
        val many = Presets.customChecks((1..40).joinToString("\n") { "s$it.example.com" })
        expect("свои сайты: не больше ${Presets.CUSTOM_CHECKS_MAX}", many.size, Presets.CUSTOM_CHECKS_MAX)

        // Подключение к серверам приложения (Telegram): открытый порт — да, закрытый — нет.
        val server = java.net.ServerSocket(0, 4, java.net.InetAddress.getByName("127.0.0.1"))
        try {
            val port = server.localPort
            val prober = dev.warpscout.core.net.ResourceProber()
            val open = prober.check(ResourceCheck("t", "tcp://127.0.0.1:$port", timeoutMs = 2_000))
            check("доступность: серверы отвечают — «открылся»", open.ok, "${open.errorClass}")
            val closedPort = java.net.ServerSocket(0).use { it.localPort }
            val closed = prober.check(ResourceCheck("t", "tcp://127.0.0.1:$closedPort|127.0.0.1:$port", timeoutMs = 2_000))
            check("доступность: годится любой из адресов", closed.ok, "${closed.errorClass}")
            val none = prober.check(ResourceCheck("t", "tcp://127.0.0.1:$closedPort", timeoutMs = 2_000))
            check("доступность: порт закрыт — не «открылся»", !none.ok && none.errorClass != null)
            // Параллельная проверка (подбор и «Проверить сейчас»): порядок — как в списке, итог —
            // у каждой своей строки, отметка «через туннель» не теряется.
            val batch = listOf(
                ResourceCheck("a", "tcp://127.0.0.1:$port", timeoutMs = 2_000),
                ResourceCheck("b", "tcp://127.0.0.1:$closedPort", timeoutMs = 2_000),
                ResourceCheck("c", "tcp://127.0.0.1:$port", timeoutMs = 2_000)
            )
            val par = prober.checkParallel(batch, "tunnel")
            expect("доступность: параллельно — порядок как в списке", par.joinToString("") { it.check.name }, "abc")
            check("доступность: параллельно — итог у каждой строки свой", par.map { it.ok } == listOf(true, false, true))
            check(
                "доступность: параллельно — помечено «через туннель»",
                par.all { it.via == dev.warpscout.core.model.NetworkVia.TUNNEL }
            )
            val cancelled = prober.checkParallel(batch, "tunnel") { true }
            check("доступность: отмена — пустой итог, без ожидания", cancelled.isEmpty())
        } finally {
            runCatching { server.close() }
        }
    }

    /** Книга шума по сетям (1.10.30): когда шум считать замерзающим и на что его менять. */
    private fun noiseBookChecks() {
        val net = "wifi·665"
        val now = 1_763_800_000_000L
        val order = JunkLibrary.serviceOrder().map { it.name }
        fun ev(noise: String, kind: Char, ep: String, ago: Long = 60_000L, n: String = net) =
            NoiseBook.Event(n, noise, kind, ep, now - ago)

        val plainFroze = listOf(ev("none", NoiseBook.FROZE, "8.39.204.10:4500"))
        check("шум: «пошли и встали» без шума — сразу замерзающий", "none" in NoiseBook.frozen(plainFroze, net, now))
        expect("шум: замена «none» — tls-fixed", NoiseBook.replacement(plainFroze, net, "none", order, now), "tls-fixed")
        check("шум: на другой сети ничего не известно", NoiseBook.frozen(plainFroze, "мобильная·25001", now).isEmpty())
        check("шум: через четверо суток запись забыта", NoiseBook.frozen(listOf(ev("none", NoiseBook.FROZE, "a", ago = 4L * 24 * 3600 * 1000)), net, now).isEmpty())

        val maskOnce = listOf(ev("tls-fixed", NoiseBook.FROZE, "a"))
        check("шум: маска встала на одной точке — это может быть точка", "tls-fixed" !in NoiseBook.frozen(maskOnce, net, now))
        check("шум: маска встала на двух точках — замерзающий", "tls-fixed" in NoiseBook.frozen(maskOnce + ev("tls-fixed", NoiseBook.FROZE, "b"), net, now))

        val noDataSame = listOf(ev("none", NoiseBook.NO_DATA, "a"), ev("none", NoiseBook.NO_DATA, "a", ago = 30_000L))
        check("шум: «данных нет» дважды на одной точке — ещё не шум", "none" !in NoiseBook.frozen(noDataSame, net, now))
        check("шум: «данных нет» на двух точках — замерзающий", "none" in NoiseBook.frozen(noDataSame + ev("none", NoiseBook.NO_DATA, "b"), net, now))

        val healed = plainFroze + ev("none", NoiseBook.WORKED, "c", ago = 1_000L)
        check("шум: данные пошли после заморозки — снова годится", "none" !in NoiseBook.frozen(healed, net, now))
        expect("шум: незамерзающий не меняем", NoiseBook.replacement(healed, net, "none", order, now), null)

        val worked = plainFroze + ev("quic:akbars.ru", NoiseBook.WORKED, "d", ago = 2_000L)
        expect("шум: первым — тот, с которым здесь уже шли данные", NoiseBook.replacement(worked, net, "none", order, now), "quic:akbars.ru")
        check("шум: «подбор сказал встают» — сразу", "sip-invite" in NoiseBook.frozen(listOf(ev("sip-invite", NoiseBook.TUNER, "")), net, now))

        val all = order.map { ev(it, NoiseBook.TUNER, "") }
        expect("шум: замерзает всё — не меняем, не на что", NoiseBook.replacement(all, net, "none", order, now), null)

        val text = NoiseBook.render(plainFroze + ev("quic:x|y", NoiseBook.WORKED, "1.2.3.4:500"))
        val back = NoiseBook.parse(text + "битая строка\n|||\n")
        expect("шум: книга переживает файл", back.size, 2)
        expect("шум: «|» в имени не ломает строку", back.lastOrNull()?.noise, "quic:x/y")
        var many = emptyList<NoiseBook.Event>()
        for (i in 0 until NoiseBook.MAX_EVENTS + 20) many = NoiseBook.add(many, ev("none", NoiseBook.NO_DATA, "p$i", ago = 0L))
        expect("шум: в книге не больше ${NoiseBook.MAX_EVENTS} записей", many.size, NoiseBook.MAX_EVENTS)
    }

    /**
     * Быстрый старт принимает сохранённую точку без полного скана. Ошибка здесь тише и хуже, чем
     * кажется: подбор отрапортует «готово», а конфиг не работает. Поэтому подтверждение требует
     * настоящих признаков, а не «кандидат найден».
     */
    private fun cachedPoint() {
        val c = CachedPoint
        check("быстрый старт: без ответа сервера не подтверждается", !c.confirmed(0, 0, 0))
        check("быстрый старт: ответ есть, проверок не было — подтверждается", c.confirmed(1, 0, 0))
        check("быстрый старт: ответ есть, но изнутри ничего не открылось", !c.confirmed(3, 9, 0))
        check("быстрый старт: открылся хотя бы один ресурс", c.confirmed(3, 9, 1))
        check("быстрый старт: все ресурсы открылись", c.confirmed(3, 9, 9))
        check("быстрый старт: отрицательные числа не считаются успехом", !c.confirmed(-1, 9, 9))
    }

    /**
     * Топ-3 для переключения. Проверяем не «функция вернула три элемента», а два свойства, из-за
     * которых список вообще имеет смысл: варианты стоят на разных адресах (иначе сеть режет их
     * вместе) и первым идёт тот, что реально пускал трафик, а не просто отвечал на handshake.
     */
    private fun shortlistPick() {
        fun cand(host: String, port: Int, junk: String, score: Int, replies: Int = 1, ok: Int = -1, total: Int = 0): Candidate {
            val cfg = WarpConfig(
                name = "тест",
                account = WarpAccount("a=", "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=", "172.16.0.2", "2606::1"),
                endpoint = Endpoint(host, port),
                junk = if (junk == "none") JunkLibrary.none() else JunkLibrary.tlsFixed(),
                allowedIps = "0.0.0.0/0, ::/0"
            )
            val st = EndpointStats(cfg.endpoint, emptyList(), Verdict.HANDSHAKE_OK, replies, 1)
            return Candidate(cfg, st, Scoring.evaluate(st, replies > 0, ok.coerceAtLeast(0), total), emptyList(), ok, total)
        }

        val a = cand("162.159.192.1", 2408, "tls-fixed", 900, ok = 9, total = 9)
        val b = cand("162.159.192.1", 2408, "none", 950, ok = 4, total = 9)      // та же точка, другой шум
        val c = cand("188.114.97.1", 500, "tls-fixed", 800, ok = 7, total = 9)
        val d = cand("162.159.195.1", 1701, "tls-fixed", 700, ok = 5, total = 9)
        val dead = cand("188.114.99.1", 2408, "tls-fixed", -500, replies = 0, ok = -1, total = 0)

        val top = Shortlist.pick(listOf(dead, d, b, c, a))
        expect("топ-3: ровно три варианта", top.size, Shortlist.LIMIT)
        expect("топ-3: первым — где открылось больше всего", top.first().config.endpoint.render(), "162.159.192.1:2408")
        expect("топ-3: на первом месте тот же адрес, но с лучшим результатом изнутри", top.first().resourcesOk, 9)
        check("топ-3: сначала разные адреса, а не три профиля на одном",
            top.map { it.config.endpoint.render() }.distinct().size == 3,
            top.joinToString { it.config.endpoint.render() + "/" + it.junk.name })
        check("топ-3: мёртвая точка не предлагается", top.none { it.config.endpoint.port == 2408 && it.stats.replies == 0 })

        // Если точек меньше трёх — добираем профилями шума, но не повторяем один и тот же вариант.
        val two = Shortlist.pick(listOf(a, b), limit = 3)
        expect("топ-3: при двух точках добирается вторым профилем шума", two.size, 2)
        expect("топ-3: варианты не повторяются", two.map { it.config.endpoint.render() + "/" + it.junk.name }.distinct().size, 2)

        // Непроверенное изнутри не должно обгонять проверенное, даже если балл выше.
        val unverified = cand("162.159.198.2", 443, "tls-fixed", 990, replies = 2, ok = -1, total = 0)
        val ordered = Shortlist.pick(listOf(unverified, c), limit = 1)
        expect("топ-3: проверенный изнутри выше более «балльного»", ordered.single().resourcesOk, 7)

        check("топ-3: пустой отчёт не ломает отбор", Shortlist.pick(emptyList()).isEmpty())
    }

    /**
     * 1.10.28: замер скорости (и «заморозка»), DNS в маршрутах туннеля, проверка «умного» DNS,
     * новые поля снимков. Всё без сети: потоки и пакеты — подставные.
     */
    private fun speedAndDns() {
        val st = dev.warpscout.core.net.SpeedTest
        // Поток, который отдаёт [give] байт и потом молчит (таймаут сокета) — «заморозка».
        class FreezingStream(private val give: Int) : java.io.InputStream() {
            private var sent = 0
            override fun read(): Int {
                if (sent >= give) throw java.net.SocketTimeoutException("тишина")
                sent++
                return 0
            }
            override fun read(b: ByteArray, off: Int, len: Int): Int {
                if (sent >= give) throw java.net.SocketTimeoutException("тишина")
                val n = minOf(len, give - sent)
                sent += n
                return n
            }
        }
        val full = st.drain(java.io.ByteArrayInputStream(ByteArray(300_000)), 300_000, 1_000_000, 10_000)
        expect("скорость: тело дочитано — замер прошёл", full.state, st.OK)
        expect("скорость: прочитано всё обещанное", full.bytes, 300_000L)
        check("скорость: посчитана", full.kbps > 0, "${full.kbps}")
        val frozen = st.drain(FreezingStream(20 * 1024), 512 * 1024, 512 * 1024, 10_000)
        expect("скорость: 20 КБ и тишина — это «заморозка»", frozen.state, st.FROZEN)
        expect("скорость: при заморозке видно, сколько успело прийти", frozen.bytes, 20L * 1024)
        val silent = st.drain(FreezingStream(0), 512 * 1024, 512 * 1024, 10_000)
        expect("скорость: ни байта — это провал, а не заморозка", silent.state, st.FAIL)
        val cut = st.drain(java.io.ByteArrayInputStream(ByteArray(10_000)), 100_000, 1_000_000, 10_000)
        expect("скорость: оборванное посреди тело — тоже заморозка", cut.state, st.FROZEN)
        val noLength = st.drain(java.io.ByteArrayInputStream(ByteArray(50_000)), -1, 1_000_000, 10_000)
        expect("скорость: без Content-Length читаем до конца", noLength.state, st.OK)
        expect("скорость: без Content-Length — все байты", noLength.bytes, 50_000L)
        val capped = st.drain(java.io.ByteArrayInputStream(ByteArray(300_000)), 1_000_000, 100_000, 10_000)
        expect("скорость: предел байт соблюдается", capped.bytes, 100_000L)
        expect("скорость: предел байт — не заморозка", capped.state, st.OK)
        expect("скорость: Кбит/с из байт и мс", st.kbpsOf(1_000_000, 1_000), 8_000)
        expect("скорость: слишком короткое окно не даёт «тысячу мегабит»", st.kbpsOf(1_000, 0), 400)
        expect("скорость: нет байт — нет скорости", st.kbpsOf(0, 100), -1)
        expect("скорость: ступень — не мерили", st.bucket(-1), 0)
        expect("скорость: ступень — меньше мегабита", st.bucket(500), 1)
        expect("скорость: ступень — 1–2 Мбит/с", st.bucket(1_500), 2)
        expect("скорость: ступень — 3 Мбит/с выше 2", st.bucket(3_000), 3)
        check("скорость: ступени растут со скоростью", st.bucket(50_000) > st.bucket(10_000))
        expect("скорость: подпись в Кбит/с", st.human(850), "850 Кбит/с")
        expect("скорость: подпись с запятой", st.human(24_500), "24,5 Мбит/с")
        expect("скорость: большие — без дробной части", st.human(150_000), "150 Мбит/с")
        expect("скорость: нет замера — прочерк", st.human(-1), "—")

        // DNS в маршрутах туннеля: только при раздельных маршрутах и только то, что не покрыто.
        expect(
            "DNS в туннеле: весь трафик — маршруты не меняются",
            SplitRoutes.withDns("0.0.0.0/0, ::/0", listOf("1.1.1.1", "2606:4700:4700::1111")),
            "0.0.0.0/0, ::/0"
        )
        expect(
            "DNS в туннеле: раздельные — добавляются /32 и /128",
            SplitRoutes.withDns("10.0.0.0/8, 8.8.8.0/24", listOf("8.8.8.8", "1.1.1.1", "2606:4700:4700::1111")),
            "10.0.0.0/8, 8.8.8.0/24, 1.1.1.1/32, 2606:4700:4700::1111/128"
        )
        expect(
            "DNS в туннеле: адрес внутри подсети не дублируется",
            SplitRoutes.withDns("1.0.0.0/8", listOf("1.1.1.1")),
            "1.0.0.0/8"
        )
        expect("DNS в туннеле: без маршрутов ничего не придумываем", SplitRoutes.withDns("", listOf("1.1.1.1")), "")

        // Проверка «умного» DNS: запрос A-записи и разбор ответа.
        val q = dev.warpscout.core.net.SmartDnsCheck.buildQuery(0x1234, "chatgpt.com")
        expect("DNS-запрос: длина", q.size, 29)
        expect("DNS-запрос: номер", ((q[0].toInt() and 0xFF) shl 8) or (q[1].toInt() and 0xFF), 0x1234)
        val answer = java.io.ByteArrayOutputStream().apply {
            write(byteArrayOf(0x12, 0x34, 0x81.toByte(), 0x80.toByte(), 0, 1, 0, 2, 0, 0, 0, 0))
            write(q, 12, q.size - 12)
            // CNAME на то же имя (указатель на вопрос) — пропускается
            write(byteArrayOf(0xC0.toByte(), 0x0C, 0, 5, 0, 1, 0, 0, 0, 60, 0, 2, 0xC0.toByte(), 0x0C))
            // A 104.18.32.47
            write(byteArrayOf(0xC0.toByte(), 0x0C, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 104, 18, 32, 47))
        }.toByteArray()
        expect(
            "DNS-ответ: адрес из A-записи, CNAME пропущен",
            dev.warpscout.core.net.SmartDnsCheck.parseA(answer, answer.size, 0x1234),
            listOf("104.18.32.47")
        )
        expect(
            "DNS-ответ: чужой номер запроса — пусто",
            dev.warpscout.core.net.SmartDnsCheck.parseA(answer, answer.size, 0x4321),
            emptyList<String>()
        )
        expect(
            "DNS-ответ: обрезанный пакет не роняет разбор",
            dev.warpscout.core.net.SmartDnsCheck.parseA(answer, 40, 0x1234),
            emptyList<String>()
        )
        val nx = answer.copyOf().also { it[3] = 0x83.toByte() }
        expect(
            "DNS-ответ: ошибка сервера — пусто",
            dev.warpscout.core.net.SmartDnsCheck.parseA(nx, nx.size, 0x1234),
            emptyList<String>()
        )
        expect(
            "trace: страна и площадка",
            dev.warpscout.core.net.SmartDnsCheck.traceFields("fl=1\nh=chatgpt.com\nloc=DE\ncolo=FRA\n"),
            "DE" to "FRA"
        )
        check(
            "ChatGPT: выход RU — не откроется",
            !dev.warpscout.core.net.SmartDnsCheck.Result(true, "1.2.3.4", "RU", "DME", "").opens
        )
        check(
            "ChatGPT: выход DE — откроется",
            dev.warpscout.core.net.SmartDnsCheck.Result(true, "1.2.3.4", "DE", "FRA", "").opens
        )

        // Снимок: замер скорости переживает передачу между процессами.
        val speedSnap = TunnelStatus(
            speedAt = 1_758_000_100_000L, speedState = TunnelStatus.SPEED_FROZEN, speedKbps = 1234,
            speedPingMs = 48, speedBytes = 20_480L, speedFull = true, speedRunningSince = 1_758_000_099_000L
        )
        expect("снимок: замер скорости без потерь", TunnelStatus.fromJson(speedSnap.toJson()), speedSnap)
        expect("снимок: старый формат — скорости нет", TunnelStatus.fromJson("{}")?.speedKbps, -1)

        // Настройки сервиса: резервные и тройки по сетям, переключатели функций.
        val perNet = ServiceSettings(
            backup = "162.159.192.1:2408",
            backupMobile = "188.114.97.1:500",
            listWifi = listOf("162.159.192.1:2408", "162.159.195.1:1701"),
            listMobile = listOf("188.114.97.1:500"),
            autoStart = false,
            linkReconnect = false,
            speedAuto = false,
            freezeReconnect = false,
            dnsInTunnel = false,
        )
        expect("настройки сервиса: резервные и тройки по сетям", ServiceSettings.fromJson(perNet.toJson()), perNet)
        val oldSettings = ServiceSettings.fromJson("""{"ver":1,"backup":"1.2.3.4:500"}""")
        expect("настройки сервиса: старый снимок — мобильной резервной нет", oldSettings?.backupMobile, "")
        expect("настройки сервиса: старый снимок — автоподъём включён", oldSettings?.autoStart, true)
        expect("настройки сервиса: старый снимок — DNS через туннель", oldSettings?.dnsInTunnel, true)

        // Подбор: из одинаково открывшихся выше та, через которую быстрее качается.
        fun fast(host: String, kbps: Int): Candidate {
            val cfg = WarpConfig(
                name = "тест",
                account = WarpAccount("a=", "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=", "172.16.0.2", "2606::1"),
                endpoint = Endpoint(host, 2408),
                junk = JunkLibrary.tlsFixed(),
                allowedIps = "0.0.0.0/0, ::/0"
            )
            val es = EndpointStats(cfg.endpoint, emptyList(), Verdict.HANDSHAKE_OK, 1, 1)
            return Candidate(cfg, es, Scoring.evaluate(es, true, 9, 9), emptyList(), 9, 9, kbps)
        }
        val slow = fast("162.159.192.5", 900)
        val quick = fast("162.159.192.6", 40_000)
        expect(
            "топ-3: при равных сайтах первой идёт более быстрая",
            Shortlist.pick(listOf(slow, quick), limit = 1).single().config.endpoint.host,
            "162.159.192.6"
        )
    }

    /**
     * Интервал keepalive — главный наш вклад в расход батареи на мобильной сети. Проверяем ровно
     * то, что важно: активный экран будит радио не реже раза в минуту, лежащий телефон — реже,
     * а сам пользователь может попросить ещё реже, но не чаще нижней границы.
     */
    private fun keepalivePolicy() {
        val k = Keepalive
        val active = k.intervalMs(configuredSeconds = 25, idleMs = 0, screenOn = true)
        check("батарея: на активном экране не чаще раза в минуту", active == Keepalive.ACTIVE_FLOOR_MS, "$active")

        val idle = k.intervalMs(25, idleMs = 300_000, screenOn = false)
        check("батарея: экран погашен и тишина — полторы минуты", idle == Keepalive.IDLE_SCREEN_OFF_FLOOR_MS, "$idle")

        val idleScreenOn = k.intervalMs(25, idleMs = 300_000, screenOn = true)
        check("батарея: экран горит — минута даже в тишине", idleScreenOn == Keepalive.ACTIVE_FLOOR_MS, "$idleScreenOn")

        val justIdle = k.intervalMs(25, idleMs = Keepalive.IDLE_AFTER_MS - 1_000, screenOn = false)
        check("батарея: тишина ещё не наступила — держим минуту", justIdle == Keepalive.ACTIVE_FLOOR_MS, "$justIdle")

        val userWantsRare = k.intervalMs(110, idleMs = 0, screenOn = true)
        check("батарея: просьбу «реже» уважаем", userWantsRare == 110_000L, "$userWantsRare")

        val tooSlow = k.intervalMs(120, idleMs = 300_000, screenOn = false)
        check("батарея: дольше двух минут не растягиваем", tooSlow == Keepalive.MAX_MS, "$tooSlow")

        val off = k.intervalMs(0, idleMs = 0, screenOn = true)
        check("батарея: keepalive выключен — не будим вовсе", off == Long.MAX_VALUE, "$off")

        // Частота за час: было 144 пробуждения (25 с), стало не больше 60/40.
        val perHourActive = 3_600_000L / active
        val perHourIdle = 3_600_000L / idle
        check("батарея: за час активных пробуждений не больше 60", perHourActive <= 60, "$perHourActive")
        check("батарея: за час в тишине не больше 40", perHourIdle <= 40, "$perHourIdle")
        check(
            "батарея: тишина реже активности",
            perHourIdle < perHourActive,
            "$perHourIdle против $perHourActive"
        )
        check(
            "батарея: пересогласование успевает до жёсткого предела протокола",
            NetSettings().rekeyAfterMs < 180_000L,
            "${NetSettings().rekeyAfterMs}"
        )
        check(
            "батарея: запас на повторные попытки не меньше трёх штук",
            (180_000L - NetSettings().rekeyAfterMs) / NetSettings().rekeyRetryMs >= 3,
            "${(180_000L - NetSettings().rekeyAfterMs) / NetSettings().rekeyRetryMs}"
        )
    }

    // ------------------------------------------------- живость сессии по трафику

    /**
     * Правило «сессия мертва» решает, рвать ли рабочий туннель. Слишком чувствительное — рвёт
     * нормальную работу, слишком грубое — оставляет мёртвое соединение на минуты. Поэтому
     * проверяются ровно те сценарии, которые бывают в жизни.
     */
    private fun stallDetection() {
        val d = StallDetector
        val t0 = 1_000_000L

        // Пока трафик стоит, судить не о чем: молчащий туннель без трафика — норма.
        check("живость: без трафика не считается мёртвой", !d.isStalled(t0 + 600_000, t0, 0L, 0))
        check("живость: трафика нет, но счётчик шумит", !d.isStalled(t0 + 600_000, t0, 0L, 500))

        // Единичные пакеты (UDP-датаграммы, DNS) ответа не ждут — порог по количеству обязателен.
        check(
            "живость: 10 пакетов без ответа — ещё не приговор",
            !d.isStalled(t0 + 300_000, t0, t0, 10)
        )
        check(
            "живость: 49 пакетов за 10 минут — под порогом",
            !d.isStalled(t0 + 600_000, t0, t0, StallDetector.MIN_PACKETS - 1)
        )

        // Поток только начался — окно ещё не вышло, даже если ответа не было давно.
        val burst = t0 + 600_000
        check(
            "живость: поток только начался",
            !d.isStalled(burst + 1_000, t0, burst, 80)
        )

        // Ответ был недавно — соединение живое, сколько бы ни ушло пакетов.
        check(
            "живость: недавний ответ снимает подозрения",
            !d.isStalled(t0 + 60_000, t0 + 55_000, t0, 200)
        )

        // Классический случай: 50+ пакетов, 45 секунд тишины.
        check(
            "живость: 50 пакетов и 45 секунд тишины — мертва",
            d.isStalled(t0 + 45_000, t0, t0, StallDetector.MIN_PACKETS)
        )
        check(
            "живость: за секунду до окна — ещё нет",
            !d.isStalled(t0 + 44_000, t0, t0, StallDetector.MIN_PACKETS)
        )
        check(
            "живость: окно считается от последнего ответа, а не от начала",
            !d.isStalled(t0 + 100_000, t0 + 80_000, t0, 500)
        )

        // Ни одного ответа за всю жизнь сессии: отсчёт от начала потока.
        check(
            "живость: ответов не было вовсе",
            d.isStalled(t0 + 50_000, 0L, t0, StallDetector.MIN_PACKETS)
        )

        // Объяснение должно быть понятным человеку и содержать секунды и число пакетов.
        val why = d.explain(t0 + 60_000, t0, t0, 120)
        check("живость: объяснение называет число пакетов", why.contains("120"), why)
        check("живость: объяснение называет время тишины", why.contains("60 с"), why)
    }

    // -------------------------------------------------- состояние между процессами

    /**
     * Снимок состояния — единственный способ узнать что-либо о туннеле из другого процесса,
     * поэтому сериализация проверяется отдельно: битый снимок = «туннель работает, а UI молчит».
     */
    /**
     * «Остановить подбор» должно останавливать: скан с поднятым флагом отмены не шлёт ни одной
     * пробы и возвращается сразу, а не через весь пул (раньше пул досчитывался до конца).
     */
    private fun scanCancel() {
        val priv = ByteArray(32) { (it + 5).toByte() }.also { it[31] = 0 }
        val account = WarpAccount(Crypto.base64(priv), Crypto.base64(Crypto.publicOf(priv)))
        // TEST-NET-1 (192.0.2.0/24) никуда не ведёт: без отмены каждая проба ждала бы до трёх секунд.
        val pool = (1..40).map { Endpoint("192.0.2.$it", 2408) }
        val prober = WgProber(NetSettings(attempts = 3, timeoutMs = 1000, concurrency = 4))
        val t0 = System.currentTimeMillis()
        val res = prober.scan(pool, account, Crypto.publicOf(priv), isCancelled = { true })
        val took = System.currentTimeMillis() - t0
        expect("отмена: скан после «Остановить» не возвращает проб", res.size, 0)
        check("отмена: скан возвращается сразу, а не через весь пул", took < 1500, "заняло $took мс")
    }

    /**
     * «Подключено» должно значить «данные ходят». Здесь — всё, на чём это держится и что можно
     * проверить без Android: мягкий порог подозрения, разбор ответа Cloudflare, перенос итогов
     * проверки, пробы точки и меток дозора через снимок, резервная точка в настройках сервиса.
     */
    private fun linkCheckState() {
        val t0 = 1_700_000_000_000L
        // Мягкий порог: Telegram, потерявший связь, шлёт мало — 50 пакетов за 45 с не набирается.
        check(
            "подозрение: 8 пакетов и 15 с без ответа — пора проверить связь",
            StallDetector.isSuspect(t0 + StallDetector.SUSPECT_MS, 0L, t0, StallDetector.SUSPECT_PACKETS)
        )
        check(
            "подозрение: 7 пакетов — ещё рано",
            !StallDetector.isSuspect(t0 + 60_000, 0L, t0, StallDetector.SUSPECT_PACKETS - 1)
        )
        check(
            "подозрение: ответ был 5 с назад — всё в порядке",
            !StallDetector.isSuspect(t0 + 20_000, t0 + 15_000, t0, 40)
        )
        check(
            "подозрение: за секунду до окна — ещё нет",
            !StallDetector.isSuspect(t0 + StallDetector.SUSPECT_MS - 1_000, 0L, t0, 40)
        )
        check(
            "подозрение раньше приговора: на мягком пороге сессия ещё не «мертва»",
            !StallDetector.isStalled(t0 + StallDetector.SUSPECT_MS, 0L, t0, StallDetector.SUSPECT_PACKETS)
        )

        // Ответ Cloudflare: через WARP / мимо / не trace вовсе.
        val warpOn = dev.warpscout.core.net.CfTrace.parse(
            "fl=12f3\nh=1.1.1.1\nip=2a09:bac1:6181:6888::1d6:18d\nts=1732278600.1\n" +
                "visit_scheme=https\ncolo=FRA\nhttp=http/1.1\nloc=RU\ntls=TLSv1.3\nwarp=on\ngateway=off\n"
        )
        check("trace: разобран", warpOn != null)
        expect("trace: площадка", warpOn?.colo, "FRA")
        expect("trace: адрес выхода", warpOn?.ip, "2a09:bac1:6181:6888::1d6:18d")
        expect("trace: через WARP", warpOn?.viaWarp, true)
        expect("trace: коротко", warpOn?.summary(), "FRA · RU · 2a09:bac1:6181:6888::1d6:18d")
        val warpOff = dev.warpscout.core.net.CfTrace.parse("ip=185.126.130.6\ncolo=HEL\nloc=RU\nwarp=off\n")
        expect("trace: мимо WARP так и называется", warpOff?.viaWarp, false)
        expect("trace: plus — тоже WARP", dev.warpscout.core.net.CfTrace.parse("colo=AMS\nwarp=plus")?.viaWarp, true)
        expect("trace: страница портала — не trace", dev.warpscout.core.net.CfTrace.parse("<html><body>login=1</body></html>"), null)
        expect("trace: пусто — не trace", dev.warpscout.core.net.CfTrace.parse(""), null)

        // Итоги проверки, проба точки и метки дозора переживают снимок между процессами.
        val st = TunnelStatus(
            up = true,
            probe = "17|162.159.192.8:859|${TunnelStatus.PROBE_SILENT}|-1",
            marks = "162.159.192.8:859|0|3|1758000000000;188.114.97.1:500|1758000001000|0|0",
            linkAt = 1_758_000_002_000L,
            linkWeb = TunnelStatus.LINK_OK,
            linkMs = 183,
            linkTg = TunnelStatus.LINK_FAIL,
            linkTgMs = -1,
            linkExit = "FRA · RU · 2a09:bac1::1",
        )
        val back = TunnelStatus.fromJson(st.toJson())
        expect("снимок: проба точки", back?.probe, st.probe)
        expect("снимок: метки дозора", back?.marks, st.marks)
        expect("снимок: время проверки связи", back?.linkAt, 1_758_000_002_000L)
        expect("снимок: интернет через туннель", back?.linkWeb, TunnelStatus.LINK_OK)
        expect("снимок: задержка проверки", back?.linkMs, 183)
        expect("снимок: Telegram через туннель", back?.linkTg, TunnelStatus.LINK_FAIL)
        expect("снимок: выход", back?.linkExit, "FRA · RU · 2a09:bac1::1")
        val old = TunnelStatus.fromJson("{\"up\": true}")
        expect("снимок: старый формат — связь не проверяли", old?.linkWeb, TunnelStatus.LINK_UNKNOWN)
        expect("снимок: старый формат — задержки нет (-1, а не 0 мс)", old?.linkMs, -1)

        // Резервная точка, выбранная человеком, доходит до сервиса.
        expect(
            "настройки сервиса: резервная точка",
            ServiceSettings.fromJson(ServiceSettings(backup = "162.159.192.2:864").toJson())?.backup,
            "162.159.192.2:864"
        )
        expect(
            "настройки сервиса: без резервной точки — пусто",
            ServiceSettings.fromJson("""{"ver":1}""")?.backup,
            ""
        )
    }

    private fun serviceState() {
        val full = TunnelStatus(
            up = true,
            status = "туннель поднят",
            endpoint = "162.159.192.7:2408",
            error = null,
            gaveUp = false,
            busy = true,
            startedAt = 1_758_000_000_123,
            updatedAt = 1_758_000_004_456,
            bytesUp = 12_345_678_901L,
            bytesDown = 98_765_432_109L,
            handshakeAttempts = 3,
            lastError = "endpoint молчит",
            lastStageMs = 1_758_000_004_000,
            touched = true,
        )
        val back = TunnelStatus.fromJson(full.toJson())
        check("снимок: читается обратно", back != null)
        expect("снимок: up", back?.up, true)
        expect("снимок: статус", back?.status, "туннель поднят")
        expect("снимок: endpoint", back?.endpoint, "162.159.192.7:2408")
        expect("снимок: нет ошибки", back?.error, null)
        expect("снимок: busy", back?.busy, true)
        expect("снимок: время старта без потерь", back?.startedAt, 1_758_000_000_123L)
        expect("снимок: время обновления без потерь", back?.updatedAt, 1_758_000_004_456L)
        expect("снимок: счётчик вверх без потерь", back?.bytesUp, 12_345_678_901L)
        expect("снимок: счётчик вниз без потерь", back?.bytesDown, 98_765_432_109L)
        expect("снимок: попытки handshake", back?.handshakeAttempts, 3)
        expect("снимок: последняя ошибка", back?.lastError, "endpoint молчит")
        expect("снимок: время этапа", back?.lastStageMs, 1_758_000_004_000L)
        expect("снимок: журнал трогали", back?.touched, true)

        // «Туннель нужен» и «выключил сам человек»: по ним кнопка и плитка решают, что предлагать,
        // а фоновый подбор — включать ли туннель. Потерять их при сериализации — значит снова
        // «выключил руками, а он включился сам».
        val heldBack = TunnelStatus.fromJson(TunnelStatus(wanted = true, stoppedByUser = true).toJson())
        expect("снимок: туннель нужен", heldBack?.wanted, true)
        expect("снимок: выключен вручную", heldBack?.stoppedByUser, true)
        // По времени ручного выключения перебор точек видит выключение плиткой во время перебора.
        expect(
            "снимок: время ручного выключения без потерь",
            TunnelStatus.fromJson(TunnelStatus(stoppedByUserAt = 1_758_000_009_999L).toJson())?.stoppedByUserAt,
            1_758_000_009_999L
        )
        val beforeFields = TunnelStatus.fromJson("{\"up\": false, \"phase\": 5}")
        expect("снимок: старый формат — туннель не нужен", beforeFields?.wanted, false)
        expect("снимок: старый формат — не выключался вручную", beforeFields?.stoppedByUser, false)

        // Русский текст с кавычками и переводами строк — иначе журнал превратится в кашу.
        val tricky = TunnelStatus(
            status = "строка \"в кавычках\" и \\ слэш\nвторая строка\tтаб",
            error = "ошибка: «ёлка», тире — и юникод ✓",
        )
        val trickyBack = TunnelStatus.fromJson(tricky.toJson())
        expect("снимок: кавычки и переводы строк", trickyBack?.status, tricky.status)
        expect("снимок: юникод в ошибке", trickyBack?.error, tricky.error)

        // Битый и чужой ввод не должен ронять процесс интерфейса.
        expect("снимок: пустая строка → null", TunnelStatus.fromJson(""), null)
        expect("снимок: null → null", TunnelStatus.fromJson(null), null)
        expect("снимок: мусор → null", TunnelStatus.fromJson("не json"), null)
        expect("снимок: обрезанный json → null", TunnelStatus.fromJson("{\"up\": true, \"status\": \"тун"), null)
        expect("снимок: не объект → null", TunnelStatus.fromJson("[1,2,3]"), null)
        expect("снимок: пустой объект → значения по умолчанию", TunnelStatus.fromJson("{}"), TunnelStatus())
        val unknown = TunnelStatus.fromJson("{\"up\": true, \"чужоеПоле\": 5, \"ещё\": {\"a\": 1}}")
        expect("снимок: лишние поля не мешают", unknown?.up, true)
        expect("снимок: лишние поля не ломают статус", unknown?.status, "")

        // Настройки сервиса: то, из-за чего «поменял в настройках — туннель не заметил».
        val settings = ServiceSettings(
            secondExitOn = true,
            secondConf = "[Interface]\nPrivateKey = abc=\n[Peer]\nEndpoint = 1.2.3.4:51820",
            secondCidrs = "1.1.1.0/24, 8.8.8.8/32",
            appsMode = 1,
            appsSelected = listOf("org.telegram.messenger", "com.google.android.youtube", "ru.yandex.music"),
        )
        val settingsBack = ServiceSettings.fromJson(settings.toJson())
        check("настройки сервиса: читаются обратно", settingsBack != null)
        expect("настройки сервиса: второй выход", settingsBack?.secondExitOn, true)
        expect("настройки сервиса: конфиг дословно", settingsBack?.secondConf, settings.secondConf)
        expect("настройки сервиса: подсети", settingsBack?.secondCidrs, settings.secondCidrs)
        expect("настройки сервиса: режим приложений", settingsBack?.appsMode, 1)
        expect("настройки сервиса: список приложений", settingsBack?.appsSelected, settings.appsSelected)

        val many = (0 until 300).map { "app.number.$it" }
        expect(
            "настройки сервиса: 300 приложений",
            ServiceSettings.fromJson(ServiceSettings(appsSelected = many).toJson())?.appsSelected,
            many
        )
        expect(
            "настройки сервиса: пустой список",
            ServiceSettings.fromJson(ServiceSettings().toJson())?.appsSelected,
            emptyList<String>()
        )
        expect("настройки сервиса: мусор → null", ServiceSettings.fromJson("<xml/>"), null)

        // Очередь точек: по ней процесс туннеля сам меняет точку, когда прежняя замолчала.
        val queue = listOf("162.159.192.10:864", "162.159.192.7:500", "188.114.97.1:500")
        expect(
            "настройки сервиса: очередь точек сохраняется",
            ServiceSettings.fromJson(ServiceSettings(failover = queue).toJson())?.failover,
            queue
        )
        expect(
            "настройки сервиса: пустая очередь",
            ServiceSettings.fromJson(ServiceSettings().toJson())?.failover,
            emptyList<String>()
        )
        // Старый снимок без поля обязан читаться: обновление не должно ломать уже поднятый туннель.
        expect(
            "настройки сервиса: снимок без очереди читается",
            ServiceSettings.fromJson("""{"ver":1,"appsMode":2}""")?.failover,
            emptyList<String>()
        )

        // Фаза: машинный код вместо поиска подстрок в русском статусе.
        expect("фаза: по умолчанию простаивает", TunnelStatus().phase, TunnelStatus.PHASE_IDLE)
        expect(
            "фаза: переживает сериализацию",
            TunnelStatus.fromJson(TunnelStatus(phase = TunnelStatus.PHASE_RECONNECTING).toJson())?.phase,
            TunnelStatus.PHASE_RECONNECTING
        )
        expect(
            "фаза: «идёт подключение» у подъёма",
            TunnelStatus(phase = TunnelStatus.PHASE_STARTING).isStarting,
            true
        )
        expect(
            "фаза: «идёт подключение» у переподключения",
            TunnelStatus(phase = TunnelStatus.PHASE_RECONNECTING).isStarting,
            true
        )
        expect("фаза: работа — это не «идёт подключение»", TunnelStatus(phase = TunnelStatus.PHASE_UP).isStarting, false)
        expect(
            "фаза: «нет сети» — отдельный признак",
            TunnelStatus(phase = TunnelStatus.PHASE_NO_NETWORK).hasNoNetwork,
            true
        )
        expect(
            "фаза: старый снимок без фазы читается как простой",
            TunnelStatus.fromJson("{\"up\": false}")?.phase,
            TunnelStatus.PHASE_IDLE
        )

        // Совместимость: снимок без новых полей (он же — снимок старой версии приложения).
        val legacy = TunnelStatus.fromJson("{\"up\": true, \"status\": \"старый снимок\"}")
        expect("снимок: читается без новых полей", legacy?.status, "старый снимок")
        expect("снимок: отсутствующие поля по умолчанию", legacy, TunnelStatus(up = true, status = "старый снимок"))
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
    /** Пакет-«пользовательские данные»: 48 байт с правдоподобным IPv4-заголовком. */
    private fun testPacket(): ByteArray = ByteArray(48).also { b ->
        b[0] = 0x45; b[12] = 108.toByte(); b[13] = 64.toByte()
        b[16] = 1.toByte(); b[17] = 1; b[18] = 1; b[19] = 1
        for (i in 20 until 48) b[i] = (i % 251).toByte()
    }

    /** Обвязка для тестов data plane: туннель без настоящего tun-устройства. */
    private class PlaneHarness(
        val plane: dev.warpscout.core.tunnel.DataPlane,
        val tunIn: QueueInputStream,
        val tunOut: QueueOutputStream,
        val log: StringBuilder,
        val thread: Thread
    ) {
        fun awaitUp(timeoutMs: Long): Boolean {
            val until = System.currentTimeMillis() + timeoutMs
            while (!plane.handshakeOk && System.currentTimeMillis() < until) Thread.sleep(10)
            return plane.handshakeOk
        }

        fun stop() {
            plane.stop()
            runCatching { thread.join(1500) }
        }
    }

    private fun startPlane(
        clientPriv: ByteArray,
        serverPub: ByteArray,
        port: Int,
        settings: NetSettings
    ): PlaneHarness {
        val tunIn = QueueInputStream()
        val tunOut = QueueOutputStream()
        val sock = java.net.DatagramSocket().apply {
            connect(java.net.InetSocketAddress("127.0.0.1", port))
            soTimeout = 300
        }
        val config = dev.warpscout.core.model.WarpConfig(
            name = "test",
            account = dev.warpscout.core.model.WarpAccount(Crypto.base64(clientPriv), Crypto.base64(serverPub)),
            endpoint = Endpoint("127.0.0.1", port),
            junk = dev.warpscout.core.junk.JunkLibrary.none(),
            persistentKeepalive = null
        )
        val log = StringBuilder()
        val plane = dev.warpscout.core.tunnel.DataPlane(
            dev.warpscout.core.tunnel.SocketUdpChannel(sock, Endpoint("127.0.0.1", port), 300),
            tunIn, tunOut, config, settings
        ) { line -> log.append(line).append("; ") }
        val thread = Thread { plane.run() }.apply { isDaemon = true; start() }
        return PlaneHarness(plane, tunIn, tunOut, log, thread)
    }

    /**
     * ICMP port unreachable — самый частый ответ на «мёртвой» точке: сервер прямо говорит, что на
     * этом порту WARP нет. Раньше это тонуло в общем «чтение сокета» и туннель продолжал ждать
     * ещё пять инициаций по 400 мс — то есть каждая мёртвая точка стоила двух с половиной секунд
     * и лишних датаграмм. Проверяем именно это: отказ быстрый и с внятной причиной.
     */
    private fun deadPortFailsFast() {
        val clientPriv = ByteArray(32) { (it * 3 + 7).toByte() }
        val serverPriv = ByteArray(32) { (it * 5 + 11).toByte() }
        val dead = object : dev.warpscout.core.tunnel.UdpChannel {
            override fun send(packet: ByteArray) = Unit
            override fun receive(): ByteArray? =
                throw java.net.PortUnreachableException("ICMP Port Unreachable")
            override fun close() = Unit
        }
        val config = WarpConfig(
            name = "test",
            account = WarpAccount(Crypto.base64(clientPriv), Crypto.base64(Crypto.publicOf(serverPriv))),
            endpoint = Endpoint("127.0.0.1", 9),
            junk = JunkLibrary.none(),
            persistentKeepalive = null
        )
        val startedAt = System.currentTimeMillis()
        val plane = dev.warpscout.core.tunnel.DataPlane(
            dead,
            java.io.PipedInputStream(),
            java.io.ByteArrayOutputStream(),
            config,
            NetSettings(attempts = 5, timeoutMs = 1000, retryEveryMs = 400, junkPacketsBeforeHandshake = 1)
        )
        val ok = plane.run()
        val took = System.currentTimeMillis() - startedAt
        check("закрытый порт: туннель не поднят", !ok)
        check(
            "закрытый порт: причина названа портом, а не «сервер молчит»",
            plane.failureReason?.contains("порт закрыт") == true,
            plane.failureReason ?: "причина не записана"
        )
        check("закрытый порт: не ждём остальные инициации", took < 1_500, "$took мс")
    }

    private fun dataPlaneLoopback() {
        val clientPriv = ByteArray(32) { (it * 3 + 7).toByte() }
        val serverPriv = ByteArray(32) { (it * 5 + 11).toByte() }
        val server = LoopbackServer(serverPriv).start()
        val h = startPlane(clientPriv, Crypto.publicOf(serverPriv), server.port,
            NetSettings(attempts = 3, timeoutMs = 1200))
        try {
            val ipPacket = testPacket()
            h.tunIn.offer(ipPacket)
            val seen = server.firstPacket(8000)
            check("data plane: handshake поднят", h.plane.handshakeOk, h.log.toString())
            check("data plane: пакет дошёл до пира", seen?.contentEquals(ipPacket) == true,
                server.error ?: "payload=${seen?.size}")
            val back = h.tunOut.poll(3000L)
            check("data plane: эхо вернулось в tun", back?.contentEquals(ipPacket) == true, "back=${back?.size}")
            val counterDeadline = System.currentTimeMillis() + 1000
            while (System.currentTimeMillis() < counterDeadline &&
                (h.plane.bytesUp < ipPacket.size || h.plane.bytesDown == 0L)
            ) Thread.sleep(25)
            check(
                "data plane: счётчики учтены",
                h.plane.bytesUp == ipPacket.size.toLong() && h.plane.bytesDown == ipPacket.size.toLong(),
                "up=${h.plane.bytesUp} down=${h.plane.bytesDown} ожидалось=${ipPacket.size}"
            )
        } finally {
            h.stop()
            server.stop()
        }
    }

    /**
     * Пересогласование сессии (rekey) — регрессия на «работает 3–5 минут, потом Telegram пишет
     * Соединение…». Таймеры ускорены, сервер локальный, поэтому проверка идёт офлайн.
     */
    private fun dataPlaneRekey() {
        val clientPriv = ByteArray(32) { (it * 3 + 17).toByte() }
        val serverPriv = ByteArray(32) { (it * 5 + 23).toByte() }
        val server = LoopbackServer(serverPriv).start()
        val h = startPlane(clientPriv, Crypto.publicOf(serverPriv), server.port,
            NetSettings(attempts = 2, timeoutMs = 1000, rekeyAfterMs = 700, rekeyRetryMs = 150))
        try {
            check("rekey: сессия поднялась", h.awaitUp(4000), h.log.toString())

            // Пересогласование по требованию (1.10.13): в полной тишине rekey не выполняется —
            // иначе модем просыпается каждые 150 с без всякой пользы. Значит, чтобы проверить
            // плановый rekey, нужен живой трафик: подкидываем по пакету, пока не наберётся два.
            val rekeyUntil = System.currentTimeMillis() + 6000
            while (h.plane.rekeyCount < 2 && System.currentTimeMillis() < rekeyUntil) {
                h.tunIn.offer(testPacket())
                Thread.sleep(50)
            }
            check(
                "rekey: сессия пересогласована сама (2 раза)",
                h.plane.rekeyCount >= 2,
                "rekey=${h.plane.rekeyCount}, инициаций=${server.initiations.get()}, ${h.log}"
            )

            val ipPacket = testPacket()
            h.tunIn.offer(ipPacket)
            val back = h.tunOut.poll(4000L)
            check("rekey: данные идут после пересогласования", back?.contentEquals(ipPacket) == true,
                server.error ?: "back=${back?.size}; ${h.log}")
            check("rekey: возраст сессии обнулился", h.plane.sessionAgeMs() < 4000,
                "age=${h.plane.sessionAgeMs()}")
            // Как настоящий сервер: каждая инициация обязана нести метку новее прошлой, иначе он
            // молча отбросит её как повтор (WARP этого не проверяет — свой сервер проверяет).
            check(
                "rekey: метка времени каждой инициации новее прошлой",
                server.staleStamps.get() == 0,
                "инициаций с меткой не новее прошлой: ${server.staleStamps.get()} из ${server.initiations.get()}"
            )

            // Тишина: ждём дольше, чем rekeyAfterMs, и убеждаемся, что рукопожатий не прибавилось.
            // Это и есть «не будить радио зря»: расход батареи в простое давали именно эти
            // пересогласования каждые 150 секунд.
            //
            // Сначала даём плоскости доработать накопленные пакеты и трафику стихнуть: пока хоть
            // один пакет идёт, «живой трафик» — это правда, и плановый rekey в это время законен.
            // Заодно вычерпываем эхо, иначе очередь в tun переполнится и задержит доставку.
            val settleUntil = System.currentTimeMillis() + 1200
            while (System.currentTimeMillis() < settleUntil) {
                h.tunOut.poll(50L)
            }
            val before = h.plane.rekeyCount
            Thread.sleep(1400)
            check(
                "rekey: в тишине сессия не пересогласовывается",
                h.plane.rekeyCount == before,
                "было $before, стало ${h.plane.rekeyCount}; ${h.log}"
            )

            // А первый пакет после простоя должен вернуть сессию: либо уже действующую, либо
            // пересогласованную на месте (см. tunToUdp).
            val afterIdle = testPacket()
            h.tunIn.offer(afterIdle)
            check(
                "rekey: после простоя данные идут",
                h.tunOut.poll(4000L) != null,
                "back=null; ${h.log}"
            )
        } finally {
            h.stop()
            server.stop()
        }
    }

    /**
     * «Поднимается только с пятой попытки» — регрессия ровно на эту жалобу.
     *
     * Сервер нарочно игнорирует первую инициацию (так ведёт себя сеть, теряющая первый датаграмм
     * нового UDP-потока). Клиент обязан не ждать полное окно `timeoutMs`, а повторить инициацию
     * через `retryEveryMs` и подняться быстро.
     */
    private fun dataPlaneRetryAfterLoss() {
        val clientPriv = ByteArray(32) { (it * 7 + 3).toByte() }
        val serverPriv = ByteArray(32) { (it * 11 + 5).toByte() }
        val server = LoopbackServer(serverPriv, answerInitiation = { n -> n >= 2 }).start()
        val h = startPlane(clientPriv, Crypto.publicOf(serverPriv), server.port,
            NetSettings(attempts = 5, timeoutMs = 1000, retryEveryMs = 200))
        val startedAt = System.currentTimeMillis()
        try {
            val up = h.awaitUp(4000)
            val took = System.currentTimeMillis() - startedAt
            check("сеть: handshake переживает потерю первой инициации", up, h.log.toString())
            check("сеть: повтор ушёл раньше общего окна (быстро)", up && took < 1500,
                "заняло ${took} мс; ${h.log}")
            check("сеть: потребовалось больше одной инициации", h.plane.attemptCount >= 2,
                "инициаций=${h.plane.attemptCount}")

            val ipPacket = testPacket()
            h.tunIn.offer(ipPacket)
            val back = h.tunOut.poll(3000L)
            check("сеть: данные идут после потери инициации", back?.contentEquals(ipPacket) == true,
                "back=${back?.size}; ${h.log}")
        } finally {
            h.stop()
            server.stop()
        }
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
                // Трафик во время ожидания обязателен: с 1.10.13 в полной тишине пересогласования
                // нет (не будим радио зря), а с потоком пакетов плановый rekey работает как раньше.
                val rekeyUntil = System.currentTimeMillis() + 6000
                while (plane.rekeyCount < 1 && System.currentTimeMillis() < rekeyUntil) {
                    tunIn.offer(ip)
                    tunOut.poll(200L)
                    Thread.sleep(50)
                }
                check("integration: сессия пересогласована автоматически", plane.rekeyCount >= 1,
                    "rekey=${plane.rekeyCount}; ${planeLog}")
            } finally {
                plane.stop()
                runCatching { sock.close() }
                runCatching { thread.join(1500) }
            }
        }.onFailure { reportFail("integration: data plane упал — ${it.javaClass.simpleName}: ${it.message}") }
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

        // ---- второй выход: таблица «адрес → выход» и разбор IP-пакета ----
        val router = ExitRouter.of(
            ExitRouter.parse("31.13.0.0/16, 5.6.7.8/32, 2a00:1450:4001:800::/128, мусор, 1.2.3.4/33")
        )
        fun route(ip: String) = router.route(ExitRouter.ipBytes(ip)!!)
        expect("router: во второй выход по /16", route("31.13.9.9"), 1)
        expect("router: тот же диапазон — граница", route("31.13.255.255"), 1)
        expect("router: вне диапазона", route("31.14.0.1"), 0)
        expect("router: точный /32", route("5.6.7.8"), 1)
        expect("router: соседний адрес", route("5.6.7.9"), 0)
        expect("router: IPv6 /128", route("2a00:1450:4001:800::"), 1)
        expect("router: IPv6 другой", route("2a00:1450:4001:801::"), 0)
        expect("router: битый CIDR не ломает таблицу", router.size, 3)

        val v4Packet = ByteArray(20).also {
            it[0] = 0x45
            it[9] = 6
            it[16] = 31; it[17] = 13; it[18] = 9; it[19] = 9
        }
        expect("пакет: адрес назначения IPv4", ExitRouter.ipBytes("31.13.9.9")!!.toList(), IpPacket.dst(v4Packet)!!.toList())
        expect("пакет: протокол TCP", IpPacket.protocol(v4Packet), 6)
        expect("пакет: не IP", IpPacket.dst(ByteArray(4)), null)
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

    /**
     * Ответ + ключи сессии сервера (receiving = out1, sending = out2 — зеркально инициатору).
     *
     * [senderIndex] — наш адрес, на который клиент шлёт transport-пакеты. Настоящий WireGuard
     * выдаёт новый индекс на каждое рукопожатие и держит несколько сессий одновременно; тестам
     * это тоже нужно, иначе параллельные инициации (повтор через 400 мс) путают сессии.
     */
    fun respondWithSession(
        initiation: ByteArray,
        serverPrivate: ByteArray,
        receiverIndex: Int? = null,
        senderIndex: Int = 0x5a5a5a5a
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
     * Расшифрованная метка времени инициации (12 байт TAI64N) — то, что настоящий сервер сверяет с
     * прошлой принятой. null — инициация не для этого ключа сервера.
     */
    fun timestampOf(initiation: ByteArray, serverPrivate: ByteArray): ByteArray? = runCatching {
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
        val clientStatic = Crypto.chacha20Poly1305Open(key, ByteArray(12), encStatic, h) ?: return@runCatching null
        h = Blake2s.hash(h + encStatic)
        temp = Blake2s.hmac(ck, Crypto.dh(serverPrivate, clientStatic))
        ck = Blake2s.hmac(temp, byteArrayOf(0x01))
        key = Blake2s.hmac(temp, ck + byteArrayOf(0x02))
        Crypto.chacha20Poly1305Open(key, ByteArray(12), initiation.copyOfRange(88, 116), h)
    }.getOrNull()

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

/**
 * Ответ «DNS-сервера» на пробу данных: те же адреса и порты наоборот, флаг «ответ». null — это не
 * DNS-запрос (тогда тестовый сервер пакет выбрасывает).
 */
private fun fakeDnsReply(query: ByteArray): ByteArray? {
    if (query.size < 28 || ((query[0].toInt() ushr 4) and 0x0f) != 4 || (query[9].toInt() and 0xff) != 17) return null
    val ihl = (query[0].toInt() and 0x0f) * 4
    if (query.size < ihl + 8 + 12) return null
    val src = query.copyOfRange(12, 16)
    val dst = query.copyOfRange(16, 20)
    val sport = ((query[ihl].toInt() and 0xff) shl 8) or (query[ihl + 1].toInt() and 0xff)
    val dport = ((query[ihl + 2].toInt() and 0xff) shl 8) or (query[ihl + 3].toInt() and 0xff)
    if (dport != 53) return null
    val dns = query.copyOfRange(ihl + 8, query.size)
    dns[2] = (dns[2].toInt() or 0x80).toByte()
    return dev.warpscout.core.tunnel.DataProbe.udp4(dst, 53, src, sport, dns)
}

/** Сравнение меток TAI64N побайтно без знака — ровно как memcmp в ядре Linux. */
private fun stampCompare(a: ByteArray, b: ByteArray): Int {
    for (i in 0 until minOf(a.size, b.size)) {
        val d = (a[i].toInt() and 0xff) - (b[i].toInt() and 0xff)
        if (d != 0) return d
    }
    return a.size - b.size
}

/**
 * Локальный «сервер» WireGuard для тестов: отвечает на инициации и эхом возвращает transport.
 *
 * Держит несколько сессий одновременно — у каждого рукопожатия свой sender_index, ровно как
 * в настоящем WireGuard. Это обязательно: клиент повторяет инициацию через 400 мс, и ответ на
 * повтор может прийти позже ответа на первую — сервер не должен путать сессии.
 */
private class LoopbackServer(
    private val serverPrivate: ByteArray,
    /** false — инициацию «теряем» (имитация сети, которая съела первый датаграмм). */
    private val answerInitiation: (Int) -> Boolean = { true },
    /**
     * Что вернуть на пакет данных: по умолчанию эхо; null — выбросить (сеть, которая пропускает
     * рукопожатие, но режет данные — «вверх есть, вниз 0»).
     */
    private val answerData: (ByteArray) -> ByteArray? = { it }
) {
    private val socket = java.net.DatagramSocket()
    private val sessions = HashMap<Int, dev.warpscout.core.wg.Wg.Session>()
    private val clientIndex = HashMap<Int, Int>()
    private var serverIndex = 0x5a5a0000
    private val stopped = java.util.concurrent.atomic.AtomicBoolean(false)
    private val thread = Thread { loop() }

    val port: Int get() = socket.localPort
    val initiations = java.util.concurrent.atomic.AtomicInteger(0)

    /**
     * Инициации, чья метка времени не новее прошлой принятой: настоящий сервер на них молчит
     * (защита от повтора). Здесь отвечаем всё равно — чтобы не ломать остальные проверки, — но
     * считаем: проверка rekey требует ноль.
     */
    val staleStamps = java.util.concurrent.atomic.AtomicInteger(0)
    private var newestStamp: ByteArray? = null

    @Volatile
    var lastPayload: ByteArray? = null

    @Volatile
    var error: String? = null

    fun start(): LoopbackServer {
        thread.isDaemon = true
        thread.start()
        return this
    }

    fun stop() {
        stopped.set(true)
        runCatching { socket.close() }
        runCatching { thread.join(1500) }
    }

    /** Ждёт первый непустой пользовательский пакет (keepalive не считается). */
    fun firstPacket(timeoutMs: Long): ByteArray? {
        val until = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < until) {
            lastPayload?.let { return it }
            Thread.sleep(10)
        }
        return null
    }

    private fun loop() {
        try {
            socket.soTimeout = 300
            val buf = ByteArray(65536)
            while (!stopped.get()) {
                val p = java.net.DatagramPacket(buf, buf.size)
                try {
                    socket.receive(p)
                } catch (e: java.net.SocketTimeoutException) {
                    continue
                }
                val pkt = p.data.copyOfRange(0, p.length)
                when (if (pkt.size >= 4) Crypto.readLe32(pkt, 0) else -1) {
                    dev.warpscout.core.wg.Wg.TYPE_INITIATION -> {
                        if (pkt.size != dev.warpscout.core.wg.Wg.INITIATION_LEN) continue
                        val n = initiations.incrementAndGet()
                        if (!answerInitiation(n)) continue
                        val stamp = WgResponder.timestampOf(pkt, serverPrivate)
                        val newest = newestStamp
                        if (stamp != null) {
                            if (newest != null && stampCompare(stamp, newest) <= 0) staleStamps.incrementAndGet()
                            else newestStamp = stamp
                        }
                        val idx = serverIndex++
                        val (resp, srv) = WgResponder.respondWithSession(pkt, serverPrivate, senderIndex = idx)
                        sessions[idx] = srv
                        clientIndex[idx] = Crypto.readLe32(pkt, 4)
                        socket.send(java.net.DatagramPacket(resp, resp.size, p.socketAddress))
                    }

                    dev.warpscout.core.wg.Wg.TYPE_TRANSPORT -> {
                        val idx = if (pkt.size >= 8) Crypto.readLe32(pkt, 4) else -1
                        val s = sessions[idx] ?: continue
                        val got = dev.warpscout.core.wg.Wg.openTransport(pkt, idx, s) ?: continue
                        sessions[idx] = got.second
                        if (got.first.isEmpty()) continue   // keepalive: подтверждаем и молчим
                        lastPayload = got.first
                        val client = clientIndex[idx] ?: continue
                        val answer = answerData(got.first) ?: continue
                        val (echo, next) = dev.warpscout.core.wg.Wg.buildTransport(client, got.second, answer)
                        sessions[idx] = next
                        socket.send(java.net.DatagramPacket(echo, echo.size, p.socketAddress))
                    }
                }
            }
        } catch (e: Exception) {
            if (!stopped.get()) error = "${e.javaClass.simpleName}: ${e.message}"
        } finally {
            runCatching { socket.close() }
        }
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
