package dev.warpscout.core.test

import dev.warpscout.core.config.WgConf
import dev.warpscout.core.crypto.Crypto
import dev.warpscout.core.json.JsonVal
import dev.warpscout.core.json.parseJson
import dev.warpscout.core.lists.ProtonFree
import dev.warpscout.core.proton.HttpReply
import dev.warpscout.core.proton.ProtonAlt
import dev.warpscout.core.proton.ProtonApi
import dev.warpscout.core.proton.ProtonChoice
import dev.warpscout.core.proton.ProtonDevice
import dev.warpscout.core.proton.ProtonException
import dev.warpscout.core.proton.ProtonHttp
import dev.warpscout.core.proton.ProtonKeys
import dev.warpscout.core.proton.ProtonService
import dev.warpscout.core.proton.ProtonSrp
import dev.warpscout.core.proton.SrpException
import java.io.IOException
import java.math.BigInteger
import java.security.MessageDigest

/**
 * 1.10.44-beta5: второй выход Proton — кнопкой (просьба 25.11). Вход в свой аккаунт (SRP, второй
 * фактор, «я не робот»), режим без аккаунта и сторонний сервис proton-generation.
 *
 * В песочнице до Proton не достучаться, поэтому всё проверяется на чужих эталонах и на поддельном
 * сервере: наборы go-srp и python-proton-core (самого Proton), значения, посчитанные эталонной
 * Python-реализацией Proton и библиотекой cryptography (независимо от нашего кода), а сервер SRP —
 * по go-srp (server.go).
 */
internal class ProtonChecks(private val report: (String, Boolean, String) -> Unit) {

    private fun check(name: String, ok: Boolean, detail: String = "") = report(name, ok, detail)

    private fun expect(name: String, actual: Any?, expected: Any?) =
        report(name, actual?.toString() == expected?.toString(), "факт=$actual ожидалось=$expected")

    private fun part(name: String, block: () -> Unit) {
        runCatching(block).onFailure { report("$name: исключение ${it.javaClass.simpleName}: ${it.message}", false, "") }
    }

    private fun b64(s: String): ByteArray = Crypto.unBase64(s)

    fun run() {
        part("Proton: подпись модуля") { signatures() }
        part("Proton: пароль") { verifiers() }
        part("Proton: доказательства SRP") { proofVector() }
        part("Proton: ключи") { keys() }
        part("Proton: вход") { loginFlows() }
        part("Proton: без аккаунта и ключ") { anonymousAndKey() }
        part("Proton: сторонний сервис") { serviceFlows() }
        part("Proton: мелочи") { helpers() }
        part("Proton: обходной путь") { altRouting() }
    }

    // ------------------------------------------------------------------ эталоны

    private fun signatures() {
        val text = runCatching { ProtonSrp.verifyClearSigned(GO_SIGNED, MODULUS_KEY) }.getOrNull()
        expect("Proton: модуль go-srp с подписью Proton принят", text, GO_MODULUS)
        val modulus = runCatching { ProtonSrp.readSignedModulus(GO_SIGNED) }.getOrNull()
        check("Proton: модуль — 256 байт, те самые", modulus != null && modulus.contentEquals(b64(GO_MODULUS)))
        check("Proton: модуль python-proton-core принят", runCatching { ProtonSrp.readSignedModulus(PY_SIGNED_OK) }.isSuccess)
        check("Proton: подменённый текст модуля отвергнут", runCatching { ProtonSrp.readSignedModulus(PY_SIGNED_BAD) }.exceptionOrNull() is SrpException)
        val last = GO_SIGNED.length
        val broken = GO_SIGNED.substring(0, last - 100) + "c" + GO_SIGNED.substring(last - 99)
        check("Proton: испорченная подпись отвергнута (как в go-srp)", runCatching { ProtonSrp.readSignedModulus(broken) }.isFailure)
        check("Proton: данные после подписи отвергнуты", runCatching { ProtonSrp.readSignedModulus(GO_SIGNED + "\ndata after modulus") }.isFailure)
        check("Proton: модуль без подписи отвергнут", runCatching { ProtonSrp.readSignedModulus(GO_MODULUS) }.isFailure)
        check("Proton: модуль go-srp — безопасное простое", runCatching { ProtonSrp.checkModulus(ProtonSrp.fromLe(b64(GO_MODULUS))) }.isSuccess)
        check("Proton: чётный «модуль» отвергнут", runCatching { ProtonSrp.checkModulus(BigInteger.ONE.shiftLeft(2047)) }.isFailure)
    }

    private fun verifiers() {
        var ok = 0
        val bad = ArrayList<String>()
        for (v in VERIFIERS) {
            val got = Crypto.base64(ProtonSrp.verifier(v[0].toByteArray(Charsets.UTF_8), b64(v[1]), Crypto.unHex(v[2])))
            if (got == v[3]) ok++ else bad += v[0].take(12) + "/" + v[1]
        }
        expect("Proton: пароль → проверочное число как у python-proton-core (соль с нулями, пароль длиннее 72, пробелы)", ok, VERIFIERS.size)
        if (bad.isNotEmpty()) check("Proton: расхождения в наборах", false, bad.joinToString())
        val h = ProtonSrp.expandHash("abc".toByteArray())
        val md = MessageDigest.getInstance("SHA-512")
        md.update("abc".toByteArray()); md.update(2.toByte())
        check("Proton: растянутый хеш — четыре SHA-512 с байтом 0…3", h.size == 256 && h.copyOfRange(128, 192).contentEquals(md.digest()))
    }

    private fun proofVector() {
        val a = ByteArray(32) { ((it * 7 + 3) % 256).toByte() }
        val proofs = ProtonSrp.proofs(
            "abc123".toByteArray(), b64("yKlc5/CvObfoiw=="), b64(GO_MODULUS), b64(GO_SERVER_EPHEMERAL),
            secret = ProtonSrp.fromLe(a),
        )
        expect("Proton: A как у python-proton-core", Crypto.base64(proofs.clientEphemeral), REF_A)
        expect("Proton: доказательство клиента M1 как у python-proton-core", Crypto.base64(proofs.clientProof), REF_M1)
        expect("Proton: ожидаемое доказательство сервера M2 как у python-proton-core", Crypto.base64(proofs.expectedServerProof), REF_M2)
        val r1 = ProtonSrp.proofs("abc123".toByteArray(), b64("yKlc5/CvObfoiw=="), b64(GO_MODULUS), b64(GO_SERVER_EPHEMERAL))
        val r2 = ProtonSrp.proofs("abc123".toByteArray(), b64("yKlc5/CvObfoiw=="), b64(GO_MODULUS), b64(GO_SERVER_EPHEMERAL))
        check("Proton: случайный секрет каждый раз новый", !r1.clientEphemeral.contentEquals(r2.clientEphemeral))
        check("Proton: число сервера 0 отвергнуто",
            runCatching { ProtonSrp.proofs("x".toByteArray(), b64("yKlc5/CvObfoiw=="), b64(GO_MODULUS), ByteArray(256)) }.exceptionOrNull() is SrpException)
    }

    private fun keys() {
        val pair = ProtonKeys.fromSeed(ByteArray(32) { it.toByte() })
        // Эталоны — библиотека cryptography (Python): Ed25519 из зерна и X25519 из «зажатого» SHA-512.
        expect("Proton: открытый Ed25519 из зерна — как у cryptography", Crypto.hex(pair.edPublic), "03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8")
        expect("Proton: закрытый ключ WireGuard — SHA-512 зерна, зажатый", Crypto.base64(pair.wgPrivate), "OJTupJxYCu+BaTV2K+BJVZ1tFEDe3hLmoSXxhB//jm8=")
        expect("Proton: открытый ключ WireGuard — как у cryptography", Crypto.base64(pair.wgPublic), "RwHQhIhFH1RaQJ+1iuPlhYHKQKw/fxFGmM1x3qxzygE=")
        check("Proton: Proton узнает ключ WireGuard по сертификату (Ed25519 → X25519)",
            ProtonKeys.montgomeryOf(pair.edPublic).contentEquals(pair.wgPublic))
        expect("Proton: PEM — как у cryptography", pair.pem,
            "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAA6EHv/POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg=\n-----END PUBLIC KEY-----\n")
        val g1 = ProtonKeys.generate()
        val g2 = ProtonKeys.generate()
        check("Proton: новые ключи разные и сходятся сами с собой",
            !g1.wgPrivate.contentEquals(g2.wgPrivate) && ProtonKeys.montgomeryOf(g1.edPublic).contentEquals(g1.wgPublic))
    }

    // ------------------------------------------------------------------ поддельный Proton

    private val device = ProtonDevice(
        model = "SM-N985F", brand = "samsung", device = "c2s", androidRelease = "13", language = "ru", region = "RU",
        timezone = "Europe/Moscow", timezoneOffset = -180, fontScale = "1.0", storageGb = 256.0, darkMode = false,
        keyboards = listOf("com.samsung.android.honeyboard"),
    )

    private fun fake() = FakeProton(GO_SIGNED, b64(GO_MODULUS), "kos", "секрет 123", b64("yKlc5/CvObfoiw=="))

    private fun api(fake: ProtonHttp, newer: (() -> String?)? = null) = ProtonApi(fake, device, newerVersion = newer)

    private fun reasonOf(block: () -> Unit): ProtonException.Reason? =
        (runCatching(block).exceptionOrNull() as? ProtonException)?.reason

    private fun loginFlows() {
        val f = fake()
        val s = api(f).login("kos", "секрет 123".toByteArray())
        check("Proton: вход по паролю — сессия с доступом к VPN", s.hasVpn && s.uid == "user-uid" && !s.needsTwoFactor)
        check("Proton: пароль на сервер не ушёл", f.bodies.values.none { it.render().contains("секрет") })
        expect("Proton: порядок как у приложения Proton", f.calls.joinToString(), "POST /auth/v4/sessions, POST /auth/v4/info, POST /auth/v4")
        check("Proton: заголовки приложения Proton для Android",
            f.lastHeaders["x-pm-appversion"] == "android-vpn@${ProtonApi.APP_VERSION}" && f.lastHeaders["x-pm-uid"] == "anon-uid" &&
                f.lastHeaders["User-Agent"]?.startsWith("ProtonVPN/") == true)
        val frame = f.bodies["/auth/v4"]?.obj("Payload")?.obj(ProtonApi.FRAME_KEY)
        check("Proton: кадр устройства в запросе входа", frame?.str("timezone") == "Europe/Moscow" && frame.fields.size == 11)
        expect("Proton: хеш модели — как deviceModelName() у Proton", device.nameHash, 70230005767L)

        expect("Proton: неверный пароль — так и говорим",
            reasonOf { api(fake()).login("kos", "не тот".toByteArray()) }, ProtonException.Reason.WRONG_PASSWORD)
        val liar = fake().apply { badServerProof = true }
        expect("Proton: сервер без нашего пароля разоблачён", reasonOf { api(liar).login("kos", "секрет 123".toByteArray()) },
            ProtonException.Reason.BAD_SERVER)

        val hv = fake().apply { hvRequired = true }
        val hvApi = api(hv)
        val first = runCatching { hvApi.login("kos", "секрет 123".toByteArray()) }.exceptionOrNull() as? ProtonException
        check("Proton: «я не робот» — токен и способы из ответа",
            first?.reason == ProtonException.Reason.HUMAN_VERIFICATION && first.hvToken == "hv-1" && first.hvMethods == listOf("captcha", "email"))
        hvApi.humanVerification = "hv-1:решено" to "captcha"
        val after = runCatching { hvApi.login("kos", "секрет 123".toByteArray()) }.getOrNull()
        check("Proton: после проверки вход проходит, токен ушёл заголовком",
            after?.hasVpn == true && hv.lastAuthHeaders["x-pm-human-verification-token"] == "hv-1:решено" &&
                hv.lastAuthHeaders["x-pm-human-verification-token-type"] == "captcha")

        val tf = fake().apply { twoFactor = true }
        val tfApi = api(tf)
        val half = tfApi.login("kos", "секрет 123".toByteArray())
        check("Proton: второй фактор — сессия просит код", half.needsTwoFactor && !half.hasVpn && half.totp)
        expect("Proton: неверный код — так и говорим", reasonOf { tfApi.submitTwoFactor(half, "000000") }, ProtonException.Reason.TWO_FACTOR_WRONG)
        check("Proton: верный код — доступ к VPN", tfApi.submitTwoFactor(half, " 123456 ").hasVpn)

        val old = fake().apply { requireVersion = "android-vpn@5.99.1.0" }
        expect("Proton: устаревшая версия без запасной — понятная ошибка", reasonOf { api(old).anonymousSession() }, ProtonException.Reason.APP_VERSION)
        val bumped = api(old) { "5.99.1.0" }
        check("Proton: устаревшая версия — берём новую с GitHub и повторяем",
            runCatching { bumped.anonymousSession() }.isSuccess && bumped.appVersion == "5.99.1.0")

        val down = fake().apply { failHosts = setOf("https://vpn-api.proton.me") }
        val downApi = api(down)
        val viaSecond = runCatching { downApi.anonymousSession() }.isSuccess
        downApi.anonymousSession()
        check("Proton: основной адрес закрыт — работает запасной и дальше начинаем с него",
            viaSecond && down.hosts.count { it == "https://vpn-api.proton.me" } == 1 && down.hosts.last() == "https://api.protonvpn.ch")
        val dead = fake().apply { failHosts = setOf("https://vpn-api.proton.me", "https://api.protonvpn.ch") }
        expect("Proton: нет связи — причина «сеть»", reasonOf { api(dead).anonymousSession() }, ProtonException.Reason.NETWORK)
    }

    private fun anonymousAndKey() {
        val f = fake()
        val a = api(f)
        val s = a.withoutAccount()
        check("Proton: без аккаунта — сессия с доступом к VPN", s.hasVpn && s.uid == "cl-uid")
        check("Proton: без аккаунта — носитель и credentialless с кадром устройства",
            f.calls.take(2) == listOf("POST /auth/v4/sessions", "POST /auth/v4/credentialless") &&
                f.bodies["/auth/v4/credentialless"]?.obj("Payload")?.obj(ProtonApi.FRAME_KEY) != null)
        val tied = fake().apply { tiedOnce = true }
        check("Proton: «Session already tied» — новая сессия и один повтор",
            runCatching { api(tied).withoutAccount() }.isSuccess && tied.calls.count { it == "POST /auth/v4/sessions" } == 2)

        val servers = a.freeServers(s)
        expect("Proton: бесплатные серверы — включённые, с ключом, без платных",
            servers.joinToString { it.server.name + "@" + it.server.ip + ":" + it.load }, "NL-FREE#1@10.1.0.1:37, NL-FREE#2@10.1.0.2:12, JP-FREE#3@10.1.0.3:5, RO-FREE#5@10.1.0.7:50")
        val best = ProtonChoice.best(servers, "")
        expect("Proton: «любая страна» — наименее загруженный из ближних", best?.server?.name, "NL-FREE#2")
        expect("Proton: выбрана страна — её наименее загруженный", ProtonChoice.best(servers, "JP")?.server?.name, "JP-FREE#3")
        expect("Proton: страны — ближние первыми, с числом и загрузкой",
            ProtonChoice.countries(servers).joinToString { "${it.code}${it.count}/${it.minLoad}" }, "NL2/12, RO1/50, JP1/5")
        expect("Proton: серверы страны — по загрузке", ProtonChoice.inCountry(servers, "NL").joinToString { it.server.name }, "NL-FREE#2, NL-FREE#1")

        val keys = ProtonKeys.generate()
        val cert = a.registerKey(s, keys, "WarpScout · SM-N985F")
        check("Proton: ключ зарегистрирован постоянным, срок — из ответа",
            cert.expiresAt == 1_795_000_000_000L && cert.serial == "4242" && f.bodies["/vpn/v1/certificate"]?.str("Mode") == "persistent")
        expect("Proton: в Proton ушла только открытая часть ключа", f.bodies["/vpn/v1/certificate"]?.str("ClientPublicKey"), keys.pem)
        check("Proton: закрытого ключа нет ни в одном запросе",
            f.bodies.values.none { it.render().contains(Crypto.base64(keys.wgPrivate)) })

        val conf = ProtonFree.confFor(Crypto.base64(keys.wgPrivate), best!!.server, "WarpScout: Proton без аккаунта, ключ до 25.11.2027")
        check("Proton: конфиг из выданного ключа узнаётся как Proton", ProtonFree.isProton(conf))
        check("Proton: конфиг разбирается как WireGuard", WgConf.toWarpConfig("второй выход", conf) != null)
        expect("Proton: сервер в конфиге — выбранный", ProtonFree.peerOf(conf)?.ip, "10.1.0.2")
        check("Proton: многострочная заметка не ломает конфиг",
            ProtonFree.confFor("k", best.server, "раз\nPrivateKey = чужой").lines().count { it.startsWith("PrivateKey") } == 1)
        a.logout(s)
        expect("Proton: выход — DELETE /auth/v4", f.calls.last(), "DELETE /auth/v4")
    }

    private fun serviceFlows() {
        val svc = FakeService().apply { firstDown = true }
        val client = ProtonService(svc)
        val session = client.session()
        check("Proton, сервис: первый адрес молчит — сессия у зеркала", svc.hosts.last() == "https://www.api-proton.workers.dev")
        val servers = client.servers(session)
        expect("Proton, сервис: серверы в разных написаниях полей", servers.joinToString { it.server.name + "/" + it.server.code + ":" + it.load },
            "NL-FREE#7/NL:20, US-FREE#9/US:35")
        check("Proton, сервис: сессия уходит обратно как есть", svc.lastBody?.fields?.get("session") == session && svc.hosts.last() == "https://www.api-proton.workers.dev")
        val keys = ProtonKeys.generate()
        expect("Proton, сервис: срок ключа из ответа", client.register(session, keys), 1_795_000_000_000L)
        check("Proton, сервис: ушла только открытая часть ключа",
            svc.lastBody?.str("clientPublicKey") == keys.pem && svc.lastBody?.bool("persistent") == true &&
                svc.allBodies.none { it.contains(Crypto.base64(keys.wgPrivate)) })
        val broken = FakeService().apply { expired = true }
        val err = runCatching { ProtonService(broken).session() }.exceptionOrNull() as? ProtonException
        check("Proton, сервис: ошибка сервиса — его словами", err?.reason == ProtonException.Reason.API && err.message?.contains("Session expired") == true)
        val dead = FakeService().apply { firstDown = true; secondDown = true }
        expect("Proton, сервис: оба адреса молчат — «сеть»", (runCatching { ProtonService(dead).session() }.exceptionOrNull() as? ProtonException)?.reason,
            ProtonException.Reason.NETWORK)
        expect("Proton, сервис: срок, вложенный в ответ", ProtonService.expirationOf(parseJson("""{"ok":true,"data":{"ExpirationTime":1800000000}}""") as JsonVal.Obj), 1_800_000_000_000L)
    }

    private fun helpers() {
        val url = ProtonApi.hvUrl("tok 1", listOf("captcha", "email", "sms", "ownership-email"), dark = true, locale = "ru")
        check("Proton: страница проверки — verify.proton.me, токен и способы",
            url.startsWith("https://verify.proton.me/?embed=true&token=tok+1") && url.contains("methods=captcha%2Cemail%2Csms") &&
                url.contains("theme=1") && url.contains("vpn=true"), url)
        expect("Proton: ответ страницы проверки",
            ProtonApi.hvResult("""{"type":"HUMAN_VERIFICATION_SUCCESS","payload":{"token":"abc","type":"email"}}"""), "abc" to "email")
        expect("Proton: сообщение капчи", ProtonApi.hvResult("""{"type":"pm_captcha","token":"t:r"}"""), "t:r" to "captcha")
        check("Proton: прочие сообщения страницы не путаем с успехом",
            ProtonApi.hvResult("""{"type":"RESIZE","payload":{"height":300}}""") == null && ProtonApi.hvResult("мусор") == null)
        expect("Proton: новая версия приложения Proton из тегов GitHub",
            ProtonApi.newestVersion("""[{"name":"5.21.57.0"},{"name":"5.20.98.0"},{"name":"v5.22.1.0"},{"name":"beta"}]"""), "5.22.1.0")
        expect("Proton: кадр устройства — поля как у Proton",
            device.frame().fields.keys.joinToString(","), "v,appLang,timezone,deviceName,regionCode,timezoneOffset,isJailbreak,preferredContentSize,storageCapacity,isDarkmodeOn,keyboards")
    }

    // ------------------------------------------------------------------ обходной путь (1.10.46)

    private fun altRouting() {
        expect("Proton: обходной путь — имя записи как у Proton (base32 заглавными без «=»)",
            ProtonAlt.queryName("vpn-api.proton.me"), "dOZYG4LLBOBUS44DSN52G63RONVSQ.protonpro.xyz")
        expect("Proton: base32 — эталоны RFC 4648",
            listOf("", "f", "fo", "foo", "foob", "fooba", "foobar").joinToString(",") { ProtonAlt.base32(it.toByteArray()) },
            ",MY,MZXQ,MZXW6,MZXW6YQ,MZXW6YTB,MZXW6YTBOI")
        expect("Proton: DNS-запрос — заголовок, метки, TXT класса IN",
            ProtonAlt.encodeQuery("a.bc").joinToString(" ") { (it.toInt() and 0xFF).toString() },
            "0 0 1 0 0 1 0 0 0 0 0 0 1 97 2 98 99 0 0 16 0 1")
        val ips = listOf("3.76.252.252", "18.157.168.84")
        val reply = dnsReply("dOZYG4LLBOBUS44DSN52G63RONVSQ.protonpro.xyz", "vpn.protonpro.xyz", ips)
        expect("Proton: ответ DoH — TXT за CNAME, имена сжаты ссылками", ProtonAlt.txtRecords(reply), ips)
        val nx = reply.copyOf().also { it[3] = (it[3].toInt() or 3).toByte() }
        check("Proton: ответ DoH с ошибкой (NXDOMAIN) — посредников нет", ProtonAlt.txtRecords(nx).isEmpty())
        check("Proton: обрезанный ответ DoH — пусто и без исключения", ProtonAlt.txtRecords(reply.copyOf(20)).isEmpty())
        check("Proton: посредник — только адрес или имя хоста",
            ProtonAlt.hostOf("3.76.252.252") == "3.76.252.252" && ProtonAlt.hostOf("vpn.protonpro.xyz.") == "vpn.protonpro.xyz" &&
                ProtonAlt.hostOf("evil.example/x?y") == null && ProtonAlt.hostOf("") == null)

        // Прямые адреса молчат (как 25.11 через московскую площадку WARP) — отвечает посредник.
        val blocked = fake().apply {
            failHosts = setOf("https://vpn-api.proton.me", "https://api.protonvpn.ch", "https://3.76.252.252")
            altReply = reply
        }
        val logs = ArrayList<String>()
        val viaAlt = ProtonApi(blocked, device, log = { logs += it })
        val s = runCatching { viaAlt.withoutAccount() }.getOrNull()
        check("Proton: прямые адреса молчат — сессия через посредника, с закреплёнными ключами",
            s?.hasVpn == true && s.uid == "cl-uid" && blocked.pinned.lastOrNull() == "https://18.157.168.84" &&
                blocked.pinnedWith == ProtonAlt.PINS)
        check("Proton: DoH — сначала 1.1.1.1, запрос в формате RFC 8484",
            blocked.dohUrls.firstOrNull()?.startsWith("https://1.1.1.1/dns-query?dns=") == true && blocked.dohAccept == "application/dns-message")
        val before = blocked.hosts.size
        val again = runCatching { viaAlt.anonymousSession() }.isSuccess
        check("Proton: дальше — сразу к посреднику, без прямых адресов и без нового DoH",
            again && blocked.hosts.drop(before).all { it == "https://18.157.168.84" } && blocked.dohUrls.size == 1)
        check("Proton: в журнале — что выручил посредник", logs.any { it.contains("посредник Proton 18.157.168.84") })
        val nothing = fake().apply { failHosts = setOf("https://vpn-api.proton.me", "https://api.protonvpn.ch") }
        val err = runCatching { api(nothing).anonymousSession() }.exceptionOrNull() as? ProtonException
        check("Proton: и посредников нет — причина «сеть», в тексте все три DoH",
            err?.reason == ProtonException.Reason.NETWORK &&
                ProtonAlt.DOH.all { d -> err.message?.contains("DoH " + d.substringAfter("://").substringBefore('/')) == true })
    }

    /** Ответ DNS: CNAME на [target] и TXT-записи [texts] у него; имена сжаты ссылками, как у настоящих серверов. */
    private fun dnsReply(name: String, target: String, texts: List<String>): ByteArray {
        val out = java.io.ByteArrayOutputStream()
        fun u16(v: Int) {
            out.write(v shr 8)
            out.write(v and 0xFF)
        }
        fun labels(n: String): ByteArray {
            val b = java.io.ByteArrayOutputStream()
            for (l in n.split('.')) {
                b.write(l.length)
                b.write(l.toByteArray())
            }
            b.write(0)
            return b.toByteArray()
        }
        u16(0); u16(0x8180); u16(1); u16(1 + texts.size); u16(0); u16(0)
        out.write(labels(name)); u16(ProtonAlt.TYPE_TXT); u16(1)
        val cname = labels(target)
        u16(0xC00C); u16(5); u16(1); u16(0); u16(120); u16(cname.size)
        val targetAt = out.size()
        out.write(cname)
        for (t in texts) {
            u16(0xC000 or targetAt); u16(ProtonAlt.TYPE_TXT); u16(1); u16(0); u16(120); u16(t.length + 1)
            out.write(t.length)
            out.write(t.toByteArray())
        }
        return out.toByteArray()
    }

    // ------------------------------------------------------------------ подделки

    /** Сервер Proton на минималках: SRP по go-srp (server.go), сессии, второй фактор, «я не робот», ключи. */
    private class FakeProton(
        private val signedModulus: String,
        modulus: ByteArray,
        private val username: String,
        password: String,
        private val salt: ByteArray,
    ) : ProtonHttp {
        var hvRequired = false
        var twoFactor = false
        var badServerProof = false
        var tiedOnce = false
        var requireVersion: String? = null
        var failHosts: Set<String> = emptySet()
        /** Ответ DoH для обходного пути (null — DoH недоступен). */
        var altReply: ByteArray? = null
        val dohUrls = ArrayList<String>()
        var dohAccept: String? = null
        val pinned = ArrayList<String>()
        var pinnedWith: List<String>? = null
        private var pinnedCall = false
        val calls = ArrayList<String>()
        val hosts = ArrayList<String>()
        val bodies = LinkedHashMap<String, JsonVal.Obj>()
        var lastHeaders: Map<String, String> = emptyMap()
        var lastAuthHeaders: Map<String, String> = emptyMap()

        private val n = ProtonSrp.fromLe(modulus)
        private val v = ProtonSrp.fromLe(ProtonSrp.verifier(password.toByteArray(), salt, modulus))
        private val b = BigInteger(2040, java.util.Random(42)).add(BigInteger.valueOf(5000))
        private val k = ProtonSrp.fromLe(ProtonSrp.expandHash(ProtonSrp.toLe(BigInteger.valueOf(2)) + ProtonSrp.toLe(n))).mod(n)
        private val bEph = ProtonSrp.toLe(k.multiply(v).add(BigInteger.valueOf(2).modPow(b, n)).mod(n))
        private var anonCount = 0

        private fun ok(vararg fields: Pair<String, JsonVal>) = HttpReply(200, JsonVal.obj("Code" to JsonVal.num(1000), *fields).render())
        private fun err(status: Int, code: Int, text: String, details: JsonVal.Obj? = null): HttpReply {
            val f = linkedMapOf<String, JsonVal>("Code" to JsonVal.num(code), "Error" to JsonVal.str(text))
            if (details != null) f["Details"] = details
            return HttpReply(status, JsonVal.obj(f).render())
        }
        private fun strs(vararg s: String) = JsonVal.arr(s.map { JsonVal.str(it) })

        override fun getBytes(url: String, headers: Map<String, String>): ByteArray? {
            dohUrls += url
            dohAccept = headers["Accept"]
            return altReply ?: throw IOException("DoH недоступен")
        }

        override fun sendPinned(method: String, url: String, headers: Map<String, String>, body: String?, pins: List<String>): HttpReply {
            pinned += url.substring(0, url.indexOf('/', 8))
            pinnedWith = pins
            pinnedCall = true
            try {
                return send(method, url, headers, body)
            } finally {
                pinnedCall = false
            }
        }

        override fun send(method: String, url: String, headers: Map<String, String>, body: String?): HttpReply {
            val host = url.substring(0, url.indexOf('/', 8))
            val path = url.substring(host.length)
            hosts += host
            if (host in failHosts) throw IOException("connect timed out")
            // Посредник (адрес вместо имени) — только с закреплёнными ключами, как у Proton.
            if (Regex("https://\\d+\\.\\d+\\.\\d+\\.\\d+").matches(host) && !pinnedCall) {
                throw IOException("посредник без закреплённых ключей")
            }
            calls += "$method $path"
            lastHeaders = headers
            val obj = body?.let { parseJson(it) as JsonVal.Obj }
            if (obj != null) bodies[path.substringBefore('?')] = obj
            requireVersion?.let { if (headers["x-pm-appversion"] != it) return err(400, 5003, "This version of the app is no longer supported") }
            val uid = headers["x-pm-uid"]
            return when ("$method $path") {
                "POST /auth/v4/sessions" -> {
                    if (obj?.obj("Payload")?.obj(ProtonApi.FRAME_KEY) == null) return err(422, 2001, "Payload required")
                    anonCount++
                    ok("UID" to JsonVal.str("anon-uid"), "AccessToken" to JsonVal.str("anon-at-$anonCount"), "RefreshToken" to JsonVal.str("anon-rt"), "Scopes" to JsonVal.arr(emptyList()))
                }
                "POST /auth/v4/info" -> {
                    if (uid != "anon-uid") return err(401, 401, "Invalid access token")
                    ok("Version" to JsonVal.num(4), "Modulus" to JsonVal.str(signedModulus), "ServerEphemeral" to JsonVal.str(Crypto.base64(bEph)),
                        "Salt" to JsonVal.str(Crypto.base64(salt)), "SRPSession" to JsonVal.str("srp-1"))
                }
                "POST /auth/v4" -> {
                    lastAuthHeaders = headers
                    if (hvRequired && headers["x-pm-human-verification-token"] != "hv-1:решено") {
                        return err(422, ProtonApi.CODE_HV, "Human verification required",
                            JsonVal.obj("HumanVerificationToken" to JsonVal.str("hv-1"), "HumanVerificationMethods" to strs("captcha", "email")))
                    }
                    if (obj == null || obj.str("Username") != username || obj.str("SRPSession") != "srp-1") return err(422, 8002, "Incorrect login credentials")
                    val aBytes = Crypto.unBase64(obj.str("ClientEphemeral").orEmpty())
                    val a = ProtonSrp.fromLe(aBytes)
                    val u = ProtonSrp.fromLe(ProtonSrp.expandHash(ProtonSrp.toLe(a) + bEph))
                    val s = ProtonSrp.toLe(a.multiply(v.modPow(u, n)).mod(n).modPow(b, n))
                    val m1 = ProtonSrp.expandHash(ProtonSrp.toLe(a) + bEph + s)
                    if (!m1.contentEquals(Crypto.unBase64(obj.str("ClientProof").orEmpty()))) return err(422, 8002, "Incorrect login credentials. Please try again")
                    var m2 = ProtonSrp.expandHash(ProtonSrp.toLe(a) + m1 + s)
                    if (badServerProof) m2 = m2.copyOf().also { it[0] = (it[0] + 1).toByte() }
                    ok("UID" to JsonVal.str("user-uid"), "AccessToken" to JsonVal.str("user-at"), "RefreshToken" to JsonVal.str("user-rt"),
                        "Scopes" to if (twoFactor) strs("twofactor") else strs("self", "user", "loggedin", "vpn", "verified", "settings"),
                        "ServerProof" to JsonVal.str(Crypto.base64(m2)), "PasswordMode" to JsonVal.num(1),
                        "2FA" to JsonVal.obj("Enabled" to JsonVal.num(if (twoFactor) 1 else 0), "TOTP" to JsonVal.num(if (twoFactor) 1 else 0)))
                }
                "POST /auth/v4/2fa" -> {
                    if (uid != "user-uid") return err(401, 401, "Invalid access token")
                    if (obj?.str("TwoFactorCode") != "123456") return err(422, 8002, "Incorrect code")
                    ok("Scopes" to strs("self", "user", "loggedin", "vpn", "verified", "settings"))
                }
                "POST /auth/v4/credentialless" -> {
                    if (uid != "anon-uid" || obj?.obj("Payload")?.obj(ProtonApi.FRAME_KEY) == null) return err(422, 2001, "Payload required")
                    if (tiedOnce) {
                        tiedOnce = false
                        return err(400, 2500, "Session already tied to a user")
                    }
                    ok("UID" to JsonVal.str("cl-uid"), "AccessToken" to JsonVal.str("cl-at"), "RefreshToken" to JsonVal.str("cl-rt"), "Scopes" to strs("vpn", "loggedin"))
                }
                "GET /vpn/v1/logicals?Tier=0&WithState=true" -> {
                    if (uid != "cl-uid" && uid != "user-uid") return err(401, 401, "Invalid access token")
                    HttpReply(200, LOGICALS)
                }
                "POST /vpn/v1/certificate" -> {
                    if (uid != "cl-uid" && uid != "user-uid") return err(401, 401, "Invalid access token")
                    val pem = obj?.str("ClientPublicKey").orEmpty()
                    if (!pem.startsWith("-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA") || obj?.str("Mode") != "persistent") return err(422, 2001, "Invalid key")
                    ok("SerialNumber" to JsonVal.str("4242"), "ExpirationTime" to JsonVal.num(1_795_000_000L), "Mode" to JsonVal.str("persistent"))
                }
                "DELETE /auth/v4" -> ok()
                else -> err(404, 2000, "Not found: $method $path")
            }
        }
    }

    /** Сервис proton-generation на минималках: сессия, серверы, ключ. */
    private class FakeService : ProtonHttp {
        var firstDown = false
        var secondDown = false
        var expired = false
        val hosts = ArrayList<String>()
        var lastBody: JsonVal.Obj? = null
        val allBodies = ArrayList<String>()

        override fun send(method: String, url: String, headers: Map<String, String>, body: String?): HttpReply {
            val host = url.substring(0, url.indexOf('/', 8))
            val path = url.substring(host.length)
            hosts += host
            if (firstDown && host == "https://warp-api.cfd") throw IOException("connect timed out")
            if (secondDown && host == "https://www.api-proton.workers.dev") throw IOException("connect timed out")
            allBodies += body.orEmpty()
            lastBody = body?.let { parseJson(it) as JsonVal.Obj }
            if (expired) return HttpReply(403, """{"ok":false,"error":"Session expired"}""")
            val key1 = ProtonFree.BUILTIN[0].publicKey
            val key2 = ProtonFree.BUILTIN[1].publicKey
            return when (path) {
                "/api/proton/session" -> HttpReply(200, """{"ok":true,"session":{"uid":"u-1","token":"t-1"}}""")
                "/api/proton/servers" -> HttpReply(200, """{"ok":true,"servers":[
                    {"id":"1","name":"NL-FREE#7","exitCountry":"NL","city":"Amsterdam","load":20,"entryIp":"10.2.0.7","publicKey":"$key1"},
                    {"id":"2","name":"US-FREE#9","exitCountry":"US","city":"New York","load":"35","entryIP":"10.2.0.9","PublicKey":"$key2"},
                    {"id":"3","name":"bad","exitCountry":"NL","entryIp":"","publicKey":"$key1"}]}""")
                "/api/proton/certificate" -> HttpReply(200, """{"ok":true,"SerialNumber":"77","ExpirationTime":1795000000}""")
                else -> HttpReply(404, """{"ok":false,"error":"not found"}""")
            }
        }
    }

    // ------------------------------------------------------------------ данные

    private companion object {
        /** Ключ Proton для модулей SRP (как в ProtonSrp) — для проверки verifyClearSigned напрямую. */
        val MODULUS_KEY: ByteArray = Crypto.unHex("16ead65d7c234de9aa8c3ec25e35d5c8a7f4a1fee7f42b662fcbfd7a79338201")

        val LOGICALS: String by lazy {
            val k = ProtonFree.BUILTIN.map { it.publicKey }
            """{"Code":1000,"LogicalServers":[
              {"Name":"NL-FREE#1","Tier":0,"Status":1,"ExitCountry":"NL","EntryCountry":"NL","City":"Amsterdam","Load":37,"Servers":[{"EntryIP":"10.1.0.1","X25519PublicKey":"${k[0]}","Status":1}]},
              {"Name":"NL-FREE#2","Tier":0,"Status":1,"ExitCountry":"NL","City":"Amsterdam","Load":12,"Servers":[{"EntryIP":"10.1.0.2","X25519PublicKey":"${k[1]}","Status":1}]},
              {"Name":"JP-FREE#3","Tier":0,"Status":1,"ExitCountry":"JP","City":"Tokyo","Load":5,"Servers":[{"EntryIP":"10.1.0.3","X25519PublicKey":"${k[2]}","Status":1}]},
              {"Name":"CH#10","Tier":2,"Status":1,"ExitCountry":"CH","City":"Zurich","Load":3,"Servers":[{"EntryIP":"10.1.0.4","X25519PublicKey":"${k[3]}","Status":1}]},
              {"Name":"PL-FREE#4","Tier":0,"Status":0,"ExitCountry":"PL","City":"Warsaw","Load":1,"Servers":[{"EntryIP":"10.1.0.5","X25519PublicKey":"${k[4]}","Status":1}]},
              {"Name":"RO-FREE#5","Tier":0,"Status":1,"ExitCountry":"RO","City":"Bucharest","Load":50,"Servers":[{"EntryIP":"10.1.0.6","X25519PublicKey":"short","Status":1},{"EntryIP":"10.1.0.7","X25519PublicKey":"${k[5]}","Status":1}]}
            ]}"""
        }

    /** go-srp (srp_test.go): модуль с подписью Proton и число сервера. */
    private val GO_SIGNED = "-----BEGIN PGP SIGNED MESSAGE-----\n" +
        "Hash: SHA256\n" +
        "\n" +
        "W2z5HBi8RvsfYzZTS7qBaUxxPhsfHJFZpu3Kd6s1JafNrCCH9rfvPLrfuqocxWPgWDH2R8neK7PkNvjxto9TStuY5z7jAzWRvFWN9cQhAKkdWgy0JY6ywVn22+HFpF4cYesHrqFIKUPDMSSIlWjBVmEJZ/MusD44ZT29xcPrOqeZvwtCffKtGAIjLYPZIEbZKnDM1Dm3q2K/xS5h+xdhjnndhsrkwm9U9oyA2wxzSXFL+pdfj2fOdRwuR5nW0J2NFrq3kJjkRmpO/Genq1UW+TEknIWAb6VzJJJA244K/H8cnSx2+nSNZO3bbo6Ys228ruV9A8m6DhxmS+bihN3ttQ==\n" +
        "-----BEGIN PGP SIGNATURE-----\n" +
        "Version: ProtonMail\n" +
        "Comment: https://protonmail.com\n" +
        "\n" +
        "wl4EARYIABAFAlwB1j0JEDUFhcTpUY8mAAD8CgEAnsFnF4cF0uSHKkXa1GIa\n" +
        "GO86yMV4zDZEZcDSJo0fgr8A/AlupGN9EdHlsrZLmTA1vhIx+rOgxdEff28N\n" +
        "kvNM7qIK\n" +
        "=q6vu\n" +
        "-----END PGP SIGNATURE-----"
    private const val GO_MODULUS = "W2z5HBi8RvsfYzZTS7qBaUxxPhsfHJFZpu3Kd6s1JafNrCCH9rfvPLrfuqocxWPgWDH2R8neK7PkNvjxto9TStuY5z7jAzWRvFWN" +
        "9cQhAKkdWgy0JY6ywVn22+HFpF4cYesHrqFIKUPDMSSIlWjBVmEJZ/MusD44ZT29xcPrOqeZvwtCffKtGAIjLYPZIEbZKnDM1Dm3" +
        "q2K/xS5h+xdhjnndhsrkwm9U9oyA2wxzSXFL+pdfj2fOdRwuR5nW0J2NFrq3kJjkRmpO/Genq1UW+TEknIWAb6VzJJJA244K/H8c" +
        "nSx2+nSNZO3bbo6Ys228ruV9A8m6DhxmS+bihN3ttQ=="
    private const val GO_SERVER_EPHEMERAL = "l13IQSVFBEV0ZZREuRQ4ZgP6OpGiIfIjbSDYQG3Yp39FkT2B/k3n1ZhwqrAdy+qvPPFq/le0b7UDtayoX4aOTJihoRvifas8Hr3i" +
        "cd9nAHqd0TUBbkZkT6Iy6UpzmirCXQtEhvGQIdOLuwvy+vZWh24G2ahBM75dAqwkP961EJMh67/I5PA5hJdQZjdPT5luCyVa7BS1" +
        "d9ZdmuR0/VCjUOdJbYjgtIH7BQoZs+KacjhUN8gybu+fsycvTK3eC+9mCN2Y6GdsuCMuR3pFB0RF9eKae7cA6RbJfF1bjm0nNfWL" +
        "XzgKguKBOeF3GEAsnCgK68q82/pq9etiUDizUlUBcA=="
    /** python-proton-core (modulus_instances): верный модуль и он же с подменённым текстом. */
    private val PY_SIGNED_OK = "-----BEGIN PGP SIGNED MESSAGE-----\n" +
        "Hash: SHA256\n" +
        "\n" +
        "091HBWnHlR+qphOhmi9ZrTWMnPT/jXqWzUh7F8CShuXIfHe5srT4y3BoBi85N89ceDhety3oVKoaS9sTQ6hVoRjjCulEuNQ5L6uN+9jG/f3/c3yVYjl6d9P1ktLsS21p3+2dQEAcNP0SQvMIdJPva1aBWsaoHKA3nzOp7pCIJHRw2Xx7T8AwzndW8r6KcNeZSLltj3FBIbWmKsaA8d3x+Db2D4M2Rngdf/eW2CQ39RlMvPdefMISs3jKSwduCJKCKbhYh6WSCjpgXrombuYIiMynfx38IibvSIURLOhXC9JKXY0k+bCPxZpt5iloe/11wK4ZSwuhYLEukD1ulvR1rw==\n" +
        "-----BEGIN PGP SIGNATURE-----\n" +
        "Version: ProtonMail\n" +
        "Comment: https://protonmail.com\n" +
        "\n" +
        "wl4EARYIABAFAlwB1jwJEDUFhcTpUY8mAABQpAD/VWjPiBcTZLU9t9GcLPtI\n" +
        "tv2iIdcvaOJg3hpl/XyEmAoA/0jNeiOMHl0Hpd4PoF/SCqmO/gDZDByy+t1n\n" +
        "5xsxCLEM\n" +
        "=a1KZ\n" +
        "-----END PGP SIGNATURE-----\n" +
        ""
    private val PY_SIGNED_BAD = "-----BEGIN PGP SIGNED MESSAGE-----\n" +
        "Hash: SHA256\n" +
        "\n" +
        "091HBWnHlR+qphOhmi9ZerfnPT/jXqWzUh7F8CShuXIfHe5srT4y3BoBi85N89ceDhety3oVKoaS9sTQ6hVoRjjCulEuNQ5L6uN+9jG/f3/c3yVYjl6d9P1ktLsS21p3+2dQEAcNP0SQvMIdJPva1aBWsaoHKA3nzOp7pCIJHRw2Xx7T8AwzndW8r6KcNeZSLltj3FBIbWmKsaA8d3x+Db2D4M2Rngdf/eW2CQ39RlMvPdefMISs3jKSwduCJKCKbhYh6WSCjpgXrombuYIiMynfx38IibvSIURLOhXC9JKXY0k+bCPxZpt5iloe/11wK4ZSwuhYLEukD1ulvR1rw==\n" +
        "-----BEGIN PGP SIGNATURE-----\n" +
        "Version: ProtonMail\n" +
        "Comment: https://protonmail.com\n" +
        "\n" +
        "wl4EARYIABAFAlwB1jwJEDUFhcTpUY8mAABQpAD/VWjPiBcTZLU9t9GcLPtI\n" +
        "tv2iIdcvaOJg3hpl/XyEmAoA/0jNeiOMHl0Hpd4PoF/SCqmO/gDZDByy+t1n\n" +
        "5xsxCLEM\n" +
        "=a1KZ\n" +
        "-----END PGP SIGNATURE-----\n" +
        ""
    /** Эталон python-proton-core (_pysrp.User, bcrypt из PyCA) для go-srp-набора: a = (7i + 3) mod 256, i = 0…31. */
    private const val REF_A = "kkbmsv1iWMF9WGaa4e/65Oj1/WnURyzGjE1sVb/cUAhAdcgGlZ+D/DfNe3PkE74t9tADCRMLLIoerScKwbUO4ZSiYL7EsYlxqsC7" +
        "6i/3sf+21LKEUN7Sbfvge31+cLR4Fy11KRzJ0n41Zkg0kYfC5C1fdQgzLtowVakBGklD1RTCAYJMcUd614pa91cx68i8fmdw0MGD" +
        "3S3HLVWsvhJox+/MmSun6kasEN9gHpbUObbg5b4TGzN2gW+Y/fdiUYm3WrDMDAjEUpLTGUOgI7VlmnjmnysnVMd7Xi9twF2Co+pa" +
        "RVhUG4fKZ1af4yMnMQRYcZGhsEsI55chfldrV1bBoQ=="
    private const val REF_M1 = "UTXTUH3MwW0PfNZWHNMOVrFVcg6xHVnS0m/p9Zw0dNe65YoMzq0TapAjzISMtfPAYmMT8qXyA2/kRK6bkXWJP02uoQeSp2DuR/HG" +
        "h4Y+H4gZn2U3QbrkWLqpJrLmQIq3b56F2n9aAmCEZtOSnWfmCPo2ihgA6I7aG+1RtpS8oqf8Yxi8uDzrlU5QnzmKgbm4s3obumqm" +
        "9yXuheqooDGGl1rrKHzlh4ioMeHFiQaFcXPAAIoufGkaZQCNVUfOd2VKKx8IgY3J2lsvcdsNd/+XiDMXlXjqn5R5WdPd8Ssj85BL" +
        "cGKVErpGECFGoJ7KhyNUdZRyG3dG+rUzailICmSKWg=="
    private const val REF_M2 = "h5RB44Xdmg14/LmJQXpWZ7IwY+SGjzdgIJ2/0kxR74+WaTbbEmdGRtIIVIWEJpq6X6/J44pjfZ4NJ4bwjIIISXtt2MhKzYI0qyNr" +
        "gt31k7gBVNo05bYi6sN7/6CCnrY6bG9ftw/2rXBowr5VX8GEPQ2moLmulyQ7niuJKfSq1gVU0d7Lkngzr74nOldGHm7uqM/kAkSL" +
        "YKN4fijZx3TFQQ9t+5NzhaVQIJuSgiuC4wGf/ohI02Hqk3a+sxdruWiRNhUbtg6hBU2XQ6ROqSqb81uq1kaxKJuarxBpam5wO5+7" +
        "XE19L8sol7v5g+fvMmJTRmYqN/wJDWsqxBKtGs/pfA=="
    /** Наборы python-proton-core (tests/testdata.py, srp_instances): пароль, соль, модуль (hex, little-endian), проверочное число. */
    private val VERIFIERS = listOf(
        listOf(
            "test", "Jl54BOeNTVl8Ng==",
            "1B64DF29DEDD8656245DB7EEE751442AD9CF1DAFC5A71A94076385C2FBF9FA7AD63E94CB365EC94EBA5BE131CF63D3930CAC" +
            "4755DE6D0625C24DD9A906551D216601222EBA94FF50C78B8B26DBF27636F4019F1700BA091287462CFFAD4F88B22D66BBF8" +
            "993090865E46D077ECF1DB78CB2AB0D036AD786B046B5D93BD473C95779914CB93F607FD7EFB9D34161951263CE794BF181F" +
            "B301EE444D170999EAFF9427CC4151BD91A755F1A184009C1418B16EEC7BFC2D5F88D42B38A4CC176B73EAB132FE37DD7E11" +
            "62DCA1D13E81A6F10F090DE77EB8CC492CD0B19BB6FC151F5B4AD56B14308D582D86471390C4223400AEE3D5E94C973FB997" +
            "D59F8A9F309F",
            "rhmWw1f4YsGq/cVgIePVSaot9Zj2kGNLxIgPytirz9/Nd8X8a28ZvFnWMQD0Jj8IgJPfO4EsI2nU5NuFqIbPI4OKs6s0nWvEHXkd" +
            "tzxT1n451MGThvZ6o7I+0Ofi1Dh6Rgkv3MxVL/6cNev3EDyhcvh5w9hUIOk5OfRDcFMKv8ht5OYI5a/++m1++x58LQyrrTsRMMIc" +
            "vDFXsjmMj4Ch3leP02S56cxDl6IQTosU+JcXGHsgNDf90aDnlsDFMGt6As1FSQm8bw0Yat+P02IZrXURQKsMLOKxdwb8xWySVymX" +
            "AyjcJ7Z9ZabGjCX6Lelo9Wiz0hIEGE7nnOeVwzJKaA==",
        ),
        listOf(
            "test", "AA54BOeNTVl8kg==",
            "1B64DF29DEDD8656245DB7EEE751442AD9CF1DAFC5A71A94076385C2FBF9FA7AD63E94CB365EC94EBA5BE131CF63D3930CAC" +
            "4755DE6D0625C24DD9A906551D216601222EBA94FF50C78B8B26DBF27636F4019F1700BA091287462CFFAD4F88B22D66BBF8" +
            "993090865E46D077ECF1DB78CB2AB0D036AD786B046B5D93BD473C95779914CB93F607FD7EFB9D34161951263CE794BF181F" +
            "B301EE444D170999EAFF9427CC4151BD91A755F1A184009C1418B16EEC7BFC2D5F88D42B38A4CC176B73EAB132FE37DD7E11" +
            "62DCA1D13E81A6F10F090DE77EB8CC492CD0B19BB6FC151F5B4AD56B14308D582D86471390C4223400AEE3D5E94C973FB997" +
            "D59F8A9F309F",
            "P3YwOj/6yNdZEe9sJoCtXKCvp/KUOtT8TwQXa1i410CgJJqmOaPjb460JoDl3a+2p5p3MXBQ+EvEYe2C9INuNDgQRSvLSAwAczJe" +
            "hPPl8vYYDfbda8kdKSI7iV3l4acA8oLyLSfZpdPNj+YQL/cjfBbHJssir+Fhm3wclSk0NvBjk5DgmDow3E9HzGqfcZTSqVDH7sSq" +
            "rfR8K1r7wFjm9WDkv27agUXdgJJtQidqsRBz7IAY00NtMFiyoFjh8qUqRkV5/RX2KdAbqQWDBfrIAaQ6GWLJ1T66RTq4IyOtdWD6" +
            "edJcRFnI8qNyNCjRAXrZrSNtPbo88ho79O9oOmEhmw==",
        ),
        listOf(
            "test", "Jl54BOeNTVl8AA==",
            "1B64DF29DEDD8656245DB7EEE751442AD9CF1DAFC5A71A94076385C2FBF9FA7AD63E94CB365EC94EBA5BE131CF63D3930CAC" +
            "4755DE6D0625C24DD9A906551D216601222EBA94FF50C78B8B26DBF27636F4019F1700BA091287462CFFAD4F88B22D66BBF8" +
            "993090865E46D077ECF1DB78CB2AB0D036AD786B046B5D93BD473C95779914CB93F607FD7EFB9D34161951263CE794BF181F" +
            "B301EE444D170999EAFF9427CC4151BD91A755F1A184009C1418B16EEC7BFC2D5F88D42B38A4CC176B73EAB132FE37DD7E11" +
            "62DCA1D13E81A6F10F090DE77EB8CC492CD0B19BB6FC151F5B4AD56B14308D582D86471390C4223400AEE3D5E94C973FB997" +
            "D59F8A9F309F",
            "s5KfuE1T7TtZDVvYCfOe/DTlfIw0eMUYc9oNMfDP9KduIhiczGEejjZnDo9ztrs+Cw/EBUSdfR8Hl1S0EOQPCpWCP/utUHU1mx0p" +
            "Ok/A5TlX0uug52nbuPLzICJKWHjwzTHbLntCrioMOh6ARyIOvi819dwpU42VrEPtQpxfNg2yMsfdRyq3Y08IRa4eZorDkM0idA3z" +
            "6loIQlUNH+kE+xq4rLMjFvn5+jujNWJhaGrM4xv+nosiGVpUYAyzbyQXtvYjSS79Z/37AfhKilhldOBk8SgF8/+rjX/3frOdPbGc" +
            "LIvlQsm39drnsJkoyR/fLnWeo23LSuc8ROPfmg2adA==",
        ),
        listOf(
            "Test Password With Spaces", "vSds4CNJcRFDog==",
            "530B86096FE2BA84CBD4518EE26386BFF353127BC9545537B55148374619392CB90C05EA35F0032583D9928EB6309642236D" +
            "F0D2EB00736BD8ACC349AE8094C97F330AEE0F493E76D1C092C98C61B880C942C54D9BA0AE2483AAD6A125E601685ECDD8BD" +
            "984C4F15EDDEC8D21F873C5CE2F47B16069D95023F6CAF2E4C25703DCF2E09C66E3927E19D4C6377D5C31F9EB2D881E820BC" +
            "B97747274C3F465DF3C17BFAC9C37DF6B255209697755AC068517A191364BF7D7A3A3B4321606A540590D70A1A0AEEA580B7" +
            "731B89D2D2FD4EC5D0AB65ED91757041C1E088ABC8C4BAC2B9B586DB036F035F04BC9ED6ADE0713CFCB85BAE556C4D3FA2A0" +
            "0B9CE55D04C4",
            "9TcpTx2TZ2oyPXMtQ+jn+rTIGxl6MpOMnazV5tGMlcNg00VujDzqsEi3O0pwB2r1x0T9H4UMi7/l+1qy0HlsdG53OTO4ij+z+gRu" +
            "A5xQAb/521g34q+/zJobBYuHISfV+LaHRgn1Z9VMYURkTNF66WyHMn1nd7swzGE+zWxBa0gN1d4HFW1h9VjLUOeOGGp4UwWIR2+p" +
            "SO50hJO6yGC8pQgEZhmyM0VfliWWzKsLMxRdfS4eHArvKsVOLN/IChSRKjeiDSSkOVGQZyNUoZDpg4AsGBLeXJovlbdjQoM/8pBy" +
            "JJpX71Ze6WZIltTRyjTYirYORDrLNCQr8DHpE6hLKA==",
        ),
        listOf(
            "PasswordThatIsLongerThan72CharsAndContainsSomeRandomStuffThatNoOneCaresAbout", "lSIG/btGTkKS4Q==",
            "C376377AC6C62697E211C0BE80DA3C5F7B7381AB92D94536B406594AD0C1BFE90A424E36085CD2F553F370ED863E72597210" +
            "DD94A19B0DA4257CD18EEDAF33A71E5BD7657DB25BE602F0430FE4762D9F6100DD319D7E5870DC0583D0782832E68E8A12C1" +
            "AA0B8018FB71D5F3C9AEB80208DE62CAB066FCC80E274F32199AA2193882E256A86E2B8993C7278CE470BA4A9B315AF33C02" +
            "9967EB96C470987F440F7CD4688072B98DC0B57686B580DE76BF10F3D277D24CAD012A83A98A834F90A22A29D113F272A38E" +
            "750DF3188ACFCADC8642B7F9847CE4F721EBF1D9105BE33CDC19A01080A9427F4F76B27D3FCF8926A5C4884C42D1B6D052C2" +
            "F744452283DB",
            "Ft8p5GMgowgwSRb2jJ7uoTkvptOQmNqH+Aov/Lawsc5vbaBIIoIwnF03jiGVEEO9kVVTZG/+5zQorvY5voZJrgJev+I/LR0WbzIY" +
            "+Tqm7BbVRSARc7jkTFHXYFFiasuOR5myTDPyctxyfTQzAwGX7MccC82nWUuPn/yWsAgqppvVatC+QUilEKALvHqjnupJoLay0Zfm" +
            "LOkV8eeXUQFkOcRzGFYtkCSD5aCQYBMZYkuLm/4rUEQsYQ9GyluGDNfYm0kDUy9oq0ujJdDciSvFAw3arIANsuEDmGg/eo0/1iZL" +
            "ywcZPzS20Cu07KIgQ+Ct2HemCmgFDJKQ2CBnW+HvFQ==",
        ),
    )
    }
}
