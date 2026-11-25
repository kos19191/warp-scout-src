package dev.warpscout.core.proton

import dev.warpscout.core.crypto.Crypto
import dev.warpscout.core.json.JsonVal
import dev.warpscout.core.json.parseJson
import dev.warpscout.core.lists.ProtonFree
import java.io.IOException
import java.net.URLEncoder
import java.security.MessageDigest

/** Ответ HTTP: код и тело. */
class HttpReply(val status: Int, val body: String)

/**
 * HTTP для Proton и стороннего сервиса: на телефоне — HttpURLConnection (через туннель, если он
 * поднят), в самопроверке — поддельный сервер. Нет связи — IOException.
 */
fun interface ProtonHttp {
    fun send(method: String, url: String, headers: Map<String, String>, body: String?): HttpReply

    /** Двоичный GET — для DNS-over-HTTPS обходного пути (см. [ProtonAlt]); null — ответа нет. */
    fun getBytes(url: String, headers: Map<String, String>): ByteArray? = null

    /**
     * Запрос к посреднику Proton (обходной путь, см. [ProtonAlt]): сертификат сверяется по закреплённым
     * ключам [pins], имя — нет. Не умеет — IOException.
     */
    fun sendPinned(method: String, url: String, headers: Map<String, String>, body: String?, pins: List<String>): HttpReply =
        throw IOException("обходной путь Proton здесь не поддержан")
}

/** Что пошло не так — с причиной, по которой экран решает, что показать. */
class ProtonException(
    message: String,
    val code: Int = 0,
    val reason: Reason = Reason.API,
    /** «Я не робот»: токен и способы проверки из ответа Proton (код 9001). */
    val hvToken: String = "",
    val hvMethods: List<String> = emptyList(),
) : Exception(message) {
    enum class Reason { NETWORK, API, HUMAN_VERIFICATION, WRONG_PASSWORD, TWO_FACTOR_WRONG, APP_VERSION, UNSUPPORTED, BAD_SERVER }
}

/**
 * Устройство для «кадра» защиты Proton от злоупотреблений — поля те же, что шлёт приложение Proton
 * для Android (ChallengeFrame.Device в protoncore_android): язык, часовой пояс, хеш модели, регион,
 * размер шрифта, объём памяти, тёмная тема, клавиатуры.
 */
data class ProtonDevice(
    val model: String,
    val brand: String,
    val device: String,
    val androidRelease: String,
    val language: String,
    val region: String,
    val timezone: String,
    /** Минуты, со знаком как в protoncore: −(смещение пояса), для Москвы −180. */
    val timezoneOffset: Int,
    val fontScale: String,
    val storageGb: Double,
    val darkMode: Boolean,
    val keyboards: List<String>,
) {
    /** deviceName — «скользящий хеш» строки «модель/бренд устройство», как deviceModelName() в protoncore. */
    val nameHash: Long
        get() {
            var answer = 0L
            var coefficient = 0L
            for (code in "$model/$brand $device".toByteArray(Charsets.UTF_8)) {
                coefficient = if (coefficient == 0L) 1L else coefficient * 7L % 100000007L
                answer += code * coefficient
            }
            return answer
        }

    fun frame(): JsonVal.Obj = JsonVal.obj(
        "v" to JsonVal.str(ProtonApi.CHALLENGE_VERSION),
        "appLang" to JsonVal.str(language),
        "timezone" to JsonVal.str(timezone),
        "deviceName" to JsonVal.num(nameHash),
        "regionCode" to JsonVal.str(region),
        "timezoneOffset" to JsonVal.num(timezoneOffset),
        "isJailbreak" to JsonVal.bool(false),
        "preferredContentSize" to JsonVal.str(fontScale),
        "storageCapacity" to JsonVal.num(storageGb),
        "isDarkmodeOn" to JsonVal.bool(darkMode),
        "keyboards" to JsonVal.arr(keyboards.map { JsonVal.str(it) }),
    )
}

/**
 * Клиент API Proton VPN для второго выхода (с 1.10.44-beta5): вход в свой аккаунт (SRP, второй
 * фактор, проверка «я не робот»), режим без аккаунта, бесплатные серверы и ключ WireGuard на год.
 *
 * Говорит как приложение Proton для Android (github.com/ProtonVPN/android-app, protoncore_android):
 * те же адреса (vpn-api.proton.me, запасной api.protonvpn.ch), заголовки и «кадр» устройства. Ключ
 * регистрируется как постоянный («persistent») — так же, как «WireGuard configuration» в кабинете
 * Proton: живёт год и не зависит от сессии, поэтому после входа сессию закрываем, пароль и токены
 * не храним.
 *
 * Из России адреса API Proton закрыты (TCP 443 не открывается) — запросы должны идти через туннель
 * WARP; это решает приложение (WarpScout сам всегда в туннеле). Но с московской площадки WARP их режут
 * и через туннель (25.11: «Unable to resolve host» при работающем туннеле) — тогда, как приложения
 * Proton, идём обходным путём: посредники Proton по TXT-записи через DNS-over-HTTPS ([ProtonAlt], с 1.10.46).
 */
class ProtonApi(
    private val http: ProtonHttp,
    private val device: ProtonDevice,
    appVersion: String = APP_VERSION,
    private val hosts: List<String> = HOSTS,
    private val log: (String) -> Unit = {},
    /** Версия приложения Proton новее нашей, когда API отвечает «версия устарела» (5003): берём с GitHub. */
    private val newerVersion: (() -> String?)? = null,
    /** Оба адреса API молчат — обходной путь Proton (посредники, см. [ProtonAlt]). */
    private val altRouting: Boolean = true,
) {
    /** Версия приложения Proton, от имени которого говорим («5.21.57.0»). */
    var appVersion: String = appVersion
        private set

    /** Решённая проверка «я не робот» (токен, способ): уходит заголовками, пока шаг не пройдёт. */
    var humanVerification: Pair<String, String>? = null

    /** Хост, который ответил последним, — с него и начинаем. */
    private var preferred: String? = null

    /** Посредник Proton (обходной путь), который ответил последним, — тогда начинаем с него. */
    private var altPreferred: String? = null

    /** Найденные посредники: DoH спрашиваем один раз на клиента (не нашли — спросим в следующий раз). */
    private var altCache: List<String>? = null

    private val altAnnounced = HashSet<String>()

    data class Session(
        val uid: String,
        val accessToken: String,
        val refreshToken: String,
        val scopes: List<String>,
        /** Включён второй фактор (из ответа на вход). */
        val twoFactor: Boolean = false,
        /** Второй фактор можно ввести кодом из приложения-аутентификатора. */
        val totp: Boolean = true,
    ) {
        val hasVpn: Boolean get() = "vpn" in scopes
        val needsTwoFactor: Boolean get() = !hasVpn && (twoFactor || "twofactor" in scopes)
    }

    /** Бесплатный сервер с загрузкой (0…100 %, −1 — неизвестно). */
    class FreeServer(val server: ProtonFree.Server, val load: Int)

    class Certificate(val expiresAt: Long, val serial: String)

    companion object {
        val HOSTS = listOf("https://vpn-api.proton.me", "https://api.protonvpn.ch")

        /** Свежая версия приложения Proton для Android на 19.11.2026 (тег 5.21.57.0 на GitHub). */
        const val APP_VERSION = "5.21.57.0"
        const val CHALLENGE_VERSION = "2.0.7"
        const val FRAME_KEY = "vpn-android-v4-challenge-0"
        const val HV_URL = "https://verify.proton.me"

        /** Теги приложения Proton на GitHub: оттуда берём новую версию, если API скажет «устарела». */
        const val TAGS_URL = "https://api.github.com/repos/ProtonVPN/android-app/tags?per_page=20"

        const val CODE_OK = 1000
        const val CODE_MULTI = 1001
        const val CODE_HV = 9001
        const val CODE_WRONG_PASSWORD = 8002
        val CODES_APP_VERSION = setOf(5001, 5002, 5003, 5005, 5099)

        private val VERSION_RE = Regex("""\d+\.\d+\.\d+(\.\d+)?""")

        /** Самая новая версия из ответа GitHub со списком тегов. */
        fun newestVersion(tagsJson: String): String? {
            val arr = runCatching { parseJson(tagsJson) }.getOrNull() as? JsonVal.Arr ?: return null
            val names = arr.items.mapNotNull { (it as? JsonVal.Obj)?.str("name")?.removePrefix("v") }.filter { VERSION_RE.matches(it) }
            return names.maxWithOrNull { a, b -> compareVersions(a, b) }
        }

        fun compareVersions(a: String, b: String): Int {
            val pa = a.split('.').map { it.toIntOrNull() ?: 0 }
            val pb = b.split('.').map { it.toIntOrNull() ?: 0 }
            for (i in 0 until maxOf(pa.size, pb.size)) {
                val d = pa.getOrElse(i) { 0 } - pb.getOrElse(i) { 0 }
                if (d != 0) return d
            }
            return 0
        }

        /** Страница проверки «я не робот» — та же, что открывает приложение Proton (HV3). */
        fun hvUrl(token: String, methods: List<String>, dark: Boolean, locale: String): String {
            val known = methods.filter { it in setOf("captcha", "email", "sms") }.ifEmpty { listOf("captcha") }
            val params = listOf(
                "embed" to "true",
                "token" to token,
                "methods" to known.joinToString(","),
                "theme" to if (dark) "1" else "2",
                "vpn" to "true",
                "locale" to locale,
            )
            return HV_URL + "/?" + params.joinToString("&") { (k, v) -> k + "=" + URLEncoder.encode(v, "UTF-8") }
        }

        /**
         * Ответ страницы проверки: «HUMAN_VERIFICATION_SUCCESS» → (токен, способ). Понимает и
         * сообщение самой капчи («pm_captcha»: токен уже вида «вызов:ответ»). Иначе null.
         */
        fun hvResult(message: String): Pair<String, String>? {
            val obj = runCatching { parseJson(message) }.getOrNull() as? JsonVal.Obj ?: return null
            return when (obj.str("type")) {
                "HUMAN_VERIFICATION_SUCCESS" -> {
                    val payload = obj.obj("payload") ?: return null
                    val token = payload.str("token")?.takeIf { it.isNotBlank() } ?: return null
                    token to (payload.str("type")?.takeIf { it.isNotBlank() } ?: "captcha")
                }
                "pm_captcha", "proton_captcha" -> obj.str("token")?.takeIf { it.isNotBlank() }?.let { it to "captcha" }
                else -> null
            }
        }

        /** Бесплатные серверы из /vpn/logicals: уровень 0, включённые, с адресом и ключом WireGuard. */
        fun parseLogicals(obj: JsonVal.Obj): List<FreeServer> {
            val out = LinkedHashMap<String, FreeServer>()
            for (item in obj.arr("LogicalServers")?.items.orEmpty()) {
                val logical = item as? JsonVal.Obj ?: continue
                if (logical.num("Tier")?.toInt() != 0) continue
                if ((logical.num("Status") ?: 1.0).toInt() != 1) continue
                val name = logical.str("Name").orEmpty()
                val country = logical.str("ExitCountry").orEmpty().ifBlank { logical.str("EntryCountry").orEmpty() }
                val city = logical.str("City").orEmpty()
                val load = logical.num("Load")?.toInt() ?: -1
                for (p in logical.arr("Servers")?.items.orEmpty()) {
                    val physical = p as? JsonVal.Obj ?: continue
                    if ((physical.num("Status") ?: 1.0).toInt() != 1) continue
                    val ip = physical.str("EntryIP").orEmpty().trim()
                    val key = physical.str("X25519PublicKey").orEmpty().trim()
                    if (ip.isBlank() || ip.contains(':') || key.length != 44) continue
                    out.putIfAbsent("$ip|$key", FreeServer(ProtonFree.Server(name, country, city, ip, key), load))
                    // Физические серверы одного логического — одна площадка: хватит первого живого.
                    break
                }
            }
            return out.values.toList()
        }

        /** Строка в одну строку для комментария конфига. */
        private fun oneLine(s: String): String = s.replace('\r', ' ').replace('\n', ' ').trim()
    }

    // ------------------------------------------------------------------ шаги

    /** Сессия без входа — носитель для входа и режима без аккаунта (requestSession в protoncore). */
    fun anonymousSession(): Session = sessionOf(call("POST", "/auth/v4/sessions", JsonVal.obj("Payload" to payload()), null))

    /**
     * Вход по логину и паролю (SRP, пароль на сервер не уходит). Нужен второй фактор — у сессии
     * [Session.needsTwoFactor], дальше [submitTwoFactor].
     */
    fun login(username: String, password: ByteArray): Session {
        val carrier = try {
            anonymousSession()
        } catch (e: ProtonException) {
            if (e.reason == ProtonException.Reason.HUMAN_VERIFICATION || e.reason == ProtonException.Reason.NETWORK) throw e
            log("Proton: сессия-носитель не выдана (${e.message}) — входим без неё")
            null
        }
        val info = call("POST", "/auth/v4/info", JsonVal.obj("Username" to JsonVal.str(username), "Intent" to JsonVal.str("Proton")), carrier)
        val version = info.num("Version")?.toInt() ?: 0
        if (version != 3 && version != 4) {
            throw ProtonException(
                "пароль аккаунта записан у Proton по старой схеме (версия $version) — войдите один раз на account.proton.me и повторите",
                reason = ProtonException.Reason.UNSUPPORTED,
            )
        }
        fun field(name: String): String = info.str(name)?.takeIf { it.isNotBlank() }
            ?: throw ProtonException("в ответе Proton нет поля $name", reason = ProtonException.Reason.BAD_SERVER)
        val proofs = try {
            val modulus = ProtonSrp.readSignedModulus(field("Modulus"))
            ProtonSrp.proofs(password, Crypto.unBase64(field("Salt")), modulus, Crypto.unBase64(field("ServerEphemeral")))
        } catch (e: SrpException) {
            throw ProtonException(e.message ?: "SRP", reason = ProtonException.Reason.BAD_SERVER)
        }
        val obj = call(
            "POST", "/auth/v4",
            JsonVal.obj(
                "Username" to JsonVal.str(username),
                "ClientEphemeral" to JsonVal.str(Crypto.base64(proofs.clientEphemeral)),
                "ClientProof" to JsonVal.str(Crypto.base64(proofs.clientProof)),
                "SRPSession" to JsonVal.str(field("SRPSession")),
                "Payload" to payload(),
            ),
            carrier,
        )
        val serverProof = obj.str("ServerProof")?.let { runCatching { Crypto.unBase64(it) }.getOrNull() }
        if (serverProof == null || !MessageDigest.isEqual(serverProof, proofs.expectedServerProof)) {
            throw ProtonException("сервер не подтвердил пароль — это не Proton или ответ подменён", reason = ProtonException.Reason.BAD_SERVER)
        }
        return sessionOf(obj)
    }

    /** Второй фактор: код из приложения-аутентификатора (6 цифр). */
    fun submitTwoFactor(session: Session, code: String): Session {
        val obj = try {
            call("POST", "/auth/v4/2fa", JsonVal.obj("TwoFactorCode" to JsonVal.str(code.trim())), session)
        } catch (e: ProtonException) {
            if (e.reason == ProtonException.Reason.API || e.reason == ProtonException.Reason.WRONG_PASSWORD) {
                throw ProtonException(e.message ?: "код не подошёл", e.code, ProtonException.Reason.TWO_FACTOR_WRONG)
            }
            throw e
        }
        val scopes = scopesOf(obj)
        return session.copy(scopes = scopes.ifEmpty { session.scopes + "vpn" }, twoFactor = false)
    }

    /**
     * Без аккаунта — как «без регистрации» в приложении Proton для Android: сессия-носитель, затем
     * /auth/v4/credentialless. Ответ на прошлую попытку потерялся («Session already tied») — берём
     * новую сессию и повторяем один раз.
     */
    fun withoutAccount(): Session {
        fun once(): Session {
            val carrier = anonymousSession()
            val s = sessionOf(call("POST", "/auth/v4/credentialless", JsonVal.obj("Payload" to payload()), carrier))
            if (!s.hasVpn) {
                throw ProtonException("Proton выдал сессию без доступа к VPN (${s.scopes.joinToString(",")})", reason = ProtonException.Reason.API)
            }
            return s
        }
        return try {
            once()
        } catch (e: ProtonException) {
            if (e.message?.contains("already tied", ignoreCase = true) != true) throw e
            log("Proton: сессия уже привязана (ответ на прошлую попытку потерялся) — повторяю с новой")
            once()
        }
    }

    /** Бесплатные серверы с загрузкой. Старый адрес списка — запасной. */
    fun freeServers(session: Session): List<FreeServer> {
        var last: ProtonException? = null
        for (path in listOf("/vpn/v1/logicals?Tier=0&WithState=true", "/vpn/logicals?Tier=0")) {
            try {
                return parseLogicals(call("GET", path, null, session))
            } catch (e: ProtonException) {
                if (e.reason == ProtonException.Reason.NETWORK || e.reason == ProtonException.Reason.HUMAN_VERIFICATION) throw e
                log("Proton: список серверов ($path) — ${e.message}")
                last = e
            }
        }
        throw last ?: ProtonException("список серверов не получен")
    }

    /**
     * Регистрирует ключ: постоянный, как конфиг из кабинета Proton — год, независимо от сессии.
     * [deviceName] Proton покажет в списке конфигураций аккаунта.
     */
    fun registerKey(session: Session, keys: ProtonKeys.Pair, deviceName: String): Certificate {
        val obj = call(
            "POST", "/vpn/v1/certificate",
            JsonVal.obj(
                "ClientPublicKey" to JsonVal.str(keys.pem),
                "Mode" to JsonVal.str("persistent"),
                "DeviceName" to JsonVal.str(oneLine(deviceName).take(60)),
            ),
            session,
        )
        val exp = obj.num("ExpirationTime")?.toLong()
            ?: throw ProtonException("Proton не сообщил срок ключа", reason = ProtonException.Reason.BAD_SERVER)
        val serial = when (val s = obj.fields["SerialNumber"]) {
            is JsonVal.Str -> s.v
            is JsonVal.Num -> s.raw
            else -> ""
        }
        return Certificate(exp * 1000L, serial)
    }

    /** Закрыть сессию (ключ остаётся: он постоянный). Ошибки не важны. */
    fun logout(session: Session) {
        runCatching { call("DELETE", "/auth/v4", null, session) }
    }

    // ------------------------------------------------------------------ транспорт

    private fun payload(): JsonVal.Obj = JsonVal.obj(FRAME_KEY to device.frame())

    private fun scopesOf(obj: JsonVal.Obj): List<String> =
        obj.arr("Scopes")?.items?.mapNotNull { (it as? JsonVal.Str)?.v }
            ?: obj.str("Scope")?.split(' ')?.filter { it.isNotBlank() }
            ?: emptyList()

    private fun sessionOf(obj: JsonVal.Obj): Session {
        val uid = obj.str("UID")?.takeIf { it.isNotBlank() }
            ?: throw ProtonException("в ответе Proton нет UID", reason = ProtonException.Reason.BAD_SERVER)
        val access = obj.str("AccessToken")?.takeIf { it.isNotBlank() }
            ?: throw ProtonException("в ответе Proton нет токена", reason = ProtonException.Reason.BAD_SERVER)
        val twoFa = obj.obj("2FA")
        return Session(
            uid = uid,
            accessToken = access,
            refreshToken = obj.str("RefreshToken").orEmpty(),
            scopes = scopesOf(obj),
            twoFactor = (twoFa?.num("Enabled") ?: 0.0) != 0.0,
            totp = twoFa == null || (twoFa.num("TOTP") ?: 1.0) != 0.0,
        )
    }

    private fun headers(session: Session?, json: Boolean): Map<String, String> {
        val h = LinkedHashMap<String, String>()
        h["x-pm-appversion"] = "android-vpn@$appVersion"
        h["x-pm-apiversion"] = "3"
        h["Accept"] = "application/vnd.protonmail.v1+json"
        h["User-Agent"] = "ProtonVPN/$appVersion (Android ${device.androidRelease}; ${device.brand} ${device.model})"
        if (json) h["Content-Type"] = "application/json;charset=utf-8"
        if (session != null) {
            h["x-pm-uid"] = session.uid
            h["Authorization"] = "Bearer ${session.accessToken}"
        }
        humanVerification?.let { (token, type) ->
            h["x-pm-human-verification-token"] = token
            h["x-pm-human-verification-token-type"] = type
        }
        return h
    }

    private fun call(method: String, path: String, body: JsonVal.Obj?, session: Session?): JsonVal.Obj {
        var versionRetried = false
        while (true) {
            val reply = send(method, path, body, session)
            val obj = runCatching { parseJson(reply.body) }.getOrNull() as? JsonVal.Obj
                ?: throw ProtonException("Proton ответил не JSON (HTTP ${reply.status})", reason = ProtonException.Reason.API)
            val code = obj.num("Code")?.toInt() ?: 0
            if (code == CODE_OK || code == CODE_MULTI) return obj
            val provider = newerVersion
            if (code in CODES_APP_VERSION && !versionRetried && provider != null) {
                versionRetried = true
                val newer = runCatching { provider() }.getOrNull()
                if (newer != null && compareVersions(newer, appVersion) > 0) {
                    log("Proton: версия $appVersion устарела — говорю как $newer")
                    appVersion = newer
                    continue
                }
            }
            throw errorOf(obj, code, reply.status)
        }
    }

    private fun errorOf(obj: JsonVal.Obj, code: Int, status: Int): ProtonException {
        val text = obj.str("Error").orEmpty().ifBlank { "HTTP $status" }
        return when (code) {
            CODE_HV -> {
                val d = obj.obj("Details")
                ProtonException(
                    "Proton просит подтвердить, что вы не робот",
                    code, ProtonException.Reason.HUMAN_VERIFICATION,
                    hvToken = d?.str("HumanVerificationToken").orEmpty(),
                    hvMethods = d?.arr("HumanVerificationMethods")?.items?.mapNotNull { (it as? JsonVal.Str)?.v }.orEmpty(),
                )
            }
            CODE_WRONG_PASSWORD -> ProtonException("неверный логин или пароль ($text)", code, ProtonException.Reason.WRONG_PASSWORD)
            in CODES_APP_VERSION -> ProtonException("Proton не принимает версию приложения $appVersion ($text)", code, ProtonException.Reason.APP_VERSION)
            else -> ProtonException("$text (код $code)", code, ProtonException.Reason.API)
        }
    }

    private fun send(method: String, path: String, body: JsonVal.Obj?, session: Session?): HttpReply {
        val failures = ArrayList<String>()
        // Посредник уже выручал — сразу к нему: прямые адреса в этой сети закрыты, и каждый заход на них —
        // лишние секунды (а при «чёрной дыре» и 12 с ожидания соединения).
        altPreferred?.let { alt ->
            try {
                return sendAlt(alt, method, path, body, session)
            } catch (e: IOException) {
                failures += "посредник " + alt.substringAfter("://") + ": " + (e.message ?: e.javaClass.simpleName)
                altPreferred = null
            }
        }
        val order = hosts.sortedByDescending { it == preferred }
        for (host in order) {
            try {
                val reply = http.send(method, host + path, headers(session, body != null), body?.render())
                preferred = host
                return reply
            } catch (e: IOException) {
                failures += host.substringAfter("://") + ": " + (e.message ?: e.javaClass.simpleName)
            }
        }
        if (altRouting) {
            for (alt in altHosts(failures)) {
                try {
                    val reply = sendAlt(alt, method, path, body, session)
                    if (altAnnounced.add(alt)) {
                        log("Proton: напрямую не отвечает — ответил посредник Proton ${alt.substringAfter("://")} (обходной путь)")
                    }
                    altPreferred = alt
                    return reply
                } catch (e: IOException) {
                    failures += "посредник " + alt.substringAfter("://") + ": " + (e.message ?: e.javaClass.simpleName)
                }
            }
        }
        throw ProtonException(
            "Proton не отвечает (${failures.joinToString("; ")})",
            reason = ProtonException.Reason.NETWORK,
        )
    }

    private fun sendAlt(alt: String, method: String, path: String, body: JsonVal.Obj?, session: Session?): HttpReply =
        http.sendPinned(method, alt + path, headers(session, body != null), body?.render(), ProtonAlt.PINS)

    /**
     * Адреса посредников Proton по TXT-записи (см. [ProtonAlt]) через DNS-over-HTTPS — по очереди у
     * [ProtonAlt.DOH]. Найденные запоминаем на всё время работы с этим клиентом.
     */
    private fun altHosts(failures: MutableList<String>): List<String> {
        altCache?.let { return it }
        val primary = hosts.firstOrNull()?.substringAfter("://")?.substringBefore('/') ?: return emptyList()
        val query = ProtonAlt.base64Url(ProtonAlt.encodeQuery(ProtonAlt.queryName(primary)))
        for (doh in ProtonAlt.DOH) {
            val name = doh.substringAfter("://").substringBefore('/')
            val bytes = try {
                http.getBytes("$doh?dns=$query", mapOf("Accept" to "application/dns-message"))
            } catch (e: IOException) {
                failures += "DoH $name: " + (e.message ?: e.javaClass.simpleName)
                continue
            }
            if (bytes == null) {
                failures += "DoH $name: нет ответа"
                continue
            }
            val found = ProtonAlt.txtRecords(bytes).mapNotNull { ProtonAlt.hostOf(it) }.distinct()
            if (found.isEmpty()) {
                failures += "DoH $name: посредников нет"
                continue
            }
            log("Proton: обходной путь — посредники от $name: ${found.joinToString(", ")}")
            return found.map { "https://$it" }.also { altCache = it }
        }
        return emptyList()
    }
}

/**
 * Сторонний сервис proton-generation (warp-api.cfd, зеркало api-proton.workers.dev) — запасной
 * путь «без аккаунта», по просьбе 25.11. Им пользуется сайт proton-generation.github.io: браузеру
 * нельзя ходить в API Proton напрямую, и сервис делает это за него — держит сессию Proton у себя.
 *
 * Ключ создаётся на телефоне, сервису уходит только открытая часть (как и со страницы сайта).
 * Сервис видит адрес, с которого пришли, и может исчезнуть или ввести ограничения в любой день, а
 * аккаунт Proton под ним — временный: удалят — перестанет работать и ключ.
 */
class ProtonService(
    private val http: ProtonHttp,
    private val bases: List<String> = BASES,
    private val userAgent: String = "WarpScout",
    private val log: (String) -> Unit = {},
) {
    companion object {
        val BASES = listOf("https://warp-api.cfd", "https://www.api-proton.workers.dev")
        const val SITE = "https://proton-generation.github.io"

        private fun str(o: JsonVal.Obj, vararg keys: String): String =
            keys.firstNotNullOfOrNull { k -> (o.fields[k] as? JsonVal.Str)?.v?.takeIf { it.isNotBlank() } }.orEmpty()

        private fun num(o: JsonVal.Obj, vararg keys: String): Double? =
            keys.firstNotNullOfOrNull { k ->
                when (val v = o.fields[k]) {
                    is JsonVal.Num -> v.v
                    is JsonVal.Str -> v.v.toDoubleOrNull()
                    else -> null
                }
            }

        /** Серверы из ответа сервиса: имя, страна, город, загрузка, адрес и ключ — как у сайта. */
        fun parseServers(obj: JsonVal.Obj): List<ProtonApi.FreeServer> {
            val out = LinkedHashMap<String, ProtonApi.FreeServer>()
            for (item in obj.arr("servers")?.items.orEmpty()) {
                val s = item as? JsonVal.Obj ?: continue
                val ip = str(s, "entryIp", "entryIP", "EntryIP", "entry_ip")
                val key = str(s, "publicKey", "PublicKey", "X25519PublicKey", "public_key")
                if (ip.isBlank() || ip.contains(':') || key.length != 44) continue
                val server = ProtonFree.Server(
                    name = str(s, "name", "Name"),
                    country = str(s, "exitCountry", "ExitCountry", "country"),
                    city = str(s, "city", "City"),
                    ip = ip,
                    publicKey = key,
                )
                out.putIfAbsent("$ip|$key", ProtonApi.FreeServer(server, num(s, "load", "Load")?.toInt() ?: -1))
            }
            return out.values.toList()
        }

        /** Срок ключа, если сервис его передал (ExpirationTime Proton, в секундах). */
        fun expirationOf(obj: JsonVal.Obj): Long? {
            num(obj, "ExpirationTime", "expirationTime")?.let { return it.toLong() * 1000L }
            for (v in obj.fields.values) {
                val inner = v as? JsonVal.Obj ?: continue
                num(inner, "ExpirationTime", "expirationTime")?.let { return it.toLong() * 1000L }
            }
            return null
        }
    }

    /** Адрес сервиса, выдавший сессию: дальше — только он (сессия живёт у него). */
    private var base: String? = null

    fun session(): JsonVal {
        val failures = ArrayList<String>()
        for (b in bases) {
            try {
                val obj = post(b, "/api/proton/session", JsonVal.obj())
                val session = obj.fields["session"] ?: throw ProtonException("сервис не выдал сессию", reason = ProtonException.Reason.BAD_SERVER)
                base = b
                return session
            } catch (e: IOException) {
                failures += b.substringAfter("://") + ": " + (e.message ?: e.javaClass.simpleName)
            }
        }
        throw ProtonException("сторонний сервис не отвечает (${failures.joinToString("; ")})", reason = ProtonException.Reason.NETWORK)
    }

    fun servers(session: JsonVal): List<ProtonApi.FreeServer> = parseServers(postSame("/api/proton/servers", JsonVal.obj("session" to session)))

    /** Регистрирует открытую часть ключа; срок — если сервис его сообщил. */
    fun register(session: JsonVal, keys: ProtonKeys.Pair): Long? = expirationOf(
        postSame(
            "/api/proton/certificate",
            JsonVal.obj("session" to session, "clientPublicKey" to JsonVal.str(keys.pem), "persistent" to JsonVal.bool(true)),
        )
    )

    private fun postSame(path: String, body: JsonVal.Obj): JsonVal.Obj {
        val b = base ?: throw ProtonException("сначала сессия сервиса", reason = ProtonException.Reason.API)
        return try {
            post(b, path, body)
        } catch (e: IOException) {
            throw ProtonException("сторонний сервис не отвечает (${e.message ?: e.javaClass.simpleName})", reason = ProtonException.Reason.NETWORK)
        }
    }

    private fun post(b: String, path: String, body: JsonVal.Obj): JsonVal.Obj {
        val reply = http.send(
            "POST", b + path,
            linkedMapOf("Content-Type" to "application/json", "Accept" to "application/json", "User-Agent" to userAgent),
            body.render(),
        )
        val obj = runCatching { parseJson(reply.body) }.getOrNull() as? JsonVal.Obj
            ?: throw ProtonException("сервис ответил не JSON (HTTP ${reply.status})", reason = ProtonException.Reason.API)
        if (obj.bool("ok") != true) {
            val text = obj.str("error").orEmpty().ifBlank { "HTTP ${reply.status}" }
            log("сторонний сервис: $path — $text")
            throw ProtonException("сервис: $text", reason = ProtonException.Reason.API)
        }
        return obj
    }
}

/** Выбор сервера и страны для экрана (с 1.10.44-beta5). */
object ProtonChoice {

    class Country(val code: String, val count: Int, val minLoad: Int)

    /** Страны по удалённости от России (как в ProtonFree.NEAR), с числом серверов и наименьшей загрузкой. */
    fun countries(servers: List<ProtonApi.FreeServer>): List<Country> {
        val by = servers.groupBy { it.server.code }
        val order = ProtonFree.NEAR.filter { it in by } + by.keys.filter { it !in ProtonFree.NEAR }.sorted()
        return order.map { code ->
            val list = by.getValue(code)
            Country(code, list.size, list.map { it.load }.filter { it >= 0 }.minOrNull() ?: -1)
        }
    }

    /** Серверы страны — наименее загруженные первыми (неизвестная загрузка — в конце). */
    fun inCountry(servers: List<ProtonApi.FreeServer>, code: String): List<ProtonApi.FreeServer> =
        servers.filter { it.server.code == code }.sortedWith(compareBy({ if (it.load < 0) 1000 else it.load }, { it.server.name }))

    /**
     * Сервер для конфига: выбранный; иначе наименее загруженный в стране; при «любой стране» — из
     * ближних (Европа), затем любой.
     */
    fun best(servers: List<ProtonApi.FreeServer>, country: String): ProtonApi.FreeServer? {
        if (country.isNotBlank()) inCountry(servers, country).firstOrNull()?.let { return it }
        val near = servers.filter { it.server.code in ProtonFree.NEAR_GROUP }
        return (near.ifEmpty { servers }).minWithOrNull(compareBy({ if (it.load < 0) 1000 else it.load }, { it.server.name }))
    }
}
