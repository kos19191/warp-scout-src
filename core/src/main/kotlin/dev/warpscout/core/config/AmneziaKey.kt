package dev.warpscout.core.config

import dev.warpscout.core.json.JsonVal
import dev.warpscout.core.json.parseJson

/**
 * Ключ AmneziaVPN «vpn://…» → текст конфига для второго выхода (с 1.10.49-beta1).
 *
 * Как его собирает AmneziaVPN (amnezia-client, exportController.cpp): `vpn://` + base64url без «=»
 * от qCompress(JSON) — 4 байта длины (big-endian), за ними поток zlib. В JSON — сервер: containers[],
 * defaultContainer, dns1, dns2, description, hostName. У контейнера `amnezia-awg` параметры лежат в
 * объекте "awg", у `amnezia-wireguard` — в "wireguard"; конфиг подключения — JSON-строкой в
 * "last_config": в поле "config" — готовый .conf, рядом — те же значения по отдельности (client_ip,
 * client_priv_key, server_pub_key, psk_key, hostName, port, mtu, persistent_keep_alive, allowed_ips и
 * параметры AmneziaWG — Jc…I5, HeaderProtectionKey и др.).
 *
 * Подходят только AmneziaWG и WireGuard: XRay (VLESS), Shadowsocks и OpenVPN переносят соединения, а
 * не пакеты, — для них нужен свой TCP-стек. Ключи сервиса Amnezia Premium/Free конфига не содержат
 * (сервис выдаёт его своему приложению по запросу), ключ полного доступа к серверу — тоже.
 */
object AmneziaKey {

    sealed class Result {
        /** [text] — конфиг для второго выхода, [protocol] — «AmneziaWG 3.1» / «WireGuard», [name] — сервер. */
        data class Conf(val text: String, val protocol: String, val name: String) : Result()

        data class Unsupported(val reason: String) : Result()
    }

    fun looksLike(text: String): Boolean = text.trimStart().startsWith("vpn://", ignoreCase = true)

    fun decode(text: String): Result {
        val trimmed = text.trim()
        val body = trimmed.substring(trimmed.indexOf("://").let { if (it < 0) 0 else it + 3 })
            .filter { !it.isWhitespace() }
            .replace('+', '-').replace('/', '_').trimEnd('=')
        if (body.isEmpty()) return Result.Unsupported("ключ пустой")
        val raw = runCatching { java.util.Base64.getUrlDecoder().decode(body) }.getOrNull()
            ?: return Result.Unsupported("ключ не читается — скопируйте его целиком, от «vpn://» до конца")
        val json = inflateQt(raw)
            ?: raw.takeIf { it.isNotEmpty() && it[0] == '{'.code.toByte() }?.toString(Charsets.UTF_8)
            ?: return Result.Unsupported("ключ не распаковался — скорее всего, он скопирован не целиком")
        val root = runCatching { parseJson(json) as? JsonVal.Obj }.getOrNull()
            ?: return Result.Unsupported("внутри ключа нет описания сервера")

        val containers = root.arr("containers")?.items.orEmpty().mapNotNull { it as? JsonVal.Obj }
        if (containers.isEmpty()) {
            val service = listOf("auth_data", "api_config", "api_key", "config_version").any { root.fields.containsKey(it) }
            return Result.Unsupported(
                if (service) {
                    "это ключ сервиса Amnezia (Premium или Free): конфига в нём нет — сервис выдаёт его " +
                        "только своему приложению. Подойдёт ключ своего сервера Amnezia с протоколом AmneziaWG или WireGuard"
                } else {
                    "в ключе нет ни одного подключения"
                }
            )
        }
        val preferred = root.str("defaultContainer")
        val ordered = containers.sortedBy { if (it.str("container") == preferred) 0 else 1 }
        var sawWireguard = false
        var lastProblem: String? = null
        for (c in ordered) {
            val container = c.str("container").orEmpty()
            val protoKey = when {
                container.contains("awg") -> "awg"
                container.contains("wireguard") -> "wireguard"
                else -> null
            } ?: continue
            sawWireguard = true
            val proto = c.obj(protoKey) ?: continue
            val client = proto.str("last_config")?.let { runCatching { parseJson(it) as? JsonVal.Obj }.getOrNull() }
                ?: continue
            val conf = confOf(client, proto, root) ?: run {
                lastProblem = "в ключе не хватает ключей или адреса сервера"
                null
            } ?: continue
            val parsed = runCatching { WgConf.toWarpConfig("amnezia", conf) }.getOrNull()
            if (parsed == null) {
                lastProblem = "конфиг из ключа не разобрался"
                continue
            }
            val version = proto.text("protocol_version")?.takeIf { protoKey == "awg" && it.isNotBlank() }
            val protocol = if (protoKey == "awg") "AmneziaWG" + (version?.let { " $it" } ?: "") else "WireGuard"
            val name = root.str("description")?.takeIf { it.isNotBlank() } ?: parsed.endpoint.host
            return Result.Conf(conf, protocol, name)
        }
        lastProblem?.let { return Result.Unsupported(it) }
        if (sawWireguard) {
            return Result.Unsupported(
                "это ключ полного доступа к серверу (для управления им): своего подключения в нём нет. " +
                    "В AmneziaVPN откройте сервер → «Поделиться» и выдайте доступ по AmneziaWG — получится ключ подключения"
            )
        }
        val names = containers.mapNotNull { it.str("container") }.map(::pretty).distinct()
        return Result.Unsupported(
            "в ключе ${names.joinToString(", ")} — второй выход понимает только AmneziaWG и WireGuard: " +
                "остальные протоколы переносят соединения, а не пакеты"
        )
    }

    /** Ключи AmneziaWG, которые переносятся в [Interface], если готового .conf в ключе нет. */
    private val AWG_KEYS = listOf(
        "Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4", "H1", "H2", "H3", "H4", "I1", "I2", "I3", "I4", "I5",
        "HeaderProtectionKey", "ContentPaddingAddition", "RekeyAfterTime", "RekeyTimeout", "RejectAfterTime",
        "KeepaliveTimeout", "MaxHandshakeAttempts", "RandomTrailers", "DisableCookies",
    )

    private fun confOf(client: JsonVal.Obj, proto: JsonVal.Obj, root: JsonVal.Obj): String? {
        val dns1 = root.text("dns1")?.takeIf { it.isNotBlank() } ?: "1.1.1.1"
        val dns2 = root.text("dns2")?.takeIf { it.isNotBlank() } ?: "1.0.0.1"
        val native = client.text("config")?.replace("\r\n", "\n")
        if (native != null && native.contains("[Interface]") && native.contains("[Peer]") &&
            Regex("(?im)^\\s*Endpoint\\s*=\\s*[^\\s$]").containsMatchIn(native)
        ) {
            return native.replace("\$PRIMARY_DNS", dns1).replace("\$SECONDARY_DNS", dns2).trim() + "\n"
        }
        val priv = client.text("client_priv_key") ?: return null
        val serverPub = client.text("server_pub_key") ?: return null
        val ip = client.text("client_ip") ?: return null
        val host = client.text("hostName") ?: root.text("hostName") ?: return null
        val port = client.text("port") ?: proto.text("port") ?: return null
        val allowed = client.arr("allowed_ips")?.items?.mapNotNull { (it as? JsonVal.Str)?.v }
            ?.filter { it.isNotBlank() }?.takeIf { it.isNotEmpty() }?.joinToString(", ") ?: "0.0.0.0/0, ::/0"
        val endpointHost = if (host.contains(':') && !host.startsWith("[")) "[$host]" else host
        return buildString {
            append("[Interface]\n")
            append("PrivateKey = ").append(priv).append('\n')
            append("Address = ").append(if (ip.contains('/')) ip else "$ip/32").append('\n')
            append("DNS = ").append(dns1).append(", ").append(dns2).append('\n')
            client.text("mtu")?.takeIf { it.isNotBlank() }?.let { append("MTU = ").append(it).append('\n') }
            for (k in AWG_KEYS) {
                val v = (client.text(k) ?: proto.text(k))?.takeIf { it.isNotBlank() } ?: continue
                append(k).append(" = ").append(v).append('\n')
            }
            append("\n[Peer]\n")
            append("PublicKey = ").append(serverPub).append('\n')
            client.text("psk_key")?.takeIf { it.isNotBlank() }?.let { append("PresharedKey = ").append(it).append('\n') }
            append("AllowedIPs = ").append(allowed).append('\n')
            append("Endpoint = ").append(endpointHost).append(':').append(port).append('\n')
            client.text("persistent_keep_alive")?.takeIf { it.isNotBlank() }
                ?.let { append("PersistentKeepalive = ").append(it).append('\n') }
        }
    }

    /** Строка или число как строка (port у AmneziaVPN бывает и тем и другим). */
    private fun JsonVal.Obj.text(key: String): String? = when (val v = fields[key]) {
        is JsonVal.Str -> v.v
        is JsonVal.Num -> v.raw
        else -> null
    }

    private fun pretty(container: String): String = when (container) {
        "amnezia-openvpn" -> "OpenVPN"
        "amnezia-cloak" -> "OpenVPN через Cloak"
        "amnezia-shadowsocks" -> "Shadowsocks"
        "amnezia-ssxray" -> "Shadowsocks (XRay)"
        "amnezia-xray" -> "XRay (VLESS)"
        "amnezia-ipsec" -> "IKEv2/IPsec"
        else -> container
    }

    /**
     * qUncompress у Qt: 4 байта ожидаемой длины (big-endian), дальше поток zlib. null — не похоже.
     */
    private fun inflateQt(data: ByteArray): String? {
        if (data.size < 6) return null
        val expected = ((data[0].toInt() and 0xff) shl 24) or ((data[1].toInt() and 0xff) shl 16) or
            ((data[2].toInt() and 0xff) shl 8) or (data[3].toInt() and 0xff)
        if (expected <= 0 || expected > 4 * 1024 * 1024) return null
        return runCatching {
            val inflater = java.util.zip.Inflater()
            try {
                inflater.setInput(data, 4, data.size - 4)
                val out = java.io.ByteArrayOutputStream(expected)
                val buf = ByteArray(8192)
                while (!inflater.finished()) {
                    val n = inflater.inflate(buf)
                    if (n == 0 && (inflater.needsInput() || inflater.needsDictionary())) break
                    out.write(buf, 0, n)
                    if (out.size() > 4 * 1024 * 1024) return null
                }
                if (!inflater.finished()) null else out.toString("UTF-8")
            } finally {
                inflater.end()
            }
        }.getOrNull()
    }
}
