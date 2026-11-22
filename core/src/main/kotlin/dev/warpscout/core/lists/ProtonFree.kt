package dev.warpscout.core.lists

import dev.warpscout.core.json.JsonVal
import dev.warpscout.core.json.parseJson

/**
 * Proton VPN Free как второй выход с автопоиском сервера (с 1.10.31).
 *
 * Человек один раз вставляет конфиг WireGuard из бесплатного аккаунта Proton (account.protonvpn.com →
 * Downloads → WireGuard configuration → Free server configs), а сервер выбирает приложение: ключ
 * клиента у Proton общий для всех серверов его уровня (так подключается и gluetun), поэтому к
 * ключу из конфига подставляется [Peer] любого бесплатного сервера. Перестал отвечать — берётся
 * следующий.
 *
 * Список серверов. Свой список Proton с декабря 2023 отдаёт только после входа в аккаунт, поэтому
 * берём открытый список проекта gluetun (github.com/qdm12/gluetun-servers, лицензия MIT):
 * бесплатные серверы WireGuard с ключами. В приложение встроен снимок от 01.11.2026 ([BUILTIN]),
 * раз в неделю он обновляется из сети ([SOURCE_URL]).
 */
object ProtonFree {

    data class Server(
        /** «NL-FREE#12». */
        val name: String,
        /** Страна по-английски, как в списке gluetun: «Netherlands». */
        val country: String,
        val city: String,
        val ip: String,
        val publicKey: String,
        val port: Int = PORT,
    ) {
        /** Код страны: «NL» из «NL-FREE#12», иначе — по названию страны. */
        val code: String get() = codeOf(name, country)
    }

    const val PORT = 51820

    /** Список gluetun (≈650 КБ, все серверы Proton): обновляется у них раз в несколько месяцев. */
    const val SOURCE_URL = "https://raw.githubusercontent.com/qdm12/gluetun-servers/main/pkg/servers/protonvpn.json"
    const val SOURCE_API = "https://api.github.com/repos/qdm12/gluetun-servers/contents/pkg/servers/protonvpn.json"

    /** Страны по удалённости от России: при «любой стране» ближние идут первыми. */
    val NEAR: List<String> = listOf("NL", "PL", "RO", "CH", "NO", "DE", "FI", "SE", "CA", "US", "JP", "SG", "MX")

    private val CODES = mapOf(
        "Netherlands" to "NL", "Poland" to "PL", "Romania" to "RO", "Switzerland" to "CH", "Norway" to "NO",
        "Germany" to "DE", "Finland" to "FI", "Sweden" to "SE", "Canada" to "CA", "United States" to "US",
        "Japan" to "JP", "Singapore" to "SG", "Mexico" to "MX",
    )

    fun codeOf(name: String, country: String): String {
        val prefix = name.substringBefore('-').trim().uppercase()
        if (prefix.length == 2 && prefix.all { it in 'A'..'Z' }) return prefix
        return CODES[country] ?: country.take(2).uppercase()
    }

    /**
     * Конфиг из Proton: у всех их конфигов WireGuard адрес клиента 10.2.0.2 и DNS 10.2.0.1 (первый
     * NAT на их стороне, см. FAQ Proton). По этим двум строкам и узнаём.
     */
    fun isProton(conf: String): Boolean {
        var address = false
        var dns = false
        for (raw in conf.lineSequence()) {
            val line = raw.substringBefore('#').trim()
            val key = line.substringBefore('=').trim().lowercase()
            val value = line.substringAfter('=', "").trim()
            if (key == "address" && value.split(',').any { it.trim().substringBefore('/') == "10.2.0.2" }) address = true
            if (key == "dns" && value.split(',').any { it.trim() == "10.2.0.1" }) dns = true
        }
        return address && dns
    }

    /** [Peer] из конфига: ключ сервера и адрес; null — не нашлось. */
    fun peerOf(conf: String): Server? {
        var inPeer = false
        var key = ""
        var endpoint = ""
        for (raw in conf.lineSequence()) {
            val line = raw.substringBefore('#').trim()
            if (line.startsWith("[")) {
                inPeer = line.equals("[Peer]", ignoreCase = true)
                continue
            }
            if (!inPeer) continue
            val k = line.substringBefore('=').trim().lowercase()
            val v = line.substringAfter('=', "").trim()
            if (k == "publickey") key = v
            if (k == "endpoint") endpoint = v
        }
        if (key.isBlank() || endpoint.isBlank()) return null
        val host = endpoint.substringBeforeLast(':').removePrefix("[").removeSuffix("]")
        val port = endpoint.substringAfterLast(':', "").toIntOrNull() ?: PORT
        if (host.isBlank()) return null
        return Server(name = "", country = "", city = "", ip = host, publicKey = key, port = port)
    }

    /** Список gluetun → бесплатные серверы WireGuard с ключом и IPv4-адресом, без повторов. */
    fun parseGluetun(json: String): List<Server> {
        val root = parseJson(json) as? JsonVal.Obj ?: return emptyList()
        val items = root.arr("servers")?.items.orEmpty()
        val out = LinkedHashMap<String, Server>()
        for (item in items) {
            val s = item as? JsonVal.Obj ?: continue
            if (s.str("vpn") != "wireguard" || s.bool("free") != true) continue
            val key = s.str("wgpubkey").orEmpty().trim()
            if (key.length != 44) continue
            val ip = s.arr("ips")?.items.orEmpty().mapNotNull { (it as? JsonVal.Str)?.v }.firstOrNull { !it.contains(':') }
                ?: continue
            val name = s.str("server_name").orEmpty().ifBlank { s.str("hostname").orEmpty() }
            out.putIfAbsent("$ip|$key", Server(name, s.str("country").orEmpty(), s.str("city").orEmpty(), ip, key))
        }
        return out.values.toList()
    }

    /** Компактная запись для кеша: «имя|страна|город|адрес|ключ» построчно. */
    fun render(servers: List<Server>): String =
        servers.joinToString("\n") { listOf(it.name, it.country, it.city, it.ip, it.publicKey).joinToString("|") }

    fun parseCompact(text: String): List<Server> = text.lineSequence().mapNotNull { line ->
        val p = line.trim().split('|')
        if (p.size < 5 || p[3].isBlank() || p[4].length != 44) null else Server(p[0], p[1], p[2], p[3], p[4])
    }.toList()

    /** Строка для ServiceSettings.secondPeers: «имя|адрес|порт|ключ». */
    fun encode(s: Server): String = listOf(s.name, s.ip, s.port.toString(), s.publicKey).joinToString("|")

    fun decode(line: String): Server? {
        val p = line.trim().split('|')
        if (p.size != 4) return null
        val port = p[2].toIntOrNull()?.takeIf { it in 1..65535 } ?: return null
        if (p[1].isBlank() || p[3].length != 44) return null
        return Server(name = p[0], country = "", city = "", ip = p[1], publicKey = p[3], port = port)
    }

    /**
     * Порядок перебора: сервер, работавший последним ([lastGood] — имя), → серверы выбранной
     * страны ([prefer] — код, пусто — любая) → сервер из самого конфига ([original]) → остальные,
     * ближние страны первыми. Внутри страны — по кругу от [seed]: бесплатные серверы загружены, и
     * все телефоны не должны ломиться в первый по списку.
     */
    fun ordered(servers: List<Server>, prefer: String, lastGood: String, original: Server?, seed: Long): List<Server> {
        fun rotate(list: List<Server>): List<Server> {
            if (list.size < 2) return list
            val shift = ((seed % list.size) + list.size).toInt() % list.size
            return list.drop(shift) + list.take(shift)
        }
        val byCountry = servers.groupBy { it.code }
        val out = ArrayList<Server>()
        servers.firstOrNull { lastGood.isNotBlank() && it.name == lastGood && (prefer.isBlank() || it.code == prefer) }?.let { out += it }
        if (prefer.isNotBlank()) out += rotate(byCountry[prefer].orEmpty())
        if (original != null) {
            out += servers.firstOrNull { it.publicKey == original.publicKey && it.ip == original.ip }
                ?: original.copy(name = original.name.ifBlank { "из конфига" })
        }
        NEAR.forEach { code -> out += rotate(byCountry[code].orEmpty()) }
        byCountry.keys.filter { it !in NEAR }.sorted().forEach { code -> out += rotate(byCountry[code].orEmpty()) }
        return out.distinctBy { it.ip + "|" + it.publicKey + "|" + it.port }
    }

    /** Страны, которые есть в списке, — коды в порядке [NEAR]. */
    fun countries(servers: List<Server>): List<String> {
        val have = servers.map { it.code }.toSet()
        return NEAR.filter { it in have } + have.filter { it !in NEAR }.sorted()
    }

    /** Снимок списка gluetun от 01.11.2026: 53 бесплатных сервера WireGuard. */
    val BUILTIN: List<Server> by lazy { parseCompact(BUILTIN_TEXT) }

    private val BUILTIN_TEXT = """
CA-FREE#25|Canada|Montreal|195.242.214.66|1fGFZtHU8r8qwdnron9E80NdvLw5WcUdhPgh7phzQnA=
CA-FREE#28|Canada|Montreal|195.242.214.114|cFWV9L1uNf/u4Hiojt0u4G4E4I12WB65JRq7nkHl0ns=
CA-FREE#29|Canada|Montreal|195.242.214.130|TEUAMY5iMm31LFvOgYjJKRsjZrF8ICRjSrqgwscrFx0=
CA-FREE#5|Canada|Toronto|149.88.97.122|mS8GfqvUvazXvSYg7VHV7s8eEyU0yyGjJwYgdjHq23A=
CA-FREE#6|Canada|Toronto|149.88.97.110|9mTDh5Tku0gxDdzqxnpnzItHQBm2h2B2hXnUHvhGCFw=
CA-FREE#9|Canada|Toronto|149.22.82.1|7nj3Zh17Dzx+1SKIPE+dPfFmDbTTOggDK6SfK6tlEgE=
CA-FREE#12|Canada|Vancouver|79.127.254.92|WajeJDezN7JFBe//v/VMsASFyBUk01Hlyvjb0T+dTjE=
JP-FREE#20|Japan|Tokyo|212.102.51.1|jXayHq4Z5KQC1woRwm6ymLFZot/+158IWDT++u5d2Qc=
JP-FREE#24|Japan|Tokyo|212.102.51.28|9k38UMd5ufDVYu/im3M4N+kLy8ahfAT6NqAFdJePHyU=
JP-FREE#34|Japan|Tokyo|149.88.103.162|sKWRXpOQRf5Q7LUaBvCAGUTOI5IonZg7+NFRHHiX3xE=
MX-FREE#11|Mexico|Mexico City|84.20.27.48|7VxfDXa073wXtKpGeczTuID/XmwSwmWSPTUBt20SwBo=
NL-FREE#121|Netherlands|Amsterdam|149.34.244.174|S4sou/kWKF1tDtb98ik1PJs5DIOXONZrL0E9lI5lWEI=
NL-FREE#125|Netherlands|Amsterdam|185.107.56.49|miiJL4putHojjkN0tOnNHu1/ae8rxvrBPCF47mqWnko=
NL-FREE#129|Netherlands|Amsterdam|89.38.99.72|Wj4jupUpBGVmyMmpME1qw1s2wAxDbygPfz2+ATVGC3c=
NL-FREE#225|Netherlands|Amsterdam|185.132.134.35|BsqBdtyn9af3zjX0ZrWFAcQHfFKC+60iLOsItjVa2Xo=
NO-FREE#10|Norway|Oslo|95.173.205.161|N9uq1Vwlu7tHTzG13/P/Plo8m4HJLeal8rdHeD96MxE=
NO-FREE#5|Norway|Oslo|95.173.205.167|2s+PN1/EcGL6LAK7YamHOYqL0waTlwc43+RR6+hxORQ=
NO-FREE#6|Norway|Oslo|95.173.205.165|84dSFrHWsJr34E8GWyXZsxFourH7+vbjUoJWlZmS13I=
PL-FREE#13|Poland|Warsaw|149.102.244.112|zear23pwkz4A+s8Q3KiCW8el4SrYYzv/lSgd4+xrVEU=
RO-FREE#23|Romania|Bucharest|146.70.246.98|ehwHh3WXBDwFxqTs4Oa8aZZYjOnd3NwjbMArKRwTqzs=
RO-FREE#24|Romania|Bucharest|146.70.246.114|dgVvjsBPhkKantancTMGlcd10ikyQjCtSTG2muBjvHA=
RO-FREE#25|Romania|Bucharest|185.45.15.34|AQMQis3/N2TP377PKH0D6DjEhu0pLanSK6dCbYE7q3U=
RO-FREE#26|Romania|Bucharest|185.252.220.146|Io8cLLfUyY9INwZ26X+thOzpMGRim0ek1VzZ19RpM2o=
SG-FREE#14|Singapore|Singapore|103.216.221.68|sze+UvjxRhaUuBHVPEf7XwPcgu6Y715XljvHmKGiZkw=
SG-FREE#18|Singapore|Singapore|103.216.221.72|whEECgH2k+DQjnLR/Vf/Chm7pLsxCnTd9fzCRcWFqzM=
SG-FREE#28|Singapore|Singapore|134.82.69.8|IguxCgINPgHZTq/szxWNYmbkDcBzGF2xi9QQaKhtLyA=
SG-FREE#3|Singapore|Singapore|149.50.211.139|9lzYRM9SNjGGkYjc0FcYCWFO9ZWEFRwHboW6RLeUnBU=
CH-FREE#10|Switzerland|Zurich|135.136.39.2|1WO+SU1kJCYR5ZWBVK/M7bNsvz1HWIFlq/xafhDqHnk=
CH-FREE#3|Switzerland|Zurich|138.199.6.178|YpOUROUnumcF/snGX8zka0nThnvHesceJAYUSbZL1XQ=
CH-FREE#7|Switzerland|Zurich|149.88.27.234|XPVCz7LndzqWe7y3+WSo51hvNOX8nX5CTwVTWhzg8g8=
US-FREE#46|United States|Chicago|89.187.180.55|yB6ySO0kjqbgVWanDYKDgWoAMwM3X//nBiKXwaqmiwU=
US-FREE#44|United States|Houston|37.19.221.196|4wqoqnWaoR8FLWkihmN4DVma/8lFn1fXQMRVs/4TD0A=
US-FREE#45|United States|Houston|37.19.221.199|qBUTSloO8PKGUl0ZrfTx1AZwwCwJRB+9kGD0hquFqVQ=
US-FREE#47|United States|Houston|37.19.221.198|ksK3faRBQlFLul2FcKPphBR9LYR+6/FbP1etg0T2liA=
US-FREE#130|United States|Los Angeles|194.180.33.20|jyiQbTTHvl6eLhIQWi1zL7xzPppbV7z+hFJ6e7CEmAg=
US-FREE#131|United States|Los Angeles|194.180.33.6|FOJ0a5AFAg9qx7PyT5EPv2Puan799os+b9NT0gZEeFc=
US-FREE#94|United States|Los Angeles|149.22.80.114|0t8cQ6GkwX1CYTO8AuIwDjbBZKYFrYZjEDqkUNCBAzQ=
US-FREE#106|United States|Miami|138.199.50.134|/iPQhCh0/kEzS60D5ysFOQHSyUAFV9sx77AckhzA9Xw=
US-FREE#88|United States|Miami|138.199.50.139|gow8oSZwAXmv3bv2yaYye5b7GxZVni6gNcz8PxKvWgA=
US-FREE#89|United States|Miami|138.199.50.129|A1lZjTXsjqmvmehp9i0zV+jzl89Vf2y2fXxeMRSjp18=
US-FREE#121|United States|New York|195.86.56.193|MSijg4vzeYXFltBAChuWBWlsCj/nHu0/UwiLPBeRn3I=
US-FREE#134|United States|New York|194.180.34.4|dmLneQlg7RcqifSS3aHA4VGMVbSf4eTdxi5QfIoF1z4=
US-FREE#138|United States|New York|194.180.34.9|6ZjXjsAFfUYg0j3YadtfiBr9EZtiuZeqhD5zTP/VsT4=
US-FREE#77|United States|San Jose|149.22.84.144|4R1OAr1fQR4ZHNq7T4Gkage3p7LyqMfOyhCqfu04gno=
US-FREE#78|United States|San Jose|149.22.84.134|s2T8s4nQ9QSLxZm8JHGtaKgErj+/iFhPyjSvLLIM2S8=
US-FREE#79|United States|San Jose|149.22.84.139|igHNlAQgaI70R0w0OdWC9XR11xagXRcib1V4tPuU4RQ=
US-FREE#90|United States|San Jose|149.22.84.154|TaxwFJ2ajJdHlowb91UhfBxl60lsjBicCxC+dE2wDEE=
US-FREE#91|United States|San Jose|149.22.84.155|lqpUGVCjx+PWmhdxC36zbJZopUc/9XM2EG5SNKoqqE4=
US-FREE#33|United States|Seattle|149.102.254.90|SOXFyakZ9HI9TeiMRyMoy3PXYEzJJ/IDJcMvxZ3uWSE=
US-FREE#70|United States|Secaucus|151.243.141.159|MNTtBSAv3VQ8W059Rbf7pQ37WDxQ4h5vkhmBARjmmiU=
US-FREE#75|United States|Secaucus|151.243.141.163|0RyHTsq0vwayZVZUhuIKGcU7FiMl9Gn4dvNiOlYYpyc=
US-FREE#83|United States|Secaucus|151.243.141.165|rgPoLtUhJ946CVYPkp8r3VL8KHUYSmTIrPo7Wsw9sn4=
US-FREE#147|United States|Washington|170.23.224.1|XqibeQ+FeeN0aihPq4/WfOOobh9aNtUBfLU7sYs0JwU=
""".trimIndent()
}
