package dev.warpscout.app

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities

/**
 * Какая это сеть — точнее, чем «Wi-Fi или мобильная».
 *
 * Зачем. Память точек («на такой сети работала такая точка») раньше знала только вид сети. Но у
 * двух операторов связи — разные фильтры: точка, живая у одного, у другого молчит; то же с
 * домашним и рабочим Wi-Fi. После поездки с другой SIM или из офиса сервис начинал с точки «от
 * чужой сети» и тратил на неё попытку.
 *
 * Ключ теперь «вид·уточнение»:
 *  • мобильная — код оператора (MCC+MNC, например «25001»): его система отдаёт без разрешений;
 *  • Wi-Fi и Ethernet — адрес шлюза. Имя Wi-Fi (SSID) требует доступа к местоположению, а шлюз —
 *    нет; у двух разных домашних сетей он может совпасть, тогда память просто общая, как раньше.
 *
 * Уточнения нет — ключ равен виду сети, и всё работает по-старому. Память на чтении сначала ищет
 * точный ключ, потом вид (см. [EndpointMemory]).
 */
object NetIdentity {

    /** Разделитель вида и уточнения в ключе: «мобильная·25001». */
    const val SEP = "·"

    const val WIFI = "Wi-Fi"
    const val MOBILE = "мобильная"
    const val ETHERNET = "Ethernet"

    /** Вид сети одним словом; пусто — не знаем. */
    fun kindOf(caps: NetworkCapabilities?): String = when {
        caps == null -> ""
        caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> WIFI
        caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> MOBILE
        caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> ETHERNET
        else -> ""
    }

    /** Ключ сети для памяти точек: «мобильная·25001», «Wi-Fi·192.168.1.1» или просто вид. */
    fun keyOf(context: Context, network: Network?, caps: NetworkCapabilities?): String {
        val kind = kindOf(caps)
        if (kind.isEmpty()) return ""
        val detail = runCatching {
            when (kind) {
                MOBILE -> operatorCode(context)
                WIFI, ETHERNET -> gatewayOf(context, network)
                else -> ""
            }
        }.getOrDefault("")
        return if (detail.isBlank()) kind else kind + SEP + detail
    }

    /**
     * Ключ настоящей (не VPN) сети, через которую сейчас ходит телефон. При поднятом туннеле
     * активная сеть — это наш VPN, поэтому ищем среди всех: с интернетом, без VPN, Wi-Fi раньше
     * мобильной (так выбирает и система).
     */
    fun currentKey(context: Context): String = runCatching {
        val cm = context.getSystemService(ConnectivityManager::class.java) ?: return@runCatching ""
        val active = cm.activeNetwork
        val activeCaps = active?.let { cm.getNetworkCapabilities(it) }
        if (active != null && activeCaps != null && !activeCaps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) {
            return@runCatching keyOf(context, active, activeCaps)
        }
        @Suppress("DEPRECATION")
        val candidates = cm.allNetworks.mapNotNull { n ->
            val caps = cm.getNetworkCapabilities(n) ?: return@mapNotNull null
            if (!caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) return@mapNotNull null
            if (caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) return@mapNotNull null
            val rank = when (kindOf(caps)) {
                WIFI -> 0
                ETHERNET -> 1
                MOBILE -> 2
                else -> 3
            }
            Triple(n, caps, rank)
        }.sortedBy { it.third }
        val best = candidates.firstOrNull() ?: return@runCatching ""
        keyOf(context, best.first, best.second)
    }.getOrDefault("")

    /** Вид из ключа: «мобильная·25001» → «мобильная». */
    fun kindPart(key: String): String = key.substringBefore(SEP).trim()

    /** Мобильная ли это сеть (по ключу или виду). */
    fun isMobile(key: String): Boolean = kindPart(key) == MOBILE

    /** Код оператора мобильной сети (MCC+MNC) — без разрешений; пусто — не знаем. */
    fun operatorCode(context: Context): String = runCatching {
        val tm = context.getSystemService(android.telephony.TelephonyManager::class.java) ?: return@runCatching ""
        val code = tm.networkOperator.orEmpty().trim()
        if (code.length in 5..6 && code.all { it.isDigit() }) code else ""
    }.getOrDefault("")

    /** Имя оператора («MTS RUS») — для подписи в журнале; пусто — не знаем. */
    fun operatorName(context: Context): String = runCatching {
        val tm = context.getSystemService(android.telephony.TelephonyManager::class.java) ?: return@runCatching ""
        tm.networkOperatorName.orEmpty().trim()
    }.getOrDefault("")

    /** Шлюз по умолчанию (IPv4) у этой сети; пусто — не знаем. */
    private fun gatewayOf(context: Context, network: Network?): String {
        val net = network ?: return ""
        val cm = context.getSystemService(ConnectivityManager::class.java) ?: return ""
        val lp = cm.getLinkProperties(net) ?: return ""
        val gw = lp.routes.firstOrNull { route ->
            route.isDefaultRoute && route.gateway is java.net.Inet4Address
        }?.gateway?.hostAddress
        return gw.orEmpty()
    }
}
