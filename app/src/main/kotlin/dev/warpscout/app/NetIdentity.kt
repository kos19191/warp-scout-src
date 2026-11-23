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

    /**
     * Поколение мобильной связи, как его пишет строка состояния телефона: «5G», «LTE», «H+», «H»,
     * «3G», «E», «G», «2G» (с 1.10.40). Пусто — не мобильная сеть или система не сказала.
     *
     * Без разрешений: тип мобильной сети отдаёт сам ConnectivityManager (NetworkInfo — устаревший
     * API, но единственный без доступа к состоянию телефона; TelephonyManager.getDataNetworkType
     * требует READ_PHONE_STATE). Система обновляет его при смене типа связи и без смены сети.
     */
    fun radioOf(context: Context, network: Network?): String = runCatching {
        val net = network ?: return@runCatching ""
        val cm = context.getSystemService(ConnectivityManager::class.java) ?: return@runCatching ""
        @Suppress("DEPRECATION")
        val info = cm.getNetworkInfo(net) ?: return@runCatching ""
        @Suppress("DEPRECATION")
        if (info.type != ConnectivityManager.TYPE_MOBILE) return@runCatching ""
        @Suppress("DEPRECATION")
        radioName(info.subtype)
    }.getOrDefault("")

    /** Тип связи по коду TelephonyManager.NETWORK_TYPE_*; пусто — неизвестный код. */
    fun radioName(subtype: Int): String = when (subtype) {
        android.telephony.TelephonyManager.NETWORK_TYPE_NR -> "5G"
        android.telephony.TelephonyManager.NETWORK_TYPE_LTE, 19 /* LTE_CA, скрытая константа */ -> "LTE"
        android.telephony.TelephonyManager.NETWORK_TYPE_HSPAP -> "H+"
        android.telephony.TelephonyManager.NETWORK_TYPE_HSPA,
        android.telephony.TelephonyManager.NETWORK_TYPE_HSDPA,
        android.telephony.TelephonyManager.NETWORK_TYPE_HSUPA -> "H"
        android.telephony.TelephonyManager.NETWORK_TYPE_UMTS,
        android.telephony.TelephonyManager.NETWORK_TYPE_TD_SCDMA,
        android.telephony.TelephonyManager.NETWORK_TYPE_EVDO_0,
        android.telephony.TelephonyManager.NETWORK_TYPE_EVDO_A,
        android.telephony.TelephonyManager.NETWORK_TYPE_EVDO_B,
        android.telephony.TelephonyManager.NETWORK_TYPE_EHRPD -> "3G"
        android.telephony.TelephonyManager.NETWORK_TYPE_EDGE -> "E"
        android.telephony.TelephonyManager.NETWORK_TYPE_GPRS -> "G"
        android.telephony.TelephonyManager.NETWORK_TYPE_GSM,
        android.telephony.TelephonyManager.NETWORK_TYPE_CDMA,
        android.telephony.TelephonyManager.NETWORK_TYPE_1xRTT,
        11 /* NETWORK_TYPE_IDEN, устаревшая константа */ -> "2G"
        else -> ""
    }

    /**
     * Медленная мобильная связь — H+ и всё, что старше. На ней задержка под нагрузкой доходит до
     * секунд, а полоса — до единиц мегабит (журнал 23.11: пинг 1157 мс, замер 310 Кбит/с).
     */
    fun isSlowRadio(radio: String): Boolean = radio in SLOW_RADIOS

    private val SLOW_RADIOS = setOf("H+", "H", "3G", "E", "G", "2G")

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
