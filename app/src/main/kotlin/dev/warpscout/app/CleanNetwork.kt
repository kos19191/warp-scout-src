package dev.warpscout.app

import android.content.Context
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import dev.warpscout.core.net.TcpSocketFactory
import dev.warpscout.core.net.UdpSocketFactory
import java.net.InetSocketAddress
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/**
 * Замеры «на чистой сети».
 *
 * Чужой VPN (Orbot, Proton, включённая Amnezia) портит базовые проверки: «ресурс недоступен» тогда
 * может означать «не прошло через чужой туннель», а не «режет провайдер» — и подбор начнёт искать
 * endpoint под несуществующей проблемой. Выключить чужой VPN из приложения нельзя (разрешения нет),
 * поэтому делаем то, что реально работает: просим у системы сеть без флага VPN и ходим через неё.
 *
 *  • пробы endpoint'ов — через [factories] (сокет создаётся на конкретном Network);
 *  • HTTP-проверки ресурсов — через bindProcessToNetwork, у HttpURLConnection своего способа
 *    указать сеть нет;
 *  • перед проверкой «из-под туннеля» привязку снимаем, иначе мы бы обошли собственный туннель.
 *
 * Если non-VPN сеть не отдаётся (Always-on с «блокировать другие приложения») — честно говорим об
 * этом в [describe]: молча врать про «чистую сеть» хуже, чем предупредить.
 *
 * С 1.10.45 подбор при чужом VPN не запускается вовсе (см. [ForeignVpn]): Android пускает мимо VPN,
 * только если тот сам это разрешил, — по умолчанию замеры шли бы через чужой туннель.
 */
object CleanNetwork {

    @Volatile
    private var clean: Network? = null

    @Volatile
    private var callback: ConnectivityManager.NetworkCallback? = null

    @Volatile
    private var bound = false

    /** true — если нашли сеть без VPN. Идемпотентно: второй вызов ничего не перерегистрирует. */
    fun prepare(context: Context, waitMs: Long = 2500): Boolean {
        if (clean != null) return true
        val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager ?: return false
        val request = runCatching {
            NetworkRequest.Builder()
                .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
                .build()
        }.getOrNull() ?: return false

        val gate = CountDownLatch(1)
        val cb = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                clean = network
                gate.countDown()
            }

            override fun onLost(network: Network) {
                if (clean == network) clean = null
            }
        }
        if (runCatching { cm.registerNetworkCallback(request, cb) }.isFailure) return false
        runCatching { gate.await(waitMs, TimeUnit.MILLISECONDS) }
        callback = cb
        if (clean == null) releaseCallback(cm)
        return clean != null
    }

    /** Привязать процесс к non-VPN сети: закрывает и HttpURLConnection, и всё остальное в процессе. */
    fun bind(context: Context): Boolean {
        val net = clean ?: return false
        val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager ?: return false
        // Отказ bindProcessToNetwork — это false, а не исключение (VPN без allowBypass): с isSuccess
        // журнал писал «замеры идут в обход», когда обхода не было (до 1.10.45).
        bound = runCatching { cm.bindProcessToNetwork(net) }.getOrDefault(false)
        return bound
    }

    /** Отвязать процесс (сеть остаётся запомненной: фабрики проб продолжают ходить через неё). */
    fun unbind(context: Context) {
        if (!bound) return
        val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager ?: return
        runCatching { cm.bindProcessToNetwork(null) }
        bound = false
    }

    /** Сокеты проб через найденную сеть; null — если обошли нечего и ходим как обычно. */
    fun factories(): Pair<UdpSocketFactory, TcpSocketFactory>? {
        val net = clean ?: return null
        val udp = UdpSocketFactory { ep ->
            // У android.net.Network нет openDatagramSocket() (в отличие от openSocket), поэтому
            // сокет создаём сами и привязываем к сети bindSocket() — обязательно ДО connect().
            val sock = java.net.DatagramSocket()
            // Не вышло привязать — не беда: мёрим как обычно, подбор падать не должен.
            runCatching { net.bindSocket(sock) }
            // connect() обязателен: только на connected-сокете ICMP «порт закрыт» превращается
            // в SocketException, а это единственный способ отличить закрытый порт от чёрной дыры.
            runCatching { sock.connect(InetSocketAddress(ep.host, ep.port)) }
            sock
        }
        val tcp = TcpSocketFactory {
            runCatching { net.socketFactory.createSocket() }.getOrElse { java.net.Socket() }
        }
        return udp to tcp
    }

    /**
     * Что вообще сейчас активно из туннелей — для строки состояния и для отчёта.
     * Возвращает пустую строку, если чужих VPN нет (и привязываться было не к чему).
     */
    fun describe(context: Context): String {
        val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
            ?: return "нет ConnectivityManager"
        val vpnNets = runCatching {
            (cm.allNetworks ?: emptyArray()).filter { n ->
                val caps = runCatching { cm.getNetworkCapabilities(n) }.getOrNull()
                // «VPN» как отдельной возможности в API нет — есть NOT_VPN: значит туннель, когда флага нет
                caps?.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) == true &&
                    !caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
            }
        }.getOrDefault(emptyList())
        if (vpnNets.isEmpty()) {
            return if (bound) "чужих VPN нет, замеры идут по обычной сети"
            else "чужих VPN нет"
        }
        val names = vpnNets.mapNotNull { n ->
            runCatching { cm.getLinkProperties(n) }.getOrNull()?.let { linkOf(it) }
        }.distinct().ifEmpty { listOf("неизвестный туннель") }
        val how = when {
            bound -> "замеры идут в обход"
            clean == null -> "ОБАЙТИ НЕ УДАЛОСЬ (похоже на Always-on с блокировкой других приложений)"
            else -> "не привязаны"
        }
        return "активен VPN: ${names.joinToString(", ")} · $how"
    }

    private fun linkOf(props: LinkProperties): String? =
        runCatching { props.interfaceName }.getOrNull()?.takeIf { it.isNotBlank() }

    private fun releaseCallback(cm: ConnectivityManager) {
        val cb = callback ?: return
        runCatching { cm.unregisterNetworkCallback(cb) }
        callback = null
    }

    /** Для логов: коротко и по-русски, что с сетью. */
    fun statusLine(context: Context): String {
        val d = describe(context)
        return when {
            d == "чужих VPN нет" -> "сеть чистая: ни одного активного туннеля"
            d.contains("ОБАЙТИ НЕ УДАЛОСЬ") ->
                "внимание: $d — отключи VPN в настройках, иначе базовые проверки будут кривыми"
            else -> "базовые замеры: $d"
        }
    }

}
