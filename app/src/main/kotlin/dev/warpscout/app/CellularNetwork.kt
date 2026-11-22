package dev.warpscout.app

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import dev.warpscout.core.net.TcpSocketFactory
import dev.warpscout.core.net.UdpSocketFactory
import java.net.InetSocketAddress
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference

/**
 * Мобильная сеть, не уходя с Wi-Fi.
 *
 * Зачем. Точки для мобильной сети раньше можно было подобрать, только выйдя из дома: адреса,
 * живые на Wi-Fi, на мобильной часто молчат, а подбор знал только текущую сеть. Android даёт
 * приложению попросить мобильную сеть рядом с Wi-Fi (`requestNetwork` с CELLULAR): система держит
 * её поднятой, пока запрос не снят, и сокеты, привязанные к ней, ходят через оператора. Так
 * подбирают и в NetFix.
 *
 * Пробы через неё — только рукопожатием: поднять сам туннель через мобильную сеть, оставаясь на
 * Wi-Fi, нельзя (туннель идёт по сети по умолчанию), поэтому проверки сайтов «изнутри» для этой
 * тройки нет — так и подписываем.
 */
object CellularNetwork {

    /** Есть ли смысл просить: SIM на месте. Нет SIM — не ждём восемь секунд впустую. */
    fun maybeAvailable(context: Context): Boolean = runCatching {
        val tm = context.getSystemService(android.telephony.TelephonyManager::class.java) ?: return@runCatching false
        tm.simState == android.telephony.TelephonyManager.SIM_STATE_READY
    }.getOrDefault(true)

    /**
     * Попросить мобильную сеть. null — не дали за [waitMs] (выключены мобильные данные, нет SIM,
     * запрет системы). Запрос держится, пока не вызван [release]: без этого система погасит
     * мобильную сеть через несколько секунд — Wi-Fi ведь есть.
     */
    fun acquire(context: Context, waitMs: Long = 8_000L): Pair<Network, ConnectivityManager.NetworkCallback>? {
        val cm = context.getSystemService(ConnectivityManager::class.java) ?: return null
        val request = runCatching {
            NetworkRequest.Builder()
                .addTransportType(NetworkCapabilities.TRANSPORT_CELLULAR)
                .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
                .build()
        }.getOrNull() ?: return null
        val found = AtomicReference<Network?>(null)
        val gate = CountDownLatch(1)
        val cb = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                found.set(network)
                gate.countDown()
            }

            override fun onUnavailable() {
                gate.countDown()
            }

            override fun onLost(network: Network) {
                if (found.get() == network) found.set(null)
            }
        }
        if (runCatching { cm.requestNetwork(request, cb, waitMs.toInt()) }.isFailure) return null
        runCatching { gate.await(waitMs + 500L, TimeUnit.MILLISECONDS) }
        val net = found.get()
        if (net == null) {
            release(context, cb)
            return null
        }
        return net to cb
    }

    /** Снять запрос: система вернётся к обычному порядку (мобильная гаснет, если не нужна). */
    fun release(context: Context, cb: ConnectivityManager.NetworkCallback) {
        val cm = context.getSystemService(ConnectivityManager::class.java) ?: return
        runCatching { cm.unregisterNetworkCallback(cb) }
    }

    /** Сокеты проб через мобильную сеть (как у CleanNetwork, но на конкретной сети). */
    fun factories(net: Network): Pair<UdpSocketFactory, TcpSocketFactory> {
        val udp = UdpSocketFactory { ep ->
            val sock = java.net.DatagramSocket()
            // Привязка — до connect(): иначе сокет уйдёт по сети по умолчанию, то есть по Wi-Fi.
            runCatching { net.bindSocket(sock) }
            runCatching { sock.connect(InetSocketAddress(ep.host, ep.port)) }
            sock
        }
        val tcp = TcpSocketFactory {
            runCatching { net.socketFactory.createSocket() }.getOrElse { java.net.Socket() }
        }
        return udp to tcp
    }

    /** «MTS RUS (25001)» — для журнала. */
    fun describe(context: Context): String {
        val name = NetIdentity.operatorName(context)
        val code = NetIdentity.operatorCode(context)
        return when {
            name.isNotBlank() && code.isNotBlank() -> "$name ($code)"
            name.isNotBlank() -> name
            code.isNotBlank() -> code
            else -> "оператор неизвестен"
        }
    }
}
