package dev.warpscout.netdiag

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.wifi.WifiInfo
import android.net.wifi.WifiManager
import android.os.Build
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.NetworkInterface

object AndroidNetworkCollector {

    @Suppress("DEPRECATION")
    fun collect(context: Context): NetworkEnvInfo {
        val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
        val activeNet = cm?.activeNetwork
        val caps = activeNet?.let { cm.getNetworkCapabilities(it) }
        val lp = activeNet?.let { cm.getLinkProperties(it) }

        val transports = ArrayList<String>()
        if (caps != null) {
            if (caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) transports += "WIFI"
            if (caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)) transports += "CELLULAR"
            if (caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) transports += "VPN"
            if (caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET)) transports += "ETHERNET"
            if (caps.hasTransport(NetworkCapabilities.TRANSPORT_BLUETOOTH)) transports += "BLUETOOTH"
        }

        val validated = caps?.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED) == true
        val metered = caps?.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED) != true
        val vpnActive = caps?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true ||
            (caps != null && !caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN))

        val downKbps = caps?.linkDownstreamBandwidthKbps ?: 0
        val upKbps = caps?.linkUpstreamBandwidthKbps ?: 0

        // Wi-Fi информация (сначала из NetworkCapabilities.transportInfo на Android 10+, затем фолбэк WifiManager)
        val wifiInfo: WifiInfo? = runCatching {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                (caps?.transportInfo as? WifiInfo)
            } else null
        }.getOrNull() ?: runCatching {
            val wm = context.applicationContext.getSystemService(Context.WIFI_SERVICE) as? WifiManager
            wm?.connectionInfo
        }.getOrNull()

        val wifiSummary = if (wifiInfo != null && (transports.contains("WIFI") || wifiInfo.frequency > 0)) {
            val ssid = wifiInfo.ssid?.trim('"').orEmpty().let {
                if (it.isBlank() || it == "<unknown ssid>") "скрыто ОС (без геолокации)" else it
            }
            val freq = if (wifiInfo.frequency > 0) "${wifiInfo.frequency} МГц" else "?"
            val band = when {
                wifiInfo.frequency in 2400..2500 -> "2.4 ГГц"
                wifiInfo.frequency in 4900..5900 -> "5 ГГц"
                wifiInfo.frequency >= 5925 -> "6 ГГц"
                else -> ""
            }
            val speed = if (wifiInfo.linkSpeed > 0) "${wifiInfo.linkSpeed} Мбит/с" else "?"
            val rssi = if (wifiInfo.rssi != -127) "${wifiInfo.rssi} дБм" else "?"
            val std = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                when (wifiInfo.wifiStandard) {
                    4 -> "Wi-Fi 4 (802.11n)"
                    5 -> "Wi-Fi 5 (802.11ac)"
                    6 -> "Wi-Fi 6 (802.11ax)"
                    7 -> "Wi-Fi 7 (802.11be)"
                    else -> ""
                }
            } else ""
            listOfNotNull(
                "SSID=$ssid",
                "сигнал=$rssi",
                "линк=$speed",
                "$freq${if (band.isNotEmpty()) " ($band)" else ""}",
                std.ifEmpty { null }
            ).joinToString(", ")
        } else {
            "не активен / мобильная сеть"
        }

        val ipv4 = ArrayList<String>()
        val ipv6 = ArrayList<String>()
        lp?.linkAddresses?.forEach { la ->
            val addr = la.address
            val str = "${addr.hostAddress?.substringBefore('%')}/${la.prefixLength}"
            when (addr) {
                is Inet4Address -> ipv4 += str
                is Inet6Address -> if (!addr.isLinkLocalAddress) ipv6 += str
            }
        }

        val dnsServers = lp?.dnsServers?.mapNotNull { it.hostAddress?.substringBefore('%') }.orEmpty()
        val privateDnsActive = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) lp?.isPrivateDnsActive == true else false
        val privateDnsServer = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) lp?.privateDnsServerName.orEmpty() else ""

        val proxyInfo = lp?.httpProxy
        val pacStr = proxyInfo?.pacFileUrl?.toString().orEmpty()
        val httpProxy = when {
            proxyInfo == null -> "нет"
            pacStr.isNotBlank() && pacStr != "null" -> "PAC: $pacStr"
            !proxyInfo.host.isNullOrBlank() -> "${proxyInfo.host}:${proxyInfo.port}"
            else -> "нет"
        }

        val mtu = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) lp?.mtu ?: 0 else 0
        val routes = lp?.routes?.map { r ->
            val dst = r.destination.toString()
            val gw = r.gateway?.hostAddress?.substringBefore('%') ?: "direct"
            val iface = r.`interface` ?: "?"
            "$dst -> $gw ($iface)"
        }.orEmpty()

        val allIfaces = ArrayList<String>()
        runCatching {
            val en = NetworkInterface.getNetworkInterfaces()
            while (en != null && en.hasMoreElements()) {
                val nif = en.nextElement()
                if (!nif.isUp || nif.isLoopback) continue
                val addrs = nif.inetAddresses.toList()
                    .filter { !it.isLinkLocalAddress }
                    .mapNotNull { it.hostAddress?.substringBefore('%') }
                if (addrs.isEmpty()) continue
                allIfaces += "${nif.name} (MTU=${nif.mtu}): ${addrs.joinToString(", ")}"
            }
        }

        return NetworkEnvInfo(
            timestampIso = DiagModelsHelper.nowIso(),
            deviceModel = "${Build.MANUFACTURER} ${Build.MODEL}".trim(),
            androidVersion = "${Build.VERSION.RELEASE} (API ${Build.VERSION.SDK_INT})",
            transports = transports,
            validated = validated,
            metered = metered,
            vpnActive = vpnActive,
            downstreamKbps = downKbps,
            upstreamKbps = upKbps,
            wifiSummary = wifiSummary,
            interfaceName = lp?.interfaceName.orEmpty(),
            mtu = mtu,
            ipv4Addresses = ipv4,
            ipv6Addresses = ipv6,
            dnsServers = dnsServers,
            privateDnsActive = privateDnsActive,
            privateDnsServer = privateDnsServer,
            httpProxy = httpProxy,
            routes = routes,
            allInterfaces = allIfaces
        )
    }

    fun briefStatus(context: Context): String {
        val env = collect(context)
        val tr = env.transports.ifEmpty { listOf("Нет сети") }.joinToString("+")
        val dns = env.dnsServers.take(2).joinToString(", ").ifBlank { "—" }
        val v6 = if (env.ipv6Addresses.isNotEmpty()) "IPv6: да" else "IPv6: нет"
        val pdns = if (env.privateDnsActive) " · PrivateDNS" else ""
        return "Сеть: $tr · DNS: $dns · $v6$pdns"
    }
}

private object DiagModelsHelper {
    fun nowIso(): String = FullDiagReport.nowIso()
}
