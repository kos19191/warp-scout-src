package dev.warpscout.app

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.Build

/**
 * Чужой VPN — включённый VPN другого приложения (с 1.10.45, просьба 25.11: «не давай сканировать
 * сеть, если другой VPN включён, — предупреждай, чтобы его отключили»).
 *
 * Почему подбор при чужом VPN не запускается, а не «обходит» его ([CleanNetwork]):
 *  • обойти чужой туннель Android разрешает, только если тот VPN сам это позволил
 *    (VpnService.Builder.allowBypass), — по умолчанию замеры молча шли бы через чужой туннель;
 *  • подбор сам поднимает туннель WarpScout для проверки изнутри (VpnTunnelVerifier), а приложению,
 *    которому разрешение на VPN уже давали, Android на это без спроса отключает чужой VPN — человек
 *    оставался без VPN вообще.
 * Выключить чужой VPN честно может только сам человек — ему и говорим.
 *
 * Свой туннель от чужого отличаем так. Android держит один VPN на пользователя; с Android 10
 * владельцу VPN система показывает его uid (NetworkCapabilities.getOwnerUid), остальным — -1, а
 * процессы приложения и туннеля — один uid. До Android 10 владельца не видно: VPN считаем своим,
 * пока свой туннель поднят или его держит сервис.
 */
object ForeignVpn {

    /**
     * Имя интерфейса чужого VPN («tun0»; «VPN», если имени нет) или null — чужого VPN нет.
     * [ownUp] — свой туннель поднят или сервис его держит (подключается, ждёт повтора).
     */
    fun find(context: Context, ownUp: Boolean): String? = runCatching { scan(context, ownUp) }.getOrNull()

    private fun scan(context: Context, ownUp: Boolean): String? {
        val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager ?: return null
        val me = android.os.Process.myUid()
        @Suppress("DEPRECATION")
        val nets = cm.allNetworks
        for (n in nets) {
            val caps = runCatching { cm.getNetworkCapabilities(n) }.getOrNull() ?: continue
            if (!caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) continue
            val owner = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) caps.ownerUid else -1
            if (owner == me) continue
            // Владелец скрыт, а свой туннель поднят: два VPN сразу Android не держит — это наш.
            if (owner < 0 && ownUp) continue
            val name = runCatching { cm.getLinkProperties(n)?.interfaceName }.getOrNull()
            return name?.takeIf { it.isNotBlank() } ?: "VPN"
        }
        return null
    }
}
