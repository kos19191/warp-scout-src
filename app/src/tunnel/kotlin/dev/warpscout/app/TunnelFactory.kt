package dev.warpscout.app

import android.content.Context

/** Сборка `tunnel`: собственный WireGuard-туннель через VpnService (см. tunnel/WarpVpnService.kt). */
object TunnelFactory {
    fun create(context: Context): TunnelController = VpnTunnelController(context.applicationContext)
}
