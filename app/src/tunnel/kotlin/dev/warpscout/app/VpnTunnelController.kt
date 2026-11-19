package dev.warpscout.app

import android.app.Activity
import android.content.Context
import android.net.VpnService
import dev.warpscout.app.tunnel.TunnelState
import dev.warpscout.app.tunnel.WarpVpnService
import dev.warpscout.core.model.ResourceCheck
import dev.warpscout.core.model.ResourceResult
import dev.warpscout.core.model.WarpConfig
import dev.warpscout.core.net.ResourceProber
import dev.warpscout.core.tune.TunnelVerifier

class VpnTunnelController(private val context: Context) : TunnelController {

    override val supported: Boolean get() = true
    override val isUp: Boolean get() = TunnelState.up
    override val status: String get() = TunnelState.status

    override fun ensurePermission(activity: Activity): Boolean {
        val request = runCatching { VpnService.prepare(activity) }.getOrNull()
        if (request == null) return true
        runCatching { activity.startActivityForResult(request, REQUEST_VPN) }
        return false
    }

    override fun start(config: WarpConfig): Boolean {
        if (runCatching { VpnService.prepare(context) != null }.getOrDefault(true)) return false
        WarpVpnService.start(context, config)
        return true
    }

    override fun stop() = WarpVpnService.stop(context)

    override fun verifier(): TunnelVerifier = VpnTunnelVerifier(context)

    companion object {
        const val REQUEST_VPN = 4211
    }
}

/**
 * Поднимает туннель по проверяемой конфигурации, гоняет проверки ресурсов уже сквозь него и
 * гасит его. Это то, что отличает «порт отвечает» от «трафик реально идёт»: после смены
 * endpoint'а именно здесь видно, работает ли ChatGPT/Google/Discord из-под WARP.
 */
class VpnTunnelVerifier(private val context: Context) : TunnelVerifier {

    private val prober = ResourceProber()

    override val title: String get() = "собственный туннель WarpScout"

    override fun verify(config: WarpConfig, checks: List<ResourceCheck>, settleMs: Int): List<ResourceResult> {
        if (checks.isEmpty()) return emptyList()
        // Проверка «из-под туннеля» должна идти ЧЕРЕЗ туннель: снимаем привязку к non-VPN сети,
        // иначе CleanNetwork вернул бы нам ту же самую чистую сеть и смысл проверки пропал.
        CleanNetwork.unbind(context)
        if (!WarpVpnService.startAndWait(context, config, settleMs)) {
            return checks.map {
                ResourceResult(check = it, ok = false, errorClass = "tunnel_not_started")
            }
        }
        return try {
            checks.map { prober.check(it, "tunnel") }
        } finally {
            WarpVpnService.stop(context)
            CleanNetwork.bind(context)   // возвращаем «чистую» привязку для остатка подбора
        }
    }

    override fun stop() = WarpVpnService.stop(context)
}
