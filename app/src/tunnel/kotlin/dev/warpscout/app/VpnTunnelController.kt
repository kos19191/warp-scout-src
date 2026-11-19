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
import dev.warpscout.core.tunnel.TunnelDiagnostics

class VpnTunnelController(private val context: Context) : TunnelController {

    override val supported: Boolean get() = true
    override val isUp: Boolean get() = TunnelState.up
    override val status: String get() = TunnelState.status
    override val lastError: String? get() = TunnelState.error
    override val statusLine: String get() = TunnelState.summary()
    override val bytesUp: Long get() = TunnelState.bytesUp
    override val bytesDown: Long get() = TunnelState.bytesDown

    /** true — разрешение уже есть; false — диалог показан (или показать не удалось, см. [status]). */
    override fun ensurePermission(activity: Activity): Boolean {
        val request = runCatching { VpnService.prepare(activity) }.getOrNull()
        if (request == null) return true
        runCatching { activity.startActivityForResult(request, REQUEST_VPN) }
            .onFailure { TunnelState.fail(TunnelDiagnostics.Stage.START, "E_PERMISSION", "диалог VPN не открылся: ${it.message}") }
        return false
    }

    override fun start(config: WarpConfig): Boolean {
        if (runCatching { VpnService.prepare(context) != null }.getOrDefault(true)) {
            TunnelState.fail(TunnelDiagnostics.Stage.START, "E_PERMISSION", "нет разрешения на VPN — нажмите «Туннель» ещё раз")
            return false
        }
        WarpVpnService.start(context, config)
        return true
    }

    override fun stop() = WarpVpnService.stop(context)

    override fun diagnostics(): String = TunnelDiagnostics.dump()

    override fun clearDiagnostics() = TunnelDiagnostics.clear()

    /**
     * Проверка «трафик реально идёт»: три пробы через поднятый туннель. Это то, чего не хватало —
     * «туннель поднят» и «через туннель что-то открывается» — разные вещи.
     */
    override fun selfTest(): String {
        if (!isUp) return "туннель не поднят: сначала включите его, потом проверяйте"
        val prober = ResourceProber()
        val checks = listOf(
            ResourceCheck("Cloudflare trace", "https://www.cloudflare.com/cdn-cgi/trace", 200..399),
            ResourceCheck("YouTube", "https://www.youtube.com/", 200..399),
            ResourceCheck("Telegram web", "https://web.telegram.org/a/", 200..399),
            ResourceCheck("ChatGPT", "https://chatgpt.com/cdn-cgi/trace", 200..399)
        )
        val results = runCatching { checks.map { prober.check(it, "tunnel") } }
            .getOrElse { return "пробы не выполнились: ${it.javaClass.simpleName}: ${it.message}" }
        val okCount = results.count { it.ok }
        return buildString {
            appendLine("$okCount/${results.size} через туннель · ↑${TunnelState.bytesUp} Б ↓${TunnelState.bytesDown} Б")
            results.forEach { appendLine(line(it)) }
        }.trimEnd()
    }

    private fun line(r: ResourceResult): String =
        (if (r.ok) "✓ " else "✗ ") + r.check.name + " — " + (r.status?.toString() ?: r.errorClass ?: "—") + ", ${r.elapsedMs} мс"

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
            val why = TunnelState.lastErrorOrStatus()
            return checks.map {
                ResourceResult(check = it, ok = false, errorClass = "tunnel_not_started: $why")
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

/** Единая строка «почему не поднялся» — используется и в отчёте, и в UI. */
internal fun TunnelState.lastErrorOrStatus(): String = error ?: status.ifBlank { "причина неизвестна" }
