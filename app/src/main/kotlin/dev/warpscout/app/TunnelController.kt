package dev.warpscout.app

import android.app.Activity
import dev.warpscout.core.model.WarpConfig
import dev.warpscout.core.tune.TunnelVerifier

/**
 * Мост к собственному туннелю. В сборке `scout` реализации нет (возвращается
 * [UnsupportedTunnelController]) — там конфигурация передаётся в AmneziaVPN.
 * В сборке `tunnel` работает [VpnTunnelController] поверх VpnService.
 */
interface TunnelController {
    val supported: Boolean
    val isUp: Boolean
    val status: String

    /** true — если разрешение на VPN уже выдано и туннель можно поднимать. */
    fun ensurePermission(activity: Activity): Boolean

    fun start(config: WarpConfig): Boolean
    fun stop()

    /** Код последней ошибки поднятия (`E_TUN`, `E_HANDSHAKE`, …) или null. */
    val lastError: String? get() = null

    /** Строка для UI: состояние + трафик. */
    val statusLine: String get() = status

    val bytesUp: Long get() = 0L
    val bytesDown: Long get() = 0L

    /** Проверка «трафик реально идёт»: несколько проб через поднятый туннель. Блокирующая. */
    fun selfTest(): String = "в этой сборке самопроверки туннеля нет"

    /** Журнал этапов поднятия туннеля (для копирования в отчёт/issue). */
    fun diagnostics(): String = ""

    fun clearDiagnostics() {}

    /** Верификация доступности ресурсов из-под туннеля; null — если туннеля нет. */
    fun verifier(): TunnelVerifier? = null
}

class UnsupportedTunnelController : TunnelController {
    override val supported: Boolean get() = false
    override val isUp: Boolean get() = false
    override val status: String get() = "Туннеля в этой сборке нет"
    override fun ensurePermission(activity: Activity): Boolean = false
    override fun start(config: WarpConfig): Boolean = false
    override fun stop() {}
}
