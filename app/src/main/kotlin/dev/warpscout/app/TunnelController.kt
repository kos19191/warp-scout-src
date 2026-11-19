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

    /**
     * Поднять и дождаться реального handshake. Возвращает true только если туннель действительно
     * работает — «сервис запущен» и «туннель поднят» это разные вещи, и врать про второе нельзя.
     * [waitMs] — сколько ждём; причина отказа потом читается в [lastError] и [debugDump].
     */
    fun startAndAwait(config: WarpConfig, waitMs: Int = 20000): Boolean = start(config)

    /** Верификация доступности ресурсов из-под туннеля; null — если туннеля нет. */
    fun verifier(): TunnelVerifier? = null

    /** Последняя понятная причина отказа, если она была. */
    fun lastError(): String? = null

    /** Журнал этапов туннеля — то, что просят прислать в issue. */
    fun debugDump(): String = ""

    /**
     * Ждём, пока прошлая сессия действительно завершится. Без этого переподключение (смена точки,
     * изменение настроек, «Отключить» + «Подключить») упирается в «уже поднимается»: сервис
     * асинхронный, и старый подъём ещё жив.
     */
    fun waitStopped(timeoutMs: Int): Boolean = true
}

class UnsupportedTunnelController : TunnelController {
    override val supported: Boolean get() = false
    override val isUp: Boolean get() = false
    override val status: String get() = "Туннеля в этой сборке нет"
    override fun ensurePermission(activity: Activity): Boolean = false
    override fun start(config: WarpConfig): Boolean = false
    override fun startAndAwait(config: WarpConfig, waitMs: Int): Boolean = false
    override fun stop() {}
    override fun lastError(): String? = "в этой сборке туннеля нет: собирай flavor tunnel"
}
