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
     * Сервис держит туннель: он поднят, поднимается, переподключается или ждёт повтора. Пока это
     * так, кнопка предлагает «Выключить» — иначе туннель, который ждёт повтора, выключить было
     * нечем: кнопка звала «Включить», а сервис продолжал переподключаться сам.
     */
    val active: Boolean get() = isUp

    /**
     * Выключить по просьбе человека. В отличие от [stop] (его зовут и перебор точек, и подбор
     * перед замерами) это решение «больше не включать самому»: переподключения и фоновый подбор
     * после него молчат, пока человек сам не нажмёт «Включить».
     */
    fun stopByUser() = stop()

    /**
     * Поднять и дождаться реального handshake. Возвращает true только если туннель действительно
     * работает — «сервис запущен» и «туннель поднят» это разные вещи, и врать про второе нельзя.
     * [waitMs] — сколько ждём; причина отказа потом читается в [lastError] и [debugDump].
     */
    fun startAndAwait(config: WarpConfig, waitMs: Int = 20000): Boolean = start(config)

    /**
     * То же, но с отменой: [isCancelled] спрашивается всё время ожидания, и при `true` ожидание
     * обрывается сразу, а не по истечении [waitMs]. Туннель гасит тот, кто отменил.
     *
     * [requestedAt] — когда человек начал подключение. Если после этого туннель выключили вручную
     * (плитка, «Отключить» в уведомлении), сервис такой старт пропустит: он опоздал.
     */
    fun startAndAwait(config: WarpConfig, waitMs: Int, requestedAt: Long, isCancelled: () -> Boolean): Boolean =
        startAndAwait(config, waitMs)

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
