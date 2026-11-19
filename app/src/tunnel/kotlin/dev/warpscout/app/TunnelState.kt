package dev.warpscout.app.tunnel

import dev.warpscout.core.tunnel.TunnelDiagnostics

/**
 * Общее состояние туннеля: читают UI и верификатор, пишет — сервис.
 *
 * Отдельно хранится [error]: раньше причина падения записывалась в [status], а затем её затирал
 * `shutdown()` строкой «туннель остановлен» — и пользователь видел «ничего не произошло».
 * Теперь ошибка живёт до следующего запуска.
 */
object TunnelState {

    @Volatile
    var up: Boolean = false
        internal set

    @Volatile
    var status: String = ""

    /** Код последней ошибки (`E_TUN`, `E_HANDSHAKE`, …) или null. */
    @Volatile
    var error: String? = null
        private set

    @Volatile
    var stage: TunnelDiagnostics.Stage = TunnelDiagnostics.Stage.START
        private set

    @Volatile
    var endpoint: String = ""

    @Volatile
    var bytesUp: Long = 0L

    @Volatile
    var bytesDown: Long = 0L

    /** Прогресс без ошибки: «handshake…», «туннель поднят». */
    fun set(stage: TunnelDiagnostics.Stage, message: String) {
        this.stage = stage
        status = message
        TunnelDiagnostics.log(stage, message)
    }

    fun fail(stage: TunnelDiagnostics.Stage, code: String, message: String) {
        this.stage = stage
        error = code
        up = false
        status = "$code: $message"
        TunnelDiagnostics.fail(stage, code, message)
    }

    fun started() {
        up = true
        error = null
        bytesUp = 0
        bytesDown = 0
    }

    fun stopped(reason: String) {
        up = false
        status = if (error == null) reason else status
        TunnelDiagnostics.log(TunnelDiagnostics.Stage.STOP, reason)
    }

    fun reset() {
        up = false
        error = null
        status = ""
        endpoint = ""
        bytesUp = 0
        bytesDown = 0
        stage = TunnelDiagnostics.Stage.START
    }

    /** Одна строка для UI: состояние + трафик + причина, если есть. */
    fun summary(): String = when {
        up -> "туннель активен · ↑${humanBytes(bytesUp)} ↓${humanBytes(bytesDown)}"
        error != null -> status
        status.isNotBlank() -> status
        else -> "туннель выключен"
    }

    private fun humanBytes(value: Long): String = when {
        value < 1024 -> "$value Б"
        value < 1024 * 1024 -> "%.1f КБ".format(value / 1024.0)
        else -> "%.1f МБ".format(value / 1024.0 / 1024.0)
    }
}
