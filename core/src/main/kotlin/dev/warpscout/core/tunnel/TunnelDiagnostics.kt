package dev.warpscout.core.tunnel

import java.time.LocalTime
import java.time.format.DateTimeFormatter

/**
 * Журнал подъёма туннеля: короткий, с этапами и кодами ошибок.
 *
 * Зачем отдельно от logcat: у пользователя нет logcat. Симптом «нажал — написало „поднимается“ —
 * и ничего» раньше было невозможно объяснить, потому что причина затиралась статусом
 * «туннель остановлен». Здесь причина остаётся, а этапы видно по порядку.
 *
 * Кольцевой буфер на [CAPACITY] записей: памяти не жалко, а последние 300 строк всегда
 * можно скопировать одной кнопкой.
 */
object TunnelDiagnostics {

    /** Этапы жизни туннеля — ровно те, на которых он может умереть. */
    enum class Stage(val title: String) {
        START("старт"),
        CONFIG("конфиг"),
        SOCKET("сокет"),
        PROTECT("protect()"),
        TUN("tun"),
        HANDSHAKE("handshake"),
        TRANSPORT("трафик"),
        STOP("остановка"),
        REVOKE("отзыв разрешения"),
    }

    data class Event(val at: LocalTime, val stage: Stage, val message: String, val error: Boolean)

    const val CAPACITY = 300

    private val lock = Any()
    private val events = ArrayDeque<Event>(CAPACITY)
    private val timeFormat = DateTimeFormatter.ofPattern("HH:mm:ss.SSS")

    @Volatile
    var lastError: Event? = null
        private set

    fun log(stage: Stage, message: String) = add(Event(LocalTime.now(), stage, message, false))

    fun fail(stage: Stage, code: String, message: String) {
        val event = Event(LocalTime.now(), stage, "$code: $message", true)
        lastError = event
        add(event)
    }

    private fun add(event: Event) = synchronized(lock) {
        if (events.size >= CAPACITY) events.removeFirst()
        events.addLast(event)
    }

    fun clear() = synchronized(lock) {
        events.clear()
        lastError = null
    }

    fun dump(): String = synchronized(lock) {
        if (events.isEmpty()) return "журнал пуст: туннель ещё не запускали"
        buildString {
            appendLine("WARP Scout — журнал туннеля (${events.size} записей)")
            events.forEach { e ->
                append(if (e.error) "!! " else "   ")
                append(e.at.format(timeFormat)).append("  [").append(e.stage.title).append("] ")
                appendLine(e.message)
            }
        }.trimEnd()
    }

    /** Последние [n] строк — для строки состояния в UI. */
    fun tail(n: Int = 3): String = synchronized(lock) {
        events.takeLast(n).joinToString("\n") { "${it.stage.title}: ${it.message}" }
    }
}
