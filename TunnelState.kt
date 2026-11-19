package dev.warpscout.app.tunnel

/** Общее состояние туннеля: читают UI и верификатор, пишет — сервис. */
object TunnelState {
    @Volatile
    var up: Boolean = false

    @Volatile
    var status: String = ""

    @Volatile
    var endpoint: String = ""
}
