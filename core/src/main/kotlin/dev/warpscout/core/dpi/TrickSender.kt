package dev.warpscout.core.dpi

import java.io.IOException
import java.net.Socket

/**
 * Первый пакет соединения — кусками по приёму [DpiTrick]. Общий для проверки ([DpiProbe]: свой
 * ClientHello) и обхода в туннеле ([DpiRelay]: ClientHello приложения) — с 1.10.49-beta3; до того
 * жил внутри проверки.
 */
object TrickSender {

    /** Приём на этом телефоне не работает: нет доступа к TTL или срочный байт не уходит. */
    class Unsupported(message: String) : IOException(message)

    const val DEFAULT_TTL = 64

    /** Сколько держать TTL 1 после отправки куска (см. [send]). */
    const val LOW_TTL_HOLD_MS = 20L

    /** Пауза между кусками первого пакета: иначе ядро может склеить их в один пакет. */
    const val PIECE_GAP_MS = 15L

    /** Отправить [hello] кусками по плану [trick]. Паузы — чтобы куски ушли разными пакетами TCP. */
    fun send(s: Socket, hello: ByteArray, trick: DpiTrick, ttl: DpiProbe.SocketTtl?) {
        val out = s.getOutputStream()
        val pieces = TlsHello.plan(trick, hello)
        pieces.forEachIndexed { i, p ->
            if (p.lowTtl) {
                val t = ttl ?: throw Unsupported("нет доступа к TTL")
                val normal = runCatching { t.get(s) }.getOrNull()?.takeIf { it in 2..255 } ?: DEFAULT_TTL
                if (!runCatching { t.set(s, 1) }.getOrDefault(false)) throw Unsupported("система не дала поменять TTL")
                try {
                    out.write(p.bytes)
                    out.flush()
                    // Кусок должен уйти с TTL 1 до того, как вернём обычный: ядро может придержать
                    // мелкую запись на миллисекунды (autocork), и тогда он ушёл бы с обычным TTL.
                    Thread.sleep(LOW_TTL_HOLD_MS)
                } finally {
                    runCatching { t.set(s, normal) }
                }
            } else {
                out.write(p.bytes)
                out.flush()
            }
            if (p.oobAfter) {
                try {
                    s.sendUrgentData(TlsHello.OOB_BYTE)
                } catch (e: IOException) {
                    throw Unsupported("срочный байт не отправляется: ${e.message ?: e.javaClass.simpleName}")
                }
            }
            if (i < pieces.size - 1) Thread.sleep(PIECE_GAP_MS)
        }
    }
}
