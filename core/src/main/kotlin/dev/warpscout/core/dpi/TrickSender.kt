package dev.warpscout.core.dpi

import java.io.IOException
import java.net.Socket

/**
 * Фейк ByeDPI без root (с 1.10.49-beta4): [fake] уходит в сеть с TTL [ttl] на месте [real] (той же
 * длины), а потом система сама пересылает уже [real] — фильтр видит чужое имя, сервер получает своё.
 *
 * ByeDPI на Linux делает это через vmsplice, на Windows — передачей из файла. В Android приложение
 * может то же через sendfile из своего файла: ядро не копирует байты, а ссылается на страницу файла;
 * после отправки страница переписывается настоящими байтами, и повтор уходит уже с ними (проверено
 * на ядре Linux: фильтр по пути видит фейк, сервер получает настоящее). Реализация — в приложении.
 */
interface FakeSender {
    fun send(socket: Socket, fake: ByteArray, real: ByteArray, ttl: Int, normalTtl: Int)
}

/**
 * Первый пакет соединения — кусками по приёму [DpiTrick]. Общий для проверки ([DpiProbe]: свой
 * ClientHello) и обхода в туннеле ([DpiRelay]: ClientHello приложения) — с 1.10.49-beta3; до того
 * жил внутри проверки. С beta4 — по строке ByeDPI ([DpiDesync]), с фейком.
 */
object TrickSender {

    /** Приём на этом телефоне не работает: нет доступа к TTL, фейка или срочный байт не уходит. */
    class Unsupported(message: String) : IOException(message)

    const val DEFAULT_TTL = 64

    /** Сколько держать TTL 1 после отправки куска (см. [send]). */
    const val LOW_TTL_HOLD_MS = 20L

    /** Пауза между кусками первого пакета: иначе ядро может склеить их в один пакет. */
    const val PIECE_GAP_MS = 15L

    /**
     * Отправить [hello] кусками по группе [group] стратегии приёма [trick]. Паузы — чтобы куски ушли
     * разными пакетами TCP.
     */
    fun send(
        s: Socket,
        hello: ByteArray,
        trick: DpiTrick,
        ttl: DpiProbe.SocketTtl?,
        fake: FakeSender? = null,
        group: Int = 0,
        rnd: java.util.Random = java.util.Random()
    ) {
        val out = s.getOutputStream()
        val st = trick.strategy
        val g = st.groups.getOrElse(group) { st.groups.first() }
        val pieces = if (st.isPlain || hello.size < 8) listOf(TlsHello.Piece(hello)) else DpiDesync.plan(hello, g, rnd).pieces
        val needTtl = st.defTtl > 0 || pieces.any { it.lowTtl || it.fake != null }
        var normal = DEFAULT_TTL
        if (needTtl) {
            val t = ttl ?: throw Unsupported("нет доступа к TTL")
            normal = runCatching { t.get(s) }.getOrNull()?.takeIf { it in 2..255 } ?: DEFAULT_TTL
            if (st.defTtl > 0) {
                if (!runCatching { t.set(s, st.defTtl) }.getOrDefault(false)) throw Unsupported("система не дала поменять TTL")
                normal = st.defTtl
            }
        }
        pieces.forEachIndexed { i, p ->
            val f = p.fake
            when {
                f != null -> {
                    val fs = fake ?: throw Unsupported("фейк на этом телефоне не отправить")
                    fs.send(s, f, p.bytes, p.fakeTtl.coerceIn(1, 255), normal)
                }

                p.lowTtl -> {
                    val t = ttl ?: throw Unsupported("нет доступа к TTL")
                    if (!runCatching { t.set(s, 1) }.getOrDefault(false)) throw Unsupported("система не дала поменять TTL")
                    try {
                        if (p.bytes.isNotEmpty()) {
                            out.write(p.bytes)
                            out.flush()
                        }
                        if (p.oobAfter) urgent(s, g.oobChar)
                        // Кусок должен уйти с TTL 1 до того, как вернём обычный: ядро может придержать
                        // мелкую запись на миллисекунды (autocork), и тогда он ушёл бы с обычным TTL.
                        Thread.sleep(LOW_TTL_HOLD_MS)
                    } finally {
                        runCatching { t.set(s, normal) }
                    }
                }

                else -> if (p.bytes.isNotEmpty()) {
                    out.write(p.bytes)
                    out.flush()
                }
            }
            if (p.oobAfter && !p.lowTtl) urgent(s, g.oobChar)
            if (i < pieces.size - 1) Thread.sleep(PIECE_GAP_MS)
        }
    }

    private fun urgent(s: Socket, c: Int) {
        try {
            s.sendUrgentData(c)
        } catch (e: IOException) {
            throw Unsupported("срочный байт не отправляется: ${e.message ?: e.javaClass.simpleName}")
        }
    }
}
