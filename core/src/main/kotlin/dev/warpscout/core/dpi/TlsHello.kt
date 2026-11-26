package dev.warpscout.core.dpi

/**
 * Первое сообщение TLS (ClientHello) и то, как его режут приёмы обхода DPI (с 1.10.49-beta2).
 *
 * Фильтр провайдера (ТСПУ) узнаёт сайт по имени (SNI) в первом пакете соединения: имя лежит в
 * ClientHello открытым текстом. Приёмы ByeDPI не прячут имя, а ломают фильтру разбор: режут пакет
 * посреди имени, делят запись TLS на две, отправляют части не по порядку или вставляют байт, который
 * сервер выбросит, а фильтр — нет. Сервер собирает всё как обычно.
 *
 * Здесь только байты: где в ClientHello имя, как запись делится на две и какими кусками что уходит.
 * Сеть — в [DpiProbe]. Позиции — как у ByeDPI: «1+s» = первый байт имени плюс один.
 */
object TlsHello {

    /** Имя сайта в записи ClientHello: смещение байтов имени от начала записи, длина и само имя. */
    data class Sni(val offset: Int, val length: Int, val name: String)

    /**
     * Кусок первого пакета. [lowTtl] — отправить с TTL 1: он умрёт на первом же маршрутизаторе, до
     * фильтра не дойдёт, и система сама перешлёт его позже, уже после остальных байтов. [oobAfter] —
     * сразу за куском отправить один срочный байт (TCP OOB): сервер его из потока выбросит, а фильтр,
     * который срочные данные не понимает, увидит лишний байт посреди имени.
     */
    class Piece(val bytes: ByteArray, val lowTtl: Boolean = false, val oobAfter: Boolean = false)

    /** Байт, который уходит срочным (OOB): как у ByeDPI по умолчанию. */
    const val OOB_BYTE: Int = 'a'.code

    private fun u8(b: ByteArray, i: Int): Int = b[i].toInt() and 0xFF
    private fun u16(b: ByteArray, i: Int): Int = (u8(b, i) shl 8) or u8(b, i + 1)

    /**
     * Где имя сайта в записи ClientHello. null — это не ClientHello, запись обрезана или имени нет.
     * Разбор строгий по длинам: ни одно поле не читается за пределами своей записи.
     */
    fun findSni(rec: ByteArray, len: Int = rec.size): Sni? {
        val size = minOf(len, rec.size)
        if (size < 5 + 4 + 2 + 32 + 1) return null
        if (u8(rec, 0) != 0x16) return null          // запись «handshake»
        val end = minOf(size, 5 + u16(rec, 3))
        var p = 5
        if (u8(rec, p) != 0x01) return null          // сообщение ClientHello
        p += 4                                       // тип + длина (3 байта)
        p += 2 + 32                                  // версия + random
        if (p >= end) return null
        p += 1 + u8(rec, p)                          // session_id
        if (p + 2 > end) return null
        p += 2 + u16(rec, p)                         // cipher_suites
        if (p + 1 > end) return null
        p += 1 + u8(rec, p)                          // compression_methods
        if (p + 2 > end) return null
        val extEnd = minOf(end, p + 2 + u16(rec, p))
        p += 2
        while (p + 4 <= extEnd) {
            val type = u16(rec, p)
            val l = u16(rec, p + 2)
            p += 4
            if (p + l > extEnd) return null
            if (type == 0x0000 && l >= 2) {          // server_name
                val listEnd = minOf(p + l, p + 2 + u16(rec, p))
                var q = p + 2
                while (q + 3 <= listEnd) {
                    val nameType = u8(rec, q)
                    val nameLen = u16(rec, q + 1)
                    q += 3
                    if (q + nameLen > listEnd) return null
                    if (nameType == 0 && nameLen > 0) {
                        return Sni(q, nameLen, String(rec, q, nameLen, Charsets.US_ASCII))
                    }
                    q += nameLen
                }
                return null
            }
            p += l
        }
        return null
    }

    /**
     * Позиция разреза «1+s»: первый байт имени плюс один (фильтр увидит в первом куске только «w»
     * от «www.youtube.com»). Имени нет — середина записи: тоже ломает разбор, хоть и хуже.
     */
    fun cutPos(hello: ByteArray): Int {
        val sni = findSni(hello)
        val recEnd = recordEnd(hello)
        val pos = if (sni != null) sni.offset + 1 else recEnd / 2
        return pos.coerceIn(6, maxOf(6, recEnd - 1))
    }

    /** Конец первой записи (заголовок 5 байт + длина); запись обрезана — размер массива. */
    fun recordEnd(hello: ByteArray): Int =
        if (hello.size < 5) hello.size else minOf(hello.size, 5 + u16(hello, 3))

    /**
     * Одна запись TLS → две (приём ByeDPI `--tlsrec`): первая несёт тело до [pos] (смещение от начала
     * записи), вторая — остальное. Заголовки — того же типа и версии. Всё, что шло после первой
     * записи, остаётся как было. Итог длиннее на 5 байт — второй заголовок.
     */
    fun splitRecord(rec: ByteArray, pos: Int): ByteArray {
        require(rec.size >= 6 && u8(rec, 0) == 0x16) { "это не запись handshake TLS" }
        val recLen = u16(rec, 3)
        val bodyEnd = 5 + recLen
        require(bodyEnd <= rec.size) { "запись обрезана: $bodyEnd > ${rec.size}" }
        require(pos in 6 until bodyEnd) { "разрез $pos вне тела записи 6..${bodyEnd - 1}" }
        val first = pos - 5
        val second = recLen - first
        val out = ByteArray(rec.size + 5)
        out[0] = rec[0]; out[1] = rec[1]; out[2] = rec[2]
        out[3] = (first ushr 8).toByte(); out[4] = first.toByte()
        System.arraycopy(rec, 5, out, 5, first)
        val h2 = 5 + first
        out[h2] = rec[0]; out[h2 + 1] = rec[1]; out[h2 + 2] = rec[2]
        out[h2 + 3] = (second ushr 8).toByte(); out[h2 + 4] = second.toByte()
        System.arraycopy(rec, pos, out, h2 + 5, rec.size - pos)
        return out
    }

    /**
     * Какими кусками уходит первый пакет при приёме [trick]. Склейка кусков (без срочного байта) —
     * ровно то, что получит сервер: для «как есть», разреза, перестановки и OOB это исходный
     * ClientHello, для «двух записей» — он же, поделённый на две записи.
     */
    fun plan(trick: DpiTrick, hello: ByteArray): List<Piece> {
        if (hello.size < 8) return listOf(Piece(hello))
        val cut = cutPos(hello)
        fun tlsrec(): ByteArray = runCatching { splitRecord(hello, cut) }.getOrDefault(hello)
        return when (trick) {
            DpiTrick.PLAIN -> listOf(Piece(hello))
            DpiTrick.SPLIT -> listOf(Piece(hello.copyOfRange(0, cut)), Piece(hello.copyOfRange(cut, hello.size)))
            DpiTrick.TLSREC -> listOf(Piece(tlsrec()))
            // `--disorder 1`: первый байт — с TTL 1. Фильтр видит поток с середины заголовка записи и
            // разобрать его не может, а пропавший байт система перешлёт сама, когда сервер о нём спросит.
            DpiTrick.DISORDER -> listOf(Piece(hello.copyOfRange(0, 1), lowTtl = true), Piece(hello.copyOfRange(1, hello.size)))
            DpiTrick.DISORDER_TLSREC -> tlsrec().let { rec ->
                listOf(Piece(rec.copyOfRange(0, 1), lowTtl = true), Piece(rec.copyOfRange(1, rec.size)))
            }
            DpiTrick.OOB -> listOf(Piece(hello.copyOfRange(0, cut), oobAfter = true), Piece(hello.copyOfRange(cut, hello.size)))
        }
    }

    /** Что получит сервер, если кусков [plan] — склейка без срочного байта (для проверок). */
    fun joined(pieces: List<Piece>): ByteArray {
        val out = java.io.ByteArrayOutputStream()
        pieces.forEach { out.write(it.bytes) }
        return out.toByteArray()
    }
}

/**
 * Приёмы обхода, которые приложение умеет само, без root и без ByeDPI. [byedpi] — те же приёмы в
 * параметрах ByeDPI: их можно перенести в ByeDPI на телефоне или в версию для компьютера.
 */
enum class DpiTrick(val id: String, val title: String, val byedpi: String, val needsTtl: Boolean = false) {
    PLAIN("plain", "как есть", ""),
    SPLIT("split", "разрез", "--split 1+s"),
    TLSREC("tlsrec", "две записи TLS", "--tlsrec 1+s"),
    DISORDER("disorder", "перестановка", "--disorder 1", needsTtl = true),
    DISORDER_TLSREC("disorder+tlsrec", "перестановка + две записи", "--disorder 1 --tlsrec 1+s", needsTtl = true),
    OOB("oob", "лишний байт (OOB)", "--oob 1+s");

    companion object {
        fun byId(id: String): DpiTrick? = entries.firstOrNull { it.id == id }

        /** Приёмы, кроме «как есть», — в порядке проверки: от самых безобидных к требующим TTL. */
        val BYPASS: List<DpiTrick> = listOf(SPLIT, TLSREC, DISORDER, DISORDER_TLSREC, OOB)
    }
}
