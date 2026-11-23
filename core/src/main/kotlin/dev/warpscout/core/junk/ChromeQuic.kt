package dev.warpscout.core.junk

import java.io.ByteArrayOutputStream

/**
 * Пакет «как Chrome» (с 1.10.40): первый пакет QUIC, с которого Chrome открывает сайт по HTTP/3.
 *
 * Откуда. Человек прислал конфиг WARP (23.11), который на его сети «прям хорошо работает со всеми
 * ресурсами». Особенное в нём одно — I1: записанный целиком первый пакет Chrome к apteka.ru, 1250 байт.
 * Ключи первого пакета QUIC публичны (RFC 9001, §5.2: выводятся из DCID пакета), поэтому фильтр
 * оператора его расшифровывает и видит то же, что увидел бы от браузера: QUIC v1, ClientHello с именем
 * российского сайта, расширения и параметры Chrome, PADDING до 1250 байт. Прежняя маска ([QuicMask]) —
 * 53–96 байт, половина случайные, расшифровать её нельзя, а браузер такой пакет не отправляет вовсе:
 * клиентский Initial короче 1200 байт запрещён (RFC 9000, §14.1). Фильтр, который это проверяет,
 * узнаёт подделку сразу.
 *
 * Что повторяем — по пакету из того конфига и по исходникам QUIC в Chromium:
 *  • заголовок: Initial, QUIC v1, DCID 8 байт, SCID пустой, без токена, номер пакета 1 в одном байте;
 *  • ClientHello TLS 1.3: три набора шифров, пустой session id, десять расширений Chrome — группы,
 *    подписи, имя сайта, ключ X25519, транспортные параметры QUIC (с параметрами Google и GREASE),
 *    ALPS и ALPN «h3», сжатие сертификата brotli, версии. Порядок расширений и параметров случайный —
 *    так делает Chrome (с версии 110). Без постквантового ключа: с ним ClientHello не влезает в один
 *    пакет, а такие соединения фильтры в России с конца 2024 года режут;
 *  • «chaos protection» Chrome: ClientHello разрезан на несколько CRYPTO-кусков, они перемешаны с PING
 *    и PADDING;
 *  • ровно 1250 байт.
 * Случайные поля (DCID, random, ключ, порядок, разрезы) — от зерна: профиль с тем же именем даёт те же
 * байты, иначе шум из памяти не совпал бы с проверенным подбором (см. JunkLibrary.byName / nameOf).
 * Пакет целиком — литерал: случайный кусок в нём испортил бы шифр, и фильтр не расшифровал бы пакет.
 */
object ChromeQuic {

    /** Размер пакета, как у Chrome: 1250 байт UDP. */
    const val SIZE = 1250

    /** Длина DCID у Chrome. */
    private const val DCID_LEN = 8

    /** Заголовок: флаги, версия, DCID (длина + 8), SCID (0), токен (0), длина (2 байта), номер (1). */
    private const val HEADER_LEN = 1 + 4 + 1 + DCID_LEN + 1 + 1 + 2 + 1

    /** Расширения ClientHello — типы, как у Chrome (для проверки и журнала). */
    val EXTENSIONS = listOf(0x000a, 0x000d, 0x0000, 0x0033, 0x0039, 0x4469, 0x002d, 0x0010, 0x001b, 0x002b)

    /** Пакет к [sni] целиком: зашифрованный Initial QUIC v1 на [SIZE] байт. */
    fun packet(sni: String, seed: Long): ByteArray {
        val rnd = java.util.Random(seed)
        val dcid = ByteArray(DCID_LEN).also { rnd.nextBytes(it) }
        val ch = clientHello(sni, rnd)
        val payload = frames(ch, SIZE - HEADER_LEN - 16, rnd, sniRange(ch, sni))
        val packet = QuicMask.initial(dcid, payload, pkn = byteArrayOf(1))
        check(packet.size == SIZE) { "пакет «как Chrome» — ${packet.size} байт вместо $SIZE" }
        return packet
    }

    /** ClientHello Chrome (TLS 1.3, QUIC) с именем [sni]. */
    fun clientHello(sni: String, rnd: java.util.Random): ByteArray {
        val name = sni.trim().lowercase().toByteArray(Charsets.US_ASCII)
        require(name.isNotEmpty() && name.size < 200) { "имя сайта для пакета «как Chrome»: «$sni»" }
        val random = ByteArray(32).also { rnd.nextBytes(it) }
        val share = ByteArray(32).also { rnd.nextBytes(it) }
        val h3 = byteArrayOf(2) + "h3".toByteArray(Charsets.US_ASCII)
        val extensions = mutableListOf(
            // supported_groups: X25519, P-256, P-384
            ext(0x000a, u16(6) + u16(0x001d) + u16(0x0017) + u16(0x0018)),
            // signature_algorithms: ECDSA-P256, RSA-PSS, RSA-PKCS1 и т. д. — как у Chrome
            ext(0x000d, u16(18) + unhex("040308040401050308050501080606010201")),
            // server_name
            ext(0x0000, u16(name.size + 3) + byteArrayOf(0) + u16(name.size) + name),
            // key_share: X25519
            ext(0x0033, u16(36) + u16(0x001d) + u16(32) + share),
            // quic_transport_parameters
            ext(0x0039, transportParameters(rnd)),
            // application_settings (ALPS, старый номер) для h3
            ext(0x4469, u16(h3.size) + h3),
            // psk_key_exchange_modes: psk_dhe_ke
            ext(0x002d, byteArrayOf(1, 1)),
            // ALPN: h3
            ext(0x0010, u16(h3.size) + h3),
            // compress_certificate: brotli
            ext(0x001b, byteArrayOf(2, 0, 2)),
            // supported_versions: TLS 1.3
            ext(0x002b, byteArrayOf(2, 3, 4)),
        )
        shuffle(extensions, rnd)
        val all = concat(extensions)
        val body = byteArrayOf(3, 3) + random + byteArrayOf(0) +
            u16(6) + unhex("130113021303") +
            byteArrayOf(1, 0) +
            u16(all.size) + all
        return byteArrayOf(1, (body.size ushr 16).toByte(), (body.size ushr 8).toByte(), body.size.toByte()) + body
    }

    /**
     * Транспортные параметры QUIC — значения Chrome: потоки, окна, тайм-аут 30 с, размер датаграммы,
     * параметры Google (версия, connection options) и по одному GREASE — версия вида 0x?a?a?a?a и
     * параметр с номером 31·N + 27 и случайным значением (RFC 9000 §18.1, RFC 9368).
     */
    private fun transportParameters(rnd: java.util.Random): ByteArray {
        val greaseVersion = (rnd.nextInt() and 0xf0f0f0f0.toInt()) or 0x0a0a0a0a
        val greaseId = ((rnd.nextLong() ushr 2) % ((1L shl 62) - 31)) / 31 * 31 + 27
        val greaseValue = ByteArray(rnd.nextInt(16)).also { rnd.nextBytes(it) }
        val params = mutableListOf(
            tp(0x0f, ByteArray(0)),                                    // initial_source_connection_id (SCID пустой)
            tp(0x08, QuicMask.varint(100)),                            // initial_max_streams_bidi
            tp(0x09, QuicMask.varint(103)),                            // initial_max_streams_uni
            tp(0x06, QuicMask.varint(6_291_456)),                      // initial_max_stream_data_uni
            tp(0x3128, "RVCM".toByteArray(Charsets.US_ASCII)),         // google_connection_options
            tp(0xff73db, u32(1) + u32(greaseVersion) + u32(1)),        // version_information
            tp(0x05, QuicMask.varint(6_291_456)),                      // initial_max_stream_data_bidi_remote
            tp(greaseId, greaseValue),                                 // GREASE
            tp(0x01, QuicMask.varint(30_000)),                         // max_idle_timeout
            tp(0x04, QuicMask.varint(15_728_640)),                     // initial_max_data
            tp(0x07, QuicMask.varint(6_291_456)),                      // initial_max_stream_data_bidi_local
            tp(0x4752, u32(1)),                                        // google_version
            tp(0x03, QuicMask.varint(1472)),                           // max_udp_payload_size
            tp(0x20, QuicMask.varint(65_536)),                         // max_datagram_frame_size
        )
        shuffle(params, rnd)
        return concat(params)
    }

    /**
     * Где в ClientHello расширение server_name — от его заголовка до конца имени. null — не нашлось.
     */
    fun sniRange(ch: ByteArray, sni: String): IntRange? {
        val name = sni.trim().lowercase().toByteArray(Charsets.US_ASCII)
        // Заголовок расширения: тип (2) + длина (2) + длина списка (2) + тип имени (1) + длина имени (2).
        for (at in 9..ch.size - name.size) {
            if (ch[at - 9].toInt() != 0 || ch[at - 8].toInt() != 0 || ch[at - 2].toInt() != (name.size ushr 8).toByte().toInt() ||
                ch[at - 1] != name.size.toByte()
            ) continue
            var same = true
            for (i in name.indices) if (ch[at + i] != name[i]) { same = false; break }
            if (same) return (at - 9) until (at + name.size)
        }
        return null
    }

    /**
     * Полезная нагрузка на [size] байт — как «chaos protection» в Chromium: ClientHello разрезан на
     * несколько CRYPTO-кусков в случайных местах, к ним добавлены PING, всё перемешано, а PADDING
     * разложен между кадрами (перед каждым — случайная доля остатка, остаток — в конец).
     *
     * Разрез не проходит через расширение с именем сайта ([whole]): Chrome это не важно, но фильтр,
     * который не склеивает куски, иначе имени не увидел бы. В пакете из конфига человека имя тоже лежит
     * в одном куске.
     */
    private fun frames(ch: ByteArray, size: Int, rnd: java.util.Random, whole: IntRange?): ByteArray {
        val pieces = mutableListOf(intArrayOf(0, ch.size))
        repeat(3 + rnd.nextInt(6)) {
            val p = pieces[rnd.nextInt(pieces.size)]
            if (p[1] > 1) {
                val keep = 1 + rnd.nextInt(p[1] - 1)
                val cut = p[0] + keep
                if (whole == null || cut <= whole.first || cut > whole.last) {
                    pieces += intArrayOf(cut, p[1] - keep)
                    p[1] = keep
                }
            }
        }
        val items = ArrayList<ByteArray>()
        for (p in pieces) {
            items += byteArrayOf(0x06) + QuicMask.varint(p[0].toLong()) + QuicMask.varint(p[1].toLong()) +
                ch.copyOfRange(p[0], p[0] + p[1])
        }
        repeat(1 + rnd.nextInt(4)) { items += byteArrayOf(0x01) }
        shuffle(items, rnd)
        var left = size - items.sumOf { it.size }
        require(left >= 0) { "ClientHello не помещается в пакет «как Chrome»" }
        val out = ByteArrayOutputStream(size)
        for (item in items) {
            val pad = if (left > 0) rnd.nextInt(left + 1) else 0
            out.write(ByteArray(pad))
            left -= pad
            out.write(item)
        }
        out.write(ByteArray(left))
        return out.toByteArray()
    }

    private fun ext(type: Int, data: ByteArray): ByteArray = u16(type) + u16(data.size) + data

    private fun tp(id: Long, value: ByteArray): ByteArray =
        QuicMask.varint(id) + QuicMask.varint(value.size.toLong()) + value

    private fun tp(id: Int, value: ByteArray): ByteArray = tp(id.toLong(), value)

    private fun u16(v: Int): ByteArray = byteArrayOf((v ushr 8).toByte(), v.toByte())

    private fun u32(v: Int): ByteArray =
        byteArrayOf((v ushr 24).toByte(), (v ushr 16).toByte(), (v ushr 8).toByte(), v.toByte())

    private fun unhex(s: String): ByteArray = ByteArray(s.length / 2) { i -> s.substring(2 * i, 2 * i + 2).toInt(16).toByte() }

    private fun concat(parts: List<ByteArray>): ByteArray {
        val out = ByteArrayOutputStream(parts.sumOf { it.size })
        parts.forEach { out.write(it) }
        return out.toByteArray()
    }

    /** Перемешать на месте от того же генератора (Fisher–Yates): порядок зависит только от зерна. */
    private fun <T> shuffle(list: MutableList<T>, rnd: java.util.Random) {
        for (i in list.size - 1 downTo 1) {
            val j = rnd.nextInt(i + 1)
            val t = list[i]
            list[i] = list[j]
            list[j] = t
        }
    }
}
