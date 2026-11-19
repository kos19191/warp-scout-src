package dev.warpscout.core.junk

import dev.warpscout.core.crypto.Crypto
import dev.warpscout.core.model.JunkChunk

/**
 * Генератор «QUIC-маски» — мусорного пакета, которым AmneziaWG засыпает канал перед настоящим
 * handshake. Порт алгоритма mini_quic_generator (тот же код, что крутится в warp-generation):
 * это корректно выглядящий QUIC v1 Initial-пакет с CRYPTO-фреймом, в котором лежит ClientHello
 * с SNI. Смысл: для DPI трафик похож на обычный QUIC к сайту из белого списка, а не на WireGuard.
 *
 * Формат вывода — шаблоны AmneziaWG: `<b 0x…>` (фиксированные байты) и `<r N>` (N случайных байт),
 * чтобы пакет не был байт-в-байт одинаковым.
 */
object QuicMask {

    /** salt дляInitial-ключей QUIC v1 (RFC 9001 §5.2). */
    /** initial salt для QUIC v1: 38762cf7f55934b34d179ae6a4c80cadccbb7f0a */
    private val INITIAL_SALT_V1 = byteArrayOf(
        0x38, 0x76, 0x2c, 0xf7.toByte(), 0xf5.toByte(), 0x59, 0x34, 0xb3.toByte(), 0x4d, 0x17,
        0x9a.toByte(), 0xe6.toByte(), 0xa4.toByte(), 0xc8.toByte(), 0x0c, 0xad.toByte(),
        0xcc.toByte(), 0xbb.toByte(), 0x7f, 0x0a
    )

    // ------------------------------------------------------------------ varint

    fun varintLen(value: Long): Int = when {
        value < 0x40 -> 1
        value < 0x4000 -> 2
        value < 0x40000000 -> 4
        else -> 8
    }

    fun varint(value: Long): ByteArray {
        return when {
            value < 0x40 -> byteArrayOf(value.toByte())
            value < 0x4000 -> {
                val b = ByteArray(2)
                b[0] = (value ushr 8).toByte(); b[1] = value.toByte()
                b[0] = (b[0].toInt() or 0x40).toByte(); b
            }
            value < 0x40000000 -> {
                val b = ByteArray(4)
                for (i in 0 until 4) b[i] = (value ushr (8 * (3 - i))).toByte()
                b[0] = (b[0].toInt() or 0x80).toByte(); b
            }
            else -> {
                val b = ByteArray(8)
                for (i in 0 until 8) b[i] = (value ushr (8 * (7 - i))).toByte()
                b[0] = (b[0].toInt() or 0xC0).toByte(); b
            }
        }
    }

    private fun str8(data: ByteArray): ByteArray = byteArrayOf(data.size.toByte()) + data
    private fun str16(data: ByteArray): ByteArray =
        byteArrayOf((data.size ushr 8).toByte(), data.size.toByte()) + data

    // ------------------------------------------------------------------- TLS CH

    /** ClientHello «только SNI» — ровно как в генераторе (без шифрования, это же декорация). */
    fun clientHelloSniOnly(sni: String, chRandom: ByteArray): ByteArray {
        require(chRandom.size == 32)
        val sniBytes = sni.toByteArray()
        val sniList = str16(sniBytes)                        // ServerNameList length + name
        val extInner = ByteArray(3 + sniList.size).also {
            it[0] = ((sniList.size + 1) ushr 8).toByte()
            it[1] = (sniList.size + 1).toByte()
            it[2] = 0                                         // host_name
            sniList.copyInto(it, 3)
        }
        val ext = ByteArray(4 + extInner.size).also {
            it[0] = 0; it[1] = 0                              // extension_type = server_name (0)
            it[2] = (extInner.size ushr 8).toByte()
            it[3] = extInner.size.toByte()
            extInner.copyInto(it, 4)
        }
        val sniExtBlock = str16(ext)                          // extensions block
        val body = ByteArray(2 + 32 + 4) .also {
            it[0] = 0x03; it[1] = 0x03
            chRandom.copyInto(it, 2)
            // session_id: длина 0 (4 байта: 0,0,0,0 — как в исходном генераторе)
        } + sniExtBlock

        val out = ByteArray(4 + body.size)
        val len = body.size
        out[0] = 0x01                                          // handshake_type = client_hello
        out[1] = (len ushr 16).toByte()
        out[2] = (len ushr 8).toByte()
        out[3] = len.toByte()
        body.copyInto(out, 4)
        return out
    }

    private fun cryptoFrame(data: ByteArray, offset: Int): ByteArray =
        byteArrayOf(0x06) + varint(offset.toLong()) + varint(data.size.toLong()) + data

    /** Разрезание ClientHello на CRYPTO-фреймы (уровни «правдоподобия» 1..4 как в генераторе). */
    /** @return пара (payload-в-криптофреймах, cutSettings для AWG-шаблона). */
    fun clientHelloToFrames(ch: ByteArray, level: Int): Pair<ByteArray, IntArray> {
        if (level == 0) {
            val payload = cryptoFrame(ch, 0)
            val dataOffset = payload.size - ch.size
            return payload to intArrayOf(dataOffset + 6, 32, ch.size - 38, 16)
        }
        val preset: List<Any> = when (level) {
            1 -> listOf(38, Int.MAX_VALUE, 0, 38, 32, false)
            2 -> listOf(38, Int.MAX_VALUE, 0, 38, 37, false)
            3 -> listOf(0, 1, 38, Int.MAX_VALUE, 0, false)
            else -> listOf(0, 1, 38, Int.MAX_VALUE, 0, true)
        }
        var p1s = preset[0] as Int
        val p1e = preset[1] as Int
        var p2s = preset[2] as Int
        val p2e = preset[3] as Int
        val dropTail = preset[4] as Int
        val skipZeroes = preset[5] as Boolean

        if (skipZeroes) while (p2s < ch.size && ch[p2s].toInt() == 0) p2s++

        val payload = cryptoFrame(ch.copyOfRange(p1s, minOf(p1e, ch.size)), p1s) +
            cryptoFrame(ch.copyOfRange(p2s, minOf(p2e, ch.size)), p2s)
        return payload to intArrayOf(payload.size - dropTail, 16 + dropTail)
    }

    // ------------------------------------------------------------- Initial packet

    data class Lengths(val total: Int, val header: Int, val padding: Int)

    private fun measureLengths(
        dcidLen: Int,
        scidLen: Int,
        tokenLen: Int,
        pknLen: Int,
        payloadLen: Int,
        padto: Int
    ): Lengths {
        val baseHeader = 8 + dcidLen + scidLen + tokenLen + pknLen
        val tag = 16
        var padding = 0
        fun lengthBytes() = varintLen((pknLen + payloadLen + padding + tag).toLong())
        fun overall() = baseHeader + lengthBytes() + payloadLen + padding + tag

        var total = overall()
        if (total < padto) {
            padding = padto - total
            while (padding > 0 && overall() > padto) padding--
            if (overall() < padto) padding++
            total = overall()
        }
        if (pknLen + payloadLen + padding + tag < 20) {
            padding = 20 - pknLen - payloadLen - tag
            total = overall()
        }
        return Lengths(total, baseHeader + lengthBytes(), padding)
    }

    /**
     * Сборка пакета Initial: заголовок, AES-GCM по ключам «client in» из QUIC v1, header protection.
     * Возвращает (пакет, cutSettings) — cutSettings говорит, какие байты оставить литералом в I1.
     */
    fun initial(dcid: ByteArray, payload: ByteArray, pkn: ByteArray = byteArrayOf(0), padto: Int = 0): ByteArray {
        val lengths = measureLengths(dcid.size, 0, 0, pkn.size, payload.size, padto)
        val payloadTotal = (pkn.size + payload.size + lengths.padding + 16).toLong()
        val header = byteArrayOf((0xC0 or (pkn.size - 1)).toByte(), 0, 0, 0, 1) +
            str8(dcid) + str8(ByteArray(0)) + str8(ByteArray(0)) + varint(payloadTotal) + pkn

        val initialSecret = Crypto.hmacSha256(INITIAL_SALT_V1, dcid)
        val clientSecret = Crypto.tlsDeriveSecret(initialSecret, 32, "client in")
        val key = Crypto.tlsDeriveSecret(clientSecret, 16, "quic key")
        val iv = Crypto.tlsDeriveSecret(clientSecret, 12, "quic iv")
        val hp = Crypto.tlsDeriveSecret(clientSecret, 16, "quic hp")
        Crypto.xorInto(iv, iv.size - pkn.size, pkn, 0, pkn.size)

        val padded = payload + ByteArray(lengths.padding)
        val encrypted = Crypto.aesGcm(key, iv, padded, header)

        val sampleStart = 4 - pkn.size
        val mask = Crypto.aesEcbBlock(hp, encrypted.copyOfRange(sampleStart, sampleStart + 16))
        mask[0] = (mask[0].toInt() and 0x0f).toByte()
        val hdr = header.copyOf()
        hdr[0] = (hdr[0].toInt() xor mask[0].toInt()).toByte()
        for (i in pkn.indices) {
            val at = hdr.size - pkn.size + i
            hdr[at] = (hdr[at].toInt() xor mask[1 + i].toInt()).toByte()
        }
        return hdr + encrypted
    }

    /** То же самое, что quicFixCutSettings + quicToAWG в генераторе. */
    fun buildTemplate(sni: String, level: Int = 3, seed: Long? = null): List<JunkChunk> {
        val rnd = if (seed != null) java.util.Random(seed) else java.util.Random()
        val dcid = ByteArray(1).also { it[0] = (rnd.nextInt(256)).toByte() }
        val chRandom = ByteArray(32).also { rnd.nextBytes(it) }
        val ch = clientHelloSniOnly(sni, chRandom)
        val (payload, cut0) = clientHelloToFrames(ch, level)
        val packet = initial(dcid, payload)

        val cut = cut0.copyOf()
        if (cut[0] < 20 - 1) {
            val toAdd = 20 - 1 - cut[0]
            cut[0] += toAdd
            cut[1] -= toAdd
        }
        cut[0] += packet.size - payload.size - 16

        return toAwgChunks(packet, cut)
    }

    /** `<b 0x…><r N>` — чередование буквальных и случайных участков. */
    fun toAwgChunks(packet: ByteArray, cut: IntArray, includeFirst: Boolean = true): List<JunkChunk> {
        if (cut.isEmpty()) return listOf(JunkChunk.Literal(packet))
        val out = mutableListOf<JunkChunk>()
        var offset = 0
        var include = includeFirst
        var idx = 0
        while (idx < cut.size && offset < packet.size) {
            val part = cut[idx]
            if (part > 0) {
                val take = minOf(part, packet.size - offset)
                if (include) out.add(JunkChunk.Literal(packet.copyOfRange(offset, offset + take)))
                else if (take > 0) out.add(JunkChunk.RandomBytes(take))
                offset += take
            }
            include = !include
            idx++
        }
        if (offset < packet.size) out.add(JunkChunk.Literal(packet.copyOfRange(offset, packet.size)))
        return out
    }
}
