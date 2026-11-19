package dev.warpscout.core.test

import dev.warpscout.core.crypto.Crypto
import dev.warpscout.core.junk.QuicMask
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Независимая «распаковка» сгенерированной QUIC-маски: снимаем header protection, расшифровываем
 * AES-GCM по ключам Initial из dcid, собираем CRYPTO-фреймы обратно в ClientHello и проверяем SNI.
 *
 * Это не «тест самого себя»: реализация идёт другим путём (RFC 9001 наоборот), поэтому если сборка
 * маски где-то врёт — проверка это поймает.
 */
object QuicMaskForTest {

    /** тот же salt, что и в QuicMask: 38762cf7f55934b34d179ae6a4c80cadccbb7f0a */
    private val INITIAL_SALT_V1 = byteArrayOf(
        0x38, 0x76, 0x2c, 0xf7.toByte(), 0xf5.toByte(), 0x59, 0x34, 0xb3.toByte(), 0x4d, 0x17,
        0x9a.toByte(), 0xe6.toByte(), 0xa4.toByte(), 0xc8.toByte(), 0x0c, 0xad.toByte(),
        0xcc.toByte(), 0xbb.toByte(), 0x7f, 0x0a
    )

    private class Header(val length: Int, val flags: Int, val pkn: Long, val dcidLen: Int, val pknOffset: Int)

    private fun readVarint(b: ByteArray, off: Int): Pair<Long, Int> {
        val first = b[off].toInt() and 0xff
        val len = 1 shl (first ushr 6)
        var v = (first and 0x3f).toLong()
        for (i in 1 until len) v = (v shl 8) or (b[off + i].toLong() and 0xff)
        return v to len
    }

    private fun parseHeader(packet: ByteArray): Header {
        var off = 5 // flags(1) + version(4)
        val dcidLen = packet[off].toInt() and 0xff
        off += 1 + dcidLen
        val scidLen = packet[off].toInt() and 0xff
        off += 1 + scidLen
        val (_, tokenLenLen) = readVarint(packet, off)
        off += tokenLenLen
        val (_, lenLen) = readVarint(packet, off)
        off += lenLen
        val pknOffset = off
        val flags = packet[0].toInt() and 0xff
        val pknLen = (flags and 0x03) + 1
        var pkn = 0L
        for (i in 0 until pknLen) pkn = (pkn shl 8) or (packet[pknOffset + i].toLong() and 0xff)
        return Header(pknOffset + pknLen, flags, pkn, dcidLen, pknOffset)
    }

    /** Возвращает пакет с восстановленными (unprotected) флагами и номером пакета. */
    fun unprotect(packet: ByteArray, dcid: ByteArray): ByteArray {
        val h = parseHeader(packet)
        val pknLen = (h.flags and 0x03) + 1
        val encrypted = packet.copyOfRange(h.length, packet.size)

        val initialSecret = Crypto.hmacSha256(INITIAL_SALT_V1, dcid)
        val clientSecret = Crypto.tlsDeriveSecret(initialSecret, 32, "client in")
        val hp = Crypto.tlsDeriveSecret(clientSecret, 16, "quic hp")

        val sampleStart = (4 - pknLen).coerceAtLeast(0)
        val mask = Crypto.aesEcbBlock(hp, encrypted.copyOfRange(sampleStart, sampleStart + 16))
            .also { it[0] = (it[0].toInt() and 0x0f).toByte() }

        val out = packet.copyOf()
        out[0] = (out[0].toInt() xor mask[0].toInt()).toByte()
        for (i in 0 until pknLen) {
            val at = h.pknOffset + i
            out[at] = (out[at].toInt() xor mask[1 + i].toInt()).toByte()
        }
        return out
    }

    /** Полный ClientHello, собранный из CRYPTO-фреймов (или пустой массив, если не собрался). */
    fun extractClientHello(packet: ByteArray, dcid: ByteArray): ByteArray {
        val unprotected = runCatching { unprotect(packet, dcid) }.getOrNull() ?: return ByteArray(0)
        val h = parseHeader(unprotected)
        val pknLen = (h.flags and 0x03) + 1
        val initialSecret = Crypto.hmacSha256(INITIAL_SALT_V1, dcid)
        val clientSecret = Crypto.tlsDeriveSecret(initialSecret, 32, "client in")
        val key = Crypto.tlsDeriveSecret(clientSecret, 16, "quic key")
        val iv = Crypto.tlsDeriveSecret(clientSecret, 12, "quic iv")

        var pkn = 0L
        for (i in 0 until pknLen) pkn = (pkn shl 8) or (unprotected[h.pknOffset + i].toLong() and 0xff)
        val nonce = iv.copyOf()
        // nonce = iv XOR номер пакета, выровненный вправо (RFC 9001 §5.3)
        val pknBytes = ByteArray(8)
        for (i in 0 until 8) pknBytes[i] = ((pkn ushr (8 * (7 - i))) and 0xff).toByte()
        Crypto.xorInto(nonce, nonce.size - 8, pknBytes, 0, 8)

        val aad = unprotected.copyOfRange(0, h.length)
        val ct = unprotected.copyOfRange(h.length, unprotected.size)

        val plain = try {
            val c = Cipher.getInstance("AES/GCM/NoPadding")
            c.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
            c.updateAAD(aad)
            c.doFinal(ct)
        } catch (e: Exception) {
            return ByteArray(0)
        }

        // CRYPTO-фреймы: 0x06 offset varint | length varint | data
        var off = 0
        val pieces = sortedMapOf<Int, ByteArray>()
        while (off < plain.size) {
            val type = plain[off].toInt() and 0xff
            if (type != 0x06) { off++; continue }
            off++
            val (offset, n1) = readVarint(plain, off); off += n1
            val (length, n2) = readVarint(plain, off); off += n2
            pieces[offset.toInt()] = plain.copyOfRange(off, off + length.toInt())
            off += length.toInt()
        }
        if (pieces.isEmpty()) return ByteArray(0)
        val total = pieces.entries.maxOf { it.key + it.value.size }
        val ch = ByteArray(total)
        for ((o, data) in pieces) data.copyInto(ch, o)
        return ch
    }
}
