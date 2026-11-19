package dev.warpscout.core.crypto

/**
 * BLAKE2s (RFC 7693) — неключевой и ключевой режим, произвольная длина дайджеста.
 *
 * Нужен нам в двух видах:
 *  1. `HASH(x)`  WireGuard = BLAKE2s-256(x)                  — используется в handshake-цепочке Noise_IKpsk2;
 *  2. `MAC(k,x)` WireGuard = Keyed BLAKE2s, 16 байт вывода   — поле mac1/mac2 в пакетах handshake;
 *  3. `HMAC(k,x)` = HMAC-BLAKE2s-256 (RFC 2104 поверх BLAKE2s) — обновление chaining key.
 *
 * Реализация своя (а не из BouncyCastle) потому, что BC не даёт собрать *ключевой*
 * Blake2s с укороченным дайджестом (16 байт), который требует протокол WireGuard.
 * Корректность проверяется в SelfTest против hashlib.blake2s (CPython) и RFC 7693.
 */
class Blake2s(private val digestLength: Int = 32, key: ByteArray? = null) {

    private val h = IntArray(8)
    private val block = ByteArray(BLOCK_BYTES)
    private var blockLen = 0
    private var counter = 0L

    init {
        require(digestLength in 1..32) { "BLAKE2s digestLength must be 1..32" }
        val keyLen = key?.size ?: 0
        require(keyLen <= 32) { "BLAKE2s key must be at most 32 bytes" }

        IV.copyInto(h)
        h[0] = h[0] xor (0x01010000 or (keyLen shl 8) or digestLength)

        if (key != null && keyLen > 0) {
            // Ключ дописывается первым полным 64-байтовым блоком (RFC 7693, §2.4.8).
            key.copyInto(block, 0, 0, keyLen)
            blockLen = BLOCK_BYTES
        }
    }

    fun update(input: ByteArray, offset: Int = 0, length: Int = input.size - offset) {
        var off = offset
        var left = length
        while (left > 0) {
            if (blockLen == BLOCK_BYTES) {
                // В буфере полный блок, а впереди ещё данные → жмём его, счётчик растёт.
                counter += BLOCK_BYTES
                compress(last = false)
                blockLen = 0
            }
            val take = minOf(BLOCK_BYTES - blockLen, left)
            input.copyInto(block, blockLen, off, off + take)
            blockLen += take
            off += take
            left -= take
        }
    }

    fun finalize(out: ByteArray, outOffset: Int = 0): Int {
        counter += blockLen
        for (i in blockLen until BLOCK_BYTES) block[i] = 0
        compress(last = true)
        for (i in 0 until digestLength) {
            out[outOffset + i] = (h[i ushr 2] ushr (8 * (i and 3))).toByte()
        }
        return digestLength
    }

    fun digest(input: ByteArray): ByteArray {
        update(input)
        val out = ByteArray(digestLength)
        finalize(out)
        return out
    }

    private fun compress(last: Boolean) {
        val m = IntArray(16)
        for (i in 0 until 16) {
            m[i] = (block[i * 4].toInt() and 0xff) or
                ((block[i * 4 + 1].toInt() and 0xff) shl 8) or
                ((block[i * 4 + 2].toInt() and 0xff) shl 16) or
                ((block[i * 4 + 3].toInt() and 0xff) shl 24)
        }

        val v = IntArray(16)
        h.copyInto(v, 0, 0, 8)
        IV.copyInto(v, 8, 0, 8)
        v[12] = v[12] xor (counter and 0xffffffffL).toInt()
        v[13] = v[13] xor ((counter ushr 32) and 0xffffffffL).toInt()
        if (last) v[14] = v[14] xor -1 // f0 = 0xFFFFFFFF

        for (r in 0 until ROUNDS) {
            val s = SIGMA[r % 10]
            g(v, 0, 4, 8, 12, m[s[0]], m[s[1]])
            g(v, 1, 5, 9, 13, m[s[2]], m[s[3]])
            g(v, 2, 6, 10, 14, m[s[4]], m[s[5]])
            g(v, 3, 7, 11, 15, m[s[6]], m[s[7]])
            g(v, 0, 5, 10, 15, m[s[8]], m[s[9]])
            g(v, 1, 6, 11, 12, m[s[10]], m[s[11]])
            g(v, 2, 7, 8, 13, m[s[12]], m[s[13]])
            g(v, 3, 4, 9, 14, m[s[14]], m[s[15]])
        }

        for (i in 0 until 8) h[i] = h[i] xor v[i] xor v[i + 8]
    }

    private inline fun g(v: IntArray, a: Int, b: Int, c: Int, d: Int, x: Int, y: Int) {
        v[a] = v[a] + v[b] + x
        v[d] = java.lang.Integer.rotateRight(v[d] xor v[a], 16)
        v[c] = v[c] + v[d]
        v[b] = java.lang.Integer.rotateRight(v[b] xor v[c], 12)
        v[a] = v[a] + v[b] + y
        v[d] = java.lang.Integer.rotateRight(v[d] xor v[a], 8)
        v[c] = v[c] + v[d]
        v[b] = java.lang.Integer.rotateRight(v[b] xor v[c], 7)
    }

    companion object {
        private const val BLOCK_BYTES = 64
        private const val ROUNDS = 10

        private val IV = intArrayOf(
            0x6A09E667.toInt(), 0xBB67AE85.toInt(), 0x3C6EF372, 0xA54FF53A.toInt(),
            0x510E527F, 0x9B05688C.toInt(), 0x1F83D9AB.toInt(), 0x5BE0CD19
        )

        private val SIGMA = arrayOf(
            intArrayOf(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15),
            intArrayOf(14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3),
            intArrayOf(11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4),
            intArrayOf(7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8),
            intArrayOf(9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13),
            intArrayOf(2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9),
            intArrayOf(12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11),
            intArrayOf(13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10),
            intArrayOf(6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5),
            intArrayOf(10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0)
        )

        fun hash(data: ByteArray, digestLength: Int = 32): ByteArray =
            Blake2s(digestLength).digest(data)

        /** Keyed BLAKE2s (то, что WireGuard называет MAC) — mac1/mac2, длина вывода 16. */
        fun mac(key: ByteArray, data: ByteArray, outLength: Int = 16): ByteArray =
            Blake2s(outLength, key).digest(data)

        /** HMAC-BLAKE2s-256 (то, что WireGuard называет HMAC). */
        fun hmac(keyIn: ByteArray, data: ByteArray, digestLength: Int = 32): ByteArray {
            var key = keyIn
            if (key.size > BLOCK_BYTES) key = Blake2s(BLOCK_BYTES, key).digest(EMPTY)
            val padded = ByteArray(BLOCK_BYTES)
            key.copyInto(padded, 0, 0, minOf(key.size, BLOCK_BYTES))
            val ipad = ByteArray(BLOCK_BYTES)
            val opad = ByteArray(BLOCK_BYTES)
            for (i in 0 until BLOCK_BYTES) {
                ipad[i] = (padded[i].toInt() xor 0x36).toByte()
                opad[i] = (padded[i].toInt() xor 0x5c).toByte()
            }
            val inner = Blake2s(digestLength).digest(ipad + data)   // H(ipad || data)
            return Blake2s(digestLength).digest(opad + inner)        // H(opad || inner)
        }

        private val EMPTY = ByteArray(0)
    }
}
