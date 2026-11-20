package dev.warpscout.core.crypto

import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import org.bouncycastle.crypto.params.X25519PublicKeyParameters
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec
import javax.crypto.spec.ChaCha20ParameterSpec

/**
 * Примитивы, которые нужны для сборки/разбора пакетов WireGuard и QUIC-масок.
 *
 * X25519 и ChaCha20-Poly1305 берём из BouncyCastle (работает идентично на Android и JVM),
 * AES-GCM/AES-ECB и HMAC-SHA256 — из стандартного JCA (есть на Android с API 1).
 */
object Crypto {

    val random = SecureRandom()

    // ---------------------------------------------------------------- encoding

    private const val B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

    fun base64(data: ByteArray): String {
        val sb = StringBuilder((data.size + 2) / 3 * 4)
        var i = 0
        while (i + 3 <= data.size) {
            val n = ((data[i].toInt() and 0xff) shl 16) or
                ((data[i + 1].toInt() and 0xff) shl 8) or
                (data[i + 2].toInt() and 0xff)
            sb.append(B64[(n ushr 18) and 63]).append(B64[(n ushr 12) and 63])
                .append(B64[(n ushr 6) and 63]).append(B64[n and 63])
            i += 3
        }
        when (data.size - i) {
            1 -> {
                val n = (data[i].toInt() and 0xff) shl 16
                sb.append(B64[(n ushr 18) and 63]).append(B64[(n ushr 12) and 63])
                    .append("==")
            }
            2 -> {
                val n = ((data[i].toInt() and 0xff) shl 16) or ((data[i + 1].toInt() and 0xff) shl 8)
                sb.append(B64[(n ushr 18) and 63]).append(B64[(n ushr 12) and 63])
                    .append(B64[(n ushr 6) and 63]).append('=')
            }
        }
        return sb.toString()
    }

    fun unBase64(text: String): ByteArray {
        val clean = text.filter { !it.isWhitespace() }
        val out = ByteArray(clean.length * 3 / 4)
        var o = 0
        var bits = 0
        var acc = 0
        for (ch in clean) {
            if (ch == '=') break
            val v = B64.indexOf(ch)
            require(v >= 0) { "не-base64 символ '$ch'" }
            acc = (acc shl 6) or v
            bits += 6
            if (bits >= 8) {
                bits -= 8
                out[o++] = (acc ushr bits and 0xff).toByte()
            }
        }
        return if (o == out.size) out else out.copyOf(o)
    }

    fun hex(data: ByteArray, upper: Boolean = false): String {
        val digits = if (upper) "0123456789ABCDEF" else "0123456789abcdef"
        val sb = StringBuilder(data.size * 2)
        for (b in data) {
            sb.append(digits[(b.toInt() shr 4) and 0xf]).append(digits[b.toInt() and 0xf])
        }
        return sb.toString()
    }

    fun unHex(text: String): ByteArray {
        val clean = text.filter { !it.isWhitespace() }.removePrefix("0x")
        require(clean.length % 2 == 0) { "чётная длина hex обязательна" }
        return ByteArray(clean.length / 2) {
            clean.substring(it * 2, it * 2 + 2).toInt(16).toByte()
        }
    }

    fun xorInto(dst: ByteArray, dstOff: Int, src: ByteArray, srcOff: Int, len: Int) {
        for (i in 0 until len) dst[dstOff + i] = (dst[dstOff + i].toInt() xor src[srcOff + i].toInt()).toByte()
    }

    fun le32(v: Int): ByteArray =
        byteArrayOf(v.toByte(), (v ushr 8).toByte(), (v ushr 16).toByte(), (v ushr 24).toByte())

    fun readLe32(b: ByteArray, off: Int): Int =
        (b[off].toInt() and 0xff) or ((b[off + 1].toInt() and 0xff) shl 8) or
            ((b[off + 2].toInt() and 0xff) shl 16) or ((b[off + 3].toInt() and 0xff) shl 24)

    /** Чтение uint64 little-endian (счётчик в transport-пакете WireGuard). */
    fun readLe64(b: ByteArray, off: Int): Long {
        var v = 0L
        for (i in 7 downTo 0) v = (v shl 8) or (b[off + i].toLong() and 0xff)
        return v
    }


    // ---------------------------------------------------------------- curves

    /** Генерация пары ключей WireGuard (32 байта, base64 наружу). */
    fun generateKeyPair(): KeyPair {
        val priv = X25519PrivateKeyParameters(random)
        return KeyPair(priv.getEncoded().copyOf(32), priv.generatePublicKey().encoded)
    }

    fun publicOf(privateKey: ByteArray): ByteArray =
        X25519PrivateKeyParameters(privateKey, 0).generatePublicKey().encoded

    fun dh(privateKey: ByteArray, peerPublicKey: ByteArray): ByteArray {
        val out = ByteArray(32)
        X25519PrivateKeyParameters(privateKey, 0)
            .generateSecret(X25519PublicKeyParameters(peerPublicKey, 0), out, 0)
        return out
    }

    // ---------------------------------------------------------------- aead

    /** Общий пустой AAD: в транспортных пакетах WireGuard он всегда пустой, а аллокация — на каждый пакет. */
    val EMPTY_AAD = ByteArray(0)

    /**
     * Один экземпляр AEAD на поток.
     *
     * Раньше `ChaCha20Poly1305()` создавался на **каждый пакет**: при сотне пакетов в секунду это
     * сотня объектов в секунду только на шифр, не считая параметров. На телефоне такой мусор
     * превращается в работу сборщика мусора, а он будит процессор — то есть в расход батареи.
     * Открытый текст и ключ в объекте не кэшируются: `init` обязателен для каждого nonce, так что
     * совместное использование безопасно, если экземпляр свой у каждого потока.
     */
    private val aeadPerThread = ThreadLocal.withInitial { org.bouncycastle.crypto.modes.ChaCha20Poly1305() }

    fun chacha20Poly1305Seal(key: ByteArray, nonce: ByteArray, plaintext: ByteArray, aad: ByteArray): ByteArray =
        chachaPoly(true, key, nonce, plaintext, aad)

    fun chacha20Poly1305Open(key: ByteArray, nonce: ByteArray, ciphertext: ByteArray, aad: ByteArray): ByteArray? =
        try {
            chachaPoly(false, key, nonce, ciphertext, aad)
        } catch (e: Exception) {
            null
        }

    private fun chachaPoly(
        encrypt: Boolean,
        key: ByteArray,
        nonce: ByteArray,
        input: ByteArray,
        aad: ByteArray
    ): ByteArray {
        require(nonce.size == 12) { "ChaCha20-Poly1305 nonce = 12 байт" }
        val c = aeadPerThread.get() ?: org.bouncycastle.crypto.modes.ChaCha20Poly1305()
        val params = org.bouncycastle.crypto.params.AEADParameters(
            org.bouncycastle.crypto.params.KeyParameter(key), 128, nonce, aad
        )
        c.init(encrypt, params)
        // Паттерн BC: processBytes + doFinal в тот же буфер, размер — из getOutputSize().
        val out = ByteArray(c.getOutputSize(input.size))
        var n = c.processBytes(input, 0, input.size, out, 0)
        n += c.doFinal(out, n)
        // Копируем только если размер не совпал: при шифровании он совпадает всегда, и лишняя
        // копия каждого пакета — это ещё один объект в кучу на ровном месте.
        return if (n == out.size) out else out.copyOf(n)
    }

// ------------------------------------------------ xchacha20poly1305 (cookie WG)

    /** HChaCha20 (§2.2 draft-irtf-cfrg-xchacha): 20 раундов, вывод = строки 0 и 3 без обратной связи. */
    fun hChaCha20(key: ByteArray, nonce16: ByteArray): ByteArray {
        require(key.size == 32 && nonce16.size == 16) { "HChaCha20: ключ 32, nonce 16 байт" }
        val s = IntArray(16)
        intArrayOf(0x61707865, 0x3320646e, 0x79622d32, 0x6b206574).copyInto(s, 0)
        for (i in 0 until 8) s[4 + i] = le32(key, i * 4)
        for (i in 0 until 4) s[12 + i] = le32(nonce16, i * 4)
        fun rot(v: Int, n: Int) = (v shl n) or (v ushr (32 - n))
        fun qr(a: Int, b: Int, c: Int, d: Int) {
            s[a] += s[b]; s[d] = rot(s[d] xor s[a], 16)
            s[c] += s[d]; s[b] = rot(s[b] xor s[c], 12)
            s[a] += s[b]; s[d] = rot(s[d] xor s[a], 8)
            s[c] += s[d]; s[b] = rot(s[b] xor s[c], 7)
        }
        repeat(10) {
            qr(0, 4, 8, 12); qr(1, 5, 9, 13); qr(2, 6, 10, 14); qr(3, 7, 11, 15)
            qr(0, 5, 10, 15); qr(1, 6, 11, 12); qr(2, 7, 8, 13); qr(3, 4, 9, 14)
        }
        val out = ByteArray(32)
        for (i in 0 until 4) putLe32(out, i * 4, s[i])
        for (i in 0 until 4) putLe32(out, 16 + i * 4, s[12 + i])
        return out
    }

    private fun le32(b: ByteArray, o: Int): Int =
        (b[o].toInt() and 0xff) or ((b[o + 1].toInt() and 0xff) shl 8) or
            ((b[o + 2].toInt() and 0xff) shl 16) or ((b[o + 3].toInt() and 0xff) shl 24)

    private fun putLe32(dst: ByteArray, o: Int, v: Int) {
        dst[o] = (v and 0xff).toByte(); dst[o + 1] = ((v ushr 8) and 0xff).toByte()
        dst[o + 2] = ((v ushr 16) and 0xff).toByte(); dst[o + 3] = ((v ushr 24) and 0xff).toByte()
    }

    /**
     * AEAD_XChaCha20_Poly1305 (draft-irtf-cfrg-xchacha). Нужен, чтобы расшифровать cookie reply
     * WireGuard: сервер шифрует cookie ключом BLAKE2s("cookie--" || публичный_ключ_сервера),
     * 24-байтным nonce и AAD = mac1 нашей инициации.
     */
    fun xChaCha20Poly1305Seal(key: ByteArray, nonce24: ByteArray, plaintext: ByteArray, aad: ByteArray): ByteArray {
        require(key.size == 32 && nonce24.size == 24) { "XChaCha20-Poly1305: ключ 32, nonce 24 байта" }
        val sub = hChaCha20(key, nonce24.copyOfRange(0, 16))
        val iv = ByteArray(4) + nonce24.copyOfRange(16, 24)
        val eng = org.bouncycastle.crypto.engines.ChaCha7539Engine()
        eng.init(false, org.bouncycastle.crypto.params.ParametersWithIV(
            org.bouncycastle.crypto.params.KeyParameter(sub), iv))
        val block0 = ByteArray(64)
        eng.processBytes(ByteArray(64), 0, 64, block0, 0)   // блок счётчика 0 → Poly1305-ключ
        val ks = ByteArray(plaintext.size)
        eng.processBytes(ByteArray(ks.size), 0, ks.size, ks, 0)  // дальше счётчик = 1
        val ct = ByteArray(plaintext.size)
        for (i in plaintext.indices) ct[i] = (plaintext[i].toInt() xor ks[i].toInt()).toByte()
        return ct + poly1305(block0.copyOfRange(0, 32), aad, ct)
    }

    fun xChaCha20Poly1305Open(key: ByteArray, nonce24: ByteArray, ciphertext: ByteArray, aad: ByteArray): ByteArray? {
        if (ciphertext.size < 16) return null
        val ct = ciphertext.copyOfRange(0, ciphertext.size - 16)
        val tag = ciphertext.copyOfRange(ciphertext.size - 16, ciphertext.size)
        val sub = hChaCha20(key, nonce24.copyOfRange(0, 16))
        val iv = ByteArray(4) + nonce24.copyOfRange(16, 24)
        val eng = org.bouncycastle.crypto.engines.ChaCha7539Engine()
        eng.init(false, org.bouncycastle.crypto.params.ParametersWithIV(
            org.bouncycastle.crypto.params.KeyParameter(sub), iv))
        val block0 = ByteArray(64)
        eng.processBytes(ByteArray(64), 0, 64, block0, 0)
        val ks = ByteArray(ct.size)
        eng.processBytes(ByteArray(ks.size), 0, ks.size, ks, 0)
        if (!java.security.MessageDigest.isEqual(poly1305(block0.copyOfRange(0, 32), aad, ct), tag)) return null
        val pt = ByteArray(ct.size)
        for (i in ct.indices) pt[i] = (ct[i].toInt() xor ks[i].toInt()).toByte()
        return pt
    }

    /** Poly1305 по RFC 8439 §2.5.1 (padding + длины в конце). */
    private fun poly1305(polyKey: ByteArray, aad: ByteArray, ct: ByteArray): ByteArray {
        val block = ArrayList<Byte>(aad.size + ct.size + 32)
        fun addAll(b: ByteArray) { b.forEach { block.add(it) } }
        fun pad(b: ByteArray) {
            addAll(b)
            val rem = b.size % 16
            if (rem != 0) repeat(16 - rem) { block.add(0) }
        }
        pad(aad); pad(ct)
        var v = aad.size.toLong()
        for (i in 0 until 8) { block.add((v and 0xff).toByte()); v = v ushr 8 }
        v = ct.size.toLong()
        for (i in 0 until 8) { block.add((v and 0xff).toByte()); v = v ushr 8 }
        val arr = block.toByteArray()
        val mac = org.bouncycastle.crypto.macs.Poly1305()
        mac.init(org.bouncycastle.crypto.params.KeyParameter(polyKey))
        mac.update(arr, 0, arr.size)
        val out = ByteArray(16)
        mac.doFinal(out, 0)
        return out
    }

    // ------------------------------------------------------------------- misc

    fun hmacSha256(key: ByteArray, data: ByteArray): ByteArray {
        val mac = javax.crypto.Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        return mac.doFinal(data)
    }

    /** HKDF-Expand-Label в варианте TLS 1.3 / QUIC (RFC 8446 §7.1 + RFC 9001 §5.1). */
    fun tlsDeriveSecret(secret: ByteArray, length: Int, label: String, context: ByteArray = ByteArray(0)): ByteArray {
        val full = "tls13 $label".toByteArray()
        val body = byteArrayOf(full.size.toByte()) + full +
            byteArrayOf(context.size.toByte()) + context +
            byteArrayOf(0x01)
        val prefixed = byteArrayOf(length.ushr(8).toByte(), length.toByte()) + body
        return hmacSha256(secret, prefixed).copyOf(length)
    }

    fun aesGcm(key: ByteArray, iv: ByteArray, plaintext: ByteArray, aad: ByteArray): ByteArray {
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(
            Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"),
            javax.crypto.spec.GCMParameterSpec(128, iv)
        )
        c.updateAAD(aad)
        return c.doFinal(plaintext)
    }

    /** Один блок AES-ECB — то же, что QUIC использует для header protection mask. */
    fun aesEcbBlock(key: ByteArray, block: ByteArray): ByteArray {
        val c = Cipher.getInstance("AES/ECB/NoPadding")
        c.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"))
        return c.doFinal(block.copyOf(16))
    }
}

/** Проверка, что JCA-реализация ChaCha20-Poly1305 доступна (нужно для SelfTest). */
fun jcaChaChaAvailable(): Boolean = try {
    val key = ByteArray(32)
    val c = Cipher.getInstance("ChaCha20-Poly1305")
    c.init(
        Cipher.ENCRYPT_MODE, SecretKeySpec(key, "ChaCha20"),
        ChaCha20ParameterSpec(ByteArray(12), 0)
    )
    c.updateAAD(ByteArray(0))
    c.doFinal(ByteArray(4))
    true
} catch (e: Throwable) {
    false
}

data class KeyPair(val privateBase64: ByteArray, val public: ByteArray) {
    val private: String get() = Crypto.base64(privateBase64)
    val publicBase64: String get() = Crypto.base64(public)
}
