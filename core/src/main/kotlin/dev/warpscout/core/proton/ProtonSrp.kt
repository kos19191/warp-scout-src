package dev.warpscout.core.proton

import dev.warpscout.core.crypto.Crypto
import org.bouncycastle.crypto.generators.OpenBSDBCrypt
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import java.math.BigInteger
import java.security.MessageDigest
import java.security.SecureRandom

/** Вход не удался на нашей стороне: модуль без подписи Proton, неверные числа, чужой ответ сервера. */
class SrpException(message: String) : Exception(message)

/**
 * Вход в аккаунт Proton по SRP (с 1.10.44-beta5): пароль на сервер не уходит вовсе — ни открытым
 * текстом, ни хешем. Телефон и сервер доказывают друг другу, что знают одно и то же, и из обмена
 * пароль не восстановить.
 *
 * Повторяет go-srp (github.com/ProtonMail/go-srp) и python-proton-core (srp/_pysrp.py) — клиентов
 * самого Proton: SRP-6a на 2048 битах, генератор 2, числа в little-endian, хеш — SHA-512, растянутый
 * до 256 байт, пароль — bcrypt («$2y$10$», соль из ответа сервера и «proton»). Проверено их же
 * тестовыми наборами (см. ProtonChecks).
 *
 * Модуль приходит подписанным: подпись проверяем ключом Proton, зашитым в приложение (как go-srp),
 * — подменить модуль на слабый не выйдет даже тому, кто вклинится в соединение.
 */
object ProtonSrp {

    const val BITS = 2048
    const val BYTES = BITS / 8

    /**
     * Ключ, которым Proton подписывает модули SRP: EdDSA «proton@srp.modulus», ID 350585C4E9518F26.
     * Это открытая часть ключа из go-srp (modulusPubkey), вынутая из PGP-блока.
     */
    private val MODULUS_KEY: ByteArray = Crypto.unHex("16ead65d7c234de9aa8c3ec25e35d5c8a7f4a1fee7f42b662fcbfd7a79338201")

    private val TWO: BigInteger = BigInteger.valueOf(2)

    class Proofs(
        /** A — наше открытое число (256 байт, little-endian). */
        val clientEphemeral: ByteArray,
        /** M1 — доказательство, что пароль знаем мы. */
        val clientProof: ByteArray,
        /** M2, которого ждём от сервера: совпало — значит, это настоящий Proton с нашим паролем. */
        val expectedServerProof: ByteArray,
    )

    /** SHA-512 четыре раза (с байтом 0…3 в конце) — 256 байт: хеш SRP у Proton. */
    fun expandHash(data: ByteArray): ByteArray {
        val out = ByteArray(256)
        for (i in 0 until 4) {
            val md = MessageDigest.getInstance("SHA-512")
            md.update(data)
            md.update(i.toByte())
            md.digest().copyInto(out, i * 64)
        }
        return out
    }

    /**
     * Пароль → x (версии 3 и 4, другие Proton не выдаёт с 2018 года): bcrypt с солью «соль + proton»
     * (16 байт), затем растянутый хеш от строки bcrypt и модуля. Пароль длиннее 72 байт bcrypt
     * обрезает — так же, как python-proton-core.
     */
    fun hashPassword(password: ByteArray, salt: ByteArray, modulus: ByteArray): ByteArray {
        val bsalt = (salt + "proton".toByteArray(Charsets.US_ASCII)).copyOf(16)
        if (salt.size + 6 < 16) throw SrpException("соль SRP короче 10 байт (${salt.size})")
        val pwd = if (password.size > 72) password.copyOf(72) else password.copyOf()
        val crypted = OpenBSDBCrypt.generate("2y", pwd, bsalt, 10)
        pwd.fill(0)
        return expandHash(crypted.toByteArray(Charsets.US_ASCII) + modulus)
    }

    fun fromLe(b: ByteArray): BigInteger = BigInteger(1, b.reversedArray())

    fun toLe(n: BigInteger, len: Int = BYTES): ByteArray {
        require(n.signum() >= 0) { "отрицательное число" }
        var be = n.toByteArray()
        if (be.size > 1 && be[0] == 0.toByte()) be = be.copyOfRange(1, be.size)
        if (be.size > len) throw SrpException("число длиннее $len байт")
        val out = ByteArray(len)
        for (i in be.indices) out[i] = be[be.size - 1 - i]
        return out
    }

    /**
     * Модуль годится (как checkParams в go-srp): 2048 бит, N ≡ 3 (mod 8), (N−1)/2 — простое, и
     * 2^((N−1)/2) ≡ −1 (mod N) — значит, N простое и 2 порождает всю группу.
     */
    fun checkModulus(n: BigInteger) {
        if (n.bitLength() != BITS) throw SrpException("модуль SRP не 2048 бит (${n.bitLength()})")
        if (n.toInt() and 7 != 3) throw SrpException("модуль SRP не сравним с 3 по модулю 8")
        val half = n.shiftRight(1)
        if (!half.isProbablePrime(10)) throw SrpException("модуль SRP — не безопасное простое")
        if (TWO.modPow(half, n) != n.subtract(BigInteger.ONE)) throw SrpException("модуль SRP — не простое")
    }

    /**
     * Доказательства для входа. [secret] — только для самопроверки (тестовые наборы); в жизни a
     * случайное, как в go-srp: от 2·2048 до N−2.
     */
    fun proofs(
        password: ByteArray,
        salt: ByteArray,
        modulus: ByteArray,
        serverEphemeral: ByteArray,
        secret: BigInteger? = null,
        random: SecureRandom = SecureRandom(),
    ): Proofs {
        if (modulus.size != BYTES) throw SrpException("модуль SRP не 256 байт (${modulus.size})")
        val n = fromLe(modulus)
        checkModulus(n)
        val nm1 = n.subtract(BigInteger.ONE)
        val b = fromLe(serverEphemeral)
        if (b <= BigInteger.ONE || b >= nm1) throw SrpException("число сервера SRP вне допустимых границ")
        val bBytes = toLe(b)
        val k = fromLe(expandHash(toLe(TWO) + toLe(n))).mod(n)
        if (k <= BigInteger.ONE || k >= nm1) throw SrpException("множитель SRP вне границ")
        val x = fromLe(hashPassword(password, salt, toLe(n)))
        val lower = BigInteger.valueOf(BITS * 2L)
        var a: BigInteger
        var aBytes: ByteArray
        var u: BigInteger
        while (true) {
            a = secret ?: randomSecret(nm1, lower, random)
            aBytes = toLe(TWO.modPow(a, n))
            u = fromLe(expandHash(aBytes + bBytes))
            if (u.signum() != 0) break
            if (secret != null) throw SrpException("u = 0 при заданном секрете")
        }
        val base = b.subtract(k.multiply(TWO.modPow(x, n))).mod(n)
        val exp = u.multiply(x).add(a).mod(nm1)
        val sBytes = toLe(base.modPow(exp, n))
        val m1 = expandHash(aBytes + bBytes + sBytes)
        val m2 = expandHash(aBytes + m1 + sBytes)
        return Proofs(aBytes, m1, m2)
    }

    private fun randomSecret(nm1: BigInteger, lower: BigInteger, random: SecureRandom): BigInteger {
        while (true) {
            val r = BigInteger(BITS, random).mod(nm1)
            if (r > lower) return r
        }
    }

    /** v = g^x mod N — «проверочное число», которое хранит сервер (для тестовых наборов и поддельного сервера). */
    fun verifier(password: ByteArray, salt: ByteArray, modulus: ByteArray): ByteArray {
        val n = fromLe(modulus)
        val x = fromLe(hashPassword(password, salt, toLe(n)))
        return toLe(TWO.modPow(x, n))
    }

    /** Модуль из подписанного сообщения: подпись Proton проверена, 256 байт. */
    fun readSignedModulus(signed: String): ByteArray {
        val text = verifyClearSigned(signed, MODULUS_KEY)
        val modulus = runCatching { Crypto.unBase64(text.trim()) }.getOrElse { throw SrpException("модуль SRP — не base64") }
        if (modulus.size != BYTES) throw SrpException("модуль SRP не 256 байт (${modulus.size})")
        return modulus
    }

    /**
     * Проверка подписи «-----BEGIN PGP SIGNED MESSAGE-----» (RFC 4880, §7): текст канонизируется
     * (CRLF, без пробелов в конце строк), подпись v4 EdDSA/SHA-256 сверяется с ключом [publicKey].
     * Возвращает подписанный текст. Подпись не сошлась или после неё что-то есть — исключение.
     */
    fun verifyClearSigned(signed: String, publicKey: ByteArray): String {
        val lines = signed.replace("\r\n", "\n").replace('\r', '\n').split('\n')
        var i = lines.indexOfFirst { it.trimEnd() == "-----BEGIN PGP SIGNED MESSAGE-----" }
        if (i < 0) throw SrpException("модуль SRP без подписи")
        i++
        while (i < lines.size && lines[i].trim().isNotEmpty()) i++
        i++
        val text = ArrayList<String>()
        while (i < lines.size && lines[i].trimEnd() != "-----BEGIN PGP SIGNATURE-----") text += lines[i++]
        if (i >= lines.size) throw SrpException("в модуле SRP нет подписи")
        i++
        while (i < lines.size && lines[i].contains(':')) i++
        if (i < lines.size && lines[i].isBlank()) i++
        val b64 = StringBuilder()
        while (i < lines.size && lines[i].trimEnd() != "-----END PGP SIGNATURE-----") {
            val l = lines[i++].trim()
            if (l.isNotEmpty() && !l.startsWith("=")) b64.append(l)
        }
        if (i >= lines.size) throw SrpException("подпись модуля SRP оборвана")
        if (lines.drop(i + 1).any { it.isNotBlank() }) throw SrpException("после подписи модуля SRP лишние данные")
        val packet = runCatching { Crypto.unBase64(b64.toString()) }.getOrElse { throw SrpException("подпись модуля SRP — не base64") }
        val canon = text.joinToString("\r\n") { line -> (if (line.startsWith("- ")) line.substring(2) else line).trimEnd(' ', '\t') }
            .toByteArray(Charsets.UTF_8)
        if (!verifyPacket(packet, canon, publicKey)) throw SrpException("подпись модуля SRP не сошлась — это не Proton")
        return text.joinToString("\n")
    }

    private fun verifyPacket(pkt: ByteArray, data: ByteArray, publicKey: ByteArray): Boolean {
        fun u8(at: Int): Int = if (at < pkt.size) pkt[at].toInt() and 0xff else throw SrpException("подпись модуля SRP оборвана")
        fun u16(at: Int): Int = (u8(at) shl 8) or u8(at + 1)
        val t = u8(0)
        if (t and 0x80 == 0) return false
        val tag: Int
        val len: Int
        val off: Int
        if (t and 0x40 != 0) {
            tag = t and 0x3f
            val l0 = u8(1)
            when {
                l0 < 192 -> { len = l0; off = 2 }
                l0 < 224 -> { len = ((l0 - 192) shl 8) + u8(2) + 192; off = 3 }
                l0 == 255 -> { len = (u16(2) shl 16) or u16(4); off = 6 }
                else -> return false
            }
        } else {
            tag = (t ushr 2) and 0x0f
            when (t and 3) {
                0 -> { len = u8(1); off = 2 }
                1 -> { len = u16(1); off = 3 }
                2 -> { len = (u16(1) shl 16) or u16(3); off = 5 }
                else -> return false
            }
        }
        if (tag != 2 || off + len > pkt.size) return false
        val body = pkt.copyOfRange(off, off + len)
        fun b8(at: Int): Int = if (at < body.size) body[at].toInt() and 0xff else throw SrpException("подпись модуля SRP оборвана")
        fun b16(at: Int): Int = (b8(at) shl 8) or b8(at + 1)
        // v4, «канонический текст», EdDSA, SHA-256 — так Proton подписывает модули.
        if (b8(0) != 4 || b8(1) != 0x01 || b8(2) != 22 || b8(3) != 8) return false
        val hashedLen = 6 + b16(4)
        if (hashedLen > body.size) return false
        val hashed = body.copyOfRange(0, hashedLen)
        var p = hashedLen
        p += 2 + b16(p)
        val left16 = b16(p)
        p += 2
        fun mpi(): ByteArray {
            val bits = b16(p)
            val n = (bits + 7) / 8
            if (p + 2 + n > body.size || n > 32) throw SrpException("подпись модуля SRP повреждена")
            val v = body.copyOfRange(p + 2, p + 2 + n)
            p += 2 + n
            return ByteArray(32 - n) + v
        }
        val r = mpi()
        val s = mpi()
        val md = MessageDigest.getInstance("SHA-256")
        md.update(data)
        md.update(hashed)
        md.update(byteArrayOf(0x04, 0xff.toByte()))
        md.update(byteArrayOf((hashedLen ushr 24).toByte(), (hashedLen ushr 16).toByte(), (hashedLen ushr 8).toByte(), hashedLen.toByte()))
        val digest = md.digest()
        if (((digest[0].toInt() and 0xff) shl 8 or (digest[1].toInt() and 0xff)) != left16) return false
        val verifier = Ed25519Signer()
        verifier.init(false, Ed25519PublicKeyParameters(publicKey, 0))
        verifier.update(digest, 0, digest.size)
        return verifier.verifySignature(r + s)
    }
}
