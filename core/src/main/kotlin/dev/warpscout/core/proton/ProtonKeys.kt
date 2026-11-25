package dev.warpscout.core.proton

import dev.warpscout.core.crypto.Crypto
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import java.math.BigInteger
import java.security.MessageDigest
import java.security.SecureRandom

/**
 * Ключ второго выхода Proton (с 1.10.44-beta5) создаётся на телефоне и никуда не уходит.
 *
 * Proton выдаёт доступ к WireGuard под ключ Ed25519: в сертификат идёт открытая часть, а сервер
 * узнаёт по ней ключ WireGuard — это та же точка кривой в другой записи (Монтгомери). Поэтому
 * закрытый ключ WireGuard — это скаляр того же ключа: SHA-512 от зерна, первые 32 байта, «зажатые»
 * по правилам X25519. Так делают и приложения Proton (go-vpn-lib), и страница proton-generation.
 */
object ProtonKeys {

    class Pair(private val seed: ByteArray) {
        init {
            require(seed.size == 32) { "зерно ключа — 32 байта" }
        }

        /** Открытый ключ Ed25519 (32 байта) — он и уходит в Proton. */
        val edPublic: ByteArray by lazy { Ed25519PrivateKeyParameters(seed, 0).generatePublicKey().encoded }

        /** Закрытый ключ WireGuard (32 байта): для строки PrivateKey конфига. */
        val wgPrivate: ByteArray by lazy {
            val h = MessageDigest.getInstance("SHA-512").digest(seed)
            val k = h.copyOf(32)
            k[0] = (k[0].toInt() and 248).toByte()
            k[31] = ((k[31].toInt() and 127) or 64).toByte()
            k
        }

        /** Открытый ключ WireGuard — тот, что Proton видит в рукопожатии. */
        val wgPublic: ByteArray get() = Crypto.publicOf(wgPrivate)

        /** PEM SubjectPublicKeyInfo Ed25519, как его ждёт /vpn/v1/certificate. */
        val pem: String get() = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA" + Crypto.base64(edPublic) + "\n-----END PUBLIC KEY-----\n"
    }

    fun generate(random: SecureRandom = SecureRandom()): Pair = Pair(ByteArray(32).also { random.nextBytes(it) })

    /** Для самопроверки: ключ из заданного зерна. */
    fun fromSeed(seed: ByteArray): Pair = Pair(seed.copyOf())

    /**
     * Ed25519 → X25519: u = (1 + y) / (1 − y) mod p. Так Proton находит ключ WireGuard по ключу из
     * сертификата; самопроверка сверяет это с [Pair.wgPublic] — значит, ключ в конфиге подойдёт.
     */
    fun montgomeryOf(edPublic: ByteArray): ByteArray {
        val p = BigInteger.ONE.shiftLeft(255).subtract(BigInteger.valueOf(19))
        val yLe = edPublic.copyOf(32)
        yLe[31] = (yLe[31].toInt() and 0x7f).toByte()
        val y = ProtonSrp.fromLe(yLe)
        val u = BigInteger.ONE.add(y).multiply(BigInteger.ONE.subtract(y).mod(p).modInverse(p)).mod(p)
        return ProtonSrp.toLe(u, 32)
    }
}
