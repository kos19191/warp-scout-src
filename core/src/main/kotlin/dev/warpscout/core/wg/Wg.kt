package dev.warpscout.core.wg

import dev.warpscout.core.crypto.Blake2s
import dev.warpscout.core.crypto.Crypto
import java.security.SecureRandom

/**
 * Минимальная, но честная реализация handshake-части WireGuard (Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s).
 *
 * Нам НЕ нужен туннель — только:
 *  • собрать корректный handshake initiation (148 байт), чтобы живовой WireGuard-сервер на него ответил;
 *  • распознать и проверить ответ (92 байта) / cookie reply (60 байт) — это и есть «endpoint жив и
 *    наш ключ принят» на уровне криптографии, а не «порт открывает UDP».
 *
 * Всё точно по https://www.wireguard.com/protocol/ — константы, порядок MIX_HASH/MIX_KEY и MAC
 * взяты оттуда же, поэтому проверяется против независимой реализации (tools/fake_warp_endpoint.py).
 */
object Wg {

    const val TYPE_INITIATION = 1
    const val TYPE_RESPONSE = 2
    const val TYPE_COOKIE = 3
    const val TYPE_TRANSPORT = 4

    const val INITIATION_LEN = 148
    const val RESPONSE_LEN = 92
    /** cookie reply: type(4) + receiver_index(4) + nonce(24) + encrypted_cookie(16+16) = 64 байта. */
    const val COOKIE_MSG_LEN = 64
    /** сам cookie — 16 байт, клиент кладёт его в mac2 следующей инициации. */
    const val COOKIE_VALUE_LEN = 16

    const val KEY_LEN = 32

    private val CONSTRUCTION = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s".toByteArray()
    private val IDENTIFIER = "WireGuard v1 zx2c4 Jason@zx2c4.com".toByteArray()
    private val LABEL_MAC1 = "mac1----".toByteArray()
    private val LABEL_COOKIE = "cookie--".toByteArray()
    private val PSK = ByteArray(KEY_LEN) // «psk2» в WireGuard — это нулевой PSK

    /** Состояние handshake, нужное чтобы проверить ответ сервера и вывести ключи сессии. */
    data class HandshakeState(
        val chainingKey: ByteArray,
        val hash: ByteArray,
        val localStaticPrivate: ByteArray,
        val localStaticPublic: ByteArray,
        val localEphemeralPrivate: ByteArray,
        val senderIndex: Int
    )

    data class Initiation(
        val packet: ByteArray,
        val state: HandshakeState,
        val mac1Key: ByteArray
    )

    /** TAI64N (12 байт): 8 байт = секунды (младшие 62 бита) + старшие биты наносекунд, 4 байта = остаток. */
    fun tai64n(millis: Long = System.currentTimeMillis()): ByteArray {
        val nsTotal = millis * 1_000_000L
        val sec = nsTotal / 1_000_000_000L
        val nsec = nsTotal % 1_000_000_000L
        val packed = ((nsec shl 2) and 0x3f00000000000000L) or (sec and 0x3fffffffffffffffL)
        val out = ByteArray(12)
        var v = packed
        for (i in 0 until 8) {
            out[i] = (v and 0xff).toByte()
            v = v ushr 8
        }
        val hi = (nsec ushr 62).toInt()
        out[8] = hi.toByte(); out[9] = (hi ushr 8).toByte()
        out[10] = (hi ushr 16).toByte(); out[11] = (hi ushr 24).toByte()
        return out
    }

    private fun aeadKey(counter: Long = 0): ByteArray = ByteArray(12) // nonce = 0 (4 байта нуля + le64(0))

    private fun putLe64(dst: ByteArray, off: Int, value: Long) {
        var v = value
        for (i in 0 until 8) {
            dst[off + i] = (v and 0xff).toByte()
            v = v ushr 8
        }
    }

    /** Ключевые шаги «-> e, es, s, ee» + payload(таймстамп), как в спецификации. */
    fun buildInitiation(
        localStaticPrivate: ByteArray,
        localStaticPublic: ByteArray,
        remoteStaticPublic: ByteArray,
        senderIndex: Int,
        lastCookie: ByteArray? = null,
        ephPrivate: ByteArray? = null,
        timestamp: ByteArray? = null,
        random: SecureRandom = Crypto.random
    ): Initiation {
        require(localStaticPrivate.size == KEY_LEN && localStaticPublic.size == KEY_LEN) { "ключи должны быть 32 байта" }
        require(remoteStaticPublic.size == KEY_LEN) { "ключ пира должен быть 32 байта" }

        var ck = Blake2s.hash(CONSTRUCTION)                       // chaining_key = HASH(CONSTRUCTION)
        var h = Blake2s.hash(ck + IDENTIFIER)                      // hash = HASH(HASH(ck || IDENTIFIER) || responder.static)
        h = Blake2s.hash(h + remoteStaticPublic)

        val ephPriv = ephPrivate ?: ByteArray(KEY_LEN).also { random.nextBytes(it) }
        val ephPub = Crypto.publicOf(ephPriv)

        val buf = ByteArray(INITIATION_LEN)
        // u32 type = 1, u32 sender_index
        Crypto.le32(TYPE_INITIATION).copyInto(buf, 0)
        Crypto.le32(senderIndex).copyInto(buf, 4)
        ephPub.copyInto(buf, 8)                                    // unencrypted_ephemeral
        h = Blake2s.hash(h + ephPub)                               // MIX_HASH(e)

        // es: MIX_KEY(DH(eph_priv, responder_static))
        var temp = Blake2s.hmac(ck, ephPub)
        ck = Blake2s.hmac(temp, byteArrayOf(0x01))
        temp = Blake2s.hmac(ck, Crypto.dh(ephPriv, remoteStaticPublic))
        ck = Blake2s.hmac(temp, byteArrayOf(0x01))
        var key = Blake2s.hmac(temp, ck + byteArrayOf(0x02))

        // s: encrypted_static = AEAD(key, 0, our_static_pub, hash)
        val encryptedStatic = Crypto.chacha20Poly1305Seal(key, aeadKey(), localStaticPublic, h)
        encryptedStatic.copyInto(buf, 40)
        h = Blake2s.hash(h + encryptedStatic)

        // ee → в WireGuard это DH(static_priv, responder_static)
        temp = Blake2s.hmac(ck, Crypto.dh(localStaticPrivate, remoteStaticPublic))
        ck = Blake2s.hmac(temp, byteArrayOf(0x01))
        key = Blake2s.hmac(temp, ck + byteArrayOf(0x02))

        val ts = timestamp ?: tai64n()
        require(ts.size == 12) { "TAI64N = 12 байт" }
        val encryptedTimestamp = Crypto.chacha20Poly1305Seal(key, aeadKey(), ts, h)
        encryptedTimestamp.copyInto(buf, 88)                        // 28 байт: 12 + 16(tag)
        h = Blake2s.hash(h + encryptedTimestamp)

        val mac1Key = Blake2s.hash(LABEL_MAC1 + remoteStaticPublic)
        val mac1 = Blake2s.mac(mac1Key, buf.copyOfRange(0, 116))
        mac1.copyInto(buf, 116)
        if (lastCookie != null && lastCookie.size == 16) {
            Blake2s.mac(lastCookie, buf.copyOfRange(0, 132)).copyInto(buf, 132)
        }

        return Initiation(
            buf,
            HandshakeState(ck, h, localStaticPrivate, localStaticPublic, ephPriv, senderIndex),
            mac1Key
        )
    }

    enum class ResponseKind { HANDSHAKE_RESPONSE, COOKIE_REPLY, MALFORMED, MISMATCH }

    data class ProbeReply(
        val kind: ResponseKind,
        val peerEphemeral: ByteArray? = null,
        val session: Session? = null,
        /** sender_index сервера — адрес, на который шлём transport-пакеты. */
        val peerSenderIndex: Int? = null,
        /** расшифрованный cookie (если сервер прислал cookie reply и мы смогли его достать) */
        val cookie: ByteArray? = null
    )

    /**
     * Скользящее окно защиты от повторов (RFC 6479, глубина 2048 пакетов — как в эталонном WireGuard).
     *
     * Позволяет принимать переупорядоченные UDP-пакеты (обычное явление при параллельных потоках
     * Telegram/YouTube и ECMP-маршрутизации у провайдера), отбрасывая только настоящие повторы и
     * пакеты старше 2048 номеров. Кольцо из 64 слов (4096 бит) гарантирует, что очистка новых слов
     * никогда не затрёт биты внутри активного 2048-пакетного окна.
     */
    class ReplayWindow {
        private var last: Long = -1L
        private val bitmap = LongArray(RING_WORDS)

        /** Проверяет, допустим ли [counter] (без изменения состояния — вызывать до проверки AEAD). */
        fun isAcceptable(counter: Long): Boolean {
            if (counter < 0L) return false
            if (last < 0L || counter > last) return true
            val diff = last - counter
            if (diff >= WINDOW_SIZE) return false
            val word = ((counter ushr 6) and RING_MASK).toInt()
            val bit = 1L shl (counter.toInt() and 63)
            return (bitmap[word] and bit) == 0L
        }

        /** Фиксирует успешно расшифрованный [counter] (вызывать ТОЛЬКО после проверки тега AEAD!). */
        fun mark(counter: Long) {
            if (counter < 0L) return
            if (last < 0L) {
                bitmap.fill(0L)
                val word = ((counter ushr 6) and RING_MASK).toInt()
                bitmap[word] = 1L shl (counter.toInt() and 63)
                last = counter
                return
            }
            if (counter > last) {
                val oldWord = last ushr 6
                val newWord = counter ushr 6
                val wordDiff = newWord - oldWord
                if (wordDiff >= RING_WORDS) {
                    bitmap.fill(0L)
                } else {
                    var w = oldWord + 1L
                    while (w <= newWord) {
                        bitmap[(w and RING_MASK).toInt()] = 0L
                        w++
                    }
                }
                last = counter
            }
            val word = ((counter ushr 6) and RING_MASK).toInt()
            bitmap[word] = bitmap[word] or (1L shl (counter.toInt() and 63))
        }

        fun highest(): Long = last

        companion object {
            const val WINDOW_SIZE: Long = 2048L
            private const val RING_WORDS: Int = 64
            private const val RING_MASK: Long = (RING_WORDS - 1).toLong()
        }
    }

    /**
     * Ключи сессии + счётчики. Отправитель увеличивает [sendCounter] на каждый пакет,
     * получатель проверяет счётчик по скользящему окну [replayWindow] (защита от повторов RFC 6479).
     */
    data class Session(
        val receiveKey: ByteArray,
        val sendKey: ByteArray,
        val sendCounter: Long = 0,
        val receiveCounter: Long = -1L,
        val replayWindow: ReplayWindow = ReplayWindow()
    )

    /**
     * Разбор и КРИПТОграфическая проверка ответа сервера. Возвращает [ResponseKind.HANDSHAKE_RESPONSE]
     * только если tag у `encrypted_nothing` сошёлся — то есть на той стороне реально сидит WireGuard
     * с приватным ключом, соответствующим нашему ключу пира, и он принял наш статический ключ.
     */
    fun consumeResponse(packet: ByteArray, initiation: Initiation, peerStaticPublic: ByteArray? = null): ProbeReply {
        if (packet.size == COOKIE_MSG_LEN && Crypto.readLe32(packet, 0) == TYPE_COOKIE) {
            if (Crypto.readLe32(packet, 4) != initiation.state.senderIndex) return ProbeReply(ResponseKind.MISMATCH)
            val cookie = peerStaticPublic?.let { peer ->
                // Сервер шифрует cookie ключом BLAKE2s("cookie--" || свой публичный ключ),
                // nonce — 24 байта из ответа, AAD — mac1 нашей инициации.
                Crypto.xChaCha20Poly1305Open(
                    Blake2s.hash(LABEL_COOKIE + peer),
                    packet.copyOfRange(8, 32),
                    packet.copyOfRange(32, 64),
                    initiation.packet.copyOfRange(116, 132)
                )?.takeIf { it.size == COOKIE_VALUE_LEN }
            }
            return ProbeReply(ResponseKind.COOKIE_REPLY, cookie = cookie)
        }
        if (packet.size != RESPONSE_LEN || Crypto.readLe32(packet, 0) != TYPE_RESPONSE) {
            return ProbeReply(ResponseKind.MALFORMED)
        }
        val peerSenderIndex = Crypto.readLe32(packet, 4)
        val receiverIndex = Crypto.readLe32(packet, 8)
        if (receiverIndex != initiation.state.senderIndex) return ProbeReply(ResponseKind.MISMATCH)

        var ck = initiation.state.chainingKey
        var h = initiation.state.hash
        val respEph = packet.copyOfRange(12, 44)              // unencrypted_ephemeral

        h = Blake2s.hash(h + respEph)
        var temp = Blake2s.hmac(ck, respEph)
        ck = Blake2s.hmac(temp, byteArrayOf(0x01))
        temp = Blake2s.hmac(ck, Crypto.dh(initiation.state.localEphemeralPrivate, respEph))   // ee
        ck = Blake2s.hmac(temp, byteArrayOf(0x01))
        temp = Blake2s.hmac(ck, Crypto.dh(initiation.state.localStaticPrivate, respEph))      // se
        ck = Blake2s.hmac(temp, byteArrayOf(0x01))
        temp = Blake2s.hmac(ck, PSK)                                                            // psk
        ck = Blake2s.hmac(temp, byteArrayOf(0x01))
        val temp2 = Blake2s.hmac(temp, ck + byteArrayOf(0x02))
        val key = Blake2s.hmac(temp, temp2 + byteArrayOf(0x03))
        h = Blake2s.hash(h + temp2)

        val encryptedNothing = packet.copyOfRange(44, 60)      // AEAD пустого сообщения = 16 байт тега
        val plain = Crypto.chacha20Poly1305Open(key, aeadKey(), encryptedNothing, h)
            ?: return ProbeReply(ResponseKind.MISMATCH)
        if (plain.isNotEmpty()) return ProbeReply(ResponseKind.MALFORMED)
        h = Blake2s.hash(h + encryptedNothing)

        // mac1 считается от первых (92 - 32) = 60 байт, ключ — от НАШЕГО публичного ключа.
        val expectedMac1 = Blake2s.mac(
            Blake2s.hash(LABEL_MAC1 + initiation.state.localStaticPublic),
            packet.copyOfRange(0, 60)
        )
        if (!expectedMac1.contentEquals(packet.copyOfRange(60, 76))) return ProbeReply(ResponseKind.MISMATCH)

        // Ключи сессии (нужны, чтобы отправить пустой transport-пакет для key confirmation).
        val t1 = Blake2s.hmac(ck, ByteArray(0))
        val t2 = Blake2s.hmac(t1, byteArrayOf(0x01))
        val t3 = Blake2s.hmac(t1, t2 + byteArrayOf(0x02))
        return ProbeReply(ResponseKind.HANDSHAKE_RESPONSE, respEph, Session(t3, t2), peerSenderIndex)
    }

    /**
     * Transport-пакет (type=4): `type | receiver | counter | AEAD(sendKey, nonce=counter, data, ∅)`.
     * Возвращает пакет и сессию с увеличенным счётчиком отправки.
     */
    fun buildTransport(receiverIndex: Int, session: Session, data: ByteArray): Pair<ByteArray, Session> =
        buildTransport(receiverIndex, session, data, data.size)

    /**
     * То же, но шифрует первые [dataLength] байт: tun отдаёт пакет в переиспользуемый буфер, и
     * копия только ради обрезки длины — лишняя работа на каждый отправленный пакет.
     */
    fun buildTransport(
        receiverIndex: Int,
        session: Session,
        data: ByteArray,
        dataLength: Int
    ): Pair<ByteArray, Session> {
        val out = ByteArray(32 + dataLength)
        Crypto.le32(TYPE_TRANSPORT).copyInto(out, 0)
        Crypto.le32(receiverIndex).copyInto(out, 4)
        putLe64(out, 8, session.sendCounter)
        val nonce = ByteArray(12).also { putLe64(it, 4, session.sendCounter) }
        Crypto.chacha20Poly1305Seal(session.sendKey, nonce, data, Crypto.EMPTY_AAD, dataLength).copyInto(out, 16)
        return out to session.copy(sendCounter = session.sendCounter + 1)
    }

    /** Пустой transport-пакет (keepalive) — 32 байта: type(4)+receiver(4)+counter(8)+tag(16). */
    fun buildKeepalive(receiverIndex: Int, session: Session, counter: Long = 0): ByteArray =
        buildTransport(receiverIndex, session.copy(sendCounter = counter), ByteArray(0)).first

    /**
     * Приём transport-пакета: проверяет тип, индекс, скользящее окно повторов (RFC 6479) и AEAD-тег.
     * `null` — пакет не наш (шум, повтор, слишком старый пакет или битый тег).
     *
     * Важно: окно обновляется ТОЛЬКО после успешной проверки Poly1305-тега, чтобы поддельный
     * пакет с большим счётчиком не мог сдвинуть окно и заблокировать настоящий трафик.
     */
    fun openTransport(packet: ByteArray, receiverIndex: Int, session: Session): Pair<ByteArray, Session>? {
        if (packet.size < 32 || Crypto.readLe32(packet, 0) != TYPE_TRANSPORT) return null
        if (Crypto.readLe32(packet, 4) != receiverIndex) return null
        val counter = Crypto.readLe64(packet, 8)
        if (!session.replayWindow.isAcceptable(counter)) return null
        val nonce = ByteArray(12).also { putLe64(it, 4, counter) }
        val data = packet.copyOfRange(16, packet.size)
        val plain = Crypto.chacha20Poly1305Open(session.receiveKey, nonce, data, Crypto.EMPTY_AAD) ?: return null
        session.replayWindow.mark(counter)
        val nextHighest = maxOf(session.receiveCounter, counter)
        return plain to session.copy(receiveCounter = nextHighest)
    }

    /** Публичный ключ → «sender index» (KEYID), как в WireGuard: первые 4 байта le32 от HASH(pub). */
    fun keyId(publicKey: ByteArray): Int = Crypto.readLe32(Blake2s.hash(publicKey), 0)
}
