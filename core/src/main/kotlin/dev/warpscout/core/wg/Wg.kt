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

    /**
     * TAI64N (12 байт) — метка времени в инициации, ровно как её пишет WireGuard: 8 байт секунд
     * TAI64 (2^62 + 10 + секунды Unix) и 4 байта наносекунд, оба числа старшим байтом вперёд.
     *
     * Раньше здесь были секунды младшим байтом вперёд и нулевые наносекунды. Сервер WireGuard
     * (ядро Linux, wireguard-go, amneziawg-go, boringtun) принимает инициацию, только если её метка
     * больше прошлой принятой от этого ключа, и сравнивает байты по порядку. У метки «младшим байтом
     * вперёд» первым стоит младший байт секунд, а он прокручивается каждые 256 с: новая метка
     * то и дело оказывалась «меньше» старой, и rekey отвергался как повтор. Пять повторов
     * инициации в пределах одной секунды к тому же несли одну и ту же метку. WARP метку не
     * проверяет — поэтому на нём этого не было видно (Диагностика-8: 174 rekey подряд), а свой
     * сервер второго выхода через несколько минут переставал пересогласовываться.
     */
    fun tai64n(millis: Long = System.currentTimeMillis()): ByteArray =
        tai64nAt(Math.floorDiv(millis, 1000L), (Math.floorMod(millis, 1000L) * 1_000_000L).toInt())

    /** Начало шкалы TAI64 (2^62) плюс 10 с разницы TAI−UTC — так считает WireGuard. */
    private const val TAI64_BASE = 0x400000000000000aL

    private fun tai64nAt(unixSeconds: Long, nanos: Int): ByteArray {
        val out = ByteArray(12)
        var sec = TAI64_BASE + unixSeconds
        for (i in 7 downTo 0) {
            out[i] = (sec and 0xff).toByte()
            sec = sec ushr 8
        }
        var ns = nanos
        for (i in 11 downTo 8) {
            out[i] = (ns and 0xff).toByte()
            ns = ns ushr 8
        }
        return out
    }

    /** Последняя выданная метка, наносекунды Unix: следующая обязана быть строго больше. */
    private val lastStampNanos = java.util.concurrent.atomic.AtomicLong(0L)

    /**
     * Метка для новой инициации: строго больше любой, выданной в этом процессе раньше.
     *
     * Часы дают миллисекунды, а две инициации на одном ключе (повтор у туннеля, проба дозора рядом
     * с rekey) могут попасть в одну миллисекунду — тогда сервер отверг бы вторую как повтор. Если
     * часы не сдвинулись (или ушли назад), берём прошлую метку плюс наносекунду.
     */
    fun freshTai64n(): ByteArray {
        val now = System.currentTimeMillis() * 1_000_000L
        val stamp = lastStampNanos.updateAndGet { prev -> if (now > prev) now else prev + 1 }
        return tai64nAt(Math.floorDiv(stamp, 1_000_000_000L), Math.floorMod(stamp, 1_000_000_000L).toInt())
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

        // Метка — монотонная на процесс: см. [freshTai64n] и [tai64n].
        val ts = timestamp ?: freshTai64n()
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
     * Скользящее окно защиты от повторов (RFC 6479, 2048 номеров — как в эталонном WireGuard; с
     * 1.10.49-beta1, перенесено из версии для компьютера).
     *
     * Раньше пакет с номером не больше последнего принятого отбрасывался. Но UDP по дороге часто
     * переставляет пакеты местами (Wi-Fi, мобильная сеть, несколько маршрутов у оператора): опоздавший
     * пакет терялся, TCP считал это потерей и сбавлял скорость — так тормозили медиа Telegram и
     * загрузки. Теперь отбрасываются только настоящие повторы и пакеты старше 2048 номеров. Кольцо из
     * 64 слов (4096 бит) — очистка новых слов не задевает биты внутри действующего окна.
     */
    class ReplayWindow {
        private var last: Long = -1L
        private val bitmap = LongArray(RING_WORDS)

        /** Можно ли принять [counter] (состояние не меняет — вызывать до проверки тега AEAD). */
        fun isAcceptable(counter: Long): Boolean {
            if (counter < 0L) return false
            if (last < 0L || counter > last) return true
            if (last - counter >= WINDOW_SIZE) return false
            val word = ((counter ushr 6) and RING_MASK).toInt()
            val bit = 1L shl (counter.toInt() and 63)
            return (bitmap[word] and bit) == 0L
        }

        /** Отметить принятый [counter] — ТОЛЬКО после проверки тега: поддельный пакет окно не сдвинет. */
        fun mark(counter: Long) {
            if (counter < 0L) return
            if (last < 0L) {
                bitmap.fill(0L)
                last = counter
            } else if (counter > last) {
                val oldWord = last ushr 6
                val newWord = counter ushr 6
                if (newWord - oldWord >= RING_WORDS) {
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

        companion object {
            const val WINDOW_SIZE: Long = 2048L
            private const val RING_WORDS: Int = 64
            private const val RING_MASK: Long = (RING_WORDS - 1).toLong()
        }
    }

    /**
     * Ключи сессии + счётчики. Отправитель увеличивает [sendCounter] на каждый пакет; получатель
     * проверяет номер по скользящему окну [replayWindow] (RFC 6479), [receiveCounter] — наибольший
     * принятый номер. Окно — одно на сессию: копии сессии (`copy`) делят его.
     */
    data class Session(
        val receiveKey: ByteArray,
        val sendKey: ByteArray,
        val sendCounter: Long = 0,
        val receiveCounter: Long = -1L,
        val replayWindow: ReplayWindow = ReplayWindow(),
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
     * Приём transport-пакета: проверяет тип, индекс, номер по окну повторов (RFC 6479) и тег.
     * `null` — пакет не наш (шум, повтор, слишком старый номер, битый тег). Окно сдвигается только
     * после проверки тега Poly1305.
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
        return plain to session.copy(receiveCounter = maxOf(session.receiveCounter, counter))
    }

    /** Публичный ключ → «sender index» (KEYID), как в WireGuard: первые 4 байта le32 от HASH(pub). */
    fun keyId(publicKey: ByteArray): Int = Crypto.readLe32(Blake2s.hash(publicKey), 0)

    /**
     * Пересчитать mac1 рукопожатия после замены типа сообщения (AmneziaWG: H1 у инициации, H2 у
     * ответа). mac1 считается по байтам сообщения вместе с типом, поэтому сервер AmneziaWG ждёт его
     * посчитанным уже по своему типу, а наша проверка ответа — по стандартному. [receiverStatic] —
     * публичный ключ получателя: для инициации — ключ сервера, для ответа — наш. mac2 не трогаем:
     * он нужен только под нагрузкой (cookie), и без cookie посчитать его заново нечем.
     */
    fun remac1(msg: ByteArray, receiverStatic: ByteArray) {
        val macOff = msg.size - 32
        if (macOff <= 0 || receiverStatic.size != KEY_LEN) return
        val key = Blake2s.hash(LABEL_MAC1 + receiverStatic)
        Blake2s.mac(key, msg.copyOfRange(0, macOff)).copyInto(msg, macOff)
    }
}
