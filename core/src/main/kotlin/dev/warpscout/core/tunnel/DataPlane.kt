package dev.warpscout.core.tunnel

import dev.warpscout.core.crypto.Crypto
import dev.warpscout.core.model.Endpoint
import dev.warpscout.core.model.JunkProfile
import dev.warpscout.core.model.WarpConfig
import dev.warpscout.core.net.NetSettings
import dev.warpscout.core.wg.Wg
import java.io.InputStream
import java.io.OutputStream
import java.net.DatagramSocket
import java.net.InetSocketAddress
import java.util.LinkedHashMap
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit

/** Куда отправлять собранные пакеты и откуда брать входящие (сокет, туннель, пара сокетов в тестах). */
interface UdpChannel {
    fun send(packet: ByteArray)
    fun receive(): ByteArray?
    fun close()
}

/** Обычный connected-datagram-сокет (используется CLI и тестами). */
class SocketUdpChannel(
    private val socket: DatagramSocket,
    private val endpoint: Endpoint,
    private val timeoutMs: Int = 1500
) : UdpChannel {

    /**
     * Буфер и пакет приёма — одни на канал, а не на пакет.
     *
     * Раньше `receive()` создавал массив на 64 КБ **на каждый входящий пакет** и ещё один пакет
     * поверх него. На скорости в сотни пакетов в секунду это десятки мегабайт мусора в секунду:
     * сборщик мусора работает без остановки, процессор занят им, и скорость загрузки проседает —
     * именно это и видно на медиа в мессенджерах. wireguard-пакет не бывает больше MTU + 32 байта,
     * поэтому 4 КБ хватает с запасом на любой шум.
     */
    private val rxBuf = ByteArray(4096)
    private val rxPacket = java.net.DatagramPacket(rxBuf, rxBuf.size)
    private val txPacket = java.net.DatagramPacket(ByteArray(1), 0)

    init {
        if (!socket.isConnected) socket.connect(InetSocketAddress(endpoint.host, endpoint.port))
        socket.soTimeout = timeoutMs
    }

    override fun send(packet: ByteArray) {
        // Пакет отправки переиспользуется: send() копирует данные в ядро сразу и не держит ссылку.
        txPacket.data = packet
        txPacket.length = packet.size
        socket.send(txPacket)
    }

    override fun receive(): ByteArray? = try {
        rxPacket.setLength(rxBuf.size)
        socket.receive(rxPacket)
        // Копия нужна: буфер приёма переиспользуется, а расшифровка идёт уже после возврата.
        // Но это одна копия размера пакета вместо 64 КБ мусора на каждый пакет.
        rxPacket.data.copyOfRange(0, rxPacket.length)
    } catch (e: java.net.SocketTimeoutException) {
        null
    }

    override fun close() {
        runCatching { socket.close() }
    }
}

/**
 * Двусторонний поток между tun-устройством (InputStream/OutputStream) и UDP-сокетом:
 * WireGuard transport-пакеты в обе стороны, **пересогласование сессии**, keepalive, счётчики,
 * защита от повторов.
 *
 * Про rekey — это была главная причина «работает 3–5 минут, потом Telegram пишет Соединение…».
 * WireGuard-сессия не вечная: ядро само пересогласовывает её через `REKEY_AFTER_TIME` (120 с),
 * а через `REJECT_AFTER_TIME` (180 с) отбрасывает. Раньше handshake делался один раз при старте,
 * дальше сессия умирала молча: keepalive уходил в никуда, ответный handshake-пакет (тип 2) в
 * транспортном цикле отбрасывался как «не наш», и туннель «оставался поднятым» без данных.
 *
 * Теперь: один читатель сокета на всё, handshake-ответы уходят в очередь ожидающего
 * пересогласования, таймер в 120 с инициирует rekey и повторяет его каждые 5 с, пока не получится.
 * Старая сессия живёт до подтверждения новой, поэтому TCP-соединения не рвутся.
 *
 * Это тот самый «собственный туннель»: никакого чужого бэкенда не нужно — AWG отличается от
 * WireGuard только handshake-мусором перед инициацией, а он обрабатывается здесь же.
 */
class DataPlane(
    private val udp: UdpChannel,
    private val tunInput: InputStream,
    private val tunOutput: OutputStream,
    private val config: WarpConfig,
    private val settings: NetSettings = NetSettings(),
    /**
     * Зовётся, когда handshake действительно прошёл и туннель поднят.
     *
     * Зачем отдельный сигнал, если в журнал пишется «туннель поднят»: сервис раньше определял
     * подъём поиском этой подстроки в строке журнала. Одна правка формулировки в ядре — и
     * состояние «работает» перестало бы устанавливаться вовсе, молча и без ошибки. Логика должна
     * опираться на событие, а текст журнала остаётся текстом для человека.
     *
     * Параметр стоит ДО `log`/`onFatal` намеренно: хвостовая лямбда в вызовах привязывается к
     * последнему параметру, и её смысл не должен меняться от добавления нового события.
     */
    private val onTunnelUp: (() -> Unit)? = null,
    /**
     * Горит ли экран. От этого зависит частота keepalive: с погашенным экраном и без трафика
     * телефон должен спать, а не будить радио каждые 25 секунд. Ядро не знает про Android, поэтому
     * состояние приходит снаружи.
     */
    private val screenOn: () -> Boolean = { true },
    /**
     * Дополнительные цифры для строки статистики (расход процессора, число переподключений).
     * Считает вызывающий: ядро не знает ни Android, ни сервиса, а гадать о расходе батареи без
     * цифр — ровно то, чем мы занимались до сих пор.
     */
    private val vitals: (() -> String)? = null,
    private val log: (String) -> Unit = {},
    /**
     * Зовётся, когда сокет перестал отправлять пакеты (ENETUNREACH/EPERM после смены сети или
     * потери маршрута). Сверху это означает «туннель мёртв, надо переподнять»: без такого сигнала
     * туннель висит «поднятым», а трафик молча не ходит.
     */
    private val onFatal: ((String) -> Unit)? = null
) {

    @Volatile
    private var stopped = false

    /** Итог handshake: false — туннель не поднялся (эндпоинт молчит или ключи не подошли). */
    @Volatile
    var handshakeOk: Boolean = false
        private set

    /** Сколько попыток инициации реально ушло в сеть — без этого «тихий» отказ не объяснить. */
    @Volatile
    var attemptCount: Int = 0
        private set

    /** Почему handshake не состоялся (null — причина не задокументирована, например пользователь остановил). */
    @Volatile
    var failureReason: String? = null
        private set

    /** Сколько раз сессия успешно пересогласовывалась после старта. */
    @Volatile
    var rekeyCount: Int = 0
        private set

    /** Последняя неудача rekey — для журнала туннеля («сессия не восстанавливается»). */
    @Volatile
    var lastRekeyFailure: String? = null
        private set

    /** Сколько байт прошло в каждую сторону (для статистики в уведомлении). */
    @Volatile
    var bytesUp: Long = 0L
        private set

    @Volatile
    var bytesDown: Long = 0L
        private set

    @Volatile
    private var sessionStartedAt: Long = 0L

    @Volatile
    private var lastOutboundAt: Long = 0L

    /**
     * Когда последний раз был настоящий пользовательский трафик (в любую сторону).
     *
     * Отдельно от `lastOutboundAt`: тот обновляется и самим keepalive, поэтому «сколько уже тихо»
     * по нему не измерить — интервал никогда не вырастал, и телефон будили с прежней частотой.
     */
    @Volatile
    private var lastUserTrafficAt: Long = 0L

    /** Счётчики сеанса — для строки «сколько чего было» в журнале. */
    @Volatile
    private var keepalivesSent: Int = 0
    @Volatile
    private var handshakesDone: Int = 0
    @Volatile
    private var nextStatsAt: Long = 0L

    /** Момент запуска: по нему считается тишина, если трафика не было вовсе. */
    private val startedAt: Long = System.currentTimeMillis()

    /** Когда последний раз с сервера пришёл хоть один пакет: любое «да» — признак живой сети. */
    @Volatile
    private var lastRxAt: Long = 0L

    /** Когда начался текущий поток исходящих пакетов, на который ответа ещё не было. */
    @Volatile
    private var burstStartAt: Long = 0L

    /** Сколько пользовательских пакетов ушло с начала этого потока. */
    @Volatile
    private var burstPackets: Int = 0

    /** О мёртвой сессии сообщаем один раз, иначе каждая следующая отправка дёргала бы сервис. */
    @Volatile
    private var stallReported: Boolean = false

    /** Сколько раз подряд не удалось пересогласовать сессию (rekey). */
    private var rekeyFailures = 0

    /** Сколько раз ПОДРЯД не удалось отправить пакет: несколько подряд = сеть ушла. */
    private val sendFailures = java.util.concurrent.atomic.AtomicInteger(0)


    private val lock = Any()
    private var session: Wg.Session? = null
    private var peerIndex: Int = 0
    private var localIndex: Int = 0

    /** Ответы на наши инициации (тип 2/3): один читатель — сюда, ожидающий — оттуда. */
    private val handshakeInbox = LinkedBlockingQueue<ByteArray>(16)

    private val localPriv: ByteArray? by lazy {
        runCatching { Crypto.unBase64(config.account.privateB64) }.getOrNull()
            ?.takeIf { it.size == Wg.KEY_LEN }
    }
    private val localPub: ByteArray? by lazy { localPriv?.let { Crypto.publicOf(it) } }
    private val peerPub: ByteArray? by lazy {
        runCatching { Crypto.unBase64(config.account.peerPublicB64) }.getOrNull()
            ?.takeIf { it.size == Wg.KEY_LEN }
    }

    fun stop() {
        stopped = true
        runCatching { udp.close() }
        runCatching { tunInput.close() }
        runCatching { tunOutput.close() }
    }

    /** Возраст текущей сессии: по нему видно, жива ли она вообще. */
    fun sessionAgeMs(): Long = if (sessionStartedAt == 0L) 0 else System.currentTimeMillis() - sessionStartedAt

    /** @return true, если handshake удался и передача шла (поток завершается при stop()). */
    fun run(): Boolean {
        if (localPriv == null || localPub == null) return fail("PrivateKey не разбирается как base64 или короче ${Wg.KEY_LEN} байт")
        if (peerPub == null) return fail("PublicKey пира не разбирается как base64 или короче ${Wg.KEY_LEN} байт")

        // Читатель стартует ДО handshake: теперь он один на всё — и транспорт, и ответы на rekey.
        val reader = Thread({
            try {
                readerLoop()
            } catch (e: InterruptedException) {
                stopped = true   // штатная остановка
            }
        }, "warpscout-tunnel-in").apply { isDaemon = true; start() }

        if (!negotiate(initial = true)) {
            log("handshake не прошёл — туннель не поднят")
            stop()
            reader.join(1000)
            return false
        }
        handshakeOk = true
        log("handshake OK, туннель поднят")
        runCatching { onTunnelUp?.invoke() }

        val timers = Thread({
            try {
                timerLoop()
            } catch (e: InterruptedException) {
                stopped = true   // штатная остановка, а не сбой
            }
        }, "warpscout-tunnel-timers").apply { isDaemon = true; start() }
        val sender = Thread({ tunToUdp() }, "warpscout-tunnel-out").apply { isDaemon = true; start() }

        reader.join()
        sender.join(1000)
        timers.interrupt()
        return true
    }

    // --------------------------------------------------------------- читатель

    private fun readerLoop() {
        while (!stopped) {
            // Закрытие сокета при stop() — штатный выход, а не ошибка: ловим и уходим.
            val pkt = try {
                udp.receive()
            } catch (e: java.net.PortUnreachableException) {
                // ICMP port unreachable — сервер явно сказал «на этом порту WARP нет». Это не
                // потеря пакета и не «сеть пропала»: точка мертва прямо сейчас, и ждать остальные
                // инициации (ещё две секунды и пять датаграмм) незачем — переходим к следующей.
                if (!stopped) {
                    failureReason = "порт закрыт: ICMP port unreachable"
                    log("точка мертва: порт закрыт (ICMP port unreachable)")
                }
                stopped = true
                return
            } catch (e: Exception) {
                if (!stopped) log("чтение сокета: ${e.javaClass.simpleName}: ${e.message}")
                return
            } ?: continue
            if (pkt.isEmpty()) continue
            // Любой пришедший пакет (даже чужой/мусорный) значит, что путь до сервера жив.
            lastRxAt = System.currentTimeMillis()
            burstPackets = 0
            burstStartAt = 0L
            stallReported = false
            val type = if (pkt.size >= 4) Crypto.readLe32(pkt, 0) else -1
            when (type) {
                // Ответ на инициацию (в том числе на rekey) или cookie reply — отдаём ожидающему.
                Wg.TYPE_RESPONSE, Wg.TYPE_COOKIE -> handshakeInbox.offer(pkt)
                Wg.TYPE_TRANSPORT -> deliver(pkt)
                else -> Unit // junk/чужое: молча игнорируем, иначе журнал забьётся мусором
            }
        }
    }

    /**
     * Отправка с распознаванием «сеть ушла». Одиночный сбой — норма (UDP теряется постоянно);
     * пять подряд с ошибкой маршрута/доступа — это уже мёртвый сокет, о котором надо сказать наверх.
     */
    private fun sendTracked(pkt: ByteArray) {
        val error = try {
            udp.send(pkt)
            null
        } catch (e: Exception) {
            e
        }
        if (error == null) {
            sendFailures.set(0)
            lastOutboundAt = System.currentTimeMillis()
            return
        }
        val n = sendFailures.incrementAndGet()
        val name = error.javaClass.simpleName
        if (n == 1) log("отправка не удалась: $name: ${error.message}")
        if (n >= 5) {
            sendFailures.set(0)
            val reason = "сокет не отправляет пакеты ($name) — похоже, сменилась сеть"
            log(reason)
            onFatal?.invoke(reason)
        }
    }

    private fun deliver(pkt: ByteArray) {
        val plain = synchronized(lock) {
            val s = session ?: return
            val idx = localIndex
            val opened = Wg.openTransport(pkt, idx, s) ?: return
            session = opened.second
            opened.first
        }
        if (plain.isEmpty()) return
        try {
            tunOutput.write(plain)
            tunOutput.flush()
            bytesDown += plain.size
            lastUserTrafficAt = System.currentTimeMillis()
        } catch (e: java.io.IOException) {
            // EIO/EBADF на запись в tun — это закрытый файловый дескриптор, а не сбой данных:
            // так выглядит смена сессии (старый tun закрыли, новый уже поднимают) и обычная
            // остановка. Пишем в журнал нейтрально, чтобы это не читалось как падение.
            if (!stopped) log("туннель закрыт (${e.message ?: e.javaClass.simpleName})")
            stop()
        } catch (e: Exception) {
            if (!stopped) log("в tun: ${e.javaClass.simpleName}: ${e.message}")
            stop()
        }
    }

    // ------------------------------------------------------------- handshake

    /**
     * Одна итерация пересогласования: инициация → (cookie) → ответ, с дедлайном.
     * Вызывается и при старте, и таймером для rekey — код один, поэтому rekey не может «отстать»
     * от основного пути по обработке cookie или мусора.
     */
    private fun negotiate(initial: Boolean): Boolean {
        val priv = localPriv ?: return fail("нет приватного ключа")
        val pub = localPub ?: return fail("нет публичного ключа")
        val peer = peerPub ?: return fail("нет ключа пира")
        val junk: JunkProfile? = config.junk.takeIf { !it.isEmpty }
        val attempts = maxOf(1, settings.attempts)
        val spacing = settings.retryEveryMs.coerceIn(120L, 3_000L)
        val startedAt = System.currentTimeMillis()

        // Инициации уходят пачкой: ответ принимаем на любую. Это главное ускорение — на мобильной
        // сети первый датаграмм регулярно теряется, и «ждать 1.5 с одну попытку» было дорого.
        val outstanding = LinkedHashMap<Int, Wg.Initiation>()
        var sent = 0
        var nextSendAt = startedAt

        fun sendOne(cookie: ByteArray? = null) {
            val idx = Crypto.random.nextInt()
            val init = Wg.buildInitiation(priv, pub, peer, idx, lastCookie = cookie)
            outstanding[idx] = init
            if (junk != null) sendJunk(junk)
            runCatching { udp.send(init.packet) }
            sent++
            attemptCount = sent
        }

        sendOne()
        nextSendAt = startedAt + spacing
        val deadline = startedAt + spacing * (attempts - 1) + settings.timeoutMs
        while (!stopped && System.currentTimeMillis() < deadline) {
            val now = System.currentTimeMillis()
            if (sent < attempts && now >= nextSendAt) {
                sendOne()
                nextSendAt = now + spacing
                log("повтор инициации №${sent} — ответа не было ${spacing} мс")
            }
            val waitMs = minOf(deadline - now, (nextSendAt - now).coerceAtLeast(20))
            // Прерывание — это штатная остановка (closeAll() будит ожидающие потоки), а не сбой.
            // Раньше оно вылетало из negotiate, убивало поток и попадало в «падения» журнала.
            val reply = try {
                handshakeInbox.poll(waitMs.coerceAtLeast(1), TimeUnit.MILLISECONDS)
            } catch (e: InterruptedException) {
                failureReason = "остановлено"
                return false
            } ?: continue

            // Чей это ответ? В response receiver_index на смещении 8, в cookie reply — на 4.
            val type = if (reply.size >= 4) Crypto.readLe32(reply, 0) else -1
            val ourIndex = when (type) {
                Wg.TYPE_RESPONSE -> if (reply.size >= 12) Crypto.readLe32(reply, 8) else -1
                Wg.TYPE_COOKIE -> if (reply.size >= 8) Crypto.readLe32(reply, 4) else -1
                else -> -1
            }
            val initiation = outstanding[ourIndex] ?: continue

            // Один разбор на пакет: внутри DH-умножение, второй вызов — впустую потраченное время.
            val res = Wg.consumeResponse(reply, initiation, peer)
            when (res.kind) {
                Wg.ResponseKind.HANDSHAKE_RESPONSE -> {
                    val s = res.session ?: continue
                    val idx = res.peerSenderIndex ?: continue
                    log("handshake за ${System.currentTimeMillis() - startedAt} мс, инициаций: $sent")
                    install(s, idx, initiation.state.senderIndex, initial)
                    handshakesDone += 1
                    return true
                }

                Wg.ResponseKind.COOKIE_REPLY -> {
                    val cookie = res.cookie
                    if (cookie == null) {
                        log("cookie reply, но cookie не расшифровался — пробую ещё раз")
                        continue
                    }
                    log("сервер требует cookie — повторяю инициацию с cookie")
                    outstanding.clear()
                    sendOne(cookie)
                    nextSendAt = System.currentTimeMillis() + spacing
                }

                // Ответ на чужую/просроченную инициацию — просто ждём дальше.
                else -> continue
            }
        }

        // Причина могла быть названа точнее прямо по ходу (ICMP port unreachable). Общее «сервер
        // молчит» на этом месте её перекрывало, и в журнале вместо «порт закрыт» появлялось
        // «сервер молчит» — то есть подсказка вела не туда.
        val known = failureReason
        if (known == null) {
            failureReason = "сервер молчит: $sent ${if (sent == 1) "инициация" else "инициаций"} за " +
                "${System.currentTimeMillis() - startedAt} мс без ответа"
            log("ответа нет: $failureReason")
        } else {
            log("ответа нет: $known")
        }
        return false
    }

    private fun sendJunk(junk: JunkProfile) {
        val chunks = junk.i1 + junk.i2
        if (chunks.isEmpty()) return
        for (i in 0 until settings.junkPacketsBeforeHandshake) {
            val bytes = chunks[i % chunks.size].materialize(Crypto.random)
            if (bytes.isNotEmpty()) runCatching { udp.send(bytes) }
        }
    }

    private fun install(s: Wg.Session, peer: Int, local: Int, initial: Boolean) {
        synchronized(lock) {
            session = s
            peerIndex = peer
            localIndex = local
            sessionStartedAt = System.currentTimeMillis()
        }
        handshakeInbox.clear() // чужие/старые ответы больше не нужны
        // WireGuard подтверждает новую сессию первым transport-пакетом; пустой keepalive делает это
        // сразу, не дожидаясь, пока пользователь что-нибудь отправит (иначе сервер может продолжать
        // считать активной старую сессию, а мы уже шифруем новой — и данные «теряются»).
        sendKeepalive()
        if (!initial) {
            rekeyCount++
            lastRekeyFailure = null
            log("rekey OK: сессия обновлена (${rekeyCount}-й раз)")
        }
    }

    // ---------------------------------------------------------------- таймеры

    /**
     * Rekey и keepalive. Отдельный поток, потому что пересогласование занимает до нескольких
     * секунд и не должно останавливать пересылку.
     */
    private fun timerLoop() {
        var lastAttemptAt = 0L
        var warnedExpiry = false
        while (!stopped) {
            // Раньше здесь было Thread.sleep(200): поток просыпался пять раз в секунду всё время,
            // пока поднят туннель, — только чтобы посмотреть на часы. Теперь спим ровно до
            // ближайшего события (keepalive или rekey), то есть просыпаемся раз в 25–60 секунд.
            // Для батареи это разница между «процесс постоянно на процессоре» и «спит».
            val now = System.currentTimeMillis()
            val age = if (sessionStartedAt == 0L) 0 else now - sessionStartedAt
            val keepaliveSeconds = config.persistentKeepalive ?: 0
            val nextKeepaliveAt = if (keepaliveSeconds > 0) {
                lastOutboundAt + keepaliveIntervalMs(now)
            } else {
                Long.MAX_VALUE
            }
            val nextRekeyAt = if (age >= settings.rekeyAfterMs) now else {
                val wait = settings.rekeyAfterMs - age
                if (lastAttemptAt == 0L || now - lastAttemptAt >= settings.rekeyRetryMs) now + wait
                else lastAttemptAt + settings.rekeyRetryMs
            }
            // Спим до ближайшего события. Верхняя граница — минута, чтобы смена настроек и
            // остановка туннеля замечались быстро, нижняя — чтобы не крутиться вхолостую.
            val nextEvent = minOf(nextKeepaliveAt, nextRekeyAt)
            if (now < nextEvent) {
                val sleep = (nextEvent - now).coerceIn(250L, 60_000L)
                try {
                    Thread.sleep(sleep)
                } catch (e: InterruptedException) {
                    return
                }
                continue
            }

            if (age >= settings.rekeyAfterMs && now - lastAttemptAt >= settings.rekeyRetryMs) {
                lastAttemptAt = now
                if (age >= 180_000 && !warnedExpiry) {
                    warnedExpiry = true
                    log("сессия старше 180 с — сервер её уже мог выбросить, пересогласовываю")
                }
                if (!negotiate(initial = false)) {
                    lastRekeyFailure = failureReason ?: "rekey не удался"
                    rekeyFailures += 1
                    log("rekey не удался: ${lastRekeyFailure}")
                    // Два провала пересогласования подряд — сессия мертва, хотя туннель числится
                    // поднятым. Именно так выглядит «подключено, но ничего не открывается».
                    if (rekeyFailures >= 2) {
                        rekeyFailures = 0
                        val reason = "сессия не пересогласовывается: $lastRekeyFailure"
                        log(reason)
                        onFatal?.invoke(reason)
                    }
                } else {
                    warnedExpiry = false
                    rekeyFailures = 0
                }
                continue
            }

            // Keepalive по PersistentKeepalive: пустой transport-пакет держит NAT и сессию живой.
            if (keepaliveSeconds > 0 && now - lastOutboundAt >= keepaliveIntervalMs(now)) {
                sendKeepalive()
            }

            // Сюда попадаем, когда ближайшее событие уже наступило, но выполнять его нельзя:
            // например, rekey только что провалился и до повтора ещё несколько секунд. Без этой
            // паузы цикл крутится без сна и держит процессор занятым всё окно повтора — а это
            // ровно те моменты, когда сессия восстанавливается после сбоя.
            val untilRetry = (lastAttemptAt + settings.rekeyRetryMs) - System.currentTimeMillis()
            if (untilRetry > 0) runCatching { Thread.sleep(untilRetry.coerceAtMost(1_000L)) }

            // Раз в полчаса — честные цифры в журнал: сколько было пробуждений радио и рукопожатий.
            // Без этого «батарея садится» обсуждается догадками, а не фактами.
            if (now >= nextStatsAt) {
                nextStatsAt = now + STATS_EVERY_MS
                val idle = if (lastUserTrafficAt == 0L) now - startedAt else now - lastUserTrafficAt
                val extra = vitals?.invoke().orEmpty()
                log(
                    "$STATS_PREFIX keepalive $keepalivesSent, рукопожатий $handshakesDone, " +
                        "трафика нет ${idle / 1000} с, " +
                        Keepalive.describe(keepaliveIntervalMs(now), screenOn(), idle) +
                        (if (extra.isNotBlank()) ", $extra" else "")
                )
            }
        }
    }

    /**
     * Как часто шлём keepalive. Раньше здесь было «интервал из конфига, а после двух минут тишины —
     * вдвое реже», и это не работало: тишину мерили по `lastOutboundAt`, который обновляет сам же
     * keepalive, поэтому удвоение не наступало никогда. Теперь решение принимает [Keepalive] по
     * настоящему простою и состоянию экрана.
     */
    private fun keepaliveIntervalMs(now: Long): Long {
        val idleMs = if (lastUserTrafficAt == 0L) Long.MAX_VALUE else now - lastUserTrafficAt
        return Keepalive.intervalMs(config.persistentKeepalive ?: 0, idleMs, screenOn())
    }

    private fun sendKeepalive() {
        val pkt = synchronized(lock) {
            val s = session ?: return
            val (bytes, next) = Wg.buildTransport(peerIndex, s, ByteArray(0))
            session = next
            bytes
        }
        sendTracked(pkt)
        keepalivesSent += 1
        // Отметку времени ставим даже при ошибке: иначе таймер будет пытаться слать keepalive
        // вплотную, пока сеть не вернётся.
        lastOutboundAt = System.currentTimeMillis()
    }

    // --------------------------------------------------------------- пересылка

    private fun fail(reason: String): Boolean {
        failureReason = reason
        log("handshake невозможен: $reason")
        return false
    }

    private fun tunToUdp() {
        val mtu = config.mtu.coerceIn(576, 1420)
        val buf = ByteArray(mtu)
        while (!stopped) {
            val n = try {
                tunInput.read(buf)
            } catch (e: Exception) {
                -1
            }
            if (n < 0) break
            if (n == 0) {
                // Пустое чтение на неблокирующем дескрипторе — не повод крутить цикл: 20 мс паузы
                // стоят дешевле, чем поток, который жжёт процессор вхолостую.
                runCatching { Thread.sleep(20) }
                continue
            }
            // Без копии: буфер tun переиспользуется, а длина передаётся отдельно. Раньше под
            // каждый пакет делался ByteArray(n) только ради того, чтобы «подрезать» буфер.
            val packet: ByteArray? = synchronized(lock) {
                val s = session
                if (s == null) null else {
                    val (pkt, next) = Wg.buildTransport(peerIndex, s, buf, n)
                    session = next
                    pkt
                }
            }
            if (packet == null) {
                // Сессии нет (только что стартовали или идёт rekey) — пакет теряем, но туннель живой.
                runCatching { Thread.sleep(20) }
                continue
            }
            try {
                sendTracked(packet)
                bytesUp += n
                noteUserPacketSent()
            } catch (e: Exception) {
                if (!stopped) log("отправка: ${e.javaClass.simpleName}: ${e.message}")
                break
            }
        }
        // tun закрылся — значит, сервис останавливают: гасим и читателя с таймерами.
        stopped = true
    }

    /**
     * Учёт пользовательских пакетов и проверка «а отвечает ли сервер».
     *
     * Раньше мёртвая сессия обнаруживалась только по провалу пересогласования — это две-три
     * минуты, в течение которых интернет «есть», но ничего не открывается. Здесь видно раньше:
     * если ушло [StallDetector.MIN_PACKETS] пакетов и за [StallDetector.WINDOW_MS] не пришло ни
     * одного ответа, соединение мертво. Проверка стоит одно сравнение времени на пакет, никаких
     * таймеров и пробуждений.
     */
    private fun noteUserPacketSent() {
        val now = System.currentTimeMillis()
        lastUserTrafficAt = now
        if (stallReported) return
        val sent = burstPackets + 1
        burstPackets = sent
        if (sent == 1) burstStartAt = now
        if (!StallDetector.isStalled(now, lastRxAt, burstStartAt, sent)) return
        stallReported = true
        val reason = StallDetector.explain(now, lastRxAt, burstStartAt, sent)
        log(reason)
        onFatal?.invoke(reason)
    }

    companion object {
        /**
         * Строки с этим префиксом — статистика, а не состояние: сервис пишет их в журнал, но не
         * выставляет в уведомление, иначе вместо «туннель поднят» там мелькали бы цифры.
         */
        const val STATS_PREFIX = "статистика:"

        /** Раз в полчаса — достаточно, чтобы увидеть расход, и мало, чтобы не засорять журнал. */
        private const val STATS_EVERY_MS = 30 * 60_000L
    }
}
