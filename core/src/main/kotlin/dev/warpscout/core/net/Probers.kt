package dev.warpscout.core.net

import dev.warpscout.core.crypto.Crypto
import dev.warpscout.core.model.Endpoint
import dev.warpscout.core.model.EndpointStats
import dev.warpscout.core.model.JunkProfile
import dev.warpscout.core.model.ProbeSample
import dev.warpscout.core.model.Verdict
import dev.warpscout.core.model.WarpAccount
import dev.warpscout.core.tunnel.DataProbe
import dev.warpscout.core.wg.Wg
import java.net.ConnectException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.NoRouteToHostException
import java.net.Socket
import java.net.SocketException
import java.net.SocketTimeoutException
import java.net.UnknownHostException
import java.util.concurrent.Callable
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import java.util.concurrent.atomic.AtomicInteger

/**
 * Создание сокетов вынесено в фабрики: в приложении на Android мы привязываем сокет к конкретной
 * сети (ConnectivityManager#Network), чтобы уметь измерять «без VPN» даже когда туннель уже поднят,
 * и наоборот — мерить внутри туннеля. В CLI/на десктопе фабрики по умолчанию.
 */
fun interface UdpSocketFactory {
    fun create(endpoint: Endpoint): DatagramSocket
}

fun interface TcpSocketFactory {
    fun create(endpoint: Endpoint): Socket
}

object DefaultFactories {
    val udp = UdpSocketFactory { DatagramSocket(null).apply {
        // connect() обязателен: только на connected-сокете Linux/Android отдаёт ICMP «port unreachable»
        // как SocketException, а это для нас единственный способ отличить закрытый порт от чёрной дыры.
        reuseAddress = true
    } }
    val tcp = TcpSocketFactory { Socket() }
}

data class NetSettings(
    val attempts: Int = 4,
    val timeoutMs: Int = 1200,
    val connectTimeoutMs: Int = 4000,
    val concurrency: Int = 48,
    val betweenAttemptsMs: Int = 60,
    val junkPacketsBeforeHandshake: Int = 1,
    /**
     * Через сколько пересогласовывать сессию (rekey). WireGuard: `REKEY_AFTER_TIME` = 120 с,
     * `REJECT_AFTER_TIME` = 180 с. Без rekey сервер выбрасывает сессию через три минуты — снаружи
     * это выглядит как «туннель поднят, а Telegram пишет Соединение…».
     */
    /**
     * Когда пересогласовывать сессию. 150 с вместо 120: протокол требует успеть до 180 с (жёсткий
     * предел для transport-пакетов), а каждое лишнее рукопожатие — это пробуждение радиомодуля.
     * Запас 30 с оставлен на потерю пакетов и повторные попытки (они идут каждые 5 с).
     */
    val rekeyAfterMs: Long = 150_000,
    /** Как часто повторять неудачный rekey: `REKEY_TIMEOUT` в ядре — 5 с. */
    val rekeyRetryMs: Long = 5_000,
    /**
     * Через сколько повторять инициацию, не дожидаясь конца окна `timeoutMs`.
     *
     * Раньше handshake шёл «строго по очереди»: 1500 мс ждём один пакет, потом второй, третий —
     * и на мобильной сети первая инициация регулярно теряется. Теперь инициации уходят пачкой
     * с интервалом в полсекунды, и принимается ответ на любую из них: подключение занимает
     * доли секунды вместо «с пятой попытки и через полминуты».
     */
    val retryEveryMs: Long = 450,
    val udpFactory: UdpSocketFactory = DefaultFactories.udp,
    val tcpFactory: TcpSocketFactory = DefaultFactories.tcp,
    /**
     * Локальный SOCKS5 (по умолчанию — то, что поднимает ByeDPI for Android). Ставится только для
     * TCP-проб: UDP-хэндшейк WireGuard через SOCKS5 не пушится, а вот TLS-пробы MASQUE и HTTP-замеры
     * ресурсов через него идут и показывают, что изменит обход DPI.
     */
    val socks5: Socks5Endpoint? = null
)

/** Результат пробы одной конечной точки. */
data class WgProbeResult(val stats: EndpointStats, val accepted: Boolean, val replyTypes: List<Int>)

/**
 * Проба «это живой WireGuard/AmneziaWG-сервер, и он принимает НАШ ключ».
 *
 * Отправка: [мусорные пакеты выбранного профиля] → handshake initiation (148 байт).
 * Ответ:   handshake response (92) — проверяем receiver_index, MAC1 и AEAD-тег;
 *          cookie reply (60) — тоже признак живого сервера.
 * Молчание/ICMP — отличаем друг от друга по ECONNREFUSED на connected UDP-сокете.
 */
class WgProber(private val settings: NetSettings) {

    /**
     * [dataProbe] — после удачного рукопожатия проверить, идут ли данные: DNS-запрос внутри только
     * что открытой сессии (см. [DataProbe]). Только для подбора, когда своего туннеля нет: рядом с
     * работающим туннелем такой запрос сделал бы новую сессию текущей на сервере, и ответы
     * работающему туннелю шли бы ключами пробы (поэтому дозор и проверка точки по просьбе экрана
     * обходятся рукопожатием).
     *
     * [askSite] (с 1.10.34) — вместе с проверкой данных спросить площадку Cloudflare, через которую
     * выходит точка (см. [DataProbe.siteQuery]): ещё один пакет в той же сессии. Подбор спрашивает,
     * пока площадка адреса не известна.
     */
    fun probe(
        endpoint: Endpoint,
        account: WarpAccount,
        peerPublic: ByteArray,
        junk: JunkProfile? = null,
        dataProbe: Boolean = false,
        askSite: Boolean = false
    ): WgProbeResult {
        val samples = ArrayList<ProbeSample>()
        val replyTypes = mutableListOf<Int>()
        var accepted = false
        // Данные проверяем один раз на удачное рукопожатие и не больше двух раз за пробу: ответ
        // пришёл — дальше незачем, два раза подряд не пришёл — это уже не потеря пакета.
        var dataSeen = false
        var dataAttempts = 0

        val address = try {
            InetAddress.getByName(endpoint.host)
        } catch (e: UnknownHostException) {
            return WgProbeResult(
                EndpointStats(endpoint, listOf(
                    ProbeSample(endpoint, Verdict.DNS_FAIL, note = "не разрешился ${endpoint.host}")
                ), Verdict.DNS_FAIL, 0, settings.attempts), false, replyTypes
            )
        }

        val localPriv = Crypto.unBase64(account.privateB64)
        val localPub = Crypto.publicOf(localPriv)
        val socket = try {
            settings.udpFactory.create(endpoint).apply {
                soTimeout = settings.timeoutMs
                connect(InetSocketAddress(address, endpoint.port))
            }
        } catch (e: Exception) {
            return WgProbeResult(
                EndpointStats(endpoint, listOf(ProbeSample(endpoint, Verdict.ERROR, note = "сокет: ${e.message}")),
                    Verdict.ERROR, 0, settings.attempts), false, replyTypes
            )
        }

        try {
            for (attempt in 0 until settings.attempts) {
                val initiation = Wg.buildInitiation(localPriv, localPub, peerPublic, Crypto.random.nextInt())
                var t0 = System.nanoTime()
                try {
                    sendJunk(socket, junk)
                    // Время ответа — от самой инициации, а не от мусорного пакета перед ней. Раньше
                    // в него входила и пауза после мусора (40–70 мс по Jmin/Jmax): у любого профиля
                    // с шумом «пинг» выходил на полосу хуже, и подбор за подбором побеждал «none» —
                    // ровно тот вариант, который на сети человека замерзает через секунду (1.10.30).
                    t0 = System.nanoTime()
                    socket.send(DatagramPacket(initiation.packet, initiation.packet.size))

                    val buf = ByteArray(2048)
                    val pkt = DatagramPacket(buf, buf.size)
                    socket.receive(pkt)
                    val rtt = (System.nanoTime() - t0) / 1e6
                    val data = pkt.data.copyOfRange(0, pkt.length)
                    val type = if (data.size >= 4) Crypto.readLe32(data, 0) else -1
                    replyTypes.add(type)
                    val reply = Wg.consumeResponse(data, initiation, peerPublic)
                    // Чем открыта сессия (если открыта): по ним пойдёт проба данных.
                    var sessionInit: Wg.Initiation? = null
                    var sessionReply: Wg.ProbeReply? = null
                    var verdict = when (reply.kind) {
                        Wg.ResponseKind.HANDSHAKE_RESPONSE -> {
                            accepted = true
                            sessionInit = initiation
                            sessionReply = reply
                            Verdict.HANDSHAKE_OK
                        }
                        Wg.ResponseKind.COOKIE_REPLY -> { accepted = true; Verdict.COOKIE_REPLY }
                        Wg.ResponseKind.MISMATCH -> Verdict.UDP_SILENT
                        Wg.ResponseKind.MALFORMED -> Verdict.UDP_SILENT
                    }
                    var note = "type=$type len=${data.size} ${reply.kind}"
                    if (reply.kind == Wg.ResponseKind.COOKIE_REPLY && reply.cookie != null) {
                        // Сервер перегружен и требует cookie. Повторяем инициацию с mac2 =
                        // MAC(cookie) — если и тогда придёт валидный ответ, endpoint точно живой.
                        val retry = Wg.buildInitiation(
                            localPriv, localPub, peerPublic, Crypto.random.nextInt(), lastCookie = reply.cookie
                        )
                        val retryReply = runCatching {
                            socket.send(DatagramPacket(retry.packet, retry.packet.size))
                            val pkt2 = DatagramPacket(ByteArray(2048), 2048)
                            socket.receive(pkt2)
                            Wg.consumeResponse(pkt2.data.copyOfRange(0, pkt2.length), retry, peerPublic)
                        }.getOrNull()
                        if (retryReply?.kind == Wg.ResponseKind.HANDSHAKE_RESPONSE) {
                            accepted = true; verdict = Verdict.HANDSHAKE_OK; note += " +cookie-retry"
                            sessionInit = retry
                            sessionReply = retryReply
                        }
                    }
                    var dataTried = false
                    var dataMs: Double? = null
                    var site: String? = null
                    val openedBy = sessionInit
                    val openedWith = sessionReply
                    if (dataProbe && !dataSeen && dataAttempts < 2 && openedBy != null && openedWith != null) {
                        dataAttempts++
                        dataTried = true
                        val dataReply = dataRoundTrip(socket, openedBy, openedWith, account, askSite)
                        dataMs = dataReply.ms
                        site = dataReply.site
                        if (dataMs != null) {
                            dataSeen = true
                            note += " +данные ${dataMs.toLong()} мс"
                        } else {
                            note += " данных нет"
                        }
                        if (site != null) note += " выход $site"
                    }
                    samples.add(
                        ProbeSample(
                            endpoint, verdict, rtt, attempt, junk?.name ?: "none", note = note,
                            dataTried = dataTried, dataMs = dataMs, site = site
                        )
                    )
                } catch (e: SocketTimeoutException) {
                    samples.add(ProbeSample(endpoint, Verdict.UDP_SILENT, null, attempt, junk?.name ?: "none",
                        note = "нет ответа ${settings.timeoutMs}мс"))
                } catch (e: Exception) {
                    val closed = e is ConnectException || e is NoRouteToHostException ||
                        (e is SocketException && e.message?.contains("ECONNREFUSED") == true) ||
                        (e.message?.contains("Connection refused", true) == true) ||
                        (e.message?.contains("unreachable", true) == true)
                    samples.add(ProbeSample(endpoint, if (closed) Verdict.UDP_CLOSED else Verdict.ERROR,
                        null, attempt, junk?.name ?: "none", note = e.javaClass.simpleName + ": " + e.message))
                }
                if (attempt < settings.attempts - 1 && settings.betweenAttemptsMs > 0) {
                    Thread.sleep(settings.betweenAttemptsMs.toLong())
                }
            }
        } finally {
            runCatching { socket.close() }
        }

        val replies = samples.count { it.verdict in setOf(Verdict.HANDSHAKE_OK, Verdict.COOKIE_REPLY, Verdict.TLS_OK) }
        val best = samples.minByOrNull { it.verdict.rank }?.verdict ?: Verdict.ERROR
        return WgProbeResult(EndpointStats(endpoint, samples, best, replies, samples.size), accepted, replyTypes)
    }

    /**
     * Мусорные пакеты профиля перед инициацией — как у AmneziaWG: пакет шаблона I1/I2 и пауза
     * Jmin..Jmax. Без профиля (или «none») не шлём ничего — это чистый WireGuard.
     */
    private fun sendJunk(socket: DatagramSocket, junk: JunkProfile?) {
        if (junk == null || junk.isEmpty || settings.junkPacketsBeforeHandshake <= 0) return
        val chunks = junk.i1 + junk.i2
        if (chunks.isEmpty()) return
        for (i in 0 until settings.junkPacketsBeforeHandshake) {
            val bytes = chunks[i % chunks.size].materialize(Crypto.random)
            if (bytes.isNotEmpty()) socket.send(DatagramPacket(bytes, bytes.size))
            val spread = (junk.awg.jmax - junk.awg.jmin).coerceAtLeast(0)
            Thread.sleep((junk.awg.jmin + Crypto.random.nextInt(spread + 1)).toLong())
        }
    }

    /**
     * Долгая проба данных (с 1.10.30): рукопожатие, затем DNS-запросы внутри сессии в течение
     * [sustainMs]. Годной точка считается, только если ответ приходит и на запрос, отправленный
     * через полторы секунды после начала и позже.
     *
     * Зачем. Сеть человека пропускала рукопожатие и первый ответ, а дальше молчала: обычная проба
     * (один запрос) говорила «данные идут» про туннель, который замерзал через секунду. Подбор
     * ставил такие точки первыми, сервис объявлял «подключено», а через 25 с проверка связи находила
     * обман — и так по кругу (журнал 22.11 19:04–19:10, все точки с шумом none). Цена — четыре
     * пакета по 60 байт и до трёх секунд, поэтому так проверяются только лучшие кандидаты.
     */
    fun probeSustained(
        endpoint: Endpoint,
        account: WarpAccount,
        peerPublic: ByteArray,
        junk: JunkProfile? = null,
        sustainMs: Int = SUSTAIN_DEFAULT_MS
    ): ProbeSample {
        val name = junk?.name ?: "none"
        val address = try {
            InetAddress.getByName(endpoint.host)
        } catch (e: UnknownHostException) {
            return ProbeSample(endpoint, Verdict.DNS_FAIL, profile = name, note = "не разрешился ${endpoint.host}")
        }
        val localPriv = Crypto.unBase64(account.privateB64)
        val localPub = Crypto.publicOf(localPriv)
        val socket = try {
            settings.udpFactory.create(endpoint).apply {
                soTimeout = settings.timeoutMs
                connect(InetSocketAddress(address, endpoint.port))
            }
        } catch (e: Exception) {
            return ProbeSample(endpoint, Verdict.ERROR, profile = name, note = "сокет: ${e.message}")
        }
        try {
            var lastVerdict = Verdict.UDP_SILENT
            var lastNote = "нет ответа"
            // Две инициации, не больше: эта проба повторяет уже ответившую точку, ей нужна сессия,
            // а не статистика потерь.
            for (attempt in 0 until settings.attempts.coerceIn(1, 2)) {
                var initiation = Wg.buildInitiation(localPriv, localPub, peerPublic, Crypto.random.nextInt())
                try {
                    sendJunk(socket, junk)
                    val t0 = System.nanoTime()
                    socket.send(DatagramPacket(initiation.packet, initiation.packet.size))
                    val buf = ByteArray(2048)
                    val pkt = DatagramPacket(buf, buf.size)
                    socket.receive(pkt)
                    val rtt = (System.nanoTime() - t0) / 1e6
                    var reply = Wg.consumeResponse(pkt.data.copyOfRange(0, pkt.length), initiation, peerPublic)
                    if (reply.kind == Wg.ResponseKind.COOKIE_REPLY && reply.cookie != null) {
                        // Сервер под нагрузкой: повтор с cookie, как в [probe].
                        val retry = Wg.buildInitiation(
                            localPriv, localPub, peerPublic, Crypto.random.nextInt(), lastCookie = reply.cookie
                        )
                        socket.send(DatagramPacket(retry.packet, retry.packet.size))
                        val pkt2 = DatagramPacket(ByteArray(2048), 2048)
                        socket.receive(pkt2)
                        reply = Wg.consumeResponse(pkt2.data.copyOfRange(0, pkt2.length), retry, peerPublic)
                        initiation = retry
                    }
                    if (reply.kind != Wg.ResponseKind.HANDSHAKE_RESPONSE) {
                        lastVerdict = if (reply.kind == Wg.ResponseKind.COOKIE_REPLY) Verdict.COOKIE_REPLY else Verdict.UDP_SILENT
                        lastNote = "ответ ${reply.kind}"
                        continue
                    }
                    val series = dataSeries(socket, initiation, reply, account, sustainMs)
                    return ProbeSample(
                        endpoint, Verdict.HANDSHAKE_OK, rtt, attempt, name,
                        note = series.describe(),
                        dataTried = true,
                        dataMs = series.firstMs,
                        dataFrozen = series.firstMs != null && !series.late,
                        dataSustained = series.late
                    )
                } catch (e: SocketTimeoutException) {
                    lastVerdict = Verdict.UDP_SILENT
                    lastNote = "нет ответа ${settings.timeoutMs}мс"
                } catch (e: Exception) {
                    lastVerdict = Verdict.ERROR
                    lastNote = "${e.javaClass.simpleName}: ${e.message}"
                }
            }
            return ProbeSample(endpoint, lastVerdict, null, 0, name, note = lastNote)
        } finally {
            runCatching { socket.close() }
        }
    }

    /** Итог серии запросов долгой пробы. */
    private class Series(val sent: Int, val replies: Int, val firstMs: Double?, val late: Boolean) {
        fun describe(): String = when {
            firstMs == null -> "данных нет: $sent запросов без ответа"
            late -> "данные идут: ответов $replies из $sent, первый за ${firstMs.toLong()} мс"
            else -> "данные встали: первый ответ за ${firstMs.toLong()} мс, дальше тишина ($replies из $sent)"
        }
    }

    /**
     * Серия DNS-запросов внутри открытой сессии: в моменты [SUSTAIN_SEND_AT_MS] (не дальше
     * [sustainMs]) и ожидание ответов. Каждый запрос — свой порт и номер, поэтому ответ узнаётся,
     * даже если пришёл после следующего запроса. Поздний ответ (на запрос через [SUSTAIN_LATE_MS] и
     * позже) — и проба сразу заканчивается: дальше ждать незачем.
     */
    private fun dataSeries(
        socket: DatagramSocket,
        init: Wg.Initiation,
        reply: Wg.ProbeReply,
        account: WarpAccount,
        sustainMs: Int
    ): Series {
        val session = reply.session ?: return Series(0, 0, null, false)
        val peerIndex = reply.peerSenderIndex ?: return Series(0, 0, null, false)
        val src = DataProbe.ipv4Of(account.ipv4) ?: DataProbe.ipv4Of("172.16.0.2") ?: return Series(0, 0, null, false)
        val plan = SUSTAIN_SEND_AT_MS.filter { it <= sustainMs.toLong() }
        // порт → (номер запроса, когда ушёл, мс от начала серии)
        val pending = HashMap<Int, Pair<Int, Long>>()
        var sending = session
        var receiving = session
        val before = runCatching { socket.soTimeout }.getOrDefault(settings.timeoutMs)
        val t0 = System.nanoTime()
        fun nowMs(): Long = (System.nanoTime() - t0) / 1_000_000L
        val endMs = (plan.lastOrNull() ?: 0L) + SUSTAIN_TAIL_MS
        var next = 0
        var sent = 0
        var replies = 0
        var firstMs: Double? = null
        var late = false
        val buf = ByteArray(2048)
        try {
            while (!late) {
                val now = nowMs()
                if (now >= endMs) break
                if (next < plan.size && now >= plan[next]) {
                    val port = DataProbe.randomPort(Crypto.random)
                    val txId = Crypto.random.nextInt(0x10000)
                    val (bytes, nextSend) = Wg.buildTransport(peerIndex, sending, DataProbe.dnsQuery(src, port, txId))
                    sending = nextSend
                    pending[port] = txId to now
                    socket.send(DatagramPacket(bytes, bytes.size))
                    sent++
                    next++
                    continue
                }
                val untilSend = if (next < plan.size) plan[next] - now else Long.MAX_VALUE
                val wait = minOf(untilSend, endMs - now).coerceIn(1L, 1_000L)
                socket.soTimeout = wait.toInt()
                val pkt = DatagramPacket(buf, buf.size)
                try {
                    socket.receive(pkt)
                } catch (e: SocketTimeoutException) {
                    continue
                }
                val data = pkt.data.copyOfRange(0, pkt.length)
                val opened = Wg.openTransport(data, init.state.senderIndex, receiving) ?: continue
                receiving = opened.second
                val match = pending.entries.firstOrNull { (port, v) -> DataProbe.isReply(opened.first, port, v.first) }
                    ?: continue
                pending.remove(match.key)
                replies++
                val sentAt = match.value.second
                if (firstMs == null) firstMs = (nowMs() - sentAt).toDouble()
                if (sentAt >= SUSTAIN_LATE_MS) late = true
            }
        } catch (e: Exception) {
            // Сокет закрыли или сеть пропала: что успели узнать, то и итог.
        } finally {
            runCatching { socket.soTimeout = before }
        }
        return Series(sent, replies, firstMs, late)
    }

    companion object {
        /** Когда слать запросы долгой пробы, мс от конца рукопожатия. */
        val SUSTAIN_SEND_AT_MS = longArrayOf(0L, 600L, 1_500L, 2_400L).toList()

        /** Ответ на запрос, ушедший с этого момента и позже, — «данные идут и не встают». */
        const val SUSTAIN_LATE_MS = 1_500L

        /** Сколько ждать ответа после последнего запроса. */
        const val SUSTAIN_TAIL_MS = 700L

        /** Длина долгой пробы по умолчанию: до последнего запроса. */
        const val SUSTAIN_DEFAULT_MS = 2_400
    }

    /** Итог проверки данных: время ответа (null — ответа нет) и площадка выхода (null — не узнали). */
    private class DataReply(val ms: Double?, val site: String?)

    /**
     * Данные после рукопожатия: DNS-запрос внутри только что открытой сессии и ответ на него.
     * Сокет тот же, что у рукопожатия: сеть видит один поток, как у настоящего туннеля, — именно
     * такой поток она и режет (или нет).
     *
     * С [askSite] вторым пакетом идёт запрос площадки (см. [DataProbe.siteQuery]): свой порт и номер,
     * ответы узнаются по ним, в каком бы порядке ни пришли. Ответ на него ждём не дольше 250 мс
     * после ответа на данные — проба не растягивает подбор, если площадку резолвер не назвал.
     */
    private fun dataRoundTrip(
        socket: DatagramSocket,
        init: Wg.Initiation,
        reply: Wg.ProbeReply,
        account: WarpAccount,
        askSite: Boolean = false
    ): DataReply {
        val session = reply.session ?: return DataReply(null, null)
        val peerIndex = reply.peerSenderIndex ?: return DataReply(null, null)
        val src = DataProbe.ipv4Of(account.ipv4) ?: DataProbe.ipv4Of("172.16.0.2") ?: return DataReply(null, null)
        val port = DataProbe.randomPort(Crypto.random)
        val txId = Crypto.random.nextInt(0x10000)
        val (packet, afterFirst) = Wg.buildTransport(peerIndex, session, DataProbe.dnsQuery(src, port, txId))
        var sitePort = -1
        var siteTx = -1
        val sitePacket = if (askSite) {
            sitePort = DataProbe.randomPort(Crypto.random).let { if (it == port) it + 1 else it }
            siteTx = Crypto.random.nextInt(0x10000)
            Wg.buildTransport(peerIndex, afterFirst, DataProbe.siteQuery(src, sitePort, siteTx)).first
        } else {
            null
        }
        // Ответ DNS внутри WARP приходит за время одного круга до Cloudflare: 0,9 с — с запасом,
        // а на точке без данных проба не растягивает подбор на полные секунды таймаута.
        val waitMs = settings.timeoutMs.coerceIn(400, 900)
        val before = runCatching { socket.soTimeout }.getOrDefault(settings.timeoutMs)
        val t0 = System.nanoTime()
        val deadline = t0 + waitMs * 1_000_000L
        var siteDeadline = Long.MAX_VALUE
        var ms: Double? = null
        var site: String? = null
        try {
            socket.send(DatagramPacket(packet, packet.size))
            if (sitePacket != null) socket.send(DatagramPacket(sitePacket, sitePacket.size))
            val buf = ByteArray(2048)
            while (true) {
                if (ms != null && (sitePacket == null || site != null)) break
                val until = if (ms == null) deadline else minOf(deadline, siteDeadline)
                val leftMs = (until - System.nanoTime()) / 1_000_000L
                if (leftMs <= 0L) break
                socket.soTimeout = leftMs.toInt().coerceAtLeast(1)
                val pkt = DatagramPacket(buf, buf.size)
                try {
                    socket.receive(pkt)
                } catch (e: SocketTimeoutException) {
                    break
                }
                val data = pkt.data.copyOfRange(0, pkt.length)
                // Расшифровываем ключами самой сессии, без счётчика повторов: ответов два, и
                // пришедший вторым мог уйти от сервера первым — проверка порядка отбросила бы его.
                val opened = Wg.openTransport(data, init.state.senderIndex, session) ?: continue
                if (ms == null && DataProbe.isReply(opened.first, port, txId)) {
                    val got = (System.nanoTime() - t0) / 1e6
                    ms = got
                    siteDeadline = System.nanoTime() + (got.toLong() + 80L).coerceIn(80L, 250L) * 1_000_000L
                    continue
                }
                if (sitePacket != null && site == null) {
                    DataProbe.siteOf(opened.first, sitePort, siteTx)?.let { site = it }
                }
            }
        } catch (e: Exception) {
            // Сокет закрыли или сеть пропала: что успели узнать, то и итог.
        } finally {
            runCatching { socket.soTimeout = before }
        }
        return DataReply(ms, site)
    }

    /**
     * Параллельный скан по пулу конечных точек.
     *
     * [isCancelled] — «человек нажал «Остановить подбор»». Раньше скан о нём не знал: пул в 120
     * (а в полном режиме — 1500) точек досчитывался до конца, и «Остановить» срабатывало только
     * через минуты. Теперь ещё не начатые пробы пропускаются, а результаты собираются мелкими
     * ожиданиями, чтобы отмена была видна за доли секунды.
     */
    fun scan(
        endpoints: List<Endpoint>,
        account: WarpAccount,
        peerPublic: ByteArray,
        junk: JunkProfile? = null,
        isCancelled: () -> Boolean = { false },
        onProgress: ((done: Int, total: Int, EndpointStats) -> Unit)? = null
    ): List<EndpointStats> {
        val pool = Executors.newFixedThreadPool(settings.concurrency.coerceIn(1, 256))
        val done = AtomicInteger(0)
        try {
            val futures = endpoints.map { ep ->
                pool.submit(Callable<EndpointStats?> {
                    if (isCancelled()) return@Callable null
                    val res = probe(ep, account, peerPublic, junk)
                    onProgress?.invoke(done.incrementAndGet(), endpoints.size, res.stats)
                    res.stats
                })
            }
            val out = ArrayList<EndpointStats>(futures.size)
            for (future in futures) {
                while (true) {
                    if (isCancelled()) return out
                    val stats = try {
                        future.get(250, TimeUnit.MILLISECONDS)
                    } catch (e: TimeoutException) {
                        continue
                    } catch (e: Exception) {
                        null
                    }
                    if (stats != null) out.add(stats)
                    break
                }
            }
            return out
        } finally {
            pool.shutdownNow()
        }
    }
}

/**
 * TLS/TCP-проба. Нужна в основном для MASQUE (QUIC/HTTP/3 поверх 443/8443/…): там сервер честно
 * отвечает на TLS ClientHello, и это надёжнее любого UDP-гадания.
 */
class TlsProber(private val settings: NetSettings) {

    fun probe(endpoint: Endpoint, sni: String = endpoint.host, alpn: List<String> = listOf("h3", "h2")): ProbeSample {
        val t0 = System.nanoTime()
        var sock: Socket? = null
        return try {
            sock = settings.socks5?.takeIf { it.configured }?.let {
                // Сокет уже соединён (SOCKS5 CONNECT сделан), поэтому ниже не коннектимся второй раз.
                Socks5.connect(it, endpoint.host, endpoint.port, settings.connectTimeoutMs, settings.tcpFactory)
            } ?: settings.tcpFactory.create(endpoint).apply {
                connect(InetSocketAddress(endpoint.host, endpoint.port), settings.connectTimeoutMs)
            }
            val ctx = javax.net.ssl.SSLContext.getInstance("TLS")
            ctx.init(null, arrayOf(TrustAll), null)
            val ssl = ctx.socketFactory.createSocket(sock, sni, endpoint.port, true) as javax.net.ssl.SSLSocket
            sock = ssl
            // ALPN h3/h2 ставим аккуратно: на части Android-провайдеров setApplicationProtocols нет.
            runCatching {
                val params = ssl.sslParameters
                params.applicationProtocols = alpn.toTypedArray()
                ssl.sslParameters = params
            }
            ssl.soTimeout = settings.connectTimeoutMs
            ssl.startHandshake()
            val session = ssl.session
            ProbeSample(endpoint, Verdict.TLS_OK, (System.nanoTime() - t0) / 1e6, 0, "tls",
                note = "proto=${session?.protocol} cipher=${session?.cipherSuite?.take(18)}")
        } catch (e: SocketTimeoutException) {
            ProbeSample(endpoint, Verdict.UDP_SILENT, (System.nanoTime() - t0) / 1e6, 0, "tls", "таймаут TCP")
        } catch (e: ConnectException) {
            ProbeSample(endpoint, Verdict.UDP_CLOSED, (System.nanoTime() - t0) / 1e6, 0, "tls", "refused")
        } catch (e: UnknownHostException) {
            ProbeSample(endpoint, Verdict.DNS_FAIL, null, 0, "tls", "DNS: ${e.message}")
        } catch (e: Exception) {
            ProbeSample(endpoint, Verdict.ERROR, (System.nanoTime() - t0) / 1e6, 0, "tls",
                "${e.javaClass.simpleName}: ${e.message?.take(80)}")
        } finally {
            runCatching { sock?.close() }
        }
    }

    private val TrustAll = object : javax.net.ssl.X509TrustManager {
        override fun checkClientTrusted(chain: Array<java.security.cert.X509Certificate>?, authType: String?) {}
        override fun checkServerTrusted(chain: Array<java.security.cert.X509Certificate>?, authType: String?) {}
        override fun getAcceptedIssuers(): Array<java.security.cert.X509Certificate> = arrayOf()
    }
}
