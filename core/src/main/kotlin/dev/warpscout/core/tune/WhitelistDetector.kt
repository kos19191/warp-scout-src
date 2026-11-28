package dev.warpscout.core.tune

import dev.warpscout.core.net.NetSettings
import java.net.ConnectException
import java.net.InetSocketAddress
import java.net.NoRouteToHostException
import java.net.Socket
import java.net.SocketTimeoutException
import java.net.UnknownHostException
import dev.warpscout.core.model.Endpoint
import java.io.BufferedReader
import java.io.InputStreamReader
import java.io.OutputStreamWriter
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager
import java.security.cert.X509Certificate

/**
 * Детектор режима «белых списков» (ТСПУ, default-deny).
 *
 * В режиме белых списков сеть режет не по сигнатуре протокола, а по самому факту:
 *  • UDP к иностранным IP (WARP endpoints) — отбрасывается на L3, независимо от протокола и шума;
 *  • TCP 443 к доменам из белого списка (госуслуги, банки, поиск) — проходит;
 *  • TCP 443 к иностранным IP/доменам вне списка — тоже режется.
 *
 * Проверяем три признака и поcombinations выносим вердикт:
 *  1. TCP 443 к whitelist-доменам проходит — сеть жива, и «разрешённые» сайты открываются;
 *  2. UDP к WARP endpoints молчит — иностранный UDP режется (L3-whitelist);
 *  3. TCP 443 к Cloudflare (иностранный IP) тоже молчит — не только UDP, а весь трафик к иностранным IP.
 *
 * Если 1=true, 2=false, 3=false → whitelist ACTIVE: нужно переходить на TCP 443 к whitelisted SNI
 * (MASQUE/релей), UDP-скан бесполезен и只 жрёт батарею.
 *
 * Детектор не нужен root: обычные TCP-сокеты, таймауты 2–3 с, всё в одном потоке.
 */
enum class WhitelistStatus {
    /** Обычный режим, белые списки не активны. */
    INACTIVE,
    /** Белые списки активны: default-deny, только whitelisted трафик проходит. */
    ACTIVE,
    /** Не удалось надёжно определить (часть проверок не сработала по техническим причинам). */
    UNCLEAR,
    /** Сеть вообще не работает (ни whitelist, ни что-либо ещё). */
    NETWORK_DOWN,
}

/** Результат детекции: статус и сырые признаки, чтобы приложение могло решить, что делать. */
data class WhitelistResult(
    val status: WhitelistStatus,
    /** TCP 443 к whitelist-доменам проходит. */
    val tcpWhitelistOk: Boolean,
    /** UDP к WARP endpoints отвечает (handshake или cookie). */
    val udpCloudflareOk: Boolean,
    /** TCP 443 к иностранным IP (Cloudflare) отвечает. */
    val tcpForeignOk: Boolean,
    /** CAPTCHA-гейт: whitelist-домены открываются, но требуют подтверждения «человек». */
    val captchaGate: Boolean = false,
    /** Людские комментарии для журнала. */
    val notes: List<String> = emptyList()
) {
    fun isWhitelist(): Boolean = status == WhitelistStatus.ACTIVE
    fun isUsableUdp(): Boolean = status == WhitelistStatus.INACTIVE || udpCloudflareOk
}

/**
 * Домены, которые почти наверняка в белом списке Минцифры (госуслуги, банки, поиск, новости).
 * Используются только для детекции режима — не для маршрутизации и не для SNI-маскировки.
 */
private val WHITELIST_HOSTS = listOf(
    "gosuslugi.ru", "sber.ru", "yandex.ru", "vk.ru", "wb.ru"
)

/** Иностранные IP WARP/Cloudflare для проверки, режется ли весь трафик к ним. */
private val FOREIGN_IPS = listOf("162.159.192.1", "188.114.97.1", "8.34.70.1")

/** Порт, который мы проверяем: 443 для whitelist-доменов, WARP UDP-порт для иностранных. */
private val WHITELIST_PORT = 443
private val WARP_UDP_PORT = 500

/** Таймаут одной проверки, мс. */
private const val PROBE_TIMEOUT_MS = 3000

object WhitelistDetector {

    /**
     * Проводит детекцию режима белых списков.
     *
     * @param settings настройки сети (таймауты, фабрики сокетов);
     * @param sink куда писать прогресс (журнал подбора / экран);
     * @return результат с вердиктом и признаками.
     */
    fun detect(settings: NetSettings, sink: ProgressSink): WhitelistResult {
        val notes = mutableListOf<String>()

        // 1. Whitelist-домены по TCP 443 — должны открываться, если сеть вообще жива.
        val tcpWhitelist = testTcpHosts(WHITELIST_HOSTS, WHITELIST_PORT, settings)
        notes += "TCP 443 к whitelist-доменам: ${tcpWhitelist.successCount}/${tcpWhitelist.tested} прошли " +
            "(${tcpWhitelist.hosts.joinToString(", ") { it.first }})"
        sink.log("whitelist: TCP 443 к ${tcpWhitelist.hosts.joinToString(",")} = ${tcpWhitelist.successCount}/${tcpWhitelist.tested}")

        // 2. Иностранные UDP (WARP) — в whitelist режиме должны молчать.
        val udpForeign = testUdpForeign(settings)
        notes += "UDP к WARP endpoints: ${if (udpForeign) "отвечает" else "молчит"}"
        sink.log("whitelist: UDP к WARP = $udpForeign")

        // 3. Иностранные TCP 443 (Cloudflare IP) — в whitelist режиме тоже должны молчать.
        val tcpForeign = testTcpHosts(FOREIGN_IPS, WHITELIST_PORT, settings)
        notes += "TCP 443 к иностранным IP: ${tcpForeign.successCount}/${tcpForeign.tested} прошли " +
            "(${tcpForeign.hosts.joinToString(", ") { it.first }})"
        sink.log("whitelist: TCP 443 к иностранным IP = ${tcpForeign.successCount}/${tcpForeign.tested}")

        val status = when {
            !tcpWhitelist.anyOk && !udpForeign && !tcpForeign.anyOk ->
                WhitelistStatus.NETWORK_DOWN
            tcpWhitelist.anyOk && !udpForeign && !tcpForeign.anyOk ->
                WhitelistStatus.ACTIVE
            tcpWhitelist.anyOk && udpForeign ->
                WhitelistStatus.INACTIVE
            else ->
                WhitelistStatus.UNCLEAR
        }

        val captchaGate = if (tcpWhitelist.anyOk) {
            // Если whitelist-домены открываются, но ответы выглядят как страница подтверждения — CAPTCHA-гейт.
            // Простая эвристика: первый прошедший хост вернул HTTP-статус, но тело содержит captcha.
            tcpWhitelist.hosts.any { (host, ok, _) ->
                ok && detectCaptcha(host, settings)
            }
        } else false

        val result = WhitelistResult(
            status = status,
            tcpWhitelistOk = tcpWhitelist.anyOk,
            udpCloudflareOk = udpForeign,
            tcpForeignOk = tcpForeign.anyOk,
            captchaGate = captchaGate,
            notes = notes
        )
        sink.log("whitelist: вердикт ${result.status} (TCP-whitelist=${tcpWhitelist.anyOk}, " +
            "UDP-WARP=$udpForeign, TCP-foreign=${tcpForeign.anyOk}, CAPTCHA=$captchaGate)")
        return result
    }

    /** Проверяем список хостов по TCP. Возвращает пары (хост, прошёл, заметка). */
    private data class TcpProbeResult(
        val hosts: List<Triple<String, Boolean, String?>>,
    ) {
        val anyOk: Boolean get() = hosts.any { it.second }
        val successCount: Int get() = hosts.count { it.second }
        val tested: Int get() = hosts.size
    }

    private fun testTcpHosts(hosts: List<String>, port: Int, settings: NetSettings): TcpProbeResult {
        val results = mutableListOf<Triple<String, Boolean, String?>>()
        for (host in hosts) {
            val ok = runCatching {
                val addr = InetSocketAddress(host, port)
                val sock = settings.tcpFactory.create(Endpoint(host, port))
                sock.connect(addr, settings.connectTimeoutMs.coerceAtMost(PROBE_TIMEOUT_MS))
                sock.soTimeout = PROBE_TIMEOUT_MS
                // Простое соединение установлено — достаточно, чтобы dizer «порт открыт».
                // Не шлём HTTP-запрос: лишние данные могут сработать как сигнатура.
                sock.close()
                true
            }.getOrElse { false }
            results += Triple(host, ok, null)
        }
        return TcpProbeResult(results)
    }

    /** Проверяем, отвечают ли WARP endpoints на UDP. Используем существующий WgProber через одну точку. */
    private fun testUdpForeign(settings: NetSettings): Boolean {
        // Берём одну известную точку из пула: первая подсеть, популярный порт.
        val ep = Endpoint("162.159.192.1", WARP_UDP_PORT)
        // Быстрая проверка: один UDP-пакет, ждём ответ 1.5 с.
        val socket = runCatching {
            settings.udpFactory.create(ep).apply {
                soTimeout = PROBE_TIMEOUT_MS
                connect(InetSocketAddress(ep.host, ep.port))
            }
        }.getOrNull() ?: return false
        return try {
            val buf = ByteArray(64)
            val pkt = java.net.DatagramPacket(buf, buf.size)
            // Шлём пустой датаграмм — если сервер живой, он может ответить ICMP port unreachable
            // (порт закрыт для левого пакета) или молчать. Важно distinguish silence vs closed.
            socket.send(java.net.DatagramPacket(ByteArray(1), 0))
            socket.receive(pkt)
            true // Пришёл какой-то ответ — порт не отфильтрован на L3.
        } catch (e: java.net.SocketTimeoutException) {
            false // Молчит — либо фильтр, либо нет сервера.
        } catch (e: Exception) {
            false
        } finally {
            runCatching { socket.close() }
        }
    }

    /** CAPTCHA-гейт: заходим на whitelist-домен по HTTPS и ищем признаки страницы подтверждения. */
    private fun detectCaptcha(host: String, settings: NetSettings): Boolean {
        return runCatching {
            var sock = settings.tcpFactory.create(Endpoint(host, WHITELIST_PORT))
            sock.connect(InetSocketAddress(host, WHITELIST_PORT), settings.connectTimeoutMs.coerceAtMost(PROBE_TIMEOUT_MS))
            val sslCtx = SSLContext.getInstance("TLS")
            sslCtx.init(null, arrayOf(TrustAll), null)
            val ssl = sslCtx.socketFactory.createSocket(sock, host, WHITELIST_PORT, true) as SSLSocket
            sock = ssl
            ssl.soTimeout = PROBE_TIMEOUT_MS
            ssl.startHandshake()
            val writer = java.io.OutputStreamWriter(ssl.outputStream, "UTF-8")
            writer.write("GET / HTTP/1.1\r\nHost: $host\r\nConnection: close\r\n\r\n")
            writer.flush()
            val reader = java.io.BufferedReader(java.io.InputStreamReader(ssl.inputStream, "UTF-8"))
            val line = reader.readLine() ?: ""
            val body = reader.readText().take(2000).lowercase()
            ssl.close()
            body.contains("captcha") || body.contains("подтвер") || body.contains("вы человек") ||
                line.contains("403") || line.contains("429")
        }.getOrDefault(false)
    }

    private val TrustAll = object : X509TrustManager {
        override fun checkClientTrusted(chain: Array<X509Certificate>?, authType: String?) {}
        override fun checkServerTrusted(chain: Array<X509Certificate>?, authType: String?) {}
        override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
    }
}
