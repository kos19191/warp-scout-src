package dev.warpscout.core.net

import java.io.ByteArrayOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

/**
 * «Откроется ли ChatGPT с этим DNS» — проверка одной кнопкой.
 *
 * Зачем. Выход WARP для России ChatGPT и Gemini часто видят как «неподдерживаемую страну» и не
 * пускают. «Умные» DNS (Comss, WLRus, GeoHide…) решают это иначе, чем туннель: на имя chatgpt.com
 * они отвечают адресом своего прокси за границей, и сайт видит уже его страну. Работает ли это
 * сейчас — заранее не скажешь: адреса прокси меняются, а оператор может перехватывать DNS.
 *
 * Что делаем, ровно как сделает телефон:
 *  1) спрашиваем у выбранного DNS адрес chatgpt.com — обычным DNS-запросом по UDP 53;
 *  2) открываем TLS с этим адресом под именем chatgpt.com и просим `/cdn-cgi/trace` (страница
 *     Cloudflare: в ней `loc=` — страна, из которой сайт видит запрос);
 *  3) страна из списка «не обслуживаются» — ChatGPT, скорее всего, откажет.
 *
 * Сборка и разбор DNS-пакета — чистые функции: их проверяет самопроверка ядра без сети.
 */
object SmartDnsCheck {

    /** Страны, где ChatGPT не обслуживает (по ним «откроется» = нет). */
    val UNSUPPORTED = setOf("RU", "BY", "CN", "HK", "MO", "IR", "KP", "SY", "CU")

    data class Result(
        /** DNS ответил хоть каким-то адресом. */
        val dnsOk: Boolean,
        /** Адрес, который DNS дал для имени (первый). */
        val address: String,
        /** Страна, из которой сайт видит запрос (`loc=`); пусто — не дошли. */
        val country: String,
        /** Площадка Cloudflare (`colo=`), для журнала. */
        val colo: String,
        /** Что пошло не так — для человека. */
        val note: String,
    ) {
        /** Сайт ответил, и страна обслуживается. */
        val opens: Boolean get() = country.isNotEmpty() && country !in UNSUPPORTED
    }

    /** Запрос A-записи: заголовок (12 байт) + имя + тип A + класс IN. */
    fun buildQuery(id: Int, name: String): ByteArray {
        val out = ByteArrayOutputStream()
        out.write(id ushr 8 and 0xFF)
        out.write(id and 0xFF)
        out.write(0x01) // RD — рекурсия
        out.write(0x00)
        out.write(0x00); out.write(0x01) // QDCOUNT = 1
        repeat(6) { out.write(0x00) }    // AN/NS/AR = 0
        for (label in name.trim().trimEnd('.').split('.')) {
            val bytes = label.toByteArray(Charsets.US_ASCII)
            require(bytes.size in 1..63) { "метка имени: $label" }
            out.write(bytes.size)
            out.write(bytes)
        }
        out.write(0x00)
        out.write(0x00); out.write(0x01) // QTYPE = A
        out.write(0x00); out.write(0x01) // QCLASS = IN
        return out.toByteArray()
    }

    /**
     * Адреса IPv4 из ответа (A-записи раздела ответов). Чужой номер запроса, ошибка сервера или
     * обрезанный пакет — пустой список, а не исключение.
     */
    fun parseA(packet: ByteArray, length: Int, id: Int): List<String> {
        val len = minOf(length, packet.size)
        if (len < 12) return emptyList()
        fun u8(i: Int): Int = packet[i].toInt() and 0xFF
        fun u16(i: Int): Int = (u8(i) shl 8) or u8(i + 1)
        if (u16(0) != (id and 0xFFFF)) return emptyList()
        val flags = u16(2)
        if (flags and 0x8000 == 0) return emptyList() // не ответ
        if (flags and 0x000F != 0) return emptyList() // RCODE ≠ 0
        val qd = u16(4)
        val an = u16(6)
        var pos = 12
        // Пропустить имя: метки или ссылка-указатель (два байта, старшие биты 11).
        fun skipName(): Boolean {
            while (pos < len) {
                val b = u8(pos)
                when {
                    b == 0 -> { pos += 1; return true }
                    b and 0xC0 == 0xC0 -> { pos += 2; return pos <= len }
                    else -> pos += 1 + b
                }
            }
            return false
        }
        repeat(qd) {
            if (!skipName()) return emptyList()
            pos += 4
        }
        val out = ArrayList<String>()
        repeat(an) {
            if (!skipName() || pos + 10 > len) return out
            val type = u16(pos)
            val klass = u16(pos + 2)
            val rdLen = u16(pos + 8)
            pos += 10
            if (pos + rdLen > len) return out
            if (type == 1 && klass == 1 && rdLen == 4) {
                out += "${u8(pos)}.${u8(pos + 1)}.${u8(pos + 2)}.${u8(pos + 3)}"
            }
            pos += rdLen
        }
        return out
    }

    /** Обычный DNS-запрос по UDP 53 к [server]. Пустой список — нет ответа или нет A-записей. */
    fun queryA(server: String, name: String, timeoutMs: Int = 3_000): List<String> {
        val id = (System.nanoTime() and 0xFFFF).toInt()
        val query = buildQuery(id, name)
        return runCatching {
            DatagramSocket().use { sock ->
                sock.soTimeout = timeoutMs
                val addr = InetAddress.getByName(server)
                sock.send(DatagramPacket(query, query.size, addr, 53))
                val buf = ByteArray(1500)
                val packet = DatagramPacket(buf, buf.size)
                sock.receive(packet)
                parseA(buf, packet.length, id)
            }
        }.getOrDefault(emptyList())
    }

    /** Значения `loc=` и `colo=` из текста trace Cloudflare. */
    fun traceFields(text: String): Pair<String, String> {
        val loc = Regex("""(?m)^loc=([A-Z]{2})\s*$""").find(text)?.groupValues?.get(1).orEmpty()
        val colo = Regex("""(?m)^colo=([A-Z]{3})\s*$""").find(text)?.groupValues?.get(1).orEmpty()
        return loc to colo
    }

    /**
     * TLS с адресом [ip] под именем [host] (сертификат проверяется по имени) и запрос
     * `/cdn-cgi/trace`. Возвращает текст ответа или null.
     */
    fun traceVia(ip: String, host: String, timeoutMs: Int = 6_000): String? = runCatching {
        Socket().use { raw ->
            raw.connect(InetSocketAddress(ip, 443), timeoutMs)
            raw.soTimeout = timeoutMs
            val factory = SSLSocketFactory.getDefault() as SSLSocketFactory
            (factory.createSocket(raw, host, 443, true) as SSLSocket).use { ssl ->
                runCatching {
                    val params = ssl.sslParameters
                    params.serverNames = listOf<javax.net.ssl.SNIServerName>(SNIHostName(host))
                    // Проверка имени в сертификате — средствами самого TLS: адрес чужой, имя наше.
                    params.endpointIdentificationAlgorithm = "HTTPS"
                    ssl.sslParameters = params
                }
                ssl.soTimeout = timeoutMs
                ssl.startHandshake()
                val request = "GET /cdn-cgi/trace HTTP/1.1\r\nHost: $host\r\nUser-Agent: Mozilla/5.0\r\n" +
                    "Accept: */*\r\nConnection: close\r\n\r\n"
                ssl.outputStream.write(request.toByteArray(Charsets.US_ASCII))
                ssl.outputStream.flush()
                val input = ssl.inputStream
                val buf = ByteArray(8192)
                var total = 0
                while (total < buf.size) {
                    val n = input.read(buf, total, buf.size - total)
                    if (n <= 0) break
                    total += n
                }
                String(buf, 0, total, Charsets.UTF_8)
            }
        }
    }.getOrNull()

    /** Проверить [host] через DNS [server] целиком. */
    fun check(server: String, host: String = "chatgpt.com"): Result {
        val addrs = queryA(server, host)
        if (addrs.isEmpty()) {
            return Result(false, "", "", "", "DNS $server не ответил на запрос $host")
        }
        val ip = addrs.first()
        val text = traceVia(ip, host)
            ?: return Result(true, ip, "", "", "адрес $ip не открылся под именем $host")
        val (loc, colo) = traceFields(text)
        if (loc.isEmpty()) return Result(true, ip, "", colo, "ответ $ip не похож на Cloudflare")
        return Result(true, ip, loc, colo, "")
    }
}
