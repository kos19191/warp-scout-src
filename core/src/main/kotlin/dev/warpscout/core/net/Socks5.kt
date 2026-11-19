package dev.warpscout.core.net

import dev.warpscout.core.model.Endpoint
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.Socket

/**
 * Адрес локального SOCKS5-прокси.
 *
 * Зачем он нам: обход DPI на Android уже сделан — [ByeDPI for Android](https://github.com/dovecoteescapee/ByeDPIAndroid)
 * поднимает локальный SOCKS5 (по умолчанию `127.0.0.1:1080`) и прогоняет трафик через свой
 * fragmented/fake-packet движок. Нам это интересно с двух сторон:
 *
 *  1. проверить «через ByeDPI открываются ли те ресурсы, которые напрямую лежат» — это и есть
 *     ответ на вопрос «блокировка DPI-образная или по IP» (а значит, что лечить: настройки ByeDPI
 *     или endpoint'ом WARP);
 *  2. прогонять базовые замеры через ByeDPI, когда он включён в режим прокси, — иначе подбор
 *     стартует с кривой картины («сайт лежит», хотя лежит только наш прямой путь).
 */
data class Socks5Endpoint(val host: String = DEFAULT_HOST, val port: Int = DEFAULT_PORT) {

    val configured: Boolean get() = host.isNotBlank() && port in 1..65535

    fun render(): String = "$host:$port"

    fun toEndpoint(): Endpoint = Endpoint(host, port)

    companion object {
        const val DEFAULT_HOST = "127.0.0.1"
        const val DEFAULT_PORT = 1080

        /** ByeDPI для Android в режиме прокси слушает именно это: 127.0.0.1:1080. */
        val BYEDPI_DEFAULT = Socks5Endpoint(DEFAULT_HOST, DEFAULT_PORT)

        /**
         * Разбирает «127.0.0.1:1080», «socks5://[::1]:1080» или просто «1080» (тогда хост — loopback).
         * Пустая строка и мусор → null: «прокси нет» для нас честнее, чем молча мерить не туда.
         */
        fun parse(raw: String?): Socks5Endpoint? {
            val s = raw?.trim().orEmpty()
                .removePrefix("socks5://")
                .removePrefix("socks5h://")
                .removePrefix("socks5 ")
                .trim()
            if (s.isEmpty()) return null
            if (s.all { it.isDigit() }) {
                return s.toIntOrNull()?.let { Socks5Endpoint(DEFAULT_HOST, it) }?.takeIf { it.configured }
            }
            val cut = if (s.endsWith("]")) -1 else s.lastIndexOf(':')
            if (cut <= 0) return null
            val hostPart = s.substring(0, cut).removePrefix("[").removeSuffix("]")
            val portPart = s.substring(cut + 1)
            val port = portPart.toIntOrNull() ?: return null
            return Socks5Endpoint(hostPart, port).takeIf { it.configured }
        }
    }
}

/**
 * Минимальный клиент SOCKS5 (RFC 1928, только `CONNECT` и только «без аутентификации»).
 *
 * Реализован вручную, а не через `java.net.Proxy(SOCKS)`, по одной причине: `Proxy` нельзя
 * подсунуть в наш [TcpSocketFactory]-путь (сокет, привязанный к конкретной сети через
 * ConnectivityManager), а прокси-хоп должен ходить именно так. Домен отдаём прокси как ATYPE=3 —
 * резолвит он, а не мы: заодно отравленный локальный DNS не мешает сравнению.
 */
object Socks5 {

    /** Прокси не отвечает/отвечает дичью: сам обход не запущен. */
    open class Socks5Exception(message: String) : IOException(message)

    /** Прокси жив, но соединения до цели не пустил — это про цель, а не про «ByeDPI выключен». */
    class Socks5Rejected(replyCode: Int, why: String) : Socks5Exception("SOCKS5: CONNECT отклонён, код $replyCode ($why)")

    /**
     * Возвращает сокет, уже соединённый с [targetHost]:[targetPort] через [proxy].
     * [socketFactory] создаёт сокет до самого прокси — так привязка к сети не теряется.
     */
    fun connect(
        proxy: Socks5Endpoint,
        targetHost: String,
        targetPort: Int,
        timeoutMs: Int = 4000,
        socketFactory: TcpSocketFactory = DefaultFactories.tcp
    ): Socket {
        val sock = socketFactory.create(proxy.toEndpoint())
        sock.connect(InetSocketAddress(proxy.host, proxy.port), timeoutMs)
        sock.soTimeout = timeoutMs
        try {
            val out = sock.getOutputStream()
            val input = sock.getInputStream()
            greeting(out)
            expectReply(input, timeoutMs)
            request(out, targetHost, targetPort)
            readReply(input, timeoutMs)
            sock.soTimeout = 0
            return sock
        } catch (e: Exception) {
            runCatching { sock.close() }
            throw e
        }
    }

    private fun greeting(out: OutputStream) {
        // VER=5 NMETHODS=1 METHOD=0 (no auth)
        out.write(byteArrayOf(0x05, 0x01, 0x00))
        out.flush()
    }

    private fun expectReply(input: InputStream, timeoutMs: Int) {
        val chosen = readN(input, 2, timeoutMs)
        if (chosen[0].toInt() != 0x05) throw Socks5Exception("SOCKS5: не SOCKS5-ответ (версия ${chosen[0].toInt() and 0xFF})")
        when (val m = chosen[1].toInt() and 0xFF) {
            0x00 -> Unit
            0xFF -> throw Socks5Exception("SOCKS5: прокси требует аутентификацию — в ByeDPI её включить нечего, проверь адрес порта")
            else -> throw Socks5Exception("SOCKS5: выбрал метод $m, мы умеем только «без аутентификации»")
        }
    }

    private fun request(out: OutputStream, host: String, port: Int) {
        val msg = java.io.ByteArrayOutputStream()
        msg.write(0x05)  // VER
        msg.write(0x01)  // CMD = CONNECT
        msg.write(0x00)  // RSV
        val ip = runCatching { java.net.InetAddress.getByName(host) }.getOrNull()
        if (ip != null && ip.hostAddress == host) {
            val addr = ip.address
            msg.write(if (addr.size == 4) 0x01 else 0x04)  // ATYP IPv4 / IPv6
            msg.write(addr)
        } else {
            val raw = host.toByteArray(Charsets.UTF_8)
            require(raw.size in 1..255) { "имя хоста длиннее 255 байт: $host" }
            msg.write(0x03)                                  // ATYP = domain
            msg.write(raw.size)
            msg.write(raw)
        }
        msg.write((port shr 8) and 0xFF)
        msg.write(port and 0xFF)
        out.write(msg.toByteArray())
        out.flush()
    }

    private fun readReply(input: InputStream, timeoutMs: Int) {
        val head = readN(input, 4, timeoutMs)
        if (head[0].toInt() != 0x05) throw Socks5Exception("SOCKS5: кривый заголовок ответа")
        val rep = head[1].toInt() and 0xFF
        if (rep != 0) throw Socks5Rejected(rep, explain(rep))
        when (val atyp = head[3].toInt() and 0xFF) {
            0x01 -> readN(input, 4, timeoutMs)                 // IPv4
            0x03 -> {                                           // домен
                val len = readN(input, 1, timeoutMs)[0].toInt() and 0xFF
                readN(input, len, timeoutMs)
            }
            0x04 -> readN(input, 16, timeoutMs)                // IPv6
            else -> throw Socks5Exception("SOCKS5: неизвестный ATYP $atyp")
        }
        readN(input, 2, timeoutMs)  // BIND.PORT — нам не важен, но его надо съесть
    }

    private fun explain(rep: Int): String = when (rep) {
        0x01 -> "отказ сервера"
        0x02 -> "запрещено правилами"
        0x03 -> "сеть недоступна"
        0x04 -> "хост недоступен"
        0x05 -> "команда не поддерживается"
        0x06 -> "тип адреса не поддерживается"
        else -> "код $rep"
    }

    private fun readN(input: InputStream, n: Int, timeoutMs: Int): ByteArray {
        val buf = ByteArray(n)
        var got = 0
        while (got < n) {
            val read = try {
                input.read(buf, got, n - got)
            } catch (e: java.net.SocketTimeoutException) {
                throw Socks5Exception("SOCKS5: прокси молчит ${timeoutMs} мс — он запущен? (ByeDPI → режим прокси, порт 1080)")
            }
            if (read < 0) throw Socks5Exception("SOCKS5: прокси закрыл соединение на ${got}-м байте из $n")
            got += read
        }
        return buf
    }
}
