package dev.warpscout.core.tunnel

/**
 * Проба «данные ходят»: один DNS-запрос внутри WireGuard-сессии и ответ на него.
 *
 * Зачем. Рукопожатие доказывает только одно — сервер принял наш ключ. Данные после него сеть может
 * не пропускать: в журнале 22.11 16:33 точка 188.114.97.1:500 отвечала на рукопожатие за 200 мс,
 * а вниз не пришло ни байта («вверх 5542, вниз 0»). Приложение считало её рабочей и писало
 * «Туннель работает», проверка связи замечала обман только через 28 секунд — и переподключала на
 * ту же точку. Подбор тоже судил по рукопожатию и ставил такие точки в очередь.
 *
 * Запрос собирается здесь, а не через сокет: он идёт внутри сессии мимо маршрутов телефона
 * (раздельные маршруты и «только выбранные приложения» на него не влияют), а ответ узнаётся по
 * порту и номеру запроса. Спрашиваем DNS Cloudflare (1.1.1.1:53) — внутри WARP он есть всегда.
 * Один запрос — 60 байт вверх и около сотни вниз: для батареи это ничто.
 */
object DataProbe {

    /** Куда: DNS Cloudflare внутри WARP. */
    val TARGET: ByteArray = byteArrayOf(1, 1, 1, 1)
    const val TARGET_PORT = 53

    /** Что спрашиваем: имя, которое существует всегда (запись A). */
    private val QNAME = listOf("cloudflare", "com")

    /** Адрес туннеля из конфига («172.16.0.2/32» → 4 байта). null — это не IPv4. */
    fun ipv4Of(text: String?): ByteArray? {
        val host = text?.substringBefore('/')?.trim().orEmpty()
        val parts = host.split('.')
        if (parts.size != 4) return null
        val out = ByteArray(4)
        for (i in 0 until 4) {
            val n = parts[i].toIntOrNull() ?: return null
            if (n !in 0..255) return null
            out[i] = n.toByte()
        }
        return out
    }

    /** Порт отправителя из динамического диапазона: по нему (и номеру запроса) узнаётся ответ. */
    fun randomPort(random: java.util.Random): Int = 40_000 + random.nextInt(20_000)

    /** IPv4/UDP-пакет с DNS-запросом «A cloudflare.com» от [src]:[srcPort] к [dst]:53. */
    fun dnsQuery(src: ByteArray, srcPort: Int, txId: Int, dst: ByteArray = TARGET): ByteArray =
        udp4(src, srcPort, dst, TARGET_PORT, question(txId, QNAME, qtype = 1, qclass = 1, recursive = true))

    /** Что спрашиваем о площадке: «id.server» класса CHAOS. */
    private val SITE_QNAME = listOf("id", "server")

    /**
     * IPv4/UDP-пакет с запросом «id.server» класса CHAOS, тип TXT (с 1.10.34). Резолвер 1.1.1.1
     * отвечает на него кодом площадки Cloudflare, которая обработала запрос («DME», «HEL») — так
     * его и описывает документация Cloudflare для диагностики. Внутри WARP это площадка выхода:
     * через Москву трафик выходит в российский интернет, под фильтры (журнал 23.11 — медиа Telegram
     * «через раз и рывками»). Один пакет рядом с проверкой данных — подбор узнаёт площадку каждой
     * точки бесплатно, без подъёма туннеля.
     */
    fun siteQuery(src: ByteArray, srcPort: Int, txId: Int, dst: ByteArray = TARGET): ByteArray =
        udp4(src, srcPort, dst, TARGET_PORT, question(txId, SITE_QNAME, qtype = 16, qclass = 3, recursive = false))

    /** Тело DNS-запроса с одним вопросом. */
    private fun question(txId: Int, labels: List<String>, qtype: Int, qclass: Int, recursive: Boolean): ByteArray {
        val dns = java.io.ByteArrayOutputStream()
        dns.write((txId ushr 8) and 0xff)
        dns.write(txId and 0xff)
        dns.write(if (recursive) 0x01 else 0x00)   // RD: рекурсивный запрос (CHAOS отвечает сам резолвер)
        dns.write(0x00)
        dns.write(0); dns.write(1)      // QDCOUNT = 1
        repeat(6) { dns.write(0) }      // ANCOUNT, NSCOUNT, ARCOUNT = 0
        for (label in labels) {
            val bytes = label.toByteArray(Charsets.US_ASCII)
            dns.write(bytes.size)
            dns.write(bytes, 0, bytes.size)
        }
        dns.write(0)
        dns.write((qtype ushr 8) and 0xff); dns.write(qtype and 0xff)
        dns.write((qclass ushr 8) and 0xff); dns.write(qclass and 0xff)
        return dns.toByteArray()
    }

    /**
     * IPv4 + UDP вокруг [payload]. Контрольные суммы честные: пакет с нулевой суммой IP-заголовка
     * сервер вправе выбросить молча, и проба показала бы «данных нет» там, где они есть.
     */
    fun udp4(src: ByteArray, srcPort: Int, dst: ByteArray, dstPort: Int, payload: ByteArray): ByteArray {
        val udpLen = 8 + payload.size
        val total = 20 + udpLen
        val p = ByteArray(total)
        p[0] = 0x45                                     // IPv4, заголовок 20 байт
        p[2] = (total ushr 8).toByte()
        p[3] = total.toByte()
        val id = (srcPort * 31 + payload.size) and 0xffff
        p[4] = (id ushr 8).toByte()
        p[5] = id.toByte()
        p[6] = 0x40                                     // DF: не дробить
        p[8] = 64                                       // TTL
        p[9] = 17                                       // UDP
        src.copyInto(p, 12)
        dst.copyInto(p, 16)
        val ipSum = checksum(p, 0, 20, 0L)
        p[10] = (ipSum ushr 8).toByte()
        p[11] = ipSum.toByte()
        p[20] = (srcPort ushr 8).toByte()
        p[21] = srcPort.toByte()
        p[22] = (dstPort ushr 8).toByte()
        p[23] = dstPort.toByte()
        p[24] = (udpLen ushr 8).toByte()
        p[25] = udpLen.toByte()
        payload.copyInto(p, 28)
        // Псевдозаголовок UDP: адреса, протокол и длина — они входят в сумму, но не в пакет.
        val pseudo = word(src, 0) + word(src, 2) + word(dst, 0) + word(dst, 2) + 17L + udpLen.toLong()
        var udpSum = checksum(p, 20, udpLen, pseudo)
        if (udpSum == 0) udpSum = 0xffff                // ноль в UDP означает «суммы нет»
        p[26] = (udpSum ushr 8).toByte()
        p[27] = udpSum.toByte()
        return p
    }

    /**
     * Ответ ли это на наш запрос: IPv4/UDP с порта 53 на наш [srcPort], тот же номер запроса и флаг
     * «ответ». Трафик приложений сюда не подходит, даже если они успели что-то спросить у DNS.
     */
    fun isReply(packet: ByteArray, srcPort: Int, txId: Int, length: Int = packet.size): Boolean {
        if (length < 28 || packet.size < length) return false
        if (((packet[0].toInt() ushr 4) and 0x0f) != 4) return false
        val ihl = (packet[0].toInt() and 0x0f) * 4
        if (ihl < 20 || length < ihl + 8 + 12) return false
        if ((packet[9].toInt() and 0xff) != 17) return false
        if (u16(packet, ihl) != TARGET_PORT || u16(packet, ihl + 2) != srcPort) return false
        val dnsAt = ihl + 8
        if (u16(packet, dnsAt) != (txId and 0xffff)) return false
        return (packet[dnsAt + 2].toInt() and 0x80) != 0
    }

    /**
     * Код площадки из ответа на [siteQuery] («DME»); null — это не ответ на наш запрос, ответ без
     * записи TXT или в ней не код площадки. Имена в ответе могут быть сжаты (ссылки 0xC0xx) — их
     * пропускаем, не разворачивая: нужен только первый TXT.
     */
    fun siteOf(packet: ByteArray, srcPort: Int, txId: Int, length: Int = packet.size): String? {
        if (!isReply(packet, srcPort, txId, length)) return null
        val ihl = (packet[0].toInt() and 0x0f) * 4
        val dns = ihl + 8
        // Расшифрованный пакет WireGuard дополнен нулями до кратного 16 — граница по длине из
        // заголовка IP, иначе нули дополнения читались бы как часть ответа.
        val total = u16(packet, 2)
        val end = if (total in (dns + 12)..length) total else length
        if (end < dns + 12) return null
        val qd = u16(packet, dns + 4)
        val an = u16(packet, dns + 6)
        if (an <= 0) return null
        var pos = dns + 12
        repeat(qd) {
            pos = skipName(packet, pos, end) ?: return null
            pos += 4                                   // QTYPE, QCLASS
            if (pos > end) return null
        }
        repeat(an) {
            pos = skipName(packet, pos, end) ?: return null
            if (pos + 10 > end) return null
            val type = u16(packet, pos)
            val rdLen = u16(packet, pos + 8)
            val rd = pos + 10
            if (rd + rdLen > end) return null
            if (type == 16 && rdLen >= 1) {
                val len = packet[rd].toInt() and 0xff
                if (len >= 1 && 1 + len <= rdLen) {
                    val text = String(packet, rd + 1, len, Charsets.US_ASCII)
                    return dev.warpscout.core.net.ExitSite.normalize(text).ifEmpty { null }
                }
                return null
            }
            pos = rd + rdLen
        }
        return null
    }

    /** Пропустить имя в DNS-сообщении: метки или ссылку (два байта 0xC0xx). null — имя битое. */
    private fun skipName(b: ByteArray, start: Int, end: Int): Int? {
        var pos = start
        var guard = 0
        while (pos < end && guard++ < 64) {
            val len = b[pos].toInt() and 0xff
            if (len == 0) return pos + 1
            if ((len and 0xc0) == 0xc0) return if (pos + 2 <= end) pos + 2 else null
            if ((len and 0xc0) != 0) return null
            pos += 1 + len
        }
        return null
    }

    /** Интернет-контрольная сумма (RFC 1071): сумма 16-битных слов с переносом, инвертированная. */
    fun checksum(buf: ByteArray, off: Int, len: Int, initial: Long): Int {
        var sum = initial
        var i = off
        val end = off + len
        while (i + 1 < end) {
            sum += (((buf[i].toInt() and 0xff) shl 8) or (buf[i + 1].toInt() and 0xff)).toLong()
            i += 2
        }
        if (i < end) sum += ((buf[i].toInt() and 0xff) shl 8).toLong()
        while ((sum ushr 16) != 0L) sum = (sum and 0xffffL) + (sum ushr 16)
        return (sum.inv() and 0xffffL).toInt()
    }

    private fun word(b: ByteArray, off: Int): Long =
        ((((b[off].toInt() and 0xff) shl 8) or (b[off + 1].toInt() and 0xff))).toLong()

    private fun u16(b: ByteArray, off: Int): Int =
        ((b[off].toInt() and 0xff) shl 8) or (b[off + 1].toInt() and 0xff)
}
