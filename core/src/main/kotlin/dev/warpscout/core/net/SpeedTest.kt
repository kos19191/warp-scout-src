package dev.warpscout.core.net

import java.io.InputStream
import java.net.HttpURLConnection
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketTimeoutException
import java.net.URL

/**
 * Замер скорости настоящей загрузкой — и заодно проверка на «заморозку».
 *
 * Зачем. Проверка связи (trace Cloudflare, пара сотен байт) проходит и там, где оператор
 * пропускает начало соединения и «замораживает» его после первых 16–20 КБ: так с 2025–2026 года
 * режут Cloudflare на части российских сетей (об этом пишут и в NetFix). Экран тогда честно
 * показывал «подключено», а видео и файлы стояли. Загрузка в сотни килобайт с проверкой, что
 * тело дочитано до конца (сколько обещал Content-Length), видит и заморозку, и реальную скорость.
 *
 * Чтение тела — чистая функция над потоком ([drain]): её гоняет самопроверка ядра без сети.
 * Заморозка — это read(), который молчит дольше таймаута сокета: его задаёт вызывающий
 * (readTimeout = «сколько тишины считать остановкой»).
 */
object SpeedTest {

    /** Загрузка прошла (дочитали или упёрлись в лимит времени полного замера) — скорость посчитана. */
    const val OK = 1

    /** Данные пошли и встали: пришло сколько-то байт, дальше тишина — или соединение оборвали. */
    const val FROZEN = 2

    /** Ни байта тела: нет ответа, ошибка соединения или HTTP-ошибка. */
    const val FAIL = 3

    /**
     * Сколько качать при автозамере после подключения: «заморозка» (16–20 КБ и тишина) видна
     * задолго до конца, скорость — примерно, а трафика — полмегабайта.
     */
    const val AUTO_BYTES = 512L * 1024

    /**
     * Полный замер по нажатию: до 10 МБ, но не дольше [FULL_MS]. На мобильной сети каждое нажатие
     * — это трафик, поэтому без «качать, пока не надоест».
     */
    const val FULL_BYTES = 10_000_000L
    const val FULL_MS = 6_000L

    /** Короткая загрузка для подбора: на каждую проверенную точку. */
    const val SCAN_BYTES = 256L * 1024

    data class Result(
        val state: Int,
        /** Сколько байт тела прочитано. */
        val bytes: Long,
        /** Сколько шло чтение тела, мс. */
        val ms: Long,
        /** Килобит в секунду; -1 — посчитать не из чего. */
        val kbps: Int,
        /** До заголовков ответа, мс (-1 — не дошли). */
        val ttfbMs: Int = -1,
        /** Что пошло не так — для журнала. */
        val note: String = "",
    )

    /**
     * Загрузка ровно [bytes] байт с Cloudflare. Через туннель WARP это свой же Cloudflare, так что
     * замер показывает именно канал «телефон — точка входа — выход», а не чужой сервер.
     */
    fun cloudflareUrl(bytes: Long): String = "https://speed.cloudflare.com/__down?bytes=$bytes"

    /**
     * Прочитать тело: до [maxBytes] (и не больше обещанного [expected], если он известен) или до
     * [maxMs]. SocketTimeoutException посреди тела — заморозка, в самом начале — провал.
     * Тело кончилось раньше обещанного — соединение оборвали посреди загрузки: тоже заморозка
     * (для человека разницы нет — видео встало).
     */
    fun drain(
        input: InputStream,
        expected: Long,
        maxBytes: Long,
        maxMs: Long,
        now: () -> Long = System::currentTimeMillis,
    ): Result {
        val buf = ByteArray(16 * 1024)
        val start = now()
        val limit = if (expected > 0) minOf(expected, maxBytes) else maxBytes
        var total = 0L
        var eof = false
        // Разгон TCP: первые десятки килобайт идут медленнее, чем позволяет канал. Скорость
        // считаем по тому, что пришло после первых [WARM_BYTES], — иначе короткий замер всегда
        // занижает число в разы.
        var warmAt = -1L
        var warmBytes = 0L
        while (total < limit) {
            val want = minOf(buf.size.toLong(), limit - total).toInt()
            val n = try {
                input.read(buf, 0, want)
            } catch (e: SocketTimeoutException) {
                val ms = (now() - start).coerceAtLeast(0L)
                return if (total > 0) {
                    Result(FROZEN, total, ms, kbpsOf(total, ms), note = "данные встали после ${total / 1024} КБ")
                } else {
                    Result(FAIL, 0L, ms, -1, note = "тело ответа не пришло")
                }
            }
            if (n < 0) {
                eof = true
                break
            }
            total += n
            if (warmAt < 0L && total >= WARM_BYTES) {
                warmAt = now()
                warmBytes = total
            }
            if (now() - start >= maxMs) break
        }
        val end = now()
        val ms = (end - start).coerceAtLeast(0L)
        if (eof && expected > 0 && total < limit) {
            return Result(
                FROZEN, total, ms, kbpsOf(total, ms),
                note = "соединение оборвалось на ${total / 1024} КБ из ${limit / 1024}"
            )
        }
        if (total == 0L) return Result(FAIL, 0L, ms, -1, note = "пустой ответ")
        val tail = total - warmBytes
        val kbps = if (warmAt >= 0L && tail >= WARM_BYTES && end - warmAt >= 50L) {
            kbpsOf(tail, end - warmAt)
        } else {
            kbpsOf(total, ms)
        }
        return Result(OK, total, ms, kbps)
    }

    /** Сколько байт отдать на разгон соединения, прежде чем считать скорость. */
    const val WARM_BYTES = 64L * 1024

    /**
     * Скорость: биты за миллисекунду — это и есть килобиты в секунду. Окно меньше 20 мс считаем
     * за 20: маленький файл на быстром канале успевает лечь в буфер ещё до первого read(), и
     * «тысяча мегабит» в таком замере — артефакт, а не скорость.
     */
    fun kbpsOf(bytes: Long, ms: Long): Int {
        if (bytes <= 0L) return -1
        val window = ms.coerceAtLeast(20L)
        return ((bytes * 8L) / window).coerceIn(0L, Int.MAX_VALUE.toLong()).toInt()
    }

    /**
     * Загрузка по HTTP(S) обычным сокетом процесса (через туннель, если процесс в нём).
     * [stallMs] — сколько тишины посреди тела считать заморозкой.
     */
    fun run(url: String, maxBytes: Long, maxMs: Long, stallMs: Int, connectMs: Int = 5_000): Result {
        val t0 = System.currentTimeMillis()
        val conn = try {
            URL(url).openConnection() as HttpURLConnection
        } catch (e: Exception) {
            return Result(FAIL, 0L, 0L, -1, note = "${e.javaClass.simpleName}: ${e.message.orEmpty().take(60)}")
        }
        try {
            conn.connectTimeout = connectMs
            conn.readTimeout = stallMs
            conn.useCaches = false
            conn.instanceFollowRedirects = false
            conn.setRequestProperty("Cache-Control", "no-cache")
            // Без сжатия: считаем байты канала. Сжатый поток нулей «качался» бы в сотни раз быстрее.
            conn.setRequestProperty("Accept-Encoding", "identity")
            conn.setRequestProperty("User-Agent", "WarpScout")
            val code = try {
                conn.responseCode
            } catch (e: SocketTimeoutException) {
                return Result(FAIL, 0L, 0L, -1, note = "нет ответа за ${(System.currentTimeMillis() - t0) / 1000} с")
            } catch (e: Exception) {
                return Result(FAIL, 0L, 0L, -1, note = "${e.javaClass.simpleName}: ${e.message.orEmpty().take(60)}")
            }
            val ttfb = (System.currentTimeMillis() - t0).toInt()
            if (code !in 200..299) return Result(FAIL, 0L, 0L, -1, ttfb, "HTTP $code")
            val expected = conn.contentLengthLong
            val body = try {
                conn.inputStream.use { drain(it, expected, maxBytes, maxMs) }
            } catch (e: Exception) {
                Result(FAIL, 0L, 0L, -1, note = "${e.javaClass.simpleName}: ${e.message.orEmpty().take(60)}")
            }
            return body.copy(ttfbMs = ttfb)
        } finally {
            runCatching { conn.disconnect() }
        }
    }

    /**
     * Пинг без ICMP (его у приложений нет): время TCP-соединения, лучшее из [tries]. Соединение —
     * ровно один круг «туда и обратно», без TLS, поэтому это честная задержка канала.
     */
    fun tcpPing(host: String, port: Int, timeoutMs: Int, tries: Int = 2): Int {
        var best = -1
        repeat(tries.coerceAtLeast(1)) {
            val t0 = System.nanoTime()
            val ok = runCatching {
                Socket().use { sock -> sock.connect(InetSocketAddress(host, port), timeoutMs) }
            }.isSuccess
            if (ok) {
                val ms = ((System.nanoTime() - t0) / 1_000_000L).toInt()
                if (best < 0 || ms < best) best = ms
            }
        }
        return best
    }

    /**
     * Ступень скорости для сравнения точек в подборе: границы удваиваются (меньше 1 Мбит/с,
     * 1–2, 3–6, 7–14, 15–30…). Разница внутри одной ступени — шум одного замера, а не
     * преимущество точки; сравнивать по сырому числу значило бы выбирать случайно.
     */
    fun bucket(kbps: Int): Int {
        if (kbps <= 0) return 0
        val mbit = kbps / 1000 + 1
        return 32 - Integer.numberOfLeadingZeros(mbit)
    }

    /** «24,5 Мбит/с», «850 Кбит/с» — как пишут люди, с запятой. */
    fun human(kbps: Int): String = when {
        kbps < 0 -> "—"
        kbps < 1000 -> "$kbps Кбит/с"
        kbps < 100_000 -> {
            val tenths = (kbps + 50) / 100
            "${tenths / 10},${tenths % 10} Мбит/с"
        }
        else -> "${(kbps + 500) / 1000} Мбит/с"
    }
}
