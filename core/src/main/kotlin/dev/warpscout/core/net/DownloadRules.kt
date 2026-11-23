package dev.warpscout.core.net

/**
 * Встала ли загрузка (с 1.10.40). До 1.10.39 экран ждал системную загрузку Android до 20 минут, что
 * бы с ней ни было: ждёт сеть, повторяет попытку, стоит в очереди — а на каждое нажатие отвечал
 * «Обновление уже скачивается». Жалоба на 1.10.38: «пишет, что уже качается, но ничего не происходит».
 *
 * Правило: ни байта за [firstByteMs] с начала — встала; байты шли и [progressMs] нет прироста — тоже.
 * Через рабочую сеть 11 МБ обновления приходят за 10–30 с (журнал 23.11, 08:15–08:16: 30 с), первый
 * байт — за секунды; полминуты без него — это уже не «медленно», а «не идёт».
 *
 * Время — снаружи (elapsedRealtime на телефоне, числа в проверке), чтобы правило проверялось без часов.
 */
class StallWatch(
    startMs: Long,
    private val firstByteMs: Long = 30_000L,
    private val progressMs: Long = 45_000L,
) {
    private var bytes = 0L
    private var movedAt = startMs

    /** Сколько миллисекунд ещё ждать прироста при [done] байтах к моменту [nowMs]; ≤ 0 — встала. */
    fun left(done: Long, nowMs: Long): Long {
        if (done > bytes) {
            bytes = done
            movedAt = nowMs
        }
        val limit = if (bytes <= 0L) firstByteMs else progressMs
        return limit - (nowMs - movedAt)
    }

    fun stalled(done: Long, nowMs: Long): Boolean = left(done, nowMs) <= 0L
}

/**
 * Докачка с места обрыва (с 1.10.40): своя загрузка обновления просит у сервера продолжение
 * (`Range: bytes=N-`), а сервер может ответить и с начала. Здесь — что делать с ответом.
 */
object DownloadRules {

    /**
     * Сколько байт ответа пропустить, если уже записано [written]: 206 — продолжение с [rangeStart]
     * (пропускаем то, что уже есть, если сервер начал раньше), 200 — файл с начала (пропускаем всё
     * записанное). null — ответ не годится: ошибка HTTP или дыра (сервер начал дальше, чем записано).
     */
    fun skipFor(code: Int, written: Long, rangeStart: Long?): Long? = when {
        code == 206 -> {
            val start = rangeStart ?: if (written == 0L) 0L else -1L
            if (start in 0L..written) written - start else null
        }
        code in 200..299 -> written
        else -> null
    }

    /** Начало куска из `Content-Range: bytes 1000-1999/5000` (→ 1000); null — заголовка нет или он не такой. */
    fun rangeStart(contentRange: String?): Long? =
        contentRange?.trim()?.removePrefix("bytes")?.trim()?.substringBefore('-')?.trim()?.toLongOrNull()

    /** Полный размер из `Content-Range: bytes 1000-1999/5000` (→ 5000); null — неизвестен («*») или заголовка нет. */
    fun rangeTotal(contentRange: String?): Long? =
        contentRange?.substringAfterLast('/', "")?.trim()?.toLongOrNull()

    /**
     * Полный размер файла по ответу: для 206 — из `Content-Range`, иначе — длина тела. −1 — неизвестен.
     * [written] — сколько уже записано до этого ответа (для 206 без полного размера — начало + длина куска).
     */
    fun totalFrom(code: Int, contentLength: Long, contentRange: String?, written: Long): Long {
        if (code == 206) {
            rangeTotal(contentRange)?.let { return it }
            val start = rangeStart(contentRange) ?: written
            return if (contentLength > 0L) start + contentLength else -1L
        }
        return if (code in 200..299 && contentLength > 0L) contentLength else -1L
    }
}
