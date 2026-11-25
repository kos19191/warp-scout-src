package dev.warpscout.app

import dev.warpscout.core.state.TunnelStatus
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Диагностика туннеля. Отдельный файл, потому что «туннель не поднимается» — это единственный
 * случай, когда без подробностей приложение бесполезно: у пользователя нет ни logcat под рукой,
 * ни возможности поставить отладчик.
 *
 * Пишется из flavor'а `tunnel` (main-исходники видит любой flavor, наоборот — нет), читается UI
 * через [TunnelController.debugDump]. Кольцевой буфер + сальное время, чтобы было видно не только
 * «упало», но и «сколько висело на каждом шаге».
 *
 * Почему строки журнала остаются в коде, а не в `strings.xml`: журнал пишут три стороны — ядро
 * (`:core`, там нет Android-ресурсов), сервис и интерфейс, — и он же попадает в issue и в чат при
 * разборе. Тексты этапов — это фактически протокол обмена, а не подписи на экране. Чтобы перевести
 * журнал, нужно сначала заменить тексты кодами событий (как это уже сделано для подъёма туннеля:
 * `DataPlane.onTunnelUp`), и только потом переводить. Подписи интерфейса, уведомления, советы и
 * баннеры — уже в ресурсах (см. `strings.xml`).
 */
object TunnelDebug {

    private const val MAX_LINES = 220

    /**
     * Журнал ещё и в файле. Причина простая: туннель живёт в отдельном процессе, и кольцевой
     * буфер в памяти интерфейса о нём ничего не знает. Файл — единственное место, где сходятся
     * строки обоих процессов: сервис пишет этапы подъёма и rekey, интерфейс — подбор и ошибки.
     * Дописывание строки — одна запись в конец (O_APPEND), поэтому два процесса не перемешивают
     * половины строк; размер ограничен, старое вытесняется.
     *
     * С 1.10.42 — до мегабайта, а при переполнении остаются последние ~640 КБ (около суток). Было
     * 256 КБ и 120 строк после ротации: журнал 24.11 начинался с 09:40 — ночь на Wi-Fi и поездка
     * по LTE ушли целиком, хотя разобрать хотели именно их.
     */
    private const val JOURNAL = "tunnel-journal.log"
    private const val JOURNAL_MAX_BYTES = 1024 * 1024
    private const val JOURNAL_KEEP_BYTES = 640 * 1024
    private const val DUMP_LIMIT_BYTES = 24 * 1024

    @Volatile
    private var journal: File? = null

    /** Подключить журнал к файлу в `filesDir` (зовётся из обоих процессов при старте). */
    fun attach(context: android.content.Context) {
        val file = File(context.applicationContext.filesDir, JOURNAL)
        if (journal?.absolutePath == file.absolutePath) return
        journal = file
    }

    private val lock = Any()
    private val lines = ArrayDeque<String>()
    private var lastStageAt = 0L
    /**
     * SimpleDateFormat не потокобезопасен, а журнал пишут минимум четыре потока (boot сервиса,
     * диспетчер пакетов, проба региона, главный поток UI). Общий экземпляр на этом месте падал
     * с ArrayIndexOutOfBoundsException — то есть «приложение вылетает, журнал ничего не пишет».
     * Свой экземпляр на поток дешевле, чем блокировка вокруг форматирования.
     */
    private val stamp = object : ThreadLocal<SimpleDateFormat>() {
        override fun initialValue() = SimpleDateFormat("HH:mm:ss.SSS", Locale.US)
    }

    /** Признак того, что вообще была попытка поднять туннель (в `scout`-сборке — никогда). */
    @Volatile
    var touched: Boolean = false
        private set

    @Volatile
    var lastError: String? = null
        private set

    /** Байты, прошедшие через туннель: «поднят, но нулевой трафик» — отдельный диагноз. */
    @Volatile
    var bytesUp: Long = 0L

    @Volatile
    var bytesDown: Long = 0L

    @Volatile
    var handshakeAttempts: Int = 0

    /** Сервер, на который сейчас пробуем подняться — чтобы UI не лез во flavor-специфичный TunnelState. */
    @Volatile
    var endpoint: String = ""

    /** Когда был последний этап: по нему UI решает, «поднимается» или «зависло». */
    @Volatile
    var lastStageMs: Long = 0L
        private set

    fun reset() = synchronized(lock) {
        lines.clear()
        appendToJournal("──── новая попытка ────")
        lastStageAt = System.currentTimeMillis()
        lastError = null
        bytesUp = 0L
        bytesDown = 0L
        handshakeAttempts = 0
        lastStageMs = System.currentTimeMillis()
        touched = true
    }

    /**
     * Стереть журнал целиком: кольцевой буфер, общий файл и счётчики этой сессии.
     *
     * Зачем кнопка: после обновления нужен чистый журнал за новый период, а не хвост прошлой
     * ночи — иначе в разборе смешиваются два разных поведения. Файл удаляем (а не обнуляем
     * содержимое): его заново создаст первая же запись, и в нём не останется пустых строк,
     * из-за которых «журнал пуст» выглядел бы как «строки потерялись».
     */
    fun clear() = synchronized(lock) {
        lines.clear()
        lastError = null
        bytesUp = 0L
        bytesDown = 0L
        handshakeAttempts = 0
        lastStageAt = 0L
        lastStageMs = 0L
        runCatching { journal?.delete() }
    }

    fun stage(message: String) {
        touched = true
        val took = synchronized(lock) {
            val now = System.currentTimeMillis()
            val diff = if (lastStageAt == 0L) "" else " (+${now - lastStageAt} мс)"
            lastStageAt = now
            diff
        }
        add("→ $message$took")
    }

    /** Строка этапа handshake из ядра: нумеруем сами, чтобы не зависеть от формата лога. */
    fun noteAttempt(detail: String) {
        touched = true
        handshakeAttempts += 1
        add("  $detail")
    }

    fun error(message: String, hint: String? = null) {
        touched = true
        lastError = message
        add("✗ $message" + (hint?.let { " · подсказка: $it" }.orEmpty()))
    }

    /**
     * ✗ в журнал, но не «последняя ошибка туннеля» (с 1.10.45). [error] встаёт в строку состояния как
     * «Не удалось подключиться: …», а сбой, скажем, получения ключа Proton — не сбой подключения: на
     * скриншоте 25.11 туннель был просто выключен, а строка винила его в ошибке Proton.
     */
    fun problem(message: String, hint: String? = null) {
        add("✗ $message" + (hint?.let { " · подсказка: $it" }.orEmpty()))
    }

    fun ok(message: String) {
        touched = true
        add("✓ $message")
    }

    private fun add(line: String) {
        lastStageMs = System.currentTimeMillis()
        val full = "${stamp.get()!!.format(Date())} $line"
        synchronized(lock) {
            lines.addLast(full)
            while (lines.size > MAX_LINES) lines.removeFirst()
        }
        appendToJournal(full)
        runCatching { android.util.Log.i(TAG, line) }
    }

    /** Дописать строку в общий журнал. Ошибки записи не должны влиять на туннель. */
    private fun appendToJournal(full: String) {
        val file = journal ?: return
        runCatching {
            if (file.length() > JOURNAL_MAX_BYTES) rotate(file)
            java.io.FileOutputStream(file, true).use { out ->
                out.write((full + "\n").toByteArray(Charsets.UTF_8))
            }
        }
    }

    /**
     * Журнал вырос: оставляем хвост — последние [JOURNAL_KEEP_BYTES], с первой целой строки (без
     * половины строки и половины буквы в начале), чтобы файл не рос бесконечно.
     */
    private fun rotate(file: File) {
        val tail = runCatching {
            val length = file.length()
            val from = (length - JOURNAL_KEEP_BYTES).coerceAtLeast(0L)
            java.io.RandomAccessFile(file, "r").use { raf ->
                raf.seek(from)
                val buffer = ByteArray((length - from).toInt())
                raf.readFully(buffer)
                val start = if (from == 0L) 0 else buffer.indexOf('\n'.code.toByte()) + 1
                buffer.copyOfRange(start.coerceIn(0, buffer.size), buffer.size)
            }
        }.getOrDefault(ByteArray(0))
        val tmp = File(file.parentFile, file.name + ".tmp")
        runCatching {
            tmp.writeBytes(tail)
            if (!tmp.renameTo(file)) {
                file.delete()
                tmp.renameTo(file)
            }
        }
    }

    /** Содержимое общего журнала (хвост ограниченной длины), без обращения к памяти процесса. */
    /**
     * Последняя непустая строка журнала. Нужна, когда надо объяснить отказ, а своего текста у
     * вызывающего нет: пустое «(этап: )» в сообщении — это отсутствие объяснения, а не объяснение.
     */
    fun lastLine(): String =
        readJournal().lineSequence().map { it.trim() }.lastOrNull { it.isNotEmpty() }.orEmpty()

    private fun readJournal(): String {
        val file = journal ?: return ""
        // Читаем только хвост файла: журнал открыт на экране и перечитывается часто, а целиком
        // он может занимать мегабайт — это лишние чтения с флеша на ровном месте.
        val text = runCatching {
            if (!file.exists()) return ""
            val length = file.length()
            if (length <= 0L) return ""
            val from = (length - DUMP_LIMIT_BYTES).coerceAtLeast(0L)
            java.io.RandomAccessFile(file, "r").use { raf ->
                raf.seek(from)
                val buffer = ByteArray((length - from).toInt())
                raf.readFully(buffer)
                String(buffer, Charsets.UTF_8)
            }
        }.getOrNull().orEmpty()
        if (text.isBlank()) return ""
        val tail = if (text.length > DUMP_LIMIT_BYTES) {
            val cut = text.substring(text.length - DUMP_LIMIT_BYTES)
            cut.substringAfter('\n', cut)   // не показываем половину первой строки
        } else text
        // Нули в журнале — след совпавшей ротации из двух процессов; показывать их незачем.
        return tail.replace("\u0000", "").trimEnd()
    }

    /**
     * Отразить состояние, пришедшее из процесса сервиса: счётчики, последняя ошибка и время
     * последнего этапа живут в журнале сервиса, а интерфейсу они нужны для карточки.
     */
    fun mirror(status: TunnelStatus) {
        bytesUp = status.bytesUp
        bytesDown = status.bytesDown
        handshakeAttempts = status.handshakeAttempts
        lastError = status.lastError
        if (status.lastStageMs > lastStageMs) lastStageMs = status.lastStageMs
        if (status.touched) touched = true
        if (status.endpoint.isNotBlank()) endpoint = status.endpoint
    }

    fun dump(): String {
        val fromFile = readJournal()
        if (fromFile.isNotEmpty()) return fromFile
        return synchronized(lock) {
            if (lines.isEmpty()) {
                if (touched) "журнал пуст" else "туннель ещё не запускался"
            } else {
                lines.joinToString("\n")
            }
        }
    }

    /**
     * Журнал целиком — для выгрузки в файл. В буфер обмена идёт только хвост ([dump], 24 КБ):
     * длинный текст режут и буфер, и мессенджеры, поэтому присланные журналы начинались с
     * середины строки и без начала аварии. Файлу этот предел не нужен: весь журнал — до
     * мегабайта (с 1.10.42; раньше — четверть).
     */
    fun fullDump(): String {
        val file = journal
        val text = runCatching {
            if (file != null && file.exists()) file.readText(Charsets.UTF_8) else ""
        }.getOrDefault("")
        // Нули в журнале — след совпавшей ротации из двух процессов; показывать их незачем.
        val clean = text.replace("\u0000", "").trimEnd()
        return clean.ifEmpty { dump() }
    }

    /** Короткая «что не так»-строка для Toast/плашки: последняя ошибка или последний этап. */
    fun brief(): String {
        lastError?.let { return it }
        val fromFile = readJournal()
        if (fromFile.isNotEmpty()) {
            return fromFile.substringAfterLast('\n').substringAfter(' ').ifBlank { "нет журнала" }
        }
        return synchronized(lock) { lines.lastOrNull()?.substringAfter(' ') ?: "нет журнала" }
    }

    fun writeToFile(file: java.io.File): String? = runCatching {
        file.parentFile?.mkdirs()
        file.writeText(
            buildString {
                appendLine("WarpScout: журнал туннеля")
                appendLine("время: ${SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault()).format(Date())}")
                appendLine("байт вверх/вниз: $bytesUp / $bytesDown, попыток handshake: $handshakeAttempts")
                appendLine()
                appendLine(dump())
            }
        )
        file.absolutePath
    }.getOrNull()

    private const val TAG = "WarpScout/tunnel"
}

/**
 * Как объяснить пользователю, почему туннель не поднялся. Соответствия подбираются по тексту
 * этапа — ядро и VpnService говорят человеческими терминами, и это дешевле, чем городить коды
 * ошибок, которые всё равно никто не запоминает.
 */
object TunnelTrouble {

    /**
     * Совет по журналу. Тексты — в ресурсах: это то, что человек читает на экране, и оно должно
     * переводиться. Сопоставление (`matches`) остаётся по тексту журнала, потому что журнал
     * пишут и ядро, и сервис, и он же попадает в issue.
     */
    data class Advice(
        val matches: List<String>,
        @androidx.annotation.StringRes val titleRes: Int,
        @androidx.annotation.StringRes val whatToDoRes: Int
    )

    private val TABLE = listOf(
        Advice(
            listOf("ноль пакетов за", "туннель есть, интернета нет"),
            R.string.advice_1_title,
            R.string.advice_1_what
        ),
        Advice(
            listOf("handshake не прошёл", "endpoint молчит", "ответа нет"),
            R.string.advice_2_title,
            R.string.advice_2_what
        ),
        Advice(
            listOf("VpnService не выдал tun", "tun:"),
            R.string.advice_3_title,
            R.string.advice_3_what
        ),
        Advice(
            listOf("protect()"),
            R.string.advice_4_title,
            R.string.advice_4_what
        ),
        Advice(
            listOf("конфиг не разбирается", "нет конфигурации"),
            R.string.advice_5_title,
            R.string.advice_5_what
        ),
        Advice(
            listOf("сокет"),
            R.string.advice_6_title,
            R.string.advice_6_what
        ),
        Advice(
            listOf("startForeground отказал"),
            R.string.advice_7_title,
            R.string.advice_7_what
        ),
        Advice(
            listOf("нулевой трафик", "ноль пакетов"),
            R.string.advice_8_title,
            R.string.advice_8_what
        ),
    )

    /** Подбирает объяснение по журналу. Пустой список — если ничего из известного не узнали. */
    fun advise(dump: String): List<Advice> {
        val low = dump.lowercase(Locale.ROOT)
        return TABLE.filter { a -> a.matches.any { low.contains(it.lowercase(Locale.ROOT)) } }
    }
}
