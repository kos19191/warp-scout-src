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
 */
object TunnelDebug {

    private const val MAX_LINES = 220

    /**
     * Журнал ещё и в файле. Причина простая: туннель живёт в отдельном процессе, и кольцевой
     * буфер в памяти интерфейса о нём ничего не знает. Файл — единственное место, где сходятся
     * строки обоих процессов: сервис пишет этапы подъёма и rekey, интерфейс — подбор и ошибки.
     * Дописывание строки — одна запись в конец (O_APPEND), поэтому два процесса не перемешивают
     * половины строк; размер ограничен, старое вытесняется.
     */
    private const val JOURNAL = "tunnel-journal.log"
    private const val JOURNAL_MAX_BYTES = 256 * 1024
    private const val JOURNAL_KEEP_LINES = 120
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

    /** Журнал вырос: оставляем хвост, чтобы файл не рос бесконечно. */
    private fun rotate(file: File) {
        val tail = runCatching { file.readLines().takeLast(JOURNAL_KEEP_LINES) }.getOrDefault(emptyList())
        val tmp = File(file.parentFile, file.name + ".tmp")
        runCatching {
            tmp.writeText(tail.joinToString("\n", postfix = "\n"))
            if (!tmp.renameTo(file)) {
                file.delete()
                tmp.renameTo(file)
            }
        }
    }

    /** Содержимое общего журнала (хвост ограниченной длины), без обращения к памяти процесса. */
    private fun readJournal(): String {
        val file = journal ?: return ""
        // Читаем только хвост файла: журнал открыт на экране и перечитывается часто, а целиком
        // он может занимать четверть мегабайта — это лишние чтения с флеша на ровном месте.
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
        if (text.isBlank()) return "
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

    data class Advice(val matches: List<String>, val title: String, val whatToDo: String)

    private val TABLE = listOf(
        Advice(
            listOf("ноль пакетов за", "туннель есть, интернета нет"),
            "Туннель поднялся, но трафик не идёт",
            "Чаще всего это IPv6: приложение выбирает IPv6-адрес сайта, а туннель его не уносит. " +
                "Отключи переключатель IPv6 во вкладке «Туннель», переподключись и проверь снова. " +
                "Второй подозреваемый — MTU: поставь 1280 и сравни."
        ),
        Advice(
            listOf("handshake не прошёл", "endpoint молчит", "ответа нет"),
            "Сервер не ответил на инициацию",
            "Это не «нет интернета», а «нет ответа от WARP-эндпоинта». Попробуй другой профиль шума " +
                "(AWG без мусора часто режется) или другой порт; затем «Подобрать конфигурацию» заново — " +
                "возможно, выбранный endpoint уже умер."
        ),
        Advice(
            listOf("VpnService не выдал tun", "tun:"),
            "Система не дала tun-интерфейс",
            "Обычно это значит, что уже работает другой VPN (Amnezia, Orbot, ByeDPI в режиме VPN). " +
                "Android поднимает только один туннель: выключи его и повтори."
        ),
        Advice(
            listOf("protect()"),
            "Не удалось вывести сокет из-под туннеля",
            "Без protect() пакеты туннеля попали бы внутрь туннеля (петля). Такое бывает при включённом " +
                "Always-on VPN у другого приложения или при ограничителе фоновой работы для WarpScout."
        ),
        Advice(
            listOf("конфиг не разбирается", "нет конфигурации"),
            "Конфиг не дошёл до сервиса",
            "Нужен подобранный или импортированный конфиг: нажми «Подобрать конфигурацию» либо " +
                "«Импортировать .conf» и повтори запуск туннеля."
        ),
        Advice(
            listOf("сокет"),
            "Не удалось создать UDP-сокет",
            "Проверь, что у приложения есть сеть (Wi-Fi/данные) и что не включён режим «только белый список " +
                "приложений» в настройках VPN провайдера."
        ),
        Advice(
            listOf("startForeground отказал"),
            "Сервис не смог остаться живым",
            "На Android 14+ нужно разрешение на уведомления и нормальный режим батареи для WarpScout: " +
                "выключи агрессивную оптимизацию battery saver для приложения."
        ),
        Advice(
            listOf("нулевой трафик", "ноль пакетов"),
            "Туннель поднят, но трафик через него не идёт",
            "Смотри AllowedIPs: при split-tunnel в туннель попадают только перечисленные сети. Если ты " +
                "проверял сайт, которого в списке нет, — он и не должен идти через WARP. Для «всё через " +
                "туннель» выбери режим «весь трафик»."
        )
    )

    /** Подбирает объяснение по журналу. Пустой список — если ничего из известного не узнали. */
    fun advise(dump: String): List<Advice> {
        val low = dump.lowercase(Locale.ROOT)
        return TABLE.filter { a -> a.matches.any { low.contains(it.lowercase(Locale.ROOT)) } }
    }
}
