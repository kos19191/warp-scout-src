package dev.warpscout.app

import android.content.Context
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Бекап настроек и рабочего конфига.
 *
 * Зачем: всё, что пользователь настроил (маршруты, приложения в туннеле, профили шума, списки,
 * последний рабочий конфиг с ключом), живёт в одном месте — в SharedPreferences приложения. Чистка
 * данных, переустановка или новый телефон — и настройки приходится собирать заново. Поэтому:
 *  • бекап пишется автоматически после каждого успешного подключения и после каждого подбора;
 *  • хранится последние [KEEP] штук в приватном каталоге приложения (files/backups);
 *  • файл можно отдать наружу кнопкой «Сохранить бекап» (шторка «Поделиться»);
 *  • восстановить можно и из файла снаружи (с 1.10.40, см. [restoreText]): при удалении приложения
 *    Android стирает files/backups, и после переустановки других копий, кроме сохранённой наружу, нет.
 *
 * Формат — построчный, без JSON-экранирования: `тип:ключ=значение`, где тип — s/i/l/b/f/set.
 * Этого достаточно, чтобы восстановить всё точно и не зависеть от парсера.
 */
object Backup {

    private const val HEADER = "# WarpScout backup v1"
    private const val KEEP = 10
    private val stamp = SimpleDateFormat("yyyyMMdd-HHmmss", Locale.US)

    fun dir(context: Context): File = File(context.filesDir, "backups").apply { mkdirs() }

    /** Сохранить текущее состояние. Возвращает файл или null, если не получилось. */
    fun save(context: Context, reason: String): File? = runCatching {
        val prefs = Prefs(context)
        val body = StringBuilder(HEADER).append('\n')
        body.append("# reason: ").append(reason.replace('\n', ' ')).append('\n')
        body.append("# at: ").append(System.currentTimeMillis()).append('\n')
        prefs.snapshot().forEach { (key, value) ->
            when (value) {
                is String -> body.append("s:").append(key).append('=').append(escape(value)).append('\n')
                is Int -> body.append("i:").append(key).append('=').append(value).append('\n')
                is Long -> body.append("l:").append(key).append('=').append(value).append('\n')
                is Boolean -> body.append("b:").append(key).append('=').append(value).append('\n')
                is Float -> body.append("f:").append(key).append('=').append(value).append('\n')
                is Set<*> -> body.append("set:").append(key).append('=')
                    .append(value.joinToString("\u0001") { it.toString() }).append('\n')
            }
        }
        val file = File(dir(context), "warpscout-${stamp.format(Date())}.bak")
        file.writeText(body.toString())
        prune(context)
        file
    }?.getOrNull()

    fun list(context: Context): List<File> =
        (dir(context).listFiles() ?: emptyArray()).filter { it.name.endsWith(".bak") }
            .sortedByDescending { it.name }

    fun newest(context: Context): File? = list(context).firstOrNull()

    /** Восстановить файл. Возвращает число применённых ключей (0 — файл не наш или битый). */
    fun restore(context: Context, file: File): Int =
        runCatching { restoreText(context, file.readText()) }.getOrDefault(0)

    /**
     * Восстановить из текста бекапа — файла приложения или выбранного в системном окне (с 1.10.40).
     * Возвращает число применённых ключей (0 — текст не наш или битый).
     */
    fun restoreText(context: Context, text: String): Int = runCatching {
        val values = parse(text) ?: return 0
        if (values.isEmpty()) return 0
        Prefs(context).restoreAll(values)
        // Разовые переносы (Prefs.init) — заново, уже по восстановленным настройкам: копия из прошлой
        // версии получает то, что появилось после неё (например, шум «как Chrome» в наборе профилей).
        // syncFromPrefs создаёт Prefs (переносы) и пишет сервису снимок уже с ними.
        runCatching { dev.warpscout.app.status.ServiceSettingsStore.syncFromPrefs(context) }
        values.size
    }.getOrDefault(0)

    /** Это наш бекап? Первая строка — заголовок; BOM и \r, которые добавляют облака, не мешают. */
    fun isBackup(text: String): Boolean = lines(text).firstOrNull()?.trim() == HEADER

    /**
     * «23.11.2026 17:03 · подключение 8.35.211.1:4233» — когда и почему записана копия (служебные
     * строки в начале файла). null — их нет: в вопросе «Восстановить?» останется только имя файла.
     */
    fun describe(text: String): String? {
        var at: Long? = null
        var reason: String? = null
        for (line in lines(text).take(6)) {
            when {
                line.startsWith("# at: ") -> at = line.removePrefix("# at: ").trim().toLongOrNull()
                line.startsWith("# reason: ") -> reason = line.removePrefix("# reason: ").trim().ifEmpty { null }
            }
        }
        val date = at?.takeIf { it > 0L }?.let { SimpleDateFormat("dd.MM.yyyy HH:mm", Locale.getDefault()).format(Date(it)) }
        return listOfNotNull(date, reason).joinToString(" · ").ifEmpty { null }
    }

    private fun lines(text: String): List<String> = text.removePrefix("\uFEFF").lines().map { it.removeSuffix("\r") }

    /** Ключи и значения бекапа; null — первая строка не наша (это не бекап WarpScout). */
    internal fun parse(text: String): Map<String, Any?>? {
        val lines = lines(text)
        if (lines.firstOrNull()?.trim() != HEADER) return null
        val values = LinkedHashMap<String, Any?>()
        lines.drop(1).forEach { line ->
            if (line.isBlank() || line.startsWith("#")) return@forEach
            val type = line.substringBefore(':', "")
            val body = line.substringAfter(':', "")
            val key = body.substringBefore('=', "")
            val raw = body.substringAfter('=', "")
            if (key.isEmpty()) return@forEach
            when (type) {
                "s" -> values[key] = unescape(raw)
                "i" -> raw.toIntOrNull()?.let { values[key] = it }
                "l" -> raw.toLongOrNull()?.let { values[key] = it }
                "b" -> values[key] = raw.toBoolean()
                "f" -> raw.toFloatOrNull()?.let { values[key] = it }
                "set" -> values[key] = raw.split('\u0001').filter { it.isNotEmpty() }.toSet()
            }
        }
        return values
    }

    private fun escape(text: String): String =
        text.replace("\\", "\\\\").replace("\n", "\\n").replace("\r", "")

    private fun unescape(text: String): String =
        text.replace("\\n", "\n").replace("\\\\", "\\")

    /** Держим последние [KEEP] файлов: бекап не должен сам съесть память. */
    private fun prune(context: Context) {
        val files = list(context)
        if (files.size <= KEEP) return
        files.drop(KEEP).forEach { runCatching { it.delete() } }
    }
}
