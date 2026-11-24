package dev.warpscout.core.backup

/**
 * Формат резервной копии WarpScout — без Android, чтобы его можно было проверить самопроверкой.
 *
 * До 1.10.43.1 (и 1.10.44-beta2) в копию попадали только основные настройки (SharedPreferences
 * «warpscout»). Человек восстановил копию в бете (24.11) — «а там половины данных нет»: тройки точек
 * для Wi-Fi и мобильной сети, из которых берётся резервная точка, память точек и площадок выхода,
 * ответы про Telegram, кеш подбора, конфиг для автоподъёма, скачанные списки, адреса DNS и ключ
 * аккаунта лежат не в основных настройках, и в копию они не попадали. Теперь копия — всё это.
 *
 * Формат построчный, как и был: `тип:ключ=значение`. Заголовок прежний («v1»): старые версии читают
 * из новой копии основные настройки и пропускают строки, которых не знают. Новые строки:
 *  • `p:<файл настроек>|<тип>:<ключ>=<значение>` — другие файлы SharedPreferences;
 *  • `vault:<имя>=<base64>` — секреты из хранилища ключей (в копии — открытым текстом: копия и так
 *    содержит рабочий конфиг с ключом, а зашифрованное ключом этого телефона на другом не прочесть);
 *  • `file:<путь в files/>=<base64>` — файлы приложения.
 * Служебные строки `# имя: значение` — когда, почему и каким приложением записана копия.
 */
object BackupFormat {

    /** Прежний заголовок: по нему копию узнают и старые версии (они восстановят основные настройки). */
    const val HEADER = "# WarpScout backup v1"

    /** Полная копия (с 1.10.43.1): файлы, другие настройки, секреты. 1 — только основные настройки. */
    const val FORMAT = 2

    data class Data(
        /** Основные настройки (SharedPreferences «warpscout»): ключ → String/Int/Long/Boolean/Float/Set. */
        val main: Map<String, Any?>,
        /** Другие файлы настроек: имя файла → ключи. */
        val prefs: Map<String, Map<String, Any?>> = emptyMap(),
        /** Файлы приложения: путь внутри files/ («shortlist.txt», «allowlists/tiktok.lst») → содержимое. */
        val files: Map<String, ByteArray> = emptyMap(),
        /** Секреты хранилища ключей: имя → значение. */
        val vault: Map<String, String> = emptyMap(),
        /** Служебные строки: reason, at, app, format, skipped. */
        val notes: Map<String, String> = emptyMap(),
    ) {
        /** Формат копии: 2 — полная, 1 — старая (только основные настройки). */
        val format: Int get() = notes["format"]?.trim()?.toIntOrNull() ?: 1
    }

    fun isBackup(text: String): Boolean = lines(text).firstOrNull()?.trim() == HEADER

    /** Текст копии. Порядок: заголовок, служебные строки, основные настройки, остальное. */
    fun render(data: Data): String {
        val out = StringBuilder(HEADER).append('\n')
        val notes = LinkedHashMap(data.notes)
        notes["format"] = FORMAT.toString()
        notes.forEach { (key, value) ->
            val k = key.filter { it.isLetterOrDigit() || it == '_' || it == '-' }
            if (k.isNotEmpty()) out.append("# ").append(k).append(": ").append(value.replace('\n', ' ').replace('\r', ' ')).append('\n')
        }
        data.main.forEach { (key, value) -> entry(key, value)?.let { out.append(it).append('\n') } }
        data.prefs.toSortedMap().forEach { (name, values) ->
            if (!safeName(name)) return@forEach
            values.forEach { (key, value) -> entry(key, value)?.let { out.append("p:").append(name).append('|').append(it).append('\n') } }
        }
        data.vault.toSortedMap().forEach { (alias, value) ->
            if (!safeName(alias)) return@forEach
            out.append("vault:").append(alias).append('=').append(b64(value.toByteArray(Charsets.UTF_8))).append('\n')
        }
        data.files.toSortedMap().forEach { (path, bytes) ->
            if (!safePath(path)) return@forEach
            out.append("file:").append(path).append('=').append(b64(bytes)).append('\n')
        }
        return out.toString()
    }

    /** Разбор; null — первая строка не наша (это не копия WarpScout). Битые строки пропускаются. */
    fun parse(text: String): Data? {
        val lines = lines(text)
        if (lines.firstOrNull()?.trim() != HEADER) return null
        // Сначала служебные строки: от формата зависит разбор наборов (до формата 2 их элементы
        // писались как есть, без экранирования).
        val notes = LinkedHashMap<String, String>()
        lines.drop(1).forEach { line ->
            if (!line.startsWith("#")) return@forEach
            val body = line.removePrefix("#").trim()
            val key = body.substringBefore(':', "").trim()
            if (key.isNotEmpty() && key.all { it.isLetterOrDigit() || it == '_' || it == '-' }) {
                notes[key] = body.substringAfter(':', "").trim()
            }
        }
        val escapedSets = (notes["format"]?.trim()?.toIntOrNull() ?: 1) >= 2
        val main = LinkedHashMap<String, Any?>()
        val prefs = LinkedHashMap<String, LinkedHashMap<String, Any?>>()
        val files = LinkedHashMap<String, ByteArray>()
        val vault = LinkedHashMap<String, String>()
        lines.drop(1).forEach { line ->
            if (line.isBlank() || line.startsWith("#")) return@forEach
            when {
                line.startsWith("p:") -> {
                    val body = line.removePrefix("p:")
                    val name = body.substringBefore('|', "")
                    if (!safeName(name)) return@forEach
                    val parsed = typed(body.substringAfter('|', ""), escapedSets) ?: return@forEach
                    prefs.getOrPut(name) { LinkedHashMap() }[parsed.first] = parsed.second
                }

                line.startsWith("vault:") -> {
                    val body = line.removePrefix("vault:")
                    val alias = body.substringBefore('=', "")
                    if (!safeName(alias)) return@forEach
                    unb64(body.substringAfter('=', ""))?.let { vault[alias] = String(it, Charsets.UTF_8) }
                }

                line.startsWith("file:") -> {
                    val body = line.removePrefix("file:")
                    val path = body.substringBefore('=', "")
                    if (!safePath(path)) return@forEach
                    unb64(body.substringAfter('=', ""))?.let { files[path] = it }
                }

                else -> typed(line, escapedSets)?.let { (key, value) -> main[key] = value }
            }
        }
        return Data(main, prefs, files, vault, notes)
    }

    /** Одна строка «тип:ключ=значение»; null — тип не поддерживается. */
    private fun entry(key: String, value: Any?): String? {
        if (key.isEmpty() || key.contains('=') || key.contains('\n') || key.contains('\r')) return null
        return when (value) {
            is String -> "s:$key=${escape(value)}"
            is Int -> "i:$key=$value"
            is Long -> "l:$key=$value"
            is Boolean -> "b:$key=$value"
            is Float -> "f:$key=$value"
            is Set<*> -> "set:$key=" + value.joinToString("\u0001") { escape(it.toString()) }
            else -> null
        }
    }

    private fun typed(line: String, escapedSets: Boolean): Pair<String, Any?>? {
        val type = line.substringBefore(':', "")
        val body = line.substringAfter(':', "")
        val key = body.substringBefore('=', "")
        val raw = body.substringAfter('=', "")
        if (key.isEmpty()) return null
        val value: Any? = when (type) {
            "s" -> unescape(raw)
            "i" -> raw.toIntOrNull() ?: return null
            "l" -> raw.toLongOrNull() ?: return null
            "b" -> raw.toBoolean()
            "f" -> raw.toFloatOrNull() ?: return null
            "set" -> raw.split('\u0001').filter { it.isNotEmpty() }.map { if (escapedSets) unescape(it) else it }.toSet()
            else -> return null
        }
        return key to value
    }

    /**
     * Строка в одну строку файла: «\» → «\\», перевод строки → «\n», возврат каретки выбрасывается —
     * как и раньше: копию нового формата должны правильно читать и прежние версии (их разбор не знает
     * «\r» и оставил бы его в тексте конфига двумя знаками). Обратный разбор до 1.10.43.1 путал «\»
     * перед «n» с переводом строки — теперь он посимвольный.
     */
    fun escape(text: String): String {
        val out = StringBuilder(text.length + 8)
        text.forEach { c ->
            when (c) {
                '\\' -> out.append("\\\\")
                '\n' -> out.append("\\n")
                '\r' -> Unit
                else -> out.append(c)
            }
        }
        return out.toString()
    }

    fun unescape(text: String): String {
        if (!text.contains('\\')) return text
        val out = StringBuilder(text.length)
        var i = 0
        while (i < text.length) {
            val c = text[i]
            if (c == '\\' && i + 1 < text.length) {
                when (text[i + 1]) {
                    'n' -> { out.append('\n'); i += 2; continue }
                    'r' -> { out.append('\r'); i += 2; continue }
                    '\\' -> { out.append('\\'); i += 2; continue }
                }
            }
            out.append(c)
            i++
        }
        return out.toString()
    }

    /** Имя файла настроек или секрета: буквы, цифры, «._-». */
    fun safeName(name: String): Boolean =
        name.isNotEmpty() && name.length <= 100 && name.all { it.isLetterOrDigit() || it == '.' || it == '_' || it == '-' } &&
            name != "." && name != ".."

    /** Путь внутри files/: без «..», без абсолютных путей, части — буквы, цифры, «._-». */
    fun safePath(path: String): Boolean {
        if (path.isEmpty() || path.length > 240 || path.startsWith("/") || path.contains('\\')) return false
        return path.split('/').all { safeName(it) }
    }

    private fun lines(text: String): List<String> = text.removePrefix("\uFEFF").lines().map { it.removeSuffix("\r") }

    private fun b64(bytes: ByteArray): String = java.util.Base64.getEncoder().encodeToString(bytes)

    private fun unb64(text: String): ByteArray? = runCatching { java.util.Base64.getDecoder().decode(text.trim()) }.getOrNull()
}
