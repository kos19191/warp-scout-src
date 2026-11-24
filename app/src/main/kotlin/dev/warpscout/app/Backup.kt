package dev.warpscout.app

import android.content.ContentUris
import android.content.ContentValues
import android.content.Context
import android.content.SharedPreferences
import android.net.Uri
import android.os.Build
import android.os.Environment
import android.provider.MediaStore
import dev.warpscout.core.backup.BackupFormat
import dev.warpscout.core.lists.ProtonFree
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Резервная копия: всё, что приложение помнит, одним файлом.
 *
 * Зачем: настройки, точки, второй выход, приложения в туннеле, память точек — всё это теряется при
 * чистке данных или переустановке, а в бету (отдельное приложение) это надо перенести. Поэтому:
 *  • копия пишется сама после каждого удачного подключения и каждого подбора и хранится в приложении
 *    (последние [KEEP] штук, files/backups) — при удалении приложения Android их стирает;
 *  • кнопка «Сохранить резервную копию» (с 1.10.43.1) кладёт копию в «Загрузки/WarpScout» — оттуда её
 *    откроет «Восстановить из копии» → «Выбрать файл…» и после переустановки, и в бете (окно выбора
 *    сразу открывается в этой папке). Раньше кнопка только открывала «Поделиться», и файл оставался
 *    там, куда его отправили; отправить копию дальше (Диск, Telegram) можно и теперь;
 *  • восстановить можно из копии в приложении, из «Загрузок/WarpScout» или из любого файла.
 *
 * До 1.10.43.1 в копию попадали только основные настройки. Человек восстановил копию в бете (24.11) —
 * «а там половины данных нет»: тройки точек (из них же выбирается резервная точка), память точек и
 * площадок, ответы про Telegram, кеш подбора, конфиг для автоподъёма, скачанные списки и ключ аккаунта
 * лежат отдельно. Теперь в копии всё это; формат — [BackupFormat].
 */
object Backup {

    private const val KEEP = 10

    /** Папка копий в «Загрузках» (с 1.10.43.1). */
    const val FOLDER = "WarpScout"

    private const val VAULT_PREFS = "warpscout_vault"

    /** Другие файлы настроек в копии (основные — «warpscout» — отдельно). */
    private val EXTRA_PREFS = listOf(
        "dns-book", // адреса DNS, найденные по имени (DnsBook)
    )

    /**
     * Файлы состояния (пути внутри files/). Полная копия восстанавливает их точно: файла нет в копии —
     * его убирают и здесь (иначе к настройкам из копии примешались бы точки и память этого приложения).
     */
    private val STATE_FILES = listOf(
        "shortlist.txt", // тройки точек для Wi-Fi и мобильной сети — из них резервная точка и перебор
        "tuning-cache.txt", // кеш подбора: следующий подбор начинается с проверенных точек
        "endpoint-memory.txt", // какая точка работала на какой сети
        "site-memory.txt", // площадка выхода точек (Москва, Хельсинки)
        "noise-memory.txt", // какой шум замерзает на какой сети
        "tg-choice.txt", // ответы «Переключить / Оставить» про Telegram
        "tunnel-last.conf", // конфиг для автоподъёма туннеля после перезагрузки
    )

    /**
     * Общие данные: список бесплатных серверов Proton и скачанные списки сайтов. Заменяются, только если
     * есть в копии: их можно скачать заново, и убирать их, когда в копии их нет, незачем.
     */
    private val SHARED_FILES = listOf("proton_free.txt")
    private val SHARED_DIRS = listOf("allowlists")

    /** Пределы: копия должна открываться окном выбора (MainActivity.BACKUP_FILE_LIMIT — 8 МБ). */
    private const val FILE_MAX = 1L * 1024 * 1024
    private const val TOTAL_MAX = 4L * 1024 * 1024

    fun dir(context: Context): File = File(context.filesDir, "backups").apply { mkdirs() }

    /** Всё, что войдёт в копию. */
    fun collect(context: Context, reason: String): BackupFormat.Data {
        val main = Prefs(context).snapshot().toMap()
        val extra = EXTRA_PREFS.associateWith { name ->
            runCatching { context.getSharedPreferences(name, Context.MODE_PRIVATE).all.toMap() }.getOrDefault(emptyMap())
        }.filterValues { it.isNotEmpty() }
        val skipped = ArrayList<String>()
        val files = collectFiles(context, skipped)
        val notes = linkedMapOf(
            "reason" to reason,
            "at" to System.currentTimeMillis().toString(),
            "app" to "${context.packageName} ${BuildConfig.VERSION_NAME}",
        )
        if (skipped.isNotEmpty()) notes["skipped"] = skipped.joinToString(", ")
        return BackupFormat.Data(main, extra, files, vaultSecrets(context), notes)
    }

    private fun collectFiles(context: Context, skipped: MutableList<String>): Map<String, ByteArray> {
        val base = context.filesDir
        val out = LinkedHashMap<String, ByteArray>()
        var total = 0L
        fun add(rel: String, f: File) {
            if (!f.isFile || !BackupFormat.safePath(rel)) return
            val size = f.length()
            if (size > FILE_MAX || total + size > TOTAL_MAX) {
                skipped += "$rel (${size / 1024} КБ)"
                return
            }
            val bytes = runCatching { f.readBytes() }.getOrNull() ?: return
            out[rel] = bytes
            total += bytes.size
        }
        (STATE_FILES + SHARED_FILES).forEach { name -> add(name, File(base, name)) }
        SHARED_DIRS.forEach { d ->
            val dir = File(base, d)
            if (!dir.isDirectory) return@forEach
            dir.walkTopDown().filter { it.isFile && !it.name.endsWith(".tmp") }.sortedBy { it.path }
                .forEach { f -> add(f.relativeTo(base).invariantSeparatorsPath, f) }
        }
        return out
    }

    /**
     * Секреты хранилища ключей — открытым текстом: там они зашифрованы ключом этого телефона
     * (AndroidKeyStore), и в другом приложении (бете) или на другом телефоне их не расшифровать. Копия
     * и раньше содержала рабочий конфиг с ключом — её надо хранить как пароль.
     */
    private fun vaultSecrets(context: Context): Map<String, String> {
        val raw = runCatching { context.getSharedPreferences(VAULT_PREFS, Context.MODE_PRIVATE).all }.getOrNull()
        if (raw.isNullOrEmpty()) return emptyMap()
        val vault = KeyVault(context)
        val out = LinkedHashMap<String, String>()
        raw.keys.sorted().forEach { alias ->
            val plainCopy = alias == KeyVault.ALIAS_ACCOUNT_PLAIN
            val value = if (plainCopy) raw[alias] as? String else runCatching { vault.get(alias) }.getOrNull()
            val name = if (plainCopy) KeyVault.ALIAS_ACCOUNT else alias
            if (!value.isNullOrEmpty() && name !in out) out[name] = value
        }
        return out
    }

    private val lock = Any()

    private val worker = java.util.concurrent.Executors.newSingleThreadExecutor { r ->
        Thread(r, "warpscout-backup").apply { isDaemon = true }
    }

    /** Сохранить копию в приложении. Возвращает файл или null, если не получилось. */
    fun save(context: Context, reason: String): File? = synchronized(lock) {
        runCatching {
            val text = BackupFormat.render(collect(context, reason))
            val name = "warpscout-${SimpleDateFormat("yyyyMMdd-HHmmss", Locale.US).format(Date())}.bak"
            val file = File(dir(context), name)
            val tmp = File(file.parentFile, file.name + ".tmp")
            tmp.writeText(text)
            if (!tmp.renameTo(file)) {
                tmp.copyTo(file, overwrite = true)
                tmp.delete()
            }
            prune(context)
            file
        }.getOrNull()
    }

    /**
     * Копия «на всякий случай» (после подключения и подбора) — в своём потоке: с 1.10.43.1 в неё входят
     * файлы точек, списки и ключ из хранилища, и делать это в потоке экрана незачем.
     */
    fun saveAsync(context: Context, reason: String) {
        val app = context.applicationContext
        runCatching { worker.execute { save(app, reason) } }
    }

    /**
     * Копию — в «Загрузки/WarpScout» (Android 10+, без разрешений). Возвращает, где она теперь лежит
     * («Загрузки/WarpScout/warpscout-….bak»), или null: не вышло или Android 8–9 (туда без разрешения
     * на память не записать — тогда копию сохраняют через системное окно «Сохранить как»).
     */
    fun saveToDownloads(context: Context, file: File): String? {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) return null
        return runCatching {
            val resolver = context.contentResolver
            val values = ContentValues().apply {
                put(MediaStore.MediaColumns.DISPLAY_NAME, file.name)
                // Не text/plain: иначе система допишет к имени «.txt», и «.bak» потеряется.
                put(MediaStore.MediaColumns.MIME_TYPE, MIME)
                put(MediaStore.MediaColumns.RELATIVE_PATH, Environment.DIRECTORY_DOWNLOADS + "/" + FOLDER)
                put(MediaStore.MediaColumns.IS_PENDING, 1)
            }
            val uri = resolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, values) ?: return@runCatching null
            val written = runCatching {
                resolver.openOutputStream(uri)?.use { out -> file.inputStream().use { it.copyTo(out) }; true } ?: false
            }.getOrDefault(false)
            if (!written) {
                runCatching { resolver.delete(uri, null, null) }
                return@runCatching null
            }
            values.clear()
            values.put(MediaStore.MediaColumns.IS_PENDING, 0)
            runCatching { resolver.update(uri, values, null, null) }
            val shown = runCatching {
                resolver.query(uri, arrayOf(MediaStore.MediaColumns.DISPLAY_NAME), null, null, null)?.use { c ->
                    if (c.moveToFirst()) c.getString(0) else null
                }
            }.getOrNull() ?: file.name
            "Загрузки/$FOLDER/$shown"
        }.getOrNull()
    }

    /** Тип файла копии для «Загрузок» и окна «Сохранить как». */
    const val MIME = "application/octet-stream"

    /** Копия в «Загрузках/WarpScout». */
    data class Item(val uri: Uri, val name: String, val modifiedMs: Long, val size: Long)

    /**
     * Копии в «Загрузках/WarpScout», записанные этим приложением (новые — первыми). Записанные другим
     * (обычным приложением для беты и наоборот) Android без разрешений не показывает — их открывает
     * окно выбора файла, оно открывается сразу в этой папке.
     */
    fun downloads(context: Context): List<Item> {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) return emptyList()
        return runCatching {
            val projection = arrayOf(
                android.provider.BaseColumns._ID,
                MediaStore.MediaColumns.DISPLAY_NAME,
                MediaStore.MediaColumns.DATE_MODIFIED,
                MediaStore.MediaColumns.SIZE,
            )
            val selection = "${MediaStore.MediaColumns.RELATIVE_PATH} LIKE ? AND ${MediaStore.MediaColumns.DISPLAY_NAME} LIKE ?"
            val args = arrayOf("${Environment.DIRECTORY_DOWNLOADS}/$FOLDER%", "%.bak")
            val out = ArrayList<Item>()
            context.contentResolver.query(
                MediaStore.Downloads.EXTERNAL_CONTENT_URI, projection, selection, args,
                "${MediaStore.MediaColumns.DATE_MODIFIED} DESC"
            )?.use { c ->
                while (c.moveToNext()) {
                    out += Item(
                        ContentUris.withAppendedId(MediaStore.Downloads.EXTERNAL_CONTENT_URI, c.getLong(0)),
                        c.getString(1).orEmpty(),
                        c.getLong(2) * 1000L,
                        c.getLong(3),
                    )
                }
            }
            out
        }.getOrDefault(emptyList())
    }

    /** Папка «Загрузки/WarpScout» уже есть — окно выбора файла открываем сразу в ней. */
    fun downloadsFolderExists(): Boolean = runCatching {
        @Suppress("DEPRECATION")
        File(Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS), FOLDER).isDirectory
    }.getOrDefault(false)

    fun list(context: Context): List<File> =
        (dir(context).listFiles() ?: emptyArray()).filter { it.name.endsWith(".bak") }
            .sortedByDescending { it.name }

    fun newest(context: Context): File? = list(context).firstOrNull()

    /** Восстановить файл. Возвращает итог (null — файл не наш или битый). */
    fun restore(context: Context, file: File): Result? =
        runCatching { restoreText(context, file.readText()) }.getOrNull()

    /** Итог восстановления — для строки журнала и сообщения на экране. */
    data class Result(
        val format: Int,
        val settings: Int,
        val files: Int,
        val other: Int,
        val secrets: Int,
    ) {
        /** «настроек 212, файлов 9, прочего 4, ключей 1». */
        fun text(): String = buildList {
            add("настроек $settings")
            if (format >= 2) {
                add("файлов $files")
                if (other > 0) add("прочего $other")
                add("ключей $secrets")
            }
        }.joinToString(", ")
    }

    /**
     * Восстановить из текста копии. Полная копия (формат 2) заменяет всё, что в неё входит; старая —
     * только основные настройки (остального в ней нет, и его не трогаем). null — текст не наш или битый.
     */
    fun restoreText(context: Context, text: String): Result? = runCatching {
        val data = BackupFormat.parse(text) ?: return null
        if (data.main.isEmpty()) return null
        val full = data.format >= 2
        val files = if (full) restoreFiles(context, data) else 0
        val other = if (full) restorePrefs(context, data) else 0
        val secrets = if (full) restoreVault(context, data) else 0
        // Основные настройки — последними: restoreAll сразу пишет сервису снимок настроек, а сервис
        // берёт резервную точку из тройки, которая к этому времени уже восстановлена.
        Prefs(context).restoreAll(data.main)
        // Разовые переносы (Prefs.init) — заново, уже по восстановленным настройкам: копия из прошлой
        // версии получает то, что появилось после неё (например, шум «как Chrome» в наборе профилей).
        // syncFromPrefs создаёт Prefs (переносы) и пишет сервису снимок уже с ними.
        runCatching { dev.warpscout.app.status.ServiceSettingsStore.syncFromPrefs(context) }
        Result(data.format, data.main.size, files, other, secrets)
    }.getOrNull()

    private fun allowedPath(rel: String): Boolean = BackupFormat.safePath(rel) && (
        rel in STATE_FILES || rel in SHARED_FILES || SHARED_DIRS.any { rel.startsWith("$it/") }
        )

    private fun restoreFiles(context: Context, data: BackupFormat.Data): Int {
        val base = context.filesDir
        STATE_FILES.filter { it !in data.files }.forEach { runCatching { File(base, it).delete() } }
        // Каталог списков заменяется целиком, если он есть в копии.
        SHARED_DIRS.filter { d -> data.files.keys.any { it.startsWith("$d/") } }
            .forEach { d -> File(base, d).listFiles()?.forEach { runCatching { it.deleteRecursively() } } }
        val root = base.canonicalPath + File.separator
        var n = 0
        data.files.forEach { (rel, bytes) ->
            if (!allowedPath(rel)) return@forEach
            val target = File(base, rel)
            if (!runCatching { target.canonicalPath.startsWith(root) }.getOrDefault(false)) return@forEach
            val ok = runCatching {
                target.parentFile?.mkdirs()
                val tmp = File(target.parentFile, target.name + ".tmp")
                tmp.writeBytes(bytes)
                if (!tmp.renameTo(target)) {
                    tmp.copyTo(target, overwrite = true)
                    tmp.delete()
                }
            }.isSuccess
            if (ok) n++
        }
        return n
    }

    private fun restorePrefs(context: Context, data: BackupFormat.Data): Int {
        var n = 0
        EXTRA_PREFS.forEach { name ->
            val edit = context.getSharedPreferences(name, Context.MODE_PRIVATE).edit().clear()
            data.prefs[name]?.forEach { (key, value) -> if (put(edit, key, value)) n++ }
            edit.commit()
        }
        return n
    }

    private fun restoreVault(context: Context, data: BackupFormat.Data): Int {
        if (data.vault.isEmpty()) return 0
        val vault = KeyVault(context)
        var n = 0
        data.vault.forEach { (alias, value) ->
            val ok = if (alias == KeyVault.ALIAS_ACCOUNT) {
                runCatching { vault.accountStore().save(value) }.isSuccess
            } else {
                runCatching { vault.put(alias, value) }.getOrDefault(false)
            }
            if (ok) n++
        }
        return n
    }

    private fun put(edit: SharedPreferences.Editor, key: String, value: Any?): Boolean {
        when (value) {
            is String -> edit.putString(key, value)
            is Int -> edit.putInt(key, value)
            is Long -> edit.putLong(key, value)
            is Boolean -> edit.putBoolean(key, value)
            is Float -> edit.putFloat(key, value)
            is Set<*> -> edit.putStringSet(key, value.map { it.toString() }.toSet())
            else -> return false
        }
        return true
    }

    /** Это наш бекап? Первая строка — заголовок; BOM и \r, которые добавляют облака, не мешают. */
    fun isBackup(text: String): Boolean = BackupFormat.isBackup(text)

    /**
     * «23.11.2026 17:03 · подключение 8.35.211.1:4233» — когда и почему записана копия (служебные
     * строки в начале файла). null — их нет: в вопросе «Восстановить?» останется только имя файла.
     */
    fun describe(text: String): String? {
        val notes = BackupFormat.parse(text)?.notes ?: return null
        val at = notes["at"]?.toLongOrNull()
        val reason = notes["reason"]?.ifBlank { null }
        val date = at?.takeIf { it > 0L }?.let { SimpleDateFormat("dd.MM.yyyy HH:mm", Locale.getDefault()).format(Date(it)) }
        return listOfNotNull(date, reason).joinToString(" · ").ifEmpty { null }
    }

    /**
     * Что внутри копии — строками для вопроса «Восстановить?» и окна «Копия сохранена»: заранее видно,
     * перенесутся ли точки, второй выход и остальное. null — это не копия WarpScout.
     */
    fun contents(context: Context, text: String): String? {
        val data = BackupFormat.parse(text) ?: return null
        val m = data.main
        val apps = (m["appsSelected"] as? Set<*>)?.size ?: 0
        val exits = (m["appExits"] as? Set<*>)?.size ?: 0
        val conf = (m["secondConf"] as? String).orEmpty()
        val country = (m["secondProtonCountry"] as? String).orEmpty()
        val second = when {
            conf.isBlank() -> "не настроен"
            ProtonFree.isProton(conf) -> "Proton Free, " +
                (if (country.isBlank()) "страна любая" else SecondProton.countryName(context, country)) +
                (if (m["secondExitOn"] == true) "" else " (выключен)")
            else -> "свой сервер" + if (m["secondExitOn"] == true) "" else " (выключен)"
        }
        val lines = ArrayList<String>()
        data.notes["app"]?.substringAfter(' ', "")?.ifBlank { null }?.let { lines += "Записана в WarpScout $it." }
        lines += "Внутри:"
        lines += "• настройки: ${m.size} (приложений в туннеле: $apps, выход по приложениям: $exits)"
        lines += "• второй выход: $second"
        if (data.format < 2) {
            lines += ""
            lines += "Это копия старого формата: в ней только основные настройки. Тройки точек (резервная точка), " +
                "память точек, ответы про Telegram, конфиг для автоподъёма, скачанные списки и ключ аккаунта в неё " +
                "не попадали. Чтобы перенести всё, сохраните копию заново в обновлённом приложении."
            return lines.joinToString("\n")
        }
        val shortlist = data.files["shortlist.txt"]?.toString(Charsets.UTF_8)
        val (wifi, mobile, stored) = shortlist?.let { ConfigShortlist.countIn(it) } ?: Triple(0, 0, 0)
        lines += when {
            stored == 0 -> "• тройки точек: нет (подбора ещё не было)"
            wifi + mobile == 0 -> "• тройки точек: старше недели — после восстановления нужен новый подбор"
            else -> "• тройки точек: Wi-Fi — $wifi, мобильная сеть — $mobile"
        }
        val memory = listOf("endpoint-memory.txt", "site-memory.txt", "noise-memory.txt", "tg-choice.txt", "tuning-cache.txt")
            .count { it in data.files }
        lines += "• память точек, площадок и ответов про Telegram: " + if (memory > 0) "есть" else "пусто"
        val lists = data.files.keys.count { it.startsWith("allowlists/") && it.endsWith(".lst") }
        lines += "• скачанные списки сайтов: " + if (lists > 0) "$lists" else "нет"
        lines += "• конфиг для автоподъёма: " + if ("tunnel-last.conf" in data.files) "есть" else "нет"
        lines += "• ключ аккаунта WARP: " + if (data.vault.isNotEmpty()) "есть" else "нет"
        data.notes["skipped"]?.takeIf { it.isNotBlank() }?.let { lines += "• не вошло (слишком большое): $it" }
        return lines.joinToString("\n")
    }

    /** Держим последние [KEEP] файлов: бекап не должен сам съесть память. */
    private fun prune(context: Context) {
        val files = list(context)
        if (files.size <= KEEP) return
        files.drop(KEEP).forEach { runCatching { it.delete() } }
    }
}
