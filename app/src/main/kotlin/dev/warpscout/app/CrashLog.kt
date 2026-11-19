package dev.warpscout.app

import android.content.Context
import java.io.File
import java.io.PrintWriter
import java.io.StringWriter
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Журнал падений.
 *
 * Пользователь видит «приложение вылетело, журнал ничего не пишет» — и это правда: необработанное
 * исключение убивает процесс раньше, чем что-либо успевает записаться, а вместе с процессом
 * умирает и туннель (VpnService живёт в нём же). Отсюда два симптома сразу: «вылетает» и
 * «соединение отваливается».
 *
 * Поэтому ставим обработчик на самом раннем этапе: стектрейс пишется в файл (filesDir/crashes.txt,
 * последние три падения), и при следующем запуске первая строка попадает в журнал туннеля и в
 * «Скопировать журнал». Цепочку прежнего обработчика вызываем дальше — приложение должно упасть
 * штатно, а не притворяться живым.
 */
object CrashLog {

    private const val FILE = "crashes.txt"
    private const val KEEP = 3

    @Volatile
    private var installed = false

    fun install(context: Context) {
        if (installed) return
        installed = true
        val app = context.applicationContext
        val previous = Thread.getDefaultUncaughtExceptionHandler()
        Thread.setDefaultUncaughtExceptionHandler { thread, error ->
            runCatching { write(app, thread, error) }
            previous?.uncaughtException(thread, error)
        }
    }

    private fun write(context: Context, thread: Thread, error: Throwable) {
        val file = File(context.filesDir, FILE)
        val stack = StringWriter().also { sw -> PrintWriter(sw).use { error.printStackTrace(it) } }
            .toString()
        val head = StringBuilder()
            .append("── ").append(stamp()).append(" · поток ").append(thread.name).append('\n')
            .append(stack.take(4000)).append('\n')
        val old = runCatching { file.readText() }.getOrDefault("")
        // Свежие падения сверху, старые обрезаем: файл не должен расти сам по себе.
        val merged = (head.toString() + old).let { text ->
            val parts = text.split("── ")
            ("── " + parts.drop(1).take(KEEP).joinToString("── ")).trimEnd() + "\n"
        }
        runCatching {
            context.getSharedPreferences("crashes", Context.MODE_PRIVATE).edit()
                .putString("last", head.toString()).apply()
            file.writeText(merged)
        }
        runCatching { TunnelDebug.error("падение: " + (error.message ?: error.javaClass.simpleName)) }
    }

    /** Последнее падение (для журнала при следующем запуске) или null, если падений не было. */
    fun lastCrash(context: Context): String? {
        val saved = runCatching {
            context.getSharedPreferences("crashes", Context.MODE_PRIVATE).getString("last", null)
        }.getOrNull()
        return saved?.takeIf { it.isNotBlank() }
    }

    /** Отчёт целиком — попадает в «Скопировать журнал», чтобы не гадать по скриншоту. */
    fun report(context: Context): String {
        val saved = runCatching { File(context.filesDir, FILE).readText() }.getOrDefault("")
        return if (saved.isBlank()) "падений не зафиксировано" else saved
    }

    fun clear(context: Context) {
        runCatching { File(context.filesDir, FILE).delete() }
        runCatching { context.getSharedPreferences("crashes", Context.MODE_PRIVATE).edit().clear().apply() }
    }

    private fun stamp(): String =
        SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US).format(Date())

    /** Падения не должны переживать «очистить журнал» — иначе старое будет пугать вечно. */
    fun describe(context: Context): String {
        val text = report(context)
        return if (text.startsWith("падений")) text else "── падения ──\n" + text.take(3000)
    }
}
