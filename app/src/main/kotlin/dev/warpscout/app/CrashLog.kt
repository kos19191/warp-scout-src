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
        // Запоминаем, когда начался этот запуск: по этой отметке потом понятно, падает приложение
        // сразу на старте (тогда причину надо показать до интерфейса) или упало позже.
        runCatching {
            app.getSharedPreferences("crashes", Context.MODE_PRIVATE).edit()
                .putLong("runStartedAt", System.currentTimeMillis()).apply()
        }
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
            val now = System.currentTimeMillis()
            val sp = context.getSharedPreferences("crashes", Context.MODE_PRIVATE)
            val startedAt = sp.getLong("runStartedAt", 0L)
            sp.edit()
                .putString("last", head.toString())
                .putLong("lastAt", now)
                // Сколько прожил запуск до падения: «упало сразу» — отдельный, самый неприятный случай.
                .putLong("lastAgeMs", if (startedAt > 0L && now >= startedAt) now - startedAt else -1L)
                .putBoolean("shown", false)
                .apply()
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

    /**
     * Падение, случившееся совсем недавно (по умолчанию — меньше трёх минут назад, и о нём ещё
     * не рассказывали). Нужно ровно для одного сценария: приложение падает при запуске, и тогда
     * человек не может открыть журнал, чтобы прислать причину. Такой отчёт показывается
     * аварийным экраном ДО построения интерфейса, и кнопка «Продолжить» ведёт дальше как обычно.
     *
     * Повторно один и тот же отчёт не показывается: отметка «рассказали» снимается при следующем
     * падении.
     */
    fun recentCrash(
        context: Context,
        maxAgeMs: Long = 3 * 60 * 1000L,
        maxRunMs: Long = 20 * 1000L
    ): String? {
        val sp = runCatching {
            context.getSharedPreferences("crashes", Context.MODE_PRIVATE)
        }.getOrNull() ?: return null
        val text = sp.getString("last", null)?.takeIf { it.isNotBlank() } ?: return null
        if (sp.getBoolean("shown", false)) return null
        val at = sp.getLong("lastAt", 0L)
        if (at <= 0L || System.currentTimeMillis() - at > maxAgeMs) return null
        // Только «упало почти сразу после запуска»: иначе человека, который вернулся в приложение
        // через минуту после падения в фоне, встречала бы стена текста вместо обычного экрана.
        val age = sp.getLong("lastAgeMs", -1L)
        if (age < 0L || age > maxRunMs) return null
        runCatching { sp.edit().putBoolean("shown", true).apply() }
        return text
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

    /**
     * Записать в тот же файл событие, которое не является падением (например, отказ startForeground).
     *
     * Дописываем в конец, а не «прочитать + перезаписать»: файл пишут оба процесса (интерфейс и
     * туннель), и перезапись одного стирала бы строку другого.
     */
    fun note(context: Context, text: String) {
        val app = context.applicationContext
        val file = File(app.filesDir, FILE)
        runCatching {
            java.io.FileOutputStream(file, true).use { out ->
                out.write(("── " + stamp() + " · " + text + "\n").toByteArray(Charsets.UTF_8))
            }
        }
    }

    /** Падения не должны переживать «очистить журнал» — иначе старое будет пугать вечно. */
    fun describe(context: Context): String {
        val text = report(context)
        return if (text.startsWith("падений")) text else "── падения ──\n" + text.take(3000)
    }
}
