package dev.warpscout.app

import android.content.Context
import dev.warpscout.core.net.TelegramChoice
import java.io.File

/**
 * Ответы на вопрос «пустить Telegram через второй выход?» по сетям (с 1.10.36). Правила — в
 * [TelegramChoice], здесь только хранение.
 *
 * Как [SiteMemory] — обычный файл в приватном каталоге, а не `SharedPreferences`: спрашивает и
 * читает ответ туннель (отдельный процесс), а сбрасывает экран («Сбросить всё»). Запись — через
 * временный файл и переименование. Битый файл значит «ответов нет» — приложение просто спросит снова.
 */
object TelegramChoiceMemory {

    private const val FILE = "tg-choice.txt"

    /**
     * Канал уведомлений с вопросом (обычной важности, без звука). Объявлен здесь, в общей части:
     * его создаёт туннель, а экран проверяет, не выключен ли он (тогда спрашивает сам).
     */
    const val ASK_CHANNEL = "warpscout.tg.ask"

    private val lock = Any()

    /** Действующее решение для сети: [TelegramChoice.SECOND], [TelegramChoice.STAY], [TelegramChoice.ASKED] или пусто. */
    fun choiceOf(context: Context, net: String): String =
        runCatching { TelegramChoice.choiceOf(read(file(context)), net, System.currentTimeMillis()) }.getOrDefault("")

    /** Запомнить решение для сети (заменяет прежнее). */
    fun note(context: Context, net: String, choice: String) {
        if (net.isBlank()) return
        synchronized(lock) {
            val target = file(context)
            val mark = TelegramChoice.Mark(net, choice, System.currentTimeMillis())
            write(target, TelegramChoice.put(read(target), mark))
        }
    }

    /** Сброс по умолчанию: забыть ответы для всех сетей. */
    fun forgetAll(context: Context) {
        synchronized(lock) { runCatching { file(context).delete() } }
    }

    private fun file(context: Context): File = File(context.applicationContext.filesDir, FILE)

    private fun read(f: File): List<TelegramChoice.Mark> = runCatching {
        if (!f.exists()) emptyList() else TelegramChoice.parse(f.readText())
    }.getOrDefault(emptyList())

    private fun write(target: File, marks: List<TelegramChoice.Mark>) {
        runCatching {
            val dir = target.parentFile ?: return
            dir.mkdirs()
            // Пишут два процесса (туннель и экран): у каждого свой временный файл.
            val tmp = File(dir, target.name + ".tmp" + android.os.Process.myPid())
            tmp.writeText(TelegramChoice.render(marks))
            if (!tmp.renameTo(target)) {
                target.delete()
                if (!tmp.renameTo(target)) tmp.copyTo(target, overwrite = true)
            }
        }
    }
}
