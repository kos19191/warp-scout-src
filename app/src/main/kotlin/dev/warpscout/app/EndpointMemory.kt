package dev.warpscout.app

import android.content.Context
import java.io.File

/**
 * Какая точка входа работала на какой сети.
 *
 * Зачем это нужно. У Cloudflare десятки anycast-адресов, и «живой на Wi-Fi» может закрывать порт
 * на мобильной сети — в журнале с улицы это видно по секундам: на Wi-Fi работал
 * `162.159.192.10:500`, а после выхода из дома поднялся только `162.159.192.2:500`. Без памяти
 * сервис при каждом переходе начинал с точки, оставшейся от другой сети, тратил на неё попытку
 * (полсекунды при ICMP, до пяти секунд при молчании) и только потом доходил до рабочей.
 *
 * С памятью переключение начинается сразу с нужного адреса: одна попытка вместо двух-трёх.
 * Пользуются ей обе стороны: сервис — при переподключении после смены сети, интерфейс — когда
 * человек нажимает «Подключить» вручную.
 *
 * Лежит в приватном каталоге приложения, а не в `SharedPreferences`: туннель живёт в отдельном
 * процессе, и общий с интерфейсом файл настроек ему читать нельзя (см. `ServiceSettingsStore`).
 * Здесь обе стороны работают с обычным файлом, запись идёт через временный файл и переименование,
 * чтобы чтение никогда не увидело половину строки. Формат нарочно простой — `вид сети|адрес:порт`;
 * битый файл означает «памяти нет», а не падение: это подсказка, а не состояние туннеля.
 */
object EndpointMemory {

    private const val FILE = "endpoint-memory.txt"

    /** Видов сети единицы; ограничение нужно, чтобы файл не рос из-за случайных записей. */
    private const val MAX_ENTRIES = 8

    private val lock = Any()

    /** Адрес, который работал на таком виде сети (`Wi-Fi`, `мобильная`, `Ethernet`), или null. */
    fun goodFor(context: Context, netKind: String): String? {
        if (netKind.isBlank()) return null
        return read(file(context))[netKind]
    }

    /** Запомнить рабочую пару «вид сети → адрес». */
    fun remember(context: Context, netKind: String, endpoint: String) {
        if (netKind.isBlank() || endpoint.isBlank()) return
        synchronized(lock) {
            val target = file(context)
            val all = read(target).toMutableMap()
            if (all[netKind] == endpoint) return
            all[netKind] = endpoint
            runCatching {
                val dir = target.parentFile ?: return
                dir.mkdirs()
                val text = all.entries
                    .take(MAX_ENTRIES)
                    .joinToString("\n") { (kind, ep) -> "$kind|$ep" } + "\n"
                val tmp = File(dir, target.name + ".tmp")
                tmp.writeText(text)
                if (!tmp.renameTo(target)) {
                    target.delete()
                    if (!tmp.renameTo(target)) tmp.copyTo(target, overwrite = true)
                }
            }
        }
    }

    private fun file(context: Context): File =
        File(context.applicationContext.filesDir, FILE)

    private fun read(f: File): Map<String, String> = runCatching {
        if (!f.exists()) return@runCatching emptyMap()
        f.readLines().mapNotNull { line ->
            val kind = line.substringBefore('|').trim()
            val ep = line.substringAfter('|', "").trim()
            if (kind.isEmpty() || ep.isEmpty()) null else kind to ep
        }.toMap()
    }.getOrDefault(emptyMap())
}
