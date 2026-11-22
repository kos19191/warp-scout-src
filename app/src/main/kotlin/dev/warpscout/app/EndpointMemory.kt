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

    /**
     * Сетей немного, но теперь ключ различает операторов и разные Wi-Fi (см. [NetIdentity]), так
     * что записей больше, чем видов сети. Предел нужен, чтобы файл не рос из-за случайных сетей:
     * при переполнении уходят самые давние.
     */
    private const val MAX_ENTRIES = 24

    private val lock = Any()

    /**
     * Адрес, который работал на этой сети, или null. Ключ — из [NetIdentity] («мобильная·25001»)
     * или просто вид сети: сначала ищем точное совпадение (этот оператор, этот Wi-Fi), потом —
     * по виду, как раньше.
     */
    fun goodFor(context: Context, netKind: String): String? {
        if (netKind.isBlank()) return null
        val all = read(file(context))
        return all[netKind] ?: all[NetIdentity.kindPart(netKind)]
    }

    /** Запомнить рабочую пару «сеть → адрес» — и для точного ключа, и для вида сети. */
    fun remember(context: Context, netKind: String, endpoint: String) {
        if (netKind.isBlank() || endpoint.isBlank()) return
        val kind = NetIdentity.kindPart(netKind)
        synchronized(lock) {
            val target = file(context)
            val all = LinkedHashMap(read(target))
            if (all[netKind] == endpoint && all[kind] == endpoint) return
            // Удаляем и кладём заново: свежие записи — в конец, при переполнении уходят давние.
            all.remove(netKind)
            all[netKind] = endpoint
            if (kind.isNotEmpty() && kind != netKind) {
                all.remove(kind)
                all[kind] = endpoint
            }
            runCatching {
                val dir = target.parentFile ?: return
                dir.mkdirs()
                val text = all.entries
                    .toList()
                    .takeLast(MAX_ENTRIES)
                    .joinToString("\n") { (key, ep) -> "$key|$ep" } + "\n"
                val tmp = File(dir, target.name + ".tmp")
                tmp.writeText(text)
                if (!tmp.renameTo(target)) {
                    target.delete()
                    if (!tmp.renameTo(target)) tmp.copyTo(target, overwrite = true)
                }
            }
        }
    }

    /**
     * Забыть точку для этой сети — если запомнена именно она. Нужна, когда точка отвечает на
     * рукопожатие, но не пропускает данные: иначе каждый переподъём начинался бы с неё снова (журнал
     * 22.11: три переподключения подряд на 188.114.97.1:500, и ни одного на следующую точку).
     */
    fun forget(context: Context, netKind: String, endpoint: String) {
        if (netKind.isBlank() || endpoint.isBlank()) return
        val kind = NetIdentity.kindPart(netKind)
        synchronized(lock) {
            val target = file(context)
            val all = LinkedHashMap(read(target))
            var changed = false
            for (key in listOf(netKind, kind)) {
                if (key.isNotEmpty() && all[key] == endpoint) {
                    all.remove(key)
                    changed = true
                }
            }
            if (!changed) return
            runCatching {
                val dir = target.parentFile ?: return
                val text = all.entries.joinToString("\n") { (key, ep) -> "$key|$ep" } + "\n"
                val tmp = File(dir, target.name + ".tmp")
                tmp.writeText(text)
                if (!tmp.renameTo(target)) {
                    target.delete()
                    if (!tmp.renameTo(target)) tmp.copyTo(target, overwrite = true)
                }
            }
        }
    }

    /** Сброс по умолчанию (с 1.10.32): забыть рабочие точки всех сетей. */
    fun forgetAll(context: Context) {
        synchronized(lock) { runCatching { file(context).delete() } }
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
