package dev.warpscout.app

import android.content.Context
import dev.warpscout.core.tune.NoiseBook
import java.io.File

/**
 * Память «на этой сети такой шум замерзает» (с 1.10.30). Правила — в [NoiseBook], здесь только
 * хранение.
 *
 * Зачем. Журнал 22.11: на Wi-Fi человека чистый WireGuard (шум «none») пропускал рукопожатие и
 * первый ответ, а дальше молчал — на любой точке; та же точка с TLS-маской работала 12 часов.
 * Сервис же помечал мёртвыми точки, а не шум, и полчаса перебирал точки с тем же «none». Теперь
 * сервис записывает сюда итог каждой проверки данных, а сам подъём туннеля и подбор смотрят сюда:
 * замерзающий на этой сети шум заменяется маской ещё до рукопожатия.
 *
 * Как и [EndpointMemory] — обычный файл в приватном каталоге, а не `SharedPreferences`: туннель
 * живёт в отдельном процессе. Запись — через временный файл и переименование. Битый файл значит
 * «памяти нет», а не падение: это подсказка, а не состояние туннеля.
 */
object NoiseMemory {

    private const val FILE = "noise-memory.txt"

    private val lock = Any()

    /** Записать итог проверки данных: [kind] — один из видов [NoiseBook] (FROZE, NO_DATA, WORKED, TUNER). */
    fun note(context: Context, net: String, noise: String, kind: Char, endpoint: String) {
        if (net.isBlank() || noise.isBlank()) return
        val now = System.currentTimeMillis()
        synchronized(lock) {
            val target = file(context)
            val events = read(target)
            // «Идут» на той же сети с тем же шумом пишем не чаще раза в десять минут: туннель
            // поднимается часто (каждая смена сети), а для правил важна только последняя такая запись.
            if (kind == NoiseBook.WORKED) {
                val last = events.lastOrNull { it.net == net && it.noise == noise && it.kind == NoiseBook.WORKED }
                val stale = events.any { it.net == net && it.noise == noise && it.kind != NoiseBook.WORKED && it.at > (last?.at ?: 0L) }
                if (last != null && !stale && now - last.at in 0..10 * 60_000L) return
            }
            write(target, NoiseBook.add(events, NoiseBook.Event(net, noise, kind, endpoint, now)))
        }
    }

    /** Шум, который на этой сети замерзает. */
    fun frozen(context: Context, net: String): Set<String> =
        runCatching { NoiseBook.frozen(read(file(context)), net, System.currentTimeMillis()) }.getOrDefault(emptySet())

    /** Чем заменить шум [current] на этой сети (null — не нужно или не на что), см. [NoiseBook.replacement]. */
    fun replacement(context: Context, net: String, current: String, order: List<String>): String? =
        runCatching {
            NoiseBook.replacement(read(file(context)), net, current, order, System.currentTimeMillis())
        }.getOrNull()

    /** Шум, с которым на этой сети последними шли данные. */
    fun preferred(context: Context, net: String): String? =
        runCatching { NoiseBook.preferred(read(file(context)), net, System.currentTimeMillis()) }.getOrNull()

    /** Сброс по умолчанию (с 1.10.32): забыть, какой шум где замерзал. */
    fun forgetAll(context: Context) {
        synchronized(lock) { runCatching { file(context).delete() } }
    }

    private fun file(context: Context): File = File(context.applicationContext.filesDir, FILE)

    private fun read(f: File): List<NoiseBook.Event> = runCatching {
        if (!f.exists()) emptyList() else NoiseBook.parse(f.readText())
    }.getOrDefault(emptyList())

    private fun write(target: File, events: List<NoiseBook.Event>) {
        runCatching {
            val dir = target.parentFile ?: return
            dir.mkdirs()
            val tmp = File(dir, target.name + ".tmp")
            tmp.writeText(NoiseBook.render(events))
            if (!tmp.renameTo(target)) {
                target.delete()
                if (!tmp.renameTo(target)) tmp.copyTo(target, overwrite = true)
            }
        }
    }
}
