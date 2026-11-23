package dev.warpscout.app

import android.content.Context
import dev.warpscout.core.net.ExitSite
import java.io.File

/**
 * Память «на этой сети эта точка выходит через такую площадку Cloudflare» (с 1.10.34). Правила — в
 * [ExitSite], здесь только хранение.
 *
 * Зачем. Журнал 23.11: в 07:39 Wi-Fi перешёл с Хельсинки (HEL) на Москву (DME), и медиа Telegram
 * стало грузиться рывками. Площадку выбирает маршрут оператора, но разные адреса Cloudflare приходят
 * на разные площадки, поэтому подбор узнаёт площадку каждой точки, а проверка связи — площадку той
 * точки, через которую туннель работает сейчас. По этой памяти:
 *  • перебор при обрыве ставит точки с выходом за рубежом раньше московских;
 *  • туннель решает, пускать ли Telegram через второй выход (выход в России — да);
 *  • поиск выхода за рубежом ходит не чаще раза в сутки на сеть (запись [ExitSite.SEARCH]).
 *
 * Как [EndpointMemory] и [NoiseMemory] — обычный файл в приватном каталоге, а не `SharedPreferences`:
 * туннель живёт в отдельном процессе. Запись — через временный файл и переименование. Битый файл
 * значит «памяти нет», а не падение: это подсказка, а не состояние туннеля.
 */
object SiteMemory {

    private const val FILE = "site-memory.txt"

    private val lock = Any()

    /**
     * Точка [endpoint] на сети [net] выходит через [site] (проверено только что). [live] — это
     * проверка связи работающего туннеля (а не проверка подбора): тогда это и «выход на этой сети
     * сейчас» (см. [lastSite]).
     */
    fun note(context: Context, net: String, endpoint: String, site: String?, live: Boolean = false) {
        val code = ExitSite.normalize(site)
        if (net.isBlank() || endpoint.isBlank() || code.isEmpty()) return
        val now = System.currentTimeMillis()
        synchronized(lock) {
            val target = file(context)
            var marks = read(target)
            // Та же площадка у той же точки записана меньше 10 минут назад — файл не трогаем:
            // проверка связи идёт при каждом открытии экрана.
            val last = marks.lastOrNull { it.net == net && it.endpoint == endpoint }
            val liveMark = marks.lastOrNull { it.net == net && it.endpoint == ExitSite.LIVE }
            val sameLast = last != null && last.site == code && now - last.at in 0..10 * 60_000L
            val sameLive = !live || (liveMark != null && liveMark.site == code && now - liveMark.at in 0..10 * 60_000L)
            if (sameLast && sameLive) return
            marks = ExitSite.put(marks, ExitSite.Mark(net, endpoint, code, now))
            if (live) marks = ExitSite.put(marks, ExitSite.Mark(net, ExitSite.LIVE, code, now))
            write(target, marks)
        }
    }

    /** Несколько точек разом (итог подбора): одна запись в файл. */
    fun noteAll(context: Context, net: String, sites: Map<String, String>) {
        if (net.isBlank() || sites.isEmpty()) return
        val now = System.currentTimeMillis()
        synchronized(lock) {
            val target = file(context)
            var marks = read(target)
            for ((endpoint, site) in sites) {
                val code = ExitSite.normalize(site)
                if (endpoint.isBlank() || code.isEmpty()) continue
                marks = ExitSite.put(marks, ExitSite.Mark(net, endpoint, code, now))
            }
            write(target, marks)
        }
    }

    /** Площадка точки на этой сети («DME»); пусто — не знаем или давно. */
    fun siteOf(context: Context, net: String, endpoint: String): String =
        runCatching { ExitSite.siteOf(read(file(context)), net, endpoint, System.currentTimeMillis()) }.getOrDefault("")

    /** Все свежие площадки точек этой сети: «адрес:порт» → «DME». Для порядка перебора — одно чтение файла. */
    fun sitesFor(context: Context, net: String): Map<String, String> = runCatching {
        if (net.isBlank()) return@runCatching emptyMap()
        val now = System.currentTimeMillis()
        val out = LinkedHashMap<String, String>()
        for (m in read(file(context))) {
            if (m.net != net || m.endpoint == ExitSite.SEARCH || m.endpoint == ExitSite.LIVE) continue
            if (now - m.at !in 0..ExitSite.FRESH_MS) continue
            val code = ExitSite.normalize(m.site)
            if (code.isNotEmpty()) out[m.endpoint] = code
        }
        out
    }.getOrDefault(emptyMap())

    /**
     * Площадка, через которую работающий туннель на этой сети выходил последним (по проверке связи,
     * см. [note] с live). Пусто — не знаем или давно.
     */
    fun lastSite(context: Context, net: String): String =
        runCatching { ExitSite.siteOf(read(file(context)), net, ExitSite.LIVE, System.currentTimeMillis()) }.getOrDefault("")

    /** Пора ли искать выход за рубежом на этой сети (не чаще раза в сутки). */
    fun searchDue(context: Context, net: String): Boolean =
        net.isNotBlank() && runCatching { ExitSite.searchDue(read(file(context)), net, System.currentTimeMillis()) }.getOrDefault(true)

    /** Итог поиска выхода за рубежом на этой сети: [found] — нашёлся. */
    fun noteSearch(context: Context, net: String, found: Boolean) {
        if (net.isBlank()) return
        synchronized(lock) {
            val target = file(context)
            val mark = ExitSite.Mark(net, ExitSite.SEARCH, if (found) ExitSite.FOUND else ExitSite.NONE, System.currentTimeMillis())
            write(target, ExitSite.put(read(target), mark))
        }
    }

    /** Сброс по умолчанию: забыть площадки всех сетей. */
    fun forgetAll(context: Context) {
        synchronized(lock) { runCatching { file(context).delete() } }
    }

    private fun file(context: Context): File = File(context.applicationContext.filesDir, FILE)

    private fun read(f: File): List<ExitSite.Mark> = runCatching {
        if (!f.exists()) emptyList() else ExitSite.parse(f.readText())
    }.getOrDefault(emptyList())

    private fun write(target: File, marks: List<ExitSite.Mark>) {
        runCatching {
            val dir = target.parentFile ?: return
            dir.mkdirs()
            // Пишут два процесса (подбор в приложении и туннель): у каждого свой временный файл,
            // иначе один мог бы переименовать недописанный файл другого.
            val tmp = File(dir, target.name + ".tmp" + android.os.Process.myPid())
            tmp.writeText(ExitSite.render(marks))
            if (!tmp.renameTo(target)) {
                target.delete()
                if (!tmp.renameTo(target)) tmp.copyTo(target, overwrite = true)
            }
        }
    }
}
