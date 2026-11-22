package dev.warpscout.app

import android.content.Context
import dev.warpscout.core.model.ResourceResult
import dev.warpscout.core.model.TuningReport
import dev.warpscout.core.net.HttpClient
import dev.warpscout.core.net.ResourceProber
import java.io.File

/**
 * Список «Доступность» в Журнале (с 1.10.30): что открылось через туннель и что — без VPN.
 *
 * Зачем. Раньше в Журнале был один список «Что реально открылось» — итог проверки без VPN (база
 * сравнения подбора), и подписи у него не было. ChatGPT в нём стоял «открылся», хотя через туннель
 * не открывался: проверка спрашивала служебную страницу Cloudflare, которая отвечает всем. Теперь
 * списка два, и у каждого написано, откуда проверяли, через какую точку и когда.
 *
 * Итог лежит в файле, а не в настройках: он переживает перезапуск приложения, и Журнал сразу
 * показывает последний результат. Формат построчный — файл маленький и читается глазами.
 */
object Availability {

    const val VIA_TUNNEL = "tunnel"
    const val VIA_DIRECT = "direct"

    const val SOURCE_SCAN = "scan"
    const val SOURCE_BUTTON = "button"

    /** Одна строка списка: сервис, открылся ли, и что именно увидели — словами. */
    data class Line(val name: String, val ok: Boolean, val text: String)

    data class Report(
        val via: String,
        val source: String,
        val at: Long,
        /** Точка, через которую проверяли («188.114.97.1:500 · tls-fixed»); для «без VPN» — пусто. */
        val point: String,
        val lines: List<Line>
    )

    private const val HEADER = "v1"

    private fun file(context: Context, via: String) = File(context.filesDir, "availability-$via.txt")

    /** Сброс по умолчанию (с 1.10.32): забыть итоги проверок доступности (через туннель и без). */
    fun forgetAll(context: Context) {
        listOf(VIA_TUNNEL, VIA_DIRECT).forEach { via -> runCatching { file(context, via).delete() } }
    }

    /** Разделитель полей в файле — из текста убираем, переводы строк тоже. */
    private fun clean(s: String): String = s.replace('|', '/').replace('\n', ' ').replace('\r', ' ').trim()

    fun save(context: Context, report: Report) {
        val text = buildString {
            append(HEADER).append('|').append(clean(report.via)).append('|').append(clean(report.source))
                .append('|').append(report.at).append('|').append(clean(report.point)).append('\n')
            for (line in report.lines) {
                append(if (line.ok) '1' else '0').append('|').append(clean(line.name)).append('|')
                    .append(clean(line.text)).append('\n')
            }
        }
        val target = file(context, report.via)
        val tmp = File(target.parentFile, target.name + ".tmp")
        tmp.writeText(text)
        if (!tmp.renameTo(target)) {
            target.writeText(text)
            tmp.delete()
        }
    }

    fun load(context: Context, via: String): Report? = runCatching {
        val f = file(context, via)
        if (!f.exists()) return@runCatching null
        val rows = f.readLines().filter { it.isNotBlank() }
        val head = rows.firstOrNull()?.split('|') ?: return@runCatching null
        if (head.size < 5 || head[0] != HEADER) return@runCatching null
        val lines = rows.drop(1).mapNotNull { row ->
            val parts = row.split('|', limit = 3)
            if (parts.size < 3) null else Line(parts[1], parts[0] == "1", parts[2])
        }
        Report(head[1], head[2], head[3].toLongOrNull() ?: 0L, head[4], lines)
    }.getOrNull()

    fun fromResults(via: String, source: String, at: Long, point: String, results: List<ResourceResult>): Report =
        Report(
            via = via,
            source = source,
            at = at,
            point = point,
            lines = results.map { r -> Line(r.check.name, r.ok, ResourceProber.describe(r)) }
        )

    /**
     * После подбора: без VPN — база сравнения, через туннель — у лучшей из проверенных точек
     * (той, к которой подключимся; если её не проверяли — у первой проверенной).
     */
    fun saveFromScan(context: Context, report: TuningReport, bestEndpoint: String?) {
        val now = System.currentTimeMillis()
        if (report.resources.isNotEmpty()) {
            save(context, fromResults(VIA_DIRECT, SOURCE_SCAN, now, "", report.resources))
        }
        val verified = report.candidates.filter { it.resourceResults.isNotEmpty() }
        val pick = verified.firstOrNull { it.config.endpoint.render() == bestEndpoint } ?: verified.firstOrNull()
        if (pick != null) {
            val point = pick.config.endpoint.render() + " · " + pick.junk.name
            save(context, fromResults(VIA_TUNNEL, SOURCE_SCAN, now, point, pick.resourceResults))
        }
    }

    /**
     * Процесс сейчас привязан к отдельной сети — значит, идёт подбор (свой или фоновый, см.
     * CleanNetwork): запросы пошли бы мимо туннеля, и «через туннель» было бы неправдой.
     */
    fun processBound(context: Context): Boolean = runCatching {
        val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as android.net.ConnectivityManager
        cm.boundNetworkForProcess != null
    }.getOrDefault(false)

    /**
     * «Проверить сейчас»: те же проверки из процесса приложения через туннель, который работает
     * сейчас (WarpScout входит в туннель и в режиме «только выбранные», см. applyAppSplit). Не из
     * главного потока: это сетевые запросы, до полуминуты.
     */
    fun checkNow(context: Context, point: String, isCancelled: () -> Boolean): Report {
        // Подбор мог начаться, пока нажимали кнопку: тогда проверка пошла бы мимо туннеля.
        check(!processBound(context)) { "идёт подбор — проверка через туннель сейчас невозможна" }
        val checks = Prefs(context).availabilityChecks()
        val results = ResourceProber(HttpClient(8000)).checkParallel(checks, VIA_TUNNEL, isCancelled)
        val report = fromResults(VIA_TUNNEL, SOURCE_BUTTON, System.currentTimeMillis(), point, results)
        if (!isCancelled() && results.isNotEmpty()) save(context, report)
        return report
    }
}
