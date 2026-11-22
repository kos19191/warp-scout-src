package dev.warpscout.app

import android.app.DownloadManager
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Environment
import dev.warpscout.core.json.JsonVal
import dev.warpscout.core.json.parseJson
import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest

/**
 * «Обновления» (с 1.10.31): только по нажатию — проверить последний релиз на GitHub и скачать APK
 * своей сборки (scout или tunnel). Ключ подписи у всех версий один, поэтому новая ставится поверх,
 * с настройками.
 *
 * С 1.10.32 скачивает системная загрузка Android — в «Загрузки», с уведомлением «Загрузка
 * завершена», — а ставит человек нажатием на файл (или на уведомление). В 1.10.31 WarpScout ставил
 * APK сам, для этого нужно было разрешение «Установка приложений», и «Защита приложений» Samsung
 * (движок McAfee) назвала 1.10.31 вредоносной: приложение, которое само скачивает и ставит другие
 * APK, для антивируса выглядит как «загрузчик» вирусов. Без разрешения ставить нечем — и не за что
 * подозревать.
 *
 * Сначала спрашиваем API GitHub: там размер файла и коммит тега (по нему видна пересборка той же
 * версии). Но лимит API без входа — 60 запросов в час на адрес, а адрес выхода WARP общий на многих
 * людей: лимит бывает исчерпан чужими запросами. Тогда — запасной путь без API: страница
 * `releases/latest` перенаправляет на тег, а имя файла в релизе известно заранее.
 */
object Updater {

    const val REPO = "kos19191/warp-scout-src"
    private const val API = "https://api.github.com/repos/$REPO"
    private const val WEB = "https://github.com/$REPO"

    data class Release(
        val tag: String,
        val version: String,
        val apkName: String,
        val apkUrl: String,
        /** Размер APK в байтах; 0 — неизвестен (запасной путь без API). */
        val size: Long,
        val sumsUrl: String?,
    )

    sealed class Check {
        data class Newer(val release: Release) : Check()

        /** Та же версия, но в релизе другая сборка (доправка поверх): [remoteRev] — её коммит. */
        data class Rebuild(val release: Release, val remoteRev: String) : Check()
        data class Latest(val version: String) : Check()
        data class NoAsset(val tag: String, val want: String) : Check()
    }

    /** Файл скачался, но контрольная сумма не сошлась с SHA256SUMS.txt релиза. */
    class BadHash : Exception("контрольная сумма не сошлась")

    fun apkName(version: String, flavor: String): String = "WarpScout-$version-$flavor.apk"

    /** Состояние системной загрузки: [status] — DownloadManager.STATUS_*, байты — сколько из скольких. */
    data class Download(val status: Int, val done: Long, val total: Long, val reason: Int)

    fun check(currentVersion: String, buildRev: String, flavor: String): Check {
        val viaApi = runCatching { latestFromApi(flavor) }
        val release = viaApi.getOrNull() ?: latestFromWeb(flavor)
        if (release.apkUrl.isBlank()) return Check.NoAsset(release.tag, apkName(release.version, flavor))
        val cmp = compareVersions(release.version, currentVersion)
        if (cmp > 0) return Check.Newer(release)
        if (cmp < 0) return Check.Latest(currentVersion)
        // Та же версия: доправки пересобирают её поверх (тег переносится). Сравниваем коммит тега
        // с меткой сборки — только если API доступен и сборка из CI (локальная — «local»).
        if (viaApi.isSuccess && buildRev.length >= 7 && buildRev.all { it in '0'..'9' || it in 'a'..'f' }) {
            val sha = runCatching { tagCommit(release.tag) }.getOrNull()
            if (sha != null && sha.length >= 7 && !sha.startsWith(buildRev)) {
                return Check.Rebuild(release, sha.take(7))
            }
        }
        return Check.Latest(currentVersion)
    }

    /** «1.10.31» против «1.10.30»: по числам, недостающие части — нули. */
    fun compareVersions(a: String, b: String): Int {
        fun parts(v: String) = v.trim().removePrefix("v").split('.', '-', '_').map { p -> p.takeWhile { it.isDigit() }.toIntOrNull() ?: 0 }
        val x = parts(a)
        val y = parts(b)
        for (i in 0 until maxOf(x.size, y.size)) {
            val d = (x.getOrElse(i) { 0 }).compareTo(y.getOrElse(i) { 0 })
            if (d != 0) return d
        }
        return 0
    }

    private fun latestFromApi(flavor: String): Release {
        val json = parseJson(get("$API/releases/latest", api = true)) as? JsonVal.Obj
            ?: error("ответ GitHub не разобрался")
        val tag = json.str("tag_name").orEmpty().ifBlank { error("в ответе нет тега") }
        val version = tag.removePrefix("v")
        val assets = json.arr("assets")?.items.orEmpty().mapNotNull { it as? JsonVal.Obj }
        val want = apkName(version, flavor)
        val apk = assets.firstOrNull { it.str("name") == want }
            ?: assets.firstOrNull { it.str("name").orEmpty().endsWith("-$flavor.apk") }
        val sums = assets.firstOrNull { it.str("name") == "SHA256SUMS.txt" }
        return Release(
            tag = tag,
            version = version,
            apkName = apk?.str("name") ?: want,
            apkUrl = apk?.str("browser_download_url").orEmpty(),
            size = apk?.num("size")?.toLong() ?: 0L,
            sumsUrl = sums?.str("browser_download_url"),
        )
    }

    /** Без API: `releases/latest` перенаправляет на `releases/tag/vX`, имена файлов известны. */
    private fun latestFromWeb(flavor: String): Release {
        val conn = (URL("$WEB/releases/latest").openConnection() as HttpURLConnection).apply {
            instanceFollowRedirects = false
            connectTimeout = 10_000
            readTimeout = 10_000
            setRequestProperty("User-Agent", userAgent())
        }
        val location = try {
            conn.responseCode
            conn.getHeaderField("Location").orEmpty()
        } finally {
            runCatching { conn.disconnect() }
        }
        val tag = location.substringAfter("/releases/tag/", "").substringBefore('?').trim()
        if (tag.isBlank()) error("GitHub не назвал последний релиз")
        val version = tag.removePrefix("v")
        val name = apkName(version, flavor)
        return Release(
            tag = tag,
            version = version,
            apkName = name,
            apkUrl = "$WEB/releases/download/$tag/$name",
            size = 0L,
            sumsUrl = "$WEB/releases/download/$tag/SHA256SUMS.txt",
        )
    }

    /** Коммит, на который указывает тег (теги у нас лёгкие — сразу коммит). */
    private fun tagCommit(tag: String): String? {
        val json = parseJson(get("$API/git/ref/tags/$tag", api = true)) as? JsonVal.Obj ?: return null
        return json.obj("object")?.str("sha")
    }

    /**
     * Поставить APK в системную загрузку: файл ляжет в «Загрузки», по окончании Android покажет
     * уведомление «Загрузка завершена». null — системная загрузка недоступна: на Android 8–9 ей
     * нужно разрешение на запись в память, которого у нас нет, — тогда качает браузер
     * ([browserIntent]).
     */
    fun enqueue(context: Context, release: Release): Long? {
        if (Build.VERSION.SDK_INT < 29) return null
        val dm = context.getSystemService(DownloadManager::class.java) ?: return null
        // Тип файла не задаём: GitHub отдаёт его сам (в переадресации на файл релиза стоит
        // response-content-type APK), и по нему нажатие на «Загрузка завершена» открывает установщик.
        val request = DownloadManager.Request(Uri.parse(release.apkUrl))
            .setTitle(release.apkName)
            .setDescription("WarpScout ${release.version}")
            .setNotificationVisibility(DownloadManager.Request.VISIBILITY_VISIBLE_NOTIFY_COMPLETED)
            .setDestinationInExternalPublicDir(Environment.DIRECTORY_DOWNLOADS, release.apkName)
            .addRequestHeader("User-Agent", userAgent())
        return dm.enqueue(request)
    }

    /** Как идёт загрузка [id]; null — её нет (отменили в шторке или удалили файл). */
    fun query(context: Context, id: Long): Download? {
        val dm = context.getSystemService(DownloadManager::class.java) ?: return null
        dm.query(DownloadManager.Query().setFilterById(id))?.use { c ->
            if (!c.moveToFirst()) return null
            fun long(column: String): Long = c.getColumnIndex(column).takeIf { it >= 0 }?.let { c.getLong(it) } ?: 0L
            return Download(
                status = long(DownloadManager.COLUMN_STATUS).toInt(),
                done = long(DownloadManager.COLUMN_BYTES_DOWNLOADED_SO_FAR),
                total = long(DownloadManager.COLUMN_TOTAL_SIZE_BYTES),
                reason = long(DownloadManager.COLUMN_REASON).toInt(),
            )
        }
        return null
    }

    /**
     * Сверить скачанный файл с SHA256SUMS.txt релиза: true — совпало, false — файл испорчен,
     * null — сверить не с чем (списка нет или он не скачался).
     */
    fun verify(context: Context, id: Long, release: Release): Boolean? {
        val expected = release.sumsUrl?.let { url -> runCatching { expectedHash(url, release.apkName) }.getOrNull() }
            ?: return null
        val dm = context.getSystemService(DownloadManager::class.java) ?: return null
        val digest = MessageDigest.getInstance("SHA-256")
        dm.openDownloadedFile(id).use { pfd ->
            java.io.FileInputStream(pfd.fileDescriptor).use { input ->
                val buf = ByteArray(64 * 1024)
                while (true) {
                    val n = input.read(buf)
                    if (n < 0) break
                    digest.update(buf, 0, n)
                }
            }
        }
        val hash = digest.digest().joinToString("") { "%02x".format(it) }
        return expected.equals(hash, ignoreCase = true)
    }

    /** Файл загрузки на месте (его не удалили из «Загрузок» руками). */
    fun fileExists(context: Context, id: Long): Boolean = runCatching {
        context.getSystemService(DownloadManager::class.java)?.openDownloadedFile(id)?.close() != null
    }.getOrDefault(false)

    /** Убрать загрузку вместе с файлом (испорченный файл ставить нельзя). */
    fun remove(context: Context, id: Long) {
        runCatching { context.getSystemService(DownloadManager::class.java)?.remove(id) }
    }

    /** Строка «<sha256>  <имя>» из SHA256SUMS.txt; null — файла нет в списке. */
    private fun expectedHash(url: String, name: String): String? = get(url, api = false)
        .lineSequence()
        .map { it.trim() }
        .firstOrNull { line -> line.split(Regex("\\s+")).lastOrNull()?.removePrefix("*") == name }
        ?.split(Regex("\\s+"))?.firstOrNull()
        ?.takeIf { it.length == 64 }

    /**
     * Список загрузок Android. Нажатие на файл там открывает установщик — и ставит обновление тот,
     * кто открыл файл («Загрузки»), а не WarpScout.
     */
    fun downloadsIntent(): Intent = Intent(DownloadManager.ACTION_VIEW_DOWNLOADS).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)

    /** Android 8–9: скачать браузером (см. [enqueue]). */
    fun browserIntent(release: Release): Intent =
        Intent(Intent.ACTION_VIEW, Uri.parse(release.apkUrl)).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)

    private fun get(url: String, api: Boolean): String {
        val conn = (URL(url).openConnection() as HttpURLConnection).apply {
            instanceFollowRedirects = true
            connectTimeout = 10_000
            readTimeout = 15_000
            setRequestProperty("User-Agent", userAgent())
            if (api) {
                setRequestProperty("Accept", "application/vnd.github+json")
                setRequestProperty("X-GitHub-Api-Version", "2022-11-28")
            }
        }
        try {
            val code = conn.responseCode
            if (code !in 200..299) error("HTTP $code")
            return conn.inputStream.bufferedReader().use { it.readText() }
        } finally {
            runCatching { conn.disconnect() }
        }
    }

    private fun userAgent(): String = "WarpScout/${BuildConfig.VERSION_NAME} (${BuildConfig.FLAVOR})"
}
