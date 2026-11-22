package dev.warpscout.app

import android.content.Context
import android.content.Intent
import dev.warpscout.core.json.JsonVal
import dev.warpscout.core.json.parseJson
import java.io.File
import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest

/**
 * «Обновления» (с 1.10.31): только по нажатию — проверить последний релиз на GitHub, скачать APK
 * своей сборки (scout или tunnel) и отдать установщику Android. Ключ подписи у всех версий один,
 * поэтому новая ставится поверх, с настройками.
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
     * Скачать APK в [dir] (старые скачанные удаляются) и сверить с SHA256SUMS.txt релиза, если он
     * есть. [progress] — проценты (или -1, если размер неизвестен).
     */
    fun download(release: Release, dir: File, progress: (Int) -> Unit): File {
        dir.mkdirs()
        dir.listFiles()?.forEach { runCatching { it.delete() } }
        val target = File(dir, release.apkName)
        val part = File(dir, release.apkName + ".part")
        val conn = (URL(release.apkUrl).openConnection() as HttpURLConnection).apply {
            instanceFollowRedirects = true
            connectTimeout = 15_000
            readTimeout = 30_000
            setRequestProperty("User-Agent", userAgent())
        }
        val digest = MessageDigest.getInstance("SHA-256")
        try {
            val code = conn.responseCode
            if (code !in 200..299) error("HTTP $code")
            val total = conn.contentLengthLong.takeIf { it > 0 } ?: release.size
            var done = 0L
            conn.inputStream.use { input ->
                part.outputStream().use { out ->
                    val buf = ByteArray(64 * 1024)
                    while (true) {
                        val n = input.read(buf)
                        if (n < 0) break
                        out.write(buf, 0, n)
                        digest.update(buf, 0, n)
                        done += n
                        progress(if (total > 0) ((done * 100) / total).toInt().coerceIn(0, 100) else -1)
                    }
                }
            }
            if (total > 0 && done != total) error("скачано $done из $total байт")
        } finally {
            runCatching { conn.disconnect() }
        }
        val hash = digest.digest().joinToString("") { "%02x".format(it) }
        val expected = release.sumsUrl?.let { url -> runCatching { expectedHash(url, release.apkName) }.getOrNull() }
        if (expected != null && !expected.equals(hash, ignoreCase = true)) {
            runCatching { part.delete() }
            throw BadHash()
        }
        if (target.exists()) target.delete()
        if (!part.renameTo(target)) {
            part.copyTo(target, overwrite = true)
            part.delete()
        }
        return target
    }

    /** Строка «<sha256>  <имя>» из SHA256SUMS.txt; null — файла нет в списке. */
    private fun expectedHash(url: String, name: String): String? = get(url, api = false)
        .lineSequence()
        .map { it.trim() }
        .firstOrNull { line -> line.split(Regex("\\s+")).lastOrNull()?.removePrefix("*") == name }
        ?.split(Regex("\\s+"))?.firstOrNull()
        ?.takeIf { it.length == 64 }

    /** Установщик Android для скачанного файла (через FileProvider: file:// он не принимает). */
    fun installIntent(context: Context, file: File): Intent {
        val uri = androidx.core.content.FileProvider.getUriForFile(context, "${context.packageName}.fileprovider", file)
        return Intent(Intent.ACTION_VIEW)
            .setDataAndType(uri, "application/vnd.android.package-archive")
            .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_ACTIVITY_NEW_TASK)
    }

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
