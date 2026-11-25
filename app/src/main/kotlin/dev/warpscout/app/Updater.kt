package dev.warpscout.app

import android.app.DownloadManager
import android.content.ContentValues
import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.Uri
import android.os.Build
import android.os.Environment
import android.provider.MediaStore
import androidx.annotation.RequiresApi
import dev.warpscout.core.json.JsonVal
import dev.warpscout.core.json.parseJson
import dev.warpscout.core.net.DownloadRules
import java.io.IOException
import java.net.ConnectException
import java.net.HttpURLConnection
import java.net.SocketTimeoutException
import java.net.URL
import java.net.UnknownHostException
import java.security.MessageDigest
import javax.net.ssl.SSLException

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
 *
 * С 1.10.40 системная загрузка — не единственный путь: встала (ждёт сеть, повторяет попытку, стоит
 * в очереди) — WarpScout качает файл сам, тоже в «Загрузки» ([downloadDirect]); как это решается —
 * в UpdateFlow. Ставит обновление по-прежнему человек нажатием на файл.
 */
object Updater {

    const val REPO = "kos19191/warp-scout-src"
    private const val API = "https://api.github.com/repos/$REPO"
    private const val WEB = "https://github.com/$REPO"

    /** Тип APK: с ним файл в «Загрузках» открывается установщиком. */
    private const val APK_MIME = "application/vnd.android.package-archive"

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

    /**
     * Имя APK в релизе. С 1.10.48 приложение одно и называется WilyScout: «WilyScout-1.10.48.apk»,
     * у беты — «WilyScout-1.10.49-beta1.apk». До неё было две сборки: «WarpScout-<версия>-tunnel.apk»
     * и «…-scout.apk».
     */
    fun apkName(version: String): String = "WilyScout-$version.apk"

    /**
     * Состояние системной загрузки: [status] — DownloadManager.STATUS_*, байты — сколько из скольких,
     * [name] — имя файла в «Загрузках» (Android добавляет «-1», если такое уже есть; «» — неизвестно).
     */
    data class Download(val status: Int, val done: Long, val total: Long, val reason: Int, val name: String = "")

    /**
     * Свой загруженный файл (с 1.10.40, см. [downloadDirect]): [name] — как он называется в
     * «Загрузках» (при совпадении имён Android добавляет « (1)»), [verified] — сошлась ли контрольная
     * сумма (null — сверить было не с чем).
     */
    data class Direct(val uri: Uri, val name: String, val size: Long, val verified: Boolean?)

    fun check(currentVersion: String, buildRev: String): Check {
        // Бета (с 1.10.44-beta1) — отдельное приложение: ей предлагаются только беты, обычные версии — нет.
        if (BuildConfig.BETA) return checkBeta(currentVersion, buildRev)
        val viaApi = runCatching { latestFromApi() }
        val release = viaApi.getOrNull() ?: latestFromWeb()
        if (release.apkUrl.isBlank()) return Check.NoAsset(release.tag, apkName(release.version))
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

    /**
     * Бета: свежая бета — первая (самая новая) из релизов с тегом «v…-betaN». Обычные версии бете не
     * предлагаются: это другое приложение (applicationId с «.beta»), его APK встал бы рядом, а не поверх.
     * Только через API: страница releases/latest пре-релизов не показывает.
     */
    private fun checkBeta(currentVersion: String, buildRev: String): Check {
        val release = latestBetaFromApi()
        if (release.apkUrl.isBlank()) return Check.NoAsset(release.tag, apkName(release.version))
        val cmp = compareBeta(release.version, currentVersion)
        if (cmp > 0) return Check.Newer(release)
        if (cmp < 0) return Check.Latest(currentVersion)
        if (buildRev.length >= 7 && buildRev.all { it in '0'..'9' || it in 'a'..'f' }) {
            val sha = runCatching { tagCommit(release.tag) }.getOrNull()
            if (sha != null && sha.length >= 7 && !sha.startsWith(buildRev)) return Check.Rebuild(release, sha.take(7))
        }
        return Check.Latest(currentVersion)
    }

    private fun latestBetaFromApi(): Release {
        val body = runCatching { get("$API/releases?per_page=30", api = true) }.getOrElse {
            error("бета: GitHub API сейчас не отвечает (без входа — 60 запросов в час на адрес), попробуй позже")
        }
        val items = (parseJson(body) as? JsonVal.Arr)?.items.orEmpty().mapNotNull { it as? JsonVal.Obj }
        val json = items.firstOrNull { o -> o.str("tag_name").orEmpty().contains("-beta") && o.bool("draft") != true }
            ?: error("бета: на странице релизов пока нет бета-версий")
        val tag = json.str("tag_name").orEmpty()
        val version = tag.removePrefix("v")
        val assets = json.arr("assets")?.items.orEmpty().mapNotNull { it as? JsonVal.Obj }
        val want = apkName(version)
        val apk = assets.firstOrNull { it.str("name") == want }
            ?: assets.firstOrNull { it.str("name").orEmpty().endsWith(".apk") }
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

    /**
     * «1.10.44-beta2» против «1.10.44-beta1»: сначала числа версии, потом номер беты. Версия без беты
     * новее любой своей беты (1.10.44 > 1.10.44-beta3).
     */
    fun compareBeta(a: String, b: String): Int {
        fun split(v: String): Pair<String, Int> {
            val t = v.trim().removePrefix("v")
            val base = t.substringBefore("-beta")
            val n = if (t.contains("-beta")) t.substringAfter("-beta").takeWhile { it.isDigit() }.toIntOrNull() ?: 0 else Int.MAX_VALUE
            return base to n
        }
        val (ab, an) = split(a)
        val (bb, bn) = split(b)
        val d = compareVersions(ab, bb)
        return if (d != 0) d else an.compareTo(bn)
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

    private fun latestFromApi(): Release {
        val json = parseJson(get("$API/releases/latest", api = true)) as? JsonVal.Obj
            ?: error("ответ GitHub не разобрался")
        val tag = json.str("tag_name").orEmpty().ifBlank { error("в ответе нет тега") }
        val version = tag.removePrefix("v")
        val assets = json.arr("assets")?.items.orEmpty().mapNotNull { it as? JsonVal.Obj }
        val want = apkName(version)
        val apk = assets.firstOrNull { it.str("name") == want }
            ?: assets.firstOrNull { it.str("name").orEmpty().endsWith(".apk") }
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
    private fun latestFromWeb(): Release {
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
        val name = apkName(version)
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
            .setDescription("WilyScout ${release.version}")
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
            fun text(column: String): String =
                c.getColumnIndex(column).takeIf { it >= 0 }?.let { runCatching { c.getString(it) }.getOrNull() }.orEmpty()
            return Download(
                status = long(DownloadManager.COLUMN_STATUS).toInt(),
                done = long(DownloadManager.COLUMN_BYTES_DOWNLOADED_SO_FAR),
                total = long(DownloadManager.COLUMN_TOTAL_SIZE_BYTES),
                reason = long(DownloadManager.COLUMN_REASON).toInt(),
                // Имя — из адреса файла (file:///…/Download/WarpScout-…-1.apk); адрес вида content://…/123
                // имени не даёт, тогда пусто, и экран называет файл по релизу.
                name = Uri.parse(text(DownloadManager.COLUMN_LOCAL_URI).ifBlank { "x:/" }).lastPathSegment
                    ?.takeIf { it.endsWith(".apk") }.orEmpty(),
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

    /**
     * Убрать свои недоделанные системные загрузки обновлений, кроме [keep] (с 1.10.40), — вместе с
     * недокачанными файлами. В 1.10.38–1.10.39 вставшая загрузка так и висела в очереди и в шторке,
     * а приложение на каждое нажатие отвечало «уже скачивается». Скачанные файлы не трогаем: они в
     * «Загрузках» у человека. Android показывает приложению только его собственные загрузки.
     * Возвращает, сколько убрано.
     */
    fun removeStale(context: Context, keep: Long): Int {
        val dm = context.getSystemService(DownloadManager::class.java) ?: return 0
        val stale = ArrayList<Long>()
        dm.query(DownloadManager.Query())?.use { c ->
            val idCol = c.getColumnIndex(DownloadManager.COLUMN_ID)
            val statusCol = c.getColumnIndex(DownloadManager.COLUMN_STATUS)
            val titleCol = c.getColumnIndex(DownloadManager.COLUMN_TITLE)
            if (idCol < 0 || statusCol < 0) return 0
            while (c.moveToNext()) {
                val id = c.getLong(idCol)
                val title = if (titleCol >= 0) runCatching { c.getString(titleCol) }.getOrNull().orEmpty() else ""
                if (id != keep && c.getInt(statusCol) != DownloadManager.STATUS_SUCCESSFUL &&
                    (title.startsWith("WilyScout-") || title.startsWith("WarpScout-")) && title.endsWith(".apk")
                ) {
                    stale += id
                }
            }
        }
        if (stale.isNotEmpty()) runCatching { dm.remove(*stale.toLongArray()) }
        return stale.size
    }

    /**
     * Состояние системной загрузки словами — так, чтобы читалось после «Системная загрузка …»:
     * «ждёт сеть», «стоит в очереди», «не скачала: обрыв связи». Для журнала и плашки (с 1.10.40):
     * до этого в журнал попадал только код причины, и только когда загрузка сдавалась.
     */
    fun describe(d: Download): String = when (d.status) {
        DownloadManager.STATUS_PENDING -> "стоит в очереди"
        DownloadManager.STATUS_RUNNING -> if (d.done > 0L) "идёт" else "соединяется"
        DownloadManager.STATUS_PAUSED -> when (d.reason) {
            DownloadManager.PAUSED_WAITING_TO_RETRY -> "повторяет попытку после ошибки сети"
            DownloadManager.PAUSED_WAITING_FOR_NETWORK -> "ждёт сеть"
            DownloadManager.PAUSED_QUEUED_FOR_WIFI -> "ждёт Wi-Fi"
            else -> "приостановлена"
        }
        DownloadManager.STATUS_FAILED -> "не скачала: " + when (d.reason) {
            DownloadManager.ERROR_CANNOT_RESUME -> "не продолжить с места обрыва"
            DownloadManager.ERROR_DEVICE_NOT_FOUND -> "нет памяти для «Загрузок»"
            DownloadManager.ERROR_FILE_ALREADY_EXISTS -> "файл уже есть"
            DownloadManager.ERROR_FILE_ERROR -> "ошибка записи файла"
            DownloadManager.ERROR_HTTP_DATA_ERROR -> "обрыв связи"
            DownloadManager.ERROR_INSUFFICIENT_SPACE -> "мало места"
            DownloadManager.ERROR_TOO_MANY_REDIRECTS -> "слишком много переадресаций"
            DownloadManager.ERROR_UNHANDLED_HTTP_CODE -> "неожиданный ответ сервера"
            in 400..599 -> "сервер ответил HTTP ${d.reason}"
            else -> "код ${d.reason}"
        }
        DownloadManager.STATUS_SUCCESSFUL -> "скачала файл"
        else -> "в состоянии ${d.status}"
    }

    /** Почему не скачалось — словами, для экрана и журнала (с 1.10.40). */
    fun explain(t: Throwable?): String = when (t) {
        null -> "причина неизвестна"
        is BadHash -> "файл испорчен (контрольная сумма не сошлась)"
        is UnknownHostException -> "адрес GitHub не нашёлся"
        is SocketTimeoutException -> "GitHub не отвечает"
        is ConnectException -> "соединение с GitHub не установилось"
        is SSLException -> "защищённое соединение с GitHub оборвалось"
        else -> t.message?.takeIf { it.isNotBlank() } ?: t.javaClass.simpleName
    }

    /** Сеть приложения по умолчанию сейчас — VPN (туннель WarpScout или чужой). */
    fun defaultIsVpn(context: Context): Boolean = runCatching {
        val cm = context.getSystemService(ConnectivityManager::class.java) ?: return@runCatching false
        cm.getNetworkCapabilities(cm.activeNetwork ?: return@runCatching false)
            ?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true
    }.getOrDefault(false)

    /**
     * Сеть мимо туннеля — для второй попытки своей загрузки (с 1.10.40): туннель поднят, а данные
     * через него не идут. null — сеть приложения и так не VPN (вторая попытка ничего не даст) или
     * обычной сети нет. Привязаться к ней может только владелец VPN — то есть WarpScout, чей туннель
     * сейчас включён; другой сборке Android откажет, и это просто неудавшаяся попытка.
     */
    fun bypassNetwork(context: Context): Network? = runCatching {
        if (!defaultIsVpn(context)) return@runCatching null
        val cm = context.getSystemService(ConnectivityManager::class.java) ?: return@runCatching null
        @Suppress("DEPRECATION")
        val all = cm.allNetworks.mapNotNull { n -> cm.getNetworkCapabilities(n)?.let { n to it } }
        all.filter { (_, caps) ->
            !caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN) &&
                caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
                caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)
        }.minByOrNull { (_, caps) ->
            // Как выбрала бы система: Wi-Fi, затем Ethernet, затем мобильная.
            when {
                caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> 0
                caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> 1
                else -> 2
            }
        }?.first
    }.getOrNull()

    /**
     * Скачать APK самому, без системной загрузки (с 1.10.40), — в «Загрузки» через MediaStore
     * (Android 10+; разрешений не нужно: файл свой). Нужна, когда системная загрузка встала: так было с
     * 1.10.38 — «пишет, что уже качается, но ничего не происходит». Ставит файл, как и раньше, человек
     * нажатием в «Загрузках»: разрешения «Установка приложений» у WarpScout нет (см. шапку).
     *
     * [network] — через какую сеть (null — как всё приложение: при включённом туннеле через него).
     * Обрыв — докачка с места обрыва (Range), всего до трёх попыток. Пока файл не докачан и не сверен с
     * SHA256SUMS.txt, он помечен «в работе» (IS_PENDING) и в «Загрузках» не виден; не вышло — удаляется.
     * [progress] зовётся из этого же потока на каждый кусок — он должен быть быстрым.
     */
    @RequiresApi(29)
    fun downloadDirect(
        context: Context,
        release: Release,
        network: Network?,
        progress: (done: Long, total: Long) -> Unit,
    ): Direct {
        val expected = release.sumsUrl?.let { url -> runCatching { expectedHash(url, release.apkName, network) }.getOrNull() }
        val resolver = context.contentResolver
        val values = ContentValues().apply {
            put(MediaStore.MediaColumns.DISPLAY_NAME, release.apkName)
            put(MediaStore.MediaColumns.MIME_TYPE, APK_MIME)
            put(MediaStore.MediaColumns.RELATIVE_PATH, Environment.DIRECTORY_DOWNLOADS)
            put(MediaStore.MediaColumns.IS_PENDING, 1)
        }
        val uri = resolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, values)
            ?: error("«Загрузки» не приняли файл")
        var kept = false
        try {
            val digest = MessageDigest.getInstance("SHA-256")
            var written = 0L
            var total = release.size.takeIf { it > 0L } ?: -1L
            val sink = resolver.openOutputStream(uri, "w") ?: error("файл в «Загрузках» не открылся")
            sink.use { out ->
                var attempt = 0
                while (true) {
                    attempt++
                    try {
                        val conn = openGet(release.apkUrl, network, written)
                        try {
                            val code = conn.responseCode
                            val range = conn.getHeaderField("Content-Range")
                            var skip = DownloadRules.skipFor(code, written, DownloadRules.rangeStart(range))
                                ?: error(if (code in 200..299) "сервер продолжил не с того места" else "HTTP $code")
                            DownloadRules.totalFrom(code, conn.contentLengthLong, range, written)
                                .takeIf { it > 0L }?.let { total = it }
                            conn.inputStream.use { input ->
                                val buf = ByteArray(64 * 1024)
                                while (true) {
                                    val n = input.read(buf)
                                    if (n < 0) break
                                    // Сервер начал раньше, чем у нас записано (или с начала): повтор пропускаем.
                                    val from = if (skip > 0L) minOf(skip, n.toLong()).toInt() else 0
                                    skip -= from
                                    if (from == n) continue
                                    out.write(buf, from, n - from)
                                    digest.update(buf, from, n - from)
                                    written += n - from
                                    progress(written, total)
                                }
                            }
                        } finally {
                            runCatching { conn.disconnect() }
                        }
                        if (total > 0L && written < total) throw IOException("связь оборвалась: $written байт из $total")
                        break
                    } catch (e: IOException) {
                        if (attempt >= 3) throw e
                        Thread.sleep(2_000L * attempt)
                    }
                }
                out.flush()
            }
            if (total > 0L && written != total) error("скачано $written байт из $total")
            if (written <= 0L) error("файл пустой")
            val hash = digest.digest().joinToString("") { "%02x".format(it) }
            val verified = expected?.equals(hash, ignoreCase = true)
            if (verified == false) throw BadHash()
            resolver.update(uri, ContentValues().apply { put(MediaStore.MediaColumns.IS_PENDING, 0) }, null, null)
            kept = true
            return Direct(uri, storedName(context, uri) ?: release.apkName, written, verified)
        } finally {
            if (!kept) runCatching { resolver.delete(uri, null, null) }
        }
    }

    /** Свой скачанный файл ещё в «Загрузках»: его размер; −1 — файла нет (удалили). */
    fun storedSize(context: Context, uri: Uri): Long = runCatching {
        context.contentResolver.query(uri, arrayOf(MediaStore.MediaColumns.SIZE), null, null, null)?.use { c ->
            if (c.moveToFirst()) c.getLong(0) else -1L
        } ?: -1L
    }.getOrDefault(-1L)

    private fun storedName(context: Context, uri: Uri): String? = runCatching {
        context.contentResolver.query(uri, arrayOf(MediaStore.MediaColumns.DISPLAY_NAME), null, null, null)?.use { c ->
            if (c.moveToFirst()) c.getString(0) else null
        }
    }.getOrNull()

    private fun openGet(url: String, network: Network?, from: Long): HttpURLConnection {
        val u = URL(url)
        return ((network?.openConnection(u) ?: u.openConnection()) as HttpURLConnection).apply {
            instanceFollowRedirects = true
            connectTimeout = 15_000
            readTimeout = 30_000
            setRequestProperty("User-Agent", userAgent())
            if (from > 0L) setRequestProperty("Range", "bytes=$from-")
        }
    }

    /** Строка «<sha256>  <имя>» из SHA256SUMS.txt; null — файла нет в списке. */
    private fun expectedHash(url: String, name: String, network: Network? = null): String? = get(url, api = false, network = network)
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

    private fun get(url: String, api: Boolean, network: Network? = null): String {
        val u = URL(url)
        val conn = ((network?.openConnection(u) ?: u.openConnection()) as HttpURLConnection).apply {
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

    private fun userAgent(): String = "WilyScout/${BuildConfig.VERSION_NAME}"
}
