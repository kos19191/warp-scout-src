package dev.warpscout.app

import android.content.ClipData
import android.content.ClipboardManager
import android.content.ContentValues
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Environment
import android.provider.MediaStore
import androidx.core.content.FileProvider
import dev.warpscout.core.config.WgConf
import dev.warpscout.core.model.WarpConfig
import dev.warpscout.core.report.ConfigExport
import java.io.File

/** Куда и как приложение отдаёт готовый конфиг: файл, шаринг, буфер обмена, Amnezia. */
object ConfigFiles {

    fun dir(context: Context, name: String): File =
        File(context.filesDir, name).apply { mkdirs() }

    fun write(context: Context, cfg: WarpConfig, text: String): File {
        val file = File(dir(context, "configs"), ConfigExport.filename(cfg))
        file.writeText(text)
        return file
    }

    /** То же, но с именем под выбранного клиента (WARP_…_clash.yaml, WARP_…_routes.txt). */
    fun write(context: Context, cfg: WarpConfig, text: String, name: String): File {
        val safe = name.replace(Regex("[^A-Za-z0-9_.-]"), "_")
        val file = File(dir(context, "configs"), safe)
        file.writeText(text)
        return file
    }

    /** Кладёт .conf в «Загрузки» через MediaStore (без разрешений) либо в app-specific каталог. */
    fun saveToDownloads(context: Context, cfg: WarpConfig, text: String, name: String? = null): String =
        saveTextToDownloads(context, name ?: ConfigExport.filename(cfg), text)

    /**
     * Любой текстовый файл — в «Загрузки» (на Android 10+ через MediaStore, без разрешений), на
     * старых версиях — в каталог приложения. Возвращает, где файл теперь лежит.
     */
    fun saveTextToDownloads(context: Context, name2: String, text: String): String {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            val values = ContentValues().apply {
                put(MediaStore.Downloads.DISPLAY_NAME, name2)
                put(MediaStore.Downloads.MIME_TYPE, "text/plain")
                put(MediaStore.Downloads.RELATIVE_PATH, Environment.DIRECTORY_DOWNLOADS)
                put(MediaStore.Downloads.IS_PENDING, 1)
            }
            val resolver = context.contentResolver
            val uri = resolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, values)
            if (uri != null) {
                resolver.openOutputStream(uri)?.use { it.write(text.toByteArray(Charsets.UTF_8)) }
                values.clear()
                values.put(MediaStore.Downloads.IS_PENDING, 0)
                runCatching { resolver.update(uri, values, null, null) }
                return "Загрузки/$name2"
            }
        }
        val out = File(
            context.getExternalFilesDir(Environment.DIRECTORY_DOWNLOADS) ?: dir(context, "configs"),
            name2
        )
        out.writeText(text)
        return out.absolutePath
    }

    fun shareIntent(context: Context, file: File): Intent {
        val uri: Uri = FileProvider.getUriForFile(context, "${context.packageName}.fileprovider", file)
        return Intent.createChooser(
            Intent(Intent.ACTION_SEND).apply {
                type = "text/plain"
                putExtra(Intent.EXTRA_STREAM, uri)
                addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            },
            context.getString(R.string.share_file, file.name)
        ).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
    }

    fun copyToClipboard(context: Context, text: String) {
        val cm = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        cm.setPrimaryClip(ClipData.newPlainText("WARP config", text))
    }

    /** Текст для ручного переноса в AmneziaVPN (инструкция + сам конфиг одним блоком). */
    fun amneziaHandoff(cfg: WarpConfig, text: String): String =
        buildString {
            appendLine(ConfigExport.handoffHint(cfg))
            appendLine()
            appendLine(text)
        }

    fun render(cfg: WarpConfig): String = WgConf.render(cfg)

    /** Рендер под выбранного клиента (AmneziaWG / голый WG / Clash / только маршруты). */
    fun render(cfg: WarpConfig, target: dev.warpscout.core.config.ConfTarget): String =
        WgConf.render(cfg, target)
}
