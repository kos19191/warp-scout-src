package dev.warpscout.app

import android.app.Activity
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.widget.Toast
import dev.warpscout.core.config.WgConf

/**
 * Отвечает на «Поделиться в WarpScout» (.conf / текст) и на ссылку warp-scout://.
 * Одна задача: сохранить конфиг как запасной, чтобы ключи можно было вообще не запрашивать.
 */
class ImportActivity : Activity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val text = readIncoming()
        val prefs = Prefs(this)
        val message = when {
            text == null -> getString(R.string.import_failed)
            else -> {
                val parsed = runCatching { WgConf.toWarpConfig("import", text) }.getOrNull()
                prefs.manualConf = text
                when {
                    parsed != null -> getString(R.string.import_ok, parsed.endpoint.render(), parsed.junk.name)
                    else -> getString(R.string.import_partial)
                }
            }
        }
        Toast.makeText(this, message, Toast.LENGTH_LONG).show()
        startActivity(
            Intent(this, MainActivity::class.java)
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP)
        )
        finish()
    }

    private fun readIncoming(): String? {
        val data = intent?.data
        if (intent?.action == Intent.ACTION_VIEW && data?.scheme == "warp-scout") {
            return data.getQueryParameter("conf")
        }
        val uri = when (intent?.action) {
            Intent.ACTION_SEND -> intent?.getStringExtra(Intent.EXTRA_TEXT)?.let { return it }
                ?:@Suppress("DEPRECATION") intent?.getParcelableExtra(Intent.EXTRA_STREAM)
            Intent.ACTION_VIEW -> data
            else -> null
        }
        return (uri as? Uri)?.readText()
    }

    private fun Uri.readText(): String? = runCatching {
        contentResolver.openInputStream(this)?.use { it.readBytes().toString(Charsets.UTF_8) }
    }.getOrNull()
}
