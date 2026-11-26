package dev.warpscout.app

import android.content.ActivityNotFoundException
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.view.Gravity
import android.view.View
import android.widget.LinearLayout
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import com.google.android.material.button.MaterialButton
import dev.warpscout.app.databinding.ActivityMainBinding
import dev.warpscout.core.telegram.MtProxy

/**
 * «Прокси для Telegram» (с 1.10.49-beta4, бета): найти публичные прокси MTProto, проверить их до
 * ответа Telegram мимо туннеля ([TgProxies]) и одной кнопкой добавить в Telegram (ссылка
 * tg://proxy — Telegram сам спросит «Подключить прокси?»). Последний список хранится.
 */
class TelegramProxyPanel(
    private val activity: AppCompatActivity,
    private val binding: ActivityMainBinding,
    private val banner: (String, Boolean) -> Unit,
    /** Идёт подбор (он привязывает процесс к сети) — искать не время. */
    private val busy: () -> Boolean,
    private val ownTunnelUp: () -> Boolean,
) {
    @Volatile
    private var running = false

    private fun str(id: Int, vararg args: Any): String = activity.getString(id, *args)

    fun bind() {
        binding.btnTgProxyFind.setOnClickListener {
            runCatching { find() }.onFailure { t ->
                running = false
                TunnelDebug.problem("Telegram: " + SafeMode.describe(t))
                banner(str(R.string.banner_ui_error, SafeMode.describe(t)), true)
            }
        }
        render()
    }

    private fun find() {
        if (running) return
        if (busy()) {
            banner(str(R.string.tg_proxy_busy_scan), false)
            return
        }
        val ownUp = ownTunnelUp()
        val foreign = ForeignVpn.find(activity, ownUp = ownUp)
        if (foreign != null) {
            TunnelDebug.stage("Telegram: поиск прокси не запущен — работает другой VPN ($foreign)")
            banner(str(R.string.tg_proxy_foreign_vpn, foreign), true)
            return
        }
        running = true
        binding.btnTgProxyFind.isEnabled = false
        binding.btnTgProxyFind.setText(R.string.tg_proxy_searching)
        binding.textTgProxyProgress.visibility = View.VISIBLE
        binding.textTgProxyProgress.text = str(R.string.tg_proxy_searching)
        val app = activity.applicationContext
        Thread({
            val result = runCatching {
                TgProxies.find(app, ownUp, progress = { line ->
                    activity.runOnUiThread { if (running) binding.textTgProxyProgress.text = line }
                }, cancelled = { activity.isFinishing || activity.isDestroyed })
            }
            activity.runOnUiThread {
                running = false
                if (activity.isFinishing || activity.isDestroyed) return@runOnUiThread
                runCatching {
                    binding.btnTgProxyFind.isEnabled = true
                    binding.textTgProxyProgress.visibility = View.GONE
                    render()
                    result.onSuccess { r ->
                        if (r.working.isEmpty()) {
                            banner(str(R.string.tg_proxy_none, r.checked), true)
                            binding.textTgProxyNote.visibility = View.VISIBLE
                            binding.textTgProxyNote.text = str(R.string.tg_proxy_none, r.checked) + "\n" + r.note
                        } else {
                            banner(str(R.string.tg_proxy_done, r.working.size), false)
                        }
                    }.onFailure { t ->
                        val why = if (t is DpiCheck.NoBypass) str(R.string.dpi_no_bypass) else SafeMode.describe(t)
                        TunnelDebug.problem("Telegram: прокси найти не удалось — $why")
                        banner(str(R.string.tg_proxy_failed, why), true)
                    }
                }
            }
        }, "warpscout-tgproxy-find").apply { isDaemon = true }.start()
    }

    fun render() {
        val saved = TgProxies.load(activity)
        if (!running) binding.btnTgProxyFind.setText(if (saved == null) R.string.tg_proxy_find else R.string.tg_proxy_refresh)
        val box = binding.tgProxyBox
        box.removeAllViews()
        if (saved == null || saved.working.isEmpty()) {
            binding.textTgProxyHead.visibility = View.GONE
            binding.textTgProxyNote.visibility = View.GONE
            return
        }
        binding.textTgProxyHead.visibility = View.VISIBLE
        binding.textTgProxyHead.text = str(R.string.tg_proxy_head, saved.working.size, saved.label, whenText(saved.at))
        saved.working.forEach { f -> box.addView(row(f)) }
        val stale = System.currentTimeMillis() - saved.at > TgProxies.STALE_MS
        binding.textTgProxyNote.visibility = View.VISIBLE
        binding.textTgProxyNote.text = (if (stale) str(R.string.tg_proxy_stale, whenText(saved.at)) + "\n" else "") + saved.note
    }

    private fun row(f: TgProxies.Found): View {
        val density = activity.resources.displayMetrics.density
        val e = f.entry
        return LinearLayout(activity).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            layoutParams = LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT)
            addView(
                TextView(activity).apply {
                    text = "✓ ${e.server}:${e.port}\n${e.badge} · ${f.pingMs} мс"
                    textSize = 13f
                    setTextColor(ContextCompat.getColor(activity, R.color.check_ok))
                    setPadding(0, (2 * density).toInt(), 0, (2 * density).toInt())
                },
                LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
            )
            addView(
                MaterialButton(activity, null, com.google.android.material.R.attr.materialButtonOutlinedStyle).apply {
                    text = str(R.string.tg_proxy_add)
                    isAllCaps = false
                    setOnClickListener { addToTelegram(e) }
                    setOnLongClickListener { copy(e); true }
                },
                LinearLayout.LayoutParams(LinearLayout.LayoutParams.WRAP_CONTENT, LinearLayout.LayoutParams.WRAP_CONTENT)
            )
            setOnLongClickListener { copy(e); true }
        }
    }

    private fun addToTelegram(e: MtProxy.Entry) {
        TunnelDebug.stage("Telegram: добавляю прокси ${e.server}:${e.port} (${e.badge})")
        try {
            activity.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(e.tgLink)))
        } catch (x: ActivityNotFoundException) {
            copy(e, quiet = true)
            banner(str(R.string.tg_proxy_no_telegram), true)
        } catch (x: Exception) {
            copy(e, quiet = true)
            banner(str(R.string.tg_proxy_no_telegram), true)
        }
    }

    private fun copy(e: MtProxy.Entry, quiet: Boolean = false) {
        runCatching {
            val cm = activity.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
            cm.setPrimaryClip(ClipData.newPlainText("MTProto", e.tmeLink))
        }
        if (!quiet) banner(str(R.string.tg_proxy_copied), false)
    }

    private fun whenText(at: Long): String {
        val d = java.util.Date(at)
        val sameDay = java.text.SimpleDateFormat("yyyyMMdd", java.util.Locale.US).let { it.format(d) == it.format(java.util.Date()) }
        return java.text.SimpleDateFormat(if (sameDay) "HH:mm" else "dd.MM HH:mm", java.util.Locale.getDefault()).format(d)
    }
}
