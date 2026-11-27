package dev.warpscout.netdiag

import android.content.Intent
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.View
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.FileProvider
import com.google.android.material.button.MaterialButton
import com.google.android.material.progressindicator.LinearProgressIndicator
import java.io.File
import java.util.concurrent.atomic.AtomicBoolean

class MainActivity : AppCompatActivity() {

    private lateinit var tvNetworkBrief: TextView
    private lateinit var tvStatus: TextView
    private lateinit var progressBar: LinearProgressIndicator
    private lateinit var btnCheck: MaterialButton
    private lateinit var btnShare: MaterialButton
    private lateinit var tvPreview: TextView

    private val mainHandler = Handler(Looper.getMainLooper())
    private val running = AtomicBoolean(false)
    private val cancelled = AtomicBoolean(false)
    private var lastReportFile: File? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        tvNetworkBrief = findViewById(R.id.tvNetworkBrief)
        tvStatus = findViewById(R.id.tvStatus)
        progressBar = findViewById(R.id.progressBar)
        btnCheck = findViewById(R.id.btnCheck)
        btnShare = findViewById(R.id.btnShare)
        tvPreview = findViewById(R.id.tvPreview)

        refreshNetworkBrief()

        btnCheck.setOnClickListener {
            if (running.get()) {
                cancelled.set(true)
                tvStatus.text = "Останавливаю проверку…"
            } else {
                startScan()
            }
        }

        btnShare.setOnClickListener {
            shareSavedReport()
        }
    }

    override fun onResume() {
        super.onResume()
        if (!running.get()) refreshNetworkBrief()
    }

    private fun refreshNetworkBrief() {
        tvNetworkBrief.text = runCatching { AndroidNetworkCollector.briefStatus(this) }
            .getOrDefault("Сеть: не удалось определить")
    }

    private fun startScan() {
        if (!running.compareAndSet(false, true)) return
        cancelled.set(false)
        lastReportFile = null

        refreshNetworkBrief()
        btnCheck.text = getString(R.string.btn_stop)
        btnShare.visibility = View.GONE
        progressBar.visibility = View.VISIBLE
        progressBar.progress = 0
        tvStatus.text = "Запуск диагностики…"
        tvPreview.text = "Сканирую Wi-Fi, DNS, Telegram, Meta, YouTube, QUIC и UDP…"

        Thread({
            try {
                val engine = DiagEngine(applicationContext)
                val report = engine.runFullScan(cancelled) { prog ->
                    mainHandler.post {
                        progressBar.progress = prog.percent
                        tvStatus.text = "${prog.percent}% · ${prog.currentLabel}"
                    }
                }
                val file = saveReportTxt(report)
                mainHandler.post {
                    running.set(false)
                    btnCheck.text = getString(R.string.btn_check)
                    progressBar.visibility = View.GONE
                    lastReportFile = file
                    tvNetworkBrief.text = AndroidNetworkCollector.briefStatus(this)
                    if (cancelled.get()) {
                        tvStatus.text = "Проверка остановлена. Частичный отчёт сохранён (${file.name})."
                    } else {
                        tvStatus.text = "Готово за ${String.format("%.1f", report.durationMs / 1000.0)} с · файл ${file.name}"
                    }
                    tvPreview.text = report.renderShortSummary()
                    btnShare.visibility = View.VISIBLE
                }
            } catch (e: Exception) {
                mainHandler.post {
                    running.set(false)
                    btnCheck.text = getString(R.string.btn_check)
                    progressBar.visibility = View.GONE
                    tvStatus.text = "Ошибка проверки: ${e.message}"
                    tvPreview.text = e.stackTraceToString().take(1500)
                }
            }
        }, "wilydiag-main").apply {
            isDaemon = true
            start()
        }
    }

    private fun saveReportTxt(report: FullDiagReport): File {
        val dir = File(cacheDir, "reports").apply { mkdirs() }
        // Удаляем старые отчёты старше 10 штук, чтобы не копить мусор в кэше.
        dir.listFiles()?.sortedByDescending { it.lastModified() }?.drop(10)?.forEach { runCatching { it.delete() } }
        val file = File(dir, "wilydiag-${FullDiagReport.fileTimestamp()}.txt")
        file.writeText(report.renderTxt(), Charsets.UTF_8)
        return file
    }

    private fun shareSavedReport() {
        val file = lastReportFile
        if (file == null || !file.exists()) {
            Toast.makeText(this, "Сначала запустите проверку", Toast.LENGTH_SHORT).show()
            return
        }
        try {
            val uri = FileProvider.getUriForFile(this, "${packageName}.fileprovider", file)
            val intent = Intent(Intent.ACTION_SEND).apply {
                type = "text/plain"
                putExtra(Intent.EXTRA_STREAM, uri)
                putExtra(Intent.EXTRA_SUBJECT, "Отчёт диагностики сети WilyDiag (${file.name})")
                addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            }
            startActivity(Intent.createChooser(intent, getString(R.string.share_chooser_title)))
        } catch (e: Exception) {
            Toast.makeText(this, "Не удалось открыть отправку: ${e.message}", Toast.LENGTH_LONG).show()
        }
    }
}
