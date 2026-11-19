package dev.warpscout.app

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.view.View
import android.widget.ArrayAdapter
import android.widget.LinearLayout
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import com.google.android.material.checkbox.MaterialCheckBox
import dev.warpscout.app.databinding.ActivityMainBinding
import dev.warpscout.core.config.WgConf
import dev.warpscout.core.junk.JunkLibrary
import dev.warpscout.core.keys.KeySource
import dev.warpscout.core.model.WarpConfig
import dev.warpscout.core.net.WarpDefaults
import dev.warpscout.core.presets.Presets
import dev.warpscout.core.report.ConfigExport
import dev.warpscout.core.report.Report
import dev.warpscout.core.tune.ProgressSink
import dev.warpscout.core.tune.TuningResult
import java.io.File
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Экран один, и он нарочно делает ровно одну вещь: «настроить пул → Подобрать → применить».
 * Всё тяжёлое (подбор, скан, проверка ресурсов, запись файлов) делает [Engine] на своём потоке,
 * сюда прилетают только строки лога и готовый отчёт.
 */
class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding
    private lateinit var prefs: Prefs
    private val engine by lazy { Engine(this) }
    private val tunnel by lazy { TunnelFactory.create(this) }
    private val log = StringBuilder()
    private val cancelled = AtomicBoolean(false)
    private val junkChecks = mutableListOf<MaterialCheckBox>()
    private var lastConfigFile: File? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        prefs = Prefs(this)
        fillFromPrefs()
        buildJunkChecks()
        buildResourceList()
        setupButtons()
        askNotificationPermission()
        binding.textStatus.setText(R.string.status_idle)
    }

    override fun onResume() {
        super.onResume()
        updateTunnelButton()
        showKeys()
    }

    // ------------------------------------------------------------- заполнение UI

    private fun fillFromPrefs() {
        binding.editHosts.setText(prefs.hostsText)
        binding.editPorts.setText(prefs.portsText)
        binding.editCount.setText(prefs.endpointCount.toString())
        binding.editKeepalive.setText(prefs.keepalive.toString())
        binding.editMtu.setText(prefs.mtu.toString())
        binding.switchWhitelist.isChecked = prefs.splitWhitelist
        binding.switchIpv6.isChecked = prefs.enableIpv6
        binding.switchResources.isChecked = prefs.checkResources
        binding.switchTunnelVerify.isChecked = prefs.verifyInTunnel
        binding.switchTunnelVerify.isEnabled = tunnel.supported
        binding.dnsSpinner.adapter = ArrayAdapter(
            this, android.R.layout.simple_spinner_dropdown_item,
            Presets.DNS.map { "${it.name} — ${it.servers.joinToString(", ")}" }
        )
        binding.dnsSpinner.setSelection(prefs.dnsIndex.coerceIn(0, (Presets.DNS.size - 1).coerceAtLeast(0)))
        binding.btnSchedule.setText(if (prefs.scheduleOn) R.string.btn_schedule_off else R.string.btn_schedule)
        binding.btnTunnel.isEnabled = tunnel.supported
        if (!tunnel.supported) binding.btnTunnel.setText(R.string.tunnel_unavailable)
    }

    /** Собрать значения с экрана и сохранить — все настройки живут в Prefs, чтобы их видел WorkManager. */
    private fun persistUi() {
        prefs.hostsText = binding.editHosts.text?.toString()?.trim().orEmpty()
        prefs.portsText = binding.editPorts.text?.toString()?.trim().orEmpty()
        binding.editCount.text?.toString()?.toIntOrNull()?.let { prefs.endpointCount = it }
        binding.editKeepalive.text?.toString()?.toIntOrNull()?.let { prefs.keepalive = it }
        binding.editMtu.text?.toString()?.toIntOrNull()?.let { prefs.mtu = it }
        prefs.splitWhitelist = binding.switchWhitelist.isChecked
        prefs.enableIpv6 = binding.switchIpv6.isChecked
        prefs.checkResources = binding.switchResources.isChecked
        prefs.verifyInTunnel = binding.switchTunnelVerify.isChecked
        if (binding.dnsSpinner.selectedItemPosition >= 0) prefs.dnsIndex = binding.dnsSpinner.selectedItemPosition
        prefs.enabledJunk = junkChecks.filter { it.isChecked }.map { it.tag.toString() }.toSet()
    }

    private fun buildJunkChecks() {
        binding.junkBox.removeAllViews()
        junkChecks.clear()
        val enabled = prefs.enabledJunk
        JunkLibrary.defaultPool().forEach { profile ->
            val box = MaterialCheckBox(this).apply {
                text = "${profile.name}   ·   ${profile.note}"
                tag = profile.name
                isChecked = enabled.isEmpty() || profile.name in enabled
                layoutParams = LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.MATCH_PARENT,
                    LinearLayout.LayoutParams.WRAP_CONTENT
                )
            }
            junkChecks += box
            binding.junkBox.addView(box)
        }
    }

    private fun buildResourceList() {
        binding.resourceBox.removeAllViews()
        Presets.RESOURCE_CHECKS.forEach { check ->
            binding.resourceBox.addView(
                android.widget.TextView(this).apply {
                    text = "• ${check.name}"
                    textSize = 12f
                    layoutParams = LinearLayout.LayoutParams(
                        LinearLayout.LayoutParams.MATCH_PARENT,
                        LinearLayout.LayoutParams.WRAP_CONTENT
                    )
                }
            )
        }
    }

    private fun showKeys() {
        val raw = runCatching { KeyVault(this).accountStore().load() }.getOrNull()
        val account = raw?.let { KeySource.parseAccount(it, "кеш") }
        binding.textKeys.text = if (account == null) {
            getString(R.string.keys_source, "ключей ещё нет — появятся после первого подбора")
        } else {
            val kind = if (KeySource.looksLikeCurve25519(account.privateB64)) "Curve25519" else "EC (MASQUE)"
            getString(R.string.keys_source, "кеш: $kind, peer ${account.peerPublicB64.take(10)}…")
        }
    }

    // ---------------------------------------------------------------- кнопки

    private fun setupButtons() {
        binding.btnRun.setOnClickListener {
            persistUi()
            log.setLength(0)
            binding.textLog.text = ""
            cancelled.set(false)
            binding.progress.visibility = View.VISIBLE
            binding.progress.isIndeterminate = true
            binding.textStatus.setText(R.string.status_running)
            engine.start(prefs.tuningSpec(), manualConfig(), sink()) { result, error ->
                binding.progress.visibility = View.GONE
                when {
                    error != null -> binding.textStatus.text = "Ошибка: $error"
                    result == null -> binding.textStatus.setText(R.string.status_cancelled)
                    else -> showResult(result)
                }
            }
        }

        binding.btnStop.setOnClickListener {
            cancelled.set(true)
            engine.cancel()
            binding.textStatus.setText(R.string.status_cancelled)
        }

        binding.btnPoolDefault.setOnClickListener {
            binding.editHosts.setText("")
            binding.editPorts.setText("")
            binding.editCount.setText("120")
            toast("Берём пул самого генератора: подсети Cloudflare × 52 порта (500…8886)")
        }

        binding.btnPoolMasque.setOnClickListener {
            binding.editHosts.setText(WarpDefaults.MASQUE_SUBNETS.joinToString(", ") { "$it*" })
            binding.editPorts.setText(WarpDefaults.MASQUE_PORTS.joinToString(", "))
            binding.editCount.setText("60")
            toast("MASQUE слушает на 443/8443/… — их мы проверяем TLS'ом, а не UDP-хэндшейком")
        }

        binding.btnPoolFull.setOnClickListener {
            binding.editHosts.setText("")
            binding.editPorts.setText("")
            binding.editCount.setText("1500")
            toast("Полный перебор: подсеть × октет × порт. Долго, но видно всю картину")
        }

        binding.btnSchedule.setOnClickListener {
            persistUi()
            if (prefs.scheduleOn) {
                Schedule.disable(this)
                prefs.scheduleOn = false
                binding.btnSchedule.setText(R.string.btn_schedule)
                toast(getString(R.string.schedule_off))
            } else {
                Schedule.enable(this)
                prefs.scheduleOn = true
                binding.btnSchedule.setText(R.string.btn_schedule_off)
                toast(getString(R.string.schedule_on))
            }
        }

        binding.btnExportAmnezia.setOnClickListener {
            val cfg = currentConfig() ?: return@setOnClickListener noConfig()
            val text = currentConfigText(cfg)
            ConfigFiles.copyToClipboard(this, text)
            val send = Intent(Intent.ACTION_SEND).apply {
                type = "text/plain"
                putExtra(Intent.EXTRA_TEXT, ConfigFiles.amneziaHandoff(cfg, text))
            }
            runCatching { startActivity(Intent.createChooser(send, getString(R.string.share_title))) }
                .onFailure { toast(getString(R.string.share_failed)) }
            toast(getString(R.string.copied_ok) + " · " + getString(R.string.amnezia_hint))
        }

        binding.btnCopy.setOnClickListener {
            val cfg = currentConfig() ?: return@setOnClickListener noConfig()
            ConfigFiles.copyToClipboard(this, currentConfigText(cfg))
            toast(getString(R.string.copied_ok))
        }

        binding.btnSave.setOnClickListener {
            val cfg = currentConfig() ?: return@setOnClickListener noConfig()
            val path = ConfigFiles.saveToDownloads(this, cfg, currentConfigText(cfg))
            toast(getString(R.string.saved_ok, path))
        }

        binding.btnShare.setOnClickListener {
            val cfg = currentConfig() ?: return@setOnClickListener noConfig()
            val file = lastConfigFile
                ?: runCatching { ConfigFiles.write(this, cfg, currentConfigText(cfg)) }.getOrNull()
            if (file == null) {
                toast(getString(R.string.err_no_config))
            } else {
                runCatching { startActivity(Intent.createChooser(ConfigFiles.shareIntent(this, file), getString(R.string.share_title))) }
                    .onFailure { toast(getString(R.string.share_failed)) }
            }
        }

        binding.btnTunnel.setOnClickListener {
            if (!tunnel.supported) {
                toast(getString(R.string.tunnel_unavailable))
                return@setOnClickListener
            }
            if (tunnel.isUp) {
                tunnel.stop()
                binding.btnTunnel.setText(R.string.btn_tunnel_on)
                return@setOnClickListener
            }
            val cfg = currentConfig() ?: return@setOnClickListener noConfig()
            if (!tunnel.ensurePermission(this)) return@setOnClickListener
            if (tunnel.start(cfg)) {
                binding.btnTunnel.setText(R.string.btn_tunnel_off)
                toast("Туннель поднимается: ${cfg.endpoint.render()}")
            } else {
                toast(tunnel.status.ifBlank { getString(R.string.tunnel_unavailable) })
            }
        }
    }

    /** Приёмник прогресса: ядро зовёт его из своего потока, поэтому всё в runOnUiThread. */
    private fun sink(): ProgressSink = object : ProgressSink {
        override fun isCancelled(): Boolean = cancelled.get()

        override fun log(message: String) = runOnUiThread {
            if (log.isNotEmpty()) log.append('\n')
            log.append(message)
            if (log.length > 30000) log.delete(0, log.length - 30000)
            binding.textLog.text = log.toString()
        }

        override fun progress(done: Int, total: Int, current: String) = runOnUiThread {
            binding.progress.isIndeterminate = total <= 0
            if (total > 0) {
                binding.progress.max = total
                binding.progress.progress = done
            }
            binding.textStatus.text = "[$done/$total] $current"
        }
    }

    // ----------------------------------------------------------------- итог

    private fun manualConfig(): WarpConfig? = prefs.manualConf
        .takeIf { it.isNotBlank() }
        ?.let { runCatching { WgConf.toWarpConfig("импорт", it) }.getOrNull() }

    private fun currentConfig(): WarpConfig? = engine.last?.best ?: manualConfig()

    private fun currentConfigText(cfg: WarpConfig): String =
        engine.last?.configText?.takeIf { it.isNotBlank() } ?: ConfigFiles.render(cfg)

    private fun showResult(result: TuningResult) {
        binding.textStatus.setText(R.string.status_done)
        val best = result.best
        binding.textBest.text = best?.let {
            getString(R.string.best_endpoint, it.endpoint.render(), it.junk.name, result.report.best?.score ?: 0)
        } ?: "Живых endpoint'ов не нашлось. Увеличьте число точек, включите MASQUE и попробуйте ещё раз."
        binding.textKeys.text = getString(R.string.keys_source, result.accountSource)
        binding.textConfig.text = result.configText ?: best?.let { ConfigFiles.render(it) }.orEmpty()
        binding.textReport.text = runCatching { Report.toMarkdown(result.report) }
            .getOrElse { "Отчёт сломался: ${it.message}" }
        lastConfigFile = best?.let { cfg ->
            runCatching { File(ConfigFiles.dir(this, "configs"), ConfigExport.filename(cfg)) }
                .getOrNull()?.takeIf { it.exists() }
        }
        showKeys()
    }

    private fun updateTunnelButton() {
        if (!tunnel.supported) {
            binding.btnTunnel.isEnabled = false
            binding.btnTunnel.setText(R.string.tunnel_unavailable)
            return
        }
        binding.btnTunnel.isEnabled = true
        binding.btnTunnel.setText(if (tunnel.isUp) R.string.btn_tunnel_off else R.string.btn_tunnel_on)
    }

    private fun noConfig() {
        toast(getString(R.string.err_no_config))
    }

    private fun toast(text: String) = Toast.makeText(this, text, Toast.LENGTH_LONG).show()

    private fun askNotificationPermission() {
        if (Build.VERSION.SDK_INT >= 33 &&
            ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) !=
            PackageManager.PERMISSION_GRANTED
        ) {
            runCatching { requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), 10) }
        }
    }
}
