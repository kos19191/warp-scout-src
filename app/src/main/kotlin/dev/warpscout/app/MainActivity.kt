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
import android.net.Uri
import dev.warpscout.core.config.WgConf
import dev.warpscout.core.dpi.DpiComparator
import dev.warpscout.core.dpi.DpiComparison
import dev.warpscout.core.dpi.DpiOutcome
import dev.warpscout.core.model.ResourceCheck
import dev.warpscout.core.net.Socks5Endpoint
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
    private var runStartedAt = 0L
    private var endpointBeforeRun = ""
    private var suppressPoolListener = false
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

        binding.poolGroup.check(poolButtonId(prefs.poolMode))
        binding.checkAutoApply.isEnabled = tunnel.supported
        binding.checkAutoApply.isChecked = prefs.autoApply && tunnel.supported
        binding.checkAutoApply.text = getString(
            if (tunnel.supported) R.string.check_auto_apply else R.string.check_auto_apply_off
        )
        binding.editSocks.setText(prefs.byedpiProxy)
        binding.switchViaByedpi.isChecked = prefs.tuneViaByedpi
        binding.textByedpiState.text = byedpiState()
        updatePoolSummary()
        showLastRun()
        binding.textNetwork.text = CleanNetwork.statusLine(this)
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
        prefs.poolMode = poolModeOf(binding.poolGroup.checkedButtonId)
        prefs.byedpiProxy = binding.editSocks.text?.toString()?.trim().orEmpty()
        prefs.tuneViaByedpi = binding.switchViaByedpi.isChecked
        prefs.autoApply = binding.checkAutoApply.isChecked
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
            runStartedAt = System.currentTimeMillis()
            endpointBeforeRun = prefs.lastTunedEndpoint
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

        binding.btnDpiCompare.setOnClickListener { runDpiCompare() }

        binding.btnStop.setOnClickListener {
            cancelled.set(true)
            engine.cancel()
            binding.textStatus.setText(R.string.status_cancelled)
        }

        binding.poolGroup.addOnButtonCheckedListener { _, checkedId, isChecked ->
            if (!isChecked) return@addOnButtonCheckedListener
            val mode = poolModeOf(checkedId)
            when (mode) {
                Prefs.POOL_MASQUE -> {
                    binding.editHosts.setText(WarpDefaults.MASQUE_SUBNETS.joinToString(", ") { "$it*" })
                    binding.editPorts.setText(WarpDefaults.MASQUE_PORTS.joinToString(", "))
                    binding.editCount.setText("60")
                    toast("MASQUE слушает на 443/8443/… — их проверяем TLS'ом, а не UDP-хэндшейком")
                }
                Prefs.POOL_FULL -> {
                    binding.editHosts.setText("")
                    binding.editPorts.setText("")
                    binding.editCount.setText("1500")
                    toast("Полный перебор: подсеть × октет × порт. Долго, но видно всю картину")
                }
                else -> {
                    binding.editHosts.setText("")
                    binding.editPorts.setText("")
                    binding.editCount.setText("120")
                    toast("Берём пул самого генератора: подсети Cloudflare × 52 порта")
                }
            }
            prefs.poolMode = mode
            updatePoolSummary()
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
        val took = humanDuration(System.currentTimeMillis() - runStartedAt)
        val hhmm = java.text.SimpleDateFormat("HH:mm", java.util.Locale.getDefault())
        val time = hhmm.format(java.util.Date(prefs.lastTunedAt))
        val bestNow = result.best?.endpoint?.render()
        binding.textDone.text = when {
            // сменой считается только случай, когда endpoint реально другой, чем до этого запуска
            bestNow != null && endpointBeforeRun.isNotBlank() && bestNow != endpointBeforeRun ->
                getString(R.string.done_new, time, hhmm.format(java.util.Date(prefs.lastChangedAt)))
            bestNow != null && bestNow == endpointBeforeRun -> getString(R.string.done_same, time)
            else -> getString(R.string.done_ok, time, took)
        }
        binding.textNetwork.text = CleanNetwork.statusLine(this)
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

    private fun poolButtonId(mode: Int): Int = when (mode) {
        Prefs.POOL_MASQUE -> R.id.btnPoolMasque
        Prefs.POOL_FULL -> R.id.btnPoolFull
        else -> R.id.btnPoolDefault
    }

    private fun poolModeOf(buttonId: Int): Int = when (buttonId) {
        R.id.btnPoolMasque -> Prefs.POOL_MASQUE
        R.id.btnPoolFull -> Prefs.POOL_FULL
        else -> Prefs.POOL_DEFAULT
    }

    /** Явная строчка «что именно я выбрал» — сколько сетей, портов и точек реально пойдёт в скан. */
    private fun updatePoolSummary() {
        persistUi()
        val spec = prefs.endpointSpec()
        val explicit = prefs.hostsText.isNotBlank()
        val count = runCatching { dev.warpscout.core.net.EndpointPool.build(spec).size }.getOrDefault(0)
        binding.textPoolSummary.text = if (explicit) {
            getString(R.string.pool_summary_explicit, count)
        } else {
            getString(R.string.pool_summary_default, prefs.poolModeName(), spec.subnets.size, spec.ports.size, count)
        }
    }

    /** «Готово в 14:32» + «это новый конфиг» — чтобы по экрану было видно результат и его свежесть. */
    private fun showLastRun() {
        val at = prefs.lastTunedAt
        if (at <= 0L) {
            binding.textDone.setText(R.string.done_never)
            return
        }
        val time = java.text.SimpleDateFormat("HH:mm", java.util.Locale.getDefault()).format(java.util.Date(at))
        val ago = humanDuration(System.currentTimeMillis() - at)
        val stale = System.currentTimeMillis() - at > 6L * 3600_000L
        binding.textDone.text = getString(if (stale) R.string.done_last_stale else R.string.done_last, time, ago)
    }

    private fun humanDuration(ms: Long): String {
        val s = (ms / 1000).coerceAtLeast(0)
        return when {
            s < 60 -> getString(R.string.duration_sec, s.toInt())
            s < 3600 -> getString(R.string.duration_min, (s / 60).toInt())
            else -> getString(R.string.duration_hours, (s / 3600).toInt(), ((s % 3600) / 60).toInt())
        }
    }

    /** Есть ли на устройстве ByeDPI и в каком режиме он нам поможет. */
    private fun byedpiState(): String {
        val installed = runCatching {
            packageManager.getPackageInfo(BYEDPI_PACKAGE, 0)
            true
        }.getOrDefault(false)
        val proxy = Socks5Endpoint.parse(prefs.byedpiProxy.ifBlank { Socks5Endpoint.BYEDPI_DEFAULT.render() })
        val alive = proxy != null && threadProxyAlive(proxy)
        return when {
            installed && alive -> "ByeDPI установлен, SOCKS5 на ${proxy?.render()} отвечает — можно сравнивать"
            installed -> "ByeDPI установлен, но ${proxy?.render() ?: "SOCKS5"} не отвечает: включи режим прокси (не VPN)"
            alive -> "ByeDPI не найден среди приложений, но SOCKS5 на ${proxy?.render()} отвечает — сравниваем"
            else -> getString(R.string.byedpi_not_installed)
        }
    }

    private fun threadProxyAlive(proxy: Socks5Endpoint): Boolean = runCatching {
        java.net.Socket().apply {
            connect(java.net.InetSocketAddress(proxy.host, proxy.port), 400)
            close()
        }
        true
    }.getOrDefault(false)

    /**
     * «Что режет: DPI или IP?» — одна и та же пачка ресурсов мерится напрямую и через SOCKS5 ByeDPI.
     * Идём по своему же потоку: сравнение сетевое, по UI-потоку оно бы заблочило экран на десятки секунд.
     */
    private fun runDpiCompare() {
        persistUi()
        val proxy = Socks5Endpoint.parse(prefs.byedpiProxy)
        if (proxy == null) {
            toast(getString(R.string.hint_socks))
            binding.textByedpiState.text = byedpiState()
            return
        }
        binding.btnDpiCompare.isEnabled = false
        binding.textByedpiState.setText(R.string.byedpi_compare_running)
        val checks = Presets.RESOURCE_CHECKS
        Thread {
            val cmp = runCatching { DpiComparator().compare(checks, proxy) }
            runOnUiThread {
                binding.btnDpiCompare.isEnabled = true
                val comparison = cmp.getOrNull()
                if (comparison == null) {
                    binding.textByedpiState.text =
                        "Сравнение не вышло: ${cmp.exceptionOrNull()?.let { it.javaClass.simpleName }} " +
                            "(${cmp.exceptionOrNull()?.message?.take(120)})"
                    return@runOnUiThread
                }
                binding.textByedpiState.text = renderComparison(comparison)
                val saved = runCatching {
                    val file = File(ConfigFiles.dir(this, "reports"), "byedpi-compare.txt")
                    file.writeText(comparison.renderText())
                    file.absolutePath
                }.getOrNull()
                if (saved != null) toast(getString(R.string.byedpi_saved, saved))
                sink().log("byedpi: ${comparison.headline()}")
            }
        }.apply { isDaemon = true }.start()
    }

    private fun renderComparison(cmp: DpiComparison): String = buildString {
        append(cmp.headline())
        if (!cmp.usable) return@buildString
        appendLine()
        cmp.rows.groupBy { it.outcome }.forEach { (outcome, rows) ->
            appendLine("${getString(labelFor(outcome))} — ${rows.size}: ${rows.joinToString(", ") { it.name }}")
        }
    }

    private fun labelFor(outcome: DpiOutcome): Int = when (outcome) {
        DpiOutcome.OPEN_BOTH -> R.string.dpi_outcome_open_both
        DpiOutcome.OPEN_ONLY_VIA_PROXY -> R.string.dpi_outcome_dpi
        DpiOutcome.OPEN_ONLY_DIRECT -> R.string.dpi_outcome_proxy_bad
        DpiOutcome.BLOCKED_BOTH -> R.string.dpi_outcome_ip
        DpiOutcome.PROXY_UNREACHABLE -> R.string.dpi_outcome_no_proxy
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

    private companion object {
        /** Пакет ByeDPI for Android — нужен только чтобы подсказать «установлено/не установлено». */
        const val BYEDPI_PACKAGE = "io.github.dovecoteescapee.byedpi"
    }
}
