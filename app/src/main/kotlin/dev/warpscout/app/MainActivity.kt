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
import androidx.core.widget.doAfterTextChanged
import com.google.android.material.checkbox.MaterialCheckBox
import com.google.android.material.tabs.TabLayout
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
 * Шесть вкладок: первая — быстрый путь («проверить → сгенерировать → подключить») с настройками по
 * умолчанию, остальные пять — то же самое, но по частям, на случай когда быстрый путь не сработал.
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
    private var suppressExportListener = false
    private val listChecks = LinkedHashMap<String, MaterialCheckBox>()
    private val tunnelHandler = android.os.Handler(android.os.Looper.getMainLooper())
    private val lists by lazy { AllowListsRepo(this) }
    private var lastConfigFile: File? = null

    /** Панели вкладок в том же порядке, что и заголовки в [setupTabs]. */
    private lateinit var pages: List<View>
    private val appChecks = LinkedHashMap<String, MaterialCheckBox>()
    private var appEntries: List<AppEntry> = emptyList()

    /** Одна строка списка приложений: только то, что нужно для показа и сохранения. */
    private data class AppEntry(val pkg: String, val label: String, val system: Boolean)
    private var selectedTab = 0

    /** Когда туннель поднялся (мс, локальные часы): от этой точки считаем расход по приложениям. */
    private var tunnelStartedAtLocal = 0L

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        prefs = Prefs(this)
        setupTabs(savedInstanceState?.getInt(STATE_TAB) ?: 0)
        fillFromPrefs()
        buildJunkChecks()
        buildResourceList()
        setupButtons()
        setupApps()
        buildListsChecks()
        refreshRoutesState()
        askNotificationPermission()
        binding.textStatus.setText(R.string.status_idle)
    }

    override fun onResume() {
        super.onResume()
        updateAppsState()
        updateTunnelButton()
        updateTunnelDiagnostics()
        showKeys()
    }

    // ------------------------------------------------------------- заполнение UI

    private fun fillFromPrefs() {
        binding.editHosts.setText(prefs.hostsText)
        binding.editPorts.setText(prefs.portsText)
        binding.editCount.setText(prefs.endpointCount.toString())
        binding.editKeepalive.setText(prefs.keepalive.toString())
        binding.editMtu.setText(prefs.mtu.toString())
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
        suppressExportListener = true
        binding.exportGroup.check(exportButtonId(prefs.confTarget))
        binding.routeGroup.check(routeButtonId(prefs.routesMode))
        suppressExportListener = false
        binding.editServer.setText(prefs.pinnedEndpoint)
        binding.editAllowedIps.setText(prefs.allowedIpsText)
        binding.appsGroup.check(appsButtonId(prefs.appsMode))
        binding.checkListChecks.isChecked = prefs.checkByLists
        binding.textTargetNote.text = prefs.confTargetEnum().note
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
        prefs.enableIpv6 = binding.switchIpv6.isChecked
        prefs.checkResources = binding.switchResources.isChecked
        prefs.verifyInTunnel = binding.switchTunnelVerify.isChecked
        if (binding.dnsSpinner.selectedItemPosition >= 0) prefs.dnsIndex = binding.dnsSpinner.selectedItemPosition
        prefs.poolMode = poolModeOf(binding.poolGroup.checkedButtonId)
        prefs.byedpiProxy = binding.editSocks.text?.toString()?.trim().orEmpty()
        prefs.tuneViaByedpi = binding.switchViaByedpi.isChecked
        prefs.autoApply = binding.checkAutoApply.isChecked
        prefs.confTarget = confTargetOf(binding.exportGroup.checkedButtonId)
        prefs.routesMode = routesModeOf(binding.routeGroup.checkedButtonId)
        prefs.pinnedEndpoint = binding.editServer.text?.toString()?.trim().orEmpty()
        prefs.allowedIpsText = binding.editAllowedIps.text?.toString()?.trim()?.replace("\n", " ").orEmpty()
        prefs.checkByLists = binding.checkListChecks.isChecked
        prefs.allowBlockIds = listChecks.filter { it.value.isChecked && it.key in BLOCK_IDS }.map { it.key }.toSet()
        prefs.allowDirectIds = listChecks.filter { it.value.isChecked && it.key in DIRECT_IDS }.map { it.key }.toSet()
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

    /**
     * Шесть вкладок вместо одной длинной страницы. Первая — «быстрый путь»: проверить,
     * сгенерировать, подключить — с настройками по умолчанию. Остальные нужны только когда
     * быстрый путь не сработал или нужен особый конфиг, поэтому ничего не удалено — всё разложено.
     */
    private fun setupTabs(initial: Int) {
        pages = listOf(
            binding.pageStart, binding.pageScan, binding.pageConfig,
            binding.pageTunnel, binding.pageApps, binding.pageDpi, binding.pageLog
        )
        val titles = listOf(
            R.string.tab_start, R.string.tab_scan, R.string.tab_config,
            R.string.tab_tunnel, R.string.tab_apps, R.string.tab_dpi, R.string.tab_log
        )
        binding.tabs.removeAllTabs()
        titles.forEach { binding.tabs.addTab(binding.tabs.newTab().setText(it)) }
        // TabLayout сам подсветит выбранную вкладку сразу после addTab(0), поэтому панели
        // показываем вручную и тем же вызовом, что и по клику.
        showPage(initial.coerceIn(0, pages.size - 1))
        binding.tabs.addOnTabSelectedListener(object : TabLayout.OnTabSelectedListener {
            override fun onTabSelected(tab: TabLayout.Tab) = showPage(tab.position)
            override fun onTabUnselected(tab: TabLayout.Tab) = Unit
            override fun onTabReselected(tab: TabLayout.Tab) = Unit
        })
    }

    private fun showPage(index: Int) {
        selectedTab = index
        pages.forEachIndexed { i, page -> page.visibility = if (i == index) View.VISIBLE else View.GONE }
        if (binding.tabs.selectedTabPosition != index) binding.tabs.getTabAt(index)?.select()
    }

    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        outState.putInt(STATE_TAB, selectedTab)
    }

    /** «Сгенерировать конфиг» с первого экрана: тот же конфиг, что уйдёт в файл, только на виду. */
    private fun quickGenerate() {
        val cfg = currentConfig()
        if (cfg == null) {
            toast(getString(R.string.err_no_config))
            showPage(TAB_CONFIG)
            return
        }
        binding.textConfig.text = currentConfigText(cfg)
        prefs.lastConfigText = runCatching { WgConf.render(cfg) }.getOrDefault(prefs.lastConfigText)
        showPage(TAB_CONFIG)
        toast(getString(R.string.quick_config_ready))
    }

    // ------------------------------------------------------ приложения в туннеле

    /**
     * Вкладка «Приложения»: то же разделение, что в Amnezia — пустить через туннель только
     * выбранные приложения или все, кроме выбранных. Правило применяется при следующем подключении:
     * `VpnService.Builder.addAllowedApplication/addDisallowedApplication` — это настройка туннеля,
     * а не что-то, что можно менять на лету.
     */
    private fun setupApps() {
        loadApps()
        binding.appsGroup.addOnButtonCheckedListener { _, checkedId, isChecked ->
            if (!isChecked) return@addOnButtonCheckedListener
            prefs.appsMode = appsModeOf(checkedId)
            updateAppsState()
        }
        binding.checkAppsSystem.setOnCheckedChangeListener { _, _ -> rebuildAppsList() }
        binding.editAppSearch.doAfterTextChanged { rebuildAppsList() }
        rebuildAppsList()
    }

    private fun appsModeOf(buttonId: Int): Int = when (buttonId) {
        R.id.btnAppsOnly -> Prefs.APPS_ONLY
        R.id.btnAppsExcept -> Prefs.APPS_EXCEPT
        else -> Prefs.APPS_ALL
    }

    private fun appsButtonId(mode: Int): Int = when (mode) {
        Prefs.APPS_ONLY -> R.id.btnAppsOnly
        Prefs.APPS_EXCEPT -> R.id.btnAppsExcept
        else -> R.id.btnAppsAll
    }

    /** Список только «запускаемых» приложений: библиотеки и сервисы без иконки пользователю не нужны. */
    private fun loadApps() {
        appEntries = runCatching {
            val pm = packageManager
            pm.getInstalledApplications(0).mapNotNull { info ->
                if (info.packageName == packageName) return@mapNotNull null
                if (pm.getLaunchIntentForPackage(info.packageName) == null) return@mapNotNull null
                val system = (info.flags and android.content.pm.ApplicationInfo.FLAG_SYSTEM) != 0
                AppEntry(info.packageName, pm.getApplicationLabel(info).toString(), system)
            }.sortedBy { it.label.lowercase() }
        }.getOrDefault(emptyList())
    }

    private fun rebuildAppsList() {
        binding.appsBox.removeAllViews()
        appChecks.clear()
        val query = binding.editAppSearch.text?.toString()?.trim()?.lowercase().orEmpty()
        val showSystem = binding.checkAppsSystem.isChecked
        val selected = prefs.appsSelected
        val matched = appEntries.filter { app ->
            (showSystem || !app.system) &&
                (query.isEmpty() || app.label.lowercase().contains(query) || app.pkg.contains(query))
        }
        matched.take(APP_ROWS_LIMIT).forEach { app ->
            val row = MaterialCheckBox(this).apply {
                text = if (app.system) "${app.label}  ·  системное" else app.label
                tag = app.pkg
                isChecked = app.pkg in selected
                setOnClickListener { saveAppsSelection() }
                layoutParams = LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.MATCH_PARENT,
                    LinearLayout.LayoutParams.WRAP_CONTENT
                )
            }
            appChecks[app.pkg] = row
            binding.appsBox.addView(row)
        }
        if (matched.isEmpty()) {
            binding.appsBox.addView(
                android.widget.TextView(this).apply {
                    text = getString(R.string.apps_none)
                    textSize = 12f
                }
            )
        } else if (matched.size > APP_ROWS_LIMIT) {
            binding.appsBox.addView(
                android.widget.TextView(this).apply {
                    text = getString(R.string.apps_more, matched.size - APP_ROWS_LIMIT)
                    textSize = 12f
                }
            )
        }
        updateAppsState()
    }

    /** Отметки сохраняем поверх прежнего выбора: отфильтрованные строки не должны «слетать». */
    private fun saveAppsSelection() {
        val merged = prefs.appsSelected.toMutableSet()
        appChecks.forEach { (pkg, cb) -> if (cb.isChecked) merged.add(pkg) else merged.remove(pkg) }
        prefs.appsSelected = merged
        updateAppsState()
    }

    private fun labelOfPackage(pkg: String): String =
        appEntries.firstOrNull { it.pkg == pkg }?.label ?: pkg

    private fun summaryOf(pkgs: Set<String>): String {
        val names = pkgs.sortedBy { labelOfPackage(it) }
        val head = names.take(8).joinToString(", ") { labelOfPackage(it) }
        return if (names.size > 8) "$head и ещё ${names.size - 8}" else head
    }

    private fun updateAppsState() {
        val selected = prefs.appsSelected
        binding.textAppsState.text = when (prefs.appsMode) {
            Prefs.APPS_ONLY ->
                if (selected.isEmpty()) getString(R.string.apps_only_empty)
                else getString(R.string.apps_only_state, selected.size, summaryOf(selected))

            Prefs.APPS_EXCEPT ->
                if (selected.isEmpty()) getString(R.string.apps_except_empty)
                else getString(R.string.apps_except_state, selected.size, summaryOf(selected))

            else -> getString(R.string.apps_all_state)
        }
        binding.textAppsTraffic.text = if (tunnel.supported && tunnel.isUp) {
            getString(
                R.string.apps_traffic,
                getString(
                    R.string.tunnel_bytes,
                    humanBytes(TunnelDebug.bytesUp), humanBytes(TunnelDebug.bytesDown)
                )
            )
        } else {
            getString(R.string.apps_traffic_off)
        }
    }

    private fun humanBytes(value: Long): String = when {
        value < 1024 -> "$value Б"
        value < 1024 * 1024 -> "${value / 1024} КБ"
        else -> String.format(java.util.Locale.getDefault(), "%.1f МБ", value / 1048576.0)
    }

    // ------------------------------------------------ проверки ресурсов (Журнал)

    /**
     * «Что реально открылось» — построчный список проверок с ✓/✗, а не пересказ отчёта.
     * Сюда смотришь, когда сайт «вроде должен работать, но не работает».
     */
    private fun renderResources(results: List<dev.warpscout.core.model.ResourceResult>) {
        binding.resourceResultsBox.removeAllViews()
        if (results.isEmpty()) {
            binding.resourceResultsBox.addView(verdictRow(getString(R.string.resources_off), false))
            return
        }
        results.forEach { r ->
            val via = if (r.via == dev.warpscout.core.model.NetworkVia.TUNNEL) {
                ", " + getString(R.string.resource_via_tunnel)
            } else {
                ""
            }
            val tail = when {
                !r.ok -> ", " + (r.errorClass ?: "нет ответа") + (r.status?.let { " ($it)" } ?: "")
                r.status != null && r.elapsedMs > 0 -> ", ${r.status}, ${r.elapsedMs} мс"
                r.status != null -> ", ${r.status}"
                else -> ""
            }
            binding.resourceResultsBox.addView(
                verdictRow((if (r.ok) "✓ " else "✗ ") + r.check.name + tail + via, r.ok)
            )
        }
    }

    private fun verdictRow(text: String, ok: Boolean): android.widget.TextView =
        android.widget.TextView(this).apply {
            this.text = text
            textSize = 13f
            setPadding(0, 4, 0, 4)
            setTextColor(if (ok) 0xFF2E7D32.toInt() else 0xFFC62828.toInt())
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            )
        }

    // ---------------------------------------------------- расход по приложениям

    /** Без «Доступа к истории использования» Android не отдаёт расход по приложениям. */
    private fun hasUsageAccess(): Boolean = runCatching {
        val ops = getSystemService(android.app.AppOpsManager::class.java)
        val uid = android.os.Process.myUid()
        val op = android.app.AppOpsManager.OPSTR_GET_USAGE_STATS
        val mode = if (android.os.Build.VERSION.SDK_INT >= 29) {
            ops.unsafeCheckOpNoThrow(op, uid, packageName)
        } else {
            @Suppress("DEPRECATION")
            ops.checkOpNoThrow(op, uid, packageName)
        }
        mode == android.app.AppOpsManager.MODE_ALLOWED
    }.getOrDefault(false)

    /**
     * Живой расход по приложениям. Честная оговорка: Android не умеет сказать «сколько ушло
     * именно через туннель», поэтому считаем весь трафик приложения за время, пока туннель поднят.
     * Для полного туннеля это одно и то же, для раздельного — верхняя оценка.
     */
    private fun showAppTraffic() {
        if (!hasUsageAccess()) {
            toast(getString(R.string.apps_traffic_need_access))
            runCatching {
                startActivity(android.content.Intent(android.provider.Settings.ACTION_USAGE_ACCESS_SETTINGS))
            }
            return
        }
        val from = tunnelStartedAtLocal.takeIf { it > 0L } ?: (System.currentTimeMillis() - 3_600_000L)
        val to = System.currentTimeMillis()
        val stats = runCatching { getSystemService(android.app.usage.NetworkStatsManager::class.java) }.getOrNull()
        val rows = mutableListOf<Pair<String, Long>>()
        if (stats != null) {
            val types = listOf(
                android.net.ConnectivityManager.TYPE_MOBILE,
                android.net.ConnectivityManager.TYPE_WIFI
            )
            appEntries.forEach { app ->
                val uid = runCatching { packageManager.getApplicationInfo(app.pkg, 0).uid }.getOrDefault(-1)
                if (uid >= 0) {
                    var bytes = 0L
                    for (type in types) {
                        bytes += runCatching {
                            stats.queryDetailsForUid(type, null, from, to, uid).use { bucketSet ->
                                var sum = 0L
                                while (bucketSet.hasNextBucket()) {
                                    val bucket = android.app.usage.NetworkStats.Bucket()
                                    bucketSet.getNextBucket(bucket)
                                    sum += bucket.rxBytes + bucket.txBytes
                                }
                                sum
                            }
                        }.getOrDefault(0L)
                    }
                    if (bytes > 0L) rows += app.label to bytes
                }
            }
        }
        binding.textAppsTraffic.text = if (rows.isEmpty()) {
            getString(R.string.apps_traffic_none)
        } else {
            buildString {
                appendLine(getString(R.string.apps_traffic_header))
                rows.sortedByDescending { it.second }.take(12).forEach { row ->
                    appendLine("• ${row.first} — ${humanBytes(row.second)}")
                }
            }
        }
    }

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

        binding.btnQuickConfig.setOnClickListener { quickGenerate() }

        binding.btnDpiCompare.setOnClickListener { runDpiCompare() }

        binding.exportGroup.addOnButtonCheckedListener { _, checkedId, isChecked ->
            if (!isChecked || suppressExportListener) return@addOnButtonCheckedListener
            prefs.confTarget = confTargetOf(checkedId)
            binding.textTargetNote.text = dev.warpscout.core.config.ConfTarget.values()[prefs.confTarget].note
            refreshRoutesState()
        }

        binding.routeGroup.addOnButtonCheckedListener { _, checkedId, isChecked ->
            if (!isChecked || suppressExportListener) return@addOnButtonCheckedListener
            prefs.routesMode = routesModeOf(checkedId)
            refreshRoutesState()
        }

        binding.btnPickServer.setOnClickListener { pickServerFromReport() }

        binding.btnRefreshLists.setOnClickListener { refreshLists() }

        binding.btnBuildRoutes.setOnClickListener { buildRoutes() }

        binding.btnTunnelRefresh.setOnClickListener { updateTunnelDiagnostics() }
        binding.btnAppTraffic.setOnClickListener { showAppTraffic() }

        binding.btnTunnelCopy.setOnClickListener {
            ConfigFiles.copyToClipboard(this, TunnelDebug.dump())
            toast(getString(R.string.copied_ok))
        }

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
            val target = prefs.confTargetEnum()
            val send = Intent(Intent.ACTION_SEND).apply {
                type = "text/plain"
                putExtra(
                    Intent.EXTRA_TEXT,
                    getString(R.string.hint_for_target, target.title) + "\n" +
                        ConfigFiles.amneziaHandoff(cfg, text)
                )
            }
            runCatching { startActivity(Intent.createChooser(send, getString(R.string.share_title))) }
                .onFailure { toast(getString(R.string.share_failed)) }
            toast(getString(R.string.copied_ok) + " · " + target.note)
        }

        binding.btnCopy.setOnClickListener {
            val cfg = currentConfig() ?: return@setOnClickListener noConfig()
            ConfigFiles.copyToClipboard(this, currentConfigText(cfg))
            toast(getString(R.string.copied_ok))
        }

        binding.btnSave.setOnClickListener {
            val cfg = currentConfig() ?: return@setOnClickListener noConfig()
            val name = ConfigComposer.fileName(cfg, prefs)
            val path = ConfigFiles.saveToDownloads(this, cfg, currentConfigText(cfg), name)
            lastConfigFile = runCatching { File(ConfigFiles.dir(this, "configs"), name).takeIf { it.exists() } }
                .getOrNull() ?: lastConfigFile
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
                tunnelStartedAtLocal = 0L
                binding.btnTunnel.setText(R.string.btn_tunnel_on)
                return@setOnClickListener
            }
            val cfg = currentConfig() ?: return@setOnClickListener noConfig()
            // Запоминаем именно этот конфиг: плитка быстрых настроек потом поднимет «то же самое»
            // одним нажатием, не собирая конфиг заново и не требуя открывать приложение.
            prefs.lastConfigText = runCatching { WgConf.render(cfg) }.getOrDefault("")
            if (!tunnel.ensurePermission(this)) return@setOnClickListener
            binding.btnTunnel.isEnabled = false
            toast(getString(R.string.tunnel_starting, cfg.endpoint.render()))
            startTunnelPolling()
            Thread {
                // 15 с, а не 25: сервис всё равно продолжает попытки, но пользователь не должен
                // смотреть на «Поднимаю…» полминуты — при быстром рукопожатии ответ придёт за секунды.
                val ok = runCatching { tunnel.startAndAwait(cfg, 15000) }.getOrDefault(false)
                if (ok) tunnelStartedAtLocal = System.currentTimeMillis()
                val why = tunnel.lastError()
                runOnUiThread {
                    binding.btnTunnel.isEnabled = true
                    stopTunnelPolling()
                    updateTunnelButton()
                    updateTunnelDiagnostics()
                    toast(
                        if (ok) getString(R.string.tunnel_up, cfg.endpoint.render())
                        else getString(R.string.tunnel_failed, why ?: "см. журнал ниже")
                    )
                }
            }.apply { isDaemon = true }.start()
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

    /**
     * «Текущий» конфиг — уже с учётом ручного выбора сервера/шума/каналов. И Engine, и кнопки
     * экспорта берут его отсюда, чтобы то, что показано на экране, и то, что легло в файл,
     * не отличались.
     */
    private fun currentConfig(): WarpConfig? =
        (engine.last?.best ?: manualConfig())?.let { ConfigComposer.applyPrefs(it, prefs, prefs.junkPool) }

    private fun currentConfigText(cfg: WarpConfig): String =
        runCatching { ConfigComposer.render(cfg, prefs) }.getOrElse { ConfigFiles.render(cfg) }

    private fun showResult(result: TuningResult) {
        showPage(TAB_START)
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
        binding.textConfig.text = currentConfig()?.let { runCatching { ConfigComposer.render(it, prefs) }.getOrNull() }
            ?: result.configText
            ?: best?.let { ConfigFiles.render(it) }.orEmpty()
        updateServerNote()
        renderResources(result.report.resources)
        binding.textReport.text = runCatching { Report.toMarkdown(result.report) }
            .getOrElse { "Отчёт сломался: ${it.message}" }
        lastConfigFile = engine.storedConfigFile ?: best?.let { cfg ->
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

    // ------------------------------------------------ экспорт/сервер/каналы

    private val BLOCK_IDS get() = dev.warpscout.core.lists.AllowLists.bySide(dev.warpscout.core.lists.ListSide.BLOCK).map { it.id }.toSet()
    private val DIRECT_IDS get() = dev.warpscout.core.lists.AllowLists.bySide(dev.warpscout.core.lists.ListSide.DIRECT).map { it.id }.toSet()

    private fun exportButtonId(target: Int): Int = when (target) {
        1 -> R.id.btnTargetWg
        2 -> R.id.btnTargetClash
        3 -> R.id.btnTargetRoutes
        else -> R.id.btnTargetAmnezia
    }

    private fun confTargetOf(buttonId: Int): Int = when (buttonId) {
        R.id.btnTargetWg -> 1
        R.id.btnTargetClash -> 2
        R.id.btnTargetRoutes -> 3
        else -> 0
    }

    private fun routeButtonId(mode: Int): Int = when (mode) {
        1 -> R.id.btnRoutePreset
        2 -> R.id.btnRouteLists
        3 -> R.id.btnRouteManual
        else -> R.id.btnRouteAll
    }

    private fun routesModeOf(buttonId: Int): Int = when (buttonId) {
        R.id.btnRoutePreset -> 1
        R.id.btnRouteLists -> 2
        R.id.btnRouteManual -> 3
        else -> 0
    }

    /** Чекбоксы категорий allow-domains: слева — что туннелируем, справа — что не трогаем. */
    private fun buildListsChecks() {
        binding.listsBlockBox.removeAllViews()
        binding.listsDirectBox.removeAllViews()
        listChecks.clear()
        val wantBlock = prefs.allowBlockIds
        val wantDirect = prefs.allowDirectIds
        dev.warpscout.core.lists.AllowLists.ALL.forEach { list ->
            val want = if (list.side == dev.warpscout.core.lists.ListSide.BLOCK) wantBlock else wantDirect
            val box = if (list.side == dev.warpscout.core.lists.ListSide.BLOCK) binding.listsBlockBox else binding.listsDirectBox
            val cb = MaterialCheckBox(this).apply {
                text = list.title
                isChecked = list.id in want
                setOnClickListener { refreshRoutesState() }
            }
            listChecks[list.id] = cb
            box.addView(cb)
        }
    }

    private fun refreshRoutesState() {
        val cached = lists.cached()
        val state = buildString {
            append(getString(R.string.routes_state_off, prefs.routesModeName(), "списков в кеше: ${cached.size}"))
            val age = cached.values.map { it.fetchedAt }.maxOrNull() ?: 0L
            if (age > 0L) append(" · ").append(dev.warpscout.core.lists.AllowLists.freshnessOf(age))
            if (prefs.routesMode == 2 && prefs.allowedIpsText.isBlank()) {
                append("\nмаршрутов ещё нет: «Собрать маршруты» (нужен интернет для DoH)")
            }
            if (cached.isEmpty()) append("\nскачай списки — они актуализируются в репозитории, а не в приложении")
        }
        binding.textRoutesState.text = state
    }

    private fun refreshLists() {
        val ids = (listChecks.filter { it.value.isChecked }.keys + DIRECT_IDS).toList()
        if (ids.isEmpty()) {
            toast(getString(R.string.routes_need_lists))
            return
        }
        binding.btnRefreshLists.isEnabled = false
        binding.textRoutesState.setText(R.string.byedpi_compare_running)
        Thread {
            val res = lists.refresh(ids) { line -> runOnUiThread { sink().log(line) } }
            runOnUiThread {
                binding.btnRefreshLists.isEnabled = true
                res.onSuccess { n ->
                    toast(getString(R.string.lists_refreshed, n, ids.size))
                    updateServerNote()
                }.onFailure { toast(getString(R.string.lists_failed, it.message ?: it.javaClass.simpleName)) }
                refreshRoutesState()
            }
        }.apply { isDaemon = true }.start()
    }

    private fun buildRoutes() {
        persistUi()
        if (lists.cached().isEmpty()) {
            toast(getString(R.string.routes_need_lists))
            return
        }
        binding.btnBuildRoutes.isEnabled = false
        binding.textRoutesState.text = "разворачиваю домены в маршруты через DoH…"
        Thread {
            val result = runCatching { lists.buildPlan(prefs) { line -> runOnUiThread { sink().log(line) } } }
            runOnUiThread {
                binding.btnBuildRoutes.isEnabled = true
                result.onSuccess { r ->
                    val summary = lists.savePlan(prefs, r.plan)
                    binding.editAllowedIps.setText(r.plan.allowedIps.replace(", ", ",\n"))
                    binding.routeGroup.check(R.id.btnRouteLists)
                    toast(getString(R.string.routes_built, summary))
                    if (r.missing().isNotEmpty()) {
                        sink().log("не скачано: ${r.missing().joinToString(", ") { it.id }} — нажми «Скачать списки»")
                    }
                }.onFailure {
                    toast(it.message ?: it.javaClass.simpleName)
                }
                refreshRoutesState()
            }
        }.apply { isDaemon = true }.start()
    }

    /** Выбор сервера из отчёта: endpoint + шум + балл, как в таблице, только тапабельно. */
    private fun pickServerFromReport() {
        val report = engine.last?.report
        val cands = report?.candidates.orEmpty()
        if (cands.isEmpty()) {
            toast(getString(R.string.no_report_yet))
            return
        }
        val top = cands.take(12)
        val labels = (listOf("Авто: лучший по баллу") + top.map {
            getString(R.string.server_picked, it.config.endpoint.render(), it.junk.name, it.score)
        }).toTypedArray()
        android.app.AlertDialog.Builder(this)
            .setTitle(R.string.hint_server)
            .setItems(labels) { _, which ->
                if (which == 0) {
                    prefs.pinnedEndpoint = ""
                    prefs.pinnedJunk = ""
                    binding.editServer.setText("")
                    toast(getString(R.string.server_auto))
                } else {
                    val c = top[which - 1]
                    prefs.pinnedEndpoint = c.config.endpoint.render()
                    prefs.pinnedJunk = c.junk.name
                    binding.editServer.setText(c.config.endpoint.render())
                    toast(getString(R.string.server_picked, c.config.endpoint.render(), c.junk.name, c.score))
                }
                updateServerNote()
            }
            .setNegativeButton("Закрыть", null)
            .show()
    }

    private fun updateServerNote() {
        val cfg = currentConfig() ?: return
        binding.textBest.text = getString(
            R.string.best_endpoint, cfg.endpoint.render(), cfg.junk.name,
            engine.last?.report?.best?.score ?: 0
        ) + "\n" + ConfigComposer.explain(cfg, prefs)
    }

    // ------------------------------------------------ диагностика туннеля

    private fun startTunnelPolling() {
        tunnelHandler.removeCallbacks(tunnelPollerTask)
        tunnelHandler.postDelayed(tunnelPollerTask, 400L)
    }

    private fun stopTunnelPolling() = tunnelHandler.removeCallbacks(tunnelPollerTask)

    private val tunnelPollerTask = object : Runnable {
        override fun run() {
            updateTunnelDiagnostics()
            if (tunnel.supported && !tunnel.isUp) tunnelHandler.postDelayed(this, 700L)
        }
    }

    private fun updateTunnelDiagnostics() {
        binding.tunnelDiagBox.visibility = if (tunnel.supported) View.VISIBLE else View.GONE
        if (!tunnel.supported) return
        val dump = tunnel.debugDump()
        val status = when {
            tunnel.isUp -> getString(R.string.tunnel_state_up, TunnelDebug.endpoint.ifBlank { "endpoint неизвестен" })
            TunnelDebug.touched && System.currentTimeMillis() - TunnelDebug.lastStageMs < 30_000L ->
                getString(R.string.tunnel_state_starting)
            TunnelDebug.lastError != null -> getString(R.string.tunnel_state_failed, TunnelDebug.lastError)
            else -> getString(R.string.tunnel_state_idle)
        }
        binding.textTunnelState.text = "$status\n$dump"
        binding.tunnelAdviceBox.removeAllViews()
        TunnelTrouble.advise(dump).forEach { advice ->
            binding.tunnelAdviceBox.addView(
                android.widget.TextView(this).apply {
                    text = "• ${advice.title}: ${advice.whatToDo}"
                    textSize = 12f
                    setPadding(0, 6, 0, 6)
                    layoutParams = LinearLayout.LayoutParams(
                        LinearLayout.LayoutParams.MATCH_PARENT,
                        LinearLayout.LayoutParams.WRAP_CONTENT
                    )
                }
            )
        }
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

        /** Индекс выбранной вкладки переживает поворот экрана. */
        /** Сколько приложений рисуем сразу: остальные — через поиск (иначе экран «залипает»). */
        const val APP_ROWS_LIMIT = 60
        const val STATE_TAB = "warpscout.tab"
        const val TAB_START = 0
        const val TAB_CONFIG = 2
    }
}
