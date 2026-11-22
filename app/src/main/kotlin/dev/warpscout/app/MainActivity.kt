package dev.warpscout.app

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.view.MotionEvent
import android.view.View
import android.widget.ArrayAdapter
import android.widget.LinearLayout
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.core.widget.NestedScrollView
import androidx.core.widget.doAfterTextChanged
import com.google.android.material.checkbox.MaterialCheckBox
import com.google.android.material.radiobutton.MaterialRadioButton
import dev.warpscout.app.databinding.ActivityMainBinding
import dev.warpscout.app.status.ServiceSettingsStore
import dev.warpscout.core.state.TunnelStatus
import dev.warpscout.app.status.TunnelStatusBus
import android.net.Uri
import dev.warpscout.core.config.WgConf
import dev.warpscout.core.model.ResourceCheck
import dev.warpscout.core.junk.JunkLibrary
import dev.warpscout.core.keys.KeySource
import dev.warpscout.core.lists.AllowListPlanner
import dev.warpscout.core.model.WarpConfig
import dev.warpscout.core.net.WarpDefaults
import dev.warpscout.core.presets.Presets
import dev.warpscout.core.report.ConfigExport
import dev.warpscout.core.report.Report
import dev.warpscout.core.tune.ProgressSink
import dev.warpscout.core.tune.TuningResult
import java.io.File
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.math.abs

/**
 * Шесть вкладок: первая — быстрый путь («проверить → сгенерировать → подключить») с настройками по
 * умолчанию, остальные пять — то же самое, но по частям, на случай когда быстрый путь не сработал.
 * Всё тяжёлое (подбор, скан, проверка ресурсов, запись файлов) делает [Engine] на своём потоке,
 * сюда прилетают только строки лога и готовый отчёт.
 */
class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding
    private lateinit var prefs: Prefs
    private val engine by lazy { Engine.shared(this) }
    private val tunnel by lazy { TunnelFactory.create(this) }
    /** Журнал подбора и флаг «Остановить» — общие для всех экранов (см. [scanLog]). */
    private val log: StringBuilder get() = scanLog
    private val cancelled: AtomicBoolean get() = scanCancelled
    private val junkChecks = mutableListOf<MaterialCheckBox>()
    private var runStartedAt = 0L
    private var endpointBeforeRun = ""
    private var suppressPoolListener = false
    private var suppressExportListener = false
    private val listChecks = LinkedHashMap<String, MaterialCheckBox>()
    private val tunnelHandler = android.os.Handler(android.os.Looper.getMainLooper())

    /** Окна «Журнал» и «Диагностика»: сами держатся за самый свежий край (см. [TailKeeper]). */
    private val logTail by lazy { TailKeeper(binding.logBox) }
    private val diagTail by lazy { TailKeeper(binding.diagBox) }

    /**
     * Сколько точек пробуем за одно подключение.
     *
     * Шесть, а не пять: в перебор теперь входят проверенные точки из последнего подбора (до трёх),
     * и при пяти слотах они вытесняли запасные адреса Cloudflare целиком. Верхняя граница важна не
     * меньше нижней — каждая неудачная точка стоит около пяти секунд ожидания handshake, и десять
     * попыток означали бы минуту молчания.
     */
    private val MAX_ENDPOINT_TRIES = 6

    /**
     * Когда какая точка последний раз не поднялась (только в этом запуске приложения).
     *
     * Нужна, чтобы второй перебор не начинался с того же самого: в журнале за час было видно, как
     * подряд идут круги по одним и тем же пяти адресам, хотя сеть их уже отклонила. Точки, которые
     * не поднялись меньше десяти минут назад, уходят в конец очереди (но не выбрасываются: сеть
     * меняется, и «мёртвая минуту назад» через десять минут может работать).
     */
    private val failedPoints = HashMap<String, Long>()

    /** Сколько помним неудачу точки: дольше — уже неактуально, сеть успевает измениться. */
    private val FAILED_MEMORY_MS = 10 * 60 * 1000L
    private val lists by lazy { AllowListsRepo(this) }
    private var lastConfigFile: File? = null

    /** Панели разделов в том же порядке, что и кнопки нижней панели (см. [navButtons]). */
    private lateinit var pages: List<View>
    private val appChecks = LinkedHashMap<String, MaterialCheckBox>()
    private var appEntries: List<AppEntry> = emptyList()

    /** Одна строка списка приложений: только то, что нужно для показа и сохранения. */
    private data class AppEntry(val pkg: String, val label: String, val system: Boolean)
    private var selectedTab = 0

    /** Когда туннель поднялся (мс, локальные часы): от этой точки считаем расход по приложениям. */
    private var tunnelStartedAtLocal = 0L
    private var connecting = false

    /**
     * «Отменить подключение» нажато: перебор точек не стартует следующую и гасит текущую попытку.
     * Раньше кнопка все ~45 с перебора была неактивна, а выключение плиткой не останавливало
     * перебор — следующая точка стартовала и снимала отметку «выключил сам».
     */
    @Volatile
    private var connectCancel = false

    /** Когда показана текущая панель и ошибка ли это: «успех» после возврата не должен висеть вечно. */
    private var bannerShownAt = 0L
    private var bannerIsError = false

    /** В строке «Последний подбор» сейчас «… назад» из [showLastRun] — её надо освежать при возврате. */
    private var lastRunShown = false

    /** Экран на виду (между onResume и onPause): только тогда нужен опрос состояния туннеля. */
    private var screenResumed = false

    /** Подбор запущен кнопкой подключения: когда закончится — сразу поднимаем туннель. */
    private var autoConnectAfterScan = false
    private var endpointIndex = 0
    private var exitRegion = ""
    private var settingsReconnect: Runnable? = null

    /** Тройка подобранных конфигов, показанная сейчас (в порядке «лучший → третий»). */
    private var shortlistEntries: List<ConfigShortlist.Entry> = emptyList()

    /** Пока true — переподключение по настройкам не затевается (идёт заполнение экрана из Prefs). */
    private var suppressSettingsReconnect = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // Первым делом: если приложение падало, это должно попасть в журнал, а не исчезнуть.
        CrashLog.install(this)
        // Журнал общий с процессом туннеля: строки обоих процессов сходятся в одном файле.
        TunnelDebug.attach(this)
        // Настройки сервиса — отдельным снимком: SharedPreferences между процессами расходятся.
        // Синхронизация — внутри try ниже: она тоже может бросить (битый файл снимка).
        // Если приложение падало только что (меньше трёх минут назад), сначала показываем причину:
        // иначе получается замкнутый круг — падает при запуске, а журнал открыть не успеваешь.
        // «Продолжить» ведёт к обычному экрану, так что застрять здесь нельзя.
        val recent = CrashLog.recentCrash(this)
        if (recent != null) {
            TunnelDebug.error("показываю причину прошлого падения до запуска интерфейса")
            SafeMode.showReport(this, recent) { buildUi(savedInstanceState) }
        } else {
            buildUi(savedInstanceState)
        }
    }

    /**
     * Построение экрана целиком.
     *
     * Любая ошибка здесь раньше означала системное «приложение закрыто из-за ошибки»: ни журнала,
     * ни возможности рассказать, что случилось. Теперь показываем аварийный экран с причиной — он
     * собран из системных View и не может не загрузиться (см. [SafeMode]).
     */
    private fun buildUi(savedInstanceState: Bundle?) {
        try {
            ServiceSettingsStore.syncFromPrefs(this)
            binding = ActivityMainBinding.inflate(layoutInflater)
            setContentView(binding.root)

            prefs = Prefs(this)
            // Подключаемся к состоянию туннеля из его процесса (идемпотентно, см. TunnelStatusBus).
            TunnelStatusBus.install(this)
            setupNav(savedInstanceState?.getInt(STATE_TAB) ?: 0)
            fillFromPrefs()
            buildJunkChecks()
            buildResourceList()
            setupButtons()
            setupApps()
            buildListsChecks()
            refreshRoutesState()
            updateEndpointNote()
            renderShortlist()
            askNotificationPermission()
            CrashLog.lastCrash(this)?.let { crash ->
                banner(getString(R.string.banner_last_crash), error = true)
                TunnelDebug.error("прошлый запуск завершился падением", crash.lineSequence().first().take(160))
                sink().log("✗ прошлый запуск завершился падением: " + crash.lineSequence().first().take(160))
                sink().log("   подробности: Journal → «Скопировать журнал» (раздел «Падения»)")
            }
            binding.textStatus.setText(R.string.status_idle)
            // Номер сборки рядом с версией: мелкие доправки пересобирают ту же версию поверх, и
            // только так видно, какая именно сборка стоит.
            binding.textVersion.text = getString(
                R.string.version_footer,
                BuildConfig.VERSION_NAME + " · " + BuildConfig.BUILD_REV,
                getString(if (BuildConfig.TUNNEL_SUPPORTED) R.string.variant_tunnel else R.string.variant_scout)
            )
            shown = this
            // Подбор мог идти, пока экран создавался заново: показываем его и даём остановить.
            syncScanUi(fresh = true)
        } catch (t: Throwable) {
            SafeMode.show(this, t, "запуск интерфейса")
        }
    }

    override fun onDestroy() {
        stopTunnelPolling()
        if (shown === this) shown = null
        super.onDestroy()
    }

    /** Экран мог не построиться (см. [SafeMode]) — тогда обращаться к binding нельзя. */
    private fun uiReady(): Boolean =
        ::binding.isInitialized && ::prefs.isInitialized && ::pages.isInitialized

    /**
     * В фоне экран не нужен: останавливаем опрос состояния туннеля (он ходит каждые 700 мс, пока
     * туннель не поднят) и отложенное скрытие панели. Иначе «свернул приложение во время
     * подключения» = вечный таймер на процессоре.
     */
    override fun onPause() {
        screenResumed = false
        stopTunnelPolling()
        tunnelHandler.removeCallbacks(bannerHide)
        super.onPause()
    }


    override fun onResume() {
        super.onResume()
        screenResumed = true
        if (!uiReady()) return
        // Опрос нужен всегда, пока экран открыт: сервис сам переподнимает туннель после смены
        // сети, и кнопка должна это показывать. В фоне опрос выключен (см. onPause).
        //
        // Всё обновление экрана — в runCatching: onResume вызывается после каждого возврата в
        // приложение, и исключение здесь раньше снимало приложение целиком (системное «закрыто
        // из-за ошибки»). Ошибка обновления — не повод терять экран.
        runCatching {
            shown = this
            startTunnelPolling()
            refreshInstalledApps()
            updateAppsState()
            // Внутри — проверка процесса сервиса сразу, а не через 2,5 минуты: после обновления
            // приложения или убийства системой экран иначе ещё долго показывал «работает».
            updateTunnelButton()
            // «… назад» считается в момент показа: без этого после возврата висело «11 ч 45 мин
            // назад», хотя прошло уже 12 ч 14 мин (снимок экрана к Диагностике-8).
            if (lastRunShown) showLastRun()
            // Панель «успех» прячется через 8 с, но onPause снимает этот таймер — и если уйти из
            // приложения раньше, «Туннель поднят: …» висела до следующего пересоздания экрана, даже
            // когда туннель давно выключен. Возвращаем таймер (или прячем сразу, если 8 с прошли).
            if (binding.cardBanner.visibility == View.VISIBLE && !bannerIsError) {
                val left = BANNER_MS - (System.currentTimeMillis() - bannerShownAt)
                if (left <= 0L) hideBanner() else tunnelHandler.postDelayed(bannerHide, left)
            }
            updateTunnelDiagnostics()
            refreshLogBox()
            renderShortlist()
            showKeys()
            syncScanUi(fresh = false)
        }.onFailure { t ->
            TunnelDebug.error("обновление экрана: " + SafeMode.describe(t))
            runCatching { banner(getString(R.string.banner_ui_error, SafeMode.describe(t)), error = true) }
        }
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
        binding.spinnerSchedule.adapter = ArrayAdapter(
            this, android.R.layout.simple_spinner_dropdown_item, Schedule.PERIODS.map { periodLabel(it) }
        )
        binding.spinnerSchedule.setSelection(Schedule.PERIODS.indexOf(prefs.scheduleHours).coerceAtLeast(0))
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
        binding.spinnerRoutes.adapter = ArrayAdapter(
            this, android.R.layout.simple_spinner_dropdown_item, routeLabels()
        )
        binding.spinnerRoutes.setSelection(prefs.routesMode.coerceIn(0, 3))
        binding.switchSecondExit.isChecked = prefs.secondExitOn
        binding.editSecondConf.setText(prefs.secondConf)
        binding.editSecondDomains.setText(prefs.secondDomains)
        updateSecondState()
        suppressExportListener = false
        binding.editServer.setText(prefs.pinnedEndpoint)
        binding.editAllowedIps.setText(prefs.allowedIpsText)
        binding.appsGroup.check(appsButtonId(prefs.appsMode))
        binding.checkListChecks.isChecked = prefs.checkByLists
        binding.textTargetNote.text = prefs.confTargetEnum().note
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
        prefs.autoApply = binding.checkAutoApply.isChecked
        prefs.confTarget = confTargetOf(binding.exportGroup.checkedButtonId)
        prefs.routesMode = binding.spinnerRoutes.selectedItemPosition.coerceIn(0, 3)
        prefs.secondExitOn = binding.switchSecondExit.isChecked
        prefs.secondConf = binding.editSecondConf.text?.toString()?.trim().orEmpty()
        prefs.secondDomains = binding.editSecondDomains.text?.toString()?.trim().orEmpty()
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
            getString(R.string.keys_source, getString(R.string.keys_none))
        } else {
            val kind = if (KeySource.looksLikeCurve25519(account.privateB64)) "Curve25519" else "EC (MASQUE)"
            getString(R.string.keys_source, getString(R.string.keys_cached, kind, account.peerPublicB64.take(10)))
        }
    }

    // ---------------------------------------------------------------- кнопки

    /**
     * Шесть вкладок вместо одной длинной страницы. Первая — «быстрый путь»: проверить,
     * сгенерировать, подключить — с настройками по умолчанию. Остальные нужны только когда
     * быстрый путь не сработал или нужен особый конфиг, поэтому ничего не удалено — всё разложено.
     */
    private fun setupNav(initial: Int) {
        pages = listOf(
            binding.pageStart, binding.pageScan, binding.pageConfig,
            binding.pageApps, binding.pageLog
        )
        navButtons().forEachIndexed { index, button ->
            button.setOnClickListener { showPage(index) }
        }
        // Первый показ — тем же вызовом, что и по нажатию: один путь — одно поведение.
        showPage(initial.coerceIn(0, pages.size - 1))
    }

    /** Пять кнопок нижней панели в том же порядке, что и [pages]. */
    private fun navButtons(): List<com.google.android.material.button.MaterialButton> = listOf(
        binding.navStart, binding.navScan, binding.navSettings, binding.navApps, binding.navLog
    )

    /**
     * Показать раздел.
     *
     * Внутри `runCatching`: переключение разделов — самое частое действие, и оно не должно уметь
     * ронять приложение. Если что-то пойдёт не так, человек останется на прежнем экране, а причина
     * попадёт в журнал — это несравнимо лучше системного «приложение закрыто из-за ошибки».
     */
    private fun showPage(index: Int) {
        runCatching {
            val safe = index.coerceIn(0, pages.size - 1)
            selectedTab = safe
            pages.forEachIndexed { i, page ->
                page.visibility = if (i == safe) View.VISIBLE else View.GONE
            }
            navButtons().forEachIndexed { i, button ->
                val active = i == safe
                button.isSelected = active
                button.setTextColor(
                    ContextCompat.getColor(
                        this,
                        if (active) R.color.colorPrimary else R.color.colorOnSurfaceVariant
                    )
                )
            }
            // Открыли «Журнал» — сразу видно, что происходит сейчас. Раньше окно показывало
            // начало списка, и свежую строку приходилось искать листанием.
            if (safe == TAB_LOG) {
                logTail.forceEnd()
                diagTail.forceEnd()
            }
        }.onFailure { t ->
            TunnelDebug.error("не удалось открыть раздел $index: " + SafeMode.describe(t))
        }
    }

    /** Начало пальца при смахивании: по нему считаем, было ли движение боковым. */
    private var swipeFromX = 0f
    private var swipeFromY = 0f
    private var swipeTracking = false

    /**
     * Смахивание влево-вправо переключает разделы — привычный жест «пейджера».
     *
     * Смотрим события раньше всех: иначе вложенные окна (журнал, диагностика) съедали жест
     * целиком. Переключаем только явно боковое движение — вертикальная прокрутка списков и
     * протаскивание ползунков должны остаться собой. Ошибка в жесте не имеет права уронить
     * экран, поэтому обработка в `runCatching`.
     */
    override fun dispatchTouchEvent(ev: MotionEvent): Boolean {
        // До построения экрана (или на аварийном) переключать нечего — жест просто не наш.
        if (::pages.isInitialized) runCatching {
            when (ev.actionMasked) {
                MotionEvent.ACTION_DOWN -> {
                    swipeFromX = ev.x
                    swipeFromY = ev.y
                    swipeTracking = true
                }
                MotionEvent.ACTION_UP -> {
                    if (swipeTracking) {
                        swipeTracking = false
                        val dx = ev.x - swipeFromX
                        val dy = ev.y - swipeFromY
                        val threshold = 72f * resources.displayMetrics.density
                        if (abs(dx) > threshold && abs(dx) > abs(dy) * 2f) {
                            showPage(selectedTab + if (dx < 0f) 1 else -1)
                        }
                    }
                }
                MotionEvent.ACTION_CANCEL -> swipeTracking = false
            }
        }
        return super.dispatchTouchEvent(ev)
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
        refreshInstalledApps()
        binding.appsGroup.setOnCheckedChangeListener { _, checkedId ->
            if (checkedId == View.NO_ID) return@setOnCheckedChangeListener
            prefs.appsMode = appsModeOf(checkedId)
            updateAppsState()
            markSettingsDirty(getString(R.string.dirty_apps_mode))
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
    /** Чтение списка приложений: дорогое (getApplicationLabel на каждое), поэтому зовём вне UI-потока. */
    private fun loadAppsSync(): List<AppEntry> = runCatching {
        val pm = packageManager
        pm.getInstalledApplications(0).mapNotNull { info ->
            if (info.packageName == packageName) return@mapNotNull null
            if (pm.getLaunchIntentForPackage(info.packageName) == null) return@mapNotNull null
            val system = (info.flags and android.content.pm.ApplicationInfo.FLAG_SYSTEM) != 0
            AppEntry(info.packageName, pm.getApplicationLabel(info).toString(), system)
        }.sortedBy { it.label.lowercase() }
    }.getOrDefault(emptyList())

    /**
     * Приложения могли установить, пока приложение открыто (или туннель уже поднят). Список
     * перечитывается при возврате в приложение — иначе только что установленное приложение просто
     * некуда отметить. Читаем в фоне: `getInstalledApplications` + подпись каждого приложения на
     * главном потоке — это заметные подтормаживания при каждом возврате в приложение.
     */
    private fun refreshInstalledApps() {
        val before = appEntries.size
        Thread {
            val loaded = loadAppsSync()
            runOnUiThread {
                if (!::binding.isInitialized) return@runOnUiThread
                appEntries = loaded
                if (loaded.size != before) {
                    rebuildAppsList()
                    updateAppsState()
                }
            }
        }.apply { isDaemon = true; name = "warpscout-apps" }.start()
    }

    private fun rebuildAppsList() {
        binding.appsBox.removeAllViews()
        appChecks.clear()
        // В режиме «все приложения» список не нужен: не тратим время на getApplicationLabel
        // для сотни пакетов и не показываем то, что ни на что не влияет.
        if (prefs.appsMode == Prefs.APPS_ALL) return
        val query = binding.editAppSearch.text?.toString()?.trim()?.lowercase().orEmpty()
        val showSystem = binding.checkAppsSystem.isChecked
        val selected = prefs.appsSelected
        val matched = appEntries.filter { app ->
            (showSystem || !app.system) &&
                (query.isEmpty() || app.label.lowercase().contains(query) || app.pkg.contains(query))
        }
        matched.take(APP_ROWS_LIMIT).forEach { app ->
            val row = MaterialCheckBox(this).apply {
                text = if (app.system) getString(R.string.app_row_system, app.label) else app.label
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
        // Список приложений в туннеле — часть конфигурации VpnService: применяется только при
        // установлении туннеля. Поэтому при поднятом туннеле ставим переподключение в очередь.
        markSettingsDirty(getString(R.string.dirty_apps_list))
    }

    private fun labelOfPackage(pkg: String): String =
        appEntries.firstOrNull { it.pkg == pkg }?.label ?: pkg

    private fun summaryOf(pkgs: Set<String>): String {
        val names = pkgs.sortedBy { labelOfPackage(it) }
        val head = names.take(8).joinToString(", ") { labelOfPackage(it) }
        return if (names.size > 8) getString(R.string.apps_more_summary, head, names.size - 8) else head
    }

    private fun updateAppsState() {
        // Список нужен только там, где есть что выбирать. В режиме «все приложения» он
        // ничего не переключает, но занимает пол-экрана и выглядит как рабочая настройка —
        // поэтому прячем его целиком: поиск, «системные», сам список.
        val needsList = prefs.appsMode != Prefs.APPS_ALL
        binding.tilAppSearch.visibility = if (needsList) View.VISIBLE else View.GONE
        binding.checkAppsSystem.visibility = if (needsList) View.VISIBLE else View.GONE
        binding.appsBox.visibility = if (needsList) View.VISIBLE else View.GONE
        if (!needsList) {
            binding.appsBox.removeAllViews()
        } else if (binding.appsBox.childCount == 0) {
            rebuildAppsList()
        }
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
        value < 1024 -> getString(R.string.bytes_b, value)
        value < 1024 * 1024 -> getString(R.string.bytes_kb, value / 1024)
        else -> getString(R.string.bytes_mb, value / 1048576.0)
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
                !r.ok -> ", " + (r.errorClass ?: getString(R.string.no_answer)) + (r.status?.let { " ($it)" } ?: "")
                r.status != null && r.elapsedMs > 0 -> getString(R.string.check_result_ms, r.status, r.elapsedMs)
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
            setTextColor(
                androidx.core.content.ContextCompat.getColor(
                    this@MainActivity,
                    if (ok) R.color.check_ok else R.color.check_fail
                )
            )
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

    /**
     * Подбор точек. [autoConnect] — после успешного подбора сразу поднять туннель.
     *
     * Подбор и подключение **одновременно** не запускаются никогда: подбор гасит туннель перед
     * замерами, и попытка подъёма в это время обречена (в журнале это выглядело как «ни одна из
     * 5 точек не поднялась» сразу после «сеть чистая», плюс падения по таймауту foreground).
     * Подключение идёт строго после того, как движок закончил.
     */
    private fun startScan(autoConnect: Boolean) {
        if (connecting) {
            banner(getString(R.string.scan_busy_connecting))
            return
        }
        if (engine.running) {
            // Повторный запуск подбора поверх идущего: молчать нельзя, иначе выглядит как
            // «кнопка не работает».
            banner(getString(R.string.scan_busy_scan))
            return
        }
        autoConnectAfterScan = autoConnect
        scanAutoConnect = autoConnect
        persistUi()
        // Туннель, который мы сейчас погасим ради замеров, вернём в конце подбора — чем бы тот ни
        // кончился (см. restoreTunnelAfterScan). Запоминаем до остановки: после неё isUp уже false.
        // «Держит» — тоже считается: туннель, который ждёт повтора, поднялся бы посреди замеров.
        val tunnelWasUp = tunnel.supported && (tunnel.isUp || tunnel.active)
        // Важно: при поднятом туннеле замеры идут через сам туннель (и через WARP), поэтому
        // «живых 0 из 120» — это не сеть, а самообман. Перед подбором туннель гасим.
        if (tunnelWasUp) {
            banner(getString(R.string.banner_scan_stops_tunnel))
            tunnel.stop()
            runCatching { tunnel.waitStopped(3000) }
            tunnelStartedAtLocal = 0L
            exitRegion = ""
            binding.btnTunnel.setText(R.string.btn_tunnel_on)
        }
        runStartedAt = System.currentTimeMillis()
        endpointBeforeRun = prefs.lastTunedEndpoint
        log.setLength(0)
        binding.textLog.text = ""
        cancelled.set(false)
        refreshLogBox()
        binding.progress.visibility = View.VISIBLE
        binding.progress.isIndeterminate = true
        binding.textStatus.setText(R.string.status_running)
        binding.btnStop.visibility = View.VISIBLE
        binding.btnStop.isEnabled = true
        binding.btnStop.setText(R.string.btn_stop)
        // Пока идёт подбор, кнопка подключения честно говорит, чем занята: иначе кажется, что
        // нажатие не сработало.
        if (autoConnect) {
            binding.btnTunnel.isEnabled = false
            binding.btnTunnel.setText(R.string.btn_tunnel_searching)
        }
        engine.start(prefs.tuningSpec(), manualConfig(), sink()) { result, error ->
            autoConnectAfterScan = false
            // Итог — на тот экран, что сейчас на виду: подбор переживает поворот и возврат в
            // приложение, а экран, который его запускал, к этому времени мог быть уже закрыт.
            val ui = shown?.takeIf { it.uiReady() } ?: this
            ui.onScanDone(result, error, autoConnect, tunnelWasUp)
        }
    }

    /** Подбор закончился (или его остановили): показать итог и сделать то, что было обещано. */
    private fun onScanDone(result: TuningResult?, error: String?, connect: Boolean, tunnelWasUp: Boolean) {
        scanAutoConnect = false
        if (!::binding.isInitialized) return
        binding.progress.visibility = View.GONE
        binding.btnStop.visibility = View.GONE
        when {
            error != null -> binding.textStatus.text = getString(R.string.status_error, error)
            result == null -> binding.textStatus.setText(R.string.status_cancelled)
            else -> showResult(result)
        }
        binding.btnTunnel.isEnabled = tunnel.supported
        binding.btnTunnel.setText(if (tunnel.isUp) R.string.btn_tunnel_off else R.string.btn_tunnel_on)
        val found = error == null && result?.best != null
        val target = result?.best?.endpoint?.render().orEmpty()
        when {
            // Подбор уже поднял туннель сам (авто-применение). Переключатель на поднятом
            // туннеле его ВЫКЛЮЧАЕТ — раньше «подобрать и подключиться» так и гасило только что
            // поднятое подключение.
            connect && found && tunnel.isUp -> banner(getString(R.string.top3_now, target))
            connect && found -> {
                banner(getString(R.string.scan_found_connecting_to, target))
                connectAfterScan()
            }
            // До подбора туннель работал — возвращаем его при любом исходе: ошибка, отмена,
            // «живых точек нет». Раньше в этих случаях человек оставался без туннеля.
            tunnelWasUp && !tunnel.isUp -> runCatching { restoreTunnelAfterScan(found, target) }
            connect && error == null && result != null -> banner(getString(R.string.scan_no_point))
        }
    }

    /**
     * Подключиться по итогам подбора — то же, что «Включить» на выключенном туннеле, но без
     * переключателя: он теперь выключает и туннель, который сервис держит в ожидании повтора.
     */
    private fun connectAfterScan() {
        val cfg = currentConfig() ?: return noConfig()
        if (!tunnel.ensurePermission(this)) return
        connectWithFallback(cfg)
    }

    /**
     * Вернуть подключение, которое подбор погасил перед замерами.
     *
     * Подключаемся обычным путём — как будто нажата «Подключить»: с перебором точек и с очередью
     * для сервиса, по которой он сам переходит на соседнюю точку после аварии. Если подбор нашёл
     * точку, поднимаемся на ней (она только что проверена на этой сети), иначе — на прежней.
     */
    private fun restoreTunnelAfterScan(found: Boolean, target: String) {
        if (!tunnel.supported || tunnel.active || connecting) return
        // Без новой точки поднимаем ровно то, что работало до подбора (сохранённый текст), а не
        // лучшую точку какого-нибудь прошлого подбора: та могла давно умереть.
        val cfg = if (found) {
            currentConfig()
        } else {
            savedConfig()?.let { ConfigComposer.applyPrefs(it, prefs, prefs.junkPool) } ?: currentConfig()
        }
        if (cfg == null) {
            banner(getString(R.string.scan_restore_nothing), error = true)
            return
        }
        banner(
            if (found) getString(R.string.scan_restore_found, target)
            else getString(R.string.scan_restore_previous)
        )
        if (!tunnel.ensurePermission(this)) return
        connectWithFallback(cfg)
    }

    private fun setupButtons() {
        // «Сканировать и подобрать»: находит точку и, если она есть, сразу поднимает туннель.
        // Раньше после подбора надо было ещё нажать «Подключить», и это ровно тот шаг, на котором
        // человек терялся: подбор закончился, на экране цифры, кнопка внизу.
        binding.btnRun.setOnClickListener { startScan(autoConnect = true) }

        binding.btnQuickConfig.setOnClickListener { quickGenerate() }


        binding.exportGroup.addOnButtonCheckedListener { _, checkedId, isChecked ->
            if (!isChecked || suppressExportListener) return@addOnButtonCheckedListener
            prefs.confTarget = confTargetOf(checkedId)
            binding.textTargetNote.text = dev.warpscout.core.config.ConfTarget.values()[prefs.confTarget].note
            refreshRoutesState()
        }

        // Спиннер сам сообщает о выборе при первой раскладке, а вкладка «Настройки» раскладывается
        // при первом показе. Это не правка: раньше каждое первое открытие вкладки писало в журнал
        // «изменено: DNS / режим маршрутов (не применено)» и показывало плашку о несохранённых
        // изменениях (Диагностика-8, 12:57:10). Правка — только когда значение действительно другое.
        binding.spinnerRoutes.onItemSelectedListener = object : android.widget.AdapterView.OnItemSelectedListener {
            override fun onItemSelected(parent: android.widget.AdapterView<*>?, view: View?, position: Int, id: Long) {
                val mode = position.coerceIn(0, 3)
                if (mode == prefs.routesMode) return
                prefs.routesMode = mode
                refreshRoutesState()
                markSettingsDirty(getString(R.string.dirty_routes_mode))
            }

            override fun onNothingSelected(parent: android.widget.AdapterView<*>?) {}
        }

        // Всё, что попадает в VpnService.Builder, меняется только переустановлением туннеля —
        // поэтому правки настроек при поднятом туннеле ставят переподключение в очередь.
        // Переключатели и поля восстанавливают своё состояние сами (после пересоздания экрана) и
        // при этом зовут слушателя — то же значение, что в настройках, правкой не считаем.
        binding.switchIpv6.setOnCheckedChangeListener { _, isChecked ->
            if (isChecked == prefs.enableIpv6) return@setOnCheckedChangeListener
            prefs.enableIpv6 = isChecked
            markSettingsDirty("IPv6")
        }
        binding.dnsSpinner.onItemSelectedListener = object : android.widget.AdapterView.OnItemSelectedListener {
            override fun onItemSelected(parent: android.widget.AdapterView<*>?, view: View?, position: Int, id: Long) {
                if (position == prefs.dnsIndex) return
                prefs.dnsIndex = position
                markSettingsDirty("DNS")
            }

            override fun onNothingSelected(parent: android.widget.AdapterView<*>?) {}
        }
        binding.editMtu.doAfterTextChanged { text ->
            text?.toString()?.toIntOrNull()?.takeIf { it in 576..1420 && it != prefs.mtu }?.let {
                prefs.mtu = it
                markSettingsDirty("MTU")
            }
        }
        binding.editKeepalive.doAfterTextChanged { text ->
            text?.toString()?.toIntOrNull()?.takeIf { it != prefs.keepalive }?.let {
                prefs.keepalive = it
                markSettingsDirty("keepalive")
            }
        }
        binding.checkListChecks.setOnCheckedChangeListener { _, isChecked ->
            if (isChecked == prefs.checkByLists) return@setOnCheckedChangeListener
            prefs.checkByLists = isChecked
            refreshRoutesState()
            markSettingsDirty(getString(R.string.dirty_lists))
        }

        // «Сохранить» на каждой вкладке, где что-то меняется: применяем и только потом переподключаем.
        binding.switchSecondExit.setOnCheckedChangeListener { _, isChecked ->
            if (isChecked == prefs.secondExitOn) return@setOnCheckedChangeListener
            prefs.secondExitOn = isChecked
            updateSecondState()
            markSettingsDirty(getString(R.string.dirty_second_exit))
        }
        binding.btnSecondResolve.setOnClickListener { resolveSecondDomains() }
        // Конфиг второго выхода вставляют копипастом: пока он не разобран, включённый
        // переключатель ничего не значит. Поэтому состояние пересчитываем сразу, а не
        // после «Сохранить и применить».
        binding.editSecondConf.doAfterTextChanged {
            prefs.secondConf = it?.toString()?.trim().orEmpty()
            updateSecondState()
        }
        binding.editSecondDomains.doAfterTextChanged {
            prefs.secondDomains = it?.toString().orEmpty()
            updateSecondState()
        }

        binding.btnSaveAndApply.setOnClickListener { saveAndApply(getString(R.string.dirty_config)) }
        binding.btnSaveAndSend.setOnClickListener { saveAndSend() }
        binding.btnSaveScan.setOnClickListener { saveAndApply(getString(R.string.dirty_scan)) }
        binding.btnSaveApps.setOnClickListener { saveAndApply(getString(R.string.dirty_apps)) }
        binding.btnSaveDpi.setOnClickListener { saveAndApply(getString(R.string.dirty_junk)) }
        binding.cardBanner.setOnClickListener { hideBanner() }

        binding.btnPickServer.setOnClickListener { pickServerFromReport() }

        binding.btnRefreshLists.setOnClickListener { refreshLists() }

        binding.btnBuildRoutes.setOnClickListener { buildRoutes() }

        binding.btnTunnelRefresh.setOnClickListener { updateTunnelDiagnostics() }
        binding.btnAppTraffic.setOnClickListener { showAppTraffic() }

        binding.btnTunnelCopy.setOnClickListener {
            ConfigFiles.copyToClipboard(this, TunnelDebug.dump() + "\n\n" + CrashLog.describe(this))
            toast(getString(R.string.copied_ok))
        }
        binding.btnTunnelExport.setOnClickListener { exportJournal() }

        binding.btnStop.setOnClickListener {
            cancelled.set(true)
            engine.cancel()
            if (engine.running) {
                // Подбор доделывает уже начатые пробы (секунда-две) и только потом сообщает итог —
                // показываем, что остановка идёт, а не делаем вид, что нажатие не сработало.
                binding.btnStop.isEnabled = false
                binding.btnStop.setText(R.string.btn_stopping)
                binding.textStatus.setText(R.string.status_stopping)
            } else {
                binding.btnStop.visibility = View.GONE
                binding.textStatus.setText(R.string.status_cancelled)
            }
        }

        binding.poolGroup.addOnButtonCheckedListener { _, checkedId, isChecked ->
            if (!isChecked) return@addOnButtonCheckedListener
            val mode = poolModeOf(checkedId)
            when (mode) {
                Prefs.POOL_MASQUE -> {
                    binding.editHosts.setText(WarpDefaults.MASQUE_SUBNETS.joinToString(", ") { "$it*" })
                    binding.editPorts.setText(WarpDefaults.MASQUE_PORTS.joinToString(", "))
                    binding.editCount.setText("60")
                    toast(getString(R.string.pool_note_masque))
                }
                Prefs.POOL_FULL -> {
                    binding.editHosts.setText("")
                    binding.editPorts.setText("")
                    binding.editCount.setText("1500")
                    toast(getString(R.string.pool_note_full))
                }
                else -> {
                    binding.editHosts.setText("")
                    binding.editPorts.setText("")
                    binding.editCount.setText("120")
                    toast(getString(R.string.pool_note_default))
                }
            }
            prefs.poolMode = mode
            updatePoolSummary()
        }

        // Период фонового подбора: 0 — выключен, иначе часы из Schedule.PERIODS.
        binding.spinnerSchedule.onItemSelectedListener = object : android.widget.AdapterView.OnItemSelectedListener {
            override fun onItemSelected(parent: android.widget.AdapterView<*>?, view: View?, position: Int, id: Long) {
                val hours = Schedule.PERIODS.getOrElse(position) { 6 }
                // Начальный выбор при первой раскладке — не правка. Раньше он заодно включал
                // фоновый подбор обратно, если его выключили кнопкой: период оставался прежним,
                // и первое же открытие «Настроек» ставил scheduleOn = true.
                if (hours == prefs.scheduleHours) return
                prefs.scheduleHours = hours
                prefs.scheduleOn = hours > 0
                if (hours > 0) Schedule.enable(this@MainActivity, hours) else Schedule.disable(this@MainActivity)
                binding.btnSchedule.setText(if (hours > 0) R.string.btn_schedule_off else R.string.btn_schedule)
                updateScheduleNote()
            }

            override fun onNothingSelected(parent: android.widget.AdapterView<*>?) {}
        }

        binding.btnSchedule.setOnClickListener {
            persistUi()
            if (prefs.scheduleOn) {
                Schedule.disable(this)
                prefs.scheduleOn = false
                binding.btnSchedule.setText(R.string.btn_schedule)
                toast(getString(R.string.schedule_off))
            } else {
                val hours = prefs.scheduleHours.takeIf { it > 0 } ?: 6
                prefs.scheduleHours = hours
                prefs.scheduleOn = true
                Schedule.enable(this, hours)
                binding.spinnerSchedule.setSelection(Schedule.PERIODS.indexOf(hours).coerceAtLeast(0))
                binding.btnSchedule.setText(R.string.btn_schedule_off)
                toast(getString(R.string.schedule_on, periodLabel(hours)))
            }
            updateScheduleNote()
        }

        binding.btnTop3Forget.setOnClickListener {
            // Список — подсказка из прошлого скана, а не настройка: убрать его должно быть так же
            // просто, как он появился. Следующий подбор соберёт новый.
            ConfigShortlist.forget(this)
            renderShortlist()
            banner(getString(R.string.top3_forgotten))
        }

        binding.btnBackup.setOnClickListener {
            persistUi()
            val file = Backup.save(this, getString(R.string.backup_note_manual))
            if (file == null) {
                toast(getString(R.string.backup_failed))
                return@setOnClickListener
            }
            toast(getString(R.string.backup_saved, file.name))
            // Отдать файл наружу: «Сохранить в Drive», «Отправить в Telegram» — что угодно.
            runCatching {
                val uri = androidx.core.content.FileProvider.getUriForFile(this, "$packageName.fileprovider", file)
                val send = Intent(Intent.ACTION_SEND).apply {
                    type = "text/plain"
                    putExtra(Intent.EXTRA_STREAM, uri)
                    addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                }
                startActivity(Intent.createChooser(send, getString(R.string.backup_share_title)))
            }
        }

        binding.btnRestore.setOnClickListener {
            val file = Backup.newest(this)
            if (file == null) {
                toast(getString(R.string.backup_none))
                return@setOnClickListener
            }
            androidx.appcompat.app.AlertDialog.Builder(this)
                .setTitle(R.string.backup_restore_title)
                .setMessage(getString(R.string.backup_restore_message, file.name))
                .setPositiveButton(R.string.backup_restore_ok) { _, _ ->
                    val applied = Backup.restore(this, file)
                    if (applied > 0) {
                        toast(getString(R.string.backup_restored, file.name, applied))
                        suppressSettingsReconnect = true
                        runCatching { fillFromPrefs() }
                        suppressSettingsReconnect = false
                        runCatching { buildListsChecks() }
                        runCatching { rebuildAppsList() }
                        runCatching { refreshRoutesState() }
                        runCatching { updateEndpointNote() }
                    } else {
                        toast(getString(R.string.backup_failed))
                    }
                }
                .setNegativeButton(android.R.string.cancel, null)
                .show()
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

        binding.btnTunnel.setOnClickListener { toggleTunnel() }
        binding.btnLogClear.setOnClickListener { clearJournal() }
        binding.btnNextEndpoint.setOnClickListener { nextEndpoint() }
    }

    /**
     * Журнал — файлом .txt: копия в «Загрузки» и сразу окно «Поделиться».
     *
     * Зачем, если есть «Скопировать журнал»: буфер обмена несёт только хвост (24 КБ), и длинный
     * текст ещё режут мессенджеры — присланные журналы начинались с середины строки, без начала
     * аварии. В файл идёт весь журнал туннеля, последний подбор, падения и шапка: версия с номером
     * сборки, телефон и состояние сервиса прямо сейчас.
     */
    private fun exportJournal() {
        // Журнал подбора и состояние читаем здесь, на главном потоке, — файл собираем в фоне.
        val scanText = log.toString()
        // С проверкой процесса сервиса: в шапке журнала, выгруженного через минуту после
        // обновления, стояло «туннель работает», хотя обновление его уже закрыло (Диагностика-8).
        val snapshot = runCatching { TunnelStatusBus.snapshot(this, verify = true) }.getOrNull()
        val app = applicationContext
        Thread({
            val now = java.util.Date()
            val text = buildString {
                appendLine(
                    "WarpScout ${BuildConfig.VERSION_NAME} · сборка ${BuildConfig.BUILD_REV} · " +
                        app.getString(if (BuildConfig.TUNNEL_SUPPORTED) R.string.variant_tunnel else R.string.variant_scout)
                )
                appendLine(
                    "выгружено: " +
                        java.text.SimpleDateFormat("yyyy-MM-dd HH:mm:ss", java.util.Locale.getDefault()).format(now)
                )
                appendLine(
                    "телефон: ${Build.MANUFACTURER} ${Build.MODEL}, Android ${Build.VERSION.RELEASE} " +
                        "(API ${Build.VERSION.SDK_INT})"
                )
                if (snapshot != null) {
                    appendLine(
                        "состояние: " + (if (snapshot.up) "туннель работает" else "туннель не поднят") +
                            (if (snapshot.wanted) ", сервис держит туннель" else "") +
                            (if (snapshot.stoppedByUser) ", выключен вручную" else "") +
                            ", фаза ${snapshot.phase}" +
                            snapshot.endpoint.takeIf { it.isNotBlank() }?.let { ", точка $it" }.orEmpty() +
                            snapshot.status.takeIf { it.isNotBlank() }?.let { ", «$it»" }.orEmpty()
                    )
                }
                appendLine()
                appendLine("── журнал туннеля ──")
                appendLine(TunnelDebug.fullDump())
                if (scanText.isNotBlank()) {
                    appendLine()
                    appendLine("── последний подбор ──")
                    appendLine(scanText)
                }
                appendLine()
                appendLine(CrashLog.describe(app))
            }
            val stamp = java.text.SimpleDateFormat("yyyyMMdd-HHmm", java.util.Locale.US).format(now)
            val name = "WarpScout-log-$stamp.txt"
            // Для «Поделиться» — копия во временном каталоге (его отдаёт FileProvider); прежние
            // выгрузки удаляем, чтобы они не копились.
            val shareFile = runCatching {
                val dir = java.io.File(app.cacheDir, "share").apply { mkdirs() }
                dir.listFiles()?.filter { it.name.startsWith("WarpScout-log-") }?.forEach { it.delete() }
                java.io.File(dir, name).apply { writeText(text) }
            }.getOrNull()
            val saved = runCatching { ConfigFiles.saveTextToDownloads(app, name, text) }.getOrNull()
            runOnUiThread {
                if (shareFile == null && saved == null) {
                    toast(getString(R.string.log_export_failed))
                    return@runOnUiThread
                }
                if (saved != null) toast(getString(R.string.log_export_saved, saved))
                if (shareFile != null) {
                    runCatching { startActivity(ConfigFiles.shareIntent(this, shareFile)) }
                }
            }
        }, "warpscout-log-export").apply { isDaemon = true }.start()
    }

    /**
     * «Очистить журнал»: стирает и журнал подбора (этот экран), и журнал туннеля (его пишет
     * процесс сервиса в общий файл, поэтому удаления памяти мало — файл тоже).
     *
     * Ничего не спрашиваем: действие обратимое в том смысле, что журнал и так собирается заново
     * с первой же строки, а лишний диалог на вкладке «Журнал» только мешает.
     */
    /** Подсказка журнала уже возвращена к обычной после очистки (см. [clearJournal]). */
    private var hintRestored = true

    private fun clearJournal() {
        hintRestored = false
        log.setLength(0)
        TunnelDebug.clear()
        lastDiagDump = null
        binding.textLog.text = ""
        // Подсказка «журнал пуст: туннель ещё не запускался» здесь была бы неправдой: он был,
        // просто его стёрли. Об этом и говорим — иначе экран врёт о состоянии.
        binding.textLogHint.setText(R.string.journal_cleared_hint)
        refreshLogBox()
        updateTunnelDiagnostics()
        banner(getString(R.string.banner_log_cleared))
    }

    /**
     * Держит окно журнала у самого свежего края.
     *
     * Строки дописываются в конец, а окно после обновления текста остаётся там, где было: открыв
     * вкладку, человек видел начало журнала и должен был листать вниз, чтобы понять, что
     * происходит сейчас. Пока окно у конца — новая строка сама остаётся видимой; как только окно
     * отлистали вверх почитать, обновления больше не дёргают текст из-под пальца, а вернувшись
     * к концу, окно снова «прилипает».
     */
    private class TailKeeper(private val box: NestedScrollView) {

        /** Окно у конца содержимого: новые строки подтягиваем. */
        private var stick = true

        init {
            // Слушатель берём именно у NestedScrollView: у View есть одноимённый, и лямбда без
            // явного типа не даёт выбрать между ними.
            box.setOnScrollChangeListener(
                NestedScrollView.OnScrollChangeListener { view, _, top, _, _ ->
                    val content = view.getChildAt(0)?.height ?: 0
                    stick = top + view.height >= content - 24
                }
            )
        }

        /** Догнать хвост, если человек не отлистал выше. */
        fun toEnd() {
            if (!stick) return
            box.post { box.fullScroll(View.FOCUS_DOWN) }
        }

        /** Показать хвост принудительно: раздел только что открыли. */
        fun forceEnd() {
            stick = true
            box.post { box.fullScroll(View.FOCUS_DOWN) }
        }
    }

    /**
     * Пустое окно журнала не показываем: рамка на пол-экрана без единой строки выглядела как
     * «сломанный журнал» (и ровно так и попала на скриншот). Появилась первая строка — окно есть.
     */
    private fun refreshLogBox() {
        if (!::binding.isInitialized) return
        binding.logBox.visibility = if (log.isBlank()) View.GONE else View.VISIBLE
        binding.textLogHint.visibility = if (log.isBlank()) View.VISIBLE else View.GONE
    }

    /** Приёмник прогресса: ядро зовёт его из своего потока, поэтому всё в runOnUiThread. */
    private fun sink(): ProgressSink = object : ProgressSink {
        override fun isCancelled(): Boolean = cancelled.get()

        override fun log(message: String) = runOnUiThread {
            if (log.isNotEmpty()) log.append('\n')
            log.append(message)
            if (log.length > 30000) log.delete(0, log.length - 30000)
            // Строки — на экран, который сейчас на виду: подбор мог запустить прежний экран, уже
            // пересозданный (поворот, смена темы, возврат в приложение).
            (shown ?: this@MainActivity).showScanLog()
        }

        override fun progress(done: Int, total: Int, current: String) = runOnUiThread {
            (shown ?: this@MainActivity).showScanProgress(done, total, current)
        }
    }

    private fun showScanLog() {
        if (!::binding.isInitialized) return
        // После очистки подсказка другая; как только пошли строки, возвращаем обычную —
        // иначе она всплывёт при следующем пустом журнале и снова соврёт.
        if (!hintRestored) {
            hintRestored = true
            binding.textLogHint.setText(R.string.journal_empty)
        }
        binding.textLogHint.visibility = View.GONE
        binding.textLog.text = log.toString()
        refreshLogBox()
        // Новые строки дописываются в конец: окно должно оставаться у них, пока человек сам не
        // отлистал вверх почитать — иначе текст выдёргивался бы из-под пальца.
        logTail.toEnd()
    }

    private fun showScanProgress(done: Int, total: Int, current: String) {
        if (!::binding.isInitialized) return
        binding.progress.visibility = View.VISIBLE
        binding.progress.isIndeterminate = total <= 0
        if (total > 0) {
            binding.progress.max = total
            binding.progress.progress = done
        }
        // После «Остановить» ещё приходят строки доделываемых проб: статус «останавливаю» не перетираем.
        if (!cancelled.get()) binding.textStatus.text = "[$done/$total] $current"
    }

    /**
     * Подбор на этом экране. Экран мог создаться заново посреди подбора (поворот, смена темы,
     * возврат в приложение): тогда он обязан показать, что подбор идёт, и дать его остановить.
     * Раньше новый экран показывал «Готово», а кнопка «Остановить подбор» висела всегда — и
     * останавливала уже не тот подбор. Теперь кнопка видна только пока подбор идёт.
     */
    private fun syncScanUi(fresh: Boolean) {
        if (!::binding.isInitialized) return
        val running = engine.running
        binding.btnStop.visibility = if (running) View.VISIBLE else View.GONE
        if (!running) return
        val stopping = cancelled.get()
        binding.btnStop.isEnabled = !stopping
        binding.btnStop.setText(if (stopping) R.string.btn_stopping else R.string.btn_stop)
        binding.progress.visibility = View.VISIBLE
        when {
            stopping -> binding.textStatus.setText(R.string.status_stopping)
            fresh -> binding.textStatus.setText(R.string.status_running)
        }
        if (scanAutoConnect) {
            binding.btnTunnel.isEnabled = false
            binding.btnTunnel.setText(R.string.btn_tunnel_searching)
        }
        if (fresh && log.isNotEmpty()) showScanLog()
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
        (engine.last?.best ?: savedConfig() ?: manualConfig())
            ?.let { ConfigComposer.applyPrefs(it, prefs, prefs.junkPool) }

    /**
     * Конфиг, которым поднимали туннель в прошлый раз (тот самый текст, что работает у плитки).
     * Нужен, чтобы «Отключить → Подключить» не требовало нового подбора: подключаемся ровно тем,
     * что уже доказало работоспособность. Подбор — отдельная кнопка, и он не обязан быть частью
     * подключения.
     */
    private fun savedConfig(): WarpConfig? = prefs.lastConfigText
        .takeIf { it.isNotBlank() }
        ?.let { runCatching { WgConf.toWarpConfig("сохранённый", it) }.getOrNull() }

    private fun currentConfigText(cfg: WarpConfig): String =
        runCatching { ConfigComposer.render(cfg, prefs) }.getOrElse { ConfigFiles.render(cfg) }

    private fun showResult(result: TuningResult) {
        showPage(TAB_START)
        runCatching { Backup.save(this, getString(R.string.backup_note_tuned, result.best?.endpoint?.render().orEmpty())) }
        binding.textStatus.setText(R.string.status_done)
        val took = humanDuration(System.currentTimeMillis() - runStartedAt)
        val hhmm = java.text.SimpleDateFormat("HH:mm", java.util.Locale.getDefault())
        val time = hhmm.format(java.util.Date(prefs.lastTunedAt))
        val bestNow = result.best?.endpoint?.render()
        // Итог только что закончившегося подбора — его при возврате не перетираем строкой «… назад».
        lastRunShown = false
        binding.textDone.text = when {
            // сменой считается только случай, когда endpoint реально другой, чем до этого запуска
            bestNow != null && endpointBeforeRun.isNotBlank() && bestNow != endpointBeforeRun ->
                getString(R.string.done_new, time, hhmm.format(java.util.Date(prefs.lastChangedAt)))
            bestNow != null && bestNow == endpointBeforeRun -> getString(R.string.done_same, time)
            else -> getString(R.string.done_ok, time, took)
        }
        binding.textNetwork.text = CleanNetwork.statusLine(this)
        val best = result.best
        resetStalePin(result, best)
        binding.textBest.text = best?.let {
            getString(R.string.best_endpoint, it.endpoint.render(), it.junk.name, result.report.best?.score ?: 0)
        } ?: getString(R.string.report_no_alive)
        binding.textKeys.text = getString(R.string.keys_source, result.accountSource)
        binding.textConfig.text = currentConfig()?.let { runCatching { ConfigComposer.render(it, prefs) }.getOrNull() }
            ?: result.configText
            ?: best?.let { ConfigFiles.render(it) }.orEmpty()
        updateServerNote()
        renderResources(result.report.resources)
        binding.textReport.text = runCatching { Report.toMarkdown(result.report) }
            .getOrElse { getString(R.string.report_broken, it.message.orEmpty()) }
        renderShortlist()
        lastConfigFile = engine.storedConfigFile ?: best?.let { cfg ->
            runCatching { File(ConfigFiles.dir(this, "configs"), ConfigExport.filename(cfg)) }
                .getOrNull()?.takeIf { it.exists() }
        }
        showKeys()
    }

    /**
     * Ручной сервер в настройках сильнее подбора — и это ровно то, из-за чего «после скана
     * подключился не к лучшему»: поле было заполнено когда-то раньше (или после переключения
     * на точку из списка), и любое подключение шло туда, хотя подбор уже нашёл точку лучше.
     *
     * Правило: если вручную выбранная точка всё ещё в тройке лучших — уважаем выбор; если она
     * оттуда выпала (умерла или стала хуже) — снимаем её и подключаемся к лучшей, сказав об этом.
     */
    private fun resetStalePin(result: dev.warpscout.core.tune.TuningResult, best: dev.warpscout.core.model.WarpConfig?) {
        val pinnedLine = prefs.pinnedEndpoint
        if (pinnedLine.isBlank()) return
        val pinned = runCatching {
            dev.warpscout.core.config.WgConf.parseEndpoint(
                if (pinnedLine.contains(':')) pinnedLine else "$pinnedLine:2408"
            )
        }.getOrNull()?.render() ?: return
        val top = result.report.candidates.sortedByDescending { it.score }
            .take(3)
            .map { it.config.endpoint.render() }
        if (pinned in top) return
        prefs.pinnedEndpoint = ""
        runCatching { binding.editServer.setText("") }
        val target = best?.endpoint?.render()
        TunnelDebug.stage("снял ручной сервер $pinnedLine: в тройке лучших его нет")
        if (target != null) banner(getString(R.string.pin_reset_to_best, pinnedLine, target))
    }

    // ---------------------------------------------------------- второй выход

    /**
     * Домены → адреса через DoH. Системный резолвер не используем: он может отдать подменённые
     * адреса, и правило уведёт не тот трафик. Дальше эти /32 и /128 раскладывает ExitRouter
     * внутри сервиса: пакет на такой адрес уходит во второй туннель, остальные — в WARP.
     */
    private fun resolveSecondDomains() {
        val hosts = binding.editSecondDomains.text?.toString().orEmpty()
            .split(',', '\n', ';', ' ')
            .map { it.trim().removePrefix("http://").removePrefix("https://").substringBefore('/') }
            .filter { it.contains('.') }
            .distinct()
        if (hosts.isEmpty()) {
            banner(getString(R.string.second_no_domains), error = true)
            return
        }
        binding.btnSecondResolve.isEnabled = false
        binding.textSecondState.text = getString(R.string.second_resolving)
        Thread {
            val resolved = runCatching { AllowListPlanner.resolveAll(hosts) }.getOrDefault(emptyMap())
            val cidrs = LinkedHashSet<String>()
            resolved.values.flatten().forEach { ip ->
                if (ip.isNotBlank()) cidrs += if (ip.contains(':')) "$ip/128" else "$ip/32"
            }
            runOnUiThread {
                binding.btnSecondResolve.isEnabled = true
                prefs.secondDomains = hosts.joinToString(", ")
                prefs.secondCidrs = cidrs.joinToString(", ")
                updateSecondState()
                if (cidrs.isEmpty()) {
                    banner(getString(R.string.second_no_domains), error = true)
                } else {
                    banner(getString(R.string.second_resolved, cidrs.size, hosts.size))
                    markSettingsDirty(getString(R.string.dirty_second_cidrs))
                }
            }
        }.apply { isDaemon = true; name = "warpscout-resolve-second" }.start()
    }

    private fun updateSecondState() {
        val cidrs = prefs.secondCidrs.split(',', '\n').count { it.isNotBlank() }
        val domains = prefs.secondDomains.split(',', '\n').count { it.isNotBlank() }
        val server = runCatching {
            WgConf.toWarpConfig("второй выход", prefs.secondConf)?.endpoint?.render()
        }.getOrNull()
        binding.textSecondState.text = when {
            !prefs.secondExitOn -> getString(R.string.second_off)
            // Конфиг вставлен, но не разбирается — это единственная ошибка, которую человек
            // не увидит сам: переключатель включён, а сервера фактически нет.
            prefs.secondConf.isBlank() -> getString(R.string.second_need_conf)
            server == null -> getString(R.string.second_bad_conf)
            cidrs == 0 -> getString(R.string.second_need_cidrs)
            else -> getString(R.string.second_on_summary, domains, cidrs, server) +
                "\n" + getString(R.string.second_apply_note)
        }
    }

    private fun periodLabel(hours: Int): String = when {
        hours <= 0 -> getString(R.string.schedule_period_off)
        hours == 1 -> getString(R.string.schedule_period_hour)
        hours >= 24 -> getString(R.string.schedule_period_day)
        else -> getString(R.string.schedule_period_hours, hours)
    }

    private fun updateScheduleNote() {
        // Подпись кнопки уже говорит «включить/выключить» — здесь только период для тоста и бекапа.
        if (prefs.scheduleOn) prefs.scheduleHours = prefs.scheduleHours.coerceAtLeast(1)
    }

    private fun updateTunnelButton() {
        // Снимок мог «зависнуть» на «работает», если сервис убила система или его закрыло
        // обновление приложения: проверяем процесс сервиса до того, как кнопка покажет состояние.
        runCatching { TunnelStatusBus.snapshot(this, verify = true) }
        updateConnStatus()
        if (!tunnel.supported) {
            binding.btnTunnel.isEnabled = false
            binding.btnTunnel.setText(R.string.tunnel_unavailable)
            return
        }
        // Идёт перебор точек: кнопка — «Отменить подключение», а не «Выключить туннель».
        if (connecting) {
            binding.btnTunnel.isEnabled = !connectCancel
            binding.btnTunnel.setText(if (connectCancel) R.string.btn_connect_cancelling else R.string.btn_connect_cancel)
            return
        }
        binding.btnTunnel.isEnabled = true
        refreshTunnelButtonLabel()
    }

    /**
     * Подпись главной кнопки по состоянию сервиса. Зовётся и из опроса: туннель меняет состояние
     * сам (переподключился, выключен из плитки или уведомления), и кнопка не должна звать
     * «Включить», когда он работает, — как на снимке экрана с «выключен» при живом туннеле.
     */
    private fun refreshTunnelButtonLabel() {
        if (!tunnel.supported) return
        // Пока конфигурации нет, кнопка называется «Найти и подключить»: иначе «Подключить»
        // обещает действие, которого без конфига не будет.
        val hasConfig = engine.last?.best != null || prefs.lastConfigText.isNotBlank() || prefs.manualConf.isNotBlank()
        val text = getString(
            when {
                tunnel.isUp || tunnel.active -> R.string.btn_tunnel_off
                !hasConfig -> R.string.btn_tunnel_search
                else -> R.string.btn_tunnel_on
            }
        )
        // Опрос идёт раз в 0,7–3 с: одинаковый текст заново не ставим, иначе кнопка
        // переверстывается на каждом тике.
        if (binding.btnTunnel.text.toString() != text) binding.btnTunnel.text = text
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
        lastRunShown = true
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

    // ------------------------------------------- топ-3 подобранных конфигов

    /**
     * «Чем заменить текущую точку»: три конфига из последнего подбора. Строим вручную, а не через
     * адаптер — строк максимум три, зато каждая должна выглядеть как выбор, а не как текст: работающая
     * сейчас отмечена, остальные доступны одним нажатием.
     */
    private fun renderShortlist() {
        if (!::binding.isInitialized) return
        runCatching { renderShortlistUnsafe() }.onFailure { t ->
            // Список замен — удобство, а не основа работы: его сбой не должен снимать экран.
            TunnelDebug.error("список лучших конфигов: " + SafeMode.describe(t))
            binding.cardTop3.visibility = View.GONE
        }
    }

    private fun renderShortlistUnsafe() {
        val entries = runCatching { ConfigShortlist.load(this) }.getOrDefault(emptyList())
        shortlistEntries = entries
        val liveEndpointEarly = runCatching { TunnelDebug.endpoint }.getOrDefault("").trim()
        if (entries.isEmpty() && liveEndpointEarly.isBlank()) {
            binding.cardTop3.visibility = View.GONE
            binding.groupTop3.removeAllViews()
            return
        }
        binding.cardTop3.visibility = View.VISIBLE
        binding.groupTop3.removeAllViews()
        val network = runCatching { TuningCache.transportOf(this) }.getOrDefault("")
        val up = runCatching { tunnel.isUp }.getOrDefault(false)
        // Отмечаем ту точку, через которую реально идёт (или шёл последний) трафик. Раньше метка
        // появлялась только при поднятом туннеле и только если переключились из этого списка —
        // то есть после обычного «Включить туннель» не было видно ничего. Теперь сверяемся с
        // последней точкой входа: она ставится при любом подключении.
        // Реальная точка, через которую идёт туннель, а не «последняя из подбора»: сервис знает
        // точный host:port, и он может отличаться от того, что записан в настройках.
        val liveEndpoint = liveEndpointEarly
        val lastEndpoint = liveEndpoint.ifBlank { prefs.lastEndpoint.trim() }
        if (lastEndpoint.isNotEmpty() && entries.none { it.endpoint.trim() == lastEndpoint }) {
            // Подключены к точке, которой нет в списке трёх (например, поднимали сохранённый
            // конфиг). Молчать нельзя: иначе в списке «ничего не выбрано» при живом туннеле.
            binding.groupTop3.addView(
                MaterialRadioButton(this).apply {
                    id = View.generateViewId()
                    // «Сейчас подключён» — только когда туннель работает: на снимке экрана к
                    // Диагностике-8 эта строка стояла под «Туннель выключен».
                    text = getString(if (up) R.string.top3_now else R.string.top3_last, lastEndpoint) + "\n" +
                        getString(if (up) R.string.top3_row_active else R.string.top3_row_off)
                    textSize = 14f
                    setPadding(0, 8, 0, 8)
                    isChecked = true
                    setTypeface(typeface, android.graphics.Typeface.BOLD)
                    isEnabled = false
                },
                LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.MATCH_PARENT,
                    LinearLayout.LayoutParams.WRAP_CONTENT
                )
            )
        }
        val lp = LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT,
            LinearLayout.LayoutParams.WRAP_CONTENT
        )
        for ((i, entry) in entries.withIndex()) {
            val active = if (lastEndpoint.isNotEmpty()) {
                entry.endpoint.trim() == lastEndpoint
            } else {
                ConfigShortlist.isActive(entry, prefs)
            }
            val row = MaterialRadioButton(this)
            row.id = View.generateViewId()
            row.text = shortlistRowText(i, entry, network, active, up)
            row.textSize = 14f
            row.setPadding(0, 8, 0, 8)
            row.isChecked = active
            if (active) row.setTypeface(row.typeface, android.graphics.Typeface.BOLD)
            // Нажатие на уже выбранную строку тоже обрабатываем: «переподключиться к ней» — законное
            // желание, если туннель отвалился, а RadioGroup сам по себе повторный выбор не заметит.
            row.setOnClickListener { switchToShortlist(entry) }
            binding.groupTop3.addView(row, lp)
        }
    }

    /** Две строки в одной: кто это и насколько он хорош. Ширины хватает, длинный шум переносится. */
    private fun shortlistRowText(
        index: Int,
        entry: ConfigShortlist.Entry,
        network: String,
        active: Boolean,
        up: Boolean
    ): String {
        val header = getString(R.string.top3_row, index + 1, entry.endpoint, entry.junk)
        val result = if (entry.resourcesOk >= 0 && entry.resourcesTotal > 0) {
            getString(R.string.top3_res, entry.resourcesOk, entry.resourcesTotal)
        } else {
            getString(R.string.top3_row_unknown)
        }
        val age = humanDuration((System.currentTimeMillis() - entry.savedAt).coerceAtLeast(0L))
        val detail = StringBuilder(getString(R.string.top3_row_detail, result, age))
        if (active) {
            detail.append(" · ").append(
                getString(if (up) R.string.top3_row_active else R.string.top3_row_chosen)
            )
        }
        if (entry.network.isNotBlank() && network.isNotBlank() && entry.network != network) {
            detail.append(" · ").append(getString(R.string.top3_row_other_network))
        }
        return header + "\n" + detail
    }

    /**
     * Переключение на один из трёх: тот же путь, что и «Включить туннель», поэтому работает и когда
     * туннель уже поднят (он перезапускается), и когда выключен.
     */
    private fun switchToShortlist(entry: ConfigShortlist.Entry) {
        if (!tunnel.supported) {
            banner(getString(R.string.tunnel_unavailable), error = true)
            return
        }
        val cfg = ConfigShortlist.config(entry)
        if (cfg == null) {
            // Испорченную запись не оставляем: иначе нажатие «переключиться» просто ничего не делает.
            val rest = shortlistEntries.filter { it !== entry }
            if (rest.isEmpty()) ConfigShortlist.forget(this) else ConfigShortlist.save(this, rest)
            renderShortlist()
            banner(getString(R.string.top3_broken), error = true)
            return
        }
        if (tunnel.isUp && ConfigShortlist.isActive(entry, prefs)) {
            banner(getString(R.string.top3_already))
            return
        }
        if (!tunnel.ensurePermission(this)) return
        TunnelDebug.stage("переключение из топа: ${entry.endpoint} · шум ${entry.junk}")
        banner(getString(R.string.top3_switching, entry.endpoint))
        // Нажатая строка пробуется первой: раньше перебор начинался с «последнего сохранённого»
        // конфига, и нажатие на второй-третий вариант фактически игнорировалось.
        connectWithFallback(cfg, cfg)
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

    /** Подписи выпадающего списка режимов маршрутов (порядок = значение Prefs.routesMode). */
    private fun routeLabels(): List<String> = listOf(
        getString(R.string.route_all_dd),
        getString(R.string.route_preset_dd),
        getString(R.string.route_lists_dd),
        getString(R.string.route_manual_dd)
    )

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
            append(getString(R.string.routes_state_off, prefs.routesModeName(), getString(R.string.lists_cached, cached.size)))
            val age = cached.values.map { it.fetchedAt }.maxOrNull() ?: 0L
            if (age > 0L) append(" · ").append(dev.warpscout.core.lists.AllowLists.freshnessOf(age))
            if (prefs.routesMode == 2 && prefs.allowedIpsText.isBlank()) {
                append("\n").append(getString(R.string.routes_none_yet))
            }
            if (cached.isEmpty()) append("\n").append(getString(R.string.routes_download_hint))
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
        binding.textRoutesState.setText(R.string.state_working)
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
        binding.textRoutesState.text = getString(R.string.routes_expanding)
        Thread {
            val result = runCatching { lists.buildPlan(prefs) { line -> runOnUiThread { sink().log(line) } } }
            runOnUiThread {
                binding.btnBuildRoutes.isEnabled = true
                result.onSuccess { r ->
                    val summary = lists.savePlan(prefs, r.plan)
                    binding.editAllowedIps.setText(r.plan.allowedIps.replace(", ", ",\n"))
                    binding.spinnerRoutes.setSelection(2)
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
        val labels = (listOf(getString(R.string.server_auto_choice)) + top.map {
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
            .setNegativeButton(R.string.close_label, null)
            .show()
    }

    private fun updateServerNote() {
        val cfg = currentConfig() ?: return
        binding.textBest.text = getString(
            R.string.best_endpoint, cfg.endpoint.render(), cfg.junk.name,
            engine.last?.report?.best?.score ?: 0
        ) + "\n" + ConfigComposer.explain(cfg, prefs)
    }

    // ------------------------------------------- туннель: перебор и смена точки входа

    /**
     * Подключение с перебором точек входа.
     *
     * Один endpoint — одна точка отказа: если именно эта точка не отвечает (у Cloudflare их много,
     * и часть адресов в конкретной сети режется), «туннель не поднимается» и объяснений нет.
     * Поэтому пробуем по очереди: текущая точка → последняя доказанно рабочая → точки из последнего
     * скана → запасные anycast-адреса Cloudflare на разных портах. Поднялась — она и запоминается.
     */
    private fun toggleTunnel() {
        if (!tunnel.supported) {
            banner(getString(R.string.tunnel_unavailable), error = true)
            return
        }
        // Идёт перебор точек — кнопка его отменяет. Раньше она была неактивна до конца перебора.
        if (connecting) {
            requestConnectCancel()
            return
        }
        // «Выключить» — и когда туннель работает, и когда сервис его держит в ожидании повтора:
        // раньше в ожидании кнопка звала «Включить», и выключить переподключения было нечем.
        if (tunnel.isUp || tunnel.active) {
            // Выключает человек: сервис запомнит это и сам туннель больше не включит.
            tunnel.stopByUser()
            tunnelStartedAtLocal = 0L
            binding.btnTunnel.setText(R.string.btn_tunnel_on)
            renderShortlist()
            banner(getString(R.string.banner_stopped))
            return
        }
        val cfg = currentConfig()
        if (cfg == null) {
            // Конфигурации ещё нет — первый запуск или всё стёрли. Раньше кнопка отвечала тостом
            // «сначала выполните подбор», человек жал её ещё раз и только потом догадывался, что
            // нужная кнопка ниже. Теперь она делает то, чего от неё ждут: ищет точку и подключается.
            if (!tunnel.supported) {
                banner(getString(R.string.tunnel_unavailable), error = true)
                return
            }
            banner(getString(R.string.banner_no_config_scanning))
            animateShield()
            startScan(autoConnect = true)
            return
        }
        if (!tunnel.ensurePermission(this)) return
        connectWithFallback(cfg)
    }

    /**
     * «Отменить подключение». Сам туннель гасит поток перебора — он единственный, кто шлёт старты,
     * поэтому после его «Выключить» никакой старт следующей точки уже не придёт.
     */
    private fun requestConnectCancel() {
        if (!connecting || connectCancel) return
        connectCancel = true
        binding.btnTunnel.isEnabled = false
        binding.btnTunnel.setText(R.string.btn_connect_cancelling)
    }

    private fun connectWithFallback(base: WarpConfig, preferred: WarpConfig? = null) {
        if (connecting) {
            // Молча игнорировать нельзя: со стороны это выглядит как «кнопка не работает».
            banner(getString(R.string.tunnel_connecting_busy))
            return
        }
        // Пока идёт подбор, подключаться нельзя: подбор перед замерами гасит туннель, и любая
        // попытка подъёма в это время обречена — плюс перегруженный процесс не успевает вызвать
        // startForeground() за отведённые пять секунд, за что система убивает приложение.
        if (engine.running) {
            banner(getString(R.string.connect_busy_scan))
            return
        }
        animateShield()
        val candidates = tunnelCandidates(base, preferred)
        if (candidates.isEmpty()) return noConfig()
        // Очередь целиком — в журнал. Вопрос «куда он вообще лезет» должен иметь ответ в тексте, а
        // не в чтении исходников: первая строка всегда человеку (выбранная или проверенная точка).
        TunnelDebug.stage(
            "перебор ${candidates.size}: " +
                candidates.joinToString(", ") { it.endpoint.render() + "/" + it.junk.name }
        )
        // Очередь отдаём и процессу туннеля: если после смены сети точка перестанет отвечать,
        // сервис сам возьмёт следующую, а не будет трижды стучаться в мёртвую и сдаваться.
        prefs.failoverQueue = candidates.map { it.endpoint.render() }
        runCatching { ServiceSettingsStore.syncFromPrefs(this) }
        val savedFirst = savedConfig()?.takeIf { it.endpoint == candidates.first().endpoint }
        connecting = true
        connectCancel = false
        // С этой минуты любое ручное «Выключить» (плитка, «Отключить» в уведомлении) — сигнал
        // остановить перебор: сервис ставит отметку времени, и она новее этой.
        val connectMark = System.currentTimeMillis()
        // Кнопка во время перебора — «Отменить подключение», а ход перебора — в строке состояния.
        binding.btnTunnel.isEnabled = true
        binding.btnTunnel.setText(R.string.btn_connect_cancel)
        val statusBefore: CharSequence = binding.textStatus.text
        startTunnelPolling()
        Thread {
            // Если туннель уже поднят (переподключение по «Сохранить и применить»), сначала гасим
            // текущую сессию: иначе сервис ответит «уже поднимается» и попытки пройдут впустую.
            if (tunnel.isUp || tunnel.active) {
                runCatching { tunnel.stop() }
                runCatching { tunnel.waitStopped(3000) }
            }
            // Выключили ли туннель руками после начала перебора. Снимок читаем с диска (его пишет
            // процесс сервиса), но не чаще раза в 400 мс: ожидание подъёма спрашивает каждые 150 мс.
            var manualStop = false
            var manualCheckedAt = 0L
            fun stopRequested(fresh: Boolean = false): Boolean {
                if (connectCancel || manualStop) return true
                val now = System.currentTimeMillis()
                if (fresh || now - manualCheckedAt >= 400L) {
                    manualCheckedAt = now
                    val at = runCatching { TunnelStatusBus.read(this@MainActivity)?.stoppedByUserAt }.getOrNull() ?: 0L
                    manualStop = at >= connectMark
                }
                return manualStop
            }
            var winner: WarpConfig? = null
            val failures = StringBuilder()
            // Внимание: здесь НЕЛЬЗЯ проверять cancelled — это флаг отмены скана. Он остаётся true
            // после любого нажатия «Стоп» и раньше тихо обрывал подключение на первой же итерации.
            for ((i, cfg) in candidates.withIndex()) {
                if (winner != null) break
                // Выключили во время перебора — следующую точку не стартуем. Раньше перебор шёл
                // дальше, а новый старт снимал отметку «выключил сам»: туннель включался вопреки
                // человеку, выключившему его плиткой или из уведомления.
                if (stopRequested(fresh = true)) break
                val n = i + 1
                runOnUiThread {
                    if (!::binding.isInitialized) return@runOnUiThread
                    binding.textStatus.text = if (n == 1 && savedFirst != null && cfg.endpoint == savedFirst.endpoint) {
                        getString(R.string.tunnel_connecting_saved, cfg.endpoint.render())
                    } else {
                        getString(R.string.tunnel_trying, n, candidates.size, cfg.endpoint.render())
                    }
                }
                TunnelDebug.stage("точка $n/${candidates.size}: ${cfg.endpoint.render()}, шум ${cfg.junk.name}")
                val ok = runCatching { tunnel.startAndAwait(cfg, 5000, connectMark) { stopRequested() } }.getOrDefault(false)
                if (stopRequested(fresh = true)) break
                if (ok) {
                    winner = cfg
                    break
                }
                val why = tunnel.lastError() ?: getString(R.string.no_answer)
                failedPoints[pointKey(cfg)] = System.currentTimeMillis()
                if (failures.isNotEmpty()) failures.append("; ")
                failures.append("${cfg.endpoint.render()} — $why")
                // Гасим неудачную попытку и ДОЖИДАЕМСЯ фактической остановки: сервис
                // асинхронный, и без ожидания следующий старт упирался в «уже поднимается».
                runCatching { tunnel.stop() }
                runCatching { tunnel.waitStopped(2500) }
            }
            val cancelled = stopRequested(fresh = true)
            if (cancelled) {
                if (connectCancel) {
                    // «Отменить подключение»: текущую попытку гасим как ручное выключение — сервис
                    // запомнит, что выключил человек, и сам туннель не включит. Шлёт его этот же
                    // поток, единственный, кто шлёт старты, — так «Выключить» гарантированно последнее.
                    runCatching { tunnel.stopByUser() }
                    TunnelDebug.stage("подключение отменено кнопкой — следующие точки не пробую")
                } else {
                    // Выключили плиткой или из уведомления: сервис это уже сделал. Старт, который
                    // мог разминуться с выключением, сервис пропустит сам (он новее отметки начала).
                    TunnelDebug.stage("туннель выключен вручную во время перебора — следующие точки не пробую")
                }
            }
            val used = if (cancelled) null else winner
            runOnUiThread {
                connecting = false
                connectCancel = false
                if (!::binding.isInitialized) return@runOnUiThread
                binding.btnTunnel.isEnabled = true
                binding.textStatus.text = statusBefore
                // Опрос оставляем, пока экран на виду (его остановит onPause): раньше он гас здесь, и
                // кнопка до следующего возврата в приложение не замечала, что сервис сделал сам.
                if (screenResumed) startTunnelPolling() else stopTunnelPolling()
                updateTunnelButton()
                updateTunnelDiagnostics()
                if (cancelled) {
                    // Сервис ещё может не успеть сообщить, что выключился: подпись ставим сразу.
                    binding.btnTunnel.setText(R.string.btn_tunnel_on)
                    renderShortlist()
                    banner(getString(R.string.banner_connect_cancelled))
                } else if (used != null) {
                    prefs.endpointCursor = 0
                    prefs.lastConfigText = runCatching { WgConf.render(used) }.getOrDefault("")
                    prefs.lastEndpoint = used.endpoint.render()
                    // Какой строке из топа соответствует работающий туннель (точка + профиль шума).
                    prefs.shortlistActive = used.endpoint.render() + "|" + used.junk.name
                    tunnelStartedAtLocal = System.currentTimeMillis()
                    exitRegion = ""
                    renderShortlist()
                    updateEndpointNote()
                    banner(getString(R.string.banner_connect_ok, used.endpoint.render()))
                    // Бекап «на всякий случай»: после каждого удачного подключения, молча.
                    runCatching { Backup.save(this, getString(R.string.backup_note_connected, used.endpoint.render())) }
                    // Ручное подключение тоже наполняет кеш: следующая «Подбор» начнётся с этой точки.
                    runCatching { TuningCache.save(this, used.endpoint, used.junk.name) }
                    probeExitRegion()
                } else {
                    TunnelDebug.error(
                        getString(R.string.no_candidates_up, candidates.size),
                        failures.toString().take(300) +
                            " · " + getString(R.string.tunnel_failed_hint)
                    )
                    updateEndpointNote()
                    // «Не получилось» — на первой вкладке, а не всплывающей плашкой поверх любой вкладки.
                    prefs.endpointCursor = prefs.endpointCursor + 1
                    // В панель — только последняя причина: полный список из пяти точек в неё не
                    // влезает и обрезается на полуслове. Всё остальное уже в журнале.
                    banner(
                        getString(
                            R.string.banner_connect_failed,
                            candidates.size,
                            failures.toString().substringAfterLast("; ").take(160)
                        ),
                        error = true
                    )
                    showPage(TAB_START)
                }
            }
        }.apply { isDaemon = true; name = "warpscout-connect" }.start()
    }

    /**
     * Правка настроек больше не переподключает туннель сама: сначала пользователь нажимает
     * «Сохранить и применить» на соответствующей вкладке. Здесь только напоминание об этом.
     */
    private fun markSettingsDirty(why: String) {
        if (suppressSettingsReconnect) return
        TunnelDebug.stage("изменено: $why (не применено)")
        banner(getString(R.string.banner_unsaved))
    }

    /**
     * «Сохранить и применить»: сохраняем экран в Prefs и — если туннель поднят — переподключаем
     * его с новыми настройками (до трёх попыток). Если туннель не поднят, применять нечего:
     * настройки вступят в силу при следующем подключении.
     */
    private fun saveAndApply(why: String) {
        persistUi()
        updateServerNote()
        refreshRoutesState()
        binding.textConfig.text = runCatching { currentConfig()?.let { currentConfigText(it) } }.getOrNull().orEmpty()
        if (tunnel.supported && (tunnel.isUp || tunnel.active)) {
            val cfg = currentConfig()
            if (cfg == null) {
                banner(getString(R.string.banner_saved_only))
                return
            }
            banner(getString(R.string.banner_applying))
            Thread {
                runCatching { tunnel.stop() }
                runCatching { tunnel.waitStopped(3000) }
                tunnelStartedAtLocal = 0L
                exitRegion = ""
                runOnUiThread {
                    binding.btnTunnel.setText(R.string.btn_tunnel_on)
                    connectWithFallback(cfg)
                }
            }.apply { isDaemon = true; name = "warpscout-apply" }.start()
        } else {
            banner(getString(R.string.banner_saved_only))
        }
    }

    /**
     * «Сохранить и отправить»: конфиг собирается с текущими настройками (включая AllowedIPs —
     * то есть CIDR вписаны жёстко), сохраняется в «Загрузки» и отдаётся в «Поделиться». Туннель
     * при этом не трогаем: это режим «сделать конфиг для других / для другого клиента».
     */
    private fun saveAndSend() {
        persistUi()
        val cfg = currentConfig()
        if (cfg == null) {
            noConfig()
            return
        }
        val text = currentConfigText(cfg)
        val name = runCatching { ConfigComposer.fileName(cfg, prefs) }.getOrDefault("warpscout.conf")
        val path = runCatching { ConfigFiles.saveToDownloads(this, cfg, text, name) }.getOrNull()
        binding.textConfig.text = text
        if (path == null) {
            banner(getString(R.string.err_no_config), error = true)
            return
        }
        lastConfigFile = runCatching { File(ConfigFiles.dir(this, "configs"), name).takeIf { it.exists() } }
            .getOrNull() ?: lastConfigFile
        banner(getString(R.string.banner_sent, path))
        val file = lastConfigFile
        if (file != null) {
            runCatching {
                startActivity(Intent.createChooser(ConfigFiles.shareIntent(this, file), getString(R.string.share_title)))
            }
        }
    }

    /** Сообщение внизу первой вкладки вместо всплывающей плашки. Ошибки висят до следующего действия. */
    private fun banner(text: String, error: Boolean = false) {
        if (!::binding.isInitialized) return
        binding.textBanner.text = text
        binding.textBanner.setTextColor(
            androidx.core.content.ContextCompat.getColor(this, if (error) R.color.state_error else R.color.state_ok)
        )
        binding.cardBanner.visibility = View.VISIBLE
        bannerShownAt = System.currentTimeMillis()
        bannerIsError = error
        tunnelHandler.removeCallbacks(bannerHide)
        if (!error) tunnelHandler.postDelayed(bannerHide, BANNER_MS)
    }

    private val bannerHide = Runnable {
        if (::binding.isInitialized) binding.cardBanner.visibility = View.GONE
    }

    private fun hideBanner() {
        tunnelHandler.removeCallbacks(bannerHide)
        if (::binding.isInitialized) binding.cardBanner.visibility = View.GONE
    }

    /** Wi-Fi / мобильная / Ethernet по активной сети — ключ для памяти рабочих точек. */
    private fun netKindNow(): String = runCatching {
        val cm = getSystemService(android.net.ConnectivityManager::class.java)
            ?: return@runCatching ""
        val caps = cm.getNetworkCapabilities(cm.activeNetwork ?: return@runCatching "")
            ?: return@runCatching ""
        when {
            caps.hasTransport(android.net.NetworkCapabilities.TRANSPORT_WIFI) -> "Wi-Fi"
            caps.hasTransport(android.net.NetworkCapabilities.TRANSPORT_CELLULAR) -> "мобильная"
            caps.hasTransport(android.net.NetworkCapabilities.TRANSPORT_ETHERNET) -> "Ethernet"
            else -> ""
        }
    }.getOrDefault("")

    /**
     * Очередь точек входа для перебора.
     *
     * Порядок — от «доказано в этой сети» к «догадка»:
     * 0) нажатая человеком строка топ-3 (если подключение начато с неё);
     * 1) конфиг, который работал последним;
     * 2) все точки из последнего подбора — единственный список, где handshake уже проходил;
     * 3) текущие настройки;
     * 4) разные anycast-адреса Cloudflare на разных портах, с ротацией от попытки к попытке;
     * 5) два «чистых» варианта — без мусорных пакетов и без IPv6-адреса на интерфейсе.
     *
     * Это же и есть ответ на «предлагает три варианта, а пробует другие»: раньше пункта 2 здесь не
     * было вообще, и проверенные подбором точки в перебор не попадали. Плюс точки, которые только
     * что не поднялись, уезжают в конец очереди — второй перебор не должен повторять первый.
     */
    private fun tunnelCandidates(base: WarpConfig, preferred: WarpConfig? = null): List<WarpConfig> {
        val out = mutableListOf<WarpConfig>()
        val seen = HashSet<String>()
        fun add(cfg: WarpConfig?) {
            if (cfg == null || out.size >= MAX_ENDPOINT_TRIES) return
            val key = pointKey(cfg)
            if (seen.add(key)) out += cfg
        }
        fun addAll(list: List<WarpConfig?>) = list.forEach { add(it) }

        // 0) Выбор человека: нажатая строка топ-3. Она идёт первой и не сдвигается никакой
        //    статистикой — если человек показал пальцем, спорить не о чем.
        add(preferred)

        // 0.5) Точка, которая уже работала на такой же сети. Адреса Cloudflare не универсальны:
        //    адрес, живой на домашнем Wi-Fi, может закрывать порт на мобильной сети. В журнале с
        //    улицы это стоило лишней попытки и секунд тишины при каждом переключении.
        runCatching {
            val remembered = EndpointMemory.goodFor(this, netKindNow())
            if (!remembered.isNullOrBlank()) {
                val ep = WgConf.parseEndpoint(
                    if (remembered.contains(':')) remembered else "$remembered:2408"
                )
                add(base.copy(endpoint = ep))
            }
        }

        val head = mutableListOf<WarpConfig?>()
        // 1) конфиг, который работал последним
        head += savedConfig()
        // 2) точки из последнего подбора: их handshake уже проходил в этой сети, и это
        //    единственный список, который не является догадкой. Раньше его здесь не было вовсе —
        //    отсюда и «предлагает три варианта, а пробует какие-то другие адреса».
        runCatching { ConfigShortlist.load(this) }.getOrDefault(emptyList())
            .forEach { entry -> head += runCatching { ConfigShortlist.config(entry) }.getOrNull() }
        // 3) текущие настройки
        head += base
        addAll(head)

        // 4) запасные anycast-адреса Cloudflare с ротацией: следующий перебор начинается со
        //    следующего порта, чтобы ручные попытки не повторяли одну и ту же пятёрку.
        val dials = listOf(
            "162.159.192.1" to 2408,
            "188.114.97.1" to 500,
            "162.159.195.1" to 1701,
            "188.114.99.1" to 2408,
            "162.159.192.9" to 854,
            "188.114.96.1" to 4500
        )
        val start = prefs.endpointCursor.mod(dials.size)
        for (i in dials.indices) {
            val (host, port) = dials[(start + i) % dials.size]
            add(runCatching { base.copy(endpoint = dev.warpscout.core.model.Endpoint(host, port)) }.getOrNull())
        }
        // 5) «чистые» варианты: на сетях с DPI отказ чаще всего даёт именно мусор
        add(runCatching { base.copy(junk = JunkLibrary.none(), mtu = 1280) }.getOrNull())
        add(runCatching { base.copy(enableIpv6Address = false, mtu = 1280) }.getOrNull())

        // Точки, которые только что не поднялись, — в конец. Порядок остальных не меняем.
        val now = System.currentTimeMillis()
        failedPoints.entries.removeAll { now - it.value > FAILED_MEMORY_MS }
        val first = out.firstOrNull().takeIf { preferred != null }
        val rest = out.filter { it !== first }
        val ordered = rest.sortedBy { failedPoints[pointKey(it)] ?: 0L }
        return (listOfNotNull(first) + ordered).take(MAX_ENDPOINT_TRIES)
    }

    /**
     * Ключ точки: адрес, порт и профиль шума.
     *
     * MTU сюда намеренно не входит. В журнале было видно, как перебор дважды подряд шёл на один и
     * тот же адрес с одним и тем же шумом — конфиги отличались только MTU (1280 против 1420), и
     * второй заход стоил ещё пяти секунд ожидания. Для handshake это одна и та же точка.
     */
    private fun pointKey(cfg: WarpConfig): String =
        cfg.endpoint.render() + "|" + cfg.junk.name

    /** «Другая точка входа»: следующая из очереди, сразу с переподключением. */
    private fun nextEndpoint() {
        if (!tunnel.supported) {
            toast(getString(R.string.tunnel_unavailable))
            return
        }
        val base = currentConfig() ?: return noConfig()
        val list = tunnelCandidates(base)
        if (list.isEmpty()) return noConfig()
        endpointIndex = (endpointIndex + 1) % list.size
        val chosen = list[endpointIndex]
        prefs.lastEndpoint = chosen.endpoint.render()
        updateEndpointNote()
        if (tunnel.isUp) {
            tunnel.stop()
            tunnelStartedAtLocal = 0L
            exitRegion = ""
            binding.btnTunnel.setText(R.string.btn_tunnel_on)
            Thread {
                // Раньше здесь была фиксированная пауза 900 мс — «на глазок». Если сервис
                // освобождался позже, старт упирался в «уже поднимается» и подключение молча
                // не происходило. Теперь ждём фактического завершения прошлой сессии.
                tunnel.waitStopped(6000)
                runOnUiThread { connectWithFallback(chosen) }
            }.apply { isDaemon = true }.start()
        } else {
            connectWithFallback(chosen)
        }
    }

    private fun endpointOf(text: String): dev.warpscout.core.model.Endpoint? {
        val t = text.trim()
        if (t.isEmpty()) return null
        val port = t.substringAfterLast(':', "").toIntOrNull() ?: return null
        val host = t.substringBeforeLast(':').removePrefix("[").removeSuffix("]").trim()
        if (host.isEmpty()) return null
        return runCatching { dev.warpscout.core.model.Endpoint(host, port) }.getOrNull()
    }

    /**
     * Какая точка входа и какой регион выхода. Регион — тот, что реально ответил через туннель
     * (`cdn-cgi/trace`): WARP — anycast, страну выхода выбирает Cloudflare по сети, из приложения
     * её не назначить. А точку входа (адрес:порт) — можно, она и переключается.
     */
    private fun updateEndpointNote() {
        val now = prefs.lastEndpoint.ifBlank { runCatching { currentConfig()?.endpoint?.render() }.getOrNull().orEmpty() }
        val region = exitRegion.ifBlank { prefs.lastExitRegion }.ifBlank { getString(R.string.region_unknown) }
        binding.textEndpointNow.text = getString(
            R.string.endpoint_now,
            now.ifBlank { "—" },
            region
        )
    }

    private fun probeExitRegion() {
        Thread {
            val found = runCatching {
                val conn = java.net.URL("https://www.cloudflare.com/cdn-cgi/trace").openConnection() as java.net.HttpURLConnection
                conn.connectTimeout = 5000
                conn.readTimeout = 5000
                val text = conn.inputStream.bufferedReader().use { it.readText() }
                val map = text.lineSequence()
                    .mapNotNull { line -> line.split('=', limit = 2).takeIf { it.size == 2 } }
                    .associate { it[0].trim() to it[1].trim() }
                val colo = map["colo"] ?: return@runCatching null
                listOfNotNull(colo, map["loc"], map["ip"]).joinToString(" · ")
            }.getOrNull()
            runOnUiThread {
                exitRegion = found ?: getString(R.string.region_unknown)
                prefs.lastExitRegion = exitRegion
                TunnelDebug.stage("регион выхода через WARP: $exitRegion")
                updateEndpointNote()
            }
        }.apply { isDaemon = true; name = "warpscout-region" }.start()
    }

    // ------------------------------------------------ диагностика туннеля

    private fun startTunnelPolling() {
        tunnelHandler.removeCallbacks(tunnelPollerTask)
        tunnelHandler.postDelayed(tunnelPollerTask, 400L)
    }

    private fun stopTunnelPolling() = tunnelHandler.removeCallbacks(tunnelPollerTask)

    /** Каким был признак «туннель работает» на прошлом тике — чтобы не перерисовывать список зря. */
    private var lastShortlistUp = false

    /** Журнал, для которого уже построены подсказки: чтобы не пересобирать их на каждом тике. */
    private var lastDiagDump: String? = null

    private val tunnelPollerTask = object : Runnable {
        override fun run() {
            updateTunnelDiagnostics()
            if (!tunnel.supported) return
            // Отметка «сейчас подключён» в списке трёх должна появляться сразу после подъёма
            // (и сниматься после падения), а не при следующем случайном обновлении экрана.
            // Кнопка свободна (не идёт подключение и подбор) — держим её подпись в согласии с сервисом.
            if (!connecting && !engine.running) runCatching { refreshTunnelButtonLabel() }
            val upNow = runCatching { tunnel.isUp }.getOrDefault(false)
            if (upNow != lastShortlistUp) {
                lastShortlistUp = upNow
                renderShortlist()
                if (upNow) learnLiveEndpoint()
            }
            // Пока туннель не поднят — часто (видно этапы подъёма), когда работает — редко.
            tunnelHandler.postDelayed(this, if (tunnel.isUp) 3000L else 700L)
        }
    }

    /**
     * Сервис мог сам сменить точку (прежняя замолчала — см. `restartAfterNetworkChange`), и тогда
     * сохранённый текст конфига описывает уже мёртвый адрес: плитка быстрого доступа и следующий
     * запуск взяли бы его. Как только туннель поднялся, подставляем фактический endpoint в
     * сохранённый конфиг — ровно ту строку, которая сейчас работает.
     */
    private fun learnLiveEndpoint() {
        val live = TunnelDebug.endpoint.trim()
        if (live.isEmpty() || ':' !in live) return
        if (prefs.lastEndpoint == live) return
        val saved = prefs.lastConfigText
        if (saved.isBlank()) {
            prefs.lastEndpoint = live
            return
        }
        val current = saved.lineSequence()
            .firstOrNull { it.trimStart().startsWith("Endpoint") && '=' in it }
            ?.substringAfter('=')?.trim()
        if (current == live) {
            prefs.lastEndpoint = live
            return
        }
        val swapped = saved.lineSequence().joinToString("\n") { line ->
            if (line.trimStart().startsWith("Endpoint") && '=' in line) "Endpoint = $live" else line
        }
        prefs.lastConfigText = swapped
        prefs.lastEndpoint = live
        TunnelDebug.stage("конфиг обновлён на работающую точку: $live")
    }

    /**
     * Постоянный статус соединения: зелёный «работает», красный «потерян», серый «выключен».
     * В отличие от [banner] он никогда не исчезает сам — по просьбе: состояние должно быть видно
     * в любой момент, а не последние восемь секунд.
     */
    private fun updateConnStatus() {
        if (!::binding.isInitialized) return
        val up = tunnel.supported && tunnel.isUp
        // Раньше здесь искали подстроки в русском статусе («Поднимаю», «переподключаюсь»,
        // «нет сети»). Любая правка формулировки в сервисе молча ломала оформление, поэтому
        // состояние приходит машинным кодом.
        val snapshot = runCatching { TunnelStatusBus.snapshot(this) }.getOrNull()
        val phase = snapshot?.phase ?: TunnelStatus.PHASE_IDLE
        val starting = connecting || phase == TunnelStatus.PHASE_STARTING || phase == TunnelStatus.PHASE_RECONNECTING
        val noNet = phase == TunnelStatus.PHASE_NO_NETWORK
        // Туннель лежит, но сервис его держит и переподключится сам (медленный повтор, ожидание
        // сети). Это не «не удалось» и не «выключен» — так и говорим, с причиной от сервиса.
        val waiting = snapshot?.wanted == true
        val failed = TunnelDebug.lastError
        val text: String
        val color: Int
        when {
            up -> {
                // Время работы берём из снимка сервиса: он помнит, когда началась текущая сессия,
                // даже если экран был закрыт, а приложение перезапущено или обновлено. Локальная
                // отметка ставится только при подключении из этого экрана, поэтому после
                // перезапуска интерфейса она была нулевой и экран показывал «активен 0 с» при
                // часе реальной работы (Диагностика-5: подъём 13:59:58, экран открыт в 15:00).
                val since = snapshot?.startedAt?.takeIf { it > 0L } ?: tunnelStartedAtLocal
                val uptime = if (since > 0L && since <= System.currentTimeMillis()) {
                    humanDuration(System.currentTimeMillis() - since)
                } else {
                    getString(R.string.duration_sec, 0)
                }
                val endpoint = TunnelDebug.endpoint.ifBlank { prefs.lastEndpoint.ifBlank { "endpoint?" } }
                text = getString(R.string.conn_on, uptime, endpoint)
                color = androidx.core.content.ContextCompat.getColor(this, R.color.state_ok)
            }
            noNet -> {
                text = getString(R.string.conn_no_network)
                color = androidx.core.content.ContextCompat.getColor(this, R.color.state_warn)
            }
            starting -> {
                text = getString(R.string.conn_starting_plain)
                color = androidx.core.content.ContextCompat.getColor(this, R.color.state_warn)
            }
            waiting -> {
                val why = snapshot?.status.orEmpty().ifBlank { getString(R.string.status_reconnect_net) }
                text = getString(R.string.conn_waiting, why.take(90))
                color = androidx.core.content.ContextCompat.getColor(this, R.color.state_warn)
            }
            // Сервис закрыло обновление, перезагрузка или система: говорим это словами и что делать.
            // Раньше после обновления здесь было просто «выключен» (а первые 2,5 минуты — «работает»).
            TunnelStatusBus.death != TunnelStatusBus.DEATH_NONE -> {
                text = getString(
                    when (TunnelStatusBus.death) {
                        TunnelStatusBus.DEATH_UPDATE -> R.string.conn_off_updated
                        TunnelStatusBus.DEATH_REBOOT -> R.string.conn_off_rebooted
                        else -> R.string.conn_off_killed
                    }
                )
                color = androidx.core.content.ContextCompat.getColor(this, R.color.state_off)
            }
            // Выключил сам человек — это «выключен», а не красное «не удалось» от прошлой ошибки,
            // которая в журнале ещё висит последней.
            snapshot?.stoppedByUser == true -> {
                text = getString(R.string.conn_off)
                color = androidx.core.content.ContextCompat.getColor(this, R.color.state_off)
            }
            failed != null -> {
                text = getString(R.string.conn_failed, failed.take(90))
                color = androidx.core.content.ContextCompat.getColor(this, R.color.state_error)
            }
            else -> {
                text = getString(R.string.conn_off)
                color = androidx.core.content.ContextCompat.getColor(this, R.color.state_off)
            }
        }
        binding.textConnStatus.text = text
        binding.textConnStatus.setTextColor(color)
    }

    private fun updateTunnelDiagnostics() {
        updateConnStatus()
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
        // Экран открыт и обновляется несколько раз в секунду: переписываем только изменившееся,
        // иначе каждые 700 мс заново строится список подсказок и переверстывается текст.
        val full = "$status\n$dump"
        if (binding.textTunnelState.text.toString() != full) {
            binding.textTunnelState.text = full
            // Новые шаги дописываются в конец: если человек не отлистал выше, держимся за хвост,
            // иначе свежие строки уезжали бы вниз за пределы окна.
            diagTail.toEnd()
        }
        if (dump == lastDiagDump) return
        lastDiagDump = dump
        binding.tunnelAdviceBox.removeAllViews()
        TunnelTrouble.advise(dump).forEach { advice ->
            binding.tunnelAdviceBox.addView(
                android.widget.TextView(this).apply {
                    text = "• ${getString(advice.titleRes)}: ${getString(advice.whatToDoRes)}"
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

    /**
     * Лиса «появляется» на щите, когда начинается подключение.
     *
     * Простая и короткая: щит чуть меньше своего размера, прозрачный, за 400 мс проявляется с
     * лёгким перелётом. Это единственная анимация в приложении — она сообщает «я начал работать»
     * раньше, чем успевает обновиться текст статуса, и ничего не стоит: длится доли секунды,
     * при выключенном экране не запускается вовсе (экран в этот момент не рисуется).
     */
    private fun animateShield() {
        runCatching {
            val v = binding.imageShield
            v.animate().cancel()
            v.alpha = 0f
            v.scaleX = 0.82f
            v.scaleY = 0.82f
            v.animate()
                .alpha(1f)
                .scaleX(1f)
                .scaleY(1f)
                .setDuration(420)
                .setInterpolator(android.view.animation.OvershootInterpolator(0.9f))
                .start()
        }
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
        /**
         * Журнал подбора и флаг «Остановить» живут дольше экрана: подбор идёт в своём потоке и
         * переживает пересоздание активности (поворот, смена темы, возврат в приложение).
         * Пишут и читают их только с главного потока.
         */
        val scanLog = StringBuilder()
        val scanCancelled = AtomicBoolean(false)

        /** Подбор запущен с «подключить после»: кнопка подключения в это время занята. */
        @Volatile
        var scanAutoConnect = false

        /** Экран, который сейчас на виду: туда идут строки и итог подбора, кто бы его ни запускал. */
        @Volatile
        var shown: MainActivity? = null

        /** Индекс выбранной вкладки переживает поворот экрана. */
        /** Сколько приложений рисуем сразу: остальные — через поиск (иначе экран «залипает»). */
        const val APP_ROWS_LIMIT = 60
        const val STATE_TAB = "warpscout.tab"

        const val TAB_START = 0
        const val TAB_CONFIG = 2
        const val TAB_LOG = 4

        /** Сколько держится панель «успех». */
        const val BANNER_MS = 8000L
    }
}
