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
import androidx.appcompat.app.AppCompatDelegate
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
import dev.warpscout.core.lists.AppServices
import dev.warpscout.core.lists.ProtonFree
import dev.warpscout.core.lists.SiteList
import dev.warpscout.core.model.WarpConfig
import dev.warpscout.core.net.ExitCheck
import dev.warpscout.core.net.SpeedTest
import dev.warpscout.core.net.WarpDefaults
import dev.warpscout.core.presets.Presets
import dev.warpscout.core.report.ConfigExport
import dev.warpscout.core.report.Report
import dev.warpscout.core.tune.ProgressSink
import dev.warpscout.core.tune.TuningResult
import dev.warpscout.core.tunnel.AppExit
import dev.warpscout.core.tunnel.ExitRouter
import dev.warpscout.core.tunnel.SecondDefaults
import dev.warpscout.core.tunnel.WelcomeApps
import java.io.File
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.math.abs

/**
 * Шесть вкладок: первая — быстрый путь («проверить → сгенерировать → подключить») с настройками по
 * умолчанию, остальные пять — то же самое, но по частям, на случай когда быстрый путь не сработал.
 * Всё тяжёлое (подбор, скан, проверка ресурсов, запись файлов) делает [Engine] на своём потоке,
 * сюда прилетают только строки лога и готовый отчёт.
 */
class MainActivity : AppCompatActivity(), UpdateFlow.Ui {

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

    /**
     * Не чаще этого подбираем точки сами, когда «Включить» не нашло ни одной рабочей: подбор,
     * который только что был, повторять бессмысленно (и так не будет круга «подбор → не
     * подключилось → подбор»).
     */
    private val AUTO_RESCAN_GAP_MS = 10 * 60 * 1000L
    private val lists by lazy { AllowListsRepo(this) }
    private var lastConfigFile: File? = null

    /** Панели разделов в том же порядке, что и кнопки нижней панели (см. [navButtons]). */
    private lateinit var pages: List<View>
    private val appChecks = LinkedHashMap<String, MaterialCheckBox>()
    private var appEntries: List<AppEntry> = emptyList()

    /** Кнопки выхода в строках вкладки «Туннелирование» (с 1.10.39): пакет → кнопка. */
    private val appExitButtons = HashMap<String, com.google.android.material.button.MaterialButton>()

    /** Список вкладки «Туннелирование» построен с кнопками выхода — чтобы перестроить, когда это меняется. */
    private var appExitsShown = false

    /**
     * Выбор файла конфига второго выхода (с 1.10.39): файл .conf, скачанный с сайта Proton, — без
     * копирования текста. Системное окно выбора файла: разрешений не нужно.
     */
    private val pickSecondConf = registerForActivityResult(
        androidx.activity.result.contract.ActivityResultContracts.OpenDocument()
    ) { uri ->
        // Окно закрыли без выбора — «применить сразу» (начальные экраны) файла больше не ждёт.
        if (uri == null) secondConfApplyNow = false
        if (uri != null && ::binding.isInitialized) {
            runCatching { loadSecondConf(uri) }.onFailure { t ->
                TunnelDebug.error("второй выход: файл конфига — " + SafeMode.describe(t))
                banner(getString(R.string.second_file_fail, SafeMode.describe(t)), error = true)
            }
        }
    }

    /**
     * Выбор файла бекапа (с 1.10.40). При удалении приложения Android стирает и его копии
     * (files/backups), и после переустановки «Восстановить из копии» писала только «Бекапов пока нет» —
     * хотя файл, сохранённый раньше кнопкой «Сохранить резервную копию», лежал в «Загрузках», на Диске
     * или в Telegram. Теперь открывается системное окно выбора файла. Разрешений не нужно.
     */
    private val pickBackup = registerForActivityResult(
        androidx.activity.result.contract.ActivityResultContracts.StartActivityForResult()
    ) { result ->
        val uri = result.data?.data
        if (result.resultCode == android.app.Activity.RESULT_OK && uri != null && ::binding.isInitialized) {
            runCatching { loadBackupFile(uri) }.onFailure { t ->
                TunnelDebug.error("бекап: файл не прочитался — " + SafeMode.describe(t))
                banner(getString(R.string.backup_file_fail, SafeMode.describe(t)), error = true)
            }
        }
    }

    /** Копия, которую человек сохраняет через окно «Сохранить как» (см. [exportBackupAs]). */
    private var pendingBackupExport: File? = null

    /**
     * «Сохранить как» для резервной копии (с 1.10.43.1) — когда в «Загрузки/WarpScout» записать не
     * вышло: Android 8–9 без разрешения на память или прошивка не дала записать. Место выбирает
     * человек, окно открывается в «Загрузках».
     */
    private val createBackupDoc = registerForActivityResult(
        androidx.activity.result.contract.ActivityResultContracts.StartActivityForResult()
    ) { result ->
        val uri = result.data?.data
        val file = pendingBackupExport ?: Backup.newest(this)
        pendingBackupExport = null
        if (result.resultCode == android.app.Activity.RESULT_OK && uri != null && file != null && ::binding.isInitialized) {
            runCatching { writeBackupTo(uri, file) }.onFailure { t ->
                TunnelDebug.error("бекап: «Сохранить как» — " + SafeMode.describe(t))
                banner(getString(R.string.backup_export_fail, SafeMode.describe(t)), error = true)
            }
        }
    }

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
    private var exitRegion = ""
    private var settingsReconnect: Runnable? = null

    /** Тройка подобранных конфигов, показанная сейчас (в порядке «лучший → третий»). */

    /** Пока true — переподключение по настройкам не затевается (идёт заполнение экрана из Prefs). */
    private var suppressSettingsReconnect = false

    override fun onCreate(savedInstanceState: Bundle?) {
        // Тема — до super.onCreate: экран сразу создаётся светлым или тёмным, без пересоздания и
        // мигания. Ошибка чтения настроек темы не должна мешать запуску — тогда просто как в системе.
        runCatching { applyThemeMode(Prefs(this).themeMode) }
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
            // С 1.10.47: если окно легло под строку состояния и панель навигации (так бывает на части
            // телефонов), строка статуса и вкладки отступают от них сами; иначе отступы нулевые.
            SystemBars.keepClear(binding.root)

            prefs = Prefs(this)
            // Подключаемся к состоянию туннеля из его процесса (идемпотентно, см. TunnelStatusBus).
            TunnelStatusBus.install(this)
            setupNav(savedInstanceState?.getInt(STATE_TAB) ?: 0)
            fillFromPrefs()
            buildJunkChecks()
            buildResourceList()
            setupButtons()
            runCatching { setupFeatureSwitches() }.onFailure { t ->
                TunnelDebug.error("переключатели автоматики: " + SafeMode.describe(t))
            }
            setupApps()
            buildListsChecks()
            refreshRoutesState()
            updateEndpointNote()
            renderShortlist()
            renderAvailability()
            askNotificationPermission()
            CrashLog.lastCrash(this)?.let { crash ->
                banner(getString(R.string.banner_last_crash), error = true)
                TunnelDebug.error("прошлый запуск завершился падением", crash.lineSequence().first().take(160))
                sink().log("✗ прошлый запуск завершился падением: " + crash.lineSequence().first().take(160))
                sink().log("   подробности: Journal → «Скопировать журнал» (раздел «Падения»)")
            }
            binding.textStatus.setText(R.string.status_idle)
            // Номер сборки рядом с версией: мелкие доправки пересобирают ту же версию поверх, и
            // только так видно, какая именно сборка стоит. С 1.10.27 туннель есть в обеих сборках —
            // они различаются тем, каким экраном открываются.
            // С 1.10.31 внизу — только название и номер релиза. Номер сборки и вариант остались в
            // шапке выгружаемого журнала: по ним по-прежнему видно, какая сборка стоит.
            binding.textVersion.text = getString(R.string.version_footer, BuildConfig.VERSION_NAME)
            // Упрощённый экран и выбор вида — после всего остального: им нужны готовые настройки,
            // список лучших точек и подпись версии. Сбой здесь не должен снимать весь экран.
            runCatching { setupSimple() }.onFailure { t ->
                TunnelDebug.error("упрощённый экран не настроился: " + SafeMode.describe(t))
            }
            runCatching { setupThemeToggle() }
            applyUiMode()
            shown = this
            // Загрузка обновления живёт дольше экрана (с 1.10.40, см. UpdateFlow): ход и итог — этому экрану.
            UpdateFlow.ui = this
            // Подбор мог идти, пока экран создавался заново: показываем его и даём остановить.
            syncScanUi(fresh = true)
            // Экран создан заново после сброса по умолчанию (с 1.10.32): говорим, что дальше.
            // Плашку через секунду может сменить «приложения по умолчанию» — поэтому и всплывающей строкой.
            afterResetNote?.let { note ->
                afterResetNote = null
                banner(note)
                toast(note)
            }
            // APK, скачанный «Обновлениями» 1.10.31 в кеш приложения, больше не нужен: с 1.10.32
            // обновление качается в «Загрузки» (см. Updater). 11 МБ не должны лежать вечно.
            runCatching { File(cacheDir, "updates").takeIf { it.exists() }?.deleteRecursively() }
            // Системные загрузки обновлений, вставшие в прошлых версиях (с 1.10.40, см. UpdateFlow), — убрать.
            runCatching { cleanStaleUpdateDownloads() }
            // Ждали подключения, чтобы открыть выбор второго выхода (начальные экраны), — ждём и дальше.
            secondSetupUntil = savedInstanceState?.getLong(STATE_SECOND_SETUP, 0L) ?: 0L
            // Начальные экраны (бета, с 1.10.44-beta6): после новой установки, один раз. Не открылись —
            // не пытаемся при каждом запуске: экран и без них работает.
            runCatching { maybeShowWelcome(savedInstanceState) }.onFailure { t ->
                TunnelDebug.error("начальные экраны не открылись: " + SafeMode.describe(t))
                runCatching { prefs.welcomePending = false }
            }
        } catch (t: Throwable) {
            SafeMode.show(this, t, "запуск интерфейса")
        }
    }

    override fun onDestroy() {
        welcome?.dismiss()
        welcome = null
        stopTunnelPolling()
        if (shown === this) shown = null
        if (UpdateFlow.ui === this) UpdateFlow.ui = null
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
        // Свои сайты для «Доступности» — сохраняем и без кнопки «Сохранить»: набрал список и ушёл
        // из приложения — список не должен пропасть (с 1.10.30).
        // Во время сброса по умолчанию (с 1.10.32) экран пересоздаётся: старые поля не должны
        // записаться обратно в только что очищенные настройки.
        if (uiReady() && !resetInProgress) runCatching {
            prefs.availCustom = binding.editAvailCustom.text?.toString()?.trim().orEmpty()
        }
        stopTunnelPolling()
        tunnelHandler.removeCallbacks(bannerHide)
        tunnelHandler.removeCallbacks(simpleTick)
        // Отложенное «изменено…» — сразу, а не после ухода с экрана.
        dirtyLater?.let { tunnelHandler.removeCallbacks(it); if (!resetInProgress) it.run() }
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
            UpdateFlow.ui = this
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
            // «Подключено» на экране должно быть проверенным: открыли приложение — сервис ещё раз
            // проверяет связь через туннель (сам он делает это не чаще раза в 30 секунд).
            if (tunnel.supported && tunnel.isUp) tunnel.requestLinkCheck()
            // Адреса «умного» DNS — раз в сутки заново (они меняются, имя остаётся).
            refreshDnsByName(prefs.dnsIndex, force = false)
            startSimpleTick()
            // Адреса сайтов второго выхода — тоже раз в сутки (с 1.10.31).
            refreshSecondIfStale()
            // «Браузер — только к нужным сайтам» — собрать нужное, если ещё не собрано (с 1.10.35).
            prepareBrowserSitesInBackground()
            // Список бесплатных серверов Proton — раз в неделю.
            refreshProtonIfStale()
            updateSecondState()
            // Итог автовыбора выхода (эксперимент, с 1.10.43): сервис мог намерить новое, пока экран был закрыт.
            renderAppAuto()
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
        binding.editAvailCustom.setText(prefs.availCustom)
        fillDnsSpinner()
        fillFeatureSwitches()
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
        // Прежний ручной список CIDR (режим «вручную») становится «моими сайтами» (с 1.10.31).
        prefs.migrateManualRoutes()
        // Маршруты по спискам, собранные прежней версией, актуальными больше не помечаем (с 1.10.33):
        // подпись включает версию правил сборки, и при следующем «Сохранить и применить» они
        // соберутся заново. До 1.10.33 здесь помечали — и сети Google для видео YouTube из 1.10.31
        // до телефона не дошли (журнал 23.11: те же 683 маршрута с 1.10.30 до 1.10.32).
        binding.editTunnelSites.setText(prefs.tunnelSites)
        binding.switchSecondViaWarp.isChecked = prefs.secondViaWarp
        runCatching { buildSecondSources() }
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
        prefs.availCustom = binding.editAvailCustom.text?.toString()?.trim().orEmpty()
        saveAvailServices()
        if (binding.dnsSpinner.selectedItemPosition >= 0) prefs.dnsIndex = binding.dnsSpinner.selectedItemPosition
        prefs.poolMode = poolModeOf(binding.poolGroup.checkedButtonId)
        prefs.autoApply = binding.checkAutoApply.isChecked
        prefs.confTarget = confTargetOf(binding.exportGroup.checkedButtonId)
        prefs.routesMode = binding.spinnerRoutes.selectedItemPosition.coerceIn(0, 3)
        prefs.secondExitOn = binding.switchSecondExit.isChecked
        prefs.secondConf = binding.editSecondConf.text?.toString()?.trim().orEmpty()
        prefs.secondDomains = binding.editSecondDomains.text?.toString()?.trim().orEmpty()
        prefs.pinnedEndpoint = binding.editServer.text?.toString()?.trim().orEmpty()
        // Готовые маршруты (allowedIpsText, адреса своих сайтов) с экрана больше не читаются:
        // их пишут только сборки — «Обновить списки», «Найти адреса сайтов», «Сохранить и применить».
        prefs.tunnelSites = binding.editTunnelSites.text?.toString().orEmpty()
        prefs.secondViaWarp = binding.switchSecondViaWarp.isChecked
        if (secondChecks.isNotEmpty()) {
            prefs.secondSources = secondChecks.filter { it.value.isChecked }.keys.toSet()
        }
        prefs.checkByLists = binding.checkListChecks.isChecked
        prefs.allowBlockIds = listChecks.filter { it.value.isChecked && it.key in BLOCK_IDS }.map { it.key }.toSet()
        prefs.allowDirectIds = listChecks.filter { it.value.isChecked && it.key in DIRECT_IDS }.map { it.key }.toSet()
        prefs.enabledJunk = junkChecks.filter { it.isChecked }.map { it.tag.toString() }.toSet()
    }

    // ------------------------------------------------ DNS по имени и проверка ChatGPT

    /** Список DNS: имя и то, что сейчас пойдёт в конфиг (адреса по имени или запасные). */
    private fun fillDnsSpinner() {
        val index = prefs.dnsIndex.coerceIn(0, (Presets.DNS.size - 1).coerceAtLeast(0))
        binding.dnsSpinner.adapter = ArrayAdapter(
            this, android.R.layout.simple_spinner_dropdown_item,
            Presets.DNS.indices.map { DnsBook.label(this, it) }
        )
        binding.dnsSpinner.setSelection(index)
        updateDnsNote()
    }

    /** Подпись под списком DNS: откуда адреса и что делать, если их нет. */
    private fun updateDnsNote() {
        runCatching {
            val index = prefs.dnsIndex
            val preset = DnsBook.preset(index)
            val note = when {
                preset.host.isBlank() -> ""
                DnsBook.usesFallback(this, index) -> getString(R.string.dns_fallback_note, preset.name)
                else -> {
                    val byName = DnsBook.resolved(this, preset.host)
                    if (byName.isEmpty()) "" else getString(R.string.dns_resolved_note, preset.name, preset.host, byName.joinToString(", "))
                }
            }
            binding.textDnsNote.text = note
            binding.textDnsNote.visibility = if (note.isBlank()) View.GONE else View.VISIBLE
        }
    }

    /** Найти адреса DNS по имени в фоне и обновить список (раз в сутки или по выбору набора). */
    private fun refreshDnsByName(index: Int, force: Boolean) {
        if (DnsBook.preset(index).host.isBlank()) return
        if (!force && !DnsBook.needsRefresh(this, index)) return
        val app = applicationContext
        Thread({
            val found = runCatching { DnsBook.refresh(app, index) }.getOrDefault(emptyList())
            runOnUiThread {
                if (!::binding.isInitialized) return@runOnUiThread
                if (found.isNotEmpty()) {
                    TunnelDebug.stage("DNS «${DnsBook.preset(index).name}»: адреса по имени — ${found.joinToString(", ")}")
                }
                // Пересобираем подписи, не трогая выбор (слушатель сравнит с prefs и промолчит).
                runCatching { fillDnsSpinner() }
            }
        }, "warpscout-dns-name").apply { isDaemon = true }.start()
    }

    // ------------------------------------------------ переключатели новых функций

    private fun fillFeatureSwitches() {
        binding.switchFeatAutoStart.isChecked = prefs.featAutoStart
        binding.switchFeatLink.isChecked = prefs.featLinkReconnect
        binding.switchFeatProbe.isChecked = prefs.featProbeBeforeSwitch
        binding.switchFeatSpeed.isChecked = prefs.featSpeedAuto
        binding.switchFeatFreeze.isChecked = prefs.featFreezeReconnect
        binding.switchFeatDns.isChecked = prefs.featDnsInTunnel
        binding.switchFeatAbroad.isChecked = prefs.featAbroadSearch
        binding.switchFeatTgSecond.isChecked = prefs.featTgSecond
        binding.switchFeatAppAuto.isChecked = prefs.featAppAuto
        binding.switchFeatSecondWhole.isChecked = prefs.featSecondWhole
        renderAppAuto()
    }

    /** Итог последнего замера автовыбора выхода (файл пишет сервис) — читаем один раз на показ. */
    private fun appAutoStatus(): dev.warpscout.core.tunnel.AppAuto.Status? = runCatching {
        val f = File(filesDir, dev.warpscout.core.tunnel.AppAuto.STATUS_FILE)
        if (f.exists()) dev.warpscout.core.tunnel.AppAuto.Status.decode(f.readText()) else null
    }.getOrNull()

    /**
     * Под переключателем «выход для приложений — сам» (эксперимент, с 1.10.43): как он работает и что
     * намерил сервис в последний раз. Выключен — ничего не показываем.
     */
    private fun renderAppAuto() {
        val view = binding.textAppAuto
        if (!prefs.featAppAuto) {
            view.visibility = View.GONE
            return
        }
        val status = appAutoStatus()
        view.text = getString(R.string.app_auto_note) + "\n" +
            (status?.let { dev.warpscout.core.tunnel.AppAuto.statusLines(it).joinToString("\n") } ?: getString(R.string.app_auto_none))
        view.visibility = View.VISIBLE
    }

    /** Раздел отчёта «Приложения по точкам» (эксперимент, с 1.10.43) — только при включённом автовыборе. */
    private fun appsByPointSection(report: dev.warpscout.core.model.TuningReport): String {
        if (!prefs.featAppAuto) return ""
        return runCatching { "\n" + dev.warpscout.core.tunnel.AppAuto.byPointText(report, appAutoStatus()) }.getOrDefault("")
    }

    /**
     * Переключатели автоматики. Сервис читает их из своего снимка при каждом решении, поэтому
     * действуют сразу; «DNS через туннель» — при следующем подъёме (это маршруты туннеля).
     */
    private fun setupFeatureSwitches() {
        fun bind(view: com.google.android.material.materialswitch.MaterialSwitch, name: String, get: () -> Boolean, set: (Boolean) -> Unit) {
            view.setOnCheckedChangeListener { _, isChecked ->
                if (isChecked == get()) return@setOnCheckedChangeListener
                set(isChecked)
                TunnelDebug.stage("настройка «$name»: ${if (isChecked) "включена" else "выключена"}")
            }
        }
        bind(binding.switchFeatAutoStart, getString(R.string.feat_autostart), { prefs.featAutoStart }, { prefs.featAutoStart = it })
        bind(binding.switchFeatLink, getString(R.string.feat_link), { prefs.featLinkReconnect }, { prefs.featLinkReconnect = it })
        bind(binding.switchFeatProbe, getString(R.string.feat_probe), { prefs.featProbeBeforeSwitch }, { prefs.featProbeBeforeSwitch = it })
        bind(binding.switchFeatSpeed, getString(R.string.feat_speed), { prefs.featSpeedAuto }, { prefs.featSpeedAuto = it })
        bind(binding.switchFeatFreeze, getString(R.string.feat_freeze), { prefs.featFreezeReconnect }, { prefs.featFreezeReconnect = it })
        bind(binding.switchFeatDns, getString(R.string.feat_dns), { prefs.featDnsInTunnel }, { prefs.featDnsInTunnel = it })
        bind(binding.switchFeatAbroad, getString(R.string.feat_abroad), { prefs.featAbroadSearch }, { prefs.featAbroadSearch = it })
        bind(binding.switchFeatTgSecond, getString(R.string.feat_tg_second), { prefs.featTgSecond }, { prefs.featTgSecond = it })
        bind(binding.switchFeatAppAuto, getString(R.string.feat_app_auto_short), { prefs.featAppAuto }, {
            prefs.featAppAuto = it
            renderAppAuto()
            // Включили — первый замер сразу: сервис меряет после проверки связи.
            if (it && tunnel.supported && tunnel.isUp) runCatching { tunnel.requestLinkCheck() }
        })
        // «Второй выход» — приложение целиком (с 1.10.44-beta1): это маршруты туннеля — они меняются
        // при подключении, поэтому говорим, как применить сразу.
        bind(binding.switchFeatSecondWhole, getString(R.string.feat_second_whole_short), { prefs.featSecondWhole }, {
            prefs.featSecondWhole = it
            runCatching { updateTunnelSummary() }
            if (tunnel.supported && tunnel.isUp) banner(getString(R.string.feat_second_whole_apply))
        })
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

    /** Отметки «Что проверять»: код сервиса → его галочка (см. buildResourceList). */
    private val availBoxes = ArrayList<Pair<String, MaterialCheckBox>>()

    /**
     * «Что проверять» (с 1.10.30): галочки сервисов из Presets.SERVICE_CHECKS вместо прежнего
     * списка-подсказки, который нельзя было менять. Сохраняются сразу при нажатии.
     */
    private fun buildResourceList() {
        binding.resourceBox.removeAllViews()
        availBoxes.clear()
        val chosen = prefs.availServices
        Presets.SERVICE_CHECKS.forEach { check ->
            val box = MaterialCheckBox(this).apply {
                text = getString(R.string.avail_service_line, check.name, check.hint)
                isChecked = check.id in chosen
                layoutParams = LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.MATCH_PARENT,
                    LinearLayout.LayoutParams.WRAP_CONTENT
                )
            }
            box.setOnCheckedChangeListener { _, _ -> runCatching { saveAvailServices() } }
            availBoxes += check.id to box
            binding.resourceBox.addView(box)
        }
    }

    private fun saveAvailServices() {
        if (availBoxes.isEmpty()) return
        prefs.availServices = availBoxes.filter { it.second.isChecked }.map { it.first }.toSet()
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
                // Подбор мог пройти в фоне — список «Доступность» показываем свежим.
                renderAvailability()
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
        // До построения экрана (или на аварийном) переключать нечего — жест просто не наш. В
        // упрощённом виде вкладок на экране нет — и листать нечего.
        if (::pages.isInitialized && !simpleShown()) runCatching {
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
        // Начальные экраны (с 1.10.44-beta6) переживают поворот: страница, отметки, ожидание туннеля.
        welcome?.takeIf { it.isShowing }?.let { w ->
            outState.putInt(STATE_WELCOME_PAGE, w.currentPage)
            w.checkedNow()?.let { outState.putStringArrayList(STATE_WELCOME_CHECKED, it) }
        }
        if (secondSetupUntil != 0L) outState.putLong(STATE_SECOND_SETUP, secondSetupUntil)
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
            // Приложение со своим выходом идёт через туннель в любом режиме (с 1.10.39): отмечаем его
            // в «только выбранные» и убираем из исключений — чтобы отметки не расходились с делом.
            runCatching {
                val rules = prefs.appExitsActive().keys
                if (rules.isNotEmpty()) prefs.appsSelected = alignWithExits(prefs.appsMode, prefs.appsSelected, rules)
            }
            // Строки в «Все приложения» — без отметок, только выход (с 1.10.39): перестраиваем.
            rebuildAppsList()
            updateAppsState()
            markSettingsDirty(getString(R.string.dirty_apps_mode))
        }
        binding.checkAppsSystem.setOnCheckedChangeListener { _, _ -> rebuildAppsList() }
        binding.editAppSearch.doAfterTextChanged { rebuildAppsList() }
        rebuildAppsList()
        runCatching { setupTunnelTab() }.onFailure { t ->
            TunnelDebug.error("вкладка «Туннелирование»: " + SafeMode.describe(t))
        }
    }

    // ------------------------------------------------ туннелирование: сайты и списки (с 1.10.31)

    /**
     * Вкладка «Туннелирование»: сверху выбор — приложения, сайты или списки. Это выбор того, что
     * настраиваем, а не режим: приложения и сайты действуют вместе. Режим маршрутов (все сайты /
     * кроме российских / из списков / мои) — выпадающий список над сайтами и списками.
     */
    private fun setupTunnelTab() {
        binding.tunnelKindGroup.addOnButtonCheckedListener { _, checkedId, isChecked ->
            if (!isChecked) return@addOnButtonCheckedListener
            showTunnelPanel(
                when (checkedId) {
                    R.id.btnKindSites -> KIND_SITES
                    R.id.btnKindLists -> KIND_LISTS
                    else -> KIND_APPS
                }
            )
        }
        binding.tunnelKindGroup.check(
            when (prefs.routesMode) {
                3 -> R.id.btnKindSites
                2 -> R.id.btnKindLists
                else -> R.id.btnKindApps
            }
        )
        showTunnelPanel(
            when (prefs.routesMode) {
                3 -> KIND_SITES
                2 -> KIND_LISTS
                else -> KIND_APPS
            }
        )
        binding.editTunnelSites.doAfterTextChanged { text ->
            val value = text?.toString().orEmpty()
            if (value == prefs.tunnelSites) return@doAfterTextChanged
            prefs.tunnelSites = value
            // Вписали сайты — значит, через туннель должны идти они; стёрли всё — снова все сайты. В
            // режиме браузера свои сайты и так в деле — режим не трогаем (с 1.10.43, browserHoldsRoutes).
            if (value.isNotBlank() && prefs.routesMode != 3 && !browserHoldsRoutes()) binding.spinnerRoutes.setSelection(3)
            else if (value.isBlank() && prefs.routesMode == 3) binding.spinnerRoutes.setSelection(0)
            updateSitesState()
            updateTunnelSummary()
            markSettingsDirtyLater(getString(R.string.dirty_sites))
        }
        binding.btnBuildSites.setOnClickListener { buildSites() }
        // «Браузер — только к нужным сайтам» (с 1.10.35). Маршруты задаются при подключении —
        // правка ставит переподключение в очередь, как и выбор приложений.
        binding.switchBrowserSites.isChecked = prefs.featBrowserSites
        binding.switchBrowserSites.setOnCheckedChangeListener { _, isChecked ->
            if (isChecked == prefs.featBrowserSites) return@setOnCheckedChangeListener
            prefs.featBrowserSites = isChecked
            updateTunnelSummary()
            markSettingsDirty(getString(R.string.browser_sites_switch))
        }
        updateSitesState()
        updateTunnelSummary()
    }

    private fun showTunnelPanel(kind: Int) {
        binding.panelApps.visibility = if (kind == KIND_APPS) View.VISIBLE else View.GONE
        binding.panelRoutes.visibility = if (kind == KIND_APPS) View.GONE else View.VISIBLE
        binding.panelSites.visibility = if (kind == KIND_SITES) View.VISIBLE else View.GONE
        binding.panelLists.visibility = if (kind == KIND_LISTS) View.VISIBLE else View.GONE
    }

    /** Сколько маршрутов в строке CIDR через запятую. */
    private fun routeCount(text: String): Int = text.split(',').count { it.isNotBlank() }

    /**
     * «Сейчас через туннель: …» и предупреждения о пустом выборе. Пустого туннеля не бывает: без
     * отмеченных приложений и без собранных адресов через туннель идёт всё, — об этом и говорим.
     */
    private fun updateTunnelSummary() {
        if (!uiReady()) return
        runCatching {
            val selected = prefs.appsSelected.size
            val apps = when (prefs.appsMode) {
                Prefs.APPS_ONLY -> if (selected == 0) getString(R.string.tunnel_sum_apps_all)
                else getString(R.string.tunnel_sum_apps_only, selected)
                Prefs.APPS_EXCEPT -> if (selected == 0) getString(R.string.tunnel_sum_apps_all)
                else getString(R.string.tunnel_sum_apps_except, selected)
                else -> getString(R.string.tunnel_sum_apps_all)
            }
            val sitesRoutes = routeCount(prefs.tunnelSitesCidrs)
            val listRoutes = routeCount(prefs.allowedIpsText)
            // Сколько маршрутов получит туннель: к собранным добавляются сети Google для видео
            // YouTube (с 1.10.33), а без IPv6 v6-маршруты не выпускаются.
            val liveRoutes = runCatching { routeCount(prefs.allowedIps()) }.getOrDefault(0)
            val browserWanted = runCatching { prefs.browserSitesWanted() }.getOrDefault(false)
            val browserActive = browserWanted && runCatching { prefs.browserSitesActive() }.getOrDefault(false)
            // «Второй выход» — приложение целиком (с 1.10.44-beta1): маршруты — весь трафик выбранных.
            val whole = runCatching { prefs.secondWholeActive() }.getOrDefault(false)
            val routes = when {
                whole -> getString(R.string.tunnel_sum_routes_whole)
                browserActive -> getString(R.string.tunnel_sum_routes_browser, liveRoutes)
                prefs.routesMode == 1 -> getString(R.string.tunnel_sum_routes_preset)
                prefs.routesMode == 2 -> if (listRoutes == 0) getString(R.string.tunnel_sum_routes_all)
                else getString(R.string.tunnel_sum_routes_lists, if (liveRoutes > 0) liveRoutes else listRoutes)
                prefs.routesMode == 3 -> if (sitesRoutes == 0) getString(R.string.tunnel_sum_routes_all)
                else getString(R.string.tunnel_sum_routes_sites, if (liveRoutes > 0) liveRoutes else sitesRoutes)
                else -> getString(R.string.tunnel_sum_routes_all)
            }
            val text = buildString {
                append(getString(R.string.tunnel_sum, apps, routes))
                if (whole) {
                    append("\n").append(getString(R.string.tunnel_second_whole, prefs.secondWholeTitles()))
                }
                if (prefs.appsMode == Prefs.APPS_ONLY && selected == 0) {
                    append("\n").append(getString(R.string.tunnel_warn_apps_empty))
                }
                if (!whole && ((prefs.routesMode == 2 && listRoutes == 0) || (prefs.routesMode == 3 && sitesRoutes == 0))) {
                    append("\n").append(getString(R.string.tunnel_warn_routes_empty))
                }
                // Браузер выбран, а сети выбранных приложений ещё не собраны — пока браузер идёт целиком.
                if (browserWanted && !browserActive && !whole) {
                    append("\n").append(getString(R.string.tunnel_browser_pending))
                }
                // Сайты выбраны не все (с 1.10.35): известные сервисы идут целиком по своим сетям, а о
                // приложениях, чьих сетей мы не знаем, — предупреждаем: они идут только к выбранным
                // сайтам (так решил человек 23.11).
                val partial = !whole && (browserActive ||
                    ((prefs.routesMode == 2 && listRoutes > 0) || (prefs.routesMode == 3 && sitesRoutes > 0)))
                if (prefs.appsMode == Prefs.APPS_ONLY && selected > 0 && partial) {
                    val whole = dev.warpscout.core.lists.AppServices.titlesFor(prefs.appsSelected)
                    if (whole.isNotEmpty()) {
                        append("\n").append(getString(R.string.tunnel_apps_whole, whole.joinToString(", ")))
                    }
                    val unknown = runCatching { prefs.unknownSelectedApps() }.getOrDefault(emptyList())
                    if (unknown.isNotEmpty()) {
                        val names = unknown.take(6).joinToString(", ") { "«${labelOfPackage(it)}»" } +
                            if (unknown.size > 6) " и ещё ${unknown.size - 6}" else ""
                        append("\n").append(getString(R.string.tunnel_warn_unknown_apps, names))
                        if (browserActive || prefs.routesMode == 3) {
                            append(" ").append(getString(R.string.tunnel_warn_unknown_fix))
                        }
                    }
                }
                // Спутники (с 1.10.37): Gemini работает внутри приложения Google, и оно идёт через туннель
                // вместе с ним — иначе Gemini писал «Эта страна не поддерживается». Говорим, куда оно
                // идёт, и предупреждаем, если его нет на телефоне: без него Gemini не откроется.
                if (prefs.appsMode == Prefs.APPS_ONLY && selected > 0) {
                    dev.warpscout.core.lists.AppServices.companionsFor(prefs.appsSelected).forEach { j ->
                        val installed = runCatching {
                            @Suppress("DEPRECATION")
                            packageManager.getApplicationInfo(j.companion.pkg, 0)
                        }.isSuccess
                        val res = when {
                            !installed -> R.string.tunnel_apps_companion_missing
                            partial -> R.string.tunnel_apps_companion_sites
                            else -> R.string.tunnel_apps_companion
                        }
                        append("\n").append(getString(res, j.service, j.companion.title))
                    }
                }
                append(otherProfileNote())
            }
            binding.textTunnelSummary.text = text
        }
    }

    /** Что с моими сайтами: сколько вписано, сколько маршрутов собрано, не правили ли с тех пор. */
    private fun updateSitesState() {
        if (!uiReady()) return
        runCatching {
            val parsed = SiteList.parse(prefs.tunnelSites)
            val built = routeCount(prefs.tunnelSitesCidrs)
            val text = buildString {
                when {
                    parsed.isEmpty -> append(getString(R.string.sites_state_none))
                    prefs.tunnelSitesSig != prefs.tunnelSites.trim() || built == 0 ->
                        append(getString(R.string.sites_state_dirty))
                    else -> append(
                        getString(
                            R.string.sites_state_built, parsed.total, built,
                            agoText(prefs.tunnelSitesAt)
                        )
                    )
                }
                if (parsed.bad.isNotEmpty()) {
                    append("\n").append(getString(R.string.sites_bad, parsed.bad.take(5).joinToString(", ")))
                }
            }
            binding.textSitesState.text = text
        }
    }

    /** «Найти адреса сайтов»: домены → адреса через DoH, режим — «только мои сайты». */
    private fun buildSites() {
        persistUi()
        if (SiteList.parse(prefs.tunnelSites).isEmpty) {
            toast(getString(R.string.sites_state_none))
            return
        }
        binding.btnBuildSites.isEnabled = false
        binding.textSitesState.setText(R.string.sites_resolving)
        Thread {
            val result = runCatching { buildSitesSync() }
            runOnUiThread {
                if (!uiReady()) return@runOnUiThread
                binding.btnBuildSites.isEnabled = true
                result.onSuccess { n ->
                    if (n > 0) {
                        if (prefs.routesMode != 3 && !browserHoldsRoutes()) binding.spinnerRoutes.setSelection(3)
                        toast(getString(R.string.sites_built, n))
                        markSettingsDirty(getString(R.string.dirty_sites))
                    } else {
                        toast(getString(R.string.sites_failed))
                    }
                }.onFailure { toast(it.message ?: it.javaClass.simpleName) }
                updateSitesState()
                updateTunnelSummary()
                refreshRoutesState()
            }
        }.apply { isDaemon = true; name = "warpscout-sites" }.start()
    }

    /** Мои сайты → маршруты (сеть: не из UI-потока). Возвращает число маршрутов. */
    private fun buildSitesSync(): Int {
        val text = prefs.tunnelSites
        val parsed = SiteList.parse(text)
        val resolved = if (parsed.hosts.isEmpty()) emptyMap() else AllowListPlanner.resolveAll(SiteList.withWww(parsed.hosts))
        val cidrs = SiteList.cidrs(parsed, resolved)
        if (cidrs.isNotEmpty()) {
            prefs.tunnelSitesCidrs = cidrs.joinToString(", ")
            prefs.tunnelSitesSig = text.trim()
            prefs.tunnelSitesAt = System.currentTimeMillis()
        }
        TunnelDebug.stage("мои сайты: ${parsed.total} → ${cidrs.size} маршрутов")
        return cidrs.size
    }

    /** Подпись отмеченных списков и правил сборки (см. Prefs.listsSignature). */
    private fun listsSignature(): String = prefs.listsSignature()

    /**
     * Сайты сейчас — это сайты браузера (с 1.10.43): «только выбранные», среди них браузер, включено
     * «Браузер — только к нужным сайтам», а режим сайтов — «все» или «всё, кроме российских сетей».
     * Тогда списки и «Мои сайты» задают, куда браузер идёт через туннель, и их правка не должна
     * переключать режим. Раньше галочка списка (и «Собрать маршруты») ставила «Только сайты из
     * списков», а правка своих сайтов — «Только мои сайты»: режим браузера выключался, и «Мои сайты»
     * (или списки) молча выпадали из маршрутов.
     */
    private fun browserHoldsRoutes(): Boolean = runCatching { prefs.browserSitesWanted() }.getOrDefault(false)

    /** Маршруты по спискам (сеть: не из UI-потока): недостающие списки скачиваются сами. */
    private fun buildListsSync(): String {
        val ids = (prefs.allowBlockIds.ifEmpty { dev.warpscout.core.lists.AllowLists.DEFAULT_BLOCK_IDS.toSet() } +
            prefs.allowDirectIds).toList()
        val cache = lists.cached()
        val missing = ids.filter { cache[it] == null }
        if (missing.isNotEmpty()) lists.refresh(missing) { line -> runOnUiThread { sink().log(line) } }
        val r = lists.buildPlan(prefs) { line -> runOnUiThread { sink().log(line) } }
        val summary = lists.savePlan(prefs, r.plan)
        prefs.listsBuiltSig = listsSignature()
        return summary
    }

    /** Что собрать перед применением: свои сайты, маршруты по спискам, сети выбранных приложений. */
    private class RouteNeeds(val sites: Boolean, val lists: Boolean, val apps: Boolean) {
        val any: Boolean get() = sites || lists || apps
    }

    /**
     * Что не собрано или устарело. С 1.10.35 — и для «Браузер — только к нужным сайтам» (ему нужны
     * свои сайты и отмеченные списки), и сети выбранных приложений: при неполных маршрутах
     * Telegram, Instagram, YouTube идут через туннель целиком только с ними.
     */
    private fun routeNeeds(): RouteNeeds {
        // «Второй выход» — приложение целиком (с 1.10.44-beta1): маршруты — весь трафик выбранных
        // приложений, собирать адреса сайтов и сети приложений для них не нужно.
        if (runCatching { prefs.secondWholeActive() }.getOrDefault(false)) return RouteNeeds(false, false, false)
        val browser = runCatching { prefs.browserSitesWanted() }.getOrDefault(false)
        val sites = (prefs.routesMode == 3 || browser) && prefs.tunnelSites.isNotBlank() &&
            (prefs.tunnelSitesSig != prefs.tunnelSites.trim() || prefs.tunnelSitesCidrs.isBlank())
        val lists = (prefs.routesMode == 2 || browser) &&
            (prefs.allowedIpsText.isBlank() || prefs.listsBuiltSig != listsSignature())
        val partial = browser || prefs.routesMode == 2 || prefs.routesMode == 3
        // Сети нужны выбранным приложениям («только выбранные») и, с 1.10.39, приложениям с выходом
        // «Второй выход» в любом режиме — appNetsReady() знает обоих.
        val apps = partial && !prefs.appNetsReady()
        return RouteNeeds(sites, lists, apps)
    }

    /**
     * Сети выбранных приложений → адреса (сеть: не из UI-потока, с 1.10.35): списки их сервисов
     * (AppServices) — подсети как есть, домены через DoH. false — не собрались: тогда маршруты
     * остаются прежними (браузер идёт целиком), а не без сетей Telegram и YouTube.
     */
    private fun buildAppNetsSync(): Boolean {
        val ids = prefs.appNetsLists()
        val sig = prefs.appNetsSignature()
        if (ids.isEmpty()) {
            prefs.appNetsText = ""
            prefs.appNetsSig = sig
            return true
        }
        val missing = ids.filter { lists.cached()[it] == null }
        if (missing.isNotEmpty()) lists.refresh(missing) { line -> runOnUiThread { sink().log(line) } }
        val cache = lists.cached()
        val absent = ids.filter { cache[it] == null }
        if (absent.isNotEmpty()) {
            TunnelDebug.stage("сети выбранных приложений не собраны: не скачались списки ${absent.joinToString(", ")}")
            return false
        }
        val block = ids.mapNotNull { dev.warpscout.core.lists.AllowLists.byId[it] }
        val plan = AllowListPlanner.plan(
            block = block,
            direct = emptyList(),
            parsed = cache.mapValues { it.value.parsed },
            maxDomains = prefs.routeDomainBudget
        )
        if (plan.include.isEmpty()) return false
        // Адрес замера скорости — тоже в маршруты: при неполных маршрутах замер после подключения
        // шёл бы мимо туннеля и не мерился («не мерил — адрес замера не в маршрутах»), а по нему
        // ловится «заморозка» точки.
        val speed = runCatching { AllowListPlanner.dohResolve("speed.cloudflare.com") }.getOrDefault(emptyList())
            .mapNotNull { a ->
                when {
                    a.contains(':') -> "$a/128"
                    a.count { it == '.' } == 3 -> "$a/32"
                    else -> null
                }
            }
        prefs.appNetsText = (plan.include + speed).distinct().joinToString(", ")
        prefs.appNetsSig = sig
        prefs.appNetsAt = System.currentTimeMillis()
        TunnelDebug.stage(
            "сети выбранных приложений (" + dev.warpscout.core.lists.AppServices.titlesFor(prefs.appsForNets()).joinToString(", ") +
                "): ${plan.include.size} маршрутов"
        )
        return true
    }

    /** Идёт подготовка «Браузер — только к нужным сайтам» в фоне — второй раз не запускаем. */
    @Volatile
    private var browserPrepRunning = false

    /** Подготовка в фоне уже была в этом процессе (удалась или нет) — сама больше не запускается. */
    private var browserPrepTried = false

    /**
     * Браузер среди выбранных и «Браузер — только к нужным сайтам» включён, а нужное не собрано
     * (например, сразу после обновления до 1.10.35) — собираем сами, в фоне, один раз за процесс.
     * Маршруты меняются только при подключении: собранное поднимется со следующим подключением, а
     * сразу — по «Сохранить и применить» (так и говорим). Ради этого туннель сами не рвём.
     */
    private fun prepareBrowserSitesInBackground() {
        if (browserPrepRunning || browserPrepTried || preparingRoutes) return
        val wanted = runCatching { prefs.browserSitesWanted() }.getOrDefault(false)
        if (!wanted) return
        val needs = runCatching { routeNeeds() }.getOrNull() ?: return
        if (!needs.any) return
        browserPrepRunning = true
        browserPrepTried = true
        Thread {
            val ok = runCatching {
                if (needs.sites) buildSitesSync()
                if (needs.lists) buildListsSync()
                if (needs.apps) buildAppNetsSync() else true
            }.getOrDefault(false)
            runCatching { dev.warpscout.app.status.ServiceSettingsStore.syncFromPrefs(this) }
            runOnUiThread {
                browserPrepRunning = false
                if (!uiReady()) return@runOnUiThread
                runCatching {
                    updateTunnelSummary()
                    updateSimple()
                    if (ok && prefs.browserSitesActive()) {
                        TunnelDebug.stage("браузер — только к нужным сайтам: адреса собраны — с следующего подключения (сразу — «Сохранить и применить»)")
                        if (tunnel.supported && tunnel.isUp) banner(getString(R.string.browser_sites_ready))
                    } else if (!ok) {
                        TunnelDebug.stage("браузер — только к нужным сайтам: адреса не собрались — браузер пока идёт целиком")
                    }
                }
            }
        }.apply { isDaemon = true; name = "warpscout-browser-sites" }.start()
    }

    /** Идёт сборка перед «Сохранить и применить» — второй раз не запускаем. */
    private var preparingRoutes = false

    /**
     * «Сохранить и применить» (с 1.10.31): сначала собрать то, что не собрано или устарело, —
     * адреса своих сайтов, маршруты по спискам, адреса второго выхода, — потом применить. Помнить
     * про отдельные кнопки «Собрать» больше не нужно: одна кнопка делает всё.
     */
    private fun applyWithRoutes(why: String, upText: String? = null, downText: String? = null) {
        runCatching { persistUi() }
        val needs = routeNeeds()
        val needSites = needs.sites
        val needLists = needs.lists
        val needApps = needs.apps
        val needSecond = SecondRoutes.needsBuild(prefs)
        if (!needSites && !needLists && !needApps && !needSecond) {
            saveAndApply(why, upText, downText)
            scheduleSecondCheck()
            return
        }
        if (preparingRoutes) {
            banner(getString(R.string.routes_preparing))
            return
        }
        preparingRoutes = true
        banner(getString(R.string.routes_preparing))
        Thread {
            val errors = mutableListOf<String>()
            if (needSites) {
                runCatching { buildSitesSync() }
                    .onSuccess { n -> if (n == 0) errors += getString(R.string.sites_failed) }
                    .onFailure { errors += (it.message ?: it.javaClass.simpleName) }
            }
            if (needLists) runCatching { buildListsSync() }.onFailure { errors += (it.message ?: it.javaClass.simpleName) }
            if (needApps) {
                runCatching { buildAppNetsSync() }
                    .onSuccess { ok -> if (!ok) errors += getString(R.string.app_nets_failed) }
                    .onFailure { errors += (it.message ?: it.javaClass.simpleName) }
            }
            if (needSecond) {
                runCatching {
                    val r = SecondRoutes.build(this, prefs) { line -> runOnUiThread { sink().log(line) } }
                    SecondRoutes.save(prefs, r)
                    TunnelDebug.stage("второй выход: ${r.note()}")
                    if (r.cidrs.isEmpty()) errors += "второй выход: " + r.note()
                }.onFailure { errors += (it.message ?: it.javaClass.simpleName) }
            }
            runOnUiThread {
                preparingRoutes = false
                if (!uiReady()) return@runOnUiThread
                runCatching {
                    // Не собралось — применяем как есть и говорим об этом той же плашкой: иначе
                    // «применяю…» сразу закрыла бы сообщение об ошибке.
                    val failed = if (errors.isEmpty()) null
                    else getString(R.string.routes_prepare_failed, errors.joinToString("; ").take(160))
                    if (failed != null) TunnelDebug.stage("сборка перед применением: " + errors.joinToString("; "))
                    saveAndApply(why, failed ?: upText, failed ?: downText)
                    updateSitesState()
                    updateTunnelSummary()
                    updateSecondState()
                    scheduleSecondCheck()
                }.onFailure { t -> TunnelDebug.error("применение: " + SafeMode.describe(t)) }
            }
        }.apply { isDaemon = true; name = "warpscout-prepare" }.start()
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
            val copies = DefaultApps.otherProfileCopies(this)
            runOnUiThread {
                if (!::binding.isInitialized) return@runOnUiThread
                appEntries = loaded
                otherProfileCopies = copies
                if (loaded.size != before) {
                    rebuildAppsList()
                    updateAppsState()
                }
                val shown = runCatching { applyDefaultApps() }.onFailure { t ->
                    TunnelDebug.error("приложения по умолчанию: " + SafeMode.describe(t))
                }.getOrNull()
                // С 1.10.44 (в бете — с 1.10.44-beta4): TikTok, ChatGPT, Claude, Gemini, Grok — второй выход
                // по умолчанию.
                runCatching { applySecondDefaults(shown) }.onFailure { t ->
                    TunnelDebug.error("второй выход по умолчанию: " + SafeMode.describe(t))
                }
            }
        }.apply { isDaemon = true; name = "warpscout-apps" }.start()
    }

    /** Сервисы из набора по умолчанию, у которых есть копия в другом профиле Android. */
    private var otherProfileCopies: List<String> = emptyList()

    /** «⚠ Копия Telegram — в другом профиле…» с новой строки; пусто — копий нет. */
    private fun otherProfileNote(): String =
        if (otherProfileCopies.isEmpty()) ""
        else "\n" + getString(R.string.apps_other_profile, otherProfileCopies.joinToString(", "))

    /**
     * Набор по умолчанию (с 1.10.31): Telegram, Instagram, YouTube, Facebook, X и их дубликаты (см.
     * DefaultApps). Первый раз включаем «только выбранные», если человек сам ничего не выбирал;
     * дальше отмечаем новые приложения из набора: поставили Telegram X — он тоже в туннеле. Галочку,
     * снятую вручную, не возвращаем. Работающий туннель не переподключаем: список приложений
     * применится при следующем подключении. Возвращает текст показанной плашки (null — не показывали):
     * «второй выход по умолчанию» дописывает свою строку к ней, а не затирает.
     */
    private fun applyDefaultApps(): String? {
        if (!uiReady() || appEntries.isEmpty()) return null
        val found = DefaultApps.find(appEntries.map { Triple(it.pkg, it.label, it.system) }, packageName)
        val first = !prefs.appsDefaultsDone
        if (first) prefs.appsDefaultsDone = true
        if (found.isEmpty()) return null
        var modeChanged = false
        if (first && prefs.appsMode == Prefs.APPS_ALL && prefs.appsSelected.isEmpty()) {
            prefs.appsMode = Prefs.APPS_ONLY
            modeChanged = true
        }
        if (prefs.appsMode != Prefs.APPS_ONLY) return null
        val add = found.keys - prefs.appsSelected - prefs.appsUnticked
        if (add.isEmpty() && !modeChanged) return null
        prefs.appsSelected = prefs.appsSelected + add
        runCatching { ServiceSettingsStore.syncFromPrefs(this) }
        val names = add.map { labelOfPackage(it) }.sortedBy { it.lowercase() }
        TunnelDebug.stage(
            "приложения по умолчанию: " + (if (modeChanged) "включено «только выбранные»; " else "") +
                "отмечены ${names.joinToString(", ")}"
        )
        suppressSettingsReconnect = true
        runCatching {
            binding.appsGroup.check(appsButtonId(prefs.appsMode))
            rebuildAppsList()
            updateAppsState()
        }
        suppressSettingsReconnect = false
        updateSimple()
        if (names.isEmpty()) return null
        val text = getString(
            if (tunnel.supported && tunnel.isUp) R.string.apps_defaults_added_up else R.string.apps_defaults_added,
            names.joinToString(", ")
        )
        banner(text)
        return text
    }

    /** Плашка «второй выход по умолчанию» и когда её показали — см. [markSettingsDirty]. */
    private var secondDefaultsBanner: String? = null
    private var secondDefaultsBannerAt = 0L

    /**
     * С 1.10.44 (в бете — с 1.10.44-beta4): у TikTok, ChatGPT, Claude, Gemini и Grok выход по умолчанию — «Второй
     * выход», приложение целиком через свой сервер (человек попросил 24.11; правила — SecondDefaults).
     * Только когда выход приложений есть: второй выход включён, его конфиг читается, Android 10+ — без
     * второго выхода правило не действует, а отмеченные приложения шли бы через WARP с тем же
     * российским адресом. Каждое приложение — один раз: выбрал человек потом «Само» — так и останется.
     * Работающий туннель не переподключаем, как и с набором по умолчанию: правила и отметки — со
     * следующего подключения. [shown] — плашка, которую только что показал набор по умолчанию: её не
     * затираем, а дописываем.
     */
    private fun applySecondDefaults(shown: String?) {
        if (!uiReady() || appEntries.isEmpty()) return
        if (!runCatching { appExitsAvailable() }.getOrDefault(false)) return
        val seenBefore = prefs.secondDefaultsSeen
        val plan = SecondDefaults.plan(
            installed = appEntries.map { it.pkg },
            exits = prefs.appExits,
            appsMode = prefs.appsMode,
            selected = prefs.appsSelected,
            unticked = prefs.appsUnticked,
            seen = seenBefore,
        )
        if (plan.seen != seenBefore) prefs.secondDefaultsSeen = plan.seen
        val kept = plan.kept.map { pkg ->
            labelOfPackage(pkg) + " — " + when (plan.exits[pkg]) {
                AppExit.SECOND -> "уже второй выход"
                AppExit.WARP -> "всегда WARP"
                else -> if (prefs.appsMode == Prefs.APPS_EXCEPT) "исключено из туннеля" else "снято с туннеля руками"
            }
        }.sortedBy { it.lowercase() }
        if (!plan.changed) {
            if (kept.isNotEmpty()) TunnelDebug.stage("второй выход по умолчанию: выбор человека не тронут — ${kept.joinToString(", ")}")
            return
        }
        prefs.appExits = plan.exits
        if (plan.selected != prefs.appsSelected) prefs.appsSelected = plan.selected
        runCatching { ServiceSettingsStore.syncFromPrefs(this) }
        val names = plan.added.map { labelOfPackage(it) }.sortedBy { it.lowercase() }
        val ticked = plan.ticked.map { labelOfPackage(it) }.sortedBy { it.lowercase() }
        TunnelDebug.stage(
            "второй выход по умолчанию: ${names.joinToString(", ")} — целиком через второй выход" +
                (if (ticked.isNotEmpty()) "; отмечены в «только выбранные»: ${ticked.joinToString(", ")}" else "") +
                (if (kept.isNotEmpty()) "; выбор человека не тронут: ${kept.joinToString(", ")}" else "")
        )
        suppressSettingsReconnect = true
        runCatching {
            rebuildAppsList()
            updateAppsState()
        }
        suppressSettingsReconnect = false
        updateSimple()
        val text = getString(
            if (tunnel.supported && tunnel.isUp) R.string.second_defaults_added_up else R.string.second_defaults_added,
            names.joinToString(", ")
        )
        secondDefaultsBanner = text
        secondDefaultsBannerAt = System.currentTimeMillis()
        banner(if (shown.isNullOrEmpty()) text else "$shown\n$text")
    }

    /** Галочку поставили или сняли руками: снятую с приложения из набора больше не возвращаем. */
    private fun noteAppTick(pkg: String, checked: Boolean) {
        val app = appEntries.firstOrNull { it.pkg == pkg }
        // С 1.10.44 (в бете — с 1.10.44-beta4) — и у приложений «второй выход по умолчанию» (SecondDefaults): галочку,
        // снятую до того, как правило поставилось, правило не вернёт.
        val secondDefault = SecondDefaults.wants(pkg)
        if (!secondDefault && DefaultApps.familyOf(pkg, app?.label.orEmpty(), app?.system ?: false) == null) return
        prefs.appsUnticked = if (checked) prefs.appsUnticked - pkg else prefs.appsUnticked + pkg
    }

    private fun rebuildAppsList() {
        binding.appsBox.removeAllViews()
        appChecks.clear()
        appExitButtons.clear()
        // Кнопка выхода в строке (с 1.10.39) — когда есть второй выход и Android 10+.
        val exitsOn = runCatching { appExitsAvailable() }.getOrDefault(false)
        appExitsShown = exitsOn
        binding.textAppExitHint.visibility = if (exitsOn) View.VISIBLE else View.GONE
        // В режиме «все приложения» отмечать нечего: список нужен только для выхода приложений.
        // Без второго выхода — не тратим время на getApplicationLabel для сотни пакетов.
        if (prefs.appsMode == Prefs.APPS_ALL && !exitsOn) return
        val query = binding.editAppSearch.text?.toString()?.trim()?.lowercase().orEmpty()
        val showSystem = binding.checkAppsSystem.isChecked
        val selected = prefs.appsSelected
        val exits = prefs.appExits
        val matched = appEntries.filter { app ->
            (showSystem || !app.system) &&
                (query.isEmpty() || app.label.lowercase().contains(query) || app.pkg.contains(query))
        }
        matched.take(APP_ROWS_LIMIT).forEach { app ->
            val title = if (app.system) getString(R.string.app_row_system, app.label) else app.label
            if (prefs.appsMode == Prefs.APPS_ALL) {
                // «Все приложения»: отметок нет — название и выход.
                val label = android.widget.TextView(this).apply {
                    text = title
                    textSize = 15f
                    minHeight = (48 * resources.displayMetrics.density).toInt()
                    gravity = android.view.Gravity.CENTER_VERTICAL
                }
                binding.appsBox.addView(exitRow(label, app.pkg, exits[app.pkg] ?: AppExit.AUTO))
                return@forEach
            }
            val row = MaterialCheckBox(this).apply {
                text = title
                tag = app.pkg
                isChecked = app.pkg in selected
                setOnClickListener {
                    noteAppTick(app.pkg, isChecked)
                    // Приложение ушло из туннеля — его выход снова «Само» (с 1.10.39).
                    val out = (prefs.appsMode == Prefs.APPS_ONLY && !isChecked) ||
                        (prefs.appsMode == Prefs.APPS_EXCEPT && isChecked)
                    if (out && app.pkg in prefs.appExits) {
                        prefs.appExits = prefs.appExits - app.pkg
                        appExitButtons[app.pkg]?.text = exitLabel(AppExit.AUTO)
                    }
                    saveAppsSelection()
                }
                layoutParams = LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.MATCH_PARENT,
                    LinearLayout.LayoutParams.WRAP_CONTENT
                )
            }
            appChecks[app.pkg] = row
            binding.appsBox.addView(if (exitsOn) exitRow(row, app.pkg, exits[app.pkg] ?: AppExit.AUTO) else row)
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
        // С 1.10.39 список нужен и в «Все приложения», когда есть второй выход: там выбирают выход.
        val exitsOn = runCatching { appExitsAvailable() }.getOrDefault(false)
        val needsList = prefs.appsMode != Prefs.APPS_ALL || exitsOn
        binding.textAppExitHint.visibility = if (exitsOn) View.VISIBLE else View.GONE
        // «Браузер — только к нужным сайтам» имеет смысл, только когда приложения выбраны (с 1.10.35).
        val onlyMode = if (prefs.appsMode == Prefs.APPS_ONLY) View.VISIBLE else View.GONE
        binding.switchBrowserSites.visibility = onlyMode
        binding.textBrowserSitesNote.visibility = onlyMode
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
        } + exitsStateLine(exitsOn)
        updateTunnelSummary()
    }

    /** « · свой выход: 2» на карточке «Туннелирование» упрощённого экрана (с 1.10.39). */
    private fun exitsCardNote(): String {
        val count = prefs.appExits.size
        if (count == 0 || !prefs.secondExitOn || Build.VERSION.SDK_INT < 29) return ""
        return " · " + getString(R.string.simple_tun_exits, count)
    }

    /** Строка «Выход по выбору: Aurora Store — второй выход, Telegram — WARP» (с 1.10.39). */
    private fun exitsStateLine(exitsOn: Boolean): String {
        val rules = prefs.appExits
        if (!exitsOn || rules.isEmpty()) return ""
        return "\n" + getString(R.string.apps_exits_state, exitsSummary(rules))
    }

    // ------------------------------------------------ доступность (Журнал)

    /**
     * «Доступность» (с 1.10.30): два списка с подписями — через туннель (точка, время, при подборе
     * или по кнопке) и без VPN (база сравнения подбора). Раньше здесь был один список без подписи,
     * и итог без VPN читался как «через туннель открылось».
     */
    private fun renderAvailability() {
        if (!::binding.isInitialized) return
        runCatching { renderAvailabilityUnsafe() }.onFailure { t ->
            TunnelDebug.error("список доступности: " + SafeMode.describe(t))
        }
        runCatching { renderDpi() }.onFailure { t ->
            TunnelDebug.problem("итог проверки DPI: " + SafeMode.describe(t))
        }
    }

    /** Идёт «Проверить DPI» — второй раз не запускаем. */
    @Volatile
    private var dpiChecking = false

    /**
     * «Проверить DPI» (с 1.10.49-beta2, бета): YouTube, Discord и др. напрямую через провайдера — как
     * есть и с приёмами обхода (см. [DpiCheck]). Туннель не трогается: проверка идёт мимо него.
     */
    private fun checkDpiNow() {
        if (dpiChecking) return
        // Подбор привязывает процесс к сети и гасит туннель — проверять в это время незачем.
        if (engine.running || Availability.processBound(this)) {
            banner(getString(R.string.dpi_busy_scan))
            return
        }
        val ownUp = tunnel.supported && (tunnel.isUp || tunnel.active)
        // Чужой VPN обойти нельзя (Android пускает мимо, только если тот сам разрешил): проверка
        // показала бы его, а не провайдера.
        val foreign = ForeignVpn.find(this, ownUp = ownUp)
        if (foreign != null) {
            TunnelDebug.stage("DPI: проверка не запущена — работает другой VPN ($foreign)")
            banner(getString(R.string.dpi_foreign_vpn, foreign), error = true)
            return
        }
        dpiChecking = true
        binding.btnDpiCheck.isEnabled = false
        binding.btnDpiCheck.setText(R.string.dpi_checking)
        binding.textDpiProgress.visibility = View.VISIBLE
        binding.textDpiProgress.text = getString(R.string.dpi_running)
        val app = applicationContext
        Thread({
            val result = runCatching {
                DpiCheck.run(app, ownUp, progress = { line ->
                    runOnUiThread {
                        if (::binding.isInitialized && dpiChecking) {
                            binding.textDpiProgress.text = getString(R.string.dpi_progress, line)
                        }
                    }
                }, cancelled = { false })
            }
            runOnUiThread {
                dpiChecking = false
                if (!::binding.isInitialized || isFinishing || isDestroyed) return@runOnUiThread
                runCatching {
                    binding.btnDpiCheck.isEnabled = true
                    binding.btnDpiCheck.setText(R.string.dpi_check_now)
                    binding.textDpiProgress.visibility = View.GONE
                    renderDpi()
                    result.onSuccess { done ->
                        banner(getString(R.string.dpi_done, done.second.label))
                        // План обхода этой сети — работающему туннелю (с 1.10.49-beta3).
                        if (tunnel.supported && (tunnel.isUp || tunnel.active)) runCatching { tunnel.reloadDpi() }
                    }.onFailure { t ->
                        if (t is DpiCheck.NoBypass) {
                            banner(getString(R.string.dpi_no_bypass), error = true)
                        } else {
                            TunnelDebug.problem("DPI: проверка не удалась: " + SafeMode.describe(t))
                            banner(getString(R.string.banner_ui_error, SafeMode.describe(t)), error = true)
                        }
                    }
                }
            }
        }, "warpscout-dpi").apply { isDaemon = true }.start()
    }

    /** Итоги «Проверить DPI»: подробно — по текущей сети, по остальным — строкой. */
    private fun renderDpi() {
        runCatching { renderDpiBypass() }
        val all = DpiCheck.load(this)
        val key = NetIdentity.currentKey(this)
        val current = all.firstOrNull { it.network == key } ?: all.firstOrNull()
        val box = binding.dpiResultsBox
        box.removeAllViews()
        if (current == null) {
            binding.textDpiHead.visibility = View.GONE
            binding.textDpiSummary.visibility = View.GONE
            binding.textDpiOther.visibility = View.GONE
            return
        }
        binding.textDpiHead.visibility = View.VISIBLE
        binding.textDpiHead.text = getString(R.string.dpi_head, current.label, dpiWhen(current.at)) +
            (if (current.network != key) "\n" + getString(R.string.dpi_other_network_note) else "")
        current.rows.forEach { r -> box.addView(dpiRow(r)) }
        binding.textDpiSummary.visibility = View.VISIBLE
        binding.textDpiSummary.text = current.summary +
            (if (current.byedpi.isNotBlank()) "\n" + getString(R.string.dpi_byedpi, current.byedpi) else "")
        val others = all.filter { it !== current }
        binding.textDpiOther.visibility = if (others.isEmpty()) View.GONE else View.VISIBLE
        binding.textDpiOther.text = others.joinToString("\n\n") { o ->
            getString(R.string.dpi_head, o.label, dpiWhen(o.at)) + ": " + o.summary
        }
    }

    /**
     * Под переключателем «Обход DPI в туннеле» (с 1.10.49-beta3): что он сделает на текущей сети — по
     * плану из её последней проверки. Итог прежней версии (без плана) — «проверки ещё не было».
     */
    private fun renderDpiBypass() {
        val on = prefs.featDpiBypass
        if (binding.switchDpiBypass.isChecked != on) binding.switchDpiBypass.isChecked = on
        val key = NetIdentity.currentKey(this)
        val label = DpiCheck.labelOf(this, key)
        val saved = DpiCheck.load(this).firstOrNull { it.network == key }
        val plan = DpiCheck.planFor(this, key)
        binding.textDpiBypass.text = when {
            !on -> getString(R.string.dpi_bypass_off)
            !plan.isEmpty -> getString(R.string.dpi_bypass_on, label, plan.describe())
            saved != null && saved.trusted && saved.plan == DpiCheck.PLAN_NONE -> getString(R.string.dpi_bypass_none, label)
            else -> getString(R.string.dpi_bypass_unknown, label)
        }
    }

    /** «14:05» сегодня, «24.11 14:05» раньше. */
    private fun dpiWhen(at: Long): String {
        val d = java.util.Date(at)
        val sameDay = java.text.SimpleDateFormat("yyyyMMdd", java.util.Locale.US).let {
            it.format(d) == it.format(java.util.Date())
        }
        return java.text.SimpleDateFormat(if (sameDay) "HH:mm" else "dd.MM HH:mm", java.util.Locale.getDefault()).format(d)
    }

    /** Строка итога DPI: зелёная — открыт, коричневая — только с обходом, красная — не открывается. */
    private fun dpiRow(r: DpiCheck.Row): android.widget.TextView =
        android.widget.TextView(this).apply {
            text = r.text
            textSize = 13f
            setPadding(0, 4, 0, 4)
            setTextColor(
                ContextCompat.getColor(
                    this@MainActivity,
                    when (r.kind) {
                        0 -> R.color.check_ok
                        1 -> R.color.state_warn
                        else -> R.color.check_fail
                    }
                )
            )
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            )
        }

    private fun renderAvailabilityUnsafe() {
        val viaTunnel = Availability.load(this, Availability.VIA_TUNNEL)
        val direct = Availability.load(this, Availability.VIA_DIRECT)
        binding.textAvailTunnelHead.text = if (viaTunnel == null) {
            getString(R.string.avail_tunnel_title)
        } else {
            val head = getString(R.string.avail_tunnel_title) +
                (if (viaTunnel.point.isNotBlank()) " · " + viaTunnel.point else "")
            head + "\n" + availWhen(viaTunnel)
        }
        fillAvailBox(binding.availTunnelBox, viaTunnel, getString(R.string.avail_tunnel_none))
        binding.textAvailDirectHead.text = if (direct == null) {
            getString(R.string.avail_direct_title)
        } else {
            getString(R.string.avail_direct_title) + "\n" + availWhen(direct)
        }
        fillAvailBox(binding.resourceResultsBox, direct, getString(R.string.avail_direct_none))
        // «Что туннелировать» — не всё: сайты вне списков идут мимо туннеля, и проверка это покажет.
        binding.textAvailRoutesNote.visibility = if (prefs.routesMode >= 2) View.VISIBLE else View.GONE
    }

    /** «проверено сегодня в 14:05 · по кнопке» / «· при подборе». */
    private fun availWhen(report: Availability.Report): String {
        val at = java.util.Date(report.at)
        val sameDay = java.text.SimpleDateFormat("yyyyMMdd", java.util.Locale.US).let {
            it.format(at) == it.format(java.util.Date())
        }
        val time = java.text.SimpleDateFormat(if (sameDay) "HH:mm" else "dd.MM HH:mm", java.util.Locale.getDefault()).format(at)
        return getString(
            if (report.source == Availability.SOURCE_BUTTON) R.string.avail_when_button else R.string.avail_when_scan,
            if (sameDay) getString(R.string.avail_today, time) else time
        )
    }

    private fun fillAvailBox(box: LinearLayout, report: Availability.Report?, empty: String) {
        box.removeAllViews()
        if (report == null || report.lines.isEmpty()) {
            box.addView(
                android.widget.TextView(this).apply {
                    text = empty
                    textSize = 13f
                    setPadding(0, 4, 0, 4)
                    setTextColor(ContextCompat.getColor(this@MainActivity, R.color.colorOnSurfaceVariant))
                }
            )
            return
        }
        report.lines.forEach { line ->
            box.addView(verdictRow((if (line.ok) "✓ " else "✗ ") + line.name + " — " + line.text, line.ok))
        }
    }

    /** Идёт «Проверить сейчас» — второй раз не запускаем. */
    @Volatile
    private var availChecking = false

    /**
     * «Проверить сейчас»: те же проверки, что при подборе, — из приложения через туннель, который
     * работает сейчас. Туннель не трогается; итог — в список «Через туннель».
     */
    private fun checkAvailabilityNow() {
        if (availChecking) return
        // Свой подбор или фоновый (у него свой движок): процесс привязан к сети без VPN.
        if (engine.running || Availability.processBound(this)) {
            banner(getString(R.string.avail_busy_scan))
            return
        }
        if (!tunnel.supported || !tunnel.isUp) {
            banner(getString(R.string.avail_need_tunnel))
            return
        }
        persistUi()
        if (prefs.availabilityChecks().isEmpty()) {
            banner(getString(R.string.avail_nothing))
            return
        }
        // Точка — та, что знает сервис (он мог сменить её сам); шум не пишем: сервис мог заменить
        // его под эту сеть (см. NoiseMemory), и подпись из настроек могла бы соврать.
        val point = runCatching { TunnelDebug.endpoint }.getOrDefault("").trim()
        availChecking = true
        binding.btnAvailCheck.isEnabled = false
        binding.btnAvailCheck.setText(R.string.avail_checking)
        TunnelDebug.stage("доступность: проверяю через туннель ${point.ifBlank { "(точка неизвестна)" }}")
        val app = applicationContext
        Thread({
            val result = runCatching { Availability.checkNow(app, point) { false } }
            runOnUiThread {
                availChecking = false
                if (!::binding.isInitialized || isFinishing || isDestroyed) return@runOnUiThread
                runCatching {
                    binding.btnAvailCheck.isEnabled = true
                    binding.btnAvailCheck.setText(R.string.avail_check_now)
                    renderAvailability()
                    result.onSuccess { r ->
                        val ok = r.lines.count { it.ok }
                        TunnelDebug.stage("доступность через туннель: открылось $ok из ${r.lines.size}" +
                            r.lines.filter { !it.ok }.joinToString("") { "; ✗ ${it.name}: ${it.text}" })
                        banner(getString(R.string.avail_done, ok, r.lines.size))
                    }.onFailure { t ->
                        TunnelDebug.error("доступность: проверка не удалась: " + SafeMode.describe(t))
                        banner(getString(R.string.banner_ui_error, SafeMode.describe(t)), error = true)
                    }
                }
            }
        }, "warpscout-avail").apply { isDaemon = true }.start()
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

    /**
     * Подбор точек. [autoConnect] — после успешного подбора сразу поднять туннель.
     *
     * Подбор и подключение **одновременно** не запускаются никогда: подбор гасит туннель перед
     * замерами, и попытка подъёма в это время обречена (в журнале это выглядело как «ни одна из
     * 5 точек не поднялась» сразу после «сеть чистая», плюс падения по таймауту foreground).
     * Подключение идёт строго после того, как движок закончил.
     */
    private fun startScan(autoConnect: Boolean, mode: Int = Engine.SCAN_CURRENT) {
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
        // Работает VPN другого приложения — подбор не запускаем (с 1.10.45, см. ForeignVpn): замеры
        // шли бы через чужой туннель, а проверка изнутри молча отключила бы его. Выключить чужой VPN
        // может только человек — говорим ему. Смотрим до остановки своего туннеля: свой — не чужой.
        val foreignVpn = ForeignVpn.find(this, ownUp = tunnel.supported && (tunnel.isUp || tunnel.active))
        if (foreignVpn != null) {
            warnForeignVpn(foreignVpn)
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
        scanProgressText = ""
        scanFraction = 0f
        scanActivityText = getString(if (mode == Engine.SCAN_MOBILE) R.string.simple_act_mobile else R.string.simple_act_start)
        if (mode == Engine.SCAN_MOBILE) banner(getString(R.string.scan_mobile_started))
        updateSimple()
        engine.start(prefs.tuningSpec(), manualConfig(), sink(), mode = mode) { result, error ->
            autoConnectAfterScan = false
            // Итог — на тот экран, что сейчас на виду: подбор переживает поворот и возврат в
            // приложение, а экран, который его запускал, к этому времени мог быть уже закрыт.
            val ui = shown?.takeIf { it.uiReady() } ?: this
            ui.onScanDone(result, error, autoConnect, tunnelWasUp, mode)
        }
    }

    /**
     * Подбор не запущен: работает VPN другого приложения (с 1.10.45). Говорим, что делать, и даём
     * дорогу в настройки VPN Android — там его можно отключить и снять «Постоянную VPN».
     */
    private fun warnForeignVpn(iface: String) {
        TunnelDebug.stage("подбор не запущен: работает другой VPN ($iface) — попросил его выключить")
        banner(getString(R.string.foreign_vpn_banner), error = true)
        if (isFinishing || isDestroyed) return
        com.google.android.material.dialog.MaterialAlertDialogBuilder(this)
            .setTitle(R.string.foreign_vpn_title)
            .setMessage(getString(R.string.foreign_vpn_msg, iface))
            .setPositiveButton(R.string.foreign_vpn_settings) { _, _ -> openVpnSettings() }
            .setNegativeButton(R.string.foreign_vpn_ok, null)
            .show()
    }

    /** Системные настройки VPN; нет такого экрана — общие настройки сетей. */
    private fun openVpnSettings() {
        val opened = runCatching { startActivity(Intent(android.provider.Settings.ACTION_VPN_SETTINGS)) }.isSuccess
        if (!opened) runCatching { startActivity(Intent(android.provider.Settings.ACTION_WIRELESS_SETTINGS)) }
    }

    /** Подбор закончился (или его остановили): показать итог и сделать то, что было обещано. */
    private fun onScanDone(
        result: TuningResult?,
        error: String?,
        connect: Boolean,
        tunnelWasUp: Boolean,
        mode: Int = Engine.SCAN_CURRENT
    ) {
        scanAutoConnect = false
        scanProgressText = ""
        scanFraction = -1f
        scanActivityText = ""
        if (!::binding.isInitialized) return
        // Список лучших точек обновился — его видно и в «Резервной» упрощённого экрана.
        runCatching { renderShortlist() }
        updateSimple()
        binding.progress.visibility = View.GONE
        binding.btnStop.visibility = View.GONE
        if (mode == Engine.SCAN_MOBILE) {
            // Подбор для мобильной сети не трогает точку текущей сети: итог — тройка в «Резервной»,
            // туннель возвращаем на то, что работало до подбора.
            binding.textStatus.setText(R.string.status_idle)
            binding.btnTunnel.isEnabled = tunnel.supported
            binding.btnTunnel.setText(if (tunnel.isUp) R.string.btn_tunnel_off else R.string.btn_tunnel_on)
            val count = runCatching { ConfigShortlist.forGroup(this, ConfigShortlist.GROUP_MOBILE).size }.getOrDefault(0)
            when {
                error != null -> banner(getString(R.string.status_error, error), error = true)
                result == null -> banner(getString(R.string.scan_mobile_none), error = true)
                else -> banner(getString(R.string.scan_mobile_done, count))
            }
            if (tunnelWasUp && !tunnel.isUp) runCatching { restoreTunnelAfterScan(false, "") }
            return
        }
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
                updateTunnelSummary()
                // «Только мои сайты» / «Только из списков» — сразу показываем, где их выбирать.
                when (mode) {
                    3 -> binding.tunnelKindGroup.check(R.id.btnKindSites)
                    2 -> binding.tunnelKindGroup.check(R.id.btnKindLists)
                }
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
                updateDnsNote()
                // У «умных» DNS адреса берутся по имени: спрашиваем сразу, чтобы в конфиг пошли
                // настоящие адреса, а не запасные (или Cloudflare, если запасных нет).
                refreshDnsByName(position, force = true)
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
        // Шаги Proton внутри приложения и конфиг из скачанного файла (с 1.10.39).
        binding.btnProtonGuide.setOnClickListener {
            runCatching { showProtonGuide() }.onFailure { t ->
                TunnelDebug.error("второй выход: шаги Proton — " + SafeMode.describe(t))
                banner(getString(R.string.banner_ui_error, SafeMode.describe(t)), error = true)
            }
        }
        binding.btnSecondFile.setOnClickListener { openSecondConfPicker() }
        // Ключ Proton кнопкой (с 1.10.44, в бете — с 1.10.44-beta5): вход в аккаунт, без аккаунта, сторонний
        // сервис.
        binding.btnProtonConnect.setOnClickListener {
            runCatching { startProtonConnect() }.onFailure { t ->
                TunnelDebug.problem("второй выход: Proton кнопкой — " + SafeMode.describe(t))
                banner(getString(R.string.banner_ui_error, SafeMode.describe(t)), error = true)
            }
        }
        binding.btnSecondResolve.setOnClickListener {
            runCatching { refreshSecondNow() }.onFailure { t ->
                secondBusy = false
                binding.btnSecondResolve.isEnabled = true
                TunnelDebug.error("второй выход: " + SafeMode.describe(t))
                secondDone(getString(R.string.banner_ui_error, SafeMode.describe(t)), RES_FAIL)
            }
        }
        // Сброс по умолчанию (с 1.10.32): всё как после установки — после подтверждения.
        binding.btnResetAll.setOnClickListener {
            runCatching { confirmResetAll() }.onFailure { t ->
                TunnelDebug.error("сброс: " + SafeMode.describe(t))
                banner(getString(R.string.banner_ui_error, SafeMode.describe(t)), error = true)
            }
        }
        binding.switchSecondViaWarp.setOnCheckedChangeListener { _, isChecked ->
            if (isChecked == prefs.secondViaWarp) return@setOnCheckedChangeListener
            prefs.secondViaWarp = isChecked
            updateSecondState()
            markSettingsDirty(getString(R.string.dirty_second_exit))
        }
        // Конфиг второго выхода вставляют копипастом: пока он не разобран, включённый
        // переключатель ничего не значит. Поэтому состояние пересчитываем сразу, а не
        // после «Сохранить и применить».
        binding.editSecondConf.doAfterTextChanged {
            val raw = it?.toString()?.trim().orEmpty()
            // Ключ AmneziaVPN «vpn://…» (с 1.10.49-beta1): в поле встаёт сам конфиг из ключа.
            if (dev.warpscout.core.config.AmneziaKey.looksLike(raw)) {
                val conf = amneziaKeyToConf(raw, "вставлен в поле")
                if (conf != null) {
                    binding.editSecondConf.post {
                        binding.editSecondConf.setText(conf)
                        if (!binding.switchSecondExit.isChecked) binding.switchSecondExit.isChecked = true
                        markSettingsDirty(getString(R.string.dirty_second_exit))
                    }
                    return@doAfterTextChanged
                }
            }
            prefs.secondConf = raw
            updateSecondState()
            // Вставили конфиг Proton — свежий список бесплатных серверов (встроенный тоже годится).
            refreshProtonIfStale()
        }
        runCatching { setupSecondCountry() }.onFailure { t ->
            TunnelDebug.error("второй выход: выбор страны — " + SafeMode.describe(t))
        }
        binding.editSecondDomains.doAfterTextChanged {
            val value = it?.toString().orEmpty()
            if (value == prefs.secondDomains) return@doAfterTextChanged
            prefs.secondDomains = value
            updateSecondState()
            markSettingsDirtyLater(getString(R.string.dirty_second_sources))
        }

        binding.btnSaveAndApply.setOnClickListener { applyWithRoutes(getString(R.string.dirty_config)) }
        binding.btnSaveAndSend.setOnClickListener { saveAndSend() }
        binding.btnSaveScan.setOnClickListener { saveAndApply(getString(R.string.dirty_scan)) }
        binding.btnSaveApps.setOnClickListener { applyWithRoutes(getString(R.string.dirty_apps)) }
        binding.btnSaveDpi.setOnClickListener { saveAndApply(getString(R.string.dirty_junk)) }
        binding.cardBanner.setOnClickListener { hideBanner() }

        binding.btnPickServer.setOnClickListener { pickServerFromReport() }

        binding.btnRefreshLists.setOnClickListener { refreshLists() }

        binding.btnTunnelRefresh.setOnClickListener { updateTunnelDiagnostics() }

        binding.btnTunnelCopy.setOnClickListener {
            ConfigFiles.copyToClipboard(this, TunnelDebug.dump() + "\n\n" + CrashLog.describe(this))
            toast(getString(R.string.copied_ok))
        }
        binding.btnTunnelExport.setOnClickListener { exportJournal() }
        // «Проверить обновления» рядом с версией (с 1.10.31) — то же, что кнопка в шапке
        // упрощённого экрана. Только по нажатию: в фоне приложение никуда не ходит.
        binding.btnCheckUpdate.setOnClickListener { checkForUpdate() }

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

        // Обход DPI в туннеле (с 1.10.49-beta3): YouTube и X напрямую с приёмом по плану этой сети.
        binding.switchDpiBypass.isChecked = prefs.featDpiBypass
        binding.switchDpiBypass.setOnCheckedChangeListener { _, isChecked ->
            if (isChecked == prefs.featDpiBypass) return@setOnCheckedChangeListener
            prefs.featDpiBypass = isChecked
            TunnelDebug.stage("настройка «обход DPI в туннеле»: ${if (isChecked) "включена" else "выключена"}")
            runCatching { renderDpiBypass() }
            if (tunnel.supported && (tunnel.isUp || tunnel.active)) {
                runCatching { tunnel.reloadDpi() }
                banner(
                    getString(
                        R.string.dpi_bypass_applied,
                        getString(if (isChecked) R.string.dpi_bypass_state_on else R.string.dpi_bypass_state_off)
                    )
                )
            }
        }

        // «Проверить DPI» в Журнале (с 1.10.49-beta2): режут сайты по имени (поможет обход) или по адресу.
        binding.btnDpiCheck.setOnClickListener {
            runCatching { checkDpiNow() }.onFailure { t ->
                dpiChecking = false
                TunnelDebug.problem("DPI: " + SafeMode.describe(t))
                banner(getString(R.string.banner_ui_error, SafeMode.describe(t)), error = true)
            }
        }

        // «Проверить сейчас» в Журнале: доступность через работающий туннель (с 1.10.30).
        binding.btnAvailCheck.setOnClickListener {
            runCatching { checkAvailabilityNow() }.onFailure { t ->
                availChecking = false
                TunnelDebug.error("доступность: " + SafeMode.describe(t))
                banner(getString(R.string.banner_ui_error, SafeMode.describe(t)), error = true)
            }
        }

        binding.btnTop3Forget.setOnClickListener {
            // Список — подсказка из прошлого скана, а не настройка: убрать его должно быть так же
            // просто, как он появился. Следующий подбор соберёт новый.
            ConfigShortlist.forget(this)
            renderShortlist()
            banner(getString(R.string.top3_forgotten))
        }

        binding.btnBackup.setOnClickListener {
            runCatching { saveBackupForUser() }.onFailure { t ->
                TunnelDebug.error("бекап: сохранение — " + SafeMode.describe(t))
                banner(getString(R.string.banner_ui_error, SafeMode.describe(t)), error = true)
            }
        }

        binding.btnRestore.setOnClickListener {
            runCatching { restoreFromBackup() }.onFailure { t ->
                TunnelDebug.error("бекап: " + SafeMode.describe(t))
                banner(getString(R.string.banner_ui_error, SafeMode.describe(t)), error = true)
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

        binding.btnTunnel.setOnClickListener { toggleTunnel() }
        binding.btnLogClear.setOnClickListener { clearJournal() }
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
                appendLine("WilyScout ${BuildConfig.VERSION_NAME} · сборка ${BuildConfig.BUILD_REV}")
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
                    // Итог последней проверки связи: «подключено» и «данные ходят» — разные вещи.
                    if (snapshot.linkAt > 0L) {
                        fun code(c: Int, ms: Int): String = when (c) {
                            TunnelStatus.LINK_OK -> "✓" + (if (ms >= 0) " $ms мс" else "")
                            TunnelStatus.LINK_FAIL -> "✗ нет ответа"
                            TunnelStatus.LINK_BYPASS -> "мимо туннеля"
                            else -> "?"
                        }
                        appendLine(
                            "связь: интернет ${code(snapshot.linkWeb, snapshot.linkMs)}, " +
                                "Telegram ${code(snapshot.linkTg, snapshot.linkTgMs)}" +
                                snapshot.linkExit.takeIf { it.isNotBlank() }?.let { ", выход $it" }.orEmpty() +
                                ", проверено " + java.text.SimpleDateFormat("HH:mm:ss", java.util.Locale.getDefault())
                                .format(java.util.Date(snapshot.linkAt))
                        )
                    }
                }
                appendLine(
                    "вид экрана: " + (if (prefs.simpleUi()) "упрощённый" else "расширенный") +
                        prefs.backupEndpoint.takeIf { it.isNotBlank() }?.let { ", резервная Wi-Fi $it" }.orEmpty() +
                        prefs.backupMobile.takeIf { it.isNotBlank() }?.let { ", резервная мобильной $it" }.orEmpty()
                )
                if (snapshot != null && snapshot.speedAt > 0L) {
                    val speedText = when (snapshot.speedState) {
                        TunnelStatus.SPEED_OK -> SpeedTest.human(snapshot.speedKbps)
                        TunnelStatus.SPEED_FROZEN -> "загрузка встаёт (${snapshot.speedBytes / 1024} КБ)"
                        TunnelStatus.SPEED_BYPASS -> "адрес замера вне туннеля"
                        else -> "замер не удался"
                    }
                    appendLine(
                        "скорость через туннель: $speedText" +
                            (if (snapshot.speedPingMs >= 0) ", пинг ${snapshot.speedPingMs} мс" else "") +
                            (if (snapshot.speedFull) ", полный замер" else ", короткий замер") +
                            ", " + java.text.SimpleDateFormat("HH:mm:ss", java.util.Locale.getDefault())
                            .format(java.util.Date(snapshot.speedAt))
                    )
                }
                appendLine(
                    "сеть: " + NetIdentity.currentKey(app).ifBlank { "неизвестно" } +
                        ", приложения: " + when (prefs.appsMode) {
                            Prefs.APPS_ONLY -> "только выбранные (${prefs.appsSelected.size})"
                            Prefs.APPS_EXCEPT -> "все, кроме ${prefs.appsSelected.size}"
                            else -> "все"
                        } +
                        ", DNS: " + DnsBook.preset(prefs.dnsIndex).name + " " +
                        DnsBook.servers(app, prefs.dnsIndex).joinToString(", ")
                )
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
            val name = "WilyScout-log-$stamp.txt"
            // Для «Поделиться» — копия во временном каталоге (его отдаёт FileProvider); прежние
            // выгрузки удаляем, чтобы они не копились.
            val shareFile = runCatching {
                val dir = java.io.File(app.cacheDir, "share").apply { mkdirs() }
                dir.listFiles()?.filter { it.name.startsWith("WilyScout-log-") || it.name.startsWith("WarpScout-log-") }
                    ?.forEach { it.delete() }
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
            val ui = shown ?: this@MainActivity
            ui.showScanLog()
            runCatching { ui.noteScanLog(message) }
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
        scanProgressText = if (total > 0) getString(R.string.simple_scan_progress, done, total) else ""
        // Кольцо-прогресс (с 1.10.30): у каждой фазы подбора свой кусок кольца — первичный скан
        // до 45 %, подробные пробы до 85 %, проверка на заморозку до 97 %; остаток — проверка сайтов
        // и запись итога. Назад кольцо идёт, только если подбор начался заново (быстрый старт не
        // подтвердился и пошёл полный поиск).
        val part = if (total > 0) (done.toFloat() / total).coerceIn(0f, 1f) else 0f
        val next = when {
            current.startsWith("первичный") -> 0.03f + 0.42f * part
            current.startsWith("проверка на заморозку") -> 0.85f + 0.12f * part
            else -> 0.45f + 0.40f * part
        }
        scanFraction = if (next >= scanFraction || next < scanFraction - 0.25f) next else scanFraction
        scanActivityText = scanActivityFor(done, total, current)
        updateSimple()
    }

    /** Строка «что сейчас делаю» по шагу подбора: «Ищу точки: 45 из 120», «Проверяю … · шум …». */
    private fun scanActivityFor(done: Int, total: Int, current: String): String {
        val parts = current.split(" · ").map { it.trim() }
        return when {
            current.startsWith("первичный") ->
                if (total > 0) getString(R.string.simple_act_scan, done, total) else getString(R.string.simple_act_start)
            current.startsWith("проверка на заморозку") ->
                parts.getOrNull(1)?.takeIf { it.isNotBlank() }?.let { getString(R.string.simple_act_sustain, it) }
                    ?: getString(R.string.simple_act_sustain_done)
            parts.size >= 2 && parts[0].isNotBlank() -> getString(R.string.simple_act_probe, parts[0], parts[1])
            else -> current
        }
    }

    /** Строки журнала подбора, после которых меняется «что сейчас делаю» (шаги без прогресса). */
    private fun noteScanLog(message: String) {
        if (!engine.running) return
        val m = message.trim()
        val text = when {
            m.startsWith("быстрый старт: проверяю") -> getString(R.string.simple_act_saved)
            m.startsWith("Проверяю доступность ресурсов") || m.startsWith("Проверяю топ-") ->
                getString(R.string.simple_act_sites)
            m.startsWith("мобильная сеть получена") -> getString(R.string.simple_act_mobile)
            else -> return
        }
        if (text == scanActivityText) return
        scanActivityText = text
        updateSimple()
    }

    /** Что сейчас делает сервис туннеля — по снимку его состояния (строка под кнопкой). */
    private fun serviceActivity(snap: TunnelStatus?): String {
        if (snap == null) return ""
        val ep = snap.endpoint.trim()
        val st = snap.status.trim()
        val now = System.currentTimeMillis()
        return when {
            ep.isNotBlank() && snap.dataCheckAt > 0L && now - snap.dataCheckAt < 15_000L ->
                getString(R.string.simple_act_data, ep)
            serviceActivityPrefixes.any { st.startsWith(it) } -> st.replaceFirstChar { it.uppercaseChar() }
            ep.isNotBlank() && (snap.isStarting || snap.busy) -> getString(R.string.simple_act_handshake, ep)
            else -> ""
        }
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
        runCatching { Backup.saveAsync(this, getString(R.string.backup_note_tuned, result.best?.endpoint?.render().orEmpty())) }
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
        renderAvailability()
        binding.textReport.text = runCatching { Report.toMarkdown(result.report) + appsByPointSection(result.report) }
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

    // ------------------------------------------------ второй выход (с 1.10.31: сайты — сами)

    // ------------------------------------------------ Proton VPN Free: автопоиск сервера (с 1.10.31)

    /** Коды стран в выпадающем списке Proton: первая строка — «любая». */
    private var secondCountryCodes: List<String> = emptyList()

    /**
     * Страна второго выхода для Proton VPN Free: сервер в ней приложение находит само (см.
     * SecondProton). Применится при следующем подключении — как и остальные настройки туннеля.
     */
    private fun setupSecondCountry() {
        val codes = listOf("") + ProtonFree.countries(SecondProton.servers(this))
        secondCountryCodes = codes
        val labels = codes.map { code ->
            if (code.isEmpty()) getString(R.string.second_country_any) else SecondProton.countryName(this, code)
        }
        binding.spinnerSecondCountry.adapter = ArrayAdapter(this, android.R.layout.simple_spinner_dropdown_item, labels)
        binding.spinnerSecondCountry.setSelection(codes.indexOf(prefs.secondProtonCountry).coerceAtLeast(0))
        binding.spinnerSecondCountry.onItemSelectedListener = object : android.widget.AdapterView.OnItemSelectedListener {
            override fun onItemSelected(parent: android.widget.AdapterView<*>?, view: View?, position: Int, id: Long) {
                val code = secondCountryCodes.getOrNull(position) ?: return
                if (code == prefs.secondProtonCountry) return
                prefs.secondProtonCountry = code
                TunnelDebug.stage("второй выход: страна — " + code.ifEmpty { "любая, ближние первыми" })
                updateSecondState()
                markSettingsDirty(getString(R.string.dirty_second_exit))
            }

            override fun onNothingSelected(parent: android.widget.AdapterView<*>?) = Unit
        }
    }

    /** «Proton VPN Free: сервер выбирается сам…» и на каком сервере второй выход сейчас. */
    private fun renderSecondProton(up: Boolean, snap: TunnelStatus?) {
        val proton = prefs.secondExitOn && ProtonFree.isProton(prefs.secondConf)
        binding.panelSecondProton.visibility = if (proton) View.VISIBLE else View.GONE
        if (!proton) return
        val servers = SecondProton.servers(this)
        val counts = ProtonFree.countries(servers).joinToString(", ") { code -> "$code ${servers.count { it.code == code }}" }
        val fetched = SecondProton.fetchedAt(this)
        val listAge = if (fetched > 0L) agoText(fetched) else getString(R.string.second_proton_builtin)
        val peer = snap?.secondPeer.orEmpty()
        // Сервер работает — с него и начнём в следующий раз.
        if (up && snap?.second == TunnelStatus.SECOND_UP && peer.isNotBlank()) prefs.secondProtonLast = peer
        binding.textSecondProton.text = buildString {
            append(getString(R.string.second_proton_info, servers.size, counts, listAge))
            if (up && peer.isNotBlank()) append("\n").append(getString(R.string.second_proton_now, peer))
            runCatching { protonKeyLine() }.getOrNull()?.let { append("\n").append(it) }
        }
    }

    private var protonRefreshAt = 0L

    /** Список бесплатных серверов Proton — раз в неделю; не скачался — снова не раньше чем через час. */
    private fun refreshProtonIfStale() {
        if (!prefs.secondExitOn || !ProtonFree.isProton(prefs.secondConf) || !SecondProton.isStale(this)) return
        val now = System.currentTimeMillis()
        if (now - protonRefreshAt < 3_600_000L) return
        protonRefreshAt = now
        Thread {
            val result = runCatching { SecondProton.refresh(this) }
            runOnUiThread {
                result.onSuccess { n ->
                    TunnelDebug.stage("Proton Free: список серверов обновлён — бесплатных $n")
                    runCatching { ServiceSettingsStore.syncFromPrefs(this) }
                    if (uiReady()) {
                        runCatching { setupSecondCountry() }
                        updateSecondState()
                    }
                }.onFailure { TunnelDebug.stage("Proton Free: список серверов не обновился — ${it.message}") }
            }
        }.apply { isDaemon = true; name = "warpscout-proton" }.start()
    }

    /** Галочки «Через второй выход идут: …» (id списка → галочка). */
    private val secondChecks = LinkedHashMap<String, MaterialCheckBox>()

    /** Галочки источников второго выхода — по SecondRoutes.SOURCES, отметки из настроек. */
    private fun buildSecondSources() {
        val box = binding.secondSourcesBox
        box.removeAllViews()
        secondChecks.clear()
        val chosen = prefs.secondSources
        SecondRoutes.SOURCES.forEach { id ->
            val cb = MaterialCheckBox(this).apply {
                text = getString(secondSourceTitle(id))
                isChecked = id in chosen
                setOnClickListener {
                    prefs.secondSources = secondChecks.filter { it.value.isChecked }.keys.toSet()
                    updateSecondState()
                    markSettingsDirty(getString(R.string.dirty_second_sources))
                }
            }
            secondChecks[id] = cb
            box.addView(cb)
        }
    }

    private fun secondSourceTitle(id: String): Int = when (id) {
        "ru-ip-blocked" -> R.string.second_src_ru_blocked
        "openai" -> R.string.second_src_openai
        "claude" -> R.string.second_src_claude
        else -> R.string.second_src_google_ai
    }

    // ------------------------------------------- второй выход: кнопка с ходом и итогом (с 1.10.32)

    /** Кнопка «Обновить адреса и проверить выход» работает — второй раз не запускаем. */
    private var secondBusy = false

    /** Что уже сделано кнопкой (адреса собраны…) — начало итоговой строки. */
    private var secondBuilt = ""

    /** По итогу кнопки предложить переподключение (новые адреса вне маршрутов, второго выхода нет в сессии). */
    private var secondWantReconnect = false

    /** Шаг работы — строкой под кнопкой, с полосой хода. */
    private fun secondProgress(text: String) {
        if (!uiReady()) return
        runCatching {
            binding.progressSecond.visibility = View.VISIBLE
            binding.textSecondResult.visibility = View.VISIBLE
            binding.textSecondResult.setTextColor(ContextCompat.getColor(this, R.color.colorOnSurfaceVariant))
            binding.textSecondResult.text = text
        }
    }

    /** Итог: цветная точка (зелёная — работает, красная — нет, жёлтая — нужно действие, серая — к сведению). */
    private fun secondDone(text: String, kind: Int) {
        if (!uiReady()) return
        runCatching {
            binding.progressSecond.visibility = View.GONE
            binding.textSecondResult.visibility = View.VISIBLE
            binding.textSecondResult.setTextColor(ContextCompat.getColor(this, R.color.colorOnSurface))
            val color = ContextCompat.getColor(
                this,
                when (kind) {
                    RES_OK -> R.color.check_ok
                    RES_FAIL -> R.color.check_fail
                    RES_WARN -> R.color.orb_warn
                    else -> R.color.state_off
                }
            )
            binding.textSecondResult.text = dotLine(text, color)
        }
    }

    /** Кнопка закончила: итог под кнопкой, кнопка снова доступна, при нужде — предложить переподключение. */
    private fun finishSecond(text: String, kind: Int) {
        secondBusy = false
        val reconnect = secondWantReconnect
        secondWantReconnect = false
        if (!uiReady()) return
        binding.btnSecondResolve.isEnabled = true
        secondDone(text, kind)
        updateSecondState()
        TunnelDebug.stage("второй выход: итог — " + text.replace('\n', ' '))
        if (reconnect) offerSecondReconnect()
    }

    /**
     * «Обновить адреса и проверить выход». Три шага, каждый виден под кнопкой:
     *  1) собрать адреса сайтов второго выхода (списки + свои сайты, DoH) — с ходом «N из M»;
     *  2) отдать новую таблицу работающему туннелю без переподключения;
     *  3) проверить, из какой страны выходит запрос (ExitCheck: на адрес из таблицы второго выхода).
     * Итог — цветной строкой прямо под кнопкой: что сделано, работает ли второй выход и что делать,
     * если нет. В 1.10.31 итог уходил в плашку на «Главной» — с «Настроек» её не видно, и человек
     * не понимал, работает ли кнопка (22.11).
     */
    private fun refreshSecondNow() {
        persistUi()
        if (secondBusy) {
            toast(getString(R.string.second_busy))
            return
        }
        val conf = prefs.secondConf
        when {
            !prefs.secondExitOn -> {
                secondDone(getString(R.string.second_res_off), RES_FAIL)
                return
            }
            conf.isBlank() -> {
                secondDone(getString(R.string.second_need_conf), RES_FAIL)
                return
            }
            runCatching { WgConf.toWarpConfig("второй выход", conf) }.getOrNull() == null -> {
                secondDone(getString(R.string.second_bad_conf), RES_FAIL)
                return
            }
        }
        secondBusy = true
        secondBuilt = ""
        secondWantReconnect = false
        binding.btnSecondResolve.isEnabled = false
        secondProgress(getString(R.string.second_step_lists))
        TunnelDebug.stage("второй выход: кнопка «Обновить адреса и проверить выход»")
        val before = ExitRouter.parse(prefs.secondCidrs).toSet()
        val upAtStart = tunnel.supported && tunnel.isUp
        val lastShown = java.util.concurrent.atomic.AtomicLong(0L)
        Thread {
            val result = runCatching {
                SecondRoutes.build(
                    this, prefs,
                    log = { line -> runOnUiThread { sink().log(line) } },
                    progress = { done, total ->
                        // Строку хода обновляем не чаще четырёх раз в секунду: доменов сотни.
                        val now = android.os.SystemClock.elapsedRealtime()
                        val prev = lastShown.get()
                        if ((done == total || now - prev >= 250L) && lastShown.compareAndSet(prev, now)) {
                            runOnUiThread { if (secondBusy) secondProgress(getString(R.string.second_step_resolve, done, total)) }
                        }
                    }
                )
            }
            val changed = result.getOrNull()?.let { SecondRoutes.save(prefs, it) } ?: false
            val after = ExitRouter.parse(prefs.secondCidrs).toSet()
            val added = after - before
            val removed = before - after
            // Новые адреса вне маршрутов туннеля (раздельный режим) заработают только после
            // переподключения: считаем их здесь, вне главного потока.
            val outside = if (changed && upAtStart) SecondRoutes.uncovered(this, added) else 0
            runOnUiThread {
                if (!uiReady()) {
                    secondBusy = false
                    return@runOnUiThread
                }
                runCatching { afterSecondBuild(result, changed, added.size, removed.size, outside) }.onFailure { t ->
                    TunnelDebug.error("второй выход: " + SafeMode.describe(t))
                    finishSecond(getString(R.string.banner_ui_error, SafeMode.describe(t)), RES_FAIL)
                }
            }
        }.apply { isDaemon = true; name = "warpscout-second" }.start()
    }

    /** Шаг 2: адреса собраны — отдать туннелю и перейти к проверке выхода. */
    private fun afterSecondBuild(result: Result<SecondRoutes.Result>, changed: Boolean, added: Int, removed: Int, outside: Int?) {
        val r = result.getOrElse { t ->
            finishSecond(getString(R.string.second_res_build_failed, t.message ?: t.javaClass.simpleName), RES_FAIL)
            return
        }
        if (r.cidrs.isEmpty()) {
            finishSecond(getString(R.string.second_res_no_cidrs, r.note()), RES_FAIL)
            return
        }
        secondBuilt = getString(R.string.second_res_built, r.note()) + " · " +
            if (changed) getString(R.string.second_res_diff, added, removed) else getString(R.string.second_res_same)
        updateSecondState()
        if (!tunnel.supported || !tunnel.isUp) {
            finishSecond(secondBuilt + "\n" + getString(R.string.second_res_tunnel_off), RES_INFO)
            return
        }
        if (changed && (outside ?: 0) > 0) {
            secondBuilt += "\n" + getString(R.string.second_res_need_reconnect, outside ?: 0)
            secondWantReconnect = true
        }
        if (!changed) {
            waitSecondThenCheck(0)
            return
        }
        // Таблицу работающего туннеля сервис меняет на лету, без переподключения, — но не мгновенно
        // (команда идёт в его процесс). Проверка раньше времени ушла бы через WARP и показала бы
        // «второй выход не принял запрос», поэтому даём сервису полторы секунды.
        tunnel.reloadSecondRoutes()
        secondProgress(getString(R.string.second_step_apply))
        tunnelHandler.postDelayed({ runCatching { waitSecondThenCheck(0) } }, 1_500L)
    }

    /** Шаг 3: второй выход в работающем туннеле поднят — проверяем; поднимается — ждём до 20 с. */
    private fun waitSecondThenCheck(attempt: Int) {
        if (!uiReady()) {
            secondBusy = false
            return
        }
        val snap = runCatching { TunnelStatusBus.snapshot(this) }.getOrNull()
        when (snap?.second) {
            TunnelStatus.SECOND_UP -> runSecondCheck(fromButton = true)
            TunnelStatus.SECOND_STARTING -> {
                if (attempt < 10) {
                    secondProgress(getString(R.string.second_step_wait_up))
                    tunnelHandler.postDelayed({ runCatching { waitSecondThenCheck(attempt + 1) } }, 2_000L)
                } else {
                    finishSecond(secondBuilt + "\n" + getString(R.string.second_res_still_starting), RES_WARN)
                }
            }
            TunnelStatus.SECOND_FAILED -> {
                secondWantReconnect = true
                finishSecond(secondBuilt + "\n" + getString(R.string.second_res_failed), RES_FAIL)
            }
            else -> {
                // В этом подключении второго выхода нет (включили после подключения).
                secondWantReconnect = true
                finishSecond(secondBuilt + "\n" + getString(R.string.second_res_not_in_session), RES_WARN)
            }
        }
    }

    /** Итог проверки словами и цветом — для строки под кнопкой. */
    private fun checkVerdict(r: ExitCheck.Result?): Pair<String, Int> = when {
        r == null -> getString(R.string.second_res_fail, "нет ответа") to RES_FAIL
        r.ok -> {
            val name = SecondProton.countryName(this, r.code)
            getString(
                R.string.second_res_ok,
                if (name == r.code) r.code else "$name (${r.code})",
                r.detail,
                if (r.ms >= 0) getString(R.string.second_res_ms, r.ms) else ""
            ) to RES_OK
        }
        r.code == "RU" -> getString(R.string.second_res_ru, r.detail) to RES_FAIL
        r.code == ExitCheck.VIA_WARP -> getString(R.string.second_res_warp) to RES_FAIL
        r.code == ExitCheck.NOT_ROUTED -> getString(R.string.second_res_not_routed, r.detail) to RES_WARN
        else -> getString(R.string.second_res_fail, r.detail) to RES_FAIL
    }

    /** Переподключить туннель, чтобы второй выход заработал с новыми адресами (по согласию). */
    private fun offerSecondReconnect() {
        if (!uiReady() || !tunnel.supported || !tunnel.isUp) return
        android.app.AlertDialog.Builder(this)
            .setTitle(R.string.second_reconnect_title)
            .setMessage(R.string.second_reconnect_msg)
            .setPositiveButton(R.string.second_reconnect_ok) { _, _ ->
                runCatching {
                    secondProgress(getString(R.string.second_step_reconnect))
                    TunnelDebug.stage("второй выход: переподключаю по кнопке — новые адреса в маршруты")
                    applyWithRoutes(getString(R.string.second_reconnect_why))
                    // Проверку после переподключения запускает scheduleSecondCheck. Если туннель так и
                    // не поднялся, строка хода не должна «крутиться» вечно: через минуту — итог.
                    tunnelHandler.postDelayed({
                        runCatching {
                            if (uiReady() && binding.progressSecond.visibility == View.VISIBLE && !secondBusy && !secondCheckRunning) {
                                secondDone(getString(R.string.second_res_reconnect_slow), RES_WARN)
                            }
                        }
                    }, 60_000L)
                }.onFailure { t -> TunnelDebug.error("второй выход: " + SafeMode.describe(t)) }
            }
            .setNegativeButton(R.string.update_later, null)
            .show()
    }

    private var secondCheckRunning = false
    private var secondRefreshRunning = false

    /**
     * Из какой страны выходит второй выход (ExitCheck через туннель). Только когда туннель поднят и
     * второй выход в нём работает — иначе проверять нечего, и это тоже пишется под кнопкой.
     * [fromButton] — проверка — последний шаг кнопки: итог дописывается к уже сделанному.
     */
    private fun runSecondCheck(fromButton: Boolean = false) {
        if (!prefs.secondExitOn || prefs.secondConf.isBlank()) {
            if (fromButton) finishSecond(secondBuilt, RES_INFO)
            return
        }
        if (secondCheckRunning) {
            // Проверка уже идёт (после «Сохранить и применить»): её итог сам появится под кнопкой.
            if (fromButton) {
                secondBusy = false
                binding.btnSecondResolve.isEnabled = true
            }
            return
        }
        if (!tunnel.supported || !tunnel.isUp) {
            updateSecondState()
            if (fromButton) finishSecond(secondBuilt + "\n" + getString(R.string.second_res_tunnel_off), RES_INFO)
            return
        }
        // Второй выход в этой сессии не работает — запрос ушёл бы через WARP, и «выход: RU»
        // приписался бы своему серверу. Не проверяем: состояние и так видно в строке выше.
        val snap = runCatching { TunnelStatusBus.snapshot(this) }.getOrNull()
        if (snap?.second != TunnelStatus.SECOND_UP) {
            updateSecondState()
            if (fromButton) finishSecond(secondBuilt + "\n" + getString(R.string.second_res_failed), RES_FAIL)
            return
        }
        secondCheckRunning = true
        binding.textSecondState.text = getString(R.string.second_checking)
        secondProgress(getString(R.string.second_step_check))
        Thread {
            val check = {
                runCatching { SecondRoutes.checkExit(this, prefs) }.getOrElse { t ->
                    ExitCheck.Result(ExitCheck.FAIL, t.message ?: t.javaClass.simpleName, System.currentTimeMillis()).encode()
                }
            }
            var res = check()
            // Адресов chatgpt.com в таблице нет (с 1.10.44-beta3): нынешние — в таблицу, сервис меняет её на
            // лету, и проверка — ещё раз. Раньше строка «не попал во второй выход» повторялась при каждом
            // подключении, пока адреса не обновят кнопкой, а chatgpt.com всё это время шёл через WARP.
            if (SecondRoutes.notInTable(res)) {
                val added = runCatching { SecondRoutes.addCheckHost(prefs) }.getOrDefault(0)
                if (added > 0) {
                    TunnelDebug.stage("второй выход: адресов ${SecondRoutes.CHECK_HOST} в таблице не было — добавил $added, проверяю ещё раз")
                    runCatching { tunnel.reloadSecondRoutes() }
                    runCatching { Thread.sleep(1_500L) }
                    res = check()
                }
            }
            runOnUiThread {
                secondCheckRunning = false
                prefs.secondCheck = res
                val r = ExitCheck.decode(res)
                TunnelDebug.stage(
                    "второй выход: проверка — " + (r?.let { "${it.code} ${it.detail}" + (if (it.ms >= 0) ", ${it.ms} мс" else "") } ?: res)
                )
                if (!uiReady()) {
                    secondBusy = false
                    return@runOnUiThread
                }
                runCatching {
                    val (text, kind) = checkVerdict(r)
                    if (r?.code == ExitCheck.NOT_ROUTED) secondWantReconnect = true
                    if (fromButton) {
                        finishSecond(secondBuilt + "\n" + text, kind)
                    } else {
                        updateSecondState()
                        secondDone(text, kind)
                    }
                }.onFailure { t -> TunnelDebug.error("второй выход: " + SafeMode.describe(t)) }
            }
        }.apply { isDaemon = true; name = "warpscout-second-check" }.start()
    }

    /**
     * После «Сохранить и применить» туннель переподключается: страну второго выхода проверяем,
     * когда он поднимется (и только если второй выход в нём заработал).
     */
    private fun scheduleSecondCheck(attempt: Int = 0) {
        if (!prefs.secondExitOn || prefs.secondConf.isBlank()) return
        if (attempt == 0 && !(tunnel.supported && (tunnel.isUp || tunnel.active))) return
        tunnelHandler.postDelayed({
            runCatching {
                if (isFinishing || isDestroyed) return@runCatching
                val snap = runCatching { TunnelStatusBus.snapshot(this) }.getOrNull()
                val up = tunnel.supported && tunnel.isUp
                when {
                    up && snap?.second == TunnelStatus.SECOND_UP -> runSecondCheck()
                    up && snap?.second == TunnelStatus.SECOND_FAILED -> {
                        updateSecondState()
                        secondDone(getString(R.string.second_res_failed), RES_FAIL)
                    }
                    attempt < 8 -> scheduleSecondCheck(attempt + 1)
                    else -> {
                        updateSecondState()
                        // Строка хода под кнопкой не должна «крутиться» вечно (с 1.10.32).
                        if (binding.progressSecond.visibility == View.VISIBLE) {
                            secondDone(getString(R.string.second_res_still_starting), RES_WARN)
                        }
                    }
                }
            }
        }, if (attempt == 0) 6_000L else 5_000L)
    }

    /** Когда последний раз пробовали обновить адреса второго выхода сами. */
    private var secondRefreshTriedAt = 0L

    /**
     * Раз в сутки адреса второго выхода — заново (когда приложение открыто и туннель работает).
     * Таблицу сервис меняет на лету. Если выбор сайтов правили и не применили — не трогаем: это
     * решит «Сохранить и применить».
     */
    private fun refreshSecondIfStale() {
        if (secondRefreshRunning || preparingRoutes) return
        // Не собралось (DoH молчит) — следующая попытка не раньше чем через полчаса.
        if (System.currentTimeMillis() - secondRefreshTriedAt < 30 * 60_000L) return
        if (!prefs.secondExitOn || prefs.secondConf.isBlank() || prefs.secondCidrs.isBlank()) return
        // Правила сборки поменялись (1.10.35 — поддомены ChatGPT, Claude, Gemini; 1.10.38 — Grok) —
        // собираем сразу, не дожидаясь суток: иначе после обновления вход в ChatGPT (а теперь и Grok)
        // ещё сутки шёл бы через WARP.
        if (System.currentTimeMillis() - prefs.secondRoutesAt < SecondRoutes.STALE_MS && !SecondRoutes.rulesChanged(prefs)) return
        if (SecondRoutes.signature(prefs) != prefs.secondBuiltSig) return
        if (!tunnel.supported || !tunnel.isUp) return
        secondRefreshRunning = true
        secondRefreshTriedAt = System.currentTimeMillis()
        Thread {
            val result = runCatching { SecondRoutes.build(this, prefs) { } }
            val changed = result.getOrNull()?.let { SecondRoutes.save(prefs, it) } ?: false
            runOnUiThread {
                secondRefreshRunning = false
                result.onSuccess { r ->
                    TunnelDebug.stage("второй выход: адреса обновлены сами — ${r.note()}")
                    if (changed && tunnel.supported && tunnel.isUp) tunnel.reloadSecondRoutes()
                }.onFailure { TunnelDebug.stage("второй выход: адреса не обновились — ${it.message}") }
                if (uiReady()) updateSecondState()
            }
        }.apply { isDaemon = true; name = "warpscout-second-daily" }.start()
    }

    private fun updateSecondState() {
        if (!uiReady()) return
        // Второй выход включили или выключили, вставили конфиг — кнопки выхода в строках приложений
        // появляются или пропадают (с 1.10.39). Перестраиваем, только когда это меняется.
        runCatching {
            if (appExitsAvailable() != appExitsShown) {
                rebuildAppsList()
                updateAppsState()
                // С 1.10.44 (в бете — с 1.10.44-beta4): выход приложений появился — сразу «второй выход по
                // умолчанию», чтобы первое же подключение со вторым выходом шло уже с ним.
                if (appExitsShown) applySecondDefaults(null)
            }
        }.onFailure { t -> TunnelDebug.error("выход приложений: список не обновился — " + SafeMode.describe(t)) }
        runCatching {
            val server = runCatching {
                WgConf.toWarpConfig("второй выход", prefs.secondConf)?.endpoint?.render()
            }.getOrNull()
            val up = tunnel.supported && tunnel.isUp
            val snap = if (up) runCatching { TunnelStatusBus.snapshot(this) }.getOrNull() else null
            renderSecondProton(up, snap)
            binding.textSecondState.text = buildString {
                when {
                    !prefs.secondExitOn -> append(getString(R.string.second_off))
                    // Конфиг вставлен, но не разбирается — это единственная ошибка, которую человек
                    // не увидит сам: переключатель включён, а сервера фактически нет.
                    prefs.secondConf.isBlank() -> append(getString(R.string.second_need_conf))
                    server == null -> append(getString(R.string.second_bad_conf))
                    prefs.secondCidrs.isBlank() -> append(getString(R.string.second_need_cidrs))
                    else -> {
                        val transport = getString(
                            if (prefs.secondViaWarp) R.string.second_transport_warp else R.string.second_transport_direct
                        ) + (dev.warpscout.core.tunnel.AwgChannel.paramsOf(prefs.secondConf)?.let { " · AmneziaWG ${it.version}" } ?: "")
                        append(
                            getString(
                                R.string.second_on_summary, server, transport,
                                prefs.secondRoutesNote.ifBlank { "адресов: ${routeCount(prefs.secondCidrs)}" },
                                agoText(prefs.secondRoutesAt)
                            )
                        )
                        if (SecondRoutes.signature(prefs) != prefs.secondBuiltSig) {
                            append("\n").append(getString(R.string.second_changed))
                        }
                        // Что с ним в работающем туннеле — по снимку сервиса, а не по настройкам.
                        if (up) {
                            append("\n").append(
                                when (snap?.second) {
                                    TunnelStatus.SECOND_UP -> getString(R.string.second_state_up)
                                    TunnelStatus.SECOND_STARTING -> getString(R.string.second_state_starting)
                                    TunnelStatus.SECOND_FAILED -> getString(R.string.second_state_failed)
                                    else -> getString(R.string.second_apply_note)
                                }
                            )
                        }
                        // Строка проверки (с 1.10.32 — и «ушло через WARP», «вне маршрутов», время ответа).
                        val check = ExitCheck.decode(prefs.secondCheck)
                        append("\n").append(
                            when {
                                check == null -> getString(R.string.second_check_none)
                                check.code == ExitCheck.FAIL -> getString(R.string.second_check_fail, check.detail, clock(check.at))
                                check.code == ExitCheck.VIA_WARP -> getString(R.string.second_check_warp, clock(check.at))
                                check.code == ExitCheck.NOT_ROUTED -> getString(R.string.second_check_not_routed, clock(check.at))
                                check.code == "RU" -> getString(R.string.second_check_ru, clock(check.at))
                                else -> getString(R.string.second_check_ok, check.code, check.detail, clock(check.at)) +
                                    if (check.ms >= 0) getString(R.string.second_check_ms, check.ms) else ""
                            }
                        )
                        if (prefs.appsMode == Prefs.APPS_ONLY && prefs.appsSelected.isNotEmpty()) {
                            append("\n").append(getString(R.string.second_apps_warn))
                        }
                    }
                }
            }
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
        // Что дозор знает о точках этой сети: «отвечает» / «не ответила в 12:53» — до нажатия.
        // Запоминаем в самом начале: опрос сравнивает с этим и не перерисовывает список зря.
        val marksText = runCatching { TunnelStatusBus.snapshot(this).marks }.getOrDefault("")
        lastMarksRendered = marksText
        // С 1.10.30 карточка — то же, что шторка «Резервная точка» упрощённого экрана: обе сети,
        // отметка резервной, «Перейти сейчас» и свой подбор у каждой (см. fillPointGroups).
        // Карточку показываем всегда: даже без точек в ней кнопки подбора для обеих сетей.
        binding.cardTop3.visibility = View.VISIBLE
        val any = fillPointGroups(binding.groupTop3, leave = {}, changed = { runCatching { renderShortlist() } })
        binding.btnTop3Forget.visibility = if (any) View.VISIBLE else View.GONE
    }

    /**
     * Лучшие точки двумя частями — Wi-Fi и мобильная сеть — одинаково в шторке упрощённого экрана
     * и в карточке расширенного (с 1.10.30). Раньше в расширенном была только тройка текущей сети:
     * нажатие переключало, резервная ставилась долгим нажатием — «в расширенном немного другое».
     * Теперь везде одно и то же:
     *  • отметка (кружок) — только резервная точка своей сети, туннель не трогается;
     *  • «Перейти сейчас» — отдельной кнопкой, только у точек текущей сети и не у работающей;
     *  • «Снять отметку» — у каждой сети своя;
     *  • у каждой части своя кнопка подбора: Wi-Fi — когда телефон на Wi-Fi, мобильная — и с Wi-Fi.
     *
     * [leave] — перед действием, которое уводит с экрана (шторку надо закрыть); [changed] — после
     * смены отметки. Возвращает true, если есть что показать (точки или работающая точка).
     */
    private fun fillPointGroups(container: LinearLayout, leave: () -> Unit, changed: () -> Unit): Boolean {
        container.removeAllViews()
        val transport = runCatching { TuningCache.transportOf(this) }.getOrDefault("")
        val all = runCatching { ConfigShortlist.ordered(this, transport) }.getOrDefault(emptyList())
        val snap = runCatching { TunnelStatusBus.snapshot(this) }.getOrNull()
        val marks = parseMarks(snap?.marks)
        val up = runCatching { tunnel.isUp }.getOrDefault(false)
        val live = if (up) runCatching { TunnelDebug.endpoint }.getOrDefault("").trim() else ""
        val currentGroup = ConfigShortlist.group(transport)
        val otherGroup = if (currentGroup == ConfigShortlist.GROUP_MOBILE) ConfigShortlist.GROUP_WIFI else ConfigShortlist.GROUP_MOBILE
        val canScanMobile = currentGroup == ConfigShortlist.GROUP_WIFI && runCatching { CellularNetwork.maybeAvailable(this) }.getOrDefault(false)
        val density = resources.displayMetrics.density
        fun dp(v: Int): Int = (v * density).toInt()
        fun wrap() = LinearLayout.LayoutParams(LinearLayout.LayoutParams.WRAP_CONTENT, LinearLayout.LayoutParams.WRAP_CONTENT)
        fun caption(text: CharSequence, bottom: Int = 4) = android.widget.TextView(this).apply {
            this.text = text
            setTextAppearance(com.google.android.material.R.style.TextAppearance_Material3_BodySmall)
            setTextColor(ContextCompat.getColor(this@MainActivity, R.color.colorOnSurfaceVariant))
            setPadding(0, 0, 0, dp(bottom))
        }
        fun textAction(text: String, onClick: () -> Unit) = android.widget.TextView(this).apply {
            // Простая текстовая кнопка цвета темы — как «Снять отметку» в шторке.
            this.text = text
            setTextAppearance(com.google.android.material.R.style.TextAppearance_Material3_LabelLarge)
            setTextColor(ContextCompat.getColor(this@MainActivity, R.color.colorPrimary))
            setPadding(0, dp(8), dp(16), dp(8))
            isClickable = true
            isFocusable = true
            setOnClickListener { onClick() }
        }

        for (group in listOf(currentGroup, otherGroup)) {
            val entries = all.filter { ConfigShortlist.group(it.network) == group }.take(ConfigShortlist.MAX)
            val isCurrent = group == currentGroup
            val title = getString(if (group == ConfigShortlist.GROUP_MOBILE) R.string.sheet_group_mobile else R.string.sheet_group_wifi)
            container.addView(
                android.widget.TextView(this).apply {
                    text = if (isCurrent) getString(R.string.sheet_group_now, title) else title
                    setTextAppearance(com.google.android.material.R.style.TextAppearance_Material3_TitleSmall)
                    setPadding(0, dp(14), 0, dp(2))
                }
            )
            val hint = when {
                entries.isEmpty() -> getString(R.string.sheet_group_empty)
                entries.any { it.handshakeOnly } -> getString(R.string.sheet_group_handshake) +
                    (if (!isCurrent) " " + getString(R.string.sheet_group_other) else "")
                !isCurrent -> getString(R.string.sheet_group_other)
                else -> ""
            }
            if (hint.isNotBlank()) container.addView(caption(hint))
            // Подключены к точке не из списка (сохранённый конфиг, ручной сервер): молчать нельзя,
            // иначе при живом туннеле в списке «ничего не работает».
            if (isCurrent && live.isNotEmpty() && entries.none { it.endpoint.trim() == live }) {
                container.addView(caption(dotLine(getString(R.string.points_live_other, live), ContextCompat.getColor(this, R.color.check_ok))))
            }
            val backup = prefs.backupFor(group)
            val radios = ArrayList<MaterialRadioButton>()
            for (entry in entries) {
                val ep = entry.endpoint.trim()
                val row = dev.warpscout.app.databinding.ItemBackupRowBinding.inflate(layoutInflater, container, false)
                val isLive = isCurrent && ep == live && live.isNotEmpty()
                // Метки дозора — про текущую сеть: у точек другой сети их не показываем.
                val state = when {
                    isLive -> getString(R.string.mark_current)
                    isCurrent -> markText(ep, marks) ?: getString(R.string.mark_unknown)
                    else -> getString(R.string.mark_unknown)
                }
                val color = when {
                    isLive -> ContextCompat.getColor(this, R.color.check_ok)
                    isCurrent -> markColor(ep, marks)
                    else -> ContextCompat.getColor(this, R.color.state_off)
                }
                val line = android.text.SpannableStringBuilder()
                    .append(ep)
                    .append("\n")
                    .append(dotLine(state, color))
                    .append(" · ")
                    .append(getString(R.string.sheet_row_junk, entry.junk))
                if (entry.resourcesOk >= 0 && entry.resourcesTotal > 0) {
                    line.append(" · ").append(getString(R.string.top3_res, entry.resourcesOk, entry.resourcesTotal))
                } else if (entry.dataMs >= 0) {
                    line.append(" · ").append(getString(R.string.sheet_row_data))
                }
                if (entry.speedKbps > 0) line.append(" · ").append(SpeedTest.human(entry.speedKbps))
                row.rowRadio.text = line
                row.rowRadio.isChecked = ep == backup
                row.rowRadio.setOnClickListener { clicked ->
                    radios.forEach { other -> other.isChecked = other === clicked }
                    // Только запоминаем: туннель не трогаем (просьба «выбрать, но не применять»).
                    if (prefs.backupFor(group) != ep) {
                        prefs.setBackupFor(group, ep)
                        TunnelDebug.stage("резервная точка для сети «${groupName(group)}» выбрана: $ep (туннель не трогаю)")
                        banner(getString(R.string.backup_set_group, groupName(group), ep))
                        changed()
                    }
                }
                radios += row.rowRadio
                // Перейти сейчас — только на точку текущей сети и не на ту, что уже работает.
                row.rowConnect.visibility = if (isCurrent && !isLive) View.VISIBLE else View.GONE
                row.rowConnect.setOnClickListener {
                    leave()
                    switchToShortlist(entry)
                }
                container.addView(row.root)
            }
            if (backup.isNotBlank()) {
                container.addView(
                    textAction(getString(R.string.sheet_clear_group)) {
                        if (prefs.backupFor(group).isNotBlank()) toggleBackup(prefs.backupFor(group), group)
                        changed()
                    },
                    wrap()
                )
            }
            // Свой подбор у каждой сети. Wi-Fi подбирается только на Wi-Fi; мобильная — и с Wi-Fi
            // (через мобильную сеть, не уходя с Wi-Fi), если в телефоне есть SIM.
            val scanMode = when {
                isCurrent -> Engine.SCAN_CURRENT
                group == ConfigShortlist.GROUP_MOBILE && canScanMobile -> Engine.SCAN_MOBILE
                else -> -1
            }
            if (scanMode >= 0) {
                val label = if (group == ConfigShortlist.GROUP_MOBILE) R.string.points_scan_mobile else R.string.points_scan_wifi
                container.addView(
                    com.google.android.material.button.MaterialButton(
                        this, null, com.google.android.material.R.attr.materialButtonOutlinedStyle
                    ).apply {
                        text = getString(label)
                        setOnClickListener {
                            leave()
                            // Подбор гасит туннель на время замеров и возвращает его сам (на новой
                            // точке, если найдёт), — см. restoreTunnelAfterScan.
                            startScan(autoConnect = false, mode = scanMode)
                        }
                    },
                    wrap().apply { topMargin = dp(4) }
                )
            } else if (group == ConfigShortlist.GROUP_WIFI) {
                container.addView(caption(getString(R.string.points_scan_wifi_later)))
            }
        }
        return all.isNotEmpty() || live.isNotEmpty()
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
        // Проверка выбранной точки уже идёт — второе нажатие ждёт её итога.
        if (probing) {
            banner(getString(R.string.tunnel_connecting_busy))
            return
        }
        val cfg = ConfigShortlist.config(entry)
        if (cfg == null) {
            // Испорченную запись не оставляем: иначе нажатие «переключиться» просто ничего не делает.
            // Переписываем весь список без неё — тройка другой сети должна остаться.
            val rest = runCatching { ConfigShortlist.load(this) }.getOrDefault(emptyList())
                .filter { !(ConfigShortlist.key(it) == ConfigShortlist.key(entry) && it.network == entry.network) }
            ConfigShortlist.saveAll(this, rest)
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
        // Туннель работает — сначала спрашиваем выбранную точку пробой рядом с ним, рабочий туннель
        // не трогая. В журнале 14:29 человек трижды выбирал точки, которые дозор уже полтора часа
        // видел молчащими: каждый раз туннель гас, три секунды ждал мёртвую точку и возвращался на
        // прежнюю, а на экране это выглядело как «переподключил ту же». Теперь молчащая точка
        // называется прямо, и рабочий туннель остаётся как был.
        if (tunnel.isUp && !connecting && !engine.running && prefs.featProbeBeforeSwitch) {
            val current = TunnelDebug.endpoint.trim().ifBlank { prefs.lastEndpoint }
            probing = true
            banner(getString(R.string.probe_checking, entry.endpoint))
            Thread {
                val code = runCatching { tunnel.probe(entry.endpoint, 6_000) }.getOrDefault(-1)
                runOnUiThread {
                    probing = false
                    if (!::binding.isInitialized) return@runOnUiThread
                    if (code == TunnelStatus.PROBE_SILENT || code == TunnelStatus.PROBE_CLOSED) {
                        failedPoints[pointKey(cfg)] = System.currentTimeMillis()
                        val msg = getString(
                            if (code == TunnelStatus.PROBE_CLOSED) R.string.probe_closed else R.string.probe_silent,
                            entry.endpoint,
                            current.ifBlank { "—" }
                        )
                        TunnelDebug.stage("переключение не начато: $msg")
                        banner(msg, error = true)
                        renderShortlist()
                        updateSimple()
                    } else {
                        // Ответила — или проверить не вышло (туннель как раз переподнимался): тогда
                        // переключаемся как раньше, но итог всё равно назовём честно.
                        banner(getString(R.string.top3_switching, entry.endpoint))
                        connectWithFallback(cfg, cfg)
                    }
                }
            }.apply { isDaemon = true; name = "warpscout-probe-ui" }.start()
            return
        }
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
                setOnClickListener {
                    // Отметили список — через туннель должны идти сайты из списков (с 1.10.31). В режиме
                    // браузера списки и так в деле — режим не трогаем (с 1.10.43, browserHoldsRoutes).
                    prefs.allowBlockIds = listChecks.filter { it.value.isChecked && it.key in BLOCK_IDS }.map { it.key }.toSet()
                    prefs.allowDirectIds = listChecks.filter { it.value.isChecked && it.key in DIRECT_IDS }.map { it.key }.toSet()
                    if (prefs.routesMode != 2 && !browserHoldsRoutes()) binding.spinnerRoutes.setSelection(2)
                    refreshRoutesState()
                    updateTunnelSummary()
                    markSettingsDirty(getString(R.string.dirty_lists))
                }
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
            // Сайты из списков в деле и в режиме браузера (с 1.10.43).
            val listsInUse = prefs.routesMode == 2 || browserHoldsRoutes()
            if (listsInUse && prefs.allowedIpsText.isBlank()) {
                append("\n").append(getString(R.string.routes_none_yet))
            } else if (listsInUse && prefs.listsBuiltSig != listsSignature()) {
                append("\n").append(getString(R.string.routes_lists_changed))
            }
            if (cached.isEmpty()) append("\n").append(getString(R.string.routes_download_hint))
        }
        binding.textRoutesState.text = state
    }

    /** Идёт «Обновить списки» — второй раз не запускаем. */
    @Volatile
    private var listsRefreshing = false

    /**
     * «Обновить списки» (с 1.10.43 — одна кнопка вместо «Скачать списки» и «Собрать маршруты»):
     * скачать свежие списки и сразу пересобрать по ним адреса — маршруты по спискам (если сайты из
     * списков в деле: «Только сайты из списков» или браузер — только к нужным сайтам) и сети
     * выбранных приложений. Туннель не трогаем: новые адреса поднимутся со следующим подключением,
     * сразу — по «Сохранить и применить» (оно увидит, что всё собрано, и только применит).
     *
     * Раньше скачанные списки не шли в дело, пока не нажмёшь ещё и «Собрать маршруты»: «Сохранить и
     * применить» пересобирает только несобранное или собранное под другие отметки. А «Собрать
     * маршруты» вдобавок ставило режим «Только сайты из списков» и этим выключало режим браузера.
     */
    private fun refreshLists() {
        if (listsRefreshing || preparingRoutes || browserPrepRunning) {
            toast(getString(R.string.lists_busy))
            return
        }
        runCatching { persistUi() }
        val block = prefs.allowBlockIds.ifEmpty { dev.warpscout.core.lists.AllowLists.DEFAULT_BLOCK_IDS.toSet() }
        val ids = (block + prefs.allowDirectIds + DIRECT_IDS + prefs.appNetsLists()).distinct()
        listsRefreshing = true
        binding.btnRefreshLists.isEnabled = false
        binding.textRoutesState.setText(R.string.state_working)
        Thread {
            val res = lists.refresh(ids) { line -> runOnUiThread { sink().log(line) } }
            val useLists = prefs.routesMode == 2 || browserHoldsRoutes()
            val useApps = prefs.appNetsLists().isNotEmpty()
            var summary = ""
            val errors = ArrayList<String>()
            if (res.isSuccess && (useLists || useApps)) {
                runOnUiThread { if (uiReady()) binding.textRoutesState.setText(R.string.routes_expanding) }
                if (useLists) {
                    runCatching { buildListsSync() }
                        .onSuccess { summary = it }
                        .onFailure { errors += (it.message ?: it.javaClass.simpleName) }
                }
                if (useApps) {
                    runCatching { buildAppNetsSync() }
                        .onSuccess { ok -> if (!ok) errors += getString(R.string.app_nets_failed) }
                        .onFailure { errors += (it.message ?: it.javaClass.simpleName) }
                }
                // Сети приложений сервис берёт из снимка настроек — переписываем его сразу.
                runCatching { dev.warpscout.app.status.ServiceSettingsStore.syncFromPrefs(this) }
                TunnelDebug.stage(
                    "обновить списки: " + (if (summary.isNotEmpty()) "маршруты — $summary" else "маршруты по спискам не в деле") +
                        (if (errors.isNotEmpty()) "; не собралось: " + errors.joinToString("; ") else "")
                )
            }
            runOnUiThread {
                listsRefreshing = false
                if (!uiReady()) return@runOnUiThread
                runCatching {
                    binding.btnRefreshLists.isEnabled = true
                    res.onSuccess { n ->
                        when {
                            errors.isNotEmpty() -> banner(
                                getString(R.string.lists_rebuild_failed, n, ids.size, errors.joinToString("; ").take(160)),
                                error = true
                            )
                            useLists || useApps -> banner(
                                getString(
                                    R.string.lists_rebuilt, n, ids.size,
                                    summary.ifEmpty { getString(R.string.lists_rebuilt_apps) }
                                )
                            )
                            else -> toast(getString(R.string.lists_refreshed, n, ids.size))
                        }
                        updateServerNote()
                    }.onFailure { toast(getString(R.string.lists_failed, it.message ?: it.javaClass.simpleName)) }
                    refreshRoutesState()
                    updateTunnelSummary()
                }.onFailure { t -> TunnelDebug.error("обновить списки: " + SafeMode.describe(t)) }
            }
        }.apply { isDaemon = true; name = "warpscout-lists" }.start()
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
            secondSetupUntil = 0L
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
            // Первый подбор на Wi-Fi — сразу и для мобильной сети (с 1.10.31): её проверяем через
            // SIM-карту, не уходя с Wi-Fi. Уйдёт человек из дома — точки для мобильной уже готовы.
            val onWifi = ConfigShortlist.group(TuningCache.transportOf(this)) == ConfigShortlist.GROUP_WIFI
            val both = onWifi && CellularNetwork.maybeAvailable(this)
            if (both) TunnelDebug.stage("первый подбор: Wi-Fi и сразу мобильная сеть")
            startScan(autoConnect = true, mode = if (both) Engine.SCAN_BOTH else Engine.SCAN_CURRENT)
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
        secondSetupUntil = 0L
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
        // На какой точке туннель работал до переключения: если выбранная не поднимется, итог
        // называем честно — «работает прежняя», а не просто «туннель поднят».
        val liveBefore = if (tunnel.isUp) TunnelDebug.endpoint.trim() else ""
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
            var preferredWhy = ""
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
                    // Строка «что сейчас делаю» под кнопкой упрощённого экрана (с 1.10.30).
                    connectActivityText = getString(R.string.simple_act_try, n, candidates.size, cfg.endpoint.render())
                    updateSimple()
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
                if (i == 0 && preferred != null) preferredWhy = why
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
                connectActivityText = ""
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
                    val chosen = preferred?.endpoint?.render()
                    if (chosen != null && chosen != used.endpoint.render()) {
                        // Выбранная точка не поднялась, поднялась другая: так и говорим. Раньше здесь
                        // было «Туннель поднят: <прежняя>», и выбор выглядел проигнорированным.
                        val why = preferredWhy.ifBlank { getString(R.string.no_answer) }.take(90)
                        val msg = getString(
                            if (used.endpoint.render() == liveBefore) R.string.switch_fell_back else R.string.switch_fell_back_other,
                            chosen, why, used.endpoint.render()
                        )
                        TunnelDebug.stage("выбранная точка $chosen не поднялась — работает ${used.endpoint.render()}")
                        banner(msg, error = true)
                    } else {
                        banner(getString(R.string.banner_connect_ok, used.endpoint.render()))
                    }
                    // Бекап «на всякий случай»: после каждого удачного подключения, молча.
                    runCatching { Backup.saveAsync(this, getString(R.string.backup_note_connected, used.endpoint.render())) }
                    // Ручное подключение тоже наполняет кеш: следующая «Подбор» начнётся с этой точки.
                    runCatching { TuningCache.save(this, used.endpoint, used.junk.name) }
                    probeExitRegion()
                    // Второй выход: страна выхода — когда он поднимется; адреса — если устарели.
                    scheduleSecondCheck()
                    refreshSecondIfStale()
                } else {
                    TunnelDebug.error(
                        getString(R.string.no_candidates_up, candidates.size),
                        failures.toString().take(300) +
                            " · " + getString(R.string.tunnel_failed_hint)
                    )
                    // Ни одна известная точка не заработала — подбираем новые сами и подключаемся
                    // к лучшей. Человек нажал «Включить», а не «разберись с точками»: одна кнопка
                    // должна доводить дело до конца. Не чаще раза в 10 минут — без кругов.
                    val sinceScan = System.currentTimeMillis() - prefs.lastTunedAt
                    if (tunnel.supported && !engine.running && sinceScan > AUTO_RESCAN_GAP_MS) {
                        TunnelDebug.stage("известные точки не работают — подбираю новые и подключусь к лучшей")
                        prefs.endpointCursor = prefs.endpointCursor + 1
                        banner(getString(R.string.banner_auto_rescan))
                        runCatching { startScan(autoConnect = true) }
                        return@runOnUiThread
                    }
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
        // Включили второй выход — бета тут же ставит «второй выход по умолчанию» (applySecondDefaults) и
        // говорит об этом плашкой: «есть несохранённые изменения» её не затирает, а дописывается.
        val recent = secondDefaultsBanner?.takeIf { System.currentTimeMillis() - secondDefaultsBannerAt < 2_000L }
        banner(if (recent != null) recent + "\n" + getString(R.string.banner_unsaved) else getString(R.string.banner_unsaved))
    }

    private var dirtyLater: Runnable? = null

    /**
     * То же для полей со списками сайтов: отмечаем, когда человек перестал печатать. Иначе каждая
     * буква писала бы в журнал «изменено…» — в журнале 2122 так набралось девять строк подряд.
     */
    private fun markSettingsDirtyLater(why: String) {
        if (suppressSettingsReconnect) return
        dirtyLater?.let { tunnelHandler.removeCallbacks(it) }
        val r = Runnable {
            dirtyLater = null
            if (uiReady()) runCatching { markSettingsDirty(why) }
        }
        dirtyLater = r
        tunnelHandler.postDelayed(r, 1500L)
    }

    /**
     * «Сохранить и применить»: сохраняем экран в Prefs и — если туннель поднят — переподключаем
     * его с новыми настройками (до трёх попыток). Если туннель не поднят, применять нечего:
     * настройки вступят в силу при следующем подключении.
     */
    private fun saveAndApply(why: String, upText: String? = null, downText: String? = null) {
        persistUi()
        // Сервис (процесс туннеля) читает общий снимок настроек: при переподключении по сети он
        // должен взять новые маршруты, даже если туннель сейчас выключен и подключения отсюда нет.
        runCatching { ServiceSettingsStore.syncFromPrefs(this) }
        updateServerNote()
        refreshRoutesState()
        binding.textConfig.text = runCatching { currentConfig()?.let { currentConfigText(it) } }.getOrNull().orEmpty()
        if (tunnel.supported && (tunnel.isUp || tunnel.active)) {
            val cfg = currentConfig()
            if (cfg == null) {
                banner(getString(R.string.banner_saved_only))
                return
            }
            banner(upText ?: getString(R.string.banner_applying))
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
            banner(downText ?: getString(R.string.banner_saved_only))
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
        // То же сообщение — строкой над плитками упрощённого экрана: панель вкладки «Главная» там
        // не видна, а «точка не отвечает — оставил текущую» человек должен прочитать.
        runCatching {
            val m = binding.simple.simpleMessage
            m.text = text
            m.setTextColor(
                androidx.core.content.ContextCompat.getColor(this, if (error) R.color.state_error else R.color.state_ok)
            )
            m.visibility = View.VISIBLE
        }
        bannerShownAt = System.currentTimeMillis()
        bannerIsError = error
        tunnelHandler.removeCallbacks(bannerHide)
        if (!error) tunnelHandler.postDelayed(bannerHide, BANNER_MS)
    }

    private val bannerHide = Runnable {
        if (::binding.isInitialized) {
            binding.cardBanner.visibility = View.GONE
            runCatching { binding.simple.simpleMessage.visibility = View.GONE }
        }
    }

    private fun hideBanner() {
        tunnelHandler.removeCallbacks(bannerHide)
        if (::binding.isInitialized) {
            binding.cardBanner.visibility = View.GONE
            runCatching { binding.simple.simpleMessage.visibility = View.GONE }
        }
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
            val remembered = EndpointMemory.goodFor(this, NetIdentity.currentKey(this).ifBlank { netKindNow() })
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
        // Тройка текущей сети — первой: точки, подобранные на мобильной, на Wi-Fi часто молчат.
        runCatching { ConfigShortlist.ordered(this, TuningCache.transportOf(this)) }.getOrDefault(emptyList())
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
        // DNS у всех кандидатов — выбранный сейчас: тексты из подбора и сохранённый конфиг несут
        // DNS того времени, и смена DNS в настройках иначе до туннеля не доходила.
        val dns = runCatching { prefs.dnsServers() }.getOrDefault(emptyList())
        // Маршруты — тоже нынешние (с 1.10.33): точка из топа несла маршруты времени подбора, и в
        // журнале 23.11 «переключение из топа» поднимало туннель с 56 маршрутами «всё, кроме
        // российских сетей», хотя выбраны были списки. То же сервис делает и сам (см.
        // WarpVpnService.routesFromSettings) — для автоподъёма, где этого кода нет.
        val routes = runCatching { dev.warpscout.core.config.SplitRoutes.prefixesOf(prefs.allowedIps()) }
            .getOrDefault(emptyList())
        return (listOfNotNull(first) + ordered).take(MAX_ENDPOINT_TRIES)
            .map { cfg -> if (dns.isNotEmpty() && cfg.dns != dns) cfg.copy(dns = dns) else cfg }
            .map { cfg ->
                if (routes.isEmpty() || dev.warpscout.core.config.SplitRoutes.prefixesOf(cfg.allowedIps) == routes) cfg
                else cfg.copy(allowedIps = routes.joinToString(", "))
            }
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
        // Выход по проверке связи сервиса — самый свежий: он проверен запросом через туннель.
        val snap = runCatching { TunnelStatusBus.snapshot(this) }.getOrNull()
        val serviceExit = snap?.takeIf { it.up && it.linkWeb == TunnelStatus.LINK_OK }?.linkExit.orEmpty()
        // Выход — только страной («RU»): площадка Cloudflare (HEL, DME) читалась как страна, а город с
        // предупреждением про Telegram («Москва — Telegram может тормозить») человек попросил убрать
        // (23.11): площадка и что с Telegram — в журнале. Страна — по свежей проверке, иначе запомненная.
        val fresh = listOf(serviceExit, exitRegion).firstOrNull { dev.warpscout.core.net.CfTrace.countryOf(it).isNotBlank() }
        val region = dev.warpscout.core.net.CfTrace.countryOf(fresh ?: prefs.lastExitRegion)
            .ifBlank { getString(R.string.region_unknown) }
        val text = StringBuilder(getString(R.string.endpoint_now, now.ifBlank { "—" }, region))
        // Второй выход — третьей строкой, только когда он поднят (см. secondExitCountry).
        secondExitCountry(snap)?.let { country ->
            text.append('\n').append(
                getString(R.string.endpoint_second, country.ifBlank { getString(R.string.region_unknown) })
            )
        }
        binding.textEndpointNow.text = text
    }

    /**
     * Страна второго выхода для строк «где мы» (с 1.10.40): null — в этой сессии он не поднят (о нём не
     * пишем), "" — поднят, страна неизвестна. По серверу Proton, иначе по последней проверке своего
     * сервера (см. ExitCheck.secondCountry).
     */
    private fun secondExitCountry(snap: TunnelStatus?): String? = runCatching {
        ExitCheck.secondCountry(
            snap != null && snap.up && snap.second == TunnelStatus.SECOND_UP,
            snap?.secondPeer.orEmpty(),
            ExitCheck.decode(prefs.secondCheck)
        )
    }.getOrNull()

    /** Вопрос про Telegram, уже показанный окном на этом экране (по времени вопроса). */
    private var tgAskShownAt = 0L

    /**
     * Вопрос «пустить Telegram через второй выход?» (с 1.10.36) задаёт уведомление. Если уведомления
     * приложения или их канал выключены, его никто не увидит — тогда спрашиваем окном, пока экран
     * открыт. Один раз на вопрос; ответ уходит в сервис, как кнопка уведомления.
     */
    private fun maybeAskTelegram() {
        if (!screenResumed || isFinishing || isDestroyed) return
        val snap = runCatching { TunnelStatusBus.snapshot(this) }.getOrNull() ?: return
        if (snap.tgAskAt <= 0L || snap.tgAsk.isBlank() || snap.tgAskAt == tgAskShownAt) return
        val nm = androidx.core.app.NotificationManagerCompat.from(this)
        val channelOff = Build.VERSION.SDK_INT >= Build.VERSION_CODES.O &&
            nm.getNotificationChannel(TelegramChoiceMemory.ASK_CHANNEL)?.importance == android.app.NotificationManager.IMPORTANCE_NONE
        if (nm.areNotificationsEnabled() && !channelOff) return
        tgAskShownAt = snap.tgAskAt
        android.app.AlertDialog.Builder(this)
            .setTitle(R.string.tg_ask_dialog_title)
            .setMessage(snap.tgAsk)
            .setPositiveButton(R.string.tg_ask_switch) { _, _ -> runCatching { tunnel.answerTelegram(true) } }
            .setNegativeButton(R.string.tg_ask_stay) { _, _ -> runCatching { tunnel.answerTelegram(false) } }
            .show()
    }

    private fun probeExitRegion() {
        Thread {
            // Сначала по адресу 1.1.1.1 (с 1.10.35): при раздельных маршрутах он в туннеле (DNS идёт
            // через туннель), а www.cloudflare.com — нет, и регион выходил «мимо WARP» (журнал 23.11).
            fun traceOf(url: String): dev.warpscout.core.net.CfTrace? = runCatching {
                val conn = java.net.URL(url).openConnection() as java.net.HttpURLConnection
                conn.connectTimeout = 5000
                conn.readTimeout = 5000
                val text = conn.inputStream.bufferedReader().use { it.readText() }
                dev.warpscout.core.net.CfTrace.parse(text)
            }.getOrNull()
            val trace = traceOf(dev.warpscout.core.net.CfTrace.URL_BY_IP)?.takeIf { it.viaWarp }
                ?: traceOf("https://www.cloudflare.com/cdn-cgi/trace")
            runOnUiThread {
                when {
                    trace == null -> {
                        exitRegion = getString(R.string.region_unknown)
                        TunnelDebug.stage("регион выхода не определён: Cloudflare не ответил")
                    }
                    trace.viaWarp -> {
                        exitRegion = trace.summary()
                        prefs.lastExitRegion = exitRegion
                        TunnelDebug.stage("регион выхода через WARP: $exitRegion")
                    }
                    else -> {
                        // Запрос ушёл мимо WARP: туннель ещё поднимался или уже переключался. Раньше
                        // это записывалось как «регион выхода через WARP: HEL · RU · <адрес провайдера>»
                        // (журнал 13:35:37 и 14:29:55) — свой адрес выдавался за выход WARP.
                        exitRegion = ""
                        TunnelDebug.stage("регион выхода не определён: запрос ушёл мимо WARP (${trace.summary()})")
                    }
                }
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

    /** Страна второго выхода в строке «Точка входа / Выход» на прошлом тике (null — его не было). */
    private var lastSecondNote: String? = null

    private val tunnelPollerTask = object : Runnable {
        override fun run() {
            updateTunnelDiagnostics()
            if (!tunnel.supported) return
            runCatching { maybeAskTelegram() }
            // Отметка «сейчас подключён» в списке трёх должна появляться сразу после подъёма
            // (и сниматься после падения), а не при следующем случайном обновлении экрана.
            // Кнопка свободна (не идёт подключение и подбор) — держим её подпись в согласии с сервисом.
            if (!connecting && !engine.running) runCatching { refreshTunnelButtonLabel() }
            val upNow = runCatching { tunnel.isUp }.getOrDefault(false)
            // Начальные экраны: «Настроить» второй выход ждёт подключения — потом выбор Proton.
            if (secondSetupUntil != 0L) runCatching { continueSecondSetup(upNow) }
            val marksNow = runCatching { TunnelStatusBus.snapshot(this@MainActivity).marks }.getOrDefault("")
            if (upNow != lastShortlistUp) {
                lastShortlistUp = upNow
                renderShortlist()
                if (upNow) learnLiveEndpoint()
            } else if (marksNow != lastMarksRendered) {
                // Дозор узнал новое о точках — отметки в списке должны это показать сразу.
                renderShortlist()
            }
            // Второй выход поднимается через секунды после туннеля и может сменить сервер: строка
            // «Точка входа / Выход / Второй выход» (расширенный вид) обновляется, как только это случилось.
            runCatching {
                val secondNow = secondExitCountry(TunnelStatusBus.snapshot(this@MainActivity))
                if (secondNow != lastSecondNote) {
                    lastSecondNote = secondNow
                    if (uiReady()) updateEndpointNote()
                }
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
        // Пока идёт подбор, туннель поднимают его проверки (quiet) — это ещё не выбор точки
        // (с 1.10.34). Журнал 23.11: «конфиг обновлён на работающую точку» писался посреди подбора,
        // и следующий подъём пошёл на 8.39.214.6:928, через которую данные не шли.
        if (engine.running || Availability.processBound(this)) return
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
                // Итог проверки связи — прямо в строке: «работает» без него значило лишь «handshake
                // прошёл», а данные могли и не ходить (Telegram молчал при «подключено»).
                val link = snapshot?.takeIf { it.linkAt > 0L && it.linkAt >= it.startedAt }
                // Проверка медиа Telegram этой сессии (с 1.10.34): соединение есть, а данные идут
                // медленно или встают — «Telegram: связь есть, медиа тормозит».
                val tgMediaSlow = snapshot != null && snapshot.tgMediaAt > 0L && snapshot.tgMediaAt >= snapshot.startedAt &&
                    (snapshot.tgMedia == dev.warpscout.core.net.TelegramMedia.SLOW ||
                        snapshot.tgMedia == dev.warpscout.core.net.TelegramMedia.STALL)
                val linkText = when {
                    link == null -> ""
                    link.linkWeb == TunnelStatus.LINK_FAIL -> getString(R.string.conn_link_fail)
                    link.linkWeb == TunnelStatus.LINK_OK && link.linkTg == TunnelStatus.LINK_FAIL ->
                        getString(R.string.conn_link_ok, link.linkMs.coerceAtLeast(0)) + getString(R.string.conn_link_tg)
                    link.linkWeb == TunnelStatus.LINK_OK && tgMediaSlow ->
                        getString(R.string.conn_link_ok, link.linkMs.coerceAtLeast(0)) + getString(R.string.conn_link_tg_media)
                    link.linkWeb == TunnelStatus.LINK_OK -> getString(R.string.conn_link_ok, link.linkMs.coerceAtLeast(0))
                    else -> ""
                }
                text = getString(R.string.conn_on, uptime, endpoint) + linkText
                color = androidx.core.content.ContextCompat.getColor(
                    this,
                    if (link?.linkWeb == TunnelStatus.LINK_FAIL) R.color.state_warn else R.color.state_ok
                )
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
        updateSimple()
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

    // ------------------------------------------------ упрощённый экран

    /** Идёт проверка выбранной точки перед переключением — второе нажатие ждёт её итога. */
    @Volatile
    private var probing = false

    /** «проверено 40 из 120» — ход подбора для упрощённого экрана (там нет журнала и полосы). */
    private var scanProgressText = ""

    /**
     * Кольцо-прогресс подбора вокруг кнопки (с 1.10.30): доля 0..1, меньше нуля — подбор не идёт.
     * Фазы подбора — свои куски кольца (см. [showScanProgress]), поэтому оно не обнуляется между ними.
     */
    private var scanFraction = -1f

    /** «Что сейчас делаю» во время подбора — строка под кнопкой упрощённого экрана. */
    private var scanActivityText = ""

    /** «Что сейчас делаю» во время перебора точек при подключении. */
    private var connectActivityText = ""

    /** Статусы сервиса, которые показываем под кнопкой как есть: они уже написаны для человека. */
    private val serviceActivityPrefixes = listOf(
        "переключаюсь", "точки очереди", "нет связи", "сеть пропала", "нет сети",
        "сервер не отвечает", "загрузка через туннель", "рукопожатие есть"
    )

    /** Метки дозора, с которыми последний раз рисовался список лучших. */
    private var lastMarksRendered = ""

    /** Пока true — тумблеры вида выставляются кодом, и их слушатели молчат. */
    private var suppressModeListener = false

    /** Прошлый отсчёт трафика для «↓ … · ↑ …» на кнопке: (время, принято, отправлено). */
    private var trafficSample: Triple<Long, Long, Long>? = null

    /** Какое состояние сейчас нарисовано на кнопке: по нему таймер решает, что показывать. */
    private var lastOrbState = PowerOrbView.STATE_OFF

    /** Что дозор знает о точке на текущей сети. */
    private data class PointMark(val okAt: Long, val fails: Int, val failAt: Long)

    /** «адрес|отвечала|молчала подряд|когда;…» из снимка → по адресу. Битые куски пропускаем. */
    private fun parseMarks(text: String?): Map<String, PointMark> {
        if (text.isNullOrBlank()) return emptyMap()
        val out = HashMap<String, PointMark>()
        for (chunk in text.split(';')) {
            val parts = chunk.split('|')
            if (parts.size < 4) continue
            val ep = parts[0].trim()
            if (ep.isEmpty()) continue
            out[ep] = PointMark(
                okAt = parts[1].trim().toLongOrNull() ?: 0L,
                fails = parts[2].trim().toIntOrNull() ?: 0,
                failAt = parts[3].trim().toLongOrNull() ?: 0L
            )
        }
        return out
    }

    private fun clock(ms: Long): String =
        java.text.SimpleDateFormat("HH:mm", java.util.Locale.getDefault()).format(java.util.Date(ms))

    /** «только что» / «12 мин назад» / «3 ч назад» / «2 дн назад»; 0 — «ещё не собирались». */
    private fun agoText(at: Long): String {
        if (at <= 0L) return getString(R.string.second_never)
        val min = ((System.currentTimeMillis() - at) / 60_000L).coerceAtLeast(0L)
        return when {
            min < 1 -> "только что"
            min < 60 -> "$min мин назад"
            min < 48 * 60 -> "${min / 60} ч назад"
            else -> "${min / 1440} дн назад"
        }
    }

    /** Отметка дозора словами, без точки-маркера: «отвечает, проверено в 14:24». null — не знаем. */
    private fun markText(endpoint: String, marks: Map<String, PointMark>): String? {
        val m = marks[endpoint.trim()] ?: return null
        return when {
            m.fails > 0 && m.failAt >= m.okAt -> getString(R.string.mark_silent, clock(m.failAt))
            m.okAt > 0L -> getString(R.string.mark_ok, clock(m.okAt))
            else -> null
        }
    }

    /** Цвет отметки: зелёный — отвечает, красный — молчит, серый — не знаем. */
    private fun markColor(endpoint: String, marks: Map<String, PointMark>): Int {
        val m = marks[endpoint.trim()]
        val res = when {
            m == null -> R.color.state_off
            m.fails > 0 && m.failAt >= m.okAt -> R.color.check_fail
            m.okAt > 0L -> R.color.check_ok
            else -> R.color.state_off
        }
        return ContextCompat.getColor(this, res)
    }

    /** «● текст» с цветной точкой: состояние видно издалека, а текст остаётся обычным. */
    private fun dotLine(text: String, color: Int): CharSequence {
        val line = android.text.SpannableString("●  $text")
        line.setSpan(
            android.text.style.ForegroundColorSpan(color), 0, 1,
            android.text.Spanned.SPAN_EXCLUSIVE_EXCLUSIVE
        )
        return line
    }

    private fun linkColor(code: Int): Int = ContextCompat.getColor(
        this,
        when (code) {
            TunnelStatus.LINK_OK -> R.color.check_ok
            TunnelStatus.LINK_FAIL -> R.color.check_fail
            else -> R.color.state_off
        }
    )

    /** Сейчас на экране упрощённый вид. */
    private fun simpleShown(): Boolean =
        ::binding.isInitialized && runCatching { binding.simple.root.visibility == View.VISIBLE }.getOrDefault(false)

    /** Обработчики упрощённого экрана — один раз при построении. */
    private fun setupSimple() {
        val s = binding.simple
        s.simpleOrb.setOnClickListener { onSimpleOrbClick() }
        // «Туннелирование» (с 1.10.31) — на месте карточки скорости: приложения, сайты, списки.
        s.simpleCardTunnel.setOnClickListener { showAppsSheet() }
        s.simpleCardBackup.setOnClickListener { showBackupSheet() }
        // Шапка: два частых действия — подобрать точку заново (на Wi-Fi заодно и для мобильной
        // сети, не уходя с Wi-Fi) и проверить обновления (с 1.10.31; журнал выгружается только
        // в расширенном виде).
        s.simpleRescan.setOnClickListener { onSimpleRescanClick() }
        s.simpleUpdate.setOnClickListener { checkForUpdate() }
        s.simpleVersion.text = binding.textVersion.text
        // Один и тот же тумблер «Расширенный режим» в обоих видах (с 1.10.30): в упрощённом он
        // выключен, в расширенном включён. Раньше в расширенном стоял «Упрощённый режим», и тумблер
        // по смыслу менялся местами. Нажали — ползунок переезжает, подпись меняется на
        // «включено»/«выключено», и через мгновение меняется вид. Выбор запоминается.
        s.simpleModeSwitch.setOnCheckedChangeListener { _, isChecked ->
            if (suppressModeListener || !isChecked) return@setOnCheckedChangeListener
            showModeLabels(advanced = true)
            switchUiModeSoon(Prefs.UI_ADVANCED)
        }
        binding.switchSimpleMode.setOnCheckedChangeListener { _, isChecked ->
            if (suppressModeListener || isChecked) return@setOnCheckedChangeListener
            showModeLabels(advanced = false)
            switchUiModeSoon(Prefs.UI_SIMPLE)
        }
    }

    /** Подписи у тумблеров: «Расширенный режим · включено» / «· выключено». */
    private fun showModeLabels(advanced: Boolean) {
        runCatching {
            val text = getString(
                R.string.mode_switch_label,
                getString(R.string.mode_advanced),
                getString(if (advanced) R.string.mode_state_on else R.string.mode_state_off)
            )
            binding.simple.simpleModeLabel.text = text
            binding.textModeLabel.text = text
        }
    }

    /** Сменить вид чуть позже: чтобы было видно, как ползунок переехал (не мгновенный скачок). */
    private fun switchUiModeSoon(mode: Int) {
        tunnelHandler.postDelayed({
            runCatching {
                if (isFinishing || isDestroyed) return@runCatching
                // Передумали за эти доли секунды (ползунок вернули назад) — вид не меняем.
                val still = if (mode == Prefs.UI_ADVANCED) binding.simple.simpleModeSwitch.isChecked
                else !binding.switchSimpleMode.isChecked
                if (!still) {
                    showModeLabels(advanced = !prefs.simpleUi())
                    return@runCatching
                }
                prefs.uiMode = mode
                applyUiMode()
            }
        }, MODE_SWITCH_DELAY_MS)
    }

    /**
     * Показать упрощённый или расширенный вид. Это не два разных экрана с двумя логиками: та же
     * активность, тот же код подключения и статуса — меняется только то, что видно.
     */
    private fun applyUiMode() {
        runCatching {
            val simple = prefs.simpleUi()
            binding.simple.root.visibility = if (simple) View.VISIBLE else View.GONE
            binding.pagesFrame.visibility = if (simple) View.GONE else View.VISIBLE
            binding.navBar.visibility = if (simple) View.GONE else View.VISIBLE
            binding.cardConnStatus.visibility = if (simple) View.GONE else View.VISIBLE
            // Тумблер «Расширенный режим»: в упрощённом виде выключен, в расширенном включён.
            suppressModeListener = true
            binding.simple.simpleModeSwitch.isChecked = false
            binding.switchSimpleMode.isChecked = true
            suppressModeListener = false
            binding.simple.simpleModeLabel.text = getString(
                R.string.mode_switch_label, getString(R.string.mode_advanced), getString(R.string.mode_state_off)
            )
            binding.textModeLabel.text = getString(
                R.string.mode_switch_label, getString(R.string.mode_advanced), getString(R.string.mode_state_on)
            )
            if (simple) {
                updateSimple()
                startSimpleTick()
            } else {
                tunnelHandler.removeCallbacks(simpleTick)
                runCatching { renderShortlist() }
            }
        }.onFailure { t ->
            suppressModeListener = false
            TunnelDebug.error("переключение вида экрана: " + SafeMode.describe(t))
        }
    }

    private fun onSimpleOrbClick() {
        runCatching {
            if (engine.running) {
                // Идёт подбор — кнопка его останавливает, как «Остановить подбор» в расширенном виде.
                binding.btnStop.performClick()
            } else {
                toggleTunnel()
            }
            updateSimple()
        }.onFailure { t ->
            TunnelDebug.error("кнопка упрощённого экрана: " + SafeMode.describe(t))
            banner(getString(R.string.banner_ui_error, SafeMode.describe(t)), error = true)
        }
    }

    /**
     * «Подобрать точку заново» из шапки. На Wi-Fi с SIM-картой — заодно и тройку для мобильной сети
     * (через неё же, не уходя с Wi-Fi). Туннель на время замеров гаснет и возвращается сам.
     */
    private fun onSimpleRescanClick() {
        runCatching {
            if (engine.running) {
                banner(getString(R.string.scan_busy_scan))
                return
            }
            val onWifi = ConfigShortlist.group(TuningCache.transportOf(this)) == ConfigShortlist.GROUP_WIFI
            val both = onWifi && CellularNetwork.maybeAvailable(this)
            startScan(autoConnect = false, mode = if (both) Engine.SCAN_BOTH else Engine.SCAN_CURRENT)
        }.onFailure { t ->
            TunnelDebug.error("подбор из шапки: " + SafeMode.describe(t))
            banner(getString(R.string.banner_ui_error, SafeMode.describe(t)), error = true)
        }
    }

    /** Обновить упрощённый экран по состоянию сервиса. Сбой — строка в журнале, не падение. */
    private fun updateSimple() {
        if (!simpleShown() || !::prefs.isInitialized) return
        runCatching { updateSimpleUnsafe() }.onFailure { t ->
            TunnelDebug.error("упрощённый экран: " + SafeMode.describe(t))
        }
    }

    private fun updateSimpleUnsafe() {
        val s = binding.simple
        val snap = runCatching { TunnelStatusBus.snapshot(this) }.getOrNull()
        val up = tunnel.supported && tunnel.isUp
        val phase = snap?.phase ?: TunnelStatus.PHASE_IDLE
        val held = !up && snap?.wanted == true
        val linkFresh = up && snap != null && snap.linkAt > 0L && snap.linkAt >= snap.startedAt
        val linkBad = linkFresh && snap?.linkWeb == TunnelStatus.LINK_FAIL
        val state: Int
        val title: String
        val sub: String
        when {
            engine.running -> {
                state = PowerOrbView.STATE_CONNECTING
                title = getString(R.string.simple_state_scanning)
                // В кнопке — проценты кольца; что именно проверяется — строкой под кнопкой.
                val pct = (scanFraction * 100f).toInt()
                sub = if (pct > 0) getString(R.string.simple_scan_percent, pct)
                else scanProgressText.ifBlank { getString(R.string.simple_tap_to_stop_scan) }
            }
            connecting -> {
                state = PowerOrbView.STATE_CONNECTING
                title = getString(if (connectCancel) R.string.simple_state_cancelling else R.string.simple_state_connecting)
                sub = getString(R.string.simple_tap_to_cancel)
            }
            up && linkBad -> {
                state = PowerOrbView.STATE_ERROR
                title = getString(R.string.simple_state_no_link)
                sub = uptimeClock(snap)
            }
            up -> {
                state = PowerOrbView.STATE_ON
                title = getString(R.string.simple_state_on)
                sub = uptimeClock(snap)
            }
            phase == TunnelStatus.PHASE_NO_NETWORK -> {
                state = PowerOrbView.STATE_CONNECTING
                title = getString(R.string.simple_state_no_network)
                sub = getString(R.string.simple_tap_to_stop)
            }
            held || phase == TunnelStatus.PHASE_STARTING || phase == TunnelStatus.PHASE_RECONNECTING -> {
                state = PowerOrbView.STATE_CONNECTING
                title = getString(R.string.simple_state_waiting)
                sub = getString(R.string.simple_tap_to_stop)
            }
            else -> {
                // С 1.10.31 без подсказки «нажмите, чтобы включить»: кнопка и так одна.
                state = PowerOrbView.STATE_OFF
                title = getString(R.string.simple_state_off)
                sub = ""
            }
        }
        lastOrbState = state
        s.simpleOrbView.setState(state)
        if (s.simpleState.text.toString() != title) s.simpleState.text = title
        if (s.simpleTimer.text.toString() != sub) s.simpleTimer.text = sub
        // Пустая строка не должна занимать место: надпись «Выключено» стоит ровно по центру кнопки.
        val timerVisibility = if (sub.isBlank()) View.GONE else View.VISIBLE
        if (s.simpleTimer.visibility != timerVisibility) s.simpleTimer.visibility = timerVisibility
        // Кольцо-прогресс и строка «что сейчас делаю» (с 1.10.30): пока идёт подбор — доля кольца
        // и шаг подбора; пока подключаемся — светлая дуга бежит по кольцу, а под кнопкой видно,
        // к какой точке и что именно проверяется.
        runCatching {
            s.simpleOrbView.setProgress(if (engine.running && scanFraction >= 0f) scanFraction else null)
            val activity = when {
                engine.running -> scanActivityText
                connecting -> serviceActivity(snap).ifBlank { connectActivityText }
                state == PowerOrbView.STATE_CONNECTING -> serviceActivity(snap)
                else -> ""
            }
            if (s.simpleActivity.text.toString() != activity) s.simpleActivity.text = activity
            s.simpleActivity.visibility = if (activity.isBlank()) View.GONE else View.VISIBLE
        }
        s.simplePowerIcon.imageTintList = android.content.res.ColorStateList.valueOf(
            ContextCompat.getColor(
                this,
                when (state) {
                    PowerOrbView.STATE_ON -> R.color.orb_accent
                    PowerOrbView.STATE_ERROR -> R.color.orb_error
                    PowerOrbView.STATE_CONNECTING -> R.color.orb_warn
                    else -> R.color.colorOnSurfaceVariant
                }
            )
        )

        // Где мы: вид сети, точка входа, страна выхода WARP (если проверка связи прошла) и страна второго
        // выхода (если он поднят): «мобильная · вход 8.35.211.3:864 · выход RU · второй выход NL». Так
        // попросил человек 23.11: «просто мобильная, какой вход, какой выход, какой выход у второго;
        // если второго нет — просто не пиши». Страной, а не площадкой Cloudflare: «выход HEL» читалось
        // как Финляндия; город и предупреждение про Telegram — только в журнале.
        val endpoint = if (up) TunnelDebug.endpoint.trim().ifBlank { snap?.endpoint.orEmpty() } else ""
        val net = netKindNow().ifBlank { "сеть" }
        val exitSummary = snap?.takeIf { linkFresh && it.linkWeb == TunnelStatus.LINK_OK }?.linkExit
        val country = dev.warpscout.core.net.CfTrace.countryOf(exitSummary)
        val where = if (endpoint.isBlank()) {
            ""
        } else {
            val parts = arrayListOf(getString(R.string.simple_where, net, endpoint))
            if (country.isNotBlank()) parts += getString(R.string.where_exit, country)
            secondExitCountry(snap)?.let { second ->
                parts += if (second.isBlank()) getString(R.string.where_second_plain) else getString(R.string.where_second, second)
            }
            parts.joinToString(" · ")
        }
        s.simpleWhere.text = where
        s.simpleWhere.visibility = if (where.isBlank()) View.INVISIBLE else View.VISIBLE

        // Скорость — на самой кнопке (живой поток раз в секунду, см. updateLiveRate); ручного
        // замера больше нет (с 1.10.31). На месте её карточки — «Туннелирование».
        if (!up) {
            trafficSample = null
            if (s.simpleRate.visibility != View.GONE) s.simpleRate.visibility = View.GONE
        }
        renderTunnelCard()

        // Резервная точка текущей сети (у Wi-Fi и мобильной — свои) и что о ней знает дозор.
        val marks = parseMarks(snap?.marks)
        val group = ConfigShortlist.group(runCatching { TuningCache.transportOf(this) }.getOrDefault(""))
        s.simpleBackupTitle.text = getString(
            R.string.simple_backup_title_net,
            getString(if (group == ConfigShortlist.GROUP_MOBILE) R.string.net_mobile else R.string.net_wifi)
        )
        val backup = prefs.backupFor(group)
        if (backup.isBlank()) {
            s.simpleBackupValue.text = getString(R.string.simple_backup_none)
            s.simpleBackupState.text = getString(R.string.simple_backup_hint_none)
            s.simpleBackupState.setTextColor(ContextCompat.getColor(this, R.color.colorOnSurfaceVariant))
        } else {
            s.simpleBackupValue.text = backup
            val text = if (up && backup == endpoint) getString(R.string.mark_current)
            else markText(backup, marks) ?: getString(R.string.mark_unknown)
            val color = if (up && backup == endpoint) ContextCompat.getColor(this, R.color.check_ok)
            else markColor(backup, marks)
            s.simpleBackupState.text = dotLine(text, color)
            s.simpleBackupState.setTextColor(ContextCompat.getColor(this, R.color.colorOnSurfaceVariant))
        }
    }

    /**
     * «↓ … · ↑ …» на кнопке — сколько качается в эту секунду. Считаем по трафику своего приложения:
     * через его сокет идёт весь туннель (в зашифрованном виде), так что это и есть поток всех
     * приложений в туннеле. Снимок сервиса для этого не годится: он обновляется раз в минуту.
     * С 1.10.31 это и есть «скорость» упрощённого экрана — без ручного замера.
     */
    private fun updateLiveRate() {
        val s = binding.simple
        val on = lastOrbState == PowerOrbView.STATE_ON || lastOrbState == PowerOrbView.STATE_ERROR
        if (!on) {
            trafficSample = null
            if (s.simpleRate.visibility != View.GONE) s.simpleRate.visibility = View.GONE
            return
        }
        val uid = android.os.Process.myUid()
        val rx = android.net.TrafficStats.getUidRxBytes(uid)
        val tx = android.net.TrafficStats.getUidTxBytes(uid)
        if (rx < 0L || tx < 0L) {
            s.simpleRate.visibility = View.GONE
            return
        }
        val t = android.os.SystemClock.elapsedRealtime()
        val prev = trafficSample
        trafficSample = Triple(t, rx, tx)
        if (prev == null) return
        val dt = t - prev.first
        if (dt <= 0L) return
        // Байты за миллисекунды × 8 = килобиты в секунду.
        val down = ((rx - prev.second).coerceAtLeast(0L) * 8L / dt).toInt()
        val upRate = ((tx - prev.third).coerceAtLeast(0L) * 8L / dt).toInt()
        // С 1.10.32 — две строки, «↓ …» над «↑ …», стрелки цветом кнопки: в одну строку скорость
        // упиралась в кольцо (снимок экрана 22.11).
        val text = getString(R.string.simple_rate, SpeedTest.human(down), SpeedTest.human(upRate))
        if (s.simpleRate.text.toString() != text) {
            val styled = android.text.SpannableString(text)
            val accent = ContextCompat.getColor(this, R.color.orb_accent)
            text.forEachIndexed { i, c ->
                if (c == '↓' || c == '↑') {
                    styled.setSpan(android.text.style.ForegroundColorSpan(accent), i, i + 1, android.text.Spanned.SPAN_EXCLUSIVE_EXCLUSIVE)
                    styled.setSpan(android.text.style.StyleSpan(android.graphics.Typeface.BOLD), i, i + 1, android.text.Spanned.SPAN_EXCLUSIVE_EXCLUSIVE)
                }
            }
            s.simpleRate.text = styled
        }
        s.simpleRate.visibility = View.VISIBLE
        runCatching { fitRateToOrb(text.split('\n')) }
    }

    /** Обычный размер строки скорости (px) — из разметки; запоминается до первого уменьшения. */
    private var rateBasePx = 0f

    /**
     * Скорость — целиком внутри внутреннего кольца кнопки (с 1.10.32). Строки стоят в нижней
     * половине круга, где он уже; ширина круга на высоте строки — хорда. Не помещается (крупный
     * шрифт в настройках телефона, «100 Мбит/с») — уменьшаем шрифт, но не меньше 9sp.
     *
     * Колонка (значок, «Подключено», время, скорость) стоит по центру кнопки, поэтому низ i-й строки
     * лежит на above/2 + (i + 1 − n/2)·h ниже центра, где above — высота всего, что над скоростью (от
     * размера скорости не зависит), h — высота строки. Расчёт не опирается на текущий размер строки:
     * размер не «прыгает» туда-обратно каждую секунду.
     */
    private fun fitRateToOrb(lines: List<String>) {
        val s = binding.simple
        val rate = s.simpleRate
        val orb = s.simpleOrb
        if (orb.width <= 0 || !rate.isLaidOut || rate.height <= 0) {
            // Строка только что появилась и ещё не разложена — посчитаем после раскладки.
            rate.post { runCatching { if (rate.isLaidOut && rate.height > 0) fitRateToOrb(lines) } }
            return
        }
        val dm = resources.displayMetrics
        if (rateBasePx <= 0f) rateBasePx = rate.textSize
        val base = rateBasePx
        // Внутреннее кольцо — 0.76 размера кнопки минус 7dp (см. PowerOrbView), и ещё 5dp поля.
        val radius = minOf(orb.width, orb.height) / 2f * 0.76f - 12f * dm.density
        val above = rate.top.toFloat()
        val paint = android.text.TextPaint(rate.paint).apply { textSize = base }
        val fm = paint.fontMetrics
        val lineH = (fm.bottom - fm.top) + rate.lineSpacingExtra
        val widths = lines.map { paint.measureText(it) }
        val n = lines.size
        val min = android.util.TypedValue.applyDimension(android.util.TypedValue.COMPLEX_UNIT_SP, 9f, dm)
        val step = android.util.TypedValue.applyDimension(android.util.TypedValue.COMPLEX_UNIT_SP, 0.5f, dm)
        var size = base
        while (size > min) {
            val k = size / base
            val fits = widths.indices.all { i ->
                val y = above / 2f + (i + 1 - n / 2f) * lineH * k
                val half = if (y >= radius) 0f else kotlin.math.sqrt(radius * radius - y * y)
                widths[i] * k / 2f <= half
            }
            if (fits) break
            size -= step
        }
        size = size.coerceAtLeast(min)
        if (abs(rate.textSize - size) > 0.5f) rate.setTextSize(android.util.TypedValue.COMPLEX_UNIT_PX, size)
    }

    /** «00:12:34» от начала текущей сессии (время помнит сервис — переживает перезапуск экрана). */
    private fun uptimeClock(snap: TunnelStatus?): String {
        val since = snap?.startedAt?.takeIf { it > 0L } ?: tunnelStartedAtLocal
        if (since <= 0L) return "00:00:00"
        val sec = ((System.currentTimeMillis() - since) / 1000L).coerceAtLeast(0L)
        return String.format(java.util.Locale.US, "%02d:%02d:%02d", sec / 3600, (sec % 3600) / 60, sec % 60)
    }

    /**
     * Таймер работы на кнопке — раз в секунду, только пока упрощённый экран на виду и туннель
     * работает. Перерисовывается одна строка текста; в фоне таймер стоит (см. onPause).
     */
    private val simpleTick = object : Runnable {
        override fun run() {
            if (!screenResumed || !simpleShown()) return
            if (lastOrbState == PowerOrbView.STATE_ON || lastOrbState == PowerOrbView.STATE_ERROR) {
                runCatching {
                    val snap = TunnelStatusBus.snapshot(this@MainActivity)
                    binding.simple.simpleTimer.text = uptimeClock(snap)
                }
            }
            runCatching { updateLiveRate() }
            tunnelHandler.postDelayed(this, 1000L)
        }
    }

    private fun startSimpleTick() {
        tunnelHandler.removeCallbacks(simpleTick)
        if (screenResumed && simpleShown()) tunnelHandler.postDelayed(simpleTick, 1000L)
    }

    /** Подпись группы сетей для сообщений: «Wi-Fi» / «мобильная». */
    private fun groupName(group: String): String =
        getString(if (group == ConfigShortlist.GROUP_MOBILE) R.string.net_mobile else R.string.net_wifi)

    /**
     * Сделать точку резервной для её сети или снять отметку, если она уже резервная. Только
     * запоминает: туннель не трогается (переход сейчас — отдельной кнопкой «Перейти сейчас»).
     */
    private fun toggleBackup(endpoint: String, group: String) {
        val ep = endpoint.trim()
        if (ep.isEmpty()) return
        if (prefs.backupFor(group) == ep) {
            prefs.setBackupFor(group, "")
            TunnelDebug.stage("резервная точка для сети «${groupName(group)}» снята")
            banner(getString(R.string.backup_cleared_group, groupName(group)))
        } else {
            prefs.setBackupFor(group, ep)
            TunnelDebug.stage("резервная точка для сети «${groupName(group)}» выбрана: $ep (туннель не трогаю)")
            banner(getString(R.string.backup_set_group, groupName(group), ep))
        }
        runCatching { renderShortlist() }
        updateSimple()
    }

    private fun showBackupSheet() {
        runCatching { showBackupSheetUnsafe() }.onFailure { t ->
            TunnelDebug.error("выбор резервной точки: " + SafeMode.describe(t))
            banner(getString(R.string.banner_ui_error, SafeMode.describe(t)), error = true)
        }
    }

    /**
     * Выбор резервной точки: две части — Wi-Fi и мобильная сеть, у каждой своя тройка лучших и
     * своя резервная (обе можно выбрать, находясь на Wi-Fi). Отметка только запоминает точку: если
     * текущая замолчит, сервис сам перейдёт на резервную своей сети. «Перейти сейчас» — отдельная
     * кнопка, и только у точек текущей сети (сначала проба рядом с работающим туннелем).
     */
    private fun showBackupSheetUnsafe() {
        val dialog = com.google.android.material.bottomsheet.BottomSheetDialog(this)
        val sheet = dev.warpscout.app.databinding.SheetBackupBinding.inflate(layoutInflater)
        val all = runCatching { ConfigShortlist.load(this) }.getOrDefault(emptyList())
        sheet.sheetEmpty.visibility = if (all.isEmpty()) View.VISIBLE else View.GONE
        // Части «Wi-Fi» и «Мобильная сеть» — общей функцией с карточкой расширенного вида: выбор
        // резервной и подбор для каждой сети выглядят и работают одинаково в обоих режимах.
        // После смены отметки шторка перерисовывается сама: «Снять отметку» появляется и уходит.
        fun fill() {
            fillPointGroups(
                sheet.sheetRows,
                leave = { dialog.dismiss() },
                changed = {
                    runCatching { renderShortlist() }
                    updateSimple()
                    runCatching { fill() }
                }
            )
        }
        fill()
        dialog.setContentView(sheet.root)
        dialog.setOnDismissListener { updateSimple() }
        dialog.show()
    }

    // ------------------------------------------------ выход по приложениям (с 1.10.39)
    //
    // Человек 23.11: «дай возможность пропускать через второй канал любые приложения и отключать
    // второй канал для них». Кнопка в строке приложения — «Само» / «Всегда WARP» / «Второй выход»
    // (решил человек: в строке, в обоих режимах). Решает сервис, по владельцу соединения (AppExit).

    /**
     * Выход приложения можно выбирать: Android 10+ (раньше система не говорит VPN, чьё соединение),
     * второй выход включён и его конфиг читается. Иначе кнопки в строках нет.
     */
    private fun appExitsAvailable(): Boolean =
        Build.VERSION.SDK_INT >= 29 && prefs.secondExitOn &&
            runCatching { WgConf.toWarpConfig("второй выход", prefs.secondConf) != null }.getOrDefault(false)

    private fun exitLabel(rule: Int): String = getString(
        when (rule) {
            AppExit.WARP -> R.string.app_exit_warp
            AppExit.SECOND -> R.string.app_exit_second
            else -> R.string.app_exit_auto
        }
    )

    /** «Aurora Store — второй выход, Telegram — WARP». */
    private fun exitsSummary(rules: Map<String, Int>): String = rules.entries
        .sortedBy { labelOfPackage(it.key).lowercase() }
        .joinToString(", ") { (pkg, rule) ->
            getString(if (rule == AppExit.SECOND) R.string.apps_exits_second else R.string.apps_exits_warp, labelOfPackage(pkg))
        }

    /**
     * «Второй выход» у приложения, адресов которого мы не знаем, а маршруты туннеля — не «весь
     * трафик»: Android пускает в туннель только адреса из маршрутов, и такое приложение пойдёт через
     * второй выход только к ним. У известных приложений свои адреса в маршрутах (AppServices).
     */
    private fun exitPartialFor(pkg: String, rule: Int): Boolean {
        if (rule != AppExit.SECOND || AppServices.serviceOf(pkg) != null) return false
        val browser = runCatching { prefs.browserSitesWanted() }.getOrDefault(false)
        return browser || prefs.routesMode == 2 || prefs.routesMode == 3
    }

    /** Предупредить сразу при выборе (строка тоже подписана). */
    private fun warnExitPartial(pkg: String, rule: Int) {
        if (exitPartialFor(pkg, rule)) toast(getString(R.string.app_exit_partial_toast, prefs.routesModeName(), labelOfPackage(pkg)))
    }

    /** Меню выхода приложения: три варианта, нынешний отмечен. Для Telegram «Само» — с вопросом. */
    private fun showExitMenu(anchor: View, pkg: String, current: Int, onPick: (Int) -> Unit) {
        val popup = androidx.appcompat.widget.PopupMenu(this, anchor)
        val menu = popup.menu
        // Номера пунктов — правило + 1: пункт с номером 0 у меню значит «без номера».
        val telegram = AppServices.serviceOf(pkg)?.title == "Telegram"
        menu.add(0, AppExit.AUTO + 1, 0, getString(if (telegram) R.string.app_exit_menu_auto_tg else R.string.app_exit_menu_auto))
        menu.add(0, AppExit.WARP + 1, 1, getString(R.string.app_exit_menu_warp))
        menu.add(0, AppExit.SECOND + 1, 2, getString(R.string.app_exit_menu_second))
        menu.setGroupCheckable(0, true, true)
        menu.findItem(current + 1)?.isChecked = true
        popup.setOnMenuItemClickListener { item ->
            runCatching { onPick(item.itemId - 1) }.onFailure { t ->
                TunnelDebug.error("выход приложения: " + SafeMode.describe(t))
                banner(getString(R.string.banner_ui_error, SafeMode.describe(t)), error = true)
            }
            true
        }
        popup.show()
    }

    /**
     * Отметки под выход приложений: в «только выбранные» — отмечены, в «все, кроме» — не исключены.
     * Всегда новый набор: шторка очищает свой и заливает этим (тот же объект очистился бы вместе с ним).
     */
    private fun alignWithExits(mode: Int, selected: Set<String>, withExit: Set<String>): Set<String> = when (mode) {
        Prefs.APPS_ONLY -> selected + withExit
        Prefs.APPS_EXCEPT -> selected - withExit
        else -> selected.toSet()
    }

    /** Строка вкладки «Туннелирование» с кнопкой выхода справа. */
    private fun exitRow(main: View, pkg: String, rule: Int): View {
        val row = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = android.view.Gravity.CENTER_VERTICAL
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            )
        }
        main.layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
        row.addView(main)
        val button = layoutInflater.inflate(R.layout.item_exit_button, row, false) as com.google.android.material.button.MaterialButton
        button.text = exitLabel(rule)
        button.setOnClickListener { v ->
            showExitMenu(v, pkg, prefs.appExits[pkg] ?: AppExit.AUTO) { picked -> pickExitAdvanced(pkg, picked) }
        }
        appExitButtons[pkg] = button
        row.addView(button)
        return row
    }

    /**
     * Выход выбран на вкладке «Туннелирование»: сразу в настройки (как отметки там же), применяется
     * по «Сохранить и применить». «WARP» или «Второй выход» — приложение идёт через туннель.
     */
    private fun pickExitAdvanced(pkg: String, rule: Int) {
        val rules = prefs.appExits.toMutableMap()
        if (rule == AppExit.AUTO) rules.remove(pkg) else rules[pkg] = rule
        prefs.appExits = rules
        if (rule != AppExit.AUTO) {
            when (prefs.appsMode) {
                Prefs.APPS_ONLY -> if (pkg !in prefs.appsSelected) {
                    prefs.appsSelected = prefs.appsSelected + pkg
                    noteAppTick(pkg, checked = true)
                    appChecks[pkg]?.isChecked = true
                }

                // Из исключений убираем молча: «снято руками» (noteAppTick) здесь не к месту — приложение,
                // наоборот, идёт через туннель.
                Prefs.APPS_EXCEPT -> if (pkg in prefs.appsSelected) {
                    prefs.appsSelected = prefs.appsSelected - pkg
                    appChecks[pkg]?.isChecked = false
                }
            }
            warnExitPartial(pkg, rule)
        }
        appExitButtons[pkg]?.text = exitLabel(rule)
        TunnelDebug.stage("выход приложения: ${labelOfPackage(pkg)} — ${exitLabel(rule)}")
        updateAppsState()
        markSettingsDirty(getString(R.string.dirty_app_exits))
    }

    // ------------------------------------------------ Proton кнопкой (с 1.10.44-beta5)

    /**
     * «Подключить второй выход (Proton)»: ключ у Proton без сайта — см. ProtonConnect.
     *
     * С 1.10.45 — сначала туннель. Proton из России закрыт, ключ приложение получает через свой
     * туннель; при выключенном запрос уходил напрямую и падал с «Unable to resolve host
     * vpn-api.proton.me» (скриншот 25.11). Теперь кнопка говорит, что туннель выключен, и даёт включить
     * его ([beginSecondSetup] сам откроет выбор, когда туннель заработает); «Всё равно продолжить» —
     * для тех, у кого Proton открыт и без туннеля.
     */
    private fun startProtonConnect() {
        if (tunnel.supported && !tunnel.isUp) {
            askTunnelForProton()
            return
        }
        launchProtonConnect()
    }

    private fun launchProtonConnect() {
        ProtonConnect(this, prefs) { result ->
            runCatching { applyProtonResult(result) }.onFailure { t ->
                // problem, а не error: сбой ключа Proton — не «Не удалось подключиться» туннеля.
                TunnelDebug.problem("второй выход: Proton кнопкой — " + SafeMode.describe(t))
                banner(getString(R.string.banner_ui_error, SafeMode.describe(t)), error = true)
            }
        }.start()
    }

    /** Туннель выключен или ещё подключается — без него Proton кнопкой из России не дойдёт. */
    private fun askTunnelForProton() {
        if (isFinishing || isDestroyed) return
        val held = tunnel.active || connecting || engine.running
        val foreign = if (held) null else ForeignVpn.find(this, ownUp = false)
        TunnelDebug.stage(
            "Proton: туннель " + (if (held) "ещё подключается" else "выключен") + " — прошу сначала туннель" +
                (foreign?.let { "; работает другой VPN ($it)" } ?: "")
        )
        val msg = StringBuilder(getString(if (held) R.string.proton_need_tunnel_wait else R.string.proton_need_tunnel_msg))
        if (foreign != null) msg.append("\n\n").append(getString(R.string.proton_need_tunnel_foreign, foreign))
        com.google.android.material.dialog.MaterialAlertDialogBuilder(this)
            .setTitle(R.string.proton_need_tunnel_title)
            .setMessage(msg.toString())
            .setPositiveButton(if (held) R.string.proton_need_tunnel_later else R.string.proton_need_tunnel_on) { _, _ ->
                runCatching { beginSecondSetup() }.onFailure { t ->
                    TunnelDebug.problem("второй выход: туннель для Proton — " + SafeMode.describe(t))
                    banner(getString(R.string.banner_ui_error, SafeMode.describe(t)), error = true)
                }
            }
            .setNeutralButton(R.string.proton_need_tunnel_anyway) { _, _ -> launchProtonConnect() }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    /**
     * Ключ получен, сервер выбран: конфиг встаёт во второй выход (как выбранный файл), страна и сервер
     * — в автопоиск (сервер — «работавшим последним», с него перебор и начнётся), свежий список
     * серверов — в proton_free.txt. И сразу «Сохранить и применить»: человек нажал «Подключить» —
     * ждать второй кнопки незачем.
     */
    private fun applyProtonResult(r: ProtonConnect.Result) {
        if (isFinishing || isDestroyed) return
        if (r.servers.isNotEmpty() && runCatching { SecondProton.save(this, r.servers) }.getOrDefault(false)) {
            TunnelDebug.stage("Proton: список серверов обновлён — ${r.servers.size} от Proton")
        }
        prefs.protonKeySource = r.via.id
        prefs.protonKeyAccount = r.account
        prefs.protonKeyExpires = r.expiresAt
        prefs.protonKeyPublic = r.wgPublic
        prefs.secondProtonCountry = r.country
        prefs.secondProtonLast = r.server.name
        binding.editSecondConf.setText(r.conf)
        if (!binding.switchSecondExit.isChecked) binding.switchSecondExit.isChecked = true
        runCatching { setupSecondCountry() }
        updateSecondState()
        val name = r.server.name.ifBlank { r.server.ip }
        val where = SecondProton.countryName(this, r.server.code)
        TunnelDebug.stage("второй выход: Proton кнопкой (${r.via.id}) — $name, страна ${r.country.ifEmpty { "любая" }}")
        applyWithRoutes(
            getString(R.string.dirty_second_exit),
            getString(R.string.proton_connect_applying, name, where),
            getString(R.string.proton_connect_saved, name, where),
        )
    }

    /**
     * «Ключ: вход в аккаунт kos, до 25.11.2027» — пока во втором выходе конфиг с ключом, полученным
     * кнопкой (сверяем открытый ключ). За две недели до срока — подсказка получить новый.
     */
    private fun protonKeyLine(): String? {
        val pub = prefs.protonKeyPublic
        if (pub.isBlank()) return null
        val priv = prefs.secondConf.lineSequence()
            .map { it.substringBefore('#').trim() }
            .firstOrNull { it.substringBefore('=').trim().equals("PrivateKey", ignoreCase = true) }
            ?.substringAfter('=')?.trim() ?: return null
        val current = dev.warpscout.core.crypto.Crypto.base64(
            dev.warpscout.core.crypto.Crypto.publicOf(dev.warpscout.core.crypto.Crypto.unBase64(priv))
        )
        if (current != pub) return null
        val source = when (prefs.protonKeySource) {
            ProtonConnect.Via.ACCOUNT.id -> getString(R.string.proton_key_account, prefs.protonKeyAccount)
            ProtonConnect.Via.ANONYMOUS.id -> getString(R.string.proton_key_anonymous)
            ProtonConnect.Via.SERVICE.id -> getString(R.string.proton_key_service)
            else -> return null
        }
        val exp = prefs.protonKeyExpires
        if (exp <= 0L) return getString(R.string.proton_key_line, source, getString(R.string.proton_until_unknown))
        val until = java.text.SimpleDateFormat("dd.MM.yyyy", java.util.Locale.getDefault()).format(java.util.Date(exp))
        val soon = exp - System.currentTimeMillis() < 14L * 86_400_000L
        return getString(if (soon) R.string.proton_key_line_soon else R.string.proton_key_line, source, until)
    }

    // ------------------------------------------------ Proton: шаги и конфиг из файла (с 1.10.39)

    /**
     * Шаги подключения Proton VPN Free прямо в приложении (человек попросил 23.11): что нажать на
     * сайте Proton и здесь. Кнопки — выбрать скачанный файл и открыть сайт.
     */
    private fun showProtonGuide() {
        com.google.android.material.dialog.MaterialAlertDialogBuilder(this)
            .setTitle(R.string.proton_guide_title)
            .setMessage(R.string.proton_guide_text)
            .setPositiveButton(R.string.proton_guide_pick) { _, _ -> openSecondConfPicker() }
            .setNeutralButton(R.string.proton_guide_site) { _, _ -> openProtonSite() }
            .setNegativeButton(R.string.proton_guide_close, null)
            .show()
    }

    private fun openProtonSite() {
        val opened = runCatching {
            startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(PROTON_DOWNLOADS_URL)))
        }.isSuccess
        if (!opened) toast(getString(R.string.proton_site_fail))
    }

    private fun openSecondConfPicker() {
        // Тип у .conf в «Загрузках» бывает любой (text/plain, application/octet-stream) — показываем все.
        runCatching { pickSecondConf.launch(arrayOf("*/*")) }.onFailure { t ->
            secondConfApplyNow = false
            TunnelDebug.error("второй выход: окно выбора файла не открылось — " + SafeMode.describe(t))
            banner(getString(R.string.second_file_fail, SafeMode.describe(t)), error = true)
        }
    }

    /**
     * Конфиг из выбранного файла: не больше 64 КБ, текстом. Разобрался — встаёт в поле (дальше как
     * при вставке: Proton узнаётся сам), второй выход включается; применяется по «Сохранить и
     * применить». Ключ из файла в журнал не пишем — только сервер.
     */
    /**
     * Ключ AmneziaVPN «vpn://…» → текст конфига второго выхода (с 1.10.49-beta1, см. AmneziaKey). null —
     * ключ не подходит (Premium, полный доступ к серверу, XRay/OpenVPN, битый): причина уже на плашке
     * и в журнале. Ключи из ключа в журнал не пишем — только протокол и имя сервера.
     */
    private fun amneziaKeyToConf(key: String, source: String): String? =
        when (val r = dev.warpscout.core.config.AmneziaKey.decode(key)) {
            is dev.warpscout.core.config.AmneziaKey.Result.Conf -> {
                TunnelDebug.stage("второй выход: ключ AmneziaVPN ($source) — ${r.protocol}, сервер «${r.name}»")
                banner(getString(R.string.second_key_ok, r.protocol, r.name))
                r.text
            }
            is dev.warpscout.core.config.AmneziaKey.Result.Unsupported -> {
                TunnelDebug.stage("второй выход: ключ vpn:// ($source) не подошёл — ${r.reason}")
                banner(getString(R.string.second_key_bad, r.reason), error = true)
                null
            }
        }

    private fun loadSecondConf(uri: Uri) {
        val limit = 64 * 1024
        val bytes = contentResolver.openInputStream(uri)?.use { input ->
            val out = java.io.ByteArrayOutputStream()
            val buf = ByteArray(8192)
            while (out.size() <= limit) {
                val n = input.read(buf)
                if (n < 0) break
                out.write(buf, 0, n)
            }
            out.toByteArray()
        } ?: throw java.io.IOException("файл не открылся")
        if (bytes.size > limit) {
            banner(getString(R.string.second_file_big), error = true)
            return
        }
        val fileText = String(bytes, Charsets.UTF_8).replace("\uFEFF", "").replace("\r\n", "\n").trim()
        // В файле может лежать ключ AmneziaVPN «vpn://…» (с 1.10.49-beta1) — берём конфиг из него.
        val text = if (dev.warpscout.core.config.AmneziaKey.looksLike(fileText)) {
            amneziaKeyToConf(fileText, "из файла") ?: return
        } else {
            fileText
        }
        val server = runCatching { WgConf.toWarpConfig("второй выход", text) }.getOrNull()
        if (server == null) {
            TunnelDebug.stage("второй выход: в выбранном файле нет конфига WireGuard")
            banner(getString(R.string.second_file_bad), error = true)
            return
        }
        binding.editSecondConf.setText(text)
        if (!binding.switchSecondExit.isChecked) binding.switchSecondExit.isChecked = true
        val proton = ProtonFree.isProton(text)
        val endpoint = server.endpoint.render()
        TunnelDebug.stage("второй выход: конфиг из файла (${if (proton) "Proton" else "свой сервер"}, сервер $endpoint)")
        // Файл выбран из начальных экранов — применяем сразу, как конфиг Proton кнопкой (с 1.10.44-beta6):
        // «Сохранить и применить» там нет. На упрощённом экране его тоже нет — так бывает, если экран
        // пересоздался, пока было открыто окно выбора файла, и отметка «из начальных экранов» потерялась.
        val applyNow = secondConfApplyNow || simpleShown()
        secondConfApplyNow = false
        if (applyNow) {
            updateSecondState()
            applyWithRoutes(
                getString(R.string.dirty_second_exit),
                getString(R.string.second_file_applying, endpoint),
                getString(R.string.second_file_saved, endpoint),
            )
            return
        }
        markSettingsDirty(getString(R.string.dirty_second_exit))
        banner(getString(if (proton) R.string.second_file_ok_proton else R.string.second_file_ok, endpoint))
    }

    // ------------------------------------------------ бекап: восстановление (с 1.10.40)

    /**
     * «Восстановить из копии». Есть копии — список: последняя копия этого приложения, последняя в
     * «Загрузках/WarpScout» и «Выбрать файл…» (копия обычного приложения для беты, с прошлого телефона).
     * Нет — а после переустановки их нет всегда — сразу открываем выбор файла, а не пишем «Бекапов пока
     * нет» и всё.
     */
    private fun restoreFromBackup() {
        val inApp = Backup.newest(this)
        val inDownloads = Backup.downloads(this).firstOrNull()?.takeIf { it.name != inApp?.name }
        if (inApp == null && inDownloads == null) {
            toast(getString(R.string.backup_none))
            openBackupPicker()
            return
        }
        // Что можно восстановить: последняя копия этого приложения, последняя из «Загрузок/WarpScout»
        // (если она другая) и любой файл. В бете своя копия появляется после первого же подключения —
        // раньше «Восстановить из копии» сразу предлагала её, и копию из обычного приложения легко было
        // не заметить за кнопкой «Выбрать файл…».
        val titles = ArrayList<String>()
        val actions = ArrayList<() -> Unit>()
        if (inApp != null) {
            val details = runCatching { Backup.describe(inApp.readText()) }.getOrNull() ?: inApp.name
            titles += getString(R.string.backup_choice_app, details)
            actions += {
                val text = inApp.readText()
                confirmRestore(inApp.name, text, pickOther = false) { Backup.restoreText(this, text) }
            }
        }
        if (inDownloads != null) {
            val date = java.text.SimpleDateFormat("dd.MM.yyyy HH:mm", java.util.Locale.getDefault()).format(java.util.Date(inDownloads.modifiedMs))
            titles += getString(R.string.backup_choice_downloads, Backup.FOLDER, date)
            actions += { loadBackupFile(inDownloads.uri, inDownloads.name) }
        }
        titles += getString(R.string.backup_choice_file, Backup.FOLDER)
        actions += { openBackupPicker() }
        androidx.appcompat.app.AlertDialog.Builder(this)
            .setTitle(R.string.backup_choice_title)
            .setItems(titles.toTypedArray()) { _, which ->
                runCatching { actions[which]() }.onFailure { t ->
                    TunnelDebug.error("бекап: " + SafeMode.describe(t))
                    banner(getString(R.string.banner_ui_error, SafeMode.describe(t)), error = true)
                }
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    /**
     * «Сохранить резервную копию» (с 1.10.43.1): копия — в приложении и в «Загрузках/WarpScout», откуда
     * её откроет «Восстановить из копии» → «Выбрать файл…» — и в бете, и после переустановки. До
     * 1.10.43.1 кнопка только открывала «Поделиться»: копия оказывалась там, куда её отправили, а в ней
     * были только основные настройки (24.11: «я загрузил, а там половины данных нет»).
     */
    private fun saveBackupForUser() {
        persistUi()
        val file = Backup.save(this, getString(R.string.backup_note_manual))
        if (file == null) {
            toast(getString(R.string.backup_failed))
            return
        }
        val where = Backup.saveToDownloads(this, file)
        if (where == null) {
            TunnelDebug.stage("бекап: в «Загрузки» не записался — предлагаю «Сохранить как»")
            exportBackupAs(file)
            return
        }
        TunnelDebug.stage("бекап: сохранён — $where, ${file.length() / 1024} КБ")
        showBackupSaved(file, where)
    }

    /** Окно «Сохранить как» (сразу в «Загрузках»); его нет — остаётся «Поделиться». */
    private fun exportBackupAs(file: File) {
        pendingBackupExport = file
        val intent = Intent(Intent.ACTION_CREATE_DOCUMENT).apply {
            addCategory(Intent.CATEGORY_OPENABLE)
            type = Backup.MIME
            putExtra(Intent.EXTRA_TITLE, file.name)
            putExtra(android.provider.DocumentsContract.EXTRA_INITIAL_URI, backupFolderUri())
        }
        if (runCatching { createBackupDoc.launch(intent) }.isFailure) {
            pendingBackupExport = null
            TunnelDebug.error("бекап: окно «Сохранить как» не открылось — отдаю через «Поделиться»")
            shareBackup(file)
        }
    }

    /** Записать копию в место, выбранное в окне «Сохранить как». В своём потоке: это может быть Диск. */
    private fun writeBackupTo(uri: Uri, file: File) {
        Thread {
            val written = runCatching {
                contentResolver.openOutputStream(uri)?.use { out -> file.inputStream().use { it.copyTo(out) } } != null
            }
            val where = displayName(uri) ?: file.name
            runOnUiThread {
                if (isFinishing || isDestroyed) return@runOnUiThread
                if (written.getOrDefault(false)) {
                    TunnelDebug.stage("бекап: сохранён через «Сохранить как» — $where")
                    runCatching { showBackupSaved(file, where) }
                } else {
                    val why = written.exceptionOrNull()?.let { SafeMode.describe(it) } ?: "файл не открылся"
                    TunnelDebug.error("бекап: «Сохранить как» — $why")
                    banner(getString(R.string.backup_export_fail, why), error = true)
                }
            }
        }.apply { isDaemon = true; name = "warpscout-backup-export" }.start()
    }

    /** «Копия сохранена»: где лежит, что внутри и как восстановить; отправить — по кнопке. */
    private fun showBackupSaved(file: File, where: String) {
        val inside = runCatching { Backup.contents(this, file.readText()) }.getOrNull().orEmpty()
        banner(getString(R.string.backup_saved_where, where))
        androidx.appcompat.app.AlertDialog.Builder(this)
            .setTitle(R.string.backup_saved_title)
            .setMessage(getString(R.string.backup_saved_message, where, inside, Backup.FOLDER))
            .setPositiveButton(android.R.string.ok, null)
            .setNeutralButton(R.string.backup_share) { _, _ -> shareBackup(file) }
            .show()
    }

    /** Отдать копию наружу: Диск, Telegram — что угодно. */
    private fun shareBackup(file: File) {
        runCatching {
            val uri = androidx.core.content.FileProvider.getUriForFile(this, "$packageName.fileprovider", file)
            val send = Intent(Intent.ACTION_SEND).apply {
                type = "text/plain"
                putExtra(Intent.EXTRA_STREAM, uri)
                addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            }
            startActivity(Intent.createChooser(send, getString(R.string.backup_share_title)))
        }.onFailure { toast(getString(R.string.share_failed)) }
    }

    /**
     * Папка копий для окон выбора: «Загрузки/WilyScout», если она уже есть, иначе «Загрузки/WarpScout»
     * (копии до 1.10.48), иначе просто «Загрузки».
     */
    private fun backupFolderUri(): Uri = android.provider.DocumentsContract.buildDocumentUri(
        "com.android.externalstorage.documents",
        Backup.pickerFolder()?.let { "primary:Download/$it" } ?: "primary:Download"
    )

    /**
     * Системное окно выбора файла — сразу в «Загрузках/WarpScout», куда копию кладёт «Сохранить
     * резервную копию» (с 1.10.43.1; папки ещё нет — в «Загрузках»). Через «Внутреннюю память», а не
     * через «Загрузки» окна: файл, записанный другим приложением (обычным WarpScout для беты), Samsung
     * оттуда не отдаёт (журнал 23.11, см. [offerOtherPicker]).
     */
    private fun openBackupPicker() {
        // Тип у .bak бывает любой (text/plain, application/octet-stream) — показываем все файлы.
        val open = Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
            addCategory(Intent.CATEGORY_OPENABLE)
            type = "*/*"
            putExtra(android.provider.DocumentsContract.EXTRA_INITIAL_URI, backupFolderUri())
        }
        // Прошивка без системного окна документов — тогда любое приложение, которое отдаёт файлы.
        val get = Intent(Intent.ACTION_GET_CONTENT).apply {
            addCategory(Intent.CATEGORY_OPENABLE)
            type = "*/*"
        }
        val opened = runCatching { pickBackup.launch(open) }.isSuccess ||
            runCatching { pickBackup.launch(get) }.isSuccess
        if (!opened) {
            TunnelDebug.error("бекап: окно выбора файла не открылось")
            banner(getString(R.string.backup_picker_fail), error = true)
        }
    }

    /**
     * Бекап из выбранного файла: не больше 4 МБ, текстом. Читаем в своём потоке: файл с Диска система
     * может сначала докачивать, и в потоке экрана это было бы зависание. Потом — на экране: проверяем,
     * что это наш файл (первая строка — заголовок бекапа), и показываем, когда и почему он записан;
     * применяем — только после «Восстановить».
     */
    private fun loadBackupFile(uri: Uri, knownName: String? = null) {
        Thread {
            val fileName = knownName ?: displayName(uri) ?: uri.lastPathSegment ?: "файл"
            val read = runCatching { readBackupBytes(uri) }
            runOnUiThread {
                if (isFinishing || isDestroyed) return@runOnUiThread
                read.onSuccess { bytes ->
                    runCatching { onBackupFileRead(fileName, bytes) }.onFailure { t ->
                        TunnelDebug.error("бекап: «$fileName» — " + SafeMode.describe(t))
                        banner(getString(R.string.banner_ui_error, SafeMode.describe(t)), error = true)
                    }
                }.onFailure { t ->
                    TunnelDebug.error("бекап: «$fileName» не прочитался — " + SafeMode.describe(t))
                    if (t is SecurityException) {
                        runCatching { offerOtherPicker(fileName) }
                            .onFailure { banner(getString(R.string.backup_file_fail, SafeMode.describe(t)), error = true) }
                    } else {
                        banner(getString(R.string.backup_file_fail, SafeMode.describe(t)), error = true)
                    }
                }
            }
        }.apply { isDaemon = true; name = "warpscout-backup-read" }.start()
    }

    /** Байты файла, не больше [BACKUP_FILE_LIMIT] + 1 (лишний байт — признак «файл больше»). */
    private fun readBackupBytes(uri: Uri): ByteArray =
        contentResolver.openInputStream(uri)?.use { input ->
            val out = java.io.ByteArrayOutputStream()
            val buf = ByteArray(8192)
            while (out.size() <= BACKUP_FILE_LIMIT) {
                val n = input.read(buf)
                if (n < 0) break
                out.write(buf, 0, n)
            }
            out.toByteArray()
        } ?: throw java.io.IOException("файл не открылся")

    private fun onBackupFileRead(fileName: String, bytes: ByteArray) {
        if (bytes.size > BACKUP_FILE_LIMIT) {
            banner(getString(R.string.backup_file_big), error = true)
            return
        }
        val text = String(bytes, Charsets.UTF_8)
        if (!Backup.isBackup(text)) {
            TunnelDebug.stage("бекап: «$fileName» — не бекап WilyScout")
            banner(getString(R.string.backup_file_bad, fileName), error = true)
            return
        }
        val details = Backup.describe(text)
        TunnelDebug.stage("бекап: выбран файл «$fileName»" + (details?.let { " ($it)" } ?: ""))
        confirmRestore(fileName, text, pickOther = false) { Backup.restoreText(this, text) }
    }

    /**
     * Samsung не дал прочитать выбранный файл (журнал 23.11, 19:31 и 19:32: «SecurityException:
     * com.samsung.android.providers.media has no access to content://media/…»). Так бывает с файлами,
     * открытыми через «Загрузки» или «Недавние»: окно отдаёт ссылку медиатеки, а она файл не читает.
     * Тот же файл через «Мои файлы» или «Внутреннюю память» открывается — в журнале с третьей попытки.
     */
    private fun offerOtherPicker(fileName: String) {
        val dialog = androidx.appcompat.app.AlertDialog.Builder(this)
            .setTitle(R.string.backup_denied_title)
            .setMessage(getString(R.string.backup_denied_message, fileName))
            .setNegativeButton(android.R.string.cancel, null)
            .setNeutralButton(R.string.backup_pick_again) { _, _ -> runCatching { openBackupPicker() } }
        if (Build.MANUFACTURER.equals("samsung", ignoreCase = true)) {
            // «Мои файлы» отдаёт файл через свой провайдер, без медиатеки. Проверять заранее, есть ли
            // оно, нельзя без запроса списка приложений, — пробуем открыть, не вышло — обычное окно.
            dialog.setPositiveButton(R.string.backup_pick_myfiles) { _, _ ->
                val myFiles = Intent(Intent.ACTION_GET_CONTENT).apply {
                    addCategory(Intent.CATEGORY_OPENABLE)
                    type = "*/*"
                    setPackage("com.sec.android.app.myfiles")
                }
                runCatching { pickBackup.launch(myFiles) }.onFailure { runCatching { openBackupPicker() } }
            }
        }
        dialog.show()
    }

    /** Имя выбранного файла, как его показывает система. */
    private fun displayName(uri: Uri): String? = runCatching {
        contentResolver.query(uri, arrayOf(android.provider.OpenableColumns.DISPLAY_NAME), null, null, null)?.use { c ->
            if (c.moveToFirst()) c.getString(0) else null
        }
    }.getOrNull()

    /**
     * Вопрос «Восстановить настройки?»: имя файла, когда и почему он записан и что внутри (точки,
     * второй выход, приложения — с 1.10.43.1). [pickOther] — кнопка «Выбрать файл…».
     */
    private fun confirmRestore(name: String, text: String, pickOther: Boolean, doRestore: () -> Backup.Result?) {
        val details = runCatching { Backup.describe(text) }.getOrNull()
        val inside = runCatching { Backup.contents(this, text) }.getOrNull()
        val label = "«$name»" + (details?.let { " ($it)" } ?: "")
        val message = getString(R.string.backup_restore_message, label) + (inside?.let { "\n\n$it" } ?: "")
        val dialog = androidx.appcompat.app.AlertDialog.Builder(this)
            .setTitle(R.string.backup_restore_title)
            .setMessage(message)
            .setPositiveButton(R.string.backup_restore_ok) { _, _ ->
                runCatching { applyRestore(name, doRestore) }.onFailure { t ->
                    TunnelDebug.error("бекап: восстановление — " + SafeMode.describe(t))
                    banner(getString(R.string.banner_ui_error, SafeMode.describe(t)), error = true)
                }
            }
            .setNegativeButton(android.R.string.cancel, null)
        if (pickOther) {
            dialog.setNeutralButton(R.string.backup_pick) { _, _ -> runCatching { openBackupPicker() } }
        }
        dialog.show()
    }

    private fun applyRestore(name: String, doRestore: () -> Backup.Result?) {
        val result = doRestore()
        if (result == null) {
            TunnelDebug.error("бекап: «$name» не восстановился")
            banner(getString(R.string.backup_restore_failed, name), error = true)
            return
        }
        val old = result.format < 2
        TunnelDebug.stage(
            "бекап: восстановлено из «$name» — ${result.text()}" +
                if (old) " (копия старого формата: только основные настройки)" else ""
        )
        banner(
            getString(if (old) R.string.backup_restored_old else R.string.backup_restored, name, result.text()),
            error = old
        )
        suppressSettingsReconnect = true
        runCatching { fillFromPrefs() }
        suppressSettingsReconnect = false
        // Галочки шума и «Что проверять» — тоже из восстановленных настроек. Раньше они оставались
        // прежними, и следующее сохранение экрана (persistUi) записывало старые отметки обратно.
        runCatching { buildJunkChecks() }
        runCatching { buildResourceList() }
        runCatching { buildListsChecks() }
        runCatching { rebuildAppsList() }
        runCatching { refreshRoutesState() }
        runCatching { updateEndpointNote() }
        // Тройки точек, резервная точка и ключи — из восстановленных файлов (с 1.10.43.1).
        runCatching { renderShortlist() }
        runCatching { showKeys() }
        runCatching { renderAppAuto() }
        runCatching { updateTunnelSummary() }
        runCatching { updateSimple() }
    }

    // ------------------------------------------------ начальные экраны (бета, с 1.10.44-beta6)

    /** Начальные экраны, пока открыты. */
    private var welcome: WelcomeScreens? = null

    /** «Настроить» второй выход из начальных экранов ждёт подключения до этого времени (0 — не ждёт). */
    private var secondSetupUntil = 0L

    /** С какого тика опроса туннель работает, пока ждём (0 — ещё не работает). */
    private var secondSetupUpSince = 0L

    /** Файл второго выхода выбран из начальных экранов: применить сразу, без «Сохранить и применить». */
    private var secondConfApplyNow = false

    /**
     * Начальные экраны (просьба 25.11) — после новой установки, один раз (Prefs.welcomePending): какие
     * приложения пускать через туннель и второй выход. С 1.10.44 (в бете — с 1.10.44-beta6). Экран
     * создан заново (поворот) — продолжаем с той же страницы и с теми же отметками.
     */
    private fun maybeShowWelcome(saved: Bundle?) {
        if (!prefs.welcomePending) return
        if (welcome?.isShowing == true) return
        val page = saved?.getInt(STATE_WELCOME_PAGE, WelcomeScreens.PAGE_APPS) ?: WelcomeScreens.PAGE_APPS
        val checked = saved?.getStringArrayList(STATE_WELCOME_CHECKED)
        TunnelDebug.stage(
            if (saved == null) "начальные экраны: новая установка — показываю"
            else "начальные экраны: экран создан заново — продолжаю (страница ${page + 1})"
        )
        welcome = WelcomeScreens(this, welcomeHost).also { it.show(page, checked) }
    }

    private val welcomeHost = object : WelcomeScreens.Host {
        override fun knownApps(): List<WelcomeScreens.App> =
            appEntries.map { WelcomeScreens.App(it.pkg, it.label, it.system) }

        override fun readApps(): List<WelcomeScreens.App> =
            loadAppsSync().map { WelcomeScreens.App(it.pkg, it.label, it.system) }

        override fun preset(apps: List<WelcomeScreens.App>): Set<String> = welcomePreset(apps)

        // Как в шторке «Туннелирование»: спутник (с Gemini пойдёт приложение Google) и что у приложения
        // второй выход по умолчанию.
        override fun rowNote(pkg: String): String {
            val joined = runCatching {
                dev.warpscout.core.lists.AppServices.serviceOf(pkg)?.companions.orEmpty()
                    .filter { it.pkg != pkg }.joinToString(", ") { it.title }
            }.getOrDefault("")
            val line = if (joined.isEmpty()) pkg else getString(R.string.apps_row_companion, pkg, joined)
            return if (SecondDefaults.wants(pkg)) getString(R.string.welcome_row_second, line) else line
        }

        override fun saveApps(installed: List<String>, preset: Set<String>, checked: Set<String>) =
            saveWelcomeApps(installed, preset, checked)

        override fun finished(how: String) {
            welcome = null
            prefs.welcomePending = false
            TunnelDebug.stage("начальные экраны: пройдены — $how")
        }

        override fun setupSecond() = beginSecondSetup()

        override fun pickSecondFile() {
            secondConfApplyNow = true
            openSecondConfPicker()
        }
    }

    /**
     * Что отмечено на первой странице сразу (WelcomeApps.preset): набор по умолчанию (DefaultApps),
     * «второй выход по умолчанию» (SecondDefaults) и то, что уже отмечено, кроме снятого руками.
     */
    private fun welcomePreset(apps: List<WelcomeScreens.App>): Set<String> {
        val defaults = runCatching {
            DefaultApps.find(apps.map { Triple(it.pkg, it.label, it.system) }, packageName).keys
        }.getOrDefault(emptySet())
        val second = apps.map { it.pkg }.filter { SecondDefaults.wants(it) }
        return WelcomeApps.preset(
            installed = apps.map { it.pkg },
            defaults = defaults,
            second = second,
            appsMode = prefs.appsMode,
            selected = prefs.appsSelected,
            unticked = prefs.appsUnticked,
        )
    }

    /**
     * «Сохранить» на первой странице: «только выбранные» ровно с отмеченными. Снятое из отмеченных сразу —
     * «сняли руками»: ни набор по умолчанию, ни второй выход по умолчанию его обратно не отметят.
     * Записывается так же, как из шторки «Туннелирование»: настройки, вкладка расширенного вида, применение.
     */
    private fun saveWelcomeApps(installed: List<String>, preset: Set<String>, checked: Set<String>) {
        val start = TunnelChoice(
            appsMode = prefs.appsMode,
            apps = prefs.appsSelected,
            routes = prefs.routesMode,
            sites = prefs.tunnelSites,
            block = prefs.allowBlockIds,
            exits = prefs.appExits,
        )
        // Выбор сделан здесь: набор по умолчанию «только выбранные» больше сам не включает.
        prefs.appsDefaultsDone = true
        val unticked = WelcomeApps.untickedOnSave(preset, checked)
        prefs.appsUnticked = prefs.appsUnticked - checked + unticked
        val now = start.copy(
            appsMode = Prefs.APPS_ONLY,
            apps = WelcomeApps.selectedAfterSave(installed, checked, start.appsMode, start.apps),
        )
        fun names(pkgs: Collection<String>) = pkgs.map { labelOfPackage(it) }.sortedBy { it.lowercase() }.joinToString(", ")
        TunnelDebug.stage(
            "начальные экраны: приложения — «Сохранить», только выбранные (${checked.size}): " +
                names(checked).take(400) + (if (unticked.isEmpty()) "" else "; сняты: " + names(unticked).take(200))
        )
        if (now == start) return
        saveTunnelSheet(now, start)
    }

    /**
     * «Настроить» второй выход из начальных экранов и «Включить туннель» в окне Proton-кнопки (с 1.10.45,
     * см. [askTunnelForProton]). Proton из России без туннеля не открывается
     * (proton_connect_tunnel_hint): туннель работает — сразу выбор способа; нет — включаем его, как
     * большой кнопкой (после новой установки — с подбором точки), и открываем выбор, как только он
     * заработает ([continueSecondSetup]). Ждём не дольше 15 минут; «Выключить» и «Отменить» — не ждём.
     */
    private fun beginSecondSetup() {
        if (!tunnel.supported) {
            banner(getString(R.string.tunnel_unavailable), error = true)
            return
        }
        if (tunnel.isUp && !connecting && !engine.running) {
            TunnelDebug.stage("второй выход: туннель работает — открываю выбор Proton")
            openProtonConnect()
            return
        }
        secondSetupUntil = System.currentTimeMillis() + SECOND_SETUP_WAIT_MS
        secondSetupUpSince = 0L
        TunnelDebug.stage("второй выход: сначала туннель, потом выбор Proton")
        // Туннель уже поднимается (подбор, перебор точек, сервис ждёт повтора) — просто ждём.
        if (!connecting && !engine.running && !tunnel.active) toggleTunnel()
        banner(getString(R.string.welcome_second_wait))
    }

    /** Опрос туннеля: ждали подключения для «Настроить» — заработал и держится пару секунд — выбор Proton. */
    private fun continueSecondSetup(upNow: Boolean) {
        val now = System.currentTimeMillis()
        if (now > secondSetupUntil) {
            secondSetupUntil = 0L
            TunnelDebug.stage("второй выход: туннель за 15 минут не заработал — выбор Proton не открываю")
            return
        }
        if (!upNow || connecting || engine.running) {
            secondSetupUpSince = 0L
            return
        }
        if (secondSetupUpSince == 0L) {
            secondSetupUpSince = now
            return
        }
        if (now - secondSetupUpSince < 2_000L || !screenResumed || isFinishing) return
        secondSetupUntil = 0L
        TunnelDebug.stage("второй выход: туннель заработал — открываю выбор Proton")
        openProtonConnect()
    }

    private fun openProtonConnect() {
        runCatching { startProtonConnect() }.onFailure { t ->
            TunnelDebug.problem("второй выход: Proton кнопкой — " + SafeMode.describe(t))
            banner(getString(R.string.banner_ui_error, SafeMode.describe(t)), error = true)
        }
    }

    // ------------------------------------------------ приложения (упрощённый экран)

    private fun showAppsSheet() {
        runCatching { showAppsSheetUnsafe() }.onFailure { t ->
            TunnelDebug.error("выбор приложений: " + SafeMode.describe(t))
            banner(getString(R.string.banner_ui_error, SafeMode.describe(t)), error = true)
        }
    }

    /**
     * Шторка «Туннелирование» (с 1.10.31; была «Приложения»): сверху — приложения, сайты или
     * списки. Приложения: все / только выбранные / все, кроме выбранных, — список с иконками и
     * поиском. Сайты: свои домены, адреса и подсети. Списки: категории галочками. До «Сохранить»
     * ничего не меняется; сохранение собирает адреса и при включённом туннеле переподключает его —
     * список приложений и маршруты задаются при подъёме туннеля.
     */
    private fun showAppsSheetUnsafe() {
        val dialog = com.google.android.material.bottomsheet.BottomSheetDialog(this)
        val sheet = dev.warpscout.app.databinding.SheetAppsBinding.inflate(layoutInflater)
        val start = TunnelChoice(
            appsMode = prefs.appsMode,
            apps = prefs.appsSelected,
            routes = prefs.routesMode,
            sites = prefs.tunnelSites,
            block = prefs.allowBlockIds,
            exits = prefs.appExits,
        )
        var mode = start.appsMode
        val selected = start.apps.toMutableSet()
        // Выход приложений (с 1.10.39): кнопка в строке, когда есть второй выход и Android 10+.
        val exits = start.exits.toMutableMap()
        val exitsOn = runCatching { appExitsAvailable() }.getOrDefault(false)
        // Выбор выхода в строке; задаётся ниже, когда готов список (строки ссылаются на него раньше).
        var pickExit: (String, Int) -> Unit = { _, _ -> }
        var apps: List<AppEntry> = appEntries
        val icons = HashMap<String, android.graphics.drawable.Drawable?>()
        var visibleApps: List<AppEntry> = emptyList()

        fun visibleList(): List<AppEntry> {
            val q = sheet.appsSearch.text?.toString()?.trim()?.lowercase().orEmpty()
            // Отмеченные — наверху: их ищут, чтобы снять, и они не должны теряться в сотне строк. В
            // «Все приложения» отметок нет — наверху те, у кого свой выход (с 1.10.39).
            return apps.filter { app ->
                q.isEmpty() || app.label.lowercase().contains(q) || app.pkg.lowercase().contains(q)
            }.sortedWith(
                compareByDescending<AppEntry> {
                    if (mode == Prefs.APPS_ALL) it.pkg in exits else it.pkg in selected || it.pkg in exits
                }.thenBy { it.label.lowercase() }
            )
        }

        val adapter = object : android.widget.BaseAdapter() {
            override fun getCount(): Int = visibleApps.size
            override fun getItem(position: Int): Any = visibleApps[position]
            override fun getItemId(position: Int): Long = position.toLong()
            override fun getView(position: Int, convertView: View?, parent: android.view.ViewGroup): View {
                val row = if (convertView != null) {
                    dev.warpscout.app.databinding.ItemAppRowBinding.bind(convertView)
                } else {
                    dev.warpscout.app.databinding.ItemAppRowBinding.inflate(layoutInflater, parent, false)
                }
                val app = visibleApps[position]
                row.appLabel.text = app.label
                // Спутник (с 1.10.37): с Gemini в туннель идёт приложение Google — говорим об этом
                // прямо в строке, пока выбирают (только в режиме «только выбранные»).
                val joined = if (mode == Prefs.APPS_ONLY) {
                    dev.warpscout.core.lists.AppServices.serviceOf(app.pkg)?.companions.orEmpty()
                        .filter { it.pkg != app.pkg }.joinToString(", ") { it.title }
                } else {
                    ""
                }
                row.appPackage.text = if (joined.isEmpty()) app.pkg else getString(R.string.apps_row_companion, app.pkg, joined)
                row.appCheck.isChecked = app.pkg in selected
                // В «Все приложения» отмечать нечего — строка только для выхода (с 1.10.39).
                row.appCheck.visibility = if (mode == Prefs.APPS_ALL) View.GONE else View.VISIBLE
                val rule = exits[app.pkg] ?: AppExit.AUTO
                row.appExit.visibility = if (exitsOn) View.VISIBLE else View.GONE
                if (exitsOn) {
                    row.appExit.text = exitLabel(rule)
                    row.appExit.setOnClickListener { v ->
                        showExitMenu(v, app.pkg, exits[app.pkg] ?: AppExit.AUTO) { picked -> pickExit(app.pkg, picked) }
                    }
                    if (exitPartialFor(app.pkg, rule)) {
                        row.appPackage.text = getString(R.string.app_exit_row_partial, row.appPackage.text)
                    }
                } else {
                    row.appExit.setOnClickListener(null)
                }
                // Иконку читаем, только когда строка видна, и запоминаем: их сотни, а видно десяток.
                val icon = icons.getOrPut(app.pkg) {
                    runCatching { packageManager.getApplicationIcon(app.pkg) }.getOrNull()
                }
                row.appIcon.setImageDrawable(icon)
                return row.root
            }
        }

        fun countText(): String = when {
            apps.isEmpty() -> getString(R.string.sheet_apps_loading)
            mode == Prefs.APPS_ALL -> getString(R.string.sheet_apps_exits_count, exits.size)
            else -> getString(R.string.sheet_apps_count, selected.size) + otherProfileNote()
        }

        fun refresh() {
            // С 1.10.39 список нужен и в «Все приложения», когда есть второй выход: там выбирают выход.
            val needsList = mode != Prefs.APPS_ALL || exitsOn
            sheet.appsListBox.visibility = if (needsList) View.VISIBLE else View.GONE
            sheet.appsExitHint.visibility = if (exitsOn) View.VISIBLE else View.GONE
            visibleApps = if (needsList) visibleList() else emptyList()
            adapter.notifyDataSetChanged()
            sheet.appsCount.text = countText()
        }

        // Выбрали выход в строке: «Само» — убрать правило; «WARP» или «Второй выход» — приложение
        // идёт через туннель (отмечается само в «только выбранные», снимается из исключений).
        pickExit = { pkg, rule ->
            if (rule == AppExit.AUTO) {
                exits.remove(pkg)
            } else {
                exits[pkg] = rule
                when (mode) {
                    Prefs.APPS_ONLY -> selected.add(pkg)
                    Prefs.APPS_EXCEPT -> selected.remove(pkg)
                }
                warnExitPartial(pkg, rule)
            }
            sheet.appsCount.text = countText()
            adapter.notifyDataSetChanged()
        }

        sheet.appsList.adapter = adapter
        // Список прокручивается внутри шторки, а не тянет её вниз.
        runCatching { sheet.appsList.isNestedScrollingEnabled = true }
        sheet.appsList.setOnItemClickListener { _, view, position, _ ->
            val app = visibleApps.getOrNull(position) ?: return@setOnItemClickListener
            if (mode == Prefs.APPS_ALL) {
                // Отметок в этом режиме нет — строка открывает выбор выхода (с 1.10.39).
                if (exitsOn) {
                    val anchor = view.findViewById<View>(R.id.appExit) ?: view
                    showExitMenu(anchor, app.pkg, exits[app.pkg] ?: AppExit.AUTO) { picked -> pickExit(app.pkg, picked) }
                }
                return@setOnItemClickListener
            }
            if (!selected.add(app.pkg)) selected.remove(app.pkg)
            // Сняли с туннеля («только выбранные») или исключили («все, кроме») — выход снова «Само».
            val out = (mode == Prefs.APPS_ONLY && app.pkg !in selected) || (mode == Prefs.APPS_EXCEPT && app.pkg in selected)
            if (out) exits.remove(app.pkg)
            sheet.appsCount.text = countText()
            adapter.notifyDataSetChanged()
        }
        sheet.appsModeGroup.check(
            when (mode) {
                Prefs.APPS_ONLY -> R.id.appsModeOnly
                Prefs.APPS_EXCEPT -> R.id.appsModeExcept
                else -> R.id.appsModeAll
            }
        )
        sheet.appsModeGroup.setOnCheckedChangeListener { _, checkedId ->
            mode = when (checkedId) {
                R.id.appsModeOnly -> Prefs.APPS_ONLY
                R.id.appsModeExcept -> Prefs.APPS_EXCEPT
                else -> Prefs.APPS_ALL
            }
            // Со своим выходом — через туннель в любом режиме (с 1.10.39); сохранится по «Сохранить».
            if (exitsOn && exits.isNotEmpty() && mode != Prefs.APPS_ALL) {
                val aligned = alignWithExits(mode, selected, exits.keys)
                selected.clear()
                selected.addAll(aligned)
            }
            refresh()
        }
        sheet.appsSearch.doAfterTextChanged { refresh() }

        // Что настраиваем: приложения, сайты или списки. Открываем там, что сейчас действует.
        fun showKind(kind: Int) {
            sheet.sheetPanelApps.visibility = if (kind == KIND_APPS) View.VISIBLE else View.GONE
            sheet.sheetPanelSites.visibility = if (kind == KIND_SITES) View.VISIBLE else View.GONE
            sheet.sheetPanelLists.visibility = if (kind == KIND_LISTS) View.VISIBLE else View.GONE
        }
        val startKind = when (start.routes) {
            3 -> KIND_SITES
            2 -> KIND_LISTS
            else -> KIND_APPS
        }
        sheet.sheetKindGroup.check(
            when (startKind) {
                KIND_SITES -> R.id.sheetKindSites
                KIND_LISTS -> R.id.sheetKindLists
                else -> R.id.sheetKindApps
            }
        )
        showKind(startKind)
        sheet.sheetKindGroup.addOnButtonCheckedListener { _, checkedId, isChecked ->
            if (!isChecked) return@addOnButtonCheckedListener
            showKind(
                when (checkedId) {
                    R.id.sheetKindSites -> KIND_SITES
                    R.id.sheetKindLists -> KIND_LISTS
                    else -> KIND_APPS
                }
            )
        }

        // Сайты и списки — взаимоисключающие режимы маршрутов: включили одно — другое выключается.
        sheet.sheetSites.setText(start.sites)
        sheet.sheetSitesOn.isChecked = start.routes == 3
        sheet.sheetListsOn.isChecked = start.routes == 2
        sheet.sheetSitesOn.setOnCheckedChangeListener { _, on -> if (on) sheet.sheetListsOn.isChecked = false }
        sheet.sheetListsOn.setOnCheckedChangeListener { _, on -> if (on) sheet.sheetSitesOn.isChecked = false }
        // Вписали первый сайт — значит, хотят именно их: переключатель включается сам.
        var sitesWereBlank = start.sites.isBlank()
        sheet.sheetSites.doAfterTextChanged { text ->
            val blank = text?.toString().isNullOrBlank()
            if (sitesWereBlank && !blank) sheet.sheetSitesOn.isChecked = true
            sitesWereBlank = blank
        }
        val blockChecks = LinkedHashMap<String, MaterialCheckBox>()
        dev.warpscout.core.lists.AllowLists.bySide(dev.warpscout.core.lists.ListSide.BLOCK).forEach { list ->
            val cb = MaterialCheckBox(this).apply {
                text = list.title
                isChecked = list.id in start.block
            }
            cb.setOnClickListener { if (cb.isChecked) sheet.sheetListsOn.isChecked = true }
            blockChecks[list.id] = cb
            sheet.sheetListsBox.addView(cb)
        }
        runCatching { sheet.sheetListsScroll.isNestedScrollingEnabled = true }

        sheet.appsCancel.setOnClickListener { dialog.dismiss() }
        sheet.appsSave.setOnClickListener {
            val routes = when {
                sheet.sheetSitesOn.isChecked -> 3
                sheet.sheetListsOn.isChecked -> 2
                // Выключили «только сайты/списки» — снова все сайты; «кроме российских» не трогаем.
                start.routes == 2 || start.routes == 3 -> 0
                else -> start.routes
            }
            val now = TunnelChoice(
                appsMode = mode,
                apps = selected.toSet(),
                routes = routes,
                sites = sheet.sheetSites.text?.toString().orEmpty(),
                block = blockChecks.filter { it.value.isChecked }.keys.toSet(),
                exits = exits.toMap(),
            )
            dialog.dismiss()
            saveTunnelSheet(now, start)
        }
        refresh()
        // Список приложений мог ещё не прочитаться (его читаем в фоне при открытии экрана).
        if (apps.isEmpty()) {
            Thread({
                val loaded = loadAppsSync()
                runOnUiThread {
                    if (!::binding.isInitialized) return@runOnUiThread
                    appEntries = loaded
                    apps = loaded
                    runCatching { refresh() }
                }
            }, "warpscout-apps-sheet").apply { isDaemon = true }.start()
        }
        dialog.setContentView(sheet.root)
        // Шторка — сразу целиком (с 1.10.44-beta6). Раньше она открывалась «половинкой» (её высота зависит
        // от высоты экрана), а «Сохранить» и «Отмена» — в самом низу шторки: с тремя кнопками навигации
        // Android экран ниже, чем с жестами, и кнопки оставались за его краем. Не помещается шторка и
        // целиком — список становится короче (sheet_apps), кнопки всегда видны. Вниз шторка закрывается
        // сразу, без промежуточной «половинки».
        runCatching {
            dialog.behavior.skipCollapsed = true
            dialog.behavior.state = com.google.android.material.bottomsheet.BottomSheetBehavior.STATE_EXPANDED
        }.onFailure { t -> TunnelDebug.error("шторка «Туннелирование»: не раскрылась целиком — " + SafeMode.describe(t)) }
        dialog.setOnDismissListener { updateSimple() }
        dialog.show()
    }

    /** Выбор в шторке «Туннелирование»: приложения + режим маршрутов + свои сайты + списки + выход приложений. */
    private data class TunnelChoice(
        val appsMode: Int,
        val apps: Set<String>,
        val routes: Int,
        val sites: String,
        val block: Set<String>,
        /** Выход приложений (с 1.10.39): пакет → «Всегда WARP» или «Второй выход». */
        val exits: Map<String, Int> = emptyMap(),
    )

    /**
     * «Сохранить» в шторке: записать выбор, показать то же на вкладке «Туннелирование» и применить —
     * адреса сайтов соберутся сами, при включённом туннеле он переподключится.
     */
    private fun saveTunnelSheet(now: TunnelChoice, start: TunnelChoice) {
        if (now == start) {
            banner(getString(R.string.apps_unchanged))
            return
        }
        prefs.appsMode = now.appsMode
        // Только то, что изменили в шторке: пока она была открыта, набор по умолчанию мог отметить
        // новое приложение — его не теряем. Снятые руками приложения из набора больше не отмечаем.
        val removed = start.apps - now.apps
        val added = now.apps - start.apps
        prefs.appsSelected = (prefs.appsSelected - removed) + added
        removed.forEach { noteAppTick(it, checked = false) }
        added.forEach { noteAppTick(it, checked = true) }
        prefs.tunnelSites = now.sites
        if (now.block != start.block) prefs.allowBlockIds = now.block
        prefs.routesMode = now.routes
        // Выход приложений — тоже только изменённое (с 1.10.44-beta4): пока шторка была открыта, бета
        // могла поставить «Второй выход» по умолчанию (SecondDefaults) — его не теряем.
        if (now.exits != start.exits) {
            val merged = prefs.appExits.toMutableMap()
            (start.exits.keys - now.exits.keys).forEach { merged.remove(it) }
            now.exits.forEach { (pkg, rule) -> if (start.exits[pkg] != rule) merged[pkg] = rule }
            prefs.appExits = merged
        }
        TunnelDebug.stage(
            "туннелирование (упрощённый экран): " + when (now.appsMode) {
                Prefs.APPS_ONLY -> "только выбранные приложения (${now.apps.size})"
                Prefs.APPS_EXCEPT -> "все приложения, кроме ${now.apps.size}"
                else -> "все приложения"
            } + " · " + prefs.routesModeName() +
                (if (now.exits.isNotEmpty()) " · выход по выбору: " + exitsSummary(now.exits) else "")
        )
        // Вкладка «Туннелирование» расширенного вида должна показывать то же самое: «Сохранить и
        // применить» записывает настройки с экрана, и старый вид затёр бы выбор из шторки. Её
        // слушатели на выставление кодом не реагируют (иначе была бы плашка «изменено»).
        runCatching {
            suppressSettingsReconnect = true
            binding.appsGroup.check(appsButtonId(now.appsMode))
            rebuildAppsList()
            updateAppsState()
            binding.editTunnelSites.setText(now.sites)
            binding.spinnerRoutes.setSelection(now.routes)
            buildListsChecks()
            binding.tunnelKindGroup.check(
                when (now.routes) {
                    3 -> R.id.btnKindSites
                    2 -> R.id.btnKindLists
                    else -> R.id.btnKindApps
                }
            )
            refreshRoutesState()
            updateSitesState()
            updateTunnelSummary()
        }.onFailure { t -> TunnelDebug.error("туннелирование: вкладка не обновилась — " + SafeMode.describe(t)) }
        suppressSettingsReconnect = false
        applyWithRoutes(
            "туннелирование",
            upText = getString(R.string.tunneling_saved_reconnect),
            downText = getString(R.string.tunneling_saved),
        )
        updateSimple()
    }

    /**
     * Карточка «Туннелирование» упрощённого экрана: крупно — какие приложения, мелко — какие сайты.
     * Нажатие открывает шторку с теми же тремя разделами.
     */
    private fun renderTunnelCard() {
        val s = binding.simple
        val selected = prefs.appsSelected.size
        val value = when {
            prefs.appsMode == Prefs.APPS_ONLY && selected > 0 -> getString(R.string.simple_tun_apps_only, selected)
            prefs.appsMode == Prefs.APPS_EXCEPT && selected > 0 -> getString(R.string.simple_tun_apps_except, selected)
            else -> getString(R.string.simple_tun_apps_all)
        }
        val sitesCount = SiteList.parse(prefs.tunnelSites).total
        val browserSites = runCatching { prefs.browserSitesActive() }.getOrDefault(false)
        val sites = if (browserSites) getString(R.string.simple_tun_sites_browser) else when (prefs.routesMode) {
            1 -> getString(R.string.simple_tun_sites_preset)
            2 -> getString(R.string.simple_tun_sites_lists)
            3 -> if (sitesCount > 0) getString(R.string.simple_tun_sites_mine, sitesCount)
            else getString(R.string.simple_tun_sites_all)
            else -> getString(R.string.simple_tun_sites_all)
        }
        val sub = sites + exitsCardNote()
        if (s.simpleTunnelValue.text.toString() != value) s.simpleTunnelValue.text = value
        if (s.simpleTunnelSub.text.toString() != sub) s.simpleTunnelSub.text = sub
    }

    // ------------------------------------------------ сброс по умолчанию (с 1.10.32)

    /** Идёт сброс: onPause не должен записать поля экрана обратно в очищенные настройки. */
    private var resetInProgress = false

    /** «Сбросить всё по умолчанию» — только после подтверждения: стирается и найденное подбором. */
    private fun confirmResetAll() {
        if (resetBusy()) return
        android.app.AlertDialog.Builder(this)
            .setTitle(R.string.reset_title)
            .setMessage(R.string.reset_message)
            .setPositiveButton(R.string.reset_ok) { _, _ ->
                runCatching { resetAll() }.onFailure { t ->
                    resetInProgress = false
                    TunnelDebug.error("сброс: " + SafeMode.describe(t))
                    banner(getString(R.string.banner_ui_error, SafeMode.describe(t)), error = true)
                }
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    /** Подбор, подключение или сборка идут — сбрасывать посреди них нельзя: говорим и не сбрасываем. */
    private fun resetBusy(): Boolean {
        val busy = engine.running || connecting || preparingRoutes || secondBusy
        if (busy) {
            banner(getString(R.string.reset_busy), error = true)
            toast(getString(R.string.reset_busy))
        }
        return busy
    }

    /**
     * Всё как после установки (так решил человек, 22.11): настройки — по умолчанию, свои списки
     * стёрты, найденные точки, очередь и резервные забыты, конфиг второго выхода удалён, туннель
     * выключен (как выключенный рукой — сам не включится). Остаются журнал и бекапы (перед сбросом
     * пишется свежий — «Восстановить» вернёт настройки), запасной ключ WARP (каждый подбор всё равно
     * берёт свежий, а без запасного при недоступном генераторе не подключиться вовсе) и скачанные
     * списки сайтов и серверов Proton (это кеш, а не настройки). Потом экран создаётся заново —
     * ровно как первый запуск: кнопка «Найти и подключить» подберёт точки.
     */
    private fun resetAll() {
        if (resetInProgress || resetBusy()) return
        resetInProgress = true
        TunnelDebug.stage("сброс по умолчанию: начинаю — всё как после установки")
        val backup = runCatching { Backup.save(this, getString(R.string.backup_note_reset)) }.getOrNull()
        val wasUp = tunnel.supported && (tunnel.isUp || tunnel.active)
        // Выключает человек: сервис запомнит это, и ни сеть, ни перезагрузка туннель не включат.
        if (wasUp) runCatching { tunnel.stopByUser() }
        binding.btnResetAll.isEnabled = false
        banner(getString(R.string.reset_running))
        val app = applicationContext
        Thread {
            if (wasUp) runCatching { tunnel.waitStopped(5000) }
            val errors = mutableListOf<String>()
            fun step(name: String, block: () -> Unit) {
                runCatching(block).onFailure { errors += "$name: ${it.message ?: it.javaClass.simpleName}" }
            }
            step("фоновый подбор") { Schedule.disable(app) }
            step("настройки") { prefs.clearAll() }
            step("обновления") { app.getSharedPreferences("warpscout_update", MODE_PRIVATE).edit().clear().commit() }
            step("точки") {
                ConfigShortlist.forget(app)
                TuningCache.forget(app)
                EndpointMemory.forgetAll(app)
                NoiseMemory.forgetAll(app)
                // Площадки выхода точек и отметки «искали выход за рубежом» (с 1.10.34).
                SiteMemory.forgetAll(app)
                // Ответы «Переключить» / «Оставить» про Telegram по сетям (с 1.10.36).
                TelegramChoiceMemory.forgetAll(app)
            }
            step("доступность") { Availability.forgetAll(app) }
            // Конфиг, которым плитка и автозапуск поднимают туннель (TunnelLastConfig сборки tunnel).
            step("конфиг туннеля") { File(app.filesDir, "tunnel-last.conf").delete() }
            step("файлы конфигов") {
                listOf("configs", "reports").forEach { dir -> File(app.filesDir, dir).listFiles()?.forEach { it.delete() } }
            }
            step("итог подбора") { engine.forgetResults() }
            // Снимок для сервиса — уже из пустых настроек (с переносами первого запуска).
            step("сервис") { ServiceSettingsStore.syncFromPrefs(app) }
            runOnUiThread {
                TunnelDebug.stage(
                    "сброс по умолчанию: готово" + (backup?.let { ", бекап ${it.name}" } ?: ", бекап не записан") +
                        (if (errors.isEmpty()) "" else " — не получилось: " + errors.joinToString("; "))
                )
                afterResetNote = getString(if (errors.isEmpty()) R.string.reset_done else R.string.reset_partly, errors.joinToString("; ").take(120))
                // Журнал подбора живёт в памяти процесса (переживает экран) — после сброса он пустой.
                runCatching { scanLog.setLength(0) }
                // Экран — заново, с настройками по умолчанию (как первый запуск после установки).
                runCatching { recreate() }.onFailure { t ->
                    resetInProgress = false
                    TunnelDebug.error("сброс: экран не пересоздался — " + SafeMode.describe(t))
                }
            }
        }.apply { isDaemon = true; name = "warpscout-reset" }.start()
    }

    // ------------------------------------------------ обновления (с 1.10.31)

    /**
     * «Проверить обновления»: последний релиз на GitHub. Есть новее (или свежая пересборка той же
     * версии) — спрашиваем, скачать ли; нет — так и говорим. Только по нажатию.
     *
     * С 1.10.40 нажатие во время проверки или загрузки говорит, что именно идёт — проверка, проценты,
     * «системная загрузка ждёт сеть» (см. UpdateFlow), — а не «Обновление уже скачивается» на всё: в
     * 1.10.38–1.10.39 так и висело, хотя ничего не происходило.
     */
    private fun checkForUpdate() {
        UpdateFlow.busyText(this)?.let { text ->
            updateNote(text)
            return
        }
        if (!UpdateFlow.beginCheck()) return
        updateNote(getString(R.string.update_checking))
        Thread {
            val result = runCatching {
                Updater.check(BuildConfig.VERSION_NAME, BuildConfig.BUILD_REV)
            }
            runOnUiThread {
                UpdateFlow.endCheck()
                if (isFinishing || isDestroyed) return@runOnUiThread
                runCatching {
                    result.onSuccess { r ->
                        when (r) {
                            is Updater.Check.Latest -> updateNote(getString(R.string.update_latest, r.version))
                            is Updater.Check.NoAsset ->
                                updateNote(getString(R.string.update_no_asset, r.tag, r.want), error = true)
                            is Updater.Check.Newer -> offerUpdate(
                                r.release,
                                getString(R.string.update_available_title, r.release.version),
                                getString(R.string.update_available_msg, BuildConfig.VERSION_NAME, sizeText(r.release.size))
                            )
                            is Updater.Check.Rebuild -> offerUpdate(
                                r.release,
                                getString(R.string.update_rebuild_title, r.release.version),
                                getString(R.string.update_rebuild_msg, BuildConfig.BUILD_REV, r.remoteRev, sizeText(r.release.size)),
                                rev = r.remoteRev
                            )
                        }
                    }.onFailure { t ->
                        TunnelDebug.stage("обновления: проверка не прошла — ${t.message ?: t.javaClass.simpleName}")
                        updateNote(getString(R.string.update_check_failed, t.message ?: t.javaClass.simpleName), error = true)
                    }
                }.onFailure { t -> TunnelDebug.error("обновления: " + SafeMode.describe(t)) }
            }
        }.apply { isDaemon = true; name = "warpscout-update-check" }.start()
    }

    /**
     * Итог проверки обновлений: плашкой и всплывающей строкой. Кнопка «Обновления» в расширенном
     * виде — в самом низу «Главной», а плашка — наверху: без всплывающей строки ответа на нажатие
     * не было бы видно.
     */
    private fun updateNote(text: String, error: Boolean = false) {
        banner(text, error)
        if (!simpleShown()) runCatching { Toast.makeText(this, text, Toast.LENGTH_SHORT).show() }
    }

    private fun sizeText(bytes: Long): String =
        if (bytes <= 0L) "APK" else String.format(java.util.Locale.US, "%.1f МБ", bytes / 1_048_576.0)

    /** Размеры совпадают; 0 — неизвестен (запасной путь без API, записи до 1.10.40) — тогда не сравниваем. */
    private fun sameSize(a: Long, b: Long): Boolean = a <= 0L || b <= 0L || a == b

    /**
     * [rev] — коммит свежей сборки той же версии (тег перенесён на доправку). Имя файла у неё прежнее, и
     * по одному имени скачанный раньше файл — это та сборка, что уже стоит: такой файл не предлагаем, а
     * качаем заново. Запомненная загрузка подходит, только если скачана для этого же коммита.
     */
    private fun offerUpdate(release: Updater.Release, title: String, message: String, rev: String? = null) {
        // Этот же файл WarpScout уже скачал сам (с 1.10.40) и он лежит в «Загрузках» — второй раз не качаем.
        directReadyName(release, rev)?.let { name ->
            TunnelDebug.stage("обновления: $name уже в «Загрузках» — ставится нажатием на файл")
            showUpdateReady(release, name)
            return
        }
        // Системная загрузка этого файла: скачана — показываем; идёт или стоит — следим за ней (встанет —
        // UpdateFlow скачает сам). До 1.10.40 здесь отвечало «Обновление уже скачивается» — и так на
        // каждое нажатие, пока загрузка ждала сеть или очередь (жалоба на 1.10.38).
        val sp = updatePrefs()
        val known = sp.getLong("dlId", -1L).takeIf {
            it >= 0L && sp.getString("dlName", null) == release.apkName && sameSize(sp.getLong("dlSize", 0L), release.size) &&
                (rev == null || sp.getString("dlRev", null) == rev)
        }
        val state = known?.let { id -> runCatching { Updater.query(this, id) }.getOrNull() }
        if (known != null && state?.status == android.app.DownloadManager.STATUS_SUCCESSFUL && Updater.fileExists(this, known)) {
            val name = state.name.ifBlank { release.apkName }
            TunnelDebug.stage("обновления: $name уже в «Загрузках» — ставится нажатием на файл")
            showUpdateReady(release, name)
            return
        }
        if (known != null && state != null && Build.VERSION.SDK_INT >= 29 &&
            state.status != android.app.DownloadManager.STATUS_SUCCESSFUL &&
            state.status != android.app.DownloadManager.STATUS_FAILED
        ) {
            if (!UpdateFlow.watch(this, known, release, rev)) UpdateFlow.busyText(this)?.let { updateNote(it) }
            return
        }
        android.app.AlertDialog.Builder(this)
            .setTitle(title)
            .setMessage(message)
            .setPositiveButton(R.string.update_download) { _, _ -> downloadUpdate(release, rev) }
            .setNegativeButton(R.string.update_later, null)
            .show()
    }

    /** Свой скачанный файл этой версии ещё лежит в «Загрузках» (с 1.10.40): его имя, иначе null. */
    private fun directReadyName(release: Updater.Release, rev: String?): String? = runCatching {
        val sp = updatePrefs()
        if (sp.getString("directFor", null) != release.apkName) return@runCatching null
        if (rev != null && sp.getString("directRev", null) != rev) return@runCatching null
        val size = sp.getLong("directSize", -1L)
        if (size <= 0L || !sameSize(size, release.size)) return@runCatching null
        val uri = Uri.parse(sp.getString("directUri", null) ?: return@runCatching null)
        if (Updater.storedSize(this, uri) != size) return@runCatching null
        sp.getString("directName", null)?.ifBlank { null } ?: release.apkName
    }.getOrNull()

    /**
     * Скачать: системной загрузкой (с 1.10.32) — в «Загрузки», с уведомлением «Загрузка завершена»; а
     * встанет — самим WarpScout, тоже в «Загрузки» (с 1.10.40, см. UpdateFlow). Ставит файл человек
     * нажатием — своего разрешения на установку у WarpScout нет (см. Updater). На Android 8–9
     * «Загрузкам» нужно разрешение на запись в память, которого у нас нет, — там качает браузер.
     */
    private fun downloadUpdate(release: Updater.Release, rev: String? = null) {
        UpdateFlow.busyText(this)?.let { text ->
            updateNote(text)
            return
        }
        if (Build.VERSION.SDK_INT < 29) {
            openUpdateInBrowser(release)
            return
        }
        if (!UpdateFlow.start(this, release, rev)) UpdateFlow.busyText(this)?.let { updateNote(it) }
    }

    private fun openUpdateInBrowser(release: Updater.Release) {
        runCatching { startActivity(Updater.browserIntent(release)) }
            .onSuccess { updateNote(getString(R.string.update_via_browser, release.apkName)) }
            .onFailure { t -> updateNote(getString(R.string.update_failed, t.message ?: t.javaClass.simpleName), error = true) }
    }

    // Что говорит загрузка обновления (UpdateFlow.Ui, с 1.10.40): она живёт дольше экрана и говорит тому,
    // что сейчас открыт.

    override fun onUpdateProgress(text: String) {
        if (uiReady()) banner(text)
    }

    override fun onUpdateNote(text: String, error: Boolean) {
        if (uiReady()) updateNote(text, error)
    }

    override fun onUpdateReady(release: Updater.Release, fileName: String) {
        if (uiReady() && !isFinishing && !isDestroyed) showUpdateReady(release, fileName)
    }

    override fun onUpdateFailed(release: Updater.Release, reason: String) {
        if (uiReady() && !isFinishing && !isDestroyed) showUpdateFailed(release, reason)
    }

    /** Скачано (и сверено): остаётся нажать на файл в «Загрузках» — Android спросит, поставить ли поверх. */
    private fun showUpdateReady(release: Updater.Release, fileName: String) {
        banner(getString(R.string.update_ready_banner, fileName))
        android.app.AlertDialog.Builder(this)
            .setTitle(getString(R.string.update_ready_title, release.version))
            .setMessage(getString(R.string.update_ready_msg, fileName))
            .setPositiveButton(R.string.update_open_downloads) { _, _ ->
                runCatching { startActivity(Updater.downloadsIntent()) }
                    .onFailure { updateNote(getString(R.string.update_open_failed, fileName), error = true) }
            }
            .setNegativeButton(R.string.update_later, null)
            .show()
    }

    /**
     * Не скачалось ни системной загрузкой, ни самим WarpScout (с 1.10.40): причина словами, подсказка,
     * если приложение сейчас ходит в сеть мимо туннеля, и «Скачать браузером» — по прямой ссылке релиза.
     */
    private fun showUpdateFailed(release: Updater.Release, reason: String) {
        banner(getString(R.string.update_failed, reason), error = true)
        val parts = ArrayList<String>()
        parts += reason.replaceFirstChar { it.uppercase() } + "."
        if (!Updater.defaultIsVpn(this)) parts += getString(R.string.update_failed_no_tunnel)
        parts += getString(R.string.update_failed_browser, release.apkName)
        android.app.AlertDialog.Builder(this)
            .setTitle(R.string.update_failed_title)
            .setMessage(parts.joinToString("\n\n"))
            .setPositiveButton(R.string.update_open_browser) { _, _ -> openUpdateInBrowser(release) }
            .setNegativeButton(R.string.update_later, null)
            .show()
    }

    private fun updatePrefs() = getSharedPreferences("warpscout_update", MODE_PRIVATE)

    /**
     * Один раз после обновления (с 1.10.40): убрать свои системные загрузки обновлений, которые так и
     * не скачались, — вместе с недокачанными файлами. В 1.10.38–1.10.39 вставшая загрузка висела в
     * очереди (и в шторке), а «Обновления» отвечали «уже скачивается»; человек ставит новую версию
     * браузером — и старая запись осталась бы висеть. Скачанные файлы не трогаем.
     */
    private fun cleanStaleUpdateDownloads() {
        val sp = updatePrefs()
        if (sp.getString("staleCheckedFor", null) == BuildConfig.VERSION_NAME) return
        sp.edit().putString("staleCheckedFor", BuildConfig.VERSION_NAME).apply()
        if (Build.VERSION.SDK_INT < 29 || UpdateFlow.phase != UpdateFlow.IDLE) return
        val app = applicationContext
        Thread {
            val n = runCatching { Updater.removeStale(app, keep = -1L) }.getOrDefault(0)
            if (n > 0) TunnelDebug.stage("обновления: убрал системные загрузки прошлых версий, которые так и не скачались: $n")
        }.apply { isDaemon = true; name = "warpscout-update-clean" }.start()
    }

    // ------------------------------------------------ тема оформления

    /** Светлая / тёмная / как в системе — для всего приложения, обоих видов экрана. */
    private fun applyThemeMode(mode: Int) {
        val night = when (mode) {
            Prefs.THEME_LIGHT -> AppCompatDelegate.MODE_NIGHT_NO
            Prefs.THEME_DARK -> AppCompatDelegate.MODE_NIGHT_YES
            else -> AppCompatDelegate.MODE_NIGHT_FOLLOW_SYSTEM
        }
        if (AppCompatDelegate.getDefaultNightMode() != night) AppCompatDelegate.setDefaultNightMode(night)
    }

    private fun themeButtonId(mode: Int): Int = when (mode) {
        Prefs.THEME_LIGHT -> R.id.btnThemeLight
        Prefs.THEME_DARK -> R.id.btnThemeDark
        else -> R.id.btnThemeSystem
    }

    private fun themeModeOf(buttonId: Int): Int = when (buttonId) {
        R.id.btnThemeLight -> Prefs.THEME_LIGHT
        R.id.btnThemeDark -> Prefs.THEME_DARK
        else -> Prefs.THEME_SYSTEM
    }

    /**
     * Переключатель темы в «Настройках». Смена темы пересоздаёт экран (так устроен Android) —
     * выбранная вкладка и подбор это переживают.
     */
    private fun setupThemeToggle() {
        binding.themeGroup.check(themeButtonId(prefs.themeMode))
        binding.themeGroup.addOnButtonCheckedListener { _, checkedId, isChecked ->
            if (!isChecked) return@addOnButtonCheckedListener
            val mode = themeModeOf(checkedId)
            if (mode == prefs.themeMode) return@addOnButtonCheckedListener
            prefs.themeMode = mode
            TunnelDebug.stage("тема оформления: " + getString(
                when (mode) {
                    Prefs.THEME_LIGHT -> R.string.theme_light
                    Prefs.THEME_DARK -> R.string.theme_dark
                    else -> R.string.theme_system
                }
            ).lowercase())
            applyThemeMode(mode)
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

        /**
         * Бекап из выбранного файла — не больше 8 МБ (с 1.10.40; с 1.10.43.1 в копии ещё точки, память и
         * списки — обычно сотни килобайт, файлы в неё берутся не больше чем на 4 МБ).
         */
        const val BACKUP_FILE_LIMIT = 8 * 1024 * 1024
        const val STATE_TAB = "warpscout.tab"

        /** Начальные экраны (с 1.10.44-beta6) переживают поворот: страница, отметки, ожидание туннеля. */
        const val STATE_WELCOME_PAGE = "warpscout.welcome.page"
        const val STATE_WELCOME_CHECKED = "warpscout.welcome.checked"
        const val STATE_SECOND_SETUP = "warpscout.welcome.second"

        /** Сколько «Настроить» второй выход ждёт подключения туннеля: первый подбор — минута-другая. */
        const val SECOND_SETUP_WAIT_MS = 15 * 60_000L

        /** Пауза между переездом ползунка «Расширенный режим» и сменой вида. */
        const val MODE_SWITCH_DELAY_MS = 280L

        const val TAB_START = 0
        const val TAB_CONFIG = 2
        const val TAB_LOG = 4

        /** Что настраивается на вкладке «Туннелирование» и в шторке (с 1.10.31). */
        const val KIND_APPS = 0
        const val KIND_SITES = 1
        const val KIND_LISTS = 2

        /** Сколько держится панель «успех». */
        const val BANNER_MS = 8000L

        /** Что сказать после сброса по умолчанию — экрану, созданному заново (с 1.10.32). */
        @Volatile
        var afterResetNote: String? = null

        /** Страница загрузок аккаунта Proton: там «WireGuard configuration» (с 1.10.39). */
        const val PROTON_DOWNLOADS_URL = "https://account.protonvpn.com/downloads"

        /** Виды итога под кнопкой второго выхода: цвет точки (с 1.10.32). */
        const val RES_OK = 0
        const val RES_FAIL = 1
        const val RES_WARN = 2
        const val RES_INFO = 3
    }
}
