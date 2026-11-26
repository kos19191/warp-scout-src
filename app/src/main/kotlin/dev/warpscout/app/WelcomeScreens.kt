package dev.warpscout.app

import android.graphics.drawable.Drawable
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.view.inputmethod.InputMethodManager
import android.widget.BaseAdapter
import androidx.activity.OnBackPressedCallback
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.app.AppCompatDialog
import androidx.core.widget.doAfterTextChanged
import dev.warpscout.app.databinding.DialogWelcomeBinding
import dev.warpscout.app.databinding.ItemAppRowBinding

/**
 * Начальные экраны (бета, с 1.10.44-beta6). Человек попросил 25.11: «Давай сделаем в начале запуска
 * приложения пару подсказок, начальные экраны… Это окно должно быть только при первом запуске».
 * Показываются после новой установки, один раз (Prefs.welcomePending):
 *
 *  1. Какие приложения пускать через туннель — список с поиском; отмечено то, что приложение отметило
 *     бы само (WelcomeApps.preset). «Сохранить» или «Пропустить».
 *  2. Второй выход — зачем он и как его настроить: «Настроить» (выбор Proton, как только заработает
 *     туннель), «Свой сервер — файл .conf» или «Пропустить».
 *
 * Окно во весь экран поверх главного. Кнопки — внизу, вне прокрутки: список сжимается, а не выталкивает
 * их за край экрана, и они всегда над системными кнопками Android (три кнопки или жесты) и над
 * клавиатурой поиска. Что сохранять и что делать по «Настроить», решает экран ([Host]).
 */
class WelcomeScreens(
    private val activity: AppCompatActivity,
    private val host: Host,
) {

    /** Строка списка: пакет, подпись, системное ли приложение. */
    class App(val pkg: String, val label: String, val system: Boolean)

    interface Host {
        /** Уже прочитанный список приложений; пусто — ещё не прочитан. */
        fun knownApps(): List<App>

        /** Прочитать список заново — дорого (подпись каждого приложения), зовётся вне главного потока. */
        fun readApps(): List<App>

        /** Что отмечено сразу. */
        fun preset(apps: List<App>): Set<String>

        /** Подпись строки вместо пакета (приложения «второго выхода по умолчанию»); null — пакет. */
        fun rowNote(pkg: String): String?

        /** «Сохранить» на первой странице: [installed] — строки списка, [preset] — что было отмечено сразу. */
        fun saveApps(installed: List<String>, preset: Set<String>, checked: Set<String>)

        /** Экраны закрыты — больше не показывать. [how] — для журнала. */
        fun finished(how: String)

        /** «Настроить» второй выход. */
        fun setupSecond()

        /** «Свой сервер — файл .conf». */
        fun pickSecondFile()
    }

    private var dialog: AppCompatDialog? = null
    private var views: DialogWelcomeBinding? = null
    private var page = PAGE_APPS
    private var apps: List<App> = emptyList()
    private var loaded = false
    private var preset: Set<String> = emptySet()
    private val checked = LinkedHashSet<String>()
    private var visible: List<App> = emptyList()

    /** Отметки, сохранённые при пересоздании экрана (поворот), — вместо отмеченных сразу. */
    private var restored: Set<String>? = null
    private val icons = HashMap<String, Drawable?>()

    val isShowing: Boolean get() = dialog?.isShowing == true

    /** Страница сейчас — для пересоздания экрана. */
    val currentPage: Int get() = page

    /** Отметки сейчас — для пересоздания экрана; null — список ещё не прочитан (отметок ещё нет). */
    fun checkedNow(): ArrayList<String>? = if (loaded) ArrayList(checked) else null

    private fun s(id: Int, vararg args: Any): String = activity.getString(id, *args)

    fun show(startPage: Int, restoredChecked: Collection<String>?) {
        restored = restoredChecked?.toSet()
        // Тема — выбранного дизайна (с 1.10.49-beta7): в «Премиуме» начальные экраны тоже тёмно-оранжевые.
        val d = AppCompatDialog(activity, Design.fullScreenTheme(activity))
        val v = DialogWelcomeBinding.inflate(LayoutInflater.from(d.context))
        dialog = d
        views = v
        d.setContentView(v.root)
        d.setCancelable(false)
        d.setCanceledOnTouchOutside(false)
        // «Назад» (кнопка навигации или жест): со второй страницы — на первую, с первой — закрыть экраны.
        d.onBackPressedDispatcher.addCallback(object : OnBackPressedCallback(true) {
            override fun handleOnBackPressed() = back()
        })
        d.window?.setLayout(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT)
        padForSystemBars(v.root)
        setupApps(v)
        setupSecond(v)
        showPage(if (startPage == PAGE_SECOND) PAGE_SECOND else PAGE_APPS)
        d.show()
        val known = host.knownApps()
        if (known.isNotEmpty()) {
            useApps(known)
        } else {
            updateCount()
            Thread({
                val list = runCatching { host.readApps() }.getOrDefault(emptyList())
                activity.runOnUiThread { if (isShowing) useApps(list) }
            }, "warpscout-welcome-apps").apply { isDaemon = true }.start()
        }
    }

    fun dismiss() {
        val d = dialog ?: return
        dialog = null
        runCatching { d.dismiss() }
    }

    /**
     * Окно во весь экран: системные панели (вверху — строка состояния, внизу — три кнопки навигации или
     * полоска жестов), вырез камеры и клавиатура не должны закрывать текст и кнопки. Там, где Android
     * сам ставит окно между панелями, сюда приходят нули — отступы остаются как в разметке; отступ
     * добавляется, только если окно легло под панели. С 1.10.47 — общий [SystemBars], как у главного экрана.
     */
    private fun padForSystemBars(root: View) = SystemBars.keepClear(root)

    // ------------------------------------------------------------------ 1. приложения

    private val adapter = object : BaseAdapter() {
        override fun getCount(): Int = visible.size
        override fun getItem(position: Int): Any = visible[position]
        override fun getItemId(position: Int): Long = position.toLong()
        override fun getView(position: Int, convertView: View?, parent: ViewGroup): View {
            val row = if (convertView != null) {
                ItemAppRowBinding.bind(convertView)
            } else {
                ItemAppRowBinding.inflate(LayoutInflater.from(parent.context), parent, false)
            }
            val app = visible[position]
            row.appLabel.text = app.label
            row.appPackage.text = host.rowNote(app.pkg) ?: app.pkg
            row.appCheck.visibility = View.VISIBLE
            row.appCheck.isChecked = app.pkg in checked
            // Выход приложения здесь не выбирают: второго выхода ещё нет.
            row.appExit.visibility = View.GONE
            row.appExit.setOnClickListener(null)
            // Иконку читаем, только когда строка видна, и запоминаем: их сотни, а видно десяток.
            val icon = icons.getOrPut(app.pkg) {
                runCatching { activity.packageManager.getApplicationIcon(app.pkg) }.getOrNull()
            }
            row.appIcon.setImageDrawable(icon)
            return row.root
        }
    }

    private fun setupApps(v: DialogWelcomeBinding) {
        v.welcomeAppsList.adapter = adapter
        v.welcomeAppsList.setOnItemClickListener { _, _, position, _ ->
            val app = visible.getOrNull(position) ?: return@setOnItemClickListener
            if (!checked.add(app.pkg)) checked.remove(app.pkg)
            // Порядок не меняем: строка не должна уезжать из-под пальца. Отмеченные поднимутся наверх
            // при следующем поиске.
            adapter.notifyDataSetChanged()
            updateCount()
        }
        v.welcomeSearch.doAfterTextChanged { refreshList() }
        v.welcomeAppsSave.setOnClickListener {
            val installed = apps.map { it.pkg }
            val chosen = LinkedHashSet(checked)
            runCatching { host.saveApps(installed, preset, chosen) }.onFailure { t ->
                TunnelDebug.error("начальные экраны: приложения не сохранились — " + SafeMode.describe(t))
            }
            showPage(PAGE_SECOND)
        }
        v.welcomeAppsSkip.setOnClickListener {
            TunnelDebug.stage("начальные экраны: приложения — «Пропустить», остаётся набор по умолчанию")
            showPage(PAGE_SECOND)
        }
    }

    private fun useApps(list: List<App>) {
        apps = list
        loaded = true
        preset = runCatching { host.preset(list) }.getOrDefault(emptySet())
        val have = list.mapTo(HashSet()) { it.pkg }
        checked.clear()
        (restored ?: preset).filterTo(checked) { it in have }
        restored = null
        refreshList()
    }

    private fun refreshList() {
        val v = views ?: return
        val q = v.welcomeSearch.text?.toString()?.trim()?.lowercase().orEmpty()
        // Отмеченные — наверху: их проверяют первыми, и в сотне строк они не теряются.
        visible = apps.filter { app ->
            q.isEmpty() || app.label.lowercase().contains(q) || app.pkg.lowercase().contains(q)
        }.sortedWith(compareByDescending<App> { it.pkg in checked }.thenBy { it.label.lowercase() })
        adapter.notifyDataSetChanged()
        updateCount()
    }

    private fun updateCount() {
        val v = views ?: return
        v.welcomeAppsCount.text = when {
            !loaded -> s(R.string.sheet_apps_loading)
            apps.isEmpty() -> s(R.string.welcome_apps_failed)
            checked.isEmpty() -> s(R.string.welcome_apps_none)
            else -> s(R.string.sheet_apps_count, checked.size)
        }
        v.welcomeAppsSave.isEnabled = loaded && apps.isNotEmpty()
    }

    // ------------------------------------------------------------------ 2. второй выход

    private fun setupSecond(v: DialogWelcomeBinding) {
        v.welcomeSecondGo.setOnClickListener { finish("второй выход — «Настроить»") { host.setupSecond() } }
        v.welcomeSecondFile.setOnClickListener { finish("второй выход — свой файл .conf") { host.pickSecondFile() } }
        v.welcomeSecondSkip.setOnClickListener { finish("второй выход — «Пропустить»") {} }
    }

    // ------------------------------------------------------------------ страницы

    private fun showPage(p: Int) {
        val v = views ?: return
        page = p
        hideKeyboard(v)
        v.welcomePageApps.visibility = if (p == PAGE_APPS) View.VISIBLE else View.GONE
        v.welcomePageSecond.visibility = if (p == PAGE_SECOND) View.VISIBLE else View.GONE
        v.welcomeStep.text = s(R.string.welcome_step, p + 1, PAGES)
    }

    private fun back() {
        if (page == PAGE_SECOND) {
            showPage(PAGE_APPS)
        } else {
            finish("закрыты кнопкой «Назад»") {}
        }
    }

    private fun finish(how: String, then: () -> Unit) {
        views?.let { hideKeyboard(it) }
        dismiss()
        runCatching { host.finished(how) }.onFailure { t ->
            TunnelDebug.error("начальные экраны: " + SafeMode.describe(t))
        }
        runCatching(then).onFailure { t ->
            TunnelDebug.error("начальные экраны: $how — " + SafeMode.describe(t))
        }
    }

    private fun hideKeyboard(v: DialogWelcomeBinding) {
        runCatching {
            activity.getSystemService(InputMethodManager::class.java)
                ?.hideSoftInputFromWindow(v.welcomeSearch.windowToken, 0)
            v.welcomeSearch.clearFocus()
        }
    }

    companion object {
        const val PAGE_APPS = 0
        const val PAGE_SECOND = 1
        private const val PAGES = 2
    }
}
