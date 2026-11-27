package dev.warpscout.app

import android.app.Activity
import android.graphics.Color
import android.graphics.drawable.GradientDrawable
import android.util.TypedValue
import android.view.Gravity
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.TextView
import androidx.activity.OnBackPressedCallback
import androidx.appcompat.app.AppCompatDialog
import dev.warpscout.app.databinding.ScreenRouteBinding

/**
 * Экран «Маршрут» (с 1.10.49-beta7): окно во весь экран поверх главного — схема на карте, шаги
 * маршрута и какие приложения через какой выход идут. Кнопка на схеме запускает новый подбор;
 * состояние маршрута считает главный экран ([Info]) — тем же кодом, что и строку «где мы».
 */
class RouteScreen(private val activity: Activity, private val onScan: () -> Unit) {

    /** Группа приложений у одного выхода. [kind] — [KIND_SECOND], [KIND_WARP] или [KIND_DIRECT]. */
    class Group(val kind: Int, val title: String, val sub: String, val pkgs: List<String>)

    class Info(
        /** Что с туннелем: [RouteMapView.MODE_OFF] / CONNECTING / ON. */
        val mode: Int,
        val stateText: String,
        val stateColor: Int,
        val net: String,
        val endpoint: String,
        val entryNote: String,
        val exitPlace: String,
        val exitDetail: String,
        /** Второй выход настроен и включён в настройках. */
        val secondConfigured: Boolean,
        /** Страна второго выхода в этой сессии: null — не поднят, "" — поднят, страна неизвестна. */
        val second: String?,
        val secondDetail: String,
        val groups: List<Group>,
        /** Подписи приложений по пакету (уже прочитанные главным экраном). */
        val labels: Map<String, String>,
    )

    private var dialog: AppCompatDialog? = null
    private var views: ScreenRouteBinding? = null
    private val kind = Design.kind(activity)
    private val pal = Design.palette(activity)
    private val density = activity.resources.displayMetrics.density
    private var shownKey = ""

    val isShowing: Boolean get() = dialog?.isShowing == true

    fun show(info: Info) {
        val d = AppCompatDialog(activity, Design.fullScreenTheme(activity))
        val v = ScreenRouteBinding.inflate(LayoutInflater.from(d.context))
        dialog = d
        views = v
        d.setContentView(v.root)
        d.window?.setLayout(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT)
        d.onBackPressedDispatcher.addCallback(object : OnBackPressedCallback(true) {
            override fun handleOnBackPressed() = dismiss()
        })
        Design.backdrop(d.context, kind)?.let { bg ->
            (bg as? GlowBackdrop)?.calm = true
            v.routeRoot.background = bg
        }
        SystemBars.keepClear(v.routeRoot)
        v.routeMap.design = kind
        v.routeScan.setOnClickListener {
            dismiss()
            onScan()
        }
        render(info, first = true)
        d.setOnDismissListener {
            if (dialog === d) {
                dialog = null
                views = null
            }
        }
        d.show()
    }

    /** Состояние поменялось, пока экран открыт: перерисовать, если есть что. */
    fun update(info: Info) {
        if (!isShowing) return
        render(info, first = false)
    }

    fun dismiss() {
        val d = dialog ?: return
        dialog = null
        views = null
        runCatching { d.dismiss() }
    }

    private fun s(id: Int, vararg args: Any): String = activity.getString(id, *args)

    private fun render(info: Info, first: Boolean) {
        val v = views ?: return
        val key = listOf(info.mode, info.stateText, info.endpoint, info.exitPlace, info.second, info.net).joinToString("|")
        if (!first && key == shownKey) return
        shownKey = key

        // Плашка состояния: точка цветом состояния и слово.
        val pill = android.text.SpannableStringBuilder("●  ").append(info.stateText)
        pill.setSpan(android.text.style.ForegroundColorSpan(info.stateColor), 0, 1, android.text.Spanned.SPAN_EXCLUSIVE_EXCLUSIVE)
        v.routeState.text = pill

        // Схема.
        val map = v.routeMap
        map.youLabel = s(R.string.route_map_you, info.net)
        map.entryLabel = if (info.endpoint.isNotBlank()) s(R.string.route_map_entry, info.endpoint) else ""
        map.warpLabel = s(R.string.route_map_warp, info.exitPlace.ifBlank { s(R.string.route_map_unknown) })
        map.secondLabel = if (info.secondConfigured && (info.second != null || info.mode != RouteMapView.MODE_ON)) {
            s(R.string.route_map_second, info.second?.ifBlank { null } ?: s(R.string.route_map_unknown))
        } else {
            null
        }
        map.warpApps = branches(info, KIND_WARP, 3)
        map.secondApps = if (map.secondLabel != null) branches(info, KIND_SECOND, 4) else emptyList()
        map.setMode(info.mode)
        if (first && info.mode == RouteMapView.MODE_ON) map.play()
        map.invalidate()

        // Шаги маршрута.
        val box = v.routeSteps
        box.removeAllViews()
        val reached = info.mode == RouteMapView.MODE_ON
        step(box, STEP_YOU, s(R.string.route_you), info.net, "", lit = true, first = true)
        step(
            box, STEP_POINT, s(R.string.route_entry), info.endpoint.ifBlank { s(R.string.simple_dash) }, info.entryNote,
            lit = info.mode != RouteMapView.MODE_OFF
        )
        step(
            box, STEP_POINT, s(R.string.route_exit), info.exitPlace.ifBlank { s(R.string.route_exit_unknown) }, info.exitDetail,
            lit = reached && info.exitPlace.isNotBlank()
        )
        if (info.secondConfigured) {
            val value = when {
                info.second == null -> s(R.string.route_second_down)
                info.second.isBlank() -> s(R.string.route_second_up)
                else -> info.second
            }
            step(box, STEP_SECOND, s(R.string.route_second), value, info.secondDetail, lit = reached && info.second != null)
        }

        // Какие приложения через какой выход.
        val apps = v.routeApps
        apps.removeAllViews()
        info.groups.forEachIndexed { i, g -> group(apps, g, info, divider = i > 0) }
    }

    private fun branches(info: Info, kind: Int, max: Int): List<RouteMapView.Branch> =
        info.groups.filter { it.kind == kind }.flatMap { it.pkgs }.take(max).map { pkg ->
            val label = info.labels[pkg] ?: pkg.substringAfterLast('.')
            val icon = runCatching { activity.packageManager.getApplicationIcon(pkg) }.getOrNull()
            RouteMapView.Branch(label, icon)
        }

    private fun dp(v: Float): Int = (v * density + 0.5f).toInt()

    private fun text(parent: LinearLayout, value: String, sizeSp: Float, color: Int, bold: Boolean = false, top: Int = 0): TextView {
        val t = TextView(parent.context)
        t.text = value
        t.setTextSize(TypedValue.COMPLEX_UNIT_SP, sizeSp)
        t.setTextColor(color)
        if (bold) t.setTypeface(t.typeface, android.graphics.Typeface.BOLD)
        val lp = LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT)
        lp.topMargin = top
        parent.addView(t, lp)
        return t
    }

    private fun withAlpha(c: Int, a: Float): Int = Color.argb((255 * a).toInt(), Color.red(c), Color.green(c), Color.blue(c))

    /** Строка шага: кружок слева (линия к предыдущему шагу) и подписи. */
    private fun step(box: LinearLayout, kind: Int, label: String, value: String, detail: String, lit: Boolean, first: Boolean = false) {
        val ctx = box.context
        if (!first) {
            val line = View(ctx)
            line.setBackgroundColor(withAlpha(if (lit) pal.accent else pal.outline, if (lit) 0.6f else 0.35f))
            val lp = LinearLayout.LayoutParams(dp(2f), dp(12f))
            lp.marginStart = dp(10f)
            box.addView(line, lp)
        }
        val row = LinearLayout(ctx)
        row.orientation = LinearLayout.HORIZONTAL
        row.gravity = Gravity.TOP
        val marker = ImageView(ctx)
        val ring = GradientDrawable()
        ring.shape = GradientDrawable.OVAL
        when {
            kind == STEP_YOU -> {
                ring.setStroke(dp(2f), pal.onSurface)
                ring.setColor(Color.TRANSPARENT)
            }
            !lit -> {
                ring.setStroke(dp(2f), withAlpha(pal.outline, 0.7f))
                ring.setColor(Color.TRANSPARENT)
            }
            kind == STEP_SECOND -> {
                ring.setStroke(dp(2f), pal.accent)
                ring.setColor(Color.TRANSPARENT)
            }
            else -> {
                ring.setStroke(dp(2f), pal.accent)
                ring.setColor(withAlpha(pal.accent, 0.16f))
            }
        }
        marker.setImageDrawable(ring)
        marker.importantForAccessibility = View.IMPORTANT_FOR_ACCESSIBILITY_NO
        val mlp = LinearLayout.LayoutParams(dp(22f), dp(22f))
        mlp.topMargin = dp(2f)
        row.addView(marker, mlp)
        val col = LinearLayout(ctx)
        col.orientation = LinearLayout.VERTICAL
        val clp = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
        clp.marginStart = dp(14f)
        row.addView(col, clp)
        text(col, label, 13f, pal.onSurfaceVariant)
        text(col, value, 15f, pal.onSurface, bold = true, top = dp(1f))
        if (detail.isNotBlank()) text(col, detail, 12.5f, pal.outline, top = dp(1f))
        box.addView(row, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT))
    }

    private fun group(box: LinearLayout, g: Group, info: Info, divider: Boolean) {
        val ctx = box.context
        if (divider) {
            val line = View(ctx)
            line.setBackgroundColor(withAlpha(pal.outline, 0.18f))
            box.addView(line, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, dp(1f)))
        }
        val row = LinearLayout(ctx)
        row.orientation = LinearLayout.HORIZONTAL
        row.setPadding(dp(16f), dp(12f), dp(16f), dp(12f))
        val tag = TextView(ctx)
        val color = when (g.kind) {
            KIND_SECOND -> pal.accent
            KIND_WARP -> pal.blue
            else -> pal.onSurfaceVariant
        }
        tag.text = s(
            when (g.kind) {
                KIND_SECOND -> R.string.route_tag_second
                KIND_WARP -> R.string.route_tag_warp
                else -> R.string.route_tag_direct
            }
        )
        tag.setTextSize(TypedValue.COMPLEX_UNIT_SP, 12f)
        tag.setTypeface(tag.typeface, android.graphics.Typeface.BOLD)
        tag.setTextColor(color)
        tag.setPadding(dp(9f), dp(4f), dp(9f), dp(4f))
        tag.background = GradientDrawable().apply {
            cornerRadius = dp(8f).toFloat()
            setColor(withAlpha(color, 0.12f))
            setStroke(dp(1f), withAlpha(color, 0.38f))
        }
        row.addView(tag, LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT))
        val col = LinearLayout(ctx)
        col.orientation = LinearLayout.VERTICAL
        val clp = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
        clp.marginStart = dp(12f)
        row.addView(col, clp)
        text(col, g.title, 14f, pal.onSurface)
        if (g.sub.isNotBlank()) text(col, g.sub, 12f, pal.outline, top = dp(2f))
        box.addView(row, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT))
    }

    companion object {
        const val KIND_SECOND = 0
        const val KIND_WARP = 1
        const val KIND_DIRECT = 2
        private const val STEP_YOU = 0
        private const val STEP_POINT = 1
        private const val STEP_SECOND = 2
    }
}
