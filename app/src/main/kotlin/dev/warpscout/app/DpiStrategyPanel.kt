package dev.warpscout.app

import android.view.Gravity
import android.view.View
import android.widget.LinearLayout
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.core.widget.doAfterTextChanged
import com.google.android.material.button.MaterialButton
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import dev.warpscout.app.databinding.ActivityMainBinding
import dev.warpscout.core.dpi.DpiPlan
import dev.warpscout.core.dpi.DpiService
import dev.warpscout.core.dpi.DpiServices
import dev.warpscout.core.dpi.DpiStrategy
import dev.warpscout.core.dpi.DpiTrick

/**
 * «Стратегия обхода» в разделе «Режут DPI или адрес?» (с 1.10.49-beta4, бета), как у версии для
 * компьютера, но без того, чего телефон без root не умеет:
 *
 *  • общая стратегия — «по проверке сети» (план из «Проверить DPI и подобрать»), «не обходить»,
 *    встроенный приём или своя строка ByeDPI;
 *  • выбор по сервисам — YouTube, X и Discord отдельно (или «как для всех»);
 *  • своя строка — разбирается на лету: что сделает, что пропущено (телефону не нужно), ошибки;
 *  • «Проверить стратегию» — одна стратегия на YouTube, его видео, X и Discord.
 *
 * Настройки — в [Prefs] (dpiStrategy, dpiOverrides, dpiCustom): сервис туннеля строит из них план
 * (см. DpiPlan.effective). Экран — только выбор и показ.
 */
class DpiStrategyPanel(
    private val activity: AppCompatActivity,
    private val binding: ActivityMainBinding,
    private val prefs: Prefs,
    private val banner: (String, Boolean) -> Unit,
    /** Применить работающему туннелю; true — туннель работает и получил новый план. */
    private val applyToTunnel: () -> Boolean,
    /** Запустить «Проверить стратегию» (проверка — у экрана: она та же, что «Проверить DPI»). */
    private val startTest: (DpiTrick) -> Unit,
    /** Перерисовать «что сделает обход на этой сети». */
    private val onChanged: () -> Unit,
) {
    private fun str(id: Int, vararg args: Any): String = activity.getString(id, *args)

    fun bind() {
        binding.btnDpiStrategy.setOnClickListener { guard { pickGeneral() } }
        binding.editDpiCustom.setText(prefs.dpiCustom)
        binding.editDpiCustom.doAfterTextChanged { runCatching { renderParse() } }
        binding.btnDpiCustomSave.setOnClickListener { guard { saveCustom() } }
        binding.btnDpiStrategyTest.setOnClickListener { guard { pickTest() } }
        render()
    }

    private fun guard(block: () -> Unit) {
        runCatching(block).onFailure { t ->
            TunnelDebug.problem("стратегия DPI: " + SafeMode.describe(t))
            banner(str(R.string.banner_ui_error, SafeMode.describe(t)), true)
        }
    }

    fun render() {
        val custom = DpiTrick.custom(prefs.dpiCustom)
        binding.btnDpiStrategy.text = str(R.string.dpi_strategy_general, choiceLabel(prefs.dpiStrategy, custom))
        val box = binding.dpiServicesBox
        box.removeAllViews()
        for (svc in DpiServices.ALL) {
            val choice = prefs.dpiOverride(svc.id)
            val label = if (choice.isBlank()) str(R.string.dpi_strategy_inherit) else choiceLabel(choice, custom)
            box.addView(
                MaterialButton(activity, null, com.google.android.material.R.attr.materialButtonOutlinedStyle).apply {
                    text = str(R.string.dpi_strategy_service, svc.title, label)
                    isAllCaps = false
                    gravity = Gravity.START or Gravity.CENTER_VERTICAL
                    setOnClickListener { guard { pickService(svc) } }
                },
                LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT)
            )
        }
        renderParse()
        renderTest()
    }

    /** «по проверке сети», «не обходить», «разрез · --split 1+s», «своя · --oob 1+s». */
    private fun choiceLabel(choice: String, custom: DpiTrick?): String = when (choice) {
        "", DpiPlan.AUTO -> "по проверке сети"
        DpiPlan.OFF -> "не обходить"
        DpiTrick.CUSTOM_ID -> custom?.let { "своя · ${it.byedpi}" } ?: "своя — не задана"
        else -> DpiTrick.byId(choice)?.let { "${it.title} · ${it.byedpi}" } ?: "неизвестный приём «$choice»"
    }

    private class Option(val choice: String, val label: String)

    private fun options(withInherit: Boolean): List<Option> {
        val custom = DpiTrick.custom(prefs.dpiCustom)
        val out = ArrayList<Option>()
        if (withInherit) out += Option(DpiPlan.INHERIT, str(R.string.dpi_choice_inherit))
        out += Option(DpiPlan.AUTO, str(R.string.dpi_choice_auto))
        out += Option(DpiPlan.OFF, str(R.string.dpi_choice_off))
        DpiTrick.BUILTIN.forEach { t ->
            out += Option(t.id, "${t.title} — ${t.byedpi}" + if (t.needsFake) " (эксперимент)" else "")
        }
        out += Option(
            DpiTrick.CUSTOM_ID,
            if (custom != null) str(R.string.dpi_choice_custom, custom.byedpi) else str(R.string.dpi_choice_custom_none)
        )
        return out
    }

    private fun pickGeneral() {
        val opts = options(withInherit = false)
        val current = opts.indexOfFirst { it.choice == prefs.dpiStrategy }.coerceAtLeast(0)
        MaterialAlertDialogBuilder(activity)
            .setTitle(R.string.dpi_strategy_pick_title)
            .setSingleChoiceItems(opts.map { it.label }.toTypedArray(), current) { d, which ->
                d.dismiss()
                guard { choose(null, opts[which].choice) }
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    private fun pickService(svc: DpiService) {
        val opts = options(withInherit = true)
        val current = opts.indexOfFirst { it.choice == prefs.dpiOverride(svc.id) }.coerceAtLeast(0)
        MaterialAlertDialogBuilder(activity)
            .setTitle(str(R.string.dpi_strategy_pick_service_title, svc.title))
            .setSingleChoiceItems(opts.map { it.label }.toTypedArray(), current) { d, which ->
                d.dismiss()
                guard { choose(svc, opts[which].choice) }
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    /** Выбор человека: общий ([svc] = null) или сервиса. */
    private fun choose(svc: DpiService?, choice: String) {
        val custom = DpiTrick.custom(prefs.dpiCustom)
        if (choice == DpiTrick.CUSTOM_ID && custom == null) {
            banner(str(R.string.dpi_choice_custom_none), true)
            binding.editDpiCustom.requestFocus()
            return
        }
        val label = if (svc != null && choice.isBlank()) str(R.string.dpi_strategy_inherit) else choiceLabel(choice, custom)
        if (svc == null) {
            if (choice == prefs.dpiStrategy) return
            prefs.dpiStrategy = choice
            TunnelDebug.stage("настройка «стратегия обхода DPI»: для всех — $label")
        } else {
            if (choice == prefs.dpiOverride(svc.id)) return
            prefs.setDpiOverride(svc.id, choice)
            TunnelDebug.stage("настройка «стратегия обхода DPI»: ${svc.title} — $label")
        }
        render()
        onChanged()
        val what = if (svc == null) label else "${svc.title} — $label"
        if (applyToTunnel()) banner(str(R.string.dpi_strategy_applied, what), false)
    }

    // ------------------------------------------------------------------------------ своя строка

    private fun renderParse() {
        val view = binding.textDpiCustomParse
        val text = binding.editDpiCustom.text?.toString().orEmpty().trim()
        val saved = prefs.dpiCustom
        var bad = false
        view.text = if (text.isEmpty()) {
            if (saved.isEmpty()) str(R.string.dpi_custom_empty) else str(R.string.dpi_custom_unsaved)
        } else {
            val p = DpiStrategy.parse(text)
            val st = p.strategy
            if (st == null) {
                bad = true
                str(R.string.dpi_custom_bad, p.error ?: "?")
            } else {
                val lines = ArrayList<String>()
                lines += str(R.string.dpi_custom_ok, st.describe())
                if (p.notes.isNotEmpty()) lines += str(R.string.dpi_custom_notes, p.notes.joinToString("; "))
                if (st.isPlain) lines += "Ничего не меняет — это «как есть»: такую сохранить можно, но выбрать нельзя."
                if (st.needsFake) lines += str(R.string.dpi_custom_fake_note)
                if (text != saved) lines += str(R.string.dpi_custom_unsaved)
                lines.joinToString("\n")
            }
        }
        view.setTextColor(
            if (bad) ContextCompat.getColor(activity, R.color.check_fail)
            else binding.textDpiStrategyHint.currentTextColor
        )
    }

    private fun saveCustom() {
        val text = binding.editDpiCustom.text?.toString().orEmpty().trim()
        if (text.isNotEmpty() && DpiStrategy.parse(text).strategy == null) {
            banner(str(R.string.dpi_custom_cant_save), true)
            return
        }
        if (text == prefs.dpiCustom) {
            renderParse()
            return
        }
        prefs.dpiCustom = text
        val usedNow = prefs.dpiStrategy == DpiTrick.CUSTOM_ID || DpiPlan.parseOverrides(prefs.dpiOverrides).values.contains(DpiTrick.CUSTOM_ID)
        TunnelDebug.stage(
            "настройка «своя стратегия DPI»: " + (if (text.isEmpty()) "удалена" else text) +
                (if (usedNow) " — выбрана, туннель берёт её" else "")
        )
        banner(if (text.isEmpty()) str(R.string.dpi_custom_cleared) else str(R.string.dpi_custom_saved, text), false)
        render()
        onChanged()
        // «custom» в плане сети и в выборе берётся из настроек — работающему туннелю нужен новый план.
        applyToTunnel()
    }

    // --------------------------------------------------------------------- «Проверить стратегию»

    private fun pickTest() {
        val custom = DpiTrick.custom(prefs.dpiCustom)
        // Своя — и несохранённая строка из поля, если разбирается: её и хочется проверить до сохранения.
        val typed = binding.editDpiCustom.text?.toString().orEmpty().trim().let { DpiTrick.custom(it) }
        val tricks = ArrayList<DpiTrick>()
        if (typed != null) tricks += typed
        if (custom != null && custom != typed) tricks += custom
        tricks += DpiTrick.BUILTIN
        val labels = tricks.map { t ->
            when {
                t === typed && t != custom -> "Своя (из поля, не сохранена) — ${t.byedpi}"
                t.isCustom -> "Своя — ${t.byedpi}"
                else -> "${t.title} — ${t.byedpi}" + if (t.needsFake) " (эксперимент)" else ""
            }
        }
        val chosen = prefs.dpiStrategy
        val pre = tricks.indexOfFirst { t -> if (chosen == DpiTrick.CUSTOM_ID) t.isCustom else t.id == chosen }.coerceAtLeast(0)
        MaterialAlertDialogBuilder(activity)
            .setTitle(R.string.dpi_strategy_test_title)
            .setSingleChoiceItems(labels.toTypedArray(), pre) { d, which ->
                d.dismiss()
                guard { startTest(tricks[which]) }
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    /** Проверка идёт: кнопка занята, строка хода. */
    fun showTesting(on: Boolean, line: String = "") {
        binding.btnDpiStrategyTest.isEnabled = !on
        binding.btnDpiStrategyTest.setText(if (on) R.string.dpi_strategy_testing else R.string.dpi_strategy_test)
        binding.textDpiStrategyProgress.visibility = if (on) View.VISIBLE else View.GONE
        if (on) binding.textDpiStrategyProgress.text = line.ifBlank { str(R.string.dpi_running) }
    }

    /** Итог последней «Проверить стратегию». */
    fun renderTest() {
        val r = DpiCheck.loadStrategy(activity)
        val box = binding.dpiStrategyBox
        box.removeAllViews()
        if (r == null) {
            binding.textDpiStrategyResultHead.visibility = View.GONE
            binding.textDpiStrategySummary.visibility = View.GONE
            return
        }
        binding.textDpiStrategyResultHead.visibility = View.VISIBLE
        binding.textDpiStrategyResultHead.text = str(
            R.string.dpi_strategy_test_head,
            if (r.trick.isCustom) "своей (${r.trick.byedpi})" else "«${r.trick.title}»",
            r.label, whenText(r.at)
        )
        r.rows.forEach { row ->
            box.addView(android.widget.TextView(activity).apply {
                text = row.text
                textSize = 13f
                setPadding(0, 2, 0, 2)
                setTextColor(
                    ContextCompat.getColor(
                        activity,
                        when (row.kind) {
                            0 -> R.color.check_ok
                            1 -> R.color.state_warn
                            else -> R.color.check_fail
                        }
                    )
                )
            })
        }
        binding.textDpiStrategySummary.visibility = View.VISIBLE
        binding.textDpiStrategySummary.text = r.summary
    }

    private fun whenText(at: Long): String {
        val d = java.util.Date(at)
        val sameDay = java.text.SimpleDateFormat("yyyyMMdd", java.util.Locale.US).let { it.format(d) == it.format(java.util.Date()) }
        return java.text.SimpleDateFormat(if (sameDay) "HH:mm" else "dd.MM HH:mm", java.util.Locale.getDefault()).format(d)
    }
}
