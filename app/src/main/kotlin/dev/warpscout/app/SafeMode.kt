package dev.warpscout.app

import android.app.Activity
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.util.Log
import android.view.Gravity
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import androidx.core.content.ContextCompat

/**
 * Аварийный экран.
 *
 * Зачем он вообще нужен: пока интерфейс падал целиком, человек видел системное «приложение
 * закрыто из-за ошибки» — и не мог ни открыть журнал, ни прислать причину. Получался замкнутый
 * круг: сломано то, через что рассказывают о поломке.
 *
 * Поэтому любую ошибку, из-за которой не удалось построить интерфейс, ловим и показываем
 * **без разметки и без Material-компонентов** — только системные TextView/Button. Здесь нечему
 * не загрузиться, а стектрейс можно прочитать и отправить одной кнопкой.
 *
 * Важно: это не «проглатывание» ошибки. Она уходит и в журнал падений, и в журнал туннеля, а на
 * экране написано, что произошло.
 */
object SafeMode {

    /** Показать аварийный экран вместо содержимого Activity. */
    fun show(activity: Activity, error: Throwable, stage: String) {
        val head = describe(error)
        runCatching { CrashLog.note(activity, "аварийный экран ($stage): $head") }
        runCatching { TunnelDebug.error("аварийный экран ($stage): $head") }
        val report = buildString {
            append("Этап: ").append(stage).append('\n')
            append("Версия: ").append(BuildConfig.VERSION_NAME).append('\n')
            append("Устройство: ").append(android.os.Build.MANUFACTURER).append(' ')
                .append(android.os.Build.MODEL).append(", Android ")
                .append(android.os.Build.VERSION.RELEASE).append('\n')
            append('\n')
            append(Log.getStackTraceString(error).take(6000))
        }
        render(activity, report, onContinue = null)
    }

    /**
     * Показать отчёт о **прошлом** падении до построения интерфейса.
     *
     * Это ответ на «приложение вылетает при запуске, журнал открыть не успеваю»: причина всегда
     * оказывается на экране, и её можно скопировать или отправить. [onContinue] — что делать
     * дальше, если человек нажмёт «Продолжить» (обычно — строить интерфейс как обычно).
     */
    fun showReport(activity: Activity, report: String, onContinue: (() -> Unit)?) {
        render(activity, report, onContinue)
    }

    private fun render(activity: Activity, report: String, onContinue: (() -> Unit)?) {
        val column = LinearLayout(activity).apply {
            orientation = LinearLayout.VERTICAL
            setBackgroundColor(ContextCompat.getColor(activity, R.color.colorSurface))
            setPadding(pad(activity, 20), pad(activity, 28), pad(activity, 20), pad(activity, 28))
        }
        column.addView(TextView(activity).apply {
            setText(R.string.safe_title)
            textSize = 20f
            setTextColor(ContextCompat.getColor(activity, R.color.colorOnSurface))
            setTypeface(typeface, Typeface.BOLD)
        })
        column.addView(TextView(activity).apply {
            setText(R.string.safe_hint)
            textSize = 14f
            setTextColor(ContextCompat.getColor(activity, R.color.colorOnSurfaceVariant))
            setPadding(0, pad(activity, 8), 0, pad(activity, 14))
        })
        column.addView(TextView(activity).apply {
            text = report
            textSize = 11f
            setTextColor(ContextCompat.getColor(activity, R.color.colorOnSurface))
            typeface = Typeface.MONOSPACE
            setTextIsSelectable(true)
        })

        val copy = action(activity, R.string.safe_copy) {
            copyToClipboard(activity, report)
            it.setText(R.string.safe_copied)
        }
        column.addView(copy, buttonParams(activity))

        column.addView(action(activity, R.string.safe_share) { share(activity, report) }, buttonParams(activity))

        if (onContinue != null) {
            column.addView(action(activity, R.string.safe_continue) { onContinue() }, buttonParams(activity))
        }

        column.addView(action(activity, R.string.safe_restart) {
            // Полный перезапуск процесса: если сломалось состояние в памяти, «ещё раз» должно
            // начинаться с чистого листа, а не с того же места.
            val intent = activity.packageManager.getLaunchIntentForPackage(activity.packageName)
            if (intent != null) {
                intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK)
                runCatching { activity.startActivity(intent) }
            }
            activity.finish()
            Runtime.getRuntime().exit(0)
        }, buttonParams(activity))

        val scroll = ScrollView(activity).apply {
            setBackgroundColor(ContextCompat.getColor(activity, R.color.colorSurface))
            addView(column)
        }
        runCatching { activity.setContentView(scroll) }
    }

    /**
     * Кнопка без Material: TextView с фоном-плашкой. Обычный `android.widget.Button` берёт стиль из
     * темы, а тема — ровно то, что могло не загрузиться; здесь только шрифт, цвет и прямоугольник.
     */
    private fun action(activity: Activity, labelRes: Int, onClick: (TextView) -> Unit): TextView =
        TextView(activity).apply {
            setText(labelRes)
            textSize = 15f
            gravity = Gravity.CENTER
            setTextColor(ContextCompat.getColor(activity, R.color.colorOnPrimary))
            setPadding(pad(activity, 12), pad(activity, 14), pad(activity, 12), pad(activity, 14))
            background = GradientDrawable().apply {
                cornerRadius = pad(activity, 10).toFloat()
                setColor(ContextCompat.getColor(activity, R.color.colorPrimary))
            }
            isClickable = true
            isFocusable = true
            setOnClickListener { onClick(this) }
        }

    /** Первая строка ошибки — для журнала: целиком стек там не нужен, он уже в crashes.txt. */
    fun describe(error: Throwable): String =
        error.javaClass.simpleName + (error.message?.let { ": " + it.take(200) } ?: "")

    private fun copyToClipboard(activity: Activity, text: String) {
        runCatching {
            val cm = activity.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
            cm.setPrimaryClip(ClipData.newPlainText("WarpScout", text))
        }
    }

    private fun share(activity: Activity, text: String) {
        runCatching {
            val send = Intent(Intent.ACTION_SEND).apply {
                type = "text/plain"
                putExtra(Intent.EXTRA_TEXT, text)
            }
            activity.startActivity(Intent.createChooser(send, activity.getString(R.string.safe_share)))
        }
    }

    private fun buttonParams(activity: Activity) = LinearLayout.LayoutParams(
        LinearLayout.LayoutParams.MATCH_PARENT,
        LinearLayout.LayoutParams.WRAP_CONTENT
    ).apply { topMargin = pad(activity, 12) }

    /** dp → px без ресурсов: аварийный экран не должен зависеть от того, что могло не загрузиться. */
    private fun pad(activity: Activity, dp: Int): Int =
        (dp * activity.resources.displayMetrics.density).toInt()
}
