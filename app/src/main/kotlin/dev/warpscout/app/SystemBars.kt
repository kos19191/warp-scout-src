package dev.warpscout.app

import android.view.View
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat

/**
 * Отступы от системных панелей (с 1.10.47): строки состояния сверху (часы, заряд, значки), выреза
 * камеры, панели навигации снизу (три кнопки или полоска жестов) и клавиатуры.
 *
 * Экраны WarpScout рассчитаны на место между панелями, и обычно Android сам ставит окно туда — на
 * Android 15–16 благодаря `windowOptOutEdgeToEdgeEnforcement` в теме. Но на части телефонов окно всё
 * равно ложится под панели («edge-to-edge»): тогда часы и значки оказываются поверх строки статуса
 * туннеля, а кнопки навигации — поверх вкладок. Поэтому отступ берётся из того, что система сообщила
 * самому окну: где окно уже стоит между панелями, сюда приходят нули и разметка не меняется; где
 * легло под них — содержимое сдвигается ровно на высоту панели (и выреза, если он больше).
 */
object SystemBars {

    /**
     * Держать содержимое [view] вне системных панелей и выреза камеры, а снизу — ещё и над
     * клавиатурой, если окно под неё не поджалось само ([ime]). Отступы из разметки сохраняются:
     * системный прибавляется к ним. Вызывать один раз, на корневом view окна.
     */
    fun keepClear(view: View, ime: Boolean = true) {
        val start = view.paddingStart
        val top = view.paddingTop
        val end = view.paddingEnd
        val bottom = view.paddingBottom
        ViewCompat.setOnApplyWindowInsetsListener(view) { v, insets ->
            val bars = insets.getInsets(WindowInsetsCompat.Type.systemBars() or WindowInsetsCompat.Type.displayCutout())
            val keyboard = if (ime) insets.getInsets(WindowInsetsCompat.Type.ime()).bottom else 0
            val rtl = v.layoutDirection == View.LAYOUT_DIRECTION_RTL
            val startBar = if (rtl) bars.right else bars.left
            val endBar = if (rtl) bars.left else bars.right
            v.setPaddingRelative(
                start + startBar,
                top + bars.top,
                end + endBar,
                bottom + maxOf(bars.bottom, keyboard),
            )
            insets
        }
        // Если окно уже показано и отступы ему разосланы, без запроса новый слушатель их не получит.
        if (view.isAttachedToWindow) view.requestApplyInsets()
    }
}
