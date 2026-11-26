package dev.warpscout.app

import android.content.Context
import androidx.core.content.ContextCompat

/**
 * Дизайн приложения (с 1.10.49-beta7): «Премиум» (по умолчанию) или «Классический» — прежний вид.
 * Выбор — «Настройки» → «Оформление» → «Дизайн»; светлая или тёмная тема выбирается отдельно и
 * действует в обоих дизайнах.
 *
 * Разметка у дизайнов общая: облик карточек, панели вкладок и заголовков даёт тема
 * (Theme.WarpScout / Theme.WarpScout.Premium, см. attrs.xml), а здесь — то немногое, что код рисует
 * сам: цвета кнопки, экрана маршрута, значков.
 */
object Design {

    /**
     * Выбран «Премиум» (по умолчанию — да, см. [Prefs.design]). Настройки не прочитались — классический,
     * как и тема главного экрана в этом случае (MainActivity.onCreate): окна поверх него не должны
     * оказаться в другом дизайне.
     */
    fun premium(context: Context): Boolean =
        runCatching { Prefs(context).design == Prefs.DESIGN_PREMIUM }.getOrDefault(false)

    /** Тема окна во весь экран (начальные экраны, «Маршрут») для выбранного дизайна. */
    fun fullScreenTheme(context: Context): Int =
        if (premium(context)) R.style.Theme_WarpScout_Premium_Welcome else R.style.Theme_WarpScout_Welcome

    /**
     * Цвет классической темы, который код задаёт сам (подписи, текстовые кнопки), — в «Премиуме» его
     * оттенок того же назначения. Остальные (зелёный «работает», красный «ошибка»…) общие.
     */
    fun premiumOf(res: Int): Int = when (res) {
        R.color.colorPrimary -> R.color.prem_accent
        R.color.colorOnSurface -> R.color.prem_on_surface
        R.color.colorOnSurfaceVariant -> R.color.prem_on_surface_variant
        R.color.colorOutline -> R.color.prem_outline
        else -> res
    }

    /** [premiumOf] по выбранному дизайну — для окон, у которых нет своего признака. */
    fun color(context: Context, res: Int): Int =
        ContextCompat.getColor(context, if (premium(context)) premiumOf(res) else res)

    /** Цвета, которые код задаёт сам. */
    class Palette(
        val accent: Int,
        val accentLight: Int,
        val onSurface: Int,
        val onSurfaceVariant: Int,
        val outline: Int,
        val error: Int,
        val blue: Int,
        val ok: Int,
        val warn: Int,
    )

    fun palette(context: Context, premium: Boolean): Palette {
        fun c(res: Int) = ContextCompat.getColor(context, res)
        return if (premium) {
            Palette(
                accent = c(R.color.prem_accent), accentLight = c(R.color.prem_accent_light),
                onSurface = c(R.color.prem_on_surface), onSurfaceVariant = c(R.color.prem_on_surface_variant),
                outline = c(R.color.prem_outline), error = c(R.color.prem_error), blue = c(R.color.prem_blue),
                ok = c(R.color.check_ok), warn = c(R.color.state_warn),
            )
        } else {
            Palette(
                accent = c(R.color.colorPrimary), accentLight = c(R.color.orb_accent),
                onSurface = c(R.color.colorOnSurface), onSurfaceVariant = c(R.color.colorOnSurfaceVariant),
                outline = c(R.color.colorOutline), error = c(R.color.colorError), blue = c(R.color.prem_blue),
                ok = c(R.color.check_ok), warn = c(R.color.state_warn),
            )
        }
    }
}
