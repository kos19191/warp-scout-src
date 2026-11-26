package dev.warpscout.app

import android.content.Context
import android.graphics.drawable.Drawable
import android.util.TypedValue
import androidx.core.content.ContextCompat

/**
 * Дизайн приложения. С 1.10.49-beta7 — «Премиум» (по умолчанию) и «Классический» (прежний вид), с
 * 1.10.49-beta8 ещё «Нежный» (светлая пастель, шесть цветов на выбор) и «Стекло» (неоновое стекло,
 * пять сочетаний). Выбор — «Настройки» → «Оформление»: «Дизайн», «Цвет» (у «Нежного» и «Стекла») и
 * «Тема» — светлая или тёмная, она действует во всех дизайнах.
 *
 * Разметка у дизайнов общая: облик карточек, панели вкладок и заголовков даёт тема окна (attrs.xml),
 * а то, что код рисует сам — кнопку, фон, схему маршрута, значки, — берёт цвета из той же темы через
 * [look]. «Премиум», «Нежный» и «Стекло» устроены одинаково (кнопка-кольцо, карточка маршрута, значки
 * вкладок), отличаются цветами, кнопкой ([PremiumOrbPainter], [SoftOrbPainter], [GlassOrbPainter]) и
 * фоном ([PremiumBackdrop], [DesignBackdrop]).
 */
object Design {

    /** Оттенок «Нежного» или «Стекла»: название, тема окна и цвета кружка в «Оформлении». */
    class Tone(val name: Int, val theme: Int, val welcome: Int, val swatch: IntArray)

    val SOFT_TONES = listOf(
        Tone(R.string.tone_lavender, R.style.Theme_WarpScout_Soft_Lavender, R.style.Theme_WarpScout_Soft_Lavender_Welcome, intArrayOf(0xFFC9B8F2.toInt())),
        Tone(R.string.tone_mint, R.style.Theme_WarpScout_Soft_Mint, R.style.Theme_WarpScout_Soft_Mint_Welcome, intArrayOf(0xFFA9E4D0.toInt())),
        Tone(R.string.tone_peach, R.style.Theme_WarpScout_Soft_Peach, R.style.Theme_WarpScout_Soft_Peach_Welcome, intArrayOf(0xFFFFCAB0.toInt())),
        Tone(R.string.tone_sky, R.style.Theme_WarpScout_Soft_Sky, R.style.Theme_WarpScout_Soft_Sky_Welcome, intArrayOf(0xFFB3D1F6.toInt())),
        Tone(R.string.tone_rose, R.style.Theme_WarpScout_Soft_Rose, R.style.Theme_WarpScout_Soft_Rose_Welcome, intArrayOf(0xFFF6BED2.toInt())),
        Tone(R.string.tone_vanilla, R.style.Theme_WarpScout_Soft_Vanilla, R.style.Theme_WarpScout_Soft_Vanilla_Welcome, intArrayOf(0xFFF2DE9A.toInt())),
    )

    val GLASS_TONES = listOf(
        Tone(R.string.tone_cyber, R.style.Theme_WarpScout_Glass_Cyber, R.style.Theme_WarpScout_Glass_Cyber_Welcome, intArrayOf(0xFF22E1FF.toInt(), 0xFFFF3DF2.toInt())),
        Tone(R.string.tone_aurora, R.style.Theme_WarpScout_Glass_Aurora, R.style.Theme_WarpScout_Glass_Aurora_Welcome, intArrayOf(0xFF3DFFB0.toInt(), 0xFF4D8DFF.toInt())),
        Tone(R.string.tone_sunset, R.style.Theme_WarpScout_Glass_Sunset, R.style.Theme_WarpScout_Glass_Sunset_Welcome, intArrayOf(0xFFFF4D8D.toInt(), 0xFFFFB443.toInt())),
        Tone(R.string.tone_violet, R.style.Theme_WarpScout_Glass_Violet, R.style.Theme_WarpScout_Glass_Violet_Welcome, intArrayOf(0xFFA066FF.toInt(), 0xFF38CFFF.toInt())),
        Tone(R.string.tone_acid, R.style.Theme_WarpScout_Glass_Acid, R.style.Theme_WarpScout_Glass_Acid_Welcome, intArrayOf(0xFFC8FF3D.toInt(), 0xFF2BF5D0.toInt())),
    )

    /** Название дизайна для журнала и подписей. */
    fun nameOf(kind: Int): Int = when (kind) {
        Prefs.DESIGN_CLASSIC -> R.string.design_classic
        Prefs.DESIGN_SOFT -> R.string.design_soft
        Prefs.DESIGN_GLASS -> R.string.design_glass
        else -> R.string.design_premium
    }

    /** Оттенки дизайна; null — у дизайна выбора цвета нет («Премиум» только оранжевый, «Классический» как был). */
    fun tones(kind: Int): List<Tone>? = when (kind) {
        Prefs.DESIGN_SOFT -> SOFT_TONES
        Prefs.DESIGN_GLASS -> GLASS_TONES
        else -> null
    }

    /** Выбранный оттенок дизайна [kind]. */
    fun toneIndex(prefs: Prefs, kind: Int): Int = when (kind) {
        Prefs.DESIGN_SOFT -> prefs.softTone
        Prefs.DESIGN_GLASS -> prefs.glassTone
        else -> 0
    }

    /**
     * Выбранный дизайн. Настройки не прочитались — классический, как и тема главного экрана в этом
     * случае (MainActivity.onCreate): окна поверх него не должны оказаться в другом дизайне.
     */
    fun kind(context: Context): Int = runCatching { Prefs(context).design }.getOrDefault(Prefs.DESIGN_CLASSIC)

    /**
     * Новый облик — «Премиум», «Нежный» или «Стекло» (кнопка-кольцо, карточка маршрута, значки
     * вкладок). Ложь — «Классический».
     */
    fun premium(context: Context): Boolean = kind(context) != Prefs.DESIGN_CLASSIC

    /** Тема главного экрана для дизайна [kind] (с выбранным оттенком). */
    fun theme(context: Context, kind: Int): Int {
        val prefs = runCatching { Prefs(context) }.getOrNull()
        return when (kind) {
            Prefs.DESIGN_PREMIUM -> R.style.Theme_WarpScout_Premium
            Prefs.DESIGN_SOFT -> SOFT_TONES[(prefs?.softTone ?: 0).coerceIn(0, SOFT_TONES.size - 1)].theme
            Prefs.DESIGN_GLASS -> GLASS_TONES[(prefs?.glassTone ?: 0).coerceIn(0, GLASS_TONES.size - 1)].theme
            else -> R.style.Theme_WarpScout
        }
    }

    /** Тема окна во весь экран (начальные экраны, «Маршрут») для выбранного дизайна. */
    fun fullScreenTheme(context: Context): Int {
        val kind = kind(context)
        val prefs = runCatching { Prefs(context) }.getOrNull()
        return when (kind) {
            Prefs.DESIGN_PREMIUM -> R.style.Theme_WarpScout_Premium_Welcome
            Prefs.DESIGN_SOFT -> SOFT_TONES[(prefs?.softTone ?: 0).coerceIn(0, SOFT_TONES.size - 1)].welcome
            Prefs.DESIGN_GLASS -> GLASS_TONES[(prefs?.glassTone ?: 0).coerceIn(0, GLASS_TONES.size - 1)].welcome
            else -> R.style.Theme_WarpScout_Welcome
        }
    }

    /** Фон экрана нового облика (неподвижный, со свечением за кнопкой); null — у классического своего фона нет. */
    fun backdrop(context: Context, kind: Int): Drawable? = when (kind) {
        Prefs.DESIGN_PREMIUM -> PremiumBackdrop(context)
        Prefs.DESIGN_SOFT, Prefs.DESIGN_GLASS -> DesignBackdrop(context, kind)
        else -> null
    }

    /**
     * Цвета, которые код рисует сам, — из темы [context] (attrs.xml: wsAccent, wsDiscA…). Каждая тема их
     * задаёт: классическая — прежними классическими, «Премиум» — премиум-цветами, оттенки «Нежного» и
     * «Стекла» — своими (tools/design_palettes.py).
     */
    class Look(
        val accent: Int,
        val accentDeep: Int,
        val accentLight: Int,
        val partner: Int,
        val neonA: Int,
        val neonB: Int,
        val onSurface: Int,
        val onSurfaceVariant: Int,
        val outline: Int,
        val error: Int,
        val blue: Int,
        val bg0: Int,
        val bg1: Int,
        val discA: Int,
        val discB: Int,
        val ringOff: Int,
        val core: Int,
        val mapBg: Int,
        val mapBlock: Int,
        val mapRoad: Int,
        val routeCore: Int,
        val dark: Boolean,
    )

    fun look(context: Context): Look {
        fun c(res: Int) = ContextCompat.getColor(context, res)
        fun a(attr: Int, fallback: Int): Int {
            val tv = TypedValue()
            if (!runCatching { context.theme.resolveAttribute(attr, tv, true) }.getOrDefault(false)) return fallback
            return when {
                tv.type >= TypedValue.TYPE_FIRST_COLOR_INT && tv.type <= TypedValue.TYPE_LAST_COLOR_INT -> tv.data
                tv.resourceId != 0 -> runCatching { ContextCompat.getColor(context, tv.resourceId) }.getOrDefault(fallback)
                else -> fallback
            }
        }
        val dark = (context.resources.configuration.uiMode and android.content.res.Configuration.UI_MODE_NIGHT_MASK) ==
            android.content.res.Configuration.UI_MODE_NIGHT_YES
        return Look(
            accent = a(R.attr.wsAccent, c(R.color.prem_accent)),
            accentDeep = a(R.attr.wsAccentDeep, c(R.color.prem_accent_deep)),
            accentLight = a(R.attr.wsAccentLight, c(R.color.prem_accent_light)),
            partner = a(R.attr.wsPartner, c(R.color.prem_accent_light)),
            neonA = a(R.attr.wsNeonA, c(R.color.prem_accent)),
            neonB = a(R.attr.wsNeonB, c(R.color.prem_accent_light)),
            onSurface = a(R.attr.wsOnSurface, c(R.color.prem_on_surface)),
            onSurfaceVariant = a(R.attr.wsOnSurfaceVariant, c(R.color.prem_on_surface_variant)),
            outline = a(R.attr.wsOutline, c(R.color.prem_outline)),
            error = a(R.attr.wsError, c(R.color.prem_error)),
            blue = a(R.attr.wsBlue, c(R.color.prem_blue)),
            bg0 = a(R.attr.wsBg0, c(R.color.prem_bg0)),
            bg1 = a(R.attr.wsBg1, c(R.color.prem_bg1)),
            discA = a(R.attr.wsDiscA, c(R.color.prem_disc_a)),
            discB = a(R.attr.wsDiscB, c(R.color.prem_disc_b)),
            ringOff = a(R.attr.wsRingOff, c(R.color.prem_ring_off)),
            core = a(R.attr.wsCore, c(R.color.prem_core)),
            mapBg = a(R.attr.wsMapBg, c(R.color.prem_map_bg)),
            mapBlock = a(R.attr.wsMapBlock, c(R.color.prem_map_bg)),
            mapRoad = a(R.attr.wsMapRoad, c(R.color.prem_map_road)),
            routeCore = a(R.attr.wsRouteCore, c(R.color.prem_core)),
            dark = dark,
        )
    }

    /**
     * Цвет классической темы, который код задаёт сам (подписи, текстовые кнопки), — в новом облике его
     * оттенок того же назначения из [look]. Остальные (зелёный «работает», красный «ошибка»…) общие.
     */
    fun lookColor(look: Look, res: Int, classic: Int): Int = when (res) {
        R.color.colorPrimary -> look.accent
        R.color.colorOnSurface -> look.onSurface
        R.color.colorOnSurfaceVariant -> look.onSurfaceVariant
        R.color.colorOutline -> look.outline
        else -> classic
    }

    /** [lookColor] по теме окна [context] — для окон, у которых нет своего признака. */
    fun color(context: Context, res: Int): Int {
        val classic = ContextCompat.getColor(context, res)
        return if (premium(context)) lookColor(look(context), res, classic) else classic
    }

    /** Цвета, которые код задаёт сам (подписи экрана «Маршрут», плашки состояния). */
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

    /** Палитра по теме [context]: у каждого дизайна — свои цвета (см. [look]). */
    fun palette(context: Context): Palette {
        val l = look(context)
        return Palette(
            accent = l.accent, accentLight = l.accentLight, onSurface = l.onSurface, onSurfaceVariant = l.onSurfaceVariant,
            outline = l.outline, error = l.error, blue = l.blue,
            ok = ContextCompat.getColor(context, R.color.check_ok), warn = ContextCompat.getColor(context, R.color.state_warn),
        )
    }
}
