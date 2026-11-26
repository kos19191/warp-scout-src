package dev.warpscout.app

import android.content.Context
import android.content.res.Configuration
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.ColorFilter
import android.graphics.LinearGradient
import android.graphics.Paint
import android.graphics.Path
import android.graphics.PixelFormat
import android.graphics.RadialGradient
import android.graphics.Rect
import android.graphics.Shader
import android.graphics.drawable.Drawable
import androidx.core.content.ContextCompat

/**
 * Фон экрана в дизайне «Премиум» (с 1.10.49-beta7): тёплая темнота, оранжевое свечение за главной
 * кнопкой и тонкие диагональные линии с плоскостями по краям — как на макете, который выбрал человек.
 *
 * Неподвижный: рисуется заново только при смене размера или места свечения, поэтому батарею не
 * тратит. Линии и свечение у кнопки построены относительно её центра и при прокрутке только
 * сдвигаются — заново ничего не строится. [glowY] — где по высоте центр свечения (центр кнопки упрощённого экрана); [calm] — спокойный
 * вариант для расширенного вида и экрана маршрута: свечение сверху и пара линий по краям.
 */
class PremiumBackdrop(private val context: Context) : Drawable() {

    private fun c(res: Int) = ContextCompat.getColor(context, res)
    private val bg0 = c(R.color.prem_bg0)
    private val bg1 = c(R.color.prem_bg1)
    private val acc = c(R.color.prem_accent)
    private val dark = (context.resources.configuration.uiMode and Configuration.UI_MODE_NIGHT_MASK) ==
        Configuration.UI_MODE_NIGHT_YES
    private val density = context.resources.displayMetrics.density

    private val paint = Paint(Paint.ANTI_ALIAS_FLAG)
    private var builtFor = ""

    /** Центр свечения по высоте, px от верха; меньше нуля — 36 % высоты. */
    var glowY: Float = -1f
        set(value) {
            if (kotlin.math.abs(field - value) < 0.5f) return
            field = value
            if (!calm) invalidateSelf()
        }

    var calm: Boolean = false
        set(value) {
            if (field == value) return
            field = value
            builtFor = ""
            invalidateSelf()
        }

    private class Item(val shader: Shader, val path: Path?, val strokeWidth: Float, val x0: Float, val y0: Float, val x1: Float, val y1: Float)

    /** Линии и плоскости у кнопки — от её центра (y = 0), в кадре сдвигаются на [glowY]. */
    private val items = ArrayList<Item>()

    /** То, что стоит на месте: углы сверху; в спокойном варианте — всё. */
    private val fixed = ArrayList<Item>()
    private var into = items
    private var base: Shader? = null
    private var glow: Shader? = null
    private var vignette: Shader? = null

    private fun withAlpha(color: Int, a: Float): Int =
        Color.argb((255 * a.coerceIn(0f, 1f)).toInt(), Color.red(color), Color.green(color), Color.blue(color))

    private fun line(x0: Float, y0: Float, x1: Float, y1: Float, a: Float, glowLine: Boolean) {
        val colors = intArrayOf(withAlpha(acc, 0f), withAlpha(acc, a), withAlpha(acc, a * 0.8f), withAlpha(acc, 0f))
        val stops = floatArrayOf(0f, 0.45f, 0.6f, 1f)
        if (glowLine) {
            val soft = intArrayOf(withAlpha(acc, 0f), withAlpha(acc, a * 0.16f), withAlpha(acc, a * 0.13f), withAlpha(acc, 0f))
            into += Item(LinearGradient(x0, y0, x1, y1, soft, stops, Shader.TileMode.CLAMP), null, 9f * density, x0, y0, x1, y1)
        }
        into += Item(LinearGradient(x0, y0, x1, y1, colors, stops, Shader.TileMode.CLAMP), null, 1.2f * density, x0, y0, x1, y1)
    }

    private fun plane(points: FloatArray, a: Float, gx0: Float, gy0: Float, gx1: Float, gy1: Float) {
        val p = Path()
        p.moveTo(points[0], points[1])
        var i = 2
        while (i < points.size) {
            p.lineTo(points[i], points[i + 1])
            i += 2
        }
        p.close()
        into += Item(LinearGradient(gx0, gy0, gx1, gy1, withAlpha(acc, a), withAlpha(acc, 0f), Shader.TileMode.CLAMP), p, 0f, 0f, 0f, 0f, 0f)
    }

    private fun build(b: Rect) {
        val key = "${b.width()}x${b.height()}:$calm"
        if (key == builtFor) return
        builtFor = key
        items.clear()
        fixed.clear()
        val w = b.width().toFloat()
        val h = b.height().toFloat()
        if (w <= 0f || h <= 0f) return
        base = LinearGradient(0f, 0f, 0f, h, intArrayOf(bg1, bg0, bg1), floatArrayOf(0f, 0.55f, 1f), Shader.TileMode.CLAMP)
        // У кнопки — от её центра (сдвиг в кадре), в спокойном варианте — от верха экрана.
        val cy = if (calm) h * 0.08f else 0f
        into = if (calm) fixed else items
        glow = RadialGradient(
            w / 2f, cy, w * (if (calm) 0.9f else 0.85f),
            intArrayOf(withAlpha(acc, if (dark) 0.13f else 0.08f), withAlpha(acc, if (dark) 0.045f else 0.03f), withAlpha(acc, 0f)),
            floatArrayOf(0f, 0.5f, 1f), Shader.TileMode.CLAMP
        )
        val a = if (dark) 0.55f else 0.32f
        val pa = if (dark) 0.05f else 0.035f
        if (!calm) {
            // Плоскости по краям — лёгкий объём, как на макете.
            plane(floatArrayOf(0f, cy - w * 0.2f, w * 0.32f, cy + w * 0.12f, 0f, cy + w * 0.45f), pa, 0f, cy, w * 0.3f, cy)
            plane(floatArrayOf(w, cy - w * 0.2f, w * 0.68f, cy + w * 0.12f, w, cy + w * 0.45f), pa, w, cy, w * 0.7f, cy)
            into = fixed
            val top = h * 0.2f
            plane(floatArrayOf(0f, 0f, w * 0.45f, 0f, 0f, top), pa * 0.8f, 0f, 0f, w * 0.2f, top * 0.55f)
            plane(floatArrayOf(w, 0f, w * 0.55f, 0f, w, top), pa * 0.8f, w, 0f, w * 0.8f, top * 0.55f)
            into = items
            // Крест за верхом кнопки и «галочка» к низу экрана.
            line(-w * 0.05f, cy - w * 0.62f, w * 0.62f, cy + w * 0.05f, a, dark)
            line(w * 1.05f, cy - w * 0.62f, w * 0.38f, cy + w * 0.05f, a, dark)
            line(-w * 0.02f, cy + w * 0.05f, w * 0.42f, cy + w * 0.55f, a * 0.75f, dark)
            line(w * 1.02f, cy + w * 0.05f, w * 0.58f, cy + w * 0.55f, a * 0.75f, dark)
            // Низ экрана — на месте.
            into = fixed
            line(-w * 0.05f, h * 0.86f, w * 0.4f, h * 0.7f, a * 0.45f, false)
            line(w * 1.05f, h * 0.86f, w * 0.6f, h * 0.7f, a * 0.45f, false)
            into = items
        } else {
            line(-w * 0.1f, h * 0.02f, w * 0.55f, h * 0.2f, a * 0.6f, dark)
            line(w * 1.1f, h * 0.02f, w * 0.45f, h * 0.2f, a * 0.6f, dark)
            plane(floatArrayOf(0f, 0f, w * 0.5f, 0f, 0f, h * 0.18f), pa, 0f, 0f, w * 0.3f, h * 0.1f)
            plane(floatArrayOf(w, 0f, w * 0.5f, 0f, w, h * 0.18f), pa, w, 0f, w * 0.7f, h * 0.1f)
        }
        vignette = RadialGradient(
            w / 2f, h * 0.45f, maxOf(w, h) * 0.8f,
            intArrayOf(Color.TRANSPARENT, Color.TRANSPARENT, if (dark) Color.argb(115, 0, 0, 0) else Color.argb(15, 120, 70, 30)),
            floatArrayOf(0f, (minOf(w, h) * 0.35f) / (maxOf(w, h) * 0.8f), 1f), Shader.TileMode.CLAMP
        )
    }

    override fun draw(canvas: Canvas) {
        val b = bounds
        build(b)
        val w = b.width().toFloat()
        val h = b.height().toFloat()
        if (w <= 0f || h <= 0f) return
        canvas.save()
        canvas.translate(b.left.toFloat(), b.top.toFloat())
        paint.style = Paint.Style.FILL
        paint.shader = base
        canvas.drawRect(0f, 0f, w, h, paint)
        drawItems(canvas, fixed)
        // Свечение и линии у кнопки — сдвигом к её центру.
        val shift = if (calm) 0f else if (glowY >= 0f) glowY else h * 0.36f
        canvas.save()
        canvas.translate(0f, shift)
        paint.style = Paint.Style.FILL
        paint.shader = glow
        canvas.drawRect(0f, -shift, w, h - shift, paint)
        drawItems(canvas, items)
        canvas.restore()
        paint.style = Paint.Style.FILL
        paint.shader = vignette
        canvas.drawRect(0f, 0f, w, h, paint)
        paint.shader = null
        canvas.restore()
    }

    private fun drawItems(canvas: Canvas, list: List<Item>) {
        for (it in list) {
            paint.shader = it.shader
            if (it.path != null) {
                paint.style = Paint.Style.FILL
                canvas.drawPath(it.path, paint)
            } else {
                paint.style = Paint.Style.STROKE
                paint.strokeWidth = it.strokeWidth
                paint.strokeCap = Paint.Cap.ROUND
                canvas.drawLine(it.x0, it.y0, it.x1, it.y1, paint)
            }
        }
    }

    override fun onBoundsChange(bounds: Rect) {
        super.onBoundsChange(bounds)
        builtFor = ""
    }

    override fun setAlpha(alpha: Int) {}
    override fun setColorFilter(colorFilter: ColorFilter?) {}

    @Deprecated("Deprecated in Java")
    override fun getOpacity(): Int = PixelFormat.OPAQUE
}
