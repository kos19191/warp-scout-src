package dev.warpscout.app

import android.content.Context
import android.graphics.Bitmap
import android.graphics.BitmapShader
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
import kotlin.math.PI
import kotlin.math.max
import kotlin.math.min
import kotlin.math.pow
import kotlin.math.sin

/**
 * Фон экрана нового облика со свечением за главной кнопкой (с 1.10.49-beta8 его рисуют два класса:
 * [PremiumBackdrop] и [DesignBackdrop]). [glowY] — где по высоте центр кнопки упрощённого экрана;
 * [calm] — спокойный вариант для расширенного вида и экрана маршрута.
 */
interface GlowBackdrop {
    var glowY: Float
    var calm: Boolean
}

/**
 * Фон «Нежного» и «Стекла» (с 1.10.49-beta8), как в макете, который выбрал человек:
 *
 *  - «Нежный» — светлая пастель: мягкие пятна цвета и цвета-напарника, как акварель, внизу две плавные
 *    волны и несколько тихих кружков; в тёмной теме те же пятна, приглушённые;
 *  - «Стекло» — глубокий тёмный фон с двумя неоновыми пятнами (их свет виден сквозь полупрозрачные
 *    карточки), тонкая сетка точек и перспективная сетка у низа; в светлой теме — те же пятна на светлом.
 *
 * Неподвижный, как и фон «Премиума»: рисуется заново только при смене размера или места свечения,
 * пятна у кнопки при прокрутке только сдвигаются — заново ничего не строится. Цвета — из темы оттенка
 * ([Design.look]).
 */
class DesignBackdrop(context: Context, kind: Int) : Drawable(), GlowBackdrop {

    private val look = Design.look(context)
    private val soft = kind == Prefs.DESIGN_SOFT
    private val dark = look.dark
    private val density = context.resources.displayMetrics.density
    private val c1 = look.neonA
    private val c2 = look.neonB

    private val paint = Paint(Paint.ANTI_ALIAS_FLAG)
    private var builtFor = ""

    override var glowY: Float = -1f
        set(value) {
            if (kotlin.math.abs(field - value) < 0.5f) return
            field = value
            if (!calm) invalidateSelf()
        }

    override var calm: Boolean = false
        set(value) {
            if (field == value) return
            field = value
            builtFor = ""
            invalidateSelf()
        }

    private class Blob(val shader: Shader, val x: Float, val y: Float, val r: Float)
    private class Ring(val x: Float, val y: Float, val r: Float, val color: Int, val stroke: Boolean)

    /** Пятна у кнопки — от её центра (y = 0), в кадре сдвигаются на [glowY]. */
    private val items = ArrayList<Blob>()
    private val fixed = ArrayList<Blob>()
    private val waves = ArrayList<Pair<Path, Shader>>()
    private val rings = ArrayList<Ring>()
    private var base: Shader? = null
    private var dots: Shader? = null
    private var dotTile: Bitmap? = null
    private var grid: Path? = null
    private var gridShader: Shader? = null
    private var vignette: Shader? = null

    private fun withAlpha(color: Int, a: Float): Int =
        Color.argb((255 * a.coerceIn(0f, 1f)).toInt(), Color.red(color), Color.green(color), Color.blue(color))

    private fun blob(into: ArrayList<Blob>, x: Float, y: Float, r: Float, c: Int, a: Float) {
        val shader = RadialGradient(
            x, y, r, intArrayOf(withAlpha(c, a), withAlpha(c, a * 0.45f), withAlpha(c, 0f)),
            floatArrayOf(0f, 0.55f, 1f), Shader.TileMode.CLAMP
        )
        into += Blob(shader, x, y, r)
    }

    private fun build(b: Rect) {
        val key = "${b.width()}x${b.height()}:$calm"
        if (key == builtFor) return
        builtFor = key
        items.clear()
        fixed.clear()
        waves.clear()
        rings.clear()
        grid = null
        gridShader = null
        vignette = null
        val w = b.width().toFloat()
        val h = b.height().toFloat()
        if (w <= 0f || h <= 0f) return
        if (soft) buildSoft(w, h) else buildGlass(w, h)
    }

    private fun buildSoft(w: Float, h: Float) {
        base = LinearGradient(0f, 0f, w * 0.3f, h, intArrayOf(look.bg1, look.bg0, look.bg1), floatArrayOf(0f, 0.5f, 1f), Shader.TileMode.CLAMP)
        val k = if (dark) 0.32f else 1f
        if (!calm) {
            blob(items, w * 0.12f, -w * 0.55f, w * 0.75f, c1, 0.55f * k)
            blob(items, w * 0.95f, -w * 0.05f, w * 0.62f, c2, 0.5f * k)
            blob(items, w * 0.5f, 0f, w * 0.55f, c1, 0.28f * k)
            blob(fixed, w * 0.05f, h * 0.82f, w * 0.6f, c2, 0.32f * k)
        } else {
            blob(fixed, w * 0.1f, -w * 0.1f, w * 0.7f, c1, 0.5f * k)
            blob(fixed, w * 0.95f, h * 0.12f, w * 0.55f, c2, 0.38f * k)
            blob(fixed, w * 0.8f, h * 0.9f, w * 0.6f, c1, 0.25f * k)
        }
        // Волны у низа экрана.
        fun wave(y0: Float, amp: Float, c: Int, a: Float, ph: Float) {
            val p = Path()
            p.moveTo(0f, h)
            var x = 0f
            val step = 6f * density
            while (x <= w + step) {
                val xx = min(x, w)
                val y = y0 + sin(xx / w * PI.toFloat() * 2f + ph) * amp + sin(xx / w * PI.toFloat() * 5f + ph * 2f) * amp * 0.25f
                p.lineTo(xx, y)
                x += step
            }
            p.lineTo(w, h)
            p.close()
            waves += p to LinearGradient(0f, y0 - amp, 0f, h, withAlpha(c, a), withAlpha(c, a * 0.2f), Shader.TileMode.CLAMP)
        }
        wave(h * 0.86f, 14f * density, c1, 0.30f * k, 0.6f)
        wave(h * 0.90f, 12f * density, c2, 0.26f * k, 2.4f)
        // Тихие кружки — всегда на тех же местах.
        val rnd = java.util.Random(if (calm) 11L else 7L)
        repeat(9) {
            val x = rnd.nextFloat() * w
            val y = rnd.nextFloat() * h * 0.8f
            val r = (3f + rnd.nextFloat() * 9f) * density
            val c = if (rnd.nextFloat() < 0.5f) c1 else c2
            rings += Ring(x, y, r, withAlpha(c, (if (dark) 0.16f else 0.45f) * (0.5f + rnd.nextFloat() * 0.5f)), false)
            if (rnd.nextFloat() < 0.4f) {
                rings += Ring(x, y, r + (5f + rnd.nextFloat() * 6f) * density, withAlpha(c, if (dark) 0.22f else 0.6f), true)
            }
        }
    }

    private fun buildGlass(w: Float, h: Float) {
        base = LinearGradient(0f, 0f, 0f, h, intArrayOf(look.bg1, look.bg0, look.bg1), floatArrayOf(0f, 0.5f, 1f), Shader.TileMode.CLAMP)
        val k = if (dark) 1f else 0.62f
        if (!calm) {
            blob(items, w * 0.08f, -w * 0.42f, w * 0.78f, c1, 0.42f * k)
            blob(items, w * 0.98f, w * 0.28f, w * 0.74f, c2, 0.40f * k)
            blob(fixed, w * 0.2f, h * 0.92f, w * 0.6f, c2, 0.22f * k)
            blob(fixed, w * 0.92f, h * 0.78f, w * 0.42f, c1, 0.16f * k)
        } else {
            blob(fixed, w * 0.05f, -w * 0.05f, w * 0.75f, c1, 0.36f * k)
            blob(fixed, w * 1.0f, h * 0.22f, w * 0.62f, c2, 0.30f * k)
            blob(fixed, w * 0.3f, h * 0.95f, w * 0.6f, c2, 0.18f * k)
        }
        // Сетка точек — одной плиткой, а не сотнями квадратиков.
        if (dots == null) {
            val tile = (22f * density).toInt().coerceAtLeast(4)
            val bmp = runCatching { Bitmap.createBitmap(tile, tile, Bitmap.Config.ARGB_8888) }.getOrNull()
            if (bmp != null) {
                val g = Canvas(bmp)
                val dot = Paint().apply { color = if (dark) Color.argb(14, 255, 255, 255) else Color.argb(15, 30, 40, 90) }
                val s = max(1f, 1.3f * density)
                g.drawRect(11f * density, 12f * density, 11f * density + s, 12f * density + s, dot)
                dotTile = bmp
                dots = BitmapShader(bmp, Shader.TileMode.REPEAT, Shader.TileMode.REPEAT)
            }
        }
        // Перспективная неоновая сетка у низа (тёмная тема, упрощённый экран).
        if (dark && !calm) {
            val top = h * 0.8f
            val vx = w / 2f
            val p = Path()
            for (i in -10..10) {
                p.moveTo(vx + i * 14f * density, top)
                p.lineTo(vx + i * 70f * density, h)
            }
            for (j in 1 until 8) {
                val y = top + (h - top) * (j / 8f).pow(1.8f)
                p.moveTo(0f, y)
                p.lineTo(w, y)
            }
            grid = p
            gridShader = LinearGradient(0f, top, 0f, h, withAlpha(c2, 0f), withAlpha(c2, 0.22f), Shader.TileMode.CLAMP)
        }
        val far = max(w, h) * 0.8f
        vignette = RadialGradient(
            w / 2f, h * 0.45f, far,
            intArrayOf(Color.TRANSPARENT, Color.TRANSPARENT, if (dark) Color.argb(128, 0, 0, 0) else Color.argb(15, 40, 50, 110)),
            floatArrayOf(0f, (min(w, h) * 0.35f) / far, 1f), Shader.TileMode.CLAMP
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
        canvas.clipRect(0f, 0f, w, h)
        paint.style = Paint.Style.FILL
        paint.shader = base
        canvas.drawRect(0f, 0f, w, h, paint)
        drawBlobs(canvas, fixed)
        // Пятна у кнопки — сдвигом к её центру.
        val shift = if (calm) 0f else if (glowY >= 0f) glowY else h * 0.36f
        canvas.save()
        canvas.translate(0f, shift)
        drawBlobs(canvas, items)
        canvas.restore()
        paint.style = Paint.Style.FILL
        for ((path, shader) in waves) {
            paint.shader = shader
            canvas.drawPath(path, paint)
        }
        paint.shader = null
        for (r in rings) {
            paint.color = r.color
            if (r.stroke) {
                paint.style = Paint.Style.STROKE
                paint.strokeWidth = 1.2f * density
            } else {
                paint.style = Paint.Style.FILL
            }
            canvas.drawCircle(r.x, r.y, r.r, paint)
        }
        paint.style = Paint.Style.FILL
        dots?.let {
            paint.shader = it
            canvas.drawRect(0f, 0f, w, h, paint)
        }
        val g = grid
        if (g != null) {
            paint.shader = gridShader
            paint.style = Paint.Style.STROKE
            paint.strokeWidth = max(1f, density)
            canvas.drawPath(g, paint)
            paint.style = Paint.Style.FILL
        }
        vignette?.let {
            paint.shader = it
            canvas.drawRect(0f, 0f, w, h, paint)
        }
        paint.shader = null
        canvas.restore()
    }

    private fun drawBlobs(canvas: Canvas, list: List<Blob>) {
        paint.style = Paint.Style.FILL
        for (it in list) {
            paint.shader = it.shader
            canvas.drawRect(it.x - it.r, it.y - it.r, it.x + it.r, it.y + it.r, paint)
        }
        paint.shader = null
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
