package dev.warpscout.app

import android.graphics.Canvas
import android.graphics.Color
import android.graphics.DashPathEffect
import android.graphics.LinearGradient
import android.graphics.Matrix
import android.graphics.Paint
import android.graphics.Path
import android.graphics.RadialGradient
import android.graphics.RectF
import android.graphics.Shader
import android.graphics.SweepGradient
import kotlin.math.cos
import kotlin.math.min
import kotlin.math.pow
import kotlin.math.sin

/**
 * Облик главной кнопки нового дизайна (кольцо поверх диска): рисует кадр по состоянию. Когда
 * перерисовывать — решает [PowerOrbView]: кадры идут только во время подбора, подключения и вспышки
 * «подключено», и только пока кнопка на экране.
 */
internal interface OrbPainter {
    /** Радиус, внутри которого помещается текст кнопки (диск минус поле). */
    fun innerRadius(size: Float, density: Float): Float

    /**
     * [progress] — доля подбора (меньше нуля — подбор не идёт), [now] — время кадра (uptime, мс),
     * [flashStart] — когда началась вспышка «подключено» (0 — не было), [animate] — анимации включены в
     * системе (иначе — неподвижный кадр).
     */
    fun draw(canvas: Canvas, w: Int, h: Int, state: Int, progress: Float, now: Long, flashStart: Long, animate: Boolean)
}

/** Общее для нарисованных кнопок: краски, цвета с прозрачностью, плавность. */
internal abstract class OrbPainterBase : OrbPainter {
    protected val fill = Paint(Paint.ANTI_ALIAS_FLAG)
    protected val stroke = Paint(Paint.ANTI_ALIAS_FLAG).apply { style = Paint.Style.STROKE }
    protected val round = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.STROKE
        strokeCap = Paint.Cap.ROUND
    }
    protected val box = RectF()
    protected val oval = RectF()

    protected var cx = 0f
    protected var cy = 0f
    protected var outer = 0f
    protected var r0 = 0f
    protected var r1 = 0f
    protected var u = 1f
    private var builtFor = ""

    /** Доли радиуса кнопки: кольцо и диск. */
    protected abstract val ring: Float
    protected abstract val disc: Float

    override fun innerRadius(size: Float, density: Float): Float = size / 2f * disc - 4f * density

    /** Всё, что зависит только от размера, — один раз на размер. */
    protected fun build(w: Int, h: Int): Boolean {
        val key = "${w}x$h"
        if (key == builtFor) return false
        builtFor = key
        val size = min(w, h).toFloat()
        cx = w / 2f
        cy = h / 2f
        outer = size / 2f
        r0 = outer * ring
        r1 = outer * disc
        u = size / 318f
        box.set(cx - r0, cy - r0, cx + r0, cy + r0)
        onBuild()
        return true
    }

    protected abstract fun onBuild()

    protected fun withAlpha(color: Int, a: Float): Int =
        Color.argb((Color.alpha(color) * a.coerceIn(0f, 1f)).toInt(), Color.red(color), Color.green(color), Color.blue(color))

    protected fun mix(a: Int, b: Int, t: Float): Int = Color.argb(
        255,
        (Color.red(a) + (Color.red(b) - Color.red(a)) * t).toInt(),
        (Color.green(a) + (Color.green(b) - Color.green(a)) * t).toInt(),
        (Color.blue(a) + (Color.blue(b) - Color.blue(a)) * t).toInt()
    )

    protected fun easeOut(x: Float): Float = 1f - (1f - x).pow(3)

    /** Время кадра в секундах (неподвижный кадр — 0) и ход вспышки 0..1 (1 — вспышки нет). */
    protected fun seconds(now: Long, animate: Boolean): Float = if (animate) (now % 3_600_000L) / 1000f else 0f

    protected fun flashOf(now: Long, flashStart: Long, animate: Boolean): Float =
        if (flashStart > 0L && animate) ((now - flashStart) / PremiumOrbPainter.FLASH_MS.toFloat()).coerceIn(0f, 1f) else 1f

    /** Дуга-заполнение подбора: градиент от [from] у начала до [to] у головы. */
    protected fun progressShader(p: Float, from: Int, to: Int): Shader {
        val end = p.coerceIn(0.003f, 0.997f)
        return SweepGradient(cx, cy, intArrayOf(from, to, from, from), floatArrayOf(0f, end, end + 0.002f, 1f))
            .apply { setLocalMatrix(Matrix().apply { setRotate(-90f, cx, cy) }) }
    }

    /** Мягкое свечение точки: широкий прозрачный круг и яркое ядро. */
    protected fun glowDot(canvas: Canvas, x: Float, y: Float, r: Float, glow: Int, core: Int) {
        fill.shader = null
        fill.color = withAlpha(glow, 0.32f)
        canvas.drawCircle(x, y, r * 2.2f, fill)
        fill.color = withAlpha(glow, 0.55f)
        canvas.drawCircle(x, y, r * 1.45f, fill)
        fill.color = core
        canvas.drawCircle(x, y, r, fill)
    }

    companion object {
        const val TAU = (Math.PI * 2).toFloat()
    }
}

/**
 * «Нежный» (с 1.10.49-beta8): мягкий диск с тенью и бликом, толстое пастельное кольцо со скруглёнными
 * концами. Подбор — кольцо заполняется, вокруг кружат три точки; подключение — дуга бежит по дорожке и
 * от кольца мягко расходятся круги; подключилось — распускаются лепестки, потом всё замирает.
 */
internal class SoftOrbPainter(look: Design.Look) : OrbPainterBase() {
    override val ring = 0.75f
    override val disc = 0.69f

    private val dark = look.dark
    private val light = look.accentLight
    private val acc = look.accent
    private val partner = look.partner
    private val err = look.error
    private val discA = look.discA
    private val discB = look.discB
    private val ringOff = look.ringOff

    private var haloMain: Shader? = null
    private var haloOn: Shader? = null
    private var haloErr: Shader? = null
    private var shadow: Shader? = null
    private var discShader: Shader? = null
    private var shine: Shader? = null
    private var onRing: Shader? = null
    private var progShader: Shader? = null
    private var progFor = -1f
    private var lw = 11f

    override fun onBuild() {
        lw = 11f * u
        fun halo(c0: Int, c1: Int): Shader {
            val p0 = r1 / outer
            val p1 = (r1 + 0.55f * (outer - r1)) / outer
            return RadialGradient(
                cx, cy, outer, intArrayOf(c0, c0, withAlpha(c1, 0.35f), withAlpha(c0, 0f)),
                floatArrayOf(0f, p0, p1, 1f), Shader.TileMode.CLAMP
            )
        }
        haloMain = halo(light, light)
        haloOn = halo(light, partner)
        haloErr = halo(err, err)
        val shadowColor = if (dark) Color.argb(115, 0, 0, 0) else withAlpha(acc, 0.20f)
        val sr = r1 + 16f * u
        shadow = RadialGradient(
            cx, cy + 9f * u, sr, intArrayOf(shadowColor, shadowColor, withAlpha(shadowColor, 0f)),
            floatArrayOf(0f, (r1 * 0.8f) / sr, 1f), Shader.TileMode.CLAMP
        )
        discShader = RadialGradient(cx - r1 * 0.25f, cy - r1 * 0.35f, r1 * 1.3f, discA, discB, Shader.TileMode.CLAMP)
        shine = LinearGradient(
            cx, cy - r1, cx, cy,
            if (dark) Color.argb(18, 255, 255, 255) else Color.argb(230, 255, 255, 255), Color.TRANSPARENT, Shader.TileMode.CLAMP
        )
        onRing = SweepGradient(
            cx, cy, intArrayOf(light, partner, mix(light, acc, 0.35f), light), floatArrayOf(0f, 0.35f, 0.65f, 1f)
        ).apply { setLocalMatrix(Matrix().apply { setRotate(-90f, cx, cy) }) }
        progShader = null
        progFor = -1f
    }

    override fun draw(canvas: Canvas, w: Int, h: Int, state: Int, progress: Float, now: Long, flashStart: Long, animate: Boolean) {
        if (min(w, h) <= 0) return
        build(w, h)
        val t = seconds(now, animate)
        val scanning = progress >= 0f
        val flashK = flashOf(now, flashStart, animate)
        val flashing = flashK < 1f && state == PowerOrbView.STATE_ON
        val error = state == PowerOrbView.STATE_ERROR
        val main = if (error) err else light

        // 1. Мягкий ореол.
        var halo = when {
            scanning -> 0.22f
            state == PowerOrbView.STATE_ON -> 0.42f
            error -> 0.25f
            state == PowerOrbView.STATE_CONNECTING -> 0.2f + 0.1f * sin(t * 2.6f)
            else -> 0f
        }
        if (flashing) halo += 0.35f * (1f - easeOut(flashK))
        if (dark) halo *= 0.7f
        if (halo > 0f) {
            fill.shader = when {
                error -> haloErr
                state == PowerOrbView.STATE_ON -> haloOn
                else -> haloMain
            }
            fill.alpha = (halo.coerceIn(0f, 1f) * 255).toInt()
            canvas.drawCircle(cx, cy, outer, fill)
            fill.alpha = 255
            fill.shader = null
        }

        // 2. Подключение: от кольца мягко расходятся круги.
        if (!scanning && state == PowerOrbView.STATE_CONNECTING) {
            for (i in 0 until 2) {
                val q = if (animate) ((t / 1.8f) + i / 2f) % 1f else 0.5f + i * 0.25f
                stroke.shader = null
                stroke.strokeWidth = (6f - 5f * q) * u
                stroke.color = withAlpha(main, (if (dark) 0.45f else 0.6f) * (1f - q))
                canvas.drawCircle(cx, cy, r0 + (outer - r0 - 3f * u) * easeOut(q), stroke)
            }
        }

        // 3. Диск с мягкой тенью и бликом сверху — как пуговица.
        fill.shader = shadow
        canvas.drawCircle(cx, cy + 9f * u, r1 + 16f * u, fill)
        fill.shader = discShader
        canvas.drawCircle(cx, cy, r1, fill)
        fill.shader = shine
        oval.set(cx - r1 * 0.72f, cy - r1 * 0.88f, cx + r1 * 0.72f, cy + r1 * 0.12f)
        canvas.drawOval(oval, fill)
        fill.shader = null

        // 4. Дорожка кольца и то, что на ней.
        round.shader = null
        round.strokeWidth = lw
        round.color = withAlpha(ringOff, if (dark) 0.9f else 1f)
        canvas.drawCircle(cx, cy, r0, round)
        when {
            scanning -> drawScan(canvas, progress, t, animate)
            state == PowerOrbView.STATE_CONNECTING -> drawRunner(canvas, t, animate)
            state == PowerOrbView.STATE_ON || error -> drawOn(canvas, main, error, flashing)
        }

        // 5. Подключилось: распускаются лепестки.
        if (flashing) {
            val e = easeOut(flashK)
            fill.shader = null
            for (i in 0 until 10) {
                val a = i * TAU / 10f + e * 0.5f
                val rr = r0 + (8f + 26f * e) * u
                canvas.save()
                canvas.translate(cx + rr * cos(a), cy + rr * sin(a))
                canvas.rotate(Math.toDegrees(a.toDouble()).toFloat())
                fill.color = withAlpha(if (i % 2 == 1) partner else light, 0.85f * (1f - e))
                val pw = (9f - 3f * e) * u
                val ph = (4.5f - 1.5f * e) * u
                oval.set(-pw, -ph, pw, ph)
                canvas.drawOval(oval, fill)
                canvas.restore()
            }
        }
    }

    private fun drawScan(canvas: Canvas, p: Float, t: Float, animate: Boolean) {
        if (p > 0.002f) {
            if (progShader == null || kotlin.math.abs(p - progFor) > 0.004f) {
                progFor = p
                progShader = progressShader(p, light, acc)
            }
            val sweep = 360f * p
            round.shader = null
            round.strokeWidth = lw + 8f * u
            round.color = withAlpha(light, if (dark) 0.25f else 0.35f)
            canvas.drawArc(box, -90f, sweep, false, round)
            round.strokeWidth = lw
            round.color = Color.WHITE
            round.shader = progShader
            canvas.drawArc(box, -90f, sweep, false, round)
            round.shader = null
        }
        // Три точки медленно кружат вокруг кольца.
        val rr = r0 + 19f * u
        for (i in 0 until 3) {
            val a = t * TAU / 3.2f + i * TAU / 3f - TAU / 4f
            val pulse = 0.6f + 0.4f * sin(t * 3f + i * 2f)
            val c = if (i == 1) partner else light
            glowDot(canvas, cx + rr * cos(a), cy + rr * sin(a), (3.2f + 1.6f * pulse) * u, c, withAlpha(c, 0.95f))
        }
    }

    private fun drawRunner(canvas: Canvas, t: Float, animate: Boolean) {
        val head = if (animate) (-90f + t * 360f / 1.6f) % 360f else -20f
        val len = 180f * (0.45f + 0.15f * (if (animate) sin(t * 2f) else 0f))
        canvas.save()
        canvas.rotate(head - len, cx, cy)
        round.shader = SweepGradient(
            cx, cy, intArrayOf(withAlpha(light, 0f), acc, withAlpha(light, 0f), withAlpha(light, 0f)),
            floatArrayOf(0f, len / 360f, len / 360f + 0.001f, 1f)
        )
        round.color = Color.WHITE
        round.strokeWidth = lw
        canvas.drawArc(box, 0f, len, false, round)
        round.shader = null
        canvas.restore()
    }

    private fun drawOn(canvas: Canvas, main: Int, error: Boolean, flashing: Boolean) {
        // Мягкое свечение под кольцом, само кольцо — переливом пастели и напарника, сверху тонкий блик.
        round.shader = null
        round.strokeWidth = lw + (if (flashing) 14f else 8f) * u
        round.color = withAlpha(main, if (dark) 0.22f else 0.30f)
        canvas.drawCircle(cx, cy, r0, round)
        round.strokeWidth = lw
        if (error) {
            round.color = main
        } else {
            round.color = Color.WHITE
            round.shader = onRing
        }
        canvas.drawCircle(cx, cy, r0, round)
        round.shader = null
        round.strokeWidth = 2f * u
        round.color = if (dark) Color.argb(64, 255, 255, 255) else Color.argb(190, 255, 255, 255)
        val r = r0 - lw * 0.18f
        oval.set(cx - r, cy - r, cx + r, cy + r)
        canvas.drawArc(oval, 189f, 126f, false, round)
    }
}

/**
 * «Стекло» (с 1.10.49-beta8): прозрачный диск с бликом и кромкой, за ним цветной свет двух неоновых
 * цветов; кольцо — неон этих двух цветов. Подбор — вокруг кольца бежит луч и крутятся пунктирные
 * орбиты; подключение — две кометы догоняют друг друга; подключилось — по кольцу пробегает белый блик и
 * расходится волна, потом всё замирает.
 */
internal class GlassOrbPainter(look: Design.Look) : OrbPainterBase() {
    override val ring = 0.78f
    override val disc = 0.71f

    private val dark = look.dark
    private val neonA = look.neonA
    private val neonB = look.neonB
    private val err = look.error
    private val discA = look.discA
    private val discB = look.discB
    private val ringOff = look.ringOff

    private var blobA: Shader? = null
    private var blobB: Shader? = null
    private var blobErrA: Shader? = null
    private var blobErrB: Shader? = null
    private var radar: Shader? = null
    private var discShader: Shader? = null
    private var tint: Shader? = null
    private var shine: Shader? = null
    private var rim: Shader? = null
    private var neon: Shader? = null
    private var progShader: Shader? = null
    private var progFor = -1f
    private val clip = Path()
    private var dashFine: DashPathEffect? = null
    private var dashLong: DashPathEffect? = null

    override fun onBuild() {
        fun blob(x: Float, y: Float, c: Int): Shader =
            RadialGradient(x, y, outer * 0.95f, c, withAlpha(c, 0f), Shader.TileMode.CLAMP)
        blobA = blob(cx - outer * 0.32f, cy - outer * 0.30f, neonA)
        blobB = blob(cx + outer * 0.34f, cy + outer * 0.32f, neonB)
        blobErrA = blob(cx - outer * 0.32f, cy - outer * 0.30f, err)
        blobErrB = blob(cx + outer * 0.34f, cy + outer * 0.32f, err)
        radar = SweepGradient(
            cx, cy, intArrayOf(withAlpha(neonA, 0f), withAlpha(neonA, 0f), withAlpha(neonA, if (dark) 0.32f else 0.22f)),
            floatArrayOf(0f, 0.8f, 1f)
        )
        discShader = RadialGradient(cx - r1 * 0.3f, cy - r1 * 0.4f, r1 * 1.3f, discA, discB, Shader.TileMode.CLAMP)
        tint = LinearGradient(
            cx - r1, cy - r1, cx + r1, cy + r1,
            withAlpha(neonA, if (dark) 0.10f else 0.06f), withAlpha(neonB, if (dark) 0.12f else 0.07f), Shader.TileMode.CLAMP
        )
        shine = LinearGradient(
            0f, cy - r1, 0f, cy - r1 * 0.1f,
            if (dark) Color.argb(56, 255, 255, 255) else Color.argb(217, 255, 255, 255), Color.TRANSPARENT, Shader.TileMode.CLAMP
        )
        rim = LinearGradient(
            cx, cy - r1, cx, cy + r1,
            if (dark) Color.argb(115, 255, 255, 255) else Color.WHITE,
            if (dark) Color.argb(15, 255, 255, 255) else Color.argb(77, 255, 255, 255), Shader.TileMode.CLAMP
        )
        neon = SweepGradient(cx, cy, intArrayOf(neonA, neonB, neonA), floatArrayOf(0f, 0.5f, 1f))
            .apply { setLocalMatrix(Matrix().apply { setRotate(-90f, cx, cy) }) }
        clip.reset()
        clip.addCircle(cx, cy, r1, Path.Direction.CW)
        dashFine = DashPathEffect(floatArrayOf(2f * u, 7f * u), 0f)
        dashLong = DashPathEffect(floatArrayOf(16f * u, 30f * u), 0f)
        progShader = null
        progFor = -1f
    }

    override fun draw(canvas: Canvas, w: Int, h: Int, state: Int, progress: Float, now: Long, flashStart: Long, animate: Boolean) {
        if (min(w, h) <= 0) return
        build(w, h)
        val t = seconds(now, animate)
        val scanning = progress >= 0f
        val flashK = flashOf(now, flashStart, animate)
        val flashing = flashK < 1f && state == PowerOrbView.STATE_ON
        val error = state == PowerOrbView.STATE_ERROR
        val a = if (error) err else neonA
        val b = if (error) err else neonB

        // 1. Цветной свет за стеклом: первый цвет сверху слева, второй снизу справа.
        var light = when {
            scanning -> 0.28f
            state == PowerOrbView.STATE_ON -> 0.48f
            error -> 0.32f
            state == PowerOrbView.STATE_CONNECTING -> 0.30f + 0.08f * sin(t * 3.2f)
            else -> 0.10f
        }
        if (flashing) light += 0.35f * (1f - easeOut(flashK))
        if (!dark) light *= 0.75f
        fill.shader = if (error) blobErrA else blobA
        fill.alpha = (light.coerceIn(0f, 1f) * 255).toInt()
        canvas.drawCircle(cx, cy, outer, fill)
        fill.shader = if (error) blobErrB else blobB
        fill.alpha = (light * 0.9f).coerceIn(0f, 1f).times(255).toInt()
        canvas.drawCircle(cx, cy, outer, fill)
        fill.alpha = 255
        fill.shader = null

        // 2. Подбор: луч вокруг кольца и пунктирные орбиты.
        if (scanning) {
            if (animate) {
                canvas.save()
                canvas.rotate((t * 360f / 2f) % 360f, cx, cy)
                stroke.shader = radar
                stroke.color = Color.WHITE
                val inner = r0 + 4f * u
                stroke.strokeWidth = outer - inner
                canvas.drawCircle(cx, cy, (outer + inner) / 2f, stroke)
                stroke.shader = null
                canvas.restore()
            }
            canvas.save()
            canvas.rotate(-(t * 360f / 14f) % 360f, cx, cy)
            stroke.shader = null
            stroke.pathEffect = dashFine
            stroke.strokeWidth = 2f * u
            stroke.color = withAlpha(b, 0.6f)
            canvas.drawCircle(cx, cy, r0 + 16f * u, stroke)
            canvas.rotate((t * 360f / 6f) % 360f, cx, cy)
            stroke.pathEffect = dashLong
            stroke.strokeWidth = 1.2f * u
            stroke.color = withAlpha(a, 0.5f)
            canvas.drawCircle(cx, cy, r0 + 26f * u, stroke)
            stroke.pathEffect = null
            canvas.restore()
        }

        // 3. Стеклянный диск: прозрачная заливка, цветной отсвет, блик и кромка.
        fill.shader = discShader
        canvas.drawCircle(cx, cy, r1, fill)
        fill.shader = tint
        canvas.drawCircle(cx, cy, r1, fill)
        canvas.save()
        canvas.clipPath(clip)
        val hx = cx - r1 * 0.12f
        val hy = cy - r1 * 0.52f
        canvas.rotate(-14.3f, hx, hy)
        fill.shader = shine
        oval.set(hx - r1 * 0.78f, hy - r1 * 0.44f, hx + r1 * 0.78f, hy + r1 * 0.44f)
        canvas.drawOval(oval, fill)
        canvas.restore()
        fill.shader = null
        stroke.shader = rim
        stroke.color = Color.WHITE
        stroke.strokeWidth = 1.3f * u
        canvas.drawCircle(cx, cy, r1 - 0.6f * u, stroke)
        stroke.shader = null

        // 4. Кольцо.
        stroke.strokeWidth = 3f * u
        stroke.color = ringOff
        canvas.drawCircle(cx, cy, r0, stroke)
        when {
            scanning -> drawScan(canvas, progress, a, b)
            state == PowerOrbView.STATE_CONNECTING -> drawComets(canvas, t, animate)
            state == PowerOrbView.STATE_ON || error -> drawNeon(canvas, a, b, error, flashing, flashK)
            else -> {
                stroke.color = Color.WHITE
                stroke.shader = neon
                stroke.alpha = ((if (dark) 0.28f else 0.35f) * 255).toInt()
                stroke.strokeWidth = 2f * u
                canvas.drawCircle(cx, cy, r0, stroke)
                stroke.alpha = 255
                stroke.shader = null
            }
        }

        // 5. Волна от кольца наружу.
        if (flashing) {
            val e = easeOut(flashK)
            val r = r0 + (outer - r0 - 2f * u) * e
            stroke.shader = null
            stroke.strokeWidth = (2.6f * (1f - e) + 0.6f) * u + 6f * u
            stroke.color = withAlpha(b, 0.22f * (1f - e))
            canvas.drawCircle(cx, cy, r, stroke)
            stroke.strokeWidth = (2.6f * (1f - e) + 0.6f) * u
            stroke.color = withAlpha(b, 0.8f * (1f - e))
            canvas.drawCircle(cx, cy, r, stroke)
        }
    }

    private fun drawScan(canvas: Canvas, p: Float, a: Int, b: Int) {
        if (p <= 0.002f) return
        if (progShader == null || kotlin.math.abs(p - progFor) > 0.004f) {
            progFor = p
            progShader = progressShader(p, a, b)
        }
        val sweep = 360f * p
        round.shader = null
        round.strokeWidth = 13f * u
        round.color = withAlpha(a, if (dark) 0.28f else 0.18f)
        canvas.drawArc(box, -90f, sweep, false, round)
        round.strokeWidth = 5f * u
        round.color = Color.WHITE
        round.shader = progShader
        canvas.drawArc(box, -90f, sweep, false, round)
        round.shader = null
        val ang = Math.toRadians((-90f + sweep).toDouble())
        glowDot(canvas, cx + r0 * cos(ang).toFloat(), cy + r0 * sin(ang).toFloat(), 4.2f * u, b, Color.WHITE)
    }

    private fun drawComets(canvas: Canvas, t: Float, animate: Boolean) {
        val tail = 99f
        for (c in 0 until 2) {
            val col = if (c == 1) neonB else neonA
            val head = (if (animate) -90f + t * 360f / 1.4f else -20f) + c * 180f
            canvas.save()
            canvas.rotate(head - tail, cx, cy)
            round.shader = SweepGradient(
                cx, cy, intArrayOf(withAlpha(col, 0f), col, withAlpha(col, 0f), withAlpha(col, 0f)),
                floatArrayOf(0f, tail / 360f, tail / 360f + 0.001f, 1f)
            )
            round.color = Color.WHITE
            round.strokeWidth = 11f * u
            round.alpha = if (dark) 80 else 55
            canvas.drawArc(box, 0f, tail, false, round)
            round.alpha = 255
            round.strokeWidth = 4.4f * u
            canvas.drawArc(box, 0f, tail, false, round)
            round.shader = null
            canvas.restore()
            val ang = Math.toRadians(head.toDouble())
            glowDot(canvas, cx + r0 * cos(ang).toFloat(), cy + r0 * sin(ang).toFloat(), 3.6f * u, col, Color.WHITE)
        }
    }

    private fun drawNeon(canvas: Canvas, a: Int, b: Int, error: Boolean, flashing: Boolean, flashK: Float) {
        // Неон двух цветов: мягкая подложка, свечение первого цвета справа и второго слева, яркая сердцевина.
        stroke.shader = null
        stroke.strokeWidth = 14f * u
        stroke.color = withAlpha(a, if (dark) 0.10f else 0.08f)
        canvas.drawCircle(cx, cy, r0, stroke)
        round.shader = null
        round.strokeWidth = 9f * u
        round.color = withAlpha(a, if (dark) 0.35f else 0.22f)
        canvas.drawArc(box, -90f, 180f, false, round)
        round.color = withAlpha(b, if (dark) 0.35f else 0.22f)
        canvas.drawArc(box, 90f, 180f, false, round)
        stroke.strokeWidth = 5f * u
        if (error) {
            stroke.color = a
        } else {
            stroke.color = Color.WHITE
            stroke.shader = neon
        }
        canvas.drawCircle(cx, cy, r0, stroke)
        stroke.shader = null
        stroke.strokeWidth = 1.2f * u
        stroke.color = if (dark) Color.argb(140, 255, 255, 255) else Color.argb(204, 255, 255, 255)
        canvas.drawCircle(cx, cy, r0 - 0.4f * u, stroke)
        // Подключилось: по кольцу пробегает белый блик.
        if (flashing) {
            val head = -90f + easeOut(flashK) * 360f
            val len = 50f
            val k = 1f - flashK
            canvas.save()
            canvas.rotate(head - len, cx, cy)
            round.shader = SweepGradient(
                cx, cy,
                intArrayOf(Color.TRANSPARENT, Color.argb((242 * k).toInt(), 255, 255, 255), Color.TRANSPARENT, Color.TRANSPARENT),
                floatArrayOf(0f, len / 360f, len / 360f + 0.001f, 1f)
            )
            round.color = Color.WHITE
            round.strokeWidth = 14f * u
            round.alpha = 90
            canvas.drawArc(box, 0f, len, false, round)
            round.alpha = 255
            round.strokeWidth = 6f * u
            canvas.drawArc(box, 0f, len, false, round)
            round.shader = null
            canvas.restore()
        }
    }
}
