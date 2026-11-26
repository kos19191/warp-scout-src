package dev.warpscout.app

import android.content.Context
import android.content.res.Configuration
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.LinearGradient
import android.graphics.Matrix
import android.graphics.Paint
import android.graphics.Path
import android.graphics.RadialGradient
import android.graphics.RectF
import android.graphics.Shader
import android.graphics.SweepGradient
import androidx.core.content.ContextCompat
import kotlin.math.abs
import kotlin.math.cos
import kotlin.math.min
import kotlin.math.pow
import kotlin.math.sin

/**
 * Главная кнопка в дизайне «Премиум» (с 1.10.49-beta7) — так её нарисовал макет, который выбрал
 * человек: неоновое оранжевое кольцо, внутри еле заметный щит, мягкий ореол.
 *
 *  - подбор — вокруг кольца медленно поворачивается «микросхема» (дорожки, площадки, импульсы),
 *    по кольцу и шкале внутри него идёт заполнение по ходу подбора;
 *  - подключение — по кольцу бежит свет с гаснущим хвостом, ореол «дышит»;
 *  - подключилось — вспыхивает щит и от кольца расходится волна, потом всё замирает.
 *
 * Только рисование: когда перерисовывать (и что анимации идут лишь пока кнопка на экране), решает
 * [PowerOrbView]. Свечение — слоями обводок, а не размытием: размытие на части телефонов рисуется
 * без видеокарты и тормозит. Всё, что зависит только от размера (дорожки, щит, шкала, градиенты),
 * строится один раз на размер; в кадре — повороты и альфа.
 */
internal class PremiumOrbPainter(private val context: Context) : OrbPainter {

    private fun c(res: Int) = ContextCompat.getColor(context, res)
    private val acc = c(R.color.prem_accent)
    private val accDeep = c(R.color.prem_accent_deep)
    private val accLight = c(R.color.prem_accent_light)
    private val err = c(R.color.prem_error)
    private val discA = c(R.color.prem_disc_a)
    private val discB = c(R.color.prem_disc_b)
    private val ringOff = c(R.color.prem_ring_off)
    private val core = c(R.color.prem_core)
    private val dark = (context.resources.configuration.uiMode and Configuration.UI_MODE_NIGHT_MASK) ==
        Configuration.UI_MODE_NIGHT_YES

    private val fill = Paint(Paint.ANTI_ALIAS_FLAG)
    private val stroke = Paint(Paint.ANTI_ALIAS_FLAG).apply { style = Paint.Style.STROKE }
    private val round = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.STROKE
        strokeCap = Paint.Cap.ROUND
    }
    private val box = RectF()

    // ---- построенное под размер
    private var builtFor = ""
    private var cx = 0f
    private var cy = 0f
    private var outer = 0f
    private var r0 = 0f
    private var r1 = 0f
    private var u = 1f
    private var haloAcc: Shader? = null
    private var haloErr: Shader? = null
    private var discShader: Shader? = null
    private var shieldFillShader: Shader? = null
    private var neonShader: Shader? = null
    private var cometShader: Shader? = null
    private var radarShader: Shader? = null
    private var progShader: Shader? = null
    private var progShaderFor = -1f
    private val shield = Path()
    private val traces = arrayOf(Path(), Path(), Path())
    private val traceEnds = Path()
    private val chips = Path()
    private val bars = Path()
    private var ticks = FloatArray(0)
    private val traceA = FloatArray(TRACES)
    private val traceA2 = FloatArray(TRACES)
    private val traceRm = FloatArray(TRACES)
    private val traceRe = FloatArray(TRACES)
    private var traceBase = 0f

    /** Радиус, внутри которого помещается текст кнопки (диск минус поле). */
    override fun innerRadius(size: Float, density: Float): Float = size / 2f * DISC - 4f * density

    private fun withAlpha(color: Int, a: Float): Int =
        Color.argb((Color.alpha(color) * a.coerceIn(0f, 1f)).toInt(), Color.red(color), Color.green(color), Color.blue(color))

    private fun mix(a: Int, b: Int, t: Float): Int = Color.argb(
        255,
        (Color.red(a) + (Color.red(b) - Color.red(a)) * t).toInt(),
        (Color.green(a) + (Color.green(b) - Color.green(a)) * t).toInt(),
        (Color.blue(a) + (Color.blue(b) - Color.blue(a)) * t).toInt()
    )

    private fun build(w: Int, h: Int) {
        val key = "${w}x$h"
        if (key == builtFor) return
        builtFor = key
        val size = min(w, h).toFloat()
        cx = w / 2f
        cy = h / 2f
        outer = size / 2f
        r0 = outer * RING
        r1 = outer * DISC
        u = size / 318f

        fun halo(color: Int): Shader {
            val inner = r1 * 0.96f
            val p0 = inner / outer
            val p1 = (inner + 0.22f * (outer - inner)) / outer
            val p2 = (inner + 0.55f * (outer - inner)) / outer
            return RadialGradient(
                cx, cy, outer,
                intArrayOf(Color.TRANSPARENT, withAlpha(color, 0f), withAlpha(color, 1f), withAlpha(color, 0.32f), withAlpha(color, 0f)),
                floatArrayOf(0f, p0, p1, p2, 1f), Shader.TileMode.CLAMP
            )
        }
        haloAcc = halo(acc)
        haloErr = halo(err)
        discShader = RadialGradient(cx, cy - r1 * 0.35f, r1 * 1.05f, discA, discB, Shader.TileMode.CLAMP)
        shieldFillShader = LinearGradient(cx, cy - r1, cx, cy + r1, withAlpha(acc, 1f), withAlpha(acc, 0f), Shader.TileMode.CLAMP)
        val turn = Matrix().apply { setRotate(-90f, cx, cy) }
        neonShader = SweepGradient(
            cx, cy,
            intArrayOf(accLight, acc, accLight, accDeep, acc, accLight, accLight),
            floatArrayOf(0f, 0.18f, 0.32f, 0.5f, 0.7f, 0.86f, 1f)
        ).apply { setLocalMatrix(turn) }
        cometShader = SweepGradient(
            cx, cy,
            intArrayOf(withAlpha(accDeep, 0f), withAlpha(accDeep, 0f), withAlpha(accDeep, 0.6f), accLight),
            floatArrayOf(0f, 1f - COMET / 360f, 1f - COMET / 720f, 1f)
        )
        radarShader = SweepGradient(
            cx, cy,
            intArrayOf(withAlpha(acc, 0f), withAlpha(acc, 0f), withAlpha(acc, if (dark) 0.22f else 0.13f)),
            floatArrayOf(0f, 0.84f, 1f)
        )
        progShaderFor = -1f

        // Щит, как на картинке со щитом: острый верх, плечи, сужение к острию внизу.
        shield.reset()
        val sw = r1 * 1.5f / 2f
        val sh = r1 * 1.62f / 2f
        val sy = cy - r1 * 0.03f
        fun x(k: Float) = cx + k * sw
        fun y(k: Float) = sy + k * sh
        shield.moveTo(x(0f), y(-1f))
        shield.cubicTo(x(0.3f), y(-0.83f), x(0.62f), y(-0.79f), x(0.92f), y(-0.78f))
        shield.cubicTo(x(0.95f), y(-0.18f), x(0.86f), y(0.3f), x(0.55f), y(0.62f))
        shield.cubicTo(x(0.37f), y(0.81f), x(0.17f), y(0.9f), x(0f), y(1f))
        shield.cubicTo(x(-0.17f), y(0.9f), x(-0.37f), y(0.81f), x(-0.55f), y(0.62f))
        shield.cubicTo(x(-0.86f), y(0.3f), x(-0.95f), y(-0.18f), x(-0.92f), y(-0.78f))
        shield.cubicTo(x(-0.62f), y(-0.79f), x(-0.3f), y(-0.83f), x(0f), y(-1f))
        shield.close()

        // Шкала внутри кольца: 96 рисок, каждая восьмая длиннее.
        ticks = FloatArray(TICKS * 4)
        val rt = r0 - 10f * u
        for (i in 0 until TICKS) {
            val a = Math.toRadians((-90.0 + i * 360.0 / TICKS))
            val len = (if (i % 8 == 0) 7f else 4f) * u
            ticks[i * 4] = cx + rt * cos(a).toFloat()
            ticks[i * 4 + 1] = cy + rt * sin(a).toFloat()
            ticks[i * 4 + 2] = cx + (rt - len) * cos(a).toFloat()
            ticks[i * 4 + 3] = cy + (rt - len) * sin(a).toFloat()
        }

        // «Микросхема»: дорожки от кольца наружу, часть с изломом по дуге; на концах площадки.
        // Зерно постоянное — рисунок одинаковый при каждом запуске.
        val rnd = java.util.Random(20261126L)
        traces.forEach { it.reset() }
        traceEnds.reset()
        chips.reset()
        bars.reset()
        traceBase = r0 + 9f * u
        val span = outer - traceBase - 3f * u
        for (i in 0 until TRACES) {
            val a = (i.toFloat() / TRACES) * TAU + (rnd.nextFloat() - 0.5f) * (TAU / TRACES) * 0.7f
            val len = span * (0.28f + rnd.nextFloat() * 0.7f)
            val mid = 0.32f + rnd.nextFloat() * 0.3f
            val bend = if (rnd.nextFloat() < 0.45f) (if (rnd.nextBoolean()) -1f else 1f) * (0.03f + rnd.nextFloat() * 0.06f) else 0f
            val a2 = a + bend
            val rm = traceBase + len * mid
            val re = traceBase + len
            traceA[i] = a; traceA2[i] = a2; traceRm[i] = rm; traceRe[i] = re
            val p = traces[i % 3]
            p.moveTo(cx + traceBase * cos(a), cy + traceBase * sin(a))
            p.lineTo(cx + rm * cos(a), cy + rm * sin(a))
            if (bend != 0f) {
                box.set(cx - rm, cy - rm, cx + rm, cy + rm)
                p.arcTo(box, Math.toDegrees(a.toDouble()).toFloat(), Math.toDegrees(bend.toDouble()).toFloat(), false)
            }
            p.lineTo(cx + re * cos(a2), cy + re * sin(a2))
            val ex = cx + re * cos(a2)
            val ey = cy + re * sin(a2)
            when {
                rnd.nextFloat() < 0.3f -> traceEnds.addRect(ex - 1.7f * u, ey - 1.7f * u, ex + 1.7f * u, ey + 1.7f * u, Path.Direction.CW)
                rnd.nextFloat() < 0.45f -> traceEnds.addCircle(ex, ey, 1.8f * u, Path.Direction.CW)
            }
        }
        repeat(16) {
            val a = rnd.nextFloat() * TAU
            val r = traceBase + span * (0.55f + rnd.nextFloat() * 0.4f)
            val s = (2.2f + rnd.nextFloat() * 4f) * u / 2f
            val x = cx + r * cos(a)
            val y = cy + r * sin(a)
            chips.addRect(x - s, y - s, x + s, y + s, Path.Direction.CW)
        }
        repeat(5) {
            val a0 = rnd.nextFloat() * TAU
            val n = 4 + rnd.nextInt(5)
            val r = traceBase + span * (0.25f + rnd.nextFloat() * 0.4f)
            for (j in 0 until n) {
                val a = a0 + j * 0.022f
                bars.moveTo(cx + r * cos(a), cy + r * sin(a))
                bars.lineTo(cx + (r + 9f * u) * cos(a), cy + (r + 9f * u) * sin(a))
            }
        }
    }

    /**
     * Нарисовать кадр. [progress] — доля подбора (меньше нуля — подбор не идёт), [now] — время кадра
     * (uptime, мс), [flashStart] — когда началась вспышка «подключено» (0 — не было), [animate] —
     * анимации включены в системе (иначе — неподвижный кадр).
     */
    override fun draw(canvas: Canvas, w: Int, h: Int, state: Int, progress: Float, now: Long, flashStart: Long, animate: Boolean) {
        if (min(w, h) <= 0) return
        build(w, h)
        val t = if (animate) (now % 3_600_000L) / 1000f else 0f
        val scanning = progress >= 0f
        val flashK = if (flashStart > 0L && animate) ((now - flashStart) / FLASH_MS.toFloat()).coerceIn(0f, 1f) else 1f
        val flashing = flashK < 1f && state == PowerOrbView.STATE_ON
        val main = if (state == PowerOrbView.STATE_ERROR) err else acc

        // 1. Ореол.
        var halo = when {
            scanning -> if (dark) 0.11f else 0.07f
            state == PowerOrbView.STATE_ON -> if (dark) 0.30f else 0.20f
            state == PowerOrbView.STATE_ERROR -> if (dark) 0.22f else 0.13f
            state == PowerOrbView.STATE_CONNECTING -> (if (dark) 0.13f else 0.08f) + (if (dark) 0.07f else 0.04f) * sin(t * 3.4f)
            else -> 0f
        }
        if (flashing) halo += (if (dark) 0.38f else 0.24f) * (1f - easeOut(flashK))
        if (halo > 0f) {
            fill.shader = if (state == PowerOrbView.STATE_ERROR) haloErr else haloAcc
            fill.alpha = (halo.coerceIn(0f, 1f) * 255).toInt()
            canvas.drawCircle(cx, cy, outer, fill)
            fill.alpha = 255
            fill.shader = null
        }

        // 2. «Микросхема» вокруг кольца — только во время подбора.
        if (scanning) drawCircuit(canvas, t, animate)

        // 3. Диск.
        fill.shader = discShader
        canvas.drawCircle(cx, cy, r1, fill)
        fill.shader = null
        stroke.strokeWidth = 1f
        stroke.color = withAlpha(main, if (dark) 0.16f else 0.20f)
        canvas.drawCircle(cx, cy, r1 - 0.5f, stroke)

        // 4. Щит внутри диска: еле виден, при подключении вспыхивает.
        var sa = when {
            scanning -> 0.08f
            state == PowerOrbView.STATE_ON -> 0.15f
            state == PowerOrbView.STATE_CONNECTING || state == PowerOrbView.STATE_ERROR -> 0.10f
            else -> 0.06f
        }
        if (!dark) sa *= 1.25f
        var sw = 1.6f * u
        var glow = 0f
        if (flashing) {
            val f = if (flashK < 0.2f) easeOut(flashK / 0.2f) else 1f - easeOut((flashK - 0.2f) / 0.8f)
            sa += (0.95f - sa) * f
            sw = (1.6f + 1.4f * f) * u
            glow = f
        }
        if (state == PowerOrbView.STATE_ON || flashing) {
            fill.shader = shieldFillShader
            fill.alpha = (((if (dark) 0.06f else 0.04f) + if (flashing) 0.10f * (1f - flashK) else 0f) * 255).toInt()
            canvas.drawPath(shield, fill)
            fill.alpha = 255
            fill.shader = null
        }
        val shieldColor = if (state == PowerOrbView.STATE_ERROR) err else accLight
        if (glow > 0f) {
            stroke.strokeWidth = 12f * u * glow + sw
            stroke.color = withAlpha(acc, 0.16f * glow)
            canvas.drawPath(shield, stroke)
            stroke.strokeWidth = 6f * u * glow + sw
            stroke.color = withAlpha(acc, 0.32f * glow)
            canvas.drawPath(shield, stroke)
        }
        stroke.strokeWidth = sw
        stroke.color = withAlpha(shieldColor, sa)
        canvas.drawPath(shield, stroke)

        // 5. Кольцо.
        box.set(cx - r0, cy - r0, cx + r0, cy + r0)
        when {
            scanning -> drawProgress(canvas, progress, main)
            state == PowerOrbView.STATE_CONNECTING -> drawComet(canvas, t, main, animate)
            state == PowerOrbView.STATE_ON || state == PowerOrbView.STATE_ERROR -> drawNeon(canvas, state, main)
            else -> {
                stroke.strokeWidth = 3f * u
                stroke.color = ringOff
                canvas.drawCircle(cx, cy, r0, stroke)
            }
        }

        // 6. Вспышка: волна от кольца наружу.
        if (flashing) {
            val e = easeOut(flashK)
            val r = r0 + (outer - r0 - 2f * u) * e
            stroke.strokeWidth = (3f * (1f - e) + 0.6f) * u + 6f * u
            stroke.color = withAlpha(acc, 0.18f * (1f - e))
            canvas.drawCircle(cx, cy, r, stroke)
            stroke.strokeWidth = (3f * (1f - e) + 0.6f) * u
            stroke.color = withAlpha(accLight, 0.75f * (1f - e))
            canvas.drawCircle(cx, cy, r, stroke)
        }
    }

    private fun drawProgress(canvas: Canvas, p: Float, main: Int) {
        stroke.strokeWidth = 4f * u
        stroke.color = withAlpha(main, 0.17f)
        canvas.drawCircle(cx, cy, r0, stroke)
        // Шкала: пройденная часть подсвечена.
        val lit = (p * TICKS).toInt().coerceIn(0, TICKS)
        stroke.strokeWidth = 1.2f * u
        if (lit > 0) {
            stroke.color = withAlpha(accLight, 0.85f)
            canvas.drawLines(ticks, 0, lit * 4, stroke)
        }
        if (lit < TICKS) {
            stroke.color = withAlpha(acc, 0.22f)
            canvas.drawLines(ticks, lit * 4, (TICKS - lit) * 4, stroke)
        }
        if (p <= 0.002f) return
        if (abs(p - progShaderFor) > 0.004f || progShader == null) {
            progShaderFor = p
            val end = p.coerceIn(0.003f, 0.997f)
            progShader = SweepGradient(
                cx, cy, intArrayOf(accDeep, accLight, accDeep, accDeep), floatArrayOf(0f, end, end + 0.002f, 1f)
            ).apply { setLocalMatrix(Matrix().apply { setRotate(-90f, cx, cy) }) }
        }
        val sweep = 360f * p
        round.shader = null
        round.strokeWidth = 13f * u
        round.color = withAlpha(acc, if (dark) 0.12f else 0.08f)
        canvas.drawArc(box, -90f, sweep, false, round)
        round.strokeWidth = 8f * u
        round.color = withAlpha(acc, if (dark) 0.26f else 0.16f)
        canvas.drawArc(box, -90f, sweep, false, round)
        round.strokeWidth = 5f * u
        round.color = Color.WHITE
        round.shader = progShader
        canvas.drawArc(box, -90f, sweep, false, round)
        round.shader = null
        val a = Math.toRadians((-90f + sweep).toDouble())
        dot(canvas, cx + r0 * cos(a).toFloat(), cy + r0 * sin(a).toFloat(), 4.6f * u)
    }

    private fun drawComet(canvas: Canvas, t: Float, main: Int, animate: Boolean) {
        stroke.strokeWidth = 4f * u
        stroke.color = withAlpha(main, 0.20f)
        canvas.drawCircle(cx, cy, r0, stroke)
        // По кольцу бежит свет: голова яркая, хвост гаснет. Без анимаций — неподвижная дуга сверху.
        val head = if (animate) (-90f + t * 360f / 1.25f) % 360f else -20f
        canvas.save()
        canvas.rotate(head, cx, cy)
        round.shader = cometShader
        round.color = Color.WHITE
        round.strokeWidth = 12f * u
        round.alpha = if (dark) 70 else 45
        canvas.drawArc(box, -COMET, COMET - 1f, false, round)
        round.alpha = 255
        round.strokeWidth = 5.5f * u
        canvas.drawArc(box, -COMET, COMET - 1f, false, round)
        round.shader = null
        canvas.restore()
        val a = Math.toRadians(head.toDouble())
        dot(canvas, cx + r0 * cos(a).toFloat(), cy + r0 * sin(a).toFloat(), 4f * u)
    }

    private fun drawNeon(canvas: Canvas, state: Int, main: Int) {
        // Неоновое кольцо: широкая мягкая подложка, слой свечения, яркая сердцевина и светлая нить.
        stroke.shader = null
        stroke.strokeWidth = 14f * u
        stroke.color = withAlpha(main, if (dark) 0.12f else 0.08f)
        canvas.drawCircle(cx, cy, r0, stroke)
        stroke.strokeWidth = 8.5f * u
        stroke.color = withAlpha(main, if (dark) 0.30f else 0.18f)
        canvas.drawCircle(cx, cy, r0, stroke)
        stroke.strokeWidth = 4.8f * u
        if (state == PowerOrbView.STATE_ON) {
            stroke.color = Color.WHITE
            stroke.shader = neonShader
        } else {
            stroke.color = main
        }
        canvas.drawCircle(cx, cy, r0, stroke)
        stroke.shader = null
        stroke.strokeWidth = 1.1f * u
        stroke.color = withAlpha(if (state == PowerOrbView.STATE_ERROR) err else accLight, if (dark) 0.6f else 0.8f)
        canvas.drawCircle(cx, cy, r0 - 0.5f, stroke)
    }

    /** Светящаяся точка — голова дуги. */
    private fun dot(canvas: Canvas, x: Float, y: Float, r: Float) {
        fill.shader = null
        fill.color = withAlpha(acc, if (dark) 0.30f else 0.22f)
        canvas.drawCircle(x, y, r * 2.2f, fill)
        fill.color = withAlpha(accLight, 0.6f)
        canvas.drawCircle(x, y, r * 1.4f, fill)
        fill.color = core
        canvas.drawCircle(x, y, r, fill)
    }

    private fun drawCircuit(canvas: Canvas, t: Float, animate: Boolean) {
        val k = if (dark) 1f else 0.85f
        // Луч-«радар»: светлый край ведёт, хвост гаснет. Оборот за 2,4 с.
        if (animate) {
            canvas.save()
            canvas.rotate((t * 360f / 2.4f) % 360f, cx, cy)
            stroke.shader = radarShader
            stroke.color = Color.WHITE
            val inner = r0 + 3f * u
            stroke.strokeWidth = outer - inner
            canvas.drawCircle(cx, cy, (outer + inner) / 2f, stroke)
            stroke.shader = null
            canvas.restore()
        }
        canvas.save()
        // Вся «микросхема» медленно поворачивается — оборот за 26 с.
        canvas.rotate((t * 360f / 26f) % 360f, cx, cy)
        stroke.strokeCap = Paint.Cap.BUTT
        val alphas = floatArrayOf(0.22f, 0.36f, 0.5f)
        traces.forEachIndexed { i, p ->
            stroke.strokeWidth = (if (i == 2) 1.6f else 1f) * u
            stroke.color = withAlpha(acc, alphas[i] * k)
            canvas.drawPath(p, stroke)
        }
        fill.shader = null
        fill.color = withAlpha(acc, 0.6f * k)
        canvas.drawPath(traceEnds, fill)
        fill.color = withAlpha(acc, 0.4f * k)
        canvas.drawPath(chips, fill)
        stroke.strokeWidth = 1.4f * u
        stroke.color = withAlpha(accLight, 0.45f * k)
        canvas.drawPath(bars, stroke)
        // Импульсы бегут по дорожкам от кольца наружу.
        if (animate) {
            for (i in 0 until PULSES) {
                val cyc = t * 0.75f + i.toFloat() / PULSES
                val idx = ((cyc.toInt() * 11 + i * 17) % TRACES + TRACES) % TRACES
                val q = cyc - cyc.toInt()
                val a = traceA[idx]
                val a2 = traceA2[idx]
                val rm = traceRm[idx]
                val re = traceRe[idx]
                val l1 = rm - traceBase
                val l2 = abs(a2 - a) * rm
                val l3 = re - rm
                val d = q * (l1 + l2 + l3)
                val x: Float
                val y: Float
                when {
                    d <= l1 -> { val r = traceBase + d; x = cx + r * cos(a); y = cy + r * sin(a) }
                    d <= l1 + l2 -> {
                        val ang = a + (a2 - a) * ((d - l1) / (if (l2 > 0f) l2 else 1f))
                        x = cx + rm * cos(ang); y = cy + rm * sin(ang)
                    }
                    else -> { val r = rm + (d - l1 - l2); x = cx + r * cos(a2); y = cy + r * sin(a2) }
                }
                val fade = 1f - q
                fill.color = withAlpha(acc, 0.35f * fade)
                canvas.drawCircle(x, y, 4.5f * u, fill)
                fill.color = withAlpha(if (dark) core else accLight, 0.95f * fade)
                canvas.drawCircle(x, y, 2.1f * u, fill)
            }
        }
        canvas.restore()
        stroke.strokeCap = Paint.Cap.BUTT
    }

    private fun easeOut(x: Float): Float = 1f - (1f - x).pow(3)

    companion object {
        /** Кольцо и диск — доли радиуса кнопки (как в макете). */
        const val RING = 0.79f
        const val DISC = 0.725f
        const val FLASH_MS = 1500L
        private const val TICKS = 96
        private const val TRACES = 64
        private const val PULSES = 9
        private const val COMET = 126f
        private const val TAU = (Math.PI * 2).toFloat()
    }
}
