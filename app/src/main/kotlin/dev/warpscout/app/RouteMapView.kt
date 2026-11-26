package dev.warpscout.app

import android.animation.ValueAnimator
import android.content.Context
import android.content.res.Configuration
import android.graphics.Bitmap
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.DashPathEffect
import android.graphics.Paint
import android.graphics.Path
import android.graphics.RadialGradient
import android.graphics.RectF
import android.graphics.Shader
import android.graphics.drawable.Drawable
import android.os.SystemClock
import android.util.AttributeSet
import android.view.View
import android.view.animation.LinearInterpolator
import androidx.core.content.ContextCompat
import kotlin.math.cos
import kotlin.math.hypot
import kotlin.math.max
import kotlin.math.min
import kotlin.math.pow
import kotlin.math.sin

/**
 * Схема маршрута на тёмной карте (с 1.10.49-beta7, экран «Маршрут»), как на картинке с картой, которую
 * прислал человек: кварталы и улицы рисуются кодом (одинаково при каждом открытии), по улицам
 * светится линия «вы → вход → выход WARP → второй выход», от выходов пунктиром — приложения, которые
 * идут через каждый из них.
 *
 * Это схема, а не карта местности: где на самом деле стоят серверы, она не показывает. Линия
 * прорисовывается при открытии и при подключении, во время подключения бежит до входа; в остальное
 * время картинка неподвижна. Кварталы рисуются один раз в картинку на размер — в кадре только линия.
 */
class RouteMapView @JvmOverloads constructor(
    context: Context,
    attrs: AttributeSet? = null,
) : View(context, attrs) {

    /** Приложение у выхода: подпись (буквы, если значка нет) и значок. */
    class Branch(val label: String, val icon: Drawable?)

    var youLabel = ""
    var entryLabel = ""
    var warpLabel = ""

    /** null — второго выхода нет (на схеме его не рисуем). */
    var secondLabel: String? = null
    var warpApps: List<Branch> = emptyList()
    var secondApps: List<Branch> = emptyList()

    /**
     * Цвета дизайна: в «Премиуме» — оранжевый на тёмном, в классическом — цвета приложения, у «Нежного» и
     * «Стекла» (с 1.10.49-beta8) — цвета оттенка из темы окна: фон карты, дома, улицы и линия маршрута.
     */
    var design = Prefs.DESIGN_PREMIUM
        set(value) {
            if (field == value) return
            field = value
            loadColors()
            base = null
            invalidate()
        }
    private val premium: Boolean get() = design != Prefs.DESIGN_CLASSIC

    /** «Нежный» и «Стекло»: карта своими цветами. */
    private val custom: Boolean get() = design == Prefs.DESIGN_SOFT || design == Prefs.DESIGN_GLASS

    private var mode = MODE_OFF
    private var startedAt = 0L
    private var ticker: ValueAnimator? = null
    private var base: Bitmap? = null
    private var baseFor = ""
    private val dark = (context.resources.configuration.uiMode and Configuration.UI_MODE_NIGHT_MASK) ==
        Configuration.UI_MODE_NIGHT_YES
    private val density = resources.displayMetrics.density

    private var acc = 0
    private var accLight = 0
    private var mapBg = 0
    private var road = 0
    private var blue = 0
    private var text = 0
    private var labelBg = 0
    private var labelStroke = 0
    private var block = 0
    private var routeCore = 0

    private val paint = Paint(Paint.ANTI_ALIAS_FLAG)
    private val textPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply { textSize = 11.5f * resources.displayMetrics.scaledDensity }
    private val dash = DashPathEffect(floatArrayOf(3f * density, 6f * density), 0f)
    private val dashFine = DashPathEffect(floatArrayOf(2f * density, 4f * density), 0f)
    private val path = Path()
    private val rect = RectF()

    init {
        loadColors()
        contentDescription = context.getString(R.string.route_map_desc)
    }

    private fun loadColors() {
        fun c(res: Int) = ContextCompat.getColor(context, res)
        if (custom) {
            val l = Design.look(context)
            acc = l.accent
            accLight = l.accentLight
            mapBg = l.mapBg
            road = l.mapRoad
            blue = l.blue
            text = l.onSurface
            block = l.mapBlock
            routeCore = l.routeCore
            labelBg = if (dark) withAlpha(l.bg0, 0.86f) else Color.argb(235, 255, 255, 255)
        } else {
            acc = if (premium) c(R.color.prem_accent) else c(R.color.orb_accent)
            accLight = if (premium) c(R.color.prem_accent_light) else c(R.color.orb_accent)
            mapBg = c(R.color.prem_map_bg)
            road = c(R.color.prem_map_road)
            blue = c(R.color.prem_blue)
            text = if (premium) c(R.color.prem_on_surface) else c(R.color.colorOnSurface)
            block = mapBg
            routeCore = if (dark) Color.rgb(255, 214, 160) else acc
            labelBg = if (dark) Color.argb(210, 14, 10, 8) else Color.argb(235, 255, 255, 255)
        }
        labelStroke = withAlpha(acc, if (dark) 0.35f else 0.30f)
    }

    /** Оттенок цвета домов: светлее (f > 0) или темнее (f < 0) основного. */
    private fun shade(c: Int, f: Float): Int {
        val to = if (f > 0f) 255 else 0
        val k = kotlin.math.abs(f)
        return Color.rgb(
            (Color.red(c) + (to - Color.red(c)) * k).toInt(),
            (Color.green(c) + (to - Color.green(c)) * k).toInt(),
            (Color.blue(c) + (to - Color.blue(c)) * k).toInt()
        )
    }

    /** Состояние туннеля: выключен — пунктир, подключается — линия бежит до входа, работает — вся. */
    fun setMode(newMode: Int) {
        if (newMode == mode) return
        val old = mode
        mode = newMode
        if (newMode == MODE_CONNECTING || (newMode == MODE_ON && old != MODE_ON)) startedAt = SystemClock.uptimeMillis()
        updateTicker()
        invalidate()
    }

    /** Прорисовать линию заново (кнопка «Ещё раз»). */
    fun play() {
        startedAt = SystemClock.uptimeMillis()
        updateTicker()
        invalidate()
    }

    private fun animating(now: Long): Boolean = ValueAnimator.areAnimatorsEnabled() && when (mode) {
        MODE_CONNECTING -> true
        MODE_ON -> startedAt > 0L && now - startedAt < DRAW_MS + BRANCH_MS + 60L
        else -> false
    }

    private fun updateTicker() {
        val need = isAttachedToWindow && isShown && animating(SystemClock.uptimeMillis())
        if (need && ticker == null) {
            ticker = ValueAnimator.ofFloat(0f, 1f).apply {
                duration = 1000L
                repeatCount = ValueAnimator.INFINITE
                interpolator = LinearInterpolator()
                addUpdateListener {
                    invalidate()
                    if (!animating(SystemClock.uptimeMillis())) post { updateTicker() }
                }
                start()
            }
        } else if (!need && ticker != null) {
            ticker?.cancel()
            ticker = null
            invalidate()
        }
    }

    override fun onAttachedToWindow() {
        super.onAttachedToWindow()
        updateTicker()
    }

    override fun onDetachedFromWindow() {
        ticker?.cancel()
        ticker = null
        base?.recycle()
        base = null
        super.onDetachedFromWindow()
    }

    override fun onVisibilityChanged(changedView: View, visibility: Int) {
        super.onVisibilityChanged(changedView, visibility)
        updateTicker()
    }

    private fun withAlpha(color: Int, a: Float): Int =
        Color.argb((255 * a.coerceIn(0f, 1f)).toInt(), Color.red(color), Color.green(color), Color.blue(color))

    // ---------------------------------------------------------------- геометрия

    /** Масштаб схемы: макет рисовался на 362×352 точки, на других размерах — пропорционально. */
    private fun scale(): Float = min(1.25f, min(width / (362f * density), height / (352f * density)))

    private fun gridX(i: Float): Float {
        val k = scale() * density
        return (width - 362f * k) / 2f + (20f + 64f * i) * k
    }

    private fun gridY(j: Float): Float {
        val k = scale() * density
        return (height - 352f * k) / 2f + (18f + 64f * j) * k
    }

    /** Точка сетки улиц → экран: улицы чуть повёрнуты, карта не выглядит таблицей. */
    private fun toScreen(x: Float, y: Float, out: FloatArray) {
        val cx = width / 2f
        val cy = height / 2f
        val c = cos(ANGLE)
        val s = sin(ANGLE)
        val dx = x - cx
        val dy = y - cy
        out[0] = cx + dx * c - dy * s
        out[1] = cy + dx * s + dy * c
    }

    private class Node(val x: Float, val y: Float, val id: Int)

    private fun route(): List<Node> {
        val raw = arrayListOf(
            floatArrayOf(1f, 4f, ID_YOU.toFloat()), floatArrayOf(1f, 3f, 0f), floatArrayOf(2f, 3f, 0f),
            floatArrayOf(2f, 1f, ID_ENTRY.toFloat()), floatArrayOf(4f, 1f, ID_WARP.toFloat())
        )
        if (secondLabel != null) {
            raw += floatArrayOf(4f, 3f, 0f)
            raw += floatArrayOf(5f, 3f, ID_SECOND.toFloat())
        }
        val out = FloatArray(2)
        return raw.map {
            toScreen(gridX(it[0]), gridY(it[1]), out)
            Node(out[0], out[1], it[2].toInt())
        }
    }

    // ---------------------------------------------------------------- город

    private fun buildBase(): Bitmap? {
        val w = width
        val h = height
        if (w <= 0 || h <= 0) return null
        val key = "${w}x$h:$design"
        base?.let { if (key == baseFor && !it.isRecycled) return it }
        base?.recycle()
        val bmp = runCatching { Bitmap.createBitmap(w, h, Bitmap.Config.ARGB_8888) }.getOrNull() ?: return null
        baseFor = key
        val g = Canvas(bmp)
        g.drawColor(mapBg)
        val rnd = java.util.Random(1126L)
        val k = scale() * density
        val m = 64f * k
        val houses = if (custom) {
            intArrayOf(shade(block, 0f), shade(block, 0.12f), shade(block, -0.08f), shade(block, 0.22f), shade(block, -0.15f))
        } else if (dark) {
            intArrayOf(0xFF2B1D13.toInt(), 0xFF33220F.toInt(), 0xFF3D2914.toInt(), 0xFF241912.toInt(), 0xFF4A2F15.toInt())
        } else {
            intArrayOf(0xFFE3CBB2.toInt(), 0xFFDCC1A6.toInt(), 0xFFEAD6C1.toInt(), 0xFFD6B796.toInt(), 0xFFF0DFCC.toInt())
        }
        g.save()
        g.rotate(Math.toDegrees(ANGLE.toDouble()).toFloat(), w / 2f, h / 2f)
        val pad = 90f * density
        val x0 = gridX(0f) - m * 3f
        val y0 = gridY(0f) - m * 3f
        val xs = ArrayList<Float>()
        val ys = ArrayList<Float>()
        var x = x0
        while (x < w + pad) { xs += x; x += m }
        var y = y0
        while (y < h + pad) { ys += y; y += m }
        val fillP = Paint()
        val step = 6f * k
        for (i in 0 until xs.size - 1) {
            for (j in 0 until ys.size - 1) {
                val bx = xs[i] + step
                val by = ys[j] + step
                val bw = m - 2 * step
                val bh = m - 2 * step
                val split = rnd.nextFloat() < 0.6f
                val sx = bx + bw * (0.35f + rnd.nextFloat() * 0.3f)
                var hy = by
                while (hy < by + bh - 3f * k) {
                    var hx = bx
                    while (hx < bx + bw - 3f * k) {
                        val skip = (split && kotlin.math.abs(hx - sx) < 4f * k) || rnd.nextFloat() < 0.18f
                        if (!skip) {
                            val hw = (3f + rnd.nextFloat() * 5f) * k
                            val hh = (3f + rnd.nextFloat() * 4f) * k
                            fillP.color = houses[rnd.nextInt(houses.size)]
                            fillP.alpha = ((if (dark) 0.55f else 0.6f) * 255 + rnd.nextFloat() * 0.4f * 255).toInt().coerceAtMost(255)
                            g.drawRect(hx, hy, min(hx + hw, bx + bw), min(hy + hh, by + bh), fillP)
                        }
                        hx += (6f + rnd.nextFloat() * 5f) * k
                    }
                    hy += (6f + rnd.nextFloat() * 4f) * k
                }
            }
        }
        val line = Paint(Paint.ANTI_ALIAS_FLAG).apply { style = Paint.Style.STROKE }
        line.color = if (custom) road else if (dark) withAlpha(Color.rgb(120, 100, 85), 0.22f) else withAlpha(Color.WHITE, 0.95f)
        line.strokeWidth = 3f * k
        val top = y0
        val bottom = h + pad
        val left = x0
        val right = w + pad
        for (vx in xs) g.drawLine(vx, top, vx, bottom, line)
        for (vy in ys) g.drawLine(left, vy, right, vy, line)
        line.color = if (custom) Color.argb((Color.alpha(road) * 0.55f).toInt(), Color.red(road), Color.green(road), Color.blue(road)) else if (dark) withAlpha(Color.rgb(120, 100, 85), 0.12f) else withAlpha(Color.WHITE, 0.7f)
        line.strokeWidth = 1.2f * k
        for (vx in xs) g.drawLine(vx + m / 2f, top, vx + m / 2f, bottom, line)
        for (vy in ys) g.drawLine(left, vy + m / 2f, right, vy + m / 2f, line)
        line.color = if (custom) road else if (dark) withAlpha(Color.rgb(140, 110, 90), 0.20f) else withAlpha(Color.WHITE, 0.9f)
        line.strokeWidth = 4f * k
        g.drawLine(left, bottom - 60f * k, right, top + 120f * k, line)
        g.restore()
        val v = Paint().apply {
            shader = RadialGradient(
                w / 2f, h / 2f, max(w, h) * 0.75f,
                intArrayOf(
                    Color.TRANSPARENT, Color.TRANSPARENT,
                    if (dark) Color.argb(140, 0, 0, 0) else if (custom) Color.argb(20, 60, 50, 90) else Color.argb(26, 120, 80, 40)
                ),
                floatArrayOf(0f, 0.4f, 1f), Shader.TileMode.CLAMP
            )
        }
        g.drawRect(0f, 0f, w.toFloat(), h.toFloat(), v)
        base = bmp
        return bmp
    }

    // ---------------------------------------------------------------- кадр

    override fun onDraw(canvas: Canvas) {
        super.onDraw(canvas)
        if (width <= 0 || height <= 0) return
        buildBase()?.let { canvas.drawBitmap(it, 0f, 0f, null) }
        val now = SystemClock.uptimeMillis()
        val animate = ValueAnimator.areAnimatorsEnabled()
        val pts = route()
        val cum = FloatArray(pts.size)
        for (i in 1 until pts.size) cum[i] = cum[i - 1] + hypot(pts[i].x - pts[i - 1].x, pts[i].y - pts[i - 1].y)
        val total = cum.last()
        val entryAt = cum[pts.indexOfFirst { it.id == ID_ENTRY }.coerceAtLeast(0)]
        var reach = 0f
        var branches = 0f
        when (mode) {
            MODE_CONNECTING -> {
                val q = if (animate) ((now - startedAt) % 1500L) / 1500f else 1f
                reach = entryAt * easeOut(q)
            }
            MODE_ON -> {
                val e = if (animate && startedAt > 0L) ((now - startedAt) / DRAW_MS.toFloat()).coerceIn(0f, 1f) else 1f
                reach = total * (if (e < 0.5f) 2f * e * e else 1f - (-2f * e + 2f).pow(2) / 2f)
                branches = if (animate && startedAt > 0L) ((now - startedAt - DRAW_MS) / BRANCH_MS.toFloat()).coerceIn(0f, 1f) else 1f
            }
        }
        val k = scale() * density

        // Будущий путь — тусклым пунктиром.
        paint.reset()
        paint.isAntiAlias = true
        paint.style = Paint.Style.STROKE
        paint.strokeJoin = Paint.Join.ROUND
        paint.strokeCap = Paint.Cap.ROUND
        paint.pathEffect = dash
        paint.strokeWidth = 1.6f * density
        paint.color = withAlpha(acc, if (mode == MODE_OFF) 0.4f else 0.28f)
        polyline(canvas, pts, total)
        paint.pathEffect = null

        if (reach > 0.5f) {
            // Тёплое пятно вдоль маршрута, свечение и яркая сердцевина.
            paint.color = withAlpha(acc, 0.10f)
            paint.strokeWidth = 34f * k
            polyline(canvas, pts, reach)
            paint.color = withAlpha(acc, if (dark) 0.22f else 0.20f)
            paint.strokeWidth = 14f * k
            polyline(canvas, pts, reach)
            paint.color = withAlpha(acc, if (dark) 0.45f else 0.35f)
            paint.strokeWidth = 7f * k
            polyline(canvas, pts, reach)
            paint.color = if (custom) routeCore else if (dark) Color.rgb(255, 214, 160) else acc
            paint.strokeWidth = 2.6f * k
            polyline(canvas, pts, reach)
        }

        if (branches > 0f) drawBranches(canvas, pts, branches, k)

        pts.forEachIndexed { i, p ->
            if (p.id == 0) return@forEachIndexed
            val lit = when {
                p.id == ID_YOU -> true
                mode == MODE_OFF -> false
                mode == MODE_CONNECTING -> p.id == ID_ENTRY && reach >= cum[i] - 0.5f
                else -> reach >= cum[i] - 0.5f
            }
            drawNode(canvas, p, lit, k)
        }
    }

    private fun polyline(canvas: Canvas, pts: List<Node>, upTo: Float) {
        path.reset()
        path.moveTo(pts[0].x, pts[0].y)
        var done = 0f
        for (i in 1 until pts.size) {
            val a = pts[i - 1]
            val b = pts[i]
            val l = hypot(b.x - a.x, b.y - a.y)
            if (done + l <= upTo) {
                path.lineTo(b.x, b.y)
                done += l
                continue
            }
            val f = ((upTo - done) / l).coerceIn(0f, 1f)
            path.lineTo(a.x + (b.x - a.x) * f, a.y + (b.y - a.y) * f)
            break
        }
        canvas.drawPath(path, paint)
    }

    private fun drawNode(canvas: Canvas, p: Node, lit: Boolean, k: Float) {
        paint.reset()
        paint.isAntiAlias = true
        if (p.id == ID_YOU) {
            // Метка «вы»: капля с кольцом.
            val x = p.x
            val y = p.y
            paint.style = Paint.Style.FILL
            paint.color = if (dark) Color.argb(30, 255, 255, 255) else Color.argb(20, 0, 0, 0)
            rect.set(x - 9f * k, y - 4f * k, x + 9f * k, y + 4f * k)
            canvas.drawOval(rect, paint)
            val ink = if (dark) Color.WHITE else Color.rgb(42, 33, 27)
            path.reset()
            path.moveTo(x, y - 6f * k)
            path.cubicTo(x - 9f * k, y - 16f * k, x - 10f * k, y - 30f * k, x, y - 31f * k)
            path.cubicTo(x + 10f * k, y - 30f * k, x + 9f * k, y - 16f * k, x, y - 6f * k)
            paint.color = mapBg
            canvas.drawPath(path, paint)
            paint.style = Paint.Style.STROKE
            paint.strokeWidth = 2.2f * k
            paint.color = ink
            canvas.drawPath(path, paint)
            canvas.drawCircle(x, y, 4f * k, paint)
            canvas.drawCircle(x, y - 21f * k, 4f * k, paint)
            label(canvas, p, youLabel, k)
            return
        }
        val r = (if (p.id == ID_SECOND) 8f else 6.5f) * k
        paint.style = Paint.Style.FILL
        if (lit) {
            paint.color = withAlpha(acc, 0.25f)
            canvas.drawCircle(p.x, p.y, r * 2.2f, paint)
        }
        if (p.id == ID_SECOND) {
            paint.color = mapBg
            canvas.drawCircle(p.x, p.y, r, paint)
            paint.style = Paint.Style.STROKE
            paint.strokeWidth = 2.4f * k
            paint.color = if (lit) (if (dark) (if (custom) routeCore else Color.rgb(255, 241, 224)) else acc) else withAlpha(acc, 0.4f)
            canvas.drawCircle(p.x, p.y, r, paint)
            paint.style = Paint.Style.FILL
            paint.color = if (lit) acc else withAlpha(acc, 0.4f)
            canvas.drawCircle(p.x, p.y, 3f * k, paint)
        } else {
            paint.color = if (lit) acc else withAlpha(acc, 0.35f)
            canvas.drawCircle(p.x, p.y, r, paint)
            paint.color = if (dark) (if (custom) routeCore else Color.rgb(255, 244, 230)) else Color.WHITE
            canvas.drawCircle(p.x, p.y, 2.6f * k, paint)
        }
        if (lit) label(canvas, p, when (p.id) {
            ID_ENTRY -> entryLabel
            ID_WARP -> warpLabel
            else -> secondLabel.orEmpty()
        }, k)
    }

    private fun label(canvas: Canvas, p: Node, value: String, k: Float) {
        if (value.isBlank()) return
        textPaint.color = text
        textPaint.isFakeBoldText = true
        val tw = textPaint.measureText(value)
        val w = tw + 16f * density
        val h = 22f * density
        var x = when (p.id) {
            ID_YOU -> p.x + 14f * k
            ID_SECOND -> p.x - w + 6f * k
            else -> p.x - w / 2f
        }
        var y = when (p.id) {
            ID_YOU -> p.y - 2f * k
            ID_SECOND -> p.y + 14f * k
            else -> p.y - 32f * k - (h - 22f * k)
        }
        x = x.coerceIn(6f * density, max(6f * density, width - w - 6f * density))
        y = y.coerceIn(6f * density, max(6f * density, height - h - 6f * density))
        paint.reset()
        paint.isAntiAlias = true
        paint.style = Paint.Style.FILL
        paint.color = labelBg
        rect.set(x, y, x + w, y + h)
        canvas.drawRoundRect(rect, 8f * density, 8f * density, paint)
        paint.style = Paint.Style.STROKE
        paint.strokeWidth = density
        paint.color = labelStroke
        canvas.drawRoundRect(rect, 8f * density, 8f * density, paint)
        val fm = textPaint.fontMetrics
        canvas.drawText(value, x + 8f * density, y + h / 2f - (fm.ascent + fm.descent) / 2f, textPaint)
    }

    /** Пунктир к приложениям у выхода WARP и у второго выхода; значки — в кружках. */
    private fun drawBranches(canvas: Canvas, pts: List<Node>, f: Float, k: Float) {
        val sets = ArrayList<Pair<Node, List<Pair<Branch, FloatArray>>>>()
        pts.firstOrNull { it.id == ID_WARP }?.let { n ->
            val spots = listOf(floatArrayOf(-70f, -54f), floatArrayOf(34f, -64f), floatArrayOf(-118f, -40f))
            sets += n to warpApps.take(spots.size).mapIndexed { i, b -> b to spots[i] }
        }
        pts.firstOrNull { it.id == ID_SECOND }?.let { n ->
            val spots = listOf(floatArrayOf(-86f, 66f), floatArrayOf(-34f, 82f), floatArrayOf(12f, 74f), floatArrayOf(-136f, 60f))
            sets += n to secondApps.take(spots.size).mapIndexed { i, b -> b to spots[i] }
        }
        val alpha = (f * 255).toInt()
        val margin = 16f * density
        for ((from, items) in sets) {
            for ((branch, d) in items) {
                val x = (from.x + d[0] * k).coerceIn(margin, width - margin)
                val y = (from.y + d[1] * k).coerceIn(margin, height - margin)
                paint.reset()
                paint.isAntiAlias = true
                paint.style = Paint.Style.STROKE
                paint.pathEffect = dashFine
                paint.strokeWidth = 1.5f * density
                paint.color = if (dark) Color.argb((0.75f * alpha).toInt(), 255, 255, 255) else Color.argb((0.55f * alpha).toInt(), 40, 30, 20)
                path.reset()
                path.moveTo(from.x, from.y)
                path.lineTo(from.x, y)
                path.lineTo(x, y)
                canvas.drawPath(path, paint)
                paint.pathEffect = null
                val r = 12f * k
                paint.style = Paint.Style.FILL
                paint.color = withAlpha(blue, 0.30f * f)
                canvas.drawCircle(x, y, r * 1.6f, paint)
                val icon = branch.icon
                if (icon != null) {
                    paint.color = Color.argb(alpha, 255, 255, 255)
                    canvas.drawCircle(x, y, r + 1.5f * density, paint)
                    canvas.save()
                    path.reset()
                    path.addCircle(x, y, r, Path.Direction.CW)
                    canvas.clipPath(path)
                    icon.setBounds((x - r).toInt(), (y - r).toInt(), (x + r).toInt(), (y + r).toInt())
                    icon.alpha = alpha
                    icon.draw(canvas)
                    icon.alpha = 255
                    canvas.restore()
                } else {
                    paint.color = withAlpha(blue, f)
                    canvas.drawCircle(x, y, r, paint)
                    paint.style = Paint.Style.STROKE
                    paint.strokeWidth = 1.5f * density
                    paint.color = Color.argb((0.9f * alpha).toInt(), 255, 255, 255)
                    canvas.drawCircle(x, y, r, paint)
                    textPaint.color = Color.argb(alpha, 255, 255, 255)
                    textPaint.isFakeBoldText = true
                    val letters = branch.label.trim().take(2).ifBlank { "•" }
                    val tw = textPaint.measureText(letters)
                    val fm = textPaint.fontMetrics
                    canvas.drawText(letters, x - tw / 2f, y - (fm.ascent + fm.descent) / 2f, textPaint)
                }
            }
        }
    }

    private fun easeOut(x: Float): Float = 1f - (1f - x).pow(3)

    companion object {
        const val MODE_OFF = 0
        const val MODE_CONNECTING = 1
        const val MODE_ON = 2
        private const val ID_YOU = 1
        private const val ID_ENTRY = 2
        private const val ID_WARP = 3
        private const val ID_SECOND = 4
        private const val ANGLE = -0.12f
        private const val DRAW_MS = 2300L
        private const val BRANCH_MS = 700L
    }
}
