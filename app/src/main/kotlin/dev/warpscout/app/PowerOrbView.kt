package dev.warpscout.app

import android.animation.ValueAnimator
import android.content.Context
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.LinearGradient
import android.graphics.Paint
import android.graphics.RadialGradient
import android.graphics.RectF
import android.graphics.Shader
import android.util.AttributeSet
import android.view.View
import android.view.animation.LinearInterpolator
import androidx.core.content.ContextCompat

/**
 * Круг главной кнопки упрощённого экрана: диск, кольцо и мягкое свечение вокруг.
 *
 * Своя View, а не картинка: цвета кольца и свечения зависят от состояния (выключен, подключаюсь,
 * работает, связи нет) и от темы, а рисовать их надо без единого пикселя растрового «стекла».
 * Анимации фона нет (так договорились: экран не должен тратить батарею, пока открыт). Движется
 * только дуга во время подключения — это индикатор работы, и он останавливается вместе с ним,
 * а также когда View не на экране.
 *
 * С 1.10.30 — кольцо-прогресс (так выбрал человек): пока идёт подбор, кольцо заполняется по ходу
 * поиска ([setProgress]), а при подключении по кольцу бежит светлая дуга. Заполнение плавное, но
 * анимируется только переход к новому значению (300 мс), без бесконечных циклов.
 *
 * Значок питания, надпись и таймер лежат поверх — обычными View в разметке: так их проще
 * озвучивать TalkBack и менять текстом, не перерисовывая круг.
 *
 * С 1.10.49-beta7 у кнопки два облика: классический (всё сказанное выше) и «Премиум» ([premium],
 * рисует [PremiumOrbPainter]): неоновое кольцо со щитом, «микросхема» при подборе, бегущий свет при
 * подключении, вспышка щита при успехе. В «Премиуме» кадры идут, пока идёт подбор, подключение или
 * вспышка, и только пока кнопка на экране; в покое кадр рисуется один раз. Если в настройках телефона
 * анимации выключены — кадры неподвижные.
 */
class PowerOrbView @JvmOverloads constructor(
    context: Context,
    attrs: AttributeSet? = null,
) : View(context, attrs) {

    private val glowPaint = Paint(Paint.ANTI_ALIAS_FLAG)
    private val discPaint = Paint(Paint.ANTI_ALIAS_FLAG)
    private val ringPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply { style = Paint.Style.STROKE }
    private val innerPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply { style = Paint.Style.STROKE }
    private val arcPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.STROKE
        strokeCap = Paint.Cap.ROUND
    }
    private val progressPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.STROKE
        strokeCap = Paint.Cap.ROUND
    }
    private val headPaint = Paint(Paint.ANTI_ALIAS_FLAG)
    private val arcBox = RectF()

    private var state = STATE_OFF
    private var sweepStart = -90f
    private var spinner: ValueAnimator? = null

    /** Доля заполнения кольца, которая сейчас нарисована; меньше нуля — прогресса нет. */
    private var shownProgress = -1f

    /** Куда кольцо идёт. */
    private var targetProgress = -1f
    private var progressAnim: ValueAnimator? = null

    /** Шейдеры зависят от размера и цвета: пересобираем только когда меняется одно из двух. */
    private var shadersFor = ""

    /** Облик «Премиум» (с 1.10.49-beta7, выбор — «Оформление»). */
    var premium: Boolean = false
        set(value) {
            if (field == value) return
            field = value
            painter = if (value) PremiumOrbPainter(context) else null
            shadersFor = ""
            // У обликов разные аниматоры: старый останавливаем, нужный запустится заново.
            spinner?.cancel()
            spinner = null
            updateSpinner()
            invalidate()
        }
    private var painter: PremiumOrbPainter? = null

    /** Когда началась вспышка «подключено» (uptime, мс); 0 — не было. Только «Премиум». */
    private var flashStart = 0L

    /** Радиус, внутри которого помещаются надписи кнопки, — для подгонки строки скорости. */
    fun innerRadius(): Float {
        val size = minOf(width, height).toFloat()
        val density = resources.displayMetrics.density
        return painter?.innerRadius(size, density) ?: (size / 2f * 0.76f - 7f * density)
    }

    /** Сменить состояние; одинаковое повторно не перерисовывает. */
    fun setState(newState: Int) {
        if (newState == state) return
        val old = state
        state = newState
        shadersFor = ""
        // «Премиум»: подключились — вспышка щита (подбор и подключение у кнопки — одно состояние).
        if (premium && newState == STATE_ON && old == STATE_CONNECTING && isShown) {
            flashStart = android.os.SystemClock.uptimeMillis()
        } else if (newState != STATE_ON) {
            flashStart = 0L
        }
        updateSpinner()
        invalidate()
    }

    /**
     * Прогресс подбора: 0..1 — кольцо заполнено на эту долю, null или меньше нуля — кольца-прогресса
     * нет (обычное кольцо состояния). Повтор того же значения ничего не делает. Заметный откат
     * назад (подбор начался заново: быстрый старт не подтвердился) — без анимации.
     */
    fun setProgress(fraction: Float?) {
        val target = fraction?.takeIf { it >= 0f }?.coerceIn(0f, 1f) ?: -1f
        if (kotlin.math.abs(target - targetProgress) < 0.002f) return
        targetProgress = target
        progressAnim?.cancel()
        progressAnim = null
        val from = shownProgress
        if (target < 0f || from < 0f || target < from - 0.25f || !isAttachedToWindow) {
            shownProgress = target
            updateSpinner()
            invalidate()
            return
        }
        progressAnim = ValueAnimator.ofFloat(from, target).apply {
            duration = 300L
            addUpdateListener { a ->
                shownProgress = a.animatedValue as Float
                invalidate()
            }
            start()
        }
        updateSpinner()
    }

    private fun color(res: Int): Int = ContextCompat.getColor(context, res)

    /** Светлый вариант цвета: дуга подключения «бежит светом» по кольцу. */
    private fun lighter(c: Int, k: Float): Int = Color.argb(
        Color.alpha(c),
        (Color.red(c) + (255 - Color.red(c)) * k).toInt().coerceIn(0, 255),
        (Color.green(c) + (255 - Color.green(c)) * k).toInt().coerceIn(0, 255),
        (Color.blue(c) + (255 - Color.blue(c)) * k).toInt().coerceIn(0, 255)
    )

    private fun accentFor(s: Int): Int = when (s) {
        STATE_ON -> color(R.color.orb_accent)
        STATE_CONNECTING -> color(R.color.orb_warn)
        STATE_ERROR -> color(R.color.orb_error)
        else -> color(R.color.orb_ring_off)
    }

    override fun onDraw(canvas: Canvas) {
        super.onDraw(canvas)
        painter?.let { p ->
            p.draw(
                canvas, width, height, state, shownProgress, android.os.SystemClock.uptimeMillis(), flashStart,
                ValueAnimator.areAnimatorsEnabled()
            )
            return
        }
        val size = minOf(width, height).toFloat()
        if (size <= 0f) return
        val cx = width / 2f
        val cy = height / 2f
        val outer = size / 2f
        val disc = outer * 0.76f
        val density = resources.displayMetrics.density
        val accent = accentFor(state)
        val key = "$width×$height:$state:$accent"
        if (key != shadersFor) {
            shadersFor = key
            // Свечение — только у «работает» и «связи нет»: выключенная кнопка не должна светиться.
            val glowAlpha = when (state) {
                STATE_ON -> 0.34f
                STATE_ERROR -> 0.28f
                STATE_CONNECTING -> 0.18f
                else -> 0f
            }
            glowPaint.shader = if (glowAlpha > 0f) {
                RadialGradient(
                    cx, cy, outer,
                    intArrayOf(withAlpha(accent, glowAlpha), withAlpha(accent, glowAlpha * 0.45f), Color.TRANSPARENT),
                    floatArrayOf(disc / outer, 0.86f, 1f),
                    Shader.TileMode.CLAMP
                )
            } else {
                null
            }
            discPaint.shader = LinearGradient(
                cx, cy - disc, cx, cy + disc,
                color(R.color.orb_disc_top), color(R.color.orb_disc_bottom),
                Shader.TileMode.CLAMP
            )
        }
        if (glowPaint.shader != null) canvas.drawCircle(cx, cy, outer, glowPaint)
        canvas.drawCircle(cx, cy, disc, discPaint)

        // Тонкое внутреннее кольцо даёт диску объём и в светлой, и в тёмной теме.
        innerPaint.strokeWidth = 1f * density
        innerPaint.color = withAlpha(color(R.color.orb_ring_off), 0.55f)
        canvas.drawCircle(cx, cy, disc - 7f * density, innerPaint)

        val showProgress = shownProgress >= 0f
        ringPaint.strokeWidth = 3f * density
        ringPaint.color = if (state == STATE_CONNECTING || showProgress) withAlpha(accent, 0.30f) else accent
        canvas.drawCircle(cx, cy, disc, ringPaint)
        arcBox.set(cx - disc, cy - disc, cx + disc, cy + disc)

        if (showProgress) {
            // Кольцо-прогресс подбора: заполненная часть — цветом состояния, конец — светлой точкой,
            // чтобы было видно, где поиск сейчас.
            val sweep = 360f * shownProgress
            progressPaint.strokeWidth = 4f * density
            progressPaint.color = accent
            if (sweep > 0.5f) canvas.drawArc(arcBox, -90f, sweep, false, progressPaint)
            val angle = Math.toRadians((-90f + sweep).toDouble())
            headPaint.color = lighter(accent, 0.55f)
            canvas.drawCircle(
                cx + disc * kotlin.math.cos(angle).toFloat(),
                cy + disc * kotlin.math.sin(angle).toFloat(),
                3.2f * density,
                headPaint
            )
        } else if (state == STATE_CONNECTING) {
            // Подключение: по кольцу бежит светлая дуга.
            arcPaint.strokeWidth = 3.5f * density
            arcPaint.color = lighter(accent, 0.45f)
            canvas.drawArc(arcBox, sweepStart, 80f, false, arcPaint)
        }
    }

    private fun withAlpha(c: Int, a: Float): Int =
        Color.argb((Color.alpha(c) * a).toInt().coerceIn(0, 255), Color.red(c), Color.green(c), Color.blue(c))

    /** «Премиум»: идёт вспышка «подключено». */
    private fun flashing(): Boolean =
        flashStart > 0L && android.os.SystemClock.uptimeMillis() - flashStart < PremiumOrbPainter.FLASH_MS

    /**
     * Дуга крутится только пока идёт подключение (не подбор с кольцом-прогрессом) и View видна. В
     * «Премиуме» кадры нужны и во время подбора («микросхема») и вспышки — тогда тот же аниматор
     * просто перерисовывает кнопку каждый кадр.
     */
    private fun updateSpinner() {
        val visible = isAttachedToWindow && isShown
        val need = if (premium) {
            visible && ValueAnimator.areAnimatorsEnabled() &&
                (state == STATE_CONNECTING || targetProgress >= 0f || flashing())
        } else {
            state == STATE_CONNECTING && targetProgress < 0f && visible
        }
        if (need && spinner == null && premium) {
            spinner = ValueAnimator.ofFloat(0f, 1f).apply {
                duration = 1_000L
                repeatCount = ValueAnimator.INFINITE
                interpolator = LinearInterpolator()
                addUpdateListener {
                    invalidate()
                    // Вспышка кончилась, а подключение уже не идёт — кадры больше не нужны.
                    if (state == STATE_ON && !flashing() && targetProgress < 0f) post { updateSpinner() }
                }
                start()
            }
        } else if (need && spinner == null) {
            spinner = ValueAnimator.ofFloat(0f, 360f).apply {
                duration = 1_400L
                repeatCount = ValueAnimator.INFINITE
                interpolator = LinearInterpolator()
                addUpdateListener { a ->
                    sweepStart = -90f + (a.animatedValue as Float)
                    invalidate()
                }
                start()
            }
        } else if (!need && spinner != null) {
            spinner?.cancel()
            spinner = null
        }
    }

    override fun onAttachedToWindow() {
        super.onAttachedToWindow()
        updateSpinner()
    }

    override fun onDetachedFromWindow() {
        spinner?.cancel()
        spinner = null
        progressAnim?.cancel()
        progressAnim = null
        if (targetProgress >= 0f) shownProgress = targetProgress
        super.onDetachedFromWindow()
    }

    override fun onVisibilityChanged(changedView: View, visibility: Int) {
        super.onVisibilityChanged(changedView, visibility)
        updateSpinner()
    }

    override fun onWindowVisibilityChanged(visibility: Int) {
        super.onWindowVisibilityChanged(visibility)
        updateSpinner()
    }

    companion object {
        const val STATE_OFF = 0
        const val STATE_CONNECTING = 1
        const val STATE_ON = 2

        /** Туннель поднят, но проверка связи не получила ответа. */
        const val STATE_ERROR = 3
    }
}
