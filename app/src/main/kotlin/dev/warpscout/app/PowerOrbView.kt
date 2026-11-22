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
 * Значок питания, надпись и таймер лежат поверх — обычными View в разметке: так их проще
 * озвучивать TalkBack и менять текстом, не перерисовывая круг.
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
    private val arcBox = RectF()

    private var state = STATE_OFF
    private var sweepStart = -90f
    private var spinner: ValueAnimator? = null

    /** Шейдеры зависят от размера и цвета: пересобираем только когда меняется одно из двух. */
    private var shadersFor = ""

    /** Сменить состояние; одинаковое повторно не перерисовывает. */
    fun setState(newState: Int) {
        if (newState == state) return
        state = newState
        shadersFor = ""
        updateSpinner()
        invalidate()
    }

    private fun color(res: Int): Int = ContextCompat.getColor(context, res)

    private fun accentFor(s: Int): Int = when (s) {
        STATE_ON -> color(R.color.orb_accent)
        STATE_CONNECTING -> color(R.color.orb_warn)
        STATE_ERROR -> color(R.color.orb_error)
        else -> color(R.color.orb_ring_off)
    }

    override fun onDraw(canvas: Canvas) {
        super.onDraw(canvas)
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

        ringPaint.strokeWidth = 3f * density
        ringPaint.color = if (state == STATE_CONNECTING) withAlpha(accent, 0.30f) else accent
        canvas.drawCircle(cx, cy, disc, ringPaint)

        if (state == STATE_CONNECTING) {
            arcPaint.strokeWidth = 3.5f * density
            arcPaint.color = accent
            arcBox.set(cx - disc, cy - disc, cx + disc, cy + disc)
            canvas.drawArc(arcBox, sweepStart, 80f, false, arcPaint)
        }
    }

    private fun withAlpha(c: Int, a: Float): Int =
        Color.argb((Color.alpha(c) * a).toInt().coerceIn(0, 255), Color.red(c), Color.green(c), Color.blue(c))

    /** Дуга крутится только пока идёт подключение и View видна. */
    private fun updateSpinner() {
        val need = state == STATE_CONNECTING && isAttachedToWindow && isShown
        if (need && spinner == null) {
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
