package dev.warpscout.app

import android.os.Build
import android.view.View

/**
 * «Настройки» гармошкой (с 1.10.49-beta5): видны только заголовки разделов, нажатие на заголовок
 * раскрывает или сворачивает раздел. Какие разделы раскрыты, помнит [Prefs.settingsOpen]: вкладка
 * открывается такой, какой её оставили, и после перезапуска тоже.
 *
 * Тело раздела в разметке видно по умолчанию, сворачивает его только этот класс. Если он не
 * отработает, настройки останутся на виду, а не спрячутся насовсем.
 *
 * @param stateText что сказать TalkBack о разделе: «развёрнуто» или «свёрнуто».
 */
class SettingsAccordion(
    private val prefs: Prefs,
    private val stateText: (open: Boolean) -> String,
) {

    private class Group(val key: String, val head: View, val body: View, val arrow: View)

    private val groups = LinkedHashMap<String, Group>()

    /** Подключить раздел: заголовок [head] раскрывает и сворачивает [body], стрелка [arrow] поворачивается. */
    fun add(key: String, head: View, body: View, arrow: View) {
        val group = Group(key, head, body, arrow)
        groups[key] = group
        head.setOnClickListener { toggle(key) }
        render(group, isOpen(key), animate = false)
    }

    fun isOpen(key: String): Boolean = key in prefs.settingsOpen

    /** Раскрыть раздел, если он свёрнут (например, «Показать конфиг» открывает «Экспорт»). */
    fun open(key: String) = set(key, true)

    fun toggle(key: String) = set(key, !isOpen(key))

    /** Заголовок раздела: к нему прокручивают, когда раздел открывают из кода. */
    fun head(key: String): View? = groups[key]?.head

    /** Раскрыть всё: запасной путь, если что-то пошло не так, — настройки не должны прятаться. */
    fun showAll() {
        groups.values.forEach { it.body.visibility = View.VISIBLE }
    }

    private fun set(key: String, open: Boolean) {
        val now = prefs.settingsOpen
        val next = if (open) now + key else now - key
        if (next != now) prefs.settingsOpen = next
        groups[key]?.let { render(it, open, animate = true) }
    }

    private fun render(group: Group, open: Boolean, animate: Boolean) {
        group.body.visibility = if (open) View.VISIBLE else View.GONE
        val angle = if (open) 180f else 0f
        if (animate) {
            group.arrow.animate().rotation(angle).setDuration(ARROW_MS).start()
        } else {
            group.arrow.rotation = angle
        }
        if (Build.VERSION.SDK_INT >= 30) group.head.stateDescription = stateText(open)
    }

    companion object {
        private const val ARROW_MS = 160L
    }
}
