package dev.warpscout.core.tunnel

import dev.warpscout.core.state.ServiceSettings

/**
 * Начальные экраны (бета, с 1.10.44-beta6), первый из двух: какие приложения пускать через туннель.
 *
 * Человек попросил 25.11: «Первый будет указать какие приложения будут идти через туннель, которые
 * мы отметили уже должны быть отмечены и там выбрать можно, сохранить или пропустить». Экраны —
 * только после новой установки, один раз.
 *
 * Отмечено сразу то, что приложение отметило бы само: набор по умолчанию (Telegram, Instagram,
 * YouTube, Facebook, X — DefaultApps) и в бете — приложения «второго выхода по умолчанию» (TikTok,
 * ChatGPT, Claude, Gemini, Grok — [SecondDefaults]), плюс то, что уже отмечено в «только выбранные».
 * «Пропустить» ничего не меняет: наборы по умолчанию работают, как работали. «Сохранить» — режим
 * «только выбранные» ровно с отмеченными; снятое из отмеченных сразу попадает в «сняли руками», и
 * ни набор по умолчанию, ни второй выход по умолчанию его обратно не отметят.
 */
object WelcomeApps {

    /**
     * Что отмечено, когда экран открылся: прежние отметки «только выбранные» и наборы по умолчанию,
     * кроме снятых руками. Только установленные — других в списке нет. Отметки «все, кроме» — это
     * исключения из туннеля, а не выбор: отмеченными они не показываются.
     *
     * @param installed установленные приложения (пакеты) — строки списка
     * @param defaults  набор по умолчанию среди установленных
     * @param second    «второй выход по умолчанию» среди установленных (в обычной версии — пусто)
     * @param appsMode  [ServiceSettings.APPS_ALL] / [ServiceSettings.APPS_ONLY] / [ServiceSettings.APPS_EXCEPT]
     * @param selected  отмеченные сейчас
     * @param unticked  с кого человек снял галочку руками
     */
    fun preset(
        installed: Collection<String>,
        defaults: Collection<String>,
        second: Collection<String>,
        appsMode: Int,
        selected: Set<String>,
        unticked: Set<String>,
    ): Set<String> {
        val have = clean(installed)
        val out = LinkedHashSet<String>()
        if (appsMode == ServiceSettings.APPS_ONLY) selected.map { it.trim() }.filterTo(out) { it in have }
        (defaults + second).map { it.trim() }.filterTo(out) { it in have && it !in unticked }
        return out
    }

    /**
     * «Сохранить»: новый список «только выбранные» — отмеченные на экране и прежние отметки
     * приложений, которых сейчас нет на телефоне (в списке их не было, снимать их никто не просил).
     * Ничего не отмечено — пустой список: сервис тогда пускает через туннель все приложения.
     */
    fun selectedAfterSave(
        installed: Collection<String>,
        checked: Set<String>,
        appsMode: Int,
        selected: Set<String>,
    ): Set<String> {
        val have = clean(installed)
        val out = LinkedHashSet<String>()
        checked.map { it.trim() }.filterTo(out) { it in have }
        if (appsMode == ServiceSettings.APPS_ONLY) selected.map { it.trim() }.filterTo(out) { it.isNotEmpty() && it !in have }
        return out
    }

    /** Снятые на экране из отмеченных сразу: их больше не отмечаем сами (ни набор, ни второй выход). */
    fun untickedOnSave(preset: Set<String>, checked: Set<String>): Set<String> = preset - checked

    private fun clean(pkgs: Collection<String>): Set<String> =
        pkgs.map { it.trim() }.filter { it.isNotEmpty() }.toSet()
}
