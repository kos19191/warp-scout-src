package dev.warpscout.core.config

import dev.warpscout.core.lists.AllowLists

/**
 * Из чего складываются маршруты туннеля (с 1.10.35). Правила — здесь, без Android: приложение
 * (Prefs.allowedIps) подставляет собранные адреса, SelfCheck проверяет правила.
 *
 * Режимы «Туннелирования»: 0 — весь трафик, 1 — всё, кроме российских сетей, 2 — сайты из списков,
 * 3 — мои сайты. Поверх них — «Браузер — только к нужным сайтам»: если браузер среди выбранных
 * приложений, маршруты — отмеченные списки и свои сайты (сайты второго выхода сервис добавляет в
 * маршруты сам), а не весь трафик.
 *
 * При неполных маршрутах (списки, свои сайты, браузер) к ним добавляются сети выбранных приложений
 * известных сервисов (AppServices): Android пускает в туннель выбранные приложения, но адреса у
 * туннеля общие, и без своих сетей Telegram или Instagram шли бы через туннель только к выбранным
 * сайтам. Сети Google для видео YouTube — как с 1.10.33.
 */
object TunnelRoutes {

    const val FULL = "0.0.0.0/0, ::/0"

    /**
     * Части маршрутов: [base] — режим (или сайты для браузера), [apps] — добавленные сети выбранных
     * приложений, [video] — сети Google для видео YouTube, [browser] — действует «браузер — только к
     * нужным сайтам».
     */
    class Parts(val base: String, val apps: List<String>, val video: List<String>, val browser: Boolean) {
        /** Все маршруты строкой, как в `AllowedIPs`. */
        fun all(): String = (SplitRoutes.prefixesOf(base) + apps + video).joinToString(", ")
    }

    /**
     * @param mode    режим «Туннелирования» (0–3)
     * @param browser «Браузер — только к нужным сайтам» действует (браузер среди выбранных, всё собрано)
     * @param lists   маршруты по отмеченным спискам («» — не собраны)
     * @param own     маршруты своих сайтов («» — не собраны)
     * @param preset  «всё, кроме российских сетей»
     * @param appNets сети выбранных приложений («» — нет или не собраны)
     * @param youtube YouTube идёт через туннель (выбран он или его список)
     */
    fun compose(
        mode: Int,
        browser: Boolean,
        lists: String,
        own: String,
        preset: String,
        appNets: String,
        youtube: Boolean,
    ): Parts {
        val raw = when {
            browser -> SplitRoutes.union(lists, own)
            mode == 1 -> preset
            mode == 2 -> lists
            mode == 3 -> own
            else -> FULL
        }
        // «Весь трафик» и «кроме российских» — как было.
        if (!browser && (mode == 0 || mode == 1)) return Parts(raw, emptyList(), emptyList(), false)
        // Списки или свои сайты ещё не собраны — весь трафик: пустого туннеля не бывает.
        if (!browser && SplitRoutes.prefixesOf(raw).isEmpty()) return Parts(FULL, emptyList(), emptyList(), false)
        val base = SplitRoutes.prefixesOf(raw)
        val appPrefixes = SplitRoutes.prefixesOf(appNets)
        val apps = if (base.isEmpty()) appPrefixes.distinct() else SplitRoutes.missing(raw, appPrefixes)
        val withApps = (base + apps).joinToString(", ")
        // Ни сайтов, ни сетей приложений (браузер, но выбрать нечего) — весь трафик.
        if (SplitRoutes.prefixesOf(withApps).isEmpty()) return Parts(FULL, emptyList(), emptyList(), false)
        val video = if (youtube) SplitRoutes.missing(withApps, AllowLists.YOUTUBE_VIDEO_NETS) else emptyList()
        return Parts(raw, apps, video, browser)
    }
}
