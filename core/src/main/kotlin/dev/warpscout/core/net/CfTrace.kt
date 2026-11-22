package dev.warpscout.core.net

/**
 * Ответ Cloudflare на `/cdn-cgi/trace`: прошёл ли запрос через WARP и откуда виден выход.
 *
 * Зачем отдельно и в ядре. Разбор — чистая функция, и её проверяет SelfCheck. Раньше «регион
 * выхода» показывался без поля `warp`: запрос, ушедший мимо туннеля (туннель ещё поднимался или
 * уже переключался), выдавал адрес провайдера за «регион выхода через WARP» — в журнале 13:35:37
 * и 14:29:55 так и стояло «HEL · RU · 185.126.130.6». Теперь мимо WARP — так и пишется.
 */
data class CfTrace(
    /** Площадка Cloudflare, куда пришёл запрос (FRA, HEL…). */
    val colo: String,
    /** Страна по адресу выхода. У WARP это страна пользователя: Cloudflare так назначает адреса. */
    val loc: String,
    /** Адрес, с которым запрос вышел в интернет. */
    val ip: String,
    /** `on` / `plus` — через WARP, `off` — мимо. */
    val warp: String,
) {
    /** Запрос прошёл через WARP. */
    val viaWarp: Boolean get() = warp == "on" || warp == "plus"

    /** «FRA · RU · 2a09:…» — коротко, для журнала и экрана. */
    fun summary(): String = listOf(colo, loc, ip).filter { it.isNotBlank() }.joinToString(" · ")

    companion object {
        /** Адрес проверки: по IP, без DNS — проверяем сам путь данных, а не резолвер. */
        const val URL_BY_IP = "https://1.1.1.1/cdn-cgi/trace"

        /**
         * Разобрать ответ. null — это не trace: страница портала Wi-Fi, обрезанный или пустой ответ.
         */
        fun parse(text: String?): CfTrace? {
            if (text.isNullOrBlank()) return null
            val map = HashMap<String, String>()
            for (line in text.lineSequence()) {
                val i = line.indexOf('=')
                if (i <= 0) continue
                val key = line.substring(0, i).trim()
                // Ключи trace — короткие латинские слова; всё прочее (HTML, JSON) не наш ответ.
                if (key.isEmpty() || key.length > 16 || !key.all { it.isLetterOrDigit() || it == '_' }) continue
                map[key] = line.substring(i + 1).trim()
            }
            val colo = map["colo"].orEmpty()
            val ip = map["ip"].orEmpty()
            if (colo.isBlank() && ip.isBlank()) return null
            return CfTrace(
                colo = colo,
                loc = map["loc"].orEmpty(),
                ip = ip,
                warp = map["warp"].orEmpty().lowercase(),
            )
        }
    }
}
