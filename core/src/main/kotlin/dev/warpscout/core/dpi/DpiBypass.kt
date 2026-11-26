package dev.warpscout.core.dpi

/**
 * Сайты одного сервиса для обхода DPI в туннеле (с 1.10.49-beta3, см. [DpiRelay]): имена (SNI), по
 * которым соединение узнаётся, цели «Проверить DPI», по которым решается, нужен ли обход на этой
 * сети, и приложения, чьи соединения туннель разбирает сам.
 */
class DpiFamily(
    val id: String,
    val title: String,
    val suffixes: List<String>,
    val targets: List<String>,
    val packages: List<String>
) {
    /** Имя сайта — этого сервиса: совпадает с одним из [suffixes] или кончается на «.суффикс». */
    fun matches(host: String): Boolean {
        val h = host.trim().trimEnd('.').lowercase()
        if (h.isEmpty()) return false
        return suffixes.any { s -> h == s || h.endsWith(".$s") }
    }

    override fun toString(): String = title
}

object DpiFamilies {
    /**
     * YouTube: страница и API (youtube.com, youtubei.googleapis.com), видео (googlevideo.com),
     * картинки (ytimg.com, ggpht.com). Приложения — YouTube, YouTube Music, Kids, ТВ, Studio и
     * распространённые сборки ReVanced.
     */
    val YOUTUBE = DpiFamily(
        "youtube", "YouTube",
        suffixes = listOf(
            "youtube.com", "youtu.be", "googlevideo.com", "ytimg.com", "ggpht.com", "youtube-nocookie.com",
            "youtubei.googleapis.com", "youtube.googleapis.com", "youtubekids.com", "yt.be"
        ),
        targets = listOf("youtube", "ytvideo", "googlevideo", "ytimg"),
        packages = listOf(
            "com.google.android.youtube", "com.google.android.apps.youtube.music",
            "com.google.android.apps.youtube.kids", "com.google.android.youtube.tv",
            "com.google.android.apps.youtube.creator", "app.revanced.android.youtube",
            "app.revanced.android.apps.youtube.music", "app.rvx.android.youtube"
        )
    )

    /** X (Twitter): сайт и API (x.com, twitter.com), картинки и видео (twimg.com), ссылки t.co. */
    val X = DpiFamily(
        "x", "X (Twitter)",
        suffixes = listOf("x.com", "twitter.com", "twimg.com", "t.co", "twttr.com"),
        targets = listOf("x"),
        packages = listOf("com.twitter.android", "com.twitter.android.lite")
    )

    val ALL: List<DpiFamily> = listOf(YOUTUBE, X)

    fun byId(id: String, families: List<DpiFamily> = ALL): DpiFamily? = families.firstOrNull { it.id == id }

    /** Сервис по имени сайта; null — имя ничьё. */
    fun ofHost(host: String, families: List<DpiFamily> = ALL): DpiFamily? = families.firstOrNull { it.matches(host) }
}

/**
 * Что обходить на одной сети: сервис → приём (с 1.10.49-beta3). Берётся из итога «Проверить DPI»
 * этой сети ([of]): сервис попадает в план, только если его режет DPI (или замедляет по имени), а
 * приём на этой сети помог. Открытое как есть, закрытое по адресу и то, чему приёмы не помогают, —
 * идёт через туннель, как раньше.
 */
class DpiPlan(val tricks: Map<String, DpiTrick>) {
    val isEmpty: Boolean get() = tricks.isEmpty()

    fun trickFor(familyId: String): DpiTrick? = tricks[familyId]

    /** «youtube=split,x=oob» — так план хранится в настройках сервиса. */
    fun encode(): String = tricks.entries.joinToString(",") { "${it.key}=${it.value.id}" }

    /** «YouTube — «разрез», X (Twitter) — «лишний байт (OOB)»». */
    fun describe(families: List<DpiFamily> = DpiFamilies.ALL): String =
        tricks.entries.joinToString(", ") { (id, t) -> "${DpiFamilies.byId(id, families)?.title ?: id} — «${t.title}»" }

    override fun equals(other: Any?): Boolean = other is DpiPlan && other.tricks == tricks
    override fun hashCode(): Int = tricks.hashCode()
    override fun toString(): String = encode()

    companion object {
        val EMPTY = DpiPlan(emptyMap())

        /** Строка для настроек сервиса: «ключ сети<TAB>план» (см. ServiceSettings.dpiPlans). */
        fun entry(network: String, plan: DpiPlan): String =
            network.replace('\t', ' ').replace('\n', ' ').trim() + "\t" + plan.encode()

        /** План сети [network] из строк [entry]; такой сети нет или ключ пустой — план пустой. */
        fun forNetwork(entries: List<String>, network: String): DpiPlan {
            val key = network.trim()
            if (key.isEmpty()) return EMPTY
            val e = entries.lastOrNull { it.substringBefore('\t').trim() == key } ?: return EMPTY
            return decode(e.substringAfter('\t', ""))
        }

        /** Разбор [encode]; неизвестные сервисы и приёмы пропускаются, «как есть» — тоже. */
        fun decode(text: String?, families: List<DpiFamily> = DpiFamilies.ALL): DpiPlan {
            if (text.isNullOrBlank()) return EMPTY
            val out = LinkedHashMap<String, DpiTrick>()
            text.split(',').forEach { part ->
                val id = part.substringBefore('=').trim()
                val trick = DpiTrick.byId(part.substringAfter('=', "").trim()) ?: return@forEach
                if (trick == DpiTrick.PLAIN || DpiFamilies.byId(id, families) == null) return@forEach
                out[id] = trick
            }
            return DpiPlan(out)
        }

        /**
         * План по итогу проверки. Итогу без контроля не верим — план пустой. Для сервиса берётся приём,
         * который помог большему числу его целей (страница, видео, картинки); поровну — тот, что
         * проще (раньше в [DpiTrick.BYPASS]): разрез надёжнее перестановки.
         */
        fun of(report: DpiReport, families: List<DpiFamily> = DpiFamilies.ALL): DpiPlan {
            if (!report.controlOk) return EMPTY
            val out = LinkedHashMap<String, DpiTrick>()
            for (fam in families) {
                val need = report.results.filter {
                    it.target.id in fam.targets && (it.verdict == DpiVerdict.BYPASS || it.verdict == DpiVerdict.FASTER)
                }
                if (need.isEmpty()) continue
                val counts = LinkedHashMap<DpiTrick, Int>()
                need.forEach { r -> r.helpers.filter { it != DpiTrick.PLAIN }.forEach { counts[it] = (counts[it] ?: 0) + 1 } }
                val best = counts.entries.sortedWith(
                    compareByDescending<Map.Entry<DpiTrick, Int>> { it.value }.thenBy { DpiTrick.BYPASS.indexOf(it.key) }
                ).firstOrNull()?.key ?: continue
                out[fam.id] = best
            }
            return DpiPlan(out)
        }
    }
}
