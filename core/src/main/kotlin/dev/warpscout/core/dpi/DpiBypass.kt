package dev.warpscout.core.dpi

/**
 * Сервис для обхода DPI в туннеле: его приложения (их соединения туннель разбирает сам, см.
 * [DpiRelay]) и название. С 1.10.49-beta4 сервис отделён от сайтов: у YouTube страница, видео и
 * картинки — разные группы сайтов ([DpiFamily]) со своим приёмом, а приложения — одни.
 */
class DpiService(val id: String, val title: String, val packages: List<String>) {
    override fun toString(): String = title
}

object DpiServices {
    /** YouTube, YouTube Music, Kids, ТВ, Studio и распространённые сборки ReVanced. */
    val YOUTUBE = DpiService(
        "youtube", "YouTube",
        packages = listOf(
            "com.google.android.youtube", "com.google.android.apps.youtube.music",
            "com.google.android.apps.youtube.kids", "com.google.android.youtube.tv",
            "com.google.android.apps.youtube.creator", "app.revanced.android.youtube",
            "app.revanced.android.apps.youtube.music", "app.rvx.android.youtube"
        )
    )

    val X = DpiService("x", "X (Twitter)", listOf("com.twitter.android", "com.twitter.android.lite"))

    /** С 1.10.49-beta4: на Tele2 Discord режут по имени, а лишний байт (OOB) его открывает. */
    val DISCORD = DpiService("discord", "Discord", listOf("com.discord"))

    val ALL: List<DpiService> = listOf(YOUTUBE, X, DISCORD)

    fun byId(id: String, services: List<DpiService> = ALL): DpiService? = services.firstOrNull { it.id == id }
}

/**
 * Группа сайтов одного сервиса: имена (SNI), по которым соединение узнаётся, цели «Проверить DPI»,
 * по которым решается, нужен ли обход на этой сети, и сервис ([DpiService]), чьи это приложения.
 * [primary] — главное у сервиса (страница, видео): только ради него приложения сервиса разбираются
 * (картинки отдельно не стоят того, чтобы гонять через свой TCP всё приложение и закрывать ему QUIC).
 */
class DpiFamily(
    val id: String,
    val title: String,
    val suffixes: List<String>,
    val targets: List<String>,
    val service: String,
    val primary: Boolean = true
) {
    /** Имя сайта — этой группы: совпадает с одним из [suffixes] или кончается на «.суффикс». */
    fun matches(host: String): Boolean {
        val h = host.trim().trimEnd('.').lowercase()
        if (h.isEmpty()) return false
        return suffixes.any { s -> h == s || h.endsWith(".$s") }
    }

    override fun toString(): String = title
}

object DpiFamilies {
    /** Страница и API YouTube (youtube.com, youtubei.googleapis.com). */
    val YOUTUBE = DpiFamily(
        "youtube", "YouTube",
        suffixes = listOf(
            "youtube.com", "youtu.be", "youtube-nocookie.com", "youtubei.googleapis.com", "youtube.googleapis.com",
            "youtubekids.com", "yt.be"
        ),
        targets = listOf("youtube"), service = "youtube"
    )

    /** Видео YouTube: узлы rrN---sn-….googlevideo.com и их редиректор. */
    val YT_VIDEO = DpiFamily(
        "ytvideo", "Видео YouTube", listOf("googlevideo.com"), listOf(DpiTargets.VIDEO_ID, "googlevideo"), service = "youtube"
    )

    /** Картинки и аватарки YouTube. */
    val YT_IMG = DpiFamily("ytimg", "Картинки YouTube", listOf("ytimg.com", "ggpht.com"), listOf("ytimg"), service = "youtube", primary = false)

    /** X (Twitter): сайт и API (x.com, twitter.com), картинки и видео (twimg.com), ссылки t.co. */
    val X = DpiFamily("x", "X (Twitter)", listOf("x.com", "twitter.com", "twimg.com", "t.co", "twttr.com"), listOf("x"), service = "x")

    /** Discord: сайт, API, шлюз, файлы и картинки. */
    val DISCORD = DpiFamily(
        "discord", "Discord",
        listOf(
            "discord.com", "discord.gg", "discordapp.com", "discordapp.net", "discord.media", "discordcdn.com",
            "discord.new", "discord.gift", "dis.gd", "discordstatus.com"
        ),
        listOf("discord"), service = "discord"
    )

    val ALL: List<DpiFamily> = listOf(YOUTUBE, YT_VIDEO, YT_IMG, X, DISCORD)

    fun byId(id: String, families: List<DpiFamily> = ALL): DpiFamily? = families.firstOrNull { it.id == id }

    /** Группа по имени сайта; null — имя ничьё. */
    fun ofHost(host: String, families: List<DpiFamily> = ALL): DpiFamily? = families.firstOrNull { it.matches(host) }
}

/**
 * Что обходить на одной сети: группа сайтов → приём (с 1.10.49-beta3; с beta4 — по группам, а не
 * по сервисам целиком). Берётся из итога «Проверить DPI» этой сети ([of]) или из выбора человека
 * ([effective]). Открытое как есть, закрытое по адресу и то, чему приёмы не помогают, — идёт через
 * туннель, как раньше.
 */
class DpiPlan(val tricks: Map<String, DpiTrick>) {
    val isEmpty: Boolean get() = tricks.isEmpty()

    fun trickFor(familyId: String): DpiTrick? = tricks[familyId]

    /** Разбирать ли соединения приложений сервиса: в плане есть его главное (страница или видео). */
    fun coversService(service: String, families: List<DpiFamily> = DpiFamilies.ALL): Boolean =
        families.any { it.service == service && it.primary && tricks.containsKey(it.id) }

    /** «youtube=split,x=oob» — так план хранится в настройках сервиса. */
    fun encode(): String = tricks.entries.joinToString(",") { "${it.key}=${it.value.id}" }

    /** «YouTube — «разрез», X (Twitter) — «лишний байт (OOB)»». */
    fun describe(families: List<DpiFamily> = DpiFamilies.ALL): String =
        tricks.entries.joinToString(", ") { (id, t) -> "${DpiFamilies.byId(id, families)?.title ?: id} — ${trickLabel(t)}" }

    override fun equals(other: Any?): Boolean = other is DpiPlan && other.tricks == tricks
    override fun hashCode(): Int = tricks.hashCode()
    override fun toString(): String = encode()

    companion object {
        val EMPTY = DpiPlan(emptyMap())

        /** Метка формата плана в настройках (с beta4): планы beta3 подбирались по одним картинкам. */
        const val VERSION = "v2:"

        /** Выбор «по проверке этой сети». */
        const val AUTO = "auto"

        /** Выбор «не обходить». */
        const val OFF = "off"

        /** Выбор сервиса «как общая стратегия». */
        const val INHERIT = ""

        /** «разрез» или «своя стратегия (--split 1+s)». */
        fun trickLabel(t: DpiTrick): String = if (t.isCustom) "«своя» (${t.byedpi})" else "«${t.title}»"

        /** Строка для настроек сервиса: «ключ сети<TAB>v2:план» (см. ServiceSettings.dpiPlans). */
        fun entry(network: String, plan: DpiPlan): String =
            network.replace('\t', ' ').replace('\n', ' ').trim() + "\t" + VERSION + plan.encode()

        /**
         * План сети [network] из строк [entry]; такой сети нет, ключ пустой или план старого формата
         * (beta3, без [VERSION]) — план пустой: его надо подобрать заново.
         */
        fun forNetwork(entries: List<String>, network: String, custom: DpiTrick? = null): DpiPlan {
            val key = network.trim()
            if (key.isEmpty()) return EMPTY
            val e = entries.lastOrNull { it.substringBefore('\t').trim() == key } ?: return EMPTY
            val text = e.substringAfter('\t', "")
            if (!text.startsWith(VERSION)) return EMPTY
            return decode(text.removePrefix(VERSION), custom = custom)
        }

        /** Разбор [encode]; неизвестные группы и приёмы пропускаются, «как есть» — тоже. */
        fun decode(text: String?, families: List<DpiFamily> = DpiFamilies.ALL, custom: DpiTrick? = null): DpiPlan {
            if (text.isNullOrBlank()) return EMPTY
            val out = LinkedHashMap<String, DpiTrick>()
            text.removePrefix(VERSION).split(',').forEach { part ->
                val id = part.substringBefore('=').trim()
                val trick = choiceTrick(part.substringAfter('=', "").trim(), custom) ?: return@forEach
                if (trick == DpiTrick.PLAIN || DpiFamilies.byId(id, families) == null) return@forEach
                out[id] = trick
            }
            return DpiPlan(out)
        }

        /** Приём по выбору: id встроенного или «custom» (своя стратегия, если задана). */
        fun choiceTrick(choice: String, custom: DpiTrick?): DpiTrick? = when {
            choice == DpiTrick.CUSTOM_ID -> custom
            choice.isBlank() || choice == AUTO || choice == OFF -> null
            else -> DpiTrick.byId(choice)?.takeIf { it != DpiTrick.PLAIN }
        }

        /**
         * План по итогу проверки. Итогу без контроля не верим — план пустой. Цели группы — по
         * приоритету: решает первая, у которой есть итог (у видео — настоящий узел, а редиректор —
         * только если узел узнать не удалось). Группа попадает в план, если эту цель режут (или
         * замедляют), а приём помог; из помогших — самый простой (раньше в [DpiTrick.BUILTIN]).
         *
         * До beta4 приём выбирался по всем целям сервиса вместе: 26.11 на Tele2 картинки YouTube
         * открылись «перестановкой», страница и видео — ничем, а план сказал «YouTube — перестановка».
         */
        fun of(report: DpiReport, families: List<DpiFamily> = DpiFamilies.ALL): DpiPlan {
            if (!report.controlOk) return EMPTY
            val out = LinkedHashMap<String, DpiTrick>()
            for (fam in families) {
                val r = fam.targets.asSequence()
                    .mapNotNull { id -> report.results.firstOrNull { it.target.id == id } }
                    .firstOrNull { it.verdict != DpiVerdict.DNS && it.verdict != DpiVerdict.NONE } ?: continue
                if (r.verdict != DpiVerdict.BYPASS && r.verdict != DpiVerdict.FASTER) continue
                val best = r.helpers.filter { it != DpiTrick.PLAIN }.minByOrNull { DpiTrick.order(it) } ?: continue
                out[fam.id] = best
            }
            return DpiPlan(out)
        }

        /**
         * План с выбором человека (с beta4): у сервиса — свой выбор из [overrides] (сервис → выбор),
         * нет его — общий [general]. Выбор: [AUTO] — по проверке этой сети ([auto]), [OFF] — не
         * обходить, id приёма или «custom» — этот приём для всех групп сайтов сервиса.
         */
        fun effective(
            auto: DpiPlan,
            general: String,
            overrides: Map<String, String>,
            custom: DpiTrick?,
            families: List<DpiFamily> = DpiFamilies.ALL
        ): DpiPlan {
            val out = LinkedHashMap<String, DpiTrick>()
            for (f in families) {
                val choice = overrides[f.service]?.takeIf { it.isNotBlank() } ?: general.ifBlank { AUTO }
                val t = when (choice) {
                    AUTO -> auto.trickFor(f.id)
                    OFF -> null
                    else -> choiceTrick(choice, custom)
                } ?: continue
                out[f.id] = t
            }
            return DpiPlan(out)
        }

        /** «youtube=oob» → карта сервис → выбор (пустой выбор — «как общая», не попадает). */
        fun parseOverrides(lines: List<String>): Map<String, String> = lines.mapNotNull { l ->
            val k = l.substringBefore('=').trim()
            val v = l.substringAfter('=', "").trim()
            if (k.isEmpty() || v.isEmpty()) null else k to v
        }.toMap()

        /** Выбор словами: «по проверке сети», «не обходить», «разрез», «своя (--…)». */
        fun describeChoice(choice: String, custom: DpiTrick?): String = when (choice) {
            "", AUTO -> "по проверке сети"
            OFF -> "не обходить"
            DpiTrick.CUSTOM_ID -> custom?.let { "своя (${it.byedpi})" } ?: "своя — не задана"
            else -> DpiTrick.byId(choice)?.let { "«${it.title}»" } ?: "неизвестный приём «$choice»"
        }
    }
}
