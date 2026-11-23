package dev.warpscout.core.lists

/**
 * Какие списки allow-domains нужны приложению, чтобы оно шло через туннель целиком, когда
 * маршруты туннеля — не «весь трафик» (с 1.10.35), и какие приложения — браузеры.
 *
 * Зачем. Android решает сначала по приложению (выбранные идут в туннель, остальные — мимо), а потом
 * по адресам — и адреса у туннеля общие для всех выбранных приложений. Человек спросил 23.11:
 * «браузер надо пускать в туннель целиком, а нужны только некоторые сайты». Выход — маршруты не
 * «весь трафик», а нужные сайты плюс сети выбранных приложений: Telegram, Instagram, YouTube и
 * другие ходят только в свои сети, и с их сетями в маршрутах идут через туннель целиком, а браузер —
 * только к нужным сайтам. Здесь — правила без Android: какому приложению какие списки.
 *
 * Сети известны не у всех: у Telegram, Meta (Instagram, Facebook, WhatsApp), X и Discord в списках
 * есть подсети, у YouTube — сети Google для видео (см. AllowLists.EXTRA_PREFIXES); у ChatGPT, Claude,
 * Gemini и TikTok — только домены, их адреса собираются через DoH; у Grok (с 1.10.38) своего списка
 * нет — его адреса во втором выходе. Приложение без сервиса здесь
 * ([serviceOf] = null) при неполных маршрутах идёт только к выбранным сайтам — об этом экран
 * предупреждает (так решил человек 23.11).
 *
 * Спутники (с 1.10.37, [Service.companions]) — приложения, внутри которых сервис на самом деле
 * работает. Gemini на Android — оболочка в несколько мегабайт: запросы к Google, и проверку страны
 * тоже, делает приложение Google. Человек отметил Gemini, второй выход работал, а Gemini писал «Эта
 * страна не поддерживается»: приложение Google в туннель не входило, и запросы шли мимо него, с
 * российского адреса оператора. Отмечен сервис — его спутники идут в туннель вместе с ним (так решил
 * человек 23.11); сетей им не добавляем: при неполных маршрутах из них идут только сайты — для
 * Gemini это его адреса, они и так в маршрутах.
 */
object AppServices {

    /** Приложение Google: внутри него работает Gemini (с 1.10.37). */
    const val GOOGLE_APP = "com.google.android.googlequicksearchbox"

    /** Приложение, которое идёт в туннель вместе с сервисом: пакет и название для экрана и журнала. */
    data class Companion(val pkg: String, val title: String)

    /** Спутник, который нужен выбранным приложениям, и сервис, ради которого он идёт. */
    data class Joined(val companion: Companion, val service: String)

    /** Сервис: название, списки allow-domains, известные пакеты и слова в имени пакета. */
    data class Service(
        val title: String,
        val lists: List<String>,
        val packages: Set<String>,
        /** Части имени пакета для клиентов, которых нет в [packages] («…telegram…»). */
        val hints: List<String> = emptyList(),
        /** Приложения, внутри которых сервис работает: идут в туннель вместе с ним (с 1.10.37). */
        val companions: List<Companion> = emptyList(),
    )

    val SERVICES: List<Service> = listOf(
        Service(
            "Telegram", listOf("telegram"),
            setOf(
                "org.telegram.messenger", "org.telegram.messenger.web", "org.telegram.messenger.beta",
                "org.thunderdog.challegram", "org.telegram.plus", "tw.nekomimi.nekogram", "nekox.messenger",
                "xyz.nextalone.nagram", "com.exteragram.messenger", "uz.unnarsx.cherrygram", "com.radolyn.ayugram",
                "app.nicegram", "org.forkgram.messenger", "ir.ilmili.telegraph", "org.telegram.mdgram",
            ),
            listOf("telegram", "nekogram", "challegram", "exteragram", "ayugram", "nicegram", "cherrygram"),
        ),
        Service(
            "Instagram", listOf("meta"),
            setOf("com.instagram.android", "com.instagram.lite", "com.instagram.barcelona"),
            listOf("instagram"),
        ),
        Service(
            "Facebook", listOf("meta"),
            setOf("com.facebook.katana", "com.facebook.lite", "com.facebook.orca", "com.facebook.mlite"),
            listOf("facebook"),
        ),
        Service("WhatsApp", listOf("meta"), setOf("com.whatsapp", "com.whatsapp.w4b"), listOf("whatsapp")),
        Service(
            "YouTube", listOf("youtube"),
            setOf(
                "com.google.android.youtube", "com.google.android.apps.youtube.music",
                "com.google.android.apps.youtube.kids", "com.google.android.youtube.tv",
                "app.revanced.android.youtube", "app.revanced.android.apps.youtube.music",
                "app.rvx.android.youtube", "app.rvx.android.apps.youtube.music",
                "com.vanced.android.youtube", "com.vanced.android.apps.youtube.music",
                "org.schabi.newpipe", "com.github.libretube", "com.liskovsoft.smarttubetv.beta",
            ),
            listOf("youtube", "newpipe", "libretube", "smarttube"),
        ),
        Service("X", listOf("twitter"), setOf("com.twitter.android", "com.twitter.android.lite"), listOf("twitter")),
        Service("Discord", listOf("discord"), setOf("com.discord"), listOf("discord")),
        Service("ChatGPT", listOf("openai"), setOf("com.openai.chatgpt"), listOf("openai", "chatgpt")),
        Service("Claude", listOf("claude"), setOf("com.anthropic.claude"), listOf("anthropic")),
        Service(
            "Gemini", listOf("google-ai"), setOf("com.google.android.apps.bard"),
            companions = listOf(Companion(GOOGLE_APP, "Google")),
        ),
        // Grok (с 1.10.38): его адреса — во втором выходе (AllowLists.EXTRA_HOSTS, xAI отказывает
        // российским адресам), своего списка в allow-domains у него нет — сетей не добавляем. Подсказок
        // по имени пакета тоже нет: «grok» сидит и в «ngrok».
        Service("Grok", emptyList(), setOf("ai.x.grok")),
        Service(
            "TikTok", listOf("tiktok"),
            setOf("com.zhiliaoapp.musically", "com.ss.android.ugc.trill", "com.zhiliaoapp.musically.go"),
            listOf("tiktok", "musically"),
        ),
    )

    /** Сервис приложения по пакету; null — не знаем. */
    fun serviceOf(pkg: String): Service? {
        val p = pkg.trim().lowercase()
        if (p.isEmpty()) return null
        SERVICES.firstOrNull { s -> p in s.packages || s.packages.any { p.startsWith("$it.") } }?.let { return it }
        // Браузер со словом сервиса в имени («…youtube.downloader.browser») — всё равно браузер.
        if (isKnownBrowser(p)) return null
        return SERVICES.firstOrNull { s -> s.hints.any { p.contains(it) } }
    }

    /** Списки для набора приложений — без повторов, в порядке [SERVICES]. */
    fun listsFor(packages: Collection<String>): List<String> {
        val found = packages.mapNotNull { serviceOf(it) }.toSet()
        return SERVICES.filter { it in found }.flatMap { it.lists }.distinct()
    }

    /**
     * Спутники набора приложений (с 1.10.37): кого ещё пустить в туннель — без уже выбранных, без
     * повторов, в порядке [SERVICES]. Отмечен Gemini — приложение Google.
     */
    fun companionsFor(packages: Collection<String>): List<Joined> {
        val chosen = packages.map { it.trim().lowercase() }.toSet()
        val found = packages.mapNotNull { serviceOf(it) }.toSet()
        val out = LinkedHashMap<String, Joined>()
        SERVICES.filter { it in found }.forEach { s ->
            s.companions.forEach { c ->
                if (c.pkg.lowercase() !in chosen && c.pkg !in out) out[c.pkg] = Joined(c, s.title)
            }
        }
        return out.values.toList()
    }

    /** Названия сервисов набора приложений («Telegram, Instagram, YouTube»). */
    fun titlesFor(packages: Collection<String>): List<String> {
        val found = packages.mapNotNull { serviceOf(it) }.toSet()
        return SERVICES.filter { it in found }.map { it.title }
    }

    /**
     * Известные браузеры. Остальные приложение узнаёт по тому, что они открывают любую ссылку https
     * (см. Browsers в приложении); список — на случай, если система этого не скажет.
     */
    val BROWSERS: Set<String> = setOf(
        "com.android.chrome", "com.chrome.beta", "com.chrome.dev", "com.chrome.canary", "org.chromium.chrome",
        "com.sec.android.app.sbrowser", "com.sec.android.app.sbrowser.beta",
        "org.mozilla.firefox", "org.mozilla.firefox_beta", "org.mozilla.fenix", "org.mozilla.focus",
        "org.mozilla.klar", "org.mozilla.fennec_fdroid", "io.github.forkmaintainers.iceraven",
        "com.yandex.browser", "com.yandex.browser.beta", "com.yandex.browser.lite", "ru.yandex.searchplugin",
        "com.opera.browser", "com.opera.browser.beta", "com.opera.mini.native", "com.opera.gx",
        "com.microsoft.emmx", "com.brave.browser", "com.brave.browser_beta", "com.vivaldi.browser",
        "com.duckduckgo.mobile.android", "com.kiwibrowser.browser", "mark.via.gp", "mark.via",
        "com.UCMobile.intl", "com.uc.browser.en", "com.ecosia.android", "com.mi.globalbrowser",
        "com.huawei.browser", "com.heytap.browser", "org.bromite.bromite", "org.cromite.cromite",
        "com.stoutner.privacybrowser.standard", "acr.browser.lightning", "app.vanadium.browser",
        "com.aloha.browser", "com.cloudmosa.puffinFree", "org.torproject.torbrowser",
    )

    fun isKnownBrowser(pkg: String): Boolean {
        val p = pkg.trim()
        return p in BROWSERS || BROWSERS.any { p.equals(it, ignoreCase = true) }
    }
}
