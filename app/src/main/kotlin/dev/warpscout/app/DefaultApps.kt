package dev.warpscout.app

import android.content.Context
import android.content.pm.LauncherApps
import android.os.Process

/**
 * Приложения, которые идут через туннель по умолчанию (с 1.10.31): Telegram, Instagram, YouTube,
 * Facebook и X (Twitter) — то, что в России заблокировано или замедлено.
 *
 * Отмечаются не только официальные приложения, но и их дубликаты: другой клиент того же сервиса
 * (Telegram X, Nekogram, ReVanced…), Lite-версия, вторая сборка. Иначе человек ставит галочку на
 * Telegram, а пользуется Telegram X — и тот идёт мимо туннеля. Известные пакеты — списком, прочие —
 * по названию («Telegram Beta», «YouTube (2)»), только среди установленных пользователем.
 *
 * Копию из «Двойного профиля» Samsung (Dual Messenger) или рабочего профиля отметить нельзя: она
 * живёт в другом профиле Android, а туннель WarpScout работает в основном. О таких копиях экран
 * предупреждает отдельно ([otherProfileCopies]).
 */
object DefaultApps {

    data class Family(
        val title: String,
        val packages: Set<String>,
        /** Название приложения — для клиентов, которых нет в списке пакетов. */
        val label: Regex,
    )

    val FAMILIES: List<Family> = listOf(
        Family(
            "Telegram",
            setOf(
                "org.telegram.messenger", "org.telegram.messenger.web", "org.telegram.messenger.beta",
                "org.thunderdog.challegram", // Telegram X
                "org.telegram.plus", "tw.nekomimi.nekogram", "nekox.messenger", "xyz.nextalone.nagram",
                "com.exteragram.messenger", "uz.unnarsx.cherrygram", "com.radolyn.ayugram", "app.nicegram",
                "org.forkgram.messenger", "ir.ilmili.telegraph", "org.telegram.mdgram",
            ),
            Regex("(?i)telegram|телеграм"),
        ),
        Family(
            "Instagram",
            setOf("com.instagram.android", "com.instagram.lite", "com.instagram.barcelona"),
            Regex("(?i)instagram|инстаграм"),
        ),
        Family(
            "YouTube",
            setOf(
                "com.google.android.youtube", "com.google.android.apps.youtube.music",
                "com.google.android.apps.youtube.kids", "com.google.android.youtube.tv",
                "app.revanced.android.youtube", "app.revanced.android.apps.youtube.music",
                "app.rvx.android.youtube", "app.rvx.android.apps.youtube.music",
                "com.vanced.android.youtube", "com.vanced.android.apps.youtube.music",
                "org.schabi.newpipe", "com.github.libretube", "com.liskovsoft.smarttubetv.beta",
            ),
            Regex("(?i)youtube|ютуб"),
        ),
        Family(
            "Facebook",
            setOf("com.facebook.katana", "com.facebook.lite", "com.facebook.orca", "com.facebook.mlite"),
            Regex("(?i)facebook|фейсбук"),
        ),
        Family(
            "X",
            setOf("com.twitter.android", "com.twitter.android.lite"),
            // «X» — слишком короткое название: только оно само или с пометкой («X (2)»).
            Regex("(?i)twitter|твиттер|^x( \\(.*\\))?$"),
        ),
    )

    /** К какому сервису относится приложение; null — ни к какому. */
    fun familyOf(pkg: String, label: String, system: Boolean): Family? {
        FAMILIES.firstOrNull { f -> pkg in f.packages || f.packages.any { pkg.startsWith("$it.") } }?.let { return it }
        // По названию — только установленные пользователем: у системных совпадения бывают случайными.
        if (system) return null
        return FAMILIES.firstOrNull { f -> f.label.containsMatchIn(label.trim()) }
    }

    /** Установленные приложения из набора: пакет → сервис. */
    fun find(apps: List<Triple<String, String, Boolean>>, self: String): Map<String, String> =
        apps.asSequence()
            .filter { it.first != self }
            .mapNotNull { (pkg, label, system) -> familyOf(pkg, label, system)?.let { pkg to it.title } }
            .toMap()

    /**
     * Сервисы из набора, у которых есть копия в другом профиле Android (Dual Messenger, рабочий
     * профиль): туда туннель WarpScout не распространяется.
     */
    fun otherProfileCopies(context: Context): List<String> = runCatching {
        val launcher = context.getSystemService(LauncherApps::class.java) ?: return emptyList()
        val me = Process.myUserHandle()
        launcher.profiles.filter { it != me }.flatMap { profile ->
            runCatching { launcher.getActivityList(null, profile) }.getOrDefault(emptyList()).mapNotNull { info ->
                val pkg = info.applicationInfo.packageName
                familyOf(pkg, info.label?.toString().orEmpty(), system = false)?.title
            }
        }.distinct()
    }.getOrDefault(emptyList())
}
