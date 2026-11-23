package dev.warpscout.app

import android.content.Context
import android.content.Intent
import android.net.Uri
import dev.warpscout.core.lists.AppServices
import java.util.concurrent.ConcurrentHashMap

/**
 * Какие из выбранных приложений — браузеры (с 1.10.35, для «Браузер — только к нужным сайтам»).
 *
 * Браузер — приложение, которое открывает любую ссылку https: у сервисов вроде YouTube или
 * Telegram тоже есть ссылки (youtube.com, t.me), но только свои, и на произвольный адрес они не
 * откликаются. Видно это без особых разрешений: выбрать в «Туннелировании» можно только приложения с
 * иконкой на рабочем столе, а их Android и так показывает (см. `<queries>` в манифесте). Известные
 * браузеры — ещё и списком (AppServices.BROWSERS), на случай если система не ответит.
 *
 * Ответ запоминается на время процесса: маршруты собираются часто (каждая правка настроек), а
 * установленный браузер браузером и остаётся.
 */
object Browsers {

    private val cache = ConcurrentHashMap<String, Boolean>()

    /** Пакет — браузер, а не сервис из AppServices (у сервиса свои сети, он идёт целиком). */
    fun isBrowser(context: Context, pkg: String): Boolean {
        if (pkg.isBlank()) return false
        return cache.getOrPut(pkg) {
            if (AppServices.isKnownBrowser(pkg)) return@getOrPut true
            if (AppServices.serviceOf(pkg) != null) return@getOrPut false
            runCatching {
                val probe = Intent(Intent.ACTION_VIEW, Uri.parse("https://example.com/"))
                    .addCategory(Intent.CATEGORY_BROWSABLE)
                    .setPackage(pkg)
                @Suppress("DEPRECATION")
                context.packageManager.queryIntentActivities(probe, 0).isNotEmpty()
            }.getOrDefault(false)
        }
    }

    /** Браузеры среди [packages]. */
    fun among(context: Context, packages: Collection<String>): List<String> = packages.filter { isBrowser(context, it) }
}
