package dev.warpscout.app

import android.content.Context
import androidx.work.Constraints
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.NetworkType
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import java.util.concurrent.TimeUnit

/** Периодический авто-подбор: раз в N часов (0 — выключено), только когда есть сеть. */
object Schedule {

    private const val NAME = "warpscout-tune"

    /** Периоды, между которыми выбирает пользователь (часы; 0 — выключено). */
    val PERIODS = listOf(0, 1, 3, 6, 12, 24)

    /**
     * Минимальный период у WorkManager — 15 минут, поэтому часы безопасны даже для «каждый час»:
     * система всё равно может отложить запуск (Doze), и это нормально для фонового подбора.
     */
    fun enable(context: Context, hours: Int = 6) {
        val period = hours.coerceAtLeast(1).toLong()
        val request = PeriodicWorkRequestBuilder<TuneWorker>(period, TimeUnit.HOURS)
            .setConstraints(Constraints.Builder().setRequiredNetworkType(NetworkType.CONNECTED).build())
            .build()
        WorkManager.getInstance(context).enqueueUniquePeriodicWork(NAME, ExistingPeriodicWorkPolicy.UPDATE, request)
    }

    fun disable(context: Context) {
        WorkManager.getInstance(context).cancelUniqueWork(NAME)
    }
}
