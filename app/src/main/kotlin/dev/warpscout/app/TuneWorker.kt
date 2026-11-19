package dev.warpscout.app

import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Context
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.work.Worker
import androidx.work.WorkerParameters
import dev.warpscout.core.tune.ProgressSink

/** Фоновый подбор по расписанию: результат — новый лучший конфиг + уведомление. */
class TuneWorker(appContext: Context, params: WorkerParameters) : Worker(appContext, params) {

    override fun doWork(): Result {
        val context = applicationContext
        val prefs = Prefs(context)
        val manual = prefs.manualConf.takeIf { it.isNotBlank() }
            ?.let { runCatching { dev.warpscout.core.config.WgConf.toWarpConfig("импорт", it) }.getOrNull() }
        val sink = object : ProgressSink {
            override fun log(message: String) {
                if (message.contains("Лучший") || message.contains("не прошёл") || message.contains("Живых")) {
                    notify(context, message)
                }
            }

            override fun isCancelled(): Boolean = isStopped
        }
        // 0) Маршруты по спискам: если выбран этот режим и кеш протух — обновляем ДО подбора,
        //    иначе проверки ресурсов будут гоняться по чужим/старым доменам и честно всё завалют.
        if (prefs.routesMode == 2) {
            val repo = AllowListsRepo(context)
            if (repo.isStale()) {
                val ids = repo.wantedIds(prefs)
                val n = runCatching { repo.refresh(ids) { sink.log(it) }.getOrDefault(0) }.getOrDefault(0)
                sink.log("списки: авто-обновление затронуло $n из ${ids.size}")
                if (n > 0) {
                    runCatching {
                        val r = repo.buildPlan(prefs) { sink.log(it) }
                        sink.log("маршруты: ${repo.savePlan(prefs, r.plan)}")
                    }
                }
            }
        }
        val result = Engine(context).runBlocking(prefs.tuningSpec(), manual, sink, 15 * 60_000L)
            ?: return Result.retry()
        val best = result.best
        notify(context, best?.let { "Лучший endpoint: ${it.endpoint.render()} (${it.junk.name})" }
            ?: "Живых endpoint'ов не найдено — попробуйте позже")
        return Result.success()
    }

    private fun notify(context: Context, text: String) {
        val nm = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            nm.createNotificationChannel(
                NotificationChannel(CHANNEL, "WarpScout: подбор конфигурации", NotificationManager.IMPORTANCE_LOW)
            )
        }
        val n = NotificationCompat.Builder(context, CHANNEL)
            .setSmallIcon(android.R.drawable.stat_sys_data_bluetooth)
            .setContentTitle("WarpScout")
            .setContentText(text)
            .setStyle(NotificationCompat.BigTextStyle().bigText(text))
            .build()
        runCatching { nm.notify(NOTIF_ID, n) }
    }

    companion object {
        private const val CHANNEL = "warpscout.tune"
        private const val NOTIF_ID = 4001
    }
}
