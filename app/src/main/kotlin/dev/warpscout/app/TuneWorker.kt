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
        // Подбор поднимает и гасит настоящий VpnService (проверка ресурсов «из-под туннеля»).
        // Если туннель сейчас работает, это означало бы «сам себя выключил»: именно так выглядело
        // «нажал галочку каждый час — и соединение отвалилось». Не мешаем и заходим позже.
        // `TunnelState` живёт во flavor'е `tunnel`, поэтому смотрим через общий мост сборки.
        if (runCatching { TunnelFactory.create(context).isUp }.getOrDefault(false)) {
            notify(context, context.getString(R.string.tune_delayed))
            return Result.retry()
        }
        val manual = prefs.manualConf.takeIf { it.isNotBlank() }
            ?.let { runCatching { dev.warpscout.core.config.WgConf.toWarpConfig("импорт", it) }.getOrNull() }
        val sink = object : ProgressSink {
            /**
             * Прогресс идёт в журнал, а не в уведомления: раньше здесь искали слова в строках
             * подбора и на каждое совпадение показывали уведомление — за один прогон их
             * набирались десятки. Уведомление теперь одно, с результатом.
             */
            override fun log(message: String) {
                TunnelDebug.stage("подбор: $message")
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
        // Бекап и после фонового подбора: настройки меняются и без участия человека.
        runCatching { Backup.save(context, "фоновый подбор") }
        notify(
            context,
            best?.let { context.getString(R.string.tune_best, it.endpoint.render(), it.junk.name) }
                ?: context.getString(R.string.tune_none)
        )
        return Result.success()
    }

    private fun notify(context: Context, text: String) {
        val nm = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            nm.createNotificationChannel(
                NotificationChannel(
                    CHANNEL,
                    context.getString(R.string.tune_channel),
                    NotificationManager.IMPORTANCE_LOW
                )
            )
        }
        val n = NotificationCompat.Builder(context, CHANNEL)
            // Своя иконка: значок Bluetooth в уведомлении о подборе конфигурации сбивал с толку.
            .setSmallIcon(R.drawable.ic_tile_tunnel)
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
