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
        // То же, если туннель не поднят, но сервис его держит (переподключается или ждёт повтора):
        // повтор посреди подбора поднял бы туннель, и замеры пошли бы через WARP.
        val tunnel = TunnelFactory.create(context)
        val tunnelUp = runCatching { tunnel.isUp }.getOrDefault(false)
        val tunnelHeld = runCatching { tunnel.active }.getOrDefault(false)
        if (tunnelUp) {
            // С 1.10.29 работающий туннель — не повод отказаться навсегда: раньше при включённом
            // туннеле подбор откладывался каждый раз, то есть «иногда подбирать заново» не работало
            // никогда. Подбор приостанавливает туннель на 30–60 с, поэтому — только на зарядке и с
            // выключенным экраном (так решено 22.11): обычно это ночь, батарея не тратится, паузу
            // никто не заметит. В другое время пропускаем этот раз молча — следующий придёт сам.
            if (!quietMoment(context)) {
                TunnelDebug.stage("фоновый подбор пропущен: туннель работает, а телефон не на зарядке или экран включён")
                return Result.success()
            }
            TunnelDebug.stage("фоновый подбор: телефон на зарядке, экран выключен — туннель на время подбора приостанавливаю")
        } else if (tunnelHeld) {
            // Туннель не поднят, но сервис его держит (переподключается, подбирает сам или ждёт
            // повтора): повтор посреди подбора поднял бы туннель, и замеры пошли бы через WARP.
            notify(context, context.getString(R.string.tune_delayed))
            return Result.retry()
        }
        // Туннель последним выключил сам человек — фоновый подбор его не включает (даже с галочкой
        // «авто-применение»): «выключил руками» значит «не включай сам».
        val userOff = runCatching {
            dev.warpscout.app.status.TunnelStatusBus.read(context)?.stoppedByUser == true
        }.getOrDefault(false)
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
        val result = Engine(context).runBlocking(
            prefs.tuningSpec(), manual, sink, 15 * 60_000L, allowAutoApply = !userOff
        ) ?: return Result.retry()
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

    /** На зарядке и с выключенным экраном: только тогда фоновый подбор вправе прервать работающий туннель. */
    private fun quietMoment(context: Context): Boolean {
        val charging = runCatching {
            (context.getSystemService(Context.BATTERY_SERVICE) as android.os.BatteryManager).isCharging
        }.getOrDefault(false)
        val screenOff = runCatching {
            !(context.getSystemService(Context.POWER_SERVICE) as android.os.PowerManager).isInteractive
        }.getOrDefault(false)
        return charging && screenOff
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
