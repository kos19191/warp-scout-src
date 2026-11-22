package dev.warpscout.app.status

import android.app.ActivityManager
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.Build
import android.util.Log
import dev.warpscout.app.TunnelDebug
import dev.warpscout.core.state.TunnelStatus
import java.io.File
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Состояние туннеля между процессами.
 *
 * Туннель живёт в своём процессе (`android:process=":vpn"`): падение интерфейса больше не роняет
 * VPN. Платить за это приходится тем, что общий объект в памяти невозможен — поэтому процесс
 * сервиса пишет маленький снимок в файл и рассылает короткое уведомление, а процесс интерфейса
 * читает снимок и раздаёт его тем, кто спрашивает.
 *
 * Правила, без которых это ломается:
 *  - **один писатель**. Файл пишет только процесс сервиса, иначе два снимка перетирают друг друга
 *    и интерфейс показывает то, чего нет;
 *  - **запись атомарная** (временный файл + переименование): читатель никогда не увидит половину
 *    JSON;
 *  - **понятная смерть**. Если сервис убили (не наш `stopSelf`, а OOM или системный kill),
 *    снимок останется «туннель работает». Поэтому в снимке есть время записи, а сервис раз в
 *    полминуты пишет «сердцебиение»; если время давно не обновлялось, интерфейс проверяет,
 *    жив ли процесс сервиса, и не врёт про состояние.
 */
object TunnelStatusBus {

    /** Уведомление «снимок обновился». Рассылается внутри приложения, наружу не видно. */
    const val ACTION_STATUS = "dev.warpscout.app.STATUS_CHANGED"

    /** Имя файла со снимком состояния. */
    private const val SNAPSHOT = "tunnel-status.json"

    /**
     * Снимок старше этого — повод проверить, жив ли сервис. Сердцебиение идёт раз в минуту, то
     * есть на пропуск даётся два с половиной удара: чаще проверять системный статус процесса
     * незачем, а «свежесть» важна только для того, чтобы не показывать живые цифры у мёртвого
     * сервиса.
     */
    private const val STALE_MS = 150_000L

    /** Проверка «процесс сервиса жив» не чаще раза в 2 секунды: она системная и не бесплатная. */
    private const val LIVENESS_THROTTLE_MS = 2_000L

    /** Если снимок не обновлялся дольше этого, интерфейс перечитывает файл сам. */
    private const val REREAD_MS = 5_000L

    private const val TAG = "WarpScout/status"

    @Volatile
    private var current: TunnelStatus = TunnelStatus()

    @Volatile
    private var loaded: Boolean = false

    @Volatile
    private var lastLivenessAt: Long = 0L

    /** Снимок сервиса признан мёртвым по этой причине; [DEATH_NONE] — сервис жив или выключен штатно. */
    const val DEATH_NONE = 0

    /** Процесса сервиса нет, а снимок говорит «работает» (убит системой или упал). */
    const val DEATH_KILLED = 1

    /** Снимок записан до установки текущей версии: обновление убивает процесс сервиса. */
    const val DEATH_UPDATE = 2

    /** Снимок записан до загрузки телефона. */
    const val DEATH_REBOOT = 3

    /**
     * Почему туннель, который снимок называет живым, на деле не работает — интерфейс говорит это
     * словами («приложение обновилось — включи заново»), а не просто «выключен».
     */
    @Volatile
    var death: Int = DEATH_NONE
        private set

    /**
     * `updatedAt` снимка, уже признанного мёртвым. Тот же файл, перечитанный ещё раз (каждые
     * 5 с и при возврате в приложение), не должен «воскрешать» туннель до следующей проверки.
     */
    @Volatile
    private var deadStamp: Long = 0L

    /** Когда установлена текущая версия; -1 — ещё не узнавали. Пока процесс жив, не меняется. */
    @Volatile
    private var installedAt: Long = -1L

    private val installed = AtomicBoolean(false)
    private val listeners = CopyOnWriteArrayList<(TunnelStatus) -> Unit>()

    fun snapshotFile(context: Context): File = File(context.applicationContext.filesDir, SNAPSHOT)

    /**
     * Подключить процесс интерфейса к снимку: прочитать текущий и слушать обновления.
     * Повторный вызов безопасен — приёмник регистрируется один раз на процесс.
     */
    fun install(context: Context) {
        val app = context.applicationContext
        if (installed.compareAndSet(false, true)) {
            val receiver = object : BroadcastReceiver() {
                override fun onReceive(receiverContext: Context?, intent: Intent?) = applySnapshot(app, read(app))
            }
            val filter = IntentFilter(ACTION_STATUS)
            runCatching {
                if (Build.VERSION.SDK_INT >= 33) {
                    app.registerReceiver(receiver, filter, Context.RECEIVER_NOT_EXPORTED)
                } else {
                    @Suppress("UnspecifiedRegisterReceiverFlag")
                    app.registerReceiver(receiver, filter)
                }
            }.onFailure { Log.w(TAG, "не удалось подписаться на состояние туннеля: ${it.message}") }
        }
        refresh(app)
    }

    /**
     * Подписаться на обновления. Слушателю сразу отдаётся последний известный снимок — иначе
     * интерфейс, открытый при уже поднятом туннеле, показывал бы «не запускался».
     */
    fun addListener(listener: (TunnelStatus) -> Unit) {
        listeners.add(listener)
        if (loaded) runCatching { listener(current) }
    }

    /**
     * Текущее состояние для интерфейса. Скрывает «мёртвый» снимок: если сервис молчит дольше
     * [STALE_MS] и его процесса нет, показываем «не запущен», а не «работает».
     *
     * [verify] — проверить процесс сервиса сразу, не дожидаясь, пока снимок устареет: так делают
     * при возврате в приложение и при выгрузке журнала. Раньше после обновления приложения
     * (оно убивает процесс сервиса) экран ещё две с половиной минуты показывал «работает», и
     * выгруженный в это время журнал писал в шапке «туннель работает» (Диагностика-8).
     */
    fun snapshot(context: Context, verify: Boolean = false): TunnelStatus {
        // Страховка: если обновлений давно не было, а туннель считается живым, перечитываем
        // файл. Интерфейс опрашивает состояние постоянно, поэтому даже при потерянном
        // уведомлении он не замирает на устаревшей картинке.
        val before = current
        if ((before.up || before.busy || before.wanted) && System.currentTimeMillis() - before.updatedAt > REREAD_MS) {
            val disk = read(context)
            if (disk != null && disk.updatedAt != before.updatedAt) applySnapshot(context, disk)
        }
        val status = current
        if (!status.up && !status.busy && !status.wanted) return status
        val now = System.currentTimeMillis()
        // Снимок записан раньше, чем загрузился телефон или установилась текущая версия: его
        // писатель почти наверняка мёртв — и перезагрузка, и обновление убивают процесс сервиса.
        // Тогда процесс проверяем сразу, не дожидаясь, пока снимок устареет. Подтверждение всё
        // равно нужно: настенные часы могли сдвинуться, и одному времени верить нельзя.
        val bornDead = diedWith(context, status.updatedAt)
        val fresh = status.updatedAt > 0 && now - status.updatedAt < STALE_MS
        if (fresh && !verify && bornDead == DEATH_NONE) return status
        if (!verify && now - lastLivenessAt < LIVENESS_THROTTLE_MS) return current
        lastLivenessAt = now
        if (serviceProcessRunning(context) == false) {
            // Сервиса нет, а снимок говорит «работает»: процесс закрыло обновление, перезагрузка
            // или система. Правим состояние у всех, кто его показывает (кнопка, карточка, плитка).
            return markDead(context, status, if (bornDead != DEATH_NONE) bornDead else DEATH_KILLED, now)
        }
        return status
    }

    /**
     * Отметить снимок мёртвым у всех, кто его показывает. В файл это состояние не пишется — его
     * владелец только процесс сервиса.
     */
    private fun markDead(context: Context, status: TunnelStatus, reason: Int, now: Long): TunnelStatus {
        deadStamp = status.updatedAt
        death = reason
        val dead = status.copy(
            up = false,
            busy = false,
            wanted = false,
            gaveUp = false,
            // Фазу — тоже: мёртвый «переподключаюсь» иначе навсегда оставил бы на экране «Подключаюсь…».
            phase = TunnelStatus.PHASE_IDLE,
            status = when (reason) {
                DEATH_UPDATE -> "туннель остановлен: приложение обновилось"
                DEATH_REBOOT -> "туннель остановлен: телефон перезагружался"
                else -> "туннель не запущен"
            },
            // Отметку времени ставим свою: иначе проверка будет повторяться каждые две секунды и
            // каждый раз дёргать интерфейс одним и тем же выводом.
            updatedAt = now
        )
        applySnapshot(context, dead, force = true)
        return dead
    }

    /**
     * Написан ли снимок до перезагрузки или до обновления приложения: [DEATH_REBOOT],
     * [DEATH_UPDATE] или [DEATH_NONE], если по времени этого не сказать.
     */
    @Suppress("DEPRECATION")
    private fun diedWith(context: Context, writtenAt: Long): Int {
        if (writtenAt <= 0L) return DEATH_NONE
        // Время загрузки по настенным часам; 10 с запаса на их неточность.
        val bootAt = System.currentTimeMillis() - android.os.SystemClock.elapsedRealtime()
        if (writtenAt < bootAt - 10_000L) return DEATH_REBOOT
        if (installedAt < 0L) {
            installedAt = runCatching {
                context.packageManager.getPackageInfo(context.packageName, 0).lastUpdateTime
            }.getOrDefault(0L)
        }
        if (installedAt > 0L && writtenAt < installedAt) return DEATH_UPDATE
        return DEATH_NONE
    }

    /** Перечитать снимок с диска (после возврата в приложение или по кнопке «обновить»). */
    fun refresh(context: Context) = applySnapshot(context.applicationContext, read(context))

    /**
     * Записать снимок и разослать уведомление. Вызывается **только** из процесса сервиса
     * (см. [dev.warpscout.app.tunnel.TunnelStatusPublisher]).
     */
    fun publish(context: Context, status: TunnelStatus) {
        val app = context.applicationContext
        val stamped = status.copy(updatedAt = System.currentTimeMillis())
        current = stamped
        loaded = true
        val file = snapshotFile(app)
        runCatching {
            file.parentFile?.mkdirs()
            val tmp = File(file.parentFile, file.name + ".tmp")
            tmp.writeText(stamped.toJson())
            // rename поверх существующего файла атомарен: читатель видит либо старый, либо новый.
            if (!tmp.renameTo(file)) {
                file.delete()
                if (!tmp.renameTo(file)) tmp.copyTo(file, overwrite = true)
            }
        }.onFailure { Log.w(TAG, "снимок состояния не записан: ${it.message}") }
        runCatching { app.sendBroadcast(Intent(ACTION_STATUS).setPackage(app.packageName)) }
    }

    /** Прочитать снимок с диска; null — если его нет или он битый. */
    fun read(context: Context): TunnelStatus? {
        val file = snapshotFile(context)
        if (!file.exists()) return null
        return TunnelStatus.fromJson(runCatching { file.readText() }.getOrNull())
    }

    private fun applySnapshot(context: Context, status: TunnelStatus?, force: Boolean = false) {
        val fresh = status ?: return
        // Тот же самый снимок, что уже признан мёртвым, — не новость от сервиса.
        if (!force && deadStamp != 0L && fresh.updatedAt == deadStamp) return
        if (!force && loaded && fresh.updatedAt == current.updatedAt) return
        if (!force) {
            // Сервис написал новый снимок — он и есть правда, прежний вывод «мёртв» снимаем.
            deadStamp = 0L
            death = DEATH_NONE
        }
        current = fresh
        loaded = true
        // Журнал: часть полей живёт в снимке (счётчики, последняя ошибка), их надо отразить,
        // иначе интерфейс покажет нулевой трафик при работающем туннеле.
        runCatching { TunnelDebug.mirror(fresh) }
        listeners.forEach { listener -> runCatching { listener(fresh) } }
    }

    /**
     * Работает ли хоть один сервис приложения в отдельном процессе. `null` — если система
     * не дала ответа (тогда лучше верить снимку, чем показывать «не запущен» на живом туннеле).
     */
    @Suppress("DEPRECATION")
    private fun serviceProcessRunning(context: Context): Boolean? {
        val manager = runCatching {
            context.getSystemService(Context.ACTIVITY_SERVICE) as? ActivityManager
        }.getOrNull() ?: return null
        // Начиная с Android 8 метод возвращает только сервисы своего приложения — для нас это
        // ровно то, что нужно, поэтому устаревший API здесь уместнее привязки к сервису.
        val running = runCatching { manager.getRunningServices(Int.MAX_VALUE) }.getOrNull() ?: return null
        val self = context.packageName
        // `process` — имя процесса сервиса; равно имени пакета, если сервис не вынесен.
        return running.any { info -> info.service.packageName == self && info.process != self }
    }
}
