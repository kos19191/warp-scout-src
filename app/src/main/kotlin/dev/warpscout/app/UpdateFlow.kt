package dev.warpscout.app

import android.app.DownloadManager
import android.content.Context
import android.net.Network
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import dev.warpscout.core.net.StallWatch

/**
 * Загрузка обновления (с 1.10.40) — на весь процесс, отдельно от экрана.
 *
 * Было (1.10.32–1.10.39): экран ставил файл в системную загрузку Android и ждал её до 20 минут, что бы
 * с ней ни было, а на каждое нажатие «Обновлений» отвечал «Обновление уже скачивается». Системная
 * загрузка могла встать — ждать сеть, повторять попытку после ошибки, стоять в очереди, — и тогда
 * ничего не происходило, а приложение упорно говорило «уже качается». Номер загрузки ещё и
 * запоминался: после перезапуска то же нажатие снова находило её «идущей», и выхода не было, кроме как
 * отменить её в шторке. Жалоба на 1.10.38: «пишет, что уже качается, но ничего не происходит».
 *
 * Теперь:
 *  • повторное нажатие говорит, что именно идёт: проверка, проценты, «системная загрузка ждёт сеть —
 *    через 20 с скачаю сам»;
 *  • системная загрузка без единого байта 30 с (или без прироста 45 с), не скачавшая или с испорченным
 *    файлом — убирается вместе с недокачанным файлом, и WarpScout качает сам ([Updater.downloadDirect]):
 *    сначала как всё приложение (при включённом туннеле — через него), не вышло — мимо туннеля;
 *  • не вышло и так — экран предлагает скачать браузером;
 *  • в журнал — что было с системной загрузкой словами, со статусом и причиной: без них такую жалобу
 *    не разобрать (в 1.10.38 в журнале была одна строка «скачиваю …» — и тишина).
 * Состояние живёт здесь, а не в экране: загрузка переживает поворот и пересоздание экрана.
 */
object UpdateFlow {

    /** Что показывает экран. Зовётся на главном потоке — у того экрана, что сейчас открыт. */
    interface Ui {
        /** Ход загрузки — строкой (плашкой), без всплывающей строки. */
        fun onUpdateProgress(text: String)

        /** Сообщение-итог. */
        fun onUpdateNote(text: String, error: Boolean)

        /** Файл в «Загрузках»: остаётся нажать на него. [fileName] — как он там называется. */
        fun onUpdateReady(release: Updater.Release, fileName: String)

        /** Не скачалось ни системной загрузкой, ни самим: причина и «Скачать браузером». */
        fun onUpdateFailed(release: Updater.Release, reason: String)
    }

    const val IDLE = 0
    const val CHECKING = 1
    const val SYSTEM = 2
    const val DIRECT = 3

    /** Что сейчас делают «Обновления»: ничего, проверка, системная загрузка, своя загрузка. */
    @Volatile
    var phase = IDLE
        private set

    /** Что сейчас с обновлением — словами; это и отвечает повторное нажатие. */
    @Volatile
    var status = ""
        private set

    /**
     * Экран, которому говорить: MainActivity ставит себя, когда открыт, и снимает, когда закрыт. Итог,
     * пришедший без экрана, — показывается, как только экран появится.
     */
    @Volatile
    var ui: Ui? = null
        set(value) {
            field = value
            val pending = missed
            if (value != null && pending != null) {
                missed = null
                post(final = true, block = pending)
            }
        }

    @Volatile
    private var missed: ((Ui) -> Unit)? = null

    private val main by lazy { Handler(Looper.getMainLooper()) }

    /** Ни байта столько времени с начала — системная загрузка встала. */
    private const val FIRST_BYTE_MS = 30_000L

    /** Байты шли и встали на столько — тоже. */
    private const val PROGRESS_MS = 45_000L

    /** Дольше не следим: медленно, но идёт — Android сам скажет «Загрузка завершена». */
    private const val WATCH_MAX_MS = 30 * 60_000L

    private const val END_GONE = 0
    private const val END_OK = 1
    private const val END_FAILED = 2
    private const val END_STALL = 3
    private const val END_LONG = 4

    /** Ответ на нажатие, пока что-то идёт; null — ничего не идёт. */
    fun busyText(context: Context): String? = when (phase) {
        IDLE -> null
        CHECKING -> context.getString(R.string.update_checking)
        else -> status.ifBlank { context.getString(R.string.update_busy) }
    }

    /** Проверка обновлений началась; false — уже что-то идёт. */
    @Synchronized
    fun beginCheck(): Boolean {
        if (phase != IDLE) return false
        phase = CHECKING
        status = ""
        return true
    }

    @Synchronized
    fun endCheck() {
        if (phase == CHECKING) phase = IDLE
    }

    @Synchronized
    private fun claim(next: Int): Boolean {
        if (phase != IDLE) return false
        phase = next
        status = ""
        return true
    }

    /**
     * Скачать [release] (Android 10+): системной загрузкой — в «Загрузки», с уведомлением; встанет —
     * самим. false — уже что-то идёт (экран скажет что, см. [busyText]). [rev] — коммит сборки, когда
     * это свежая сборка той же версии (тег перенесён): имя файла у неё прежнее, и запомненная загрузка
     * узнаётся по коммиту, а не по имени — иначе экран предложил бы уже стоящую сборку.
     */
    fun start(context: Context, release: Updater.Release, rev: String? = null): Boolean {
        val app = context.applicationContext
        if (!claim(SYSTEM)) return false
        say(app.getString(R.string.update_state_start))
        Thread {
            runCatching {
                // Свои загрузки, вставшие в прошлых попытках (в 1.10.38–1.10.39 они так и висели в
                // очереди и в шторке), — убрать вместе с недокачанными файлами.
                val stale = runCatching { Updater.removeStale(app, keep = -1L) }.getOrDefault(0)
                if (stale > 0) TunnelDebug.stage("обновления: убрал вставшие системные загрузки прошлых попыток: $stale")
                val id = runCatching { Updater.enqueue(app, release) }.getOrElse { t ->
                    TunnelDebug.stage("обновления: системная загрузка не приняла файл — ${Updater.explain(t)}")
                    null
                }
                if (id == null) {
                    direct(app, release, app.getString(R.string.update_why_no_dm), rev)
                } else {
                    prefs(app).edit()
                        .putLong("dlId", id)
                        .putString("dlName", release.apkName)
                        .putLong("dlSize", release.size)
                        // null — не пересборка: запись убирается (putString(null) = remove).
                        .putString("dlRev", rev)
                        .apply()
                    TunnelDebug.stage("обновления: скачиваю ${release.apkName} в «Загрузки» системной загрузкой")
                    watchLoop(app, id, release, rev)
                }
            }.onFailure { t -> crashed(app, t) }
        }.apply { isDaemon = true; name = "warpscout-update-download" }.start()
        return true
    }

    /**
     * Следить за системной загрузкой [id], поставленной раньше — до перезапуска приложения или прошлой
     * версией: идёт — показываем проценты, встала — убираем и качаем сами. false — уже что-то идёт.
     */
    fun watch(context: Context, id: Long, release: Updater.Release, rev: String? = null): Boolean {
        val app = context.applicationContext
        if (!claim(SYSTEM)) return false
        say(app.getString(R.string.update_state_attach))
        TunnelDebug.stage("обновления: ${release.apkName} уже в системной загрузке — слежу; встанет — скачаю сам")
        Thread {
            runCatching { watchLoop(app, id, release, rev) }.onFailure { t -> crashed(app, t) }
        }.apply { isDaemon = true; name = "warpscout-update-download" }.start()
        return true
    }

    private fun watchLoop(app: Context, id: Long, release: Updater.Release, rev: String?) {
        val started = SystemClock.elapsedRealtime()
        val stall = StallWatch(started, FIRST_BYTE_MS, PROGRESS_MS)
        var last: Updater.Download? = null
        var shown = ""
        var end = END_LONG
        while (true) {
            val d = runCatching { Updater.query(app, id) }.getOrNull()
            if (d == null) {
                end = END_GONE
                break
            }
            last = d
            if (d.status == DownloadManager.STATUS_SUCCESSFUL) {
                end = END_OK
                break
            }
            if (d.status == DownloadManager.STATUS_FAILED) {
                end = END_FAILED
                break
            }
            val now = SystemClock.elapsedRealtime()
            val left = stall.left(d.done, now)
            if (left <= 0L) {
                end = END_STALL
                break
            }
            if (now - started >= WATCH_MAX_MS) break
            val text = progressText(app, d, left)
            if (text != shown) {
                shown = text
                say(text)
            }
            try {
                Thread.sleep(1_000L)
            } catch (e: InterruptedException) {
                break
            }
        }
        val d = last
        when (end) {
            END_GONE -> {
                TunnelDebug.stage("обновления: системную загрузку убрали (в шторке или в «Загрузках») — не качаю")
                finish(final = false) { it.onUpdateNote(app.getString(R.string.update_cancelled), false) }
            }
            END_OK -> {
                val verified = runCatching { Updater.verify(app, id, release) }.getOrNull()
                if (verified == false) {
                    Updater.remove(app, id)
                    TunnelDebug.stage("обновления: системная загрузка скачала испорченный файл (контрольная сумма не сошлась) — удалил, качаю сам")
                    direct(app, release, app.getString(R.string.update_why_bad_hash), rev)
                } else {
                    val name = d?.name?.ifBlank { null } ?: release.apkName
                    TunnelDebug.stage("обновления: $name в «Загрузках» — ставится нажатием на файл")
                    finish(final = true) { it.onUpdateReady(release, name) }
                }
            }
            END_FAILED, END_STALL -> {
                val why = when {
                    d == null -> app.getString(R.string.update_why_no_dm)
                    end == END_STALL -> stallWhy(d)
                    else -> Updater.describe(d)
                }
                val got = if (d != null && d.done > 0L) "скачано ${d.done} байт" else "ни байта"
                TunnelDebug.stage(
                    "обновления: системная загрузка $why — $got, статус ${d?.status}, причина ${d?.reason}; убираю её и качаю сам"
                )
                Updater.remove(app, id)
                direct(app, release, why, rev)
            }
            else -> {
                TunnelDebug.stage("обновления: системная загрузка идёт дольше 30 минут — больше не слежу; скачает — Android покажет «Загрузка завершена»")
                finish(final = true) { it.onUpdateNote(app.getString(R.string.update_too_long), false) }
            }
        }
    }

    /** Почему встала — так, чтобы читалось после «Системная загрузка …». */
    private fun stallWhy(d: Updater.Download): String = when {
        d.done > 0L -> "встала"
        d.status == DownloadManager.STATUS_RUNNING -> "не соединилась за ${FIRST_BYTE_MS / 1000} с"
        else -> Updater.describe(d)
    }

    private fun progressText(app: Context, d: Updater.Download, leftMs: Long): String {
        if (d.done > 0L) {
            return if (d.total > 0L) {
                app.getString(R.string.update_downloading, ((d.done * 100L) / d.total).toInt().coerceIn(0, 100))
            } else {
                app.getString(R.string.update_downloading_bytes, mb(d.done))
            }
        }
        // Секунды до «скачаю сам» — шагами по 5: плашка не мелькает каждую секунду.
        val sec = (((leftMs + 999L) / 1000L + 4L) / 5L * 5L).toInt().coerceAtLeast(5)
        return app.getString(R.string.update_system_waiting, Updater.describe(d), sec)
    }

    /**
     * Своя загрузка: сначала как всё приложение (при включённом туннеле — через него; с 1.10.40 сети
     * GitHub в маршрутах туннеля и при раздельных маршрутах), не вышло — мимо туннеля (туннель поднят,
     * а данные не идут). [why] — что было с системной загрузкой, для экрана и журнала.
     */
    private fun direct(app: Context, release: Updater.Release, why: String, rev: String?) {
        synchronized(this) { phase = DIRECT }
        say(app.getString(R.string.update_direct_start, why))
        if (Build.VERSION.SDK_INT < 29) {
            // Сюда не попадаем (на Android 8–9 экран сразу отдаёт файл браузеру), но честно скажем.
            finish(final = true) { it.onUpdateFailed(release, why) }
            return
        }
        TunnelDebug.stage("обновления: качаю ${release.apkName} сам — системная загрузка $why")
        val ways = ArrayList<Pair<Network?, String>>()
        ways += null to if (Updater.defaultIsVpn(app)) "через туннель" else "напрямую"
        Updater.bypassNetwork(app)?.let { ways += it to "мимо туннеля" }
        var error: Throwable? = null
        for ((network, label) in ways) {
            var pct = -1
            val result = runCatching {
                Updater.downloadDirect(app, release, network) { done, total ->
                    val now = if (total > 0L) ((done * 100L) / total).toInt().coerceIn(0, 100) else -1
                    if (now >= 0 && now != pct) {
                        pct = now
                        say(app.getString(R.string.update_direct_progress, now))
                    }
                }
            }
            val got = result.getOrNull()
            if (got != null) {
                prefs(app).edit()
                    .putString("directUri", got.uri.toString())
                    .putString("directName", got.name)
                    .putString("directFor", release.apkName)
                    .putLong("directSize", got.size)
                    .putString("directRev", rev)
                    .apply()
                val sum = when (got.verified) {
                    true -> "контрольная сумма сошлась"
                    false -> "контрольная сумма не сошлась"
                    null -> "сверить было не с чем"
                }
                TunnelDebug.stage("обновления: ${got.name} в «Загрузках» — скачал сам ($label, ${got.size} байт, $sum); ставится нажатием на файл")
                finish(final = true) { it.onUpdateReady(release, got.name) }
                return
            }
            error = result.exceptionOrNull()
            TunnelDebug.stage("обновления: сам ($label) не скачал — ${Updater.explain(error)}")
            // Испорченный файл с сервера другой дорогой не исправится.
            if (error is Updater.BadHash) break
        }
        val reason = Updater.explain(error)
        finish(final = true) { it.onUpdateFailed(release, reason) }
    }

    private fun crashed(app: Context, t: Throwable) {
        TunnelDebug.error("обновления: " + SafeMode.describe(t))
        finish(final = true) { it.onUpdateNote(app.getString(R.string.update_failed, Updater.explain(t)), true) }
    }

    private fun say(text: String) {
        status = text
        post(final = false) { it.onUpdateProgress(text) }
    }

    private fun finish(final: Boolean, block: (Ui) -> Unit) {
        synchronized(this) {
            phase = IDLE
            status = ""
        }
        post(final, block)
    }

    /** На главный поток, тому экрану, что открыт. [final] — итог: без экрана покажем, когда он появится. */
    private fun post(final: Boolean, block: (Ui) -> Unit) {
        main.post {
            val target = ui
            if (target == null) {
                if (final) missed = block
                return@post
            }
            runCatching { block(target) }.onFailure { TunnelDebug.error("обновления: " + SafeMode.describe(it)) }
        }
    }

    private fun mb(bytes: Long): String = String.format(java.util.Locale.US, "%.1f МБ", bytes / 1_048_576.0)

    private fun prefs(app: Context) = app.getSharedPreferences("warpscout_update", Context.MODE_PRIVATE)
}
