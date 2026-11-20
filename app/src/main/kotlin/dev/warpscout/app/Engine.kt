package dev.warpscout.app

import android.content.Context
import android.os.Handler
import android.os.Looper
import dev.warpscout.core.config.WgConf
import dev.warpscout.core.keys.KeySource
import dev.warpscout.core.keys.KeySourceConfig
import dev.warpscout.core.model.WarpConfig
import dev.warpscout.core.net.HttpClient
import dev.warpscout.core.net.ResourceProber
import dev.warpscout.core.net.Socks5Endpoint
import dev.warpscout.core.net.TlsProber
import dev.warpscout.core.net.WgProber
import dev.warpscout.core.report.Report
import dev.warpscout.core.tune.AutoTuner
import dev.warpscout.core.tune.ProgressSink
import dev.warpscout.core.tune.TuningResult
import dev.warpscout.core.tune.TuningSpec
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Двигатель подбора: бегает [AutoTuner] на отдельном потоке, складывает отчёт и конфиг
 * во внутреннее хранилище и отдаёт результат в UI. Никаких разрешений на сеть запрашивать
 * не нужно — INTERNET у приложения есть всегда.
 */
class Engine(private val context: Context) {

    private val executor = Executors.newSingleThreadExecutor { r -> Thread(r, "warpscout-engine") }
    private val cancelled = AtomicBoolean(false)

    @Volatile
    var running: Boolean = false
        private set

    @Volatile
    var last: TuningResult? = null
        private set

    /** Файл конфига, который Engine записал последним (UI отдаёт его по «Поделиться»). */
    @Volatile
    var storedConfigFile: java.io.File? = null
        private set

    fun cancel() {
        cancelled.set(true)
    }

    fun start(
        spec: TuningSpec,
        manual: WarpConfig?,
        sink: ProgressSink,
        onDone: (TuningResult?, String?) -> Unit
    ) {
        if (running) {
            onDone(null, "Подбор уже выполняется")
            return
        }
        val main = Handler(Looper.getMainLooper())
        running = true
        cancelled.set(false)
        executor.execute {
            val outcome = runCatching { runOnce(spec, manual, sink) }
            main.post {
                running = false
                onDone(outcome.getOrNull(), outcome.exceptionOrNull()?.let { describe(it) })
            }
        }
    }

    /** Для WorkManager: тот же цикл, но синхронно. */
    fun runBlocking(spec: TuningSpec, manual: WarpConfig?, sink: ProgressSink, limitMs: Long): TuningResult? {
        val latch = CountDownLatch(1)
        var result: TuningResult? = null
        start(spec, manual, sink, { r, _ -> result = r; latch.countDown() })
        latch.await(limitMs, TimeUnit.MILLISECONDS)
        return result
    }

    private fun runOnce(spec: TuningSpec, manual: WarpConfig?, sink: ProgressSink): TuningResult {
        val prefs = Prefs(context)
        val tunnel = TunnelFactory.create(context)

        // 1) Базовые замеры имеют смысл только «на чистой сети»: свой туннель гасим, чужие — обходим.
        val wasUp = tunnel.isUp
        if (wasUp) {
            tunnel.stop()
            sink.log("базовые замеры: собственный туннель приостановлен")
        }
        val haveClean = CleanNetwork.prepare(context)
        sink.log(CleanNetwork.statusLine(context))
        if (haveClean) CleanNetwork.bind(context)
        val factories = CleanNetwork.factories()
        val tuned = factories?.let { (udp, tcp) ->
            spec.copy(net = spec.net.copy(udpFactory = udp, tcpFactory = tcp))
        } ?: spec

        // 1b) «Базу» можно мерить и через обход DPI (ByeDPI в режиме прокси): тогда подбор видит
        // картину «после фрагментации», а не «что нарисовал провайдер».
        val socks = Socks5Endpoint.parse(prefs.byedpiProxy)
        val withProxy = if (prefs.tuneViaByedpi && socks != null && socks.configured) {
            sink.log("базовые замеры идут через SOCKS5 ${socks.render()} (ByeDPI)")
            tuned.copy(net = tuned.net.copy(socks5 = socks))
        } else {
            if (prefs.tuneViaByedpi) sink.log("замеры через ByeDPI включены, но адрес SOCKS5 не разобран — мёрим напрямую")
            tuned
        }
        val resourceHttp = if (withProxy.net.socks5 != null) HttpClient(6000, proxy = withProxy.net.socks5) else HttpClient(6000)

        val vault = KeyVault(context)
        val keySource = KeySource(
            http = HttpClient(timeoutMs = 4000),
            store = vault.accountStore(),
            config = KeySourceConfig(),
            manual = manual?.account
        )
        val tuner = AutoTuner(
            keySource = keySource,
            wgProber = WgProber(withProxy.net),
            tlsProber = TlsProber(withProxy.net),
            resources = ResourceProber(resourceHttp),
            tunnel = tunnel.verifier()
        )
        val result = try {
            tuner.run(withProxy, sink)
        } finally {
            CleanNetwork.unbind(context)
        }
        last = result
        runCatching { Report.writeAll(result.report, ConfigFiles.dir(context, "reports"), "warpscout") }

        // Конфиг пользователю отдаём уже «под него»: выбранный сервер, выбранный шум, выбранные
        // каналы и выбранный клиент. Иначе «я же выбрал WireGuard» расходится с файлом на диске.
        val exportable = result.best?.let { ConfigComposer.applyPrefs(it, prefs, prefs.junkPool) }
        val exportText = exportable?.let { ConfigComposer.render(it, prefs) }
        if (exportable != null && exportText != null) {
            val file = runCatching {
                val dir = ConfigFiles.dir(context, "configs")
                val out = java.io.File(dir, ConfigComposer.fileName(exportable, prefs))
                out.writeText(exportText)
                out
            }.getOrNull()
            if (file != null) {
                storedConfigFile = file
                sink.log("конфиг записан: ${file.name} · ${ConfigComposer.explain(exportable, prefs)}")
            }
        }

        // 2) Помечаем результат: «когда проверяли» и «конфиг реально новый или тот же».
        val now = System.currentTimeMillis()
        prefs.lastTunedAt = now
        result.best?.let { cfg ->
            val prev = prefs.lastTunedEndpoint
            val rendered = cfg.endpoint.render()
            if (rendered != prev) {
                prefs.lastChangedAt = now
                prefs.lastTunedEndpoint = rendered
                prefs.lastTunedScore = result.report.best?.score ?: 0
                sink.log("новый конфиг: endpoint $rendered (прежний: ${prev.ifBlank { "ещё не было подобранного" }})")
            }
        }

        // 3) Авто-применение: либо по галочке, либо восстанавливаем только что остановленный туннель.
        val best = result.best
        if (best != null && tunnel.supported) {
            val allowed = runCatching { android.net.VpnService.prepare(context) == null }.getOrDefault(false)
            when {
                prefs.autoApply && !allowed ->
                    sink.log("авто-применение пропущено: нет разрешения на VPN — открой приложение и нажми «Туннель»")
                prefs.autoApply || wasUp -> {
                    val withRoutes = ConfigComposer.applyPrefs(best, prefs, prefs.junkPool)
                    val up = runCatching { tunnel.startAndAwait(withRoutes, 25000) }.getOrDefault(false)
                    if (up) {
                        // «Подключить последнее» должно поднимать именно то, что работает сейчас.
                        prefs.lastConfigText = runCatching { WgConf.render(withRoutes) }
                            .getOrDefault(prefs.lastConfigText)
                        prefs.lastEndpoint = withRoutes.endpoint.render()
                        sink.log("туннель поднят на подобранном конфиге: ${withRoutes.endpoint.render()}")
                    } else {
                        val why = tunnel.lastError() ?: tunnel.status
                        sink.log("туннель не поднялся: $why")
                        TunnelTrouble.advise(tunnel.debugDump()).forEach {
                            sink.log("  почему: ${context.getString(it.titleRes)} — ${context.getString(it.whatToDoRes)}")
                        }
                    }
                }
            }
        }
        return result
    }

    private fun describe(e: Throwable): String {
        val msg = buildString {
            append(e.javaClass.simpleName)
            e.message?.let { append(": ").append(it.take(220)) }
            (e.cause as? KeySource.AllMirrorsFailed)?.let { append(" (все зеркала генератора недоступны — попробуйте позже или импортируйте .conf вручную)") }
        }
        return msg
    }
}
