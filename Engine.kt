package dev.warpscout.app

import android.content.Context
import android.os.Handler
import android.os.Looper
import dev.warpscout.core.keys.KeySource
import dev.warpscout.core.keys.KeySourceConfig
import dev.warpscout.core.model.WarpConfig
import dev.warpscout.core.net.HttpClient
import dev.warpscout.core.net.ResourceProber
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
        val vault = KeyVault(context)
        val keySource = KeySource(
            http = HttpClient(timeoutMs = 4000),
            store = vault.accountStore(),
            config = KeySourceConfig(),
            manual = manual?.account
        )
        val tuner = AutoTuner(
            keySource = keySource,
            wgProber = WgProber(spec.net),
            tlsProber = TlsProber(spec.net),
            resources = ResourceProber(),
            tunnel = TunnelFactory.create(context).verifier()
        )
        val result = tuner.run(spec, sink)
        last = result
        runCatching { Report.writeAll(result.report, ConfigFiles.dir(context, "reports"), "warpscout") }
        result.best?.let { cfg ->
            runCatching { ConfigFiles.write(context, cfg, result.configText ?: ConfigFiles.render(cfg)) }
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
