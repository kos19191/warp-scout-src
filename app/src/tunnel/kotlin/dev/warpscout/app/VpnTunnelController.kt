package dev.warpscout.app

import android.app.Activity
import android.content.Context
import android.net.VpnService
import dev.warpscout.app.tunnel.TunnelState
import dev.warpscout.app.tunnel.WarpVpnService
import dev.warpscout.core.model.ResourceCheck
import dev.warpscout.core.model.ResourceResult
import dev.warpscout.core.model.WarpConfig
import dev.warpscout.core.net.ResourceProber
import dev.warpscout.core.tune.TunnelVerifier

class VpnTunnelController(private val context: Context) : TunnelController {

    init {
        // Туннель живёт в отдельном процессе: подключаемся к его снимку состояния и держим
        // TunnelState зеркалом (один раз на процесс).
        TunnelState.installMirror(context)
    }

    override val supported: Boolean get() = true
    override val isUp: Boolean get() = TunnelState.up
    override val status: String get() = TunnelState.status

    override fun ensurePermission(activity: Activity): Boolean {
        val request = runCatching { VpnService.prepare(activity) }.getOrNull()
        if (request == null) return true
        runCatching { activity.startActivityForResult(request, REQUEST_VPN) }
        return false
    }

    override fun start(config: WarpConfig): Boolean {
        // Прошлая сессия могла не успеть закрыться: даём ей до 3 с, иначе старт молча «склеится».
        runCatching { WarpVpnService.waitDown(3000) }
        if (runCatching { VpnService.prepare(context) != null }.getOrDefault(true)) {
            TunnelDebug.error(
                "нет разрешения на VPN",
                "открой приложение и нажми «Включить туннель» ещё раз — система спросит разрешение один раз"
            )
            return false
        }
        // Сброс прошлого результата делает сам запуск сервиса (WarpVpnService.startWithText).
        WarpVpnService.start(context, config)
        return true
    }

    /**
     * Ждём именно handshake, а не «сервис получил команду». Это и есть ответ на «запускается и
     * ничего не происходит»: теперь либо up, либо конкретная причина с подсказкой.
     */
    override fun startAndAwait(config: WarpConfig, waitMs: Int): Boolean {
        if (!start(config)) return false
        val startMark = System.currentTimeMillis()
        val deadline = startMark + waitMs.coerceAtLeast(3000)
        var announced = false
        var lastRead = 0L
        while (System.currentTimeMillis() < deadline) {
            // Состояние пишет сервис в другом процессе. Читаем снимок сами, не полагаясь только на
            // уведомление: потерянное уведомление не должно выглядеть как «туннель не поднимается».
            val now = System.currentTimeMillis()
            if (now - lastRead >= 500) {
                lastRead = now
                runCatching { dev.warpscout.app.status.TunnelStatusBus.refresh(context) }
            }
            if (TunnelState.up) {
                TunnelDebug.ok("туннель работает: ${config.endpoint.render()}")
                return true
            }
            // Сервис уже сдался (или упал) — ждать дальше смысла нет. Но только если это про
            // НАШУ попытку: «сдался» из снимка прошлой точки раньше обрывало новую через 50 мс
            // после старта, интерфейс уходил к следующей точке, а прежняя всё равно поднималась —
            // и в итоге работали два туннеля сразу (двойные рукопожатия, двойной расход).
            val ours = TunnelState.startedAt >= startMark
            if (!announced && ours && System.currentTimeMillis() - startMark > 500 && WarpVpnService.gaveUp()) {
                announced = true
                TunnelDebug.error(
                    WarpVpnService.failureReason() ?: "сервис остановился без причины",
                    "посмотри журнал: там видно, на каком этапе всё встало"
                )
                return false
            }
            Thread.sleep(150)
        }
        // Пустой этап — это не объяснение. Если сервис ничего не сказал, показываем последнюю
        // строку общего журнала (его пишет и сервис), а если и её нет — так и говорим.
        val stage = TunnelState.status.ifBlank { TunnelDebug.lastLine() }
            .ifBlank { "сервис не написал ни строки — похоже, не запустился" }
        TunnelDebug.error(
            "за ${waitMs} мс handshake не завершился (этап: ${stage.take(160)})",
            "обычно это endpoint, который не отвечает на инициацию: смени профиль шума или порт"
        )
        return false
    }

    override fun stop() = WarpVpnService.stop(context)

    override fun waitStopped(timeoutMs: Int): Boolean = WarpVpnService.waitDown(timeoutMs)

    // Причину отказа называет сервис, а живёт она в снимке его состояния: в процессе интерфейса
    // TunnelDebug.lastError почти всегда пуст, и вместо причины показывалось «нет ответа».
    override fun lastError(): String? = TunnelState.error ?: TunnelDebug.lastError

    override fun debugDump(): String = TunnelDebug.dump()

    override fun verifier(): TunnelVerifier = VpnTunnelVerifier(context)

    companion object {
        const val REQUEST_VPN = 4211
    }
}

/**
 * Поднимает туннель по проверяемой конфигурации, гоняет проверки ресурсов уже сквозь него и
 * гасит его. Это то, что отличает «порт отвечает» от «трафик реально идёт»: после смены
 * endpoint'а именно здесь видно, работает ли ChatGPT/Google/Discord из-под WARP.
 */
class VpnTunnelVerifier(private val context: Context) : TunnelVerifier {

    private val prober = ResourceProber()

    override val title: String get() = "собственный туннель WarpScout"

    override fun verify(config: WarpConfig, checks: List<ResourceCheck>, settleMs: Int): List<ResourceResult> {
        if (checks.isEmpty()) return emptyList()
        // Проверка «из-под туннеля» должна идти ЧЕРЕЗ туннель: снимаем привязку к non-VPN сети,
        // иначе CleanNetwork вернул бы нам ту же самую чистую сеть и смысл проверки пропал.
        CleanNetwork.unbind(context)
        if (!WarpVpnService.startAndWait(context, config, settleMs)) {
            return checks.map {
                ResourceResult(check = it, ok = false, errorClass = "tunnel_not_started")
            }
        }
        return try {
            checks.map { prober.check(it, "tunnel") }
        } finally {
            WarpVpnService.stop(context)
            CleanNetwork.bind(context)   // возвращаем «чистую» привязку для остатка подбора
        }
    }

    override fun stop() = WarpVpnService.stop(context)
}
