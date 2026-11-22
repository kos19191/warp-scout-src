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
    override val active: Boolean get() = TunnelState.up || TunnelState.wanted
    override val status: String get() = TunnelState.status

    override fun ensurePermission(activity: Activity): Boolean {
        val request = runCatching { VpnService.prepare(activity) }.getOrNull()
        if (request == null) return true
        runCatching { activity.startActivityForResult(request, REQUEST_VPN) }
        return false
    }

    override fun start(config: WarpConfig): Boolean = startAt(config, 0L)

    /** Старт; [requestedAt] — когда человек начал подключение (0 — не важно), см. [startAndAwait]. */
    private fun startAt(config: WarpConfig, requestedAt: Long): Boolean {
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
        WarpVpnService.start(context, config, requestedAt)
        return true
    }

    /**
     * Ждём именно handshake, а не «сервис получил команду». Это и есть ответ на «запускается и
     * ничего не происходит»: теперь либо up, либо конкретная причина с подсказкой.
     */
    override fun startAndAwait(config: WarpConfig, waitMs: Int): Boolean = startAndAwait(config, waitMs, 0L) { false }

    /**
     * С отменой: «Отменить подключение» или выключение плиткой во время перебора обрывают ожидание
     * сразу — раньше перебор досиживал все 5 с на точке, которую уже никто не ждёт.
     */
    override fun startAndAwait(
        config: WarpConfig,
        waitMs: Int,
        requestedAt: Long,
        isCancelled: () -> Boolean
    ): Boolean {
        if (isCancelled()) return false
        if (!startAt(config, requestedAt)) return false
        val startMark = System.currentTimeMillis()
        val deadline = startMark + waitMs.coerceAtLeast(3000)
        var announced = false
        var lastRead = 0L
        while (System.currentTimeMillis() < deadline) {
            if (isCancelled()) return false
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
                // Причину уже назвал сервис, и она попадает в журнал отдельной строкой. Второй
                // строкой «посмотри журнал» мы объясняли очевидное — человек и так в нём.
                val reason = WarpVpnService.failureReason() ?: "сервис остановился без причины"
                TunnelDebug.error(reason, hintFor(reason))
                return false
            }
            Thread.sleep(150)
        }
        // Пустой этап — это не объяснение. Если сервис ничего не сказал, показываем последнюю
        // строку общего журнала (его пишет и сервис), а если и её нет — так и говорим.
        // «Этап: туннель остановлен» — это не этап, а след уже случившейся остановки: показывать
        // его вместо причины значит врать в самом важном месте. Такие служебные тексты пропускаем
        // и берём последнюю содержательную строку журнала.
        val status = TunnelState.status.trim()
        val stage = status.takeIf { it.isNotBlank() && !it.isServiceNoise() }
            ?: TunnelDebug.lastLine().takeIf { it.isNotBlank() && !it.isServiceNoise() }
            ?: "сервис не написал ни строки — похоже, не запустился"
        TunnelDebug.error(
            "за ${waitMs} мс handshake не завершился (этап: ${stage.take(160)})",
            "обычно это endpoint, который не отвечает на инициацию: смени профиль шума или порт"
        )
        return false
    }

    /** Служебные отметки «мы остановились», в которых нет причины. */
    private fun String.isServiceNoise(): Boolean =
        startsWith("туннель остановлен") || startsWith("туннель закрыт") ||
            startsWith("туннель закрыт (") || startsWith("сервис остановлен")

    /**
     * Подсказка по причине. Общая фраза «посмотри журнал» бесполезна: журнал открыт у человека на
     * экране. Полезно то, что можно сделать прямо сейчас.
     */
    private fun hintFor(reason: String): String = when {
        reason.contains("port unreachable", ignoreCase = true) || reason.contains("порт закрыт") ->
            "порт не обслуживает WARP в этой сети — следующая точка поднимется сама"
        reason.contains("молчит", ignoreCase = true) || reason.contains("ответа нет") ->
            "endpoint молчит: помогает другой профиль шума или другой порт"
        reason.contains("ключ", ignoreCase = true) ->
            "ключи не подошли: нажми «Сканировать и подобрать» — они будут получены заново"
        else -> "нажми «Включить туннель» ещё раз — перебор точек начнётся с другой пары адрес:порт"
    }

    override fun stop() = WarpVpnService.stop(context)

    override fun stopByUser() = WarpVpnService.stop(context, byUser = true)

    override fun waitStopped(timeoutMs: Int): Boolean = WarpVpnService.waitDown(timeoutMs)

    /**
     * Проверка точки рядом с работающим туннелем. Ответ сервис кладёт в снимок состояния с тем же
     * номером запроса — по номеру и узнаём свой ответ, а не оставшийся от прошлой проверки.
     */
    override fun probe(endpoint: String, timeoutMs: Int): Int {
        if (!TunnelState.up) return -1
        val id = System.currentTimeMillis()
        if (!WarpVpnService.probe(context, endpoint, id)) return -1
        val deadline = System.currentTimeMillis() + timeoutMs.coerceAtLeast(1000)
        while (System.currentTimeMillis() < deadline) {
            val parts = runCatching { dev.warpscout.app.status.TunnelStatusBus.read(context)?.probe }
                .getOrNull().orEmpty().split('|')
            if (parts.size >= 3 && parts[0] == id.toString()) return parts[2].toIntOrNull() ?: -1
            runCatching { Thread.sleep(150) }
        }
        return -1
    }

    override fun requestLinkCheck() = WarpVpnService.requestLinkCheck(context)

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

    override fun verify(config: WarpConfig, checks: List<ResourceCheck>, settleMs: Int): List<ResourceResult> =
        verify(config, checks, settleMs) { false }

    /**
     * Проверка изнутри с отменой: «Остановить подбор» прерывает и ожидание подъёма, и очередь
     * запросов к сайтам. Туннель проверки гасится в любом случае (finally).
     */
    override fun verify(
        config: WarpConfig,
        checks: List<ResourceCheck>,
        settleMs: Int,
        isCancelled: () -> Boolean
    ): List<ResourceResult> {
        if (checks.isEmpty() || isCancelled()) return emptyList()
        // Проверка «из-под туннеля» должна идти ЧЕРЕЗ туннель: снимаем привязку к non-VPN сети,
        // иначе CleanNetwork вернул бы нам ту же самую чистую сеть и смысл проверки пропал.
        CleanNetwork.unbind(context)
        if (!WarpVpnService.startAndWait(context, config, settleMs, isCancelled)) {
            CleanNetwork.bind(context)
            if (isCancelled()) return emptyList()
            return checks.map {
                ResourceResult(check = it, ok = false, errorClass = "tunnel_not_started")
            }
        }
        return try {
            val out = ArrayList<ResourceResult>(checks.size)
            for (check in checks) {
                if (isCancelled()) break
                out.add(prober.check(check, "tunnel"))
            }
            out
        } finally {
            WarpVpnService.stop(context)
            CleanNetwork.bind(context)   // возвращаем «чистую» привязку для остатка подбора
        }
    }

    override fun stop() = WarpVpnService.stop(context)
}
