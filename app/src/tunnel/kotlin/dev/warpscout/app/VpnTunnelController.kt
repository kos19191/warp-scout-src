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
import dev.warpscout.core.net.SpeedTest
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
        var deadline = startMark + waitMs.coerceAtLeast(3000)
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
            // С 1.10.29 «работает» объявляется после проверки данных (до 3,5 с после рукопожатия).
            // Пока она идёт, попытку не обрываем: иначе медленное рукопожатие плюс проверка не
            // укладывались в 5 с, и рабочая точка уходила в «не поднялась».
            val checkAt = TunnelState.dataCheckAt
            if (ours && checkAt > 0L) deadline = maxOf(deadline, checkAt + DATA_CHECK_WAIT_MS)
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
        // С 1.10.30 «пошли и встали» без шума — почти всегда DPI против чистого WireGuard: сервис
        // запоминает это для сети и следующую попытку делает с маской сам.
        reason.contains("данные не идут") && reason.contains("(без шума)") ->
            "сеть режет чистый WireGuard — следующую попытку делаю с маской (шум TLS/QUIC)"
        reason.contains("данные не идут") ->
            "сеть пропускает рукопожатие, но режет данные — беру следующую точку; помогает и другой профиль шума"
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

    override fun requestSpeedTest() = WarpVpnService.requestSpeedTest(context)

    override fun reloadSecondRoutes() {
        // Сервис читает адреса из общего снимка настроек, а не из Prefs интерфейса: сначала его
        // обновить, иначе сервис перечитал бы прежние адреса.
        runCatching { dev.warpscout.app.status.ServiceSettingsStore.syncFromPrefs(context) }
        WarpVpnService.reloadSecondRoutes(context)
    }

    override fun reloadDpi() {
        // Как и с адресами второго выхода: сначала снимок настроек, сервис читает план оттуда.
        runCatching { dev.warpscout.app.status.ServiceSettingsStore.syncFromPrefs(context) }
        WarpVpnService.reloadDpi(context)
    }

    override fun answerTelegram(switch: Boolean) = WarpVpnService.answerTelegram(context, switch)

    // Причину отказа называет сервис, а живёт она в снимке его состояния: в процессе интерфейса
    // TunnelDebug.lastError почти всегда пуст, и вместо причины показывалось «нет ответа».
    override fun lastError(): String? = TunnelState.error ?: TunnelDebug.lastError

    override fun debugDump(): String = TunnelDebug.dump()

    override fun verifier(): TunnelVerifier = VpnTunnelVerifier(context)

    companion object {
        const val REQUEST_VPN = 4211

        /**
         * Сколько ждать итога проверки данных с её начала: сама проверка — до 4 с (см.
         * DataGate.WINDOW_MS; с 1.10.30 она ждёт и позднего ответа), плюс запас на запись и чтение
         * снимка между процессами.
         */
        private const val DATA_CHECK_WAIT_MS = 5_500L
    }
}

/**
 * Поднимает туннель по проверяемой конфигурации, гоняет проверки ресурсов уже сквозь него и
 * гасит его. Это то, что отличает «порт отвечает» от «трафик реально идёт»: после смены
 * endpoint'а именно здесь видно, работает ли ChatGPT/Google/Discord из-под WARP.
 */
class VpnTunnelVerifier(private val context: Context) : TunnelVerifier {

    private val prober = ResourceProber()

    /** Скорость через туннель последней проверенной точки (см. [lastSpeedKbps]). */
    @Volatile
    private var lastSpeed = -1

    override val title: String get() = "собственный туннель WilyScout"

    override fun lastSpeedKbps(): Int = lastSpeed

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
        lastSpeed = -1
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
            // Проверки — параллельно (с 1.10.30): по одной восемь сервисов и свои сайты ждали бы
            // друг друга до минуты на каждую из трёх точек. Порядок результатов — как в списке.
            val out = prober.checkParallel(checks, "tunnel", isCancelled)
            // Скорость через эту точку: из двух, открывших одинаково много сайтов, лучше та, через
            // которую быстрее качается. Короткая загрузка (четверть мегабайта) заодно ловит
            // «заморозку» — такая точка получает 0 и уходит вниз списка.
            if (!isCancelled() && fullTunnel(config)) {
                val r = runCatching {
                    SpeedTest.run(
                        SpeedTest.cloudflareUrl(SpeedTest.SCAN_BYTES), SpeedTest.SCAN_BYTES,
                        maxMs = 5_000L, stallMs = 3_000
                    )
                }.getOrNull()
                lastSpeed = when (r?.state) {
                    SpeedTest.OK -> r?.kbps ?: -1
                    SpeedTest.FROZEN -> 0
                    else -> -1
                }
            }
            out
        } finally {
            WarpVpnService.stop(context)
            CleanNetwork.bind(context)   // возвращаем «чистую» привязку для остатка подбора
        }
    }

    override fun stop() = WarpVpnService.stop(context)

    /** Весь трафик в туннеле: иначе адрес замера мог оказаться вне маршрутов и мерил бы не то. */
    private fun fullTunnel(config: WarpConfig): Boolean =
        dev.warpscout.core.config.SplitRoutes.prefixesOf(config.allowedIps)
            .any { it.replace(" ", "") == "0.0.0.0/0" }
}
