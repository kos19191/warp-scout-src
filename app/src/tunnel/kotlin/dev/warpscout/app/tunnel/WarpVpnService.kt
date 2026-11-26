package dev.warpscout.app.tunnel

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.os.PowerManager
import androidx.core.app.NotificationCompat
import dev.warpscout.app.ConfigShortlist
import dev.warpscout.app.EndpointMemory
import dev.warpscout.app.NoiseMemory
import dev.warpscout.app.R
import dev.warpscout.app.SiteMemory
import dev.warpscout.app.TelegramChoiceMemory
import dev.warpscout.app.TunnelDebug
import dev.warpscout.core.config.SplitRoutes
import dev.warpscout.core.config.WgConf
import dev.warpscout.core.crypto.Crypto
import dev.warpscout.core.dpi.DpiPlan
import dev.warpscout.core.dpi.DpiRelay
import dev.warpscout.core.dpi.DpiServices
import dev.warpscout.core.dpi.DpiTrick
import dev.warpscout.core.junk.JunkLibrary
import dev.warpscout.core.lists.AllowLists
import dev.warpscout.core.lists.AppServices
import dev.warpscout.core.lists.ProtonFree
import dev.warpscout.core.model.AddrFamily
import dev.warpscout.core.model.Endpoint
import dev.warpscout.core.model.JunkChunk
import dev.warpscout.core.model.JunkProfile
import dev.warpscout.core.model.Verdict
import dev.warpscout.core.model.WarpConfig
import dev.warpscout.core.net.EndpointPool
import dev.warpscout.core.net.EndpointSpec
import dev.warpscout.core.net.ExitSite
import dev.warpscout.core.net.NetSettings
import dev.warpscout.core.net.SpeedTest
import dev.warpscout.core.net.TelegramChoice
import dev.warpscout.core.net.TelegramMedia
import dev.warpscout.core.net.UdpSocketFactory
import dev.warpscout.core.net.WarpDefaults
import dev.warpscout.core.net.WgProber
import dev.warpscout.core.state.ServiceSettings
import dev.warpscout.core.state.TunnelStatus
import dev.warpscout.core.tune.NoiseBook
import dev.warpscout.core.tunnel.DataGate
import dev.warpscout.core.tunnel.DataPlane
import dev.warpscout.core.tunnel.ExitRouter
import dev.warpscout.core.tunnel.PacketQueueIn
import dev.warpscout.core.tunnel.SharedPacketOut
import dev.warpscout.core.tunnel.TunDispatcher
import dev.warpscout.core.tunnel.SocketUdpChannel
import dev.warpscout.core.tunnel.AppExit
import dev.warpscout.core.tunnel.AppExitTable
import dev.warpscout.core.tunnel.AppAuto
import dev.warpscout.core.tunnel.AwgChannel
import dev.warpscout.core.tunnel.ExitNat
import dev.warpscout.core.tunnel.InnerUdpChannel
import dev.warpscout.core.tunnel.NatPacketIn
import dev.warpscout.core.tunnel.NatPacketOut
import dev.warpscout.core.tunnel.PacketMath
import dev.warpscout.core.tunnel.TapPacketOut
import dev.warpscout.core.tunnel.UdpChannel
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.net.DatagramSocket
import java.net.Inet4Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/**
 * Собственный туннель: VpnService + data plane из `:core` (handshake AWG, transport-пакеты,
 * keepalive, счётчики). Чужой бэкенд не нужен: AWG отличается от WireGuard только мусором перед
 * инициацией, а его отправляет тот же [DataPlane].
 *
 * С 1.10.27 есть в обеих сборках: код и манифест туннеля общие (см. app/build.gradle.kts).
 */
class WarpVpnService : VpnService() {

    /**
     * Сервис живёт в отдельном процессе, и всё, что в прежней однопроцессной сборке делал интерфейс,
     * здесь надо подключать заново.
     *
     * Это не формальность: без [TunnelStatusPublisher] процесс сервиса не писал ни снимка состояния,
     * ни уведомления о нём — интерфейс не видел ровно ничего. Снаружи это выглядело так: «точка
     * 1/5, через 5 секунд handshake не завершился (этап: )», все точки подряд, подключиться
     * невозможно, хотя туннель при этом мог подниматься. Три строки ниже — не прогресс ради
     * прогресса, а условие работоспособности.
     */
    override fun onCreate() {
        super.onCreate()
        runCatching { dev.warpscout.app.CrashLog.install(this) }
        runCatching { dev.warpscout.app.TunnelDebug.attach(this) }
        // «Выключил сам» помнит снимок, а не память процесса. Новый процесс сервиса (после
        // остановки, обновления, убийства системой) иначе первым же снимком стёр бы эту отметку —
        // и фоновый подбор решил бы, что туннель можно включать.
        //
        // Читаем ДО запуска публикации: публикатор сразу пишет снимок нового процесса (всё по
        // нулям), и чтение после него могло увидеть уже этот пустой снимок — отметка «выключил
        // сам» терялась. По этому же снимку автоподъём решает, был ли туннель включён.
        runCatching {
            dev.warpscout.app.status.TunnelStatusBus.read(this)?.let { previous ->
                bootSnapshot = previous
                if (previous.stoppedByUser) TunnelState.stoppedByUser = true
                if (previous.stoppedByUserAt > TunnelState.stoppedByUserAt) {
                    TunnelState.stoppedByUserAt = previous.stoppedByUserAt
                }
            }
        }
        runCatching { TunnelStatusPublisher.start(this) }
        // Первая строка журнала: по ней видно, что процесс сервиса вообще запустился.
        runCatching {
            // Сборка — в той же строке: мелкие доправки пересобирают ту же версию поверх, и по
            // журналу иначе не понять, стоит ли уже свежая сборка.
            dev.warpscout.app.TunnelDebug.stage(
                "сервис запущен, процесс ${android.os.Process.myPid()}, сборка " +
                    "${dev.warpscout.app.BuildConfig.VERSION_NAME} · ${dev.warpscout.app.BuildConfig.BUILD_REV}"
            )
        }
        if (TunnelState.status.isBlank()) {
            TunnelState.phase = dev.warpscout.core.state.TunnelStatus.PHASE_STARTING
            TunnelState.status = getString(R.string.notif_starting)
        }
        TunnelStatusPublisher.request(urgent = true)
        // В процессе живёт ровно один экземпляр сервиса. Новый система создаёт только после
        // onDestroy прежнего — значит, если прежний ещё «жив», про него забыли все, кроме него
        // самого. Такой экземпляр закрываем: в журнале 6-й диагностики их было до трёх сразу, и на
        // каждую смену сети каждый поднимал свой туннель на том же ключе.
        val previous = live
        live = this
        if (previous != null && previous !== this && !previous.destroyed) {
            runCatching {
                dev.warpscout.app.TunnelDebug.stage(
                    "в процессе остался прежний экземпляр сервиса ${System.identityHashCode(previous)} — закрываю его"
                )
            }
            Thread({ runCatching { previous.retire() } }, "warpscout-retire").apply { isDaemon = true }.start()
        }
    }

    /**
     * Снимок, оставшийся от прошлого процесса сервиса (прочитан в onCreate до первой публикации).
     * По нему перезапуск системой и «Постоянный VPN» решают, был ли туннель включён.
     */
    @Volatile
    private var bootSnapshot: dev.warpscout.core.state.TunnelStatus? = null

    private var plane: DataPlane? = null
    /** Второй выход (другой сервер): свой data plane и сокет, если включён. */
    private var plane2: DataPlane? = null
    /** Сколько раз туннель переподнимался сам: переподключения — главный подозреваемый в расходе. */
    private val reconnects = java.util.concurrent.atomic.AtomicInteger(0)
    /** Отметка процессорного времени: по разнице видно, сколько стоила работа туннеля. */
    @Volatile
    private var cpuMarkMs: Long = android.os.Process.getElapsedCpuTime()

    /** Заряд на прошлую строку статистики: по нему видно расход за интервал. */
    @Volatile
    private var batteryMark = -1

    /** Число переподключений на прошлую строку статистики. */
    @Volatile
    private var reconnectMark = 0

    // ---------------------------------------------------------------- модем и энергия
    // «LTE быстро съедает батарею» — вопрос, на который нельзя ответить, глядя только на процент
    // заряда: непонятно, тратится он на наш туннель, на другие приложения или на сам модем,
    // который в плохой сети просыпается и перестраивается. Поэтому в строку статистики добавляем
    // ровно те цифры, по которым это различимо:
    //   ток          — сколько телефон берёт из батареи прямо сейчас (мА, минус = разряд);
    //   израсходовано— сколько мА·ч ушло за интервал (по счётчику заряда, если он есть);
    //   модем        — сколько байт и пакетов реально прошло через мобильный интерфейс;
    //   смен сети    — сколько раз менялась сеть (для модема это дорогое событие);
    //   перестройки  — сколько раз система сообщала об изменении параметров сети
    //                  (полоса, качество): на LTE это след того, что модем переключается.

    /** Отметка счётчика заряда (микроампер-часы) на прошлую строку статистики. */
    @Volatile
    private var chargeMark = -1L

    /** Байты и пакеты через мобильный интерфейс на прошлую строку статистики. */
    @Volatile
    private var modemBytesMark = -1L
    @Volatile
    private var modemPacketsMark = -1L

    /** Сколько раз менялась сеть и её параметры (накопительно). */
    private val netChanges = java.util.concurrent.atomic.AtomicInteger(0)
    private val capsChanges = java.util.concurrent.atomic.AtomicInteger(0)
    @Volatile
    private var netChangesMark = 0
    @Volatile
    private var capsChangesMark = 0

    /** Отметки процессорного времени по потокам: разница между строками статистики. */
    private val threadCpuMarks = java.util.concurrent.ConcurrentHashMap<String, Long>()

    /**
     * Цифры для строки статистики: процессорное время за интервал и число переподключений.
     * Без них «батарея садится» — это разговор о догадках; с ними видно, виноват горячий путь
     * (много cpu при малом трафике) или переподключения (много попыток за час).
     */
    private fun vitalsLine(): String {
        val now = android.os.Process.getElapsedCpuTime()
        val delta = (now - cpuMarkMs).coerceAtLeast(0L)
        cpuMarkMs = now
        // Переподключения — тоже за интервал: накопленное число за час само по себе ничего не
        // объясняет, а вот «5 переподключений за 5 минут» — это уже диагноз.
        val recon = reconnects.get()
        val reconDelta = recon - reconnectMark
        reconnectMark = recon
        val base = "cpu ${delta / 1000} с за интервал, переподключений $reconDelta"
        // Какая сеть была в эти минуты и горел ли экран: на мобильной сети каждое пробуждение
        // модема стоит несравнимо дороже, чем на Wi-Fi, и без этих двух слов журнал не объясняет,
        // почему один и тот же час стоит по-разному.
        val radio = tunnelRadio
        val env = "сеть ${netKind()}${if (radio.isEmpty()) "" else "·$radio"}, экран ${if (isScreenOn()) "вкл" else "выкл"}" +
            batteryText().let { if (it.isEmpty()) "" else ", $it" } +
            energyText().let { if (it.isEmpty()) "" else ", $it" }
        val threads = threadCpuLine()
        // Кто ушёл во второй выход по правилу приложения за интервал (с 1.10.44-beta1): по этой части
        // строки видно, ходит ли TikTok через второй выход на самом деле и сколько.
        val usage = runCatching { dispatcher?.appExits?.secondUsageText(sinceLast = true).orEmpty() }.getOrDefault("")
        // Обход DPI в туннеле (с 1.10.49-beta3): сколько соединений шло напрямую с приёмом — с начала сессии.
        val dpi = runCatching {
            (dispatcher?.tap as? DpiRelay)?.let { r ->
                if (r.opened.get() == 0L) "" else "обход DPI: напрямую ${r.viaDirect.get()}, через туннель ${r.viaTunnel.get() + r.fallbacks.get()}, сейчас ${r.active}"
            }.orEmpty()
        }.getOrDefault("")
        val tail = (if (threads.isBlank()) "" else ", $threads") + (if (usage.isBlank()) "" else ", во второй выход (вверх): $usage") +
            (if (dpi.isBlank()) "" else ", $dpi")
        // Тихий подбор для Wi-Fi проверяем здесь: строка статистики пишется раз в ~5 минут и при
        // погашенном экране. Сама проверка — в своём потоке: этот поток — таймер data plane.
        if (screenOffAt > 0L && !quietScanRunning) {
            Thread({
                runCatching { maybeQuietScan() }
                // Поиск выхода за рубежом (с 1.10.34) — если тихий подбор не начался.
                if (!quietScanRunning) runCatching { maybeAbroadSearch() }
            }, "warpscout-quiet-check").apply { isDaemon = true }.start()
        }
        return "$base, $env$tail"
    }

    /** Вид активной сети одним словом — для строки статистики. */
    private fun netKind(): String = runCatching {
        val cm = getSystemService(android.net.ConnectivityManager::class.java)
            ?: return@runCatching "неизвестно"
        val caps = cm.getNetworkCapabilities(cm.activeNetwork ?: return@runCatching "нет сети")
            ?: return@runCatching "неизвестно"
        when {
            caps.hasTransport(android.net.NetworkCapabilities.TRANSPORT_WIFI) -> "Wi-Fi"
            caps.hasTransport(android.net.NetworkCapabilities.TRANSPORT_CELLULAR) -> "мобильная"
            caps.hasTransport(android.net.NetworkCapabilities.TRANSPORT_ETHERNET) -> "Ethernet"
            else -> "другая"
        }
    }.getOrDefault("неизвестно")

    /**
     * Заряд и его изменение за интервал.
     *
     * Это связывает журнал с той самой кривой расхода, на которую смотрит человек: видно не «cpu 12 с»,
     * а «заряд 74% (−2% за 5 мин)» — и сразу понятно, потратились эти два процента на туннель или
     * на что-то ещё. Значение берём из системного «липкого» сообщения о батарее: оно всегда есть,
     * отдельный приёмник регистрировать не нужно, расход нулевой.
     */
    private fun batteryText(): String = runCatching {
        val sticky = registerReceiver(
            null,
            android.content.IntentFilter(android.content.Intent.ACTION_BATTERY_CHANGED)
        )
        val level = sticky?.getIntExtra(android.os.BatteryManager.EXTRA_LEVEL, -1) ?: -1
        val scale = sticky?.getIntExtra(android.os.BatteryManager.EXTRA_SCALE, 100) ?: 100
        if (level < 0 || scale <= 0) return@runCatching ""
        val pct = level * 100 / scale
        val prev = batteryMark
        batteryMark = pct
        if (prev < 0) "заряд $pct%" else {
            val diff = pct - prev
            "заряд $pct% (${if (diff > 0) "+" else ""}$diff% за интервал)"
        }
    }.getOrDefault("")

    /**
     * Энергетика и модем за интервал.
     *
     * Зачем это в журнале. Пока в строке статистики был только процент заряда, разговор
     * «LTE быстро есть батарею, может, приложение ни при чём» упирался в догадки. Теперь видно:
     *   • «ток 380 мА, израсходовано 32 мА·ч, модем 3.1 МБ» — телефон реально жжёт, и через
     *     модем шли мегабайты: виноват трафик (наш или чужой — видно по «вверх/вниз» туннеля);
     *   • «ток 380 мА, израсходовано 32 мА·ч, модем 40 КБ, перестройки 12» — трафика нет, а
     *     модем дёргается: это сеть и модем, а не туннель;
     *   • «ток 90 мА, модем 0 Б» — туннель в простое почти ничего не стоит.
     *
     * Ничего секретного не читаем: только счётчики батареи и сетевых интерфейсов, которые
     * система и так показывает в настройках. Прав на это не требуется; если прошивка закрывает
     * `/sys`, остаются системные API и цифры просто будут чуть грубее.
     */
    private fun energyText(): String {
        val parts = StringBuilder()
        val ma = currentMa()
        if (ma != 0) parts.append("ток ${kotlin.math.abs(ma)} мА${if (ma < 0) " разряд" else " заряд"}")
        runCatching { chargeText() }.getOrNull()?.let {
            if (it.isNotEmpty()) {
                if (parts.isNotEmpty()) parts.append(", ")
                parts.append(it)
            }
        }
        runCatching { modemText() }.getOrNull()?.let {
            if (it.isNotEmpty()) {
                if (parts.isNotEmpty()) parts.append(", ")
                parts.append(it)
            }
        }
        val nc = netChanges.get()
        val dc = nc - netChangesMark
        netChangesMark = nc
        val cc = capsChanges.get()
        val dcc = cc - capsChangesMark
        capsChangesMark = cc
        if (parts.isNotEmpty()) parts.append(", ")
        parts.append("смен сети $dc, перестроек $dcc")
        return parts.toString()
    }

    /** Ток батареи в мА (минус — разряд). Система отдаёт микроамперы, часть прошивок — милли. */
    private fun currentMa(): Int {
        val raw = runCatching {
            val bm = getSystemService(android.content.Context.BATTERY_SERVICE) as? android.os.BatteryManager
            bm?.getIntProperty(android.os.BatteryManager.BATTERY_PROPERTY_CURRENT_NOW) ?: 0
        }.getOrDefault(0)
        val value = if (raw != 0 && raw != Int.MIN_VALUE) raw else sysfsLong("current_now")?.toInt() ?: 0
        if (value == 0) return 0
        val ma = if (kotlin.math.abs(value) > 10_000) value / 1000 else value
        return ma.coerceIn(-20_000, 20_000)
    }

    /** Сколько мА·ч ушло с прошлой строки статистики — по счётчику заряда, если он есть. */
    private fun chargeText(): String {
        val now = chargeMicroAh()
        if (now <= 0) return ""
        val prev = chargeMark
        chargeMark = now
        if (prev <= 0 || now > prev) return ""
        return "израсходовано ${(prev - now) / 1000} мА·ч"
    }

    private fun chargeMicroAh(): Long {
        val v = runCatching {
            val bm = getSystemService(android.content.Context.BATTERY_SERVICE) as? android.os.BatteryManager
            bm?.getIntProperty(android.os.BatteryManager.BATTERY_PROPERTY_CHARGE_COUNTER) ?: 0
        }.getOrDefault(0)
        if (v > 0) return v.toLong()
        return sysfsLong("charge_counter") ?: -1L
    }

    /** Байты и пакеты, прошедшие через мобильный интерфейс, с прошлой строки статистики. */
    private fun modemText(): String {
        val counters = modemCounters()
        val bytesNow = counters?.first ?: mobileTrafficTotal()
        if (bytesNow < 0) return ""
        val prevBytes = modemBytesMark
        modemBytesMark = bytesNow
        if (prevBytes < 0 || bytesNow < prevBytes) return ""
        // Мобильный интерфейс сменился (rmnet_data0 → rmnet_data1), и сумма счётчиков прыгнула: за
        // пять минут через модем 2 ГБ не проходят — это не трафик, строку пропускаем.
        if (bytesNow - prevBytes > 2L * 1024 * 1024 * 1024) {
            modemPacketsMark = counters?.second ?: -1L
            return ""
        }
        val text = StringBuilder("модем ${humanBytes(bytesNow - prevBytes)}")
        val packetsNow = counters?.second ?: -1L
        if (packetsNow >= 0) {
            val prevPackets = modemPacketsMark
            modemPacketsMark = packetsNow
            if (prevPackets >= 0 && packetsNow >= prevPackets) {
                text.append("/${packetsNow - prevPackets} пакетов")
            }
        }
        return text.toString()
    }

    /**
     * Счётчики мобильных интерфейсов из `/sys`. Это единственное место, где видно работу самого
     * модема: сколько байт и пакетов он реально передал, независимо от того, кто их породил —
     * наш туннель, чужое приложение или служебный трафик сети.
     */
    private fun modemCounters(): Pair<Long, Long>? = runCatching {
        val dirs = java.io.File("/sys/class/net").listFiles() ?: return@runCatching null
        var bytes = 0L
        var packets = 0L
        var seen = 0
        for (d in dirs) {
            val name = d.name
            val mobile = name.startsWith("rmnet") || name.startsWith("ccmni") ||
                name.startsWith("pdp") || name.startsWith("wwan") || name.startsWith("v4-rmnet")
            if (!mobile) continue
            val rx = readLong(java.io.File(d, "statistics/rx_bytes"))
            val tx = readLong(java.io.File(d, "statistics/tx_bytes"))
            val rp = readLong(java.io.File(d, "statistics/rx_packets"))
            val tp = readLong(java.io.File(d, "statistics/tx_packets"))
            if (rx == null && tx == null && rp == null && tp == null) continue
            seen++
            bytes += (rx ?: 0L) + (tx ?: 0L)
            packets += (rp ?: 0L) + (tp ?: 0L)
        }
        if (seen == 0) null else bytes to packets
    }.getOrNull()

    private fun readLong(f: java.io.File): Long? = runCatching {
        if (!f.canRead()) null else f.readText().trim().toLong()
    }.getOrNull()

    private fun sysfsLong(name: String): Long? = runCatching {
        java.io.File("/sys/class/power_supply/battery/$name").readText().trim().toLong()
    }.getOrNull()

    /** Запасной вариант, если `/sys` закрыт: системные счётчики мобильного трафика. */
    private fun mobileTrafficTotal(): Long {
        val rx = android.net.TrafficStats.getMobileRxBytes()
        val tx = android.net.TrafficStats.getMobileTxBytes()
        if (rx < 0 || tx < 0) return -1
        return rx + tx
    }

    private fun humanBytes(b: Long): String = when {
        b < 1024L -> "$b Б"
        b < 1024L * 1024 -> "${b / 1024} КБ"
        b < 1024L * 1024 * 1024 -> String.format(java.util.Locale.US, "%.1f МБ", b / 1048576.0)
        else -> String.format(java.util.Locale.US, "%.2f ГБ", b / 1073741824.0)
    }

    /** Экран включён? Читается из того же места, что и для keepalive. */
    private fun isScreenOn(): Boolean = runCatching {
        (getSystemService(android.content.Context.POWER_SERVICE) as android.os.PowerManager).isInteractive
    }.getOrDefault(true)

    /**
     * Процессорное время **по потокам** за интервал — чтобы следующий разбор журнала не начинался
     * с догадок. «cpu 377 с» говорит, что виноват процесс, но не кто внутри него: читатель сокета,
     * пересылка, таймеры или публикация состояния. Здесь видно имя потока и его вклад.
     *
     * Тики `/proc` считаются сотыми долями секунды (USER_HZ = 100 на Android), поэтому 1 тик = 10 мс.
     */
    private fun threadCpuLine(): String {
        val ticks = readThreadCpu() ?: return ""
        val parts = StringBuilder()
        for ((key, total) in ticks) {
            val prev = threadCpuMarks[key] ?: total
            threadCpuMarks[key] = total
            val name = key.substringAfter('|', key)
            val deltaMs = (total - prev) * 10
            if (deltaMs >= 1_000) parts.append(name).append(' ').append(deltaMs / 1000).append(" с; ")
        }
        return if (parts.isEmpty()) "" else "потоки: ${parts.toString().trimEnd(' ', ';')}"
    }

    /** Имя потока → суммарное процессорное время в тиках. null — /proc недоступен. */
    private fun readThreadCpu(): Map<String, Long>? {
        val files = java.io.File("/proc/self/task").listFiles() ?: return null
        val out = HashMap<String, Long>()
        for (task in files) {
            val stat = runCatching { java.io.File(task, "stat").readText() }.getOrNull() ?: continue
            // Второе поле (имя потока) может содержать пробелы, поэтому режем по последней скобке:
            // дальше идут ровные поля, и utime/stime — 11-е и 12-е из них.
            val tail = stat.substringAfterLast(')').trim().split(' ')
            val utime = tail.getOrNull(11)?.toLongOrNull() ?: continue
            val stime = tail.getOrNull(12)?.toLongOrNull() ?: 0L
            val name = runCatching { java.io.File(task, "comm").readText().trim() }.getOrNull().orEmpty()
            // Ключ — номер потока, а не имя. Ядро отдаёт `comm` обрезанным до 15 символов, и три
            // потока «warpscout-tunnel-in/-out/-timers» превращались в один ключ: цифры в строке
            // статистики перезаписывали друг друга и показывали разницу между разными потоками.
            if (name.isNotEmpty()) out["${task.name}|$name"] = utime + stime
        }
        return out
    }
    private var worker2: Thread? = null
    private var secondSocket: DatagramSocket? = null
    /** Разделитель пакетов между выходами: tun читает только он. */
    private var dispatcher: TunDispatcher? = null

    /**
     * Диспетчер со вторым выходом. С 1.10.49-beta3 диспетчер бывает и с одним выходом — ради обхода DPI
     * (см. dpiSetup); всё, что про второй выход (Telegram, автовыбор, адреса), смотрит только сюда.
     */
    private val secondDispatcher: TunDispatcher? get() = dispatcher?.takeIf { it.multiLane }
    private var tun: ParcelFileDescriptor? = null
    private var worker: Thread? = null
    private var udpSocket: DatagramSocket? = null
    private val stopped = java.util.concurrent.atomic.AtomicBoolean(false)

    /**
     * Номер попытки подъёма. Поток подъёма, который начался до «Отключить», обязан увидеть, что
     * его эпоха устарела, и выйти, не трогая tun/сокет/plane: иначе он закрывал бы файловые
     * дескрипторы уже следующей сессии — ровно то, из-за чего «после выключения больше не включается».
     */
    private val epoch = java.util.concurrent.atomic.AtomicInteger(0)

    /**
     * Экземпляр закрыт системой (onDestroy) — с этого момента он не имеет права ничего поднимать.
     *
     * Без этого флага в процессе копились «призраки». Поток подъёма, начавшийся до onDestroy,
     * доходил до startVpn уже после него: заново регистрировал слежение за сетью и поднимал tun.
     * Система проверяет только UID, поэтому tun выдавала, а сам сервис создавала заново через
     * привязку («сервис запущен» сразу после «tun получен» — в журнале так 11 раз). Старый
     * экземпляр жил дальше сам по себе, и на смену сети отвечали уже несколько туннелей сразу.
     */
    @Volatile
    private var destroyed = false

    /**
     * Туннель нужен: был старт, и не было ни «Отключить», ни окончательного отказа. Вся
     * автоматика (смена сети, медленный повтор, ожидание сети, включённый экран) работает только
     * при нём — иначе она поднимала бы туннель, который никто не просил.
     */
    @Volatile
    private var wanted = false

    /**
     * Замок владения ресурсами попытки: tun, сокеты, data plane. Закрытие (closeAll) и «вступление
     * во владение» в startVpn идут под ним, поэтому между проверкой «попытка ещё наша» и
     * присваиванием не может вклиниться ни onDestroy, ни «Отключить», ни новая попытка.
     */
    private val life = Any()

    /**
     * Поколение отложенного ожидания: медленный повтор или ожидание сети. Каждое новое ожидание,
     * новый старт, удачный подъём и остановка увеличивают его, и прежнее ожидание тихо гаснет.
     * Раньше каждый вызов заводил свой поток: к 23:14 «медленный повтор 2…5 из 12» шли пачкой, и
     * каждый заводил ещё один.
     */
    private val waitGen = java.util.concurrent.atomic.AtomicInteger(0)

    /** Эпоха plane, уже сообщившего о своей смерти: второй и следующие отчёты не нужны. */
    private val fatalEpoch = java.util.concurrent.atomic.AtomicInteger(-1)

    /**
     * Точки, промолчавшие в текущем цикле перебора. Мёртвыми их записываем, только когда в этом же
     * цикле поднялась другая точка: молчание само по себе ничего не доказывает — так же молчит и
     * пропавшая сеть (в журнале 18:14 шесть точек подряд за 18 с).
     */
    private val cycleSilent = java.util.Collections.synchronizedList(ArrayList<String>())

    /** Какие точки уже пробовали в этом цикле — для честной строки «не ответила ни одна из N». */
    private val cycleTried = java.util.Collections.synchronizedSet(LinkedHashSet<String>())

    /** Приёмник «экран включён»: когда туннель лежит и ждёт паузы, это повод попробовать сразу. */
    private var screenReceiver: android.content.BroadcastReceiver? = null

    @Volatile
    private var lastScreenRetryAt = 0L

    /** Идёт подъём или уже работает — второй запуск (плитка, кнопка, шторка) игнорируем. */
    @Volatile
    private var starting = false

    /** Текст конфига, которым поднят туннель: по нему же переподнимаем после смены сети. */
    @Volatile
    private var lastConfigText: String? = null
    @Volatile
    private var lastStartId: Int = 0

    /**
     * Слежение за «настоящей» сетью (без VPN). Раньше это жило в MainActivity — и в фоне, когда
     * экран погашен или активити уничтожена, не работало вовсе: переключение Wi-Fi ↔ мобильные
     * оставляло мёртвый UDP-сокет, туннель молчал, а замочек в шторке продолжал висеть.
     * Теперь наблюдатель живёт в сервисе — он существует всё время работы туннеля.
     */
    private var netCallback: android.net.ConnectivityManager.NetworkCallback? = null

    /** Сеть, через которую поднимали туннель: с ней сравниваем, чтобы не перезапускаться зря. */
    @Volatile
    private var baselineNetwork: android.net.Network? = null

    /** Сеть менялась — значит, туннель нужно переподнять, даже если новой сети пока нет. */
    @Volatile
    private var networkChanged = false

    @Volatile
    private var lastNetRestartAt: Long = 0L

    /** Сколько раз подряд не удалось переподнять туннель после смены сети (максимум 3). */
    @Volatile
    private var netRestartAttempts: Int = 0

    /** Идёт переподъём после смены сети: в этом режиме сервис не снимает себя при неудаче. */
    @Volatile
    private var autoRebind: Boolean = false

    /**
     * Текущий старт пришёл не из перебора в интерфейсе (плитка, автоподъём, возврат после подбора):
     * за него следующую точку берёт сам сервис (см. superviseStart). Перебор в интерфейсе шлёт
     * отметку начала подключения и меняет точки сам — тогда сервис при отказе снимает себя, как раньше.
     */
    @Volatile
    private var selfDrivenStart: Boolean = false

    /** Сеть поменялась повторно, пока шла пауза — перезапустимся сразу после неё. */
    @Volatile
    private var netRestartPending: Boolean = false

    /**
     * Времена автоматических переподъёмов. Ограничение нужно, чтобы «мёртвая» сеть не превратилась
     * в бесконечный цикл handshake'ов: за ночь такой цикл и радио, и процессор держит занятыми
     * (в статистике батареи это потом выглядит как «приложения нет, а батарея села»).
     */
    private val autoRestartTimes = ArrayDeque<Long>()

    /** Не больше стольких автоперезапусков за окно [AUTO_RESTART_WINDOW_MS]. */
    private val AUTO_RESTART_LIMIT = 6
    private val AUTO_RESTART_WINDOW_MS = 10 * 60_000L

    /**
     * Медленный режим после серии неудач: попытка раз в 5 минут, всего до часа.
     *
     * Компромисс между «сдались навсегда» (человек не знает, что остался без туннеля) и
     * «долбим сеть бесконечно» (батарея). 12 попыток по три пакета — это меньше, чем одно
     * обновление ленты, а шанс подняться самому после смены соты или возврата сети есть.
     */
    private val SLOW_RETRY_EVERY_MS = 5 * 60_000L
    private val SLOW_RETRY_LIMIT = 12

    /**
     * Сколько ждём тишины после события сети, прежде чем перезапускаться.
     *
     * Переключение Wi-Fi ↔ LTE приходит пачкой из трёх-четырёх событий, и склеить их надо — но не
     * четырьмя секундами, как было раньше: событие «сеть появилась» внутри паузы отодвигало старт
     * на всю паузу, и переподключение занимало 5–8 секунд вместо одной. 700 мс хватает, чтобы не
     * перезапуститься дважды и не потерять ни одного события.
     */
    private val NET_QUIET_MS = 700L

    /** Исходы ожидания попытки: поднялся / провалился / не дождались. */
    private val ATTEMPT_UP = 1
    private val ATTEMPT_FAILED = 0
    private val ATTEMPT_TIMEOUT = -1

    /**
     * Сколько раз подряд меняли точку входа, так и не подняв туннель.
     *
     * Считать надо отдельно от [netRestartAttempts]: смена точки — это не «ещё одна попытка того
     * же», а новая информация (эта точка мертва). Но и бесконечно бегать по кругу нельзя: если
     * сеть не пропускает WARP вообще, каждая точка будет молчать, и перебор съест батарею.
     */
    private var rotationsSinceUp = 0
    private val MAX_ROTATIONS = 6

    /** Переход на другую точку получает свежий бюджет быстрых попыток, иначе сработает «10 мин». */
    @Volatile
    private var forceFastRetry = false

    /**
     * Порядок перебора точек на текущий цикл переподключения и позиция в нём.
     *
     * Не просто очередь из настроек: первой идёт текущая точка, второй — та, что работала на
     * такой же сети (см. [EndpointMemory]). Адреса WARP не универсальны: на Wi-Fi живёт один,
     * на мобильной — другой, и без этого порядка сервис каждый раз тратил попытку на «чужую».
     */
    private var failoverOrder: List<String> = emptyList()
    private var failoverPos = -1

    /** Вид сети, на которой мы поднимались: Wi-Fi / мобильная / Ethernet. Для памяти точек. */
    @Volatile
    private var lastNetKind: String = ""

    /**
     * Тип мобильной связи сети туннеля: «LTE», «H+», «H»… (с 1.10.40, см. NetIdentity.radioOf); пусто —
     * Wi-Fi или неизвестно. Меняется и без смены сети: телефон переходит LTE → H+ на той же сети.
     */
    @Volatile
    private var tunnelRadio: String = ""

    /** Пояснения про медленную связь, уже написанные на этом типе связи (чтобы не на каждом подъёме). */
    private val slowRadioSaid = java.util.concurrent.ConcurrentHashMap.newKeySet<String>()

    /** Уже ждём возвращения сети, чтобы поднять туннель самой (см. [scheduleRevive]). */
    @Volatile
    private var reviving = false

    /** Сколько медленных попыток уже сделано (сбрасывается при успехе). */
    @Volatile
    private var slowRetries = 0

    /** Вид сети, под который построен [failoverOrder]: другая сеть — повод построить его заново. */
    private var failoverNet: String = ""

    // ── дозор: пробы соседних точек, пока туннель работает ─────────────────────
    //
    // Зачем. Очередь перебора собирается при подключении и дальше не обновляется. Если точка из
    // неё успела умереть, при аварии сервис тратит на неё целую попытку — в журнале это «порт
    // закрыт (ICMP port unreachable)» или «сервер молчит» и 12–20 секунд без интернета. Дозор
    // узнаёт заранее: живую точку ставит в перебор сразу за текущей, мёртвую — в конец.
    //
    // Почему сессия не страдает. Проба — одна инициация handshake с отдельного UDP-сокета,
    // выведенного из туннеля через protect(). Транспортных пакетов проба не шлёт, а сервер
    // WireGuard переходит на новую сессию только по первому такому пакету — текущая остаётся
    // текущей. Если сервер всё же перенёс наш адрес на сокет пробы, его сразу возвращает
    // внеочередной keepalive (DataPlane.keepaliveNow). И страховка: если сессия оборвётся вскоре
    // после пробы, дозор выключается до перезапуска сервиса (см. [sentryBanned]).

    /** Период обхода. Радио и так просыпается на keepalive каждые 60–120 с — это капля. */
    private val SENTRY_EVERY_MS = 12 * 60_000L

    /** Первый обход — не сразу: в первые минуты после подъёма приложения переподключаются сами. */
    private val SENTRY_FIRST_MS = 3 * 60_000L

    /** Сколько считать точку живой после удачной пробы. */
    private val SENTRY_FRESH_MS = 30 * 60_000L

    /** Сколько помнить, что точка мертва; потом она снова «неизвестна» и идёт в свою очередь. */
    private val SENTRY_DEAD_MS = 60 * 60_000L

    /** Итог обхода: проверять нечего / что-то узнали / одни ошибки сокета. */
    private val SENTRY_IDLE = 0
    private val SENTRY_INFO = 1
    private val SENTRY_ERRORS = 2

    @Volatile
    private var sentryThread: Thread? = null

    /** Пробы этой сессии упираются в ошибки сокета — дозор молчит до следующего подъёма. */
    @Volatile
    private var sentryOff = false

    /** Сессия оборвалась вскоре после пробы — дозор выключен до перезапуска сервиса. */
    @Volatile
    private var sentryBanned = false

    /** Когда ушла последняя проба: по ней видно, не совпала ли с ней смерть сессии. */
    @Volatile
    private var lastSentryProbeAt = 0L

    /** Позиция «второй» пробы: по кругу, чтобы со временем проверить всю очередь. */
    private var sentryPos = 0

    /** Что дозор знает о точке: когда отвечала, сколько раз подряд не ответила и когда. */
    private data class SentryMark(val okAt: Long = 0L, val fails: Int = 0, val failAt: Long = 0L)

    /** Ключ — «вид сети|адрес:порт»: точка, живая на Wi-Fi, может молчать на мобильной. */
    private val sentryMarks = java.util.concurrent.ConcurrentHashMap<String, SentryMark>()

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        // Проверка точки и проверка связи приходят обычным startService от открытого экрана, а не
        // startForegroundService: требования «покажи уведомление за 5 с» у них нет. Обрабатываем
        // их раньше всего остального — иначе уведомление на миг сменилось бы на «Поднимаю туннель…»
        // у работающего туннеля.
        if (intent?.action == ACTION_PROBE) {
            handleProbe(intent, startId)
            return START_NOT_STICKY
        }
        if (intent?.action == ACTION_CHECK) {
            handleCheckRequest(startId)
            return START_NOT_STICKY
        }
        if (intent?.action == ACTION_SPEED) {
            handleSpeedRequest(startId)
            return START_NOT_STICKY
        }
        if (intent?.action == ACTION_SECOND_ROUTES) {
            handleSecondRoutes(startId)
            return START_NOT_STICKY
        }
        if (intent?.action == ACTION_DPI_RELOAD) {
            handleDpiReload(startId)
            return START_NOT_STICKY
        }
        // Ответ на вопрос про Telegram (с 1.10.36): кнопка уведомления или окно на экране. Приходит
        // обычным startService, как проверки выше: туннель не трогаем и не поднимаем.
        if (intent?.action == ACTION_TG_SWITCH || intent?.action == ACTION_TG_STAY) {
            handleTelegramAnswer(intent, startId)
            return START_NOT_STICKY
        }
        // ГЛАВНОЕ ПРАВИЛО ANDROID: после startForegroundService() сервис обязан вызвать
        // startForeground() примерно за 5 секунд, иначе процесс убивают с
        // ForegroundServiceDidNotStartInTimeException — без записи в журнал, и туннель умирает
        // вместе с процессом. Поэтому объявляем себя foreground САМЫМ ПЕРВЫМ действием, до любых
        // проверок и ветвлений: раньше это происходило в потоке подъёма (после создания сокета)
        // или только в одной из ветвей — и на переподключениях пяти секунд не хватало.
        val foregroundOk = runCatching { postNotificationNow(getString(R.string.notif_starting)) }.isSuccess
        if (!foregroundOk) {
            val why = TunnelState.status
            TunnelDebug.error("startForeground не удался: $why")
            dev.warpscout.app.CrashLog.note(this, "startForeground отказал: $why")
        }

        // Остановка обрабатывается ПОСЛЕ перехода в foreground — иначе получается дыра: если
        // система успела получить startForegroundService() и следом STOP, требование «покажи
        // уведомление» осталось бы невыполненным, и она убила бы процесс приложения
        // (ForegroundServiceDidNotStartInTimeException) — со стороны это выглядит как «вылетает
        // при переключении вкладки».
        if (intent?.action == ACTION_STOP) {
            // «Выключить» нажал человек (кнопка, плитка, «Отключить» в уведомлении) — запоминаем:
            // после этого ничто не включает туннель само. Остановки перебора точек и подбора
            // приходят без этой отметки: за ними сразу следует новый старт.
            if (intent?.getBooleanExtra(EXTRA_BY_USER, false) == true) {
                // Повторное «Выключить» по уже выключенному (перебор точек в интерфейсе страхуется
                // им после отмены) в журнал вторую одинаковую строку не пишет.
                val already = TunnelState.stoppedByUser && !TunnelState.wanted && !TunnelState.up && !TunnelState.busy
                TunnelState.stoppedByUser = true
                TunnelState.stoppedByUserAt = System.currentTimeMillis()
                // Вопрос про Telegram касается работающего туннеля (с 1.10.36).
                clearTelegramAsk()
                if (!already) {
                    TunnelDebug.stage("туннель выключен вручную — сам больше не включаю, пока не нажмёшь «Включить»")
                }
            }
            shutdown()
            // Останавливаемся только если после «Отключить» ничего не пришло. Раньше здесь был
            // stopSelf() без номера — он отменял и «Подключить», присланный сразу следом (перебор
            // точек шлёт «Отключить» и тут же «Подключить» после каждой неудачной точки). Экземпляр
            // получал команду старта, а следом onDestroy, и поток подъёма поднимал туннель уже в
            // закрытом экземпляре — так рождались «призраки». stopSelf(startId) система игнорирует,
            // если после этой команды уже пришла другая.
            runCatching { stopSelf(startId) }
            return START_NOT_STICKY
        }

        // Старт из перебора точек, а туннель уже после начала подключения выключили вручную
        // (плитка, «Отключить» в уведомлении): старт разминулся с выключением и опоздал. Раньше он
        // проходил и снимал отметку «выключил сам» — туннель включался вопреки человеку.
        val requestedAt = intent?.getLongExtra(EXTRA_REQUESTED_AT, 0L) ?: 0L
        if (intent?.action == ACTION_START && requestedAt > 0L && TunnelState.stoppedByUserAt >= requestedAt) {
            TunnelDebug.stage("старт пропущен: туннель выключили вручную уже после начала подключения")
            if (plane == null && !starting) runCatching { stopSelf(startId) }
            return START_NOT_STICKY
        }

        // «Занят» — только если подъём идёт сейчас или plane действительно работает. Раньше
        // хватало plane != null: после неудачного переподъёма мёртвый plane оставался в поле, и
        // следующее «Подключить» получало «уже поднимается или работает» — в журнале 18:44:38
        // первая точка перебора сгорела так впустую, а плитка в этом состоянии не делала ничего.
        val planeRunning = plane != null && worker?.isAlive == true
        if ((starting && plane == null) || planeRunning) {
            // Повторное нажатие «Подключить» (кнопка, плитка быстрых настроек) не должно
            // поднимать второй туннель поверх первого — только напомнить, что уже работаем.
            // Работающий туннель «поднимающимся» не называем: раньше второе нажатие плитки
            // меняло «поднят» на «поднимается», и так оставалось до следующего события.
            if (!TunnelState.up) {
                TunnelState.phase = dev.warpscout.core.state.TunnelStatus.PHASE_STARTING
                TunnelState.status = "туннель уже поднимается или работает"
                postNotification(TunnelState.status)
            }
            return START_REDELIVER_INTENT
        }
        // Повторная доставка старта: система убила процесс с работающим туннелем и перезапустила
        // сервис с той же командой. Точка в ней может быть давно мёртвой (сервис мог сменить её
        // сам), поэтому поднимаем последнюю рабочую конфигурацию. Выключенный руками — не трогаем.
        val redelivered = (flags and START_FLAG_REDELIVERY) != 0
        if (redelivered && TunnelState.stoppedByUser) {
            TunnelDebug.stage("система перезапустила сервис, но туннель выключен вручную — сам не включаю")
            TunnelState.phase = dev.warpscout.core.state.TunnelStatus.PHASE_IDLE
            stopSelf(startId)
            return START_NOT_STICKY
        }
        val lastWorking = if (redelivered) TunnelLastConfig.load(this) else null
        if (lastWorking != null) {
            TunnelDebug.stage(
                "система перезапустила сервис — поднимаю последнюю рабочую конфигурацию (${endpointOf(lastWorking) ?: "точка не указана"})"
            )
        }
        val explicit = lastWorking ?: intent?.getStringExtra(EXTRA_CONF)?.takeIf { it.isNotBlank() }
        // Без конфига приходят перезапуск системой (null), «Постоянный VPN» из настроек Android и
        // автоподъём после загрузки/обновления. Раньше всё это кончалось «нет конфигурации —
        // запуск пропущен», и туннель не возвращался. Теперь поднимаем последнюю рабочую
        // конфигурацию — если туннель был включён и человек его не выключал (см. autoStartText).
        val text = explicit ?: autoStartText(intent)
        if (text.isNullOrBlank()) {
            if (explicit == null && intent?.action != ACTION_START) {
                // Автоподъём отказался сам и объяснил почему в журнале: это не сбой, а решение
                // (выключен вручную, не был включён, нет рабочей конфигурации).
                TunnelState.phase = dev.warpscout.core.state.TunnelStatus.PHASE_IDLE
                TunnelState.status = "туннель не включён"
            } else {
                TunnelState.phase = dev.warpscout.core.state.TunnelStatus.PHASE_FAILED
                TunnelState.status = "нет конфигурации — запуск пропущен"
            }
            stopSelf(startId)
            return START_NOT_STICKY
        }
        if (plane != null || tun != null) {
            // Прошлая попытка кончилась, но её plane и tun остались на месте: освобождаем их сами.
            TunnelDebug.stage("прошлая попытка закончилась, но не освободила туннель — освобождаю")
            epoch.incrementAndGet()
            closeAll()
        }
        lastConfigText = text
        lastStartId = startId
        // Проверочный подъём подбора (см. startAndWait): ему не нужен автозамер скорости — он
        // мерит сам, и два замера разом мешали бы друг другу.
        quietSession = explicit != null && intent?.getBooleanExtra(EXTRA_QUIET, false) == true
        // Подключение по кнопке/плитке — не автопереподъём: при неудаче сервис снимает себя, как
        // и раньше, иначе следующее ручное нажатие упрётся в «уже поднимается». Исключение —
        // старт без перебора в интерфейсе: мёртвую точку там меняет сам сервис (см. superviseStart).
        autoRebind = false
        val selfDriven = !quietSession && (requestedAt <= 0L || redelivered)
        selfDrivenStart = selfDriven
        netRestartAttempts = 0
        // Ручной старт — новый отсчёт: отложенные повторы отменяются, счётчики циклов — с нуля.
        wanted = true
        TunnelState.wanted = true
        // Проверочный подъём подбора (quiet) — не решение человека включить туннель: отметку
        // «выключил вручную» он не снимает. С 1.10.30 проверка доступности через туннель при
        // подборе включена у всех, и без этого подбор при выключенном туннеле стирал бы отметку.
        if (!quietSession) TunnelState.stoppedByUser = false
        cancelWaits()
        slowRetries = 0
        cycleSilent.clear()
        cycleTried.clear()
        // Номер на момент команды: если до запуска потока успели нажать «Отключить», подниматься
        // нельзя — иначе «Отключить», нажатое сразу после «Подключить», не срабатывало бы.
        val bootEpoch = epoch.get()
        // Раньше здесь был startVpn(text) напрямую, и onStartCommand блокировался на 12 с, ожидая
        // handshake. Главный поток сервиса — он же главный поток приложения: UI в это время висел,
        // и выглядело это ровно как «туннель запускается, потом без ошибок ничего не происходит».
        Thread({
            if (epoch.get() == bootEpoch && wanted && !destroyed) {
                startVpnSafely(text, startId)
                if (selfDriven) superviseStart()
            }
        }, "warpscout-vpn-boot").apply { isDaemon = true }.start()
        return START_REDELIVER_INTENT
    }

    override fun onDestroy() {
        // Флаг — первым: всё, что этот экземпляр ещё делает в фоне (подъём, переподъём, медленный
        // повтор, ожидание сети), увидит его и остановится, а не поднимет туннель «без хозяина».
        destroyed = true
        wanted = false
        shutdown()
        if (live === this) live = null
        super.onDestroy()
    }

    /**
     * Система отозвала VPN: включили другой VPN или сняли разрешение в настройках. Раньше это
     * проходило молча — туннель просто исчезал, и в журнале не было ни строки. Теперь причина
     * остаётся в журнале, а сервис закрывается аккуратно.
     */
    override fun onRevoke() {
        runCatching {
            TunnelDebug.error(
                "система отозвала VPN",
                "включён другой VPN или снято разрешение — нажми «Подключить», когда он станет не нужен"
            )
        }
        shutdown()
        super.onRevoke()
    }

    /**
     * Закрыть экземпляр, о котором система уже забыла (см. onCreate). Общее состояние не трогаем:
     * оно принадлежит новому экземпляру, который в эту минуту поднимается.
     */
    private fun retire() {
        destroyed = true
        wanted = false
        epoch.incrementAndGet()
        stopped.set(true)
        cancelWaits()
        unwatchNetwork()
        closeAll()
    }

    /**
     * [startVpn] под присмотром (с 1.10.42). Исключение в потоке подъёма роняло весь процесс туннеля:
     * журнал 24.11, 08:23:22 — «Socket is closed» при переподъёме после смены сети, и туннель лежал,
     * пока система не перезапустит сервис. Теперь сбой — строка в журнале и запись в «падениях» (без
     * падения), а переподнимает туннель обычная логика: ожидание попытки, перебор точек, медленный режим.
     */
    private fun startVpnSafely(text: String, startId: Int) {
        try {
            startVpn(text, startId)
        } catch (e: Exception) {
            starting = false
            TunnelState.busy = false
            runCatching {
                TunnelDebug.error(
                    "подъём сорвался: ${e.javaClass.simpleName}: ${e.message?.take(160).orEmpty()}",
                    "туннель переподнимется сам; если повторяется — пришли журнал"
                )
            }
            runCatching {
                val stack = java.io.StringWriter()
                    .also { sw -> java.io.PrintWriter(sw).use { e.printStackTrace(it) } }
                    .toString()
                dev.warpscout.app.CrashLog.note(
                    this,
                    "сбой подъёма без падения · поток ${Thread.currentThread().name}\n${stack.take(2500)}"
                )
            }
        }
    }

    private fun startVpn(text: String, startId: Int) {
        // Закрытый системой экземпляр не поднимает ничего (см. [destroyed]).
        if (destroyed) {
            TunnelDebug.stage("подъём отменён: этот экземпляр сервиса уже закрыт системой")
            return
        }
        val myEpoch = epoch.incrementAndGet()
        fun alive() = myEpoch == epoch.get() && !stopped.get() && !destroyed
        // Выход из устаревшей попытки обязан снять свои флаги, иначе сервис навсегда останется
        // «занятым»: следующий старт получит «уже поднимается» и не сделает ничего. Именно это
        // выглядело как «немного работает, потом больше не подключается».
        fun abandon() {
            if (myEpoch == epoch.get() && !stopped.get()) {
                starting = false
                TunnelState.busy = false
            }
        }
        // Остатки прошлой попытки (plane, сокет, tun) закрываем до новой. startVpn не должен
        // поднимать второй data plane рядом с первым: в журнале 23:14:01 два переподъёма подряд
        // оставили в одном экземпляре два plane (эпохи 73 и 74), и первый, никому не нужный, ещё
        // долго слал свои rekey на том же ключе.
        if (plane != null || tun != null || udpSocket != null) closeAll()
        starting = true
        // Экземпляр сервиса переиспользуется: без сброса флага «остановлен» второй подъём после
        // «Отключить» жил бы с чужим состоянием (watchdog и статусы считали бы себя остановленными).
        stopped.set(false)
        TunnelState.busy = true
        TunnelState.up = false
        TunnelState.error = null
        TunnelState.gaveUp = false
        TunnelState.phase = dev.warpscout.core.state.TunnelStatus.PHASE_STARTING
        TunnelState.startedAt = System.currentTimeMillis()
        // Итог проверки связи и замер скорости — про прошлую сессию; у новой их ещё нет.
        TunnelState.clearLink()
        TunnelState.clearSpeed()
        TunnelState.dataCheckAt = 0L
        freezeStreak = 0
        TunnelDebug.reset()
        createChannel()
        postNotification(getString(R.string.notif_starting))

        watchNetwork()
        // Экземпляр и эпоха в журнале: по ним видно, один подъём идёт или два параллельно (второй
        // экземпляр сервиса — это двойные рукопожатия и двойной расход, а не «просто лог»).
        TunnelDebug.stage("подъём: экземпляр ${System.identityHashCode(this)}, эпоха $myEpoch")
        TunnelDebug.stage("конфиг получен (${text.toByteArray().size} байт)")
        val parsed = runCatching { WgConf.toWarpConfig("WARP", text) }.getOrNull()
        if (parsed == null) {
            fail("конфиг не разбирается: нет PrivateKey или PublicKey", startId, myEpoch)
            return
        }
        // Маршруты — нынешние из «Туннелирования» (с 1.10.33), а не те, что лежат в конфиге: точки
        // из подбора и конфиг для автоподъёма несли маршруты своего времени. Журнал 23.11:
        // «переключение из топа» и подъём после обновления шли с 56 маршрутами «всё, кроме
        // российских сетей», хотя выбраны были списки. Проверочный подъём подбора (quiet) не
        // трогаем: он проверяет ровно тот конфиг, что ему дали, — и замер скорости смотрит на его
        // маршруты (см. VpnTunnelVerifier).
        val withRoutes = if (quietSession) null else routesFromSettings(parsed)
        val routedCfg = withRoutes?.first ?: parsed
        val routedText = withRoutes?.second ?: text
        if (withRoutes != null && myEpoch == epoch.get()) lastConfigText = routedText
        // Шум под эту сеть (с 1.10.30): если на ней шум конфига замерзает (см. NoiseMemory), та же
        // точка поднимается с маской, которая здесь работает. Конфиг, который потом сохранится для
        // перезагрузки и пойдёт в перебор, — уже с новым шумом.
        val noiseFix = noiseForNetwork(routedCfg)
        val cfg = noiseFix?.first ?: routedCfg
        val runText = noiseFix?.second ?: routedText
        if (noiseFix != null && myEpoch == epoch.get()) lastConfigText = runText
        TunnelState.endpoint = cfg.endpoint.render()
        TunnelDebug.stage("сервер ${cfg.endpoint.render()}, шум ${JunkLibrary.nameOf(cfg.junk)}, MTU ${cfg.mtu}")

        val socket = try {
            // soTimeout = 1500: ровно столько ждём один ответ handshake; attempts в NetSettings умножает это.
            DatagramSocket(null).apply { reuseAddress = true; soTimeout = 1500 }
        } catch (e: Exception) {
            fail("сокет: ${e.javaClass.simpleName} ${e.message}", startId, myEpoch)
            return
        }
        // Без protect() пакеты туннеля попадут в сам туннель — трафик замкнётся по кругу.
        val protected = runCatching { protect(socket) }.getOrDefault(false)
        if (!protected) {
            runCatching { socket.close() }
            // Чаще всего у приложения нет разрешения на VPN: после переустановки его дают заново, а
            // восстановление копии или автозапуск поднимают сервис раньше (журнал 23.11, 19:35).
            val noPermission = runCatching { android.net.VpnService.prepare(this) != null }.getOrDefault(false)
            fail(
                if (noPermission) "нет разрешения на VPN (после переустановки его дают заново) — нажми «Подключить»"
                else "protect() отказал — туннель не поднят во избежание петли",
                startId, myEpoch
            )
            return
        }
        runCatching { socket.connect(InetSocketAddress(cfg.endpoint.host, cfg.endpoint.port)) }
            .onFailure { runCatching { socket.close() }; fail("connect(): ${it.message}", startId, myEpoch); return }
        TunnelDebug.stage("UDP-сокет создан и защищён")
        // Точка отсчёта для слежения за сетью — сеть, через которую пойдёт этот сокет. Раньше
        // после каждого переподъёма сервис забывал её и первую же новую сеть принимал за «свою»:
        // в журнале 20:06:35 «сеть туннеля: мобильная 204» вместо переподключения, и ещё 13 с
        // пакеты уходили в пропавший Wi-Fi, пока сокет не ответил ENETUNREACH.
        underlyingNetwork()?.let { net ->
            if (net != baselineNetwork) TunnelDebug.stage("сеть туннеля: ${describeNetwork(net)}")
            baselineNetwork = net
            rememberNetKind(net)
            updateRadio(net)
        }
        if (!alive()) {
            // Пока поднимались, пользователь нажал «Отключить» (или пошла следующая попытка).
            runCatching { socket.close() }
            abandon()
            return
        }

        // Второй выход: другой сервер для выбранных подсетей (страна/провайдер на выбор).
        // Внутри WARP выбрать регион нельзя, поэтому «регион для сайта» = второй туннель рядом.
        // С 1.10.31 серверов второго выхода может быть несколько (автопоиск Proton Free): начинаем с
        // первого по порядку, дальше перебирает поток второго выхода (см. ниже).
        val secondList = secondCandidates(secondConfig())
        val secondCfg = secondList.firstOrNull()?.second
        // Telegram — через второй выход с самого подъёма, только если на этой сети человек ответил
        // «Переключить» меньше суток назад, а точка выходила через Россию (с 1.10.36, см.
        // checkTelegramMedia). Иначе — через WARP, как всё остальное: в Москве Telegram режут не
        // всегда, а второй выход бывает медленнее (23.11: через Мексику было «прямо тяжело»).
        // Выход по приложениям (с 1.10.39, см. AppExit): выбор человека для Telegram в его строке
        // («Всегда WARP» или «Второй выход») отменяет и вопрос, и автоматику ниже.
        val exitRules = appExitRules()
        tgFixed = telegramFixed(exitRules)
        val tgSite = if (secondCfg != null && !quietSession) telegramSiteFor(cfg) else ""
        val tgWanted = when (tgFixed) {
            AppExit.SECOND -> secondCfg != null && !quietSession
            AppExit.WARP -> false
            else -> tgSite.isNotEmpty()
        }
        val tunRoutes = runCatching { ExitRouter.of(SplitRoutes.prefixesOf(cfg.allowedIps)) }.getOrNull()
        val router = secondCfg?.let { ExitRouter.of(secondExitCidrs(tgWanted, tunRoutes)) }
            ?.takeIf { !it.isEmpty } ?: ExitRouter.EMPTY
        val multiExit = secondCfg != null && !router.isEmpty
        tgViaSecond = multiExit && tgWanted
        TunnelState.tgSecond = tgViaSecond
        probeHosts.clear()
        siteSaid = ""
        tgFarSaid = false
        // Говорим и про выключенный второй выход: иначе «две цепочки рукопожатий в журнале»
        // невозможно объяснить, не заглядывая в настройки.
        TunnelDebug.stage(if (multiExit) "второй выход включён" else "второй выход выключен")
        if (tgViaSecond && tgFixed == AppExit.SECOND) {
            TunnelDebug.stage("Telegram — через второй выход: так выбрано в «Туннелировании» (вопросов не задаю)")
        } else if (tgViaSecond) {
            TunnelDebug.stage(
                "Telegram — через второй выход: на этой сети ты ответил «Переключить» (действует сутки), " +
                    "точка выходила через ${ExitSite.describe(tgSite)}; станет медленнее Москвы — верну через WARP"
            )
        } else if (tgFixed == AppExit.WARP && multiExit) {
            TunnelDebug.stage("Telegram — всегда через WARP: так выбрано в «Туннелировании», второй выход для него выключен, вопросов не задаю")
        } else if (tgFixed == AppExit.SECOND && !quietSession) {
            TunnelDebug.stage("Telegram: выбран «Второй выход», но второго выхода в этой сессии нет — Telegram идёт через WARP")
        }

        val builder = builderFor(cfg)
        if (multiExit && !isFullTunnel(cfg)) {
            // В split-режиме подсети второго выхода должны попадать в tun, иначе они уйдут мимо.
            // При «весь трафик» они и так в tun: тысячи лишних маршрутов не добавляем (с 1.10.31
            // адресов второго выхода стало много — сайты из списков «заблокировано для РФ»).
            router.cidrs.forEach { cidr ->
                val host = cidr.substringBefore('/').trim()
                val bits = cidr.substringAfter('/', "").trim().toIntOrNull()
                if (host.isNotEmpty() && bits != null) runCatching { builder.addRoute(host, bits) }
            }
        }
        if (multiExit) {
            TunnelDebug.stage("второй выход: ${router.size} подсетей, сервер ${secondCfg?.endpoint?.render()}")
        }

        val pfd = try {
            builder.establish()
        } catch (e: Exception) {
            runCatching { socket.close() }
            fail("tun: ${e.javaClass.simpleName} ${e.message?.take(140)}", startId, myEpoch)
            return
        }
        if (pfd == null) {
            runCatching { socket.close() }
            fail("VpnService не выдал tun (обычно уже работает другой VPN)", startId, myEpoch)
            return
        }
        // Во владение tun и сокетом вступаем под тем же замком, под которым их закрывают: иначе
        // закрытие (onDestroy, «Отключить», новая попытка) могло пройти между проверкой и
        // присваиванием, и tun этой попытки остался бы работать без хозяина.
        val owned = synchronized(life) {
            if (alive()) {
                tun = pfd
                udpSocket = socket
                true
            } else {
                false
            }
        }
        if (!owned) {
            // tun уже выдан, но эта попытка устарела: закрываем, иначе интерфейс останется чужим.
            runCatching { pfd.close() }
            runCatching { socket.close() }
            abandon()
            return
        }
        val routes = SplitRoutes.prefixesOf(cfg.allowedIps)
        TunnelDebug.stage(
            "tun получен: ${routes.size} маршрутов (${if (isFullTunnel(cfg)) "весь трафик" else "раздельные"}), чтение по poll"
        )

        val handshake = CountDownLatch(1)

        // Со вторым выходом tun читает диспетчер, а каждый data plane читает свою очередь.
        // Без второго выхода — ровно прежнее поведение (прямые потоки), регрессии быть не должно.
        // С 1.10.31 второй выход по умолчанию идёт внутри WARP (см. planSecondExit), тогда своего
        // сокета у него нет: его датаграммы уходят пакетами в основной туннель.
        val secondPlan = if (multiExit && secondCfg != null) planSecondExit(cfg, secondCfg) else null
        val secondSock = if (secondPlan != null && !secondPlan.inner && secondCfg != null) {
            openSecondSocket(secondCfg, secondPlan.remote)
        } else {
            null
        }
        val secondReady = secondPlan != null && (secondPlan.inner || secondSock != null)
        // Экрану — честно: второй выход в этой сессии поднимается, не поднялся или не включён.
        TunnelState.second = when {
            !multiExit -> TunnelStatus.SECOND_OFF
            secondReady -> TunnelStatus.SECOND_STARTING
            else -> TunnelStatus.SECOND_FAILED
        }
        val rawIn = FileInputStream(pfd.fileDescriptor)
        // Ожидание данных в tun — poll() по его дескриптору вместо паузы 20 мс между пустыми
        // чтениями (см. DataPlane.tunReady и waitTunReadable).
        val tunFd = pfd.fileDescriptor
        val tunWait: (Long) -> Boolean = { ms -> waitTunReadable(tunFd, ms) }
        val rawOut = FileOutputStream(pfd.fileDescriptor)
        // Обход DPI в туннеле (с 1.10.49-beta3): YouTube, X и (с beta4) Discord напрямую с приёмом, если
        // «Проверить DPI» на этой сети нашла, что приём помогает, или человек выбрал стратегию сам. Ему нужен диспетчер tun — и без второго выхода (с одним
        // выходом). Обходить нечего — ровно прежний путь.
        val dpiOn = if (quietSession) null else runCatching { dpiSetup(exitRules) }
            .onFailure { TunnelDebug.problem("обход DPI: не включился (${it.javaClass.simpleName}: ${it.message?.take(80)})") }
            .getOrNull()
        val lanes = when {
            secondReady -> listOf(PacketQueueIn("основной"), PacketQueueIn("второй"))
            dpiOn != null -> listOf(PacketQueueIn("основной"))
            else -> emptyList()
        }
        val tunOut: OutputStream = if (lanes.isEmpty()) rawOut else SharedPacketOut(rawOut)
        val tunIn: InputStream = if (lanes.isEmpty()) rawIn else lanes[0]
        // Второй выход внутри WARP: его датаграммы — обычные пакеты основного туннеля (к адресу
        // своего сервера), а ответы сервера основной туннель отдаёт ему, а не в tun.
        val innerChannel = if (secondReady && secondPlan?.inner == true && secondPlan.local4 != null &&
            secondPlan.remote4 != null && secondCfg != null
        ) {
            InnerUdpChannel(
                inject = { packet -> lanes[0].offer(packet) },
                localIp = secondPlan.local4,
                remoteIp = secondPlan.remote4,
                remotePort = secondCfg.endpoint.port,
                maxPacket = cfg.mtu.coerceIn(576, 1420),
            )
        } else {
            null
        }
        // Ответы своего сервера забирает текущий канал второго выхода: при автопоиске Proton (с
        // 1.10.31) сервер меняется на ходу, а с ним — и канал.
        val innerRef = java.util.concurrent.atomic.AtomicReference<InnerUdpChannel?>(innerChannel)
        val primaryOut: OutputStream = if (innerChannel != null) {
            TapPacketOut(tunOut) { packet, len -> innerRef.get()?.accept(packet, len) ?: false }
        } else {
            tunOut
        }
        val splitter = if (lanes.isNotEmpty()) {
            TunDispatcher(rawIn, router, lanes, tunReady = tunWait) { line -> TunnelDebug.stage(line) }
        } else {
            null
        }
        if (splitter != null) {
            if (secondReady) {
                // Выход по приложениям (с 1.10.39): правило приложения перекрывает решение по адресу.
                splitter.appExits = runCatching { buildAppExits(exitRules, auto = !quietSession && serviceSettings().appAuto) }
                    .onFailure { TunnelDebug.stage("выход по приложениям: не включился (${it.javaClass.simpleName}) — у всех «Само»") }
                    .getOrNull()
            } else if (exitRules.values.any { it == AppExit.SECOND } && !quietSession) {
                // Диспетчер только ради обхода DPI: второго выхода нет — как и без диспетчера, всё через WARP
                // (таблицы выхода нет, и «только второй выход» ничего не придерживает).
                TunnelDebug.stage("выход по приложениям: второго выхода в этой сессии нет — приложения с «Второй выход» идут через WARP")
            }
            if (dpiOn != null) {
                splitter.tap = runCatching { buildDpiRelay(dpiOn, tunOut, splitter, cfg.mtu) }
                    .onFailure { TunnelDebug.problem("обход DPI: не включился (${it.javaClass.simpleName}: ${it.message?.take(80)})") }
                    .getOrNull()
            }
            this.dispatcher = splitter
            Thread(splitter, "warpscout-tun-split").apply { isDaemon = true; start() }
        } else if (exitRules.values.any { it == AppExit.SECOND } && !quietSession) {
            // Честно: «Второй выход» выбран, а второго выхода в этой сессии нет (решил человек 23.11:
            // такие приложения идут через WARP, а не остаются без интернета).
            TunnelDebug.stage("выход по приложениям: второго выхода в этой сессии нет — приложения с «Второй выход» идут через WARP")
        }

        // Канал — до data plane и под присмотром (с 1.10.42). С той минуты, как сокет стал «нашим»
        // (udpSocket = socket выше), его может закрыть closeAll() другого потока: новая смена сети,
        // «Отключить». Настройка закрытого сокета бросает «Socket is closed», и раньше это роняло
        // весь процесс туннеля (журнал 24.11, 08:23:22, поток warpscout-net-restart). Теперь
        // сменённая попытка молча уступает следующей, а несменённая честно сообщает об отказе.
        val udpChannel = try {
            SocketUdpChannel(socket, cfg.endpoint, 0)
        } catch (e: Exception) {
            synchronized(life) {
                if (tun === pfd) tun = null
                if (udpSocket === socket) udpSocket = null
                if (splitter != null && dispatcher === splitter) dispatcher = null
            }
            runCatching { splitter?.stop() }
            runCatching { secondSock?.close() }
            runCatching { socket.close() }
            runCatching { pfd.close() }
            if (alive()) {
                fail("сокет закрылся во время подъёма (${e.javaClass.simpleName}: ${e.message?.take(80).orEmpty()})", startId, myEpoch)
            } else {
                TunnelDebug.stage("подъём уступил следующей попытке: сокет уже закрыт")
                abandon()
            }
            return
        }
        val plane = DataPlane(
            // Таймаут приёма 0 — ждать пакет бесконечно. Было 1500 мс: в тишине поток просыпался
            // 40 раз в минуту только чтобы посмотреть на часы, и процесс не уходил в глубокий сон.
            // Остановка и смена сети будят его закрытием сокета, а не таймаутом.
            udp = udpChannel,
            tunInput = tunIn,
            tunOutput = primaryOut,
            config = cfg,
            // Пять инициаций с интервалом 400 мс: первая же обычно отвечает за доли секунды,
            // а если датаграмм потерялся — следующая уходит не через 1.5 с, а почти сразу.
            // На медленной связи (H+, H — с 1.10.40) — через 600 мс и ждём ещё 3 с после последней:
            // 5,4 с вместо 2,6 (столько же, сколько у второго выхода внутри WARP).
            settings = if (slowRadio()) {
                noteSlowRadio("рукопожатие жду до 5,4 с, а не 2,6")
                NetSettings(attempts = 5, timeoutMs = 3000, retryEveryMs = 600, junkPacketsBeforeHandshake = 1)
            } else {
                NetSettings(attempts = 5, timeoutMs = 1000, retryEveryMs = 400, junkPacketsBeforeHandshake = 1)
            },
            // Экран решает, как часто будить радио: с погашенным экраном и без трафика keepalive
            // уходит реже. Сам сервис про экран ничего не решает — только сообщает состояние.
            screenOn = {
                runCatching {
                    (getSystemService(Context.POWER_SERVICE) as PowerManager).isInteractive
                }.getOrDefault(true)
            },
            // Цифры расхода — в строку статистики журнала.
            vitals = { vitalsLine() },
            // Мало пакетов без ответа — не повод рвать, но повод проверить связь по-настоящему:
            // так ловится «подключено, а Telegram не работает», когда приложение шлёт редко.
            onSuspect = { reason ->
                if (myEpoch == epoch.get() && !destroyed) {
                    val sinceCheck = System.currentTimeMillis() - lastLinkCheckAt
                    if (sinceCheck >= LINK_SUSPECT_GAP_MS) {
                        startLinkCheck(myEpoch, "подозрение: $reason", 0L, reconnectOnFail = true)
                    }
                }
            },
            // Читает tun сам data plane — ему и ждать данных. Со вторым выходом tun читает
            // диспетчер (ему передано то же ожидание), а plane читает свою очередь.
            tunReady = if (lanes.isEmpty()) tunWait else null,
            // Сокет перестал отправлять — сеть ушла без уведомления от системы. Переподнимаем.
            onFatal = fatal@{ reason ->
                // Отчёт о смерти принимаем только от текущего plane и только один раз. DataPlane шлёт
                // его на каждые пять неудачных отправок: в журнале 20:06:48 «сокет не отправляет
                // пакеты» пришёл четыре раза за 200 мс, и каждый следующий заводил ещё один
                // переподъём поверх уже идущего.
                if (myEpoch != epoch.get() || destroyed) return@fatal
                if (fatalEpoch.getAndSet(myEpoch) == myEpoch) return@fatal
                // Дозор — гость в чужой сессии: если она оборвалась вскоре после его пробы, считаем
                // это его виной и выключаем до перезапуска сервиса. Дозор можно потерять, подключение — нет.
                // Но не тогда, когда виновата сеть: «сокет не отправляет пакеты» (ENETUNREACH) — это
                // ушедший Wi-Fi, а не проба. В журнале 20:06:48 дозор выключили именно так — зря.
                val sinceProbe = System.currentTimeMillis() - lastSentryProbeAt
                val networkFault = reason.contains("сокет не отправляет") || !hasUsableNetwork()
                if (lastSentryProbeAt > 0 && sinceProbe < 30_000 && !sentryBanned && !networkFault) {
                    sentryBanned = true
                    TunnelDebug.stage("дозор выключен: сессия оборвалась через ${sinceProbe / 1000} с после пробы")
                }
                // Сессия умерла (нет ответов/rekey не проходит) — говорим об этом прямо, а не
                // «после смены сети»: сеть могла и не меняться.
                restartAfterNetworkChange(reason, R.string.status_reconnect_silent)
            },
            // Подъём — по событию, а не по тексту журнала: правка формулировки в ядре раньше
            // молча лишала сервис сигнала «туннель работает».
            //
            // С 1.10.29 рукопожатие — ещё не «работает». Журнал 22.11 16:33: точка 188.114.97.1:500
            // отвечала на рукопожатие за 200 мс, а данных назад не шло ни байта («вверх 5542,
            // вниз 0»), и экран всё это время писал «Туннель работает». Теперь «работает», память
            // точки и дозор — только после ответа через туннель (см. [dataGate]).
            onTunnelUp = {
                handshake.countDown()
                // Рукопожатие есть — отложенные повторы и ожидание сети больше не нужны.
                cancelWaits()
            },
            log = { line ->
                // Статистика расхода — для журнала, в уведомлении ей не место.
                if (!line.startsWith(dev.warpscout.core.tunnel.DataPlane.STATS_PREFIX)) {
                    TunnelState.status = line
                }
                when {
                    // Пересогласование сессии — штатное событие раз в две минуты, но именно его
                    // отсутствие раньше выглядело как «туннель есть, интернета нет».
                    // «rekey не удался» и «rekey не проходит» — не успех: раньше они шли с галочкой.
                    line.startsWith("rekey не") -> TunnelDebug.stage(line)
                    line.startsWith("rekey") || line.contains("cookie") -> {
                        TunnelDebug.ok(line)
                    }
                    line.startsWith("попытка") -> {
                        TunnelDebug.noteAttempt(line)
                    }
                    // Сводку с числом инициаций и причиной даёт fail() ниже — эта строка ядра
                    // только фиксирует этап, иначе на один отказ в журнале приходится три ошибки.
                    line.startsWith("handshake не прошёл —") -> TunnelDebug.stage(line)
                    line.contains("не прошёл") -> TunnelDebug.error(line, "endpoint молчит или ключи не подошли")
                    else -> TunnelDebug.stage(line)
                }
                TunnelDebug.bytesUp = planeBytesUp()
            }
        )
        val planeThread = Thread {
            val ok = runCatching { plane.run() }.getOrDefault(false)
            // Пока этот data plane работал, попытку могли уже заменить следующей (перебор точек,
            // «Отключить → Подключить», смена сети). Тогда всё, что ниже, — не новость о живом
            // туннеле, а эхо прошлого: без этой проверки старая сессия снимала up/phase у новой и
            // могла её же и погасить через stopSelf — ровно то, что видно в журнале как «туннель
            // закрыт» сразу после успешного подъёма на другой точке.
            if (myEpoch != epoch.get()) {
                TunnelDebug.stage("старая сессия освободилась (эпоха $myEpoch) — не трогаю текущую")
                return@Thread
            }
            TunnelDebug.bytesUp = plane.bytesUp
            TunnelDebug.bytesDown = plane.bytesDown
            TunnelState.up = false
            TunnelState.phase = dev.warpscout.core.state.TunnelStatus.PHASE_IDLE
            when {
                stopped.get() -> TunnelState.status = "туннель остановлен"
                !ok -> {
                    val why = plane.failureReason ?: "endpoint молчит"
                    fail(
                        if (plane.handshakeOk) "туннель закрылся во время работы"
                        else "handshake не прошёл (инициаций: ${plane.attemptCount}): $why",
                        startId,
                        myEpoch
                    )
                }
                else -> {
                    TunnelState.status = "туннель закрыт (пира не стало)"
                    TunnelDebug.stage("туннель закрыт: прошло ${plane.bytesUp} байт вверх, ${plane.bytesDown} вниз")
                    // Сессия кончилась сама, а туннель по-прежнему нужен: это обрыв, а не повод
                    // выключиться насовсем. Раньше сервис здесь снимал себя — и больше не подключался.
                    if (wanted && !destroyed) {
                        restartAfterNetworkChange("сессия закрылась сама", R.string.status_reconnect_silent)
                    } else {
                        stopSelfSafely(startId)
                    }
                }
            }
        }.apply { isDaemon = true; name = "warpscout-vpn" }
        val committed = synchronized(life) {
            if (alive()) {
                this.plane = plane
                worker = planeThread
                planeThread.start()
                true
            } else {
                false
            }
        }
        if (!committed) {
            // Пока собирали data plane, попытку закрыли или сменили. Всё созданное здесь — наше, и
            // закрыть его должны мы: closeAll() другого потока этих объектов уже не увидит.
            runCatching { plane.stop() }
            synchronized(life) {
                if (tun === pfd) tun = null
                if (udpSocket === socket) udpSocket = null
                if (splitter != null && dispatcher === splitter) dispatcher = null
            }
            runCatching { splitter?.stop() }
            runCatching { secondSock?.close() }
            runCatching { socket.close() }
            runCatching { pfd.close() }
            abandon()
            return
        }

        // Второй выход запускаем сразу после основного: он независим (своя сессия, свой rekey),
        // и его падение не должно ронять туннель — трафик просто продолжит идти через WARP.
        //
        // С 1.10.31 серверов может быть несколько (автопоиск Proton Free): не ответил или сессия
        // умерла — берётся следующий. Очередь второго выхода на время смены не закрывается, и сайты
        // не уходят в WARP. Один сервер (свой конфиг) — как раньше, только с одним повтором.
        val lane2 = lanes.getOrNull(1)
        if (lane2 != null && secondCfg != null && secondPlan != null && (innerChannel != null || secondSock != null)) {
            val inner = innerChannel != null

            // Data plane одного сервера. Канал до него — внутри WARP или свой сокет; поверх —
            // AmneziaWG, если в конфиге свои типы пакетов (H1–H4) или добавки (S1–S4).
            fun buildSecond(plan: SecondPlan, candCfg: WarpConfig, label: String, base: UdpChannel): DataPlane {
                val udp2: UdpChannel = plan.awg?.let { params ->
                    AwgChannel(base, params, plan.localPublic, plan.peerPublic)
                } ?: base
                val nat = plan.nat
                var self: DataPlane? = null
                val dp = DataPlane(
                    udp = udp2,
                    // Адрес отправителя — из второго конфига: сервер принимает только тот адрес, что
                    // сам выдал. Пакет IPv6 при сервере без IPv6 не теряется молча — приложению сразу
                    // уходит отказ, и оно повторяет по IPv4. Читаем через «вид» очереди: остановка
                    // этого сервера не закрывает саму очередь (см. PacketQueueIn.view).
                    tunInput = NatPacketIn(lane2.view(), nat, plan.mss) { reject ->
                        runCatching { tunOut.write(reject, 0, reject.size) }
                    },
                    tunOutput = NatPacketOut(tunOut, nat, plan.mss),
                    config = candCfg,
                    // Внутри WARP ответ идёт дольше (через Cloudflare до своего сервера): попыток больше.
                    settings = if (inner) {
                        NetSettings(attempts = 5, timeoutMs = 2000, retryEveryMs = 800, junkPacketsBeforeHandshake = 1)
                    } else {
                        NetSettings(attempts = 3, timeoutMs = 1000, retryEveryMs = 500, junkPacketsBeforeHandshake = 1)
                    },
                    // Сессия умерла (rekey не проходит, ответов нет) — останавливаем её: перебор
                    // возьмёт этот же сервер ещё раз или следующий. Раньше она числилась «поднятой»
                    // до переподключения всего туннеля, а сайты второго выхода не открывались.
                    // Сервер принял рукопожатие, а данных не пропускает — следующий через 15 с, а не 45
                    // (с 1.10.44-beta3; журнал 24.11, 14:47: NL-FREE#125 молчал на 392 пакета).
                    freshStall = true,
                    onFatal = { reason ->
                        TunnelDebug.stage("второй выход ($label): $reason")
                        runCatching { self?.stop() }
                    },
                    log = { line ->
                        when {
                            line.contains("туннель поднят") -> {
                                TunnelDebug.ok("второй выход поднят: $label")
                                if (myEpoch == epoch.get()) TunnelState.second = TunnelStatus.SECOND_UP
                            }
                            line.contains("не прошёл") || line.contains("невозможен") ->
                                // С 1.10.26 метка времени в инициации — стандартная TAI64N. Свой сервер
                                // помнит самую большую метку от прошлых версий (она была записана не тем
                                // порядком байт) и, пока не перезапущен, новые инициации считает повтором.
                                TunnelDebug.error(
                                    "второй выход ($label): $line",
                                    if (secondList.size > 1) "беру следующий сервер"
                                    else "проверь второй конфиг и его endpoint; если сервер перестал отвечать сразу после " +
                                        "обновления до 1.10.26 — перезапусти на нём WireGuard/AmneziaWG"
                                )
                            else -> TunnelDebug.stage("второй: $line")
                        }
                    }
                )
                self = dp
                return dp
            }

            // Сколько неудач подряд терпим: при списке серверов — до восьми разных, при своём
            // конфиге — две попытки.
            val maxFails = if (secondList.size > 1) minOf(secondList.size, 8) else 2
            val secondThread = Thread {
                // Внутри WARP второму выходу нужен работающий основной туннель: его инициации
                // идут через WARP. Пока WARP не ответил, они пропали бы впустую.
                if (inner) {
                    // Ждём кусками и бросаем, как только попытку сменили (с 1.10.42). При переборе точек
                    // каждая сменённая попытка раньше ждала свои 30 с и потом писала «основной туннель
                    // не поднялся» — уже после «туннель поднят» следующей (журнал 24.11, 09:46:31 и
                    // 09:46:36), и по журналу выходило, будто второй выход сломан.
                    val waitUntil = System.currentTimeMillis() + 30_000L
                    var primaryUp = false
                    while (!primaryUp && alive() && System.currentTimeMillis() < waitUntil) {
                        primaryUp = try {
                            handshake.await(500, TimeUnit.MILLISECONDS)
                        } catch (e: InterruptedException) {
                            break
                        }
                    }
                    if (!primaryUp || !alive()) {
                        runCatching { lane2.close() }
                        // Сменённой попытке сказать нечего: второй выход поднимет следующая.
                        if (alive()) {
                            TunnelDebug.stage("второй выход не запущен: основной туннель не поднялся")
                            TunnelState.second = TunnelStatus.SECOND_FAILED
                        }
                        return@Thread
                    }
                }
                var index = 0
                var fails = 0
                var attempt = 0
                var totalUp = 0L
                var totalDown = 0L
                while (alive()) {
                    val (peerName, candCfg) = secondList[index % secondList.size]
                    val label = peerName.ifBlank { candCfg.endpoint.render() }
                    // Первая попытка — на том, что уже подготовлено; дальше канал каждый раз новый:
                    // остановленный data plane свой канал закрыл.
                    val plan: SecondPlan?
                    val base: UdpChannel?
                    if (attempt == 0) {
                        plan = secondPlan
                        // Сокет могли закрыть, пока шёл подъём (новая смена сети): тогда канала нет, и
                        // это обычная неудача сервера, а не падение процесса (с 1.10.42).
                        base = innerChannel ?: secondSock?.let { sock ->
                            runCatching { SocketUdpChannel(sock, candCfg.endpoint, 0) }.getOrNull()
                        }
                    } else {
                        plan = planSecondExit(cfg, candCfg)?.takeIf { !inner || (it.local4 != null && it.remote4 != null) }
                        base = when {
                            plan == null -> null
                            inner -> InnerUdpChannel(
                                inject = { packet -> lanes[0].offer(packet) },
                                localIp = plan.local4!!,
                                remoteIp = plan.remote4!!,
                                remotePort = candCfg.endpoint.port,
                                maxPacket = cfg.mtu.coerceIn(576, 1420),
                            ).also { innerRef.set(it) }
                            else -> openSecondSocket(candCfg, plan.remote)?.let { sock ->
                                val old = synchronized(life) {
                                    val prev = secondSocket
                                    secondSocket = sock
                                    prev
                                }
                                runCatching { old?.close() }
                                runCatching { SocketUdpChannel(sock, candCfg.endpoint, 0) }.getOrNull()
                            }
                        }
                    }
                    attempt++
                    var lived = 0L
                    var wasUp = false
                    var noData = false
                    if (plan != null && base != null) {
                        val dp = buildSecond(plan, candCfg, label, base)
                        val owns = synchronized(life) {
                            if (alive()) {
                                plane2 = dp
                                true
                            } else {
                                false
                            }
                        }
                        if (!owns) {
                            runCatching { dp.stop() }
                            break
                        }
                        TunnelState.secondPeer = peerName
                        val startedAt = System.currentTimeMillis()
                        runCatching { dp.run() }
                        lived = System.currentTimeMillis() - startedAt
                        wasUp = dp.handshakeOk
                        noData = dp.freshDead
                        totalUp += dp.bytesUp
                        totalDown += dp.bytesDown
                    }
                    if (!alive()) break
                    // Проработал хотя бы минуту — сервер живой, сессия просто кончилась: тот же сервер
                    // ещё раз. Не ответил или умер сразу — следующий.
                    if (wasUp && lived >= 60_000L) {
                        fails = 0
                    } else {
                        fails++
                        index++
                    }
                    if (fails >= maxFails) break
                    TunnelState.second = TunnelStatus.SECOND_STARTING
                    val next = secondList[index % secondList.size]
                    val nextLabel = next.first.ifBlank { next.second.endpoint.render() }
                    TunnelDebug.stage(
                        when {
                            noData -> "второй выход: $label не пропускает данные — подключаю $nextLabel"
                            wasUp -> "второй выход: сессия на $label закончилась — подключаю $nextLabel"
                            else -> "второй выход: $label не ответил — пробую $nextLabel"
                        }
                    )
                    try {
                        Thread.sleep(if (wasUp && !noData) 2_000L else 500L)
                    } catch (e: InterruptedException) {
                        break
                    }
                }
                // Очередь закрываем: диспетчер увидит это и вернёт подсети в основной туннель.
                runCatching { lane2.close() }
                if (alive()) TunnelState.second = TunnelStatus.SECOND_FAILED
                TunnelDebug.stage(
                    "второй выход остановлен: прошло $totalUp вверх / $totalDown вниз" +
                        (if (fails >= maxFails) " — серверы не ответили, сайты второго выхода идут через WARP" else "")
                )
                // Приложения с «Второй выход» (с 1.10.39) — тоже через WARP, а не без интернета (решил человек 23.11).
                if (fails >= maxFails && alive()) {
                    val secondApps = exitRules.count { it.value == AppExit.SECOND }
                    if (secondApps > 0) {
                        TunnelDebug.stage("выход по приложениям: второй выход не поднят — приложения с «Второй выход» ($secondApps) идут через WARP")
                    }
                }
            }.apply { isDaemon = true; name = "warpscout-vpn-2" }
            val ownsSecond = synchronized(life) {
                if (alive()) {
                    secondSocket = secondSock
                    worker2 = secondThread
                    secondThread.start()
                    true
                } else {
                    false
                }
            }
            if (!ownsSecond) {
                runCatching { lane2.close() }
                runCatching { secondSock?.close() }
            }
        } else {
            runCatching { secondSock?.close() }
        }

        // Handshake ждём НЕ здесь (мы и так на отдельном потоке, а главному потоку делать нечего):
        // ждёт [dev.warpscout.app.VpnTunnelController.startAndAwait], опрашивая TunnelState.
        // Тут только страховка: если за 25 с туннель не поднялся — сами себя снимаем и объясняем почему.
        Thread {
            val waited = runCatching { handshake.await(25, TimeUnit.SECONDS) }.getOrDefault(false)
            // Попытку уже сменили — её сторожу сказать нечего. Раньше он всё равно писал
            // «устаревшая попытка: таймаут…» — по строке на каждую точку перебора.
            if (!waited && myEpoch == epoch.get() && !stopped.get() && !TunnelState.up) {
                fail("таймаут: за 25 с handshake не завершился", startId, myEpoch)
            } else if (waited && dataGate(cfg, runText, startId, myEpoch)) {
                // Данные ходят. Через полторы секунды после подъёма (приложения как раз начинают
                // переподключаться) проверяем ещё и настоящим запросом через маршруты телефона;
                // два провала подряд — точка не годится, переходим на следующую. Проверка идёт в
                // своём потоке, поэтому запускается раньше слежения за трафиком (оно ждёт до 8 с).
                startLinkCheck(myEpoch, "после подъёма", 1_500L, reconnectOnFail = true, autoSpeed = true)
                watchTraffic(startId, myEpoch)
            }
        }.apply { isDaemon = true; name = "warpscout-vpn-watch"; start() }
    }

    // ------------------------------------------------------------ проверка данных после рукопожатия

    /**
     * Рукопожатие прошло — идут ли данные, и не встают ли они через секунду? DNS-запросы внутри
     * сессии (мимо маршрутов телефона, см. DataPlane.sendDataProbe) по расписанию [DataGate]: две
     * ранние пробы и две поздние, окно 4 с. Любой пакет приложений вниз — тоже ответ.
     *
     * С 1.10.30 рабочим туннель считается, только если данные идут и через полторы секунды: сеть
     * человека пропускала рукопожатие и первые 60–200 байт, а дальше молчала (журнал 22.11,
     * 19:04:45 «данные идут: ответ за 82 мс» → через 28 с «нет ответа»), и сервис полчаса
     * объявлял «подключено» точкам, через которые ничего не шло.
     *
     * Итог записывается в память шума этой сети (см. NoiseMemory): «пошли и встали» без шума — и
     * следующая попытка пойдёт с маской. Точку без шума мёртвой не считаем: с маской она может
     * работать (та же 188.114.97.1:500 с tls-fixed держалась 12 часов).
     *
     * @return true — данные идут, туннель объявлен рабочим.
     */
    private fun dataGate(cfg: WarpConfig, text: String, startId: Int, myEpoch: Int): Boolean {
        val p = plane ?: return false
        fun current() = myEpoch == epoch.get() && !stopped.get() && !destroyed
        if (!current()) return false
        val began = System.currentTimeMillis()
        TunnelState.dataCheckAt = began
        TunnelState.status = "рукопожатие есть — проверяю, идут ли данные"
        val slow = slowRadio()
        val gate = if (slow) DataGate.forSlowNetwork() else DataGate()
        try {
            while (current()) {
                when (gate.step(System.currentTimeMillis() - began, p.probeReplies, p.bytesDown)) {
                    DataGate.Step.SEND_PROBE -> p.sendDataProbe()
                    DataGate.Step.WAIT -> Thread.sleep(40)
                    DataGate.Step.DONE -> break
                }
            }
        } catch (e: InterruptedException) {
            return false
        } finally {
            if (TunnelState.dataCheckAt == began) TunnelState.dataCheckAt = 0L
        }
        if (!current()) return false
        val verdict = gate.verdict ?: return false
        val ep = cfg.endpoint.render()
        val noise = JunkLibrary.nameOf(cfg.junk)
        val plain = cfg.junk.isEmpty
        val warp = isWarpPeer(cfg)
        val net = memoryNetKind()
        val kind = when (verdict) {
            DataGate.Verdict.FLOWING -> NoiseBook.WORKED
            DataGate.Verdict.FROZEN -> NoiseBook.FROZE
            DataGate.Verdict.NO_DATA -> NoiseBook.NO_DATA
        }
        // Свой сервер AmneziaWG в память шума не пишем: менять шум сами мы умеем только для WARP.
        // На медленной связи (с 1.10.40) — только «работал»: «встал» на H/H+ — чаще радио и очередь
        // в соте, чем фильтр, а память у мобильной сети общая с LTE: шум потом обходили бы и там.
        val blameNoise = warp && (!slow || verdict == DataGate.Verdict.FLOWING)
        if (blameNoise) runCatching { NoiseMemory.note(this, net, noise, kind, ep) }
        if (verdict == DataGate.Verdict.FLOWING) {
            val ms = p.probeReplyMs.takeIf { it >= 0L } ?: gate.firstMs.coerceAtLeast(0L)
            TunnelDebug.ok(
                if (p.probeReplies > 0) "данные идут: первый ответ через туннель за $ms мс, поздний тоже пришёл"
                else "данные идут: приложения получают ответы"
            )
            markTunnelUp(cfg, text, myEpoch)
            return true
        }
        val label = if (plain) "без шума" else "шум $noise"
        val reason = if (verdict == DataGate.Verdict.FROZEN) {
            "данные не идут через $ep ($label): пошли и встали — первый ответ за ${gate.firstMs} мс, " +
                "а через полторы секунды тишина"
        } else {
            "данные не идут через $ep ($label): рукопожатие есть, а за ${gate.windowMs / 1000.0} с " +
                "ни ответа через туннель, ни одного пакета вниз"
        }
        if (slow) noteSlowRadio("остановку данных шуму и точке не приписываю — пробую дальше")
        if (blameNoise) {
            val next = runCatching {
                NoiseMemory.replacement(this, net, noise, JunkLibrary.serviceOrder().map { it.name })
            }.getOrNull()
            if (next != null) TunnelDebug.stage("на этой сети шум $noise замерзает — следующая попытка с шумом $next")
        }
        // Точку — в мёртвые для этой сети и из памяти «работала здесь», но только с маской: без шума
        // виноват скорее сам чистый WireGuard, а не точка. На медленной связи — нет (см. выше).
        if (!plain && !slow) markDataDead(ep)
        fail(reason, startId, myEpoch)
        return false
    }

    /**
     * Записать в память шума этой сети итог для туннеля, который работает сейчас (текст —
     * [lastConfigText]). [onlyPlain] — только если он без шума. Свой сервер AmneziaWG не пишем.
     */
    private fun noteRunningNoise(kind: Char, onlyPlain: Boolean) {
        // На медленной связи (с 1.10.40) замерзание шуму не приписываем — см. dataGate.
        if (kind != NoiseBook.WORKED && slowRadio()) {
            noteSlowRadio("остановку данных шуму не приписываю")
            return
        }
        runCatching {
            val text = lastConfigText ?: return@runCatching
            val cfg = WgConf.toWarpConfig("WARP", text) ?: return@runCatching
            if (!isWarpPeer(cfg)) return@runCatching
            if (onlyPlain && !cfg.junk.isEmpty) return@runCatching
            val noise = JunkLibrary.nameOf(cfg.junk)
            NoiseMemory.note(this, memoryNetKind(), noise, kind, cfg.endpoint.render())
            if (kind != NoiseBook.WORKED) {
                val next = NoiseMemory.replacement(this, memoryNetKind(), noise, JunkLibrary.serviceOrder().map { it.name })
                if (next != null) TunnelDebug.stage("на этой сети шум $noise замерзает — следующий подъём с шумом $next")
            }
        }
    }

    /** Пир — Cloudflare WARP (а не свой сервер WireGuard/AmneziaWG). */
    private fun isWarpPeer(cfg: WarpConfig): Boolean =
        cfg.account.peerPublicB64.trim() == WarpDefaults.WARP_PEER_PUBLIC

    /**
     * Маршруты из снимка настроек вместо маршрутов конфига (с 1.10.33). null — менять нечего:
     * снимок от прежней версии (поля нет) или маршруты уже совпадают. Строка «маршруты: …» — при
     * каждом подъёме: по ней в журнале видно, в каком режиме поднялся туннель.
     */
    private fun routesFromSettings(cfg: WarpConfig): Pair<WarpConfig, String>? = runCatching {
        val s = serviceSettings()
        val wanted = SplitRoutes.prefixesOf(s.routes)
        if (wanted.isEmpty()) return@runCatching null
        if (s.routesNote.isNotBlank()) TunnelDebug.stage("маршруты: ${s.routesNote}")
        val had = SplitRoutes.prefixesOf(cfg.allowedIps)
        if (wanted == had) return@runCatching null
        val next = cfg.copy(allowedIps = wanted.joinToString(", "))
        TunnelDebug.stage("маршруты — нынешние из «Туннелирования» (${wanted.size}), а не из сохранённого конфига (${had.size})")
        next to WgConf.render(next)
    }.getOrNull()

    /**
     * Шум под текущую сеть: если шум конфига здесь замерзает (см. NoiseMemory), — конфиг с маской,
     * которая здесь работала или идёт следующей по [JunkLibrary.serviceOrder]. null — менять не нужно.
     *
     * Только для WARP: у своего сервера AmneziaWG шум — часть договорённости с сервером. H1–H4,
     * S1–S4 и прочие ключи AWG остаются как были: меняются только мусорные пакеты перед рукопожатием.
     */
    private fun noiseForNetwork(cfg: WarpConfig): Pair<WarpConfig, String>? = runCatching {
        if (!isWarpPeer(cfg)) return@runCatching null
        val net = memoryNetKind()
        if (net.isBlank()) return@runCatching null
        val current = JunkLibrary.nameOf(cfg.junk)
        val pick = NoiseMemory.replacement(this, net, current, JunkLibrary.serviceOrder().map { it.name })
            ?: return@runCatching null
        val lib = JunkLibrary.byName(pick) ?: return@runCatching null
        val old = cfg.junk.awg
        val awg = lib.awg.copy(
            h1 = old.h1, h2 = old.h2, h3 = old.h3, h4 = old.h4,
            s1 = old.s1, s2 = old.s2, s3 = old.s3, s4 = old.s4,
            extra = old.extra
        )
        val next = cfg.copy(junk = lib.copy(awg = awg))
        val text = WgConf.render(next)
        TunnelDebug.stage("на этой сети шум $current замерзает — подключаюсь к ${cfg.endpoint.render()} с шумом ${lib.name}")
        next to text
    }.getOrNull()

    /**
     * Туннель работает: данные через него идут. Всё, что раньше делалось сразу после рукопожатия, —
     * здесь: статус, память точки, сохранённый конфиг для перезагрузки, уведомление, дозор.
     */
    private fun markTunnelUp(cfg: WarpConfig, text: String, myEpoch: Int) {
        TunnelState.up = true
        TunnelState.phase = dev.warpscout.core.state.TunnelStatus.PHASE_UP
        // Туннель поднят — цикл перебора закончен, следующая авария начнёт новый. Раньше
        // счётчик сбрасывался только при переподъёме самим сервисом: после ручного
        // «Подключить» он оставался исчерпанным, и сервис больше не менял точку сам.
        rotationsSinceUp = 0
        // Проверочный подъём подбора (quiet) — ещё не выбор точки (с 1.10.34). Журнал 23.11: такие
        // подъёмы записывались как «работающая точка», и после подбора туннель пошёл на
        // 8.39.214.6:928 (через неё данные не шли, 0/8), а не на победителя 8.34.70.3:8854.
        if (!quietSession) {
            // Память «на такой сети работает такая точка»: следующая смена сети начнётся
            // сразу с неё, без неудачной попытки на адресе из другой сети.
            runCatching {
                EndpointMemory.remember(this, memoryNetKind(), cfg.endpoint.render())
            }
            // Ровно этот текст и поднимется после перезагрузки, обновления или перезапуска
            // системой: точка в нём та, что работает сейчас (см. TunnelLastConfig).
            runCatching { TunnelLastConfig.save(this, text) }
        }
        TunnelDebug.ok(
            "туннель поднят: ${cfg.endpoint.render()}" +
                if (quietSession) " (проверка подбора — точку не запоминаю)" else ""
        )
        TunnelState.status = getString(R.string.notif_active, cfg.endpoint.render())
        postNotification(getString(R.string.notif_active, cfg.endpoint.render()))
        // Тихая проверка соседних точек: сессию не трогает, очередь держит свежей. Проверке подбора
        // она не нужна — её сессия живёт секунды.
        if (!quietSession) startSentry(cfg, myEpoch)
    }

    /**
     * Точка пропускает рукопожатие, но не данные. Для перебора на этой сети она мертва (как «порт
     * закрыт»), а запись «на этой сети работала она» стираем: иначе каждый переподъём начинался бы
     * с неё (журнал 22.11: три переподключения подряд на 188.114.97.1:500 и ни одного на следующую).
     */
    private fun markDataDead(endpoint: String) {
        if (endpoint.isBlank()) return
        sentryMarkDead(endpoint)
        runCatching { EndpointMemory.forget(this, memoryNetKind(), endpoint) }
    }

    /** Причина отказа — «рукопожатие есть, данных нет» или «пошли и встали» (см. [dataGate]). */
    private fun isDataDead(reason: String?): Boolean = reason.orEmpty().contains("данные не идут")

    /**
     * Отказ был без шума (чистый WireGuard): точку за него мёртвой не считаем — следующая попытка
     * пойдёт с маской, и с ней точка может работать.
     */
    private fun isPlainNoise(reason: String?): Boolean = reason.orEmpty().contains("(без шума)")

    /**
     * «Туннель поднят, а интернета нет» — отдельный диагноз: if up, но счётчики нулевые, значит
     * маршруты не совпали (split-tunnel) или пира не шлёт трафик. Молча это оставлять нельзя.
     */
    private fun watchTraffic(startId: Int, myEpoch: Int) {
        val deadline = System.currentTimeMillis() + 8000
        while (System.currentTimeMillis() < deadline && !stopped.get() && myEpoch == epoch.get()) {
            val p = plane
            // «Трафик пошёл» — только когда что-то пришло ВНИЗ. Раньше хватало байт вверх, и в
            // журнале стояло «✓ трафик пошёл: вверх 5542, вниз 0 байт» — галочка при мёртвой точке.
            if (p != null && p.bytesDown > 0) {
                TunnelDebug.ok("трафик пошёл: вверх ${p.bytesUp}, вниз ${p.bytesDown} байт")
                TunnelDebug.bytesUp = p.bytesUp
                TunnelDebug.bytesDown = p.bytesDown
                return
            }
            Thread.sleep(500)
        }
        if (!stopped.get() && TunnelState.up && myEpoch == epoch.get()) {
            val p = plane ?: return
            TunnelDebug.bytesUp = p.bytesUp
            TunnelDebug.bytesDown = p.bytesDown
            if (p.bytesUp == 0L && p.bytesDown == 0L) {
                TunnelDebug.error(
                    "туннель поднят, но ноль пакетов за 8 с",
                    "проверь AllowedIPs: в split-tunnel через WARP идут только перечисленные сети"
                )
                postNotification(getString(R.string.notif_no_traffic))
            } else if (p.bytesDown == 0L) {
                // Сама точка проверена ответом через туннель (см. dataGate), а приложениям за 8 с
                // ничего не пришло: решит проверка связи — она уже идёт.
                TunnelDebug.stage("приложения отправили ${p.bytesUp} байт, ответов им пока нет — жду проверку связи")
            }
        }
    }

    // ------------------------------------------------------------ проверка связи
    //
    // «Подключено» раньше значило «handshake прошёл». Этого мало: в журнале 00:58–01:21 handshake
    // проходил каждый раз, а данные назад не шли («трафик пошёл: вверх 4768, вниз 0 байт»), и
    // экран всё это время показывал «подключено». Сторож «сессия молчит» ловит такое только при
    // 50 пакетах за 45 с, а Telegram, потерявший связь, столько не шлёт. Поэтому теперь после
    // подъёма, по подозрению из data plane и при открытии экрана сервис проверяет связь настоящим
    // запросом через туннель: Cloudflare по IP (заодно видно, через WARP ли ушёл запрос, и откуда
    // виден выход) и TCP-соединение с сервером Telegram. Два провала подряд — переподключение.

    /**
     * Когда последний раз проверяли связь. По подозрению проверяем не чаще раза в
     * [LINK_SUSPECT_GAP_MS]: приложение может часами слать пакеты в никуда, и будить радио
     * проверкой на каждый такой поток незачем.
     */
    @Volatile
    private var lastLinkCheckAt = 0L
    private val LINK_SUSPECT_GAP_MS = 2 * 60_000L

    /** Когда последний раз переподнимали туннель из-за «трафик идёт мимо» (с 1.10.44-beta1). */
    @Volatile
    private var bypassHealAt = 0L

    /** Последний удачный замер после подъёма: когда, на какой точке и сети (с 1.10.44-beta1, см. UP_SPEED_GAP_MS). */
    @Volatile
    private var upSpeedAt = 0L

    @Volatile
    private var upSpeedKey = ""

    /** Проверка уже идёт — вторую параллельно не запускаем. */
    private val linkCheckBusy = java.util.concurrent.atomic.AtomicBoolean(false)

    /** Серверы Telegram (DC2 и DC1, порт 443): для проверки хватает TCP-соединения. */
    private val TELEGRAM_DCS = listOf("149.154.167.51", "149.154.175.53")

    /** Итог одной проверки связи. */
    private data class LinkResult(
        val web: Int,
        val webMs: Int,
        val exit: String,
        val tg: Int,
        val tgMs: Int,
        val webNote: String,
    )

    private fun linkAlive(myEpoch: Int): Boolean =
        myEpoch == epoch.get() && !stopped.get() && !destroyed && TunnelState.up

    /**
     * Проверить связь в своём потоке. [reconnectOnFail] — если и повторная проверка не получила
     * ответа, сессия мертва: переподнимаем туннель тем же путём, что и после обрыва (с его
     * лимитами — бесконечного цикла переподключений не будет).
     */
    private fun startLinkCheck(
        myEpoch: Int,
        reason: String,
        delayMs: Long,
        reconnectOnFail: Boolean,
        autoSpeed: Boolean = false,
    ) {
        if (!linkCheckBusy.compareAndSet(false, true)) return
        val thread = Thread({
            try {
                if (delayMs > 0L) Thread.sleep(delayMs)
                if (!linkAlive(myEpoch)) return@Thread
                var result = runLinkCheck()
                if (result.web == TunnelStatus.LINK_FAIL && linkAlive(myEpoch)) {
                    // Одна потеря — ещё не диагноз: первый запрос после подъёма иногда ждёт
                    // маршрута. Повторяем через 4 секунды (на медленной связи — через 6) и только потом решаем.
                    Thread.sleep(if (slowRadio()) 6_000L else 4_000L)
                    if (!linkAlive(myEpoch)) return@Thread
                    result = runLinkCheck()
                }
                if (!linkAlive(myEpoch)) return@Thread
                TunnelState.setLink(System.currentTimeMillis(), result.web, result.webMs, result.tg, result.tgMs, result.exit)
                reportLink(reason, result)
                // Трафик идёт мимо туннеля (с 1.10.44-beta1). Журнал 24.11, 13:38–13:41: после подбора туннель
                // «работал» (rekey проходили), а проверка трижды писала «ответ пришёл мимо WARP» и «Telegram не
                // отвечает» — три минуты всё шло мимо, пока человек не нажал «Сохранить и применить».
                // Переподнимаем сами, не чаще раза в 15 минут — по кругу не пойдём.
                if (!quietSession && wanted && linkAlive(myEpoch) && result.web == TunnelStatus.LINK_BYPASS &&
                    result.webNote == BYPASS_WARP_NOTE && result.tg == TunnelStatus.LINK_FAIL
                ) {
                    val now = System.currentTimeMillis()
                    if (bypassHealAt <= 0L || now - bypassHealAt !in 0 until BYPASS_HEAL_GAP_MS) {
                        bypassHealAt = now
                        restartAfterNetworkChange(
                            "трафик идёт мимо туннеля (ответ пришёл мимо WARP, Telegram не отвечает)",
                            R.string.status_reconnect_silent
                        )
                        return@Thread
                    }
                    TunnelDebug.stage("трафик снова мимо туннеля — переподнимал меньше 15 минут назад, жду")
                }
                // Площадка выхода (с 1.10.34): в память — по ней перебор ставит выход за рубежом
                // раньше московского. Выход за рубежом — Telegram снова через WARP; на второй выход
                // его с 1.10.36 переключает только ответ человека (см. checkTelegramMedia).
                val site = if (result.web == TunnelStatus.LINK_OK) ExitSite.fromSummary(result.exit) else ""
                if (site.isNotEmpty()) {
                    TunnelState.endpoint.takeIf { it.isNotBlank() }?.let { ep ->
                        runCatching { SiteMemory.note(this, memoryNetKind(), ep, site, live = !quietSession) }
                    }
                    if (!quietSession) {
                        runCatching { applyTelegramRoute(site) }
                        // Строка в журнал — когда площадка сменилась, а не на каждую проверку связи
                        // (она идёт при каждом открытии экрана).
                        if (site != siteSaid) {
                            siteSaid = site
                            if (ExitSite.isRussian(site)) {
                                TunnelDebug.stage(
                                    "выход WARP через ${ExitSite.describe(site)}: там медиа Telegram и часть сайтов режут фильтры" +
                                        (if (tgViaSecond) " — Telegram идёт через второй выход" else "")
                                )
                            }
                        }
                    }
                }
                if (!quietSession && result.web == TunnelStatus.LINK_OK && result.tg == TunnelStatus.LINK_OK &&
                    linkAlive(myEpoch) && tgMediaDue(site)
                ) {
                    runCatching { checkTelegramMedia(myEpoch, site) }
                }
                // Автовыбор выхода для приложений (эксперимент, с 1.10.43): замер — в своём потоке.
                if (!quietSession && result.web == TunnelStatus.LINK_OK && linkAlive(myEpoch)) {
                    runCatching { appAutoAfterLink(myEpoch, site) }
                }
                if (!linkAlive(myEpoch)) return@Thread
                val settings = serviceSettings()
                if (result.web == TunnelStatus.LINK_FAIL && reconnectOnFail && wanted && linkAlive(myEpoch) && quietSession) {
                    // Проверочный подъём подбора точку не меняет: «связи нет» — это и есть ответ
                    // проверки, а переключение подменило бы проверяемую точку другой (с 1.10.30).
                    TunnelDebug.stage("проверка в подборе: связи через точку нет — точку не меняю, это итог проверки")
                } else if (result.web == TunnelStatus.LINK_FAIL && reconnectOnFail && wanted && linkAlive(myEpoch)) {
                    if (settings.linkReconnect) {
                        switchAfterDeadLink()
                    } else {
                        TunnelDebug.stage("переподключение по проверке связи выключено в настройках — туннель не трогаю")
                    }
                } else if (result.web != TunnelStatus.LINK_FAIL && autoSpeed && settings.speedAuto && !quietSession) {
                    // Связь есть — заодно проверим, что данные не встают через пару десятков
                    // килобайт («заморозка»), и покажем примерную скорость. На медленной связи (с
                    // 1.10.40) — нет: полмегабайта на 0,3–1 Мбит/с — это 5–15 с занятого канала ровно
                    // тогда, когда приложения переподключаются, а «встал» там чаще радио, чем фильтр.
                    if (slowRadio()) {
                        noteSlowRadio("замер скорости после подъёма пропускаю — он занял бы весь канал")
                    } else if (upSpeedRecent()) {
                        // С 1.10.44-beta1: журнал 24.11 — 44 замера по 512 КБ за 4 часа, почти все после
                        // переподъёмов из-за смены сети, ровно когда Telegram и остальные переподключаются.
                        TunnelDebug.stage(
                            "замер скорости после подъёма пропускаю: на этой точке и сети он прошёл " +
                                "${(System.currentTimeMillis() - upSpeedAt) / 60_000} мин назад"
                        )
                    } else {
                        startSpeedTest(myEpoch, "после подъёма", full = false, delayMs = 400L)
                    }
                }
            } catch (e: InterruptedException) {
                // штатная остановка вместе с сервисом
            } catch (e: Throwable) {
                runCatching {
                    TunnelDebug.stage("проверка связи не удалась: ${e.javaClass.simpleName} ${e.message.orEmpty().take(80)}")
                }
            } finally {
                linkCheckBusy.set(false)
            }
        }, "warpscout-link")
        thread.isDaemon = true
        thread.priority = Thread.MIN_PRIORITY
        thread.start()
    }

    /**
     * Одна проверка. Сокеты обычные (без protect), то есть идут через сам туннель. Если адрес не
     * входит в маршруты туннеля (раздельные маршруты, «только выбранные приложения»), проверка про
     * туннель ничего не скажет — так и помечаем, а не объявляем туннель мёртвым.
     */
    private fun runLinkCheck(): LinkResult {
        lastLinkCheckAt = System.currentTimeMillis()
        // Маршруты tun вместе с адресами DNS (с 1.10.35, см. tunRoutesOf).
        val routes = currentRoutes()
        // С 1.10.28 сам WarpScout входит в туннель и в режиме «только выбранные» (см.
        // applyAppSplit) — мимо идут только адреса вне маршрутов.
        fun routed(ip: String): Boolean = routedIp(routes, ip)

        var web = TunnelStatus.LINK_FAIL
        var webMs = -1
        var exit = ""
        var webNote = ""
        if (!routed("1.1.1.1")) {
            web = TunnelStatus.LINK_BYPASS
            webNote = "адрес проверки не в маршрутах туннеля"
        } else {
            val t0 = android.os.SystemClock.elapsedRealtime()
            // На медленной связи (H+, H — с 1.10.40) ответ под нагрузкой идёт секундами: ждём 10 с, а не 5.
            val slow = slowRadio()
            val body = runCatching { httpGetSmall(dev.warpscout.core.net.CfTrace.URL_BY_IP, if (slow) 10_000 else 5_000) }
            val trace = dev.warpscout.core.net.CfTrace.parse(body.getOrNull())
            if (trace != null) {
                webMs = (android.os.SystemClock.elapsedRealtime() - t0).toInt()
                exit = trace.summary()
                web = if (trace.viaWarp) TunnelStatus.LINK_OK else TunnelStatus.LINK_BYPASS
                if (!trace.viaWarp) webNote = BYPASS_WARP_NOTE
            } else {
                webNote = body.exceptionOrNull()
                    ?.let { "${it.javaClass.simpleName}: ${it.message.orEmpty().take(60)}" }
                    ?: "ответ не похож на Cloudflare"
            }
        }

        var tg = TunnelStatus.LINK_FAIL
        var tgMs = -1
        val tgRouted = TELEGRAM_DCS.filter { routed(it) }
        if (tgRouted.isEmpty()) {
            tg = TunnelStatus.LINK_BYPASS
        } else {
            for (host in tgRouted) {
                val t0 = android.os.SystemClock.elapsedRealtime()
                val ok = runCatching {
                    java.net.Socket().use { sock -> sock.connect(InetSocketAddress(host, 443), if (slowRadio()) 6_000 else 3_000) }
                }.isSuccess
                if (ok) {
                    tg = TunnelStatus.LINK_OK
                    tgMs = (android.os.SystemClock.elapsedRealtime() - t0).toInt()
                    break
                }
            }
        }
        return LinkResult(web, webMs, exit, tg, tgMs, webNote)
    }

    // ------------------------------------------------------------ Telegram при выходе через Россию
    //
    // Журнал 23.11: с 07:39 все точки выходили через московскую площадку Cloudflare (DME), и медиа
    // Telegram грузилось «через раз и рывками», а проверка связи писала «Telegram ✓»: соединение
    // открывалось, резали уже поток. С 1.10.34 Telegram при выходе через Россию сразу уходил во
    // второй выход — но в Москве его режут не всегда, а второй выход бывает медленнее: человек
    // написал, что через Москву было нормально, а через второй выход (Мексика) — «прямо тяжело».
    // С 1.10.36 решает человек (ответ 23.11): Telegram идёт через Москву; проверка медиа показала
    // «тормозит» — та же загрузка через второй выход; он заметно быстрее — вопрос с цифрами
    // «Переключить» / «Оставить», ответ — на сутки для этой сети (см. TelegramChoice). Переключили —
    // меряем оба пути; второй выход стал медленнее Москвы — Telegram сам возвращается через WARP.

    /** Telegram сейчас идёт через второй выход: подсети Telegram — в таблице второго выхода. */
    @Volatile
    private var tgViaSecond = false

    /**
     * Выбор человека для Telegram в его строке «Туннелирования» (с 1.10.39): AppExit.AUTO — как
     * раньше (Москва и вопрос), WARP — всегда через WARP, SECOND — всегда через второй выход. Выбран —
     * не спрашиваем и сами не переключаем: 23.11 Telegram застрял на втором выходе без медиа, и
     * вернуть его можно было, только выключив второй выход.
     */
    @Volatile
    private var tgFixed = AppExit.AUTO

    /** Выход по приложениям из настроек (с 1.10.39): пакет → «Всегда WARP» / «Второй выход». */
    private fun appExitRules(): Map<String, Int> =
        runCatching { AppExit.decodeAll(serviceSettings().appExits) }.getOrDefault(emptyMap())

    /** Выбор для Telegram: одинаковый у всех клиентов Telegram с правилом — он, иначе «Само». */
    private fun telegramFixed(rules: Map<String, Int>): Int {
        val chosen = rules.filterKeys { AppServices.serviceOf(it)?.title == "Telegram" }.values.toSet()
        return if (chosen.size == 1) chosen.first() else AppExit.AUTO
    }

    /**
     * Таблица выхода по приложениям на эту сессию (см. AppExitTable): пакеты → uid установленных
     * приложений. null — правил нет или Android старше 10: владельца соединения система сообщает VPN
     * только с Android 10 (ConnectivityManager.getConnectionOwnerUid). [auto] — включён автовыбор
     * выхода (эксперимент, с 1.10.43): таблица нужна и без ручных правил — автоправила ставит замер.
     */
    private fun buildAppExits(rules: Map<String, Int>, auto: Boolean = false): AppExitTable? {
        if (rules.isEmpty() && !auto) return null
        if (Build.VERSION.SDK_INT < 29) {
            TunnelDebug.stage(
                if (rules.isEmpty()) "автовыбор выхода: нужен Android 10 или новее — выключен"
                else "выход по приложениям: нужен Android 10 или новее — у всех приложений «Само»"
            )
            return null
        }
        val cm = getSystemService(android.net.ConnectivityManager::class.java) ?: return null
        val byUid = HashMap<Int, Int>()
        val names = HashMap<Int, String>()
        val missing = ArrayList<String>()
        // «Только второй выход» (с 1.10.44-beta1): TikTok с выходом «Второй выход» при упавшем втором
        // выходе не уходит в WARP — см. AppServices.strictSecond.
        val strict = HashSet<Int>()
        rules.forEach { (pkg, rule) ->
            val info = runCatching {
                @Suppress("DEPRECATION")
                packageManager.getApplicationInfo(pkg, 0)
            }.getOrNull()
            if (info == null) {
                missing += pkg
                return@forEach
            }
            byUid[info.uid] = AppExit.stronger(byUid[info.uid] ?: AppExit.AUTO, rule)
            names[info.uid] = runCatching { packageManager.getApplicationLabel(info).toString() }.getOrDefault(pkg)
            if (rule == AppExit.SECOND && dev.warpscout.core.lists.AppServices.strictSecond(pkg)) strict += info.uid
        }
        if (byUid.isEmpty() && !auto) {
            TunnelDebug.stage("выход по приложениям: выбранных приложений нет на телефоне (${missing.joinToString(", ")})")
            return null
        }
        if (byUid.isNotEmpty()) {
            TunnelDebug.stage(
                "выход по приложениям: " + byUid.entries.joinToString(", ") { (uid, rule) ->
                    "${names[uid]} — " + if (rule == AppExit.SECOND) "второй выход" else "WARP"
                } + (if (missing.isNotEmpty()) "; нет на телефоне: ${missing.joinToString(", ")}" else "")
            )
        }
        if (strict.isNotEmpty()) {
            TunnelDebug.stage(
                "выход по приложениям: ${strict.mapNotNull { names[it] }.sorted().joinToString(", ")} — только через второй " +
                    "выход: если он ляжет, приложение подождёт его, а через WARP не пойдёт (TikTok запоминает регион по адресу)"
            )
        }
        return AppExitTable(
            byUid,
            owner = { proto, local, remote ->
                if (Build.VERSION.SDK_INT >= 29) cm.getConnectionOwnerUid(proto, local, remote) else -1
            },
            names = names,
            log = { line -> TunnelDebug.stage(line) },
            strict = strict,
        )
    }

    // ------------------------------------------------ автовыбор выхода для приложений (эксперимент, с 1.10.43)
    // Для приложений с выходом «Само» сервис сравнивает их сервис через WARP и через второй выход
    // (AppAuto) и ведёт приложение туда, где сервис работает: автоправилом в таблице выхода, только
    // для новых соединений. Замер идёт своим соединением, закреплённым за выходом (TunDispatcher.pin):
    // по адресу назначения его направлять нельзя — тем же адресом пользуется само приложение, и его
    // живые соединения переехали бы на другой выход. Telegram — как раньше (checkTelegramMedia).

    /** Идёт замер — второй не запускаем. */
    private val appAutoBusy = java.util.concurrent.atomic.AtomicBoolean(false)

    /** Последний замер: когда, на какой сети и площадке выхода, и что решили (сервис → AppExit). */
    @Volatile
    private var appAutoAt = 0L

    @Volatile
    private var appAutoNet = ""

    @Volatile
    private var appAutoSite = ""

    @Volatile
    private var appAutoChoice: Map<String, Int> = emptyMap()

    /** Площадка выхода из последней удачной проверки связи — для замеров по таймеру. */
    @Volatile
    private var appAutoLastSite = ""

    /** Сессия, для которой уже идёт таймер замеров (-1 — ни для какой). */
    @Volatile
    private var appAutoTimerEpoch = -1

    /** Как часто таймер смотрит, не пора ли мерить снова, и сколько ждать перед замером. */
    private val APP_AUTO_TICK_MS = 5 * 60_000L
    private val APP_AUTO_SETTLE_MS = 15_000L

    /**
     * Приложения под автовыбором: сервис → (uid → название). Только те, что идут через туннель, с
     * выходом «Само» и с замером (см. AppAuto.covers): при «только выбранные» — выбранные, иначе —
     * известные пакеты сервисов, которые стоят на телефоне.
     */
    private fun appAutoTargets(settings: ServiceSettings): Map<String, Map<Int, String>> {
        val manual = AppExit.decodeAll(settings.appExits).keys
        val pkgs: Collection<String> = when (settings.appsMode) {
            ServiceSettings.APPS_ONLY -> settings.appsSelected
            else -> AppServices.SERVICES.flatMap { it.packages }
                .filter { settings.appsMode != ServiceSettings.APPS_EXCEPT || it !in settings.appsSelected }
        }
        val out = LinkedHashMap<String, LinkedHashMap<Int, String>>()
        for (pkg in pkgs) {
            if (pkg in manual) continue
            val service = AppServices.serviceOf(pkg) ?: continue
            if (!AppAuto.covers(service.title)) continue
            val info = runCatching {
                @Suppress("DEPRECATION")
                packageManager.getApplicationInfo(pkg, 0)
            }.getOrNull() ?: continue
            val name = runCatching { packageManager.getApplicationLabel(info).toString() }.getOrDefault(pkg)
            out.getOrPut(service.title) { LinkedHashMap() }[info.uid] = name
        }
        return out
    }

    /** Решения → автоправила таблицы этой сессии: uid приложений сервиса → «Второй выход». */
    private fun applyAppAuto(targets: Map<String, Map<Int, String>>, choice: Map<String, Int>) {
        val table = dispatcher?.appExits ?: return
        val rules = HashMap<Int, Int>()
        choice.forEach { (service, exit) ->
            if (exit == AppExit.SECOND) targets[service]?.keys?.forEach { uid -> rules[uid] = AppExit.SECOND }
        }
        table.setAuto(rules)
    }

    /** Итог для экрана — в файл: экран живёт в другом процессе. null — стереть. */
    private fun saveAppAutoStatus(status: AppAuto.Status?) {
        runCatching {
            val target = File(filesDir, AppAuto.STATUS_FILE)
            if (status == null) {
                target.delete()
                return@runCatching
            }
            val text = status.encode()
            val tmp = File(filesDir, AppAuto.STATUS_FILE + ".tmp")
            tmp.writeText(text)
            if (!tmp.renameTo(target)) {
                target.writeText(text)
                tmp.delete()
            }
        }
    }

    /**
     * После проверки связи (связь есть). Автовыбор выключен — снять автоправила и итог. Та же сеть и
     * площадка, решение свежее — поставить его новой сессии сразу, без замера. Пора мерить (и экран
     * включён, связь не медленная) — замер в своём потоке.
     */
    private fun appAutoAfterLink(myEpoch: Int, site: String) {
        val settings = serviceSettings()
        if (site.isNotEmpty()) appAutoLastSite = site
        val d = secondDispatcher
        if (settings.appAuto && d != null && d.appExits == null && Build.VERSION.SDK_INT >= 29) {
            // Включили, когда туннель уже шёл (а ручных правил нет): таблицы выхода по приложениям в
            // этой сессии нет — ставим её сейчас, на лету; без автоправил она ничего не меняет.
            d.appExits = runCatching { buildAppExits(appExitRules(), auto = true) }.getOrNull()
        }
        val table = d?.appExits
        if (!settings.appAuto) {
            if (table != null && table.autoRules().isNotEmpty()) {
                table.setAuto(emptyMap())
                TunnelDebug.stage("автовыбор выхода выключен — приложения снова идут как «Само»; идущие соединения доживают прежним путём")
            }
            if (appAutoAt > 0L || appAutoChoice.isNotEmpty()) {
                appAutoAt = 0L
                appAutoChoice = emptyMap()
                saveAppAutoStatus(null)
            }
            return
        }
        ensureAppAutoTimer(myEpoch)
        if (TunnelState.second != TunnelStatus.SECOND_UP && table != null && table.autoRules().isNotEmpty()) {
            // Второй выход лёг — новые соединения сразу через WARP (иначе ждали бы следующего замера),
            // а когда поднимется — замер заново.
            table.setAuto(emptyMap())
            appAutoAt = 0L
            TunnelDebug.stage("автовыбор выхода: второй выход не поднят — приложения снова идут через WARP; замерю, когда поднимется")
        }
        val net = memoryNetKind()
        val fresh = appAutoAt > 0L && net == appAutoNet && site == appAutoSite &&
            System.currentTimeMillis() - appAutoAt in 0 until AppAuto.GAP_MS
        if (fresh) {
            // Новая сессия (переподключение) — таблица новая и пустая: решение ставим сразу.
            if (table != null && table.autoRules().isEmpty() && appAutoChoice.values.any { it == AppExit.SECOND }) {
                applyAppAuto(appAutoTargets(settings), appAutoChoice)
            }
            return
        }
        if (!isScreenOn() || slowRadio()) return
        if (!appAutoBusy.compareAndSet(false, true)) return
        Thread({
            try {
                if (appAutoQuiet(myEpoch)) runAppAuto(myEpoch, site, net)
            } catch (e: InterruptedException) {
                // штатная остановка вместе с сервисом
            } catch (e: Throwable) {
                runCatching { TunnelDebug.stage("автовыбор выхода: замер не удался (${e.javaClass.simpleName} ${e.message.orEmpty().take(60)})") }
            } finally {
                appAutoBusy.set(false)
            }
        }, "warpscout-app-exit").apply { isDaemon = true; priority = Thread.MIN_PRIORITY }.start()
    }

    /**
     * Перед замером: пусть приложения переподключатся (после подъёма их соединения рвутся разом), а
     * проверка связи и замер скорости закончатся — иначе они делят канал с замером через WARP, и WARP
     * выглядит медленнее, чем есть. false — сессия кончилась, экран погас или связь медленная.
     */
    private fun appAutoQuiet(myEpoch: Int): Boolean {
        Thread.sleep(APP_AUTO_SETTLE_MS)
        val until = System.currentTimeMillis() + 90_000L
        while ((linkCheckBusy.get() || speedBusy.get()) && System.currentTimeMillis() < until) {
            if (!linkAlive(myEpoch)) return false
            Thread.sleep(1_000L)
        }
        return linkAlive(myEpoch) && isScreenOn() && !slowRadio() && serviceSettings().appAuto
    }

    /**
     * Таймер сессии: проверка связи идёт после подъёма, при открытии экрана и по подозрению, а экран
     * может гореть часами (видео). Раз в 5 минут смотрим, не пора ли мерить снова (30 минут прошло,
     * экран включён, связь есть); решает appAutoAfterLink. Кончается с сессией или выключением.
     */
    private fun ensureAppAutoTimer(myEpoch: Int) {
        if (appAutoTimerEpoch == myEpoch) return
        appAutoTimerEpoch = myEpoch
        Thread({
            try {
                while (true) {
                    Thread.sleep(APP_AUTO_TICK_MS)
                    if (myEpoch != epoch.get() || stopped.get() || destroyed) break
                    if (!serviceSettings().appAuto) break
                    if (!linkAlive(myEpoch) || TunnelState.linkWeb != TunnelStatus.LINK_OK) continue
                    runCatching { appAutoAfterLink(myEpoch, appAutoLastSite) }
                }
            } catch (e: InterruptedException) {
                // штатная остановка вместе с сервисом
            } finally {
                if (appAutoTimerEpoch == myEpoch) appAutoTimerEpoch = -1
            }
        }, "warpscout-app-exit-timer").apply { isDaemon = true; priority = Thread.MIN_PRIORITY }.start()
    }

    /** Один замер сервиса через выход [lane] (0 — WARP, 1 — второй выход): своё соединение, закреплённое за выходом. */
    private fun probeVia(d: TunDispatcher, probe: AppAuto.Probe, lane: Int, routes: ExitRouter?): AppAuto.Measure {
        val pinned = ArrayList<Triple<Int, String, Int>>()
        try {
            return AppAuto.fetch(
                probe,
                resolve = { host -> java.net.InetAddress.getAllByName(host).mapNotNull { it.hostAddress } },
                inTunnel = { ip -> routedIp(routes, ip) },
                opener = AppAuto.tlsOpener { localPort, ip, port ->
                    d.pin(localPort, ip, port, lane)
                    pinned += Triple(localPort, ip, port)
                },
            )
        } finally {
            pinned.forEach { (localPort, ip, port) -> d.unpin(localPort, ip, port) }
        }
    }

    /**
     * Замер: каждый сервис — через WARP и через второй выход, решение (AppAuto.decide), автоправила,
     * итог в файл и в журнал. Туннель переподнялся посреди — бросаем: замер был не про эту сессию.
     */
    private fun runAppAuto(myEpoch: Int, site: String, net: String) {
        val settings = serviceSettings()
        val label = secondLabel()
        // [settled] — итог на 30 минут (дальше мерить незачем); нет — попробовать при следующей
        // проверке связи: второй выход мог ещё подниматься.
        fun finish(status: AppAuto.Status, choice: Map<String, Int>, settled: Boolean = true) {
            if (settled) {
                appAutoAt = status.at
                appAutoNet = net
                appAutoSite = site
                appAutoChoice = choice
            }
            saveAppAutoStatus(status)
        }
        val now = System.currentTimeMillis()
        val d = secondDispatcher
        val table = d?.appExits
        if (d == null || TunnelState.second != TunnelStatus.SECOND_UP) {
            finish(
                AppAuto.Status(now, site, label, emptyList(), "второй выход сейчас не поднят (или выключен) — автовыбору не из чего выбирать"),
                emptyMap(), settled = false
            )
            return
        }
        if (table == null) {
            val old = Build.VERSION.SDK_INT < 29
            finish(
                AppAuto.Status(
                    now, site, label, emptyList(),
                    if (old) "выход по приложениям работает с Android 10 — автовыбор выключен"
                    else "выход по приложениям в этой сессии не включился — включится со следующего подключения"
                ),
                emptyMap(), settled = old
            )
            return
        }
        if (table.disabled) {
            finish(AppAuto.Status(now, site, label, emptyList(), "Android не называет владельцев соединений — автовыбор не работает"), emptyMap())
            return
        }
        val targets = appAutoTargets(settings)
        if (targets.isEmpty()) {
            table.setAuto(emptyMap())
            finish(
                AppAuto.Status(
                    now, site, label, emptyList(),
                    "нет приложений с выходом «Само», для которых есть замер (" + AppAuto.PROBES.joinToString(", ") { it.service } + ")"
                ),
                emptyMap()
            )
            return
        }
        val routes = currentRoutes()
        val rows = ArrayList<AppAuto.Row>()
        val choice = LinkedHashMap<String, Int>()
        for (service in targets.keys) {
            val probe = AppAuto.probeFor(service) ?: continue
            if (!linkAlive(myEpoch) || dispatcher !== d) return
            val warp = probeVia(d, probe, 0, routes)
            if (!linkAlive(myEpoch) || dispatcher !== d) return
            var second = probeVia(d, probe, 1, routes)
            if (!linkAlive(myEpoch) || dispatcher !== d) return
            // Второй выход упал посреди замера — пакеты шли через WARP, замер не про него.
            if (TunnelState.second != TunnelStatus.SECOND_UP) {
                second = second.copy(unknown = true, note = "второй выход упал во время замера")
            }
            val exit = AppAuto.decide(warp, second, appAutoChoice[service] ?: AppExit.AUTO)
            choice[service] = exit
            rows += AppAuto.Row(service, exit, warp, second, AppAuto.why(warp, second, exit))
        }
        val before = appAutoChoice
        applyAppAuto(targets, choice)
        finish(AppAuto.Status(System.currentTimeMillis(), site, label, rows), choice)
        TunnelDebug.stage(
            "автовыбор выхода: " + rows.joinToString("; ") { r ->
                "${r.service} — WARP ${AppAuto.describe(r.warp)}, второй выход ${AppAuto.describe(r.second)} → ${AppAuto.exitName(r.exit)}"
            }
        )
        rows.forEach { r ->
            if (r.exit == (before[r.service] ?: AppExit.AUTO)) return@forEach
            val apps = targets[r.service]?.values?.joinToString(", ").orEmpty().ifBlank { r.service }
            TunnelDebug.stage(
                if (r.exit == AppExit.SECOND) "автовыбор выхода: $apps — через $label (${r.why}); туда идут новые соединения, идущие не рвутся"
                else "автовыбор выхода: $apps — снова как «Само», через WARP (${r.why})"
            )
        }
    }

    /** Площадка, о которой в этой сессии уже написали в журнал. */
    @Volatile
    private var siteSaid = ""

    /** Когда и на какой площадке последний раз проверяли медиа Telegram. */
    @Volatile
    private var tgMediaCheckedAt = 0L

    @Volatile
    private var tgMediaCheckedSite = ""

    /** Медиа проверяем не чаще раза в 30 минут (256 КБ на проверку) — или сразу, если сменилась площадка. */
    private val TG_MEDIA_GAP_MS = 30 * 60_000L

    /** Повтор сравнения Telegram, когда второй выход не загрузил вовсе: через 3 мин, потом через 6 (с 1.10.44-beta3). */
    private val TG_RECHECK_MS = 3 * 60_000L
    private val TG_RECHECK_MAX = 2

    /**
     * Замер другим путём идёт сейчас: адреса замера — через второй выход ([probeViaSecond]) или мимо
     * него, через WARP. Остальной Telegram остаётся, где был: живые соединения при замере не
     * переезжают на другой выход (у него другой адрес отправителя — они бы оборвались).
     */
    private val probeHosts = java.util.concurrent.CopyOnWriteArraySet<String>()

    @Volatile
    private var probeViaSecond = false

    /** Таблицу второго выхода меняют несколько потоков (замер, ответ, обновление адресов) — по очереди. */
    private val routerLock = Any()

    /** Сеть, о которой задан вопрос (ответ с экрана приходит без сети). */
    @Volatile
    private var tgAskNet = ""

    /**
     * Подсети второго выхода из настроек плюс, если [withTelegram], подсети Telegram — те, что и так
     * идут в туннель по маршрутам [routes] (null — весь трафик). Выбор в «Туннелировании» не меняем:
     * если Telegram идёт мимо туннеля, площадка WARP его не касается.
     */
    private fun secondExitCidrs(withTelegram: Boolean, routes: ExitRouter? = currentRoutes()): List<String> {
        val base = ExitRouter.parse(serviceSettings().secondCidrs)
        if (!withTelegram) return base
        val tg = TelegramMedia.NETS_V4.filter { routedIp(routes, it.substringBefore('/')) }
        return (base + tg).distinct()
    }

    /** Таблица второго выхода сейчас: адреса из настроек, Telegram (если переключён) и адреса идущего замера. */
    private fun telegramRouter(): ExitRouter {
        val cidrs = secondExitCidrs(tgViaSecond)
        val hosts = probeHosts.toList()
        val list = when {
            hosts.isEmpty() -> cidrs
            probeViaSecond -> (cidrs + hosts.map { "$it/32" }).distinct()
            else -> SplitRoutes.excludeHosts(cidrs, hosts)
        }
        return ExitRouter.of(list)
    }

    /**
     * Начинать ли сессию с Telegram через второй выход (с 1.10.36 — только по ответу человека): на
     * этой сети меньше суток назад ответили «Переключить», а эта точка выходила через Россию.
     * Возвращает площадку; пусто — Telegram идёт через WARP, дальше решит проверка медиа.
     */
    private fun telegramSiteFor(cfg: WarpConfig): String = runCatching {
        // Выход Telegram выбран вручную (с 1.10.39) — ответ на вопрос не действует.
        if (tgFixed != AppExit.AUTO) return@runCatching ""
        if (!serviceSettings().tgSecond || !isWarpPeer(cfg)) return@runCatching ""
        val net = memoryNetKind()
        if (TelegramChoiceMemory.choiceOf(this, net) != TelegramChoice.SECOND) return@runCatching ""
        val site = SiteMemory.siteOf(this, net, cfg.endpoint.render())
        if (ExitSite.isRussian(site)) site else ""
    }.getOrDefault("")

    /**
     * Переключить Telegram на второй выход или вернуть через WARP — на лету, как при обновлении
     * адресов второго выхода (handleSecondRoutes): туннель не переподключается. [line] — в журнал.
     * false — второго выхода в этой сессии нет или Telegram уже идёт так.
     */
    private fun setTelegramViaSecond(want: Boolean, line: String): Boolean {
        val splitter = secondDispatcher ?: return false
        synchronized(routerLock) {
            if (want == tgViaSecond) return false
            tgViaSecond = want
            splitter.router = telegramRouter()
        }
        TunnelState.tgSecond = want
        TunnelDebug.stage(line)
        return true
    }

    /**
     * После проверки связи: выход WARP оказался за рубежом — Telegram, если шёл через второй выход,
     * снова напрямую через WARP (там его не режут), а вопрос, если ждал ответа, снимается. Сам на
     * второй выход не переключает (с 1.10.36): это решает человек, см. checkTelegramMedia.
     */
    private fun applyTelegramRoute(site: String) {
        val abroad = ExitSite.isAbroad(site)
        if (abroad && TunnelState.tgAskAt > 0L) clearTelegramAsk()
        // Выход Telegram выбран вручную (с 1.10.39): сами его не переключаем.
        if (tgFixed != AppExit.AUTO) return
        if (!tgViaSecond) return
        val back = when {
            !serviceSettings().tgSecond -> "Telegram: второй выход для Telegram выключен в «Автоматике» — снова напрямую через WARP"
            abroad -> "выход WARP за рубежом (${ExitSite.describe(site)}) — Telegram снова напрямую через WARP"
            else -> return
        }
        // Путь сменился — медиа проверим заново уже по новому пути.
        if (setTelegramViaSecond(false, back)) tgMediaCheckedAt = 0L
    }

    /**
     * Пора ли проверять медиа Telegram: давно не проверяли или сменилась площадка. При погашенном
     * экране — нет: Telegram сейчас никто не смотрит, а трафик и радио это стоит.
     */
    private fun tgMediaDue(site: String): Boolean {
        if (!isScreenOn()) return false
        // Загрузки по 256 КБ (и вторая — для сравнения) на медленной связи не делаем (с 1.10.40).
        if (slowRadio()) return false
        val now = System.currentTimeMillis()
        if (tgMediaCheckedAt <= 0L) return true
        if (site.isNotEmpty() && site != tgMediaCheckedSite) return true
        return now - tgMediaCheckedAt !in 0 until TG_MEDIA_GAP_MS
    }

    /**
     * Проверка медиа Telegram (см. TelegramMedia): вывод — в снимок и в журнал. С 1.10.36 — и
     * сравнение со вторым выходом (см. начало раздела).
     */
    private fun checkTelegramMedia(myEpoch: Int, site: String) {
        val routes = currentRoutes()
        val tgRouted = TelegramMedia.NETS_V4.any { cidr -> routedIp(routes, cidr.substringBefore('/')) }
        if (!tgRouted) return
        tgMediaCheckedAt = System.currentTimeMillis()
        tgMediaCheckedSite = site
        val secondUp = secondDispatcher != null && TunnelState.second == TunnelStatus.SECOND_UP
        if (tgViaSecond && secondUp && tgFixed == AppExit.AUTO) {
            checkBothWays(myEpoch, site)
            return
        }
        if (tgFixed != AppExit.AUTO) {
            // Выбрано вручную (с 1.10.39): проверяем путь, которым Telegram идёт, — без сравнения и вопросов.
            val r = runTelegramMedia()
            if (!linkAlive(myEpoch)) return
            TunnelState.setTgMedia(System.currentTimeMillis(), r.verdict, r.kbps)
            val via = when {
                tgViaSecond && secondUp -> " (через ${secondLabel()} — так выбрано)"
                tgViaSecond -> " (выбран второй выход, но он сейчас не поднят — через WARP)"
                else -> " (через WARP — так выбрано)"
            }
            reportTelegramMedia(r, via, site)
            // Telegram закреплён за WARP, WARP выходит через Россию, медиа не грузится (с 1.10.44-beta1):
            // журнал 24.11, 13:41 — так и было, а в журнале стояла обычная строка. Говорим уведомлением.
            if (tgFixed == AppExit.WARP && ExitSite.isRussian(site) && TelegramChoice.poor(r.verdict)) {
                runCatching { warnTelegramPinnedWarp(site, r) }
            }
            if (tgViaSecond && secondUp) runCatching { noteTelegramFar() }
            return
        }
        val r = runTelegramMedia()
        if (!linkAlive(myEpoch)) return
        TunnelState.setTgMedia(System.currentTimeMillis(), r.verdict, r.kbps)
        reportTelegramMedia(r, if (tgViaSecond) " (Telegram переключён на второй выход, но он сейчас не поднят)" else "", site)
        // Через Москву плохо — сравним со вторым выходом (с 1.10.36).
        if (!tgViaSecond && ExitSite.isRussian(site) && TelegramChoice.poor(r.verdict)) {
            runCatching { compareWithSecond(myEpoch, site, r) }
                .onFailure { TunnelDebug.stage("Telegram: сравнить со вторым выходом не вышло (${it.javaClass.simpleName})") }
        }
    }

    /** Строка о проверке медиа в журнал: «тормозит» — ошибкой, с подсказкой, что делать. */
    private fun reportTelegramMedia(r: TelegramMedia.Fetch, via: String, site: String) {
        val line = "проверка Telegram: " + TelegramMedia.describe(r.verdict, r.kbps, r.maxGapMs) + via +
            (if (r.note.isNotBlank()) " — ${r.note}" else "")
        when (r.verdict) {
            TelegramMedia.OK -> TunnelDebug.ok(line)
            TelegramMedia.SLOW, TelegramMedia.STALL -> TunnelDebug.error(line, tgMediaHint(site))
            // «Не грузится» при Telegram, закреплённом за WARP с выходом через Россию (с 1.10.44-beta1), —
            // тоже ошибка с подсказкой: само приложение Telegram оттуда не уведёт.
            TelegramMedia.FAIL ->
                if (tgFixed == AppExit.WARP && ExitSite.isRussian(site)) TunnelDebug.error(line, tgMediaHint(site))
                else TunnelDebug.stage(line)
            else -> TunnelDebug.stage(line)
        }
    }

    /** Когда последний раз предупреждали «Telegram закреплён за WARP, а медиа не грузится» (с 1.10.44-beta1). */
    @Volatile
    private var tgPinnedWarnAt = 0L

    /** Про далёкую страну второго выхода для Telegram — один раз за сессию (с 1.10.44-beta1). */
    @Volatile
    private var tgFarSaid = false

    /**
     * Telegram закреплён за WARP («Туннелирование», строка Telegram), а WARP выходит через Россию, и
     * медиа не грузится: уведомление раз в 6 часов. Сам выход не меняем — его выбрал человек.
     */
    private fun warnTelegramPinnedWarp(site: String, r: TelegramMedia.Fetch) {
        val now = System.currentTimeMillis()
        if (tgPinnedWarnAt > 0L && now - tgPinnedWarnAt in 0 until TG_PINNED_WARN_GAP_MS) return
        tgPinnedWarnAt = now
        val city = ExitSite.cityAcc(site).ifBlank { "Россию" }
        val result = TelegramChoice.short(r.verdict, r.kbps)
        TunnelDebug.stage("Telegram закреплён за WARP, а выход WARP — через $city: медиа $result — предупреждаю уведомлением")
        postTelegramNote(getString(R.string.tg_pinned_title), getString(R.string.tg_pinned_text, city, result))
    }

    /**
     * Telegram идёт через второй выход в далёкой стране (США, Канада, Мексика, Япония, Сингапур): серверы
     * Telegram у российских номеров — в Амстердаме (медиа — cdn4.telesco.pe, 149.154.164–167), и путь
     * Москва → Америка → Амстердам в разы длиннее, чем через Нидерланды. Журнал 24.11: второй выход США,
     * медиа 1,5–2,1 Мбит/с. Строка в журнал — раз за сессию; страну выбирает человек.
     */
    private fun noteTelegramFar() {
        if (tgFarSaid || !tgViaSecond) return
        val name = TunnelState.secondPeer
        val code = if (name.isBlank()) "" else ProtonFree.codeOf(name, "")
        if (code !in TG_FAR_COUNTRIES) return
        tgFarSaid = true
        TunnelDebug.stage(
            "Telegram идёт через ${secondLabel()}: его серверы — в Амстердаме, и путь Москва → " +
                "${dev.warpscout.app.SecondProton.countryName(this, code)} → Амстердам в разы длиннее; для Telegram страна " +
                "второго выхода «Нидерланды» (или «Любая — ближние первыми») обычно в 2–3 раза быстрее"
        )
    }

    /** Уведомление о Telegram без кнопок (с 1.10.44-beta1): канал вопросов, своё место — вопрос не затирается. */
    private fun postTelegramNote(title: String, text: String) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            notifyManager().createNotificationChannel(
                NotificationChannel(
                    TelegramChoiceMemory.ASK_CHANNEL, getString(R.string.tg_ask_channel), NotificationManager.IMPORTANCE_DEFAULT
                ).apply {
                    setSound(null, null)
                    enableVibration(false)
                }
            )
        }
        val open = android.app.PendingIntent.getActivity(
            this, 0,
            Intent(this, dev.warpscout.app.MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
            android.app.PendingIntent.FLAG_UPDATE_CURRENT or android.app.PendingIntent.FLAG_IMMUTABLE
        )
        val n = NotificationCompat.Builder(this, TelegramChoiceMemory.ASK_CHANNEL)
            .setContentTitle(title)
            .setContentText(text)
            .setStyle(NotificationCompat.BigTextStyle().bigText(text))
            .setSmallIcon(R.drawable.ic_tile_tunnel)
            .setPriority(NotificationCompat.PRIORITY_DEFAULT)
            .setOnlyAlertOnce(true)
            .setAutoCancel(true)
            .setTimeoutAfter(TG_PINNED_WARN_GAP_MS)
            .setContentIntent(open)
            .build()
        runCatching { notifyManager().notify(NOTIF_TG_NOTE_ID, n) }
    }

    /** Строка о замере для сравнения: «проверка Telegram через Москву (для сравнения): …». */
    private fun reportCompare(r: TelegramMedia.Fetch, via: String) {
        TunnelDebug.stage(
            "проверка Telegram через $via (для сравнения): " + TelegramMedia.describe(r.verdict, r.kbps, r.maxGapMs) +
                (if (r.note.isNotBlank()) " — ${r.note}" else "")
        )
    }

    /**
     * Telegram идёт через второй выход: меряем его путь (это и видит человек) и путь через WARP —
     * адрес замера на это время идёт мимо второго выхода. Второй выход стал медленнее Москвы —
     * Telegram возвращается через WARP. Ответ «Переключить» действует до конца суток: если Москва
     * снова затормозит, а второй выход окажется быстрее, Telegram переедет без вопроса.
     */
    private fun checkBothWays(myEpoch: Int, site: String) {
        val label = secondLabel()
        val second = runTelegramMedia()
        if (!linkAlive(myEpoch)) return
        TunnelState.setTgMedia(System.currentTimeMillis(), second.verdict, second.kbps)
        reportTelegramMedia(second, " (через $label)", site)
        runCatching { noteTelegramFar() }
        val warp = probeTelegram(viaSecond = false)
        if (!linkAlive(myEpoch) || !tgViaSecond) return
        val city = ExitSite.cityAcc(site).ifBlank { "WARP" }
        reportCompare(warp, city)
        if (TelegramChoice.secondWorse(warp.verdict, warp.kbps, second.verdict, second.kbps)) {
            val moved = setTelegramViaSecond(
                false,
                "Telegram: $label медленнее, чем через $city (${TelegramChoice.short(second.verdict, second.kbps)} против " +
                    "${TelegramChoice.short(warp.verdict, warp.kbps)}) — снова через WARP"
            )
            if (moved) TunnelState.setTgMedia(System.currentTimeMillis(), warp.verdict, warp.kbps)
        }
    }

    /**
     * Через Москву медиа тормозит — та же загрузка через второй выход (с 1.10.36). Заметно быстрее —
     * спрашиваем человека (а если на этой сети он уже ответил «Переключить», переключаем сразу).
     * Ответил «Оставить» или вопрос уже ждёт ответа — второй выход не меряем: трафик зря.
     */
    private fun compareWithSecond(myEpoch: Int, site: String, moscow: TelegramMedia.Fetch) {
        if (tgFixed != AppExit.AUTO) return
        if (!serviceSettings().tgSecond) return
        if (secondDispatcher == null || TunnelState.second != TunnelStatus.SECOND_UP) return
        val net = memoryNetKind()
        val choice = TelegramChoiceMemory.choiceOf(this, net)
        if (choice == TelegramChoice.STAY || choice == TelegramChoice.ASKED) return
        val label = secondLabel()
        val second = probeTelegram(viaSecond = true)
        if (!linkAlive(myEpoch) || tgViaSecond) return
        reportCompare(second, label)
        val city = ExitSite.cityAcc(site)
        val numbers = "через $city ${TelegramChoice.short(moscow.verdict, moscow.kbps)}, " +
            "через $label ${TelegramChoice.short(second.verdict, second.kbps)}"
        // Через второй выход не загрузилось вовсе — это не «не быстрее», а «сервер сейчас не пропускает
        // данные» (с 1.10.44-beta3). Журнал 24.11, 14:47: сравнение пришлось на умиравший NL-FREE#125, вывод
        // «оставляю через Москву» держался бы полчаса, хотя через минуту второй выход (Румыния) давал 3,4 Мбит/с.
        if (second.verdict == TelegramMedia.FAIL) {
            scheduleTelegramRecheck("Telegram: $numbers — второй выход сейчас не пропускает данные")
            return
        }
        tgRecheckCount = 0
        if (!TelegramChoice.secondHelps(moscow.verdict, moscow.kbps, second.verdict, second.kbps)) {
            TunnelDebug.stage("Telegram: $numbers — второй выход не быстрее, оставляю через $city")
            return
        }
        if (choice == TelegramChoice.SECOND) {
            val moved = setTelegramViaSecond(
                true,
                "Telegram: $numbers — переключаю на второй выход (ты ответил «Переключить», действует сутки)"
            )
            if (moved) TunnelState.setTgMedia(System.currentTimeMillis(), second.verdict, second.kbps)
            return
        }
        askTelegramSwitch(net, site, moscow, second, label)
        TunnelDebug.stage("Telegram: $numbers — спрашиваю, переключить ли (уведомление «Переключить» / «Оставить»)")
    }

    /** Сколько раз подряд сравнение Telegram откладывали из-за неработающего второго выхода (с 1.10.44-beta3). */
    @Volatile
    private var tgRecheckCount = 0

    /**
     * Сравнить Telegram со вторым выходом ещё раз — через 3 мин, потом через 6 (с 1.10.44-beta3): второй
     * выход к тому времени обычно уже на другом сервере. Дальше — как обычно, раз в 30 мин. Повтор идёт
     * через проверку связи: она сама решит, нужно ли ещё (экран, медленная связь, Telegram уже переключён).
     */
    private fun scheduleTelegramRecheck(line: String) {
        if (tgRecheckCount >= TG_RECHECK_MAX) {
            TunnelDebug.stage("$line; следующая проверка — как обычно, через 30 мин")
            return
        }
        tgRecheckCount++
        val delay = TG_RECHECK_MS * tgRecheckCount
        TunnelDebug.stage("$line — сравню ещё раз через ${delay / 60_000} мин")
        Thread {
            try {
                Thread.sleep(delay)
            } catch (e: InterruptedException) {
                return@Thread
            }
            if (!wanted || tgViaSecond) return@Thread
            // Проверка медиа — при ближайшей проверке связи; сейчас — если туннель тот же и жив.
            tgMediaCheckedAt = 0L
            val now = epoch.get()
            if (linkAlive(now)) startLinkCheck(now, "повторное сравнение Telegram", 0L, reconnectOnFail = false)
        }.apply { isDaemon = true; name = "warpscout-tg-recheck" }.start()
    }

    /** «второй выход (Нидерланды)» — страна по имени сервера Proton; свой сервер — просто «второй выход». */
    private fun secondLabel(): String {
        val name = TunnelState.secondPeer
        val code = if (name.isBlank()) "" else ProtonFree.codeOf(name, "")
        val known = code.length == 2 && code.all { it in 'A'..'Z' }
        return if (known) {
            getString(R.string.tg_second_country, dev.warpscout.app.SecondProton.countryName(this, code))
        } else {
            getString(R.string.tg_second_plain)
        }
    }

    /**
     * Задать вопрос: уведомление с цифрами и кнопками «Переключить» / «Оставить». Канал свой,
     * обычной важности: канал туннеля самый тихий, в нём вопрос никто бы не увидел. Ответа нет —
     * три часа не спрашиваем снова (TelegramChoice.ASKED), уведомление уходит само через то же время.
     */
    private fun askTelegramSwitch(net: String, site: String, moscow: TelegramMedia.Fetch, second: TelegramMedia.Fetch, label: String) {
        val city = ExitSite.cityAcc(site)
        val text = getString(
            R.string.tg_ask_text,
            city, TelegramChoice.short(moscow.verdict, moscow.kbps),
            label, TelegramChoice.short(second.verdict, second.kbps)
        )
        TelegramChoiceMemory.note(this, net, TelegramChoice.ASKED)
        tgAskNet = net
        TunnelState.setTgAsk(System.currentTimeMillis(), text)
        runCatching { postTelegramAsk(net, getString(R.string.tg_ask_title, city), text) }
            .onFailure { TunnelDebug.stage("Telegram: уведомление с вопросом не показалось (${it.javaClass.simpleName}) — спрошу на экране") }
    }

    private fun postTelegramAsk(net: String, title: String, text: String) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            notifyManager().createNotificationChannel(
                NotificationChannel(
                    TelegramChoiceMemory.ASK_CHANNEL, getString(R.string.tg_ask_channel), NotificationManager.IMPORTANCE_DEFAULT
                ).apply {
                    // Видно в строке состояния, но без звука и вибрации: вопрос не срочный.
                    setSound(null, null)
                    enableVibration(false)
                }
            )
        }
        fun answer(act: String, code: Int) = android.app.PendingIntent.getService(
            this, code,
            Intent(this, WarpVpnService::class.java).apply {
                action = act
                putExtra(EXTRA_NET, net)
            },
            android.app.PendingIntent.FLAG_UPDATE_CURRENT or android.app.PendingIntent.FLAG_IMMUTABLE
        )
        val open = android.app.PendingIntent.getActivity(
            this, 0,
            Intent(this, dev.warpscout.app.MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
            android.app.PendingIntent.FLAG_UPDATE_CURRENT or android.app.PendingIntent.FLAG_IMMUTABLE
        )
        val n = NotificationCompat.Builder(this, TelegramChoiceMemory.ASK_CHANNEL)
            .setContentTitle(title)
            .setContentText(text)
            .setStyle(NotificationCompat.BigTextStyle().bigText(text))
            // Лиса в щите, как у уведомлений подбора: пустой значок туннеля здесь не годится.
            .setSmallIcon(R.drawable.ic_tile_tunnel)
            .setPriority(NotificationCompat.PRIORITY_DEFAULT)
            .setOnlyAlertOnce(true)
            .setAutoCancel(true)
            .setTimeoutAfter(TelegramChoice.ASK_GAP_MS)
            .setContentIntent(open)
            .addAction(0, getString(R.string.tg_ask_switch), answer(ACTION_TG_SWITCH, 21))
            .addAction(0, getString(R.string.tg_ask_stay), answer(ACTION_TG_STAY, 22))
            .build()
        notifyManager().notify(NOTIF_ASK_ID, n)
    }

    /** Снять вопрос: уведомление и отметку в снимке (ответили, выход ушёл за рубеж, туннель выключили). */
    private fun clearTelegramAsk() {
        runCatching { notifyManager().cancel(NOTIF_ASK_ID) }
        if (TunnelState.tgAskAt != 0L || TunnelState.tgAsk.isNotEmpty()) TunnelState.setTgAsk(0L, "")
    }

    /**
     * Ответ на вопрос: запомнить на сутки для сети, о которой спрашивали; «Переключить» на той же
     * сети при работающем туннеле — сразу переключить Telegram (на лету).
     */
    private fun handleTelegramAnswer(intent: Intent, startId: Int) {
        val switch = intent.action == ACTION_TG_SWITCH
        val net = intent.getStringExtra(EXTRA_NET).orEmpty().ifBlank { tgAskNet }.ifBlank { memoryNetKind() }
        runCatching { TelegramChoiceMemory.note(this, net, if (switch) TelegramChoice.SECOND else TelegramChoice.STAY) }
        clearTelegramAsk()
        val running = plane != null && worker?.isAlive == true && TunnelState.up
        val here = running && net == memoryNetKind()
        when {
            tgFixed != AppExit.AUTO -> TunnelDebug.stage(
                "Telegram: ответ запомнен, но выход Telegram выбран в «Туннелировании» — по нему и идёт"
            )
            !switch -> TunnelDebug.stage("Telegram: ответ «Оставить» — идёт через выход WARP, сутки на этой сети не спрашиваю")
            !here -> TunnelDebug.stage("Telegram: ответ «Переключить» запомнен на сутки для этой сети — переключу, когда туннель будет на ней")
            else -> {
                val moved = setTelegramViaSecond(
                    true,
                    "Telegram: ответ «Переключить» — Telegram через ${secondLabel()} (на сутки для этой сети; " +
                        "станет медленнее Москвы — верну через WARP)"
                )
                if (!moved && !tgViaSecond) {
                    TunnelDebug.stage("Telegram: ответ «Переключить» запомнен — второго выхода в этой сессии нет, переключу при следующем подключении")
                }
            }
        }
        if (!running) idleStop(startId)
    }

    /** Что делать, если медиа Telegram тормозит: зависит от площадки и от того, где сейчас Telegram. */
    private fun tgMediaHint(site: String): String {
        val settings = serviceSettings()
        // Выход Telegram выбран вручную (с 1.10.39) — подсказка о том, как его поменять.
        if (tgFixed == AppExit.WARP) {
            return "Telegram всегда идёт через WARP — так выбрано в «Туннелировании»; если медиа тормозит, " +
                "поставь в строке Telegram «Само» или «Второй выход»"
        }
        if (tgFixed == AppExit.SECOND) {
            return "Telegram идёт через второй выход — так выбрано в «Туннелировании»; если медиа тормозит, " +
                "поставь в строке Telegram «WARP»"
        }
        if (!ExitSite.isRussian(site)) {
            return "связь с Telegram есть, медиа тормозит, а выход WARP — не в России: попробуй другую точку"
        }
        val city = ExitSite.cityAcc(site)
        if (tgViaSecond && TunnelState.second == TunnelStatus.SECOND_UP) {
            return "выход WARP через $city, Telegram идёт через второй выход — сравню с путём через $city и, если там быстрее, верну"
        }
        if (tgViaSecond) return "выход WARP через $city: второй выход сейчас не работает — Telegram идёт через WARP"
        val choice = TelegramChoiceMemory.choiceOf(this, memoryNetKind())
        val fix = when {
            !settings.tgSecond -> "включи «Telegram: предлагать второй выход» в «Автоматике» — приложение сравнит скорость и спросит"
            secondConfig() == null -> "включи второй выход — приложение сравнит скорость и предложит пустить Telegram через него"
            TunnelState.second != TunnelStatus.SECOND_UP -> "второй выход сейчас не поднят — сравнить не с чем"
            choice == TelegramChoice.STAY -> "ты ответил «Оставить» — сутки на этой сети Telegram идёт через $city"
            choice == TelegramChoice.ASKED -> "вопрос про второй выход уже задан — ответ в уведомлении"
            else -> "сравниваю со вторым выходом"
        }
        val wait = if (settings.abroadSearch) {
            "; точку с выходом за рубежом приложение поищет само — на зарядке с погашенным экраном"
        } else {
            ""
        }
        return "выход WARP через $city: $fix$wait"
    }

    /**
     * Загрузка начала APK Telegram с telegram.org через туннель (см. TelegramMedia.fetch): по IPv4,
     * как ходит сам Telegram, с проверкой, что сервер — в сетях Telegram. Сокет обычный, без protect:
     * идёт через туннель, а подсети Telegram — через второй выход, если они сейчас там.
     */
    private fun runTelegramMedia(): TelegramMedia.Fetch = TelegramMedia.fetch(
        resolve = { host -> java.net.InetAddress.getAllByName(host).mapNotNull { it.hostAddress } }
    )

    /**
     * Та же загрузка, но другим путём (с 1.10.36): [viaSecond] — через второй выход, иначе — через
     * WARP. Адрес, к которому идёт загрузка, на время замера ставится в таблицу второго выхода
     * отдельно (/32 или вырезом из подсетей Telegram); остальной Telegram остаётся, где был. Без
     * второго выхода в этой сессии или если Telegram и так идёт этим путём — обычная загрузка.
     */
    private fun probeTelegram(viaSecond: Boolean): TelegramMedia.Fetch {
        if (secondDispatcher == null || viaSecond == tgViaSecond) return runTelegramMedia()
        try {
            return TelegramMedia.fetch(resolve = { host ->
                val all = java.net.InetAddress.getAllByName(host).mapNotNull { it.hostAddress }
                // Тот же адрес, что выберет сама загрузка: первый IPv4 в сетях Telegram.
                val ip = all.map { it.trim() }.firstOrNull { TelegramMedia.isTelegramIp(it) }
                if (ip == null) {
                    all
                } else {
                    synchronized(routerLock) {
                        probeViaSecond = viaSecond
                        if (probeHosts.add(ip)) dispatcher?.router = telegramRouter()
                    }
                    listOf(ip)
                }
            })
        } finally {
            synchronized(routerLock) {
                if (probeHosts.isNotEmpty()) {
                    probeHosts.clear()
                    dispatcher?.router = telegramRouter()
                }
            }
        }
    }

    /** GET с коротким телом (trace — пара сотен байт). Без кешей и перенаправлений. */
    private fun httpGetSmall(url: String, timeoutMs: Int): String {
        val conn = java.net.URL(url).openConnection() as java.net.HttpURLConnection
        try {
            conn.connectTimeout = timeoutMs
            conn.readTimeout = timeoutMs
            conn.useCaches = false
            conn.instanceFollowRedirects = false
            conn.setRequestProperty("Cache-Control", "no-cache")
            conn.setRequestProperty("Connection", "close")
            val code = conn.responseCode
            if (code !in 200..299) throw java.io.IOException("HTTP $code")
            return conn.inputStream.use { input ->
                val buf = ByteArray(4096)
                var total = 0
                while (total < buf.size) {
                    val n = input.read(buf, total, buf.size - total)
                    if (n <= 0) break
                    total += n
                }
                String(buf, 0, total, Charsets.UTF_8)
            }
        } finally {
            runCatching { conn.disconnect() }
        }
    }

    /** Строка в журнал: что проверили и что из этого следует. */
    private fun reportLink(reason: String, r: LinkResult) {
        val web = when (r.web) {
            TunnelStatus.LINK_OK -> "интернет ✓ ${r.webMs} мс" + (if (r.exit.isNotBlank()) ", выход ${r.exit}" else "")
            TunnelStatus.LINK_BYPASS -> "интернет — мимо туннеля" + (if (r.webNote.isNotBlank()) " (${r.webNote})" else "")
            else -> "интернет ✗ нет ответа" + (if (r.webNote.isNotBlank()) " (${r.webNote})" else "")
        }
        val tg = when (r.tg) {
            // Это соединение с сервером Telegram, а не загрузка медиа (журнал 23.11: «Telegram ✓» при
            // медиа «рывками»). Медиа проверяет отдельная загрузка — строка «проверка Telegram: …».
            TunnelStatus.LINK_OK -> "Telegram: соединение ✓ ${r.tgMs} мс"
            TunnelStatus.LINK_BYPASS -> "Telegram — мимо туннеля"
            else -> "Telegram ✗ сервер не отвечает"
        }
        val line = "проверка связи ($reason): $web; $tg"
        when {
            r.web == TunnelStatus.LINK_FAIL ->
                TunnelDebug.error(line, "туннель поднят, но данные через него не ходят — переподключаю")
            // Интернет через туннель есть, а Telegram молчит: туннель тут ни при чём, рвать его незачем.
            r.tg == TunnelStatus.LINK_FAIL && r.web == TunnelStatus.LINK_OK ->
                TunnelDebug.stage("$line — интернет через туннель есть, не отвечает именно Telegram")
            else -> TunnelDebug.ok(line)
        }
    }

    /** Экран попросил проверить связь (открыли приложение). */
    private fun handleCheckRequest(startId: Int) {
        val running = plane != null && worker?.isAlive == true && TunnelState.up
        if (!running) {
            idleStop(startId)
            return
        }
        // Экран открывают часто — радио проверкой будим не чаще раза в 30 секунд.
        if (System.currentTimeMillis() - lastLinkCheckAt < 30_000L) return
        startLinkCheck(epoch.get(), "открыт экран", 0L, reconnectOnFail = true)
    }

    /**
     * Остановиться после служебной команды (проба, проверка), только если сервису и правда нечего
     * делать. Просто stopSelf(startId) здесь нельзя: сервис мог ждать медленного повтора или сети
     * (туннель нужен, но сейчас лежит) — служебная команда не должна это ожидание обрывать.
     */
    private fun idleStop(startId: Int) {
        if (!wanted && plane == null && !starting) runCatching { stopSelf(startId) }
    }

    // ------------------------------------------------------------ скорость через туннель
    //
    // Проверка связи отвечает на «ходят ли данные», но не на «сколько». А главное — она не видит
    // «заморозку»: оператор пропускает начало соединения и останавливает его после 16–20 КБ (так
    // режут Cloudflare в части российских сетей). Короткий trace проходит, экран честно пишет
    // «подключено», а видео стоит. Загрузка в сотни килобайт с проверкой, что тело дочитано до
    // конца, видит и это, и реальную скорость. Мерим обычным сокетом — то есть через сам туннель.

    /** Замер уже идёт — второй параллельно не запускаем. */
    private val speedBusy = java.util.concurrent.atomic.AtomicBoolean(false)

    /** Сколько автозамеров подряд «замёрзли» в этой сессии. */
    @Volatile
    private var freezeStreak = 0

    /** Подъём для проверки в подборе: автозамера не будет (см. EXTRA_QUIET). */
    @Volatile
    private var quietSession = false

    /** Адрес IPv4 в маршрутах туннеля (null — маршрутов не знаем, считаем «весь трафик»). */
    private fun routedIp(routes: ExitRouter?, ip: String): Boolean {
        if (routes == null) return true
        val bytes = runCatching { ip.split('.').map { it.toInt().toByte() }.toByteArray() }.getOrNull() ?: return false
        return bytes.size == 4 && routes.route(bytes) == 1
    }

    private fun currentRoutes(): ExitRouter? = lastConfigText
        ?.let { text -> runCatching { WgConf.toWarpConfig("WARP", text) }.getOrNull() }
        ?.let { cfg -> tunRoutesOf(cfg) }

    /**
     * Маршруты tun так, как их ставит [builderFor] (с 1.10.35): маршруты конфига плюс адреса DNS при
     * раздельных маршрутах. Раньше проверки смотрели только маршруты конфига: при «сайтах из списков»
     * адрес 1.1.1.1 в туннеле был (DNS идёт через туннель), а проверка связи писала «интернет — мимо
     * туннеля» и не видела, через какой город выходит WARP (журнал 23.11, 08:41–09:26).
     */
    private fun tunRoutesOf(cfg: WarpConfig): ExitRouter? = runCatching {
        ExitRouter.of(SplitRoutes.prefixesOf(tunRouteText(cfg, log = false)))
    }.getOrNull()

    /**
     * Маршруты tun строкой: маршруты конфига, а при раздельных — ещё адреса DNS (с 1.10.35) и сети
     * GitHub (с 1.10.40, [AllowLists.GITHUB_NETS]). Сети GitHub — ради обновлений WarpScout: без них при
     * «сайтах из списков» обновление качалось мимо туннеля, напрямую через оператора, где GitHub бывает
     * недоступен, — системная загрузка вставала, а приложение отвечало «уже скачивается» (жалоба на
     * 1.10.38). Системная загрузка Android берёт сеть приложения, которое её поставило (так в AOSP), —
     * туннель, если WarpScout в нём; но маршрута к GitHub в туннеле не было, и она шла мимо. Если на
     * каком-то телефоне она идёт мимо туннеля всегда — через 30 с без байта WarpScout качает сам, уже
     * через туннель (см. UpdateFlow).
     * [log] — писать ли в журнал (при подъёме — да, при проверках — нет); [v6] — у tun есть адрес IPv6
     * (без него IPv6-маршруты не ставятся, и в журнале их не считаем).
     */
    private fun tunRouteText(cfg: WarpConfig, log: Boolean, v6: Boolean = true): String {
        // Раздельные маршруты: адреса DNS — тоже в туннель (см. SplitRoutes.withDns). Иначе запросы
        // имён шли мимо туннеля, и подменённый оператором ответ уводил «сайт из списка» на чужой
        // адрес — маршрут к настоящему адресу уже не помогал.
        val withDns = if (runCatching { serviceSettings().dnsInTunnel }.getOrDefault(true)) {
            runCatching { SplitRoutes.withDns(cfg.allowedIps, cfg.dns) }.getOrDefault(cfg.allowedIps)
        } else {
            cfg.allowedIps
        }
        if (log && withDns != cfg.allowedIps) {
            val added = SplitRoutes.prefixesOf(withDns).size - SplitRoutes.prefixesOf(cfg.allowedIps).size
            TunnelDebug.stage("DNS через туннель: +$added маршрута к ${cfg.dns.joinToString(", ")}")
        }
        // При «весь трафик» добавлять нечего: GitHub и так в туннеле (SplitRoutes.withExtra это учитывает).
        val withGithub = runCatching { SplitRoutes.withExtra(withDns, AllowLists.GITHUB_NETS) }.getOrDefault(withDns)
        if (log && withGithub != withDns) {
            val had = SplitRoutes.prefixesOf(withDns).toHashSet()
            val added = SplitRoutes.prefixesOf(withGithub).count { it !in had && (v6 || !it.contains(':')) }
            if (added > 0) {
                TunnelDebug.stage("обновления WilyScout: сети GitHub в маршрутах туннеля (+$added) — обновление и списки сайтов качаются через туннель")
            }
        }
        return withGithub
    }

    /**
     * Замер в своём потоке. [full] — по нажатию (до 10 МБ / 6 с), иначе короткий (полмегабайта).
     * Короткий, «замёрзший» дважды подряд, — повод сменить точку (если это не выключено).
     */
    /** Точка и сеть — для «замер после подъёма недавно прошёл» (с 1.10.44-beta1). */
    private fun speedKey(): String = "${TunnelState.endpoint}|${memoryNetKind()}"

    /** Удачный замер после подъёма был меньше [UP_SPEED_GAP_MS] назад на той же точке и сети. */
    private fun upSpeedRecent(): Boolean {
        val at = upSpeedAt
        if (at <= 0L) return false
        val age = System.currentTimeMillis() - at
        return age in 0 until UP_SPEED_GAP_MS && upSpeedKey == speedKey()
    }

    private fun startSpeedTest(myEpoch: Int, reason: String, full: Boolean, delayMs: Long) {
        if (!speedBusy.compareAndSet(false, true)) return
        val thread = Thread({
            try {
                if (delayMs > 0L) Thread.sleep(delayMs)
                if (!linkAlive(myEpoch)) return@Thread
                TunnelState.setSpeedRunning(System.currentTimeMillis())
                var r = runSpeedTest(full)
                if (!full && r.state == SpeedTest.FROZEN && linkAlive(myEpoch)) {
                    // Одна остановка — ещё не диагноз (мог дёрнуться радиоканал): повтор через 5 с.
                    TunnelDebug.stage("замер скорости: ${r.note} — повторю через 5 с")
                    Thread.sleep(5_000L)
                    if (!linkAlive(myEpoch)) return@Thread
                    r = runSpeedTest(false)
                }
                if (!linkAlive(myEpoch)) return@Thread
                val state = when (r.state) {
                    SpeedTest.OK -> TunnelStatus.SPEED_OK
                    SpeedTest.FROZEN -> TunnelStatus.SPEED_FROZEN
                    SPEED_BYPASS_CODE -> TunnelStatus.SPEED_BYPASS
                    else -> TunnelStatus.SPEED_FAIL
                }
                TunnelState.setSpeed(System.currentTimeMillis(), state, r.kbps, r.ttfbMs, r.bytes, full)
                reportSpeed(reason, r, full)
                // Удачный замер после подъёма — на 10 минут хватит той же точке на той же сети (с 1.10.44-beta1).
                if (!full && reason == "после подъёма") {
                    if (state == TunnelStatus.SPEED_OK) {
                        upSpeedAt = System.currentTimeMillis()
                        upSpeedKey = speedKey()
                    } else {
                        upSpeedAt = 0L
                    }
                }
                if (state == TunnelStatus.SPEED_FROZEN && !full) {
                    freezeStreak += 1
                    val settings = serviceSettings()
                    if (settings.freezeReconnect && wanted && linkAlive(myEpoch)) {
                        switchAfterFreeze(r.note)
                    } else if (!settings.freezeReconnect) {
                        TunnelDebug.stage("смена точки при «заморозке» выключена в настройках — туннель не трогаю")
                    }
                } else if (state == TunnelStatus.SPEED_OK) {
                    freezeStreak = 0
                }
            } catch (e: InterruptedException) {
                // штатная остановка вместе с сервисом
            } catch (e: Throwable) {
                runCatching {
                    TunnelDebug.stage("замер скорости не удался: ${e.javaClass.simpleName} ${e.message.orEmpty().take(80)}")
                }
            } finally {
                if (TunnelState.speedRunningSince != 0L) TunnelState.setSpeedRunning(0L)
                speedBusy.set(false)
            }
        }, "warpscout-speed")
        thread.isDaemon = true
        thread.priority = Thread.MIN_PRIORITY
        thread.start()
    }

    /**
     * Одна загрузка через туннель плюс пинг (время TCP-соединения с 1.1.1.1:443 — один круг через
     * туннель). Пинг кладём в `ttfbMs` результата: экрану нужны два числа, а не заголовки HTTP.
     */
    private fun runSpeedTest(full: Boolean): SpeedTest.Result {
        val routes = currentRoutes()
        // Адрес замера (Cloudflare) должен идти через туннель. В раздельном режиме он может быть
        // вне маршрутов — тогда мерили бы обычный интернет и выдавали его за туннель.
        val speedIp = runCatching {
            java.net.InetAddress.getAllByName("speed.cloudflare.com")
                .filterIsInstance<java.net.Inet4Address>()
                .firstOrNull()?.hostAddress
        }.getOrNull()
        if (routes != null && speedIp != null && !routedIp(routes, speedIp)) {
            return SpeedTest.Result(SPEED_BYPASS_CODE, 0L, 0L, -1, note = "адрес замера не в маршрутах туннеля")
        }
        val ping = if (routedIp(routes, "1.1.1.1")) SpeedTest.tcpPing("1.1.1.1", 443, 3_000) else -1
        val bytes = if (full) SpeedTest.FULL_BYTES else SpeedTest.AUTO_BYTES
        val maxMs = if (full) SpeedTest.FULL_MS else 8_000L
        val r = SpeedTest.run(SpeedTest.cloudflareUrl(bytes), bytes, maxMs, stallMs = 4_000)
        return r.copy(ttfbMs = ping)
    }

    private fun reportSpeed(reason: String, r: SpeedTest.Result, full: Boolean) {
        val kind = if (full) "полный" else "короткий"
        val ping = if (r.ttfbMs >= 0) ", пинг ${r.ttfbMs} мс" else ""
        val line = "замер скорости ($reason, $kind): " + when (r.state) {
            SpeedTest.OK -> "${SpeedTest.human(r.kbps)} — ${r.bytes / 1024} КБ за ${r.ms} мс$ping"
            SpeedTest.FROZEN -> "загрузка встала: ${r.note}$ping"
            SPEED_BYPASS_CODE -> "не мерил — ${r.note}"
            else -> "не получилось: ${r.note}$ping"
        }
        when (r.state) {
            SpeedTest.FROZEN -> TunnelDebug.error(line, "похоже на «заморозку»: данные идут первые килобайты и встают")
            SpeedTest.OK -> TunnelDebug.ok(line)
            else -> TunnelDebug.stage(line)
        }
    }

    /**
     * Загрузка через туннель встала дважды подряд — точка «замерзает». Переходим на следующую из
     * перебора этой сети (резервная — первой). Не на что переходить — переподключаемся к той же:
     * новое соединение с другого порта иногда снимает «заморозку».
     */
    private fun switchAfterFreeze(why: String) {
        val oldPoint = currentEndpointLine().orEmpty()
        // Точку, на которой встала загрузка, на этой сети пока обходим (как дважды молчавшую).
        if (oldPoint.isNotEmpty()) sentryMarkDead(oldPoint)
        // И шум — в память сети (с 1.10.30): без шума одной заморозки хватает, чтобы следующий
        // подъём пошёл с маской; маске — двух разных точек (см. NoiseBook.frozen).
        noteRunningNoise(NoiseBook.FROZE, onlyPlain = false)
        failoverOrder = emptyList()
        rebuildFailoverOrder()
        val next = nextFailoverEndpoint()
        if (next != null && next.first != oldPoint) {
            lastConfigText = next.second
            // Чтобы переподъём не вернул «работавшую на этой сети» — ту самую замёрзшую точку.
            rotationsSinceUp += 1
            forceFastRetry = true
            TunnelDebug.stage("$oldPoint: загрузка встала ($why) — перехожу на ${next.first}")
            restartAfterNetworkChange("загрузка через туннель встала — переход на ${next.first}", R.string.status_reconnect_frozen)
        } else {
            TunnelDebug.stage("$oldPoint: загрузка встала ($why), других точек нет — переподключаюсь к ней же")
            restartAfterNetworkChange("загрузка через туннель встала", R.string.status_reconnect_frozen)
        }
    }

    /**
     * Проверка связи дважды не получила ответа через туннель: точка перестала пропускать данные.
     * Переходим на следующую из очереди этой сети. Раньше переподключались к той же точке (журнал
     * 22.11: 16:33:31, 16:34:00, 16:34:29 — три раза подряд 188.114.97.1:500), и до следующей
     * точки дело не доходило.
     */
    private fun switchAfterDeadLink() {
        val oldPoint = currentEndpointLine().orEmpty()
        // Не в «мёртвые» сразу: ответа нет и тогда, когда пропала вся сеть. Точка — кандидат в
        // мёртвые; мёртвой она станет, если поднимется следующая (см. commitCycleMarks).
        if (oldPoint.isNotEmpty()) {
            cycleTried.add(oldPoint)
            cycleSilent.add(oldPoint)
        }
        // Без шума «поднялся, а через полминуты тишина» — почерк DPI против WireGuard (журнал 22.11,
        // 19:04–19:10, шесть точек подряд): следующий подъём пойдёт с маской. С маской так же
        // выглядит и пропажа сети, поэтому её шум здесь не судим.
        noteRunningNoise(NoiseBook.FROZE, onlyPlain = true)
        failoverOrder = emptyList()
        rebuildFailoverOrder()
        val next = nextFailoverEndpoint()
        if (next != null && next.first != oldPoint) {
            lastConfigText = next.second
            // Чтобы переподъём не вернул «работавшую на этой сети» — ту самую точку без ответа.
            rotationsSinceUp += 1
            forceFastRetry = true
            TunnelDebug.stage("$oldPoint: через туннель нет ответа — перехожу на ${next.first}")
            restartAfterNetworkChange(
                "проверка связи: через туннель нет ответа — переход на ${next.first}",
                R.string.status_reconnect_silent
            )
        } else {
            TunnelDebug.stage("$oldPoint: через туннель нет ответа, других точек нет — переподключаюсь к ней же")
            restartAfterNetworkChange("проверка связи: через туннель нет ответа", R.string.status_reconnect_silent)
        }
    }

    /** Экран попросил замерить скорость (нажатие на «Скорость»). */
    /**
     * Адреса сайтов второго выхода обновились (раз в сутки, см. SecondRoutes в интерфейсе) —
     * меняем таблицу на лету, не переподключая туннель. Если второй выход сейчас не работает,
     * новые адреса просто подхватит следующее подключение.
     */
    private fun handleSecondRoutes(startId: Int) {
        val splitter = secondDispatcher
        val running = plane != null && worker?.isAlive == true && TunnelState.up
        if (!running) {
            idleStop(startId)
            return
        }
        if (splitter == null) {
            TunnelDebug.stage("адреса второго выхода обновлены — применятся при следующем подключении")
            return
        }
        // Через telegramRouter: Telegram (если переключён) и идущий замер остаются в таблице.
        val router = runCatching {
            synchronized(routerLock) { telegramRouter().also { if (!it.isEmpty) splitter.router = it } }
        }.getOrNull()
        if (router == null || router.isEmpty) return
        val split = lastConfigText?.let { text -> runCatching { WgConf.toWarpConfig("WARP", text) }.getOrNull() }
            ?.let { !isFullTunnel(it) } ?: false
        TunnelDebug.stage(
            "второй выход: адреса обновлены на лету — ${router.size} подсетей" +
                if (split) " (новые адреса вне маршрутов туннеля заработают после переподключения)" else ""
        )
    }

    // ------------------------------------------------------------ обход DPI в туннеле (с 1.10.49-beta3)
    // YouTube и X — напрямую через провайдера с приёмом ByeDPI, а не через WARP: соединения их приложений
    // к :443 туннель принимает сам (DpiRelay) и по имени сайта в первом сообщении TLS решает, куда их
    // вести. План — из «Проверить DPI» этой сети; напрямую не открылось — то же соединение через туннель.

    /** Обход на эту сессию: план сети, приложения (uid → сервис) и правила выхода по uid. */
    private class DpiSetup(
        val plan: DpiPlan,
        val apps: Map<Int, DpiRelay.App>,
        val network: String,
        val warpUids: Set<Int>,
    )

    /**
     * План обхода для текущей сети; выключен — пустой. С 1.10.49-beta4 — с выбором человека: общая
     * стратегия («по проверке сети» — план из «Проверить DPI» этой сети), выбор по сервисам и своя
     * строка ByeDPI.
     */
    private fun dpiPlanNow(settings: ServiceSettings = serviceSettings()): Pair<DpiPlan, String> {
        val net = dev.warpscout.app.NetIdentity.currentKey(this)
        if (!settings.dpiBypass) return DpiPlan.EMPTY to net
        val custom = DpiTrick.custom(settings.dpiCustom)
        val auto = DpiPlan.forNetwork(settings.dpiPlans, net, custom)
        return DpiPlan.effective(auto, settings.dpiStrategy, DpiPlan.parseOverrides(settings.dpiOverrides), custom) to net
    }

    /** Человек выбрал стратегию сам (не «по проверке сети») — общую или для какого-то сервиса. */
    private fun dpiChosen(settings: ServiceSettings): Boolean =
        settings.dpiStrategy != DpiPlan.AUTO || DpiPlan.parseOverrides(settings.dpiOverrides).values.any { it != DpiPlan.AUTO }

    /**
     * Нужен ли обход в этой сессии. null — нет: выключен, Android старше 10 (владельца соединения система
     * называет с 10-го), на этой сети проверка не нашла, что обходить, или нужных приложений нет.
     */
    private fun dpiSetup(exitRules: Map<String, Int>): DpiSetup? {
        val settings = serviceSettings()
        val (plan, net) = dpiPlanNow(settings)
        val label = dev.warpscout.app.DpiCheck.labelOf(this, net)
        if (!settings.dpiBypass) {
            if (settings.dpiPlans.isNotEmpty()) TunnelDebug.stage("обход DPI: выключен в настройках — YouTube, X и Discord идут как раньше")
            return null
        }
        if (plan.isEmpty) {
            if (settings.dpiPlans.isNotEmpty() || dpiChosen(settings)) {
                TunnelDebug.stage(
                    "обход DPI: для сети «$label» плана нет (" +
                        (if (dpiChosen(settings)) "выбрано «не обходить» или своя стратегия не задана" else "проверки не было или обходить нечего") +
                        ") — всё как раньше"
                )
            }
            return null
        }
        if (Build.VERSION.SDK_INT < 29) {
            TunnelDebug.stage("обход DPI: нужен Android 10 или новее — выключен")
            return null
        }
        // Приложения всех сервисов, а не только из плана: план меняется на лету (новая проверка).
        val apps = HashMap<Int, DpiRelay.App>()
        val names = ArrayList<String>()
        val outside = ArrayList<String>()
        val second = ArrayList<String>()
        val selected = settings.appsSelected.toSet()
        for (svc in DpiServices.ALL) {
            val covered = plan.coversService(svc.id)
            for (pkg in svc.packages) {
                if (pkg == packageName) continue
                val info = runCatching {
                    @Suppress("DEPRECATION")
                    packageManager.getApplicationInfo(pkg, 0)
                }.getOrNull() ?: continue
                val title = runCatching { packageManager.getApplicationLabel(info).toString() }.getOrDefault(pkg)
                if (exitRules[pkg] == AppExit.SECOND) {
                    if (covered) second += title
                    continue
                }
                val inTunnel = when (settings.appsMode) {
                    ServiceSettings.APPS_ONLY -> selected.isEmpty() || pkg in selected || pkg in exitRules.keys
                    ServiceSettings.APPS_EXCEPT -> pkg !in selected || pkg in exitRules.keys
                    else -> true
                }
                if (!inTunnel) {
                    if (covered) outside += title
                    continue
                }
                apps[info.uid] = DpiRelay.App(title, svc.id)
                if (covered) names += title
            }
        }
        if (outside.isNotEmpty()) {
            TunnelDebug.stage("обход DPI: ${outside.joinToString(", ")} — мимо туннеля (не отмечены в «Приложениях»), обход их не видит")
        }
        if (second.isNotEmpty()) {
            TunnelDebug.stage("обход DPI: ${second.joinToString(", ")} — «Второй выход», не трогаю")
        }
        if (names.isEmpty()) {
            TunnelDebug.stage("обход DPI: на сети «$label» план есть (${plan.describe()}), но приложений для него в туннеле нет")
            return null
        }
        val warpUids = HashSet<Int>()
        exitRules.forEach { (pkg, rule) ->
            if (rule != AppExit.WARP) return@forEach
            runCatching {
                @Suppress("DEPRECATION")
                packageManager.getApplicationInfo(pkg, 0).uid
            }.getOrNull()?.let { warpUids += it }
        }
        TunnelDebug.stage(
            "обход DPI: сеть «$label» — ${plan.describe()}: напрямую через провайдера, мимо WARP; приложения: " +
                "${names.joinToString(", ")}. Их QUIC закрываю — перейдут на TCP; другие сайты этих приложений и " +
                "всё, что напрямую не откроется, — через туннель, как раньше"
        )
        return DpiSetup(plan, apps, net, warpUids)
    }

    /** Свой конец TCP для обхода: сокеты мимо туннеля — с protect(), через туннель — обычные. */
    private fun buildDpiRelay(setup: DpiSetup, out: OutputStream, splitter: TunDispatcher, mtu: Int): DpiRelay {
        val cm = getSystemService(android.net.ConnectivityManager::class.java)
        val direct = object : DpiRelay.Connector {
            override fun connect(address: InetAddress, port: Int, timeoutMs: Int, uid: Int, bound: (Int) -> Unit): Socket {
                val s = Socket()
                try {
                    // Настройка создаёт дескриптор сокета: без него protect() защищать нечего.
                    s.tcpNoDelay = true
                    if (!protect(s)) throw java.io.IOException("protect() отказал")
                    s.connect(InetSocketAddress(address, port), timeoutMs)
                    return s
                } catch (e: Exception) {
                    runCatching { s.close() }
                    throw e
                }
            }
        }
        val tunnel = object : DpiRelay.Connector {
            override fun connect(address: InetAddress, port: Int, timeoutMs: Int, uid: Int, bound: (Int) -> Unit): Socket {
                val s = Socket()
                try {
                    s.tcpNoDelay = true
                    // Свой порт — до подключения: диспетчер не должен разобрать наш же SYN, а со вторым
                    // выходом соединение закрепляется за выходом приложения («Всегда WARP» — WARP).
                    s.bind(InetSocketAddress(0))
                    bound(s.localPort)
                    if (splitter.multiLane && address is Inet4Address) {
                        val lane = if (uid in setup.warpUids) 0 else splitter.router.route(address.address)
                        splitter.pin(s.localPort, address.hostAddress.orEmpty(), port, lane)
                    }
                    s.connect(InetSocketAddress(address, port), timeoutMs)
                    return s
                } catch (e: Exception) {
                    runCatching { s.close() }
                    throw e
                }
            }

            override fun release(localPort: Int, address: InetAddress, port: Int) {
                if (splitter.multiLane && address is Inet4Address) splitter.unpin(localPort, address.hostAddress.orEmpty(), port)
            }
        }
        return DpiRelay(
            tunOut = { p -> out.write(p, 0, p.size) },
            owner = { proto, local, remote ->
                if (Build.VERSION.SDK_INT >= 29 && cm != null) cm.getConnectionOwnerUid(proto, local, remote) else -1
            },
            apps = setup.apps,
            plan = setup.plan,
            direct = direct,
            tunnel = tunnel,
            ttl = dev.warpscout.app.DpiCheck.AndroidTtl,
            mtu = mtu.coerceIn(576, 1420),
            log = { line -> TunnelDebug.stage(line) },
            // Фейк (с 1.10.49-beta4): только если в плане есть приём с фейком и Android 9+.
            fake = dev.warpscout.app.DpiCheck.fakeSender(this),
        )
    }

    /**
     * План обхода или переключатель поменялись (новая «Проверить DPI», переключатель на экране). Обход в
     * сессии есть — план меняется на лету, для новых соединений. Нет, а план появился — переподключаемся:
     * обходу нужен диспетчер tun, и поставить его можно только при подъёме.
     */
    private fun handleDpiReload(startId: Int) {
        val running = plane != null && worker?.isAlive == true && TunnelState.up
        if (!running) {
            idleStop(startId)
            return
        }
        val relay = dispatcher?.tap as? DpiRelay
        val (plan, net) = dpiPlanNow()
        if (relay != null) {
            if (relay.plan != plan) {
                relay.plan = plan
                TunnelDebug.stage(
                    if (plan.isEmpty) "обход DPI: выключен — новые соединения YouTube, X и Discord идут через туннель"
                    else "обход DPI: план обновлён на лету — ${plan.describe()}"
                )
            }
            return
        }
        if (plan.isEmpty || quietSession) return
        TunnelDebug.stage(
            "обход DPI: для сети «${dev.warpscout.app.DpiCheck.labelOf(this, net)}» появился план (${plan.describe()}) — " +
                "переподключаюсь, чтобы включить"
        )
        restartAfterNetworkChange("включаю обход DPI", R.string.status_reconnect_silent)
    }

    private fun handleSpeedRequest(startId: Int) {
        val running = plane != null && worker?.isAlive == true && TunnelState.up
        if (!running) {
            idleStop(startId)
            return
        }
        startSpeedTest(epoch.get(), "по нажатию", full = true, delayMs = 0L)
    }

    // ------------------------------------------------------------ проба точки по просьбе экрана

    /**
     * Проверить точку, не трогая работающий туннель: та же проба, что у дозора (своим ключом, с
     * отдельного защищённого сокета, с внеочередным keepalive после). Ответ — в снимок состояния
     * (`TunnelStatus.probe`) с номером запроса.
     */
    private fun handleProbe(intent: Intent, startId: Int) {
        val id = intent.getLongExtra(EXTRA_PROBE_ID, 0L)
        val line = intent.getStringExtra(EXTRA_ENDPOINT).orEmpty().trim()
        val target = parseEndpoint(line)
        val cfg = lastConfigText?.let { text -> runCatching { WgConf.toWarpConfig("WARP", text) }.getOrNull() }
        val peer = cfg?.let { c -> runCatching { Crypto.unBase64(c.account.peerPublicB64) }.getOrNull() }
            ?.takeIf { it.size == 32 }
        val running = plane != null && worker?.isAlive == true && TunnelState.up
        if (target == null || cfg == null || peer == null || !running) {
            TunnelState.probe = "$id|$line|${TunnelStatus.PROBE_NONE}|-1"
            idleStop(startId)
            return
        }
        val myEpoch = epoch.get()
        val thread = Thread({
            val prober = WgProber(
                NetSettings(
                    attempts = 1,
                    timeoutMs = 1500,
                    betweenAttemptsMs = 0,
                    junkPacketsBeforeHandshake = 1,
                    udpFactory = protectedUdp()
                )
            )
            val (verdict, rtt) = runCatching { sentryProbe(prober, target, cfg, peer) }
                .getOrDefault(Verdict.ERROR to null)
            val code = when (verdict) {
                Verdict.HANDSHAKE_OK, Verdict.COOKIE_REPLY -> TunnelStatus.PROBE_OK
                Verdict.UDP_CLOSED -> TunnelStatus.PROBE_CLOSED
                Verdict.UDP_SILENT -> TunnelStatus.PROBE_SILENT
                else -> TunnelStatus.PROBE_NONE
            }
            // Итог — и в метки дозора: точка, проверенная по просьбе, тоже «проверена».
            if (myEpoch == epoch.get()) noteProbeResult(line, code)
            TunnelDebug.stage(
                "проверка точки перед переключением: $line " + when (code) {
                    TunnelStatus.PROBE_OK -> "✓ отвечает" + (rtt?.let { " за ${it.toLong()} мс" } ?: "")
                    TunnelStatus.PROBE_CLOSED -> "✗ порт закрыт — текущий туннель не трогаю"
                    TunnelStatus.PROBE_SILENT -> "✗ молчит — текущий туннель не трогаю"
                    else -> "? проверить не вышло (${verdict.name.lowercase()})"
                }
            )
            TunnelState.probe = "$id|$line|$code|${rtt?.toLong() ?: -1}"
        }, "warpscout-probe")
        thread.isDaemon = true
        thread.start()
    }

    /** Итог пробы по просьбе экрана — в метки дозора, как итог его собственного обхода. */
    private fun noteProbeResult(line: String, code: Int) {
        val key = "${memoryNetKind()}|$line"
        val before = sentryMarks[key] ?: SentryMark()
        val now = System.currentTimeMillis()
        when (code) {
            TunnelStatus.PROBE_OK -> sentryMarks[key] = SentryMark(okAt = now)
            TunnelStatus.PROBE_CLOSED -> sentryMarks[key] = SentryMark(okAt = before.okAt, fails = 2, failAt = now)
            TunnelStatus.PROBE_SILENT ->
                sentryMarks[key] = SentryMark(okAt = before.okAt, fails = before.fails + 1, failAt = now)
            else -> return
        }
        publishMarks()
    }

    /**
     * Метки дозора текущей сети — в снимок: интерфейс показывает их в списке лучших и в выборе
     * резервной точки, чтобы человек видел «молчит с 12:53» до нажатия, а не после.
     */
    private fun publishMarks() {
        val prefix = "${memoryNetKind()}|"
        TunnelState.marks = sentryMarks.entries
            .filter { it.key.startsWith(prefix) }
            .sortedBy { it.key }
            .joinToString(";") { (key, m) -> "${key.removePrefix(prefix)}|${m.okAt}|${m.fails}|${m.failAt}" }
    }

    // ------------------------------------------------------------ автоподъём

    /**
     * Текст для запуска без конфига: перезапуск системой (null), «Постоянный VPN» из настроек
     * Android, автоподъём после загрузки или обновления. null — поднимать не надо (или нечего).
     *
     * Правило то же, что везде: выключенный руками туннель сам не включается. Для «Постоянного
     * VPN» отдельной проверки «был ли включён» нет — его включил сам человек в настройках системы.
     */
    private fun autoStartText(intent: Intent?): String? {
        val action = intent?.action
        val why = when {
            intent == null -> "система перезапустила сервис"
            action == VpnService.SERVICE_INTERFACE -> "постоянный VPN (настройки Android)"
            action == ACTION_AUTOSTART -> intent?.getStringExtra(EXTRA_REASON) ?: "автоподъём"
            else -> return null
        }
        if (TunnelState.stoppedByUser) {
            TunnelDebug.stage("$why: туннель выключен вручную — сам не включаю, пока не нажмёшь «Включить»")
            return null
        }
        // Автоподъём после загрузки и обновления можно выключить в настройках. «Постоянный VPN»
        // и перезапуск системой — не про него: первое включил сам человек в настройках Android,
        // второе — восстановление после обрыва без его участия.
        if (action == ACTION_AUTOSTART && !runCatching { serviceSettings().autoStart }.getOrDefault(true)) {
            TunnelDebug.stage("$why: автоподъём выключен в настройках — сам не включаю")
            return null
        }
        val previous = bootSnapshot
        val wasOn = previous == null || previous.wanted || previous.up
        if (action != VpnService.SERVICE_INTERFACE && !wasOn) {
            TunnelDebug.stage("$why: туннель перед этим не был включён — не поднимаю")
            return null
        }
        // Файл пишет только удачный подъём; до первого такого (сразу после обновления) берём то,
        // чем туннель поднимался по кнопке. Процесс сервиса здесь свежий — настройки он читает с диска.
        val saved = TunnelLastConfig.load(this)
            ?: runCatching { dev.warpscout.app.Prefs(this).lastConfigText }.getOrNull()?.takeIf { it.contains("PrivateKey") }
        if (saved.isNullOrBlank()) {
            TunnelDebug.stage("$why: рабочей конфигурации ещё нет — открой приложение и нажми «Включить»")
            return null
        }
        TunnelDebug.stage("$why — поднимаю последнюю рабочую конфигурацию (${endpointOf(saved) ?: "точка не указана"})")
        return saved
    }

    // ------------------------------------------------------------ ожидание данных в tun

    /**
     * Ждать, пока в tun появятся данные: poll() по дескриптору, без пробуждений по таймеру.
     * true — можно читать. Закрытие tun будит ожидание, а предел [ms] страхует, если не разбудит.
     */
    private fun waitTunReadable(tunFd: java.io.FileDescriptor, ms: Long): Boolean = try {
        val pollFd = android.system.StructPollfd()
        pollFd.fd = tunFd
        pollFd.events = android.system.OsConstants.POLLIN.toShort()
        android.system.Os.poll(arrayOf(pollFd), ms.coerceIn(1L, 60_000L).toInt()) > 0 &&
            (pollFd.revents.toInt() and android.system.OsConstants.POLLIN) != 0
    } catch (e: android.system.ErrnoException) {
        false
    } catch (e: Exception) {
        false
    }

    /**
     * Настройки для подъёма туннеля. Читаются из файла-снимка, а не из SharedPreferences: у
     * каждого процесса своя копия настроек в памяти, и сервис мог бы поднимать туннель по
     * устаревшим значениям («поменял в настройках — туннель не заметил»).
     */
    private fun serviceSettings(): dev.warpscout.core.state.ServiceSettings =
        dev.warpscout.app.status.ServiceSettingsStore.read(this)
            ?: dev.warpscout.core.state.ServiceSettings()

    /**
     * Серверы второго выхода по порядку (с 1.10.31). Proton Free — список из настроек: ключ клиента
     * тот же, меняются ключ и адрес сервера (см. ProtonFree). Иначе — один сервер из конфига.
     * Имя пустое — свой сервер из конфига.
     */
    private fun secondCandidates(base: WarpConfig?): List<Pair<String, WarpConfig>> {
        if (base == null) return emptyList()
        val peers = serviceSettings().secondPeers.mapNotNull { ProtonFree.decode(it) }
        val list = peers.mapNotNull { srv ->
            runCatching {
                srv.name to base.copy(
                    endpoint = Endpoint(srv.ip, srv.port),
                    account = base.account.copy(peerPublicB64 = srv.publicKey),
                )
            }.getOrNull()
        }
        if (list.isNotEmpty()) {
            TunnelDebug.stage("второй выход: Proton Free, автопоиск — ${list.size} серверов, первый ${list.first().first}")
        }
        return list.ifEmpty { listOf("" to base) }
    }

    /** Конфиг второго выхода (null — выключен или пустой). */
    private fun secondConfig(): WarpConfig? {
        val settings = serviceSettings()
        if (!settings.secondExitOn) return null
        val text = settings.secondConf
        if (text.isBlank()) return null
        return runCatching { WgConf.toWarpConfig("второй выход", text) }.getOrNull()
    }

    /**
     * Как поднимать второй выход (с 1.10.31).
     *
     * [inner] — внутри основного туннеля (WARP): провайдер видит только WARP. [nat] — подмена
     * адреса отправителя на адрес из второго конфига (без неё обычный сервер WireGuard молча
     * отбрасывал наши пакеты: у них был адрес WARP). [awg] — параметры AmneziaWG, если сервер их ждёт.
     * [mss] — предел сегмента TCP для туннеля в туннеле (0 — не урезать).
     */
    private class SecondPlan(
        val inner: Boolean,
        val remote: java.net.InetAddress?,
        val local4: ByteArray?,
        val remote4: ByteArray?,
        val nat: ExitNat,
        val awg: AwgChannel.Params?,
        val localPublic: ByteArray,
        val peerPublic: ByteArray,
        val mss: Int,
    )

    private fun planSecondExit(cfg: WarpConfig, second: WarpConfig): SecondPlan? {
        val settings = serviceSettings()
        val localPublic = runCatching { Crypto.publicOf(Crypto.unBase64(second.account.privateB64)) }.getOrNull()
        val peerPublic = runCatching { Crypto.unBase64(second.account.peerPublicB64) }.getOrNull()
        if (localPublic == null || peerPublic == null || localPublic.size != 32 || peerPublic.size != 32) {
            TunnelDebug.error("второй выход: ключи конфига не читаются", "трафик идёт через WARP")
            return null
        }
        val remote = resolveOutside(second.endpoint.host)
        if (remote == null) {
            TunnelDebug.error(
                "второй выход: адрес сервера ${second.endpoint.host} не найден",
                "трафик идёт через WARP; проверь Endpoint во втором конфиге"
            )
            return null
        }
        val tun6 = cfg.account.ipv6?.takeIf { cfg.enableIpv6Address && it.isNotBlank() }
        val nat = ExitNat.of(cfg.account.ipv4, tun6, settings.secondConf)
        val awg = AwgChannel.paramsOf(settings.secondConf)
        val local4 = PacketMath.addrOf(cfg.account.ipv4)
        val remote4 = remote.address.takeIf { it.size == 4 }
        // Внутри WARP — только к IPv4-адресу сервера (пакеты-обёртки собираются IPv4).
        val inner = settings.secondViaWarp && local4 != null && remote4 != null
        if (settings.secondViaWarp && !inner) {
            TunnelDebug.stage("второй выход: у сервера нет IPv4-адреса — подключаюсь напрямую, не через WARP")
        }
        // Обёртка внутри WARP: 20 (IPv4) + 8 (UDP) + 32 (WireGuard) + добавка S4; и ещё 60 на
        // заголовки IPv6 + TCP — так сегмент влезает в MTU основного туннеля без дробления.
        val mss = if (inner) (cfg.mtu.coerceIn(576, 1420) - 28 - 32 - (awg?.s4 ?: 0) - 60).coerceAtLeast(536) else 0
        TunnelDebug.stage(
            "второй выход: " + (if (inner) "через WARP" else "напрямую") +
                " к ${remote.hostAddress}:${second.endpoint.port}" +
                (if (nat.v4) ", адрес отправителя — из второго конфига" else ", адреса IPv4 во втором конфиге нет") +
                (if (tun6 != null && !nat.v6) ", IPv6 у сервера нет — сайты пойдут по IPv4" else "") +
                (awg?.let { ", ${it.describe()}" } ?: "")
        )
        return SecondPlan(inner, remote, local4, remote4, nat, awg, localPublic, peerPublic, mss)
    }

    /**
     * Адрес сервера второго выхода по имени — через настоящую сеть, мимо своего же туннеля: пока
     * туннель поднимается, запрос имени через него ушёл бы в никуда.
     */
    private fun resolveOutside(host: String): java.net.InetAddress? {
        PacketMath.addrOf(host)?.let { bytes -> return runCatching { java.net.InetAddress.getByAddress(bytes) }.getOrNull() }
        val cm = getSystemService(android.net.ConnectivityManager::class.java)
        val networks = runCatching {
            cm?.allNetworks.orEmpty().filter { n ->
                val caps = cm?.getNetworkCapabilities(n) ?: return@filter false
                caps.hasCapability(android.net.NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
                    !caps.hasTransport(android.net.NetworkCapabilities.TRANSPORT_VPN)
            }
        }.getOrDefault(emptyList())
        val ordered = listOfNotNull(underlyingNetwork()) + networks
        for (n in ordered.distinct()) {
            val all = runCatching { n.getAllByName(host).toList() }.getOrNull().orEmpty()
            (all.firstOrNull { it.address.size == 4 } ?: all.firstOrNull())?.let { return it }
        }
        return runCatching { java.net.InetAddress.getAllByName(host).toList() }.getOrNull().orEmpty()
            .let { all -> all.firstOrNull { it.address.size == 4 } ?: all.firstOrNull() }
    }

    /** Отдельный защищённый сокет для второго выхода: свой protect() обязателен, иначе петля. */
    private fun openSecondSocket(cfg: WarpConfig, remote: java.net.InetAddress?): DatagramSocket? {
        val socket = runCatching {
            DatagramSocket(null).apply { reuseAddress = true; soTimeout = 1500 }
        }.getOrNull() ?: return null
        if (!runCatching { protect(socket) }.getOrDefault(false)) {
            runCatching { socket.close() }
            TunnelDebug.error("второй выход: protect() отказал", "второй туннель не поднят, трафик идёт через WARP")
            return null
        }
        val connected = runCatching {
            socket.connect(
                if (remote != null) InetSocketAddress(remote, cfg.endpoint.port)
                else InetSocketAddress(cfg.endpoint.host, cfg.endpoint.port)
            )
        }.isSuccess
        if (!connected) {
            runCatching { socket.close() }
            TunnelDebug.error("второй выход: connect() не удался", "проверь endpoint второго конфига")
            return null
        }
        return socket
    }

    private fun isFullTunnel(cfg: WarpConfig): Boolean =
        SplitRoutes.prefixesOf(cfg.allowedIps).any { it == "0.0.0.0/0" || it == "::/0" }

    private fun planeBytesUp(): Long = plane?.bytesUp ?: 0L

    /** Единственная точка «мы сдались»: статус + журнал + аккуратная остановка. */
    private fun fail(reason: String, startId: Int, myEpoch: Int = -1) {
        // Попытку могли уже заменить следующей (перебор точек, повторное нажатие, смена сети).
        // Тогда её отказ — не новость о текущем туннеле: без этой проверки старая попытка
        // объявляла «сдался» и снимала сервис, пока новый подъём ещё шёл. Именно так выглядело
        // «ни одна точка не поднялась», хотя следующая поднималась через секунду.
        if (myEpoch >= 0 && myEpoch != epoch.get()) {
            TunnelDebug.stage("устаревшая попытка: $reason — текущую не трогаю")
            return
        }
        // Закрытому экземпляру сдаваться не от чего: общее состояние уже принадлежит другому.
        if (destroyed) return
        // Старт без перебора в интерфейсе (плитка, автоподъём): мёртвую точку меняет сам сервис
        // (см. superviseStart) — снять себя здесь значило оставить туннель лежать до нажатия.
        if (autoRebind || (selfDrivenStart && isSilentPoint(reason))) {
            // После смены сети сервис не снимаем: сеть может появиться снова, а пользователь —
            // не нажать «Подключить». Просто честно говорим, что не вышло.
            starting = false
            TunnelState.busy = false
            TunnelState.up = false
            TunnelState.phase = dev.warpscout.core.state.TunnelStatus.PHASE_FAILED
            TunnelState.status = reason
            TunnelState.error = reason
            TunnelDebug.error(reason)
            postNotification(reason)
            return
        }
        starting = false
        TunnelState.busy = false
        TunnelState.phase = dev.warpscout.core.state.TunnelStatus.PHASE_FAILED
        TunnelState.status = reason
        TunnelState.error = reason
        TunnelState.gaveUp = true
        TunnelDebug.error(reason)
        runCatching { TunnelStatusPublisher.flush() }
        runCatching {
            TunnelDebug.writeToFile(File(filesDir, "tunnel-debug.log"))
        }
        // Попытка кончилась — освобождаем её сами, не дожидаясь onDestroy: если следом уже пришло
        // новое «Подключить», onDestroy не будет вовсе, и мёртвый plane упёр бы новый старт в
        // «уже поднимается». Новая эпоха гасит сторожа этой попытки.
        wanted = false
        TunnelState.wanted = false
        epoch.incrementAndGet()
        closeAll()
        stopSelfSafely(startId)
    }

    /**
     * Остановиться, только если после команды [startId] ничего не пришло. stopSelf() без номера
     * отменял и «Подключить», пришедшее следом, — см. обработку ACTION_STOP.
     */
    private fun stopSelfSafely(startId: Int = -1) {
        runCatching { if (startId > 0) stopSelf(startId) else stopSelf() }
    }

    private fun builderFor(cfg: WarpConfig): Builder {
        val builder = Builder()
            .setSession("WilyScout")
            .setMtu(cfg.mtu.coerceIn(576, 1420))
            // setBlocking — это НЕ «запретить трафик мимо маршрутов» (так ошибочно было написано
            // здесь раньше), а режим дескриптора tun: блокирующее чтение или нет. Дескриптор
            // всегда неблокирующий, а ждать пакетов помогает poll() (см. waitTunReadable): поток
            // спит до пакета и гарантированно выходит при остановке. Раньше пустое чтение в
            // раздельном режиме значило «поспать 20 мс и снова» — 50 пробуждений в секунду.
            .setBlocking(false)
        runCatching { builder.setMetered(false) }   // иначе часть телефонов режет фоновый трафик в туннеле
        runCatching { builder.addAddress(cfg.account.ipv4.substringBefore('/'), 32) }
        val v6 = cfg.account.ipv6?.takeIf { cfg.enableIpv6Address && it.isNotBlank() }
        if (v6 != null) runCatching { builder.addAddress(v6.substringBefore('/'), 128) }
        cfg.dns.forEach { if (it.isNotBlank()) runCatching { builder.addDnsServer(it.trim()) } }
        // Раздельные маршруты: плюс адреса DNS и сети GitHub (см. tunRouteText).
        val routeText = tunRouteText(cfg, log = true, v6 = v6 != null)
        routeText.split(',').map { it.trim() }.filter { it.contains('/') }.forEach { cidr ->
            // IPv6-маршрут без IPv6-адреса на интерфейсе — чёрная дыра (пакеты уходят в tun и
            // пропадают). Проверено на живом запросе: с таким маршрутом Telegram и браузер
            // «открывались наполовину». Поэтому v6-маршруты добавляем только с адресом.
            if (cidr.contains(':') && v6 == null) return@forEach
            val parts = cidr.split('/')
            val bits = parts[1].trim().toIntOrNull() ?: return@forEach
            runCatching { builder.addRoute(parts[0].trim(), bits) }
        }
        applyAppSplit(builder)
        return builder
    }

    /**
     * Разделение по приложениям. Amnezia делает то же самое: в режиме «только выбранные»
     * в туннель попадают лишь отмеченные пакеты, в режиме «всё, кроме выбранных» — наоборот.
     *
     * Пустой список не должен означать «ничего не туннелировать»: если пользователь выбрал
     * «только выбранные», но ничего не отметил, честнее пустить всё и сказать об этом в журнале,
     * чем оставить телефон без интернета и без объяснений.
     */
    private fun applyAppSplit(builder: Builder) {
        val settings = serviceSettings()
        val selected = settings.appsSelected.filter { it != packageName }
        when (settings.appsMode) {
            dev.warpscout.core.state.ServiceSettings.APPS_ONLY -> {
                if (selected.isEmpty()) {
                    TunnelDebug.stage("приложения: режим «только выбранные», но список пуст — идут все")
                } else {
                    selected.forEach { runCatching { builder.addAllowedApplication(it) } }
                    // Приложения со своим выходом (с 1.10.39) идут через туннель, даже если галочку с
                    // них сняли в другом режиме: выбранный выход значит «через туннель».
                    val withExit = appExitRules().keys.filter { it != packageName && it !in selected }
                    val addedExit = withExit.filter { runCatching { builder.addAllowedApplication(it) }.isSuccess }
                    if (addedExit.isNotEmpty()) {
                        TunnelDebug.stage("приложения: со своим выходом — ещё ${addedExit.size} (${addedExit.joinToString(", ")})")
                    }
                    // Спутники выбранных (с 1.10.37, см. AppServices.companionsFor): Gemini на Android —
                    // оболочка, запросы к Google и проверку страны делает приложение Google. Без него
                    // в туннеле Gemini писал «Эта страна не поддерживается» (23.11): запросы шли мимо
                    // туннеля, с российского адреса оператора. Нет на телефоне — так и говорим.
                    val joined = runCatching { AppServices.companionsFor(selected) }.getOrDefault(emptyList())
                    val (added, absent) = joined.partition {
                        runCatching { builder.addAllowedApplication(it.companion.pkg) }.isSuccess
                    }
                    // Сам WarpScout — тоже в туннель: иначе проверка связи и замер скорости шли
                    // мимо него и показывали скорость обычного интернета, а не туннеля, через
                    // который идут выбранные приложения.
                    runCatching { builder.addAllowedApplication(packageName) }
                    TunnelDebug.stage(
                        "приложения: только выбранные (${selected.size}) и сам WilyScout — для проверок" +
                            added.joinToString("") { "; с ними приложение ${it.companion.title} — внутри него работает ${it.service}" }
                    )
                    absent.forEach {
                        TunnelDebug.stage(
                            "приложения: ${it.service} работает внутри приложения ${it.companion.title}, а его нет на " +
                                "телефоне (или оно выключено) — ${it.service} может не открыться"
                        )
                    }
                }
            }

            dev.warpscout.core.state.ServiceSettings.APPS_EXCEPT -> {
                // Приложение со своим выходом (с 1.10.39) из туннеля не исключаем.
                val withExit = appExitRules().keys
                val excluded = selected.filter { it !in withExit }
                if (excluded.isEmpty()) {
                    TunnelDebug.stage("приложения: все через туннель (исключений нет)")
                } else {
                    excluded.forEach { runCatching { builder.addDisallowedApplication(it) } }
                    TunnelDebug.stage("приложения: все, кроме выбранных (${excluded.size})")
                }
            }

            else -> TunnelDebug.stage("приложения: все через туннель")
        }
    }

    private fun postNotification(text: String) {
        // Закрытый экземпляр уведомлений не публикует: иначе в шторке оставалось «туннель поднят»
        // от сервиса, которого уже нет.
        if (destroyed) return
        // startForeground обязаны быть вызваны в течение ~5 с после startForegroundService, а теперь
        // весь путь у нас на worker-потоке — поэтому просто кидаем задачу на главный (он свободен).
        if (Thread.currentThread() !== mainLooperThread) {
            android.os.Handler(android.os.Looper.getMainLooper()).post { postNotificationNow(text) }
            return
        }
        postNotificationNow(text)
    }

    private val mainLooperThread: Thread get() = android.os.Looper.getMainLooper().thread

    private fun postNotificationNow(text: String) {
        if (destroyed) return
        createChannel()
        val open = android.app.PendingIntent.getActivity(
            this, 0,
            Intent(this, dev.warpscout.app.MainActivity::class.java)
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
            android.app.PendingIntent.FLAG_UPDATE_CURRENT or android.app.PendingIntent.FLAG_IMMUTABLE
        )
        val stopPi = android.app.PendingIntent.getService(
            this, 1,
            Intent(this, WarpVpnService::class.java).apply {
                action = ACTION_STOP
                putExtra(EXTRA_BY_USER, true)
            },
            android.app.PendingIntent.FLAG_UPDATE_CURRENT or android.app.PendingIntent.FLAG_IMMUTABLE
        )
        val n = NotificationCompat.Builder(this, CHANNEL)
            .setContentTitle(getString(R.string.app_name))
            .setContentText(text)
            // Пустая иконка: значок приложения в строке состояния не появляется (см. ic_stat_blank).
            .setSmallIcon(R.drawable.ic_stat_blank)
            .setOngoing(true)
            .setSilent(true)
            .setShowWhen(false)
            .setPriority(NotificationCompat.PRIORITY_MIN)
            .setVisibility(NotificationCompat.VISIBILITY_SECRET)
            .setContentIntent(open)
            .addAction(0, getString(R.string.notif_stop), stopPi)
            .build()
        // Тип сервиса — specialUse (см. манифест): «vpn» приложению недоступен. На 34+
        // тип передаём явно, иначе летит MissingForegroundServiceTypeException.
        val started = if (Build.VERSION.SDK_INT >= 34) {
            runCatching { startForeground(NOTIF_ID, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE) }
                .recoverCatching { startForeground(NOTIF_ID, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC) }
                .recoverCatching { startForeground(NOTIF_ID, n) }
        } else {
            runCatching { startForeground(NOTIF_ID, n) }
        }
        if (started.isFailure) {
            // Причина должна остаться в файле: система убьёт процесс через 5 секунд, и без этой
            // записи в журнале не будет ничего (именно так и выглядело «вылет без логов»).
            val why = started.exceptionOrNull()?.let { "${it.javaClass.simpleName}: ${it.message}" } ?: "неизвестно"
            TunnelState.status = "startForeground отказал: $why"
            dev.warpscout.app.CrashLog.note(this, "startForeground отказал: $why")
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            runCatching { notifyManager().notify(NOTIF_ID, n) }
        }
        refreshTile()
    }

    /** Плитка быстрых настроек показывает не своё «я», а реальное состояние сервиса. */
    private fun refreshTile() = runCatching {
        android.service.quicksettings.TileService.requestListeningState(
            this, android.content.ComponentName(this, TunnelTileService::class.java)
        )
    }

    private fun createChannel() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return
        val mgr = notifyManager()
        // Важность канала нельзя понизить после создания — поэтому новый id и удаление старого.
        // IMPORTANCE_MIN: уведомление сворачивается в самый низ шторки и молчит.
        mgr.createNotificationChannel(
            NotificationChannel(CHANNEL, getString(R.string.notif_channel), NotificationManager.IMPORTANCE_MIN).apply {
                setShowBadge(false)
                enableVibration(false)
                setSound(null, null)
                lockscreenVisibility = Notification.VISIBILITY_SECRET
            }
        )
        runCatching { mgr.deleteNotificationChannel(LEGACY_CHANNEL) }
    }

    private fun notifyManager(): NotificationManager =
        getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager

    private fun shutdown() {
        // Эпоха растёт первой: любой поток подъёма сразу становится недействительным.
        epoch.incrementAndGet()
        TunnelState.busy = false
        // Без раннего выхода «уже остановлен». Раньше второй вызов (onDestroy после «Отключить»
        // или во время переподъёма, когда флаг уже поднят) выходил сразу — и слежение за сетью
        // оставалось зарегистрированным навсегда: закрытый экземпляр продолжал отвечать на каждую
        // смену сети своим туннелем. Всё ниже можно повторять сколько угодно раз.
        stopped.set(true)
        wanted = false
        TunnelState.wanted = false
        cancelWaits()
        starting = false
        autoRebind = false
        netRestartAttempts = 0
        TunnelState.up = false
        TunnelState.phase = dev.warpscout.core.state.TunnelStatus.PHASE_IDLE
        TunnelState.status = "туннель остановлен"
        unwatchNetwork()
        closeAll()
        runCatching { stopForeground(STOP_FOREGROUND_REMOVE) }
        // Процесс может умереть сразу после stopSelf — состояние должно быть записано уже сейчас.
        runCatching { TunnelStatusPublisher.flush() }
    }

    /**
     * Закрыть сокеты, tun и оба data plane — без решения «останавливаемся навсегда».
     *
     * Поля забираем под замком [life] (под ним же startVpn вступает во владение), а закрываем уже
     * вне его: join потоков может занять до полутора секунд, держать замок всё это время незачем.
     */
    private fun closeAll() {
        runCatching { sentryThread?.interrupt() }
        sentryThread = null
        sentryOff = false
        var d: TunDispatcher? = null
        var p2: DataPlane? = null
        var s2: DatagramSocket? = null
        var w2: Thread? = null
        var p: DataPlane? = null
        var w: Thread? = null
        var s: DatagramSocket? = null
        var t: ParcelFileDescriptor? = null
        synchronized(life) {
            d = dispatcher
            dispatcher = null
            p2 = plane2
            plane2 = null
            s2 = secondSocket
            secondSocket = null
            w2 = worker2
            worker2 = null
            p = plane
            plane = null
            w = worker
            worker = null
            s = udpSocket
            udpSocket = null
            t = tun
            tun = null
        }
        runCatching { d?.stop() }
        // Обход DPI в туннеле (с 1.10.49-beta3): итог сессии — сколько напрямую, сколько через туннель.
        (d?.tap as? DpiRelay)?.let { relay ->
            if (relay.opened.get() > 0 || relay.quicBlocked.get() > 0) runCatching { TunnelDebug.stage(relay.summary()) }
        }
        // Сколько стоил выход по приложениям в этой сессии (с 1.10.39) — строка в журнал.
        d?.appExits?.let { table -> if (table.lookups > 0) runCatching { TunnelDebug.stage(table.summary()) } }
        // Пакеты «только второй выход» (TikTok, с 1.10.44-beta1), придержанные без второго выхода.
        d?.let { disp ->
            if (disp.strictHeld > 0) {
                runCatching {
                    TunnelDebug.stage("второй выход не работал — пакетов «только второй выход» придержано: ${disp.strictHeld} (в WARP не пускал)")
                }
            }
        }
        // Диспетчера нет — Telegram через второй выход больше не идёт (с 1.10.34).
        if (tgViaSecond) {
            tgViaSecond = false
            TunnelState.tgSecond = false
        }
        runCatching { p2?.stop() }
        runCatching { s2?.close() }
        if (p2 != null) {
            TunnelState.second = TunnelStatus.SECOND_OFF
            TunnelState.secondPeer = ""
        }
        w2?.let { if (it !== Thread.currentThread()) runCatching { it.join(500) } }
        runCatching { p?.stop() }
        // Поток закрыт → читающий его цикл выйдет сам; join только из чужого потока.
        w?.let { if (it !== Thread.currentThread()) runCatching { it.join(1000) } }
        runCatching { s?.close() }
        runCatching { t?.close() }
    }

    // ------------------------------------------------------------ смена сети

    /**
     * Следим за сетью, у которой нет флага VPN (то есть за настоящей: Wi-Fi или мобильной).
     *
     * `registerDefaultNetworkCallback` здесь не годится: при поднятом туннеле «сеть по умолчанию» —
     * это сам туннель, и смена Wi-Fi ↔ LTE его не трогает. Поэтому просим сеть с
     * `NET_CAPABILITY_NOT_VPN` и сравниваем с той, на которой поднимались.
     */
    private fun watchNetwork() {
        watchScreen()
        if (netCallback != null || destroyed) return
        val cm = runCatching { getSystemService(android.net.ConnectivityManager::class.java) }.getOrNull()
            ?: return
        val request = runCatching {
            android.net.NetworkRequest.Builder()
                .addCapability(android.net.NetworkCapabilities.NET_CAPABILITY_INTERNET)
                .addCapability(android.net.NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
                .build()
        }.getOrNull() ?: return
        val cb = object : android.net.ConnectivityManager.NetworkCallback() {
            override fun onCapabilitiesChanged(
                network: android.net.Network,
                caps: android.net.NetworkCapabilities,
            ) {
                if (destroyed) {
                    dropStrayCallback(this)
                    return
                }
                // Модем перестроился: сменилась полоса, качество, набор возможностей. Считаем —
                // частые перестройки на LTE и есть та работа, которая греет модем в кармане.
                capsChanges.incrementAndGet()
                val kind = runCatching { dev.warpscout.app.NetIdentity.keyOf(this@WarpVpnService, network, caps) }
                    .getOrDefault(kindOf(caps))
                if (kind.isNotEmpty()) lastNetKind = kind
                // Тип связи сети туннеля (с 1.10.40): LTE → H+ → H бывает и без смены сети — тогда в
                // журнале видно, когда именно связь стала медленной.
                if (network == baselineNetwork) updateRadio(network, announce = true)
            }

            override fun onAvailable(network: android.net.Network) {
                // Закрытый экземпляр на смену сети не отвечает: его слежение снимается само.
                if (destroyed) {
                    dropStrayCallback(this)
                    return
                }
                netChanges.incrementAndGet()
                rememberNetKind(network)
                val base = baselineNetwork
                if (base == null) {
                    baselineNetwork = network
                    updateRadio(network)
                    TunnelDebug.stage("сеть туннеля: ${describeNetwork(network)}")
                    if (networkChanged) {
                        // Сети не было (или сменилась, пока её не было) — поднимаем заново.
                        restartAfterNetworkChange("сеть появилась: ${describeNetwork(network)}")
                    }
                    return
                }
                if (network == base) return
                baselineNetwork = network
                updateRadio(network)
                networkChanged = true
                restartAfterNetworkChange("новая сеть: ${describeNetwork(network)}")
            }

            override fun onLost(network: android.net.Network) {
                if (destroyed) {
                    dropStrayCallback(this)
                    return
                }
                netChanges.incrementAndGet()
                if (network != baselineNetwork) return
                baselineNetwork = null
                networkChanged = true
                TunnelState.up = false
                TunnelState.phase = dev.warpscout.core.state.TunnelStatus.PHASE_NO_NETWORK
                TunnelState.status = "сеть пропала — жду новую"
                postNotification(TunnelState.status)
                TunnelDebug.stage("сеть пропала (${describeNetwork(network)}): старый UDP-сокет мёртв")
                // Другая сеть уже есть (мобильные данные держатся рядом с Wi-Fi) — события «новая
                // сеть» не будет: она появилась раньше. Переподнимаемся сразу, а не ждём, пока
                // старый сокет упрётся в ENETUNREACH: с погашенным экраном это минуты.
                if (hasUsableNetwork()) {
                    restartAfterNetworkChange("сеть пропала (${describeNetwork(network)}), есть другая")
                }
                // Если новая сеть не появится, tun нельзя оставлять: приложения будут отправлять
                // трафик в туннель, из которого ничего не выходит (чёрная дыра, «интернета нет»).
                Thread({
                    runCatching { Thread.sleep(45_000) }
                    if (stopped.get() || destroyed || !wanted) return@Thread
                    // Сеть спрашиваем у системы, а не у своего поля baselineNetwork: переподъём
                    // это поле обнуляет и не восстанавливает (watchNetwork() второй раз не
                    // регистрируется, onAvailable больше не приходит). Из-за этого сторож снимал
                    // только что поднятый туннель через 45 секунд после потери Wi-Fi — в журнале
                    // человек видел «подключился и сразу потерял сеть», хотя LTE работал всё время.
                    if (TunnelState.up || hasUsableNetwork()) return@Thread
                    TunnelDebug.stage("45 секунд без сети — снимаю туннель, чтобы трафик не уходил в пустоту")
                    TunnelState.phase = dev.warpscout.core.state.TunnelStatus.PHASE_NO_NETWORK
                    TunnelState.status = "нет сети — туннель снят"
                    postNotification(TunnelState.status)
                    epoch.incrementAndGet()
                    stopped.set(true)
                    starting = false
                    TunnelState.up = false
                    TunnelState.busy = false
                    closeAll()
                    stopped.set(false)
                    // Сами себя выключили — сами и включаемся: раз в 15 секунд смотрим, не
                    // появилась ли сеть. Раньше надеялись только на событие от системы, а если
                    // сеть не менялась (LTE был всё время), события не было — и приложение стояло
                    // выключенным, пока человек не зайдёт и не нажмёт «Подключить».
                    scheduleRevive()
                }, "warpscout-net-watchdog").apply { isDaemon = true }.start()
            }
        }
        // Регистрация — под замком и с повторной проверкой: если onDestroy успел пройти, пока
        // собирали запрос, закрытый экземпляр не должен начать следить за сетью заново.
        var skipped = false
        val ok = synchronized(life) {
            if (destroyed || netCallback != null) {
                skipped = true
                false
            } else {
                val registered = runCatching { cm.registerNetworkCallback(request, cb) }.isSuccess
                if (registered) netCallback = cb
                registered
            }
        }
        if (!ok && !skipped) TunnelDebug.stage("не удалось следить за сетью: нет разрешения?")
    }

    private fun unwatchNetwork() {
        unwatchScreen()
        val cb = synchronized(life) {
            val current = netCallback
            netCallback = null
            current
        } ?: return
        runCatching {
            getSystemService(android.net.ConnectivityManager::class.java)?.unregisterNetworkCallback(cb)
        }
    }

    /** Слежение, оставшееся от закрытого экземпляра, снимает себя при первом же событии. */
    private fun dropStrayCallback(cb: android.net.ConnectivityManager.NetworkCallback) {
        runCatching {
            getSystemService(android.net.ConnectivityManager::class.java)?.unregisterNetworkCallback(cb)
        }
    }

    /**
     * Включённый экран — повод не ждать паузы медленного повтора.
     *
     * Паузы между повторами (Thread.sleep) в глубоком сне не идут: в журнале страховочные 25 с
     * растягивались до десяти минут. Человек включает экран, видит, что туннеля нет, а повтор
     * наступит только через несколько минут бодрствования. Поэтому при включении экрана, если
     * туннель лежит и ждёт, пробуем сразу — не чаще раза в 30 секунд.
     */
    private fun watchScreen() {
        val receiver = object : android.content.BroadcastReceiver() {
            override fun onReceive(context: Context?, intent: Intent?) {
                when (intent?.action) {
                    Intent.ACTION_SCREEN_ON -> {
                        screenOffAt = 0L
                        onScreenOn()
                    }
                    // С 1.10.31 — и выключение: по нему считается «телефон не используется» для
                    // тихого подбора Wi-Fi (см. maybeQuietScan).
                    Intent.ACTION_SCREEN_OFF -> screenOffAt = System.currentTimeMillis()
                }
            }
        }
        synchronized(life) {
            if (!destroyed && screenReceiver == null) {
                // SCREEN_ON/OFF — системные защищённые сообщения: флаг экспорта для них не нужен.
                val registered = runCatching {
                    registerReceiver(
                        receiver,
                        android.content.IntentFilter().apply {
                            addAction(Intent.ACTION_SCREEN_ON)
                            addAction(Intent.ACTION_SCREEN_OFF)
                        }
                    )
                }.isSuccess
                if (registered) {
                    screenReceiver = receiver
                    if (!isScreenOn() && screenOffAt == 0L) screenOffAt = System.currentTimeMillis()
                }
            }
        }
    }

    private fun unwatchScreen() {
        val receiver = synchronized(life) {
            val current = screenReceiver
            screenReceiver = null
            current
        } ?: return
        runCatching { unregisterReceiver(receiver) }
    }

    private fun onScreenOn() {
        // Идёт тихий подбор — человек взял телефон: подбор прерываем, туннель возвращаем сразу.
        if (quietScanRunning) {
            abortQuietScan()
            return
        }
        if (destroyed || !wanted || TunnelState.up) return
        // Только когда туннель лежит и ждёт: идущий подъём или переподъём не трогаем.
        val phase = TunnelState.phase
        if (phase != dev.warpscout.core.state.TunnelStatus.PHASE_FAILED &&
            phase != dev.warpscout.core.state.TunnelStatus.PHASE_NO_NETWORK
        ) return
        val now = System.currentTimeMillis()
        if (now - lastScreenRetryAt < 30_000L) return
        if (!hasUsableNetwork() || lastConfigText == null) return
        lastScreenRetryAt = now
        TunnelDebug.stage("экран включён, а туннель лежит — пробую сразу, не дожидаясь паузы")
        restartAfterNetworkChange("экран включён", R.string.status_reconnect_net, slowAttempt = true)
    }

    private fun describeNetwork(network: android.net.Network): String = runCatching {
        val cm = getSystemService(android.net.ConnectivityManager::class.java)
        val caps = cm?.getNetworkCapabilities(network)
        val kind = when {
            caps == null -> "сеть"
            caps.hasTransport(android.net.NetworkCapabilities.TRANSPORT_WIFI) -> "Wi-Fi"
            caps.hasTransport(android.net.NetworkCapabilities.TRANSPORT_CELLULAR) -> "мобильная"
            caps.hasTransport(android.net.NetworkCapabilities.TRANSPORT_ETHERNET) -> "Ethernet"
            else -> "сеть"
        }
        val radio = dev.warpscout.app.NetIdentity.radioOf(this, network)
        if (radio.isEmpty()) "$kind ${network}" else "$kind ${network} · $radio"
    }.getOrDefault("сеть")

    /**
     * Переподнять туннель на новой сети. Полный цикл закрытия/открытия здесь обязателен: старый
     * UDP-сокет привязан к прежнему маршруту, и после смены сети каждый `sendto` падает с
     * ENETUNREACH — «туннель есть, а трафика нет», при этом замочек в шторке висит активным.
     */
    private fun restartAfterNetworkChange(
        why: String,
        statusRes: Int = R.string.status_reconnect_net,
        slowAttempt: Boolean = false,
    ) {
        // Закрытому экземпляру и выключенному туннелю переподниматься незачем. Именно отсюда
        // «призраки» прошлых экземпляров поднимали свои туннели на каждую смену сети: в журнале
        // 20:19:44 «новая сеть: Wi-Fi 208 — переподключаю туннель» пришло трижды, от трёх
        // экземпляров, и три туннеля на одном ключе мешали друг другу — до ручного нажатия в 21:26.
        if (destroyed || !wanted) return
        val now = System.currentTimeMillis()
        var releaseDead = false
        synchronized(this) {
            // Переключение сети приходит пачкой событий: перезапускаемся не чаще раза в тихое окно.
            // ВАЖНО: событие внутри паузы нельзя просто терять — именно на нём и терялся туннель,
            // поэтому откладываем один перезапуск, а не выбрасываем его.
            val waitLeft = NET_QUIET_MS - (now - lastNetRestartAt)
            if (waitLeft > 0) {
                if (netRestartPending) return
                netRestartPending = true
                Thread({
                    runCatching { Thread.sleep(waitLeft.coerceAtLeast(120L)) }
                    netRestartPending = false
                    if (!stopped.get() && wanted && !destroyed) {
                        restartAfterNetworkChange("$why (после паузы)", statusRes, slowAttempt)
                    }
                }, "warpscout-net-defer").apply { isDaemon = true }.start()
                return
            }
            lastNetRestartAt = now
            // Бюджет: слишком частые автоматические переподъёмы означают, что сеть not WARP-friendly.
            val cut = now - AUTO_RESTART_WINDOW_MS
            while (autoRestartTimes.isNotEmpty() && autoRestartTimes.first() < cut) {
                autoRestartTimes.removeFirst()
            }
            // Меняем точку — значит, прежние неудачи были про мёртвый адрес, а не про сеть.
            // Копить их в бюджете незачем: иначе после трёх-четырёх таких попыток сервис уходил
            // в «медленный режим» и ждал пять минут, хотя рядом лежала живая точка.
            if (forceFastRetry) {
                forceFastRetry = false
                autoRestartTimes.clear()
            }
            // Медленный повтор и сам редкий — бюджет быстрых попыток к нему не относится. Раньше
            // он упирался в тот же бюджет: «медленный повтор 8 из 12» тут же получал
            // «приостановлено» и заводил ещё один медленный повтор — к 23:14 их шло по пять сразу.
            // Смена сети (с 1.10.40) лимит не тратит и им не останавливается: старый сокет после неё
            // мёртв наверняка, и переподняться нужно в любом случае. Телефон в дороге переходит
            // LTE ↔ H+ ↔ Wi-Fi, и система каждый раз заводит новую сеть: в журнале 23.11, 13:59–14:01
            // седьмая смена за 10 минут выключила рабочий туннель на минуты («повторю через 30 с»,
            // потом 1 и 2 минуты). Неудачный переподъём после смены сети («повтор после неудачи»)
            // лимит тратит, как раньше, — бесконечного цикла на мёртвой сети не будет.
            val netEvent = why.startsWith("новая сеть") || why.startsWith("сеть появилась") || why.startsWith("сеть пропала")
            if (!slowAttempt && !netEvent && autoRestartTimes.size >= AUTO_RESTART_LIMIT) {
                // Быстрые попытки кончились — но это не повод остаться выключенным навсегда:
                // медленный режим, одна попытка через растущую паузу (30 с, 1, 2, дальше по 5 мин).
                slowRetries += 1
                netRestartAttempts = 0
                autoRebind = false
                TunnelState.phase = dev.warpscout.core.state.TunnelStatus.PHASE_FAILED
                TunnelState.up = false
                if (slowRetries <= SLOW_RETRY_LIMIT) {
                    val pause = slowRetryDelayMs(slowRetries)
                    TunnelDebug.error(
                        "автопереподключение приостановлено: $AUTO_RESTART_LIMIT попыток за 10 минут",
                        "медленный режим: повторю через ${pauseText(pause)} " +
                            "(попытка $slowRetries из $SLOW_RETRY_LIMIT); новая сеть или включённый экран — сразу"
                    )
                    TunnelState.status = "нет связи с WARP — повторю через ${pauseText(pause)}"
                    postNotification(TunnelState.status)
                    scheduleSlowRetry(slowRetries, pause)
                } else {
                    TunnelDebug.error(
                        "переподключение прекращено: $SLOW_RETRY_LIMIT медленных попыток подряд",
                        "сеть не пропускает WARP: подключусь при смене сети или включении экрана, " +
                            "или нажми «Подключить» и смени профиль шума"
                    )
                    TunnelState.status = "не удалось подключиться — нажми «Подключить»"
                    postNotification(TunnelState.status)
                    cancelWaits()
                }
                releaseDead = true
            } else if (!netEvent) {
                autoRestartTimes.addLast(now)
            }
        }
        if (releaseDead) {
            // Мёртвую сессию не оставляем крутиться до медленного повтора. Раньше plane продолжал
            // слать rekey по пять инициаций каждые несколько секунд (журнал 23:10–23:13, «ток
            // 403 мА»), а трафик выбранных приложений уходил в пустой tun. Закрываем в своём
            // потоке: сюда приходят и из потоков самого plane, а closeAll() ждёт их завершения.
            epoch.incrementAndGet()
            starting = false
            TunnelState.busy = false
            Thread({ closeAll() }, "warpscout-release").apply { isDaemon = true }.start()
            return
        }
        reconnects.incrementAndGet()
        Thread({
            val text = lastConfigText ?: return@Thread
            autoRebind = true
            // Новая попытка отменяет отложенные (медленный повтор, ожидание сети): иначе они
            // сработали бы посреди неё и сорвали.
            cancelWaits()
            TunnelDebug.stage("$why — переподключаю туннель")
            TunnelState.phase = dev.warpscout.core.state.TunnelStatus.PHASE_RECONNECTING
            TunnelState.status = getString(statusRes)
            postNotification(TunnelState.status)
            val myEpoch = epoch.incrementAndGet()
            stopped.set(true)
            TunnelState.up = false
            starting = false
            TunnelState.busy = false
            closeAll()
            // Пауза короткая: маршрут по новой сети обычно уже поднят к моменту события, а лишние
            // 400 мс раньше складывались с другими задержками в те самые «5–8 секунд».
            runCatching { Thread.sleep(120) }
            // Пока спали, пользователь мог нажать «Отключить»: тогда переподнимать нечего.
            if (epoch.get() != myEpoch || destroyed) return@Thread
            stopped.set(false)
            networkChanged = false
            baselineNetwork = null
            // Чистим причину прошлой попытки: иначе «сервер молчит» от прежней точки будет
            // выдавать себя за диагноз новой, и сервис сменит живую точку зря.
            TunnelState.error = null
            // Порядок перебора — под эту сеть: первой пойдёт точка, работавшая на такой же сети.
            val netMoved = memoryNetKind() != failoverNet
            rebuildFailoverOrder()
            // И не тратим инициации на сеть, которая ещё не готова: сразу после включения Wi-Fi
            // адрес раздаётся, портал проверки доступа не пройден — handshake уходит в никуда.
            if (!awaitNetworkReady(3_000)) {
                TunnelDebug.stage("сеть ещё не признана рабочей — пробую как есть")
            }
            // Текст конфига только на одну строку — Endpoint: та, что работала на такой сети.
            // Посреди перебора к ней не возвращаемся: её уже пробовали в этом цикле. Раньше каждая
            // смена точки здесь откатывалась назад — «перехожу на B», а поднимался снова мёртвый A.
            val startText = if (rotationsSinceUp == 0 || netMoved) preferredStartText(text) else text
            if (startText != text) lastConfigText = startText
            // Пока ждали сеть (до трёх секунд), попытку могли сменить: «Отключить», новая смена
            // сети, ручное «Подключить». Тогда подниматься нельзя: два подъёма подряд оставляли два
            // data plane в одном экземпляре (журнал 23:14:01, эпохи 73 и 74).
            if (epoch.get() != myEpoch || destroyed || !wanted) return@Thread
            startVpnSafely(startText, lastStartId)
            // Номер попытки, которую только что запустили. Если он не «наш следующий», подъём
            // перехватили, и решать за чужую попытку этот поток не должен.
            val attemptEpoch = epoch.get()
            if (attemptEpoch != myEpoch + 1 || destroyed) return@Thread

            // Проверяем, что переподъём действительно состоялся: «сервис запущен» и «туннель
            // работает» — разные вещи. Если handshake не прошёл, пробуем ещё раз (до трёх),
            // а не оставляем пользователя с молчащим туннелем.
            val outcome = awaitAttempt(15_000)
            if (epoch.get() != attemptEpoch || destroyed || !wanted) return@Thread
            if (outcome == ATTEMPT_UP) {
                netRestartAttempts = 0
                autoRebind = false
                slowRetries = 0
                rotationsSinceUp = 0
                commitCycleMarks()
                // Причина — та, по которой переподнимали: раньше здесь всегда стояло «после смены
                // сети», даже когда сеть не менялась (журнал 22.11: переподъёмы по проверке связи).
                TunnelDebug.ok("туннель переподнят: $why")
                return@Thread
            }
            // «Сервер молчит» — это не «сеть не пускает», а «эта точка умерла»: пять инициаций
            // подряд, ни одного ответа. Повторять её ещё два раза бессмысленно (минута тишины и
            // лишние пробуждения модема), поэтому такую точку меняем сразу.
            val reason = TunnelState.error
            val deadPoint = isSilentPoint(reason)
            netRestartAttempts += 1
            if (netRestartAttempts < 3 && !stopped.get() && !deadPoint) {
                TunnelDebug.stage(
                    "переподъём не удался (попытка $netRestartAttempts из 3) — повторю через 8 с"
                )
                runCatching { Thread.sleep(8_000) }
                if (!stopped.get() && epoch.get() == attemptEpoch && wanted && !destroyed) {
                    restartAfterNetworkChange("повтор после неудачи")
                }
            } else {
                // Три раза стучались в одну точку и не достучались (или она молчит, закрыта или не
                // пропускает данные) — берём следующую из очереди последнего подключения.
                val next = moveToNextPoint(reason)
                if (next != null) {
                    runCatching { Thread.sleep(120) }
                    if (!stopped.get() && epoch.get() == attemptEpoch && wanted && !destroyed) {
                        restartAfterNetworkChange("переход на $next")
                    }
                    return@Thread
                }
                endFailedCycle()
            }
        }, "warpscout-net-restart").apply { isDaemon = true }.start()
    }

    /**
     * Точка не поднялась (молчит, порт закрыт, данные не идут): помечаем её и берём следующую из
     * очереди этой сети. Возвращает адрес следующей точки (текст конфига уже переключён на неё) или
     * null — переходить некуда.
     */
    private fun moveToNextPoint(reason: String?): String? {
        val oldPoint = currentEndpointLine().orEmpty()
        if (oldPoint.isNotEmpty()) {
            cycleTried.add(oldPoint)
            when {
                // «Порт закрыт» — прямой ответ сети: точка мертва, сколько ни жди. «Данные не
                // идут» — тоже: рукопожатие прошло, сеть до точки есть, а данных через неё нет.
                isClosedPort(reason) || (isDataDead(reason) && !isPlainNoise(reason)) -> sentryMarkDead(oldPoint)
                // Молчание — только кандидат в мёртвые (см. [cycleSilent]).
                isSilentPoint(reason) -> cycleSilent.add(oldPoint)
            }
        }
        val next = nextFailoverEndpoint() ?: return null
        lastConfigText = next.second
        rotationsSinceUp += 1
        netRestartAttempts = 0
        forceFastRetry = true
        TunnelDebug.stage(
            "$oldPoint не годится — перехожу на ${next.first} " +
                "(смена $rotationsSinceUp из $MAX_ROTATIONS, без ручного нажатия; " +
                "причина: ${(reason ?: "нет ответа").take(80)})"
        )
        TunnelState.phase = dev.warpscout.core.state.TunnelStatus.PHASE_RECONNECTING
        TunnelState.status = "переключаюсь на ${next.first}"
        postNotification(TunnelState.status)
        return next.first
    }

    /**
     * Старт без перебора в интерфейсе (плитка, автоподъём после перезагрузки, возврат туннеля после
     * подбора): если точка не годится, следующую берёт сам сервис — так же, как после смены сети.
     * Раньше такой старт на мёртвой точке кончался «сдался», и туннель лежал до ручного нажатия.
     */
    private fun superviseStart() {
        val attemptEpoch = epoch.get()
        val outcome = awaitAttempt(15_000)
        // Решение fail() уже принято (см. [selfDrivenStart]) — дальше старт обычный.
        selfDrivenStart = false
        if (epoch.get() != attemptEpoch || destroyed || !wanted || stopped.get()) return
        if (outcome != ATTEMPT_FAILED) return
        val reason = TunnelState.error
        // Не «точка не ответила», а поломка (конфиг, tun, protect): fail() уже снял сервис, как раньше.
        if (!isSilentPoint(reason)) return
        val next = moveToNextPoint(reason)
        if (next == null) {
            endFailedCycle()
            return
        }
        autoRebind = true
        runCatching { Thread.sleep(120) }
        if (epoch.get() == attemptEpoch && wanted && !destroyed) restartAfterNetworkChange("переход на $next")
    }

    /**
     * Цикл перебора кончился ничем.
     *
     * Раньше здесь сервис сдавался насовсем: «нажми «Подключить»», и до нажатия туннель лежал — в
     * журнале с 18:14:38 до 18:44:38, полчаса. Хуже того, мёртвый plane и tun оставались на месте:
     * трафик выбранных приложений уходил в пустоту, а первое же «Подключить» получало «уже
     * поднимается или работает». Теперь цикл честно закрывается и назначается следующий — через
     * растущую паузу; новая сеть и включённый экран запускают попытку сразу.
     */
    private fun endFailedCycle() {
        val tried = cycleTried.size.coerceAtLeast(1)
        val silent = cycleSilent.size
        // Все промолчали — это похоже на сеть, а не на точки: в мёртвые их не записываем.
        val allSilent = tried > 1 && silent >= tried
        cycleSilent.clear()
        cycleTried.clear()
        rotationsSinceUp = 0
        failoverOrder = emptyList()
        failoverPos = -1
        netRestartAttempts = 0
        autoRebind = false
        // Страховочный сторож этой попытки ещё спит (25 с): с новой эпохой он промолчит, а не
        // объявит «таймаут» поверх нашего объяснения.
        epoch.incrementAndGet()
        starting = false
        closeAll()
        TunnelState.busy = false
        TunnelState.up = false
        TunnelState.phase = dev.warpscout.core.state.TunnelStatus.PHASE_FAILED
        // «Не заработала», а не «не ответила»: с 1.10.29 точка, которая отвечает на рукопожатие, но
        // не пропускает данные, тоже не годится — и тоже входит в это число.
        val why = (if (tried == 1) "не удалось поднять туннель: точка не работает"
        else "не удалось поднять туннель: не заработала ни одна из $tried точек") +
            (if (allSilent) " — все молчали, похоже на сеть, а не на точки" else "")
        TunnelState.error = why
        // Вся очередь не работает — подбираем новые точки сами (не чаще раза в 30 минут): туннель
        // всё равно лежит, и пауза на подбор ничего не стоит. Не вышло — как раньше, медленные повторы.
        if (hasUsableNetwork() && startRescue(why)) return
        retryLaterAfterFailure(why)
    }

    /**
     * Медленный повтор после неудачного цикла перебора (или неудачного подбора сервиса): растущая
     * пауза; новая сеть или включённый экран — сразу.
     */
    private fun retryLaterAfterFailure(why: String) {
        TunnelState.phase = dev.warpscout.core.state.TunnelStatus.PHASE_FAILED
        TunnelState.up = false
        slowRetries += 1
        if (slowRetries > SLOW_RETRY_LIMIT) {
            TunnelDebug.error(
                why,
                "автоповторы кончились: подключусь при смене сети или включении экрана, или нажми «Подключить»"
            )
            TunnelState.status = "не удалось подключиться — нажми «Подключить»"
            postNotification(TunnelState.status)
            cancelWaits()
            return
        }
        if (!hasUsableNetwork()) {
            TunnelDebug.error(why, "сети нет — подниму туннель сам, как только она появится")
            TunnelState.phase = dev.warpscout.core.state.TunnelStatus.PHASE_NO_NETWORK
            TunnelState.status = "нет сети — подключусь, когда появится"
            postNotification(TunnelState.status)
            scheduleRevive()
            return
        }
        val pause = slowRetryDelayMs(slowRetries)
        TunnelDebug.error(
            why,
            "повторю сам через ${pauseText(pause)} (попытка $slowRetries из $SLOW_RETRY_LIMIT); " +
                "новая сеть или включённый экран — сразу"
        )
        TunnelState.status = "нет связи с WARP — повторю через ${pauseText(pause)}"
        postNotification(TunnelState.status)
        scheduleSlowRetry(slowRetries, pause)
    }

    // ------------------------------------------------------------ сам подбор, когда очередь кончилась
    //
    // Зачем. Очередь — тройка последнего подбора плюс память и дозор. Если сеть зарезала их все
    // (журнал 22.11: одна точка без данных, остальные молчат), сервис раньше только повторял те же
    // точки через растущие паузы — до ручного «Подобрать заново». Теперь он подбирает новые сам:
    // туннель всё равно не работает, и пауза на подбор ничего не стоит. Не чаще раза в
    // [RESCUE_GAP_MS]: на сети, где WARP не проходит вовсе, подбор каждые пять минут только сажал
    // бы батарею.

    private val RESCUE_GAP_MS = 30 * 60_000L

    /** Сколько точек проверять подробно: рукопожатие с шумом и данные через туннель. */
    private val RESCUE_REFINE = 8

    /**
     * Когда сервис последний раз подбирал сам — отдельно для Wi-Fi и мобильной (с 1.10.31). Пауза
     * была общей: если на мобильной подбор прошёл 10 минут назад, на новой Wi-Fi без связи сервис
     * ждал бы ещё 20 минут, хотя эта сеть — другая.
     */
    private val lastRescueAtBy = java.util.concurrent.ConcurrentHashMap<String, Long>()

    private val rescueBusy = java.util.concurrent.atomic.AtomicBoolean(false)

    /** Точки последнего подбора сервиса: в переборе на сети [rescueNet] — сразу за текущей. */
    @Volatile
    private var rescueQueue: List<String> = emptyList()

    @Volatile
    private var rescueNet: String = ""

    /**
     * Найденная точка: адрес, профиль шума, время ответа через туннель и площадка выхода (с 1.10.34;
     * null — резолвер её не назвал).
     */
    private data class RescuePoint(val endpoint: Endpoint, val junk: JunkProfile, val dataMs: Double, val site: String? = null)

    /**
     * Запустить подбор, если пора. true — подбор пошёл (дальше он решает сам), false — не время или
     * нечем (тогда — обычные медленные повторы).
     */
    private fun startRescue(why: String): Boolean {
        if (destroyed || !wanted || stopped.get()) return false
        val now = System.currentTimeMillis()
        // Ключ сети сервиса — «мобильная·25001» или «Wi-Fi·192.168.1.1»: группу берём по виду сети.
        val group = if (dev.warpscout.app.NetIdentity.isMobile(memoryNetKind())) ConfigShortlist.GROUP_MOBILE
        else ConfigShortlist.GROUP_WIFI
        val last = lastRescueAtBy[group] ?: 0L
        if (last > 0L && now - last < RESCUE_GAP_MS) return false
        val text = lastConfigText ?: return false
        val cfg = runCatching { WgConf.toWarpConfig("WARP", text) }.getOrNull() ?: return false
        val peer = runCatching { Crypto.unBase64(cfg.account.peerPublicB64) }.getOrNull()
            ?.takeIf { it.size == 32 } ?: return false
        if (!rescueBusy.compareAndSet(false, true)) return true
        lastRescueAtBy[group] = now
        val netAtStart = memoryNetKind()
        // Своё поколение ожиданий: «Выключить», новое «Включить» или смена сети отменяют подбор.
        val gen = waitGen.incrementAndGet()
        TunnelState.phase = TunnelStatus.PHASE_RECONNECTING
        TunnelState.status = "точки очереди не работают — подбираю новые"
        postNotification(TunnelState.status)
        TunnelDebug.stage("$why — подбираю новые точки сам, без нажатия (до минуты)")
        Thread({
            try {
                val found = runRescue(cfg, peer, gen)
                if (gen != waitGen.get() || destroyed || !wanted) {
                    // Подбор прервали. Если телефон перешёл на другую сеть, следующий цикл неудач на
                    // ней вправе подобрать заново, не дожидаясь получаса; на той же сети — нет, иначе
                    // включение экрана раз за разом перезапускало бы подбор и тратило батарею.
                    if (memoryNetKind() != netAtStart) lastRescueAtBy.remove(group)
                    return@Thread
                }
                if (found.isEmpty()) {
                    retryLaterAfterFailure("подбор не нашёл точек, через которые идут данные")
                } else {
                    applyRescue(found, cfg, text)
                }
            } catch (e: Throwable) {
                runCatching {
                    TunnelDebug.stage("подбор сервиса не удался: ${e.javaClass.simpleName} ${e.message.orEmpty().take(80)}")
                }
                if (gen == waitGen.get() && wanted && !destroyed) retryLaterAfterFailure(why)
            } finally {
                rescueBusy.set(false)
            }
        }, "warpscout-rescue").apply { isDaemon = true; priority = Thread.MIN_PRIORITY }.start()
        return true
    }

    /**
     * Подбор точек самим сервисом: рукопожатие по пулу без шума (параллельно), потом лучшие точки —
     * с профилями шума и проверкой данных. Туннеля в это время нет, поэтому проба данных никому не
     * мешает. Итог — до трёх точек с данными, быстрые первыми.
     */
    private fun runRescue(cfg: WarpConfig, peer: ByteArray, gen: Int, seekAbroad: Boolean = false): List<RescuePoint> {
        fun live() = gen == waitGen.get() && wanted && !destroyed
        val prober = WgProber(
            NetSettings(
                attempts = 2,
                timeoutMs = 1000,
                concurrency = 32,
                betweenAttemptsMs = 40,
                junkPacketsBeforeHandshake = 1,
                udpFactory = protectedUdp()
            )
        )
        val started = System.currentTimeMillis()
        // Известные точки (очередь, память, дозор) — вместе с пулом: вдруг какая-то ожила. Пул —
        // свежая выборка по всем подсетям (seed от времени), а не тот же срез, что не сработал.
        val known = orderedCandidates().mapNotNull { parseEndpoint(it) }
        // Поиск выхода за рубежом смотрит пул шире: площадка зависит от подсети, и нужны разные подсети.
        val pool = (known + EndpointPool.build(EndpointSpec(maxEndpoints = if (seekAbroad) 160 else 96, seed = started)))
            .distinct()
            .filter { it.family == AddrFamily.IPV4 }
        val coarse = prober.scan(pool, cfg.account, peer, junk = null, isCancelled = { !live() })
        if (!live()) return emptyList()
        val alive = coarse
            .filter { it.bestVerdict == Verdict.HANDSHAKE_OK || it.bestVerdict == Verdict.COOKIE_REPLY }
            .sortedBy { it.minRtt ?: Double.MAX_VALUE }
        TunnelDebug.stage("подбор сервиса: на рукопожатие без шума ответили ${alive.size} из ${pool.size} точек")
        // Без шума не ответил никто — сеть режет голый WireGuard: подробно смотрим точки пула с шумом.
        val ranked = if (alive.isNotEmpty()) alive.map { it.endpoint } else pool
        // Поиск выхода за рубежом (с 1.10.34): сначала по одной точке из каждой подсети — у одной
        // подсети одна площадка, и десять быстрых адресов из одной подсети дали бы десять Москв.
        val targets = if (seekAbroad) {
            (ranked.distinctBy { subnet24(it.host) } + ranked).distinct().take(RESCUE_REFINE * 2)
        } else {
            ranked.take(RESCUE_REFINE)
        }
        val profiles = rescueProfiles(cfg)
        TunnelDebug.stage("подбор сервиса: шум по порядку — " + profiles.joinToString { JunkLibrary.nameOf(it) })
        val warp = isWarpPeer(cfg)
        val net = memoryNetKind()
        val found = ArrayList<RescuePoint>()
        // Подсети, о которых уже известно «выход в России», — поиск выхода за рубежом их пропускает.
        val russianNets = HashSet<String>()
        val sites = HashMap<String, String>()
        fun enough(): Boolean = if (seekAbroad) {
            found.count { ExitSite.isAbroad(it.site) } >= dev.warpscout.core.tune.Shortlist.LIMIT
        } else {
            found.size >= dev.warpscout.core.tune.Shortlist.LIMIT
        }
        // Поиск выхода за рубежом — не дольше двух минут: туннеля всё это время нет.
        val deadline = if (seekAbroad) started + ABROAD_MAX_MS else Long.MAX_VALUE
        for (ep in targets) {
            if (!live() || enough() || System.currentTimeMillis() > deadline) break
            if (seekAbroad && subnet24(ep.host) in russianNets) continue
            for (profile in profiles) {
                if (!live()) break
                val r = runCatching {
                    prober.probe(ep, cfg.account, peer, profile.takeIf { !it.isEmpty }, dataProbe = true, askSite = true)
                }.getOrNull() ?: continue
                r.stats.site?.let { site ->
                    sites[ep.render()] = site
                    if (ExitSite.isRussian(site)) russianNets += subnet24(ep.host)
                }
                // Ищем выход за рубежом, а эта точка выходит через Россию: площадка от шума не
                // зависит — другие профили не пробуем, долгую пробу не тратим.
                if (seekAbroad && ExitSite.isRussian(r.stats.site)) break
                val ms = r.stats.dataMs ?: continue
                // Один ответ ещё ничего не обещает (журнал 22.11: подбор сервиса нашёл три точки без
                // шума «с данными», и все замерзали через секунду). Долгая проба: данные должны идти
                // и через полторы секунды. Не удалось повторить рукопожатие — верим первой пробе.
                val long = runCatching {
                    prober.probeSustained(ep, cfg.account, peer, profile.takeIf { !it.isEmpty })
                }.getOrNull()
                if (long != null && long.dataTried && !long.dataSustained) {
                    val name = JunkLibrary.nameOf(profile)
                    if (warp) runCatching { NoiseMemory.note(this, net, name, NoiseBook.FROZE, ep.render()) }
                    TunnelDebug.stage("подбор сервиса: ${ep.render()} · $name — ${long.note.take(90)}, не беру")
                    continue
                }
                found += RescuePoint(ep, profile, ms, r.stats.site)
                break // одной рабочей комбинации на точку хватает
            }
        }
        // Где выходят проверенные точки — в память площадок этой сети.
        if (sites.isNotEmpty()) runCatching { SiteMemory.noteAll(this, net, sites) }
        val siteLine = if (sites.isEmpty()) "" else {
            ", выход: " + sites.values.groupingBy { it }.eachCount().entries
                .sortedByDescending { ExitSite.rank(it.key) }
                .joinToString(", ") { "${ExitSite.describe(it.key)} — ${it.value}" }
        }
        TunnelDebug.stage(
            "подбор сервиса: точек с данными — ${found.size}, " +
                "за ${(System.currentTimeMillis() - started) / 1000} с" + siteLine
        )
        // Выход за рубежом — первыми, дальше быстрые (с 1.10.34).
        return found.sortedWith(compareByDescending<RescuePoint> { ExitSite.rank(it.site) }.thenBy { it.dataMs })
            .let { list -> if (seekAbroad) list.take(dev.warpscout.core.tune.Shortlist.LIMIT) else list }
    }

    /** Подсеть /24 адреса IPv4 («8.34.70»); не IPv4 — сам адрес. */
    private fun subnet24(host: String): String {
        val parts = host.split('.')
        return if (parts.size == 4) parts.take(3).joinToString(".") else host
    }

    /**
     * Профили шума для подбора сервиса. С 1.10.30 первыми — маски: та, с которой на этой сети уже
     * шли данные, потом по [JunkLibrary.serviceOrder] (TLS, QUIC, SIP); «без шума» — последним.
     * Шум, который на этой сети замерзает (см. NoiseMemory), не пробуем вовсе. Раньше первым шёл
     * текущий шум — а он и был «none», который здесь замерзал (журнал 22.11, 19:07: подбор сервиса
     * нашёл три точки без шума, и петля пошла по второму кругу).
     */
    private fun rescueProfiles(cfg: WarpConfig): List<JunkProfile> {
        // Свой сервер AmneziaWG: шум и параметры H/S — договорённость с сервером, их не трогаем.
        if (!isWarpPeer(cfg)) return listOf(cfg.junk)
        val net = memoryNetKind()
        val bad = runCatching { NoiseMemory.frozen(this, net) }.getOrDefault(emptySet())
        val worked = runCatching { NoiseMemory.preferred(this, net) }.getOrNull()?.let { JunkLibrary.byName(it) }
        val library = JunkLibrary.serviceOrder()
        // У разобранного из текста конфига профиль называется «imported»: возвращаем ему имя из
        // библиотеки, если шум тот же, — иначе в «Лучших конфигах» стояло бы непонятное «imported».
        val current = library.firstOrNull { sameJunk(it, cfg.junk) }?.let { cfg.junk.copy(name = it.name) } ?: cfg.junk
        val ordered = (listOfNotNull(worked) + library.filter { !it.isEmpty } + current + JunkLibrary.none())
            .distinctBy { junkKey(it) }
            .filter { JunkLibrary.nameOf(it) !in bad }
        return ordered.take(4).ifEmpty { listOf(JunkLibrary.tlsFixed()) }
    }

    private fun junkKey(p: JunkProfile): String = JunkChunk.renderAll(p.i1 + p.i2)

    private fun sameJunk(a: JunkProfile, b: JunkProfile): Boolean = junkKey(a) == junkKey(b)

    /**
     * Подбор сервиса нашёл точки: записываем их тройкой этой сети (её видно в «Лучших конфигах» и в
     * «Резервной»), ставим в перебор сразу за текущей и поднимаем туннель на лучшей.
     */
    private fun applyRescue(found: List<RescuePoint>, cfg: WarpConfig, baseText: String, keepOld: Boolean = false) {
        val kind = memoryNetKind()
        val mobile = dev.warpscout.app.NetIdentity.isMobile(kind)
        val now = System.currentTimeMillis()
        val ready = found.mapNotNull { pt ->
            val text = if (sameJunk(pt.junk, cfg.junk)) {
                swapEndpointLine(baseText, pt.endpoint.render())
            } else {
                runCatching { WgConf.render(cfg.copy(endpoint = pt.endpoint, junk = pt.junk)) }.getOrNull()
            }
            text?.takeIf { it.isNotBlank() }?.let { pt to it }
        }
        if (ready.isEmpty()) {
            retryLaterAfterFailure("подбор сервиса: конфиг для найденных точек не собрался")
            return
        }
        runCatching {
            val group = if (mobile) ConfigShortlist.GROUP_MOBILE else ConfigShortlist.GROUP_WIFI
            val fresh = ready.map { (pt, text) ->
                ConfigShortlist.Entry(
                    endpoint = pt.endpoint.render(),
                    junk = pt.junk.name,
                    score = 0,
                    resourcesOk = ConfigShortlist.UNKNOWN,
                    resourcesTotal = 0,
                    configText = text,
                    savedAt = now,
                    network = group,
                    dataMs = pt.dataMs.toInt(),
                    site = pt.site.orEmpty()
                )
            }
            // Поиск выхода за рубежом (keepOld): найденные — первыми, прежняя тройка — запасными за
            // ними. Она проверена подбором целиком, и терять её ради непроверенных сайтами точек незачем.
            val old = if (keepOld) {
                ConfigShortlist.forGroup(this, group).filter { e -> fresh.none { it.endpoint == e.endpoint } }
            } else {
                emptyList()
            }
            ConfigShortlist.save(this, (fresh + old).take(ConfigShortlist.MAX))
        }
        rescueQueue = ready.map { it.first.endpoint.render() }
        rescueNet = kind
        TunnelDebug.ok(
            "подбор сервиса нашёл новую очередь: " + ready.joinToString { (pt, _) ->
                "${pt.endpoint.render()} (шум ${pt.junk.name}, данные ${pt.dataMs.toLong()} мс" +
                    (pt.site?.let { ", выход ${ExitSite.describe(it)}" } ?: "") + ")"
            }
        )
        val best = ready.first()
        lastConfigText = best.second
        failoverOrder = emptyList()
        failoverPos = -1
        cycleSilent.clear()
        cycleTried.clear()
        // Не «с нуля»: иначе переподъём начал бы с точки, запомненной для этой сети, а она — из
        // очереди, которая только что не работала.
        rotationsSinceUp = 1
        netRestartAttempts = 0
        slowRetries = 0
        forceFastRetry = true
        autoRebind = true
        restartAfterNetworkChange("подбор нашёл ${best.first.endpoint.render()}", R.string.status_reconnect_net)
    }

    // ------------------------------------------------------------ тихий подбор для Wi-Fi (с 1.10.31)
    //
    // Сценарий из разговора 22.11: первый подбор был на мобильной, потом телефон перешёл на Wi-Fi, и
    // точки мобильной там работают — своих точек у Wi-Fi так и нет. Когда экран выключен 5 минут
    // подряд, подбираем точки для Wi-Fi тихо: туннель примерно на минуту гаснет и возвращается сам.
    // Один раз: после подбора у Wi-Fi есть свои точки (их держит дозор). Включили экран — подбор
    // прерывается, туннель сразу возвращается на прежнюю точку. Заряд ниже 20 % и не на зарядке —
    // ждём зарядки. Работающий туннель ради подбора больше ничем не прерывается.

    private val QUIET_IDLE_MS = 5 * 60_000L
    private val QUIET_MIN_BATTERY = 20

    /** На той же сети — не чаще раза в 6 часов: подбор мог ничего не найти. */
    private val QUIET_RETRY_MS = 6 * 3_600_000L

    /** Когда погас экран; 0 — горит. */
    @Volatile
    private var screenOffAt = 0L

    @Volatile
    private var quietScanRunning = false

    /** Тихий подбор прерван включением экрана — туннель возвращаем на прежнюю точку. */
    @Volatile
    private var quietAborted = false

    @Volatile
    private var quietTriedNet = ""

    @Volatile
    private var quietTriedAt = 0L

    /** Заряд в процентах (−1 — не знаем) и подключена ли зарядка. */
    private fun batteryState(): Pair<Int, Boolean> = runCatching {
        val sticky = registerReceiver(null, android.content.IntentFilter(Intent.ACTION_BATTERY_CHANGED))
        val level = sticky?.getIntExtra(android.os.BatteryManager.EXTRA_LEVEL, -1) ?: -1
        val scale = sticky?.getIntExtra(android.os.BatteryManager.EXTRA_SCALE, 100) ?: 100
        val plugged = (sticky?.getIntExtra(android.os.BatteryManager.EXTRA_PLUGGED, 0) ?: 0) != 0
        (if (level < 0 || scale <= 0) -1 else level * 100 / scale) to plugged
    }.getOrDefault(-1 to false)

    /** Пора ли тихо подобрать точки для Wi-Fi. Зовётся со строкой статистики (раз в ~5 минут). */
    private fun maybeQuietScan() {
        if (destroyed || !wanted || stopped.get() || !TunnelState.up || quietScanRunning || rescueBusy.get()) return
        val offAt = screenOffAt
        val now = System.currentTimeMillis()
        if (offAt <= 0L || isScreenOn() || now - offAt < QUIET_IDLE_MS) return
        val kind = memoryNetKind()
        if (dev.warpscout.app.NetIdentity.isMobile(kind) || !kind.startsWith(dev.warpscout.app.NetIdentity.WIFI)) return
        // Свои точки у Wi-Fi уже есть — подбирать нечего.
        val own = runCatching { ConfigShortlist.forGroup(this, ConfigShortlist.GROUP_WIFI) }.getOrDefault(emptyList())
        if (own.isNotEmpty()) return
        if (quietTriedNet == kind && now - quietTriedAt < QUIET_RETRY_MS) return
        val (pct, charging) = batteryState()
        if (pct in 0 until QUIET_MIN_BATTERY && !charging) return
        quietTriedNet = kind
        quietTriedAt = now
        startQuietScan(now - offAt)
    }

    private fun startQuietScan(idleMs: Long) {
        val text = lastConfigText ?: return
        val cfg = runCatching { WgConf.toWarpConfig("WARP", text) }.getOrNull() ?: return
        val peer = runCatching { Crypto.unBase64(cfg.account.peerPublicB64) }.getOrNull()
            ?.takeIf { it.size == 32 } ?: return
        if (!rescueBusy.compareAndSet(false, true)) return
        quietScanRunning = true
        quietAborted = false
        TunnelDebug.stage(
            "тихий подбор: у Wi-Fi нет своих точек, экран выключен ${idleMs / 60_000} мин — подбираю для этой Wi-Fi " +
                "(туннель вернётся сам, а включишь экран — сразу)"
        )
        // Сессию гасим так же, как перед переподъёмом: проба тем же ключом рядом с работающей
        // сессией отбирает её у туннеля (WARP помнит один адрес на ключ).
        epoch.incrementAndGet()
        stopped.set(true)
        TunnelState.up = false
        starting = false
        TunnelState.busy = false
        closeAll()
        stopped.set(false)
        val gen = waitGen.incrementAndGet()
        TunnelState.phase = TunnelStatus.PHASE_RECONNECTING
        TunnelState.status = "подбираю точки для этой Wi-Fi — туннель вернётся сам"
        postNotification(TunnelState.status)
        Thread({
            var found: List<RescuePoint> = emptyList()
            try {
                found = runRescue(cfg, peer, gen)
            } catch (e: Throwable) {
                runCatching {
                    TunnelDebug.stage("тихий подбор не удался: ${e.javaClass.simpleName} ${e.message.orEmpty().take(80)}")
                }
            } finally {
                rescueBusy.set(false)
                quietScanRunning = false
            }
            if (destroyed || !wanted) return@Thread
            when {
                quietAborted -> {
                    TunnelDebug.stage("тихий подбор прерван: экран включён — возвращаю туннель")
                    restartAfterNetworkChange("экран включён во время подбора", R.string.status_reconnect_net)
                }
                // Подбор отменило другое событие (смена сети, «Включить», «Выключить»): подъёмом там
                // уже занялись — сами не вмешиваемся.
                gen != waitGen.get() -> Unit
                found.isEmpty() -> {
                    TunnelDebug.stage("тихий подбор: новых точек не нашлось — возвращаю прежнюю")
                    restartAfterNetworkChange("тихий подбор окончен", R.string.status_reconnect_net)
                }
                // Найденные — в тройку Wi-Fi (тройка мобильной остаётся), туннель — на лучшую.
                else -> applyRescue(found, cfg, text)
            }
        }, "warpscout-quiet-scan").apply { isDaemon = true; priority = Thread.MIN_PRIORITY }.start()
    }

    /** Экран включили посреди тихого подбора: остановить его, туннель вернёт поток подбора. */
    private fun abortQuietScan() {
        if (!quietScanRunning) return
        quietAborted = true
        waitGen.incrementAndGet()
    }

    // ------------------------------------------------------------ поиск выхода за рубежом (с 1.10.34)
    //
    // Журнал 23.11: Wi-Fi и LTE выходили через Москву (DME) — медиа Telegram «через раз и рывками».
    // Площадку выбирает маршрут оператора, но разные подсети Cloudflare приходят на разные площадки.
    // Человек выбрал (23.11): если выход на этой сети — в России, искать точку с выходом за рубежом
    // самому, но только на зарядке с погашенным экраном и не чаще раза в сутки на сеть. Туннель
    // гаснет примерно на минуту и возвращается сам; включили экран — сразу. Выключается в
    // «Автоматике» (ServiceSettings.abroadSearch).

    /** Дольше поиск не идёт: туннеля всё это время нет. */
    private val ABROAD_MAX_MS = 120_000L

    /** Пора ли искать выход за рубежом. Зовётся со строкой статистики (раз в ~5 минут). */
    private fun maybeAbroadSearch() {
        if (destroyed || !wanted || stopped.get() || !TunnelState.up || quietScanRunning || rescueBusy.get()) return
        if (quietSession) return
        val offAt = screenOffAt
        val now = System.currentTimeMillis()
        if (offAt <= 0L || isScreenOn() || now - offAt < QUIET_IDLE_MS) return
        if (!serviceSettings().abroadSearch) return
        val site = ExitSite.fromSummary(TunnelState.linkExit)
        if (!ExitSite.isRussian(site)) return
        val (_, charging) = batteryState()
        if (!charging) return
        val kind = memoryNetKind()
        if (kind.isBlank()) return
        if (!SiteMemory.searchDue(this, kind)) return
        startAbroadSearch(site, kind, now - offAt)
    }

    private fun startAbroadSearch(site: String, kind: String, idleMs: Long) {
        val text = lastConfigText ?: return
        val cfg = runCatching { WgConf.toWarpConfig("WARP", text) }.getOrNull() ?: return
        if (!isWarpPeer(cfg)) return
        val peer = runCatching { Crypto.unBase64(cfg.account.peerPublicB64) }.getOrNull()
            ?.takeIf { it.size == 32 } ?: return
        if (!rescueBusy.compareAndSet(false, true)) return
        quietScanRunning = true
        quietAborted = false
        // Отметка поиска — до начала (пока «не нашлось»): раз в сутки на сеть, даже если поиск
        // прервут экраном, сменой сети или система закроет сервис посреди поиска.
        runCatching { SiteMemory.noteSearch(this, kind, false) }
        TunnelDebug.stage(
            "поиск выхода за рубежом: выход WARP через ${ExitSite.describe(site)}, телефон на зарядке, экран выключен " +
                "${idleMs / 60_000} мин — ищу точку с выходом за рубежом (туннель вернётся сам, а включишь экран — сразу)"
        )
        // Сессию гасим, как перед тихим подбором: проба тем же ключом рядом с работающей сессией
        // отбирает её у туннеля.
        epoch.incrementAndGet()
        stopped.set(true)
        TunnelState.up = false
        starting = false
        TunnelState.busy = false
        closeAll()
        stopped.set(false)
        val gen = waitGen.incrementAndGet()
        TunnelState.phase = TunnelStatus.PHASE_RECONNECTING
        TunnelState.status = "ищу точку с выходом за рубежом — туннель вернётся сам"
        postNotification(TunnelState.status)
        Thread({
            var found: List<RescuePoint> = emptyList()
            var failed = false
            try {
                found = runRescue(cfg, peer, gen, seekAbroad = true)
            } catch (e: Throwable) {
                failed = true
                runCatching {
                    TunnelDebug.stage("поиск выхода за рубежом не удался: ${e.javaClass.simpleName} ${e.message.orEmpty().take(80)}")
                }
            } finally {
                rescueBusy.set(false)
                quietScanRunning = false
            }
            if (destroyed || !wanted) return@Thread
            val abroad = found.filter { ExitSite.isAbroad(it.site) }
            when {
                quietAborted -> {
                    TunnelDebug.stage("поиск выхода за рубежом прерван: экран включён — возвращаю туннель, следующий поиск через сутки")
                    restartAfterNetworkChange("экран включён во время поиска", R.string.status_reconnect_net)
                }
                // Поиск отменило другое событие (смена сети, «Включить», «Выключить»): подъёмом там
                // уже занялись — сами не вмешиваемся.
                gen != waitGen.get() -> Unit
                abroad.isEmpty() -> {
                    TunnelDebug.stage(
                        if (failed) {
                            "поиск выхода за рубежом не удался — возвращаю прежнюю точку, следующий поиск через сутки"
                        } else {
                            "поиск выхода за рубежом: точек с выходом за рубежом на этой сети не нашлось — " +
                                "возвращаю прежнюю, следующий поиск через сутки"
                        }
                    )
                    restartAfterNetworkChange("поиск выхода окончен", R.string.status_reconnect_net)
                }
                else -> {
                    runCatching { SiteMemory.noteSearch(this, kind, true) }
                    TunnelDebug.ok(
                        "поиск выхода за рубежом: нашлось ${abroad.size} — " +
                            abroad.joinToString { "${it.endpoint.render()} (${ExitSite.describe(it.site)})" }
                    )
                    // Найденные — первыми в тройке этой сети, прежняя тройка — запасными за ними.
                    applyRescue(abroad, cfg, text, keepOld = true)
                }
            }
        }, "warpscout-abroad").apply { isDaemon = true; priority = Thread.MIN_PRIORITY }.start()
    }

    /** Цикл удался: промолчавшие в нём точки — в конец перебора (рядом нашлась живая, сеть ни при чём). */
    private fun commitCycleMarks() {
        val silent = synchronized(cycleSilent) {
            val copy = cycleSilent.toList()
            cycleSilent.clear()
            copy
        }
        cycleTried.clear()
        // Поднялась точка, которая в этом же цикле молчала, — значит, молчала не она, а сеть
        // (с 1.10.42; то же правило, что у дозора). Журнал 24.11, 09:45:55–09:46:09: четыре точки
        // подряд не ответили, а через полминуты первая из них подняла туннель за 118 мс. Все четыре
        // тогда ушли в конец перебора — вместе с рабочей, на которой туннель и стоял.
        val upNow = currentEndpointLine().orEmpty()
        if (upNow.isNotEmpty() && silent.contains(upNow)) {
            TunnelDebug.stage("в этом цикле молчала и точка, что поднялась ($upNow), — молчала сеть, порядок перебора не трогаю")
            return
        }
        silent.distinct().forEach { sentryMarkDead(it) }
        if (silent.isNotEmpty()) {
            TunnelDebug.stage("промолчавшие в этом цикле — в конец перебора: ${silent.distinct().joinToString(", ")}")
        }
    }

    /**
     * Пауза перед медленным повтором: сначала коротко — обрыв часто длится секунды (лифт,
     * переключение соты, роутер перезагрузился), потом реже, чтобы не тратить батарею на сеть, где
     * WARP не проходит. 12 попыток — около 50 минут, как и прежний «час».
     */
    private fun slowRetryDelayMs(attempt: Int): Long = when {
        attempt <= 1 -> 30_000L
        attempt == 2 -> 60_000L
        attempt == 3 -> 2 * 60_000L
        else -> SLOW_RETRY_EVERY_MS
    }

    private fun pauseText(ms: Long): String =
        if (ms < 60_000L) "${ms / 1000} с" else "${ms / 60_000} мин"

    /** Отменить отложенное ожидание (медленный повтор, ожидание сети): см. [waitGen]. */
    private fun cancelWaits() {
        waitGen.incrementAndGet()
    }

    /**
     * Один отложенный медленный повтор на сервис. Новый план отменяет прежний, а сработавший повтор
     * не трогает туннель, который к этому времени уже поднялся сам.
     */
    private fun scheduleSlowRetry(attempt: Int, delayMs: Long) {
        val gen = waitGen.incrementAndGet()
        Thread({
            runCatching { Thread.sleep(delayMs) }
            if (gen != waitGen.get() || destroyed || !wanted) return@Thread
            if (TunnelState.up && plane != null && worker?.isAlive == true) return@Thread
            TunnelDebug.stage("медленный повтор $attempt из $SLOW_RETRY_LIMIT")
            restartAfterNetworkChange("медленный повтор", R.string.status_reconnect_net, slowAttempt = true)
        }, "warpscout-slow-retry").apply { isDaemon = true }.start()
    }

    /**
     * Причина отказа говорит «точка не ответила», а не «сеть не пропускает».
     *
     * Разница важна: в первом случае помогает смена адреса (и ждать незачем), во втором — смена
     * адреса ничего не даст, и лучше вернуться к медленным повторам той же точки.
     */
    private fun isSilentPoint(reason: String?): Boolean {
        val r = reason.orEmpty()
        return r.contains("молчит") || r.contains("ответа не было") ||
            r.contains("порт закрыт") || r.contains("port unreachable") ||
            // «Рукопожатие есть, данных нет» — тоже про точку, а не про сеть: следующая может работать.
            isDataDead(r)
    }

    /** «Порт закрыт» (ICMP) — прямой ответ сети, а не тишина: точка мертва без оговорок. */
    private fun isClosedPort(reason: String?): Boolean {
        val r = reason.orEmpty()
        return r.contains("порт закрыт") || r.contains("port unreachable")
    }

    /** Точка, которой поднят туннель сейчас: берём строку из текста конфига, а не из настроек. */
    private fun currentEndpointLine(): String? =
        lastConfigText?.lineSequence()
            ?.firstOrNull { it.trimStart().startsWith("Endpoint") && '=' in it }
            ?.substringAfter('=')
            ?.trim()
            ?.takeIf { it.isNotEmpty() }

    /**
     * Следующая точка из очереди последнего подключения: (адрес, готовый текст конфига).
     *
     * Меняем ровно одну строку — `Endpoint = host:port`. Ключи, профиль шума и маршруты остаются
     * теми же: это тот же туннель, просто на другой anycast-адрес Cloudflare. Порядок очереди —
     * тот же, что был в «переборе» (победитель подбора первым), то есть следующая точка обычно
     * тоже проверенная.
     *
     * null — менять некуда: очередь пуста (плитка/автозапуск без подбора), в ней одна точка или
     * мы уже перебрали всё, что разрешено (MAX_ROTATIONS).
     */
    private fun nextFailoverEndpoint(): Pair<String, String>? {
        if (rotationsSinceUp >= MAX_ROTATIONS) return null
        val text = lastConfigText ?: return null
        if (failoverOrder.isEmpty()) rebuildFailoverOrder()
        if (failoverOrder.size < 2) return null
        val current = currentEndpointLine()
        val from = failoverPos.takeIf { it in failoverOrder.indices }
            ?: current?.let { failoverOrder.indexOf(it) }
            ?: -1
        for (step in 1..failoverOrder.size) {
            val idx = (from + step).mod(failoverOrder.size)
            val host = failoverOrder[idx]
            if (host == current) continue
            failoverPos = idx
            return host to swapEndpointLine(text, host)
        }
        return null
    }

    /**
     * Порядок перебора под текущую сеть: текущая точка → точка, работавшая на такой же сети →
     * очередь последнего подключения.
     *
     * Смысл в первых двух: адреса WARP не универсальны. В журнале с улицы на Wi-Fi работал
     * `162.159.192.10:500`, а на мобильной — `162.159.192.2:500`; без памяти сервис каждый раз
     * начинал с «чужой» точки, тратил на неё попытку и только потом доходил до рабочей.
     */
    private fun rebuildFailoverOrder() {
        val kind = memoryNetKind()
        // Посреди перебора порядок не трогаем. Раньше он строился заново на каждой попытке:
        // только что выбранной точкой вперёд, прежней (мёртвой) — второй, и следующий шаг вёл
        // обратно на неё. Перебор ходил между двумя мёртвыми точками и до остальных не доходил.
        // Новый порядок — в начале цикла, на другой сети или если его ещё нет.
        if (rotationsSinceUp > 0 && failoverOrder.isNotEmpty() && kind == failoverNet) return
        val current = currentEndpointLine()
        val remembered = runCatching { EndpointMemory.goodFor(this, kind) }.getOrNull()
        failoverOrder = orderedCandidates()
        failoverNet = kind
        failoverPos = current?.let { failoverOrder.indexOf(it) } ?: -1
        val backup = runCatching { backupFor(serviceSettings(), kind) }.getOrDefault("").trim()
        if (backup.isNotEmpty() && backup != current && !sentryDead(kind, backup)) {
            TunnelDebug.stage(
                "резервная точка ${if (dev.warpscout.app.NetIdentity.isMobile(kind)) "мобильной сети" else "Wi-Fi"}, " +
                    "выбранная вручную: $backup — она в переборе вторая"
            )
        } else if (remembered != null && remembered != current && !sentryDead(kind, remembered)) {
            TunnelDebug.stage("на сети «$kind» работала $remembered — она в переборе вторая")
        }
        // Сеть могла смениться — метки в снимке должны быть про неё.
        publishMarks()
        // Если порядок поправил дозор — показываем его в журнале: иначе не понять, почему сервис
        // пошёл не на следующую точку очереди, а через одну.
        if (failoverOrder.size > 1 && failoverOrder.any { it != current && sentryMarks.containsKey("$kind|$it") }) {
            TunnelDebug.stage("перебор с учётом дозора: " + failoverOrder.take(6).joinToString(", "))
        }
    }

    /**
     * Точки в порядке перебора для текущей сети. Состояние не меняет: им пользуются и перебор,
     * и дозор.
     *
     * Текущая → работавшая на такой же сети → живые по дозору (свежие первыми) → очередь
     * последнего подключения. Те, кого дозор дважды подряд застал мёртвыми, — в конец, но не вон:
     * точка может ожить, а мёртвыми могут оказаться и все сразу.
     */
    private fun orderedCandidates(): List<String> {
        val kind = memoryNetKind()
        val now = System.currentTimeMillis()
        val settings = runCatching { serviceSettings() }.getOrDefault(dev.warpscout.core.state.ServiceSettings())
        val queue = settings.failover
            .map { it.trim() }
            .filter { it.isNotEmpty() }
        // Тройка подбора именно для этой сети (Wi-Fi или мобильной) — раньше общей очереди.
        val netList = (if (dev.warpscout.app.NetIdentity.isMobile(kind)) settings.listMobile else settings.listWifi)
            .map { it.trim() }
            .filter { it.isNotEmpty() }
        val current = currentEndpointLine()
        val remembered = runCatching { EndpointMemory.goodFor(this, kind) }.getOrNull()
        // Резервная точка этой сети, выбранная человеком: на неё — первой после текущей.
        val backup = backupFor(settings, kind).trim().takeIf { it.isNotEmpty() }
        val prefix = "$kind|"
        val fresh = sentryMarks.entries
            .filter { (key, mark) ->
                key.startsWith(prefix) && mark.fails == 0 && mark.okAt > 0 && now - mark.okAt < SENTRY_FRESH_MS
            }
            .sortedByDescending { it.value.okAt }
            .map { it.key.removePrefix(prefix) }
        // Точки, которые сервис только что подобрал сам (см. applyRescue): проверены данными минуту
        // назад — раньше старой очереди и резервной из неё.
        val rescued = if (rescueNet == kind) rescueQueue else emptyList()
        val head = buildList {
            if (current != null) add(current)
            addAll(rescued)
            if (backup != null) add(backup)
        }
        val tail = buildList {
            if (remembered != null) add(remembered)
            addAll(fresh)
            addAll(netList)
            addAll(queue)
        }.distinct().filter { it !in head }
        // С 1.10.34 среди остальных точек — сначала те, что на этой сети выходили за рубежом, потом
        // неизвестные, московские — последними (см. SiteMemory). Резервная, выбранная человеком, и
        // только что подобранные остаются впереди: это решения, а не догадки.
        val sites = runCatching { SiteMemory.sitesFor(this, kind) }.getOrDefault(emptyMap())
        val all = (head + ExitSite.abroadFirst(tail) { sites[it] }).distinct()
        val (dead, alive) = all.partition { it != current && sentryDead(kind, it, now) }
        return alive + dead
    }

    /** Резервная точка для сети [kind]: своя у мобильной, своя у Wi-Fi (и прочих). */
    private fun backupFor(settings: dev.warpscout.core.state.ServiceSettings, kind: String): String =
        if (dev.warpscout.app.NetIdentity.isMobile(kind)) settings.backupMobile else settings.backup

    /** Точка не поднялась при переподключении: для перебора это то же, что две неудачные пробы. */
    private fun sentryMarkDead(endpoint: String) {
        val key = "${memoryNetKind()}|$endpoint"
        val before = sentryMarks[key] ?: SentryMark()
        sentryMarks[key] = SentryMark(okAt = before.okAt, fails = 2, failAt = System.currentTimeMillis())
        publishMarks()
    }

    /** Дозор дважды подряд не достучался до точки на этой сети, и было это недавно. */
    private fun sentryDead(kind: String, endpoint: String, now: Long = System.currentTimeMillis()): Boolean {
        val mark = sentryMarks["$kind|$endpoint"] ?: return false
        return mark.fails >= 2 && now - mark.failAt < SENTRY_DEAD_MS
    }

    // ------------------------------------------------------------ дозор

    /**
     * Дозор для только что поднятой сессии. Прежний поток гасим: у каждой сессии свой дозор, и
     * живёт он ровно столько, сколько её эпоха.
     */
    private fun startSentry(cfg: WarpConfig, myEpoch: Int) {
        runCatching { sentryThread?.interrupt() }
        sentryThread = null
        if (sentryBanned) return
        // Ключ сервера — 32 байта; без него проба ничего не докажет.
        val peerPublic = runCatching { Crypto.unBase64(cfg.account.peerPublicB64) }.getOrNull()
            ?.takeIf { it.size == 32 } ?: return
        val thread = Thread({
            try {
                sentryLoop(cfg, peerPublic, myEpoch)
            } catch (e: InterruptedException) {
                // штатная остановка вместе с сессией
            } catch (e: Throwable) {
                runCatching {
                    TunnelDebug.stage("дозор остановлен: ${e.javaClass.simpleName} ${e.message.orEmpty().take(80)}")
                }
            }
        }, "warpscout-sentry")
        thread.isDaemon = true
        thread.priority = Thread.MIN_PRIORITY
        sentryThread = thread
        thread.start()
    }

    private fun sentryLoop(cfg: WarpConfig, peerPublic: ByteArray, myEpoch: Int) {
        fun alive() = myEpoch == epoch.get() && !stopped.get() && !sentryOff && !sentryBanned
        var errorPasses = 0
        Thread.sleep(SENTRY_FIRST_MS)
        while (alive()) {
            // Только при живом туннеле и настоящей сети: во время переподъёма пробы бессмысленны.
            // На медленной связи (с 1.10.40) не ходит: пробы под нагрузкой метили бы живые точки молчащими.
            if (TunnelState.up && hasUsableNetwork() && !slowRadio()) {
                errorPasses = if (sentryPass(cfg, peerPublic, myEpoch) == SENTRY_ERRORS) errorPasses + 1 else 0
                if (errorPasses >= 3) {
                    sentryOff = true
                    TunnelDebug.stage("дозор: пробы не уходят (ошибки сокета) — выключен до переподключения")
                    return
                }
            }
            Thread.sleep(SENTRY_EVERY_MS)
        }
    }

    /**
     * Один обход: ближайшая по очереди точка и ещё одна по кругу.
     *
     * Ближайшая — та, на которую сервис перейдёт при аварии: знать про неё важнее всего. Вторая
     * перебирает остальные, чтобы со временем была проверена вся очередь.
     */
    private fun sentryPass(cfg: WarpConfig, peerPublic: ByteArray, myEpoch: Int): Int {
        val kind = memoryNetKind()
        val current = currentEndpointLine()
        val candidates = orderedCandidates().filter { it != current }
        if (candidates.isEmpty()) return SENTRY_IDLE
        val picks = buildList {
            add(candidates.first())
            val rest = candidates.drop(1)
            if (rest.isNotEmpty()) add(rest[(sentryPos++).mod(rest.size)])
        }
        val prober = WgProber(
            NetSettings(
                attempts = 1,
                timeoutMs = 1500,
                betweenAttemptsMs = 0,
                junkPacketsBeforeHandshake = 1,
                udpFactory = protectedUdp()
            )
        )
        // Сначала пробы, выводы — потом: молчание всех точек ещё надо отличить от молчания сети.
        val results = ArrayList<Triple<String, Verdict, Double?>>()
        for (line in picks) {
            if (myEpoch != epoch.get() || stopped.get() || !TunnelState.up) return SENTRY_IDLE
            val endpoint = parseEndpoint(line) ?: continue
            val (verdict, rtt) = sentryProbe(prober, endpoint, cfg, peerPublic)
            results += Triple(line, verdict, rtt)
        }
        if (myEpoch != epoch.get() || stopped.get()) return SENTRY_IDLE

        // Все выбранные точки промолчали. Это две разные вещи: точки и правда закрыли — или сеть
        // сейчас не пропускает НОВЫЕ соединения к WARP, не трогая уже идущее (так ведёт себя DPI).
        // Диагностика-8: с 05:34 все пробы дозора «молчат», а туннель на 188.114.97.1:500 жив и
        // делает rekey с первой инициации — и все запасные точки ушли в «мёртвые» зря. Различаем
        // одной контрольной пробой текущей точки с нового сокета: туннель на ней работает, и если
        // с нового порта молчит и она, виновата сеть, а не точки. Тогда метки точек не трогаем.
        var networkBlocks = false
        var controlNote: String? = null
        if (results.isNotEmpty() && results.all { it.second == Verdict.UDP_SILENT } && current != null) {
            val control = parseEndpoint(current)
            if (control != null && TunnelState.up) {
                val (cv, crtt) = sentryProbe(prober, control, cfg, peerPublic)
                if (myEpoch != epoch.get() || stopped.get()) return SENTRY_IDLE
                if (cv == Verdict.HANDSHAKE_OK || cv == Verdict.COOKIE_REPLY) {
                    controlNote = "контроль: текущая $current с нового порта ✓" +
                        (crtt?.let { " ${it.toLong()} мс" } ?: "") + " — молчат именно эти точки"
                } else {
                    networkBlocks = true
                    controlNote = "контроль: текущая $current с нового порта тоже молчит, а туннель на ней жив — " +
                        "новые соединения к WARP сейчас не проходят, точки мёртвыми не считаю"
                }
            }
        }

        val notes = ArrayList<String>()
        var learned = networkBlocks
        val now = System.currentTimeMillis()
        for ((line, verdict, rtt) in results) {
            val key = "$kind|$line"
            val before = sentryMarks[key] ?: SentryMark()
            when (verdict) {
                Verdict.HANDSHAKE_OK, Verdict.COOKIE_REPLY -> {
                    learned = true
                    sentryMarks[key] = SentryMark(okAt = now)
                    notes += "$line ✓" + (rtt?.let { " ${it.toLong()} мс" } ?: "")
                }
                Verdict.UDP_CLOSED -> {
                    // ICMP «порт закрыт» — ответ сети, а не потеря пакета: мертва сразу.
                    learned = true
                    sentryMarks[key] = SentryMark(okAt = before.okAt, fails = 2, failAt = now)
                    notes += "$line ✗ порт закрыт — в конец перебора"
                }
                Verdict.UDP_SILENT -> {
                    if (networkBlocks) {
                        // Молчит сеть, а не точка: прежняя отметка точки остаётся как была.
                        notes += "$line ✗ молчит"
                    } else {
                        learned = true
                        val fails = before.fails + 1
                        sentryMarks[key] = SentryMark(okAt = before.okAt, fails = fails, failAt = now)
                        notes += "$line ✗ молчит" + if (fails >= 2) " ($fails-й раз — в конец перебора)" else ""
                    }
                }
                else -> notes += "$line ? не проверена (${verdict.name.lowercase()})"
            }
        }
        controlNote?.let { notes += it }
        if (notes.isNotEmpty()) TunnelDebug.stage("дозор: " + notes.joinToString("; "))
        if (learned) publishMarks()
        return if (learned) SENTRY_INFO else if (notes.isEmpty()) SENTRY_IDLE else SENTRY_ERRORS
    }

    /**
     * До двух инициаций на точку. Ответ на любую — точка жива. «Порт закрыт» (ICMP) — мертва,
     * второй пакет не нужен. Молчание повторяем один раз: UDP теряется и на живой точке.
     * Возвращает вердикт и время ответа.
     */
    private fun sentryProbe(
        prober: WgProber,
        endpoint: Endpoint,
        cfg: WarpConfig,
        peerPublic: ByteArray
    ): Pair<Verdict, Double?> {
        var verdict = Verdict.ERROR
        var rtt: Double? = null
        for (attempt in 0 until 2) {
            val result = prober.probe(endpoint, cfg.account, peerPublic, cfg.junk)
            lastSentryProbeAt = System.currentTimeMillis()
            // Если сервер принял пробу за роуминг — один пакет текущей сессии возвращает адрес назад.
            runCatching { plane?.keepaliveNow() }
            verdict = result.stats.bestVerdict
            rtt = result.stats.minRtt
            if (result.accepted || verdict != Verdict.UDP_SILENT) break
        }
        return verdict to rtt
    }

    /** UDP-сокет пробы мимо туннеля: без protect() проба ушла бы внутрь WARP («WARP через WARP»). */
    private fun protectedUdp(): UdpSocketFactory = UdpSocketFactory { _ ->
        val socket = DatagramSocket(null).apply { reuseAddress = true }
        if (!runCatching { protect(socket) }.getOrDefault(false)) {
            runCatching { socket.close() }
            throw java.io.IOException("protect() отказал")
        }
        socket
    }

    /** «host:port» или «[v6]:port» → [Endpoint]; всё прочее (имена записей, мусор) — null. */
    private fun parseEndpoint(text: String): Endpoint? = runCatching {
        val t = text.trim()
        val host: String
        val port: Int
        if (t.startsWith("[")) {
            host = t.substring(1, t.indexOf(']'))
            port = t.substringAfterLast("]:").toInt()
        } else {
            host = t.substringBeforeLast(':')
            port = t.substringAfterLast(':').toInt()
        }
        if (host.isBlank() || host.any { it.isWhitespace() }) null else Endpoint(host, port)
    }.getOrNull()

    /**
     * С чего начинать подъём после смены сети: если на такой же сети уже работала конкретная
     * точка — начинаем сразу с неё. Это и есть «переключается быстро»: без лишней неудачной
     * попытки на адресе, который в этой сети закрыт.
     */
    private fun preferredStartText(text: String): String {
        val current = endpointOf(text)
        val kind = memoryNetKind()
        val remembered = runCatching { EndpointMemory.goodFor(this, kind) }.getOrNull() ?: return text
        if (remembered == current) return text
        // Дозор недавно дважды не достучался до неё — начинать с неё значит потерять попытку.
        if (sentryDead(kind, remembered)) return text
        TunnelDebug.stage("на «$kind» работала $remembered — начинаю с неё, а не с $current")
        return swapEndpointLine(text, remembered)
    }

    /** Строка Endpoint из произвольного текста конфига. */
    private fun endpointOf(text: String): String? =
        text.lineSequence()
            .firstOrNull { it.trimStart().startsWith("Endpoint") && '=' in it }
            ?.substringAfter('=')?.trim()?.takeIf { it.isNotEmpty() }

    /** Текст конфига с другой строкой `Endpoint =`. Всё остальное байт в байт прежнее. */
    private fun swapEndpointLine(text: String, endpoint: String): String =
        text.lineSequence().joinToString("\n") { line ->
            if (line.trimStart().startsWith("Endpoint") && '=' in line) "Endpoint = $endpoint" else line
        }

    /**
     * Ждём исход попытки: поднялся / провалился / не дождались.
     *
     * Раньше здесь было только «поднялся или нет», и провал выяснялся лишь по концу окна: точка
     * отвечала «порт закрыт» за 0,5 с, а сервис ещё 14,5 с ждал, прежде чем взять следующую. В
     * журнале это ровно те паузы между «✗ handshake не прошёл» и «перехожу на …» — две мёртвые
     * точки стоили полминуты, хотя работы там на две секунды.
     */
    private fun awaitAttempt(timeoutMs: Int): Int {
        val deadline = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < deadline) {
            if (stopped.get()) return ATTEMPT_FAILED
            if (TunnelState.up) return ATTEMPT_UP
            // Сервис уже сказал, что попытка кончилась: handshake не прошёл, ошибка записана.
            if (TunnelState.phase == dev.warpscout.core.state.TunnelStatus.PHASE_FAILED) return ATTEMPT_FAILED
            if (TunnelState.error != null && !starting) return ATTEMPT_FAILED
            runCatching { Thread.sleep(100) }
        }
        return if (TunnelState.up) ATTEMPT_UP else ATTEMPT_TIMEOUT
    }

    /** Wi-Fi / мобильная / Ethernet по возможностям сети — ключ для памяти точек. */
    private fun kindOf(caps: android.net.NetworkCapabilities?): String = when {
        caps == null -> ""
        caps.hasTransport(android.net.NetworkCapabilities.TRANSPORT_WIFI) -> "Wi-Fi"
        caps.hasTransport(android.net.NetworkCapabilities.TRANSPORT_CELLULAR) -> "мобильная"
        caps.hasTransport(android.net.NetworkCapabilities.TRANSPORT_ETHERNET) -> "Ethernet"
        else -> ""
    }

    /**
     * Запомнить сеть, на которой поднимались: по ней выбирается первая точка. Ключ — с оператором
     * или шлюзом (см. NetIdentity): у двух операторов разные фильтры, и точки помнятся отдельно.
     */
    private fun rememberNetKind(network: android.net.Network) {
        val kind = runCatching {
            val cm = getSystemService(android.net.ConnectivityManager::class.java)
            dev.warpscout.app.NetIdentity.keyOf(this, network, cm?.getNetworkCapabilities(network))
        }.getOrDefault("")
        if (kind.isNotEmpty()) lastNetKind = kind
    }

    /**
     * Тип связи сети туннеля сейчас (с 1.10.40): известной сети туннеля, иначе — системной сети по
     * умолчанию (до подъёма точки отсчёта ещё нет).
     */
    private fun currentRadio(): String {
        val known = tunnelRadio
        if (known.isNotEmpty() || baselineNetwork != null) return known
        return runCatching { dev.warpscout.app.NetIdentity.radioOf(this, underlyingNetwork()) }.getOrDefault("")
    }

    /**
     * Медленная мобильная связь — H+, H, 3G, EDGE (с 1.10.40). На ней задержка под нагрузкой доходит
     * до секунд: окна рукопожатия и проверки данных шире, тяжёлые проверки после подъёма не идут, а
     * замерзания шуму не приписываются (журнал 23.11, 15:13–15:56: пинг 1157 мс, замер 1,1 Мбит/с).
     */
    private fun slowRadio(): Boolean = dev.warpscout.app.NetIdentity.isSlowRadio(currentRadio())

    /**
     * Запомнить тип связи сети туннеля. Сменился — пояснения про медленную связь снова пишутся один раз;
     * [announce] — строка «мобильная связь: LTE → H+» (смена типа на той же сети).
     */
    private fun updateRadio(network: android.net.Network?, announce: Boolean = false) {
        val radio = runCatching { dev.warpscout.app.NetIdentity.radioOf(this, network) }.getOrDefault("")
        val was = tunnelRadio
        if (radio == was) return
        tunnelRadio = radio
        slowRadioSaid.clear()
        if (announce && radio.isNotEmpty() && was.isNotEmpty()) TunnelDebug.stage("мобильная связь: $was → $radio")
    }

    /** Пояснение про медленную связь — один раз на тип связи, а не на каждом подъёме. */
    private fun noteSlowRadio(what: String) {
        val radio = currentRadio()
        if (slowRadioSaid.add("$radio|$what")) TunnelDebug.stage("медленная мобильная связь ($radio): $what")
    }

    /** Вид сети для памяти точек: последний известный, иначе — по активной сети. */
    private fun memoryNetKind(): String = lastNetKind.ifBlank {
        runCatching { dev.warpscout.app.NetIdentity.currentKey(this) }.getOrDefault("").ifBlank { netKind() }
    }

    /**
     * Сеть, через которую сейчас пойдёт защищённый сокет: системная сеть по умолчанию, если это не
     * VPN. Наш tun к этому моменту закрыт (подъём всегда начинается с закрытия прежнего), поэтому
     * система отдаёт настоящую сеть. Если она всё ещё называет VPN — честно не знаем (null), и
     * точку отсчёта поставит первое событие сети, как раньше.
     */
    private fun underlyingNetwork(): android.net.Network? = runCatching {
        val cm = getSystemService(android.net.ConnectivityManager::class.java) ?: return@runCatching null
        val network = cm.activeNetwork ?: return@runCatching null
        val caps = cm.getNetworkCapabilities(network) ?: return@runCatching null
        if (caps.hasTransport(android.net.NetworkCapabilities.TRANSPORT_VPN)) null else network
    }.getOrNull()

    /** Есть ли хоть одна настоящая (не наша VPN) сеть с интернетом. */
    private fun hasUsableNetwork(): Boolean = runCatching {
        val cm = getSystemService(android.net.ConnectivityManager::class.java) ?: return@runCatching true
        cm.allNetworks.any { n ->
            val caps = cm.getNetworkCapabilities(n) ?: return@any false
            caps.hasCapability(android.net.NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
                caps.hasCapability(android.net.NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
        }
    }.getOrDefault(true)

    /**
     * Сеть, которую система признала рабочей: есть интернет, это не наш VPN и проверка доступа
     * пройдена (`NET_CAPABILITY_VALIDATED`).
     */
    private fun hasValidatedNetwork(): Boolean = runCatching {
        val cm = getSystemService(android.net.ConnectivityManager::class.java) ?: return@runCatching true
        cm.allNetworks.any { n ->
            val caps = cm.getNetworkCapabilities(n) ?: return@any false
            caps.hasCapability(android.net.NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
                caps.hasCapability(android.net.NetworkCapabilities.NET_CAPABILITY_NOT_VPN) &&
                caps.hasCapability(android.net.NetworkCapabilities.NET_CAPABILITY_VALIDATED)
        }
    }.getOrDefault(true)

    /**
     * Ждём готовности сети перед попыткой: сразу после включения Wi-Fi адрес ещё раздаётся, а
     * портал проверки доступа не пройден — четыре инициации в это время уходят в никуда и тратят
     * модем. Ждём не больше трёх секунд: если сеть так и не «подтвердилась», пробуем как есть —
     * на части прошивок VALIDATED не выставляется вообще.
     */
    private fun awaitNetworkReady(timeoutMs: Long): Boolean {
        val deadline = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < deadline) {
            if (stopped.get()) return false
            if (hasValidatedNetwork()) return true
            runCatching { Thread.sleep(100) }
        }
        return hasValidatedNetwork()
    }

    /**
     * Ждём возвращения сети после вынужденного снятия туннеля и поднимаем его сами.
     *
     * Одна проверка раз в 15 секунд — это системный вызов, радио она не будит. Дольше держать
     * бессмысленно: сеть либо есть, либо нет.
     */
    private fun scheduleRevive() {
        // Ожидание одно на сервис: новое отменяет прежнее (см. [waitGen]). Раньше флаг «уже жду»
        // мог остаться от ожидания, которое уже никому не нужно, и новое тогда не заводилось.
        val gen = waitGen.incrementAndGet()
        reviving = true
        Thread({
            try {
                while (gen == waitGen.get() && wanted && !destroyed && !TunnelState.up) {
                    runCatching { Thread.sleep(15_000) }
                    if (gen != waitGen.get() || !wanted || destroyed || TunnelState.up) return@Thread
                    if (!hasUsableNetwork()) continue
                    if (lastConfigText == null) return@Thread
                    TunnelDebug.stage("сеть вернулась — поднимаю туннель без нажатия")
                    // Бюджет быстрых попыток для этого случая не тратим: сеть только что появилась.
                    forceFastRetry = true
                    autoRebind = true
                    netRestartAttempts = 0
                    rotationsSinceUp = 0
                    restartAfterNetworkChange("сеть вернулась сама", R.string.status_reconnect_net)
                    return@Thread
                }
            } finally {
                reviving = false
            }
        }, "warpscout-net-revive").apply { isDaemon = true }.start()
    }

    companion object {
        /** Живой экземпляр сервиса в этом процессе (см. onCreate). */
        @Volatile
        private var live: WarpVpnService? = null

        const val ACTION_START = "dev.warpscout.app.tunnel.START"
        const val ACTION_STOP = "dev.warpscout.app.tunnel.STOP"

        /** Проверить точку рядом с работающим туннелем (см. handleProbe). */
        const val ACTION_PROBE = "dev.warpscout.app.tunnel.PROBE"

        /** Проверить связь через туннель (см. handleCheckRequest). */
        const val ACTION_CHECK = "dev.warpscout.app.tunnel.CHECK"

        /** Поднять последнюю рабочую конфигурацию: после загрузки и обновления (см. TunnelAutoStart). */
        const val ACTION_AUTOSTART = "dev.warpscout.app.tunnel.AUTOSTART"

        /** Замерить скорость через туннель полной загрузкой (см. handleSpeedRequest). */
        const val ACTION_SPEED = "dev.warpscout.app.tunnel.SPEED"

        /** Адреса второго выхода обновились: сменить таблицу на лету (см. handleSecondRoutes). */
        const val ACTION_SECOND_ROUTES = "dev.warpscout.app.tunnel.SECOND_ROUTES"

        /** План обхода DPI или его переключатель поменялись (с 1.10.49-beta3, см. handleDpiReload). */
        const val ACTION_DPI_RELOAD = "dev.warpscout.app.tunnel.DPI_RELOAD"

        /** Ответ на вопрос про Telegram (с 1.10.36, см. handleTelegramAnswer): «Переключить» / «Оставить». */
        const val ACTION_TG_SWITCH = "dev.warpscout.app.tunnel.TG_SWITCH"
        const val ACTION_TG_STAY = "dev.warpscout.app.tunnel.TG_STAY"

        /** Сеть, о которой задан вопрос про Telegram. */
        const val EXTRA_NET = "net"

        /** Старт для проверки в подборе: без автозамера скорости (подбор мерит сам). */
        const val EXTRA_QUIET = "quiet"

        /** Внутренний код «адрес замера вне туннеля» для SpeedTest.Result.state. */
        private const val SPEED_BYPASS_CODE = 99
        const val EXTRA_CONF = "conf"
        const val EXTRA_ENDPOINT = "endpoint"
        const val EXTRA_PROBE_ID = "probeId"
        const val EXTRA_REASON = "reason"

        /** STOP по просьбе человека: после него автоматика туннель не включает. */
        const val EXTRA_BY_USER = "byUser"

        /**
         * Когда человек начал подключение (мс). Если туннель после этого выключили вручную, старт
         * опоздал и пропускается — см. onStartCommand.
         */
        const val EXTRA_REQUESTED_AT = "requestedAt"
        private const val CHANNEL = "warpscout.tunnel.quiet"
        private const val LEGACY_CHANNEL = "warpscout.tunnel"
        private const val NOTIF_ID = 4200

        /** Уведомление с вопросом про Telegram (с 1.10.36): своё, не туннельное. */
        private const val NOTIF_ASK_ID = 4201

        /** Уведомление «Telegram закреплён за WARP, а медиа не грузится» (с 1.10.44-beta1). */
        private const val NOTIF_TG_NOTE_ID = 4202

        /** Не чаще раза в 6 часов — об одном и том же. */
        private const val TG_PINNED_WARN_GAP_MS = 6 * 60 * 60_000L

        /** Страны второго выхода, далёкие от серверов Telegram в Амстердаме (с 1.10.44-beta1). */
        private val TG_FAR_COUNTRIES = setOf("US", "CA", "MX", "JP", "SG")

        /** Пометка проверки связи «ответ пришёл, но не через WARP» — по ней узнаём «трафик мимо туннеля». */
        private const val BYPASS_WARP_NOTE = "ответ пришёл мимо WARP"

        /** «Трафик мимо туннеля» переподнимаем не чаще раза в 15 минут (с 1.10.44-beta1). */
        private const val BYPASS_HEAL_GAP_MS = 15 * 60_000L

        /** Замер после подъёма не повторяем, если на той же точке и сети он был так недавно и прошёл (с 1.10.44-beta1). */
        private const val UP_SPEED_GAP_MS = 10 * 60_000L

        fun start(context: Context, config: WarpConfig, requestedAt: Long = 0L, quiet: Boolean = false) =
            startWithText(context, WgConf.render(config), requestedAt, quiet)

        /**
         * Запуск готовым текстом конфига. Нужен плитке быстрых настроек: она не собирает конфиг
         * заново, а берёт последний использованный ([Prefs.lastConfigText]) — то есть ровно то,
         * что в последний раз реально работало.
         */
        fun startWithText(context: Context, text: String, requestedAt: Long = 0L, quiet: Boolean = false) {
            // Новая попытка: результат прежней не должен влиять на неё. Без этого интерфейс
            // успевал прочитать старое «туннель работает» или «сдался» из предыдущего снимка и
            // делал вывод по устаревшим данным. Здесь это покрывает все пути запуска: кнопку,
            // плитку, верификацию из-под туннеля и перебор точек.
            TunnelState.forgetAttempt()
            val intent = Intent(context, WarpVpnService::class.java).apply {
                action = ACTION_START
                putExtra(EXTRA_CONF, text)
                if (requestedAt > 0L) putExtra(EXTRA_REQUESTED_AT, requestedAt)
                if (quiet) putExtra(EXTRA_QUIET, true)
            }
            // startForegroundService из фона на Android 12+ может быть запрещён
            // (ForegroundServiceStartNotAllowedException). Тогда пробуем обычный startService:
            // он тоже поднимет сервис, а startForeground мы вызываем сами в onStartCommand.
            val first = runCatching { context.startForegroundService(intent) }
            if (first.isFailure) {
                val why = first.exceptionOrNull()
                TunnelState.status = "сервис не запустился: ${why?.message}"
                TunnelDebug.error("сервис не запустился: ${why?.javaClass?.simpleName} ${why?.message}")
                dev.warpscout.app.CrashLog.note(
                    context, "startForegroundService отказал: ${why?.javaClass?.simpleName}: ${why?.message}"
                )
                runCatching { context.startService(intent) }
                    .onFailure { TunnelState.status = "сервис не запустился: ${it.message}" }
            }
        }

        /**
         * Попросить проверить точку рядом с работающим туннелем. Обычный startService: зовёт его
         * открытый экран, и требования «уведомление за 5 с» у такой команды нет.
         */
        fun probe(context: Context, endpoint: String, id: Long): Boolean = runCatching {
            context.startService(
                Intent(context, WarpVpnService::class.java).apply {
                    action = ACTION_PROBE
                    putExtra(EXTRA_ENDPOINT, endpoint)
                    putExtra(EXTRA_PROBE_ID, id)
                }
            )
            true
        }.getOrDefault(false)

        /** Попросить проверить связь через туннель (итог придёт в снимке состояния). */
        fun requestLinkCheck(context: Context) {
            runCatching {
                context.startService(Intent(context, WarpVpnService::class.java).apply { action = ACTION_CHECK })
            }
        }

        /** Попросить полный замер скорости через туннель (итог придёт в снимке состояния). */
        fun requestSpeedTest(context: Context) {
            runCatching {
                context.startService(Intent(context, WarpVpnService::class.java).apply { action = ACTION_SPEED })
            }
        }

        /** Сообщить сервису, что адреса второго выхода обновились (см. handleSecondRoutes). */
        fun reloadSecondRoutes(context: Context) {
            runCatching {
                context.startService(Intent(context, WarpVpnService::class.java).apply { action = ACTION_SECOND_ROUTES })
            }
        }

        /** Сообщить сервису, что план обхода DPI или его переключатель поменялись (см. handleDpiReload). */
        fun reloadDpi(context: Context) {
            runCatching {
                context.startService(Intent(context, WarpVpnService::class.java).apply { action = ACTION_DPI_RELOAD })
            }
        }

        /** Ответ на вопрос про Telegram с экрана (уведомления выключены — см. MainActivity.maybeAskTelegram). */
        fun answerTelegram(context: Context, switch: Boolean) {
            runCatching {
                context.startService(Intent(context, WarpVpnService::class.java).apply {
                    action = if (switch) ACTION_TG_SWITCH else ACTION_TG_STAY
                })
            }
        }

        /**
         * Автоподъём (загрузка телефона, обновление приложения). Решение «поднимать ли» сервис
         * перепроверяет сам: выключенный вручную туннель не включится и отсюда.
         */
        fun autoStart(context: Context, reason: String) {
            val intent = Intent(context, WarpVpnService::class.java).apply {
                action = ACTION_AUTOSTART
                putExtra(EXTRA_REASON, reason)
            }
            val first = runCatching { context.startForegroundService(intent) }
            if (first.isFailure) {
                val why = first.exceptionOrNull()
                TunnelDebug.error("автоподъём: сервис не запустился: ${why?.javaClass?.simpleName} ${why?.message}")
            }
        }

        /** Сервис сдался (ошибка/таймаут) — ждать больше нечего. */
        fun gaveUp(): Boolean = TunnelState.gaveUp

        /** Причина, по которой сдался. */
        fun failureReason(): String? = TunnelState.error

        fun stop(context: Context, byUser: Boolean = false) {
            runCatching {
                context.startService(
                    Intent(context, WarpVpnService::class.java).apply {
                        action = ACTION_STOP
                        putExtra(EXTRA_BY_USER, byUser)
                    }
                )
            }
        }

        /** Ждём, пока сервис реально освободится: следующий старт иначе упрётся в «уже поднимается». */
        fun waitDown(timeoutMs: Int): Boolean {
            val deadline = System.currentTimeMillis() + timeoutMs
            while (System.currentTimeMillis() < deadline) {
                if (!TunnelState.busy) return true
                Thread.sleep(50)
            }
            return !TunnelState.busy
        }

        /**
         * Поднять и дождаться handshake (для проверки ресурсов из-под туннеля). [isCancelled] —
         * «Остановить подбор»: ожидание прерывается сразу, а не по истечении всего окна.
         */
        fun startAndWait(
            context: Context,
            config: WarpConfig,
            timeoutMs: Int,
            isCancelled: () -> Boolean = { false }
        ): Boolean {
            start(context, config, quiet = true)
            val deadline = System.currentTimeMillis() + timeoutMs.coerceAtLeast(2000)
            while (System.currentTimeMillis() < deadline && !isCancelled()) {
                if (TunnelState.up) return true
                Thread.sleep(200)
            }
            stop(context)
            return false
        }
    }
}
