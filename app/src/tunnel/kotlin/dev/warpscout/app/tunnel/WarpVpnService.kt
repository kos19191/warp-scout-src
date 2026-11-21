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
import dev.warpscout.app.EndpointMemory
import dev.warpscout.app.R
import dev.warpscout.app.TunnelDebug
import dev.warpscout.core.config.SplitRoutes
import dev.warpscout.core.config.WgConf
import dev.warpscout.core.model.WarpConfig
import dev.warpscout.core.net.NetSettings
import dev.warpscout.core.tunnel.DataPlane
import dev.warpscout.core.tunnel.ExitRouter
import dev.warpscout.core.tunnel.PacketQueueIn
import dev.warpscout.core.tunnel.SharedPacketOut
import dev.warpscout.core.tunnel.TunDispatcher
import dev.warpscout.core.tunnel.SocketUdpChannel
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.net.DatagramSocket
import java.net.InetSocketAddress
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/**
 * Собственный туннель: VpnService + data plane из `:core` (handshake AWG, transport-пакеты,
 * keepalive, счётчики). Чужой бэкенд не нужен: AWG отличается от WireGuard только мусором перед
 * инициацией, а его отправляет тот же [DataPlane].
 *
 * Существует только во flavor'е `tunnel` (см. app/src/tunnel/AndroidManifest.xml).
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
        runCatching { TunnelStatusPublisher.start(this) }
        // Первая строка журнала: по ней видно, что процесс сервиса вообще запустился.
        runCatching {
            dev.warpscout.app.TunnelDebug.stage("сервис запущен, процесс ${android.os.Process.myPid()}")
        }
        if (TunnelState.status.isBlank()) {
            TunnelState.phase = dev.warpscout.core.state.TunnelStatus.PHASE_STARTING
            TunnelState.status = getString(R.string.notif_starting)
        }
        TunnelStatusPublisher.request(urgent = true)
    }

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
        val env = "сеть ${netKind()}, экран ${if (isScreenOn()) "вкл" else "выкл"}" +
            batteryText().let { if (it.isEmpty()) "" else ", $it" } +
            energyText().let { if (it.isEmpty()) "" else ", $it" }
        val threads = threadCpuLine()
        val tail = if (threads.isBlank()) "" else ", $threads"
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

    /** Уже ждём возвращения сети, чтобы поднять туннель самой (см. [scheduleRevive]). */
    @Volatile
    private var reviving = false

    /** Сколько медленных попыток уже сделано (сбрасывается при успехе). */
    @Volatile
    private var slowRetries = 0

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
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
            shutdown()
            // stopSelf обязателен: без него экземпляр живёт дальше со своим состоянием, и следующий
            // запуск может прийти в него же (см. эпоху выше и сброс stopped в startVpn).
            runCatching { stopSelf() }
            return START_NOT_STICKY
        }

        if (starting || plane != null) {
            // Повторное нажатие «Подключить» (кнопка, плитка быстрых настроек) не должно
            // поднимать второй туннель поверх первого — только напомнить, что уже работаем.
            TunnelState.phase = dev.warpscout.core.state.TunnelStatus.PHASE_STARTING
            TunnelState.status = "туннель уже поднимается или работает"
            postNotification(TunnelState.status)
            return START_REDELIVER_INTENT
        }
        val text = intent?.getStringExtra(EXTRA_CONF)
        if (text.isNullOrBlank()) {
            TunnelState.phase = dev.warpscout.core.state.TunnelStatus.PHASE_FAILED
            TunnelState.status = "нет конфигурации — запуск пропущен"
            stopSelf()
            return START_NOT_STICKY
        }
        lastConfigText = text
        lastStartId = startId
        // Подключение по кнопке/плитке — не автопереподъём: при неудаче сервис снимает себя, как
        // и раньше, иначе следующее ручное нажатие упрётся в «уже поднимается».
        autoRebind = false
        netRestartAttempts = 0
        // Раньше здесь был startVpn(text) напрямую, и onStartCommand блокировался на 12 с, ожидая
        // handshake. Главный поток сервиса — он же главный поток приложения: UI в это время висел,
        // и выглядело это ровно как «туннель запускается, потом без ошибок ничего не происходит».
        Thread({ startVpn(text, startId) }, "warpscout-vpn-boot").apply { isDaemon = true }.start()
        return START_REDELIVER_INTENT
    }

    override fun onDestroy() {
        shutdown()
        super.onDestroy()
    }

    private fun startVpn(text: String, startId: Int) {
        val myEpoch = epoch.incrementAndGet()
        fun alive() = myEpoch == epoch.get() && !stopped.get()
        // Выход из устаревшей попытки обязан снять свои флаги, иначе сервис навсегда останется
        // «занятым»: следующий старт получит «уже поднимается» и не сделает ничего. Именно это
        // выглядело как «немного работает, потом больше не подключается».
        fun abandon() {
            if (myEpoch == epoch.get() && !stopped.get()) {
                starting = false
                TunnelState.busy = false
            }
        }
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
        TunnelDebug.reset()
        createChannel()
        postNotification(getString(R.string.notif_starting))

        watchNetwork()
        // Экземпляр и эпоха в журнале: по ним видно, один подъём идёт или два параллельно (второй
        // экземпляр сервиса — это двойные рукопожатия и двойной расход, а не «просто лог»).
        TunnelDebug.stage("подъём: экземпляр ${System.identityHashCode(this)}, эпоха $myEpoch")
        TunnelDebug.stage("конфиг получен (${text.toByteArray().size} байт)")
        val cfg = runCatching { WgConf.toWarpConfig("WARP", text) }.getOrNull()
        if (cfg == null) {
            fail("конфиг не разбирается: нет PrivateKey или PublicKey", startId, myEpoch)
            return
        }
        TunnelState.endpoint = cfg.endpoint.render()
        TunnelDebug.stage("сервер ${cfg.endpoint.render()}, шум ${cfg.junk.name}, MTU ${cfg.mtu}")

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
            fail("protect() отказал — туннель не поднят во избежание петли", startId, myEpoch)
            return
        }
        runCatching { socket.connect(InetSocketAddress(cfg.endpoint.host, cfg.endpoint.port)) }
            .onFailure { runCatching { socket.close() }; fail("connect(): ${it.message}", startId, myEpoch); return }
        TunnelDebug.stage("UDP-сокет создан и защищён")
        if (!alive()) {
            // Пока поднимались, пользователь нажал «Отключить» (или пошла следующая попытка).
            runCatching { socket.close() }
            abandon()
            return
        }

        // Второй выход: другой сервер для выбранных подсетей (страна/провайдер на выбор).
        // Внутри WARP выбрать регион нельзя, поэтому «регион для сайта» = второй туннель рядом.
        val secondCfg = secondConfig()
        val router = secondCfg?.let { ExitRouter.of(ExitRouter.parse(serviceSettings().secondCidrs)) }
            ?.takeIf { !it.isEmpty } ?: ExitRouter.EMPTY
        val multiExit = secondCfg != null && !router.isEmpty
        // Говорим и про выключенный второй выход: иначе «две цепочки рукопожатий в журнале»
        // невозможно объяснить, не заглядывая в настройки.
        TunnelDebug.stage(if (multiExit) "второй выход включён" else "второй выход выключен")

        val builder = builderFor(cfg)
        if (multiExit) {
            // В split-режиме подсети второго выхода должны попадать в tun, иначе они уйдут мимо.
            router.cidrs.forEach { cidr ->
                val host = cidr.substringBefore('/').trim()
                val bits = cidr.substringAfter('/', "").trim().toIntOrNull()
                if (host.isNotEmpty() && bits != null) runCatching { builder.addRoute(host, bits) }
            }
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
        if (!alive()) {
            // tun уже выдан, но эта попытка устарела: закрываем, иначе интерфейс останется чужим.
            runCatching { pfd.close() }
            runCatching { socket.close() }
            abandon()
            return
        }
        tun = pfd
        udpSocket = socket
        val routes = SplitRoutes.prefixesOf(cfg.allowedIps)
        TunnelDebug.stage("tun получен: ${routes.size} маршрутов, blocking=${isFullTunnel(cfg)}")

        val handshake = CountDownLatch(1)

        // Со вторым выходом tun читает диспетчер, а каждый data plane читает свою очередь.
        // Без второго выхода — ровно прежнее поведение (прямые потоки), регрессии быть не должно.
        val secondSock = if (multiExit && secondCfg != null) openSecondSocket(secondCfg) else null
        val rawIn = FileInputStream(pfd.fileDescriptor)
        val rawOut = FileOutputStream(pfd.fileDescriptor)
        val lanes = if (secondSock != null) listOf(PacketQueueIn("основной"), PacketQueueIn("второй")) else emptyList()
        val tunOut: OutputStream = if (lanes.isEmpty()) rawOut else SharedPacketOut(rawOut)
        val tunIn: InputStream = if (lanes.isEmpty()) rawIn else lanes[0]
        if (lanes.isNotEmpty()) {
            val dispatcher = TunDispatcher(rawIn, router, lanes) { line -> TunnelDebug.stage(line) }
            this.dispatcher = dispatcher
            Thread(dispatcher, "warpscout-tun-split").apply { isDaemon = true; start() }
        }

        val plane = DataPlane(
            // Таймаут приёма 0 — ждать пакет бесконечно. Было 1500 мс: в тишине поток просыпался
            // 40 раз в минуту только чтобы посмотреть на часы, и процесс не уходил в глубокий сон.
            // Остановка и смена сети будят его закрытием сокета, а не таймаутом.
            udp = SocketUdpChannel(socket, cfg.endpoint, 0),
            tunInput = tunIn,
            tunOutput = tunOut,
            config = cfg,
            // Пять инициаций с интервалом 400 мс: первая же обычно отвечает за доли секунды,
            // а если датаграмм потерялся — следующая уходит не через 1.5 с, а почти сразу.
            settings = NetSettings(
                attempts = 5, timeoutMs = 1000, retryEveryMs = 400, junkPacketsBeforeHandshake = 1
            ),
            // Экран решает, как часто будить радио: с погашенным экраном и без трафика keepalive
            // уходит реже. Сам сервис про экран ничего не решает — только сообщает состояние.
            screenOn = {
                runCatching {
                    (getSystemService(Context.POWER_SERVICE) as PowerManager).isInteractive
                }.getOrDefault(true)
            },
            // Цифры расхода — в строку статистики журнала.
            vitals = { vitalsLine() },
            // Сокет перестал отправлять — сеть ушла без уведомления от системы. Переподнимаем.
            onFatal = { reason ->
                // Сессия умерла (нет ответов/rekey не проходит) — говорим об этом прямо, а не
                // «после смены сети»: сеть могла и не меняться.
                restartAfterNetworkChange(reason, R.string.status_reconnect_silent)
            },
            // Подъём — по событию, а не по тексту журнала: правка формулировки в ядре раньше
            // молча лишала сервис сигнала «туннель работает».
            onTunnelUp = {
                TunnelState.up = true
                TunnelState.phase = dev.warpscout.core.state.TunnelStatus.PHASE_UP
                handshake.countDown()
                // Память «на такой сети работает такая точка»: следующая смена сети начнётся
                // сразу с неё, без неудачной попытки на адресе из другой сети.
                runCatching {
                    EndpointMemory.remember(this, memoryNetKind(), cfg.endpoint.render())
                }
                TunnelDebug.ok("туннель поднят: ${cfg.endpoint.render()}")
                postNotification(getString(R.string.notif_active, cfg.endpoint.render()))
            },
            log = { line ->
                // Статистика расхода — для журнала, в уведомлении ей не место.
                if (!line.startsWith(dev.warpscout.core.tunnel.DataPlane.STATS_PREFIX)) {
                    TunnelState.status = line
                }
                when {
                    // Пересогласование сессии — штатное событие раз в две минуты, но именно его
                    // отсутствие раньше выглядело как «туннель есть, интернета нет».
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
        this.plane = plane
        worker = Thread {
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
                    stopSelfSafely()
                }
            }
        }.apply { isDaemon = true; name = "warpscout-vpn"; start() }

        // Второй выход запускаем сразу после основного: он независим (своя сессия, свой rekey),
        // и его падение не должно ронять туннель — трафик просто продолжит идти через WARP.
        val secondary = if (lanes.size > 1 && secondCfg != null && secondSock != null) {
            DataPlane(
                udp = SocketUdpChannel(secondSock, secondCfg.endpoint, 0),
                tunInput = lanes[1],
                tunOutput = tunOut,
                config = secondCfg,
                settings = NetSettings(attempts = 3, timeoutMs = 1000, retryEveryMs = 500, junkPacketsBeforeHandshake = 1),
                log = { line ->
                    when {
                        line.contains("туннель поднят") ->
                            TunnelDebug.ok("второй выход поднят: ${secondCfg.endpoint.render()}")
                        line.contains("не прошёл") || line.contains("невозможен") ->
                            TunnelDebug.error("второй выход: $line", "проверь второй конфиг и его endpoint")
                        else -> TunnelDebug.stage("второй: $line")
                    }
                }
            )
        } else {
            null
        }
        if (secondary != null) {
            plane2 = secondary
            secondSocket = secondSock
            val lane2 = lanes.getOrNull(1)
            worker2 = Thread {
                val ok2 = runCatching { secondary.run() }.getOrDefault(false)
                // Очередь закрываем: диспетчер увидит это и вернёт подсети в основной туннель.
                runCatching { lane2?.close() }
                TunnelDebug.stage(
                    "второй выход остановлен: ${if (ok2) "закрыт" else "аварийно"}, " +
                        "прошло ${secondary.bytesUp} вверх / ${secondary.bytesDown} вниз"
                )
            }.apply { isDaemon = true; name = "warpscout-vpn-2"; start() }
        }

        // Handshake ждём НЕ здесь (мы и так на отдельном потоке, а главному потоку делать нечего):
        // ждёт [dev.warpscout.app.VpnTunnelController.startAndAwait], опрашивая TunnelState.
        // Тут только страховка: если за 25 с туннель не поднялся — сами себя снимаем и объясняем почему.
        Thread {
            val waited = runCatching { handshake.await(25, TimeUnit.SECONDS) }.getOrDefault(false)
            if (!waited && !stopped.get() && !TunnelState.up) {
                fail("таймаут: за 25 с handshake не завершился", startId, myEpoch)
            } else if (waited) {
                watchTraffic(startId, myEpoch)
            }
        }.apply { isDaemon = true; name = "warpscout-vpn-watch"; start() }
    }

    /**
     * «Туннель поднят, а интернета нет» — отдельный диагноз: if up, но счётчики нулевые, значит
     * маршруты не совпали (split-tunnel) или пира не шлёт трафик. Молча это оставлять нельзя.
     */
    private fun watchTraffic(startId: Int, myEpoch: Int) {
        val deadline = System.currentTimeMillis() + 8000
        while (System.currentTimeMillis() < deadline && !stopped.get()) {
            val p = plane
            if (p != null && (p.bytesUp > 0 || p.bytesDown > 0)) {
                TunnelDebug.ok("трафик пошёл: вверх ${p.bytesUp}, вниз ${p.bytesDown} байт")
                TunnelDebug.bytesUp = p.bytesUp
                TunnelDebug.bytesDown = p.bytesDown
                return
            }
            Thread.sleep(500)
        }
        if (!stopped.get() && TunnelState.up) {
            val p = plane
            if (p != null && p.bytesUp == 0L && p.bytesDown == 0L) {
                TunnelDebug.error(
                    "туннель поднят, но ноль пакетов за 8 с",
                    "проверь AllowedIPs: в split-tunnel через WARP идут только перечисленные сети"
                )
                postNotification(getString(R.string.notif_no_traffic))
            }
        }
    }

    /**
     * Настройки для подъёма туннеля. Читаются из файла-снимка, а не из SharedPreferences: у
     * каждого процесса своя копия настроек в памяти, и сервис мог бы поднимать туннель по
     * устаревшим значениям («поменял в настройках — туннель не заметил»).
     */
    private fun serviceSettings(): dev.warpscout.core.state.ServiceSettings =
        dev.warpscout.app.status.ServiceSettingsStore.read(this)
            ?: dev.warpscout.core.state.ServiceSettings()

    /** Конфиг второго выхода (null — выключен или пустой). */
    private fun secondConfig(): WarpConfig? {
        val settings = serviceSettings()
        if (!settings.secondExitOn) return null
        val text = settings.secondConf
        if (text.isBlank()) return null
        return runCatching { WgConf.toWarpConfig("второй выход", text) }.getOrNull()
    }

    /** Отдельный защищённый сокет для второго выхода: свой protect() обязателен, иначе петля. */
    private fun openSecondSocket(cfg: WarpConfig): DatagramSocket? {
        val socket = runCatching {
            DatagramSocket(null).apply { reuseAddress = true; soTimeout = 1500 }
        }.getOrNull() ?: return null
        if (!runCatching { protect(socket) }.getOrDefault(false)) {
            runCatching { socket.close() }
            TunnelDebug.error("второй выход: protect() отказал", "второй туннель не поднят, трафик идёт через WARP")
            return null
        }
        val connected = runCatching {
            socket.connect(InetSocketAddress(cfg.endpoint.host, cfg.endpoint.port))
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
        if (autoRebind) {
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
        stopSelfSafely()
    }

    private fun stopSelfSafely() {
        runCatching { stopSelf() }
    }

    private fun builderFor(cfg: WarpConfig): Builder {
        val builder = Builder()
            .setSession("WarpScout")
            .setMtu(cfg.mtu.coerceIn(576, 1420))
            // setBlocking(true) = «всё, что не попало в маршруты, ЗАПРЕТИТЬ». При split-tunnel это
            // убило бы весь российский трафик (его в AllowedIPs нет намеренно), поэтому блокируем
            // только когда туннель и правда полный.
            .setBlocking(isFullTunnel(cfg))
        runCatching { builder.setMetered(false) }   // иначе часть телефонов режет фоновый трафик в туннеле
        runCatching { builder.addAddress(cfg.account.ipv4.substringBefore('/'), 32) }
        val v6 = cfg.account.ipv6?.takeIf { cfg.enableIpv6Address && it.isNotBlank() }
        if (v6 != null) runCatching { builder.addAddress(v6.substringBefore('/'), 128) }
        cfg.dns.forEach { if (it.isNotBlank()) runCatching { builder.addDnsServer(it.trim()) } }
        cfg.allowedIps.split(',').map { it.trim() }.filter { it.contains('/') }.forEach { cidr ->
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
                    TunnelDebug.stage("приложения: только выбранные (${selected.size})")
                }
            }

            dev.warpscout.core.state.ServiceSettings.APPS_EXCEPT -> {
                if (selected.isEmpty()) {
                    TunnelDebug.stage("приложения: все через туннель (исключений нет)")
                } else {
                    selected.forEach { runCatching { builder.addDisallowedApplication(it) } }
                    TunnelDebug.stage("приложения: все, кроме выбранных (${selected.size})")
                }
            }

            else -> TunnelDebug.stage("приложения: все через туннель")
        }
    }

    private fun postNotification(text: String) {
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
        createChannel()
        val open = android.app.PendingIntent.getActivity(
            this, 0,
            Intent(this, dev.warpscout.app.MainActivity::class.java)
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
            android.app.PendingIntent.FLAG_UPDATE_CURRENT or android.app.PendingIntent.FLAG_IMMUTABLE
        )
        val stopPi = android.app.PendingIntent.getService(
            this, 1,
            Intent(this, WarpVpnService::class.java).apply { action = ACTION_STOP },
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
        if (!stopped.compareAndSet(false, true)) return
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

    /** Закрыть сокеты, tun и оба data plane — без решения «останавливаемся навсегда». */
    private fun closeAll() {
        runCatching { dispatcher?.stop() }
        dispatcher = null
        runCatching { plane2?.stop() }
        plane2 = null
        runCatching { secondSocket?.close() }
        secondSocket = null
        runCatching { worker2?.join(500) }
        worker2 = null
        runCatching { plane?.stop() }
        plane = null
        // Поток закрыт → читающий его цикл выйдет сам; join только из чужого потока.
        val w = worker
        if (w != null && w !== Thread.currentThread()) runCatching { w.join(1000) }
        worker = null
        runCatching { udpSocket?.close() }
        udpSocket = null
        runCatching { tun?.close() }
        tun = null
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
        if (netCallback != null) return
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
                // Модем перестроился: сменилась полоса, качество, набор возможностей. Считаем —
                // частые перестройки на LTE и есть та работа, которая греет модем в кармане.
                capsChanges.incrementAndGet()
                val kind = kindOf(caps)
                if (kind.isNotEmpty()) lastNetKind = kind
            }

            override fun onAvailable(network: android.net.Network) {
                netChanges.incrementAndGet()
                rememberNetKind(network)
                val base = baselineNetwork
                if (base == null) {
                    baselineNetwork = network
                    TunnelDebug.stage("сеть туннеля: ${describeNetwork(network)}")
                    if (networkChanged) {
                        // Сети не было (или сменилась, пока её не было) — поднимаем заново.
                        restartAfterNetworkChange("сеть появилась: ${describeNetwork(network)}")
                    }
                    return
                }
                if (network == base) return
                baselineNetwork = network
                networkChanged = true
                restartAfterNetworkChange("новая сеть: ${describeNetwork(network)}")
            }

            override fun onLost(network: android.net.Network) {
                netChanges.incrementAndGet()
                if (network != baselineNetwork) return
                baselineNetwork = null
                networkChanged = true
                TunnelState.up = false
                TunnelState.phase = dev.warpscout.core.state.TunnelStatus.PHASE_NO_NETWORK
                TunnelState.status = "сеть пропала — жду новую"
                postNotification(TunnelState.status)
                TunnelDebug.stage("сеть пропала (${describeNetwork(network)}): старый UDP-сокет мёртв")
                // Если новая сеть не появится, tun нельзя оставлять: приложения будут отправлять
                // трафик в туннель, из которого ничего не выходит (чёрная дыра, «интернета нет»).
                Thread({
                    runCatching { Thread.sleep(45_000) }
                    if (stopped.get()) return@Thread
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
        val ok = runCatching { cm.registerNetworkCallback(request, cb) }.isSuccess
        if (ok) netCallback = cb else TunnelDebug.stage("не удалось следить за сетью: нет разрешения?")
    }

    private fun unwatchNetwork() {
        val cb = netCallback ?: return
        netCallback = null
        runCatching {
            getSystemService(android.net.ConnectivityManager::class.java)?.unregisterNetworkCallback(cb)
        }
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
        "$kind ${network}"
    }.getOrDefault("сеть")

    /**
     * Переподнять туннель на новой сети. Полный цикл закрытия/открытия здесь обязателен: старый
     * UDP-сокет привязан к прежнему маршруту, и после смены сети каждый `sendto` падает с
     * ENETUNREACH — «туннель есть, а трафика нет», при этом замочек в шторке висит активным.
     */
    private fun restartAfterNetworkChange(why: String, statusRes: Int = R.string.status_reconnect_net) {
        val now = System.currentTimeMillis()
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
                    if (!stopped.get()) restartAfterNetworkChange("$why (после паузы)", statusRes)
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
            if (autoRestartTimes.size >= AUTO_RESTART_LIMIT) {
                // Быстрые попытки кончились — но это не повод остаться выключенным навсегда.
                // Раньше сервис просто сдавался: «сама отключила и обратно не включила», и человек
                // узнавал об этом, только заметив, что интернет идёт напрямую. Теперь переходим в
                // медленный режим: одна попытка раз в 5 минут, до часа. Одна попытка — это три
                // пакета, для батареи это ничто, а шанс вернуться самому — есть.
                slowRetries += 1
                if (slowRetries <= SLOW_RETRY_LIMIT) {
                    TunnelDebug.error(
                        "автопереподключение приостановлено: $AUTO_RESTART_LIMIT попыток за 10 минут",
                        "медленный режим: повторю через ${SLOW_RETRY_EVERY_MS / 60_000} мин " +
                            "(попытка $slowRetries из $SLOW_RETRY_LIMIT)"
                    )
                    TunnelState.phase = dev.warpscout.core.state.TunnelStatus.PHASE_FAILED
                    TunnelState.status = "нет связи с WARP — повторю через ${SLOW_RETRY_EVERY_MS / 60_000} мин"
                    TunnelState.up = false
                    postNotification(TunnelState.status)
                    netRestartAttempts = 0
                    autoRebind = false
                    val attempt = slowRetries
                    Thread({
                        runCatching { Thread.sleep(SLOW_RETRY_EVERY_MS) }
                        if (stopped.get()) return@Thread
                        TunnelDebug.stage("медленный повтор $attempt из $SLOW_RETRY_LIMIT")
                        // Окно быстрых попыток к этому времени уже очистилось — проходим заново.
                        restartAfterNetworkChange("медленный повтор", R.string.status_reconnect_net)
                    }, "warpscout-slow-retry").apply { isDaemon = true }.start()
                } else {
                    TunnelDebug.error(
                        "переподключение прекращено: $SLOW_RETRY_LIMIT медленных попыток за " +
                            "${SLOW_RETRY_EVERY_MS * SLOW_RETRY_LIMIT / 60_000} мин",
                        "сеть не пропускает WARP: нажми «Подключить» вручную или смени профиль шума"
                    )
                    TunnelState.phase = dev.warpscout.core.state.TunnelStatus.PHASE_FAILED
                    TunnelState.status = "не удалось подключиться — нажми «Подключить»"
                    TunnelState.up = false
                    postNotification(TunnelState.status)
                    netRestartAttempts = 0
                    autoRebind = false
                }
                return
            }
            autoRestartTimes.addLast(now)
        }
        reconnects.incrementAndGet()
        Thread({
            val text = lastConfigText ?: return@Thread
            autoRebind = true
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
            if (epoch.get() != myEpoch) return@Thread
            stopped.set(false)
            networkChanged = false
            baselineNetwork = null
            // Чистим причину прошлой попытки: иначе «сервер молчит» от прежней точки будет
            // выдавать себя за диагноз новой, и сервис сменит живую точку зря.
            TunnelState.error = null
            // Порядок перебора — под эту сеть: первой пойдёт точка, работавшая на такой же сети.
            rebuildFailoverOrder()
            // И не тратим инициации на сеть, которая ещё не готова: сразу после включения Wi-Fi
            // адрес раздаётся, портал проверки доступа не пройден — handshake уходит в никуда.
            if (!awaitNetworkReady(3_000)) {
                TunnelDebug.stage("сеть ещё не признана рабочей — пробую как есть")
            }
            // Текст конфига только на одну строку — Endpoint: та, что работала на такой сети.
            val startText = preferredStartText(text)
            if (startText != text) lastConfigText = startText
            startVpn(startText, lastStartId)

            // Проверяем, что переподъём действительно состоялся: «сервис запущен» и «туннель
            // работает» — разные вещи. Если handshake не прошёл, пробуем ещё раз (до трёх),
            // а не оставляем пользователя с молчащим туннелем.
            if (awaitAttempt(15_000) == ATTEMPT_UP) {
                netRestartAttempts = 0
                autoRebind = false
                slowRetries = 0
                rotationsSinceUp = 0
                TunnelDebug.ok("туннель переподнят после смены сети")
                return@Thread
            }
            // «Сервер молчит» — это не «сеть не пускает», а «эта точка умерла»: пять инициаций
            // подряд, ни одного ответа. Повторять её ещё два раза бессмысленно (минута тишины и
            // лишние пробуждения модема), поэтому такую точку меняем сразу.
            val deadPoint = isSilentPoint(TunnelState.error)
            netRestartAttempts += 1
            if (netRestartAttempts < 3 && !stopped.get() && !deadPoint) {
                TunnelDebug.stage(
                    "переподъём не удался (попытка $netRestartAttempts из 3) — повторю через 8 с"
                )
                runCatching { Thread.sleep(8_000) }
                if (!stopped.get()) restartAfterNetworkChange("повтор после неудачи")
            } else {
                // Три раза стучались в одну точку и не достучались — она мертва (в журнале это
                // «сервер молчит: 5 инициаций без ответа»). Раньше сервис на этом сдавался и
                // писал «нажми «Подключить»»; человек в этот момент мог спать, а интернет шёл
                // мимо туннеля. Теперь берём следующую точку из очереди последнего подключения.
                val oldPoint = currentEndpointLine().orEmpty()
                val next = nextFailoverEndpoint()
                if (next != null) {
                    lastConfigText = next.second
                    rotationsSinceUp += 1
                    netRestartAttempts = 0
                    forceFastRetry = true
                    TunnelDebug.stage(
                        "$oldPoint не поднялась — перехожу на ${next.first} " +
                            "(смена $rotationsSinceUp из $MAX_ROTATIONS, без ручного нажатия; " +
                            "причина: ${(TunnelState.error ?: "нет ответа").take(80)})"
                    )
                    TunnelState.phase = dev.warpscout.core.state.TunnelStatus.PHASE_RECONNECTING
                    TunnelState.status = "переключаюсь на ${next.first}"
                    postNotification(TunnelState.status)
                    runCatching { Thread.sleep(120) }
                    if (!stopped.get()) {
                        restartAfterNetworkChange("переход на ${next.first}")
                    }
                    return@Thread
                }
                TunnelDebug.error(
                    "не удалось поднять туннель после смены сети",
                    "точка могла стать недоступной: нажми «Подключить» — сработает перебор точек"
                )
                TunnelState.phase = dev.warpscout.core.state.TunnelStatus.PHASE_FAILED
                TunnelState.status = "не удалось поднять после смены сети"
                postNotification(TunnelState.status)
                netRestartAttempts = 0
                autoRebind = false
                // Страховочный сторож этой же попытки ещё спит (25 с). Он объявит «таймаут» и
                // снимет сервис уже ПОСЛЕ того, как мы всё объяснили — в журнале появлялись два
                // разных «✗» подряд. Поднимаем эпоху: его сообщение станет устаревшим.
                epoch.incrementAndGet()
            }
        }, "warpscout-net-restart").apply { isDaemon = true }.start()
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
            r.contains("порт закрыт") || r.contains("port unreachable")
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
        val queue = runCatching { serviceSettings().failover }.getOrDefault(emptyList())
            .filter { it.isNotBlank() }
        val current = currentEndpointLine()
        val remembered = runCatching { EndpointMemory.goodFor(this, memoryNetKind()) }.getOrNull()
        failoverOrder = buildList {
            if (current != null) add(current)
            if (remembered != null) add(remembered)
            addAll(queue)
        }.distinct()
        failoverPos = current?.let { failoverOrder.indexOf(it) } ?: -1
        if (remembered != null && remembered != current) {
            TunnelDebug.stage("на сети «${memoryNetKind()}» работала $remembered — она в переборе вторая")
        }
    }

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

    /** Запомнить вид сети, на которой поднимались: по нему выбирается первая точка. */
    private fun rememberNetKind(network: android.net.Network) {
        val kind = runCatching {
            val cm = getSystemService(android.net.ConnectivityManager::class.java)
            kindOf(cm?.getNetworkCapabilities(network))
        }.getOrDefault("")
        if (kind.isNotEmpty()) lastNetKind = kind
    }

    /** Вид сети для памяти точек: последний известный, иначе — по активной сети. */
    private fun memoryNetKind(): String = lastNetKind.ifBlank { netKind() }

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
        if (reviving) return
        reviving = true
        Thread({
            try {
                while (!stopped.get() && !TunnelState.up) {
                    runCatching { Thread.sleep(15_000) }
                    if (stopped.get() || TunnelState.up) return@Thread
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
        const val ACTION_START = "dev.warpscout.app.tunnel.START"
        const val ACTION_STOP = "dev.warpscout.app.tunnel.STOP"
        const val EXTRA_CONF = "conf"
        private const val CHANNEL = "warpscout.tunnel.quiet"
        private const val LEGACY_CHANNEL = "warpscout.tunnel"
        private const val NOTIF_ID = 4200

        fun start(context: Context, config: WarpConfig) = startWithText(context, WgConf.render(config))

        /**
         * Запуск готовым текстом конфига. Нужен плитке быстрых настроек: она не собирает конфиг
         * заново, а берёт последний использованный ([Prefs.lastConfigText]) — то есть ровно то,
         * что в последний раз реально работало.
         */
        fun startWithText(context: Context, text: String) {
            // Новая попытка: результат прежней не должен влиять на неё. Без этого интерфейс
            // успевал прочитать старое «туннель работает» или «сдался» из предыдущего снимка и
            // делал вывод по устаревшим данным. Здесь это покрывает все пути запуска: кнопку,
            // плитку, верификацию из-под туннеля и перебор точек.
            TunnelState.forgetAttempt()
            val intent = Intent(context, WarpVpnService::class.java).apply {
                action = ACTION_START
                putExtra(EXTRA_CONF, text)
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

        /** Сервис сдался (ошибка/таймаут) — ждать больше нечего. */
        fun gaveUp(): Boolean = TunnelState.gaveUp

        /** Причина, по которой сдался. */
        fun failureReason(): String? = TunnelState.error

        fun stop(context: Context) {
            runCatching {
                context.startService(Intent(context, WarpVpnService::class.java).apply { action = ACTION_STOP })
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

        /** Поднять и дождаться handshake (для проверки ресурсов из-под туннеля). */
        fun startAndWait(context: Context, config: WarpConfig, timeoutMs: Int): Boolean {
            start(context, config)
            val deadline = System.currentTimeMillis() + timeoutMs.coerceAtLeast(2000)
            while (System.currentTimeMillis() < deadline) {
                if (TunnelState.up) return true
                Thread.sleep(200)
            }
            stop(context)
            return false
        }
    }
}
