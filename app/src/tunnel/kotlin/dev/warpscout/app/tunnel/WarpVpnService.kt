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
import dev.warpscout.core.crypto.Crypto
import dev.warpscout.core.model.Endpoint
import dev.warpscout.core.model.Verdict
import dev.warpscout.core.model.WarpConfig
import dev.warpscout.core.net.NetSettings
import dev.warpscout.core.net.UdpSocketFactory
import dev.warpscout.core.net.WgProber
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
        // «Выключил сам» помнит снимок, а не память процесса. Новый процесс сервиса (после
        // остановки, обновления, убийства системой) иначе первым же снимком стёр бы эту отметку —
        // и фоновый подбор решил бы, что туннель можно включать.
        runCatching {
            dev.warpscout.app.status.TunnelStatusBus.read(this)?.let { previous ->
                if (previous.stoppedByUser) TunnelState.stoppedByUser = true
                if (previous.stoppedByUserAt > TunnelState.stoppedByUserAt) {
                    TunnelState.stoppedByUserAt = previous.stoppedByUserAt
                }
            }
        }
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
        val text = intent?.getStringExtra(EXTRA_CONF)
        if (text.isNullOrBlank()) {
            TunnelState.phase = dev.warpscout.core.state.TunnelStatus.PHASE_FAILED
            TunnelState.status = "нет конфигурации — запуск пропущен"
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
        // Подключение по кнопке/плитке — не автопереподъём: при неудаче сервис снимает себя, как
        // и раньше, иначе следующее ручное нажатие упрётся в «уже поднимается».
        autoRebind = false
        netRestartAttempts = 0
        // Ручной старт — новый отсчёт: отложенные повторы отменяются, счётчики циклов — с нуля.
        wanted = true
        TunnelState.wanted = true
        TunnelState.stoppedByUser = false
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
            if (epoch.get() == bootEpoch && wanted && !destroyed) startVpn(text, startId)
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
        // Точка отсчёта для слежения за сетью — сеть, через которую пойдёт этот сокет. Раньше
        // после каждого переподъёма сервис забывал её и первую же новую сеть принимал за «свою»:
        // в журнале 20:06:35 «сеть туннеля: мобильная 204» вместо переподключения, и ещё 13 с
        // пакеты уходили в пропавший Wi-Fi, пока сокет не ответил ENETUNREACH.
        underlyingNetwork()?.let { net ->
            if (net != baselineNetwork) TunnelDebug.stage("сеть туннеля: ${describeNetwork(net)}")
            baselineNetwork = net
            rememberNetKind(net)
        }
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
        val splitter = if (lanes.isNotEmpty()) {
            TunDispatcher(rawIn, router, lanes) { line -> TunnelDebug.stage(line) }
        } else {
            null
        }
        if (splitter != null) {
            this.dispatcher = splitter
            Thread(splitter, "warpscout-tun-split").apply { isDaemon = true; start() }
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
            onTunnelUp = {
                TunnelState.up = true
                TunnelState.phase = dev.warpscout.core.state.TunnelStatus.PHASE_UP
                handshake.countDown()
                // Туннель поднят — отложенные повторы и ожидание сети больше не нужны.
                cancelWaits()
                // Туннель поднят — цикл перебора закончен, следующая авария начнёт новый. Раньше
                // счётчик сбрасывался только при переподъёме самим сервисом: после ручного
                // «Подключить» он оставался исчерпанным, и сервис больше не менял точку сам.
                rotationsSinceUp = 0
                // Память «на такой сети работает такая точка»: следующая смена сети начнётся
                // сразу с неё, без неудачной попытки на адресе из другой сети.
                runCatching {
                    EndpointMemory.remember(this, memoryNetKind(), cfg.endpoint.render())
                }
                TunnelDebug.ok("туннель поднят: ${cfg.endpoint.render()}")
                postNotification(getString(R.string.notif_active, cfg.endpoint.render()))
                // Тихая проверка соседних точек: сессию не трогает, очередь держит свежей.
                startSentry(cfg, myEpoch)
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
                            // С 1.10.26 метка времени в инициации — стандартная TAI64N. Свой сервер
                            // помнит самую большую метку от прошлых версий (она была записана не тем
                            // порядком байт) и, пока не перезапущен, новые инициации считает повтором.
                            TunnelDebug.error(
                                "второй выход: $line",
                                "проверь второй конфиг и его endpoint; если сервер перестал отвечать сразу после " +
                                    "обновления до 1.10.26 — перезапусти на нём WireGuard/AmneziaWG"
                            )
                        else -> TunnelDebug.stage("второй: $line")
                    }
                }
            )
        } else {
            null
        }
        if (secondary != null) {
            val lane2 = lanes.getOrNull(1)
            val secondThread = Thread {
                val ok2 = runCatching { secondary.run() }.getOrDefault(false)
                // Очередь закрываем: диспетчер увидит это и вернёт подсети в основной туннель.
                runCatching { lane2?.close() }
                TunnelDebug.stage(
                    "второй выход остановлен: ${if (ok2) "закрыт" else "аварийно"}, " +
                        "прошло ${secondary.bytesUp} вверх / ${secondary.bytesDown} вниз"
                )
            }.apply { isDaemon = true; name = "warpscout-vpn-2" }
            val ownsSecond = synchronized(life) {
                if (alive()) {
                    plane2 = secondary
                    secondSocket = secondSock
                    worker2 = secondThread
                    secondThread.start()
                    true
                } else {
                    false
                }
            }
            if (!ownsSecond) {
                runCatching { secondary.stop() }
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
        // Закрытому экземпляру сдаваться не от чего: общее состояние уже принадлежит другому.
        if (destroyed) return
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
        runCatching { p2?.stop() }
        runCatching { s2?.close() }
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
                val kind = kindOf(caps)
                if (kind.isNotEmpty()) lastNetKind = kind
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
                if (intent?.action == Intent.ACTION_SCREEN_ON) onScreenOn()
            }
        }
        synchronized(life) {
            if (!destroyed && screenReceiver == null) {
                // SCREEN_ON — системное защищённое сообщение: флаг экспорта для него не нужен.
                val registered = runCatching {
                    registerReceiver(receiver, android.content.IntentFilter(Intent.ACTION_SCREEN_ON))
                }.isSuccess
                if (registered) screenReceiver = receiver
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
        "$kind ${network}"
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
            if (!slowAttempt && autoRestartTimes.size >= AUTO_RESTART_LIMIT) {
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
            } else {
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
            startVpn(startText, lastStartId)
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
                TunnelDebug.ok("туннель переподнят после смены сети")
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
                // Три раза стучались в одну точку и не достучались (или она молчит/закрыта) —
                // берём следующую из очереди последнего подключения.
                val oldPoint = currentEndpointLine().orEmpty()
                if (oldPoint.isNotEmpty()) {
                    cycleTried.add(oldPoint)
                    when {
                        // «Порт закрыт» — прямой ответ сети: точка мертва, сколько ни жди.
                        isClosedPort(reason) -> sentryMarkDead(oldPoint)
                        // Молчание — только кандидат в мёртвые (см. [cycleSilent]).
                        deadPoint -> cycleSilent.add(oldPoint)
                    }
                }
                val next = nextFailoverEndpoint()
                if (next != null) {
                    lastConfigText = next.second
                    rotationsSinceUp += 1
                    netRestartAttempts = 0
                    forceFastRetry = true
                    TunnelDebug.stage(
                        "$oldPoint не поднялась — перехожу на ${next.first} " +
                            "(смена $rotationsSinceUp из $MAX_ROTATIONS, без ручного нажатия; " +
                            "причина: ${(reason ?: "нет ответа").take(80)})"
                    )
                    TunnelState.phase = dev.warpscout.core.state.TunnelStatus.PHASE_RECONNECTING
                    TunnelState.status = "переключаюсь на ${next.first}"
                    postNotification(TunnelState.status)
                    runCatching { Thread.sleep(120) }
                    if (!stopped.get() && epoch.get() == attemptEpoch && wanted && !destroyed) {
                        restartAfterNetworkChange("переход на ${next.first}")
                    }
                    return@Thread
                }
                endFailedCycle()
            }
        }, "warpscout-net-restart").apply { isDaemon = true }.start()
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
        val why = (if (tried == 1) "не удалось поднять туннель: точка не отвечает"
        else "не удалось поднять туннель: не ответила ни одна из $tried точек") +
            (if (allSilent) " — все молчали, похоже на сеть, а не на точки" else "")
        TunnelState.error = why
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

    /** Цикл удался: промолчавшие в нём точки — в конец перебора (рядом нашлась живая, сеть ни при чём). */
    private fun commitCycleMarks() {
        val silent = synchronized(cycleSilent) {
            val copy = cycleSilent.toList()
            cycleSilent.clear()
            copy
        }
        cycleTried.clear()
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
            r.contains("порт закрыт") || r.contains("port unreachable")
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
        if (remembered != null && remembered != current && !sentryDead(kind, remembered)) {
            TunnelDebug.stage("на сети «$kind» работала $remembered — она в переборе вторая")
        }
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
        val queue = runCatching { serviceSettings().failover }.getOrDefault(emptyList())
            .map { it.trim() }
            .filter { it.isNotEmpty() }
        val current = currentEndpointLine()
        val remembered = runCatching { EndpointMemory.goodFor(this, kind) }.getOrNull()
        val prefix = "$kind|"
        val fresh = sentryMarks.entries
            .filter { (key, mark) ->
                key.startsWith(prefix) && mark.fails == 0 && mark.okAt > 0 && now - mark.okAt < SENTRY_FRESH_MS
            }
            .sortedByDescending { it.value.okAt }
            .map { it.key.removePrefix(prefix) }
        val all = buildList {
            if (current != null) add(current)
            if (remembered != null) add(remembered)
            addAll(fresh)
            addAll(queue)
        }.distinct()
        val (dead, alive) = all.partition { it != current && sentryDead(kind, it, now) }
        return alive + dead
    }

    /** Точка не поднялась при переподключении: для перебора это то же, что две неудачные пробы. */
    private fun sentryMarkDead(endpoint: String) {
        val key = "${memoryNetKind()}|$endpoint"
        val before = sentryMarks[key] ?: SentryMark()
        sentryMarks[key] = SentryMark(okAt = before.okAt, fails = 2, failAt = System.currentTimeMillis())
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
            if (TunnelState.up && hasUsableNetwork()) {
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
        const val EXTRA_CONF = "conf"

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

        fun start(context: Context, config: WarpConfig, requestedAt: Long = 0L) =
            startWithText(context, WgConf.render(config), requestedAt)

        /**
         * Запуск готовым текстом конфига. Нужен плитке быстрых настроек: она не собирает конфиг
         * заново, а берёт последний использованный ([Prefs.lastConfigText]) — то есть ровно то,
         * что в последний раз реально работало.
         */
        fun startWithText(context: Context, text: String, requestedAt: Long = 0L) {
            // Новая попытка: результат прежней не должен влиять на неё. Без этого интерфейс
            // успевал прочитать старое «туннель работает» или «сдался» из предыдущего снимка и
            // делал вывод по устаревшим данным. Здесь это покрывает все пути запуска: кнопку,
            // плитку, верификацию из-под туннеля и перебор точек.
            TunnelState.forgetAttempt()
            val intent = Intent(context, WarpVpnService::class.java).apply {
                action = ACTION_START
                putExtra(EXTRA_CONF, text)
                if (requestedAt > 0L) putExtra(EXTRA_REQUESTED_AT, requestedAt)
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
            start(context, config)
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
