package dev.warpscout.app

import android.content.Context
import android.net.Network
import android.os.Build
import android.os.ParcelFileDescriptor
import android.system.Int64Ref
import android.system.Os
import android.system.OsConstants
import dev.warpscout.core.dpi.DpiPlan
import dev.warpscout.core.dpi.DpiProbe
import dev.warpscout.core.dpi.DpiReport
import dev.warpscout.core.dpi.DpiTargets
import dev.warpscout.core.dpi.DpiTrick
import dev.warpscout.core.dpi.DpiVerdict
import dev.warpscout.core.dpi.FakeSender
import dev.warpscout.core.dpi.TrickSender
import dev.warpscout.core.json.JsonVal
import dev.warpscout.core.json.parseJson
import dev.warpscout.core.net.TcpSocketFactory
import java.io.File
import java.io.FileDescriptor
import java.io.RandomAccessFile
import java.net.HttpURLConnection
import java.net.Inet6Address
import java.net.InetAddress
import java.net.Socket
import java.net.URL
import java.net.URLEncoder
import java.nio.channels.FileChannel

/**
 * «Режут DPI или адрес» на телефоне (с 1.10.49-beta2, бета).
 *
 * Приложение само, без ByeDPI и без root, открывает YouTube, сервер его видео, Discord и другие
 * сайты напрямую через провайдера — сначала как есть, потом с приёмами обхода (см. [DpiProbe]) — и
 * пишет, что помогает на этой сети. Итог хранится по сетям (Wi-Fi и мобильная отдельно): на Tele2 и
 * дома фильтры разные, и сравнить их — смысл проверки.
 *
 * Мимо туннеля: сокеты — на сети без VPN ([CleanNetwork]; владельцу VPN Android это разрешает и при
 * своём включённом туннеле), имена — через DNS этой же сети. Чужой VPN обойти нельзя — тогда
 * проверку не запускаем (см. MainActivity).
 */
object DpiCheck {

    /** Строка итога: [kind] — 0 открыт, 1 только с обходом (или медленно), 2 не открывается. */
    class Row(val kind: Int, val text: String)

    class Saved(
        val at: Long,
        val network: String,
        val label: String,
        val summary: String,
        val byedpi: String,
        val trusted: Boolean,
        val rows: List<Row>,
        /**
         * План обхода в туннеле на этой сети (с 1.10.49-beta3, см. DpiPlan): «v2:youtube=split,x=oob».
         * С beta4 — с меткой [DpiPlan.VERSION]: планы beta3 подбирались по одним картинкам YouTube и
         * не применяются (нужна новая проверка).
         */
        val plan: String = "",
        /** Узел видео YouTube этой сети (с beta4): редиректор, который его называет, бывает закрыт. */
        val videoHost: String = ""
    )

    /** Не нашлось выхода мимо туннеля — проверка показала бы туннель, а не провайдера. */
    class NoBypass(message: String) : Exception(message)

    private const val PREFS = "dpi_check"

    /** План в итоге: проверка была, обходить нечего (см. Saved.plan). */
    const val PLAN_NONE = "-"
    private const val KEEP_NETWORKS = 6

    /** Что проверять стратегией (с 1.10.49-beta4): страница и видео YouTube, X, Discord и контроль. */
    private val STRATEGY_TARGETS = setOf("youtube", DpiTargets.VIDEO_ID, "x", "discord", "google")

    /** Итог «Проверить стратегию» (с beta4): не план сети, а ответ «открывает ли эта стратегия». */
    class StrategyResult(val at: Long, val label: String, val trick: DpiTrick, val rows: List<Row>, val summary: String)

    /** Своя стратегия из настроек (с beta4); не задана или не разбирается — null. */
    fun customTrick(context: Context): DpiTrick? = DpiTrick.custom(Prefs(context).dpiCustom)

    /** Фейк на этом телефоне (с beta4): Android 9+ — там есть публичный sendfile. */
    fun fakeSender(context: Context): FakeSender? =
        if (Build.VERSION.SDK_INT >= 28) AndroidFake(context.applicationContext.cacheDir) else null

    /**
     * Проверить текущую сеть. Долго (до минуты, в худшем случае три) — только из фонового потока.
     * [ownTunnelUp] — свой туннель поднят: тогда без сети мимо него не проверяем вовсе.
     *
     * С 1.10.49-beta4 это «Подобрать»: все встроенные приёмы и своя стратегия (если задана), фейк —
     * если телефон умеет. [only] — «Проверить стратегию»: одна стратегия, только YouTube, его видео,
     * X, Discord и контроль; итог — [StrategyResult] (план сети не меняется).
     */
    fun run(context: Context, ownTunnelUp: Boolean, progress: (String) -> Unit, cancelled: () -> Boolean): Pair<DpiReport, Saved> {
        val (report, saved) = runProbe(context, ownTunnelUp, null, progress, cancelled)
        return report to saved!!
    }

    /** «Проверить стратегию» (с beta4): см. [run]. */
    fun runStrategy(context: Context, ownTunnelUp: Boolean, trick: DpiTrick, progress: (String) -> Unit, cancelled: () -> Boolean): Pair<DpiReport, StrategyResult> {
        val app = context.applicationContext
        val (report, _) = runProbe(app, ownTunnelUp, trick, progress, cancelled)
        val label = labelOf(app, NetIdentity.currentKey(app))
        val rows = report.results.filter { !it.target.control || !it.reachable }.map { r ->
            val helped = r.helpers.any { it == trick }
            val kind = when {
                r.verdict == DpiVerdict.OPEN -> 0
                helped -> 1
                else -> 2
            }
            val text = when {
                r.verdict == DpiVerdict.OPEN -> "открыт и так — стратегия не нужна"
                helped -> "открывает" + (if (r.verdict == DpiVerdict.FASTER) " (быстрее, чем как есть)" else "")
                else -> r.text()
            }
            Row(kind, (if (kind == 0) "✓" else if (kind == 1) "◐" else "✗") + " ${r.target.name} — $text")
        }
        val opened = report.results.filter { r -> !r.target.control && r.helpers.any { it == trick } }
        val summary = when {
            !report.controlOk -> "Контрольный сайт не открылся — итогу не верь: проверь интернет и повтори."
            opened.isNotEmpty() -> "Стратегия ${DpiPlan.trickLabel(trick)} открывает: ${opened.joinToString(", ") { it.target.name }}."
            report.results.any { !it.target.control && it.verdict != DpiVerdict.OPEN } ->
                "Стратегия ${DpiPlan.trickLabel(trick)} на этой сети ничего не открывает."
            else -> "Всё открыто и так — на этой сети обход не нужен."
        }
        val result = StrategyResult(System.currentTimeMillis(), label, trick, rows, summary)
        saveStrategy(app, result)
        return report to result
    }

    private fun runProbe(
        context: Context,
        ownTunnelUp: Boolean,
        only: DpiTrick?,
        progress: (String) -> Unit,
        cancelled: () -> Boolean
    ): Pair<DpiReport, Saved?> {
        val app = context.applicationContext
        val key = NetIdentity.currentKey(app)
        val label = labelOf(app, key)
        val net: Network? = if (CleanNetwork.prepare(app)) CleanNetwork.network() else null
        // Сокет на сети мимо туннеля должен создаваться: иначе проверка молча пошла бы через туннель.
        val bypass = net != null && runCatching { net.socketFactory.createSocket().close() }.isSuccess
        if (ownTunnelUp && !bypass) {
            TunnelDebug.problem("DPI: проверка не запущена — не нашлось сети мимо туннеля")
            throw NoBypass("нет сети мимо туннеля")
        }
        val custom = customTrick(app)
        val strategies = if (only != null) listOf(only) else DpiTrick.BUILTIN + listOfNotNull(custom)
        val fake = fakeSender(app)
        val previous = load(app).firstOrNull { it.network == key && it.network.isNotBlank() }
        TunnelDebug.stage(
            (if (only != null) "DPI: проверяю стратегию ${DpiPlan.trickLabel(only)} на сети $label" else "DPI: проверяю сеть $label") +
                (if (key.isNotBlank()) " ($key)" else "") + (if (ownTunnelUp) " мимо туннеля" else "") +
                (if (only == null) " — приёмов ${strategies.size}" + (if (custom != null) ", со своей стратегией" else "") else "") +
                (if (strategies.any { it.needsFake }) (if (fake != null) ", фейк — пробую" else ", фейк — не на этом Android") else "")
        )
        val tcp = TcpSocketFactory { _ -> if (bypass && net != null) net.socketFactory.createSocket() else Socket() }
        val probe = DpiProbe(
            tcp = tcp,
            resolve = { host -> (if (bypass && net != null) net.getAllByName(host) else InetAddress.getAllByName(host)).toList() },
            fallbackResolve = { host -> doh(if (bypass) net else null, host) },
            ttl = AndroidTtl,
            strategies = strategies,
            fake = fake,
            videoHint = previous?.videoHost?.takeIf { it.isNotBlank() }
        )
        val targets = if (only != null) DpiTargets.DEFAULT.filter { it.id in STRATEGY_TARGETS } else DpiTargets.DEFAULT
        val report = probe.run(targets, network = label, progress = progress, cancelled = cancelled)
        if (only != null) {
            report.journalLines().forEachIndexed { i, line ->
                if (i == 0 || !line.startsWith("DPI: итог")) TunnelDebug.note(line)
                else if (report.controlOk) TunnelDebug.ok(line) else TunnelDebug.problem(line)
            }
            return report to null
        }
        // План обхода в туннеле (с 1.10.49-beta3): что на этой сети туннель поведёт напрямую с приёмом.
        // С beta4 — по группам сайтов: страница YouTube, его видео, картинки, X и Discord отдельно.
        val plan = DpiPlan.of(report)
        val lines = report.journalLines() + (
            if (!report.controlOk) emptyList()
            else if (plan.isEmpty) listOf("DPI: обход в туннеле на этой сети не нужен — YouTube, X и Discord идут как раньше")
            else listOf("DPI: обход в туннеле на этой сети — ${plan.describe()} (напрямую, мимо WARP)")
        )
        lines.forEachIndexed { i, line ->
            when {
                i == 0 -> TunnelDebug.note(line)
                line.startsWith("DPI: итог") -> if (report.controlOk) TunnelDebug.ok(line) else TunnelDebug.problem(line)
                else -> TunnelDebug.note(line)
            }
        }
        val saved = Saved(
            at = System.currentTimeMillis(),
            network = key,
            label = label,
            summary = report.summary(),
            byedpi = report.bestTricks().firstOrNull()?.first?.byedpi.orEmpty(),
            trusted = report.controlOk,
            rows = report.results.map { r ->
                val kind = when (r.verdict) {
                    DpiVerdict.OPEN -> 0
                    DpiVerdict.FASTER, DpiVerdict.BYPASS -> 1
                    else -> 2
                }
                val mark = when (kind) {
                    0 -> "✓"
                    1 -> "◐"
                    else -> "✗"
                }
                Row(kind, "$mark ${r.target.name} — ${r.text()}")
            },
            // «Обходить нечего» — отдельной отметкой: пустое поле у итогов прежних версий значит «не знаю».
            plan = if (!report.controlOk) "" else if (plan.isEmpty) PLAN_NONE else DpiPlan.VERSION + plan.encode(),
            // Узел видео: нашёлся сейчас — он; нет — прежний (редиректор закрыт, узел тот же).
            videoHost = report.results.firstOrNull { it.target.id == DpiTargets.VIDEO_ID }?.target?.host
                ?.takeIf { it.endsWith(".googlevideo.com") }
                ?: previous?.videoHost.orEmpty()
        )
        save(app, saved)
        // План — сервису туннеля: он читает снимок настроек, а не настройки этого процесса.
        runCatching { dev.warpscout.app.status.ServiceSettingsStore.syncFromPrefs(app) }
        return report to saved
    }

    /** «мобильная · Tele2» / «Wi-Fi». */
    fun labelOf(context: Context, key: String): String {
        if (key.isBlank()) return "сеть"
        if (NetIdentity.isMobile(key)) {
            val op = NetIdentity.operatorName(context).ifBlank { NetIdentity.operatorCode(context) }
            return "мобильная" + (if (op.isNotBlank()) " · $op" else "")
        }
        return NetIdentity.kindPart(key).ifBlank { "сеть" }
    }

    // ---------------------------------------------------------------------------- хранение по сетям

    fun load(context: Context): List<Saved> {
        val sp = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        return sp.all.entries.filter { it.key.startsWith("net:") }
            .mapNotNull { (_, v) -> (v as? String)?.let { decode(it) } }
            .sortedByDescending { it.at }
    }

    private fun save(context: Context, saved: Saved) {
        val sp = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        val ed = sp.edit().putString("net:" + saved.network, encode(saved))
        // Сетей бывает много (чужой Wi-Fi в гостях) — храним последние несколько.
        val old = load(context).filter { it.network != saved.network }.drop(KEEP_NETWORKS - 1)
        old.forEach { ed.remove("net:" + it.network) }
        ed.apply()
    }

    /**
     * Планы обхода по сетям для сервиса туннеля (с 1.10.49-beta3, см. ServiceSettings.dpiPlans): только
     * итоги, которым можно верить (контрольный сайт открылся), и только непустые. С beta4 — только
     * планы с меткой [DpiPlan.VERSION] и как есть: «custom» в плане значит «своя стратегия из
     * настроек», её подставит сервис (перекодирование здесь без своей стратегии её бы потеряло).
     */
    fun servicePlans(context: Context): List<String> = load(context)
        .filter { it.trusted && it.network.isNotBlank() && it.plan.startsWith(DpiPlan.VERSION) && it.plan.length > DpiPlan.VERSION.length }
        .map { s -> clean(s.network).trim() + "\t" + s.plan }

    /** План сети [key] из её проверки (для экрана; без выбора человека). */
    fun planFor(context: Context, key: String): DpiPlan = DpiPlan.forNetwork(servicePlans(context), key, customTrick(context))

    /** План, который туннель применит на сети [key]: проверка этой сети и выбор человека (с beta4). */
    fun effectivePlan(context: Context, key: String): DpiPlan {
        val p = Prefs(context)
        val custom = DpiTrick.custom(p.dpiCustom)
        return DpiPlan.effective(DpiPlan.forNetwork(servicePlans(context), key, custom), p.dpiStrategy, DpiPlan.parseOverrides(p.dpiOverrides), custom)
    }

    /** Итог старой версии (план beta3 без метки): его не применяем — нужна новая проверка. */
    fun isOldPlan(saved: Saved): Boolean = saved.plan.isNotBlank() && saved.plan != PLAN_NONE && !saved.plan.startsWith(DpiPlan.VERSION)

    // ------------------------------------------------------------------ последняя проверка стратегии

    private fun saveStrategy(context: Context, r: StrategyResult) {
        val text = buildString {
            append(r.at).append('\t').append(clean(r.label)).append('\t').append(clean(r.trick.id)).append('\t')
                .append(clean(r.trick.byedpi)).append('\t').append(clean(r.trick.title)).append('\t').append(clean(r.summary))
            r.rows.forEach { row -> append('\n').append(row.kind).append('\t').append(clean(row.text)) }
        }
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().putString("strategy:last", text).apply()
    }

    fun loadStrategy(context: Context): StrategyResult? = runCatching {
        val text = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getString("strategy:last", null) ?: return null
        val lines = text.split('\n')
        val h = lines.first().split('\t')
        if (h.size < 6) return null
        val rows = lines.drop(1).mapNotNull { l ->
            val i = l.indexOf('\t')
            if (i <= 0) null else Row(l.substring(0, i).toIntOrNull() ?: 2, l.substring(i + 1))
        }
        StrategyResult(h[0].toLong(), h[1], DpiTrick(h[2], h[4], h[3]), rows, h[5])
    }.getOrNull()

    private fun clean(s: String): String = s.replace('\n', ' ').replace('\t', ' ')

    private fun encode(s: Saved): String = buildString {
        append(s.at).append('\t').append(clean(s.network)).append('\t').append(clean(s.label)).append('\t')
            .append(if (s.trusted) 1 else 0).append('\t').append(clean(s.byedpi)).append('\t').append(clean(s.summary))
            .append('\t').append(clean(s.plan)).append('\t').append(clean(s.videoHost))
        s.rows.forEach { r -> append('\n').append(r.kind).append('\t').append(clean(r.text)) }
    }

    private fun decode(text: String): Saved? = runCatching {
        val lines = text.split('\n')
        val head = lines.first().split('\t')
        if (head.size < 6) return@runCatching null
        val rows = lines.drop(1).mapNotNull { l ->
            val i = l.indexOf('\t')
            if (i <= 0) null else Row(l.substring(0, i).toIntOrNull() ?: 2, l.substring(i + 1))
        }
        // Седьмое поле — план обхода (с 1.10.49-beta3), восьмое — узел видео (с beta4); у итогов
        // прежних версий их нет.
        Saved(
            head[0].toLong(), head[1], head[2], head[5], head[4], head[3] == "1", rows,
            head.getOrNull(6).orEmpty(), head.getOrNull(7).orEmpty()
        )
    }.getOrNull()

    // ------------------------------------------------------------------------------- запасной DNS

    private val IPV4 = Regex("""^\d{1,3}(\.\d{1,3}){3}$""")

    /**
     * Адрес у публичного DNS по HTTPS — когда DNS сети не отдал адрес или отдал заглушку (так
     * провайдеры «блокируют» по имени). Через ту же сеть мимо туннеля.
     */
    private fun doh(net: Network?, host: String): List<InetAddress> {
        val servers = listOf(
            "https://dns.google/resolve?type=A&name=",
            "https://cloudflare-dns.com/dns-query?type=A&name="
        )
        for (base in servers) {
            val found = runCatching {
                val url = URL(base + URLEncoder.encode(host, "UTF-8"))
                val c = (net?.openConnection(url) ?: url.openConnection()) as HttpURLConnection
                c.connectTimeout = 4000
                c.readTimeout = 4000
                c.setRequestProperty("Accept", "application/dns-json")
                try {
                    if (c.responseCode != 200) return@runCatching emptyList<InetAddress>()
                    val text = c.inputStream.use { it.readBytes().toString(Charsets.UTF_8) }
                    val obj = parseJson(text) as? JsonVal.Obj ?: return@runCatching emptyList<InetAddress>()
                    obj.arr("Answer")?.items.orEmpty().mapNotNull { a ->
                        val o = a as? JsonVal.Obj ?: return@mapNotNull null
                        if (o.num("type")?.toInt() != 1) return@mapNotNull null
                        val d = o.str("data")?.trim().orEmpty()
                        if (IPV4.matches(d)) InetAddress.getByName(d) else null
                    }
                } finally {
                    c.disconnect()
                }
            }.getOrDefault(emptyList())
            if (found.isNotEmpty()) return found
        }
        return emptyList()
    }

    // -------------------------------------------------------------------------------------- TTL

    /**
     * TTL исходящих пакетов сокета — через setsockopt (публичный android.system.Os). Узнать текущий
     * нельзя (getsockoptInt в SDK нет) — тогда [DpiProbe] вернёт стандартные 64 (так у Android).
     * Сокеты Java в Android двухстековые: для адреса IPv4 действует IP_TTL, для IPv6 — число хопов.
     */
    internal object AndroidTtl : DpiProbe.SocketTtl {
        override fun get(socket: Socket): Int? = null

        override fun set(socket: Socket, ttl: Int): Boolean = runCatching {
            ParcelFileDescriptor.fromSocket(socket).use { pfd -> setTtl(pfd.fileDescriptor, socket, ttl) }
            true
        }.getOrDefault(false)

        fun setTtl(fd: FileDescriptor, socket: Socket, ttl: Int) {
            if (socket.inetAddress is Inet6Address) {
                Os.setsockoptInt(fd, OsConstants.IPPROTO_IPV6, OsConstants.IPV6_UNICAST_HOPS, ttl)
            } else {
                Os.setsockoptInt(fd, OsConstants.IPPROTO_IP, OsConstants.IP_TTL, ttl)
            }
        }
    }

    /**
     * Фейк (`--fake` у ByeDPI, с 1.10.49-beta4) без root — как у ByeDPI на Linux: подделка лежит в
     * общей странице файла, sendfile отдаёт ядру ссылку на эту страницу (а не копию), пакет уходит с
     * маленьким TTL и до сервера не доходит — его видит только фильтр по дороге. Потом в ту же
     * страницу пишется настоящее начало, TTL возвращается, и ядро само повторяет «потерянный» пакет —
     * уже с настоящими байтами. Сервер получает только настоящее.
     *
     * Если ядро скопирует данные (сетевая карта без scatter-gather), повтор уйдёт с подделкой — сервер
     * ответит на чужое приветствие, и проверка ([DpiProbe]) честно засчитает приём неудачным.
     * Нужен Android 9+ (sendfile с Int64Ref); файл — во внутреннем кеше приложения.
     */
    internal class AndroidFake(private val dir: File) : FakeSender {
        override fun send(socket: Socket, fake: ByteArray, real: ByteArray, ttl: Int, normalTtl: Int) {
            if (Build.VERSION.SDK_INT < 28) throw TrickSender.Unsupported("фейк: нужен Android 9 или новее")
            if (fake.size != real.size || fake.isEmpty()) throw TrickSender.Unsupported("фейк: длина подделки не та")
            val file = try {
                File.createTempFile("fake", ".bin", dir)
            } catch (e: Exception) {
                throw TrickSender.Unsupported("фейк: нет места для файла (${e.message})")
            }
            try {
                RandomAccessFile(file, "rw").use { raf ->
                    raf.setLength(fake.size.toLong())
                    val map = raf.channel.map(FileChannel.MapMode.READ_WRITE, 0, fake.size.toLong())
                    map.put(fake)
                    ParcelFileDescriptor.fromSocket(socket).use { pfd ->
                        val fd = pfd.fileDescriptor
                        try {
                            AndroidTtl.setTtl(fd, socket, ttl)
                        } catch (e: Exception) {
                            throw TrickSender.Unsupported("фейк: система не дала поменять TTL")
                        }
                        try {
                            val off = Int64Ref(0)
                            var left = fake.size.toLong()
                            while (left > 0) {
                                val n = Os.sendfile(fd, raf.fd, off, left)
                                if (n <= 0) throw TrickSender.Unsupported("фейк: sendfile ничего не отправил")
                                left -= n
                            }
                            // Пакет должен уйти, пока в странице подделка; потом — настоящее начало.
                            Thread.sleep(FAKE_HOLD_MS)
                        } catch (e: TrickSender.Unsupported) {
                            throw e
                        } catch (e: InterruptedException) {
                            Thread.currentThread().interrupt()
                            throw TrickSender.Unsupported("фейк: остановлено")
                        } catch (e: Exception) {
                            throw TrickSender.Unsupported("фейк: sendfile не сработал (${e.message})")
                        } finally {
                            map.position(0)
                            map.put(real)
                            runCatching { AndroidTtl.setTtl(fd, socket, normalTtl) }
                        }
                    }
                }
            } finally {
                runCatching { file.delete() }
            }
        }
    }

    /** Сколько ждать после отправки подделки, прежде чем писать в страницу настоящее (как у ByeDPI ~10–50 мс). */
    private const val FAKE_HOLD_MS = 25L
}
