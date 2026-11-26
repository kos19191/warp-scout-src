package dev.warpscout.app

import android.content.Context
import android.net.Network
import android.os.ParcelFileDescriptor
import android.system.Os
import android.system.OsConstants
import dev.warpscout.core.dpi.DpiPlan
import dev.warpscout.core.dpi.DpiProbe
import dev.warpscout.core.dpi.DpiReport
import dev.warpscout.core.dpi.DpiTargets
import dev.warpscout.core.dpi.DpiVerdict
import dev.warpscout.core.json.JsonVal
import dev.warpscout.core.json.parseJson
import dev.warpscout.core.net.TcpSocketFactory
import java.net.HttpURLConnection
import java.net.Inet6Address
import java.net.InetAddress
import java.net.Socket
import java.net.URL
import java.net.URLEncoder

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
        /** План обхода в туннеле на этой сети (с 1.10.49-beta3, см. DpiPlan): «youtube=split,x=oob». */
        val plan: String = ""
    )

    /** Не нашлось выхода мимо туннеля — проверка показала бы туннель, а не провайдера. */
    class NoBypass(message: String) : Exception(message)

    private const val PREFS = "dpi_check"

    /** План в итоге: проверка была, обходить нечего (см. Saved.plan). */
    const val PLAN_NONE = "-"
    private const val KEEP_NETWORKS = 6

    /**
     * Проверить текущую сеть. Долго (до минуты, в худшем случае три) — только из фонового потока.
     * [ownTunnelUp] — свой туннель поднят: тогда без сети мимо него не проверяем вовсе.
     */
    fun run(context: Context, ownTunnelUp: Boolean, progress: (String) -> Unit, cancelled: () -> Boolean): Pair<DpiReport, Saved> {
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
        TunnelDebug.stage(
            "DPI: проверяю сеть $label" + (if (key.isNotBlank()) " ($key)" else "") +
                (if (ownTunnelUp) " мимо туннеля" else "")
        )
        val tcp = TcpSocketFactory { _ -> if (bypass && net != null) net.socketFactory.createSocket() else Socket() }
        val probe = DpiProbe(
            tcp = tcp,
            resolve = { host -> (if (bypass && net != null) net.getAllByName(host) else InetAddress.getAllByName(host)).toList() },
            fallbackResolve = { host -> doh(if (bypass) net else null, host) },
            ttl = AndroidTtl
        )
        val report = probe.run(DpiTargets.DEFAULT, network = label, progress = progress, cancelled = cancelled)
        // План обхода в туннеле (с 1.10.49-beta3): что на этой сети туннель поведёт напрямую с приёмом.
        val plan = DpiPlan.of(report)
        val lines = report.journalLines() + (
            if (!report.controlOk) emptyList()
            else if (plan.isEmpty) listOf("DPI: обход в туннеле на этой сети не нужен — YouTube и X идут как раньше")
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
            plan = if (!report.controlOk) "" else if (plan.isEmpty) PLAN_NONE else plan.encode()
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
     * итоги, которым можно верить (контрольный сайт открылся), и только непустые.
     */
    fun servicePlans(context: Context): List<String> = load(context)
        .filter { it.trusted && it.network.isNotBlank() && it.plan.isNotBlank() }
        .mapNotNull { s -> DpiPlan.decode(s.plan).takeIf { !it.isEmpty }?.let { DpiPlan.entry(s.network, it) } }

    /** План обхода для сети [key] из сохранённых итогов (для экрана). */
    fun planFor(context: Context, key: String): DpiPlan = DpiPlan.forNetwork(servicePlans(context), key)

    private fun clean(s: String): String = s.replace('\n', ' ').replace('\t', ' ')

    private fun encode(s: Saved): String = buildString {
        append(s.at).append('\t').append(clean(s.network)).append('\t').append(clean(s.label)).append('\t')
            .append(if (s.trusted) 1 else 0).append('\t').append(clean(s.byedpi)).append('\t').append(clean(s.summary))
            .append('\t').append(clean(s.plan))
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
        // Седьмое поле — план обхода (с 1.10.49-beta3); у итогов прежних версий его нет.
        Saved(head[0].toLong(), head[1], head[2], head[5], head[4], head[3] == "1", rows, head.getOrNull(6).orEmpty())
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
            ParcelFileDescriptor.fromSocket(socket).use { pfd ->
                val fd = pfd.fileDescriptor
                val remote = socket.inetAddress
                if (remote is Inet6Address) {
                    Os.setsockoptInt(fd, OsConstants.IPPROTO_IPV6, OsConstants.IPV6_UNICAST_HOPS, ttl)
                } else {
                    Os.setsockoptInt(fd, OsConstants.IPPROTO_IP, OsConstants.IP_TTL, ttl)
                }
            }
            true
        }.getOrDefault(false)
    }
}
