package dev.warpscout.app

import android.content.Context
import android.net.Network
import dev.warpscout.core.telegram.MtProxy
import dev.warpscout.core.telegram.MtProxyChecker
import java.io.IOException
import java.net.HttpURLConnection
import java.net.Inet4Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.URL
import java.util.concurrent.Callable
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

/**
 * Прокси MTProto для Telegram (с 1.10.49-beta4, бета): скачать публичные списки, проверить
 * кандидатов по-настоящему (до ответа сервера Telegram через прокси, см. [MtProxyChecker]) и
 * запомнить рабочие. Всё — мимо туннеля, через провайдера ([CleanNetwork]): так Telegram пойдёт
 * через прокси без VPN. Чужой VPN обойти нельзя — тогда экран поиск не запускает.
 */
object TgProxies {

    class Found(val entry: MtProxy.Entry, val pingMs: Long)

    class Saved(
        val at: Long,
        val label: String,
        val working: List<Found>,
        /** Сколько проверено и сколько было в списках. */
        val checked: Int,
        val listed: Int,
        /** Короткая сводка: по спискам и по итогам проверки. */
        val note: String
    )

    private const val PREFS = "tg_proxy"
    private const val KEEP = 8
    private const val CANDIDATES = 64
    private const val THREADS = 16
    private const val DEADLINE_MS = 75_000L
    private const val MAX_FEED_BYTES = 3 * 1024 * 1024

    /** Список старше этого — показываем «мог устареть». */
    const val STALE_MS = 6 * 3600_000L

    /** Найти и проверить. Долго (до минуты) — только из фонового потока. */
    fun find(context: Context, ownTunnelUp: Boolean, progress: (String) -> Unit, cancelled: () -> Boolean): Saved {
        val app = context.applicationContext
        val net: Network? = if (CleanNetwork.prepare(app)) CleanNetwork.network() else null
        val bypass = net != null && runCatching { net.socketFactory.createSocket().close() }.isSuccess
        if (ownTunnelUp && !bypass) {
            TunnelDebug.problem("Telegram: поиск прокси не запущен — не нашлось сети мимо туннеля")
            throw DpiCheck.NoBypass("нет сети мимо туннеля")
        }
        val via = if (bypass) net else null
        val label = DpiCheck.labelOf(app, NetIdentity.currentKey(app))
        TunnelDebug.stage("Telegram: ищу прокси MTProto на сети $label" + if (ownTunnelUp) " мимо туннеля" else "")

        val all = LinkedHashMap<String, MtProxy.Entry>()
        val feedNotes = ArrayList<String>()
        for (feed in MtProxy.FEEDS) {
            if (cancelled()) break
            progress("скачиваю список «${feed.name}»")
            val text = fetchFeed(via, feed)
            if (text == null) {
                feedNotes += "${feed.name} — не скачался"
                continue
            }
            val list = MtProxy.parse(text, feed.name)
            list.forEach { all.putIfAbsent(it.id, it) }
            feedNotes += "${feed.name} — ${list.size}"
        }
        TunnelDebug.note("Telegram: списки прокси — ${feedNotes.joinToString("; ")}")
        val previous = load(app)?.working?.map { it.entry }.orEmpty()
        if (all.isEmpty() && previous.isEmpty()) throw IOException("списки не скачались (${feedNotes.joinToString("; ")})")

        // Прежние рабочие — первыми: публичные прокси живут недолго, но вчерашний часто жив.
        val cands = (previous + MtProxy.candidates(all.values.toList(), CANDIDATES)).distinctBy { it.id }.take(CANDIDATES + KEEP)
        val checker = MtProxyChecker(connect = { host, port, timeout -> connect(via, host, port, timeout) }, connectMs = 2500, replyMs = 3500)
        val pool = Executors.newFixedThreadPool(THREADS) { r -> Thread(r, "warpscout-tgproxy").apply { isDaemon = true } }
        val done = AtomicInteger()
        val ok = AtomicInteger()
        val t0 = System.currentTimeMillis()
        val results = try {
            val futures = cands.map { e ->
                pool.submit(Callable {
                    if (cancelled()) return@Callable null
                    val r = checker.check(e)
                    if (r.works) ok.incrementAndGet()
                    progress("проверено ${done.incrementAndGet()} из ${cands.size}, работают ${ok.get()}")
                    r
                })
            }
            futures.mapNotNull { f ->
                val left = DEADLINE_MS - (System.currentTimeMillis() - t0)
                runCatching { f.get(left.coerceAtLeast(1), TimeUnit.MILLISECONDS) }.getOrElse { f.cancel(true); null }
            }
        } finally {
            pool.shutdownNow()
        }
        val working = results.filter { it.works }.sortedBy { it.pingMs }.take(KEEP).map { Found(it.entry, it.pingMs) }
        val levels = results.groupingBy { it.level }.eachCount()
        val note = "в списках ${all.size}, проверено ${results.size}: до Telegram — ${levels[MtProxyChecker.Level.TELEGRAM] ?: 0}, " +
            "рукопожатие без ответа Telegram — ${levels[MtProxyChecker.Level.HANDSHAKE] ?: 0}, " +
            "только порт — ${levels[MtProxyChecker.Level.TCP] ?: 0}, не подключились — ${levels[MtProxyChecker.Level.NONE] ?: 0}"
        TunnelDebug.note("Telegram: $note")
        working.forEach { f -> TunnelDebug.note("Telegram: ✓ ${f.entry.server}:${f.entry.port} · ${f.entry.badge} · ${f.pingMs} мс") }
        if (working.isEmpty()) TunnelDebug.problem("Telegram: ни один прокси не довёл до Telegram") else
            TunnelDebug.ok("Telegram: рабочих прокси — ${working.size}")
        val saved = Saved(System.currentTimeMillis(), label, working, results.size, all.size, note)
        // Пустой итог прежний список не затирает: экран покажет «ни один не ответил», а старые останутся
        // на случай, если сеть просто моргнула.
        if (working.isNotEmpty()) save(app, saved)
        return saved
    }

    private fun connect(net: Network?, host: String, port: Int, timeoutMs: Int): Socket {
        val addresses = (net?.getAllByName(host) ?: InetAddress.getAllByName(host)).toList()
        val addr = addresses.firstOrNull { it is Inet4Address } ?: addresses.firstOrNull() ?: throw IOException("имя не находится")
        val s = net?.socketFactory?.createSocket() ?: Socket()
        try {
            s.connect(InetSocketAddress(addr, port), timeoutMs)
            return s
        } catch (e: Exception) {
            runCatching { s.close() }
            throw e
        }
    }

    /** Список: по адресам по очереди (raw.githubusercontent.com бывает закрыт — тогда jsDelivr). */
    private fun fetchFeed(net: Network?, feed: MtProxy.Feed): String? {
        for (u in feed.urls) {
            val text = runCatching {
                val url = URL(u)
                val c = (net?.openConnection(url) ?: url.openConnection()) as HttpURLConnection
                c.connectTimeout = 6000
                c.readTimeout = 8000
                c.setRequestProperty("User-Agent", "WilyScout/${BuildConfig.VERSION_NAME}")
                try {
                    if (c.responseCode != 200) return@runCatching null
                    c.inputStream.use { inp ->
                        val out = java.io.ByteArrayOutputStream()
                        val buf = ByteArray(16 * 1024)
                        while (out.size() < MAX_FEED_BYTES) {
                            val n = inp.read(buf)
                            if (n < 0) break
                            out.write(buf, 0, n)
                        }
                        out.toString("UTF-8")
                    }
                } finally {
                    c.disconnect()
                }
            }.getOrNull()
            if (!text.isNullOrBlank()) return text
        }
        return null
    }

    // ---------------------------------------------------------------------------------- хранение

    private fun clean(s: String): String = s.replace('\n', ' ').replace('\t', ' ')

    private fun save(context: Context, s: Saved) {
        val text = buildString {
            append(s.at).append('\t').append(clean(s.label)).append('\t').append(s.checked).append('\t')
                .append(s.listed).append('\t').append(clean(s.note))
            s.working.forEach { f ->
                val e = f.entry
                append('\n').append(clean(e.server)).append('\t').append(e.port).append('\t').append(clean(e.secret))
                    .append('\t').append(f.pingMs).append('\t').append(clean(e.source))
            }
        }
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().putString("last", text).apply()
    }

    fun load(context: Context): Saved? = runCatching {
        val text = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getString("last", null) ?: return null
        val lines = text.split('\n')
        val h = lines.first().split('\t')
        if (h.size < 5) return null
        val found = lines.drop(1).mapNotNull { l ->
            val f = l.split('\t')
            if (f.size < 4) return@mapNotNull null
            val port = f[1].toIntOrNull() ?: return@mapNotNull null
            val secret = MtProxy.parseSecret(f[2]) ?: return@mapNotNull null
            Found(MtProxy.Entry(f[0], port, f[2], secret.kind, secret.domain, f.getOrNull(4).orEmpty()), f[3].toLongOrNull() ?: -1)
        }
        Saved(h[0].toLong(), h[1], found, h[2].toIntOrNull() ?: 0, h[3].toIntOrNull() ?: 0, h[4])
    }.getOrNull()
}
