package dev.warpscout.core.lists

import dev.warpscout.core.model.ResourceCheck
import java.io.File

/**
 * Списки [allow-domains](https://github.com/haritos90/allow-domains) (форк
 * [itdoginfo/allow-domains]) как источник «что туннелировать, а что надо пустовать мимо».
 *
 * Формат файлов (проверено по репозиторию): `Categories/NN-name.lst` — по домену в строке,
 * `Subnets/IPv4` и `Subnets/IPv6` (тоже `.lst`) — по CIDR в строке, комментарии `#`, ничего больше. Рядом лежат
 * `-surge.list` (`DOMAIN-SUFFIX,x`) и `.json`/`.srs` для sing-box — их мы не читаем, `.lst` достаточно.
 *
 * Зачем две стороны: «заблокировано в РФ» — это про то, что надо пустовать через туннель.
 * Но у списка есть и обратная половина: `21-hosters-ip-blocked` (сайты, банящие адреса дата-центров —
 * `adr.it` отдаёт `403 Request blocked` с Hetzner/Cloudflare) и `russia-outside` (российские сервисы,
 * чья инфраструктура живёт за рубежом: alfabank.ru, ozon). Их через WARP как раз ломает. Хороший
 * конфиг — это когда первые идут через туннель, а вторые идут напрямую, и ровно это мы и проверяем.
 */

/** Сторона: «туннелировать» (BLOCK) или «не трогать, иначе испортится» (DIRECT). */
enum class ListSide { BLOCK, DIRECT }

data class AllowList(
    val id: String,
    val title: String,
    val side: ListSide,
    /** Путь в репозитории до `.lst` с доменами. */
    val domains: String,
    /** Необязательные списки подсетей: если они есть, маршруты можно строить вообще без резолвинга. */
    val subnetsV4: String? = null,
    val subnetsV6: String? = null,
    val note: String = ""
) {
    val hasSubnets: Boolean get() = subnetsV4 != null || subnetsV6 != null
}

/** Хранилище скачанных списков (в приложении — файл во внутреннем каталоге, в CLI — на диске). */
fun interface ListStore {
    fun read(key: String): String?

    companion object {
        val none = ListStore { null }
    }
}

/**
 * Файловый кеш: `<файл>/<id>.lst` плюс `<файл>/<id>.ts` с меткой времени. Никакого JSON — список и
 * так построчный, а лишняя зависимость в ядре нам не нужна.
 */
class FileListStore(private val dir: File) : ListStore {
    override fun read(key: String): String? = runCatching { File(dir, "$key.lst").readText() }.getOrNull()

    fun stamp(key: String): Long = runCatching { File(dir, "$key.ts").readText().trim().toLong() }.getOrDefault(0L)

    fun write(key: String, text: String) {
        dir.mkdirs()
        File(dir, "$key.lst").writeText(text)
        runCatching { File(dir, "$key.ts").writeText(System.currentTimeMillis().toString()) }
    }

    fun knownIds(): List<String> = runCatching {
        (dir.listFiles() ?: emptyArray()).mapNotNull { f ->
            f.name.takeIf { it.endsWith(".lst") }?.removeSuffix(".lst")
        }
    }.getOrDefault(emptyList())
}

object AllowLists {

    const val RAW = "https://raw.githubusercontent.com/haritos90/allow-domains/main/"
    const val REPO = "https://github.com/haritos90/allow-domains"

    /** Категории репозитория. id — короткое имя, по которому храним кеш. */
    val ALL: List<AllowList> = listOf(
        AllowList("youtube", "YouTube", ListSide.BLOCK, "Categories/01-youtube.lst"),
        AllowList("discord", "Discord", ListSide.BLOCK, "Categories/02-discord.lst",
            "Subnets/IPv4/02-discord.lst"),
        AllowList("meta", "Meta (Instagram/Facebook)", ListSide.BLOCK, "Categories/03-meta.lst",
            "Subnets/IPv4/03-meta.lst", "Subnets/IPv6/03-meta.lst"),
        AllowList("telegram", "Telegram", ListSide.BLOCK, "Categories/04-telegram.lst",
            "Subnets/IPv4/04-telegram.lst", "Subnets/IPv6/04-telegram.lst",
            "без подсетей Telegram не работает: клиенты ходят по IP, минуя DNS"),
        AllowList("twitter", "X / Twitter", ListSide.BLOCK, "Categories/05-twitter.lst",
            "Subnets/IPv4/05-twitter.lst", "Subnets/IPv6/05-twitter.lst"),
        AllowList("google-ai", "Google AI", ListSide.BLOCK, "Categories/06-google-ai.lst"),
        AllowList("google-play", "Google Play", ListSide.BLOCK, "Categories/07-google-play.lst"),
        AllowList("google-meet", "Google Meet", ListSide.BLOCK, "Categories/08-google-meet.lst",
            "Subnets/IPv4/08-google-meet.lst"),
        AllowList("tiktok", "TikTok", ListSide.BLOCK, "Categories/09-tiktok.lst"),
        AllowList("hdrezka", "HDRezka", ListSide.BLOCK, "Categories/10-hdrezka.lst"),
        AllowList("roblox", "Roblox", ListSide.BLOCK, "Categories/11-roblox.lst"),
        AllowList("openai", "OpenAI / ChatGPT", ListSide.BLOCK, "Categories/12-openai.lst"),
        AllowList("claude", "Anthropic Claude", ListSide.BLOCK, "Categories/13-claude.lst"),
        AllowList("hodla", "Ktop/spor ( Hodla)", ListSide.BLOCK, "Categories/14-hodca.lst",
            "Subnets/IPv4/14-hodca.lst", "Subnets/IPv6/14-hodca.lst"),
        AllowList("ru-ip-blocked", "Ресурсы, заблокированные для РФ-адресов", ListSide.BLOCK,
            "Categories/15-ru-ip-blocked.lst",
            note = "лежат с российского IP, через WARP оживают"),
        AllowList("news", "СМИ", ListSide.BLOCK, "Categories/16-news.lst"),
        AllowList("anime", "Аниме", ListSide.BLOCK, "Categories/17-anime.lst"),
        AllowList("adult", "18+", ListSide.BLOCK, "Categories/18-adult.lst"),
        AllowList("blocked", "Прочее заблокированное", ListSide.BLOCK, "Categories/19-blocked.lst"),
        AllowList("all-blocked", "Всё заблокированное (russia-all)", ListSide.BLOCK,
            "Russia/russia-all.lst"),

        // --- обратная сторона: то, что через туннель портится ---
        AllowList("hosters-blocked", "Сайты, банящие дата-центры", ListSide.DIRECT,
            "Categories/21-hosters-ip-blocked.lst",
            note = "Cloudflare/CDN отвечают 403 с арендованных IP — через WARP лягут, держим напрямую"),
        AllowList("russia-outside", "Российские сервисы с инфраструктурой за рубежом", ListSide.DIRECT,
            "Russia/russia-outside.lst",
            note = "банки/маркетплейсы: при чужом выходе часто не работают или просят подтверждение"),
        AllowList("zscaler", "Zscaler (только подсети)", ListSide.DIRECT, "Categories/20-zscaler.lst",
            "Subnets/IPv4/20-zscaler.lst", "Subnets/IPv6/20-zscaler.lst",
            note = "домена нет — корпоративный туннель ловится только по IP"),
        AllowList("all-subnets-v4", "Все подсети списков (v4)", ListSide.BLOCK, "Subnets/IPv4/all.lst"),
        AllowList("all-subnets-v6", "Все подсети списков (v6)", ListSide.BLOCK, "Subnets/IPv6/all.lst")
    )

    val byId: Map<String, AllowList> = ALL.associateBy { it.id }

    fun bySide(side: ListSide): List<AllowList> = ALL.filter { it.side == side }

    /**
     * Подсети, которых нет в самом списке, но без которых сервис из списка не работает (с 1.10.31).
     *
     * YouTube: видео идёт с серверов вида rr3---sn-xxxx.googlevideo.com — имена выдаются на каждое
     * видео, заранее их не узнать и через DoH не развернуть. В списке youtube 18 доменов, и в режиме
     * «из списков» видео шло мимо туннеля, где YouTube в России замедляют (журнал 22.11 23:08: «ютуб
     * работает хуже» — сразу после перехода на списки). Здесь собственные сети Google (AS15169), где
     * стоят эти серверы. Кеши Google внутри сетей провайдеров сюда не входят — для выбранных
     * приложений надёжнее «все сайты».
     *
     * 1.10.33: + 192.178.0.0/15. Сверка с открытым списком адресов YouTube (touhidurrr/iplist-youtube,
     * BSD-3, 17 765 адресов IPv4 на 22.11.2026): в двенадцати сетях ниже — 87 % адресов, ещё 8 % — в
     * 192.178.0.0/15, которой здесь не было; вместе — 95 %. Остальное — кеши внутри провайдеров и
     * подменённые ответы DNS (адреса Facebook, Twitter, Dropbox). IPv6: шесть сетей ниже — 99 %.
     *
     * Эти сети добавляются и при сборке маршрутов по спискам, и при подключении (см.
     * `Prefs.allowedIps` в приложении): маршруты, собранные прежней версией, их не содержали, а
     * пересобираются они только по «Сохранить и применить» — журнал 23.11: те же 683 маршрута с
     * 1.10.30 до 1.10.32, исправление 1.10.31 до телефона так и не дошло.
     */
    val EXTRA_PREFIXES: Map<String, List<String>> = mapOf(
        "youtube" to listOf(
            "64.233.160.0/19", "66.102.0.0/20", "72.14.192.0/18", "74.125.0.0/16", "108.177.0.0/17",
            "142.250.0.0/15", "172.217.0.0/16", "172.253.0.0/16", "173.194.0.0/16", "192.178.0.0/15",
            "209.85.128.0/17", "216.58.192.0/19", "216.239.32.0/19",
            "2001:4860::/32", "2404:6800::/32", "2607:f8b0::/32", "2800:3f0::/32", "2a00:1450::/32", "2c0f:fb50::/32",
        ),
    )

    /** Сети Google, откуда идёт видео YouTube (googlevideo.com), — то же, что у списка youtube выше. */
    val YOUTUBE_VIDEO_NETS: List<String> get() = EXTRA_PREFIXES["youtube"].orEmpty()

    /** ID категорий по умолчанию: то, что люди обычно и хотят пустить через WARP. */
    val DEFAULT_BLOCK_IDS = listOf("youtube", "discord", "telegram", "meta", "openai", "claude", "google-ai")

    fun url(path: String): String = RAW + path

    /**
     * Разбор `.lst`: домены и CIDR вперемешку, комментарии `#`/`;`, строки вида
     * `DOMAIN-SUFFIX,x.com` (surge) и `!x.com` — тоже понимаем, чтобы список из соседней папки
     * не заставил нас молча отдать пустой маршрут.
     */
    class Parsed(val domains: List<String>, val prefixes: List<String>) {
        val total: Int get() = domains.size + prefixes.size
        val isEmpty: Boolean get() = total == 0

        fun render(): String = buildString {
            appendLine("домены: ${domains.size}, подсети: ${prefixes.size}")
            if (domains.isNotEmpty()) appendLine("  примеры: ${domains.take(5).joinToString(", ")}")
            if (prefixes.isNotEmpty()) appendLine("  подсети: ${prefixes.take(5).joinToString(", ")}")
        }
    }

    private val DOMAIN_RE = Regex("""^[a-z0-9]([a-z0-9._-]*[a-z0-9])?\.[a-z]{2,}$""")
    private val V4_RE = Regex("""^\d{1,3}(\.\d{1,3}){3}/\d{1,2}$""")
    private val V6_RE = Regex("""^[0-9a-f:]+/\d{1,3}$""")

    fun parse(text: String): Parsed {
        val domains = LinkedHashSet<String>()
        val prefixes = LinkedHashSet<String>()
        for (raw in text.lineSequence()) {
            var line = raw.trim()
            if (line.isEmpty() || line.startsWith("#") || line.startsWith(";")) continue
            if (line.startsWith("!")) line = line.removePrefix("!").trim()
            if (line.startsWith("||")) line = line.removePrefix("||").trim()   // uBlock-формат
            if (line.startsWith("DOMAIN-SUFFIX,") || line.startsWith("DOMAIN,")) {
                line = line.substringAfter(',').trim()
            }
            if (line.startsWith("IP-CIDR,") || line.startsWith("IP-CIDR6,")) line = line.substringAfter(',').trim()
            line = line.removePrefix("*").removePrefix(".").trimEnd('.').lowercase()
            if (line.isEmpty()) continue
            when {
                V4_RE.matches(line) || V6_RE.matches(line) -> prefixes.add(line)
                DOMAIN_RE.matches(line) -> domains.add(line)
                else -> Unit     // мусор, CIDR без маски, голые хосты без точки — не берём
            }
        }
        return Parsed(domains.toList(), prefixes.toList())
    }

    /** Готовые маршруты из подсетей списка (без резолвинга) — самый надёжный вариант. */
    fun prefixesOf(parsed: Parsed): List<String> = parsed.prefixes

    /**
     * Проверки доступности по списку: берём первые [limit] доменов. Имя проверки — «категория · домен»,
     * чтобы в отчёте было видно, про какую половину списка речь.
     */
    fun checksFor(list: AllowList, parsed: Parsed, limit: Int = 4): List<ResourceCheck> {
        val picked = parsed.domains.take(limit)
        return picked.map { d ->
            ResourceCheck(
                name = "${list.title} · $d",
                url = "https://$d/",
                // 403/404 от CDN — тоже «достучались»: нас интересует, не лежит ли коннект
                expectStatus = 200..599,
                baselineExpected = list.side == ListSide.DIRECT,
                timeoutMs = 6000
            )
        }
    }

    // ------------------------------------------------------------- кеш и загрузка

    /** Кеш одного списка: текст + метка времени, чтобы UI говорил «обновлён 2 ч назад». */
    data class Cached(val list: AllowList, val text: String, val fetchedAt: Long) {
        val parsed: Parsed get() = parse(text)
    }

    fun readCache(store: ListStore, list: AllowList): Cached? {
        val raw = store.read(list.id) ?: return null
        val stamp = if (store is FileListStore) store.stamp(list.id) else 0L
        return Cached(list, raw, stamp)
    }

    fun loadAll(store: ListStore, lists: List<AllowList> = ALL): Map<String, Cached> =
        lists.mapNotNull { readCache(store, it) }.associateBy { it.list.id }

    /** Что уже лежит в кеше: id → дата. По этому UI решает, надо ли тянуть сеть. */
    fun cachedIds(store: ListStore): Map<String, Long> = loadAll(store).mapValues { it.value.fetchedAt }

    /** Просто дата/свежесть по метке времени — для строчки состояния. */
    fun freshnessOf(at: Long, now: Long = System.currentTimeMillis()): String =
        freshness(if (at <= 0L) null else Cached(ALL.first(), "", at), now)

    /** Свежесть списка по-человечески: «обновлён 14:32» / «обновлён 3 дн назад» / «в кеше нет». */
    fun freshness(cached: Cached?, now: Long = System.currentTimeMillis()): String {
        if (cached == null) return "в кеше нет"
        val ageH = (now - cached.fetchedAt) / 3_600_000L
        return when {
            cached.fetchedAt <= 0L -> "есть в кеше (дата неизвестна)"
            ageH < 1 -> "обновлён только что"
            ageH < 48 -> "обновлён ${ageH} ч назад"
            else -> "обновлён ${ageH / 24} дн назад — стоит обновить"
        }
    }

    /** Скачивание: один список → текст. Возвращает null, если сеть молчит (тогда остаёмся на кеше). */
    fun fetch(http: (String) -> String?, list: AllowList): Map<String, String> {
        val out = LinkedHashMap<String, String>()
        out["domains"] = http(url(list.domains)) ?: return emptyMap()
        list.subnetsV4?.let { out["v4"] = http(url(it)) ?: "" }
        list.subnetsV6?.let { out["v6"] = http(url(it)) ?: "" }
        return out
    }

    /** Склеивает скачанные куски в один текст: парсер различает домены и CIDR сам. */
    fun merge(parts: Map<String, String>): String =
        listOf("domains", "v4", "v6").mapNotNull { parts[it] }.filter { it.isNotBlank() }.joinToString("\n")
}
