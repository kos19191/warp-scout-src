package dev.warpscout.core.net

/**
 * Площадка Cloudflare, через которую выходит WARP (с 1.10.34): «DME» — Москва, «HEL» — Хельсинки.
 *
 * Зачем. Журнал 23.11: с 07:39 все точки выходили через Москву (DME), а до того на Wi-Fi — через
 * Хельсинки (HEL). Через московскую площадку трафик выходит в российский интернет и попадает под
 * фильтры РКН. С февраля 2026 так замедляют медиа Telegram — человек написал ровно это: «соединение
 * быстрое, но медиа загружается через раз и рывками», и на Wi-Fi, и на LTE. Площадку выбирает
 * маршрут оператора до Cloudflare, а не приложение: одна и та же точка 8.6.112.7:968 (22.11, 21:21)
 * дала Москву на LTE и Хельсинки на Wi-Fi через шесть секунд. Но разные подсети Cloudflare приходят
 * на разные площадки (22.11 на Wi-Fi: 162.159.192.x — HEL, 188.114.97.1 — FRA), поэтому подбор
 * узнаёт площадку каждой точки и ставит выход вне России первым.
 *
 * Здесь только правила, без сети и файлов: разбор кода площадки, «российская ли она», город для
 * экрана, порядок «за рубежом → неизвестно → в России» и память «на этой сети у этой точки такая
 * площадка». Хранит память приложение (SiteMemory), правила проверяет SelfCheck.
 */
object ExitSite {

    /**
     * Площадки Cloudflare в России (DME, LED, KJA, SVX) и коды аэропортов других российских
     * городов — на случай, если Cloudflare откроет площадку и там: ошибиться в сторону «в России»
     * безопаснее, чем принять московский фильтр за заграницу.
     */
    val RUSSIAN: Set<String> = setOf(
        "DME", "SVO", "VKO", "LED", "KJA", "SVX", "OVB", "KZN", "ROV", "KRR", "AER", "UFA",
        "VVO", "KHV", "IKT", "KGD", "GOJ", "KUF", "CEK", "PEE", "TJM", "OMS", "MRV", "MCX",
        "ARH", "MMK", "SGC", "NJC", "BAX", "UUD", "YKS", "VOG", "IJK", "ASF", "STW", "NBC"
    )

    /** Города площадок — для экрана и журнала. Нет в списке — показывается сам код. */
    private val CITY: Map<String, String> = mapOf(
        "DME" to "Москва", "SVO" to "Москва", "VKO" to "Москва", "LED" to "Санкт-Петербург",
        "KJA" to "Красноярск", "SVX" to "Екатеринбург", "OVB" to "Новосибирск", "KZN" to "Казань",
        "ROV" to "Ростов-на-Дону", "KRR" to "Краснодар", "AER" to "Сочи", "UFA" to "Уфа",
        "VVO" to "Владивосток", "KHV" to "Хабаровск", "IKT" to "Иркутск", "KGD" to "Калининград",
        "GOJ" to "Нижний Новгород", "KUF" to "Самара", "CEK" to "Челябинск", "PEE" to "Пермь",
        "HEL" to "Хельсинки", "ARN" to "Стокгольм", "TLL" to "Таллин", "RIX" to "Рига",
        "VNO" to "Вильнюс", "WAW" to "Варшава", "FRA" to "Франкфурт", "AMS" to "Амстердам",
        "CPH" to "Копенгаген", "OSL" to "Осло", "PRG" to "Прага", "VIE" to "Вена",
        "BUD" to "Будапешт", "OTP" to "Бухарест", "SOF" to "София", "KIV" to "Кишинёв",
        "MSQ" to "Минск", "KBP" to "Киев", "IST" to "Стамбул", "TBS" to "Тбилиси",
        "EVN" to "Ереван", "GYD" to "Баку", "ALA" to "Алматы", "NQZ" to "Астана",
        "TAS" to "Ташкент", "FRU" to "Бишкек", "LHR" to "Лондон", "CDG" to "Париж",
        "MAD" to "Мадрид", "MXP" to "Милан", "ZRH" to "Цюрих", "DUS" to "Дюссельдорф",
        "HAM" to "Гамбург", "MUC" to "Мюнхен", "BER" to "Берлин", "TXL" to "Берлин",
        "BRU" to "Брюссель", "DUB" to "Дублин", "LIS" to "Лиссабон", "ATH" to "Афины",
        "BEG" to "Белград", "ZAG" to "Загреб", "LJU" to "Любляна", "BTS" to "Братислава",
        "DXB" to "Дубай", "SIN" to "Сингапур", "NRT" to "Токио", "HKG" to "Гонконг"
    )

    /**
     * Код площадки из текста: «DME», «dme», «"DME"» → «DME». Три латинские буквы, после них — не
     * буква (Cloudflare отвечает ровно кодом; запас — на «DME1»/«DME-…»). Иначе — пусто.
     */
    fun normalize(text: String?): String {
        val t = text.orEmpty().trim().trim('"').trim()
        if (t.length < 3) return ""
        val head = t.take(3).uppercase()
        if (!head.all { it in 'A'..'Z' }) return ""
        if (t.length > 3 && t[3].isLetter()) return ""
        return head
    }

    /**
     * Площадка из строки проверки связи сервиса («DME · RU · 104.28.244.74», см. CfTrace.summary);
     * пусто — её там нет (строка начинается со страны или пустая).
     */
    fun fromSummary(summary: String?): String {
        val first = summary.orEmpty().split('·').map { it.trim() }.firstOrNull().orEmpty()
        return if (first.length == 3 && first.all { it in 'A'..'Z' }) first else ""
    }

    /** Выход в России — трафик выходит в российский интернет, под фильтры РКН. */
    fun isRussian(site: String?): Boolean = normalize(site).let { it.isNotEmpty() && it in RUSSIAN }

    /** Выход известен и он не в России. */
    fun isAbroad(site: String?): Boolean = normalize(site).let { it.isNotEmpty() && it !in RUSSIAN }

    /** Для порядка: за рубежом — 2, неизвестно — 1, в России — 0. */
    fun rank(site: String?): Int = when {
        isAbroad(site) -> 2
        isRussian(site) -> 0
        else -> 1
    }

    /** Город площадки («Москва»); такого кода не знаем — сам код; кода нет — пусто. */
    fun city(site: String?): String {
        val s = normalize(site)
        return CITY[s] ?: s
    }

    /**
     * Город для «через …» (с 1.10.36, вопрос про Telegram): «через Москву», «через Уфу»; у остальных
     * городов России форма та же («через Санкт-Петербург», «через Казань»).
     */
    fun cityAcc(site: String?): String {
        val c = city(site)
        return if (c.endsWith("а") && c.length > 1 && c[c.length - 2] !in "аеёиоуыэюя") c.dropLast(1) + "у" else c
    }

    /** «DME · Москва» — для журнала; неизвестно — так и пишется. */
    fun describe(site: String?): String {
        val s = normalize(site)
        if (s.isEmpty()) return "неизвестно"
        val c = CITY[s] ?: return s
        return "$s · $c"
    }

    /** Устойчивый порядок: за рубежом → неизвестно → в России; внутри групп — как было. */
    fun <T> abroadFirst(items: List<T>, siteOf: (T) -> String?): List<T> =
        items.withIndex()
            .sortedWith(compareByDescending<IndexedValue<T>> { rank(siteOf(it.value)) }.thenBy { it.index })
            .map { it.value }

    // ── память: какая площадка у точки на этой сети ────────────────────────────────

    /**
     * Что узнали: на сети [net] («Wi-Fi·192.168.1.1», «мобильная·25020») точка [endpoint] выходит
     * через [site]. Запись с endpoint = [SEARCH] — не точка, а итог поиска выхода за рубежом на этой
     * сети: site = [FOUND] — нашёлся, [NONE] — не нашёлся (тогда следующий поиск — через сутки).
     */
    data class Mark(val net: String, val endpoint: String, val site: String, val at: Long)

    const val SEARCH = "*"
    const val FOUND = "+"
    const val NONE = "-"

    /**
     * Запись с endpoint = [LIVE] — площадка, которую последней показала проверка связи работающего
     * туннеля на этой сети (а не подбор): по ней решается, пора ли искать выход за рубежом.
     */
    const val LIVE = "@"

    /** Записей не больше: сетей у человека две-три, точек в их очередях — десятки. */
    const val MAX_MARKS = 160

    /**
     * Сколько верить записи о точке. Маршруты операторов меняются (23.11 Wi-Fi перешёл с HEL на DME
     * за минуту), но подключение каждый раз обновляет запись своей точки, а для порядка перебора
     * старое знание — всё равно лучше, чем никакого.
     */
    const val FRESH_MS = 3L * 24 * 3_600_000L

    /** Поиск выхода за рубежом на одной сети — не чаще раза в сутки (так решил человек 23.11). */
    const val SEARCH_GAP_MS = 24L * 3_600_000L

    /** Разбор файла памяти: «сеть|точка|площадка|время» в строке; битые строки пропускаются. */
    fun parse(text: String?): List<Mark> = text.orEmpty().lineSequence().mapNotNull { line ->
        val p = line.split('|')
        if (p.size < 4) return@mapNotNull null
        val net = p[0].trim()
        val endpoint = p[1].trim()
        val site = p[2].trim()
        val at = p[3].trim().toLongOrNull() ?: return@mapNotNull null
        if (net.isEmpty() || endpoint.isEmpty() || site.isEmpty()) return@mapNotNull null
        Mark(net, endpoint, site, at)
    }.toList()

    fun render(marks: List<Mark>): String = marks.joinToString("") { m ->
        "${clean(m.net)}|${clean(m.endpoint)}|${clean(m.site)}|${m.at}\n"
    }

    private fun clean(s: String): String = s.replace('|', '/').replace('\n', ' ').replace('\r', ' ').trim()

    /** Добавить или заменить запись (сеть + точка): свежие — в конец, давние уходят по пределу. */
    fun put(marks: List<Mark>, mark: Mark): List<Mark> {
        val rest = marks.filter { !(it.net == mark.net && it.endpoint == mark.endpoint) }
        return (rest + mark).takeLast(MAX_MARKS)
    }

    /** Площадка точки на этой сети по памяти; пусто — не знаем или запись устарела. */
    fun siteOf(marks: List<Mark>, net: String, endpoint: String, now: Long): String {
        if (net.isBlank() || endpoint.isBlank() || endpoint == SEARCH) return ""
        val m = marks.lastOrNull { it.net == net && it.endpoint == endpoint } ?: return ""
        if (now - m.at !in 0..FRESH_MS) return ""
        return normalize(m.site)
    }

    /** Последний поиск выхода за рубежом на этой сети (null — не искали). */
    fun lastSearch(marks: List<Mark>, net: String): Mark? =
        marks.lastOrNull { it.net == net && it.endpoint == SEARCH }

    /**
     * Пора ли искать выход за рубежом на этой сети: прошлого поиска не было или он был больше суток
     * назад. Нашёлся ли выход тогда — неважно: маршрут мог снова смениться.
     */
    fun searchDue(marks: List<Mark>, net: String, now: Long): Boolean {
        val last = lastSearch(marks, net) ?: return true
        return now - last.at !in 0 until SEARCH_GAP_MS
    }
}
