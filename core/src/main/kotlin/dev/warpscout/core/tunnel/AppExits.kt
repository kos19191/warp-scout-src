package dev.warpscout.core.tunnel

import java.net.InetAddress
import java.net.InetSocketAddress

/**
 * Выход по приложениям (с 1.10.39): «Само» / «Всегда WARP» / «Второй выход».
 *
 * Зачем. До 1.10.39 выход решался только по адресу назначения ([ExitRouter]): сайты из списков
 * второго выхода — через свой сервер, остальное — через WARP. Человек написал 23.11: «дай
 * возможность пропускать через второй канал любые приложения и отключать второй канал для них».
 * Telegram через Москву работал, через второй выход медиа не грузилось, а убрать его со второго
 * выхода можно было, только выключив второй выход целиком. А Aurora Store ходила с российского
 * адреса, хотя ей нужен зарубежный.
 *
 * Правило — на приложение:
 *  • [AUTO] — как раньше: по адресу ([ExitRouter]);
 *  • [WARP] — всегда WARP: второй выход для приложения выключен, даже к сайтам из его списков;
 *  • [SECOND] — приложение целиком через второй выход.
 *
 * Как узнать приложение. В tun приходят голые IP-пакеты, без пометки, чей пакет. С Android 10 VPN
 * может спросить систему, какому приложению принадлежит соединение
 * (`ConnectivityManager.getConnectionOwnerUid` — так делают RethinkDNS и NetGuard). Спрашиваем один
 * раз на соединение и запоминаем; и только когда ответ может что-то поменять (см. [AppExitTable.decide]).
 */
object AppExit {
    const val AUTO = 0
    const val WARP = 1
    const val SECOND = 2

    /** Строка снимка «пакет|правило» → пара. «Само» не хранится; кривая строка — null. */
    fun decode(line: String): Pair<String, Int>? {
        val pkg = line.substringBefore('|').trim()
        val rule = line.substringAfter('|', "").trim().toIntOrNull() ?: return null
        if (pkg.isEmpty() || (rule != WARP && rule != SECOND)) return null
        return pkg to rule
    }

    fun encode(pkg: String, rule: Int): String = "$pkg|$rule"

    fun decodeAll(lines: Collection<String>): Map<String, Int> {
        val out = LinkedHashMap<String, Int>()
        lines.forEach { line -> decode(line)?.let { (pkg, rule) -> out[pkg] = rule } }
        return out
    }

    /** Для снимка: только «WARP» и «Второй выход», по имени пакета — снимок не «меняется» сам. */
    fun encodeAll(rules: Map<String, Int>): List<String> = rules
        .filter { (pkg, rule) -> pkg.isNotBlank() && (rule == WARP || rule == SECOND) }
        .toSortedMap()
        .map { (pkg, rule) -> encode(pkg, rule) }

    /** Общий uid у нескольких пакетов: «Второй выход» сильнее «WARP», «WARP» сильнее «Само». */
    fun stronger(a: Int, b: Int): Int = maxOf(a, b)
}

/**
 * Соединение из пакета tun: протокол, адреса и порты. Только TCP и UDP, без заголовков расширения
 * IPv6; фрагмент IPv4 без начала (портов в нём нет) — null.
 */
class FlowKey private constructor(
    val proto: Int,
    val src: ByteArray,
    val sport: Int,
    val dst: ByteArray,
    val dport: Int,
) {
    private val hash: Int = (((proto * 31 + src.contentHashCode()) * 31 + sport) * 31 + dst.contentHashCode()) * 31 + dport

    override fun equals(other: Any?): Boolean =
        other is FlowKey && proto == other.proto && sport == other.sport && dport == other.dport &&
            src.contentEquals(other.src) && dst.contentEquals(other.dst)

    override fun hashCode(): Int = hash

    val local: InetSocketAddress get() = InetSocketAddress(InetAddress.getByAddress(src), sport)
    val remote: InetSocketAddress get() = InetSocketAddress(InetAddress.getByAddress(dst), dport)

    companion object {
        const val TCP = 6
        const val UDP = 17

        private fun u16(p: ByteArray, off: Int): Int = ((p[off].toInt() and 0xFF) shl 8) or (p[off + 1].toInt() and 0xFF)

        fun of(p: ByteArray, len: Int = p.size): FlowKey? {
            if (len < 1 || len > p.size) return null
            when ((p[0].toInt() ushr 4) and 0x0F) {
                4 -> {
                    if (len < 20) return null
                    val ihl = (p[0].toInt() and 0x0F) * 4
                    if (ihl < 20 || len < ihl + 4) return null
                    // Смещение фрагмента не ноль — портов в пакете нет.
                    val fragOffset = ((p[6].toInt() and 0x1F) shl 8) or (p[7].toInt() and 0xFF)
                    if (fragOffset != 0) return null
                    val proto = p[9].toInt() and 0xFF
                    if (proto != TCP && proto != UDP) return null
                    return FlowKey(proto, p.copyOfRange(12, 16), u16(p, ihl), p.copyOfRange(16, 20), u16(p, ihl + 2))
                }

                6 -> {
                    if (len < 44) return null
                    val proto = p[6].toInt() and 0xFF
                    if (proto != TCP && proto != UDP) return null
                    return FlowKey(proto, p.copyOfRange(8, 24), u16(p, 40), p.copyOfRange(24, 40), u16(p, 42))
                }
            }
            return null
        }

        /**
         * Пакет открывает соединение TCP: флаг SYN без ACK (с 1.10.43). По нему автовыбор выхода
         * отличает новое соединение от уже идущего: идущее на другой выход не переносим — у другого
         * выхода другой адрес отправителя, и соединение оборвалось бы.
         */
        fun isTcpOpen(p: ByteArray, len: Int = p.size): Boolean {
            if (len < 1 || len > p.size) return false
            val flags = when ((p[0].toInt() ushr 4) and 0x0F) {
                4 -> {
                    if (len < 20) return false
                    val ihl = (p[0].toInt() and 0x0F) * 4
                    if (ihl < 20 || len < ihl + 14 || (p[9].toInt() and 0xFF) != TCP) return false
                    p[ihl + 13].toInt() and 0xFF
                }

                6 -> {
                    if (len < 54 || (p[6].toInt() and 0xFF) != TCP) return false
                    p[53].toInt() and 0xFF
                }

                else -> return false
            }
            return (flags and 0x02) != 0 && (flags and 0x10) == 0
        }
    }
}

/**
 * Правила выхода на одну сессию туннеля: uid приложения → [AppExit]. Решает диспетчер tun
 * ([TunDispatcher.appExits]) — один поток, поэтому таблица соединений без замков.
 *
 * @param rules  uid → [AppExit.WARP] или [AppExit.SECOND] (остальное — «Само»)
 * @param owner  чьё соединение: (протокол, свой адрес, адрес назначения) → uid; меньше нуля — не знаю
 * @param names  uid → название приложения для журнала
 * @param strict uid приложений «только второй выход» (с 1.10.44-beta1, TikTok): их правило
 *               [AppExit.SECOND] без запасного пути через WARP — см. [lastStrict]
 */
class AppExitTable(
    rules: Map<Int, Int>,
    private val owner: (Int, InetSocketAddress, InetSocketAddress) -> Int,
    private val names: Map<Int, String> = emptyMap(),
    private val log: (String) -> Unit = {},
    private val maxFlows: Int = 4096,
    private val clock: () -> Long = System::currentTimeMillis,
    private val strict: Set<Int> = emptySet(),
) {
    private val rules: Map<Int, Int> = rules.filterValues { it == AppExit.WARP || it == AppExit.SECOND }
    private val anyWarp = this.rules.values.any { it == AppExit.WARP }
    private val anySecond = this.rules.values.any { it == AppExit.SECOND }

    /**
     * Автовыбор выхода (эксперимент, с 1.10.43, см. AppAuto): uid → [AppExit.SECOND] или
     * [AppExit.WARP] по замерам сервиса, меняется на ходу ([setAuto]). Ручное правило сильнее. Переезжают
     * только новые соединения — уже идущие TCP остаются на своём выходе — и только по IPv4: по IPv6
     * второй выход часто не ходит, а фильтры на московской площадке режут именно IPv4.
     */
    @Volatile
    private var auto: Map<Int, Int> = emptyMap()

    @Volatile
    private var autoWarp = false

    @Volatile
    private var autoSecond = false

    /**
     * Правило пропало (WARP снова в порядке, эксперимент выключили), а соединения, открытые по нему,
     * ещё идут: [LINGER_MS] они идут прежним путём — иначе переехали бы на другой выход и оборвались.
     * Новые соединения — уже по новым правилам. Без этого таблица без ручных правил переставала бы
     * смотреть на пакеты вовсе, и все такие соединения переехали бы разом.
     */
    @Volatile
    private var lingerSecond = false

    @Volatile
    private var lingerWarp = false

    @Volatile
    private var lingerUntil = 0L

    /** Новые автоправила (прежние заменяются целиком); у приложений с ручным правилом — не действуют. */
    fun setAuto(next: Map<Int, Int>) {
        val clean = next.filter { (uid, rule) -> uid !in rules && (rule == AppExit.WARP || rule == AppExit.SECOND) }
        val hadSecond = autoSecond || lingerSecond
        val hadWarp = autoWarp || lingerWarp
        auto = clean
        autoWarp = clean.values.any { it == AppExit.WARP }
        autoSecond = clean.values.any { it == AppExit.SECOND }
        if ((hadSecond && !autoSecond) || (hadWarp && !autoWarp)) {
            lingerUntil = clock() + LINGER_MS
            if (hadSecond && !autoSecond) lingerSecond = true
            if (hadWarp && !autoWarp) lingerWarp = true
        }
    }

    /** Действующие автоправила. */
    fun autoRules(): Map<Int, Int> = auto

    val isEmpty: Boolean get() = rules.isEmpty() && auto.isEmpty()

    /**
     * Последний [decide] отправил пакет приложения «только второй выход» во второй выход (с
     * 1.10.44-beta1, см. [strict]). TikTok запоминает регион по адресу: стоит ему один раз сходить
     * через московский WARP — и лента снова «российская», даже когда второй выход вернётся. Поэтому
     * диспетчер такой пакет при упавшем втором выходе не отдаёт в WARP, а придерживает. Пишет и
     * читает один поток — диспетчер tun.
     */
    var lastStrict: Boolean = false
        private set

    /**
     * Во второй выход по правилу приложения: uid → [пакетов, байт] (с 1.10.44-beta1). Только то, что
     * приложение отправило (из tun) — ответы диспетчер не видит, но и по этим цифрам ясно, ходит ли
     * TikTok через второй выход и сколько. Пишет диспетчер, читает строка статистики.
     */
    private val perUid = java.util.concurrent.ConcurrentHashMap<Int, LongArray>()

    /** Отметки для [secondUsage] «за интервал»: uid → [пакетов, байт] на прошлый вызов. */
    private val marks = HashMap<Int, LongArray>()

    /** Соединение → правило его приложения и uid (см. [encode]). Старые вытесняются: соединение спросим ещё раз. */
    private val flows = object : LinkedHashMap<FlowKey, Int>(256, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<FlowKey, Int>?): Boolean = size > maxFlows
    }

    /** О каком приложении уже написали в журнал (один раз на сессию). */
    private val announced = HashSet<Int>()

    @Volatile
    var lookups: Long = 0L
        private set

    /** Система не назвала владельца (соединение уже закрыто или чужое). */
    @Volatile
    var misses: Long = 0L
        private set

    @Volatile
    var lookupNanos: Long = 0L
        private set

    @Volatile
    var maxLookupNanos: Long = 0L
        private set

    /** Пакетов, ушедших не туда, куда вёл адрес: через второй выход по правилу и через WARP по правилу. */
    @Volatile
    var movedToSecond: Long = 0L
        private set

    @Volatile
    var movedToWarp: Long = 0L
        private set

    /**
     * Android не называет владельцев совсем: первые [FAIL_LIMIT] запросов подряд без ответа. Тогда
     * дальше не спрашиваем — каждый вопрос стоит вызова системы, а толку нет; в журнале — строка.
     */
    @Volatile
    var disabled: Boolean = false
        private set

    /**
     * Куда отправить пакет. [base] — решение по адресу ([ExitRouter.route]: 0 — WARP, 1 — второй
     * выход); правило приложения его перекрывает. Владельца спрашиваем, только если ответ может
     * что-то поменять: адрес ведёт во второй выход, а у кого-то «Всегда WARP», — или адрес ведёт в
     * WARP, а у кого-то «Второй выход». DNS (порт 53) — как решил адрес: запросов много, каждый —
     * новое соединение, а ответы DNS от страны выхода почти не зависят.
     */
    fun decide(p: ByteArray, len: Int, base: Int): Int {
        lastStrict = false
        if (disabled) return base
        // Часы — только пока доживают соединения снятого правила (см. lingerSecond): это редкость.
        if ((lingerSecond || lingerWarp) && clock() > lingerUntil) {
            lingerSecond = false
            lingerWarp = false
        }
        val need = (base == 1 && (anyWarp || autoWarp || lingerWarp)) || (base == 0 && (anySecond || autoSecond || lingerSecond))
        if (!need) return base
        return try {
            val key = FlowKey.of(p, len) ?: return base
            if (key.dport == 53 || key.sport == 53) return base
            val code = flows[key] ?: lookup(key, p, len).also { flows[key] = it }
            val rule = code and RULE_MASK
            when (rule) {
                AppExit.WARP -> {
                    if (base != 0) movedToWarp++
                    0
                }

                AppExit.SECOND, SECOND_STRICT -> {
                    if (base != 1) movedToSecond++
                    if (rule == SECOND_STRICT) lastStrict = true
                    val uid = (code ushr RULE_BITS) - 1
                    if (uid >= 0) {
                        val n = perUid.getOrPut(uid) { LongArray(2) }
                        n[0]++
                        n[1] += len.toLong()
                    }
                    1
                }

                else -> base
            }
        } catch (e: Exception) {
            base
        }
    }

    private fun lookup(key: FlowKey, p: ByteArray, len: Int): Int {
        val t0 = System.nanoTime()
        val uid = try {
            owner(key.proto, key.local, key.remote)
        } catch (e: Exception) {
            -1
        }
        val dt = System.nanoTime() - t0
        lookups++
        lookupNanos += dt
        if (dt > maxLookupNanos) maxLookupNanos = dt
        if (uid < 0) {
            misses++
            if (misses >= FAIL_LIMIT && misses == lookups) {
                disabled = true
                log(
                    "выход по приложениям не работает: Android не называет владельцев соединений " +
                        "($misses запросов без ответа) — приложения идут как «Само», по адресам"
                )
            }
            return AppExit.AUTO
        }
        val rule = rules[uid] ?: return encode(uid, autoRule(uid, key, p, len))
        val effective = if (rule == AppExit.SECOND && uid in strict) SECOND_STRICT else rule
        if (announced.add(uid)) {
            val name = names[uid] ?: "uid $uid"
            log(
                when (effective) {
                    SECOND_STRICT -> "выход по приложениям: $name — целиком и только через второй выход (так выбрано): " +
                        "если второй выход ляжет, $name подождёт его, через WARP не пойдёт"
                    AppExit.SECOND -> "выход по приложениям: $name — целиком через второй выход (так выбрано)"
                    else -> "выход по приложениям: $name — всегда через WARP, второй выход для него выключен (так выбрано)"
                }
            )
        }
        return encode(uid, effective)
    }

    /** Правило и uid в одном числе — так таблица соединений помнит и то и другое без лишних объектов. */
    private fun encode(uid: Int, rule: Int): Int = ((uid + 1) shl RULE_BITS) or (rule and RULE_MASK)

    /** Названия приложений «только второй выход» — для строки журнала диспетчера. */
    fun strictNames(): String = strict.mapNotNull { names[it] }.distinct().sorted().joinToString(", ").ifBlank { "TikTok" }

    /** Правило приложения, выбранное человеком ([AppExit.WARP] / [AppExit.SECOND]); нет — [AppExit.AUTO]. */
    fun manualRuleOf(uid: Int): Int = rules[uid] ?: AppExit.AUTO

    /**
     * Что ушло во второй выход по правилу приложения: (название, пакетов, байт), больше всего — первым.
     * [sinceLast] — за интервал с прошлого такого вызова (строка статистики раз в 5 минут), иначе — за сессию.
     */
    fun secondUsage(sinceLast: Boolean): List<Triple<String, Long, Long>> {
        val out = ArrayList<Triple<String, Long, Long>>()
        synchronized(marks) {
            perUid.forEach { (uid, n) ->
                val packets = n[0]
                val bytes = n[1]
                val m = if (sinceLast) marks.getOrPut(uid) { LongArray(2) } else null
                val dp = packets - (m?.get(0) ?: 0L)
                val db = bytes - (m?.get(1) ?: 0L)
                if (m != null) {
                    m[0] = packets
                    m[1] = bytes
                }
                if (dp > 0) out += Triple(names[uid] ?: "uid $uid", dp, db)
            }
        }
        return out.sortedByDescending { it.third }
    }

    /** «TikTok 1520 пак. (0,3 МБ), ChatGPT 12 пак. (4 КБ)» — пусто, если во второй выход по правилам ничего не ушло. */
    fun secondUsageText(sinceLast: Boolean): String = secondUsage(sinceLast).joinToString(", ") { (name, packets, bytes) ->
        "$name $packets пак. (${sizeText(bytes)})"
    }

    /**
     * Автоправило для соединения (см. [auto]): только IPv4, и для TCP — только если это первый пакет
     * соединения (SYN). Соединение, которое уже шло, когда правило появилось, остаётся «Само».
     */
    private fun autoRule(uid: Int, key: FlowKey, p: ByteArray, len: Int): Int {
        val rule = auto[uid] ?: return AppExit.AUTO
        if (key.dst.size != 4) return AppExit.AUTO
        if (key.proto == FlowKey.TCP && !FlowKey.isTcpOpen(p, len)) return AppExit.AUTO
        return rule
    }

    /** Строка в журнал: сколько спрашивали и сколько это стоило. */
    fun summary(): String {
        val avg = if (lookups > 0) lookupNanos / lookups / 1000 else 0L
        return "выход по приложениям: запросов владельца $lookups (не названо $misses), в среднем ${avg} мкс, " +
            "дольше всего ${maxLookupNanos / 1000} мкс; пакетов через второй выход по правилу $movedToSecond, " +
            "через WARP по правилу $movedToWarp" + (if (auto.isNotEmpty()) "; автовыбор: правил ${auto.size}" else "") +
            secondUsageText(false).let { if (it.isEmpty()) "" else "; во второй выход по правилам (вверх): $it" } +
            if (disabled) " — выключено: Android не отвечает" else ""
    }

    companion object {
        const val FAIL_LIMIT = 64L

        /** Внутреннее правило «только второй выход» (с 1.10.44-beta1): в настройках его нет, это [AppExit.SECOND] + [strict]. */
        const val SECOND_STRICT = 3

        /** Сколько младших бит числа в таблице соединений занимает правило (см. [encode]). */
        const val RULE_BITS = 4
        const val RULE_MASK = (1 shl RULE_BITS) - 1

        /** «512 Б», «48 КБ», «1,4 МБ» — для строк журнала. */
        fun sizeText(bytes: Long): String = when {
            bytes < 1024 -> "$bytes Б"
            bytes < 1024 * 1024 -> "${bytes / 1024} КБ"
            else -> String.format(java.util.Locale("ru"), "%.1f МБ", bytes / 1048576.0)
        }

        /** Сколько доживают соединения снятого автоправила (см. lingerSecond). */
        const val LINGER_MS = 10 * 60_000L
    }
}
