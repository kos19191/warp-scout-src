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
    }
}

/**
 * Правила выхода на одну сессию туннеля: uid приложения → [AppExit]. Решает диспетчер tun
 * ([TunDispatcher.appExits]) — один поток, поэтому таблица соединений без замков.
 *
 * @param rules  uid → [AppExit.WARP] или [AppExit.SECOND] (остальное — «Само»)
 * @param owner  чьё соединение: (протокол, свой адрес, адрес назначения) → uid; меньше нуля — не знаю
 * @param names  uid → название приложения для журнала
 */
class AppExitTable(
    rules: Map<Int, Int>,
    private val owner: (Int, InetSocketAddress, InetSocketAddress) -> Int,
    private val names: Map<Int, String> = emptyMap(),
    private val log: (String) -> Unit = {},
    private val maxFlows: Int = 4096,
) {
    private val rules: Map<Int, Int> = rules.filterValues { it == AppExit.WARP || it == AppExit.SECOND }
    private val anyWarp = this.rules.values.any { it == AppExit.WARP }
    private val anySecond = this.rules.values.any { it == AppExit.SECOND }

    val isEmpty: Boolean get() = rules.isEmpty()

    /** Соединение → правило его приложения. Старые вытесняются: соединение спросим ещё раз. */
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
        if (disabled) return base
        val need = (base == 1 && anyWarp) || (base == 0 && anySecond)
        if (!need) return base
        return try {
            val key = FlowKey.of(p, len) ?: return base
            if (key.dport == 53 || key.sport == 53) return base
            val rule = flows[key] ?: lookup(key).also { flows[key] = it }
            when (rule) {
                AppExit.WARP -> {
                    if (base != 0) movedToWarp++
                    0
                }

                AppExit.SECOND -> {
                    if (base != 1) movedToSecond++
                    1
                }

                else -> base
            }
        } catch (e: Exception) {
            base
        }
    }

    private fun lookup(key: FlowKey): Int {
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
        val rule = rules[uid] ?: AppExit.AUTO
        if (rule != AppExit.AUTO && announced.add(uid)) {
            val name = names[uid] ?: "uid $uid"
            log(
                when (rule) {
                    AppExit.SECOND -> "выход по приложениям: $name — целиком через второй выход (так выбрано)"
                    else -> "выход по приложениям: $name — всегда через WARP, второй выход для него выключен (так выбрано)"
                }
            )
        }
        return rule
    }

    /** Строка в журнал: сколько спрашивали и сколько это стоило. */
    fun summary(): String {
        val avg = if (lookups > 0) lookupNanos / lookups / 1000 else 0L
        return "выход по приложениям: запросов владельца $lookups (не названо $misses), в среднем ${avg} мкс, " +
            "дольше всего ${maxLookupNanos / 1000} мкс; пакетов через второй выход по правилу $movedToSecond, " +
            "через WARP по правилу $movedToWarp" + if (disabled) " — выключено: Android не отвечает" else ""
    }

    companion object {
        const val FAIL_LIMIT = 64L
    }
}
