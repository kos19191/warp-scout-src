package dev.warpscout.core.dpi

/**
 * Стратегия обхода DPI в синтаксисе ByeDPI (с 1.10.49-beta4): «--split 1+s --disorder 3+s»,
 * «-f-1 -t5», «--tlsrec 1+s --auto=torst --oob 3+s».
 *
 * Телефон без root не запускает сам ByeDPI — приёмы шлёт наш код ([TrickSender]), поэтому здесь —
 * та часть ByeDPI, что делается обычным сокетом: разрез (`--split`), перестановка (`--disorder`,
 * TTL 1), срочный байт (`--oob`, `--disoob`), запись TLS на части (`--tlsrec`), версия записи
 * (`--tlsminor`), фейк (`--fake`, `--ttl`, `--fake-sni`) и группы `--auto` (не помогла первая —
 * пробуется следующая). Позиции — как у ByeDPI: `offset[:repeats:skip][+s|h|n[e|m|r|s]]`.
 *
 * Чего телефон не умеет (`--md5sig`, `--drop-sack`, свои данные фейка) и что ему не нужно (адрес и
 * порт прокси, списки доменов — обход и так только для выбранных сервисов), разбор пропускает и
 * пишет об этом в [notes]. Неизвестный ключ или кривая позиция — ошибка ([Parsed.error]).
 *
 * Как куски уходят в сеть — [DpiDesync] (порт desync.c ByeDPI, MIT); сам разбор — по main.c.
 */
class DpiStrategy private constructor(
    /** Строка, как её ввёл человек (без лишних пробелов). */
    val source: String,
    val groups: List<Group>,
    /** Что из строки пропущено и почему — для экрана. */
    val notes: List<String>,
    /** `--def-ttl`: TTL всех пакетов соединения; 0 — системный. */
    val defTtl: Int = 0,
    /** `--timeout`: сколько ждать ответ сервера на первое сообщение; 0 — как обычно. */
    val timeoutMs: Int = 0
) {
    enum class Mode(val flag: String) { SPLIT("--split"), DISORDER("--disorder"), OOB("--oob"), DISOOB("--disoob"), FAKE("--fake") }

    /** Позиция ByeDPI. [sni]/[host] — от начала имени сайта; [end]/[mid]/[rand] — конец, середина, случайно. */
    class Pos(
        val offset: Long,
        val repeats: Int = 0,
        val skip: Long = 0,
        val sni: Boolean = false,
        val host: Boolean = false,
        val end: Boolean = false,
        val mid: Boolean = false,
        val rand: Boolean = false,
        val start: Boolean = false
    ) {
        /** Есть флаг (part.flag у ByeDPI): от него зависит, как считается позиция `--tlsrec`. */
        val flagged: Boolean get() = sni || host || end || mid || rand || start

        override fun toString(): String = buildString {
            append(offset)
            if (repeats > 0) {
                append(':').append(repeats)
                if (skip != 0L) append(':').append(skip)
            }
            val first = when {
                sni -> "s"
                host -> "h"
                end || mid || rand || start -> "n"
                else -> ""
            }
            if (first.isNotEmpty()) {
                append('+').append(first)
                when {
                    end -> append('e')
                    mid -> append('m')
                    rand -> append('r')
                    start -> append('s')
                }
            }
        }
    }

    class Part(val mode: Mode, val pos: Pos)

    /** Группа приёмов. Вторая и дальше — после `--auto`: пробуются, если не помогла предыдущая. */
    class Group(
        val parts: List<Part> = emptyList(),
        val tlsrec: List<Pos> = emptyList(),
        val tlsminor: Int = -1,
        val fakeTtl: Int = DEFAULT_FAKE_TTL,
        val oobChar: Int = TlsHello.OOB_BYTE,
        val fakeSni: List<String> = emptyList(),
        /** Условие из `--auto` (torst, ssl_err…); у первой группы — пусто. */
        val trigger: String = ""
    ) {
        val needsFake: Boolean get() = parts.any { it.mode == Mode.FAKE }
        val needsTtl: Boolean get() = parts.any { it.mode == Mode.DISORDER || it.mode == Mode.DISOOB || it.mode == Mode.FAKE }

        /** Ничего не делает: первое сообщение уходит как есть. */
        val isPlain: Boolean get() = parts.isEmpty() && tlsrec.isEmpty() && tlsminor < 0
    }

    val needsTtl: Boolean get() = defTtl > 0 || groups.any { it.needsTtl }
    val needsFake: Boolean get() = groups.any { it.needsFake }
    val isPlain: Boolean get() = defTtl <= 0 && groups.all { it.isPlain }

    /**
     * Словами — для экрана, где человек вписывает свою строку (с 1.10.49-beta4):
     * «разрез 1+s, перестановка 3+s; если не вышло (torst): фейк -1 (TTL 5)».
     */
    fun describe(): String {
        val text = groups.mapIndexed { i, g ->
            val items = ArrayList<String>()
            g.parts.forEach { p ->
                items += "${modeName(p.mode)} ${p.pos}" + (if (p.mode == Mode.FAKE) " (TTL ${g.fakeTtl})" else "")
            }
            g.tlsrec.forEach { items += "запись TLS ${it}" }
            if (g.tlsminor >= 0) items += "версия записи 3.${g.tlsminor}"
            if (g.fakeSni.isNotEmpty()) items += "имя в фейке ${g.fakeSni.joinToString("/")}"
            val body = if (items.isEmpty()) "как есть" else items.joinToString(", ")
            if (i == 0 || g.trigger.isBlank()) body else "если не вышло (${g.trigger}): $body"
        }.joinToString("; ")
        return text + (if (defTtl > 0) "; TTL $defTtl" else "")
    }

    private fun modeName(m: Mode): String = when (m) {
        Mode.SPLIT -> "разрез"
        Mode.DISORDER -> "перестановка"
        Mode.OOB -> "OOB"
        Mode.DISOOB -> "перестановка с OOB"
        Mode.FAKE -> "фейк"
    }

    override fun toString(): String = source

    /** Итог разбора: стратегия или ошибка; [notes] — что пропущено. */
    class Parsed(val strategy: DpiStrategy?, val error: String?, val notes: List<String>)

    companion object {
        /** TTL фейка по умолчанию — как у ByeDPI. */
        const val DEFAULT_FAKE_TTL = 8

        /** Самая длинная строка, которую принимаем: дальше — явно вставили не то. */
        const val MAX_LENGTH = 2000

        val NONE = DpiStrategy("", listOf(Group()), emptyList())

        /** Разобрать или упасть — для встроенных стратегий (их строки проверяет самопроверка). */
        fun of(text: String): DpiStrategy = parse(text).let { p -> p.strategy ?: throw IllegalArgumentException(p.error) }

        fun parse(text: String): Parsed = Parser(text).run()

        internal fun create(source: String, groups: List<Group>, notes: List<String>, defTtl: Int, timeoutMs: Int): DpiStrategy =
            DpiStrategy(source, groups, notes, defTtl, timeoutMs)
    }
}

/** Разбор строки ByeDPI (отдельно от модели — чтобы класс стратегии читался). */
private class Parser(private val text: String) {

    private enum class Kind {
        SPLIT, DISORDER, OOB, DISOOB, FAKE, TTL, TLSREC, TLSMINOR, OOB_DATA, FAKE_SNI, FAKE_TLS_MOD, DEF_TTL, AUTO, TIMEOUT,
        NO_MD5, NO_SACK, NO_FAKE_DATA, NO_FAKE_OFFSET, NO_HTTP, NO_UDP, NO_LIMIT, IGNORE
    }

    private class Opt(val long: String, val short: Char?, val arg: Boolean, val kind: Kind)

    private class GroupBuilder(val trigger: String) {
        val parts = ArrayList<DpiStrategy.Part>()
        val tlsrec = ArrayList<DpiStrategy.Pos>()
        var tlsminor = -1
        var fakeTtl = DpiStrategy.DEFAULT_FAKE_TTL
        var oobChar = TlsHello.OOB_BYTE
        val fakeSni = ArrayList<String>()

        fun build() = DpiStrategy.Group(parts.toList(), tlsrec.toList(), tlsminor, fakeTtl, oobChar, fakeSni.toList(), trigger)
    }

    private val groups = arrayListOf(GroupBuilder(""))
    private val notes = LinkedHashSet<String>()
    private var defTtl = 0
    private var timeoutMs = 0

    fun run(): DpiStrategy.Parsed {
        val src = text.trim()
        if (src.length > DpiStrategy.MAX_LENGTH) return fail("строка длиннее ${DpiStrategy.MAX_LENGTH} символов — вставлено что-то не то")
        val tokens = tokenize(src).toMutableList()
        // «ciadpi --split 1» — имя программы в начале не мешает.
        tokens.firstOrNull()?.let { first ->
            val low = first.lowercase().substringAfterLast('/').substringAfterLast('\\')
            if (low == "ciadpi" || low == "ciadpi.exe" || low == "byedpi" || low == "byedpi.exe") tokens.removeAt(0)
        }
        if (tokens.isEmpty()) return fail("строка пустая — пример: --split 1+s --disorder 3+s")
        var i = 0
        while (i < tokens.size) {
            val tok = tokens[i++]
            when {
                tok.startsWith("--") && tok.length > 2 -> {
                    val body = tok.substring(2)
                    val name = body.substringBefore('=')
                    val inline = if ('=' in body) body.substringAfter('=') else null
                    // Как getopt_long: можно сократить, если сокращение однозначно («--disord»).
                    val opt = OPTS.firstOrNull { it.long == name } ?: OPTS.filter { it.long.startsWith(name) }.singleOrNull()
                        ?: return fail("неизвестный ключ «$tok»")
                    val arg = if (opt.arg) {
                        inline ?: tokens.getOrNull(i++) ?: return fail("у «--${opt.long}» нет значения")
                    } else {
                        if (inline != null) return fail("у «--${opt.long}» значения не бывает")
                        null
                    }
                    apply(opt, arg)?.let { return fail(it) }
                }

                tok.startsWith("-") && tok.length >= 2 && tok != "--" -> {
                    // Короткие ключи можно склеивать: «-Sd1» = «-S -d 1».
                    var j = 1
                    while (j < tok.length) {
                        val c = tok[j]
                        val opt = OPTS.firstOrNull { it.short == c } ?: return fail("неизвестный ключ «-$c»")
                        if (opt.arg) {
                            val rest = tok.substring(j + 1).removePrefix("=")
                            val arg = rest.ifEmpty { tokens.getOrNull(i++) ?: return fail("у «-$c» нет значения") }
                            apply(opt, arg)?.let { return fail(it) }
                            break
                        }
                        apply(opt, null)?.let { return fail(it) }
                        j++
                    }
                }

                else -> return fail("лишнее «$tok» — ожидался ключ, например --split 1+s")
            }
        }
        val built = groups.map { it.build() }
        val source = tokens.joinToString(" ")
        if (DpiStrategy.create(source, built, emptyList(), defTtl, timeoutMs).isPlain) {
            notes += "в строке нет ни одного приёма — первое сообщение уйдёт как есть"
        }
        return DpiStrategy.Parsed(DpiStrategy.create(source, built, notes.toList(), defTtl, timeoutMs), null, notes.toList())
    }

    private fun fail(why: String) = DpiStrategy.Parsed(null, why, notes.toList())

    /** Применить ключ; ошибка — текст, всё хорошо — null. */
    private fun apply(opt: Opt, arg: String?): String? {
        val g = groups.last()
        val a = arg.orEmpty()
        when (opt.kind) {
            Kind.SPLIT, Kind.DISORDER, Kind.OOB, Kind.DISOOB, Kind.FAKE -> {
                val pos = parsePos(a) ?: return badPos(opt, a)
                val mode = when (opt.kind) {
                    Kind.SPLIT -> DpiStrategy.Mode.SPLIT
                    Kind.DISORDER -> DpiStrategy.Mode.DISORDER
                    Kind.OOB -> DpiStrategy.Mode.OOB
                    Kind.DISOOB -> DpiStrategy.Mode.DISOOB
                    else -> DpiStrategy.Mode.FAKE
                }
                if (g.parts.size >= MAX_PARTS) return "слишком много кусков (больше $MAX_PARTS)"
                g.parts += DpiStrategy.Part(mode, pos)
            }

            Kind.TTL -> g.fakeTtl = number(a, 1, 255) ?: return "TTL «$a» — нужно число от 1 до 255"
            Kind.TLSREC -> {
                val pos = parsePos(a) ?: return badPos(opt, a)
                if (pos.offset > 0xFFFF) return "позиция «$a» для --tlsrec больше 65535"
                if (g.tlsrec.size >= MAX_PARTS) return "слишком много --tlsrec (больше $MAX_PARTS)"
                g.tlsrec += pos
            }

            Kind.TLSMINOR -> g.tlsminor = number(a, 1, 255) ?: return "версия «$a» для --tlsminor — нужно число от 1 до 255"
            Kind.OOB_DATA -> g.oobChar = cChar(a) ?: return "--oob-data «$a» — нужен один символ (или \\xNN)"
            Kind.FAKE_SNI -> {
                val ok = a.length in 1..253 && a.all { it.isLetterOrDigit() || it == '.' || it == '-' || it == '?' || it == '#' || it == '*' } &&
                    a.all { it.code < 128 }
                if (!ok) return "имя «$a» для --fake-sni — латиница, цифры, точки, дефисы и ? # *"
                g.fakeSni += a
            }

            Kind.FAKE_TLS_MOD -> {
                val ok = a.split(',').all { p -> p == "r" || p == "rand" || p == "o" || p == "orig" || Regex("""m(size)?=-?\d+""").matches(p) }
                if (!ok) return "--fake-tls-mod «$a» — бывает rand, orig, msize=N"
                notes += "--fake-tls-mod: фейк у нас всегда — настоящее приветствие с другим именем и случайными полями (как rand,orig)"
            }

            Kind.DEF_TTL -> defTtl = number(a, 1, 255) ?: return "--def-ttl «$a» — нужно число от 1 до 255"
            Kind.AUTO -> {
                val parts = a.split(',').map { it.trim() }
                val known = parts.all { p ->
                    p in setOf("t", "torst", "r", "redirect", "s", "ssl_err", "c", "connect", "n", "none") || p.startsWith("p=") ||
                        p.startsWith("pri=")
                }
                if (!known || parts.all { it.isEmpty() }) return "--auto «$a» — бывает torst, ssl_err, redirect, none"
                if (groups.size >= MAX_GROUPS) return "слишком много групп --auto (больше $MAX_GROUPS)"
                if (parts.any { it == "r" || it == "redirect" }) {
                    notes += "--auto=redirect бывает только у HTTP — у нас любая неудача (тишина, сброс, ошибка TLS) включает следующую группу"
                }
                groups += GroupBuilder(a)
            }

            Kind.TIMEOUT -> {
                val v = a.replace(',', '.').toDoubleOrNull()
                if (v == null || v < 0.5 || v > 30) return "--timeout «$a» — секунды, от 0.5 до 30"
                timeoutMs = (v * 1000).toInt()
            }

            Kind.NO_MD5 -> notes += "--md5sig: в Android эта опция ядра обычно выключена — пропускаю (фейк держится на TTL)"
            Kind.NO_SACK -> notes += "--drop-sack: без root телефон так не умеет — пропускаю"
            Kind.NO_FAKE_DATA -> notes += "--fake-data: свои данные фейка не поддерживаются — фейк строится из настоящего приветствия"
            Kind.NO_FAKE_OFFSET -> notes += "--fake-offset: не поддерживается — фейк начинается с начала приветствия"
            Kind.NO_HTTP -> notes += "--mod-http: только для HTTP, а обход у нас — для HTTPS (TLS) — пропускаю"
            Kind.NO_UDP -> notes += "--udp-fake: QUIC этих приложений и так закрывается (они переходят на TCP) — UDP-фейки не нужны"
            Kind.NO_LIMIT -> notes += "--hosts/--proto/--ipset/--pf/--round не нужны: обход и так только для выбранных сервисов — пропускаю"
            Kind.IGNORE -> notes += "адрес, порт и прочие настройки самого прокси ByeDPI телефону не нужны — пропускаю"
        }
        return null
    }

    private fun badPos(opt: Opt, a: String): String =
        "позиция «$a» у --${opt.long} не разобрана — примеры: 1, 1+s, 3+s, -1, 0+sm, 1:3:5"

    companion object {
        const val MAX_PARTS = 64
        const val MAX_GROUPS = 8

        private val OPTS: List<Opt> = listOf(
            Opt("split", 's', true, Kind.SPLIT), Opt("disorder", 'd', true, Kind.DISORDER), Opt("oob", 'o', true, Kind.OOB),
            Opt("disoob", 'q', true, Kind.DISOOB), Opt("fake", 'f', true, Kind.FAKE), Opt("ttl", 't', true, Kind.TTL),
            Opt("tlsrec", 'r', true, Kind.TLSREC), Opt("tlsminor", 'm', true, Kind.TLSMINOR),
            Opt("oob-data", 'e', true, Kind.OOB_DATA), Opt("fake-sni", 'n', true, Kind.FAKE_SNI),
            Opt("fake-tls-mod", 'Q', true, Kind.FAKE_TLS_MOD), Opt("def-ttl", 'g', true, Kind.DEF_TTL),
            Opt("auto", 'A', true, Kind.AUTO), Opt("tcp-timeout", 'T', true, Kind.TIMEOUT), Opt("timeout", null, true, Kind.TIMEOUT),
            Opt("md5sig", 'S', false, Kind.NO_MD5), Opt("drop-sack", 'Y', false, Kind.NO_SACK),
            Opt("fake-data", 'l', true, Kind.NO_FAKE_DATA), Opt("fake-offset", 'O', true, Kind.NO_FAKE_OFFSET),
            Opt("mod-http", 'M', true, Kind.NO_HTTP), Opt("udp-fake", 'a', true, Kind.NO_UDP),
            Opt("proto", 'K', true, Kind.NO_LIMIT), Opt("hosts", 'H', true, Kind.NO_LIMIT), Opt("ipset", 'j', true, Kind.NO_LIMIT),
            Opt("pf", 'V', true, Kind.NO_LIMIT), Opt("round", 'R', true, Kind.NO_LIMIT),
            Opt("ip", 'i', true, Kind.IGNORE), Opt("port", 'p', true, Kind.IGNORE), Opt("conn-ip", 'I', true, Kind.IGNORE),
            Opt("buf-size", 'b', true, Kind.IGNORE), Opt("max-conn", 'c', true, Kind.IGNORE), Opt("debug", 'x', true, Kind.IGNORE),
            Opt("pidfile", 'w', true, Kind.IGNORE), Opt("auto-mode", 'L', true, Kind.IGNORE), Opt("cache-ttl", 'u', true, Kind.IGNORE),
            Opt("tls-timeout", 'W', true, Kind.IGNORE), Opt("copy", 'B', true, Kind.IGNORE), Opt("cache-file", 'y', true, Kind.IGNORE),
            Opt("await-int", 'z', true, Kind.IGNORE), Opt("protect-path", 'P', true, Kind.IGNORE),
            Opt("connect-to", 'C', true, Kind.IGNORE), Opt("comment", '#', true, Kind.IGNORE), Opt("cache-merge", '/', true, Kind.IGNORE),
            Opt("daemon", 'D', false, Kind.IGNORE), Opt("no-domain", 'N', false, Kind.IGNORE), Opt("no-ipv6", 'X', false, Kind.IGNORE),
            Opt("no-udp", 'U', false, Kind.IGNORE), Opt("help", 'h', false, Kind.IGNORE), Opt("version", 'v', false, Kind.IGNORE),
            Opt("transparent", 'E', false, Kind.IGNORE), Opt("tfo", 'F', false, Kind.IGNORE), Opt("wait-send", 'Z', false, Kind.IGNORE),
            Opt("rst", '0', false, Kind.IGNORE)
        )

        /** Слова строки: пробелы делят, кавычки (' и ") держат слово целым. */
        fun tokenize(raw: String): List<String> {
            val out = ArrayList<String>()
            val cur = StringBuilder()
            var quote: Char? = null
            var had = false
            for (ch in raw) {
                when {
                    quote != null -> if (ch == quote) quote = null else cur.append(ch)
                    ch == '"' || ch == '\'' -> {
                        quote = ch
                        had = true
                    }
                    ch.isWhitespace() -> {
                        if (cur.isNotEmpty() || had) out += cur.toString()
                        cur.clear()
                        had = false
                    }
                    else -> cur.append(ch)
                }
            }
            if (cur.isNotEmpty() || had) out += cur.toString()
            return out
        }

        /** Число как у strtol(…, 0): «12», «-1», «0x10», «010» (восьмеричное). */
        private fun cNumber(s: String): Long? {
            if (s.isEmpty()) return null
            val neg = s.startsWith('-')
            val body = s.removePrefix("-").removePrefix("+")
            if (body.isEmpty()) return null
            val v = when {
                body.startsWith("0x") || body.startsWith("0X") -> body.substring(2).takeIf { it.isNotEmpty() }?.toLongOrNull(16)
                body.length > 1 && body.startsWith('0') -> body.substring(1).toLongOrNull(8)
                else -> body.toLongOrNull()
            } ?: return null
            return if (neg) -v else v
        }

        private fun number(s: String, min: Int, max: Int): Int? = cNumber(s.trim())?.takeIf { it in min..max }?.toInt()

        private val POS = Regex("""^([+-]?(?:0[xX][0-9a-fA-F]+|\d+))?((?::(?:0[xX][0-9a-fA-F]+|\d+)){0,2})(?:\+([shn])([emrs])?)?$""")

        /** Позиция ByeDPI: `offset[:repeats:skip][+s|h|n[e|m|r|s]]`; null — не разобрать. */
        fun parsePos(s: String): DpiStrategy.Pos? {
            val m = POS.matchEntire(s.trim()) ?: return null
            val numText = m.groupValues[1]
            val reps = m.groupValues[2]
            val f1 = m.groupValues[3]
            val f2 = m.groupValues[4]
            if (numText.isEmpty() && f1.isEmpty()) return null
            val offset = if (numText.isEmpty()) 0L else cNumber(numText) ?: return null
            if (offset > Int.MAX_VALUE || offset < Int.MIN_VALUE) return null
            var repeats = 0
            var skip = 0L
            if (reps.isNotEmpty()) {
                val nums = reps.removePrefix(":").split(':').map { cNumber(it) ?: return null }
                repeats = nums[0].takeIf { it in 1..1000 }?.toInt() ?: return null
                if (nums.size > 1) skip = nums[1].takeIf { it in 0..Int.MAX_VALUE.toLong() } ?: return null
            }
            return DpiStrategy.Pos(
                offset, repeats, skip,
                sni = f1 == "s", host = f1 == "h",
                end = f2 == "e", mid = f2 == "m", rand = f2 == "r", start = f2 == "s"
            )
        }

        /** Один символ для `--oob-data`: «a», «\\x10», «\\0», «\\n». */
        private fun cChar(s: String): Int? {
            if (s.length == 1) return s[0].code.takeIf { it < 256 }
            if (!s.startsWith('\\')) return null
            val rest = s.substring(1)
            return when {
                rest == "n" -> 10
                rest == "r" -> 13
                rest == "t" -> 9
                rest == "0" -> 0
                rest.startsWith("x") || rest.startsWith("0x") -> rest.substringAfter('x').toIntOrNull(16)?.takeIf { it in 0..255 }
                rest.all { it in '0'..'7' } && rest.length <= 3 -> rest.toIntOrNull(8)?.takeIf { it in 0..255 }
                else -> null
            }
        }
    }
}
