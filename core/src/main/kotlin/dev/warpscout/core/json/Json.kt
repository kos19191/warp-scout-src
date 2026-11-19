package dev.warpscout.core.json

/**
 * Крошечный JSON-парсер/писатель. Нужен, чтобы ядро не тянуло зависимостей (ни kotlinx.serialization,
 * ни Gson) — тогда `:core` собирается простым kotlinc и его можно гонять и на Android, и на десктопе.
 * Поддерживает ровно то, что нужно нам: объекты, массивы, строки, числа, true/false/null.
 */
sealed class JsonVal {
    object Null : JsonVal()
    data class Bool(val v: Boolean) : JsonVal()
    data class Num(val v: Double, val raw: String) : JsonVal()
    data class Str(val v: String) : JsonVal()
    data class Arr(val items: List<JsonVal>) : JsonVal()
    data class Obj(val fields: Map<String, JsonVal>) : JsonVal() {
        fun str(key: String): String? = (fields[key] as? Str)?.v
        fun num(key: String): Double? = (fields[key] as? Num)?.v
        fun obj(key: String): Obj? = fields[key] as? Obj
        fun arr(key: String): Arr? = fields[key] as? Arr
        fun bool(key: String): Boolean? = (fields[key] as? Bool)?.v
    }

    fun render(indent: Int = 0): String = when (this) {
        Null -> "null"
        is Bool -> v.toString()
        is Num -> raw
        is Str -> escape(v)
        is Arr -> if (items.isEmpty()) "[]" else {
            val pad = " ".repeat(indent + 2)
            items.joinToString(",\n", "[\n", "\n" + " ".repeat(indent) + "]") { pad + it.render(indent + 2) }
        }
        is Obj -> if (fields.isEmpty()) "{}" else {
            val pad = " ".repeat(indent + 2)
            fields.entries.joinToString(",\n", "{\n", "\n" + " ".repeat(indent) + "}") { (k, value) ->
                pad + escape(k) + ": " + value.render(indent + 2)
            }
        }
    }

    companion object {
        fun escape(s: String): String {
            val sb = StringBuilder("\"")
            for (ch in s) when (ch) {
                '"' -> sb.append("\\\"")
                '\\' -> sb.append("\\\\")
                '\n' -> sb.append("\\n")
                '\r' -> sb.append("\\r")
                '\t' -> sb.append("\\t")
                else -> if (ch.code < 0x20) sb.append("\\u" + ch.code.toString(16).padStart(4, '0')) else sb.append(ch)
            }
            return sb.append('"').toString()
        }

        fun obj(vararg pairs: Pair<String, JsonVal>): Obj = Obj(linkedMapOf(*pairs))
        fun obj(fields: Map<String, JsonVal>): Obj = Obj(LinkedHashMap(fields))
        fun arr(items: List<JsonVal>): Arr = Arr(items)
        fun str(s: String): Str = Str(s)
        fun num(v: Number): Num = Num(v.toDouble(), v.toString())
        fun bool(v: Boolean): Bool = Bool(v)
    }
}

class JsonParseException(message: String, val position: Int) : RuntimeException("$message (позиция $position)")

private class JsonReader(private val text: String) {
    private var i = 0

    private fun fail(msg: String): Nothing = throw JsonParseException(msg, i)

    private fun skipWs() {
        while (i < text.length && text[i].isWhitespace()) i++
    }

    private fun expect(ch: Char) {
        if (i >= text.length || text[i] != ch) fail("ожидался '$ch'")
        i++
    }

    fun readValue(): JsonVal {
        skipWs()
        if (i >= text.length) fail("внезапный конец")
        return when (text[i]) {
            '{' -> readObject()
            '[' -> readArray()
            '"' -> JsonVal.Str(readString())
            't' -> readLiteral("true", JsonVal.Bool(true))
            'f' -> readLiteral("false", JsonVal.Bool(false))
            'n' -> readLiteral("null", JsonVal.Null)
            else -> readNumber()
        }
    }

    private fun readLiteral(word: String, value: JsonVal): JsonVal {
        if (!text.startsWith(word, i)) fail("ожидалось $word")
        i += word.length
        return value
    }

    private fun readString(): String {
        expect('"')
        val sb = StringBuilder()
        while (true) {
            if (i >= text.length) fail("незакрытая строка")
            val ch = text[i++]
            when {
                ch == '"' -> return sb.toString()
                ch != '\\' -> sb.append(ch)
                else -> {
                    if (i >= text.length) fail("оборван escape")
                    when (val e = text[i++]) {
                        '"' -> sb.append('"')
                        '\\' -> sb.append('\\')
                        '/' -> sb.append('/')
                        'b' -> sb.append('\b')
                        'f' -> sb.append('\u000C')
                        'n' -> sb.append('\n')
                        'r' -> sb.append('\r')
                        't' -> sb.append('\t')
                        'u' -> {
                            if (i + 4 > text.length) fail("короткий \\u")
                            val cp = text.substring(i, i + 4).toIntOrNull(16) ?: fail("плохой \\u")
                            sb.append(cp.toChar())
                            i += 4
                        }
                        else -> fail("неизвестный escape \\$e")
                    }
                }
            }
        }
    }

    private fun readNumber(): JsonVal.Num {
        val start = i
        if (i < text.length && (text[i] == '-' || text[i] == '+')) i++
        while (i < text.length && (text[i].isDigit() || text[i] in ".eE+-")) i++
        val raw = text.substring(start, i)
        val d = raw.toDoubleOrNull() ?: fail("плохое число '$raw'")
        return JsonVal.Num(d, raw)
    }

    private fun readObject(): JsonVal.Obj {
        expect('{')
        val map = LinkedHashMap<String, JsonVal>()
        skipWs()
        if (i < text.length && text[i] == '}') { i++; return JsonVal.Obj(map) }
        while (true) {
            skipWs()
            val key = readString()
            skipWs()
            expect(':')
            map[key] = readValue()
            skipWs()
            if (i >= text.length) fail("незакрытый объект")
            when (text[i++]) {
                ',' -> continue
                '}' -> return JsonVal.Obj(map)
                else -> fail("ожидался ',' или '}'")
            }
        }
    }

    private fun readArray(): JsonVal.Arr {
        expect('[')
        val items = ArrayList<JsonVal>()
        skipWs()
        if (i < text.length && text[i] == ']') { i++; return JsonVal.Arr(items) }
        while (true) {
            items.add(readValue())
            skipWs()
            if (i >= text.length) fail("незакрытый массив")
            when (text[i++]) {
                ',' -> continue
                ']' -> return JsonVal.Arr(items)
                else -> fail("ожидался ',' или ']'")
            }
        }
    }
}

fun parseJson(text: String): JsonVal = JsonReader(text).readValue()

/** Строка → map строк (для простых API-ответов вида {"privKey": "…"}). */
fun parseFlatObject(text: String): Map<String, String> {
    val obj = runCatching { parseJson(text) as? JsonVal.Obj }.getOrNull() ?: return emptyMap()
    return obj.fields.mapNotNull { (k, v) ->
        when (v) {
            is JsonVal.Str -> k to v.v
            is JsonVal.Num -> k to v.raw
            is JsonVal.Bool -> k to v.v.toString()
            else -> null
        }
    }.toMap()
}
