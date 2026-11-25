package dev.warpscout.core.tunnel

/**
 * Пакеты-«подписи» AmneziaWG — параметры I1–I5 (с 1.10.49-beta1, для второго выхода).
 *
 * Перед каждой инициацией клиент AmneziaWG отправляет эти пакеты, затем Jc пакетов шума, затем саму
 * инициацию: с ними начало соединения похоже на DNS, QUIC или другой протокол. Сервер их не
 * проверяет — это маскировка для фильтров по дороге. Запись — цепочка тегов, ровно как у
 * amneziawg-go (device/obf*.go):
 *
 * - `<b 0x…>` — байты в hex;
 * - `<t>` — время, 4 байта big-endian (секунды Unix);
 * - `<r N>` — N случайных байт, `<rc N>` — N случайных латинских букв, `<rd N>` — N случайных цифр;
 * - `<d>`, `<ds>`, `<dz N>` — данные, их base64 и их длина в N байтах: в пакетах-подписях данных нет,
 *   поэтому `<d>` и `<ds>` пустые, а `<dz N>` — N нулевых байт.
 *
 * Текст вне тегов не учитывается. Неизвестный тег или битое значение — ошибка всей цепочки, как у
 * amneziawg-go (там такой конфиг не применяется); у нас битая цепочка пропускается и пишется в журнал.
 */
object AwgObf {

    sealed class Part {
        abstract val size: Int

        class Bytes(val data: ByteArray) : Part() {
            override val size: Int get() = data.size
        }

        object Timestamp : Part() {
            override val size: Int get() = 4
        }

        class Random(override val size: Int) : Part()
        class RandomChars(override val size: Int) : Part()
        class RandomDigits(override val size: Int) : Part()

        /** `<dz N>` без данных: длина пустых данных — N нулевых байт. */
        class Zeros(override val size: Int) : Part()

        /** `<d>`, `<ds>` без данных — ноль байт. */
        object Empty : Part() {
            override val size: Int get() = 0
        }
    }

    class Chain(val spec: String, val parts: List<Part>) {
        val size: Int get() = parts.sumOf { it.size }

        fun build(random: java.util.Random, nowSec: Long = System.currentTimeMillis() / 1000): ByteArray {
            val out = ByteArray(size)
            var o = 0
            for (part in parts) {
                when (part) {
                    is Part.Bytes -> part.data.copyInto(out, o)
                    Part.Timestamp -> {
                        val t = nowSec.toInt()
                        out[o] = (t ushr 24).toByte(); out[o + 1] = (t ushr 16).toByte()
                        out[o + 2] = (t ushr 8).toByte(); out[o + 3] = t.toByte()
                    }
                    is Part.Random -> fill(random, out, o, part.size)
                    is Part.RandomChars -> {
                        fill(random, out, o, part.size)
                        for (i in o until o + part.size) out[i] = CHARS52[(out[i].toInt() and 0xff) % 52].code.toByte()
                    }
                    is Part.RandomDigits -> {
                        fill(random, out, o, part.size)
                        for (i in o until o + part.size) out[i] = DIGITS10[(out[i].toInt() and 0xff) % 10].code.toByte()
                    }
                    is Part.Zeros, Part.Empty -> Unit
                }
                o += part.size
            }
            return out
        }

        private fun fill(random: java.util.Random, out: ByteArray, off: Int, n: Int) {
            if (n <= 0) return
            val tmp = ByteArray(n).also { random.nextBytes(it) }
            tmp.copyInto(out, off)
        }
    }

    /**
     * Разбор цепочки. null — тегов нет (такой пакет amneziawg-go не шлёт); исключение — ошибка
     * разбора (текст — для журнала).
     */
    fun parse(spec: String): Chain? {
        val parts = ArrayList<Part>()
        val errors = ArrayList<String>()
        var rest = spec
        while (true) {
            val start = rest.indexOf('<')
            if (start < 0) break
            val endRel = rest.indexOf('>', start)
            if (endRel < 0) throw IllegalArgumentException("нет закрывающей «>»")
            val fields = rest.substring(start + 1, endRel).trim().split(Regex("\\s+")).filter { it.isNotEmpty() }
            rest = rest.substring(endRel + 1)
            if (fields.isEmpty()) {
                errors += "пустой тег"
                continue
            }
            val key = fields[0]
            val value = fields.getOrElse(1) { "" }
            runCatching { parts += part(key, value) }.onFailure { errors += "<$key>: ${it.message}" }
        }
        if (errors.isNotEmpty()) throw IllegalArgumentException(errors.joinToString("; "))
        return if (parts.isEmpty()) null else Chain(spec, parts)
    }

    private fun part(key: String, value: String): Part = when (key) {
        "b" -> {
            val hex = value.removePrefix("0x")
            require(hex.isNotEmpty()) { "пустое значение" }
            require(hex.length % 2 == 0) { "нечётное число символов" }
            Part.Bytes(ByteArray(hex.length / 2) { i ->
                val hi = Character.digit(hex[i * 2], 16)
                val lo = Character.digit(hex[i * 2 + 1], 16)
                require(hi >= 0 && lo >= 0) { "не hex" }
                ((hi shl 4) or lo).toByte()
            })
        }
        "t" -> Part.Timestamp
        "r" -> Part.Random(len(value))
        "rc" -> Part.RandomChars(len(value))
        "rd" -> Part.RandomDigits(len(value))
        "d", "ds" -> Part.Empty
        "dz" -> Part.Zeros(len(value))
        else -> throw IllegalArgumentException("неизвестный тег")
    }

    private fun len(value: String): Int {
        val n = value.toIntOrNull() ?: throw IllegalArgumentException("длина «$value» — не число")
        require(n >= 0) { "отрицательная длина" }
        require(n <= 65_535) { "слишком длинно" }
        return n
    }

    private const val CHARS52 = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    private const val DIGITS10 = "0123456789"
}
