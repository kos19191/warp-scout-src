package dev.warpscout.app

import android.content.Context
import dev.warpscout.core.config.WgConf
import dev.warpscout.core.model.WarpConfig
import java.io.File
import java.util.Base64

/**
 * Три лучших конфига из последнего подбора.
 *
 * Зачем отдельно от [TuningCache]: кеш отвечает на вопрос «с чего начать следующий скан», и ему
 * достаточно одной точки. Здесь другое — «чем подключаться, если текущая точка перестала работать».
 * Сеть режет адреса выборочно и без предупреждения: то, что открывалось утром, к вечеру может не
 * пропускать handshake, а подбор — это минуты и разогрев радио. Поэтому после каждого скана мы
 * запоминаем не одного победителя, а тройку: второе и третье места обычно отличаются от первого
 * адресом и портом, то есть это готовые замены, а не копии.
 *
 * Храним готовый текст конфига, а не «сырые» параметры: переключение должно быть мгновенным и не
 * зависеть от того, что сейчас выбрано в настройках. Текст перепроверяется настоящим handshake при
 * подключении — нерабочий конфиг просто не поднимется и останется в списке как история.
 */
object ConfigShortlist {

    /** Больше трёх не нужно: переключение должно быть быстрым выбором, а не вторым списком конфигов. */
    const val MAX = 3

    /** Через неделю адреса и блокировки успевают поменяться — держим список только как подсказку. */
    private const val MAX_AGE_MS = 7L * 24 * 60 * 60 * 1000

    private const val FILE_NAME = "shortlist.txt"
    private const val SEPARATOR = "---"

    data class Entry(
        /** `host:port` — то, что видит пользователь. */
        val endpoint: String,
        val junk: String,
        val score: Int,
        /** Сколько ресурсов открылось изнутри туннеля; [UNKNOWN] — изнутри не проверяли. */
        val resourcesOk: Int,
        val resourcesTotal: Int,
        val configText: String,
        val savedAt: Long,
        /** Вид сети на момент скана: «другая сеть» — полезная подсказка, если точка не поднялась. */
        val network: String
    )

    /**
     * Разбор сохранённого текста в конфиг. null — файл повреждён или это не WARP-конфиг.
     *
     * Имя профиля шума возвращаем из записи: в тексте конфига его нет, и после разбора профиль
     * назывался «imported». В журнале 14:29 это читалось как «выбрал tls-fixed, а поднимает
     * imported» — хотя параметры шума те же, байт в байт.
     */
    fun config(entry: Entry): WarpConfig? = runCatching {
        val cfg = WgConf.toWarpConfig("топ-3", entry.configText) ?: return@runCatching null
        if (entry.junk.isNotBlank() && cfg.junk.name != entry.junk) cfg.copy(junk = cfg.junk.copy(name = entry.junk)) else cfg
    }.getOrNull()

    /** Ключ «точка + профиль шума»: им и помечается активная строка списка. */
    fun key(entry: Entry): String = entry.endpoint + "|" + entry.junk

    /**
     * Работает ли сейчас именно этот конфиг. Сравниваем не текст (он зависит от выбранного клиента),
     * а точку и профиль шума — их пишет каждое удачное подключение.
     */
    fun isActive(entry: Entry, prefs: Prefs): Boolean {
        val active = prefs.shortlistActive.trim()
        if (active.isNotEmpty()) return active == key(entry)
        // Старые установки: отметки ещё нет — довольствуемся совпадением точки входа.
        return prefs.lastEndpoint.isNotBlank() && prefs.lastEndpoint.trim() == entry.endpoint
    }

    /**
     * Список для показа: только свежие записи и только с читаемым конфигом. Порядок — как сохраняли,
     * то есть от лучшего к третьему.
     */
    fun load(context: Context): List<Entry> {
        val file = File(context.filesDir, FILE_NAME)
        if (!file.isFile) return emptyList()
        val raw = runCatching { file.readText() }.getOrNull() ?: return emptyList()
        val now = System.currentTimeMillis()
        return raw.split(SEPARATOR).mapNotNull { block -> parse(block.trim()) }
            .filter { now - it.savedAt <= MAX_AGE_MS }
            .filter { it.endpoint.isNotBlank() && it.configText.isNotBlank() }
            .take(MAX)
    }

    /**
     * Запомнить тройку. Пишем через временный файл: если процесс убьют посреди записи, на месте
     * останется либо старый список, либо новый, но не половина строки — иначе разбор конфига
     * молча ломался бы, а «переключиться» переставало работать без всякой причины.
     */
    fun save(context: Context, entries: List<Entry>) {
        val list = entries.filter { it.endpoint.isNotBlank() && it.configText.isNotBlank() }.take(MAX)
        if (list.isEmpty()) return
        val text = list.joinToString("\n$SEPARATOR\n") { e ->
            buildString {
                append("endpoint=").append(e.endpoint).append('\n')
                append("junk=").append(e.junk).append('\n')
                append("score=").append(e.score).append('\n')
                append("ok=").append(e.resourcesOk).append('\n')
                append("total=").append(e.resourcesTotal).append('\n')
                append("saved=").append(e.savedAt).append('\n')
                append("network=").append(e.network).append('\n')
                append("conf=").append(encode(e.configText)).append('\n')
            }
        }
        runCatching {
            val dir = context.filesDir
            val tmp = File(dir, "$FILE_NAME.tmp")
            tmp.writeText(text)
            val dst = File(dir, FILE_NAME)
            if (!tmp.renameTo(dst)) {
                dst.writeText(text)
                tmp.delete()
            }
        }
    }

    fun forget(context: Context) {
        runCatching { File(context.filesDir, FILE_NAME).delete() }
    }

    private fun parse(block: String): Entry? {
        if (block.isBlank()) return null
        val map = block.lineSequence()
            .mapNotNull { line ->
                val i = line.indexOf('=')
                if (i <= 0) null else line.substring(0, i).trim() to line.substring(i + 1).trim()
            }
            .toMap()
        val endpoint = map["endpoint"].orEmpty()
        val text = map["conf"]?.let { decode(it) }.orEmpty()
        if (endpoint.isBlank() || text.isBlank()) return null
        return Entry(
            endpoint = endpoint,
            junk = map["junk"].orEmpty(),
            score = map["score"]?.toIntOrNull() ?: 0,
            resourcesOk = map["ok"]?.toIntOrNull() ?: UNKNOWN,
            resourcesTotal = map["total"]?.toIntOrNull() ?: 0,
            configText = text,
            savedAt = map["saved"]?.toLongOrNull() ?: 0L,
            network = map["network"].orEmpty()
        )
    }

    /**
     * Текст конфига — в одну строку. Без этого переводы строк внутри блока пришлось бы экранировать
     * вручную, а любая ошибка экранирования тихо превращала бы конфиг в мусор.
     */
    private fun encode(text: String): String =
        Base64.getEncoder().encodeToString(text.toByteArray(Charsets.UTF_8))

    private fun decode(text: String): String? = runCatching {
        String(Base64.getDecoder().decode(text), Charsets.UTF_8)
    }.getOrNull()

    /** «Изнутри не проверяли» — так же, как в отчёте подбора. */
    const val UNKNOWN = -1
}
