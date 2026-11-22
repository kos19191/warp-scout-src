package dev.warpscout.app

import android.content.Context
import dev.warpscout.core.config.WgConf
import dev.warpscout.core.model.WarpConfig
import java.io.File
import java.util.Base64

/**
 * Три лучших конфига из последнего подбора — отдельно для Wi-Fi и для мобильной сети.
 *
 * Две тройки, а не одна: адреса Cloudflare не универсальны, и точка, лучшая на домашнем Wi-Fi, на
 * мобильной сети часто молчит. Раньше подбор на Wi-Fi затирал тройку, найденную на мобильной, и
 * наоборот. Теперь подбор заменяет только тройку своей сети; мобильную можно подобрать и не уходя
 * с Wi-Fi (см. Engine.startMobile).
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

    /** Группы сетей для двух троек. Всё, что не мобильная сеть, считается «Wi-Fi». */
    const val GROUP_WIFI = "wifi"
    const val GROUP_MOBILE = "mobile"

    /** Группа по виду сети записи (`TuningCache.transportOf`: wifi / mobile / ethernet / none). */
    fun group(network: String): String = if (network.trim() == GROUP_MOBILE) GROUP_MOBILE else GROUP_WIFI

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
        val network: String,
        /** Скорость через туннель этой точки при подборе, Кбит/с; -1 — не мерили. */
        val speedKbps: Int = -1,
        /**
         * Как проверяли: true — только рукопожатием (мобильная сеть, подобранная с Wi-Fi: туннель
         * через неё не поднять, не уходя с Wi-Fi), false — как обычно.
         */
        val handshakeOnly: Boolean = false,
        /**
         * За сколько пришёл ответ через туннель этой точки при подборе, мс; -1 — данные не
         * проверяли (записи старых версий). С 1.10.29 в тройку попадают только точки с данными.
         */
        val dataMs: Int = -1
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
     * Все свежие записи с читаемым конфигом: до трёх на каждую группу сетей. Порядок внутри
     * группы — как сохраняли, то есть от лучшего к третьему.
     */
    fun load(context: Context): List<Entry> {
        val file = File(context.filesDir, FILE_NAME)
        if (!file.isFile) return emptyList()
        val raw = runCatching { file.readText() }.getOrNull() ?: return emptyList()
        val now = System.currentTimeMillis()
        val fresh = raw.split(SEPARATOR).mapNotNull { block -> parse(block.trim()) }
            .filter { now - it.savedAt <= MAX_AGE_MS }
            .filter { it.endpoint.isNotBlank() && it.configText.isNotBlank() }
        val wifi = fresh.filter { group(it.network) == GROUP_WIFI }.take(MAX)
        val mobile = fresh.filter { group(it.network) == GROUP_MOBILE }.take(MAX)
        return wifi + mobile
    }

    /** Тройка одной группы сетей ([GROUP_WIFI] или [GROUP_MOBILE]). */
    fun forGroup(context: Context, which: String): List<Entry> =
        load(context).filter { group(it.network) == which }

    /** Все записи, тройка текущей сети — первой: с неё и начинается перебор. */
    fun ordered(context: Context, network: String): List<Entry> {
        val all = load(context)
        val mine = group(network)
        return all.filter { group(it.network) == mine } + all.filter { group(it.network) != mine }
    }

    /**
     * Запомнить тройку подбора для её сети: тройка другой сети остаётся как была. Все записи
     * [entries] — из одного подбора, то есть одной группы.
     */
    fun save(context: Context, entries: List<Entry>) {
        val list = entries.filter { it.endpoint.isNotBlank() && it.configText.isNotBlank() }.take(MAX)
        if (list.isEmpty()) return
        val mine = group(list.first().network)
        val others = load(context).filter { group(it.network) != mine }
        write(context, list + others)
    }

    /** Переписать список целиком (например, без испорченной записи). */
    fun saveAll(context: Context, entries: List<Entry>) {
        val list = entries.filter { it.endpoint.isNotBlank() && it.configText.isNotBlank() }
        if (list.isEmpty()) {
            forget(context)
            return
        }
        write(context, list)
    }

    /**
     * Запись через временный файл: если процесс убьют посреди записи, на месте останется либо
     * старый список, либо новый, но не половина строки — иначе разбор конфига молча ломался бы, а
     * «переключиться» переставало работать без всякой причины.
     */
    private fun write(context: Context, list: List<Entry>) {
        val text = list.joinToString("\n$SEPARATOR\n") { e ->
            buildString {
                append("endpoint=").append(e.endpoint).append('\n')
                append("junk=").append(e.junk).append('\n')
                append("score=").append(e.score).append('\n')
                append("ok=").append(e.resourcesOk).append('\n')
                append("total=").append(e.resourcesTotal).append('\n')
                append("saved=").append(e.savedAt).append('\n')
                append("network=").append(e.network).append('\n')
                append("speed=").append(e.speedKbps).append('\n')
                append("hsOnly=").append(if (e.handshakeOnly) 1 else 0).append('\n')
                append("data=").append(e.dataMs).append('\n')
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
            network = map["network"].orEmpty(),
            speedKbps = map["speed"]?.toIntOrNull() ?: -1,
            handshakeOnly = map["hsOnly"] == "1",
            dataMs = map["data"]?.toIntOrNull() ?: -1
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
