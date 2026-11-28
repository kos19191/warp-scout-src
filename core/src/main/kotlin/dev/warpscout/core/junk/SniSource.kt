package dev.warpscout.core.junk

import dev.warpscout.core.crypto.Crypto
import java.io.BufferedReader
import java.io.File
import java.io.InputStreamReader
import java.io.OutputStreamWriter
import java.net.HttpURLConnection
import java.net.URL
import java.util.concurrent.ConcurrentHashMap

/**
 * Источник SNI-доменов для QUIC-маски.
 *
 * Статический список [JunkLibrary.SNI_DOMAINS] мал (24 домена) и использовать его всегда по порядку
 * — значит быстро выучить несколько паттернов и начать их резать. Для белых списков нужно:
 *  1. Больше доменов (лучше — весь актуальный белый список Минцифры);
 *  2. Ротация SNI при каждой попытке, а не первые три из фиксированного списка;
 *  3. Обновление списка с сервера, без пересборки приложения.
 *
 * SniSource загружает список с удалённого URL (plain-text, один домен на строку, строки с #
 * — комментарии), кеширует в файл и в память, и отдаёт случайный SNI по запросу. При любой ошибке
 * сети fallback на статический список JunkLibrary.
 *
 * Работает без Android-контекста — только java.io/java.net, поэтому пригоден и для core (CLI),
 * и для приложения.
 */
data class SniConfig(
    val domains: List<String>,
    val source: String,   // "remote" | "cache" | "local"
    val fetchedAt: Long? = null
) {
    val isEmpty: Boolean get() = domains.isEmpty()
    fun random(random: kotlin.random.Random = kotlin.random.Random.Default): String? =
        domains.randomOrNull(random)
    fun rotate(random: kotlin.random.Random = kotlin.random.Random.Default): List<String> =
        domains.shuffled(random)
}

/** Сырая строка конфигурации: URL или «local» для статического списка. */
data class SniSettings(
    /** Удалённый URL со списком SNI (plain-text, один домен на строку, # — комментарии). null — не используем удалённый источник. */
    val remoteUrl: String? = null,
    /** Таймаут загрузки, мс. */
    val timeoutMs: Int = 8000,
    /** Максимальный возраст кеша, мс (0 — всегда качать, если есть сеть). */
    val cacheMaxAgeMs: Long = 4 * 60 * 60 * 1000, // 4 часа
    /** Куда кешировать список (файл). null — только в памяти. */
    val cacheFile: String? = null,
    /** Сколько доменов использовать одновременно (для QUIC-пула). */
    val poolSize: Int = 3
) {
    companion object {
        val Default = SniSettings()
    }
}

object SniSource {

    private val cache = ConcurrentHashMap<String, SniConfig>()
    private var lastFetch: Long = 0L

    /**
     * Загружает список SNI-доменов.
     *
     * @param settings настройки источника;
     * @return конфигурацию: домены, откуда взяли, когда.
     */
    fun load(settings: SniSettings = SniSettings.Default): SniConfig {
        val now = System.currentTimeMillis()

        // 1. Пробуем удалённый источник, если задан и кеш протух.
        if (settings.remoteUrl?.isNotBlank() == true && (now - lastFetch > settings.cacheMaxAgeMs)) {
            val remote = tryLoadRemote(settings)
            if (remote.isNotEmpty()) {
                val cfg = SniConfig(remote, "remote", now)
                lastFetch = now
                cache["remote"] = cfg
                writeCache(settings, remote)
                return cfg
            }
        }

        // 2. Кеш из файла.
        settings.cacheFile?.let { file ->
            val cached = readCache(file)
            if (cached.isNotEmpty() && now - lastFetch > settings.cacheMaxAgeMs) {
                val cfg = SniConfig(cached, "cache", lastFetch)
                cache["cache"] = cfg
                return cfg
            }
        }

        // 3. Локальный статический список.
        val local = JunkLibrary.SNI_DOMAINS
        val cfg = SniConfig(local, "local")
        cache["local"] = cfg
        return cfg
    }

    /**
     * Случайный SNI из загруженного списка. Вызывает [load] при первом обращении или при протухшем
     * кеше, поэтому достаточно вызвать один раз на подбор — домены будут свежими.
     */
    fun randomSni(settings: SniSettings = SniSettings.Default): String? {
        val cfg = load(settings)
        return cfg.random()
    }

    /**
     * Перемешанный список из [settings.poolSize] доменов для QUIC-пула.
     */
    fun sniPool(settings: SniSettings = SniSettings.Default): List<String> {
        val cfg = load(settings)
        return cfg.rotate().take(settings.poolSize.coerceAtLeast(1).coerceAtMost(cfg.domains.size))
    }

    /** Сброс кеша: следующий вызов [load] снова попробует сеть. */
    fun reset() {
        cache.clear()
        lastFetch = 0L
    }

    // --------------------------------------------------------------- загрузка

    private fun tryLoadRemote(settings: SniSettings): List<String> {
        val url = settings.remoteUrl ?: return emptyList()
        return runCatching {
            val conn = url.openConnection() as HttpURLConnection
            conn.requestMethod = "GET"
            conn.connectTimeout = settings.timeoutMs
            conn.readTimeout = settings.timeoutMs
            conn.setRequestProperty("User-Agent", "WilyScout/1.10.50 (SNI-source)")
            conn.useCaches = false
            conn.connect()

            val result = if (conn.responseCode != 200) {
                emptyList<String>()
            } else {
                val reader = BufferedReader(InputStreamReader(conn.inputStream, "UTF-8"))
                val out = mutableListOf<String>()
                try {
                    var line: String?
                    while (true) {
                        line = reader.readLine()
                        if (line == null) break
                        val trimmed = line.trim()
                        if (trimmed.isNotEmpty() && !trimmed.startsWith("#")) {
                            out += sanitize(trimmed)
                        }
                    }
                } finally {
                    reader.close()
                }
                conn.disconnect()
                out.filter { it.isNotEmpty() }
            }
            result
        }.getOrDefault(emptyList())
    }

    private fun sanitize(host: String): String {
        // Только латиница, цифры, точка, дефис — кириллица в ClientHello превратится в «?».
        val valid = host.filter { it in 'a'..'z' || it in 'A'..'Z' || it in '0'..'9' || it == '.' || it == '-' }
        return if (valid.length < 4 || valid.length > 253) "" else valid
    }

    // --------------------------------------------------------------- файловый кеш

    private fun writeCache(settings: SniSettings, domains: List<String>) {
        settings.cacheFile?.let { path ->
            runCatching {
                val file = File(path)
                file.parentFile.mkdirs()
                val writer = OutputStreamWriter(java.io.FileOutputStream(file), "UTF-8")
                try {
                    for (d in domains) writer.write(d + "\n")
                } finally {
                    writer.close()
                }
            }
        }
    }

    private fun readCache(path: String): List<String> {
        return runCatching {
            val file = File(path)
            if (!file.exists()) return@runCaching emptyList()
            val ageMs = System.currentTimeMillis() - file.lastModified()
            if (ageMs > 24 * 60 * 60 * 1000) return@runCaching emptyList() // кеш старше суток — не доверяем
            BufferedReader(InputStreamReader(java.io.FileInputStream(file), "UTF-8")).use { reader ->
                reader.lines().map { it.trim() }.filter { it.isNotEmpty() && !it.startsWith("#") }.toList()
            }
        }.getOrDefault(emptyList())
    }
}

/** Устаревший синтаксис, сохранён для совместимости с вызовами из JunkLibrary. */
fun loadSniList(url: String?, timeoutMs: Int = 8000): List<String> =
    if (url.isNullOrBlank()) JunkLibrary.SNI_DOMAINS
    else SniSource.load(SniSettings(remoteUrl = url, timeoutMs = timeoutMs)).domains
