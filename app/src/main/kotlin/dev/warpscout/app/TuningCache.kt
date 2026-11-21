package dev.warpscout.app

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.Build
import dev.warpscout.core.model.Endpoint
import dev.warpscout.core.model.JunkProfile
import dev.warpscout.core.tune.CachedStart
import java.io.File

/**
 * Кеш последней удачной точки подбора.
 *
 * Полный скан пула — это тысячи проб: минуты времени и разогрев радио на всю катушку, то есть
 * самый дорогой по батарее шаг во всём приложении. На той же сети следующая попытка почти всегда
 * упирается в ту же рабочую точку, поэтому её запоминаем и в следующий раз проверяем первой.
 *
 * Кеш ничего не «назначает»: точка всё равно проходит настоящий handshake и проверки ресурсов, и
 * только после этого считается рабочей. Поэтому старый/чужой кеш не может протащить нерабочий
 * конфиг — он лишь избавляет от скана, когда и так всё работает.
 */
object TuningCache {

    /** Дольше суток держать бессмысленно: адреса и блокировки за это время меняются. */
    private const val MAX_AGE_MS = 24 * 60 * 60 * 1000L

    private const val FILE_NAME = "tuning-cache.txt"

    data class Entry(
        val transport: String,
        val host: String,
        val port: Int,
        val junk: String,
        val savedAt: Long
    )

    fun load(context: Context): Entry? {
        val file = File(context.filesDir, FILE_NAME)
        if (!file.isFile) return null
        val map = runCatching {
            file.readLines().mapNotNull { line ->
                val i = line.indexOf('=')
                if (i <= 0) null else line.substring(0, i) to line.substring(i + 1)
            }.toMap()
        }.getOrNull() ?: return null
        val host = map["host"].orEmpty()
        val port = map["port"]?.toIntOrNull() ?: return null
        val savedAt = map["saved"]?.toLongOrNull() ?: return null
        if (host.isBlank() || port !in 1..65535) return null
        return Entry(map["transport"].orEmpty(), host, port, map["junk"].orEmpty(), savedAt)
    }

    /**
     * Запомнить рабочую точку. Пишем через временный файл: если процесс убьют посреди записи,
     * на месте кеша останется либо старый кеш, либо новый, но не половина строки.
     */
    fun save(context: Context, endpoint: Endpoint, junkName: String) {
        if (endpoint.host.isBlank()) return
        val text = buildString {
            append("transport=").append(transportOf(context)).append('\n')
            append("host=").append(endpoint.host).append('\n')
            append("port=").append(endpoint.port).append('\n')
            append("junk=").append(junkName).append('\n')
            append("saved=").append(System.currentTimeMillis()).append('\n')
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

    /**
     * Готовое предложение для подбора: только если кеш с этой же сети и не старше суток, а профиль
     * шума из него ещё существует. Иначе null — пусть идёт обычный полный подбор.
     */
    fun cachedStart(context: Context, profiles: List<JunkProfile>): CachedStart? {
        val entry = load(context) ?: return null
        if (System.currentTimeMillis() - entry.savedAt > MAX_AGE_MS) return null
        if (entry.transport != transportOf(context)) return null
        if (entry.junk.isNotBlank() && profiles.none { it.name == entry.junk }) return null
        return CachedStart(Endpoint(entry.host, entry.port), entry.junk)
    }

    /**
     * Вид сети, а не её имя: имя Wi-Fi требует доступа к местоположению, а нам нужно лишь понять
     * «та же сеть или другая» — домашний Wi-Fi и мобильная сеть ведут себя по-разному.
     */
    fun transportOf(context: Context): String {
        val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
            ?: return "unknown"
        val nets = runCatching { cm.allNetworks }.getOrNull() ?: emptyArray()
        val found = nets.mapNotNull { net ->
            val caps = runCatching { cm.getNetworkCapabilities(net) }.getOrNull() ?: return@mapNotNull null
            if (!caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) return@mapNotNull null
            if (caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) return@mapNotNull null
            when {
                caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> 0 to "wifi"
                caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> 1 to "mobile"
                caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> 2 to "ethernet"
                else -> 3 to "other"
            }
        }.sortedBy { it.first }
        if (found.isNotEmpty()) return found.first().second
        // Ни одной «настоящей» сети: либо сети нет, либо всё закрыто туннелем.
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) "none" else "unknown"
    }
}
