package dev.warpscout.app

import android.content.Context
import dev.warpscout.core.lists.ProtonFree
import java.io.File
import java.net.HttpURLConnection
import java.net.URL

/**
 * Второй выход через Proton VPN Free с автопоиском сервера (с 1.10.31): список бесплатных серверов
 * и порядок, в котором сервис их перебирает (см. ProtonFree и WarpVpnService, «второй выход»).
 *
 * Список: встроенный снимок, раз в неделю — свежий из сети (список проекта gluetun на GitHub).
 * Не скачался — работаем со встроенным: бесплатные серверы Proton меняются редко.
 */
object SecondProton {

    private const val FILE = "proton_free.txt"
    private const val STALE_MS = 7L * 86_400_000L

    /** Сколько серверов отдавать сервису: на всех 53 перебор затянулся бы на минуты. */
    private const val MAX_PEERS = 16

    private fun file(context: Context) = File(context.applicationContext.filesDir, FILE)

    /** Серверы: скачанный список, иначе встроенный. */
    fun servers(context: Context): List<ProtonFree.Server> {
        val cached = runCatching { ProtonFree.parseCompact(file(context).readText()) }.getOrDefault(emptyList())
        return if (cached.size >= 5) cached else ProtonFree.BUILTIN
    }

    fun fetchedAt(context: Context): Long = file(context).takeIf { it.isFile }?.lastModified() ?: 0L

    fun isStale(context: Context): Boolean = System.currentTimeMillis() - fetchedAt(context) > STALE_MS

    /**
     * Скачать свежий список (сеть — не из UI-потока). Возвращает число бесплатных серверов. Меньше
     * пяти — считаем ответ испорченным и оставляем прежний список.
     */
    fun refresh(context: Context): Int {
        val text = runCatching { get(ProtonFree.SOURCE_URL, raw = false) }
            .recoverCatching { get(ProtonFree.SOURCE_API, raw = true) }
            .getOrThrow()
        val list = ProtonFree.parseGluetun(text)
        if (list.size < 5) error("в списке серверов Proton нет бесплатных (${list.size})")
        write(context, list)
        return list.size
    }

    /**
     * Список, который приложение получило у самого Proton (или у стороннего сервиса) вместе с ключом
     * (с 1.10.44-beta5): он свежее списка gluetun — с ним и работает автопоиск. Меньше пяти серверов —
     * оставляем прежний.
     */
    fun save(context: Context, servers: List<ProtonFree.Server>): Boolean {
        val list = servers.filter { it.ip.isNotBlank() && it.publicKey.length == 44 }.distinctBy { it.ip + "|" + it.publicKey }
        if (list.size < 5) return false
        write(context, list)
        return true
    }

    private fun write(context: Context, list: List<ProtonFree.Server>) {
        val target = file(context)
        val tmp = File(target.parentFile, "$FILE.tmp")
        tmp.writeText(ProtonFree.render(list))
        if (!tmp.renameTo(target)) {
            tmp.copyTo(target, overwrite = true)
            tmp.delete()
        }
    }

    /**
     * Порядок перебора для сервиса: строки «имя|адрес|порт|ключ». Пусто — конфиг не от Proton, и
     * второй выход работает как раньше: один сервер из конфига.
     */
    fun candidates(context: Context, prefs: Prefs): List<String> {
        val conf = prefs.secondConf
        if (!prefs.secondExitOn || !ProtonFree.isProton(conf)) return emptyList()
        val list = servers(context)
        // Круг внутри страны сдвигается раз в сутки: так все телефоны не ломятся в один сервер.
        val day = System.currentTimeMillis() / 86_400_000L
        return ProtonFree.ordered(list, prefs.secondProtonCountry, prefs.secondProtonLast, ProtonFree.peerOf(conf), day)
            .take(MAX_PEERS)
            .map { ProtonFree.encode(it) }
    }

    /** «Нидерланды» по коду страны; незнакомый код — как есть. */
    fun countryName(context: Context, code: String): String = when (code) {
        "NL" -> context.getString(R.string.country_nl)
        "PL" -> context.getString(R.string.country_pl)
        "RO" -> context.getString(R.string.country_ro)
        "CH" -> context.getString(R.string.country_ch)
        "NO" -> context.getString(R.string.country_no)
        "DE" -> context.getString(R.string.country_de)
        "FI" -> context.getString(R.string.country_fi)
        "SE" -> context.getString(R.string.country_se)
        "CA" -> context.getString(R.string.country_ca)
        "US" -> context.getString(R.string.country_us)
        "JP" -> context.getString(R.string.country_jp)
        "SG" -> context.getString(R.string.country_sg)
        "MX" -> context.getString(R.string.country_mx)
        else -> code
    }

    private fun get(url: String, raw: Boolean): String {
        val conn = (URL(url).openConnection() as HttpURLConnection).apply {
            instanceFollowRedirects = true
            connectTimeout = 15_000
            readTimeout = 30_000
            setRequestProperty("User-Agent", "WarpScout/${BuildConfig.VERSION_NAME}")
            if (raw) setRequestProperty("Accept", "application/vnd.github.raw")
        }
        try {
            val code = conn.responseCode
            if (code !in 200..299) error("HTTP $code")
            return conn.inputStream.bufferedReader().use { it.readText() }
        } finally {
            runCatching { conn.disconnect() }
        }
    }
}
