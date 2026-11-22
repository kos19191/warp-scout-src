package dev.warpscout.app

import android.content.Context
import dev.warpscout.core.net.DohClient
import dev.warpscout.core.net.HttpClient
import dev.warpscout.core.presets.Presets

/**
 * Адреса DNS из списка «DNS в конфиге» — с поиском по имени.
 *
 * Зачем. У «умных» DNS (Comss, WLRus, Dagami, GeoHide, Безмежа: они отдают для ChatGPT и Gemini
 * адреса своих прокси) адреса серверов меняются, а имя остаётся. Вписанные в приложение адреса
 * через полгода вели в никуда. Теперь адреса берутся по имени — раз в сутки и при выборе набора, —
 * а вписанные остаются запасом.
 *
 * Имя разрешаем через DoH по IP-адресу (1.1.1.1, 8.8.8.8), а не системным DNS: с августа 2026
 * ответы обычного DNS операторы подменяют, и «адрес DNS-сервера» мог прийти чужой. Если DoH
 * недоступен — системным резолвером, лучше так, чем никак.
 *
 * Кеш — в своих SharedPreferences процесса интерфейса: сервису эти адреса не нужны, они уже
 * вписаны в текст конфига, которым он поднимает туннель.
 */
object DnsBook {

    private const val FILE = "dns-book"

    /** Адреса по имени живут сутки — дальше берём заново (старые остаются, пока новых нет). */
    private const val FRESH_MS = 24L * 60 * 60 * 1000

    /** Больше двух адресов IPv4 на имя не берём: Android всё равно опрашивает первые. */
    private const val MAX_RESOLVED = 2

    private fun sp(context: Context) =
        context.applicationContext.getSharedPreferences(FILE, Context.MODE_PRIVATE)

    fun preset(index: Int): Presets.DnsPreset =
        Presets.DNS[index.coerceIn(0, Presets.DNS.size - 1)]

    /** Адреса, найденные по имени (из кеша, без сети). */
    fun resolved(context: Context, host: String): List<String> {
        if (host.isBlank()) return emptyList()
        return sp(context).getString("ip:$host", "").orEmpty()
            .split(',').map { it.trim() }.filter { it.isNotEmpty() }
    }

    private fun resolvedAt(context: Context, host: String): Long =
        sp(context).getLong("at:$host", 0L)

    /**
     * Адреса набора для конфига — без сети. Найденные по имени идут первыми, вписанные — запасом.
     * Если у набора нет ни тех, ни других (имя ещё ни разу не разрешилось), честно берём
     * Cloudflare: пустой список DNS в конфиге оставил бы туннель без имён вовсе.
     */
    fun servers(context: Context, index: Int): List<String> {
        val p = preset(index)
        val byName = if (p.host.isBlank()) emptyList() else resolved(context, p.host)
        val all = (byName + p.servers).map { it.trim() }.filter { it.isNotEmpty() }.distinct()
        return if (all.isEmpty()) Presets.DNS.first().servers else all.take(4)
    }

    /** У набора пока нет своих адресов, и в конфиг идёт Cloudflare (см. [servers]). */
    fun usesFallback(context: Context, index: Int): Boolean {
        val p = preset(index)
        return p.servers.isEmpty() && resolved(context, p.host).isEmpty()
    }

    /** Пора ли спросить адреса по имени заново. */
    fun needsRefresh(context: Context, index: Int): Boolean {
        val p = preset(index)
        if (p.host.isBlank()) return false
        return System.currentTimeMillis() - resolvedAt(context, p.host) > FRESH_MS
    }

    /**
     * Найти адреса по имени (сеть, вызывать не на главном потоке). Возвращает найденное или
     * пустой список; кеш при неудаче не трогаем — старые адреса лучше, чем никаких.
     */
    fun refresh(context: Context, index: Int): List<String> {
        val p = preset(index)
        if (p.host.isBlank()) return emptyList()
        val found = resolveIpv4(p.host)
        if (found.isNotEmpty()) {
            sp(context).edit()
                .putString("ip:${p.host}", found.joinToString(","))
                .putLong("at:${p.host}", System.currentTimeMillis())
                .apply()
        }
        return found
    }

    /** IPv4-адреса имени: DoH по IP, затем системный резолвер. */
    fun resolveIpv4(host: String): List<String> {
        val v4 = Regex("""^\d{1,3}(\.\d{1,3}){3}$""")
        val http = HttpClient(4000)
        for (endpoint in listOf("https://1.1.1.1/dns-query", "https://8.8.8.8/resolve")) {
            val list = runCatching { DohClient(endpoint, http).resolveA(host) }.getOrNull().orEmpty()
                .map { it.trim() }
                .filter { v4.matches(it) }
                .distinct()
            if (list.isNotEmpty()) return list.take(MAX_RESOLVED)
        }
        return runCatching {
            java.net.InetAddress.getAllByName(host)
                .filterIsInstance<java.net.Inet4Address>()
                .mapNotNull { it.hostAddress }
                .distinct()
                .take(MAX_RESOLVED)
        }.getOrDefault(emptyList())
    }

    /** Подпись набора в списке: имя и что сейчас пойдёт в конфиг. */
    fun label(context: Context, index: Int): String {
        val p = preset(index)
        val byName = resolved(context, p.host)
        val shown = when {
            byName.isNotEmpty() -> (byName + p.servers.filter { !it.contains(':') }).distinct().take(3).joinToString(", ")
            p.servers.isNotEmpty() -> p.servers.joinToString(", ")
            else -> context.getString(R.string.dns_by_name_pending, p.host)
        }
        return "${p.name} — $shown"
    }
}
