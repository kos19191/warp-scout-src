package dev.warpscout.app

import android.content.Context
import dev.warpscout.core.junk.JunkLibrary
import dev.warpscout.core.model.JunkProfile
import dev.warpscout.core.net.EndpointPool
import dev.warpscout.core.net.EndpointSpec
import dev.warpscout.core.net.NetSettings
import dev.warpscout.core.net.PoolMode
import dev.warpscout.core.presets.Presets
import dev.warpscout.core.presets.RoutePresets
import dev.warpscout.core.tune.TuningSpec

/**
 * Всё, что пользователь настроил в интерфейсе. Хранится в SharedPreferences; приватный ключ
 * сюда не попадает — для него есть [KeyVault] (AndroidKeyStore).
 */
class Prefs(context: Context) {

    private val sp = context.getSharedPreferences("warpscout", Context.MODE_PRIVATE)
    private val junkNames = JunkLibrary.defaultPool().map { it.name }

    var hostsText: String
        get() = sp.getString("hosts", "") ?: ""
        set(v) = sp.edit().putString("hosts", v).apply()

    /** «500-510, 2408» — пусто = порты генератора. */
    var portsText: String
        get() = sp.getString("ports", "") ?: ""
        set(v) = sp.edit().putString("ports", v).apply()

    var endpointCount: Int
        get() = sp.getInt("count", 120)
        set(v) = sp.edit().putInt("count", v.coerceIn(4, 4000)).apply()

    var dnsIndex: Int
        get() = sp.getInt("dns", 0)
        set(v) = sp.edit().putInt("dns", v).apply()

    var keepalive: Int
        get() = sp.getInt("keepalive", 25)
        set(v) = sp.edit().putInt("keepalive", v.coerceIn(0, 120)).apply()

    var mtu: Int
        get() = sp.getInt("mtu", 1280)
        set(v) = sp.edit().putInt("mtu", v.coerceIn(576, 1420)).apply()

    var splitWhitelist: Boolean
        get() = sp.getBoolean("whitelist", true)
        set(v) = sp.edit().putBoolean("whitelist", v).apply()

    var enableIpv6: Boolean
        get() = sp.getBoolean("ipv6", true)
        set(v) = sp.edit().putBoolean("ipv6", v).apply()

    var checkResources: Boolean
        get() = sp.getBoolean("resources", true)
        set(v) = sp.edit().putBoolean("resources", v).apply()

    var verifyInTunnel: Boolean
        get() = sp.getBoolean("tunnel_verify", false)
        set(v) = sp.edit().putBoolean("tunnel_verify", v).apply()

    /** Включённые профили шума (по именам из [JunkLibrary]). */
    var enabledJunk: Set<String>
        get() = sp.getStringSet("junk", junkNames.toSet()) ?: junkNames.toSet()
        set(v) = sp.edit().putStringSet("junk", v).apply()

    var scheduleOn: Boolean
        get() = sp.getBoolean("schedule", false)
        set(v) = sp.edit().putBoolean("schedule", v).apply()

    /** .conf, импортированный вручную: используется, если генератор недоступен. */
    var manualConf: String
        get() = sp.getString("manual_conf", "") ?: ""
        set(v) = sp.edit().putString("manual_conf", v).apply()

    var concurrency: Int
        get() = sp.getInt("concurrency", 48)
        set(v) = sp.edit().putInt("concurrency", v.coerceIn(4, 256)).apply()

    var attempts: Int
        get() = sp.getInt("attempts", 3)
        set(v) = sp.edit().putInt("attempts", v.coerceIn(1, 8)).apply()

    var timeoutMs: Int
        get() = sp.getInt("timeout", 1200)
        set(v) = sp.edit().putInt("timeout", v.coerceIn(300, 8000)).apply()

    /** 0 — пул генератора, 1 — только MASQUE, 2 — полный перебор. Выбирается кнопками в UI. */
    var poolMode: Int
        get() = sp.getInt("poolMode", POOL_DEFAULT)
        set(v) = sp.edit().putInt("poolMode", v.coerceIn(0, 2)).apply()

    /** Поднимать/переподнимать собственный туннель сразу после подбора (сборка tunnel). */
    /** Адрес SOCKS5-прокси ByeDPI ('' = не использовать). */
    var byedpiProxy: String
        get() = sp.getString("byedpiProxy", "") ?: ""
        set(v) = sp.edit().putString("byedpiProxy", v.trim()).apply()

    /** true — базовые замеры во время подбора идут через ByeDPI, а не напрямую. */
    var tuneViaByedpi: Boolean
        get() = sp.getBoolean("tuneViaByedpi", false)
        set(v) = sp.edit().putBoolean("tuneViaByedpi", v).apply()

    var autoApply: Boolean
        get() = sp.getBoolean("autoApply", false)
        set(v) = sp.edit().putBoolean("autoApply", v).apply()

    /** Когда последний раз заканчивался подбор — чтобы на экране было видно «это свежий конфиг». */
    var lastTunedAt: Long
        get() = sp.getLong("lastTunedAt", 0L)
        set(v) = sp.edit().putLong("lastTunedAt", v).apply()

    var lastTunedEndpoint: String
        get() = sp.getString("lastTunedEndpoint", "").orEmpty()
        set(v) = sp.edit().putString("lastTunedEndpoint", v).apply()

    var lastTunedScore: Int
        get() = sp.getInt("lastTunedScore", 0)
        set(v) = sp.edit().putInt("lastTunedScore", v).apply()

    /** Когда endpoint реально сменился: «новый конфиг» ≠ «тот же, просто перепроверен». */
    var lastChangedAt: Long
        get() = sp.getLong("lastChangedAt", 0L)
        set(v) = sp.edit().putLong("lastChangedAt", v).apply()

    val junkPool: List<JunkProfile>
        get() = JunkLibrary.defaultPool().filter { it.name in enabledJunk }
            .ifEmpty { listOf(JunkLibrary.none()) }

    /**
     * Что именно сканить.
     *
     *  • поле «IP или подсети» пустое — берём пул самого генератора (подсети Cloudflare × порты);
     *  • строки вида `1.2.3.4:500`, `engage.cloudflareclient.com:443`, `188.114.96.1-10:443`,
     *    `8.6.112.*:943` — сканируем ровно их (режим EXPLICIT, звёздочка и диапазоны разбираются ядром);
     *  • строка без порта — к ней применяются порты из второго поля (или все 52 порта AWG, если поле
     *    портов пустое).
     */
    fun endpointSpec(): EndpointSpec {
        val lines = hostsText.split('\n', ',').map { it.substringBefore('#').trim() }.filter { it.isNotEmpty() }
        val ports = portsText.split(',', ' ', '\n').mapNotNull { it.trim().toIntOrNull() }
        val seed = System.currentTimeMillis() / (24L * 3600_000L)   // один и тот же пул в течение суток
        val mode = when (poolMode) {
            POOL_MASQUE -> PoolMode.STRATIFIED
            POOL_FULL -> PoolMode.FULL
            else -> if (endpointCount >= 900) PoolMode.FULL else PoolMode.STRATIFIED
        }
        val base = when (poolMode) {
            POOL_MASQUE -> EndpointSpec(
                subnets = dev.warpscout.core.net.WarpDefaults.MASQUE_SUBNETS,
                ports = if (ports.isEmpty()) dev.warpscout.core.net.WarpDefaults.MASQUE_PORTS else ports,
                mode = mode, maxEndpoints = endpointCount, seed = seed
            )
            POOL_FULL -> EndpointSpec(mode = PoolMode.FULL, maxEndpoints = endpointCount, seed = seed)
            else -> EndpointSpec(
                ports = if (ports.isEmpty()) dev.warpscout.core.net.WarpDefaults.AWG_PORTS else ports,
                mode = mode, maxEndpoints = endpointCount, seed = seed
            )
        }
        if (lines.isEmpty()) return base
        // Набран свой список: он важнее режима (режим тогда только про «сколько» и про FULL/STRATIFIED).
        val explicit = lines.flatMap { line ->
            val p = if (line.contains(':')) null else ports
            when {
                line.contains(':') -> listOf(line)
                p != null && p.isNotEmpty() -> p.map { "$line:$it" }
                else -> listOf("$line:*")
            }
        }
        return base.copy(subnets = emptyList(), hostnames = explicit, mode = PoolMode.EXPLICIT,
            maxEndpoints = maxOf(endpointCount, explicit.size))
    }

    /** Как объяснить пользователю, что он сейчас выбрал. */
    fun poolModeName(): String = when (poolMode) {
        POOL_MASQUE -> "Только MASQUE"
        POOL_FULL -> "Полный перебор"
        else -> "Пул генератора"
    }

    fun tuningSpec(): TuningSpec = TuningSpec(
        endpointSpec = endpointSpec(),
        junkProfiles = junkPool,
        net = NetSettings(attempts = attempts, timeoutMs = timeoutMs, concurrency = concurrency),
        resources = if (checkResources) Presets.RESOURCE_CHECKS else emptyList(),
        dns = Presets.DNS[dnsIndex.coerceIn(0, Presets.DNS.size - 1)].servers,
        mtu = mtu,
        allowedIps = if (splitWhitelist) RoutePresets.BYPASS_WHITELIST_CSV else "0.0.0.0/0, ::/0",
        keepalive = keepalive.takeIf { it > 0 },
        enableIpv6Address = enableIpv6,
        checkBaselineResources = checkResources,
        verifyThroughTunnel = verifyInTunnel,
        tunnelSettleMs = 8000
    )

    companion object {
        const val POOL_DEFAULT = 0
        const val POOL_MASQUE = 1
        const val POOL_FULL = 2

        const val MIRROR_NOTE = "Ключи берутся из публичного генератора (warp-api.cfd); вводить PrivateKey не нужно."
    }
}
