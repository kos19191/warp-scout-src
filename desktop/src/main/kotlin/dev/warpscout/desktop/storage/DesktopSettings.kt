package dev.warpscout.desktop.storage

import dev.warpscout.core.config.ConfTarget
import dev.warpscout.core.lists.AllowLists
import dev.warpscout.desktop.tunnel.ByeDpiPac
import dev.warpscout.desktop.tunnel.ByeDpiPresets
import dev.warpscout.desktop.tunnel.SecondExitCatalog

enum class ThemeMode(val title: String) {
    DARK("Тёмная"),
    LIGHT("Светлая"),
    SYSTEM("Системная")
}

enum class TunnelBackendMode(val title: String, val subtitle: String) {
    BUILTIN_WINTUN(
        "Встроенный туннель WilyScout (Wintun)",
        "Собственный WireGuard/AmneziaWG туннель из ядра :core — сторонние программы не нужны"
    ),
    EXTERNAL_AWG(
        "Внешний движок AmneziaWG",
        "Использовать установленный на ПК amneziawg.exe как системную службу"
    )
}

enum class DesktopPoolMode(val title: String) {
    DEFAULT("Пул генератора"),
    MASQUE("Только MASQUE (443/8443)"),
    FULL("Полный перебор"),
    CUSTOM("Свой список")
}

enum class RouteMode(val title: String, val subtitle: String) {
    PRESET("Пресет обхода РФ (по умолчанию)", "Зарубежные сайты через туннель, российские и локальная сеть — напрямую"),
    ALL("Весь трафик", "0.0.0.0/0, ::/0 — всё идёт через туннель"),
    LISTS("Списки allow-domains", "CIDR из выбранных категорий (YouTube, Discord, Telegram, AI…)"),
    MANUAL("Вручную (CIDR)", "Точный список подсетей AllowedIPs ниже")
}

/** Один сохранённый вариант из Топ-3 лучших конфигов для мгновенного переключения. */
data class ShortlistEntry(
    val endpoint: String,
    val junkName: String,
    val score: Int,
    val resourcesOk: Int = -1,
    val resourcesTotal: Int = 0,
    val checkedAtMs: Long = 0L,
    val confText: String
)

/** Запомненная стратегия ByeDPI для конкретной сети (по Wi-Fi SSID и/или шлюзу). */
data class NetworkDpiProfile(
    val networkKey: String,
    val networkLabel: String,
    val presetId: String,
    val customArgs: String = "",
    val fixedCount: Int = 0,
    val totalChecks: Int = 0,
    val testedAtMs: Long = 0L
)

/** Все пользовательские настройки десктопного приложения. */
data class DesktopSettings(
    val theme: ThemeMode = ThemeMode.DARK,
    val minimizeToTrayOnClose: Boolean = true,
    val autostartWindows: Boolean = false,
    val autoConnectOnStart: Boolean = false,
    val disconnectOnExit: Boolean = true,
    val autoCheckUpdates: Boolean = true,
    val includePrereleaseUpdates: Boolean = true,

    // Движок туннеля (по умолчанию — встроенный Wintun + DataPlane из :core, без сторонних программ)
    val backendMode: TunnelBackendMode = TunnelBackendMode.BUILTIN_WINTUN,
    val customEnginePath: String = "",
    val autoElevateUac: Boolean = true,

    // Подбор (AutoTuner)
    val poolMode: DesktopPoolMode = DesktopPoolMode.DEFAULT,
    val customHostsText: String = "",
    val customPortsText: String = "",
    val endpointCount: Int = 120,
    val sniCount: Int = 3,
    val includeNoneJunk: Boolean = true,
    val includeTlsJunk: Boolean = true,
    val includeQuicJunk: Boolean = true,
    val includeSipJunk: Boolean = true,
    val checkResources: Boolean = true,
    val verifyThroughTunnel: Boolean = true,
    val autoScheduleHours: Int = 0,
    val autoApplyScheduled: Boolean = false,

    // Сеть
    val dnsPresetIndex: Int = 0,
    val customDns: String = "1.1.1.1, 1.0.0.1, 2606:4700:4700::1111, 2606:4700:4700::1001",
    val mtu: Int = 1280,
    val keepalive: Int = 25,
    val enableIpv6: Boolean = true,

    // Маршруты (split-tunnel): по умолчанию — пресет обхода РФ (зарубежные в туннель, РФ напрямую)
    val routeMode: RouteMode = RouteMode.PRESET,
    val selectedBlockListIds: List<String> = AllowLists.DEFAULT_BLOCK_IDS,
    val selectedDirectListIds: List<String> = listOf("hosters-blocked", "russia-outside"),
    val builtAllowedIps: String = "",
    val manualAllowedIps: String = "0.0.0.0/0, ::/0",

    // Второй выход (свой WireGuard/AmneziaWG сервер для выбранных списков и сайтов)
    val secondExitEnabled: Boolean = false,
    val secondExitConf: String = "",
    val secondExitListIds: List<String> = SecondExitCatalog.DEFAULT_LIST_IDS,
    val secondExitViaWarp: Boolean = true,
    val secondExitDomains: String = "",
    val secondExitCidrs: String = "",

    // Встроенный обход DPI (ByeDPI / ciadpi.exe — локальный SOCKS5-прокси без драйвера ядра)
    val byeDpiPresetId: String = ByeDpiPresets.DEFAULT_ID,
    val byeDpiPort: Int = 1080,
    val byeDpiCustomArgs: String = "",
    val byeDpiSystemProxy: Boolean = false,
    val byeDpiBypassTunnel: Boolean = true,
    val byeDpiPacDomains: String = ByeDpiPac.DEFAULT_DOMAINS_TEXT,
    val byeDpiNetworkProfiles: Map<String, NetworkDpiProfile> = emptyMap(),

    // Пользовательский путь к Telegram.exe (пусто — автопоиск)
    val telegramExePath: String = "",

    // Экспорт
    val exportTarget: ConfTarget = ConfTarget.AMNEZIA,

    // Сводка последнего подбора и выбранной точки
    val activeShortlistIndex: Int = 0,
    val lastTuneAtMs: Long = 0L,
    val lastTuneDurationSec: Int = 0,
    val lastTuneEndpoint: String = "",
    val lastTuneJunk: String = "",
    val lastTuneSummary: String = "",
    val lastAccountSource: String = ""
) {
    fun effectiveDns(): List<String> =
        customDns.split(',', ';', ' ', '\n', '\r', '\t')
            .map { it.trim() }
            .filter { it.isNotEmpty() }
            .ifEmpty { listOf("1.1.1.1", "1.0.0.1") }

    fun effectiveAllowedIps(): String = when (routeMode) {
        RouteMode.ALL -> if (enableIpv6) "0.0.0.0/0, ::/0" else "0.0.0.0/0"
        RouteMode.PRESET -> dev.warpscout.desktop.tunnel.RuBypassRoutes.allowedIpsCsv(includeIpv6 = enableIpv6)
        RouteMode.LISTS -> builtAllowedIps.takeIf { it.isNotBlank() }
            ?: if (enableIpv6) "0.0.0.0/0, ::/0" else "0.0.0.0/0"
        RouteMode.MANUAL -> manualAllowedIps.takeIf { it.isNotBlank() }
            ?: if (enableIpv6) "0.0.0.0/0, ::/0" else "0.0.0.0/0"
    }
}
