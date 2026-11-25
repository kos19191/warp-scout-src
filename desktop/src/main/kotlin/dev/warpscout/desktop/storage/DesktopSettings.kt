package dev.warpscout.desktop.storage

import dev.warpscout.core.config.ConfTarget
import dev.warpscout.core.lists.AllowLists

enum class ThemeMode(val title: String) {
    DARK("Тёмная"),
    LIGHT("Светлая"),
    SYSTEM("Системная")
}

enum class TunnelBackendMode(val title: String, val subtitle: String) {
    BUILTIN_WINTUN(
        "Встроенный туннель WarpScout (Wintun)",
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
    ALL("Весь трафик", "0.0.0.0/0, ::/0 — всё идёт через туннель"),
    PRESET("Пресет обхода РФ", "Зарубежные сети в туннель, российские — напрямую"),
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

/** Все пользовательские настройки десктопного приложения. */
data class DesktopSettings(
    val theme: ThemeMode = ThemeMode.DARK,
    val minimizeToTrayOnClose: Boolean = true,
    val autostartWindows: Boolean = false,
    val autoConnectOnStart: Boolean = false,
    val disconnectOnExit: Boolean = true,

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

    // Маршруты (split-tunnel)
    val routeMode: RouteMode = RouteMode.ALL,
    val selectedBlockListIds: List<String> = AllowLists.DEFAULT_BLOCK_IDS,
    val selectedDirectListIds: List<String> = listOf("hosters-blocked", "russia-outside"),
    val builtAllowedIps: String = "",
    val manualAllowedIps: String = "0.0.0.0/0, ::/0",

    // Второй выход (свой WireGuard/AmneziaWG сервер для отдельных доменов)
    val secondExitEnabled: Boolean = false,
    val secondExitConf: String = "",
    val secondExitDomains: String = "chatgpt.com, openai.com, api.openai.com, auth.openai.com",
    val secondExitCidrs: String = "",

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
        RouteMode.PRESET -> dev.warpscout.core.presets.RoutePresets.BYPASS_WHITELIST_CSV
        RouteMode.LISTS -> builtAllowedIps.takeIf { it.isNotBlank() }
            ?: if (enableIpv6) "0.0.0.0/0, ::/0" else "0.0.0.0/0"
        RouteMode.MANUAL -> manualAllowedIps.takeIf { it.isNotBlank() }
            ?: if (enableIpv6) "0.0.0.0/0, ::/0" else "0.0.0.0/0"
    }
}
