package dev.warpscout.desktop.storage

import dev.warpscout.core.config.ConfTarget
import dev.warpscout.core.json.JsonVal
import dev.warpscout.core.json.parseJson
import dev.warpscout.core.lists.AllowLists
import dev.warpscout.desktop.tunnel.ByeDpiPresets
import java.io.File

/**
 * Чтение/запись настроек, Топ-3 конфигов, активного конфига и резервных копий.
 *
 * Использует лёгкий JSON-парсер из `:core` — никаких сторонних сериализаторов и рефлексии.
 */
class DesktopStore(val paths: DesktopPaths) {

    init {
        paths.ensureDirs()
    }

    fun loadSettings(): DesktopSettings {
        val file = paths.settingsFile
        if (!file.exists()) return DesktopSettings()
        return runCatching {
            val obj = parseJson(file.readText()) as? JsonVal.Obj ?: return@runCatching DesktopSettings()
            settingsFromJson(obj)
        }.getOrDefault(DesktopSettings())
    }

    fun saveSettings(settings: DesktopSettings) {
        paths.ensureDirs()
        writeAtomic(paths.settingsFile, settingsToJson(settings).render(0))
    }

    fun loadShortlist(): List<ShortlistEntry> {
        val file = paths.shortlistFile
        if (!file.exists()) return emptyList()
        return runCatching {
            val arr = parseJson(file.readText()) as? JsonVal.Arr ?: return@runCatching emptyList()
            shortlistFromJson(arr)
        }.getOrDefault(emptyList())
    }

    fun saveShortlist(items: List<ShortlistEntry>) {
        paths.ensureDirs()
        writeAtomic(paths.shortlistFile, shortlistToJson(items).render(0))
    }

    fun loadActiveConfigText(): String? =
        runCatching { paths.activeConfFile.takeIf { it.exists() }?.readText()?.takeIf { it.isNotBlank() } }.getOrNull()

    fun saveActiveConfigText(confText: String) {
        paths.ensureDirs()
        writeAtomic(paths.activeConfFile, confText)
    }

    fun exportBackup(targetFile: File): BackupSummary {
        val settings = loadSettings()
        val shortlist = loadShortlist()
        val active = loadActiveConfigText().orEmpty()
        val accountCache = runCatching { paths.accountCacheFile.takeIf { it.exists() }?.readText().orEmpty() }.getOrDefault("")

        val root = JsonVal.obj(
            "format" to JsonVal.str("warpscout-desktop-backup"),
            "version" to JsonVal.num(1),
            "createdAtMs" to JsonVal.num(System.currentTimeMillis()),
            "settings" to settingsToJson(settings),
            "shortlist" to shortlistToJson(shortlist),
            "activeConf" to JsonVal.str(active),
            "accountCache" to JsonVal.str(accountCache)
        )
        targetFile.parentFile?.mkdirs()
        writeAtomic(targetFile, root.render(0))
        return BackupSummary(
            file = targetFile,
            settingsCount = settingsToJson(settings).fields.size,
            shortlistCount = shortlist.size,
            hasActiveConfig = active.isNotBlank()
        )
    }

    fun importBackup(sourceFile: File): RestoreResult {
        val obj = parseJson(sourceFile.readText()) as? JsonVal.Obj
            ?: throw IllegalArgumentException("Файл не является корректной резервной копией JSON")
        val settingsObj = obj.obj("settings")
            ?: throw IllegalArgumentException("В резервной копии отсутствует блок settings")
        val restoredSettings = settingsFromJson(settingsObj)
        saveSettings(restoredSettings)

        val restoredShortlist = obj.arr("shortlist")?.let { shortlistFromJson(it) } ?: emptyList()
        if (restoredShortlist.isNotEmpty()) saveShortlist(restoredShortlist)

        val active = obj.str("activeConf").orEmpty()
        if (active.isNotBlank()) saveActiveConfigText(active)

        val accountCache = obj.str("accountCache").orEmpty()
        if (accountCache.isNotBlank()) writeAtomic(paths.accountCacheFile, accountCache)

        return RestoreResult(
            settings = restoredSettings,
            shortlist = restoredShortlist,
            activeConf = active.ifBlank { null },
            restoredFields = settingsObj.fields.size
        )
    }

    data class BackupSummary(
        val file: File,
        val settingsCount: Int,
        val shortlistCount: Int,
        val hasActiveConfig: Boolean
    )

    data class RestoreResult(
        val settings: DesktopSettings,
        val shortlist: List<ShortlistEntry>,
        val activeConf: String?,
        val restoredFields: Int
    )

    private fun writeAtomic(file: File, content: String) {
        file.parentFile?.mkdirs()
        val tmp = File(file.parentFile, "${file.name}.tmp")
        tmp.writeText(content, Charsets.UTF_8)
        if (!tmp.renameTo(file)) {
            file.writeText(content, Charsets.UTF_8)
            tmp.delete()
        }
    }

    companion object {
        fun settingsToJson(s: DesktopSettings): JsonVal.Obj = JsonVal.obj(
            "theme" to JsonVal.str(s.theme.name),
            "minimizeToTrayOnClose" to JsonVal.bool(s.minimizeToTrayOnClose),
            "autostartWindows" to JsonVal.bool(s.autostartWindows),
            "autoConnectOnStart" to JsonVal.bool(s.autoConnectOnStart),
            "disconnectOnExit" to JsonVal.bool(s.disconnectOnExit),
            "autoCheckUpdates" to JsonVal.bool(s.autoCheckUpdates),
            "includePrereleaseUpdates" to JsonVal.bool(s.includePrereleaseUpdates),
            "backendMode" to JsonVal.str(s.backendMode.name),
            "customEnginePath" to JsonVal.str(s.customEnginePath),
            "autoElevateUac" to JsonVal.bool(s.autoElevateUac),
            "poolMode" to JsonVal.str(s.poolMode.name),
            "customHostsText" to JsonVal.str(s.customHostsText),
            "customPortsText" to JsonVal.str(s.customPortsText),
            "endpointCount" to JsonVal.num(s.endpointCount),
            "sniCount" to JsonVal.num(s.sniCount),
            "includeNoneJunk" to JsonVal.bool(s.includeNoneJunk),
            "includeTlsJunk" to JsonVal.bool(s.includeTlsJunk),
            "includeQuicJunk" to JsonVal.bool(s.includeQuicJunk),
            "includeSipJunk" to JsonVal.bool(s.includeSipJunk),
            "checkResources" to JsonVal.bool(s.checkResources),
            "verifyThroughTunnel" to JsonVal.bool(s.verifyThroughTunnel),
            "autoScheduleHours" to JsonVal.num(s.autoScheduleHours),
            "autoApplyScheduled" to JsonVal.bool(s.autoApplyScheduled),
            "dnsPresetIndex" to JsonVal.num(s.dnsPresetIndex),
            "customDns" to JsonVal.str(s.customDns),
            "mtu" to JsonVal.num(s.mtu),
            "keepalive" to JsonVal.num(s.keepalive),
            "enableIpv6" to JsonVal.bool(s.enableIpv6),
            "routeMode" to JsonVal.str(s.routeMode.name),
            "selectedBlockListIds" to JsonVal.arr(s.selectedBlockListIds.map { JsonVal.str(it) }),
            "selectedDirectListIds" to JsonVal.arr(s.selectedDirectListIds.map { JsonVal.str(it) }),
            "builtAllowedIps" to JsonVal.str(s.builtAllowedIps),
            "manualAllowedIps" to JsonVal.str(s.manualAllowedIps),
            "secondExitEnabled" to JsonVal.bool(s.secondExitEnabled),
            "secondExitConf" to JsonVal.str(s.secondExitConf),
            "secondExitListIds" to JsonVal.arr(s.secondExitListIds.map { JsonVal.str(it) }),
            "secondExitViaWarp" to JsonVal.bool(s.secondExitViaWarp),
            "secondExitDomains" to JsonVal.str(s.secondExitDomains),
            "secondExitCidrs" to JsonVal.str(s.secondExitCidrs),
            "byeDpiPresetId" to JsonVal.str(s.byeDpiPresetId),
            "byeDpiPort" to JsonVal.num(s.byeDpiPort),
            "byeDpiCustomArgs" to JsonVal.str(s.byeDpiCustomArgs),
            "byeDpiSystemProxy" to JsonVal.bool(s.byeDpiSystemProxy),
            "byeDpiBypassTunnel" to JsonVal.bool(s.byeDpiBypassTunnel),
            "byeDpiPacDomains" to JsonVal.str(s.byeDpiPacDomains),
            "telegramExePath" to JsonVal.str(s.telegramExePath),
            "byeDpiNetworkProfiles" to JsonVal.arr(
                s.byeDpiNetworkProfiles.values.map { p ->
                    JsonVal.obj(
                        "networkKey" to JsonVal.str(p.networkKey),
                        "networkLabel" to JsonVal.str(p.networkLabel),
                        "presetId" to JsonVal.str(p.presetId),
                        "customArgs" to JsonVal.str(p.customArgs),
                        "fixedCount" to JsonVal.num(p.fixedCount),
                        "totalChecks" to JsonVal.num(p.totalChecks),
                        "testedAtMs" to JsonVal.num(p.testedAtMs)
                    )
                }
            ),
            "exportTarget" to JsonVal.str(s.exportTarget.name),
            "activeShortlistIndex" to JsonVal.num(s.activeShortlistIndex),
            "lastTuneAtMs" to JsonVal.num(s.lastTuneAtMs),
            "lastTuneDurationSec" to JsonVal.num(s.lastTuneDurationSec),
            "lastTuneEndpoint" to JsonVal.str(s.lastTuneEndpoint),
            "lastTuneJunk" to JsonVal.str(s.lastTuneJunk),
            "lastTuneSummary" to JsonVal.str(s.lastTuneSummary),
            "lastAccountSource" to JsonVal.str(s.lastAccountSource)
        )

        fun settingsFromJson(o: JsonVal.Obj): DesktopSettings {
            val d = DesktopSettings()
            fun strList(key: String, fallback: List<String>): List<String> =
                o.arr(key)?.items?.mapNotNull { (it as? JsonVal.Str)?.v } ?: fallback
            return DesktopSettings(
                theme = o.str("theme")?.let { runCatching { ThemeMode.valueOf(it) }.getOrNull() } ?: d.theme,
                minimizeToTrayOnClose = o.bool("minimizeToTrayOnClose") ?: d.minimizeToTrayOnClose,
                autostartWindows = o.bool("autostartWindows") ?: d.autostartWindows,
                autoConnectOnStart = o.bool("autoConnectOnStart") ?: d.autoConnectOnStart,
                disconnectOnExit = o.bool("disconnectOnExit") ?: d.disconnectOnExit,
                autoCheckUpdates = o.bool("autoCheckUpdates") ?: d.autoCheckUpdates,
                includePrereleaseUpdates = o.bool("includePrereleaseUpdates") ?: d.includePrereleaseUpdates,
                backendMode = o.str("backendMode")?.let { runCatching { TunnelBackendMode.valueOf(it) }.getOrNull() } ?: d.backendMode,
                customEnginePath = o.str("customEnginePath") ?: d.customEnginePath,
                autoElevateUac = o.bool("autoElevateUac") ?: d.autoElevateUac,
                poolMode = o.str("poolMode")?.let { runCatching { DesktopPoolMode.valueOf(it) }.getOrNull() } ?: d.poolMode,
                customHostsText = o.str("customHostsText") ?: d.customHostsText,
                customPortsText = o.str("customPortsText") ?: d.customPortsText,
                endpointCount = o.num("endpointCount")?.toInt()?.coerceIn(20, 4000) ?: d.endpointCount,
                sniCount = o.num("sniCount")?.toInt()?.coerceIn(1, 10) ?: d.sniCount,
                includeNoneJunk = o.bool("includeNoneJunk") ?: d.includeNoneJunk,
                includeTlsJunk = o.bool("includeTlsJunk") ?: d.includeTlsJunk,
                includeQuicJunk = o.bool("includeQuicJunk") ?: d.includeQuicJunk,
                includeSipJunk = o.bool("includeSipJunk") ?: d.includeSipJunk,
                checkResources = o.bool("checkResources") ?: d.checkResources,
                verifyThroughTunnel = o.bool("verifyThroughTunnel") ?: d.verifyThroughTunnel,
                autoScheduleHours = o.num("autoScheduleHours")?.toInt()?.coerceIn(0, 168) ?: d.autoScheduleHours,
                autoApplyScheduled = o.bool("autoApplyScheduled") ?: d.autoApplyScheduled,
                dnsPresetIndex = o.num("dnsPresetIndex")?.toInt()?.coerceAtLeast(0) ?: d.dnsPresetIndex,
                customDns = o.str("customDns") ?: d.customDns,
                mtu = o.num("mtu")?.toInt()?.coerceIn(1000, 1500) ?: d.mtu,
                keepalive = o.num("keepalive")?.toInt()?.coerceIn(0, 120) ?: d.keepalive,
                enableIpv6 = o.bool("enableIpv6") ?: d.enableIpv6,
                routeMode = o.str("routeMode")?.let { runCatching { RouteMode.valueOf(it) }.getOrNull() } ?: d.routeMode,
                selectedBlockListIds = strList("selectedBlockListIds", AllowLists.DEFAULT_BLOCK_IDS),
                selectedDirectListIds = strList("selectedDirectListIds", d.selectedDirectListIds),
                builtAllowedIps = o.str("builtAllowedIps") ?: d.builtAllowedIps,
                manualAllowedIps = o.str("manualAllowedIps") ?: d.manualAllowedIps,
                secondExitEnabled = o.bool("secondExitEnabled") ?: d.secondExitEnabled,
                secondExitConf = o.str("secondExitConf") ?: d.secondExitConf,
                secondExitListIds = strList("secondExitListIds", d.secondExitListIds),
                secondExitViaWarp = o.bool("secondExitViaWarp") ?: d.secondExitViaWarp,
                secondExitDomains = o.str("secondExitDomains") ?: d.secondExitDomains,
                secondExitCidrs = o.str("secondExitCidrs") ?: d.secondExitCidrs,
                byeDpiPresetId = o.str("byeDpiPresetId")?.let { ByeDpiPresets.normalizeId(it) } ?: d.byeDpiPresetId,
                byeDpiPort = o.num("byeDpiPort")?.toInt()?.coerceIn(1024, 65535) ?: d.byeDpiPort,
                byeDpiCustomArgs = o.str("byeDpiCustomArgs") ?: d.byeDpiCustomArgs,
                byeDpiSystemProxy = o.bool("byeDpiSystemProxy") ?: d.byeDpiSystemProxy,
                byeDpiBypassTunnel = o.bool("byeDpiBypassTunnel") ?: d.byeDpiBypassTunnel,
                byeDpiPacDomains = o.str("byeDpiPacDomains")?.takeIf { it.isNotBlank() } ?: d.byeDpiPacDomains,
                telegramExePath = o.str("telegramExePath") ?: d.telegramExePath,
                byeDpiNetworkProfiles = o.arr("byeDpiNetworkProfiles")?.items?.mapNotNull { item ->
                    val po = item as? JsonVal.Obj ?: return@mapNotNull null
                    val key = po.str("networkKey")?.takeIf { it.isNotBlank() } ?: return@mapNotNull null
                    val preset = po.str("presetId")?.let { ByeDpiPresets.normalizeId(it) } ?: return@mapNotNull null
                    key to NetworkDpiProfile(
                        networkKey = key,
                        networkLabel = po.str("networkLabel") ?: key,
                        presetId = preset,
                        customArgs = po.str("customArgs") ?: "",
                        fixedCount = po.num("fixedCount")?.toInt() ?: 0,
                        totalChecks = po.num("totalChecks")?.toInt() ?: 0,
                        testedAtMs = po.num("testedAtMs")?.toLong() ?: 0L
                    )
                }?.toMap() ?: d.byeDpiNetworkProfiles,
                exportTarget = o.str("exportTarget")?.let { runCatching { ConfTarget.valueOf(it) }.getOrNull() } ?: d.exportTarget,
                activeShortlistIndex = o.num("activeShortlistIndex")?.toInt()?.coerceAtLeast(0) ?: d.activeShortlistIndex,
                lastTuneAtMs = o.num("lastTuneAtMs")?.toLong() ?: d.lastTuneAtMs,
                lastTuneDurationSec = o.num("lastTuneDurationSec")?.toInt() ?: d.lastTuneDurationSec,
                lastTuneEndpoint = o.str("lastTuneEndpoint") ?: d.lastTuneEndpoint,
                lastTuneJunk = o.str("lastTuneJunk") ?: d.lastTuneJunk,
                lastTuneSummary = o.str("lastTuneSummary") ?: d.lastTuneSummary,
                lastAccountSource = o.str("lastAccountSource") ?: d.lastAccountSource
            )
        }

        fun shortlistToJson(items: List<ShortlistEntry>): JsonVal.Arr = JsonVal.arr(
            items.map { e ->
                JsonVal.obj(
                    "endpoint" to JsonVal.str(e.endpoint),
                    "junkName" to JsonVal.str(e.junkName),
                    "score" to JsonVal.num(e.score),
                    "resourcesOk" to JsonVal.num(e.resourcesOk),
                    "resourcesTotal" to JsonVal.num(e.resourcesTotal),
                    "checkedAtMs" to JsonVal.num(e.checkedAtMs),
                    "confText" to JsonVal.str(e.confText)
                )
            }
        )

        fun shortlistFromJson(arr: JsonVal.Arr): List<ShortlistEntry> = arr.items.mapNotNull { item ->
            val o = item as? JsonVal.Obj ?: return@mapNotNull null
            val ep = o.str("endpoint") ?: return@mapNotNull null
            val conf = o.str("confText")?.takeIf { it.isNotBlank() } ?: return@mapNotNull null
            ShortlistEntry(
                endpoint = ep,
                junkName = o.str("junkName") ?: "none",
                score = o.num("score")?.toInt() ?: 0,
                resourcesOk = o.num("resourcesOk")?.toInt() ?: -1,
                resourcesTotal = o.num("resourcesTotal")?.toInt() ?: 0,
                checkedAtMs = o.num("checkedAtMs")?.toLong() ?: 0L,
                confText = conf
            )
        }
    }
}
