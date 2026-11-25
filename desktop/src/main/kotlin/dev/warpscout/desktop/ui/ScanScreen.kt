package dev.warpscout.desktop.ui

import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import dev.warpscout.core.dpi.DpiOutcome
import dev.warpscout.core.net.DnsVerdict
import dev.warpscout.desktop.engine.DesktopController
import dev.warpscout.desktop.engine.DesktopUiState
import dev.warpscout.desktop.engine.Formatters
import dev.warpscout.desktop.storage.DesktopPoolMode
import dev.warpscout.desktop.tunnel.ByeDpiPresets

/**
 * Вкладка «Подбор»: настройка пула точек и профилей шума AWG, запуск автоподбора,
 * проверка реальной доступности сайтов, сверка DNS с DoH и замер скорости.
 */
@Composable
fun ScanScreen(state: DesktopUiState, controller: DesktopController) {
    val warp = LocalWarpColors.current
    val s = state.settings

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 16.dp, vertical = 12.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        // --- 1. Параметры подбора ---
        WarpCard {
            SectionHeader(
                title = "Подбор точки входа Cloudflare WARP",
                subtitle = "Настоящий WireGuard/AWG handshake, сравнение профилей шума и проверка сайтов изнутри."
            )

            // Выбор режима пула
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(6.dp)
            ) {
                DesktopPoolMode.entries.forEach { mode ->
                    FilterChip(
                        selected = s.poolMode == mode,
                        onClick = { controller.updateSettings { it.copy(poolMode = mode) } },
                        label = {
                            Text(
                                when (mode) {
                                    DesktopPoolMode.DEFAULT -> "Пул"
                                    DesktopPoolMode.MASQUE -> "MASQUE"
                                    DesktopPoolMode.FULL -> "Полный"
                                    DesktopPoolMode.CUSTOM -> "Свой"
                                },
                                style = MaterialTheme.typography.labelSmall
                            )
                        },
                        modifier = Modifier.weight(1f)
                    )
                }
            }

            if (s.poolMode == DesktopPoolMode.CUSTOM) {
                OutlinedTextField(
                    value = s.customHostsText,
                    onValueChange = { v -> controller.updateSettings { it.copy(customHostsText = v) } },
                    label = { Text("Свои точки (по строке)") },
                    placeholder = { Text("162.159.192.*:2408\n188.114.96.1-10:943") },
                    modifier = Modifier.fillMaxWidth(),
                    minLines = 3,
                    maxLines = 5,
                    textStyle = MaterialTheme.typography.bodySmall
                )
            } else {
                Column {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        Text("Точек для скана", style = MaterialTheme.typography.bodySmall)
                        Text("${s.endpointCount}", style = MaterialTheme.typography.labelMedium, fontWeight = FontWeight.SemiBold)
                    }
                    Slider(
                        value = s.endpointCount.toFloat(),
                        onValueChange = { v -> controller.updateSettings { it.copy(endpointCount = (v.toInt() / 20) * 20) } },
                        valueRange = 40f..1000f,
                        steps = 23
                    )
                }
            }

            OutlinedTextField(
                value = s.customPortsText,
                onValueChange = { v -> controller.updateSettings { it.copy(customPortsText = v) } },
                label = { Text("Порты (пусто — все порты WARP)") },
                placeholder = { Text("например: 500, 943, 2408, 4500") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
                textStyle = MaterialTheme.typography.bodySmall
            )

            HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.4f))

            Text("Профили шума (AmneziaWG)", style = MaterialTheme.typography.labelMedium, fontWeight = FontWeight.SemiBold)
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(6.dp)
            ) {
                FilterChip(
                    selected = s.includeNoneJunk,
                    onClick = { controller.updateSettings { it.copy(includeNoneJunk = !it.includeNoneJunk) } },
                    label = { Text("WG", style = MaterialTheme.typography.labelSmall) }
                )
                FilterChip(
                    selected = s.includeTlsJunk,
                    onClick = { controller.updateSettings { it.copy(includeTlsJunk = !it.includeTlsJunk) } },
                    label = { Text("TLS", style = MaterialTheme.typography.labelSmall) }
                )
                FilterChip(
                    selected = s.includeQuicJunk,
                    onClick = { controller.updateSettings { it.copy(includeQuicJunk = !it.includeQuicJunk) } },
                    label = { Text("QUIC×${s.sniCount}", style = MaterialTheme.typography.labelSmall) }
                )
                FilterChip(
                    selected = s.includeSipJunk,
                    onClick = { controller.updateSettings { it.copy(includeSipJunk = !it.includeSipJunk) } },
                    label = { Text("SIP", style = MaterialTheme.typography.labelSmall) }
                )
            }

            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text("Проверять сайты", style = MaterialTheme.typography.bodySmall, fontWeight = FontWeight.Medium)
                    Text("YouTube, ChatGPT, Discord, Telegram, X…", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
                Switch(
                    checked = s.checkResources,
                    onCheckedChange = { v -> controller.updateSettings { it.copy(checkResources = v) } }
                )
            }

            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text("Проверять топ-3 изнутри туннеля", style = MaterialTheme.typography.bodySmall, fontWeight = FontWeight.Medium)
                    Text("Поднимает туннель на время теста и выбирает точку по реально открытым сайтам", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
                Switch(
                    checked = s.verifyThroughTunnel,
                    enabled = state.tunnelBackendReady,
                    onCheckedChange = { v -> controller.updateSettings { it.copy(verifyThroughTunnel = v) } }
                )
            }

            if (state.scanning) {
                val progressText = if (state.scanTotal > 0) "${state.scanDone}/${state.scanTotal} · ${state.scanStep}" else state.scanStep
                Text(progressText, style = MaterialTheme.typography.labelSmall, color = warp.accentOrange)
                if (state.scanTotal > 0) {
                    LinearProgressIndicator(
                        progress = { (state.scanDone.toFloat() / state.scanTotal.toFloat()).coerceIn(0f, 1f) },
                        modifier = Modifier.fillMaxWidth().height(5.dp).clip(RoundedCornerShape(3.dp)),
                        color = warp.accentOrange
                    )
                } else {
                    LinearProgressIndicator(
                        modifier = Modifier.fillMaxWidth().height(5.dp).clip(RoundedCornerShape(3.dp)),
                        color = warp.accentOrange
                    )
                }
                Button(
                    onClick = { controller.cancelScan() },
                    modifier = Modifier.fillMaxWidth(),
                    colors = ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.errorContainer, contentColor = MaterialTheme.colorScheme.onErrorContainer)
                ) {
                    Icon(Icons.Rounded.Stop, contentDescription = null, modifier = Modifier.size(18.dp))
                    Spacer(Modifier.width(6.dp))
                    Text("Остановить подбор")
                }
            } else {
                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Button(
                        onClick = { controller.runScan(autoConnectAfter = true) },
                        modifier = Modifier.weight(1f),
                        colors = ButtonDefaults.buttonColors(containerColor = warp.accentOrange, contentColor = Color.White)
                    ) {
                        Icon(Icons.Rounded.Radar, contentDescription = null, modifier = Modifier.size(18.dp))
                        Spacer(Modifier.width(6.dp))
                        Text("Подобрать и подключить", style = MaterialTheme.typography.labelMedium)
                    }
                    OutlinedButton(
                        onClick = { controller.runScan(autoConnectAfter = true, forceFullScan = true) },
                        contentPadding = PaddingValues(horizontal = 10.dp, vertical = 10.dp)
                    ) {
                        Text("Полный скан", style = MaterialTheme.typography.labelMedium)
                    }
                }
            }

            if (s.lastTuneAtMs > 0L) {
                Text(
                    "Последний подбор: ${Formatters.dateTimeOf(s.lastTuneAtMs)} (${Formatters.duration(s.lastTuneDurationSec.toLong())}) · ${s.lastTuneSummary}",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }

        // --- 2. Проверка сайтов, DNS и скорости ---
        WarpCard {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                SectionHeader(
                    title = "Что реально открывается",
                    subtitle = if (state.tunnel.isUp) "Проверка из-под активного туннеля" else "Проверка по текущей сети"
                )
            }

            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                FilledTonalButton(
                    onClick = { controller.runSiteAndDnsCheck() },
                    enabled = !state.checkingResources,
                    modifier = Modifier.weight(1f)
                ) {
                    if (state.checkingResources) {
                        CircularProgressIndicator(modifier = Modifier.size(15.dp), strokeWidth = 2.dp)
                    } else {
                        Icon(Icons.Rounded.FactCheck, contentDescription = null, modifier = Modifier.size(16.dp))
                    }
                    Spacer(Modifier.width(6.dp))
                    Text(if (state.checkingResources) "Проверяю…" else "Проверить сайты и DNS", style = MaterialTheme.typography.labelMedium)
                }
                OutlinedButton(
                    onClick = { controller.runSpeedTest() },
                    enabled = !state.speedTesting
                ) {
                    if (state.speedTesting) {
                        CircularProgressIndicator(modifier = Modifier.size(15.dp), strokeWidth = 2.dp)
                    } else {
                        Icon(Icons.Rounded.Speed, contentDescription = null, modifier = Modifier.size(16.dp))
                    }
                    Spacer(Modifier.width(5.dp))
                    Text("Скорость", style = MaterialTheme.typography.labelMedium)
                }
            }

            // Результат замера скорости
            state.speedResult?.let { sp ->
                Surface(
                    shape = RoundedCornerShape(10.dp),
                    color = (if (sp.ok) warp.ok else warp.error).copy(alpha = 0.12f),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Row(
                        modifier = Modifier.padding(10.dp),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(
                            if (sp.ok) String.format("Скорость загрузки: %.1f Мбит/с", sp.downloadMbps)
                            else "Ошибка замера: ${sp.error}",
                            style = MaterialTheme.typography.bodySmall,
                            fontWeight = FontWeight.SemiBold,
                            color = if (sp.ok) warp.ok else warp.error
                        )
                        if (sp.latencyMs > 0L) {
                            Text("${sp.latencyMs} мс", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                        }
                    }
                }
            }

            // Результаты DNS-инспектора
            if (state.dnsChecks.isNotEmpty()) {
                val poisoned = state.dnsChecks.filter { it.suspicious }
                Surface(
                    shape = RoundedCornerShape(10.dp),
                    color = (if (poisoned.isEmpty()) warp.ok else warp.error).copy(alpha = 0.12f),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Column(modifier = Modifier.padding(10.dp), verticalArrangement = Arrangement.spacedBy(3.dp)) {
                        Text(
                            if (poisoned.isEmpty()) "DNS: подмены не обнаружено (системный совпадает с Cloudflare/Google DoH)"
                            else "Обнаружена подмена DNS (${poisoned.joinToString(", ") { it.domain }})!",
                            style = MaterialTheme.typography.labelMedium,
                            fontWeight = FontWeight.SemiBold,
                            color = if (poisoned.isEmpty()) warp.ok else warp.error
                        )
                        if (poisoned.isNotEmpty()) {
                            Text(
                                "Убедитесь, что в Настройках указан DNS 1.1.1.1 / 8.8.8.8 и туннель включён.",
                                style = MaterialTheme.typography.labelSmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                    }
                }
            }

            // Список сайтов
            if (state.resourceResults.isNotEmpty()) {
                val okCount = state.resourceResults.count { it.ok }
                Text(
                    "Итог: открылось $okCount из ${state.resourceResults.size}",
                    style = MaterialTheme.typography.labelMedium,
                    fontWeight = FontWeight.SemiBold
                )
                state.resourceResults.forEach { r ->
                    Row(
                        modifier = Modifier.fillMaxWidth().padding(vertical = 2.dp),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(7.dp),
                            modifier = Modifier.weight(1f)
                        ) {
                            Icon(
                                imageVector = if (r.ok) Icons.Rounded.CheckCircle else Icons.Rounded.Cancel,
                                contentDescription = null,
                                tint = if (r.ok) warp.ok else warp.error,
                                modifier = Modifier.size(16.dp)
                            )
                            Text(r.check.name, style = MaterialTheme.typography.bodySmall)
                        }
                        val detail = if (r.ok) "${r.status ?: "OK"} · ${r.elapsedMs} мс"
                        else (r.errorClass ?: r.status?.let { "HTTP $it" } ?: "ошибка")
                        Text(
                            detail,
                            style = MaterialTheme.typography.labelSmall,
                            color = if (r.ok) MaterialTheme.colorScheme.onSurfaceVariant else warp.error
                        )
                    }
                }
            } else if (!state.checkingResources) {
                Text(
                    "Нажмите «Проверить сайты и DNS», чтобы увидеть, что реально открывается прямо сейчас.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }

        // --- 3. Встроенный обход DPI (ByeDPI / ciadpi.exe) + сравнение напрямую vs ByeDPI ---
        val dpi = state.byeDpi
        val clipboard = LocalClipboardManager.current
        WarpCard {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                SectionHeader(
                    title = "Обход DPI (ByeDPI)",
                    subtitle = if (dpi.running)
                        "SOCKS5 ${dpi.socksAddress} · ${dpi.presetTitle}"
                    else if (dpi.available)
                        "Встроенный ciadpi.exe (без драйверов) — помощь, если WARP уходит в DME"
                    else
                        "ciadpi.exe не найден в каталоге bin/"
                )
            }

            // Выбор стратегии
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .horizontalScroll(rememberScrollState()),
                horizontalArrangement = Arrangement.spacedBy(6.dp)
            ) {
                ByeDpiPresets.BUILTIN.forEach { preset ->
                    FilterChip(
                        selected = s.byeDpiPresetId == preset.id,
                        onClick = {
                            controller.updateSettings { it.copy(byeDpiPresetId = preset.id) }
                            if (dpi.running) controller.startByeDpi()
                        },
                        label = { Text(preset.title, style = MaterialTheme.typography.labelSmall) }
                    )
                }
            }

            Text(
                ByeDpiPresets.byId(s.byeDpiPresetId).subtitle,
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )

            if (s.byeDpiPresetId == ByeDpiPresets.CUSTOM_ID) {
                OutlinedTextField(
                    value = s.byeDpiCustomArgs,
                    onValueChange = { v -> controller.updateSettings { it.copy(byeDpiCustomArgs = v) } },
                    label = { Text("Флаги ciadpi.exe") },
                    placeholder = { Text("--disorder 1 --tlsrec 1+s --udp-fake 1") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                    textStyle = MaterialTheme.typography.bodySmall
                )
            }

            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text("Системный прокси Windows", style = MaterialTheme.typography.bodySmall, fontWeight = FontWeight.Medium)
                    Text("Браузеры через ByeDPI, сайты .ru и LAN — напрямую (при выходе сбрасывается)", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
                Switch(
                    checked = s.byeDpiSystemProxy,
                    onCheckedChange = { v -> controller.setByeDpiSystemProxy(v) }
                )
            }

            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(
                    onClick = { controller.toggleByeDpi() },
                    enabled = dpi.available || dpi.running,
                    modifier = Modifier.weight(1f),
                    colors = if (dpi.running) {
                        ButtonDefaults.buttonColors(
                            containerColor = MaterialTheme.colorScheme.errorContainer,
                            contentColor = MaterialTheme.colorScheme.onErrorContainer
                        )
                    } else {
                        ButtonDefaults.buttonColors(containerColor = warp.accentOrange, contentColor = Color.White)
                    }
                ) {
                    Icon(
                        imageVector = if (dpi.running) Icons.Rounded.Stop else Icons.Rounded.Shield,
                        contentDescription = null,
                        modifier = Modifier.size(17.dp)
                    )
                    Spacer(Modifier.width(6.dp))
                    Text(if (dpi.running) "Остановить ByeDPI" else "Запустить ByeDPI", style = MaterialTheme.typography.labelMedium)
                }
                OutlinedButton(
                    onClick = {
                        clipboard.setText(AnnotatedString("127.0.0.1:${s.byeDpiPort}"))
                        controller.showBanner("SOCKS5 127.0.0.1:${s.byeDpiPort} скопирован (для Telegram / браузера)")
                    },
                    contentPadding = PaddingValues(horizontal = 10.dp, vertical = 10.dp)
                ) {
                    Icon(Icons.Rounded.ContentCopy, contentDescription = null, modifier = Modifier.size(15.dp))
                    Spacer(Modifier.width(4.dp))
                    Text(":${s.byeDpiPort}", style = MaterialTheme.typography.labelSmall)
                }
            }

            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                FilledTonalButton(
                    onClick = { controller.runByeDpiAutoTune() },
                    enabled = !state.dpiBusy && dpi.available,
                    modifier = Modifier.weight(1f)
                ) {
                    if (state.dpiBusy) {
                        CircularProgressIndicator(modifier = Modifier.size(14.dp), strokeWidth = 2.dp)
                        Spacer(Modifier.width(6.dp))
                    }
                    Text("Подобрать стратегию", style = MaterialTheme.typography.labelSmall)
                }
                OutlinedButton(
                    onClick = { controller.runDpiCompare() },
                    enabled = !state.dpiBusy && dpi.available,
                    modifier = Modifier.weight(1f)
                ) {
                    Text("Напрямую vs ByeDPI", style = MaterialTheme.typography.labelSmall)
                }
            }

            if (state.dpiStatus.isNotBlank()) {
                Text(
                    state.dpiStatus,
                    style = MaterialTheme.typography.labelSmall,
                    color = warp.accentOrange
                )
            }

            state.dpiComparison?.let { cmp ->
                Surface(
                    shape = RoundedCornerShape(10.dp),
                    color = warp.surfaceHigh.copy(alpha = 0.7f),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Column(modifier = Modifier.padding(10.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                        Text(
                            cmp.headline(),
                            style = MaterialTheme.typography.labelMedium,
                            fontWeight = FontWeight.SemiBold
                        )
                        cmp.rows.forEach { row ->
                            val (tag, color) = when (row.outcome) {
                                DpiOutcome.OPEN_BOTH -> "OK" to warp.ok
                                DpiOutcome.OPEN_ONLY_VIA_PROXY -> "DPI ✓" to warp.ok
                                DpiOutcome.BLOCKED_BOTH -> "нужен WARP" to warp.error
                                DpiOutcome.OPEN_ONLY_DIRECT -> "прокси мешает" to warp.warn
                                DpiOutcome.PROXY_UNREACHABLE -> "нет прокси" to warp.error
                            }
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween
                            ) {
                                Text(row.name, style = MaterialTheme.typography.labelSmall)
                                Text(tag, style = MaterialTheme.typography.labelSmall, fontWeight = FontWeight.SemiBold, color = color)
                            }
                        }
                    }
                }
            }
        }
    }
}
