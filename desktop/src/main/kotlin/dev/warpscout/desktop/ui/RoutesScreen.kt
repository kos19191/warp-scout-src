package dev.warpscout.desktop.ui

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
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import dev.warpscout.core.config.SplitRoutes
import dev.warpscout.core.lists.AllowLists
import dev.warpscout.core.lists.ListSide
import dev.warpscout.desktop.engine.DesktopController
import dev.warpscout.desktop.engine.DesktopUiState
import dev.warpscout.desktop.storage.RouteMode
import dev.warpscout.desktop.tunnel.ProtonVpnHelper
import dev.warpscout.desktop.tunnel.SecondExitPreset

/**
 * Вкладка «Маршруты»: раздельное туннелирование (Весь трафик / Пресет обхода РФ / Списки allow-domains /
 * Вручную CIDR), быстрое добавление ProtonVPN (WireGuard) и «Второй выход» (свой сервер для выбранных доменов).
 */
@OptIn(ExperimentalLayoutApi::class)
@Composable
fun RoutesScreen(state: DesktopUiState, controller: DesktopController) {
    val warp = LocalWarpColors.current
    val s = state.settings
    val clipboard = LocalClipboardManager.current

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 16.dp, vertical = 12.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        // --- 1. Что туннелировать (AllowedIPs) ---
        WarpCard {
            SectionHeader(
                title = "Что туннелировать (AllowedIPs)",
                subtitle = "WireGuard/AmneziaWG маршрутизирует по IP/CIDR. Домены из списков разворачиваются в /32 и /128 через DoH."
            )

            RouteMode.entries.forEach { mode ->
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    RadioButton(
                        selected = s.routeMode == mode,
                        onClick = { controller.updateSettings { it.copy(routeMode = mode) } }
                    )
                    Column(modifier = Modifier.weight(1f)) {
                        Text(mode.title, style = MaterialTheme.typography.bodyMedium, fontWeight = FontWeight.Medium)
                        Text(mode.subtitle, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                }
            }

            if (s.routeMode == RouteMode.PRESET) {
                Text(
                    "Компактный пресет обхода РФ (~900 маршрутов, без нагрузки на службы Windows): Яндекс, VK, банки (Сбер, Т-Банк, Альфа, ВТБ), Госуслуги, Ozon, Wildberries, Авито, российские облака/провайдеры и локальная сеть идут напрямую. Всё зарубежное — через туннель.",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }

            if (s.routeMode == RouteMode.LISTS) {
                HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.4f))
                Text("Туннелируем (allow-domains):", style = MaterialTheme.typography.labelMedium, fontWeight = FontWeight.SemiBold)

                val blockLists = AllowLists.bySide(ListSide.BLOCK)
                Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
                    blockLists.chunked(2).forEach { rowItems ->
                        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                            rowItems.forEach { list ->
                                val selected = list.id in s.selectedBlockListIds
                                FilterChip(
                                    selected = selected,
                                    onClick = {
                                        controller.updateSettings { cur ->
                                            val next = if (selected) cur.selectedBlockListIds - list.id else cur.selectedBlockListIds + list.id
                                            cur.copy(selectedBlockListIds = next)
                                        }
                                    },
                                    label = { Text(list.title, style = MaterialTheme.typography.labelSmall, maxLines = 1) },
                                    modifier = Modifier.weight(1f)
                                )
                            }
                            if (rowItems.size == 1) Spacer(Modifier.weight(1f))
                        }
                    }
                }

                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedButton(
                        onClick = { controller.refreshAllowLists() },
                        enabled = !state.listsBusy,
                        modifier = Modifier.weight(1f)
                    ) {
                        Icon(Icons.Rounded.CloudDownload, contentDescription = null, modifier = Modifier.size(16.dp))
                        Spacer(Modifier.width(5.dp))
                        Text("Скачать списки", style = MaterialTheme.typography.labelMedium)
                    }
                    FilledTonalButton(
                        onClick = { controller.buildAllowListRoutes() },
                        enabled = !state.listsBusy,
                        modifier = Modifier.weight(1f)
                    ) {
                        Icon(Icons.Rounded.Build, contentDescription = null, modifier = Modifier.size(16.dp))
                        Spacer(Modifier.width(5.dp))
                        Text("Собрать маршруты", style = MaterialTheme.typography.labelMedium)
                    }
                }

                if (state.listsStatus.isNotBlank()) {
                    Text(state.listsStatus, style = MaterialTheme.typography.labelSmall, color = warp.accentOrange)
                }
                val builtCount = SplitRoutes.prefixesOf(s.builtAllowedIps).size
                Text(
                    if (builtCount > 0) "Собрано маршрутов в конфиге: $builtCount"
                    else "Маршруты ещё не собраны (сейчас используется весь трафик)",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }

            if (s.routeMode == RouteMode.MANUAL) {
                OutlinedTextField(
                    value = s.manualAllowedIps,
                    onValueChange = { v -> controller.updateSettings { it.copy(manualAllowedIps = v) } },
                    label = { Text("AllowedIPs (CIDR через запятую)") },
                    placeholder = { Text("0.0.0.0/0, ::/0") },
                    modifier = Modifier.fillMaxWidth(),
                    minLines = 2,
                    maxLines = 4,
                    textStyle = MaterialTheme.typography.bodySmall
                )
            }

            Button(
                onClick = { controller.applySettingsAndReconnect() },
                modifier = Modifier.fillMaxWidth(),
                colors = ButtonDefaults.buttonColors(containerColor = warp.accentOrange, contentColor = Color.White)
            ) {
                Icon(Icons.Rounded.Check, contentDescription = null, modifier = Modifier.size(18.dp))
                Spacer(Modifier.width(6.dp))
                Text("Сохранить и применить маршруты")
            }
        }

        // --- 2. Быстрое добавление ProtonVPN (WireGuard .conf) ---
        WarpCard {
            SectionHeader(
                title = "ProtonVPN (WireGuard)",
                subtitle = "Бесплатные и платные .conf из кабинета ProtonVPN — можно подключить как основной туннель или как 2-й выход поверх WARP (с обходом РФ)."
            )

            Text(
                "1. Откройте кабинет ProtonVPN → Downloads → WireGuard → выберите Free-сервер (NL/RO/PL/JP/US) и нажмите Create → Download.\n" +
                    "2. Загрузите скачанный файл .conf ниже — WilyScout сам подхватит сервер, ключи и 1:1 NAT для адреса 10.2.0.2.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )

            OutlinedButton(
                onClick = { DesktopPlatform.openUrl(ProtonVpnHelper.PROTON_WG_DOWNLOADS_URL) },
                modifier = Modifier.fillMaxWidth()
            ) {
                Icon(Icons.Rounded.OpenInNew, contentDescription = null, modifier = Modifier.size(16.dp))
                Spacer(Modifier.width(6.dp))
                Text("Открыть страницу WireGuard-конфигов ProtonVPN", style = MaterialTheme.typography.labelMedium)
            }

            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(
                    onClick = {
                        val file = DesktopPlatform.chooseOpenFile("Выберите файл ProtonVPN (.conf)")
                        if (file != null && file.isFile) {
                            runCatching { file.readText(Charsets.UTF_8) }
                                .onSuccess { controller.importSecondExitConf(it, preset = SecondExitPreset.TELEGRAM, applyNow = true) }
                                .onFailure { controller.showBanner("Не удалось прочитать файл: ${it.message}", isError = true) }
                        }
                    },
                    modifier = Modifier.weight(1f),
                    colors = ButtonDefaults.buttonColors(containerColor = warp.accentOrange, contentColor = Color.White)
                ) {
                    Icon(Icons.Rounded.FileOpen, contentDescription = null, modifier = Modifier.size(16.dp))
                    Spacer(Modifier.width(5.dp))
                    Text("Как 2-й выход", style = MaterialTheme.typography.labelMedium)
                }

                FilledTonalButton(
                    onClick = {
                        val file = DesktopPlatform.chooseOpenFile("Выберите файл ProtonVPN (.conf)")
                        if (file != null && file.isFile) {
                            runCatching { file.readText(Charsets.UTF_8) }
                                .onSuccess { controller.importConfigText(it, connectNow = true) }
                                .onFailure { controller.showBanner("Не удалось прочитать файл: ${it.message}", isError = true) }
                        }
                    },
                    modifier = Modifier.weight(1f)
                ) {
                    Icon(Icons.Rounded.VpnKey, contentDescription = null, modifier = Modifier.size(16.dp))
                    Spacer(Modifier.width(5.dp))
                    Text("Вместо WARP", style = MaterialTheme.typography.labelMedium)
                }
            }
        }

        // --- 3. Второй выход (свой сервер в нужной стране / ProtonVPN) ---
        val parsedSecond = remember(s.secondExitConf) {
            if (s.secondExitConf.isBlank()) null else ProtonVpnHelper.inspectConf(s.secondExitConf)
        }
        WarpCard {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text("Второй выход (свой регион / ProtonVPN)", style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.SemiBold)
                    Text(
                        "Отдельные сайты (Telegram, ChatGPT…) идут через ваш WireGuard/ProtonVPN, всё остальное — через WARP.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
                Switch(
                    checked = s.secondExitEnabled,
                    onCheckedChange = { v -> controller.updateSettings { it.copy(secondExitEnabled = v) } }
                )
            }

            if (s.secondExitEnabled) {
                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedButton(
                        onClick = {
                            val file = DesktopPlatform.chooseOpenFile("Выберите .conf второго выхода")
                            if (file != null && file.isFile) {
                                runCatching { file.readText(Charsets.UTF_8) }
                                    .onSuccess { controller.importSecondExitConf(it) }
                                    .onFailure { controller.showBanner("Не удалось прочитать файл: ${it.message}", isError = true) }
                            }
                        },
                        modifier = Modifier.weight(1f)
                    ) {
                        Icon(Icons.Rounded.FileOpen, contentDescription = null, modifier = Modifier.size(15.dp))
                        Spacer(Modifier.width(5.dp))
                        Text("Загрузить .conf", style = MaterialTheme.typography.labelSmall)
                    }
                    OutlinedButton(
                        onClick = {
                            val txt = clipboard.getText()?.text.orEmpty()
                            if (txt.isBlank()) {
                                controller.showBanner("Буфер обмена пуст", isError = true)
                            } else {
                                controller.importSecondExitConf(txt)
                            }
                        },
                        modifier = Modifier.weight(1f)
                    ) {
                        Icon(Icons.Rounded.ContentPaste, contentDescription = null, modifier = Modifier.size(15.dp))
                        Spacer(Modifier.width(5.dp))
                        Text("Вставить из буфера", style = MaterialTheme.typography.labelSmall)
                    }
                }

                if (parsedSecond != null) {
                    Surface(
                        shape = RoundedCornerShape(8.dp),
                        color = warp.surfaceHigh.copy(alpha = 0.7f),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Text(
                            text = (if (parsedSecond.isProton) "✓ ProtonVPN · ${parsedSecond.serverLabel}" else "✓ WireGuard") +
                                " · ${parsedSecond.endpoint} · IP ${parsedSecond.clientIpv4}",
                            style = MaterialTheme.typography.labelSmall,
                            color = warp.ok,
                            modifier = Modifier.padding(horizontal = 10.dp, vertical = 6.dp)
                        )
                    }
                }

                OutlinedTextField(
                    value = s.secondExitConf,
                    onValueChange = { v -> controller.updateSettings { it.copy(secondExitConf = v) } },
                    label = { Text("Клиентский конфиг второго сервера ([Interface]/[Peer])") },
                    placeholder = { Text("[Interface]\nPrivateKey = ...\nAddress = 10.2.0.2/32\n\n[Peer]\nPublicKey = ...\nEndpoint = 185.107.56.138:51820") },
                    modifier = Modifier.fillMaxWidth(),
                    minLines = 4,
                    maxLines = 7,
                    textStyle = MaterialTheme.typography.bodySmall
                )

                Text("Быстрые пресеты для 2-го выхода:", style = MaterialTheme.typography.labelSmall, fontWeight = FontWeight.Medium)
                FlowRow(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(6.dp),
                    verticalArrangement = Arrangement.spacedBy(2.dp)
                ) {
                    SecondExitPreset.entries.forEach { preset ->
                        AssistChip(
                            onClick = { controller.applySecondExitPreset(preset) },
                            label = {
                                Text(
                                    if (preset.builtInCidrs.isNotBlank()) "${preset.title} (готовые IP)" else preset.title,
                                    style = MaterialTheme.typography.labelSmall
                                )
                            }
                        )
                    }
                }

                OutlinedTextField(
                    value = s.secondExitDomains,
                    onValueChange = { v -> controller.updateSettings { it.copy(secondExitDomains = v) } },
                    label = { Text("Домены для второго выхода") },
                    placeholder = { Text("chatgpt.com, openai.com, api.openai.com") },
                    modifier = Modifier.fillMaxWidth(),
                    minLines = 2,
                    maxLines = 4,
                    textStyle = MaterialTheme.typography.bodySmall
                )

                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    FilledTonalButton(
                        onClick = { controller.resolveSecondExitDomains() },
                        enabled = !state.secondExitBusy,
                        modifier = Modifier.weight(1f)
                    ) {
                        if (state.secondExitBusy) {
                            CircularProgressIndicator(modifier = Modifier.size(15.dp), strokeWidth = 2.dp)
                        } else {
                            Icon(Icons.Rounded.Dns, contentDescription = null, modifier = Modifier.size(16.dp))
                        }
                        Spacer(Modifier.width(6.dp))
                        Text("Собрать IP через DoH", style = MaterialTheme.typography.labelMedium)
                    }
                    OutlinedButton(
                        onClick = { controller.applySettingsAndReconnect() },
                        enabled = !state.secondExitBusy
                    ) {
                        Text("Применить", style = MaterialTheme.typography.labelMedium)
                    }
                }

                if (state.secondExitStatus.isNotBlank()) {
                    Text(state.secondExitStatus, style = MaterialTheme.typography.labelSmall, color = warp.accentOrange)
                }

                val cidrCount = SplitRoutes.prefixesOf(s.secondExitCidrs).size
                Text(
                    if (cidrCount > 0) "Собрано подсетей для второго выхода: $cidrCount. Если сервер не ответит (например, порт 51820 режется провайдером), трафик автоматически вернётся в WARP."
                    else "Адреса ещё не собраны — нажмите «Telegram (готовые IP)» или «Собрать IP через DoH».",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
    }
}
