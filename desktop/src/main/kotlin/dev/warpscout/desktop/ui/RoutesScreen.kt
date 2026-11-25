package dev.warpscout.desktop.ui

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import dev.warpscout.core.config.SplitRoutes
import dev.warpscout.core.lists.AllowLists
import dev.warpscout.core.lists.ListSide
import dev.warpscout.desktop.engine.DesktopController
import dev.warpscout.desktop.engine.DesktopUiState
import dev.warpscout.desktop.storage.RouteMode

/**
 * Вкладка «Маршруты»: раздельное туннелирование (Весь трафик / Пресет обхода РФ / Списки allow-domains /
 * Вручную CIDR) и «Второй выход» (свой WireGuard/AmneziaWG сервер для выбранных доменов).
 */
@Composable
fun RoutesScreen(state: DesktopUiState, controller: DesktopController) {
    val warp = LocalWarpColors.current
    val s = state.settings

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
                    "Встроена база RIPE RU (8 690 IPv4 + 2 164 IPv6 подсетей): Яндекс, VK, банки (Сбер, Т-Банк, Альфа, ВТБ), Госуслуги, Ozon, Wildberries, Авито и локальная сеть идут напрямую. Всё зарубежное — через туннель.",
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

        // --- 2. Второй выход (свой сервер в нужной стране) ---
        WarpCard {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text("Второй выход (свой регион)", style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.SemiBold)
                    Text(
                        "Отдельные сайты идут через ваш WireGuard/AmneziaWG VPS, всё остальное — через WARP.",
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
                OutlinedTextField(
                    value = s.secondExitConf,
                    onValueChange = { v -> controller.updateSettings { it.copy(secondExitConf = v) } },
                    label = { Text("Клиентский конфиг второго сервера ([Interface]/[Peer])") },
                    placeholder = { Text("[Interface]\nPrivateKey = ...\nAddress = 10.0.0.2/32\n\n[Peer]\nPublicKey = ...\nEndpoint = 1.2.3.4:51820") },
                    modifier = Modifier.fillMaxWidth(),
                    minLines = 4,
                    maxLines = 7,
                    textStyle = MaterialTheme.typography.bodySmall
                )

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
                    if (cidrCount > 0) "Собрано подсетей для второго выхода: $cidrCount. При падении сервера трафик вернётся в WARP."
                    else "Адреса ещё не собраны — нажмите «Собрать IP через DoH».",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
    }
}
