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
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import dev.warpscout.core.config.ConfTarget
import dev.warpscout.core.config.WgConf
import dev.warpscout.core.presets.Presets
import dev.warpscout.core.report.ConfigExport
import dev.warpscout.desktop.engine.DesktopController
import dev.warpscout.desktop.engine.DesktopUiState
import dev.warpscout.desktop.storage.ThemeMode
import dev.warpscout.desktop.tunnel.EngineLocator

/**
 * Вкладка «Настройки»: движок AmneziaWG, параметры сети (DNS/MTU/Keepalive/IPv6),
 * поведение Windows (автозапуск, трей, расписание, тема), экспорт/импорт конфига и резервные копии.
 */
@Composable
fun SettingsScreen(state: DesktopUiState, controller: DesktopController) {
    val warp = LocalWarpColors.current
    val s = state.settings
    var showImportDialog by remember { mutableStateOf(false) }
    var importText by remember { mutableStateOf("") }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 16.dp, vertical = 12.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        // --- 1. Движок AmneziaWG ---
        WarpCard {
            SectionHeader(
                title = "Движок туннеля (AmneziaWG)",
                subtitle = "Поднимает виртуальный сетевой адаптер и применяет AWG-маскировку пакетов."
            )

            StatusPill(
                text = if (state.engine.available)
                    "${state.engine.kind.title} · ${state.engine.sourceLabel}"
                else "Не найден — установите AmneziaWG",
                dotColor = if (state.engine.available) warp.ok else warp.error
            )

            if (state.engine.tunnelExe != null) {
                Text(
                    state.engine.tunnelExe.absolutePath,
                    style = MaterialTheme.typography.labelSmall,
                    fontFamily = FontFamily.Monospace,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }

            OutlinedTextField(
                value = s.customEnginePath,
                onValueChange = { v -> controller.updateSettings { it.copy(customEnginePath = v) } },
                label = { Text("Путь к amneziawg.exe (пусто — автопоиск)") },
                placeholder = { Text("C:\\Program Files\\AmneziaWG\\amneziawg.exe") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
                textStyle = MaterialTheme.typography.bodySmall
            )

            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedButton(
                    onClick = {
                        DesktopPlatform.chooseOpenFile("Выберите amneziawg.exe")?.let { file ->
                            controller.updateSettings { it.copy(customEnginePath = file.absolutePath) }
                        }
                    },
                    modifier = Modifier.weight(1f)
                ) {
                    Icon(Icons.Rounded.FolderOpen, contentDescription = null, modifier = Modifier.size(16.dp))
                    Spacer(Modifier.width(5.dp))
                    Text("Указать файл", style = MaterialTheme.typography.labelMedium)
                }
                FilledTonalButton(
                    onClick = { DesktopPlatform.openUrl(EngineLocator.AMNEZIAWG_RELEASES_URL) },
                    modifier = Modifier.weight(1f)
                ) {
                    Icon(Icons.Rounded.Download, contentDescription = null, modifier = Modifier.size(16.dp))
                    Spacer(Modifier.width(5.dp))
                    Text("Скачать AWG", style = MaterialTheme.typography.labelMedium)
                }
            }

            SettingSwitchRow(
                title = "Запрашивать UAC при запуске туннеля",
                subtitle = if (state.isElevated) "Приложение уже запущено с правами администратора"
                else "Если приложение запущено без прав админа — автоматически запросит UAC",
                checked = s.autoElevateUac,
                onCheckedChange = { v -> controller.updateSettings { it.copy(autoElevateUac = v) } }
            )
        }

        // --- 2. Сеть и DNS ---
        WarpCard {
            SectionHeader(title = "Сеть и DNS", subtitle = "Применяются при следующем подключении или по кнопке «Применить».")

            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                Presets.DNS.take(3).forEachIndexed { idx, preset ->
                    FilterChip(
                        selected = s.dnsPresetIndex == idx,
                        onClick = {
                            controller.updateSettings {
                                it.copy(dnsPresetIndex = idx, customDns = preset.servers.joinToString(", "))
                            }
                        },
                        label = { Text(preset.name, style = MaterialTheme.typography.labelSmall) },
                        modifier = Modifier.weight(1f)
                    )
                }
            }

            OutlinedTextField(
                value = s.customDns,
                onValueChange = { v -> controller.updateSettings { it.copy(customDns = v, dnsPresetIndex = -1) } },
                label = { Text("DNS серверы") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
                textStyle = MaterialTheme.typography.bodySmall
            )

            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                var mtuText by remember(s.mtu) { mutableStateOf(s.mtu.toString()) }
                var kaText by remember(s.keepalive) { mutableStateOf(s.keepalive.toString()) }
                OutlinedTextField(
                    value = mtuText,
                    onValueChange = { raw ->
                        mtuText = raw.filter { it.isDigit() }
                        mtuText.toIntOrNull()?.takeIf { it in 1000..1500 }?.let { m ->
                            controller.updateSettings { it.copy(mtu = m) }
                        }
                    },
                    label = { Text("MTU") },
                    singleLine = true,
                    modifier = Modifier.weight(1f),
                    textStyle = MaterialTheme.typography.bodySmall
                )
                OutlinedTextField(
                    value = kaText,
                    onValueChange = { raw ->
                        kaText = raw.filter { it.isDigit() }
                        kaText.toIntOrNull()?.takeIf { it in 0..120 }?.let { k ->
                            controller.updateSettings { it.copy(keepalive = k) }
                        }
                    },
                    label = { Text("Keepalive, с (0 = выкл)") },
                    singleLine = true,
                    modifier = Modifier.weight(1f),
                    textStyle = MaterialTheme.typography.bodySmall
                )
            }

            SettingSwitchRow(
                title = "Отдавать IPv6-адрес",
                subtitle = "Отключите, если отдельные сервисы (например OpenAI) ругаются на IPv6",
                checked = s.enableIpv6,
                onCheckedChange = { v -> controller.updateSettings { it.copy(enableIpv6 = v) } }
            )

            Button(
                onClick = { controller.applySettingsAndReconnect() },
                modifier = Modifier.fillMaxWidth(),
                colors = ButtonDefaults.buttonColors(containerColor = warp.accentOrange, contentColor = Color.White)
            ) {
                Text("Сохранить и применить")
            }
        }

        // --- 3. Windows, трей и внешний вид ---
        WarpCard {
            SectionHeader(title = "Приложение и Windows")

            Text("Тема оформления", style = MaterialTheme.typography.labelMedium, fontWeight = FontWeight.Medium)
            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                ThemeMode.entries.forEach { mode ->
                    FilterChip(
                        selected = s.theme == mode,
                        onClick = { controller.updateSettings { it.copy(theme = mode) } },
                        label = { Text(mode.title, style = MaterialTheme.typography.labelSmall) },
                        modifier = Modifier.weight(1f)
                    )
                }
            }

            SettingSwitchRow(
                title = "Запускать вместе с Windows",
                subtitle = "Сразу сворачивается в системный трей",
                checked = s.autostartWindows,
                onCheckedChange = { v -> controller.updateSettings { it.copy(autostartWindows = v) } }
            )
            SettingSwitchRow(
                title = "Подключаться автоматически при запуске",
                subtitle = "Поднимает последний рабочий конфиг без нажатия кнопки",
                checked = s.autoConnectOnStart,
                onCheckedChange = { v -> controller.updateSettings { it.copy(autoConnectOnStart = v) } }
            )
            SettingSwitchRow(
                title = "Сворачивать в трей при закрытии окна",
                subtitle = "Туннель остаётся работать в фоне, управление через иконку в трее",
                checked = s.minimizeToTrayOnClose,
                onCheckedChange = { v -> controller.updateSettings { it.copy(minimizeToTrayOnClose = v) } }
            )
            SettingSwitchRow(
                title = "Отключать туннель при выходе",
                subtitle = "Останавливает службу AmneziaWG при нажатии «Выход» в трее",
                checked = s.disconnectOnExit,
                onCheckedChange = { v -> controller.updateSettings { it.copy(disconnectOnExit = v) } }
            )

            HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.4f))
            Text("Фоновый подбор по расписанию", style = MaterialTheme.typography.labelMedium, fontWeight = FontWeight.Medium)
            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                listOf(0 to "Выкл", 6 to "6 ч", 12 to "12 ч", 24 to "24 ч").forEach { (hours, label) ->
                    FilterChip(
                        selected = s.autoScheduleHours == hours,
                        onClick = { controller.updateSettings { it.copy(autoScheduleHours = hours) } },
                        label = { Text(label, style = MaterialTheme.typography.labelSmall) },
                        modifier = Modifier.weight(1f)
                    )
                }
            }
            if (s.autoScheduleHours > 0) {
                SettingSwitchRow(
                    title = "Автоматически переключаться после фонового подбора",
                    subtitle = "Если выключено — только обновляет список Топ-3",
                    checked = s.autoApplyScheduled,
                    onCheckedChange = { v -> controller.updateSettings { it.copy(autoApplyScheduled = v) } }
                )
            }
        }

        // --- 4. Экспорт / Импорт конфигов ---
        WarpCard {
            SectionHeader(
                title = "Экспорт и импорт конфигов",
                subtitle = "Перенос подобранной конфигурации в AmneziaWG, WireGuard или Clash."
            )

            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                ConfTarget.entries.forEach { tgt ->
                    FilterChip(
                        selected = s.exportTarget == tgt,
                        onClick = { controller.updateSettings { it.copy(exportTarget = tgt) } },
                        label = {
                            Text(
                                when (tgt) {
                                    ConfTarget.AMNEZIA -> "AWG"
                                    ConfTarget.WIREGUARD -> "WG"
                                    ConfTarget.CLASH -> "Clash"
                                    ConfTarget.ROUTES -> "Routes"
                                },
                                style = MaterialTheme.typography.labelSmall
                            )
                        },
                        modifier = Modifier.weight(1f)
                    )
                }
            }

            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                FilledTonalButton(
                    onClick = {
                        val txt = controller.renderExportText(s.exportTarget)
                        if (txt == null) {
                            controller.showBanner("Конфигурации ещё нет — сначала выполните подбор", isError = true)
                        } else {
                            DesktopPlatform.copyToClipboard(txt)
                            controller.showBanner("Конфиг (${s.exportTarget.title}) скопирован в буфер обмена")
                        }
                    },
                    modifier = Modifier.weight(1f)
                ) {
                    Icon(Icons.Rounded.ContentCopy, contentDescription = null, modifier = Modifier.size(16.dp))
                    Spacer(Modifier.width(5.dp))
                    Text("Копировать", style = MaterialTheme.typography.labelMedium)
                }

                OutlinedButton(
                    onClick = {
                        val txt = controller.renderExportText(s.exportTarget)
                        if (txt == null) {
                            controller.showBanner("Конфигурации ещё нет — сначала выполните подбор", isError = true)
                            return@OutlinedButton
                        }
                        val parsed = state.activeConfText?.let { WgConf.toWarpConfig("WarpScout", it) }
                        val defaultName = parsed?.let { ConfigExport.filename(it, s.exportTarget) }
                            ?: "warpscout.${s.exportTarget.extension}"
                        DesktopPlatform.chooseSaveFile("Сохранить конфигурацию", defaultName)?.let { file ->
                            runCatching { file.writeText(txt, Charsets.UTF_8) }
                                .onSuccess { controller.showBanner("Сохранено: ${file.name}") }
                                .onFailure { controller.showBanner("Ошибка записи: ${it.message}", isError = true) }
                        }
                    },
                    modifier = Modifier.weight(1f)
                ) {
                    Icon(Icons.Rounded.Save, contentDescription = null, modifier = Modifier.size(16.dp))
                    Spacer(Modifier.width(5.dp))
                    Text("Сохранить", style = MaterialTheme.typography.labelMedium)
                }
            }

            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedButton(
                    onClick = {
                        DesktopPlatform.chooseOpenFile("Импортировать .conf файл")?.let { file ->
                            runCatching { file.readText(Charsets.UTF_8) }
                                .onSuccess { controller.importConfigText(it) }
                                .onFailure { controller.showBanner("Не удалось прочитать файл: ${it.message}", isError = true) }
                        }
                    },
                    modifier = Modifier.weight(1f)
                ) {
                    Icon(Icons.Rounded.FileOpen, contentDescription = null, modifier = Modifier.size(16.dp))
                    Spacer(Modifier.width(5.dp))
                    Text("Импорт файла", style = MaterialTheme.typography.labelMedium)
                }
                OutlinedButton(
                    onClick = { showImportDialog = true },
                    modifier = Modifier.weight(1f)
                ) {
                    Icon(Icons.Rounded.EditNote, contentDescription = null, modifier = Modifier.size(16.dp))
                    Spacer(Modifier.width(5.dp))
                    Text("Вставить текст", style = MaterialTheme.typography.labelMedium)
                }
            }
        }

        // --- 5. Резервная копия ---
        WarpCard {
            SectionHeader(
                title = "Резервная копия и файлы",
                subtitle = "Сохраняет настройки, Топ-3, активный конфиг и ключи в один JSON-файл."
            )
            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedButton(
                    onClick = {
                        DesktopPlatform.chooseSaveFile("Сохранить резервную копию", "warpscout-backup.json")?.let {
                            controller.saveBackup(it)
                        }
                    },
                    modifier = Modifier.weight(1f)
                ) {
                    Icon(Icons.Rounded.Backup, contentDescription = null, modifier = Modifier.size(16.dp))
                    Spacer(Modifier.width(5.dp))
                    Text("Сохранить бекап", style = MaterialTheme.typography.labelMedium)
                }
                OutlinedButton(
                    onClick = {
                        DesktopPlatform.chooseOpenFile("Восстановить резервную копию")?.let {
                            controller.restoreBackup(it)
                        }
                    },
                    modifier = Modifier.weight(1f)
                ) {
                    Icon(Icons.Rounded.Restore, contentDescription = null, modifier = Modifier.size(16.dp))
                    Spacer(Modifier.width(5.dp))
                    Text("Восстановить", style = MaterialTheme.typography.labelMedium)
                }
            }
            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                TextButton(onClick = { DesktopPlatform.openFolder(controller.store.paths.root) }) {
                    Icon(Icons.Rounded.Folder, contentDescription = null, modifier = Modifier.size(15.dp))
                    Spacer(Modifier.width(4.dp))
                    Text("Открыть папку данных", style = MaterialTheme.typography.labelSmall)
                }
                if (state.shortlist.isNotEmpty()) {
                    TextButton(onClick = { controller.clearShortlist() }) {
                        Text("Очистить Топ-3", style = MaterialTheme.typography.labelSmall, color = warp.error)
                    }
                }
            }
        }
    }

    if (showImportDialog) {
        AlertDialog(
            onDismissRequest = { showImportDialog = false },
            title = { Text("Импорт конфига WireGuard / AmneziaWG") },
            text = {
                OutlinedTextField(
                    value = importText,
                    onValueChange = { importText = it },
                    placeholder = { Text("Вставьте содержимое [Interface] ... [Peer] ...") },
                    modifier = Modifier.fillMaxWidth().height(180.dp),
                    textStyle = MaterialTheme.typography.bodySmall
                )
            },
            confirmButton = {
                Button(onClick = {
                    if (controller.importConfigText(importText)) {
                        importText = ""
                        showImportDialog = false
                    }
                }) { Text("Импортировать") }
            },
            dismissButton = {
                TextButton(onClick = { showImportDialog = false }) { Text("Отмена") }
            }
        )
    }
}

@Composable
private fun SettingSwitchRow(
    title: String,
    subtitle: String,
    checked: Boolean,
    onCheckedChange: (Boolean) -> Unit
) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.SpaceBetween
    ) {
        Column(modifier = Modifier.weight(1f).padding(end = 8.dp)) {
            Text(title, style = MaterialTheme.typography.bodySmall, fontWeight = FontWeight.Medium)
            Text(subtitle, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        Switch(checked = checked, onCheckedChange = onCheckedChange)
    }
}
