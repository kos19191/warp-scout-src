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
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import dev.warpscout.core.config.SplitRoutes
import dev.warpscout.core.lists.AllowLists
import dev.warpscout.core.lists.ListSide
import dev.warpscout.desktop.engine.DesktopController
import dev.warpscout.desktop.engine.DesktopUiState
import dev.warpscout.desktop.storage.RouteMode
import dev.warpscout.desktop.tunnel.ProtonVpnHelper
import dev.warpscout.desktop.tunnel.SecondExitCatalog

/**
 * Вкладка «Маршруты»:
 *  • наглядная сводка «Напрямую / Через WARP / Через 2-й выход»;
 *  • выбор списков для WARP (и «Держим напрямую») — кнопками-чипами как в мобильном WilyScout;
 *  • быстрое добавление ProtonVPN (WireGuard .conf);
 *  • выбор списков для Второго выхода такими же кнопками-чипами + переключатель «через WARP (Double-Hop)».
 */
@OptIn(ExperimentalLayoutApi::class)
@Composable
fun RoutesScreen(state: DesktopUiState, controller: DesktopController) {
    val warp = LocalWarpColors.current
    val s = state.settings
    val clipboard = LocalClipboardManager.current

    val parsedSecond = remember(s.secondExitConf) {
        if (s.secondExitConf.isBlank()) null else ProtonVpnHelper.inspectConf(s.secondExitConf)
    }
    val secondAllForeign = SecondExitCatalog.ALL_FOREIGN_ID in s.secondExitListIds
    val secondSelectedSet = remember(s.secondExitListIds) { s.secondExitListIds.toSet() }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 16.dp, vertical = 12.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        // --- 0. Краткая карта: что куда идёт сейчас ---
        WarpCard {
            Text("Распределение трафика", style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.SemiBold)

            val directDesc = when (s.routeMode) {
                RouteMode.PRESET -> "Российские сайты (Яндекс, банки, Госуслуги, Авито…) и локальная сеть"
                RouteMode.ALL -> "Только локальная сеть"
                RouteMode.LISTS -> {
                    val directTitles = s.selectedDirectListIds.mapNotNull { AllowLists.byId[it]?.title }
                    if (directTitles.isEmpty()) "Всё, кроме выбранных списков"
                    else "Всё вне списков + ${directTitles.joinToString(", ")}"
                }
                RouteMode.MANUAL -> "Всё, кроме указанных CIDR"
            }

            val warpDesc = when {
                s.secondExitEnabled && secondAllForeign ->
                    "Транспорт (обход ТСПУ для 2-го выхода)"
                s.routeMode == RouteMode.PRESET -> "Весь зарубежный трафик" +
                    if (s.secondExitEnabled) " (кроме списков 2-го выхода)" else ""
                s.routeMode == RouteMode.ALL -> "Весь трафик" +
                    if (s.secondExitEnabled) " (кроме списков 2-го выхода)" else ""
                s.routeMode == RouteMode.LISTS -> {
                    val warpIds = if (s.secondExitEnabled) s.selectedBlockListIds.filterNot { it in secondSelectedSet }
                    else s.selectedBlockListIds
                    val names = warpIds.mapNotNull { AllowLists.byId[it]?.title }
                    if (names.isEmpty()) "Списки не выбраны" else names.joinToString(", ")
                }
                else -> "Подсети из ручного поля AllowedIPs"
            }

            val secondDesc = when {
                !s.secondExitEnabled -> "Выключен"
                secondAllForeign -> "Весь зарубежный трафик"
                else -> {
                    val names = s.secondExitListIds.mapNotNull { SecondExitCatalog.byId[it]?.title }
                    val customCount = SecondExitCatalog.parseCustomSites(s.secondExitDomains).let { it.hosts.size + it.prefixes.size }
                    buildList {
                        addAll(names)
                        if (customCount > 0) add("свои сайты ($customCount)")
                    }.ifEmpty { listOf("списки не выбраны") }.joinToString(", ")
                }
            }

            RouteSummaryLine(dotColor = MaterialTheme.colorScheme.onSurfaceVariant, label = "Напрямую:", value = directDesc)
            RouteSummaryLine(dotColor = warp.accentOrange, label = "Через WARP:", value = warpDesc)
            RouteSummaryLine(
                dotColor = if (s.secondExitEnabled) warp.ok else MaterialTheme.colorScheme.outline,
                label = if (parsedSecond != null && s.secondExitEnabled) "2-й выход (${parsedSecond.serverLabel}):" else "2-й выход:",
                value = secondDesc
            )
        }

        // --- 1. Через WARP (основной туннель) ---
        WarpCard {
            SectionHeader(
                title = "Через WARP (основной туннель)",
                subtitle = "Что пускать через основной туннель WARP. Списки, отмеченные во «Втором выходе», автоматически переходят туда."
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
                    "Компактный пресет обхода РФ (~900 маршрутов, без нагрузки на службы Windows): Яндекс, VK, банки (Сбер, Т-Банк, Альфа, ВТБ), Госуслуги, Ozon, Wildberries, Авито и локальная сеть идут напрямую. Всё зарубежное — через туннель.",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }

            if (s.routeMode == RouteMode.LISTS) {
                HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.4f))
                Text(
                    "Отправляем через WARP (allow-domains, «заблокировано в РФ»):",
                    style = MaterialTheme.typography.labelMedium,
                    fontWeight = FontWeight.SemiBold
                )

                val blockLists = AllowLists.bySide(ListSide.BLOCK)
                    .filterNot { it.id in setOf("all-blocked", "all-subnets-v4", "all-subnets-v6") }
                Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
                    blockLists.chunked(2).forEach { rowItems ->
                        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                            rowItems.forEach { list ->
                                val selected = list.id in s.selectedBlockListIds
                                val overriddenBySecond = s.secondExitEnabled && (secondAllForeign || list.id in secondSelectedSet)
                                FilterChip(
                                    selected = selected,
                                    onClick = {
                                        controller.updateSettings { cur ->
                                            val next = if (selected) cur.selectedBlockListIds - list.id else cur.selectedBlockListIds + list.id
                                            cur.copy(selectedBlockListIds = next)
                                        }
                                    },
                                    leadingIcon = if (selected) {
                                        { Icon(Icons.Rounded.Check, contentDescription = null, modifier = Modifier.size(14.dp)) }
                                    } else null,
                                    label = {
                                        Text(
                                            text = if (overriddenBySecond && selected) "${list.title} → 2-й" else list.title,
                                            style = MaterialTheme.typography.labelSmall,
                                            maxLines = 1,
                                            overflow = TextOverflow.Ellipsis
                                        )
                                    },
                                    modifier = Modifier.weight(1f)
                                )
                            }
                            if (rowItems.size == 1) Spacer(Modifier.weight(1f))
                        }
                    }
                }

                Spacer(Modifier.height(2.dp))
                Text(
                    "Держим напрямую (через WARP портится):",
                    style = MaterialTheme.typography.labelMedium,
                    fontWeight = FontWeight.SemiBold
                )
                val directLists = AllowLists.bySide(ListSide.DIRECT)
                Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
                    directLists.forEach { list ->
                        val selected = list.id in s.selectedDirectListIds
                        FilterChip(
                            selected = selected,
                            onClick = {
                                controller.updateSettings { cur ->
                                    val next = if (selected) cur.selectedDirectListIds - list.id else cur.selectedDirectListIds + list.id
                                    cur.copy(selectedDirectListIds = next)
                                }
                            },
                            leadingIcon = if (selected) {
                                { Icon(Icons.Rounded.Check, contentDescription = null, modifier = Modifier.size(14.dp)) }
                            } else null,
                            label = { Text(list.title, style = MaterialTheme.typography.labelSmall, maxLines = 1, overflow = TextOverflow.Ellipsis) },
                            modifier = Modifier.fillMaxWidth()
                        )
                    }
                }

                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Button(
                        onClick = { controller.buildAllowListRoutes(reconnectIfUp = true) },
                        enabled = !state.listsBusy,
                        modifier = Modifier.weight(1f),
                        colors = ButtonDefaults.buttonColors(containerColor = warp.accentOrange, contentColor = Color.White)
                    ) {
                        if (state.listsBusy) {
                            CircularProgressIndicator(modifier = Modifier.size(15.dp), strokeWidth = 2.dp, color = Color.White)
                        } else {
                            Icon(Icons.Rounded.Build, contentDescription = null, modifier = Modifier.size(16.dp))
                        }
                        Spacer(Modifier.width(5.dp))
                        Text("Собрать маршруты WARP и применить", style = MaterialTheme.typography.labelMedium)
                    }
                    OutlinedButton(
                        onClick = { controller.refreshAllowLists() },
                        enabled = !state.listsBusy
                    ) {
                        Icon(Icons.Rounded.CloudDownload, contentDescription = null, modifier = Modifier.size(16.dp))
                    }
                }

                if (state.listsStatus.isNotBlank()) {
                    Text(state.listsStatus, style = MaterialTheme.typography.labelSmall, color = warp.accentOrange)
                }
                val builtCount = SplitRoutes.prefixesOf(s.builtAllowedIps).size
                Text(
                    if (builtCount > 0) "Собрано подсетей WARP: $builtCount (включая сети YouTube и GitHub)"
                    else "Маршруты ещё не собраны — нажмите «Собрать маршруты WARP и применить» (списки скачаются автоматически).",
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

            if (s.routeMode != RouteMode.LISTS) {
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
        }

        // --- 2. Быстрое добавление ProtonVPN (WireGuard .conf) ---
        WarpCard {
            SectionHeader(
                title = "ProtonVPN (WireGuard)",
                subtitle = "Бесплатные и платные .conf из кабинета ProtonVPN — добавляется в 1 клик как 2-й выход поверх WARP (обход ТСПУ)."
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
                                .onSuccess { controller.importSecondExitConf(it, preset = null, applyNow = true) }
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

        // --- 3. Через Второй выход (свой регион / ProtonVPN) ---
        WarpCard {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text("Через Второй выход (ProtonVPN / свой регион)", style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.SemiBold)
                    Text(
                        "Выберите кнопками, какие списки сайтов отправлять через второй сервер — всё остальное останется в WARP.",
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
                // Живой статус подключения Второго выхода
                if (state.tunnel.isUp) {
                    val active = state.tunnel.secondExitActive
                    val badgeColor = if (active) warp.ok else warp.warn
                    val liveText = when {
                        active && state.tunnel.secondExitViaWarp ->
                            "● Активен через WARP (Double-Hop · обход ТСПУ): ${state.tunnel.secondExitServer}"
                        active ->
                            "● Активен напрямую: ${state.tunnel.secondExitServer}"
                        state.tunnel.secondExitError.isNotBlank() ->
                            "⚠ Второй выход не поднялся — трафик идёт через WARP. ${state.tunnel.secondExitError}"
                        else ->
                            "⚠ Второй выход ещё не применён — нажмите «Собрать адреса и применить»"
                    }
                    Surface(
                        shape = RoundedCornerShape(8.dp),
                        color = badgeColor.copy(alpha = 0.13f),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Text(
                            text = liveText,
                            style = MaterialTheme.typography.labelSmall,
                            color = badgeColor,
                            modifier = Modifier.padding(horizontal = 10.dp, vertical = 6.dp)
                        )
                    }
                }

                // Переключатель «Подключаться через WARP» (1-в-1 с мобильным WilyScout)
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Column(modifier = Modifier.weight(1f).padding(end = 8.dp)) {
                        Text("Подключаться ко 2-му выходу через WARP", style = MaterialTheme.typography.bodySmall, fontWeight = FontWeight.Medium)
                        Text(
                            "Провайдер (ТСПУ) видит только WARP и не режет WireGuard UDP 51820 — надёжнее в России.",
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                    Switch(
                        checked = s.secondExitViaWarp,
                        onCheckedChange = { v -> controller.updateSettings { it.copy(secondExitViaWarp = v) } }
                    )
                }

                HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.4f))

                // Кнопки-переключатели списков для Второго выхода (как у WARP и в мобильном приложении!)
                Text(
                    "Какие списки отправлять через 2-й выход:",
                    style = MaterialTheme.typography.labelMedium,
                    fontWeight = FontWeight.SemiBold
                )

                FilterChip(
                    selected = secondAllForeign,
                    onClick = { controller.toggleSecondExitList(SecondExitCatalog.ALL_FOREIGN_ID) },
                    leadingIcon = if (secondAllForeign) {
                        { Icon(Icons.Rounded.Check, contentDescription = null, modifier = Modifier.size(15.dp)) }
                    } else {
                        { Icon(Icons.Rounded.Public, contentDescription = null, modifier = Modifier.size(15.dp)) }
                    },
                    label = {
                        Text(
                            "Весь зарубежный трафик (при «Обходе РФ» российские сайты напрямую)",
                            style = MaterialTheme.typography.labelSmall,
                            maxLines = 2
                        )
                    },
                    modifier = Modifier.fillMaxWidth()
                )

                Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
                    SecondExitCatalog.CATEGORIES.chunked(2).forEach { rowItems ->
                        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                            rowItems.forEach { cat ->
                                val selected = !secondAllForeign && (cat.id in secondSelectedSet)
                                FilterChip(
                                    selected = selected,
                                    onClick = { controller.toggleSecondExitList(cat.id) },
                                    leadingIcon = if (selected) {
                                        { Icon(Icons.Rounded.Check, contentDescription = null, modifier = Modifier.size(14.dp)) }
                                    } else null,
                                    label = {
                                        Text(
                                            text = cat.title,
                                            style = MaterialTheme.typography.labelSmall,
                                            maxLines = 1,
                                            overflow = TextOverflow.Ellipsis
                                        )
                                    },
                                    modifier = Modifier.weight(1f)
                                )
                            }
                            if (rowItems.size == 1) Spacer(Modifier.weight(1f))
                        }
                    }
                }

                if (!secondAllForeign) {
                    OutlinedTextField(
                        value = s.secondExitDomains,
                        onValueChange = { v -> controller.updateSettings { it.copy(secondExitDomains = v) } },
                        label = { Text("Свои сайты или подсети для 2-го выхода (необязательно)") },
                        placeholder = { Text("https://example.com, mysite.org, 1.2.3.0/24") },
                        modifier = Modifier.fillMaxWidth(),
                        minLines = 1,
                        maxLines = 3,
                        textStyle = MaterialTheme.typography.bodySmall
                    )
                }

                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Button(
                        onClick = { controller.buildSecondExitRoutes(reconnectIfUp = true) },
                        enabled = !state.secondExitBusy,
                        modifier = Modifier.weight(1f),
                        colors = ButtonDefaults.buttonColors(containerColor = warp.accentOrange, contentColor = Color.White)
                    ) {
                        if (state.secondExitBusy) {
                            CircularProgressIndicator(modifier = Modifier.size(15.dp), strokeWidth = 2.dp, color = Color.White)
                        } else {
                            Icon(Icons.Rounded.Check, contentDescription = null, modifier = Modifier.size(16.dp))
                        }
                        Spacer(Modifier.width(6.dp))
                        Text(
                            if (secondAllForeign) "Применить (весь зарубежный)" else "Собрать адреса и применить",
                            style = MaterialTheme.typography.labelMedium
                        )
                    }
                }

                if (state.secondExitStatus.isNotBlank()) {
                    Text(state.secondExitStatus, style = MaterialTheme.typography.labelSmall, color = warp.accentOrange)
                }

                val cidrCount = SplitRoutes.prefixesOf(s.secondExitCidrs).size
                val cidrsAllForeign = SplitRoutes.prefixesOf(s.secondExitCidrs).any { it == "0.0.0.0/0" }
                Text(
                    when {
                        cidrsAllForeign -> "В таблице 2-го выхода: весь зарубежный трафик (0.0.0.0/0, без петли и с сохранением «Обхода РФ»)."
                        cidrCount > 0 -> "В таблице 2-го выхода: $cidrCount подсетей/адресов."
                        else -> "Адреса ещё не собраны — отметьте нужные кнопки выше и нажмите «Собрать адреса и применить»."
                    },
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )

                HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.4f))

                // Конфиг второго сервера (.conf)
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
                    minLines = 3,
                    maxLines = 6,
                    textStyle = MaterialTheme.typography.bodySmall
                )
            }
        }
    }
}

@Composable
private fun RouteSummaryLine(dotColor: Color, label: String, value: String) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        verticalAlignment = Alignment.Top,
        horizontalArrangement = Arrangement.spacedBy(6.dp)
    ) {
        Text("●", style = MaterialTheme.typography.labelSmall, color = dotColor)
        Text(label, style = MaterialTheme.typography.labelSmall, fontWeight = FontWeight.SemiBold)
        Text(
            value,
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.weight(1f)
        )
    }
}
