package dev.warpscout.desktop.ui

import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.FastOutSlowInEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.scale
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import dev.warpscout.desktop.engine.DesktopController
import dev.warpscout.desktop.engine.DesktopUiState
import dev.warpscout.desktop.engine.Formatters
import dev.warpscout.desktop.tunnel.EngineLocator
import dev.warpscout.desktop.tunnel.TunnelPhase
import kotlinx.coroutines.delay

/**
 * Главный экран в минималистичном стиле «одна кнопка»:
 * статус → фирменный щит с лисой (кликабельный) → одна крупная кнопка подключения.
 * Ниже — компактная живая сводка (только когда актуально) и быстрое переключение Топ-3.
 */
@Composable
fun HomeScreen(
    state: DesktopUiState,
    controller: DesktopController,
    onNavigateToScan: () -> Unit,
    onNavigateToSettings: () -> Unit
) {
    val warp = LocalWarpColors.current
    val phase = state.effectivePhase
    val shield = rememberFoxShieldBitmap()

    // Обновляем таймер аптайма раз в секунду, пока туннель поднят.
    var nowMs by remember { mutableStateOf(System.currentTimeMillis()) }
    LaunchedEffect(state.tunnel.isUp) {
        while (state.tunnel.isUp) {
            nowMs = System.currentTimeMillis()
            delay(1000L)
        }
    }

    val ringColor by animateColorAsState(
        targetValue = when (phase) {
            TunnelPhase.CONNECTED -> warp.ok
            TunnelPhase.CONNECTING, TunnelPhase.RECONNECTING, TunnelPhase.SCANNING -> warp.accentOrange
            TunnelPhase.ERROR -> warp.error
            TunnelPhase.OFF -> MaterialTheme.colorScheme.outlineVariant
        },
        animationSpec = tween(400)
    )

    val pulseTransition = rememberInfiniteTransition()
    val pulseScale by pulseTransition.animateFloat(
        initialValue = 1.0f,
        targetValue = if (phase == TunnelPhase.CONNECTING || phase == TunnelPhase.RECONNECTING || phase == TunnelPhase.SCANNING) 1.09f else 1.0f,
        animationSpec = infiniteRepeatable(
            animation = tween(900, easing = FastOutSlowInEasing),
            repeatMode = RepeatMode.Reverse
        )
    )

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 18.dp, vertical = 12.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        // --- 1. Подсказка по правам администратора или внешнему движку ---
        if (state.tunnel.needsElevation) {
            WarpCard(
                containerColor = MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.35f),
                borderColor = warp.accentOrange.copy(alpha = 0.55f)
            ) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    Icon(Icons.Rounded.AdminPanelSettings, contentDescription = null, tint = warp.accentOrange, modifier = Modifier.size(20.dp))
                    Text(
                        "Нужны права администратора",
                        style = MaterialTheme.typography.titleSmall,
                        fontWeight = FontWeight.SemiBold
                    )
                }
                Text(
                    "Встроенный туннель создаёт виртуальный сетевой адаптер Wintun. Нажмите кнопку ниже — Windows запросит UAC, и туннель поднимется сам.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Button(
                    onClick = { controller.relaunchAsAdministrator(autoConnect = true) },
                    colors = ButtonDefaults.buttonColors(containerColor = warp.accentOrange, contentColor = Color.White),
                    contentPadding = PaddingValues(horizontal = 14.dp, vertical = 8.dp)
                ) {
                    Icon(Icons.Rounded.Shield, contentDescription = null, modifier = Modifier.size(16.dp))
                    Spacer(Modifier.width(6.dp))
                    Text("Перезапустить от администратора и подключиться", style = MaterialTheme.typography.labelMedium)
                }
            }
        } else if (state.settings.backendMode == dev.warpscout.desktop.storage.TunnelBackendMode.BUILTIN_WINTUN && !state.wintunReady) {
            WarpCard(
                containerColor = MaterialTheme.colorScheme.errorContainer.copy(alpha = 0.4f),
                borderColor = warp.error.copy(alpha = 0.5f)
            ) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    Icon(Icons.Rounded.WarningAmber, contentDescription = null, tint = warp.error, modifier = Modifier.size(20.dp))
                    Text(
                        "Драйвер wintun.dll не найден",
                        style = MaterialTheme.typography.titleSmall,
                        fontWeight = FontWeight.SemiBold
                    )
                }
                Text(
                    "В готовом релизе Windows драйвер уже вшит. При запуске из исходников положите официальный wintun.dll (amd64) в папку bin/ рядом с проектом или переключитесь на внешний движок в Настройках.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                OutlinedButton(
                    onClick = { controller.refreshEngineAndPrivileges() },
                    contentPadding = PaddingValues(horizontal = 12.dp, vertical = 6.dp)
                ) {
                    Text("Проверить снова", style = MaterialTheme.typography.labelMedium)
                }
            }
        } else if (state.settings.backendMode == dev.warpscout.desktop.storage.TunnelBackendMode.EXTERNAL_AWG && !state.engine.available) {
            WarpCard(
                containerColor = MaterialTheme.colorScheme.errorContainer.copy(alpha = 0.45f),
                borderColor = warp.error.copy(alpha = 0.5f)
            ) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    Icon(Icons.Rounded.WarningAmber, contentDescription = null, tint = warp.error, modifier = Modifier.size(20.dp))
                    Text(
                        "Внешний AmneziaWG не найден",
                        style = MaterialTheme.typography.titleSmall,
                        color = MaterialTheme.colorScheme.onErrorContainer,
                        fontWeight = FontWeight.SemiBold
                    )
                }
                Text(
                    "Можно переключиться на встроенный туннель WarpScout (Wintun) — сторонние программы не понадобятся — или установить AmneziaWG.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    FilledTonalButton(
                        onClick = {
                            controller.updateSettings {
                                it.copy(backendMode = dev.warpscout.desktop.storage.TunnelBackendMode.BUILTIN_WINTUN)
                            }
                        },
                        contentPadding = PaddingValues(horizontal = 12.dp, vertical = 6.dp)
                    ) {
                        Text("Включить встроенный", style = MaterialTheme.typography.labelMedium)
                    }
                    OutlinedButton(
                        onClick = { DesktopPlatform.openUrl(EngineLocator.AMNEZIAWG_RELEASES_URL) },
                        contentPadding = PaddingValues(horizontal = 12.dp, vertical = 6.dp)
                    ) {
                        Text("Скачать AWG", style = MaterialTheme.typography.labelMedium)
                    }
                }
            }
        }

        // --- 2. Баннер уведомлений ---
        state.banner?.let { msg ->
            Surface(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(12.dp),
                color = if (state.bannerIsError) MaterialTheme.colorScheme.errorContainer.copy(alpha = 0.6f)
                else MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.45f)
            ) {
                Row(
                    modifier = Modifier.padding(horizontal = 12.dp, vertical = 9.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Text(
                        text = msg,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurface,
                        modifier = Modifier.weight(1f)
                    )
                    IconButton(onClick = { controller.clearBanner() }, modifier = Modifier.size(24.dp)) {
                        Icon(Icons.Rounded.Close, contentDescription = "Закрыть", modifier = Modifier.size(16.dp))
                    }
                }
            }
        }

        // --- 3. Главная карточка «Одна кнопка» ---
        WarpCard(
            containerColor = warp.surfaceLow,
            borderColor = ringColor.copy(alpha = if (phase == TunnelPhase.CONNECTED) 0.55f else 0.3f)
        ) {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(vertical = 10.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.spacedBy(14.dp)
            ) {
                val statusLabel = when (phase) {
                    TunnelPhase.CONNECTED -> {
                        val reg = state.tunnel.exitInfo.regionLabel().takeIf { it != "не определён" }
                        buildString {
                            append("Подключён")
                            if (reg != null) append(" · $reg")
                            if (state.tunnel.exitInfo.warpOn) append(" · warp=on")
                        }
                    }
                    TunnelPhase.SCANNING -> "Подбираю рабочую точку…"
                    TunnelPhase.CONNECTING -> "Подключаюсь…"
                    TunnelPhase.RECONNECTING -> "Меняю точку входа…"
                    TunnelPhase.ERROR -> state.tunnel.statusMessage
                    TunnelPhase.OFF -> "Туннель выключен"
                }

                StatusPill(text = statusLabel, dotColor = ringColor)

                // Центральный кликабельный щит с лисой и мягким ореолом.
                Box(
                    modifier = Modifier
                        .size(152.dp)
                        .scale(pulseScale),
                    contentAlignment = Alignment.Center
                ) {
                    Box(
                        modifier = Modifier
                            .size(148.dp)
                            .clip(CircleShape)
                            .background(
                                Brush.radialGradient(
                                    colors = listOf(
                                        ringColor.copy(alpha = if (phase == TunnelPhase.OFF) 0.10f else 0.28f),
                                        Color.Transparent
                                    )
                                )
                            )
                    )
                    Surface(
                        modifier = Modifier
                            .size(116.dp)
                            .clip(CircleShape)
                            .clickable { controller.onPrimaryButtonClick() },
                        shape = CircleShape,
                        color = Color(0xFF14110F),
                        border = BorderStroke(2.5.dp, ringColor)
                    ) {
                        Box(contentAlignment = Alignment.Center, modifier = Modifier.fillMaxSize()) {
                            if (shield != null) {
                                Image(
                                    bitmap = shield,
                                    contentDescription = "WarpScout",
                                    modifier = Modifier.size(86.dp)
                                )
                            } else {
                                Icon(
                                    Icons.Rounded.Shield,
                                    contentDescription = "WarpScout",
                                    tint = ringColor,
                                    modifier = Modifier.size(56.dp)
                                )
                            }
                        }
                    }
                }

                // Краткая строка текущего шага или точки.
                val subText = when {
                    state.scanning -> {
                        val progressPart = if (state.scanTotal > 0) "${state.scanDone}/${state.scanTotal} · " else ""
                        "$progressPart${state.scanStep}"
                    }
                    state.tunnel.isBusy -> state.tunnel.statusMessage
                    state.tunnel.isUp -> "${state.tunnel.activeEndpoint} · шум ${state.tunnel.activeJunk}"
                    state.tunnel.phase == TunnelPhase.ERROR -> state.tunnel.advice ?: state.tunnel.lastError.orEmpty()
                    state.hasConfig && state.settings.lastTuneEndpoint.isNotBlank() ->
                        "Готова точка: ${state.settings.lastTuneEndpoint} (${state.settings.lastTuneJunk})"
                    else -> "Нажмите кнопку — WarpScout сам найдёт точку Cloudflare и поднимет туннель"
                }

                Text(
                    text = subText,
                    style = MaterialTheme.typography.bodySmall,
                    color = if (phase == TunnelPhase.ERROR) warp.error else MaterialTheme.colorScheme.onSurfaceVariant,
                    textAlign = TextAlign.Center,
                    modifier = Modifier.padding(horizontal = 8.dp)
                )

                // Индикатор прогресса при поиске или подключении.
                if (state.scanning || state.tunnel.isBusy) {
                    if (state.scanning && state.scanTotal > 0) {
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
                }

                // Главная кнопка (одна, крупная, понятная).
                val buttonLabel = when {
                    phase == TunnelPhase.CONNECTED -> "Выключить туннель"
                    state.scanning -> "Остановить подбор"
                    state.tunnel.isBusy -> "Отменить подключение"
                    !state.hasConfig -> "Найти точку и подключиться"
                    else -> "Включить туннель"
                }

                val buttonColors = when (phase) {
                    TunnelPhase.CONNECTED -> ButtonDefaults.buttonColors(
                        containerColor = MaterialTheme.colorScheme.surfaceVariant,
                        contentColor = MaterialTheme.colorScheme.onSurface
                    )
                    TunnelPhase.SCANNING, TunnelPhase.CONNECTING, TunnelPhase.RECONNECTING -> ButtonDefaults.buttonColors(
                        containerColor = MaterialTheme.colorScheme.errorContainer,
                        contentColor = MaterialTheme.colorScheme.onErrorContainer
                    )
                    else -> ButtonDefaults.buttonColors(
                        containerColor = warp.accentOrange,
                        contentColor = Color.White
                    )
                }

                Button(
                    onClick = { controller.onPrimaryButtonClick() },
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(52.dp),
                    shape = RoundedCornerShape(14.dp),
                    colors = buttonColors
                ) {
                    Icon(
                        imageVector = when {
                            phase == TunnelPhase.CONNECTED -> Icons.Rounded.PowerSettingsNew
                            state.scanning || state.tunnel.isBusy -> Icons.Rounded.Stop
                            !state.hasConfig -> Icons.Rounded.Radar
                            else -> Icons.Rounded.PowerSettingsNew
                        },
                        contentDescription = null,
                        modifier = Modifier.size(20.dp)
                    )
                    Spacer(Modifier.width(8.dp))
                    Text(buttonLabel, fontSize = 15.sp, fontWeight = FontWeight.SemiBold)
                }
            }
        }

        // --- 4. Компактная живая карточка активного туннеля ---
        if (state.tunnel.isUp) {
            WarpCard {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    MetricChip(
                        label = "Вниз",
                        value = Formatters.bytes(state.tunnel.rxBytes),
                        sub = Formatters.speed(state.tunnel.rxSpeedBps)
                    )
                    MetricChip(
                        label = "Вверх",
                        value = Formatters.bytes(state.tunnel.txBytes),
                        sub = Formatters.speed(state.tunnel.txSpeedBps)
                    )
                    val uptimeSec = if (state.tunnel.connectedSinceMs > 0L) (nowMs - state.tunnel.connectedSinceMs) / 1000L else 0L
                    MetricChip(
                        label = "Время",
                        value = Formatters.duration(uptimeSec),
                        sub = if (state.tunnel.exitInfo.ip.isNotBlank()) state.tunnel.exitInfo.ip else "активен"
                    )
                }

                if (state.tunnel.secondExitActive) {
                    Surface(
                        shape = RoundedCornerShape(8.dp),
                        color = warp.ok.copy(alpha = 0.12f),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Row(
                            modifier = Modifier.padding(horizontal = 10.dp, vertical = 6.dp),
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(6.dp)
                        ) {
                            Icon(Icons.Rounded.AltRoute, contentDescription = null, tint = warp.ok, modifier = Modifier.size(16.dp))
                            Text(
                                "Второй выход активен: ${state.tunnel.secondExitServer}",
                                style = MaterialTheme.typography.labelSmall,
                                color = warp.ok
                            )
                        }
                    }
                }

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    OutlinedButton(
                        onClick = { controller.switchToNextEndpoint() },
                        modifier = Modifier.weight(1f),
                        contentPadding = PaddingValues(horizontal = 10.dp, vertical = 8.dp),
                        shape = RoundedCornerShape(10.dp)
                    ) {
                        Icon(Icons.Rounded.SwapHoriz, contentDescription = null, modifier = Modifier.size(16.dp))
                        Spacer(Modifier.width(5.dp))
                        Text("Другая точка", style = MaterialTheme.typography.labelMedium, maxLines = 1)
                    }
                    OutlinedButton(
                        onClick = {
                            controller.runSiteAndDnsCheck()
                            onNavigateToScan()
                        },
                        modifier = Modifier.weight(1f),
                        contentPadding = PaddingValues(horizontal = 10.dp, vertical = 8.dp),
                        shape = RoundedCornerShape(10.dp)
                    ) {
                        Icon(Icons.Rounded.FactCheck, contentDescription = null, modifier = Modifier.size(16.dp))
                        Spacer(Modifier.width(5.dp))
                        Text("Проверить сайты", style = MaterialTheme.typography.labelMedium, maxLines = 1)
                    }
                }
            }
        }

        // --- 5. Лучшие конфиги (Топ-3) — переключение одним кликом ---
        if (state.shortlist.isNotEmpty()) {
            WarpCard {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    SectionHeader(
                        title = "Лучшие конфиги (Топ-3)",
                        subtitle = if (state.settings.lastTuneAtMs > 0L)
                            "Подбор ${Formatters.ago(state.settings.lastTuneAtMs)} · клик переключает сразу"
                        else "Переключение одним нажатием без скана"
                    )
                    TextButton(
                        onClick = { controller.runScan(autoConnectAfter = state.tunnel.isUp) },
                        enabled = !state.scanning,
                        contentPadding = PaddingValues(horizontal = 8.dp, vertical = 4.dp)
                    ) {
                        Text("Обновить", style = MaterialTheme.typography.labelMedium)
                    }
                }

                state.shortlist.forEachIndexed { idx, entry ->
                    val isSelected = idx == state.settings.activeShortlistIndex
                    val isActiveNow = state.tunnel.isUp && state.tunnel.activeEndpoint == entry.endpoint
                    Surface(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clip(RoundedCornerShape(10.dp))
                            .clickable(enabled = !state.scanning) { controller.switchToShortlist(idx) },
                        shape = RoundedCornerShape(10.dp),
                        color = if (isActiveNow) warp.ok.copy(alpha = 0.13f)
                        else if (isSelected) MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.25f)
                        else warp.surfaceHigh.copy(alpha = 0.6f),
                        border = BorderStroke(
                            1.dp,
                            if (isActiveNow) warp.ok.copy(alpha = 0.5f)
                            else if (isSelected) MaterialTheme.colorScheme.primary.copy(alpha = 0.4f)
                            else Color.Transparent
                        )
                    ) {
                        Row(
                            modifier = Modifier.padding(horizontal = 10.dp, vertical = 8.dp),
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.SpaceBetween
                        ) {
                            Column(modifier = Modifier.weight(1f)) {
                                Text(
                                    text = "${idx + 1}) ${entry.endpoint} · ${entry.junkName}",
                                    style = MaterialTheme.typography.bodyMedium,
                                    fontWeight = if (isActiveNow || isSelected) FontWeight.SemiBold else FontWeight.Normal,
                                    maxLines = 1,
                                    overflow = TextOverflow.Ellipsis
                                )
                                val detail = buildString {
                                    if (entry.resourcesTotal > 0) append("сайты ${entry.resourcesOk}/${entry.resourcesTotal} · ")
                                    if (entry.score > 0) append("${entry.score} б.")
                                    if (isActiveNow) append(if (isNotEmpty()) " · работает" else "работает")
                                }
                                if (detail.isNotBlank()) {
                                    Text(
                                        text = detail,
                                        style = MaterialTheme.typography.labelSmall,
                                        color = if (isActiveNow) warp.ok else MaterialTheme.colorScheme.onSurfaceVariant
                                    )
                                }
                            }
                            Icon(
                                imageVector = if (isActiveNow) Icons.Rounded.CheckCircle else Icons.Rounded.PlayArrow,
                                contentDescription = null,
                                tint = if (isActiveNow) warp.ok else MaterialTheme.colorScheme.onSurfaceVariant,
                                modifier = Modifier.size(18.dp)
                            )
                        }
                    }
                }
            }
        } else if (!state.scanning) {
            // Быстрая подсказка для первого запуска.
            Row(
                modifier = Modifier.fillMaxWidth().padding(horizontal = 4.dp),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    state.backendTitle,
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                TextButton(onClick = onNavigateToSettings, contentPadding = PaddingValues(horizontal = 8.dp, vertical = 2.dp)) {
                    Text("Настройки / импорт .conf", style = MaterialTheme.typography.labelSmall)
                }
            }
        }
    }
}

@Composable
private fun MetricChip(label: String, value: String, sub: String) {
    Column(horizontalAlignment = Alignment.Start) {
        Text(label, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Text(value, style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.SemiBold)
        Text(sub, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}
