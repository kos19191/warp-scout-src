package dev.warpscout.desktop.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import dev.warpscout.desktop.engine.DesktopController
import dev.warpscout.desktop.engine.DesktopUiState
import dev.warpscout.desktop.engine.Formatters
import dev.warpscout.desktop.engine.LogLevel

/**
 * Вкладка «Журнал»: пошаговая диагностика на русском языке с отметками времени,
 * фильтрацией, копированием, сохранением в файл и объяснением причин отказов.
 */
@Composable
fun LogScreen(state: DesktopUiState, controller: DesktopController) {
    val warp = LocalWarpColors.current
    var query by remember { mutableStateOf("") }
    val filtered = remember(state.logs, query) {
        val q = query.trim().lowercase()
        if (q.isEmpty()) state.logs else state.logs.filter { q in it.message.lowercase() }
    }
    val listState = rememberLazyListState()

    LaunchedEffect(filtered.size) {
        if (filtered.isNotEmpty()) {
            listState.scrollToItem(filtered.lastIndex)
        }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(horizontal = 16.dp, vertical = 12.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp)
    ) {
        // Совет по последней ошибке, если есть.
        state.tunnel.advice?.let { advice ->
            WarpCard(
                containerColor = MaterialTheme.colorScheme.errorContainer.copy(alpha = 0.4f),
                borderColor = warp.error.copy(alpha = 0.45f)
            ) {
                Text("Почему так и что делать:", style = MaterialTheme.typography.labelMedium, fontWeight = FontWeight.SemiBold, color = warp.error)
                Text(advice, style = MaterialTheme.typography.bodySmall)
            }
        }

        // Поиск + кнопки управления
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(6.dp)
        ) {
            OutlinedTextField(
                value = query,
                onValueChange = { query = it },
                placeholder = { Text("Поиск по журналу…", style = MaterialTheme.typography.bodySmall) },
                singleLine = true,
                modifier = Modifier.weight(1f),
                textStyle = MaterialTheme.typography.bodySmall
            )
            IconButton(
                onClick = {
                    DesktopPlatform.copyToClipboard(controller.exportLogsText())
                    controller.showBanner("Журнал скопирован в буфер обмена")
                }
            ) {
                Icon(Icons.Rounded.ContentCopy, contentDescription = "Копировать журнал")
            }
            IconButton(
                onClick = {
                    DesktopPlatform.chooseSaveFile("Сохранить журнал", "warpscout-log.txt")?.let { file ->
                        runCatching { file.writeText(controller.exportLogsText(), Charsets.UTF_8) }
                            .onSuccess { controller.showBanner("Журнал сохранён: ${file.name}") }
                    }
                }
            ) {
                Icon(Icons.Rounded.Save, contentDescription = "Сохранить журнал")
            }
            IconButton(onClick = { controller.clearLogs() }) {
                Icon(Icons.Rounded.DeleteOutline, contentDescription = "Очистить журнал")
            }
        }

        // Поле вывода журнала
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .weight(1f)
                .clip(RoundedCornerShape(14.dp))
                .background(warp.surfaceLow)
                .padding(10.dp)
        ) {
            if (filtered.isEmpty()) {
                Text(
                    "Журнал пуст. Нажмите кнопку подключения на «Главной» или запустите подбор — каждый шаг появится здесь.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.align(Alignment.Center)
                )
            } else {
                LazyColumn(
                    state = listState,
                    verticalArrangement = Arrangement.spacedBy(4.dp),
                    modifier = Modifier.fillMaxSize()
                ) {
                    items(filtered) { entry ->
                        val color = when (entry.level) {
                            LogLevel.OK -> warp.ok
                            LogLevel.WARN -> warp.warn
                            LogLevel.ERROR -> warp.error
                            LogLevel.INFO -> MaterialTheme.colorScheme.onSurface.copy(alpha = 0.88f)
                        }
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.spacedBy(8.dp)
                        ) {
                            Text(
                                text = Formatters.timeOf(entry.timestampMs),
                                fontFamily = FontFamily.Monospace,
                                fontSize = 11.sp,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                            Text(
                                text = entry.message,
                                fontFamily = FontFamily.Monospace,
                                fontSize = 11.5.sp,
                                lineHeight = 15.sp,
                                color = color,
                                modifier = Modifier.weight(1f)
                            )
                        }
                    }
                }
            }
        }
    }
}
