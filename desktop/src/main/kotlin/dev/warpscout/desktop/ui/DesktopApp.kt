package dev.warpscout.desktop.ui

import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import dev.warpscout.desktop.engine.DesktopController
import dev.warpscout.desktop.storage.ThemeMode
import dev.warpscout.desktop.tunnel.TunnelPhase

enum class DesktopTab(val title: String, val icon: ImageVector) {
    HOME("Главная", Icons.Rounded.PowerSettingsNew),
    SCAN("Подбор", Icons.Rounded.Radar),
    ROUTES("Маршруты", Icons.Rounded.AltRoute),
    SETTINGS("Настройки", Icons.Rounded.Tune),
    LOG("Журнал", Icons.Rounded.Terminal)
}

@Composable
fun DesktopApp(
    controller: DesktopController,
    trayAvailable: Boolean,
    onMinimizeToTray: () -> Unit
) {
    val state by controller.state.collectAsState()
    var activeTab by remember { mutableStateOf(DesktopTab.HOME) }

    WarpScoutTheme(mode = state.settings.theme) {
        val warp = LocalWarpColors.current
        val shield = rememberFoxShieldBitmap()
        val phase = state.effectivePhase
        val dotColor = when (phase) {
            TunnelPhase.CONNECTED -> warp.ok
            TunnelPhase.CONNECTING, TunnelPhase.RECONNECTING, TunnelPhase.SCANNING -> warp.accentOrange
            TunnelPhase.ERROR -> warp.error
            TunnelPhase.OFF -> warp.off
        }

        Scaffold(
            containerColor = MaterialTheme.colorScheme.background,
            topBar = {
                Surface(
                    color = warp.surfaceLow,
                    tonalElevation = 0.dp
                ) {
                    Column {
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(horizontal = 16.dp, vertical = 10.dp),
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.SpaceBetween
                        ) {
                            Row(
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.spacedBy(10.dp)
                            ) {
                                if (shield != null) {
                                    Image(
                                        bitmap = shield,
                                        contentDescription = null,
                                        modifier = Modifier.size(32.dp)
                                    )
                                }
                                Column {
                                    Row(
                                        verticalAlignment = Alignment.CenterVertically,
                                        horizontalArrangement = Arrangement.spacedBy(6.dp)
                                    ) {
                                        Text(
                                            "WarpScout",
                                            style = MaterialTheme.typography.titleMedium,
                                            fontWeight = FontWeight.Bold
                                        )
                                        Box(
                                            modifier = Modifier
                                                .size(8.dp)
                                                .clip(CircleShape)
                                                .background(dotColor)
                                        )
                                    }
                                    Text(
                                        text = when (phase) {
                                            TunnelPhase.CONNECTED -> state.tunnel.activeEndpoint
                                            TunnelPhase.SCANNING -> "Идёт подбор…"
                                            TunnelPhase.CONNECTING -> "Подключение…"
                                            TunnelPhase.RECONNECTING -> "Переподключение…"
                                            TunnelPhase.ERROR -> "Ошибка"
                                            TunnelPhase.OFF -> "Windows · v${state.update.currentVersion}"
                                        },
                                        style = MaterialTheme.typography.labelSmall,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant
                                    )
                                }
                            }

                            Row(verticalAlignment = Alignment.CenterVertically) {
                                IconButton(
                                    onClick = {
                                        val nextTheme = when (state.settings.theme) {
                                            ThemeMode.DARK -> ThemeMode.LIGHT
                                            ThemeMode.LIGHT -> ThemeMode.DARK
                                            ThemeMode.SYSTEM -> ThemeMode.DARK
                                        }
                                        controller.updateSettings { it.copy(theme = nextTheme) }
                                    }
                                ) {
                                    Icon(
                                        imageVector = if (state.settings.theme == ThemeMode.LIGHT) Icons.Rounded.DarkMode else Icons.Rounded.LightMode,
                                        contentDescription = "Сменить тему",
                                        modifier = Modifier.size(19.dp)
                                    )
                                }
                                if (trayAvailable) {
                                    IconButton(onClick = onMinimizeToTray) {
                                        Icon(
                                            imageVector = Icons.Rounded.KeyboardArrowDown,
                                            contentDescription = "Свернуть в трей",
                                            modifier = Modifier.size(22.dp)
                                        )
                                    }
                                }
                            }
                        }
                        HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.35f))
                    }
                }
            },
            bottomBar = {
                NavigationBar(
                    containerColor = warp.surfaceLow,
                    tonalElevation = 0.dp
                ) {
                    DesktopTab.entries.forEach { tab ->
                        NavigationBarItem(
                            selected = activeTab == tab,
                            onClick = { activeTab = tab },
                            icon = { Icon(tab.icon, contentDescription = tab.title, modifier = Modifier.size(20.dp)) },
                            label = { Text(tab.title, fontSize = 10.5.sp, maxLines = 1) },
                            colors = NavigationBarItemDefaults.colors(
                                selectedIconColor = warp.accentOrange,
                                selectedTextColor = warp.accentOrange,
                                indicatorColor = warp.accentOrange.copy(alpha = 0.14f)
                            )
                        )
                    }
                }
            }
        ) { innerPadding ->
            Box(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(innerPadding)
            ) {
                when (activeTab) {
                    DesktopTab.HOME -> HomeScreen(
                        state = state,
                        controller = controller,
                        onNavigateToScan = { activeTab = DesktopTab.SCAN },
                        onNavigateToSettings = { activeTab = DesktopTab.SETTINGS }
                    )
                    DesktopTab.SCAN -> ScanScreen(state = state, controller = controller)
                    DesktopTab.ROUTES -> RoutesScreen(state = state, controller = controller)
                    DesktopTab.SETTINGS -> SettingsScreen(state = state, controller = controller)
                    DesktopTab.LOG -> LogScreen(state = state, controller = controller)
                }
            }
        }
    }
}
