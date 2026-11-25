package dev.warpscout.desktop.ui

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.graphics.Color
import dev.warpscout.desktop.storage.ThemeMode

/**
 * Фирменная палитра WarpScout: перенесена из Android `colors.xml` / `values-night/colors.xml`.
 * Тёплая нейтраль вместо холодной синеватой, чтобы фирменный WARP-оранжевый выглядел органично.
 */
data class WarpSemanticColors(
    val ok: Color,
    val warn: Color,
    val error: Color,
    val off: Color,
    val accentOrange: Color,
    val surfaceLow: Color,
    val surfaceCard: Color,
    val surfaceHigh: Color
)

private val DarkSemantic = WarpSemanticColors(
    ok = Color(0xFF7BD88F),
    warn = Color(0xFFD7BFA0),
    error = Color(0xFFFFB4AB),
    off = Color(0xFFB0B4BA),
    accentOrange = Color(0xFFF97316),
    surfaceLow = Color(0xFF1C1916),
    surfaceCard = Color(0xFF201D1A),
    surfaceHigh = Color(0xFF2B2724)
)

private val LightSemantic = WarpSemanticColors(
    ok = Color(0xFF1B5E20),
    warn = Color(0xFF8D6E63),
    error = Color(0xFFB3261E),
    off = Color(0xFF5F6368),
    accentOrange = Color(0xFFC2410C),
    surfaceLow = Color(0xFFF9F4EF),
    surfaceCard = Color(0xFFF4EDE6),
    surfaceHigh = Color(0xFFEEE5DD)
)

val LocalWarpColors = staticCompositionLocalOf { DarkSemantic }

private val WarpDarkScheme = darkColorScheme(
    primary = Color(0xFFFFB68A),
    onPrimary = Color(0xFF532200),
    primaryContainer = Color(0xFF763300),
    onPrimaryContainer = Color(0xFFFFDCC2),
    secondary = Color(0xFFCDC5BC),
    onSecondary = Color(0xFF342F2A),
    secondaryContainer = Color(0xFF4B453F),
    onSecondaryContainer = Color(0xFFE9E1D9),
    background = Color(0xFF14120F),
    onBackground = Color(0xFFE9E1D9),
    surface = Color(0xFF14120F),
    onSurface = Color(0xFFE9E1D9),
    surfaceVariant = Color(0xFF2B2724),
    onSurfaceVariant = Color(0xFFD3C8BE),
    outline = Color(0xFF9C8F84),
    outlineVariant = Color(0xFF4E453D),
    error = Color(0xFFFFB4AB),
    onError = Color(0xFF690005),
    errorContainer = Color(0xFF93000A),
    onErrorContainer = Color(0xFFFFDAD6)
)

private val WarpLightScheme = lightColorScheme(
    primary = Color(0xFFC2410C),
    onPrimary = Color(0xFFFFFFFF),
    primaryContainer = Color(0xFFFFDCC2),
    onPrimaryContainer = Color(0xFF3C1500),
    secondary = Color(0xFF54504B),
    onSecondary = Color(0xFFFFFFFF),
    secondaryContainer = Color(0xFFE9E1D9),
    onSecondaryContainer = Color(0xFF1F1B17),
    background = Color(0xFFFCF9F6),
    onBackground = Color(0xFF1C1B19),
    surface = Color(0xFFFCF9F6),
    onSurface = Color(0xFF1C1B19),
    surfaceVariant = Color(0xFFEFE7DF),
    onSurfaceVariant = Color(0xFF4E453D),
    outline = Color(0xFF80756B),
    outlineVariant = Color(0xFFD3C8BE),
    error = Color(0xFFB3261E),
    onError = Color(0xFFFFFFFF),
    errorContainer = Color(0xFFF9DEDC),
    onErrorContainer = Color(0xFF410E0B)
)

@Composable
fun WarpScoutTheme(
    mode: ThemeMode,
    content: @Composable () -> Unit
) {
    val isDark = when (mode) {
        ThemeMode.DARK -> true
        ThemeMode.LIGHT -> false
        ThemeMode.SYSTEM -> isSystemInDarkTheme()
    }
    val colors = if (isDark) WarpDarkScheme else WarpLightScheme
    val semantic = if (isDark) DarkSemantic else LightSemantic
    CompositionLocalProvider(LocalWarpColors provides semantic) {
        MaterialTheme(
            colorScheme = colors,
            content = content
        )
    }
}
