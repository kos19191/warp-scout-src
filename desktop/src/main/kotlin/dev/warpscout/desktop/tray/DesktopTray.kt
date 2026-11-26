package dev.warpscout.desktop.tray

import dev.warpscout.desktop.engine.DesktopController
import dev.warpscout.desktop.engine.DesktopUiState
import dev.warpscout.desktop.tunnel.TunnelPhase
import java.awt.BasicStroke
import java.awt.Color
import java.awt.Graphics2D
import java.awt.Image
import java.awt.Menu
import java.awt.MenuItem
import java.awt.PopupMenu
import java.awt.RenderingHints
import java.awt.SystemTray
import java.awt.TrayIcon
import java.awt.event.MouseAdapter
import java.awt.event.MouseEvent
import java.awt.image.BufferedImage
import javax.imageio.ImageIO
import javax.swing.SwingUtilities

/**
 * Иконка WarpScout в области уведомлений (системном трее Windows).
 *
 * • Левый клик — показать / скрыть главное окно.
 * • Правый клик — меню: статус, Вкл/Выкл в один клик, смена точки, Топ-3 конфигов, проверка сайтов, Выход.
 * • Цвет точки на значке отражает состояние туннеля (зелёный / оранжевый / красный / серый).
 */
class DesktopTray(
    private val controller: DesktopController,
    private val onToggleWindow: () -> Unit,
    private val onShowWindow: () -> Unit,
    private val onExit: () -> Unit
) {
    private var trayIcon: TrayIcon? = null
    private val baseIcon: BufferedImage? = loadBaseIcon()
    private val iconCache = HashMap<TunnelPhase, Image>()

    private val popup = PopupMenu()
    private val itemStatus = MenuItem("WilyScout · Выключен").apply { isEnabled = false }
    private val itemPrimary = MenuItem("Найти точку и подключиться")
    private val itemNext = MenuItem("Другая точка входа")
    private val menuTop3 = Menu("Лучшие конфиги")
    private val itemCheck = MenuItem("Проверить сайты")
    private val itemUpdate = MenuItem("Проверить обновления")
    private val itemShow = MenuItem("Открыть окно")
    private val itemExit = MenuItem("Выход")

    private var lastPhase: TunnelPhase? = null
    private var lastMenuSignature: String = ""

    fun install(): Boolean {
        if (!SystemTray.isSupported()) return false
        return runCatching {
            itemPrimary.addActionListener { controller.onPrimaryButtonClick() }
            itemNext.addActionListener { controller.switchToNextEndpoint() }
            itemCheck.addActionListener {
                onShowWindow()
                controller.runSiteAndDnsCheck()
            }
            itemUpdate.addActionListener {
                onShowWindow()
                if (controller.state.value.update.available != null) {
                    controller.downloadAndInstallUpdate()
                } else {
                    controller.checkForUpdates(manual = true)
                }
            }
            itemShow.addActionListener { onShowWindow() }
            itemExit.addActionListener { onExit() }

            popup.add(itemStatus)
            popup.addSeparator()
            popup.add(itemPrimary)
            popup.add(itemNext)
            popup.add(menuTop3)
            popup.add(itemCheck)
            popup.add(itemUpdate)
            popup.addSeparator()
            popup.add(itemShow)
            popup.add(itemExit)

            val icon = TrayIcon(renderIcon(TunnelPhase.OFF), "WilyScout — Выключен", popup).apply {
                isImageAutoSize = true
                addMouseListener(object : MouseAdapter() {
                    override fun mouseClicked(e: MouseEvent) {
                        if (e.button == MouseEvent.BUTTON1) {
                            onToggleWindow()
                        }
                    }
                })
            }
            SystemTray.getSystemTray().add(icon)
            trayIcon = icon
            true
        }.getOrDefault(false)
    }

    fun update(state: DesktopUiState) {
        val icon = trayIcon ?: return
        val phase = state.effectivePhase
        val sig = buildString {
            append(phase.name).append('|')
            append(state.hasConfig).append('|')
            append(state.tunnel.activeEndpoint).append('|')
            append(state.tunnel.exitInfo.regionLabel()).append('|')
            append(state.update.available?.version.orEmpty()).append('|')
            append(state.shortlist.joinToString(",") { "${it.endpoint}:${it.junkName}" })
        }
        if (sig == lastMenuSignature) return
        lastMenuSignature = sig

        SwingUtilities.invokeLater {
            if (lastPhase != phase) {
                icon.image = renderIcon(phase)
                lastPhase = phase
            }

            val region = state.tunnel.exitInfo.regionLabel().takeIf { it != "не определён" }
            val statusLine = when (phase) {
                TunnelPhase.CONNECTED -> buildString {
                    append("Подключён")
                    if (region != null) append(" · $region")
                    if (state.tunnel.exitInfo.warpOn) append(" · warp=on")
                }
                TunnelPhase.CONNECTING -> "Подключение…"
                TunnelPhase.RECONNECTING -> "Переподключение…"
                TunnelPhase.SCANNING -> "Идёт подбор точки…"
                TunnelPhase.ERROR -> "Ошибка подключения"
                TunnelPhase.OFF -> "Выключен"
            }

            icon.toolTip = "WilyScout — $statusLine"
            itemStatus.label = "WilyScout: $statusLine"

            itemPrimary.label = when {
                phase == TunnelPhase.CONNECTED -> "Выключить туннель"
                phase == TunnelPhase.SCANNING || phase == TunnelPhase.CONNECTING || phase == TunnelPhase.RECONNECTING -> "Остановить"
                !state.hasConfig -> "Найти точку и подключиться"
                else -> "Включить туннель"
            }

            itemNext.isEnabled = phase == TunnelPhase.CONNECTED
            itemUpdate.label = state.update.available?.let { "Обновить до ${it.version}" } ?: "Проверить обновления"

            menuTop3.removeAll()
            if (state.shortlist.isEmpty()) {
                menuTop3.add(MenuItem("Список пуст — запустите подбор").apply { isEnabled = false })
            } else {
                state.shortlist.forEachIndexed { idx, entry ->
                    val activeMark = if (state.tunnel.isUp && state.tunnel.activeEndpoint == entry.endpoint) "● " else ""
                    val mi = MenuItem("$activeMark${idx + 1}) ${entry.endpoint} · ${entry.junkName}")
                    mi.addActionListener { controller.switchToShortlist(idx) }
                    menuTop3.add(mi)
                }
            }
        }
    }

    fun notify(title: String, message: String) {
        val icon = trayIcon ?: return
        SwingUtilities.invokeLater {
            runCatching { icon.displayMessage(title, message, TrayIcon.MessageType.INFO) }
        }
    }

    fun remove() {
        val icon = trayIcon ?: return
        trayIcon = null
        runCatching { SystemTray.getSystemTray().remove(icon) }
    }

    private fun renderIcon(phase: TunnelPhase): Image = iconCache.getOrPut(phase) {
        val size = 32
        val img = BufferedImage(size, size, BufferedImage.TYPE_INT_ARGB)
        val g = img.createGraphics() as Graphics2D
        g.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON)
        g.setRenderingHint(RenderingHints.KEY_INTERPOLATION, RenderingHints.VALUE_INTERPOLATION_BICUBIC)
        if (baseIcon != null) {
            g.drawImage(baseIcon, 0, 0, size, size, null)
        } else {
            g.color = Color(0xC2, 0x41, 0x0C)
            g.fillOval(2, 2, size - 4, size - 4)
        }

        // Индикатор состояния в правом нижнем углу.
        val badgeColor = when (phase) {
            TunnelPhase.CONNECTED -> Color(0x22, 0xC5, 0x5E)
            TunnelPhase.CONNECTING, TunnelPhase.RECONNECTING, TunnelPhase.SCANNING -> Color(0xF9, 0x73, 0x16)
            TunnelPhase.ERROR -> Color(0xEF, 0x44, 0x44)
            TunnelPhase.OFF -> Color(0x8A, 0x8F, 0x98)
        }
        val d = 11
        val x = size - d - 1
        val y = size - d - 1
        g.color = Color(0x14, 0x12, 0x0F)
        g.fillOval(x - 1, y - 1, d + 2, d + 2)
        g.color = badgeColor
        g.fillOval(x, y, d, d)
        g.stroke = BasicStroke(1.2f)
        g.color = Color(0xFF, 0xFF, 0xFF, 180)
        g.drawOval(x, y, d, d)
        g.dispose()
        img
    }

    private fun loadBaseIcon(): BufferedImage? = runCatching {
        javaClass.getResourceAsStream("/icons/warpscout-icon-small.png")?.use { ImageIO.read(it) }
    }.getOrNull()
}
