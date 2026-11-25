package dev.warpscout.desktop

import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.graphics.painter.BitmapPainter
import androidx.compose.ui.graphics.toComposeImageBitmap
import androidx.compose.ui.unit.DpSize
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Window
import androidx.compose.ui.window.WindowPosition
import androidx.compose.ui.window.application
import androidx.compose.ui.window.rememberWindowState
import dev.warpscout.desktop.engine.DesktopController
import dev.warpscout.desktop.storage.DesktopPaths
import dev.warpscout.desktop.storage.DesktopStore
import dev.warpscout.desktop.tray.DesktopTray
import dev.warpscout.desktop.ui.DesktopApp
import kotlinx.coroutines.flow.collectLatest
import java.awt.Dimension
import java.io.File
import java.io.RandomAccessFile
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.nio.channels.FileLock
import javax.imageio.ImageIO

/**
 * Точка входа WarpScout Desktop (Windows).
 *
 * • Гарантирует один запущенный экземпляр: повторный запуск открывает уже работающее окно из трея.
 * • Поддерживает аргумент `--minimized` (используется при автозапуске Windows).
 * • Подключает системный трей и корректно останавливает туннель при выходе.
 */
fun main(args: Array<String>) {
    val startMinimized = args.any { it.equals("--minimized", ignoreCase = true) }
    val autoConnect = args.any { it.equals("--autoconnect", ignoreCase = true) }
    val noAutoElevate = args.any { it.equals("--no-elevate", ignoreCase = true) }

    // Резервный автозапрос UAC при запуске без встроенного манифеста (например, если exe запустили без него).
    if (!noAutoElevate && dev.warpscout.desktop.tunnel.WindowsAutostart.isWindows()) {
        val elevated = runCatching { dev.warpscout.desktop.tunnel.ProcessCommandRunner().isElevated() }.getOrDefault(true)
        if (!elevated) {
            val forwardArgs = args.toList() + "--no-elevate"
            if (dev.warpscout.desktop.tunnel.WindowsAutostart.relaunchElevated(forwardArgs)) {
                kotlin.system.exitProcess(0)
            }
        }
    }

    val paths = DesktopPaths.resolveDefault()
    val singleInstance = SingleInstanceGuard(paths.lockFile)

    if (!singleInstance.tryAcquire()) {
        // Второй экземпляр: просим первый показать окно и выходим.
        singleInstance.notifyExistingInstance()
        return
    }

    val store = DesktopStore(paths)
    var trayRef: DesktopTray? = null
    lateinit var controller: DesktopController
    controller = DesktopController(
        store = store,
        autoConnectRequested = autoConnect,
        onTrayNotify = { title, message -> trayRef?.notify(title, message) },
        onRelaunchElevated = { extraArgs ->
            singleInstance.release()
            val launched = dev.warpscout.desktop.tunnel.WindowsAutostart.relaunchElevated(extraArgs)
            if (launched) {
                runCatching { trayRef?.remove() }
                runCatching { controller.shutdown(disconnectTunnel = false) }
                kotlin.system.exitProcess(0)
            } else {
                // Пользователь отменил UAC — возвращаем замок экземпляра обратно.
                singleInstance.tryAcquire()
                false
            }
        }
    )

    Runtime.getRuntime().addShutdownHook(Thread {
        runCatching { trayRef?.remove() }
        runCatching { controller.shutdown() }
        runCatching { singleInstance.release() }
    })

    application {
        var windowVisible by remember { mutableStateOf(!startMinimized) }
        val windowState = rememberWindowState(
            size = DpSize(468.dp, 710.dp),
            position = WindowPosition(Alignment.Center)
        )

        val exitAll = remember {
            {
                trayRef?.remove()
                controller.shutdown()
                singleInstance.release()
                exitApplication()
            }
        }

        val trayAvailable = remember {
            val tray = DesktopTray(
                controller = controller,
                onToggleWindow = { windowVisible = !windowVisible },
                onShowWindow = { windowVisible = true },
                onExit = exitAll
            )
            val ok = tray.install()
            if (ok) trayRef = tray
            ok
        }

        // Если запущен второй экземпляр, поднимаем окно из трея.
        LaunchedEffect(Unit) {
            singleInstance.startWakeListener { windowVisible = true }
        }

        // Синхронизируем меню и цвет иконки трея с состоянием приложения.
        LaunchedEffect(controller) {
            controller.state.collectLatest { st ->
                trayRef?.update(st)
            }
        }

        val windowIcon = remember {
            runCatching {
                SingleInstanceGuard::class.java.getResourceAsStream("/icons/warpscout-icon.png")
                    ?.use { ImageIO.read(it)?.toComposeImageBitmap() }
                    ?.let { BitmapPainter(it) }
            }.getOrNull()
        }

        if (windowVisible) {
            Window(
                onCloseRequest = {
                    val minimizeToTray = controller.state.value.settings.minimizeToTrayOnClose && trayAvailable
                    if (minimizeToTray) {
                        windowVisible = false
                    } else {
                        exitAll()
                    }
                },
                state = windowState,
                title = "WarpScout",
                icon = windowIcon,
                resizable = true
            ) {
                LaunchedEffect(Unit) {
                    window.minimumSize = Dimension(420, 620)
                }
                DesktopApp(
                    controller = controller,
                    trayAvailable = trayAvailable,
                    onMinimizeToTray = { windowVisible = false }
                )
            }
        }
    }
}

/** Простой межпроцессный замок + локальный loopback-сигнал «покажи окно». */
private class SingleInstanceGuard(private val lockFile: File) {
    private var channelLock: FileLock? = null
    private var raf: RandomAccessFile? = null
    private var server: ServerSocket? = null
    private val portFile: File get() = File(lockFile.parentFile, "instance.port")

    fun tryAcquire(): Boolean = runCatching {
        lockFile.parentFile?.mkdirs()
        val f = RandomAccessFile(lockFile, "rw")
        val lock = f.channel.tryLock() ?: run {
            f.close()
            return false
        }
        raf = f
        channelLock = lock
        true
    }.getOrDefault(true)

    fun startWakeListener(onWake: () -> Unit) {
        val srv = runCatching { ServerSocket(0, 4, InetAddress.getLoopbackAddress()) }.getOrNull() ?: return
        server = srv
        runCatching { portFile.writeText(srv.localPort.toString()) }
        Thread {
            while (!srv.isClosed) {
                runCatching {
                    srv.accept().use {
                        onWake()
                    }
                }
            }
        }.apply {
            name = "warpscout-wake"
            isDaemon = true
            start()
        }
    }

    fun notifyExistingInstance() {
        val port = runCatching { portFile.readText().trim().toInt() }.getOrNull() ?: return
        runCatching { Socket(InetAddress.getLoopbackAddress(), port).use { } }
    }

    fun release() {
        runCatching { server?.close() }
        runCatching { channelLock?.release() }
        runCatching { raf?.close() }
        runCatching { portFile.delete() }
    }
}
