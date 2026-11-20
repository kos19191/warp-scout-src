package dev.warpscout.app.tunnel

import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import dev.warpscout.app.CrashLog
import dev.warpscout.app.MainActivity
import dev.warpscout.app.Prefs
import dev.warpscout.app.R
import dev.warpscout.app.TunnelDebug
import dev.warpscout.app.status.ServiceSettingsStore
import dev.warpscout.app.status.TunnelStatusBus

/**
 * Плитка в «шторке» (быстрые настройки).
 *
 * * **Нажатие** — подключить последний рабочий конфиг тем же путём, что и кнопка «Подключить»
 *   в приложении: берём [Prefs.lastConfigText] (то, чем туннель реально поднимался в прошлый раз)
 *   и стартуем сервис. Повторное нажатие — отключить.
 * * **Удержание** — открыть приложение: Android отправляет долгое нажатие в активность с фильтром
 *   `android.service.quicksettings.action.QS_TILE_PREFERENCES` (объявлена в
 *   app/src/tunnel/AndroidManifest.xml как alias на [MainActivity]).
 *
 * Плитка не собирает конфиг заново и не требует разблокировки: она показывает только то, что
 * сервис сообщает через [TunnelState], а состояние обновляет сам сервис
 * (`TileService.requestListeningState`).
 */
class TunnelTileService : TileService() {

    /**
     * Плитка живёт в процессе интерфейса, а туннель — в своём: состояние приходится читать из
     * общего снимка. Подключаемся в onCreate, потому что плитку могут нажать и при закрытом
     * приложении — тогда это единственная точка входа в процесс.
     */
    override fun onCreate() {
        super.onCreate()
        runCatching {
            CrashLog.install(this)
            TunnelDebug.attach(this)
            // Плитку могут нажать при закрытом приложении — тогда это единственный шанс
            // переписать снимок настроек для сервиса (после обновления приложения его может
            // ещё не быть, и туннель поднялся бы по значениям по умолчанию).
            ServiceSettingsStore.syncFromPrefs(this)
            TunnelState.installMirror(this)
        }
    }

    override fun onStartListening() {
        super.onStartListening()
        // Снимок мог устареть, пока шторка была закрыта: перечитываем перед показом.
        runCatching { TunnelStatusBus.refresh(this) }
        updateTile()
    }

    override fun onTileAdded() {
        super.onTileAdded()
        updateTile()
    }

    override fun onClick() {
        if (TunnelState.up) {
            // Состояние обновит сервис: он владелец снимка, плитка только читает.
            WarpVpnService.stop(this)
            updateTile()
            return
        }
        val text = Prefs(this).lastConfigText
        if (text.isBlank()) {
            // Конфига ещё нет: единственный разумный ход — открыть приложение и нажать «Проверить».
            openApp()
            return
        }
        val permission = runCatching { VpnService.prepare(this) }.getOrNull()
        if (permission != null) {
            // Разрешение VPN выдаётся только из активности, поэтому показываем системный диалог.
            // После согласия достаточно нажать плитку ещё раз.
            launch(permission)
            return
        }
        WarpVpnService.startWithText(this, text)
        updateTile()
    }

    private fun updateTile() {
        val tile = qsTile ?: return
        runCatching { TunnelStatusBus.snapshot(this) }
        val hasConfig = Prefs(this).lastConfigText.isNotBlank()
        tile.state = when {
            TunnelState.up -> Tile.STATE_ACTIVE
            !hasConfig -> Tile.STATE_UNAVAILABLE
            else -> Tile.STATE_INACTIVE
        }
        tile.label = getString(R.string.tile_label)
        val subtitle = getString(
            when {
                TunnelState.up -> R.string.tile_on
                !hasConfig -> R.string.tile_no_config
                else -> R.string.tile_off
            }
        )
        if (Build.VERSION.SDK_INT >= 29) tile.subtitle = subtitle
        if (Build.VERSION.SDK_INT >= 30) tile.stateDescription = subtitle
        tile.updateTile()
    }

    private fun openApp() = launch(
        Intent(this, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
    )

    /**
     * Свернуть шторку и открыть активность. На Android 14+ перегрузка с [Intent] удалена —
     * там принимают только [PendingIntent], поэтому две ветки.
     */
    private fun launch(intent: Intent) {
        val go = {
            runCatching {
                if (Build.VERSION.SDK_INT >= 34) {
                    startActivityAndCollapse(
                        PendingIntent.getActivity(
                            this, 0, intent,
                            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
                        )
                    )
                } else {
                    @Suppress("DEPRECATION")
                    startActivityAndCollapse(intent)
                }
            }
        }
        if (isLocked) {
            @Suppress("DEPRECATION")
            unlockAndRun { go() }
        } else {
            go()
        }
    }
}
