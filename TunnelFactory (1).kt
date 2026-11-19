package dev.warpscout.app

import android.content.Context

/**
 * Сборка `scout`: собственного туннеля нет. Приложение ограничивается сканированием,
 * подбором и генерацией конфигурации, которую пользователь импортирует в AmneziaVPN.
 */
object TunnelFactory {
    fun create(context: Context): TunnelController = UnsupportedTunnelController()
}
