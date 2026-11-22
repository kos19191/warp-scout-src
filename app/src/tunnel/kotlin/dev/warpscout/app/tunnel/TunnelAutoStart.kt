package dev.warpscout.app.tunnel

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.net.VpnService
import dev.warpscout.app.TunnelDebug
import dev.warpscout.app.status.TunnelStatusBus

/**
 * Автоподъём туннеля после перезагрузки телефона и после обновления приложения.
 *
 * Зачем. И перезагрузка, и установка новой версии убивают процесс сервиса — туннель пропадал, и
 * вернуть его можно было только руками (на экране было «Туннель выключен: приложение обновилось —
 * нажми «Включить туннель»»). Теперь туннель возвращается сам, но строго по правилу, о котором
 * договорились: только если перед этим он был включён и человек его не выключал. Выключенный
 * руками (кнопка, плитка, «Отключить» в уведомлении) туннель сам не включается никогда.
 *
 * Что «был включён», знает последний снимок состояния сервиса: он лежит в файле и переживает и
 * обновление, и перезагрузку. Конфигурацию берём ту, на которой туннель реально работал последним
 * ([TunnelLastConfig]); решение «поднимать или нет» сервис перепроверяет сам (см.
 * `WarpVpnService.autoStartText`).
 */
class TunnelAutoStart : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent?) {
        val reason = when (intent?.action) {
            Intent.ACTION_BOOT_COMPLETED -> "телефон загрузился"
            Intent.ACTION_MY_PACKAGE_REPLACED -> "приложение обновилось"
            else -> return
        }
        // Приёмник не имеет права уронить процесс: любая ошибка — строка в журнале, не больше.
        runCatching {
            TunnelDebug.attach(context)
            val snap = TunnelStatusBus.read(context) ?: return
            if (snap.stoppedByUser) {
                TunnelDebug.stage("$reason: туннель был выключен вручную — сам не включаю")
                return
            }
            // Туннель не был включён — и говорить не о чем: журнал не засоряем.
            if (!snap.wanted && !snap.up) return
            // Автоподъём выключен в настройках (переключатель в расширенном режиме).
            val settings = dev.warpscout.app.status.ServiceSettingsStore.read(context)
            if (settings != null && !settings.autoStart) {
                TunnelDebug.stage("$reason: туннель был включён, но автоподъём выключен в настройках — сам не включаю")
                return
            }
            if (runCatching { VpnService.prepare(context) }.getOrNull() != null) {
                TunnelDebug.error(
                    "$reason: туннель был включён, но разрешения на VPN больше нет",
                    "открой приложение и нажми «Включить» — система спросит разрешение"
                )
                return
            }
            if (TunnelLastConfig.load(context) == null) {
                // Первое обновление на версию с автоподъёмом: файла ещё нет — его пишет только
                // удачный подъём. Тогда берём то, чем туннель поднимался по кнопке в последний раз.
                val fromPrefs = runCatching { dev.warpscout.app.Prefs(context).lastConfigText }.getOrDefault("")
                if (fromPrefs.contains("PrivateKey")) TunnelLastConfig.save(context, fromPrefs)
            }
            if (TunnelLastConfig.load(context) == null) {
                TunnelDebug.stage("$reason: туннель был включён, но рабочей конфигурации ещё нет — открой приложение")
                return
            }
            TunnelDebug.stage("$reason: туннель был включён — поднимаю сам")
            WarpVpnService.autoStart(context, reason)
        }.onFailure { t ->
            runCatching { TunnelDebug.error("автоподъём ($reason) не удался: ${t.javaClass.simpleName} ${t.message.orEmpty().take(120)}") }
        }
    }
}
