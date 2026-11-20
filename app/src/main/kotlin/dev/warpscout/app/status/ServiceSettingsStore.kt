package dev.warpscout.app.status

import android.content.Context
import android.util.Log
import dev.warpscout.app.Prefs
import dev.warpscout.core.state.ServiceSettings
import java.io.File

/**
 * Настройки, которые нужны сервису при подъёме туннеля: второй выход и разделение по приложениям.
 *
 * Почему не SharedPreferences: у каждого процесса своя копия настроек в памяти, и сервис мог бы
 * работать со старыми значениями («поменял в настройках — туннель не заметил»). Здесь один
 * писатель — интерфейс, кладёт снимок целиком в файл, а сервис читает файл заново перед каждой
 * попыткой подъёма. Кеша между процессами нет, расхождению взяться неоткуда.
 */
object ServiceSettingsStore {

    private const val FILE = "service-settings.json"
    private const val TAG = "WarpScout/settings"

    private @Volatile var lastWritten: String? = null

    fun file(context: Context): File = File(context.applicationContext.filesDir, FILE)

    /** Записать снимок настроек (только из процесса интерфейса). */
    fun write(context: Context, settings: ServiceSettings) {
        val json = settings.toJson()
        if (json == lastWritten) return
        val target = file(context)
        runCatching {
            target.parentFile?.mkdirs()
            val tmp = File(target.parentFile, target.name + ".tmp")
            tmp.writeText(json)
            if (!tmp.renameTo(target)) {
                target.delete()
                if (!tmp.renameTo(target)) tmp.copyTo(target, overwrite = true)
            }
            lastWritten = json
        }.onFailure { Log.w(TAG, "настройки сервиса не записаны: ${it.message}") }
    }

    /** Прочитать снимок (сервис читает его заново на каждой попытке подъёма). */
    fun read(context: Context): ServiceSettings? =
        ServiceSettings.fromJson(runCatching { file(context).readText() }.getOrNull())

    /**
     * Переписать снимок из сохранённых настроек. Нужен после обновления приложения: старые
     * версии такого файла не писали, а без него сервис не знал бы про второй выход и разделение
     * по приложениям и работал бы «как по умолчанию».
     */
    fun syncFromPrefs(context: Context) {
        val prefs = Prefs(context)
        write(
            context,
            ServiceSettings(
                secondExitOn = prefs.secondExitOn,
                secondConf = prefs.secondConf,
                secondCidrs = prefs.secondCidrs,
                appsMode = prefs.appsMode,
                appsSelected = prefs.appsSelected.toList().sorted(),
            )
        )
    }
}
