package dev.warpscout.core.state

import dev.warpscout.core.json.JsonVal
import dev.warpscout.core.json.parseJson

/**
 * Состояние туннеля в том виде, в каком его видит интерфейс.
 *
 * Зачем отдельная модель в ядре: туннель живёт в своём процессе (см. `android:process=":vpn"`
 * в манифесте), и общий на два процесса объект в памяти невозможен. Процесс сервиса пишет снимок
 * в файл и рассылает короткое уведомление, процесс интерфейса читает снимок и показывает его.
 * Модель здесь — чтобы обе стороны сериализовали одно и то же, а проверки ядра могли прогнать
 * сериализацию без Android.
 *
 * Правила сериализации: отсутствующее поле — значение по умолчанию, лишнее поле — игнорируется,
 * битый текст — `null` (интерфейс тогда показывает «состояние неизвестно», а не падает).
 */
data class TunnelStatus(
    /** Туннель реально работает: handshake прошёл и трафик идёт. */
    val up: Boolean = false,
    /** Текущий этап человеческим языком — то, что видно в кнопке и статусе. */
    val status: String = "",
    /** Сервер, с которым работаем. */
    val endpoint: String = "",
    /** Причина отказа, если он был. */
    val error: String? = null,
    /** Сервис сдался: ждать больше нечего. */
    val gaveUp: Boolean = false,
    /** Сервис занят: поднимается или уже работает. */
    val busy: Boolean = false,
    /** Когда началась последняя попытка: по этому UI отличает «не запускался» от «висит». */
    val startedAt: Long = 0L,
    /** Когда снимок записан: по этому видно, что сервис жив и не завис. */
    val updatedAt: Long = 0L,
    val bytesUp: Long = 0L,
    val bytesDown: Long = 0L,
    val handshakeAttempts: Int = 0,
    /** Последняя ошибка журнала (то же, что `TunnelDebug.lastError`). */
    val lastError: String? = null,
    /** Время последнего этапа журнала. */
    val lastStageMs: Long = 0L,
    /** Журнал вообще трогали: иначе «туннель ещё не запускался» вместо пустого экрана. */
    val touched: Boolean = false,
) {

    fun toJson(): String = JsonVal.obj(
        "ver" to JsonVal.num(VERSION),
        "up" to JsonVal.bool(up),
        "status" to JsonVal.str(status),
        "endpoint" to JsonVal.str(endpoint),
        "error" to (error?.let { JsonVal.str(it) } ?: JsonVal.Null),
        "gaveUp" to JsonVal.bool(gaveUp),
        "busy" to JsonVal.bool(busy),
        "startedAt" to JsonVal.num(startedAt),
        "updatedAt" to JsonVal.num(updatedAt),
        "bytesUp" to JsonVal.num(bytesUp),
        "bytesDown" to JsonVal.num(bytesDown),
        "handshakeAttempts" to JsonVal.num(handshakeAttempts),
        "lastError" to (lastError?.let { JsonVal.str(it) } ?: JsonVal.Null),
        "lastStageMs" to JsonVal.num(lastStageMs),
        "touched" to JsonVal.bool(touched),
    ).render()

    companion object {
        const val VERSION = 1

        fun fromJson(text: String?): TunnelStatus? {
            if (text.isNullOrBlank()) return null
            val obj = runCatching { parseJson(text) as? JsonVal.Obj }.getOrNull() ?: return null
            return TunnelStatus(
                up = obj.bool("up") ?: false,
                status = obj.str("status").orEmpty(),
                endpoint = obj.str("endpoint").orEmpty(),
                error = obj.str("error"),
                gaveUp = obj.bool("gaveUp") ?: false,
                busy = obj.bool("busy") ?: false,
                startedAt = obj.lng("startedAt"),
                updatedAt = obj.lng("updatedAt"),
                bytesUp = obj.lng("bytesUp"),
                bytesDown = obj.lng("bytesDown"),
                handshakeAttempts = obj.lng("handshakeAttempts").toInt(),
                lastError = obj.str("lastError"),
                lastStageMs = obj.lng("lastStageMs"),
                touched = obj.bool("touched") ?: false,
            )
        }
    }
}

/**
 * Настройки, которые нужны **сервису** при подъёме туннеля: второй выход и разделение по приложениям.
 *
 * Зачем копия, а не SharedPreferences: у каждого процесса своя копия настроек в памяти, поэтому
 * «поменял в интерфейсе — сервис не увидел» — типичный баг многопроцессных приложений. Здесь
 * один писатель (интерфейс) кладёт снимок в файл целиком, а сервис читает файл заново на каждой
 * попытке подъёма. Никакого кеша между процессами — значит и расхождению взяться неоткуда.
 */
data class ServiceSettings(
    /** Второй выход включён. */
    val secondExitOn: Boolean = false,
    /** Конфиг второго выхода (текст WgConf). */
    val secondConf: String = "",
    /** Подсети, которые уходят во второй выход. */
    val secondCidrs: String = "",
    /** Режим разделения по приложениям: 0 — все, 1 — только выбранные, 2 — все, кроме выбранных. */
    val appsMode: Int = 0,
    /** Выбранные приложения. */
    val appsSelected: List<String> = emptyList(),
) {

    fun toJson(): String = JsonVal.obj(
        "ver" to JsonVal.num(VERSION),
        "secondExitOn" to JsonVal.bool(secondExitOn),
        "secondConf" to JsonVal.str(secondConf),
        "secondCidrs" to JsonVal.str(secondCidrs),
        "appsMode" to JsonVal.num(appsMode),
        "appsSelected" to JsonVal.arr(appsSelected.map { JsonVal.str(it) }),
    ).render()

    companion object {
        const val VERSION = 1

        /** Режимы разделения по приложениям — те же числа, что в настройках интерфейса. */
        const val APPS_ALL = 0
        const val APPS_ONLY = 1
        const val APPS_EXCEPT = 2

        fun fromJson(text: String?): ServiceSettings? {
            if (text.isNullOrBlank()) return null
            val obj = runCatching { parseJson(text) as? JsonVal.Obj }.getOrNull() ?: return null
            val apps = (obj.fields["appsSelected"] as? JsonVal.Arr)?.items.orEmpty()
                .mapNotNull { (it as? JsonVal.Str)?.v }
            return ServiceSettings(
                secondExitOn = obj.bool("secondExitOn") ?: false,
                secondConf = obj.str("secondConf").orEmpty(),
                secondCidrs = obj.str("secondCidrs").orEmpty(),
                appsMode = obj.lng("appsMode").toInt(),
                appsSelected = apps,
            )
        }
    }
}

/**
 * Число из JSON целым. Через `raw` (исходный текст), а не через `Double`: миллисекунды и счётчики
 * байт не должны «плыть» из-за плавающей точки.
 */
private fun JsonVal.Obj.lng(key: String): Long {
    val n = fields[key] as? JsonVal.Num ?: return 0L
    return n.raw.trim().toLongOrNull() ?: n.v.toLong()
}
