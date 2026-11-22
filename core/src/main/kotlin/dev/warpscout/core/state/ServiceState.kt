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
    /**
     * Что происходит на самом деле, машинным кодом (см. константы `PHASE_*`).
     *
     * Зачем код, а не текст: интерфейс раньше решал «идёт подключение или нет», ища подстроки в
     * русском статусе («Поднимаю», «переподключаюсь», «нет сети»). Любая правка формулировки в
     * сервисе молча ломала оформление кнопки, а перевод на другой язык сломал бы его целиком.
     */
    val phase: Int = PHASE_IDLE,
    /**
     * Туннель нужен: был старт, и не было ни «Отключить», ни окончательного отказа. Пока это так,
     * сервис переподключается сам — даже если прямо сейчас туннель лежит и ждёт повтора. По этому
     * полю кнопка и плитка предлагают «Выключить», а не «Включить»: иначе выключить туннель,
     * который ждёт повтора, было просто нечем.
     */
    val wanted: Boolean = false,
    /**
     * Последним туннель выключил сам человек (кнопка, плитка, «Отключить» в уведомлении). После
     * этого ничто не поднимает туннель само — ни переподключение, ни фоновый подбор.
     */
    val stoppedByUser: Boolean = false,
    /**
     * Когда человек последний раз выключил туннель (мс, 0 — не выключал). По ней перебор точек в
     * интерфейсе видит выключение плиткой или из уведомления, случившееся во время перебора, —
     * сам признак [stoppedByUser] для этого не годится: каждый новый старт его снимает.
     */
    val stoppedByUserAt: Long = 0L,
    /**
     * Ответ на «проверь точку, не трогая туннель» (см. `WarpVpnService.ACTION_PROBE`):
     * «номер запроса|адрес:порт|итог|мс». Итог — [PROBE_OK], [PROBE_SILENT], [PROBE_CLOSED] или
     * [PROBE_NONE] (туннеля нет, проверять нечем).
     *
     * Зачем: в журнале 14:29 человек выбрал в «лучших» точку, которую дозор уже полтора часа
     * видел молчащей. Интерфейс погасил рабочий туннель, три секунды ждал ответа от мёртвой точки
     * и вернулся на прежнюю — со стороны это выглядело как «переподключил ту же». Теперь точка
     * сначала проверяется пробой рядом с работающим туннелем, и рабочий туннель не трогается зря.
     */
    val probe: String = "",
    /**
     * Что дозор знает о точках на текущей сети: «адрес:порт|когда отвечала|сколько раз подряд
     * молчала|когда последний раз молчала» через «;». По этому интерфейс помечает строки списка
     * лучших и выбора резервной точки: «отвечает» / «молчит с 12:53».
     */
    val marks: String = "",
    /**
     * Проверка связи через туннель — «подключено» значит «данные ходят», а не только «handshake
     * прошёл». Время последней проверки (0 — не проверяли).
     */
    val linkAt: Long = 0L,
    /** Интернет через туннель: [LINK_UNKNOWN], [LINK_OK], [LINK_FAIL], [LINK_BYPASS]. */
    val linkWeb: Int = LINK_UNKNOWN,
    /** Сколько шёл ответ на проверку, мс (-1 — не было ответа). */
    val linkMs: Int = -1,
    /** Telegram через туннель: TCP-соединение с его сервером. Те же коды, что у [linkWeb]. */
    val linkTg: Int = LINK_UNKNOWN,
    val linkTgMs: Int = -1,
    /** Откуда виден выход по ответу Cloudflare: «FRA · 2a09:…». */
    val linkExit: String = "",
) {

    val isStarting: Boolean get() = phase == PHASE_STARTING || phase == PHASE_RECONNECTING
    val hasNoNetwork: Boolean get() = phase == PHASE_NO_NETWORK

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
        "phase" to JsonVal.num(phase),
        "wanted" to JsonVal.bool(wanted),
        "stoppedByUser" to JsonVal.bool(stoppedByUser),
        "stoppedByUserAt" to JsonVal.num(stoppedByUserAt),
        "probe" to JsonVal.str(probe),
        "marks" to JsonVal.str(marks),
        "linkAt" to JsonVal.num(linkAt),
        "linkWeb" to JsonVal.num(linkWeb),
        "linkMs" to JsonVal.num(linkMs),
        "linkTg" to JsonVal.num(linkTg),
        "linkTgMs" to JsonVal.num(linkTgMs),
        "linkExit" to JsonVal.str(linkExit),
    ).render()

    companion object {
        const val VERSION = 1

        /** Проверки связи ещё не было (или туннель только что поднялся). */
        const val LINK_UNKNOWN = 0

        /** Ответ пришёл через туннель. */
        const val LINK_OK = 1

        /** Ответа нет: запрос ушёл в туннель и пропал. */
        const val LINK_FAIL = 2

        /**
         * Запрос ушёл мимо туннеля: адрес не входит в маршруты (раздельные маршруты, «только
         * выбранные приложения»). Про сам туннель такая проверка ничего не говорит.
         */
        const val LINK_BYPASS = 3

        /** Проверка точки: туннеля нет — проверять нечем, подключаемся как обычно. */
        const val PROBE_NONE = 0

        /** Точка ответила на handshake. */
        const val PROBE_OK = 1

        /** Точка промолчала (две инициации без ответа). */
        const val PROBE_SILENT = 2

        /** Сеть ответила «порт закрыт» (ICMP). */
        const val PROBE_CLOSED = 3

        /** Туннель не поднимался или остановлен. */
        const val PHASE_IDLE = 0

        /** Идёт установка соединения (handshake). */
        const val PHASE_STARTING = 1

        /** Работает: handshake прошёл и трафик идёт. */
        const val PHASE_UP = 2

        /** Переподнимаем после смены сети. */
        const val PHASE_RECONNECTING = 3

        /** Сети нет, ждём появления: туннель снимается, чтобы трафик не уходил в пустоту. */
        const val PHASE_NO_NETWORK = 4

        /** Не вышло: причина в `error`, ждать больше нечего. */
        const val PHASE_FAILED = 5

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
                phase = obj.lng("phase").toInt(),
                wanted = obj.bool("wanted") ?: false,
                stoppedByUser = obj.bool("stoppedByUser") ?: false,
                stoppedByUserAt = obj.lng("stoppedByUserAt"),
                probe = obj.str("probe").orEmpty(),
                marks = obj.str("marks").orEmpty(),
                linkAt = obj.lng("linkAt"),
                linkWeb = obj.lng("linkWeb").toInt(),
                linkMs = if (obj.fields.containsKey("linkMs")) obj.lng("linkMs").toInt() else -1,
                linkTg = obj.lng("linkTg").toInt(),
                linkTgMs = if (obj.fields.containsKey("linkTgMs")) obj.lng("linkTgMs").toInt() else -1,
                linkExit = obj.str("linkExit").orEmpty(),
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
    /**
     * Очередь точек входа из последнего подключения (host:port, лучшая первой).
     *
     * Зачем сервису: когда после смены сети точка перестаёт отвечать, переподъём шёл на неё же
     * три раза подряд и сдавался — «нажми «Подключить»». Человек в этот момент спит. Теперь
     * сервис сам берёт следующую точку из этой очереди и поднимает туннель на ней, а не ждёт
     * нажатия.
     */
    val failover: List<String> = emptyList(),
    /**
     * Резервная точка, выбранная человеком (host:port; пусто — не выбрана). Если текущая точка
     * замолчит, сервис перейдёт на неё первой — раньше любой точки из памяти или очереди.
     */
    val backup: String = "",
) {

    fun toJson(): String = JsonVal.obj(
        "ver" to JsonVal.num(VERSION),
        "secondExitOn" to JsonVal.bool(secondExitOn),
        "secondConf" to JsonVal.str(secondConf),
        "secondCidrs" to JsonVal.str(secondCidrs),
        "appsMode" to JsonVal.num(appsMode),
        "appsSelected" to JsonVal.arr(appsSelected.map { JsonVal.str(it) }),
        "failover" to JsonVal.arr(failover.map { JsonVal.str(it) }),
        "backup" to JsonVal.str(backup),
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
                failover = (obj.fields["failover"] as? JsonVal.Arr)?.items.orEmpty()
                    .mapNotNull { (it as? JsonVal.Str)?.v }
                    .filter { it.isNotBlank() },
                backup = obj.str("backup").orEmpty().trim(),
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
