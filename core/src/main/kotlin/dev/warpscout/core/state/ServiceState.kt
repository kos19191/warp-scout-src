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
    /**
     * Замер скорости через туннель: когда закончился (0 — не мерили в этой сессии). Автозамер
     * после подъёма заодно ловит «заморозку» — данные идут первые килобайты и встают.
     */
    val speedAt: Long = 0L,
    /** Итог замера: [SPEED_UNKNOWN], [SPEED_OK], [SPEED_FROZEN], [SPEED_FAIL], [SPEED_BYPASS]. */
    val speedState: Int = SPEED_UNKNOWN,
    /** Скорость загрузки, Кбит/с (-1 — не посчитать). */
    val speedKbps: Int = -1,
    /** Задержка канала (время TCP-соединения через туннель), мс; -1 — не мерили. */
    val speedPingMs: Int = -1,
    /** Сколько байт скачал замер. */
    val speedBytes: Long = 0L,
    /** Замер был полным (по нажатию), а не коротким автозамером. */
    val speedFull: Boolean = false,
    /** Замер идёт с этого момента (0 — не идёт): экран пишет «замеряю…», а не прошлое число. */
    val speedRunningSince: Long = 0L,
    /**
     * Рукопожатие прошло, и с этого момента сервис проверяет, идут ли данные (0 — не проверяет).
     * Перебор точек в интерфейсе по нему ждёт итога проверки, а не обрывает попытку на пятой
     * секунде: «работает» теперь объявляется только после ответа через туннель.
     */
    val dataCheckAt: Long = 0L,
    /**
     * Второй выход в текущей сессии (с 1.10.31): [SECOND_OFF], [SECOND_STARTING], [SECOND_UP],
     * [SECOND_FAILED]. По нему экран честно пишет «второй выход работает / не поднялся», а не
     * гадает по настройкам.
     */
    val second: Int = SECOND_OFF,
    /**
     * Сервер второго выхода, на котором он сейчас работает или к которому подключается (с 1.10.31,
     * автопоиск Proton Free): «NL-FREE#12». Пусто — свой сервер из конфига.
     */
    val secondPeer: String = "",
    /**
     * Проверка медиа Telegram (с 1.10.34, см. TelegramMedia): небольшая загрузка с серверов Telegram
     * с отметками времени — видно, идут ли данные ровно, а не только открывается ли соединение.
     * Значения — TelegramMedia.UNKNOWN / OK / SLOW / STALL / FAIL / NOT_TELEGRAM.
     */
    val tgMedia: Int = 0,
    /** Скорость той загрузки, Кбит/с; −1 — не мерили. */
    val tgMediaKbps: Int = -1,
    /** Когда проверяли медиа Telegram; 0 — в этой сессии не проверяли. */
    val tgMediaAt: Long = 0L,
    /**
     * Telegram сейчас идёт через второй выход (с 1.10.34): выход WARP — в России, а второй выход
     * настроен. Через московскую площадку Cloudflare медиа Telegram режут фильтры (журнал 23.11).
     */
    val tgSecond: Boolean = false,
    /**
     * Вопрос «пустить Telegram через второй выход?» ждёт ответа (с 1.10.36): когда задан; 0 — вопроса
     * нет. Экран, открытый в это время, задаёт тот же вопрос, если уведомление не видно.
     */
    val tgAskAt: Long = 0L,
    /** Текст вопроса с цифрами обеих проверок. */
    val tgAsk: String = "",
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
        "speedAt" to JsonVal.num(speedAt),
        "speedState" to JsonVal.num(speedState),
        "speedKbps" to JsonVal.num(speedKbps),
        "speedPingMs" to JsonVal.num(speedPingMs),
        "speedBytes" to JsonVal.num(speedBytes),
        "speedFull" to JsonVal.bool(speedFull),
        "speedRunningSince" to JsonVal.num(speedRunningSince),
        "dataCheckAt" to JsonVal.num(dataCheckAt),
        "second" to JsonVal.num(second),
        "secondPeer" to JsonVal.str(secondPeer),
        "tgMedia" to JsonVal.num(tgMedia),
        "tgMediaKbps" to JsonVal.num(tgMediaKbps),
        "tgMediaAt" to JsonVal.num(tgMediaAt),
        "tgSecond" to JsonVal.bool(tgSecond),
        "tgAskAt" to JsonVal.num(tgAskAt),
        "tgAsk" to JsonVal.str(tgAsk),
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

        /** Замера скорости ещё не было в этой сессии. */
        const val SPEED_UNKNOWN = 0
        /** Загрузка прошла, скорость посчитана. */
        const val SPEED_OK = 1
        /** Данные пошли и встали: «заморозка» (или соединение оборвали посреди загрузки). */
        const val SPEED_FROZEN = 2
        /** Ни байта: сервер замера не ответил. */
        const val SPEED_FAIL = 3
        /** Адрес замера не входит в маршруты туннеля — про туннель такой замер ничего не скажет. */
        const val SPEED_BYPASS = 4

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

        /** Второй выход в этой сессии не включён (или туннеля нет). */
        const val SECOND_OFF = 0

        /** Второй выход поднимается (ждёт основной туннель или рукопожатие своего сервера). */
        const val SECOND_STARTING = 1

        /** Второй выход работает: свой сервер ответил на рукопожатие. */
        const val SECOND_UP = 2

        /** Второй выход не поднялся или упал — его сайты идут через основной туннель. */
        const val SECOND_FAILED = 3

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
                speedAt = obj.lng("speedAt"),
                speedState = obj.lng("speedState").toInt(),
                speedKbps = if (obj.fields.containsKey("speedKbps")) obj.lng("speedKbps").toInt() else -1,
                speedPingMs = if (obj.fields.containsKey("speedPingMs")) obj.lng("speedPingMs").toInt() else -1,
                speedBytes = obj.lng("speedBytes"),
                speedFull = obj.bool("speedFull") ?: false,
                speedRunningSince = obj.lng("speedRunningSince"),
                dataCheckAt = obj.lng("dataCheckAt"),
                second = obj.lng("second").toInt(),
                secondPeer = obj.str("secondPeer").orEmpty(),
                // Нет полей (снимок от прежней версии) — медиа не проверяли, Telegram через WARP.
                tgMedia = obj.lng("tgMedia").toInt(),
                tgMediaKbps = if (obj.fields.containsKey("tgMediaKbps")) obj.lng("tgMediaKbps").toInt() else -1,
                tgMediaAt = obj.lng("tgMediaAt"),
                tgSecond = obj.bool("tgSecond") ?: false,
                tgAskAt = obj.lng("tgAskAt"),
                tgAsk = obj.str("tgAsk").orEmpty(),
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
     * Это резервная для Wi-Fi (и любой немобильной сети); для мобильной — [backupMobile].
     */
    val backup: String = "",
    /**
     * Резервная точка для мобильной сети. Отдельно, потому что адреса Cloudflare не универсальны:
     * точка, живая на домашнем Wi-Fi, на мобильной сети часто молчит — и наоборот.
     */
    val backupMobile: String = "",
    /** Лучшие точки подбора для Wi-Fi (host:port, лучшая первой) — для перебора на этой сети. */
    val listWifi: List<String> = emptyList(),
    /** То же для мобильной сети (её можно подобрать, не уходя с Wi-Fi). */
    val listMobile: List<String> = emptyList(),
    // Переключатели новых функций — каждую можно выключить, не дожидаясь новой версии, если она
    // на каком-то телефоне или сети ведёт себя плохо. По умолчанию всё включено.

    /** Поднимать туннель самому после перезагрузки и обновления (если он был включён). */
    val autoStart: Boolean = true,
    /** Проверка связи не прошла дважды — переподключаться. */
    val linkReconnect: Boolean = true,
    /** Короткий замер скорости после подключения (он же ловит «заморозку»). */
    val speedAuto: Boolean = true,
    /** Загрузка «замёрзла» дважды подряд — уходить на другую точку. */
    val freezeReconnect: Boolean = true,
    /** В раздельном режиме отправлять запросы к DNS через туннель (см. SplitRoutes.withDns). */
    val dnsInTunnel: Boolean = true,
    /**
     * Второй выход — внутри основного туннеля (с 1.10.31): провайдер видит только WARP, а «голый»
     * WireGuard до своего сервера в России часто режут. false — напрямую, как раньше.
     */
    val secondViaWarp: Boolean = true,
    /**
     * Серверы второго выхода по порядку перебора (с 1.10.31, автопоиск Proton Free): строки
     * «имя|адрес|порт|ключ», см. ProtonFree.encode. Пусто — один сервер из конфига, как раньше.
     */
    val secondPeers: List<String> = emptyList(),
    /**
     * Маршруты туннеля (AllowedIPs) по нынешнему «Туннелированию» — с 1.10.33. Сервис ставит их
     * любому конфигу при подъёме: точки из подбора и конфиг для автоподъёма несли маршруты своего
     * времени, и «переключение из топа» поднимало точку не в том режиме, что выбран (журнал 23.11:
     * 56 маршрутов «всё, кроме российских сетей» при выбранных списках). Пусто — как в конфиге
     * (снимок от прежней версии).
     */
    val routes: String = "",
    /** Те же маршруты словами — строка в журнал при подъёме («сайты из списков: 679 + …»). */
    val routesNote: String = "",
    /**
     * Искать точку с выходом за рубежом, если выход WARP на этой сети — в России (с 1.10.34): на
     * зарядке с погашенным экраном, не чаще раза в сутки на сеть, туннель гаснет примерно на минуту.
     */
    val abroadSearch: Boolean = true,
    /**
     * Предлагать второй выход для Telegram (с 1.10.36; ключ JSON прежний, с 1.10.34). Telegram идёт
     * через WARP; если через Москву медиа тормозит, а второй выход заметно быстрее, туннель
     * спрашивает уведомлением «Переключить» / «Оставить» (см. TelegramChoice). Выключено — не
     * спрашивает и не переключает.
     */
    val tgSecond: Boolean = true,
    /**
     * Выход по приложениям (с 1.10.39, см. AppExit): строки «пакет|правило», 1 — всегда WARP,
     * 2 — целиком через второй выход. Приложения без строки — «Само», по адресам.
     */
    val appExits: List<String> = emptyList(),
    /**
     * Эксперимент «автовыбор выхода для приложений» (с 1.10.43, см. AppAuto): приложения с выходом
     * «Само» сервис сам ведёт через второй выход, если их сервис через WARP не открывается или заметно
     * медленнее. По умолчанию выключено.
     */
    val appAuto: Boolean = false,
    /**
     * Обход DPI в туннеле (с 1.10.49-beta3, см. dev.warpscout.core.dpi.DpiRelay): YouTube и X —
     * напрямую с приёмом, где «Проверить DPI» нашла, что приём помогает. По умолчанию включён.
     */
    val dpiBypass: Boolean = true,
    /** Планы обхода по сетям: строки «ключ сети<TAB>план» (см. DpiPlan.encode). */
    val dpiPlans: List<String> = emptyList(),
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
        "backupMobile" to JsonVal.str(backupMobile),
        "listWifi" to JsonVal.arr(listWifi.map { JsonVal.str(it) }),
        "listMobile" to JsonVal.arr(listMobile.map { JsonVal.str(it) }),
        "autoStart" to JsonVal.bool(autoStart),
        "linkReconnect" to JsonVal.bool(linkReconnect),
        "speedAuto" to JsonVal.bool(speedAuto),
        "freezeReconnect" to JsonVal.bool(freezeReconnect),
        "dnsInTunnel" to JsonVal.bool(dnsInTunnel),
        "secondViaWarp" to JsonVal.bool(secondViaWarp),
        "secondPeers" to JsonVal.arr(secondPeers.map { JsonVal.str(it) }),
        "routes" to JsonVal.str(routes),
        "routesNote" to JsonVal.str(routesNote),
        "abroadSearch" to JsonVal.bool(abroadSearch),
        "tgSecond" to JsonVal.bool(tgSecond),
        "appExits" to JsonVal.arr(appExits.map { JsonVal.str(it) }),
        "appAuto" to JsonVal.bool(appAuto),
        "dpiBypass" to JsonVal.bool(dpiBypass),
        "dpiPlans" to JsonVal.arr(dpiPlans.map { JsonVal.str(it) }),
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
                backupMobile = obj.str("backupMobile").orEmpty().trim(),
                listWifi = strings(obj, "listWifi"),
                listMobile = strings(obj, "listMobile"),
                // Нет поля (снимок от старой версии) — функция включена, как и по умолчанию.
                autoStart = obj.bool("autoStart") ?: true,
                linkReconnect = obj.bool("linkReconnect") ?: true,
                speedAuto = obj.bool("speedAuto") ?: true,
                freezeReconnect = obj.bool("freezeReconnect") ?: true,
                dnsInTunnel = obj.bool("dnsInTunnel") ?: true,
                secondViaWarp = obj.bool("secondViaWarp") ?: true,
                secondPeers = strings(obj, "secondPeers"),
                // Нет поля (снимок от прежней версии) — маршруты остаются как в конфиге.
                routes = obj.str("routes").orEmpty(),
                routesNote = obj.str("routesNote").orEmpty(),
                // Нет поля (снимок от прежней версии) — включено, как и по умолчанию.
                abroadSearch = obj.bool("abroadSearch") ?: true,
                tgSecond = obj.bool("tgSecond") ?: true,
                // Нет поля (снимок от прежней версии) — у всех приложений «Само».
                appExits = strings(obj, "appExits"),
                // Нет поля (снимок от прежней версии) — эксперимент выключен.
                appAuto = obj.bool("appAuto") ?: false,
                // Нет поля (снимок от прежней версии) — обход включён, но планов нет: ничего не меняется.
                dpiBypass = obj.bool("dpiBypass") ?: true,
                dpiPlans = strings(obj, "dpiPlans"),
            )
        }
    }
}

/** Массив строк из JSON без пустых: отсутствующее поле — пустой список. */
private fun strings(obj: JsonVal.Obj, key: String): List<String> =
    (obj.fields[key] as? JsonVal.Arr)?.items.orEmpty()
        .mapNotNull { (it as? JsonVal.Str)?.v?.trim() }
        .filter { it.isNotEmpty() }

/**
 * Число из JSON целым. Через `raw` (исходный текст), а не через `Double`: миллисекунды и счётчики
 * байт не должны «плыть» из-за плавающей точки.
 */
private fun JsonVal.Obj.lng(key: String): Long {
    val n = fields[key] as? JsonVal.Num ?: return 0L
    return n.raw.trim().toLongOrNull() ?: n.v.toLong()
}
