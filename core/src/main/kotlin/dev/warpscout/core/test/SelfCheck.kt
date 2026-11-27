package dev.warpscout.core.test

import dev.warpscout.core.backup.BackupFormat
import dev.warpscout.core.config.ConfTarget
import dev.warpscout.core.config.SplitRoutes
import dev.warpscout.core.config.WgConf
import dev.warpscout.core.lists.AllowList
import dev.warpscout.core.lists.AllowListPlanner
import dev.warpscout.core.lists.AllowLists
import dev.warpscout.core.lists.ListSide
import dev.warpscout.core.report.ConfigExport
import dev.warpscout.core.tunnel.ExitRouter
import dev.warpscout.core.tunnel.Keepalive
import dev.warpscout.core.tunnel.StallDetector
import dev.warpscout.core.tune.CachedPoint
import dev.warpscout.core.tunnel.IpPacket
import dev.warpscout.core.crypto.Blake2s
import dev.warpscout.core.crypto.Crypto
import dev.warpscout.core.junk.ChromeQuic
import dev.warpscout.core.junk.JunkLibrary
import dev.warpscout.core.junk.QuicMask
import dev.warpscout.core.keys.KeySource
import dev.warpscout.core.model.AwgParams
import dev.warpscout.core.model.Endpoint
import dev.warpscout.core.model.EndpointStats
import dev.warpscout.core.model.JunkChunk
import dev.warpscout.core.model.ProbeSample
import dev.warpscout.core.model.Verdict
import dev.warpscout.core.model.WarpConfig
import dev.warpscout.core.model.WarpAccount
import dev.warpscout.core.dpi.DpiComparator
import dev.warpscout.core.model.ResourceCheck
import dev.warpscout.core.net.CfTrace
import dev.warpscout.core.net.TelegramChoice
import dev.warpscout.core.net.TelegramMedia
import dev.warpscout.core.net.EndpointPool
import dev.warpscout.core.net.ExitCheck
import dev.warpscout.core.net.EndpointSpec
import dev.warpscout.core.net.HttpClient
import dev.warpscout.core.net.NetSettings
import dev.warpscout.core.net.Socks5
import dev.warpscout.core.net.Socks5Endpoint
import dev.warpscout.core.net.PoolMode
import dev.warpscout.core.net.TlsProber
import dev.warpscout.core.net.WgProber
import dev.warpscout.core.presets.RoutePresets
import dev.warpscout.core.report.Report
import dev.warpscout.core.state.ServiceSettings
import dev.warpscout.core.state.TunnelStatus
import dev.warpscout.core.model.Candidate
import dev.warpscout.core.tune.Scoring
import dev.warpscout.core.tune.Shortlist
import dev.warpscout.core.tune.Weights
import dev.warpscout.core.wg.Wg
import dev.warpscout.core.tune.NoiseBook
import dev.warpscout.core.tunnel.DataGate
import dev.warpscout.core.lists.SiteList
import dev.warpscout.core.lists.ProtonFree
import dev.warpscout.core.tunnel.PacketQueueIn
import dev.warpscout.core.tunnel.AwgChannel
import dev.warpscout.core.tunnel.ExitNat
import dev.warpscout.core.tunnel.Icmp6Reject
import dev.warpscout.core.tunnel.InnerUdpChannel
import dev.warpscout.core.tunnel.PacketMath
import dev.warpscout.core.tunnel.AppAuto
import dev.warpscout.core.tunnel.SecondDefaults
import dev.warpscout.core.tunnel.WelcomeApps
import dev.warpscout.core.presets.Presets
import dev.warpscout.core.model.ResourceResult

/**
 * Автономные проверки ядра. Запускаются и на десктопе (`warp-scout selftest`), и как unit-тесты
 * приложения — вся логика подобрана так, чтобы не требовать Android API.
 *
 *   ./gradlew :cli:run --args="selftest"            — офлайн-проверки (без сети)
 *   ./gradlew :cli:run --args="selftest --live"     — + сеть (генератор ключей, DoH, TLS, пробы)
 *   ./gradlew :cli:run --args="selftest --integration 127.0.0.1:34567"  — против tools/fake_warp_endpoint.py
 */
class SelfCheck(private val live: Boolean = false, private val integration: String? = null) {

    private var passed = 0
    private var failed = 0
    private val failures = mutableListOf<String>()

    fun run(): Int {
        section("криптография") {
            cryptoVectors()
            chachaCrossCheck()
        }
        section("wireguard handshake") {
            wgInitiationShape()
            wgTimestamps()
            wgHandshakeLoopback()
            dataPlaneLoopback()
            dataPlaneRekey()
            dataPlaneRetryAfterLoss()
        }
        section("медленная мобильная связь: H+, H (1.10.40)") {
            slowNetSettings()
            dataPlaneSlowRekey()
            dataPlaneRekeyAliveKeeps()
            dataPlaneRekeyDeadFails()
        }
        section("junk-профили") {
            quicMaskRoundTrip()
            templateRendering()
        }
        section("конфиги") {
            confRoundTrip()
            sampleFiles()
        }
        section("живость сессии по трафику") {
            stallDetection()
            deadPortFailsFast()
        }
        section("проверка связи и выбор точки") {
            linkCheckState()
        }
        section("быстрый старт подбора") {
            cachedPoint()
        }
        section("топ-3 конфига для переключения") {
            shortlistPick()
        }
        section("бета: подбор — точки из разных семейств адресов, против выхода через Москву (1.10.49-beta2)") {
            pointMixChecks()
        }
        section("скорость через туннель, DNS и две тройки (1.10.28)") {
            speedAndDns()
        }
        section("данные после рукопожатия и очередь (1.10.29)") {
            dataProbeChecks()
        }
        section("заморозка данных и маскировка (1.10.30)") {
            sustainChecks()
            dataGateChecks()
            noiseBookChecks()
        }

        section("доступность сервисов (1.10.30)") {
            availabilityChecks()
        }
        section("расход батареи: интервал keepalive") {
            keepalivePolicy()
        }
        section("состояние сервиса между процессами") {
            serviceState()
        }
        section("пул endpoint'ов") {
            endpointPool()
        }
        section("отмена подбора") {
            scanCancel()
        }
        section("скоринг и отчёт") {
            scoring()
            reportRendering()
        }
        section("socks5 / сравнение с ByeDPI") {
            socks5ByeDpiCompare()
        }
        section("списки allow-domains, маршруты, цели экспорта") {
            allowListsAndRoutes()
            confTargets()
        }
        section("второй выход и свои сайты (1.10.31)") {
            siteListChecks()
            secondExitNat()
            secondExitInner()
            secondExitAwg()
            amneziaV3()
            amneziaKeys()
            secondExitPipeline()
            expect(
                "снимок: состояние второго выхода переживает JSON",
                TunnelStatus.fromJson(TunnelStatus(second = TunnelStatus.SECOND_UP).toJson())?.second,
                TunnelStatus.SECOND_UP
            )
            expect("снимок: старый формат — второй выход выключен", TunnelStatus.fromJson("{}")?.second, TunnelStatus.SECOND_OFF)
            protonFreeChecks()
            exitCheckChecks()
        }
        section("выход WARP за рубежом и Telegram (1.10.34)") {
            exitSiteChecks()
            siteProbeChecks()
            telegramMediaChecks()
        }
        section("браузер — только к нужным сайтам, поддомены второго выхода (1.10.35)") {
            appServicesChecks()
            tunnelRoutesChecks()
        }
        section("Telegram через второй выход — по вопросу; ближние серверы Proton (1.10.36)") {
            telegramChoiceChecks()
            excludeHostsChecks()
            protonNearChecks()
        }
        section("Gemini — вместе с приложением Google (1.10.37)") {
            companionChecks()
        }
        section("Grok — через второй выход (1.10.38)") {
            grokChecks()
        }
        section("выход по приложениям: «Само» / «Всегда WARP» / «Второй выход» (1.10.39)") {
            appExitChecks()
        }
        section("автовыбор выхода для приложений и приложения по точкам (1.10.43)") {
            appAutoChecks()
        }
        section("обновления: GitHub через туннель, вставшая загрузка, докачка (1.10.40)") {
            updateDownloadChecks()
        }
        section("строка «где мы»: страна второго выхода (1.10.40)") {
            whereLineChecks()
        }
        section("шум «как Chrome»: первый пакет QUIC целиком (1.10.40)") {
            chromeQuicChecks()
        }
        section("резервная копия: всё, а не только основные настройки (1.10.43.1)") {
            backupFormatChecks()
        }
        section("бета: TikTok, ChatGPT, Claude, Gemini, Grok — второй выход по умолчанию (1.10.44-beta4)") {
            secondDefaultsChecks()
        }
        section("Proton кнопкой: вход в аккаунт, без аккаунта, сторонний сервис (1.10.44-beta5)") {
            ProtonChecks { name, ok, detail -> check(name, ok, detail) }.run()
        }
        section("бета: начальные экраны — что отмечено сразу и что сохраняется (1.10.44-beta6)") {
            welcomeChecks()
        }
        section("бета: режут DPI или адрес — приёмы ByeDPI в самом приложении (1.10.49-beta2)") {
            DpiChecks { name, ok, detail -> check(name, ok, detail) }.run()
        }
        section("бета: обход DPI в туннеле — YouTube и X напрямую с приёмом (1.10.49-beta3)") {
            DpiRelayChecks { name, ok, detail -> check(name, ok, detail) }.run()
        }
        section("бета: стратегии DPI как у ByeDPI — свои, фейк, Discord, план по группам сайтов (1.10.49-beta4)") {
            DpiStrategyChecks { name, ok, detail -> check(name, ok, detail) }.run()
        }
        section("бета: прокси MTProto для Telegram — найти, проверить до ответа Telegram (1.10.49-beta4)") {
            MtProxyChecks { name, ok, detail -> check(name, ok, detail) }.run()
        }
        if (live) {
            section("сеть: генератор/DoH/TLS") {
                liveNetwork()
            }
        }
        integration?.let { target ->
            section("сеть: integration с фейковым WARP-эндпоинтом") {
                liveIntegration(target)
            }
        }

        println()
        println("пройдено: $passed, провалено: $failed")
        failures.forEach { println("  ✗ $it") }
        return if (failed == 0) 0 else 1
    }

    /**
     * 1.10.34: где выходит WARP. Журнал 23.11: все точки вышли через Москву (DME), и медиа Telegram
     * стало грузиться рывками; на Wi-Fi до того был Хельсинки. Подбор должен узнавать площадку
     * каждой точки и ставить выход за рубежом первым, а экран — честно предупреждать.
     */
    private fun exitSiteChecks() {
        val x = dev.warpscout.core.net.ExitSite
        expect("площадка: код как есть", x.normalize("DME"), "DME")
        expect("площадка: в кавычках и строчными", x.normalize("\"hel\""), "HEL")
        expect("площадка: «DME1» — DME", x.normalize("DME1"), "DME")
        expect("площадка: слово — не код", x.normalize("Moscow"), "")
        expect("площадка: пусто — пусто", x.normalize(null), "")
        expect("площадка из строки проверки связи", x.fromSummary("DME · RU · 104.28.244.74"), "DME")
        expect("площадка: строка со страной — площадки нет", x.fromSummary("RU · 104.28.244.74"), "")
        check("площадка: Москва и Петербург — в России", x.isRussian("DME") && x.isRussian("LED") && x.isRussian("svx"))
        check("площадка: Хельсинки — за рубежом", x.isAbroad("HEL") && !x.isRussian("HEL"))
        check("площадка: неизвестно — ни то, ни другое", !x.isAbroad("") && !x.isRussian(null))
        expect("площадка: город для экрана", x.city("DME"), "Москва")
        expect("площадка: незнакомый код — сам код", x.city("XYZ"), "XYZ")
        expect("площадка: журнал", x.describe("HEL"), "HEL · Хельсинки")
        expect("площадка: журнал без кода", x.describe(""), "неизвестно")
        expect(
            "площадка: за рубежом → неизвестно → в России, порядок внутри групп сохранён",
            x.abroadFirst(listOf("DME", "", "HEL", "LED", "FRA")) { it }.joinToString(","),
            "HEL,FRA,,DME,LED"
        )

        val now = 1_800_000_000_000L
        var marks = emptyList<dev.warpscout.core.net.ExitSite.Mark>()
        marks = x.put(marks, dev.warpscout.core.net.ExitSite.Mark("Wi-Fi·192.168.1.1", "8.34.70.3:854", "HEL", now - 1000))
        marks = x.put(marks, dev.warpscout.core.net.ExitSite.Mark("Wi-Fi·192.168.1.1", "8.34.70.3:854", "DME", now))
        expect("память площадок: свежая запись заменяет прежнюю", x.siteOf(marks, "Wi-Fi·192.168.1.1", "8.34.70.3:854", now), "DME")
        expect("память площадок: одна запись на точку", marks.size, 1)
        expect("память площадок: другая сеть — не знаем", x.siteOf(marks, "мобильная·25020", "8.34.70.3:854", now), "")
        expect(
            "память площадок: через четыре дня запись устарела",
            x.siteOf(marks, "Wi-Fi·192.168.1.1", "8.34.70.3:854", now + 4L * 24 * 3_600_000L),
            ""
        )
        expect("память площадок: переживает файл", x.parse(x.render(marks)), marks)
        check("поиск выхода: на сети ещё не искали — пора", x.searchDue(marks, "Wi-Fi·192.168.1.1", now))
        val searched = x.put(marks, dev.warpscout.core.net.ExitSite.Mark("Wi-Fi·192.168.1.1", x.SEARCH, x.NONE, now))
        check("поиск выхода: только что искали — не пора", !x.searchDue(searched, "Wi-Fi·192.168.1.1", now + 3_600_000L))
        check("поиск выхода: через сутки — снова пора", x.searchDue(searched, "Wi-Fi·192.168.1.1", now + 25L * 3_600_000L))
        check("поиск выхода: на другой сети — своя очередь", x.searchDue(searched, "мобильная·25020", now))
        expect("поиск выхода: запись поиска — не площадка точки", x.siteOf(searched, "Wi-Fi·192.168.1.1", x.SEARCH, now), "")
        var many = emptyList<dev.warpscout.core.net.ExitSite.Mark>()
        for (i in 0 until dev.warpscout.core.net.ExitSite.MAX_MARKS + 20) {
            many = x.put(many, dev.warpscout.core.net.ExitSite.Mark("n", "1.1.1.$i:500", "HEL", now))
        }
        check(
            "память площадок: давние уходят по пределу",
            many.size == dev.warpscout.core.net.ExitSite.MAX_MARKS && many.first().endpoint == "1.1.1.20:500"
        )

        // Балл: выход за рубежом выше, в России ниже; точке без ответа бонус не положен.
        val ep = Endpoint("8.34.70.3", 854)
        val st = EndpointStats(ep, listOf(ProbeSample(ep, Verdict.HANDSHAKE_OK, 40.0, 1, "tls-fixed", dataTried = true, dataMs = 60.0)), Verdict.HANDSHAKE_OK, 1, 1)
        val none = Scoring.evaluate(st, true).total
        expect("балл: выход за рубежом — +200", Scoring.evaluate(st, true, site = "HEL").total - none, 200)
        expect("балл: выход в России — −200", Scoring.evaluate(st, true, site = "DME").total - none, -200)
        val deadSt = EndpointStats(ep, emptyList(), Verdict.UDP_SILENT, 0, 2)
        expect("балл: молчащей точке заграница не помогает", Scoring.evaluate(deadSt, false, site = "HEL").exit, 0)

        // Очередь: при равных или почти равных сайтах первой — точка с выходом за рубежом.
        fun cand(host: String, ok: Int, site: String?): Candidate {
            val cfg = WarpConfig(
                name = "тест",
                account = WarpAccount("a=", "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=", "172.16.0.2", "2606::1"),
                endpoint = Endpoint(host, 2408),
                junk = JunkLibrary.tlsFixed(),
                allowedIps = "0.0.0.0/0, ::/0"
            )
            val es = EndpointStats(cfg.endpoint, emptyList(), Verdict.HANDSHAKE_OK, 1, 1)
            return Candidate(cfg, es, Scoring.evaluate(es, true, ok, 6, site = site), emptyList(), ok, 6, 20_000, site = site)
        }
        expect(
            "очередь: поровну открылось — первой выход за рубежом",
            Shortlist.pick(listOf(cand("8.39.214.6", 5, "DME"), cand("8.34.70.3", 5, "HEL")), limit = 1).single().config.endpoint.host,
            "8.34.70.3"
        )
        expect(
            "очередь: за рубежом на сайт меньше — всё равно первой",
            Shortlist.pick(listOf(cand("8.39.214.6", 6, "DME"), cand("8.34.70.3", 5, "HEL")), limit = 1).single().config.endpoint.host,
            "8.34.70.3"
        )
        expect(
            "очередь: через Москву открылось заметно больше — Москва первой",
            Shortlist.pick(listOf(cand("8.39.214.6", 6, "DME"), cand("8.34.70.3", 3, "HEL")), limit = 1).single().config.endpoint.host,
            "8.39.214.6"
        )
        expect(
            "очередь: площадку не узнали — выше Москвы, ниже заграницы",
            Shortlist.pick(listOf(cand("8.39.214.6", 5, "DME"), cand("8.6.112.7", 5, null), cand("8.34.70.3", 5, "HEL")))
                .joinToString(",") { it.config.endpoint.host },
            "8.34.70.3,8.6.112.7,8.39.214.6"
        )
        val verified = listOf(cand("8.39.214.6", 5, "DME"), cand("8.34.70.3", 5, "HEL")).sortedWith(Shortlist.verifiedOrder())
        expect("подбор: победитель — тот же, что первая строка тройки", verified.first().config.endpoint.host, "8.34.70.3")

        // Снимки между процессами: новые поля и прежний формат.
        val tg = TunnelStatus(tgMedia = dev.warpscout.core.net.TelegramMedia.SLOW, tgMediaKbps = 420, tgMediaAt = 5L, tgSecond = true)
        expect("снимок: проверка медиа Telegram переживает JSON", TunnelStatus.fromJson(tg.toJson()), tg)
        val old = TunnelStatus.fromJson("{}")
        check("снимок: старый формат — медиа не проверяли, Telegram через WARP", old?.tgMedia == 0 && old.tgMediaKbps == -1 && !old.tgSecond)
        val off = ServiceSettings(abroadSearch = false, tgSecond = false)
        expect("настройки сервиса: переключатели 1.10.34 переживают JSON", ServiceSettings.fromJson(off.toJson()), off)
        val oldSettings = ServiceSettings.fromJson("{}")
        check("настройки сервиса: старый снимок — обе функции включены", oldSettings?.abroadSearch == true && oldSettings.tgSecond)
    }

    /** 1.10.34: запрос площадки внутри сессии — «id.server» класса CHAOS к 1.1.1.1. */
    private fun siteProbeChecks() {
        val probe = dev.warpscout.core.tunnel.DataProbe
        val src = probe.ipv4Of("172.16.0.2") ?: ByteArray(4)
        val q = probe.siteQuery(src, 40003, 0x2468)
        expect("площадка: запрос — 55 байт", q.size, 55)
        expect("площадка: сумма IP-заголовка сходится", probe.checksum(q, 0, 20, 0L), 0)
        expect(
            "площадка: тип TXT, класс CHAOS",
            q.copyOfRange(q.size - 4, q.size).joinToString(",") { (it.toInt() and 0xff).toString() },
            "0,16,0,3"
        )
        val r = fakeSiteReply(q, "DME")
        expect("площадка: ответ разобран", r?.let { probe.siteOf(it, 40003, 0x2468) }, "DME")
        val padded = fakeSiteReply(q, "HEL", pad = 13)
        expect("площадка: нули дополнения WireGuard не мешают", padded?.let { probe.siteOf(it, 40003, 0x2468) }, "HEL")
        check("площадка: чужой номер — не наш ответ", r != null && probe.siteOf(r, 40003, 0x2469) == null)
        val plainQ = probe.dnsQuery(src, 40004, 0x1357)
        val plainR = fakeDnsReply(plainQ)
        check("площадка: ответ без записей — площадки нет", plainR != null && probe.siteOf(plainR, 40004, 0x1357) == null)
        check("площадка: ответ на площадку — не ответ на пробу данных", r != null && !probe.isReply(r, 40004, 0x2468))

        // Вживую через петлю: сервер отвечает и на данные, и на площадку.
        val clientPriv = ByteArray(32) { (it * 5 + 1).toByte() }
        val serverPriv = ByteArray(32) { (it * 13 + 7).toByte() }
        val serverPub = Crypto.publicOf(serverPriv)
        val account = WarpAccount(Crypto.base64(clientPriv), Crypto.base64(serverPub))
        val prober = WgProber(NetSettings(attempts = 2, timeoutMs = 800, betweenAttemptsMs = 0))
        val server = LoopbackServer(serverPriv, answerData = { fakeSiteReply(it, "HEL") }).start()
        try {
            val withSite = prober.probe(Endpoint("127.0.0.1", server.port), account, serverPub, null, dataProbe = true, askSite = true)
            check(
                "проба: данные и площадка в одной сессии",
                withSite.stats.dataReplies > 0 && withSite.stats.site == "HEL",
                withSite.stats.samples.joinToString { it.note }
            )
            val noSite = prober.probe(Endpoint("127.0.0.1", server.port), account, serverPub, null, dataProbe = true)
            check("проба: без просьбы площадку не спрашивает", noSite.stats.dataReplies > 0 && noSite.stats.site == null)
        } finally {
            server.stop()
        }
        // Резолвер площадку не назвал (обычный DNS-ответ) — данные всё равно засчитаны.
        val mute = LoopbackServer(serverPriv, answerData = { fakeDnsReply(it) }).start()
        try {
            val t0 = System.currentTimeMillis()
            val res = prober.probe(Endpoint("127.0.0.1", mute.port), account, serverPub, null, dataProbe = true, askSite = true)
            val took = System.currentTimeMillis() - t0
            check("проба: площадку не назвали — данные засчитаны", res.stats.dataReplies > 0 && res.stats.site == null)
            check("проба: ожидание площадки не растягивает пробу", took < 2_500L, "заняло $took мс")
        } finally {
            mute.stop()
        }
    }

    /** 1.10.34: честная проверка Telegram — данные идут ровно, а не только открывается соединение. */
    private fun telegramMediaChecks() {
        val t = dev.warpscout.core.net.TelegramMedia
        check("Telegram: сервер telegram.org — в сетях Telegram", t.isTelegramIp("149.154.167.99"))
        check("Telegram: сервер медиа — в сетях Telegram", t.isTelegramIp("91.108.56.130"))
        check("Telegram: соседняя сеть — не Telegram", !t.isTelegramIp("149.154.176.1"))
        check("Telegram: чужой адрес — не Telegram", !t.isTelegramIp("8.8.8.8") && !t.isTelegramIp("мусор"))
        expect("Telegram: ни байта — не пошло", t.verdict(0, 0, 0, false), t.FAIL)
        expect("Telegram: 256 КБ за секунду ровно — норма", t.verdict(262_144, 1_000, 120, true), t.OK)
        expect("Telegram: 256 КБ за 4 с — тормозит", t.verdict(262_144, 4_000, 200, true), t.SLOW)
        expect("Telegram: пошло и встало — встаёт", t.verdict(48_000, 5_000, 3_000, false), t.STALL)
        expect("Telegram: быстро, но с паузой в 1,5 с — рывками", t.verdict(262_144, 1_800, 1_500, true), t.SLOW)
        check("Telegram: подпись говорит, что тормозит", t.describe(t.SLOW, 420, 200).contains("тормозит"))
        check("Telegram: сетей v4 — восемь", t.NETS_V4.size == 8)
        check("Telegram: имя в сертификате — точное", t.nameMatches("telegram.org", "TELEGRAM.org."))
        check("Telegram: «*.» — один уровень", t.nameMatches("*.telegram.org", "web.telegram.org") &&
            !t.nameMatches("*.telegram.org", "a.b.telegram.org") && !t.nameMatches("*.telegram.org", "telegram.org"))
        check("Telegram: чужое имя — нет", !t.nameMatches("telegram.org.evil.com", "telegram.org") && !t.nameMatches("", "telegram.org"))
        telegramFetchChecks()
    }

    /**
     * Загрузка проверки Telegram на локальном сервере (простой HTTP вместо TLS): заголовок Range,
     * перенаправления, «встало», «оборвали», короткий ответ, чужой адрес — без сети.
     */
    private fun telegramFetchChecks() {
        val t = dev.warpscout.core.net.TelegramMedia
        val plain = dev.warpscout.core.net.TelegramMedia.Connector { ip, _, port, timeoutMs ->
            java.net.Socket().apply { connect(java.net.InetSocketAddress(ip, port), timeoutMs) }
        }
        val local: (String) -> List<String> = { listOf("127.0.0.1") }
        fun body(n: Int) = ByteArray(n) { (it % 251).toByte() }
        val seenRange = java.util.concurrent.atomic.AtomicReference("")
        val server = HttpLoopback { path, headers, out ->
            when (path) {
                "/full" -> {
                    seenRange.set(headers["range"].orEmpty())
                    out.write("HTTP/1.1 206 Partial Content\r\nContent-Length: 262144\r\nConnection: close\r\n\r\n".toByteArray())
                    out.write(body(262_144))
                }
                "/dl" -> out.write("HTTP/1.1 302 Found\r\nLocation: /file\r\nContent-Length: 0\r\n\r\n".toByteArray())
                "/file" -> {
                    out.write("HTTP/1.1 200 OK\r\nContent-Length: 65536\r\n\r\n".toByteArray())
                    out.write(body(65_536))
                }
                "/stall" -> {
                    out.write("HTTP/1.1 206 Partial Content\r\nContent-Length: 262144\r\n\r\n".toByteArray())
                    out.write(body(40_000))
                    out.flush()
                    Thread.sleep(1_200)
                }
                "/cut" -> {
                    out.write("HTTP/1.1 206 Partial Content\r\nContent-Length: 262144\r\n\r\n".toByteArray())
                    out.write(body(20_000))
                }
                "/short" -> {
                    out.write("HTTP/1.1 200 OK\r\nContent-Length: 2048\r\n\r\n".toByteArray())
                    out.write(body(2_048))
                }
                "/away" -> out.write("HTTP/1.1 301 Moved\r\nLocation: https://elsewhere.test/x\r\n\r\n".toByteArray())
                else -> out.write("HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".toByteArray())
            }
        }
        try {
            val base = "http://media.test:${server.port}"
            fun get(path: String, timeout: Int = 3_000, accept: (String) -> Boolean = { true }, resolve: (String) -> List<String> = local) =
                t.fetch(base + path, resolve = resolve, connector = plain, accept = accept, readTimeoutMs = timeout)
            val full = get("/full")
            check("медиа Telegram: 256 КБ без пауз — норма", full.verdict == t.OK && full.bytes == 262_144L, full.toString())
            expect("медиа Telegram: просим только начало файла", seenRange.get(), "bytes=0-262143")
            val moved = get("/dl")
            check("медиа Telegram: перенаправление проходим сами", moved.verdict == t.OK && moved.bytes == 65_536L, moved.toString())
            val stall = get("/stall", timeout = 300)
            check("медиа Telegram: пошло и встало — встаёт", stall.verdict == t.STALL && stall.bytes in 1L..40_000L, stall.toString())
            val cut = get("/cut")
            check("медиа Telegram: оборвали посреди — встаёт", cut.verdict == t.STALL && cut.bytes == 20_000L, cut.toString())
            val short = get("/short")
            check("медиа Telegram: короткий ответ — не судим", short.verdict == t.UNKNOWN, short.toString())
            expect("медиа Telegram: нет файла — не пошло", get("/missing").verdict, t.FAIL)
            check("медиа Telegram: перенаправление на другую схему — не идём", get("/away").verdict == t.UNKNOWN)
            val before = server.connections.get()
            val foreign = get("/full", accept = t::isTelegramIp)
            check(
                "медиа Telegram: сервер не в сетях Telegram — не проверяем и не соединяемся",
                foreign.verdict == t.NOT_TELEGRAM && server.connections.get() == before, foreign.toString()
            )
            val v6 = get("/full", resolve = { listOf("::1") })
            check("медиа Telegram: только IPv4 — так ходит сам Telegram", v6.verdict == t.FAIL && v6.note.contains("IPv4"), v6.toString())
        } finally {
            server.close()
        }
    }

    /** Решение «Telegram через второй выход»: память по сетям и сравнение двух проверок медиа. */
    private fun telegramChoiceChecks() {
        val c = TelegramChoice
        val ok = TelegramMedia.OK
        val slow = TelegramMedia.SLOW
        val stall = TelegramMedia.STALL
        val fail = TelegramMedia.FAIL
        val now = 10L * TelegramChoice.VALID_MS
        var marks = c.put(emptyList(), TelegramChoice.Mark("wifi:дом", TelegramChoice.SECOND, now - 3_600_000L))
        marks = c.put(marks, TelegramChoice.Mark("mobile:25020", TelegramChoice.STAY, now - 2 * TelegramChoice.VALID_MS))
        marks = c.put(marks, TelegramChoice.Mark("wifi:кафе", TelegramChoice.ASKED, now - 3_600_000L))
        expect("Telegram: память — туда и обратно", c.parse(c.render(marks)), marks)
        expect("Telegram: «Переключить» действует сутки", c.choiceOf(marks, "wifi:дом", now), TelegramChoice.SECOND)
        expect("Telegram: ответ старше суток — забыт", c.choiceOf(marks, "mobile:25020", now), "")
        expect("Telegram: без ответа — три часа не спрашиваем", c.choiceOf(marks, "wifi:кафе", now), TelegramChoice.ASKED)
        expect("Telegram: без ответа — через четыре часа можно спросить", c.choiceOf(marks, "wifi:кафе", now + 3 * 3_600_000L), "")
        expect("Telegram: незнакомая сеть — решения нет", c.choiceOf(marks, "wifi:работа", now), "")
        val replaced = c.put(marks, TelegramChoice.Mark("wifi:дом", TelegramChoice.STAY, now))
        expect("Telegram: новый ответ заменяет прежний", c.choiceOf(replaced, "wifi:дом", now), TelegramChoice.STAY)
        check("Telegram: одна запись на сеть", replaced.count { it.net == "wifi:дом" } == 1)
        check("Telegram: битые строки пропускаются", c.parse("кривая\nwifi:x|maybe|1\nwifi:y|stay|abc\n").isEmpty())
        // Предлагать второй выход — только когда Москва тормозит, а второй выход заметно лучше.
        check("Telegram: Москва в порядке — не предлагаем", !c.secondHelps(ok, 3000, ok, 9000))
        check("Telegram: Москва встаёт, второй выход без остановок — предлагаем", c.secondHelps(stall, 200, ok, 2500))
        check("Telegram: Москва медленно, второй — тоже, но втрое быстрее — предлагаем", c.secondHelps(slow, 300, slow, 900))
        check("Telegram: Москва медленно, второй чуть быстрее — не предлагаем", !c.secondHelps(slow, 600, slow, 800))
        check("Telegram: второй выход сам встаёт — не предлагаем", !c.secondHelps(slow, 300, stall, 0))
        check("Telegram: второй выход не грузит — не предлагаем", !c.secondHelps(stall, 0, fail, -1))
        check("Telegram: через Москву загрузка не пошла, через второй выход идёт — предлагаем", c.secondHelps(fail, -1, slow, 700))
        expect("Telegram: «через Москву»", dev.warpscout.core.net.ExitSite.cityAcc("DME"), "Москву")
        expect("Telegram: «через Санкт-Петербург»", dev.warpscout.core.net.ExitSite.cityAcc("LED"), "Санкт-Петербург")
        expect("Telegram: «через Уфу»", dev.warpscout.core.net.ExitSite.cityAcc("UFA"), "Уфу")
        // Возврат через Москву — когда второй выход медленнее.
        check("Telegram: второй выход медленнее Москвы — возвращаемся", c.secondWorse(ok, 3000, ok, 1500))
        check("Telegram: второй выход чуть медленнее — остаёмся", !c.secondWorse(ok, 3000, ok, 2700))
        check("Telegram: второй выход встаёт, Москва нет — возвращаемся", c.secondWorse(slow, 600, stall, 0))
        check("Telegram: второй выход не грузит — возвращаемся", c.secondWorse(ok, 3000, fail, -1))
        check("Telegram: Москва сама не грузит — остаёмся", !c.secondWorse(fail, -1, slow, 500))
        check("Telegram: Москва по-прежнему встаёт — остаёмся", !c.secondWorse(stall, 0, ok, 2000))
        expect("Telegram: коротко — медленно", c.short(slow, 300), "300 Кбит/с, медленно")
        expect("Telegram: коротко — рывками", c.short(slow, 2000), "2,0 Мбит/с, рывками")
        expect("Telegram: коротко — без остановок", c.short(ok, 4100), "4,1 Мбит/с")
    }

    /** Подсети без адреса замера: замер через Москву, пока Telegram идёт через второй выход. */
    private fun excludeHostsChecks() {
        val tg = listOf("149.154.160.0/20", "91.108.4.0/22", "2001:67c:4e8::/48")
        val cut = SplitRoutes.excludeHosts(tg, listOf("149.154.167.99"))
        val router = dev.warpscout.core.tunnel.ExitRouter.of(cut)
        fun via(ip: String): Int = router.route(java.net.InetAddress.getByName(ip).address)
        check("подсети без адреса: адрес замера — мимо второго выхода", via("149.154.167.99") == 0)
        check("подсети без адреса: соседние адреса — через второй выход",
            via("149.154.167.98") == 1 && via("149.154.167.100") == 1 && via("149.154.160.1") == 1 && via("149.154.175.255") == 1)
        check("подсети без адреса: другие подсети не тронуты", "91.108.4.0/22" in cut && "2001:67c:4e8::/48" in cut)
        expect("подсети без адреса: /20 без одного адреса — 12 подсетей", cut.count { it.startsWith("149.154.") }, 12)
        check("подсети без адреса: адрес вне подсетей — как было", SplitRoutes.excludeHosts(tg, listOf("8.8.8.8")) == tg)
        check("подсети без адреса: /32 самого адреса уходит целиком",
            SplitRoutes.excludeHosts(listOf("1.2.3.4/32", "5.6.7.0/24"), listOf("1.2.3.4")) == listOf("5.6.7.0/24"))
    }

    /** «Любая страна» — ближние серверы Proton раньше дальнего из конфига (журнал 23.11: Мексика). */
    private fun protonNearChecks() {
        val key = "1fGFZtHU8r8qwdnron9E80NdvLw5WcUdhPgh7phzQnA="
        fun srv(name: String, country: String, ip: String) = ProtonFree.Server(name, country, "", ip, key)
        val servers = listOf(
            srv("MX-FREE#1", "Mexico", "10.1.0.1"),
            srv("NL-FREE#1", "Netherlands", "10.1.0.2"),
            srv("NL-FREE#2", "Netherlands", "10.1.0.3"),
            srv("PL-FREE#1", "Poland", "10.1.0.4"),
            srv("RO-FREE#1", "Romania", "10.1.0.5"),
            srv("CH-FREE#1", "Switzerland", "10.1.0.6"),
            srv("NO-FREE#1", "Norway", "10.1.0.7"),
            srv("US-FREE#1", "United States", "10.1.0.8"),
        )
        val fromConf = ProtonFree.Server("", "", "", "84.20.27.49", key)
        val mx = ProtonFree.ordered(servers, prefer = "", lastGood = "из конфига", original = fromConf, seed = 0)
        expect("Proton: «любая» — сначала по одному ближнему, потом сервер из конфига",
            mx.take(5).map { it.name }, listOf("NL-FREE#1", "PL-FREE#1", "RO-FREE#1", "CH-FREE#1", "из конфига"))
        val lastMx = ProtonFree.ordered(servers, prefer = "", lastGood = "MX-FREE#1", original = null, seed = 0)
        expect("Proton: дальний работавший — сразу после ближних", lastMx.getOrNull(ProtonFree.NEAR_PROBES)?.name, "MX-FREE#1")
        check("Proton: дальний работавший — в первых восьми попытках", lastMx.take(8).any { it.name == "MX-FREE#1" })
        val lastNl = ProtonFree.ordered(servers, prefer = "", lastGood = "NL-FREE#2", original = fromConf, seed = 0)
        expect("Proton: ближний работавший — первым", lastNl.first().name, "NL-FREE#2")
        check("Proton: ближний работавший — его страна второй раз в первом круге не берётся",
            lastNl.take(ProtonFree.NEAR_PROBES).count { it.code == "NL" } == 1)
        val chosen = ProtonFree.ordered(servers, prefer = "MX", lastGood = "NL-FREE#1", original = null, seed = 0)
        expect("Proton: выбранная страна — как раньше, первой", chosen.first().name, "MX-FREE#1")
        check("Proton: без повторов и без потерь", mx.size == servers.size + 1 && mx.distinctBy { it.ip }.size == mx.size)
    }

    /** Какие списки нужны выбранным приложениям, какие приложения — браузеры, поддомены сервисов. */
    private fun appServicesChecks() {
        val a = dev.warpscout.core.lists.AppServices
        expect("сервисы: Telegram — по пакету", a.serviceOf("org.telegram.messenger")?.title, "Telegram")
        expect("сервисы: Telegram X — тоже Telegram", a.serviceOf("org.thunderdog.challegram")?.lists, listOf("telegram"))
        expect("сервисы: неизвестный клиент Telegram — по имени пакета", a.serviceOf("com.example.telegram.fork")?.title, "Telegram")
        expect("сервисы: WhatsApp — сети Meta", a.serviceOf("com.whatsapp")?.lists, listOf("meta"))
        expect("сервисы: ChatGPT — список OpenAI", a.serviceOf("com.openai.chatgpt")?.lists, listOf("openai"))
        expect(
            "сервисы: Telegram, Instagram, Facebook, YouTube, X — списки без повторов",
            a.listsFor(listOf("com.twitter.android", "com.facebook.katana", "org.telegram.messenger", "com.instagram.android", "com.google.android.youtube")),
            listOf("telegram", "meta", "youtube", "twitter")
        )
        check("сервисы: Chrome — не сервис", a.serviceOf("com.android.chrome") == null)
        check("сервисы: браузер со словом сервиса в имени — всё равно браузер", a.serviceOf("com.yandex.browser") == null)
        check("сервисы: незнакомое приложение — сетей не знаем", a.serviceOf("com.valvesoftware.android.steam.community") == null)
        check(
            "браузеры: Chrome, Samsung Internet, Яндекс, Firefox — известны",
            listOf("com.android.chrome", "com.sec.android.app.sbrowser", "com.yandex.browser", "org.mozilla.firefox").all { a.isKnownBrowser(it) }
        )
        check("браузеры: Telegram — не браузер", !a.isKnownBrowser("org.telegram.messenger"))
        expect("сервисы: названия для экрана", a.titlesFor(listOf("com.whatsapp", "org.telegram.messenger")), listOf("Telegram", "WhatsApp"))
        val extra = dev.warpscout.core.lists.AllowLists.EXTRA_HOSTS
        check("второй выход: вход в ChatGPT (auth.openai.com) — в адресах", "auth.openai.com" in extra["openai"].orEmpty())
        check("второй выход: API Claude — в адресах", "api.anthropic.com" in extra["claude"].orEmpty())
        check(
            "второй выход: поддомены — только для известных списков",
            extra.keys.all { dev.warpscout.core.lists.AllowLists.byId.containsKey(it) }
        )
    }

    /**
     * 1.10.37: спутники сервисов. Человек отметил Gemini, второй выход работал, а Gemini писал «Эта
     * страна не поддерживается»: Gemini работает внутри приложения Google, а оно в туннель не входило.
     */
    private fun companionChecks() {
        val a = dev.warpscout.core.lists.AppServices
        val gemini = "com.google.android.apps.bard"
        expect(
            "спутники: отмечен Gemini — с ним приложение Google",
            a.companionsFor(listOf("org.telegram.messenger", gemini)).map { it.companion.pkg to it.service },
            listOf(a.GOOGLE_APP to "Gemini")
        )
        check("спутники: Google уже отмечен — второй раз не добавляем", a.companionsFor(listOf(gemini, a.GOOGLE_APP)).isEmpty())
        check(
            "спутники: без Gemini — никого",
            a.companionsFor(listOf("org.telegram.messenger", "com.openai.chatgpt", "com.android.chrome", "com.example.app")).isEmpty()
        )
        check("спутники: пустой выбор — никого", a.companionsFor(emptyList()).isEmpty())
        expect("спутники: название для журнала", a.companionsFor(listOf(gemini)).firstOrNull()?.companion?.title, "Google")
        // Приложение Google — не Gemini: отмеченное само по себе, оно не идёт целиком по сетям Gemini.
        check("спутники: приложение Google — не сервис", a.serviceOf(a.GOOGLE_APP) == null)
        check("спутники: приложение Google — не браузер из списка", !a.isKnownBrowser(a.GOOGLE_APP))
        expect("спутники: сетей не добавляют — у Gemini только его список", a.listsFor(listOf(gemini, a.GOOGLE_APP)), listOf("google-ai"))
    }

    /**
     * 1.10.38: Grok. xAI отказывает российским адресам, а в списке ru-ip-blocked из него только
     * grok.x.com: grok.com и x.ai шли через WARP с российским адресом.
     */
    private fun grokChecks() {
        val a = dev.warpscout.core.lists.AppServices
        val extra = dev.warpscout.core.lists.AllowLists.EXTRA_HOSTS["ru-ip-blocked"].orEmpty()
        check("Grok: grok.com — во втором выходе", "grok.com" in extra)
        check("Grok: вход (accounts.x.ai) и API (api.x.ai) — во втором выходе", "accounts.x.ai" in extra && "api.x.ai" in extra)
        check(
            "Grok: его список — среди источников второго выхода",
            dev.warpscout.core.lists.AllowLists.byId["ru-ip-blocked"] != null
        )
        expect("Grok: приложение — известный сервис", a.serviceOf("ai.x.grok")?.title, "Grok")
        check("Grok: сетей не добавляет — его адреса во втором выходе", a.listsFor(listOf("ai.x.grok")).isEmpty())
        check("Grok: ngrok — не Grok", a.serviceOf("com.ngrok.app") == null)
        expect("Grok: порядок названий для экрана", a.titlesFor(listOf("ai.x.grok", "com.anthropic.claude")), listOf("Claude", "Grok"))
        check("Grok: спутников нет", a.companionsFor(listOf("ai.x.grok")).isEmpty())
    }

    /**
     * 1.10.39: выход по приложениям. Человек: «дай возможность пропускать через второй канал любые
     * приложения и отключать второй канал для них» — Telegram через второй выход не грузил медиа, а
     * убрать его оттуда можно было, только выключив второй выход целиком.
     */
    private fun appAutoChecks() {
        val a = dev.warpscout.core.tunnel.AppAuto
        val e = dev.warpscout.core.tunnel.AppExit
        fun m(ok: Boolean, kbps: Int = -1, ms: Long = 500, unknown: Boolean = false) = AppAuto.Measure(ok, kbps, ms, unknown = unknown)

        // Решение: открывается одним путём — им; обоими — WARP, второй выход — только если заметно лучше.
        expect("автовыбор: через WARP открывается, через второй нет — WARP", a.decide(m(true), m(false), e.AUTO), e.AUTO)
        expect("автовыбор: через WARP не открывается, через второй да — второй выход", a.decide(m(false), m(true), e.AUTO), e.SECOND)
        expect("автовыбор: не открывается никак — как обычно", a.decide(m(false), m(false), e.SECOND), e.AUTO)
        expect("автовыбор: замер не показателен — как было", a.decide(m(false, unknown = true), m(true), e.SECOND), e.SECOND)
        expect("автовыбор: оба открылись, второй втрое быстрее — второй выход", a.decide(m(true, 1_000), m(true, 3_000), e.AUTO), e.SECOND)
        expect("автовыбор: оба открылись, второй в полтора раза быстрее — WARP", a.decide(m(true, 2_000), m(true, 3_000), e.AUTO), e.AUTO)
        expect("автовыбор: вдвое быстрее, но разница меньше мегабита — WARP", a.decide(m(true, 400), m(true, 900), e.AUTO), e.AUTO)
        expect("автовыбор: был второй, WARP догнал (90 %) — WARP", a.decide(m(true, 2_700), m(true, 3_000), e.SECOND), e.AUTO)
        expect("автовыбор: был второй, WARP на 60 % — остаётся второй", a.decide(m(true, 1_800), m(true, 3_000), e.SECOND), e.SECOND)
        expect("автовыбор: по времени — WARP 3 с, второй 1 с — второй выход", a.decide(m(true, ms = 3_000), m(true, ms = 1_000), e.AUTO), e.SECOND)
        expect("автовыбор: по времени — 1,2 с против 0,8 с — WARP", a.decide(m(true, ms = 1_200), m(true, ms = 800), e.AUTO), e.AUTO)
        check("автовыбор: Telegram не трогаем — у него своя проверка медиа", !a.covers("Telegram") && a.covers("Instagram") && !a.covers("Нечто"))
        check(
            "автовыбор: замеры названы как сервисы в AppServices",
            a.PROBES.all { p -> dev.warpscout.core.lists.AppServices.SERVICES.any { it.title == p.service } }
        )
        expect("настройки сервиса: автовыбор переживает JSON", ServiceSettings.fromJson(ServiceSettings(appAuto = true).toJson())?.appAuto, true)
        expect("настройки сервиса: старый снимок — автовыбор выключен", ServiceSettings.fromJson("{}")?.appAuto, false)

        // Итог для экрана: файл между процессами.
        val st = AppAuto.Status(
            1_700_000_000_000L, "DME", "второй выход (США)",
            listOf(
                AppAuto.Row(
                    "Instagram", e.SECOND, AppAuto.Measure(false, -1, 6_000, "HTTP 403|блок"),
                    AppAuto.Measure(true, 640, 900, "96 КБ"), "через WARP не открывается"
                )
            )
        )
        val back = AppAuto.Status.decode(st.encode())
        check(
            "итог автовыбора: файл читается обратно",
            back != null && back.rows.size == 1 && back.rows[0].exit == e.SECOND && back.rows[0].second.kbps == 640 &&
                back.site == "DME" && back.rows[0].warp.note == "HTTP 403/блок",
            back.toString()
        )
        check("итог автовыбора: чужой файл — null", AppAuto.Status.decode("мусор") == null && AppAuto.Status.decode("") == null)
        val lines = a.statusLines(st)
        check(
            "итог автовыбора: словами",
            lines.first().contains("WARP через Москву") && lines.any { it.startsWith("Instagram: WARP ✗") && it.contains("→ второй выход") },
            lines.toString()
        )

        // Замер: свой сокет, перенаправления, отказ по стране, «мимо туннеля», вставшие данные.
        val plain = AppAuto.Opener { ip, _, port, timeoutMs ->
            java.net.Socket().apply { connect(java.net.InetSocketAddress(ip, port), timeoutMs) }
        }
        val local: (String) -> List<String> = { listOf("127.0.0.1") }
        val page = ByteArray(64 * 1024) { 'a'.code.toByte() }
        val server = HttpLoopback { path, _, out ->
            when (path) {
                "/page" -> {
                    out.write("HTTP/1.1 200 OK\r\nContent-Length: ${page.size}\r\n\r\n".toByteArray())
                    out.write(page)
                }
                "/go" -> out.write("HTTP/1.1 302 Found\r\nLocation: /page\r\nContent-Length: 0\r\n\r\n".toByteArray())
                "/deny" -> out.write("HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n".toByteArray())
                "/trace-ru" -> out.write("HTTP/1.1 200 OK\r\n\r\nfl=1\nloc=RU\ntls=TLSv1.3\n".toByteArray())
                "/trace-nl" -> out.write("HTTP/1.1 200 OK\r\n\r\nfl=1\nloc=NL\n".toByteArray())
                "/stall" -> {
                    out.write("HTTP/1.1 200 OK\r\nContent-Length: 98304\r\n\r\n".toByteArray())
                    out.write(ByteArray(8_000))
                    out.flush()
                    Thread.sleep(1_200)
                }
                else -> out.write("HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".toByteArray())
            }
        }
        try {
            val base = "http://svc.test:${server.port}"
            fun get(
                path: String,
                blocked: Set<String> = emptySet(),
                inTunnel: (String) -> Boolean = { true },
                resolve: (String) -> List<String> = local,
                read: Int = 3_000,
            ) = a.fetch(AppAuto.Probe("Тест", base + path, blocked), resolve = resolve, inTunnel = inTunnel, opener = plain, readTimeoutMs = read)
            val ok = get("/page")
            check("замер: страница 64 КБ — открылась, скорость посчитана", ok.ok && ok.kbps > 0 && !ok.unknown, ok.toString())
            val moved = get("/go")
            check("замер: перенаправление проходим сами", moved.ok && moved.kbps > 0, moved.toString())
            val deny = get("/deny")
            check("замер: 403 — не открылась", !deny.ok && !deny.unknown && deny.note.contains("403"), deny.toString())
            val ru = get("/trace-ru", setOf("RU"))
            check("замер: страна из списка отказа — не открылась", !ru.ok && !ru.unknown && ru.note.contains("RU"), ru.toString())
            val nl = get("/trace-nl", setOf("RU"))
            check("замер: страна вне списка — открылась", nl.ok && nl.note.contains("NL"), nl.toString())
            val outside = get("/page", inTunnel = { false })
            check("замер: адрес мимо туннеля — не показателен", outside.unknown && !outside.ok, outside.toString())
            val noName = get("/page", resolve = { emptyList() })
            check("замер: имя не разрешилось — не показателен", noName.unknown, noName.toString())
            val stall = get("/stall", read = 300)
            check("замер: данные встали посреди ответа — не открылась", !stall.ok && !stall.unknown, stall.toString())
        } finally {
            server.close()
        }

        // Автоправила таблицы: только новые соединения, только IPv4; снятое правило — доживание.
        val insta = 10400
        val other = 10500
        var asked = 0
        var now = 1_000_000L
        val whose = HashMap<Int, Int>()
        val t = dev.warpscout.core.tunnel.AppExitTable(
            emptyMap(), owner = { _, local, _ -> asked++; whose[local.port] ?: -1 }, clock = { now }
        )
        fun syn(sport: Int, dst: String) = tcpSyn4("172.16.0.2", dst, 1360).also { PacketMath.put16(it, 20, sport) }
        listOf(41000, 41001, 41002, 41003, 41004, 40001).forEach { whose[it] = insta }
        whose[42000] = other
        val early = syn(41000, "157.240.1.174")
        expect("автоправила: пока их нет — по адресу и без вопросов системе", t.decide(early, early.size, 0) to asked, 0 to 0)
        t.setAuto(mapOf(insta to e.SECOND))
        check("автоправила: таблица не пустая", !t.isEmpty)
        val fresh = syn(41001, "157.240.1.174")
        expect("автоправила: новое соединение Instagram — во второй выход", t.decide(fresh, fresh.size, 0), 1)
        val running = syn(41002, "157.240.1.175").also { it[33] = 0x10 }
        expect("автоправила: уже идущее соединение TCP — остаётся, где было", t.decide(running, running.size, 0), 0)
        val quic = udp4("172.16.0.2", 41003, "157.240.1.176", 443, ByteArray(4))
        expect("автоправила: QUIC (UDP) — во второй выход", t.decide(quic, quic.size, 0), 1)
        val v6 = tcpSyn6("2606:4700:110::2", "2a03:2880::1")
        expect("автоправила: IPv6 — по адресу", t.decide(v6, v6.size, 0), 0)
        val o = syn(42000, "8.8.8.8")
        expect("автоправила: другое приложение — по адресу", t.decide(o, o.size, 0), 0)
        val manual = dev.warpscout.core.tunnel.AppExitTable(mapOf(insta to e.WARP), owner = { _, local, _ -> whose[local.port] ?: -1 })
        manual.setAuto(mapOf(insta to e.SECOND))
        check("автоправила: при ручном «Всегда WARP» не действуют", manual.autoRules().isEmpty())
        t.setAuto(emptyMap())
        expect("снятое правило: открытое по нему соединение доживает на втором выходе", t.decide(fresh, fresh.size, 0), 1)
        val after = syn(41004, "157.240.1.177")
        expect("снятое правило: новое соединение — по адресу", t.decide(after, after.size, 0), 0)
        now += dev.warpscout.core.tunnel.AppExitTable.LINGER_MS + 1
        val askedBefore = asked
        expect("снятое правило: через 10 минут — по адресу и без вопросов", t.decide(fresh, fresh.size, 0) to asked, 0 to askedBefore)

        // Диспетчер: закреплённые соединения IPv4/IPv6 идут по выбранной дорожке; соседнее соединение — по адресу.
        val q = ArrayDeque(listOf(
            syn(43000, "157.240.1.174"), syn(43001, "157.240.1.174"),
            tcpSyn6("2001:db8::1", "2a03:2880::1"), tcpSyn6("2001:db8::2", "2a03:2880::1")
        ))
        val tunIn = object : java.io.InputStream() {
            override fun read(): Int = -1
            override fun read(b: ByteArray, off: Int, len: Int): Int {
                val p = q.removeFirstOrNull() ?: return -1
                System.arraycopy(p, 0, b, off, p.size)
                return p.size
            }
        }
        val disp = dev.warpscout.core.tunnel.TunDispatcher(tunIn, ExitRouter.EMPTY, listOf(PacketQueueIn("основной"), PacketQueueIn("второй")))
        disp.pin(43000, "157.240.1.174", 443, 1)
        val v6Destination = java.net.InetAddress.getByName("2a03:2880::1")
        disp.pinAddr(40001, v6Destination, 443, 1)
        disp.run()
        expect("закрепление: IPv4 и IPv6 — во второй выход, чужие к тем же адресам — по адресу", disp.sentSecondary to disp.sentPrimary, 2L to 2L)
        disp.unpin(43000, "157.240.1.174", 443)
        disp.unpinAddr(40001, v6Destination, 443)

        // Шаг 1: приложения по точкам.
        fun cand(host: String, site: String?, vararg res: Pair<String, Pair<Boolean, Long>>): Candidate {
            val cfg = WarpConfig(
                name = "тест",
                account = WarpAccount("a=", "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=", "172.16.0.2", "2606::1"),
                endpoint = Endpoint(host, 2408),
                junk = JunkLibrary.tlsFixed(),
                allowedIps = "0.0.0.0/0, ::/0"
            )
            val es = EndpointStats(cfg.endpoint, emptyList(), Verdict.HANDSHAKE_OK, 1, 1)
            val results = res.map { (id, r) ->
                dev.warpscout.core.model.ResourceResult(ResourceCheck(id, "https://$id.test/", id = id), r.first, elapsedMs = r.second)
            }
            val ok = results.count { it.ok }
            return Candidate(cfg, es, Scoring.evaluate(es, true, ok, results.size, site = site), emptyList(), ok, results.size, 10_000, results, site)
        }
        val p1 = cand("1.1.1.1", "DME", "youtube" to (true to 400L), "instagram" to (false to 6_000L), "x" to (true to 300L))
        val p2 = cand("2.2.2.2", "DME", "youtube" to (true to 450L), "instagram" to (true to 900L), "x" to (true to 320L))
        val p3 = cand("3.3.3.3", "HEL", "youtube" to (true to 2_400L), "instagram" to (true to 950L), "x" to (true to 310L))
        val report = dev.warpscout.core.model.TuningReport("s", "f", "тест", listOf(p1, p2, p3), emptyList(), 3)
        val (pts, rows) = a.byPoint(report)
        expect("по точкам: три проверенные точки", pts.size, 3)
        val yt = rows.first { it.service == "youtube" }
        check("по точкам: YouTube — лучше ① и ② (через ③ 2,4 с)", yt.best == listOf(0, 1) && !yt.same, yt.toString())
        val ig = rows.first { it.service == "instagram" }
        check("по точкам: Instagram — ② и ③, через ① не открылся", ig.best == listOf(1, 2) && !ig.same, ig.toString())
        val xx = rows.first { it.service == "x" }
        check("по точкам: X — одинаково (разница меньше разброса)", xx.same && xx.best.size == 3, xx.toString())
        val text = a.byPointText(report)
        check(
            "по точкам: раздел отчёта",
            text.contains("Приложения по точкам") && text.contains("≈ одинаково") && text.contains("лучше ②, ③") && text.contains("Итог: разница есть"),
            text
        )
        val lone = dev.warpscout.core.model.TuningReport("s", "f", "тест", listOf(p1), emptyList(), 1)
        check("по точкам: одна точка — сравнивать не с чем", a.byPointText(lone).contains("одна точка"))
        val flat = dev.warpscout.core.model.TuningReport(
            "s", "f", "тест", listOf(cand("4.4.4.4", "DME", "x" to (true to 300L)), cand("5.5.5.5", "DME", "x" to (true to 420L))), emptyList(), 2
        )
        check("по точкам: разницы нет — так и пишем", a.byPointText(flat).contains("разницы между точками нет"))
        val withSecond = a.byPointText(report, st, 1_700_000_000_000L + 60_000L)
        check("по точкам: свежий замер второго выхода — строкой", withSecond.contains("второй выход (США)") && withSecond.contains("Instagram ✓"), withSecond)
    }

    private fun appExitChecks() {
        val e = dev.warpscout.core.tunnel.AppExit
        // Снимок: «пакет|правило», «Само» не хранится.
        expect("выход: строка снимка разбирается", e.decode("com.aurora.store|2"), "com.aurora.store" to e.SECOND)
        check("выход: «Само» в снимке не хранится", e.decode("org.telegram.messenger|0") == null)
        check("выход: кривая строка — мимо", e.decode("без-правила") == null && e.decode("|2") == null && e.decode("a|9") == null)
        expect("выход: запись — по имени пакета и без «Само»",
            e.encodeAll(mapOf("org.telegram.messenger" to e.WARP, "com.aurora.store" to e.SECOND, "x.y" to e.AUTO)),
            listOf("com.aurora.store|2", "org.telegram.messenger|1"))
        expect("выход: запись и разбор сходятся", e.decodeAll(e.encodeAll(mapOf("a.b" to e.WARP))), mapOf("a.b" to e.WARP))
        val settings = ServiceSettings(appExits = listOf("com.aurora.store|2"))
        expect("настройки сервиса: выход приложений переживает JSON", ServiceSettings.fromJson(settings.toJson())?.appExits, listOf("com.aurora.store|2"))
        expect("настройки сервиса: старый снимок — у всех «Само»", ServiceSettings.fromJson("{}")?.appExits, emptyList<String>())

        // Соединение из пакета.
        val syn = tcpSyn4("172.16.0.2", "142.250.1.1", 1360)
        val k = dev.warpscout.core.tunnel.FlowKey.of(syn)
        check("соединение: TCP по IPv4 — порты из заголовка", k != null && k.proto == 6 && k.sport == 40000 && k.dport == 443)
        expect("соединение: адреса для вопроса системе", k?.local?.address?.hostAddress + " → " + k?.remote?.address?.hostAddress,
            "172.16.0.2 → 142.250.1.1")
        val udp = udp4("172.16.0.2", 50000, "1.2.3.4", 443, ByteArray(10))
        val ku = dev.warpscout.core.tunnel.FlowKey.of(udp)
        check("соединение: UDP по IPv4", ku != null && ku.proto == 17 && ku.sport == 50000 && ku.dport == 443)
        val k6 = dev.warpscout.core.tunnel.FlowKey.of(tcpSyn6("2606:4700:110::2", "2a00:1450::1"))
        check("соединение: TCP по IPv6", k6 != null && k6.proto == 6 && k6.sport == 40001 && k6.dport == 443 && k6.src.size == 16)
        check("соединение: тот же пакет — то же соединение", dev.warpscout.core.tunnel.FlowKey.of(syn.copyOf()) == k &&
            dev.warpscout.core.tunnel.FlowKey.of(syn.copyOf())?.hashCode() == k?.hashCode())
        check("соединение: другой порт — другое соединение", ku != dev.warpscout.core.tunnel.FlowKey.of(udp4("172.16.0.2", 50001, "1.2.3.4", 443, ByteArray(10))))
        val frag = syn.copyOf().also { it[6] = 0; it[7] = 10 }
        check("соединение: фрагмент без начала — без портов", dev.warpscout.core.tunnel.FlowKey.of(frag) == null)
        check("соединение: ICMP — не соединение", dev.warpscout.core.tunnel.FlowKey.of(ip4("172.16.0.2", "1.1.1.1", 1, ByteArray(8))) == null)
        check("соединение: обрывок — null", dev.warpscout.core.tunnel.FlowKey.of(syn.copyOf(10)) == null)

        // Таблица правил: aurora (uid 10100) — «Второй выход», telegram (10200) — «Всегда WARP».
        val aurora = 10100
        val telegram = 10200
        val other = 10300
        var asked = 0
        val whose = HashMap<String, Int>()
        val logged = ArrayList<String>()
        fun owner(proto: Int, local: java.net.InetSocketAddress, remote: java.net.InetSocketAddress): Int {
            asked++
            return whose["${local.port}"] ?: -1
        }
        fun pkt(sport: Int, dst: String, dport: Int = 443) = udp4("172.16.0.2", sport, dst, dport, ByteArray(4))
        val t = dev.warpscout.core.tunnel.AppExitTable(
            mapOf(aurora to e.SECOND, telegram to e.WARP, other to e.AUTO),
            owner = ::owner, names = mapOf(aurora to "Aurora Store", telegram to "Telegram"), log = { logged += it }
        )
        whose["41000"] = aurora
        whose["42000"] = telegram
        whose["43000"] = other
        val a1 = pkt(41000, "142.250.1.1")
        expect("правило: «Второй выход» — адрес вёл в WARP, идёт во второй", t.decide(a1, a1.size, 0), 1)
        expect("правило: владельца спросили один раз", asked, 1)
        t.decide(a1, a1.size, 0)
        t.decide(a1, a1.size, 0)
        expect("правило: дальше соединение помнится — без вопросов", asked, 1)
        check("правило: в журнал — один раз, с названием", logged.count { it.contains("Aurora Store") && it.contains("второй выход") } == 1)
        val tg = pkt(42000, "149.154.167.51")
        expect("правило: «Всегда WARP» — адрес вёл во второй выход, идёт через WARP", t.decide(tg, tg.size, 1), 0)
        val tgW = pkt(42001, "149.154.167.52")
        whose["42001"] = telegram
        val before = asked
        expect("правило: «Всегда WARP» к адресу WARP — WARP", t.decide(tgW, tgW.size, 0), 0)
        expect("правило: …систему спросили: «Второй выход» есть у другого приложения", asked, before + 1)
        val o = pkt(43000, "8.8.4.4")
        expect("правило: «Само» — по адресу (WARP)", t.decide(o, o.size, 0), 0)
        val o2 = pkt(43001, "1.2.3.4")
        whose["43001"] = other
        expect("правило: «Само» — по адресу (второй выход)", t.decide(o2, o2.size, 1), 1)
        val dns = pkt(41005, "1.1.1.1", 53)
        whose["41005"] = aurora
        val beforeDns = asked
        expect("правило: DNS — по адресу", t.decide(dns, dns.size, 0), 0)
        expect("правило: о DNS систему не спрашиваем", asked, beforeDns)
        val unknown = pkt(44000, "5.6.7.8")
        expect("правило: владелец не назван — по адресу", t.decide(unknown, unknown.size, 0), 0)
        check("правило: счётчик неназванных", t.misses == 1L)
        check("правило: сводка для журнала", t.summary().contains("запросов владельца") && !t.summary().contains("выключено"))

        // Только «Всегда WARP» — к адресам WARP систему не спрашиваем вовсе.
        var asked2 = 0
        val warpOnly = dev.warpscout.core.tunnel.AppExitTable(mapOf(telegram to e.WARP), owner = { _, _, _ -> asked2++; telegram })
        val w1 = pkt(45000, "8.8.8.8")
        expect("только WARP: адрес WARP — без вопроса", warpOnly.decide(w1, w1.size, 0) to asked2, 0 to 0)
        expect("только WARP: адрес второго выхода — вопрос и WARP", warpOnly.decide(w1, w1.size, 1) to asked2, 0 to 1)
        // Пустые правила — ровно прежний путь.
        val none = dev.warpscout.core.tunnel.AppExitTable(mapOf(other to e.AUTO), owner = { _, _, _ -> error("не должны спрашивать") })
        check("без правил: таблица пустая", none.isEmpty)
        expect("без правил: решение по адресу", none.decide(w1, w1.size, 1), 1)
        // Система падает — по адресу, без исключений наружу.
        val boom = dev.warpscout.core.tunnel.AppExitTable(mapOf(aurora to e.SECOND), owner = { _, _, _ -> throw SecurityException("нет") })
        expect("ошибка системы — по адресу", boom.decide(w1, w1.size, 0), 0)
        // Android не называет никого — после 64 вопросов перестаём спрашивать.
        var asked3 = 0
        val logs3 = ArrayList<String>()
        val mute = dev.warpscout.core.tunnel.AppExitTable(mapOf(aurora to e.SECOND), owner = { _, _, _ -> asked3++; -1 }, log = { logs3 += it })
        for (i in 0 until 70) {
            val pk = pkt(46000 + i, "9.9.9.9")
            mute.decide(pk, pk.size, 0)
        }
        check("Android молчит: выключено", mute.disabled)
        expect("Android молчит: спросили ровно 64 раза", asked3, 64)
        check("Android молчит: в журнале — почему", logs3.any { it.contains("не работает") })
        // Вытеснение: таблица на 4 соединения — пятое вытесняет самое старое.
        var asked4 = 0
        val small = dev.warpscout.core.tunnel.AppExitTable(mapOf(aurora to e.SECOND), owner = { _, _, _ -> asked4++; aurora }, maxFlows = 4)
        val first = pkt(47000, "9.9.9.9")
        small.decide(first, first.size, 0)
        for (i in 1..4) {
            val pk = pkt(47000 + i, "9.9.9.9")
            small.decide(pk, pk.size, 0)
        }
        small.decide(first, first.size, 0)
        expect("вытеснение: старое соединение спрошено заново", asked4, 6)

        // Диспетчер tun: правило приложения перекрывает решение по адресу.
        val packets = ArrayDeque(listOf(pkt(41000, "142.250.1.1"), pkt(42000, "149.154.167.51"), pkt(43000, "8.8.4.4")))
        val tun = object : java.io.InputStream() {
            override fun read(): Int = -1
            override fun read(b: ByteArray, off: Int, len: Int): Int {
                val p = packets.removeFirstOrNull() ?: return -1
                System.arraycopy(p, 0, b, off, p.size)
                return p.size
            }
        }
        val lanes = listOf(PacketQueueIn("основной"), PacketQueueIn("второй"))
        val disp = dev.warpscout.core.tunnel.TunDispatcher(tun, ExitRouter.of(listOf("149.154.160.0/20")), lanes)
        disp.appExits = t
        disp.run()
        expect("диспетчер: Aurora — во второй, Telegram и остальные — в WARP", disp.sentSecondary to disp.sentPrimary, 1L to 2L)
        val disp2 = dev.warpscout.core.tunnel.TunDispatcher(
            object : java.io.InputStream() {
                val q = ArrayDeque(listOf(pkt(42000, "149.154.167.51")))
                override fun read(): Int = -1
                override fun read(b: ByteArray, off: Int, len: Int): Int {
                    val p = q.removeFirstOrNull() ?: return -1
                    System.arraycopy(p, 0, b, off, p.size)
                    return p.size
                }
            },
            ExitRouter.of(listOf("149.154.160.0/20")), listOf(PacketQueueIn("основной"), PacketQueueIn("второй"))
        )
        disp2.run()
        expect("диспетчер: без правил Telegram по адресу — во второй", disp2.sentSecondary, 1L)

        // Aurora Store — известное приложение: с адресами Google Play.
        val a = dev.warpscout.core.lists.AppServices
        expect("Aurora: известное приложение", a.serviceOf("com.aurora.store")?.title, "Aurora Store")
        expect("Aurora: её адреса — Google Play", a.listsFor(listOf("com.aurora.store")), listOf("google-play"))
        check("Aurora: список Google Play есть", AllowLists.byId["google-play"] != null)
        check("Aurora: чужой пакет со словом aurora — не она", a.serviceOf("com.aurora.weather") == null)

        // «Только второй выход» (с 1.10.44-beta1): TikTok при упавшем втором выходе в WARP не уходит.
        expect("TikTok: «только второй выход»",
            a.strictSecond("com.zhiliaoapp.musically") to a.strictSecond("com.ss.android.ugc.trill"), true to true)
        check("TikTok: остальные — с запасным WARP", !a.strictSecond("com.aurora.store") && !a.strictSecond("org.telegram.messenger"))
        val tiktok = 10400
        val strictLogs = ArrayList<String>()
        val st = dev.warpscout.core.tunnel.AppExitTable(
            mapOf(tiktok to e.SECOND, aurora to e.SECOND),
            owner = { _, local, _ -> if (local.port in 48000..48099) tiktok else aurora },
            names = mapOf(tiktok to "TikTok", aurora to "Aurora Store"), log = { strictLogs += it },
            strict = setOf(tiktok),
        )
        val tk = pkt(48000, "23.1.2.3")
        expect("TikTok: во второй выход", st.decide(tk, tk.size, 0), 1)
        check("TikTok: пометка «только второй выход»", st.lastStrict)
        val au = pkt(48500, "142.250.1.1")
        expect("Aurora: во второй выход", st.decide(au, au.size, 0), 1)
        check("Aurora: без пометки — запасной WARP остаётся", !st.lastStrict)
        check("TikTok: в журнале — что подождёт второй выход", strictLogs.any { it.contains("TikTok") && it.contains("через WARP не пойдёт") })
        st.decide(tk, tk.size, 0)
        expect("счётчик второго выхода: TikTok — два пакета, Aurora — один",
            st.secondUsage(sinceLast = true).associate { it.first to it.second }, mapOf("TikTok" to 2L, "Aurora Store" to 1L))
        check("счётчик второго выхода: за интервал — с нуля", st.secondUsage(sinceLast = true).isEmpty())
        check("счётчик второго выхода: в сводке сессии", st.summary().contains("TikTok 2 пак."))
        expect("размер для журнала: КБ и МБ",
            dev.warpscout.core.tunnel.AppExitTable.sizeText(2048) + " / " + dev.warpscout.core.tunnel.AppExitTable.sizeText(1572864),
            "2 КБ / 1,5 МБ")
        fun runStrict(list: List<ByteArray>, closeSecond: Boolean): Triple<Long, Long, Long> {
            val q = ArrayDeque(list)
            val lanes3 = listOf(PacketQueueIn("основной"), PacketQueueIn("второй"))
            if (closeSecond) lanes3[1].close()
            val d = dev.warpscout.core.tunnel.TunDispatcher(
                object : java.io.InputStream() {
                    override fun read(): Int = -1
                    override fun read(b: ByteArray, off: Int, len: Int): Int {
                        val p = q.removeFirstOrNull() ?: return -1
                        System.arraycopy(p, 0, b, off, p.size)
                        return p.size
                    }
                },
                ExitRouter.EMPTY, lanes3
            )
            d.appExits = st
            d.run()
            return Triple(d.sentPrimary, d.sentSecondary, d.strictHeld)
        }
        expect("диспетчер: второй выход лёг — TikTok придержан, Aurora — через WARP",
            runStrict(listOf(pkt(48001, "23.1.2.3"), pkt(48501, "142.250.1.1")), closeSecond = true), Triple(1L, 0L, 1L))
        expect("диспетчер: второй выход работает — оба во второй",
            runStrict(listOf(pkt(48002, "23.1.2.3"), pkt(48502, "142.250.1.1")), closeSecond = false), Triple(0L, 2L, 0L))
    }

    /** Маршруты из частей: сайты для браузера, сети выбранных приложений, прежние режимы. */
    private fun tunnelRoutesChecks() {
        val r = dev.warpscout.core.config.TunnelRoutes
        val sr = SplitRoutes
        expect("маршруты: объединение — пустое начало", sr.union("", "1.2.3.4/32"), "1.2.3.4/32")
        expect("маршруты: объединение — накрытое и повторы не добавляются", sr.union("10.0.0.0/8, 8.8.8.8/32", "10.1.2.3/32, 8.8.8.8/32, 9.9.9.9/32"),
            "10.0.0.0/8, 8.8.8.8/32, 9.9.9.9/32")
        expect("маршруты: объединение — всё пусто", sr.union("", " "), "")
        expect("маршруты: объединение — весь трафик остаётся весь", sr.union("0.0.0.0/0, ::/0", "1.2.3.4/32"), "0.0.0.0/0, ::/0")
        val preset = "5.0.0.0/8, 37.0.0.0/8"
        val tg = "91.108.4.0/22, 149.154.160.0/20"
        // Прежние режимы без браузера — как были.
        expect("маршруты: весь трафик — как был", r.compose(0, false, "", "", preset, tg, true).all(), "0.0.0.0/0, ::/0")
        expect("маршруты: кроме российских — как был", r.compose(1, false, "", "", preset, tg, false).all(), preset)
        expect("маршруты: списки не собраны — весь трафик", r.compose(2, false, "", "", preset, tg, false).all(), "0.0.0.0/0, ::/0")
        // Списки + сети выбранных приложений.
        val lists = r.compose(2, false, "1.1.1.0/24", "", preset, tg, false)
        expect("маршруты: списки + сети выбранных приложений", lists.all(), "1.1.1.0/24, 91.108.4.0/22, 149.154.160.0/20")
        expect("маршруты: добавленные сети приложений видны отдельно", lists.apps, listOf("91.108.4.0/22", "149.154.160.0/20"))
        expect("маршруты: мои сайты + сети приложений", r.compose(3, false, "", "104.18.32.47/32", preset, tg, false).all(),
            "104.18.32.47/32, 91.108.4.0/22, 149.154.160.0/20")
        // Браузер — только к нужным сайтам: списки и свои сайты вместе, плюс сети приложений.
        val browser = r.compose(0, true, "1.1.1.0/24", "104.18.32.47/32", preset, tg, false)
        check("маршруты: браузер — не весь трафик", sr.prefixesOf(browser.all()).none { it == "0.0.0.0/0" })
        expect("маршруты: браузер — списки, свои сайты и сети приложений", browser.all(),
            "1.1.1.0/24, 104.18.32.47/32, 91.108.4.0/22, 149.154.160.0/20")
        check("маршруты: браузер — режим отмечен", browser.browser)
        expect("маршруты: браузер без сайтов — только сети приложений", r.compose(0, true, "", "", preset, tg, false).all(), tg)
        expect("маршруты: браузер, но выбрать нечего — весь трафик", r.compose(0, true, "", "", preset, "", false).all(), "0.0.0.0/0, ::/0")
        // Сеть приложения, уже накрытая сайтами, второй раз не добавляется.
        expect("маршруты: накрытая сеть приложения не повторяется", r.compose(2, false, "91.108.0.0/16", "", preset, tg, false).apps,
            listOf("149.154.160.0/20"))
        // YouTube: сети Google для видео — при неполных маршрутах.
        val yt = r.compose(2, false, "1.1.1.0/24", "", preset, "", true)
        check("маршруты: YouTube — сети Google для видео добавлены", "192.178.0.0/15" in yt.video)
        check("маршруты: весь трафик — сети Google не нужны", r.compose(0, false, "", "", preset, "", true).video.isEmpty())
    }

    /**
     * Обновления (с 1.10.40): сети GitHub — в раздельные маршруты туннеля, вставшая системная загрузка
     * распознаётся за полминуты, своя загрузка докачивает с места обрыва.
     */
    private fun updateDownloadChecks() {
        val sr = SplitRoutes
        val gh = AllowLists.GITHUB_NETS
        val split = sr.prefixesOf(sr.withExtra("1.1.1.0/24, 149.154.160.0/20", gh))
        check("обновления: сети GitHub — в раздельные маршруты", "185.199.108.0/22" in split && "140.82.112.0/20" in split)
        check("обновления: прежние маршруты на месте", split.take(2) == listOf("1.1.1.0/24", "149.154.160.0/20"))
        expect("обновления: весь трафик — без лишних маршрутов", sr.withExtra("0.0.0.0/0, ::/0", gh), "0.0.0.0/0, ::/0")
        check("обновления: накрытая сеть GitHub не повторяется", "185.199.108.0/22" !in sr.missing("185.199.0.0/16", gh))
        check("обновления: сети GitHub — без ошибок записи", gh.all { it.contains('/') } && gh.size == gh.distinct().size)
        check("обновления: адреса загрузки — внутри сетей GitHub",
            ExitRouter.of(gh).let { r -> listOf("185.199.108.133", "185.199.111.133", "140.82.121.4").all { ip -> r.route(ExitRouter.ipBytes(ip)!!) == 1 } })
        // Встала ли загрузка: полминуты без первого байта, 45 с без прироста.
        val w = dev.warpscout.core.net.StallWatch(0L, 30_000L, 45_000L)
        check("загрузка: 20 с без байта — ещё ждём", !w.stalled(0L, 20_000L))
        check("загрузка: 31 с без байта — встала", w.stalled(0L, 31_000L))
        val w2 = dev.warpscout.core.net.StallWatch(0L, 30_000L, 45_000L)
        check("загрузка: байты пошли — ждём дольше", !w2.stalled(1_000L, 10_000L) && !w2.stalled(1_000L, 50_000L))
        check("загрузка: 45 с без прироста — встала", w2.stalled(1_000L, 56_000L))
        check("загрузка: прирост снова — идёт", !w2.stalled(5_000L, 57_000L))
        expect("загрузка: сколько ещё ждать", dev.warpscout.core.net.StallWatch(0L, 30_000L, 45_000L).left(0L, 12_000L), 18_000L)
        // Докачка: продолжение, ответ с начала, ошибки.
        val d = dev.warpscout.core.net.DownloadRules
        expect("докачка: 206 с того же места — ничего не пропускаем", d.skipFor(206, 1000L, 1000L), 0L)
        expect("докачка: 206 раньше записанного — пропускаем повтор", d.skipFor(206, 1000L, 600L), 400L)
        expect("докачка: 206 дальше записанного — дыра, ошибка", d.skipFor(206, 1000L, 1500L), null)
        expect("докачка: 200 вместо 206 — пропускаем записанное", d.skipFor(200, 1000L, null), 1000L)
        expect("докачка: первый запрос — с нуля", d.skipFor(200, 0L, null), 0L)
        expect("докачка: 404 — ошибка", d.skipFor(404, 0L, null), null)
        expect("докачка: начало куска", d.rangeStart("bytes 1000-1499/1500"), 1000L)
        expect("докачка: размер из Content-Range", d.totalFrom(206, 500L, "bytes 1000-1499/1500", 1000L), 1500L)
        expect("докачка: размер неизвестен (*) — начало плюс кусок", d.totalFrom(206, 500L, "bytes 1000-1499/*", 1000L), 1500L)
        expect("докачка: 200 — размер по длине", d.totalFrom(200, 1500L, null, 0L), 1500L)
        expect("докачка: длины нет — размер неизвестен", d.totalFrom(200, -1L, null, 0L), -1L)
    }

    /**
     * Строка «где мы» под кнопкой (с 1.10.40): «мобильная · вход … · выход RU · второй выход NL».
     * Второй выход — только когда поднят; страна — по серверу Proton, иначе по проверке своего сервера.
     */
    private fun whereLineChecks() {
        val nl = ExitCheck.Result("NL", "149.34.244.177", 1L, 900)
        val mx = ExitCheck.Result("MX", "84.20.27.49", 1L)
        expect("где мы: второй выход не поднят — о нём не пишем", ExitCheck.secondCountry(false, "NL-FREE#121", nl), null)
        expect("где мы: сервер Proton — страна по имени", ExitCheck.secondCountry(true, "NL-FREE#121", null), "NL")
        expect("где мы: сменился сервер Proton — страна нового, не прежней проверки", ExitCheck.secondCountry(true, "PL-FREE#3", nl), "PL")
        expect("где мы: свой сервер — страна по проверке", ExitCheck.secondCountry(true, "", mx), "MX")
        expect("где мы: свой сервер с выходом в России — так и пишем", ExitCheck.secondCountry(true, "", ExitCheck.Result("RU", "5.6.7.8", 1L)), "RU")
        expect("где мы: проверка не прошла — страны нет", ExitCheck.secondCountry(true, "", ExitCheck.Result(ExitCheck.FAIL, "нет ответа", 1L)), "")
        expect("где мы: ушло через WARP — страны нет", ExitCheck.secondCountry(true, "", ExitCheck.Result(ExitCheck.VIA_WARP, "1.2.3.4", 1L)), "")
        expect("где мы: проверки не было — страны нет", ExitCheck.secondCountry(true, "", null), "")
        expect("где мы: строка проверки из настроек", ExitCheck.secondCountry(true, "", ExitCheck.decode("NL|149.34.244.177|1700000000000|829")), "NL")
    }

    /**
     * Шум «как Chrome» (с 1.10.40): настоящий первый пакет QUIC. Расшифровывается независимой распаковкой
     * (QuicMaskForTest), внутри — ClientHello Chrome с именем сайта, ровно 1250 байт. Ключи Initial
     * сверяются с примером из RFC 9001: иначе «расшифровалось» значило бы только, что сборка и распаковка
     * ошибаются одинаково.
     */
    private fun chromeQuicChecks() {
        val rfcInitial = Crypto.hmacSha256(Crypto.unHex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a"), Crypto.unHex("8394c8f03e515708"))
        expect("quic: initial_secret — как в RFC 9001 (A.1)", Crypto.hex(rfcInitial), "7db5df06e7a69e432496adedb00851923595221596ae2ae9fb8115c1e9ed0a44")
        val rfcClient = Crypto.tlsDeriveSecret(rfcInitial, 32, "client in")
        expect("quic: client_initial_secret — как в RFC 9001", Crypto.hex(rfcClient), "c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea")
        expect("quic: key — как в RFC 9001", Crypto.hex(Crypto.tlsDeriveSecret(rfcClient, 16, "quic key")), "1f369613dd76d5467730efcbe3b1a22d")
        expect("quic: iv — как в RFC 9001", Crypto.hex(Crypto.tlsDeriveSecret(rfcClient, 12, "quic iv")), "fa044b2f42a3fd3b46fb255c")
        expect("quic: hp — как в RFC 9001", Crypto.hex(Crypto.tlsDeriveSecret(rfcClient, 16, "quic hp")), "9f50449e04a0e810283a1e9933adedd2")

        val profile = JunkLibrary.chrome()
        expect("как Chrome: имя профиля", profile.name, "chrome:apteka.ru")
        check("как Chrome: шаблон — один литерал (сервис шлёт первый кусок шаблона — значит, весь пакет)",
            profile.i1.size == 1 && profile.i1[0] is JunkChunk.Literal && profile.i2.isEmpty())
        val packet = (profile.i1[0] as JunkChunk.Literal).bytes
        expect("как Chrome: 1250 байт, как у Chrome", packet.size, ChromeQuic.SIZE)
        check("как Chrome: длинный заголовок QUIC", (packet[0].toInt() and 0xc0) == 0xc0)
        expect("как Chrome: QUIC v1", Crypto.hex(packet.copyOfRange(1, 5)), "00000001")
        expect("как Chrome: DCID 8 байт", packet[5].toInt(), 8)
        expect("как Chrome: SCID пустой", packet[14].toInt(), 0)
        expect("как Chrome: без токена", packet[15].toInt(), 0)
        val dcid = packet.copyOfRange(6, 14)
        val header = QuicMaskForTest.unprotect(packet, dcid)
        expect("как Chrome: Initial, номер пакета — один байт", header[0].toInt() and 0xff, 0xc0)
        expect("как Chrome: номер пакета 1, как у Chrome", header[18].toInt(), 1)
        val plain = QuicMaskForTest.decrypt(packet, dcid)
        expect("как Chrome: расшифровывается (1215 байт кадров)", plain.size, 1215)
        val frames = QuicMaskForTest.frames(plain)
        val crypto = frames.filter { it.startsWith("CRYPTO ") }
        check("как Chrome: ClientHello разрезан на куски, как у Chrome", crypto.size >= 2, frames.joinToString(" "))
        check("как Chrome: среди кусков есть PING", "PING" in frames, frames.joinToString(" "))
        check("как Chrome: незнакомых кадров нет", frames.none { it.startsWith("?") }, frames.joinToString(" "))
        val ch = QuicMaskForTest.extractClientHello(packet, dcid)
        check("как Chrome: собирается в ClientHello", ch.size > 100 && ch[0] == 0x01.toByte(), "${ch.size} байт")
        val covered = crypto.map { it.removePrefix("CRYPTO ").split('+').let { (o, l) -> o.toInt() to l.toInt() } }.sortedBy { it.first }
        check("как Chrome: куски покрывают ClientHello без дыр и наложений",
            covered.first().first == 0 && covered.zipWithNext().all { (a, b) -> a.first + a.second == b.first } &&
                covered.last().let { it.first + it.second } == ch.size)
        expect("как Chrome: длина ClientHello сходится",
            ((ch[1].toInt() and 0xff) shl 16) or ((ch[2].toInt() and 0xff) shl 8) or (ch[3].toInt() and 0xff), ch.size - 4)
        expect("как Chrome: TLS 1.2 в заголовке, без session id (как в QUIC)", Crypto.hex(ch.copyOfRange(4, 6)) + "/" + ch[38], "0303/0")
        expect("как Chrome: наборы шифров TLS 1.3", Crypto.hex(ch.copyOfRange(39, 47)), "0006130113021303")
        val exts = QuicMaskForTest.extensions(ch)
        expect("как Chrome: десять расширений Chrome", exts.keys.sorted(), ChromeQuic.EXTENSIONS.sorted())
        expect("как Chrome: имя сайта", QuicMaskForTest.sni(exts[0x0000]), "apteka.ru")
        expect("как Chrome: ALPN h3", exts[0x0010]?.let { Crypto.hex(it) }, "0003026833")
        expect("как Chrome: только TLS 1.3", exts[0x002b]?.let { Crypto.hex(it) }, "020304")
        expect("как Chrome: группы X25519, P-256, P-384", exts[0x000a]?.let { Crypto.hex(it) }, "0006001d00170018")
        check("как Chrome: ключ X25519 на 32 байта (без постквантового)",
            exts[0x0033]?.let { it.size == 38 && Crypto.hex(it.copyOfRange(0, 6)) == "0024001d0020" } == true)
        val tps = QuicMaskForTest.transportParameters(exts[0x0039])
        expect("как Chrome: тайм-аут простоя 30 с", tps[0x01]?.let { Crypto.hex(it) }, "80007530")
        expect("как Chrome: SCID в параметрах пустой", tps[0x0f]?.size, 0)
        check("как Chrome: GREASE-параметр (31·N + 27)", tps.keys.any { it % 31 == 27L && it > 0x20 })
        check("как Chrome: GREASE-версия вида 0x?a?a?a?a",
            tps[0xff73dbL]?.let { v -> v.size == 12 && (4 until 8).all { (v[it].toInt() and 0x0f) == 0x0a } } == true)

        // Одни и те же байты от зерна: шум из памяти совпадает с проверенным подбором.
        check("как Chrome: зерно даёт те же байты", ChromeQuic.packet("apteka.ru", 5L).contentEquals(ChromeQuic.packet("apteka.ru", 5L)))
        check("как Chrome: другое зерно — другие байты", !ChromeQuic.packet("apteka.ru", 5L).contentEquals(ChromeQuic.packet("apteka.ru", 6L)))
        check("как Chrome: по имени — тот же пакет",
            (JunkLibrary.byName("chrome:apteka.ru")?.i1?.firstOrNull() as? JunkChunk.Literal)?.bytes?.contentEquals(packet) == true)
        expect("как Chrome: шум из конфига узнаётся по байтам", JunkLibrary.nameOf(profile.copy(name = "imported")), "chrome:apteka.ru")
        expect("как Chrome: к другому сайту — по имени", JunkLibrary.byName("chrome:ozon.ru")?.let { p ->
            QuicMaskForTest.sni(QuicMaskForTest.extensions(QuicMaskForTest.extractClientHello(
                (p.i1[0] as JunkChunk.Literal).bytes, (p.i1[0] as JunkChunk.Literal).bytes.copyOfRange(6, 14)))[0x0000])
        }, "ozon.ru")
        check("как Chrome: имя сайта кириллицей или пустое — не профиль",
            JunkLibrary.byName("chrome:аптека.рф") == null && JunkLibrary.byName("chrome:") == null && JunkLibrary.byName("chrome:a b") == null)
        expect("как Chrome: в подборе", JunkLibrary.defaultPool().count { it.name == "chrome:apteka.ru" }, 1)
        expect("как Chrome: сервис пробует первым", JunkLibrary.serviceOrder().map { it.name }.take(2), listOf("chrome:apteka.ru", "tls-fixed"))
        expect("как Chrome: «без шума» — последним", JunkLibrary.serviceOrder().last().name, "none")
        val rendered = WgConf.renderJunk(profile.i1)
        check("как Chrome: в конфиге — <b 0x…> на 1250 байт", rendered.startsWith("<b 0x") && rendered.length == 2500 + 6, "${rendered.length} знаков")
        check("как Chrome: из конфига читается обратно",
            WgConf.parseJunk(rendered).let { it.size == 1 && (it[0] as? JunkChunk.Literal)?.bytes?.contentEquals(packet) == true })

        // Любое зерно и другой сайт: всегда 1250 байт, расшифровывается, имя на месте, куски без дыр.
        var bad = 0
        val sites = listOf("apteka.ru", "ozon.ru", "a.ru", "very-long-subdomain-for-test.example-site.ru")
        for (seed in 0L until 120L) {
            val site = sites[(seed % sites.size).toInt()]
            val p = ChromeQuic.packet(site, seed)
            val id = p.copyOfRange(6, 14)
            val hello = QuicMaskForTest.extractClientHello(p, id)
            val e = QuicMaskForTest.extensions(hello)
            val f = QuicMaskForTest.frames(QuicMaskForTest.decrypt(p, id))
            // Имя сайта — целиком в одном куске (фильтр, который не склеивает куски, его увидит).
            val range = ChromeQuic.sniRange(hello, site)
            val oneSlice = range != null && f.filter { it.startsWith("CRYPTO ") }
                .map { it.removePrefix("CRYPTO ").split('+').let { (o, l) -> o.toInt() until o.toInt() + l.toInt() } }
                .any { range.first in it && range.last in it }
            if (p.size != ChromeQuic.SIZE || QuicMaskForTest.sni(e[0x0000]) != site || e.size != 10 ||
                f.any { it.startsWith("?") } || f.count { it.startsWith("CRYPTO") } < 2 || !oneSlice
            ) bad++
        }
        expect("как Chrome: 120 зёрен и разные сайты — все пакеты правильные, имя сайта в одном куске", bad, 0)
    }

    // ------------------------------------------------------------------ helpers

    private fun section(name: String, block: () -> Unit) {
        println("— $name")
        runCatching(block).onFailure { reportFail("$name: исключение ${it.javaClass.simpleName}: ${it.message}") }
    }

    /**
     * 1.10.43.1: резервная копия — всё, а не только основные настройки (24.11: «я загрузил, а там
     * половины данных нет» — в бете не оказалось троек точек, памяти и списков). Формат должен
     * переносить настройки, файлы и ключи точно, а старые копии и старые версии — читаться как раньше.
     */
    private fun backupFormatChecks() {
        fun b64(s: String) = java.util.Base64.getEncoder().encodeToString(s.toByteArray())
        val conf = "[Interface]\nPrivateKey = abc\\def\nAddress = 172.16.0.2/32\n\n[Peer]\nEndpoint = 1.2.3.4:500"
        val main = linkedMapOf<String, Any?>(
            "lastConfigText" to conf,
            "tricky" to "C:\\new\\x",
            "mtu" to 1280,
            "lastTunedAt" to 1763900000000L,
            "secondExitOn" to true,
            "ratio" to 0.5f,
            "appsSelected" to setOf("com.zhiliaoapp.musically", "org.telegram.messenger"),
            "empty" to "",
        )
        val files = mapOf(
            "shortlist.txt" to "endpoint=1.2.3.4:500\nconf=xyz\n---\n".toByteArray(),
            "allowlists/tiktok.lst" to "tiktok.com\ntiktokv.com\n".toByteArray(),
            "bin.dat" to ByteArray(256) { it.toByte() },
        )
        val data = BackupFormat.Data(
            main = main,
            prefs = mapOf("dns-book" to mapOf("ip:dns.google" to "8.8.8.8,8.8.4.4", "at:dns.google" to 5L)),
            files = files,
            vault = mapOf("account" to "{\"id\":\"x\",\"token\":\"t\"}\nline2"),
            notes = linkedMapOf(
                "reason" to "подключение 8.35.211.1:4233",
                "at" to "1763900000000",
                "app" to "dev.warpscout.app.tunnel 1.10.43.1",
            ),
        )
        val text = BackupFormat.render(data)
        val back = BackupFormat.parse(text)
        check("копия: заголовок прежний — старые версии её узнают", text.startsWith(BackupFormat.HEADER + "\n") && BackupFormat.isBackup(text))
        check("копия: формат 2", back?.format == 2, "${back?.format}")
        check("копия: основные настройки точно (строки, числа, флаги, наборы)", back?.main == main, "${back?.main}")
        check("копия: «\\n» внутри текста (C:\\new) не становится переводом строки", back?.main?.get("tricky") == "C:\\new\\x")
        check("копия: другие файлы настроек (dns-book)", back?.prefs?.get("dns-book") == data.prefs["dns-book"], "${back?.prefs}")
        check(
            "копия: файлы байт в байт (точки, списки, двоичные)",
            back != null && back.files.size == files.size && files.all { (k, v) -> back.files[k]?.contentEquals(v) == true },
            "${back?.files?.keys}"
        )
        check("копия: ключ аккаунта", back?.vault == data.vault)
        check("копия: когда и почему записана", back?.notes?.get("reason") == "подключение 8.35.211.1:4233" && back.notes["at"] == "1763900000000")
        val crlf = "\uFEFF" + text.replace("\n", "\r\n")
        val back2 = BackupFormat.parse(crlf)
        check("копия: BOM и CRLF после облака не мешают", back2?.main == main && back2.files.keys == files.keys)
        val cr = BackupFormat.parse(BackupFormat.render(BackupFormat.Data(mapOf("c" to "a\r\nb"))))
        check("копия: CR в значении выбрасывается (как раньше), перевод строки остаётся", cr?.main?.get("c") == "a\nb", "${cr?.main}")
        val evil = BackupFormat.HEADER + "\n# format: 2\ns:k=v\nfile:../x=" + b64("x") + "\nfile:/etc/x=" + b64("x") +
            "\nfile:a/../../b=" + b64("x") + "\nfile:ok.txt=" + b64("x") + "\np:../p|s:a=b\nvault:a/b=" + b64("x") + "\n"
        val ev = BackupFormat.parse(evil)
        check("копия: пути с «..» и абсолютные отбрасываются", ev?.files?.keys == setOf("ok.txt"), "${ev?.files?.keys}")
        check("копия: имена настроек и ключей без «/» и «..»", ev?.prefs?.isEmpty() == true && ev.vault.isEmpty() && BackupFormat.safeName("dns-book"))
        val renderedEvil = BackupFormat.render(BackupFormat.Data(mapOf("k" to "v"), files = mapOf("../x" to byteArrayOf(1), "ok" to byteArrayOf(2))))
        check("копия: опасный путь не записывается", !renderedEvil.contains("file:../x") && renderedEvil.contains("file:ok="))
        val old = "# WarpScout backup v1\n# reason: вручную\n# at: 1763900000000\n" +
            "s:lastConfigText=[Interface]\\nPrivateKey = k\n" +
            "set:appsSelected=a.b\u0001c\\nd\ni:mtu=1280\nb:secondExitOn=true\n"
        val ob = BackupFormat.parse(old)
        check("старая копия: формат 1, настройки читаются", ob?.format == 1 && ob.main["mtu"] == 1280 && ob.main["secondExitOn"] == true, "${ob?.main}")
        check("старая копия: конфиг с переводами строк", ob?.main?.get("lastConfigText") == "[Interface]\nPrivateKey = k")
        check("старая копия: элементы наборов как есть", ob?.main?.get("appsSelected") == setOf("a.b", "c\\nd"), "${ob?.main?.get("appsSelected")}")
        check("старая копия: файлов и ключей в ней нет", ob?.files?.isEmpty() == true && ob.vault.isEmpty())
        val legacy = legacyBackupParse(text)
        check(
            "новая копия в старой версии: основные настройки на месте",
            legacy?.get("mtu") == 1280 && legacy["lastConfigText"] == conf && legacy["appsSelected"] == main["appsSelected"] &&
                legacy["secondExitOn"] == true,
            "${legacy?.get("lastConfigText")}"
        )
        check("новая копия в старой версии: чужих ключей нет", legacy?.keys == main.keys, "${legacy?.keys}")
        check("не копия — null", BackupFormat.parse("[Interface]\nPrivateKey = x") == null && !BackupFormat.isBackup("hello"))
    }

    /**
     * 1.10.44-beta4: в бете у TikTok, ChatGPT, Claude, Gemini и Grok выход по умолчанию — «Второй выход»
     * (24.11: «Добавь по умолчанию тикток и всякие там клауд, гемини, грок, чатгпт через второй туннель
     * по умолчанию. В бету пока что»). Только официальные приложения, только установленные, выбор
     * человека сильнее, и один раз на приложение.
     */
    private fun secondDefaultsChecks() {
        val d = SecondDefaults
        val e = dev.warpscout.core.tunnel.AppExit
        val a = dev.warpscout.core.lists.AppServices
        val only = ServiceSettings.APPS_ONLY
        val except = ServiceSettings.APPS_EXCEPT
        val all = ServiceSettings.APPS_ALL
        val tiktok = "com.zhiliaoapp.musically"
        val chatgpt = "com.openai.chatgpt"
        val claude = "com.anthropic.claude"
        val gemini = "com.google.android.apps.bard"
        val grok = "ai.x.grok"
        val telegram = "org.telegram.messenger"

        check("сервисы по умолчанию есть в списке сервисов",
            d.SERVICES.all { t -> a.SERVICES.any { it.title == t } }, "${d.SERVICES}")
        check("официальные приложения — да",
            listOf(tiktok, "com.ss.android.ugc.trill", "com.zhiliaoapp.musically.go", chatgpt, claude, gemini, grok).all { d.wants(it) })
        check("вариант пакета (пересобранный TikTok) — да", d.wants("com.zhiliaoapp.musically.morphe"))
        check("сторонние «AI-чат» и «скачать из TikTok» по слову в имени — нет",
            !d.wants("com.aichat.chatgpt.assistant") && !d.wants("com.video.tiktok.downloader") && !d.wants("com.anthropicfan.app"))
        check("Telegram, Aurora, приложение Google, ngrok, пусто — нет",
            !d.wants(telegram) && !d.wants("com.aurora.store") && !d.wants(a.GOOGLE_APP) && !d.wants("com.ngrok.app") && !d.wants(""))
        check("TikTok строгий, остальные по умолчанию — с запасным WARP",
            a.strictSecond(tiktok) && !a.strictSecond(chatgpt) && !a.strictSecond(claude) && !a.strictSecond(gemini) && !a.strictSecond(grok))

        // Бета из журнала 24.11: «только выбранные», TikTok на «Второй выход» руками, ИИ не отмечены.
        val installed = listOf(telegram, tiktok, chatgpt, claude, gemini, grok, a.GOOGLE_APP, "com.android.chrome")
        val p1 = d.plan(installed, mapOf(tiktok to e.SECOND), only, setOf(telegram, tiktok), emptySet(), emptySet())
        expect("бета: второй выход поставлен ИИ", p1.added, listOf(grok, claude, gemini, chatgpt))
        check("бета: у всех пятерых «Второй выход»",
            listOf(tiktok, chatgpt, claude, gemini, grok).all { p1.exits[it] == e.SECOND } && p1.exits.size == 5, "${p1.exits}")
        check("бета: ИИ отмечены в «только выбранные», прежние на месте",
            p1.selected == setOf(telegram, tiktok, grok, claude, gemini, chatgpt), "${p1.selected}")
        expect("бета: отмечены именно новые", p1.ticked, p1.added)
        expect("бета: TikTok выбран руками — оставлен", p1.kept, listOf(tiktok))
        check("бета: рассмотрены все пятеро, чужие — нет",
            p1.seen == setOf(tiktok, chatgpt, claude, gemini, grok), "${p1.seen}")
        check("бета: приложение Google (спутник Gemini) правила не получает", a.GOOGLE_APP !in p1.exits)
        check("бета: правила переживают снимок настроек",
            e.decodeAll(e.encodeAll(p1.exits)) == p1.exits)

        // Один раз на приложение.
        val p2 = d.plan(installed, p1.exits, only, p1.selected, emptySet(), p1.seen)
        check("второй раз — ничего не меняется", !p2.changed && p2.exits == p1.exits && p2.selected == p1.selected && p2.kept.isEmpty())
        val p3 = d.plan(installed, p1.exits - chatgpt, only, p1.selected, emptySet(), p1.seen)
        check("человек выбрал «Само» — обратно не ставим", !p3.changed && chatgpt !in p3.exits)

        // Выбор человека сильнее.
        val p4 = d.plan(installed, mapOf(claude to e.WARP), only, setOf(telegram), setOf(grok), emptySet())
        check("«Всегда WARP» руками — остаётся", p4.exits[claude] == e.WARP && claude in p4.kept)
        check("галочку сняли руками — не отмечаем и правило не ставим",
            grok !in p4.exits && grok !in p4.selected && grok in p4.kept && grok in p4.seen)
        val p5 = d.plan(installed, emptyMap(), except, setOf(tiktok), setOf(chatgpt), emptySet())
        check("«все, кроме»: исключённый TikTok не трогаем", tiktok !in p5.exits && tiktok in p5.kept)
        check("«все, кроме»: остальным правило, исключения те же, снятая галочка тут не в счёт",
            p5.exits[chatgpt] == e.SECOND && p5.exits[grok] == e.SECOND && p5.selected == setOf(tiktok) && p5.ticked.isEmpty())
        val p6 = d.plan(installed, emptyMap(), all, emptySet(), emptySet(), emptySet())
        check("«все приложения»: правила у пятерых, отмечать нечего",
            p6.added.size == 5 && p6.selected.isEmpty() && p6.ticked.isEmpty(), "${p6.added}")

        // Только установленные; поставили позже — правило появится.
        val p7 = d.plan(listOf(telegram, chatgpt), emptyMap(), only, setOf(telegram), emptySet(), emptySet())
        check("нет на телефоне — правила нет", p7.added == listOf(chatgpt) && grok !in p7.exits && grok !in p7.seen)
        val p8 = d.plan(listOf(telegram, chatgpt, grok), p7.exits, only, p7.selected, emptySet(), p7.seen)
        check("поставили Grok позже — второй выход и отметка", p8.added == listOf(grok) && grok in p8.selected && p8.exits[grok] == e.SECOND)
        check("пакеты с пробелами и повторами — без дублей",
            d.plan(listOf(" $grok ", grok), emptyMap(), only, emptySet(), emptySet(), emptySet()).added == listOf(grok))
    }

    /**
     * 1.10.44-beta6: начальные экраны после новой установки (25.11: «которые мы отметили уже должны быть
     * отмечены и там выбрать можно, сохранить или пропустить»). Отмечено то, что приложение отметило бы
     * само; «Сохранить» — ровно отмеченные; снятое из отмеченных сразу больше само не отмечается.
     */
    private fun welcomeChecks() {
        val w = WelcomeApps
        val only = ServiceSettings.APPS_ONLY
        val except = ServiceSettings.APPS_EXCEPT
        val all = ServiceSettings.APPS_ALL
        val telegram = "org.telegram.messenger"
        val youtube = "com.google.android.youtube"
        val tiktok = "com.zhiliaoapp.musically"
        val chatgpt = "com.openai.chatgpt"
        val chrome = "com.android.chrome"
        val bank = "ru.sberbankmobile"
        val gone = "org.example.removed"
        val installed = listOf(telegram, youtube, tiktok, chatgpt, chrome, bank)

        // Новая установка: «все приложения», ничего не отмечено и не снято.
        val fresh = w.preset(installed, listOf(telegram, youtube), listOf(tiktok, chatgpt), all, emptySet(), emptySet())
        check("начальные экраны: отмечены набор по умолчанию и второй выход по умолчанию",
            fresh == setOf(telegram, youtube, tiktok, chatgpt), "$fresh")
        check("начальные экраны: без беты — только набор по умолчанию",
            w.preset(installed, listOf(telegram, youtube), emptyList(), all, emptySet(), emptySet()) == setOf(telegram, youtube))
        check("начальные экраны: набор уже применён («только выбранные») — то же, без дублей",
            w.preset(installed, listOf(telegram, youtube), listOf(tiktok, chatgpt), only, setOf(telegram, youtube), emptySet()) == fresh)
        check("начальные экраны: снятое руками не отмечено, своё отмеченное — отмечено",
            w.preset(installed, listOf(telegram, youtube), listOf(tiktok), only, setOf(telegram, chrome), setOf(youtube)) ==
                setOf(telegram, chrome, tiktok))
        check("начальные экраны: исключения «все, кроме» отмеченными не показываются",
            w.preset(installed, listOf(telegram), emptyList(), except, setOf(bank), emptySet()) == setOf(telegram))
        check("начальные экраны: чего нет на телефоне — не отмечено",
            w.preset(listOf(telegram), listOf(telegram, youtube), listOf(tiktok), only, setOf(gone), emptySet()) == setOf(telegram))

        // «Сохранить»: ровно отмеченные; снятое из отмеченных сразу — в «сняли руками».
        val checked = setOf(telegram, chatgpt, chrome)
        val saved = w.selectedAfterSave(installed, checked, all, emptySet())
        check("начальные экраны: сохраняются ровно отмеченные", saved == checked, "$saved")
        check("начальные экраны: отметка удалённого приложения не теряется",
            w.selectedAfterSave(installed, checked, only, setOf(telegram, youtube, gone)) == checked + gone)
        check("начальные экраны: исключения «все, кроме» в выбор не переходят",
            w.selectedAfterSave(installed, setOf(telegram), except, setOf(bank, gone)) == setOf(telegram))
        check("начальные экраны: ничего не отмечено — пусто (сервис пускает все приложения)",
            w.selectedAfterSave(installed, emptySet(), all, emptySet()).isEmpty())
        val unticked = w.untickedOnSave(fresh, checked)
        check("начальные экраны: снятые из отмеченных сразу — в «сняли руками»", unticked == setOf(youtube, tiktok), "$unticked")
        // Потом настроили второй выход: снятый TikTok его по умолчанию не получает, оставленный ChatGPT — получает.
        val plan = SecondDefaults.plan(installed, emptyMap(), only, saved, unticked, emptySet())
        check("начальные экраны: снятый TikTok второй выход не получает, отмеченный ChatGPT — получает",
            tiktok !in plan.exits && plan.exits[chatgpt] == dev.warpscout.core.tunnel.AppExit.SECOND && plan.selected == saved,
            "${plan.exits} ${plan.selected}")
    }

    /** Разбор копии, как в 1.10.40–1.10.43 (прежний Backup.parse): так старая версия прочтёт новую копию. */
    private fun legacyBackupParse(text: String): Map<String, Any?>? {
        val lines = text.removePrefix("\uFEFF").lines().map { it.removeSuffix("\r") }
        if (lines.firstOrNull()?.trim() != "# WarpScout backup v1") return null
        val values = LinkedHashMap<String, Any?>()
        lines.drop(1).forEach { line ->
            if (line.isBlank() || line.startsWith("#")) return@forEach
            val type = line.substringBefore(':', "")
            val body = line.substringAfter(':', "")
            val key = body.substringBefore('=', "")
            val raw = body.substringAfter('=', "")
            if (key.isEmpty()) return@forEach
            when (type) {
                "s" -> values[key] = raw.replace("\\n", "\n").replace("\\\\", "\\")
                "i" -> raw.toIntOrNull()?.let { values[key] = it }
                "l" -> raw.toLongOrNull()?.let { values[key] = it }
                "b" -> values[key] = raw.toBoolean()
                "f" -> raw.toFloatOrNull()?.let { values[key] = it }
                "set" -> values[key] = raw.split('\u0001').filter { it.isNotEmpty() }.toSet()
            }
        }
        return values
    }

    private fun check(name: String, condition: Boolean, detail: String = "") {
        if (condition) {
            passed++
            println("  ✓ $name")
        } else reportFail(name + if (detail.isEmpty()) "" else " — $detail")
    }

    private fun reportFail(msg: String) {
        failed++
        failures.add(msg)
        println("  ✗ $msg")
    }

    private fun expect(name: String, actual: Any?, expected: Any?) =
        check(name, actual?.toString() == expected?.toString(), "факт=$actual ожидалось=$expected")

    // ------------------------------------------------------------------- crypto

    private fun cryptoVectors() {
        // BLAKE2s: значения получены hashlib.blake2s (CPython), т.е. независимо от нашей реализации.
        expect("blake2s(пусто)", Crypto.hex(Blake2s.hash(ByteArray(0))),
            "69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9")
        expect("blake2s(\"abc\")", Crypto.hex(Blake2s.hash("abc".toByteArray())),
            "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982")
        expect("blake2s-128(\"abc\")", Crypto.hex(Blake2s.hash("abc".toByteArray(), 16)),
            "aa4938119b1dc7b87cbad0ffd200d0ae")
        val key = ByteArray(32) { it.toByte() }
        expect("blake2s keyed(\"abc\")", Crypto.hex(Blake2s(32, key).digest("abc".toByteArray())),
            "a281f725754969a702f6fe36fc591b7def866e4b70173ece402fc01c064d6b65")
        expect("hmac-blake2s(\"hello world\")", Crypto.hex(Blake2s.hmac(key, "hello world".toByteArray())),
            "ab8de334c780c9f8619f195f50dc4653044dc0a584c7398a3b89c2a8206ee1b6")
        expect("blake2s 1 МБ потоком = one-shot", run {
                val chunk = ByteArray(64 * 1024) { (it % 251).toByte() }
                val d = Blake2s(32)
                repeat(16) { d.update(chunk) }
                val out = ByteArray(32); d.finalize(out)
                val oneShot = Blake2s.hash(chunk + chunk + chunk + chunk + chunk + chunk + chunk + chunk +
                    chunk + chunk + chunk + chunk + chunk + chunk + chunk + chunk)
                Crypto.hex(out) == Crypto.hex(oneShot)
            }, true)

        // X25519: значения сверены с OpenSSL (python `cryptography`) — независимая реализация,
        // включая правильный clamp приватного ключа (BC/JDK/OpenSSL сходятся байт-в-байт).
        val a = Crypto.unHex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
        val b = Crypto.unHex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0f3")
        expect("x25519 pubkey A", Crypto.hex(Crypto.publicOf(a)),
            "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
        expect("x25519 pubkey B", Crypto.hex(Crypto.publicOf(b)),
            "ad8755450a97a734c552508acee9532b824f379522a085ac05e066e3d448fc31")
        expect("x25519 общий секрет", Crypto.hex(Crypto.dh(a, Crypto.publicOf(b))),
            "2623f1ec8c905e1519e2b3aa25bf07ba09c6ffea666da889be3c2ffd647d4a65")
        check("x25519 симметричность", Crypto.dh(a, Crypto.publicOf(b)).contentEquals(Crypto.dh(b, Crypto.publicOf(a))))

        // base64/hex
        val rnd = ByteArray(32) { (it * 7 + 3).toByte() }
        check("base64 roundtrip", Crypto.unBase64(Crypto.base64(rnd)).contentEquals(rnd))
        check("base64 == java.util", Crypto.base64(rnd) == java.util.Base64.getEncoder().encodeToString(rnd))
        check("hex roundtrip", Crypto.unHex(Crypto.hex(rnd)).contentEquals(rnd))
    }

    private fun chachaCrossCheck() {
        // Шифруем нашей реализацией (BouncyCastle), расшифровываем стандартным JCA — и наоборот.
        val key = ByteArray(32) { (it + 1).toByte() }
        val nonce = ByteArray(12) { (it * 3).toByte() }
        val aad = "wireguard".toByteArray()
        val pt = ByteArray(100) { (it * 5).toByte() }
        val ct = Crypto.chacha20Poly1305Seal(key, nonce, pt, aad)
        check("chachapoly: длина = plaintext+16", ct.size == pt.size + 16)

        // Повторное шифрование тем же nonce не должно бросать: экземпляр AEAD при шифровании
        // создаётся заново. На общем экземпляре BouncyCastle запрещает повтор nonce, а после
        // пересогласования счётчик начинается с нуля — это был бы случайный обрыв туннеля.
        val ctAgain = runCatching { Crypto.chacha20Poly1305Seal(key, nonce, pt, aad) }
        check(
            "chachapoly: шифрование с тем же nonce не падает",
            ctAgain.isSuccess && ctAgain.getOrNull()!!.contentEquals(ct),
            ctAgain.exceptionOrNull()?.message ?: "разные результаты"
        )

        // Шифрование «первые N байт буфера» — путь отправки из tun без копии пакета. Результат
        // обязан совпадать с шифрованием точной копии, иначе на проводе окажется мусор.
        val full = ByteArray(64) { (it * 7).toByte() }
        val partOfBuffer = Crypto.chacha20Poly1305Seal(key, nonce, full, Crypto.EMPTY_AAD, 40)
        val partCopied = Crypto.chacha20Poly1305Seal(key, nonce, full.copyOf(40), Crypto.EMPTY_AAD)
        check("chachapoly: часть буфера шифруется как копия части", partOfBuffer.contentEquals(partCopied))
        check("chachapoly: часть даёт длину N+16", partOfBuffer.size == 56, "${partOfBuffer.size}")
        val openedPart = Crypto.chacha20Poly1305Open(key, nonce, partOfBuffer, Crypto.EMPTY_AAD)
        check(
            "chachapoly: часть расшифровывается обратно",
            openedPart != null && openedPart.contentEquals(full.copyOf(40)),
            "раскрылось ${openedPart?.size} байт"
        )

        val jca = javax.crypto.Cipher.getInstance("ChaCha20-Poly1305")
        jca.init(
            javax.crypto.Cipher.DECRYPT_MODE,
            javax.crypto.spec.SecretKeySpec(key, "ChaCha20-Poly1305"),
            javax.crypto.spec.IvParameterSpec(nonce)
        )
        jca.updateAAD(aad)
        check("chachapoly: JCA расшифровал наш текст", jca.doFinal(ct).contentEquals(pt))

        val jca2 = javax.crypto.Cipher.getInstance("ChaCha20-Poly1305")
        jca2.init(
            javax.crypto.Cipher.ENCRYPT_MODE,
            javax.crypto.spec.SecretKeySpec(key, "ChaCha20-Poly1305"),
            javax.crypto.spec.IvParameterSpec(nonce)
        )
        jca2.updateAAD(aad)
        val ours = Crypto.chacha20Poly1305Open(key, nonce, jca2.doFinal(pt), aad)
        check("chachapoly: наша расшифровка текста JCA", ours?.contentEquals(pt) == true)
        check("chachapoly: неверный AAD отвергается",
            Crypto.chacha20Poly1305Open(ct, key, nonce, "wrong".toByteArray()) == null)

        // RFC 8439 §2.8.2 — известный ответ AEAD ChaCha20-Poly1305.
        val rKey = Crypto.unHex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
        val rNonce = Crypto.unHex("070000004041424344454647")
        val rAad = Crypto.unHex("50515253c0c1c2c3c4c5c6c7")
        val rPt = ("Ladies and Gentlemen of the class of '99: If I could offer you only one tip for " +
            "the future, sunscreen would be it.").toByteArray()
        val expected = ("d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb" +
            "69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808" +
            "b4831d7bc3ff4def08e4b7a9de576d26586cec64b61161ae10b594f09e26a7e902ecbd0600691")
        expect("chachapoly RFC 8439 §2.8.2", Crypto.hex(Crypto.chacha20Poly1305Seal(rKey, rNonce, rPt, rAad)), expected)

        // HChaCha20 — вектор из draft-irtf-cfrg-xchacha §2.2.1
        expect("hchacha20 (§2.2.1)",
            Crypto.hex(Crypto.hChaCha20(ByteArray(32) { it.toByte() },
                Crypto.unHex("000000090000004a0000000031415927"))),
            "82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc")

        // AEAD_XChaCha20_Poly1305 — вектор Appendix A.1 того же черновика
        val xxKey = ByteArray(32) { (0x80 + it).toByte() }
        val xxNonce = ByteArray(24) { (0x40 + it).toByte() }
        val xxAad = Crypto.unHex("50515253c0c1c2c3c4c5c6c7")
        val xxExpected = ("bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb" +
            "731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b452" +
            "2f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9" +
            "21f9664c97637da9768812f615c68b13b52e" + "c0875924c1c7987947deafd8780acf49")
        expect("xchachapoly A.1 (seal)", Crypto.hex(Crypto.xChaCha20Poly1305Seal(xxKey, xxNonce, rPt, xxAad)), xxExpected)
        expect("xchachapoly A.1 (open)",
            Crypto.xChaCha20Poly1305Open(xxKey, xxNonce, Crypto.unHex(xxExpected), xxAad)?.let { String(it) }
                ?.substring(0, 20), rPt.toString(Charsets.ISO_8859_1).substring(0, 20))
        check("xchachapoly: битый tag отвергается",
            Crypto.xChaCha20Poly1305Open(xxKey, xxNonce,
                Crypto.unHex(xxExpected).also { it[40] = (it[40].toInt() xor 1).toByte() }, xxAad) == null)
    }

    // --------------------------------------------------------------- wireguard

    /**
     * Метка времени в инициации — ровно TAI64N из WireGuard. Сервер (ядро Linux, wireguard-go,
     * amneziawg-go) принимает инициацию, только если её метка больше прошлой принятой от этого
     * ключа, и сравнивает байты по порядку. До 1.10.26 метка шла младшим байтом вперёд: WARP её
     * не проверяет, а свой сервер второго выхода отвергал rekey как повтор.
     */
    private fun wgTimestamps() {
        expect("метка времени: эпоха Unix в TAI64N", Crypto.hex(Wg.tai64n(0)), "400000000000000a00000000")
        expect(
            "метка времени: секунды и наносекунды старшим байтом вперёд",
            Crypto.hex(Wg.tai64n(1_500)),
            "400000000000000b1dcd6500"
        )
        // Шаг 37 с прокручивает младший байт секунд десятки раз — на нём и ломалась прежняя метка.
        var earlier = Wg.tai64n(1_763_771_571_000)
        var notNewer = 0
        for (step in 1..2000) {
            val later = Wg.tai64n(1_763_771_571_000 + step * 37_000L)
            if (stampCompare(later, earlier) <= 0) notNewer++
            earlier = later
        }
        expect("метка времени: каждая следующая больше прежней по байтам (как сравнивает сервер)", notNewer, 0)
        var previousFresh = Wg.freshTai64n()
        var freshNotNewer = 0
        repeat(5000) {
            val fresh = Wg.freshTai64n()
            if (stampCompare(fresh, previousFresh) <= 0) freshNotNewer++
            previousFresh = fresh
        }
        expect("метка времени: инициации подряд (в одну миллисекунду) строго растут", freshNotNewer, 0)
    }

    private fun wgInitiationShape() {
        val priv = ByteArray(32) { (it + 2).toByte() }.also { it[31] = 0 }
        val pub = Crypto.publicOf(priv)
        val peer = Crypto.publicOf(ByteArray(32) { (it * 3 + 1).toByte() }.also { a -> a[31] = 0 })
        val init = Wg.buildInitiation(priv, pub, peer, 0x11223344, ephPrivate = ByteArray(32) { 5 }.also { it[31] = 0 }, timestamp = ByteArray(12) { 7 })

        check("init: ровно 148 байт", init.packet.size == Wg.INITIATION_LEN, "длина ${init.packet.size}")
        expect("init: type = 1", Crypto.readLe32(init.packet, 0), 1)
        expect("init: sender index", Crypto.readLe32(init.packet, 4), 0x11223344)
        check("init: эфемерный ключ = pubkey",
            init.packet.copyOfRange(8, 40).contentEquals(Crypto.publicOf(ByteArray(32) { 5 }.also { it[31] = 0 })))
        // детерминизм: те же входы → те же байты
        val init2 = Wg.buildInitiation(priv, pub, peer, 0x11223344, ephPrivate = ByteArray(32) { 5 }.also { it[31] = 0 }, timestamp = ByteArray(12) { 7 })
        check("init: детерминирован при фиксированных ключах/метке", init.packet.contentEquals(init2.packet))
        // метка TAI64N входит в шифротекст, поэтому при другом timestamp всё меняется
        val init3 = Wg.buildInitiation(priv, pub, peer, 0x11223344, ephPrivate = ByteArray(32) { 5 }.also { it[31] = 0 }, timestamp = ByteArray(12) { 8 })
        check("init: метка времени влияет на пакет", !init.packet.contentEquals(init3.packet))
        expect("keyId() = первые 4 байта HASH(pub)", Wg.keyId(pub), Crypto.readLe32(Blake2s.hash(pub), 0))
    }

    /**
     * Полный круг: инициируем handshake, сами играем роль сервера (ровно по спецификации, в обратную
     * сторону), проверяем ответ и выводим ключи сессии. Если где-то ошиблись в цепочке HASH/HMAC/AEAD —
     * tag не сойдётся.
     */
    private fun wgHandshakeLoopback() {
        val clientPriv = ByteArray(32) { (it * 5 + 1).toByte() }.also { it[31] = 0 }
        val serverPriv = ByteArray(32) { (200 - it).toByte() }.also { it[31] = 0 }
        val clientPub = Crypto.publicOf(clientPriv)
        val serverPub = Crypto.publicOf(serverPriv)

        val init = Wg.buildInitiation(clientPriv, clientPub, serverPub, 0x0badf00d)
        val response = WgResponder.respond(init.packet, serverPriv, receiverIndex = Crypto.readLe32(init.packet, 4))
        check("resp: 92 байта", response.size == Wg.RESPONSE_LEN, "длина ${response.size}")

        val reply = Wg.consumeResponse(response, init)
        expect("resp: принят как HANDSHAKE_OK", reply.kind.toString(), "HANDSHAKE_RESPONSE")
        check("resp: есть ключи сессии", reply.session != null)

        // портим 1 байт — принять должно отказаться
        val broken = response.copyOf().also { it[50] = (it[50].toInt() xor 0x01).toByte() }
        expect("resp: битый пакет отвергнут", Wg.consumeResponse(broken, init).kind.toString(), "MISMATCH")
        // ответ от другого индекса — отвергается
        expect("resp: чужой receiver_index отвергнут",
            Wg.consumeResponse(response.copyOfRange(0, 8) + Crypto.le32(1) + response.copyOfRange(12, 92), init).kind.toString(),
            "MISMATCH")
        val keep = Wg.buildKeepalive(0x1234, reply.session!!)
        check("keepalive: 32 байта, type=4", keep.size == 32 && Crypto.readLe32(keep, 0) == 4)
        expect("resp: sender index сервера проброшен", reply.peerSenderIndex?.toString(), (0x5a5a5a5a).toString())

        // ---- транспорт: данные в обе стороны через ключи сессии
        val (respSrv, srvSession) = WgResponder.respondWithSession(init.packet, serverPriv)
        val cliSession = Wg.consumeResponse(respSrv, init).session!!
        val payload = "данные сквозь туннель".toByteArray()
        val (pkt, cliAfter) = Wg.buildTransport(0x5a5a5a5a, cliSession, payload)
        check("transport: длина = 32 + данные", pkt.size == 32 + payload.size, "длина ${pkt.size}")
        check("transport: type = 4", Crypto.readLe32(pkt, 0) == 4)
        val opened = Wg.openTransport(pkt, 0x5a5a5a5a, srvSession)
        check("transport: сервер расшифровал пакет", opened?.first?.contentEquals(payload) == true)
        check("transport: повтор отвергнут", opened?.let { Wg.openTransport(pkt, 0x5a5a5a5a, it.second) } == null)
        val srvAfter = opened!!.second
        val (back, _) = Wg.buildTransport(0x0badf00d, srvAfter, payload.reversedArray())
        val cliGot = Wg.openTransport(back, 0x0badf00d, cliAfter)
        check("transport: клиент расшифровал ответ", cliGot?.first?.contentEquals(payload.reversedArray()) == true)
        val bad = back.copyOf().also { it[20] = (it[20].toInt() xor 0x40).toByte() }
        check("transport: битый тег отвергнут", Wg.openTransport(bad, 0x0badf00d, cliAfter) == null)

        // Переставленные пакеты (RFC 6479, с 1.10.49-beta1): опоздавший принимается, повтор — нет.
        val (ooo1, cliOoo1) = Wg.buildTransport(0x5a5a5a5a, cliAfter, "p1".toByteArray())
        val (ooo2, _) = Wg.buildTransport(0x5a5a5a5a, cliOoo1, "p2".toByteArray())
        val got2 = Wg.openTransport(ooo2, 0x5a5a5a5a, srvAfter)
        val got1 = got2?.let { Wg.openTransport(ooo1, 0x5a5a5a5a, it.second) }
        check("transport: переупорядоченный UDP-пакет принят (RFC 6479)", got1?.first?.contentEquals("p1".toByteArray()) == true)
        check("transport: повтор переупорядоченного пакета отвергнут", got1?.let { Wg.openTransport(ooo1, 0x5a5a5a5a, it.second) } == null)
        val window = Wg.ReplayWindow().also { it.mark(5000) }
        check("transport: окно повторов — 2048 номеров",
            window.isAcceptable(5000 - 2047) && !window.isAcceptable(5000 - 2048) && !window.isAcceptable(5000) && window.isAcceptable(5001))

        // ---- cookie reply: сервер «под нагрузкой»
        val cookie = ByteArray(16) { (it + 1).toByte() }
        val init2 = Wg.buildInitiation(clientPriv, clientPub, serverPub, 0x77)
        val msg = WgResponder.cookieReply(init2.packet, serverPriv, cookie)
        check("cookie: 64 байта", msg.size == 64, "длина ${msg.size}")
        val r3 = Wg.consumeResponse(msg, init2, serverPub)
        expect("cookie: распознан как COOKIE_REPLY", r3.kind.toString(), "COOKIE_REPLY")
        check("cookie: расшифрован XChaCha20-Poly1305", r3.cookie?.contentEquals(cookie) == true,
            "cookie=${r3.cookie?.let { Crypto.hex(it) }}")
        // без публичного ключа пира cookie не расшифровать — но вердикт всё равно верный
        check("cookie: без ключа пира cookie не расшифровывается", Wg.consumeResponse(msg, init2).cookie == null)
        // повторная инициация с mac2 = MAC(cookie) должна пройти серверную проверку
        val init3 = Wg.buildInitiation(clientPriv, clientPub, serverPub, 0x88, lastCookie = cookie)
        check("cookie: mac2 проходит проверку сервера", WgResponder.mac2Valid(init3.packet, cookie))
        check("cookie: mac2 не проходит без cookie", !WgResponder.mac2Valid(init2.packet, cookie))
        val resp3 = WgResponder.respond(init3.packet, serverPriv)
        expect("cookie: повторная инициация принята", Wg.consumeResponse(resp3, init3, serverPub).kind.toString(),
            "HANDSHAKE_RESPONSE")
    }

    // ------------------------------------------------------------------- junk

    private fun quicMaskRoundTrip() {
        val sni = "ivi.ru"
        val dcid = byteArrayOf(0x42)
        val ch = QuicMask.clientHelloSniOnly(sni, ByteArray(32) { (it + 1).toByte() })
        val (payload, _) = QuicMask.clientHelloToFrames(ch, 3)
        val packet = QuicMask.initial(dcid, payload)

        check("quic: пакет разумной длины", packet.size in 40..400, "размер ${packet.size}")
        // long header + version 1
        check("quic: это QUIC long header", (packet[0].toInt() and 0x80) != 0)
        expect("quic: version = 1 (в unprotected заголовке после снятия HP)",
            run {
                val unprotected = QuicMaskForTest.unprotect(packet, dcid)
                Crypto.hex(unprotected.copyOfRange(1, 5))
            }, "00000001")
        val clientHello = QuicMaskForTest.extractClientHello(packet, dcid)
        check("quic: CRYPTO-фреймы собираются обратно в ClientHello", clientHello.isNotEmpty() && clientHello[0] == 0x01.toByte())
        check("quic: SNI внутри ClientHello", String(clientHello, 0, clientHello.size, Charsets.ISO_8859_1).contains(sni))

        val tmpl = QuicMask.buildTemplate(sni, level = 3, seed = 11)
        check("quic: шаблон состоит из литерала", tmpl.isNotEmpty() && tmpl.first() is JunkChunk.Literal)
        val rendered = WgConf.renderJunk(tmpl)
        check("quic: шаблон рендерится в <b 0x…>", rendered.startsWith("<b 0x"), rendered.take(24))
        val reparsed = WgConf.parseJunk(rendered)
        check("quic: шаблон читается обратно", JunkChunk.renderAll(reparsed) == rendered)
    }

    private fun templateRendering() {
        val chunks = listOf(JunkChunk.Literal(byteArrayOf(0xde.toByte(), 0xad.toByte(), 0xbe.toByte(), 0xef.toByte())), JunkChunk.RandomBytes(16))
        expect("рендер чанков", JunkChunk.renderAll(chunks), "<b 0xdeadbeef><r 16>")
        val back = WgConf.parseJunk("<b 0xdeadbeef><r 16>")
        check("парсинг чанков", back.size == 2 && (back[1] as JunkChunk.RandomBytes).size == 16)
        val mat = chunks[1].materialize(Crypto.random)
        check("материализация случайного чанка", mat.size == 16 && mat.any { it != 0.toByte() })
    }

    // ------------------------------------------------------------------ конфиг

    private fun confRoundTrip() {
        val text = """
            [Interface]
            PrivateKey = 6KGXl3bW0YR6gxRxBDxI2sO1hCwSjFPHqZ4zXK+8YnM=
            Address = 172.16.0.2, 2606:4700:110:8b63:28c5:b72d:11d1:de72
            DNS = 1.1.1.1, 1.0.0.1
            MTU = 1280
            S1 = 0
            S2 = 0
            S3 = 0
            S4 = 0
            Jc = 4
            Jmin = 40
            Jmax = 70
            H1 = 1
            H2 = 2
            H3 = 3
            H4 = 4
            I1 = <b 0xdeadbeef><r 16>

            [Peer]
            PublicKey = bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=
            AllowedIPs = 0.0.0.0/0, ::/0
            Endpoint = 188.114.98.2:943
            PersistentKeepalive = 25
        """.trimIndent()

        val cfg = WgConf.toWarpConfig("тест", text)
        check("парсинг: конфиг прочитан", cfg != null)
        cfg!!
        expect("парсинг: endpoint", cfg.endpoint.render(), "188.114.98.2:943")
        expect("парсинг: mtu", cfg.mtu, 1280)
        expect("парсинг: keepalive", cfg.persistentKeepalive, 25)
        expect("парсинг: Jc", cfg.junk.awg.jc, 4)
        expect("парсинг: I1 → чанки", JunkChunk.renderAll(cfg.junk.i1), "<b 0xdeadbeef><r 16>")
        expect("парсинг: IPv6-адрес подхвачен", cfg.account.ipv6, "2606:4700:110:8b63:28c5:b72d:11d1:de72")

        val rendered = WgConf.render(cfg)
        val again = WgConf.toWarpConfig("тест2", rendered)!!
        expect("round-trip: endpoint", again.endpoint.render(), cfg.endpoint.render())
        expect("round-trip: I1", JunkChunk.renderAll(again.junk.i1), JunkChunk.renderAll(cfg.junk.i1))
        expect("round-trip: allowedIps", again.allowedIps, cfg.allowedIps)
        check("round-trip: блоки Interface/Peer на месте",
            rendered.contains("[Interface]") && rendered.contains("[Peer]"))

        // конфиг без приватного ключа — не валиден
        check("парсинг: конфиг без ключа отклонён", WgConf.toWarpConfig("x", "[Peer]\nPublicKey = y") == null)
        expect("парсинг: IPv6 endpoint", WgConf.parseEndpoint("[2606:4700:1::3]:1074").render(), "[2606:4700:1::3]:1074")
    }

    private fun sampleFiles() {
        val dir = listOf("samples", "../samples", "../../samples")
            .map { java.io.File(it) }
            .firstOrNull { it.isDirectory }
        if (dir == null) {
            println("    (каталог samples/ не найден — пропускаю)")
            return
        }
        val files: Array<java.io.File> = dir.listFiles { x: java.io.File -> x.name.endsWith(".conf") } ?: emptyArray()
        for (f in files) {
            val cfg = WgConf.toWarpConfig(f.name, f.readText())
            check("образец ${f.name} разбирается", cfg != null)
            if (cfg == null) continue
            check("образец ${f.name}: профиль шума непустой", !cfg.junk.isEmpty, "I1=${cfg.junk.i1.size} чанков")
            check("образец ${f.name}: публичный ключ Cloudflare",
                cfg.account.peerPublicB64 == "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=")
        }
    }

    // ------------------------------------------------------------ endpoint pool

    private fun endpointPool() {
        val a = EndpointPool.build(EndpointSpec(seed = 1))
        val b = EndpointPool.build(EndpointSpec(seed = 1))
        val c = EndpointPool.build(EndpointSpec(seed = 2))
        check("пул: детерминирован по seed", a == b)
        check("пул: seed меняет выборку", a != c)
        check("пул: respecting maxEndpoints", a.size <= 400 && a.isNotEmpty(), "размер ${a.size}")
        check("пул: все порты из списка генератора", a.all { it.port in dev.warpscout.core.net.WarpDefaults.AWG_PORTS })
        check("пул: хостнеймы не дублируются", a.map { it.render() }.distinct().size == a.size)

        val full = EndpointPool.build(EndpointSpec(subnets = listOf("10.0.0."), ports = listOf(500, 501), octetRange = 0..3, mode = PoolMode.FULL, maxEndpoints = 100))
        expect("пул: FULL перебор", full.size, 8)
        val parsed = EndpointPool.parseList("162.159.192.*:943\n188.114.96.1-4:443 # комментарий\nengage.cloudflareclient.com:2408")
        expect("парсинг: * → 10 хостов", parsed.count { it.host.startsWith("162.159.192.") }, 10)
        expect("парсинг: диапазон октетов", parsed.count { it.host.startsWith("188.114.96.") }, 4)
        expect("парсинг: явный хост", parsed.last().render(), "engage.cloudflareclient.com:2408")
        check("парсинг: мусор игнорируется", EndpointPool.parseList("\n# только комментарий\n").isEmpty())
        // EXPLICIT — режим, в который UI превращает набранный пользователем список
        val explicit = EndpointPool.build(
            EndpointSpec(
                subnets = emptyList(),
                hostnames = listOf("8.6.112.*:943", "188.114.96.1-3:443", "engage.example.com:2408"),
                mode = PoolMode.EXPLICIT,
                maxEndpoints = 100
            )
        )
        check(
            "пул: EXPLICIT сканит ровно то, что набрал пользователь",
            explicit.size == 14 && explicit.any { it.host == "8.6.112.1" && it.port == 943 } &&
                explicit.count { it.port == 443 } == 3 && explicit.last().render() == "engage.example.com:2408",
            "размер=${explicit.size}"
        )
        expect("роуты обхода белых списков", RoutePresets.BYPASS_WHITELIST.size, 56)

        // 1.10.29: предел пула не должен обрезать его на первой подсети (журнал 22.11 16:32: все 120
        // точек из 162.159.192.x, «живых 0», а 188.114.97.1:500 при этом отвечала).
        val spread = EndpointPool.build(EndpointSpec(maxEndpoints = 120, seed = 5))
        val subnetsSeen = spread.map { it.host.substringBeforeLast('.') + "." }.distinct()
        check(
            "пул: 120 точек покрывают все подсети, а не одну-две",
            subnetsSeen.size == dev.warpscout.core.net.WarpDefaults.AWG_SUBNETS.size,
            subnetsSeen.joinToString()
        )
        check(
            "пул: в каждой подсети есть порт 500",
            dev.warpscout.core.net.WarpDefaults.AWG_SUBNETS.all { pre -> spread.any { it.host.startsWith(pre) && it.port == 500 } }
        )
        check("пул: 120 точек — ровно 120", spread.size == 120, "размер ${spread.size}")
    }

    /**
     * 1.10.29: проверка данных после рукопожатия. Точка, которая отвечает на рукопожатие, но не
     * пропускает данные («вверх 5542, вниз 0» в журнале 22.11), не должна считаться рабочей — ни
     * в подборе, ни в очереди, ни при подключении.
     */
    private fun dataProbeChecks() {
        val probe = dev.warpscout.core.tunnel.DataProbe
        val src = probe.ipv4Of("172.16.0.2/32")
        check("проба данных: адрес туннеля разбирается", src?.toList() == listOf<Byte>(172.toByte(), 16, 0, 2))
        check("проба данных: IPv6 — не адрес для пробы", probe.ipv4Of("2606:4700::1") == null)
        val query = probe.dnsQuery(src ?: ByteArray(4), 40001, 0x1234)
        expect("проба данных: запрос — 60 байт", query.size, 60)
        expect("проба данных: сумма IP-заголовка сходится", probe.checksum(query, 0, 20, 0L), 0)
        fun w(b: ByteArray, o: Int) = (((b[o].toInt() and 0xff) shl 8) or (b[o + 1].toInt() and 0xff)).toLong()
        val udpLen = query.size - 20
        val pseudo = w(query, 12) + w(query, 14) + w(query, 16) + w(query, 18) + 17L + udpLen.toLong()
        expect("проба данных: сумма UDP сходится", probe.checksum(query, 20, udpLen, pseudo), 0)
        val reply = fakeDnsReply(query)
        check("проба данных: ответ узнаётся", reply != null && probe.isReply(reply, 40001, 0x1234))
        check("проба данных: чужой номер запроса — не наш ответ", reply != null && !probe.isReply(reply, 40001, 0x1235))
        check("проба данных: чужой порт — не наш ответ", reply != null && !probe.isReply(reply, 40002, 0x1234))
        check("проба данных: сам запрос ответом не считается", !probe.isReply(query, 40001, 0x1234))

        val clientPriv = ByteArray(32) { (it * 7 + 3).toByte() }
        val serverPriv = ByteArray(32) { (it * 11 + 5).toByte() }
        val serverPub = Crypto.publicOf(serverPriv)
        val account = WarpAccount(Crypto.base64(clientPriv), Crypto.base64(serverPub))
        val prober = WgProber(NetSettings(attempts = 2, timeoutMs = 800, betweenAttemptsMs = 0))

        // Сервер, который отвечает на DNS внутри сессии: точка рабочая.
        val dnsServer = LoopbackServer(serverPriv, answerData = { fakeDnsReply(it) }).start()
        try {
            val ok = prober.probe(Endpoint("127.0.0.1", dnsServer.port), account, serverPub, null, dataProbe = true)
            check(
                "проба данных: рукопожатие и ответ через сессию",
                ok.stats.replies > 0 && ok.stats.dataReplies > 0 && !ok.stats.dataBlocked,
                ok.stats.samples.joinToString { it.note }
            )
            check("проба данных: время ответа записано", ok.stats.dataMs != null)
            val plain = prober.probe(Endpoint("127.0.0.1", dnsServer.port), account, serverPub, null)
            check("проба данных: без флага — только рукопожатие, как раньше", plain.stats.dataTried == 0 && plain.stats.replies > 0)

            val h = startPlane(clientPriv, serverPub, dnsServer.port, NetSettings(attempts = 2, timeoutMs = 800))
            try {
                check("data plane: поднялся для пробы данных", h.awaitUp(3000), h.log.toString())
                check("data plane: проба данных ушла", h.plane.sendDataProbe())
                val until = System.currentTimeMillis() + 2000
                while (h.plane.probeReplies == 0 && System.currentTimeMillis() < until) Thread.sleep(20)
                check("data plane: ответ на пробу данных пришёл", h.plane.probeReplies > 0)
                check("data plane: ответ пробы не попал в tun", h.tunOut.poll(200L) == null)
                check("data plane: ответ пробы не считается трафиком приложений", h.plane.bytesDown == 0L)
            } finally {
                h.stop()
            }
        } finally {
            dnsServer.stop()
        }

        // Сервер отвечает на рукопожатие, а данные выбрасывает — ровно «вверх есть, вниз 0».
        val blackhole = LoopbackServer(serverPriv, answerData = { null }).start()
        try {
            val dead = prober.probe(Endpoint("127.0.0.1", blackhole.port), account, serverPub, null, dataProbe = true)
            check(
                "проба данных: «рукопожатие есть, данных нет» распознано",
                dead.stats.replies > 0 && dead.stats.dataBlocked,
                dead.stats.samples.joinToString { it.note }
            )
            val cfg = WarpConfig(
                name = "т", account = account, endpoint = Endpoint("127.0.0.1", blackhole.port), junk = JunkLibrary.none()
            )
            val blocked = Candidate(cfg, dead.stats, Scoring.evaluate(dead.stats, true))
            check("очередь: точка без данных в неё не попадает", !blocked.usable && Shortlist.pick(listOf(blocked)).isEmpty())
            val report = dev.warpscout.core.model.TuningReport("т", "т", "п", listOf(blocked), emptyList(), 1)
            check("отчёт: точка без данных не становится лучшей", report.best == null)
            check(
                "быстрый старт: точка без данных не подтверждается",
                !CachedPoint.confirmed(dead.stats.replies, 0, 0, dead.stats.dataTried, dead.stats.dataReplies)
            )
            val h = startPlane(clientPriv, serverPub, blackhole.port, NetSettings(attempts = 2, timeoutMs = 800))
            try {
                check("data plane: поднялся на точке без данных", h.awaitUp(3000), h.log.toString())
                h.plane.sendDataProbe()
                Thread.sleep(600)
                check("data plane: на точке без данных ответа на пробу нет", h.plane.probeReplies == 0)
            } finally {
                h.stop()
            }
        } finally {
            blackhole.stop()
        }

        // Балл: «рукопожатие есть, данных нет» ниже точки, через которую данные идут, при любом прочем.
        val ep = Endpoint("1.2.3.4", 500)
        val withData = EndpointStats(ep, listOf(ProbeSample(ep, Verdict.HANDSHAKE_OK, 300.0, 0, dataTried = true, dataMs = 310.0)), Verdict.HANDSHAKE_OK, 1, 3)
        val noData = EndpointStats(ep, listOf(
            ProbeSample(ep, Verdict.HANDSHAKE_OK, 10.0, 0, dataTried = true),
            ProbeSample(ep, Verdict.HANDSHAKE_OK, 11.0, 1, dataTried = true),
            ProbeSample(ep, Verdict.HANDSHAKE_OK, 12.0, 2)
        ), Verdict.HANDSHAKE_OK, 3, 3)
        check(
            "скоринг: медленная точка с данными выше быстрой без данных",
            Scoring.evaluate(withData, false).total > Scoring.evaluate(noData, true).total,
            "${Scoring.evaluate(withData, false).total} против ${Scoring.evaluate(noData, true).total}"
        )
        check("быстрый старт: данные пришли — подтверждается", CachedPoint.confirmed(1, 0, 0, 1, 1))
        expect(
            "снимок: начало проверки данных переживает JSON",
            TunnelStatus.fromJson(TunnelStatus(dataCheckAt = 1_758_000_000_777L).toJson())?.dataCheckAt,
            1_758_000_000_777L
        )
    }

    /**
     * 1.10.30: «данные пошли и встали» и маскировка. Журнал 22.11: на сети человека чистый WireGuard
     * отвечал на рукопожатие и на первый DNS-запрос, а дальше молчал — подбор выбирал его раз за
     * разом, хотя туннель держался только с шумом (tls-fixed — 12 часов подряд).
     */
    private fun sustainChecks() {
        val clientPriv = ByteArray(32) { (it * 7 + 3).toByte() }
        val serverPriv = ByteArray(32) { (it * 11 + 5).toByte() }
        val serverPub = Crypto.publicOf(serverPriv)
        val account = WarpAccount(Crypto.base64(clientPriv), Crypto.base64(serverPub))
        val prober = WgProber(NetSettings(attempts = 2, timeoutMs = 800, betweenAttemptsMs = 0))

        // Сервер отвечает на все запросы внутри сессии: данные идут и не встают.
        val steady = LoopbackServer(serverPriv, answerData = { fakeDnsReply(it) }).start()
        try {
            val ep = Endpoint("127.0.0.1", steady.port)
            val s1 = prober.probeSustained(ep, account, serverPub, null, 2_400)
            check(
                "долгая проба: данные идут и через полторы секунды",
                s1.dataTried && s1.dataSustained && !s1.dataFrozen && s1.dataMs != null,
                s1.note
            )
            val s2 = prober.probeSustained(ep, account, serverPub, JunkLibrary.tlsFixed(), 2_400)
            check("долгая проба: с шумом tls-fixed тоже", s2.dataSustained && s2.profile == "tls-fixed", s2.note)
            // Время ответа профиля с шумом — от инициации, без паузы после мусорного пакета
            // (Jmin = 40 мс): раньше любой шум проигрывал «none» по пингу на ровном месте.
            val masked = prober.probe(ep, account, serverPub, JunkLibrary.tlsFixed())
            val rtt = masked.stats.minRtt ?: 999.0
            check("пинг профиля с шумом не включает паузу после мусора", rtt < 38.0, "rtt=$rtt мс")
        } finally {
            steady.stop()
        }

        // Сервер отвечает только на первый пакет данных — ровно «пошли и встали».
        val answered = java.util.concurrent.atomic.AtomicInteger(0)
        val freezer = LoopbackServer(serverPriv, answerData = { q ->
            if (answered.incrementAndGet() <= 1) fakeDnsReply(q) else null
        }).start()
        try {
            val ep = Endpoint("127.0.0.1", freezer.port)
            val f = prober.probeSustained(ep, account, serverPub, null, 2_400)
            check(
                "долгая проба: «первый ответ есть, дальше тишина» — заморозка",
                f.dataTried && f.dataFrozen && !f.dataSustained && f.dataMs != null,
                f.note
            )
            val quick = ProbeSample(ep, Verdict.HANDSHAKE_OK, 20.0, 0, dataTried = true, dataMs = 21.0)
            val st = EndpointStats(ep, listOf(quick, f), Verdict.HANDSHAKE_OK, 1, 1)
            check("замёрзшая точка считается точкой без данных", st.dataFrozen && st.dataBlocked)
            val cfg = WarpConfig(name = "т", account = account, endpoint = ep, junk = JunkLibrary.none())
            val cand = Candidate(cfg, st, Scoring.evaluate(st, true, plain = true))
            check("замёрзшая точка в очередь не попадает", !cand.usable && Shortlist.pick(listOf(cand)).isEmpty())
            val okSample = ProbeSample(ep, Verdict.HANDSHAKE_OK, 20.0, 0, dataTried = true, dataMs = 21.0, dataSustained = true)
            val healed = EndpointStats(ep, listOf(quick, f, okSample), Verdict.HANDSHAKE_OK, 1, 1)
            check("долгая проба «идут» перевешивает прошлую заморозку", !healed.dataFrozen && !healed.dataBlocked)
        } finally {
            freezer.stop()
        }

        // Маскировка в баллах: при равных замерах вариант с шумом выше, а проверенный долгой пробой
        // шум выше быстрого «без шума».
        val ep2 = Endpoint("1.2.3.4", 500)
        fun st(ms: Double, sustained: Boolean = false) = EndpointStats(
            ep2,
            listOf(ProbeSample(ep2, Verdict.HANDSHAKE_OK, ms, 0, dataTried = true, dataMs = ms + 5, dataSustained = sustained)),
            Verdict.HANDSHAKE_OK, 3, 3
        )
        val plainScore = Scoring.evaluate(st(40.0), true, plain = true).total
        val maskedScore = Scoring.evaluate(st(40.0), true, plain = false).total
        check("маскировка: с шумом выше, чем без шума, при равных замерах", maskedScore > plainScore, "$maskedScore против $plainScore")
        val fastPlain = Scoring.evaluate(st(20.0), true, plain = true).total
        val slowMasked = Scoring.evaluate(st(150.0, sustained = true), true, plain = false).total
        check("маскировка: шум с долгой пробой выше быстрого «без шума»", slowMasked > fastPlain, "$slowMasked против $fastPlain")

        // Имя шума по самим пакетам: сервис и память сетей узнают профиль из текста конфига, где
        // имени нет (там он «imported»).
        for (p in JunkLibrary.defaultPool()) {
            expect("имя шума по пакетам: ${p.name}", JunkLibrary.nameOf(p.copy(name = "imported")), p.name)
            val cfg = WarpConfig(name = "т", account = account, endpoint = ep2, junk = p)
            val back = WgConf.toWarpConfig("т", WgConf.render(cfg))
            expect("имя шума переживает текст конфига: ${p.name}", back?.let { JunkLibrary.nameOf(it.junk) }, p.name)
            expect("профиль по имени: ${p.name}", JunkLibrary.byName(p.name)?.let { JunkChunk.renderAll(it.i1 + it.i2) }, JunkChunk.renderAll(p.i1 + p.i2))
        }
        // С 1.10.40 первым — «как Chrome», вторым — фиксированный TLS (см. JunkLibrary.serviceOrder).
        expect("порядок шума в сервисе: первым «как Chrome», вторым tls-fixed",
            JunkLibrary.serviceOrder().take(2).map { it.name }, listOf("chrome:apteka.ru", "tls-fixed"))
        expect("порядок шума в сервисе: «без шума» последним", JunkLibrary.serviceOrder().lastOrNull()?.name, "none")
        check("неизвестный шум по имени — null", JunkLibrary.byName("нет-такого") == null)
    }

    /**
     * Проверка данных в сервисе (1.10.30): рабочим туннель считается, только если данные идут и
     * через полторы секунды. Моделируем сеть: проба, отправленная в момент t, получает ответ через
     * rtt мс, если сеть её пропускает.
     */
    private fun dataGateChecks() {
        fun runGate(
            replyIf: (Long) -> Boolean,
            rtt: Long = 80L,
            bytesAt: (Long) -> Long = { 0L },
            slowNet: Boolean = false
        ): Pair<DataGate.Verdict?, Long> {
            val gate = if (slowNet) DataGate.forSlowNetwork() else DataGate()
            val sentAt = ArrayList<Long>()
            var t = 0L
            while (t <= 12_000L) {
                val replies = sentAt.count { s0 -> replyIf(s0) && t >= s0 + rtt }
                when (gate.step(t, replies, bytesAt(t))) {
                    DataGate.Step.SEND_PROBE -> sentAt += t
                    DataGate.Step.DONE -> return gate.verdict to t
                    DataGate.Step.WAIT -> t += 40L
                }
            }
            return gate.verdict to t
        }
        val flowing = runGate({ true })
        expect("проверка данных: данные идут — рабочий", flowing.first, DataGate.Verdict.FLOWING)
        check("проверка данных: рабочий — меньше чем за две секунды", flowing.second < 2_000L, "t=${flowing.second}")
        // Журнал 22.11 19:04:45: ответ на первую пробу пришёл, дальше — тишина.
        val frozen = runGate({ it < 500L })
        expect("проверка данных: «пошли и встали» — заморозка", frozen.first, DataGate.Verdict.FROZEN)
        expect("проверка данных: ни ответа — данных нет", runGate({ false }).first, DataGate.Verdict.NO_DATA)
        val apps = runGate({ false }, bytesAt = { it / 100L * 50L })
        expect("проверка данных: приложения получают байты и после 1,5 с — рабочий", apps.first, DataGate.Verdict.FLOWING)
        check("проверка данных: по байтам приложений — сразу после 1,5 с", apps.second in 1_500L..1_700L, "t=${apps.second}")
        // Журнал 22.11 18:53: «вверх 1091, вниз 60 байт» за полсекунды — и больше ничего.
        val bytesFrozen = runGate({ false }, bytesAt = { if (it >= 300L) 120L else 0L })
        expect("проверка данных: 120 байт в начале и тишина — заморозка", bytesFrozen.first, DataGate.Verdict.FROZEN)
        val slow = runGate({ true }, rtt = 1_200L)
        expect("проверка данных: медленная сеть (1,2 с на ответ) — рабочий", slow.first, DataGate.Verdict.FLOWING)
        check("проверка данных: укладывается в окно", flowing.second <= DataGate.WINDOW_MS && slow.second <= DataGate.WINDOW_MS)

        // H/H+ под нагрузкой (1.10.40): ответ через 4,5 с. Обычное окно (4 с) кончается раньше —
        // «данных нет», хотя они идут; окно медленной связи (8 с) их дожидается.
        expect("медленная связь: ответ через 4,5 с — обычная проверка его не дожидается",
            runGate({ true }, rtt = 4_500L).first, DataGate.Verdict.NO_DATA)
        val slowGate = runGate({ true }, rtt = 4_500L, slowNet = true)
        expect("медленная связь: ответ через 4,5 с — для H/H+ рабочий", slowGate.first, DataGate.Verdict.FLOWING)
        check("медленная связь: решение в пределах окна", slowGate.second <= DataGate.SLOW_WINDOW_MS, "t=${slowGate.second}")
        // Правило то же: «пошли и встали» и на медленной связи — заморозка, тишина — «данных нет».
        expect("медленная связь: «пошли и встали» — всё ещё заморозка",
            runGate({ it < 500L }, slowNet = true).first, DataGate.Verdict.FROZEN)
        expect("медленная связь: ни ответа — данных нет", runGate({ false }, slowNet = true).first, DataGate.Verdict.NO_DATA)
        expect("медленная связь: окно проверки — 8 с", DataGate.forSlowNetwork().windowMs, 8_000L)
    }

    /**
     * Доступность сервисов (1.10.30): ChatGPT «открылся» только если сайт видит обслуживаемую
     * страну; приложения проверяются подключением к их серверам; свои сайты разбираются из текста.
     */
    private fun availabilityChecks() {
        val chatgpt = Presets.SERVICE_CHECKS.firstOrNull { it.id == "chatgpt" }
        check("доступность: ChatGPT проверяется по стране", chatgpt != null && "RU" in chatgpt.blockedCountries)
        if (chatgpt != null) {
            val ru = dev.warpscout.core.net.ResourceProber.judge(chatgpt, 200, "fl=1f1\nip=1.2.3.4\nloc=RU\ncolo=ARN\n")
            check("доступность: ChatGPT видит RU — не открылся", !ru.ok && ru.errorClass == "region:RU", "${ru.errorClass}")
            val nl = dev.warpscout.core.net.ResourceProber.judge(chatgpt, 200, "ip=1.2.3.4\nloc=NL\ncolo=AMS\n")
            check("доступность: ChatGPT видит NL — открылся", nl.ok && nl.detail == "NL", nl.detail)
            val nlText = dev.warpscout.core.net.ResourceProber.describe(
                ResourceResult(chatgpt, ok = true, elapsedMs = 120, detail = nl.detail)
            )
            check("доступность: страна в строке словами", nlText.contains("страну NL"), nlText)
            val blocked = ResourceResult(chatgpt, ok = false, errorClass = "region:RU")
            check(
                "доступность: отказ по стране объяснён словами",
                dev.warpscout.core.net.ResourceProber.describe(blocked).contains("RU")
            )
            val noLoc = dev.warpscout.core.net.ResourceProber.judge(chatgpt, 200, "<html>заглушка</html>")
            check("доступность: ответ без страны — не «открылся»", !noLoc.ok)
            check("доступность: код 403 — не «открылся»", !dev.warpscout.core.net.ResourceProber.judge(chatgpt, 403, "loc=NL").ok)
        }
        val ids = Presets.SERVICE_CHECKS.map { it.id }
        expect("доступность: восемь сервисов", ids.size, 8)
        check("доступность: коды сервисов не повторяются", ids.toSet().size == ids.size && ids.none { it.isBlank() })
        val discord = Presets.SERVICE_CHECKS.first { it.id == "discord" }
        check(
            "доступность: чужой ответ вместо API — не «открылся»",
            !dev.warpscout.core.net.ResourceProber.judge(discord, 200, "<html>stub</html>").ok
        )

        val custom = Presets.customChecks("example.com\nhttps://a.example.org/путь # мой\nне сайт\n\nexample.com, локалхост")
        expect("свои сайты: разобраны два", custom.size, 2)
        expect("свои сайты: имя без адреса — https", custom.firstOrNull()?.url, "https://example.com/")
        expect("свои сайты: адрес как есть", custom.getOrNull(1)?.url, "https://a.example.org/путь")
        val idn = Presets.customChecks("сайт.рф\nhttps://Example.com:8443/a?b=1")
        expect("свои сайты: русское имя — в виде xn--", idn.firstOrNull()?.url, "https://xn--80aswg.xn--p1ai/")
        expect("свои сайты: русское имя в списке как написали", idn.firstOrNull()?.name, "сайт.рф")
        expect("свои сайты: порт и запрос сохранены", idn.getOrNull(1)?.url, "https://example.com:8443/a?b=1")
        val many = Presets.customChecks((1..40).joinToString("\n") { "s$it.example.com" })
        expect("свои сайты: не больше ${Presets.CUSTOM_CHECKS_MAX}", many.size, Presets.CUSTOM_CHECKS_MAX)

        // Подключение к серверам приложения (Telegram): открытый порт — да, закрытый — нет.
        val server = java.net.ServerSocket(0, 4, java.net.InetAddress.getByName("127.0.0.1"))
        try {
            val port = server.localPort
            val prober = dev.warpscout.core.net.ResourceProber()
            val open = prober.check(ResourceCheck("t", "tcp://127.0.0.1:$port", timeoutMs = 2_000))
            check("доступность: серверы отвечают — «открылся»", open.ok, "${open.errorClass}")
            val closedPort = java.net.ServerSocket(0).use { it.localPort }
            val closed = prober.check(ResourceCheck("t", "tcp://127.0.0.1:$closedPort|127.0.0.1:$port", timeoutMs = 2_000))
            check("доступность: годится любой из адресов", closed.ok, "${closed.errorClass}")
            val none = prober.check(ResourceCheck("t", "tcp://127.0.0.1:$closedPort", timeoutMs = 2_000))
            check("доступность: порт закрыт — не «открылся»", !none.ok && none.errorClass != null)
            // Параллельная проверка (подбор и «Проверить сейчас»): порядок — как в списке, итог —
            // у каждой своей строки, отметка «через туннель» не теряется.
            val batch = listOf(
                ResourceCheck("a", "tcp://127.0.0.1:$port", timeoutMs = 2_000),
                ResourceCheck("b", "tcp://127.0.0.1:$closedPort", timeoutMs = 2_000),
                ResourceCheck("c", "tcp://127.0.0.1:$port", timeoutMs = 2_000)
            )
            val par = prober.checkParallel(batch, "tunnel")
            expect("доступность: параллельно — порядок как в списке", par.joinToString("") { it.check.name }, "abc")
            check("доступность: параллельно — итог у каждой строки свой", par.map { it.ok } == listOf(true, false, true))
            check(
                "доступность: параллельно — помечено «через туннель»",
                par.all { it.via == dev.warpscout.core.model.NetworkVia.TUNNEL }
            )
            val cancelled = prober.checkParallel(batch, "tunnel") { true }
            check("доступность: отмена — пустой итог, без ожидания", cancelled.isEmpty())
        } finally {
            runCatching { server.close() }
        }
    }

    /** Книга шума по сетям (1.10.30): когда шум считать замерзающим и на что его менять. */
    private fun noiseBookChecks() {
        val net = "wifi·665"
        val now = 1_763_800_000_000L
        val order = JunkLibrary.serviceOrder().map { it.name }
        fun ev(noise: String, kind: Char, ep: String, ago: Long = 60_000L, n: String = net) =
            NoiseBook.Event(n, noise, kind, ep, now - ago)

        val plainFroze = listOf(ev("none", NoiseBook.FROZE, "8.39.204.10:4500"))
        check("шум: «пошли и встали» без шума — сразу замерзающий", "none" in NoiseBook.frozen(plainFroze, net, now))
        expect("шум: замена «none» — «как Chrome» (с 1.10.40)", NoiseBook.replacement(plainFroze, net, "none", order, now), "chrome:apteka.ru")
        val chromeFroze = plainFroze + ev("chrome:apteka.ru", NoiseBook.TUNER, "")
        expect("шум: «как Chrome» здесь встаёт — замена tls-fixed", NoiseBook.replacement(chromeFroze, net, "none", order, now), "tls-fixed")
        check("шум: на другой сети ничего не известно", NoiseBook.frozen(plainFroze, "мобильная·25001", now).isEmpty())
        check("шум: через четверо суток запись забыта", NoiseBook.frozen(listOf(ev("none", NoiseBook.FROZE, "a", ago = 4L * 24 * 3600 * 1000)), net, now).isEmpty())

        val maskOnce = listOf(ev("tls-fixed", NoiseBook.FROZE, "a"))
        check("шум: маска встала на одной точке — это может быть точка", "tls-fixed" !in NoiseBook.frozen(maskOnce, net, now))
        check("шум: маска встала на двух точках — замерзающий", "tls-fixed" in NoiseBook.frozen(maskOnce + ev("tls-fixed", NoiseBook.FROZE, "b"), net, now))

        val noDataSame = listOf(ev("none", NoiseBook.NO_DATA, "a"), ev("none", NoiseBook.NO_DATA, "a", ago = 30_000L))
        check("шум: «данных нет» дважды на одной точке — ещё не шум", "none" !in NoiseBook.frozen(noDataSame, net, now))
        check("шум: «данных нет» на двух точках — замерзающий", "none" in NoiseBook.frozen(noDataSame + ev("none", NoiseBook.NO_DATA, "b"), net, now))

        val healed = plainFroze + ev("none", NoiseBook.WORKED, "c", ago = 1_000L)
        check("шум: данные пошли после заморозки — снова годится", "none" !in NoiseBook.frozen(healed, net, now))
        expect("шум: незамерзающий не меняем", NoiseBook.replacement(healed, net, "none", order, now), null)

        val worked = plainFroze + ev("quic:akbars.ru", NoiseBook.WORKED, "d", ago = 2_000L)
        expect("шум: первым — тот, с которым здесь уже шли данные", NoiseBook.replacement(worked, net, "none", order, now), "quic:akbars.ru")
        check("шум: «подбор сказал встают» — сразу", "sip-invite" in NoiseBook.frozen(listOf(ev("sip-invite", NoiseBook.TUNER, "")), net, now))

        val all = order.map { ev(it, NoiseBook.TUNER, "") }
        expect("шум: замерзает всё — не меняем, не на что", NoiseBook.replacement(all, net, "none", order, now), null)

        val text = NoiseBook.render(plainFroze + ev("quic:x|y", NoiseBook.WORKED, "1.2.3.4:500"))
        val back = NoiseBook.parse(text + "битая строка\n|||\n")
        expect("шум: книга переживает файл", back.size, 2)
        expect("шум: «|» в имени не ломает строку", back.lastOrNull()?.noise, "quic:x/y")
        var many = emptyList<NoiseBook.Event>()
        for (i in 0 until NoiseBook.MAX_EVENTS + 20) many = NoiseBook.add(many, ev("none", NoiseBook.NO_DATA, "p$i", ago = 0L))
        expect("шум: в книге не больше ${NoiseBook.MAX_EVENTS} записей", many.size, NoiseBook.MAX_EVENTS)
    }

    /**
     * Быстрый старт принимает сохранённую точку без полного скана. Ошибка здесь тише и хуже, чем
     * кажется: подбор отрапортует «готово», а конфиг не работает. Поэтому подтверждение требует
     * настоящих признаков, а не «кандидат найден».
     */
    private fun cachedPoint() {
        val c = CachedPoint
        check("быстрый старт: без ответа сервера не подтверждается", !c.confirmed(0, 0, 0))
        check("быстрый старт: ответ есть, проверок не было — подтверждается", c.confirmed(1, 0, 0))
        check("быстрый старт: ответ есть, но изнутри ничего не открылось", !c.confirmed(3, 9, 0))
        // С 1.10.49-beta2 при пяти и больше проверках нужно ≥75% (как в версии для компьютера):
        // «открылся хоть один» подтверждал и точку через Москву без YouTube и Telegram.
        check("быстрый старт: из 9 открылся один — мало, полный подбор", !c.confirmed(3, 9, 1))
        check("быстрый старт: 5 из 8 (как через DME без YouTube и Telegram) — не подтверждается", !c.confirmed(3, 8, 5))
        check("быстрый старт: 6 из 8 (75%) — подтверждается", c.confirmed(3, 8, 6))
        check("быстрый старт: 6 из 9 (67%) — не подтверждается", !c.confirmed(3, 9, 6))
        check("быстрый старт: проверок меньше пяти — хватает одного открывшегося", c.confirmed(3, 4, 1))
        check("быстрый старт: все ресурсы открылись", c.confirmed(3, 9, 9))
        check("быстрый старт: отрицательные числа не считаются успехом", !c.confirmed(-1, 9, 9))
    }

    /**
     * Топ-3 для переключения. Проверяем не «функция вернула три элемента», а два свойства, из-за
     * которых список вообще имеет смысл: варианты стоят на разных адресах (иначе сеть режет их
     * вместе) и первым идёт тот, что реально пускал трафик, а не просто отвечал на handshake.
     */
    private fun shortlistPick() {
        fun cand(host: String, port: Int, junk: String, score: Int, replies: Int = 1, ok: Int = -1, total: Int = 0): Candidate {
            val cfg = WarpConfig(
                name = "тест",
                account = WarpAccount("a=", "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=", "172.16.0.2", "2606::1"),
                endpoint = Endpoint(host, port),
                junk = if (junk == "none") JunkLibrary.none() else JunkLibrary.tlsFixed(),
                allowedIps = "0.0.0.0/0, ::/0"
            )
            val st = EndpointStats(cfg.endpoint, emptyList(), Verdict.HANDSHAKE_OK, replies, 1)
            return Candidate(cfg, st, Scoring.evaluate(st, replies > 0, ok.coerceAtLeast(0), total), emptyList(), ok, total)
        }

        val a = cand("162.159.192.1", 2408, "tls-fixed", 900, ok = 9, total = 9)
        val b = cand("162.159.192.1", 2408, "none", 950, ok = 4, total = 9)      // та же точка, другой шум
        val c = cand("188.114.97.1", 500, "tls-fixed", 800, ok = 7, total = 9)
        val d = cand("162.159.195.1", 1701, "tls-fixed", 700, ok = 5, total = 9)
        val dead = cand("188.114.99.1", 2408, "tls-fixed", -500, replies = 0, ok = -1, total = 0)

        val top = Shortlist.pick(listOf(dead, d, b, c, a))
        expect("топ-3: ровно три варианта", top.size, Shortlist.LIMIT)
        expect("топ-3: первым — где открылось больше всего", top.first().config.endpoint.render(), "162.159.192.1:2408")
        expect("топ-3: на первом месте тот же адрес, но с лучшим результатом изнутри", top.first().resourcesOk, 9)
        check("топ-3: сначала разные адреса, а не три профиля на одном",
            top.map { it.config.endpoint.render() }.distinct().size == 3,
            top.joinToString { it.config.endpoint.render() + "/" + it.junk.name })
        check("топ-3: мёртвая точка не предлагается", top.none { it.config.endpoint.port == 2408 && it.stats.replies == 0 })

        // Если точек меньше трёх — добираем профилями шума, но не повторяем один и тот же вариант.
        val two = Shortlist.pick(listOf(a, b), limit = 3)
        expect("топ-3: при двух точках добирается вторым профилем шума", two.size, 2)
        expect("топ-3: варианты не повторяются", two.map { it.config.endpoint.render() + "/" + it.junk.name }.distinct().size, 2)

        // Непроверенное изнутри не должно обгонять проверенное, даже если балл выше.
        val unverified = cand("162.159.198.2", 443, "tls-fixed", 990, replies = 2, ok = -1, total = 0)
        val ordered = Shortlist.pick(listOf(unverified, c), limit = 1)
        expect("топ-3: проверенный изнутри выше более «балльного»", ordered.single().resourcesOk, 7)

        check("топ-3: пустой отчёт не ломает отбор", Shortlist.pick(emptyList()).isEmpty())
    }

    /**
     * 1.10.49-beta2 (из версии для компьютера): подробно и изнутри туннеля проверяются точки из разных
     * семейств адресов (8.*, 162.*, 188.*) и подсетей, а не самые быстрые — те почти всегда московские.
     */
    private fun pointMixChecks() {
        val mix = dev.warpscout.core.tune.PointMix
        expect("семейство: 8.39.125.1 → 8", mix.familyOf("8.39.125.1"), "8")
        expect("семейство: 162.159.192.1 → 162", mix.familyOf("162.159.192.1"), "162")
        expect("семейство: имя — само имя", mix.familyOf("Engage.CloudflareClient.com"), "engage.cloudflareclient.com")
        expect("подсеть: 8.34.70.3 → 8.34.70", mix.subnetOf("8.34.70.3"), "8.34.70")

        fun st(host: String, port: Int = 500, replies: Int = 1) =
            EndpointStats(Endpoint(host, port), emptyList(), if (replies > 0) Verdict.HANDSHAKE_OK else Verdict.UDP_SILENT, replies, 1)
        // Самые быстрые — московские 8.*: так их ранжирует скан по пингу.
        val ranked = listOf(
            st("8.6.112.2"), st("8.6.112.7"), st("8.39.214.10"), st("8.39.214.6"), st("8.39.125.1"),
            st("8.34.70.3"), st("162.159.192.1"), st("162.159.192.9"), st("188.114.97.1")
        )
        val refine = mix.pickRefine(emptyList(), ranked, 4).map { it.endpoint.host }
        check(
            "подробно: из четырёх мест — по точке от 8.*, 162.* и 188.*",
            refine.map { mix.familyOf(it) }.toSet() == setOf("8", "162", "188"), refine.joinToString()
        )
        expect("подробно: первым — самый быстрый адрес", refine.first(), "8.6.112.2")
        expect("подробно: четвёртое место — новая подсеть, а не сосед первого", refine.getOrNull(3), "8.39.214.10")
        val withPrior = mix.pickRefine(listOf(st("8.39.125.1")), ranked, 3).map { it.endpoint.host }
        expect("подробно: прежняя точка — первой, дальше недостающие семейства", withPrior, listOf("8.39.125.1", "162.159.192.1", "188.114.97.1"))
        val all = mix.pickRefine(listOf(st("8.6.112.2")), ranked, 50)
        check("подробно: без повторов и всех", all.size == ranked.size && all.map { it.endpoint.render() }.distinct().size == ranked.size)
        check("подробно: ноль мест — пусто", mix.pickRefine(emptyList(), ranked, 0).isEmpty())

        fun cand(host: String, junk: String, replies: Int = 1): Candidate {
            val cfg = WarpConfig(
                name = "тест",
                account = WarpAccount("a=", "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=", "172.16.0.2", "2606::1"),
                endpoint = Endpoint(host, 500),
                junk = if (junk == "none") JunkLibrary.none() else JunkLibrary.tlsFixed(),
                allowedIps = "0.0.0.0/0, ::/0"
            )
            val s0 = EndpointStats(cfg.endpoint, emptyList(), if (replies > 0) Verdict.HANDSHAKE_OK else Verdict.UDP_SILENT, replies, 1)
            return Candidate(cfg, s0, Scoring.evaluate(s0, replies > 0, 0, 0))
        }
        val a1 = cand("8.39.214.10", "tls")
        val a2 = cand("8.39.214.10", "none")
        val a3 = cand("8.6.112.2", "tls")
        val b1 = cand("188.114.97.1", "tls")
        val c1 = cand("162.159.192.5", "none")
        val dead = cand("162.159.193.1", "tls", replies = 0)
        val ordered = listOf(a1, a2, a3, dead, b1, c1) // по баллу: московские впереди
        fun names(l: List<Candidate>) = l.map { it.config.endpoint.host + "/" + it.junk.name }
        val v = mix.forVerification(ordered, 4)
        expect(
            "изнутри: 8.*, 188.*, 162.*, затем новая подсеть 8.* — а не три московских подряд",
            names(v), names(listOf(a1, b1, c1, a3))
        )
        check("изнутри: молчащая точка не проверяется, когда есть годные", dead !in v)
        expect("изнутри: быстрый старт — три, по семейству каждая", names(mix.forVerification(ordered, 3)), names(listOf(a1, b1, c1)))
        val deadOnly = listOf(cand("8.6.112.2", "tls", 0), cand("8.6.112.3", "tls", 0), cand("8.6.112.4", "tls", 0), cand("8.6.112.5", "tls", 0))
        expect("изнутри: годных нет — как раньше, три лучших", mix.forVerification(deadOnly, 4).size, 3)
        val oneGood = mix.forVerification(listOf(a1, dead, cand("8.6.112.9", "tls", 0)), 4)
        check("изнутри: одна годная — первой, до трёх добираются остальные", oneGood.size == 3 && oneGood.first() == a1, names(oneGood).joinToString())
        check("изнутри: пустой список — пусто", mix.forVerification(emptyList(), 4).isEmpty())

        check("изнутри: две сильные (7 из 8) из трёх — хватит", mix.enough(listOf(7, 6, 7), 8))
        check("изнутри: 6, 6, 6 из 8 (так выходит через DME) — проверяю дальше", !mix.enough(listOf(6, 6, 6), 8))
        check("изнутри: две сильные, но проверено две — проверяю третью", !mix.enough(listOf(8, 8), 8))
        check("изнутри: без сайтов правило не срабатывает", !mix.enough(listOf(0, 0, 0), 0))
    }

    /**
     * 1.10.28: замер скорости (и «заморозка»), DNS в маршрутах туннеля, проверка «умного» DNS,
     * новые поля снимков. Всё без сети: потоки и пакеты — подставные.
     */
    private fun speedAndDns() {
        val st = dev.warpscout.core.net.SpeedTest
        // Поток, который отдаёт [give] байт и потом молчит (таймаут сокета) — «заморозка».
        class FreezingStream(private val give: Int) : java.io.InputStream() {
            private var sent = 0
            override fun read(): Int {
                if (sent >= give) throw java.net.SocketTimeoutException("тишина")
                sent++
                return 0
            }
            override fun read(b: ByteArray, off: Int, len: Int): Int {
                if (sent >= give) throw java.net.SocketTimeoutException("тишина")
                val n = minOf(len, give - sent)
                sent += n
                return n
            }
        }
        val full = st.drain(java.io.ByteArrayInputStream(ByteArray(300_000)), 300_000, 1_000_000, 10_000)
        expect("скорость: тело дочитано — замер прошёл", full.state, st.OK)
        expect("скорость: прочитано всё обещанное", full.bytes, 300_000L)
        check("скорость: посчитана", full.kbps > 0, "${full.kbps}")
        val frozen = st.drain(FreezingStream(20 * 1024), 512 * 1024, 512 * 1024, 10_000)
        expect("скорость: 20 КБ и тишина — это «заморозка»", frozen.state, st.FROZEN)
        expect("скорость: при заморозке видно, сколько успело прийти", frozen.bytes, 20L * 1024)
        val silent = st.drain(FreezingStream(0), 512 * 1024, 512 * 1024, 10_000)
        expect("скорость: ни байта — это провал, а не заморозка", silent.state, st.FAIL)
        val cut = st.drain(java.io.ByteArrayInputStream(ByteArray(10_000)), 100_000, 1_000_000, 10_000)
        expect("скорость: оборванное посреди тело — тоже заморозка", cut.state, st.FROZEN)
        val noLength = st.drain(java.io.ByteArrayInputStream(ByteArray(50_000)), -1, 1_000_000, 10_000)
        expect("скорость: без Content-Length читаем до конца", noLength.state, st.OK)
        expect("скорость: без Content-Length — все байты", noLength.bytes, 50_000L)
        val capped = st.drain(java.io.ByteArrayInputStream(ByteArray(300_000)), 1_000_000, 100_000, 10_000)
        expect("скорость: предел байт соблюдается", capped.bytes, 100_000L)
        expect("скорость: предел байт — не заморозка", capped.state, st.OK)
        expect("скорость: Кбит/с из байт и мс", st.kbpsOf(1_000_000, 1_000), 8_000)
        expect("скорость: слишком короткое окно не даёт «тысячу мегабит»", st.kbpsOf(1_000, 0), 400)
        expect("скорость: нет байт — нет скорости", st.kbpsOf(0, 100), -1)
        expect("скорость: ступень — не мерили", st.bucket(-1), 0)
        expect("скорость: ступень — меньше мегабита", st.bucket(500), 1)
        expect("скорость: ступень — 1–2 Мбит/с", st.bucket(1_500), 2)
        expect("скорость: ступень — 3 Мбит/с выше 2", st.bucket(3_000), 3)
        check("скорость: ступени растут со скоростью", st.bucket(50_000) > st.bucket(10_000))
        expect("скорость: подпись в Кбит/с", st.human(850), "850 Кбит/с")
        expect("скорость: подпись с запятой", st.human(24_500), "24,5 Мбит/с")
        expect("скорость: большие — без дробной части", st.human(150_000), "150 Мбит/с")
        expect("скорость: нет замера — прочерк", st.human(-1), "—")

        // DNS в маршрутах туннеля: только при раздельных маршрутах и только то, что не покрыто.
        expect(
            "DNS в туннеле: весь трафик — маршруты не меняются",
            SplitRoutes.withDns("0.0.0.0/0, ::/0", listOf("1.1.1.1", "2606:4700:4700::1111")),
            "0.0.0.0/0, ::/0"
        )
        expect(
            "DNS в туннеле: раздельные — добавляются /32 и /128",
            SplitRoutes.withDns("10.0.0.0/8, 8.8.8.0/24", listOf("8.8.8.8", "1.1.1.1", "2606:4700:4700::1111")),
            "10.0.0.0/8, 8.8.8.0/24, 1.1.1.1/32, 2606:4700:4700::1111/128"
        )
        expect(
            "DNS в туннеле: адрес внутри подсети не дублируется",
            SplitRoutes.withDns("1.0.0.0/8", listOf("1.1.1.1")),
            "1.0.0.0/8"
        )
        expect("DNS в туннеле: без маршрутов ничего не придумываем", SplitRoutes.withDns("", listOf("1.1.1.1")), "")

        // Проверка «умного» DNS: запрос A-записи и разбор ответа.
        val q = dev.warpscout.core.net.SmartDnsCheck.buildQuery(0x1234, "chatgpt.com")
        expect("DNS-запрос: длина", q.size, 29)
        expect("DNS-запрос: номер", ((q[0].toInt() and 0xFF) shl 8) or (q[1].toInt() and 0xFF), 0x1234)
        val answer = java.io.ByteArrayOutputStream().apply {
            write(byteArrayOf(0x12, 0x34, 0x81.toByte(), 0x80.toByte(), 0, 1, 0, 2, 0, 0, 0, 0))
            write(q, 12, q.size - 12)
            // CNAME на то же имя (указатель на вопрос) — пропускается
            write(byteArrayOf(0xC0.toByte(), 0x0C, 0, 5, 0, 1, 0, 0, 0, 60, 0, 2, 0xC0.toByte(), 0x0C))
            // A 104.18.32.47
            write(byteArrayOf(0xC0.toByte(), 0x0C, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 104, 18, 32, 47))
        }.toByteArray()
        expect(
            "DNS-ответ: адрес из A-записи, CNAME пропущен",
            dev.warpscout.core.net.SmartDnsCheck.parseA(answer, answer.size, 0x1234),
            listOf("104.18.32.47")
        )
        expect(
            "DNS-ответ: чужой номер запроса — пусто",
            dev.warpscout.core.net.SmartDnsCheck.parseA(answer, answer.size, 0x4321),
            emptyList<String>()
        )
        expect(
            "DNS-ответ: обрезанный пакет не роняет разбор",
            dev.warpscout.core.net.SmartDnsCheck.parseA(answer, 40, 0x1234),
            emptyList<String>()
        )
        val nx = answer.copyOf().also { it[3] = 0x83.toByte() }
        expect(
            "DNS-ответ: ошибка сервера — пусто",
            dev.warpscout.core.net.SmartDnsCheck.parseA(nx, nx.size, 0x1234),
            emptyList<String>()
        )
        expect(
            "trace: страна и площадка",
            dev.warpscout.core.net.SmartDnsCheck.traceFields("fl=1\nh=chatgpt.com\nloc=DE\ncolo=FRA\n"),
            "DE" to "FRA"
        )
        check(
            "ChatGPT: выход RU — не откроется",
            !dev.warpscout.core.net.SmartDnsCheck.Result(true, "1.2.3.4", "RU", "DME", "").opens
        )
        check(
            "ChatGPT: выход DE — откроется",
            dev.warpscout.core.net.SmartDnsCheck.Result(true, "1.2.3.4", "DE", "FRA", "").opens
        )

        // Снимок: замер скорости переживает передачу между процессами.
        val speedSnap = TunnelStatus(
            speedAt = 1_758_000_100_000L, speedState = TunnelStatus.SPEED_FROZEN, speedKbps = 1234,
            speedPingMs = 48, speedBytes = 20_480L, speedFull = true, speedRunningSince = 1_758_000_099_000L
        )
        expect("снимок: замер скорости без потерь", TunnelStatus.fromJson(speedSnap.toJson()), speedSnap)
        expect("снимок: старый формат — скорости нет", TunnelStatus.fromJson("{}")?.speedKbps, -1)

        // Настройки сервиса: резервные и тройки по сетям, переключатели функций.
        val perNet = ServiceSettings(
            backup = "162.159.192.1:2408",
            backupMobile = "188.114.97.1:500",
            listWifi = listOf("162.159.192.1:2408", "162.159.195.1:1701"),
            listMobile = listOf("188.114.97.1:500"),
            autoStart = false,
            linkReconnect = false,
            speedAuto = false,
            freezeReconnect = false,
            dnsInTunnel = false,
        )
        expect("настройки сервиса: резервные и тройки по сетям", ServiceSettings.fromJson(perNet.toJson()), perNet)
        val oldSettings = ServiceSettings.fromJson("""{"ver":1,"backup":"1.2.3.4:500"}""")
        expect("настройки сервиса: старый снимок — мобильной резервной нет", oldSettings?.backupMobile, "")
        expect("настройки сервиса: старый снимок — автоподъём включён", oldSettings?.autoStart, true)
        expect("настройки сервиса: старый снимок — DNS через туннель", oldSettings?.dnsInTunnel, true)
        // 1.10.33: маршруты «Туннелирования» — в снимке; сервис ставит их любому конфигу.
        val withRoutes = ServiceSettings(routes = "91.108.4.0/22, 192.178.0.0/15, 2a00:1450::/32", routesNote = "сайты из списков: 2 + сети Google для видео YouTube: 1")
        expect("настройки сервиса: маршруты без потерь", ServiceSettings.fromJson(withRoutes.toJson()), withRoutes)
        expect("настройки сервиса: старый снимок — маршрутов нет (как в конфиге)", oldSettings?.routes, "")

        // Подбор: из одинаково открывшихся выше та, через которую быстрее качается.
        fun fast(host: String, kbps: Int): Candidate {
            val cfg = WarpConfig(
                name = "тест",
                account = WarpAccount("a=", "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=", "172.16.0.2", "2606::1"),
                endpoint = Endpoint(host, 2408),
                junk = JunkLibrary.tlsFixed(),
                allowedIps = "0.0.0.0/0, ::/0"
            )
            val es = EndpointStats(cfg.endpoint, emptyList(), Verdict.HANDSHAKE_OK, 1, 1)
            return Candidate(cfg, es, Scoring.evaluate(es, true, 9, 9), emptyList(), 9, 9, kbps)
        }
        val slow = fast("162.159.192.5", 900)
        val quick = fast("162.159.192.6", 40_000)
        expect(
            "топ-3: при равных сайтах первой идёт более быстрая",
            Shortlist.pick(listOf(slow, quick), limit = 1).single().config.endpoint.host,
            "162.159.192.6"
        )
    }

    /**
     * Интервал keepalive — главный наш вклад в расход батареи на мобильной сети. Проверяем ровно
     * то, что важно: активный экран будит радио не реже раза в минуту, лежащий телефон — реже,
     * а сам пользователь может попросить ещё реже, но не чаще нижней границы.
     */
    private fun keepalivePolicy() {
        val k = Keepalive
        val active = k.intervalMs(configuredSeconds = 25, idleMs = 0, screenOn = true)
        check("батарея: на активном экране не чаще раза в минуту", active == Keepalive.ACTIVE_FLOOR_MS, "$active")

        val idle = k.intervalMs(25, idleMs = 300_000, screenOn = false)
        check("батарея: экран погашен и тишина — полторы минуты", idle == Keepalive.IDLE_SCREEN_OFF_FLOOR_MS, "$idle")

        val idleScreenOn = k.intervalMs(25, idleMs = 300_000, screenOn = true)
        check("батарея: экран горит — минута даже в тишине", idleScreenOn == Keepalive.ACTIVE_FLOOR_MS, "$idleScreenOn")

        val justIdle = k.intervalMs(25, idleMs = Keepalive.IDLE_AFTER_MS - 1_000, screenOn = false)
        check("батарея: тишина ещё не наступила — держим минуту", justIdle == Keepalive.ACTIVE_FLOOR_MS, "$justIdle")

        val userWantsRare = k.intervalMs(110, idleMs = 0, screenOn = true)
        check("батарея: просьбу «реже» уважаем", userWantsRare == 110_000L, "$userWantsRare")

        val tooSlow = k.intervalMs(120, idleMs = 300_000, screenOn = false)
        check("батарея: дольше двух минут не растягиваем", tooSlow == Keepalive.MAX_MS, "$tooSlow")

        val off = k.intervalMs(0, idleMs = 0, screenOn = true)
        check("батарея: keepalive выключен — не будим вовсе", off == Long.MAX_VALUE, "$off")

        // Частота за час: было 144 пробуждения (25 с), стало не больше 60/40.
        val perHourActive = 3_600_000L / active
        val perHourIdle = 3_600_000L / idle
        check("батарея: за час активных пробуждений не больше 60", perHourActive <= 60, "$perHourActive")
        check("батарея: за час в тишине не больше 40", perHourIdle <= 40, "$perHourIdle")
        check(
            "батарея: тишина реже активности",
            perHourIdle < perHourActive,
            "$perHourIdle против $perHourActive"
        )
        check(
            "батарея: пересогласование успевает до жёсткого предела протокола",
            NetSettings().rekeyAfterMs < NetSettings().rejectAfterMs,
            "${NetSettings().rekeyAfterMs}"
        )
        check(
            "батарея: запас на повторные попытки не меньше трёх штук",
            (NetSettings().rejectAfterMs - NetSettings().rekeyAfterMs) / NetSettings().rekeyRetryMs >= 3,
            "${(NetSettings().rejectAfterMs - NetSettings().rekeyAfterMs) / NetSettings().rekeyRetryMs}"
        )
    }

    // ------------------------------------------------- живость сессии по трафику

    /**
     * Правило «сессия мертва» решает, рвать ли рабочий туннель. Слишком чувствительное — рвёт
     * нормальную работу, слишком грубое — оставляет мёртвое соединение на минуты. Поэтому
     * проверяются ровно те сценарии, которые бывают в жизни.
     */
    private fun stallDetection() {
        val d = StallDetector
        val t0 = 1_000_000L

        // Пока трафик стоит, судить не о чем: молчащий туннель без трафика — норма.
        check("живость: без трафика не считается мёртвой", !d.isStalled(t0 + 600_000, t0, 0L, 0))
        check("живость: трафика нет, но счётчик шумит", !d.isStalled(t0 + 600_000, t0, 0L, 500))

        // Единичные пакеты (UDP-датаграммы, DNS) ответа не ждут — порог по количеству обязателен.
        check(
            "живость: 10 пакетов без ответа — ещё не приговор",
            !d.isStalled(t0 + 300_000, t0, t0, 10)
        )
        check(
            "живость: 49 пакетов за 10 минут — под порогом",
            !d.isStalled(t0 + 600_000, t0, t0, StallDetector.MIN_PACKETS - 1)
        )

        // Поток только начался — окно ещё не вышло, даже если ответа не было давно.
        val burst = t0 + 600_000
        check(
            "живость: поток только начался",
            !d.isStalled(burst + 1_000, t0, burst, 80)
        )

        // Ответ был недавно — соединение живое, сколько бы ни ушло пакетов.
        check(
            "живость: недавний ответ снимает подозрения",
            !d.isStalled(t0 + 60_000, t0 + 55_000, t0, 200)
        )

        // Классический случай: 50+ пакетов, 45 секунд тишины.
        check(
            "живость: 50 пакетов и 45 секунд тишины — мертва",
            d.isStalled(t0 + 45_000, t0, t0, StallDetector.MIN_PACKETS)
        )
        check(
            "живость: за секунду до окна — ещё нет",
            !d.isStalled(t0 + 44_000, t0, t0, StallDetector.MIN_PACKETS)
        )
        check(
            "живость: окно считается от последнего ответа, а не от начала",
            !d.isStalled(t0 + 100_000, t0 + 80_000, t0, 500)
        )

        // Ни одного ответа за всю жизнь сессии: отсчёт от начала потока.
        check(
            "живость: ответов не было вовсе",
            d.isStalled(t0 + 50_000, 0L, t0, StallDetector.MIN_PACKETS)
        )

        // 1.10.44-beta3: свежая сессия второго выхода без единого ответа — 15 с вместо 45
        // (журнал 24.11, 14:47: NL-FREE#125 принял рукопожатие и молчал на 392 пакета).
        check(
            "свежая сессия: 20 пакетов и 15 с без ответа — сервер данных не пропускает",
            d.isFreshDead(t0 + StallDetector.FRESH_WINDOW_MS, t0, t0, StallDetector.FRESH_MIN_PACKETS)
        )
        check(
            "свежая сессия: 19 пакетов — ещё рано",
            !d.isFreshDead(t0 + 60_000, t0, t0, StallDetector.FRESH_MIN_PACKETS - 1)
        )
        check(
            "свежая сессия: за секунду до окна — ещё нет",
            !d.isFreshDead(t0 + StallDetector.FRESH_WINDOW_MS - 1_000, t0, t0, 300)
        )
        check(
            "свежая сессия: ответ был 5 с назад — жива",
            !d.isFreshDead(t0 + 20_000, t0 + 15_000, t0, 300)
        )
        check(
            "свежая сессия: правило быстрее общего, но не мягче подозрения",
            StallDetector.FRESH_WINDOW_MS < StallDetector.WINDOW_MS &&
                StallDetector.FRESH_WINDOW_MS >= StallDetector.SUSPECT_MS &&
                StallDetector.FRESH_MIN_PACKETS > StallDetector.SUSPECT_PACKETS
        )
        val fresh = d.explainFresh(t0 + 15_000, t0, t0, 392)
        check("свежая сессия: объяснение — пакеты, секунды и что сервер не пропускает данные",
            fresh.contains("392") && fresh.contains("15 с") && fresh.contains("данных не пропускает"), fresh)

        // Объяснение должно быть понятным человеку и содержать секунды и число пакетов.
        val why = d.explain(t0 + 60_000, t0, t0, 120)
        check("живость: объяснение называет число пакетов", why.contains("120"), why)
        check("живость: объяснение называет время тишины", why.contains("60 с"), why)
    }

    // -------------------------------------------------- состояние между процессами

    /**
     * Снимок состояния — единственный способ узнать что-либо о туннеле из другого процесса,
     * поэтому сериализация проверяется отдельно: битый снимок = «туннель работает, а UI молчит».
     */
    /**
     * «Остановить подбор» должно останавливать: скан с поднятым флагом отмены не шлёт ни одной
     * пробы и возвращается сразу, а не через весь пул (раньше пул досчитывался до конца).
     */
    private fun scanCancel() {
        val priv = ByteArray(32) { (it + 5).toByte() }.also { it[31] = 0 }
        val account = WarpAccount(Crypto.base64(priv), Crypto.base64(Crypto.publicOf(priv)))
        // TEST-NET-1 (192.0.2.0/24) никуда не ведёт: без отмены каждая проба ждала бы до трёх секунд.
        val pool = (1..40).map { Endpoint("192.0.2.$it", 2408) }
        val prober = WgProber(NetSettings(attempts = 3, timeoutMs = 1000, concurrency = 4))
        val t0 = System.currentTimeMillis()
        val res = prober.scan(pool, account, Crypto.publicOf(priv), isCancelled = { true })
        val took = System.currentTimeMillis() - t0
        expect("отмена: скан после «Остановить» не возвращает проб", res.size, 0)
        check("отмена: скан возвращается сразу, а не через весь пул", took < 1500, "заняло $took мс")
    }

    /**
     * «Подключено» должно значить «данные ходят». Здесь — всё, на чём это держится и что можно
     * проверить без Android: мягкий порог подозрения, разбор ответа Cloudflare, перенос итогов
     * проверки, пробы точки и меток дозора через снимок, резервная точка в настройках сервиса.
     */
    private fun linkCheckState() {
        val t0 = 1_700_000_000_000L
        // Мягкий порог: Telegram, потерявший связь, шлёт мало — 50 пакетов за 45 с не набирается.
        check(
            "подозрение: 8 пакетов и 15 с без ответа — пора проверить связь",
            StallDetector.isSuspect(t0 + StallDetector.SUSPECT_MS, 0L, t0, StallDetector.SUSPECT_PACKETS)
        )
        check(
            "подозрение: 7 пакетов — ещё рано",
            !StallDetector.isSuspect(t0 + 60_000, 0L, t0, StallDetector.SUSPECT_PACKETS - 1)
        )
        check(
            "подозрение: ответ был 5 с назад — всё в порядке",
            !StallDetector.isSuspect(t0 + 20_000, t0 + 15_000, t0, 40)
        )
        check(
            "подозрение: за секунду до окна — ещё нет",
            !StallDetector.isSuspect(t0 + StallDetector.SUSPECT_MS - 1_000, 0L, t0, 40)
        )
        check(
            "подозрение раньше приговора: на мягком пороге сессия ещё не «мертва»",
            !StallDetector.isStalled(t0 + StallDetector.SUSPECT_MS, 0L, t0, StallDetector.SUSPECT_PACKETS)
        )

        // Ответ Cloudflare: через WARP / мимо / не trace вовсе.
        val warpOn = dev.warpscout.core.net.CfTrace.parse(
            "fl=12f3\nh=1.1.1.1\nip=2a09:bac1:6181:6888::1d6:18d\nts=1732278600.1\n" +
                "visit_scheme=https\ncolo=FRA\nhttp=http/1.1\nloc=RU\ntls=TLSv1.3\nwarp=on\ngateway=off\n"
        )
        check("trace: разобран", warpOn != null)
        expect("trace: площадка", warpOn?.colo, "FRA")
        expect("trace: адрес выхода", warpOn?.ip, "2a09:bac1:6181:6888::1d6:18d")
        expect("trace: через WARP", warpOn?.viaWarp, true)
        expect("trace: коротко", warpOn?.summary(), "FRA · RU · 2a09:bac1:6181:6888::1d6:18d")
        val warpOff = dev.warpscout.core.net.CfTrace.parse("ip=185.126.130.6\ncolo=HEL\nloc=RU\nwarp=off\n")
        expect("trace: мимо WARP так и называется", warpOff?.viaWarp, false)
        expect("trace: plus — тоже WARP", dev.warpscout.core.net.CfTrace.parse("colo=AMS\nwarp=plus")?.viaWarp, true)
        expect("trace: страница портала — не trace", dev.warpscout.core.net.CfTrace.parse("<html><body>login=1</body></html>"), null)
        expect("trace: пусто — не trace", dev.warpscout.core.net.CfTrace.parse(""), null)

        // Итоги проверки, проба точки и метки дозора переживают снимок между процессами.
        val st = TunnelStatus(
            up = true,
            probe = "17|162.159.192.8:859|${TunnelStatus.PROBE_SILENT}|-1",
            marks = "162.159.192.8:859|0|3|1758000000000;188.114.97.1:500|1758000001000|0|0",
            linkAt = 1_758_000_002_000L,
            linkWeb = TunnelStatus.LINK_OK,
            linkMs = 183,
            linkTg = TunnelStatus.LINK_FAIL,
            linkTgMs = -1,
            linkExit = "FRA · RU · 2a09:bac1::1",
        )
        val back = TunnelStatus.fromJson(st.toJson())
        expect("снимок: проба точки", back?.probe, st.probe)
        expect("снимок: метки дозора", back?.marks, st.marks)
        expect("снимок: время проверки связи", back?.linkAt, 1_758_000_002_000L)
        expect("снимок: интернет через туннель", back?.linkWeb, TunnelStatus.LINK_OK)
        expect("снимок: задержка проверки", back?.linkMs, 183)
        expect("снимок: Telegram через туннель", back?.linkTg, TunnelStatus.LINK_FAIL)
        expect("снимок: выход", back?.linkExit, "FRA · RU · 2a09:bac1::1")
        val old = TunnelStatus.fromJson("{\"up\": true}")
        expect("снимок: старый формат — связь не проверяли", old?.linkWeb, TunnelStatus.LINK_UNKNOWN)
        expect("снимок: старый формат — задержки нет (-1, а не 0 мс)", old?.linkMs, -1)

        // Резервная точка, выбранная человеком, доходит до сервиса.
        expect(
            "настройки сервиса: резервная точка",
            ServiceSettings.fromJson(ServiceSettings(backup = "162.159.192.2:864").toJson())?.backup,
            "162.159.192.2:864"
        )
        expect(
            "настройки сервиса: без резервной точки — пусто",
            ServiceSettings.fromJson("""{"ver":1}""")?.backup,
            ""
        )
    }

    private fun serviceState() {
        val full = TunnelStatus(
            up = true,
            status = "туннель поднят",
            endpoint = "162.159.192.7:2408",
            error = null,
            gaveUp = false,
            busy = true,
            startedAt = 1_758_000_000_123,
            updatedAt = 1_758_000_004_456,
            bytesUp = 12_345_678_901L,
            bytesDown = 98_765_432_109L,
            handshakeAttempts = 3,
            lastError = "endpoint молчит",
            lastStageMs = 1_758_000_004_000,
            touched = true,
        )
        val back = TunnelStatus.fromJson(full.toJson())
        check("снимок: читается обратно", back != null)
        expect("снимок: up", back?.up, true)
        expect("снимок: статус", back?.status, "туннель поднят")
        expect("снимок: endpoint", back?.endpoint, "162.159.192.7:2408")
        expect("снимок: нет ошибки", back?.error, null)
        expect("снимок: busy", back?.busy, true)
        expect("снимок: время старта без потерь", back?.startedAt, 1_758_000_000_123L)
        expect("снимок: время обновления без потерь", back?.updatedAt, 1_758_000_004_456L)
        expect("снимок: счётчик вверх без потерь", back?.bytesUp, 12_345_678_901L)
        expect("снимок: счётчик вниз без потерь", back?.bytesDown, 98_765_432_109L)
        expect("снимок: попытки handshake", back?.handshakeAttempts, 3)
        expect("снимок: последняя ошибка", back?.lastError, "endpoint молчит")
        expect("снимок: время этапа", back?.lastStageMs, 1_758_000_004_000L)
        expect("снимок: журнал трогали", back?.touched, true)

        // «Туннель нужен» и «выключил сам человек»: по ним кнопка и плитка решают, что предлагать,
        // а фоновый подбор — включать ли туннель. Потерять их при сериализации — значит снова
        // «выключил руками, а он включился сам».
        val heldBack = TunnelStatus.fromJson(TunnelStatus(wanted = true, stoppedByUser = true).toJson())
        expect("снимок: туннель нужен", heldBack?.wanted, true)
        expect("снимок: выключен вручную", heldBack?.stoppedByUser, true)
        // По времени ручного выключения перебор точек видит выключение плиткой во время перебора.
        expect(
            "снимок: время ручного выключения без потерь",
            TunnelStatus.fromJson(TunnelStatus(stoppedByUserAt = 1_758_000_009_999L).toJson())?.stoppedByUserAt,
            1_758_000_009_999L
        )
        val beforeFields = TunnelStatus.fromJson("{\"up\": false, \"phase\": 5}")
        expect("снимок: старый формат — туннель не нужен", beforeFields?.wanted, false)
        expect("снимок: старый формат — не выключался вручную", beforeFields?.stoppedByUser, false)

        // Русский текст с кавычками и переводами строк — иначе журнал превратится в кашу.
        val tricky = TunnelStatus(
            status = "строка \"в кавычках\" и \\ слэш\nвторая строка\tтаб",
            error = "ошибка: «ёлка», тире — и юникод ✓",
        )
        val trickyBack = TunnelStatus.fromJson(tricky.toJson())
        expect("снимок: кавычки и переводы строк", trickyBack?.status, tricky.status)
        expect("снимок: юникод в ошибке", trickyBack?.error, tricky.error)

        // Битый и чужой ввод не должен ронять процесс интерфейса.
        expect("снимок: пустая строка → null", TunnelStatus.fromJson(""), null)
        expect("снимок: null → null", TunnelStatus.fromJson(null), null)
        expect("снимок: мусор → null", TunnelStatus.fromJson("не json"), null)
        expect("снимок: обрезанный json → null", TunnelStatus.fromJson("{\"up\": true, \"status\": \"тун"), null)
        expect("снимок: не объект → null", TunnelStatus.fromJson("[1,2,3]"), null)
        expect("снимок: пустой объект → значения по умолчанию", TunnelStatus.fromJson("{}"), TunnelStatus())
        val unknown = TunnelStatus.fromJson("{\"up\": true, \"чужоеПоле\": 5, \"ещё\": {\"a\": 1}}")
        expect("снимок: лишние поля не мешают", unknown?.up, true)
        expect("снимок: лишние поля не ломают статус", unknown?.status, "")

        // Настройки сервиса: то, из-за чего «поменял в настройках — туннель не заметил».
        val settings = ServiceSettings(
            secondExitOn = true,
            secondConf = "[Interface]\nPrivateKey = abc=\n[Peer]\nEndpoint = 1.2.3.4:51820",
            secondCidrs = "1.1.1.0/24, 8.8.8.8/32",
            appsMode = 1,
            appsSelected = listOf("org.telegram.messenger", "com.google.android.youtube", "ru.yandex.music"),
        )
        val settingsBack = ServiceSettings.fromJson(settings.toJson())
        check("настройки сервиса: читаются обратно", settingsBack != null)
        expect("настройки сервиса: второй выход", settingsBack?.secondExitOn, true)
        expect("настройки сервиса: конфиг дословно", settingsBack?.secondConf, settings.secondConf)
        expect("настройки сервиса: подсети", settingsBack?.secondCidrs, settings.secondCidrs)
        expect("настройки сервиса: режим приложений", settingsBack?.appsMode, 1)
        expect("настройки сервиса: список приложений", settingsBack?.appsSelected, settings.appsSelected)

        val many = (0 until 300).map { "app.number.$it" }
        expect(
            "настройки сервиса: 300 приложений",
            ServiceSettings.fromJson(ServiceSettings(appsSelected = many).toJson())?.appsSelected,
            many
        )
        expect(
            "настройки сервиса: пустой список",
            ServiceSettings.fromJson(ServiceSettings().toJson())?.appsSelected,
            emptyList<String>()
        )
        expect("настройки сервиса: мусор → null", ServiceSettings.fromJson("<xml/>"), null)

        // Очередь точек: по ней процесс туннеля сам меняет точку, когда прежняя замолчала.
        val queue = listOf("162.159.192.10:864", "162.159.192.7:500", "188.114.97.1:500")
        expect(
            "настройки сервиса: очередь точек сохраняется",
            ServiceSettings.fromJson(ServiceSettings(failover = queue).toJson())?.failover,
            queue
        )
        expect(
            "настройки сервиса: пустая очередь",
            ServiceSettings.fromJson(ServiceSettings().toJson())?.failover,
            emptyList<String>()
        )
        // Старый снимок без поля обязан читаться: обновление не должно ломать уже поднятый туннель.
        expect(
            "настройки сервиса: снимок без очереди читается",
            ServiceSettings.fromJson("""{"ver":1,"appsMode":2}""")?.failover,
            emptyList<String>()
        )

        // Фаза: машинный код вместо поиска подстрок в русском статусе.
        expect("фаза: по умолчанию простаивает", TunnelStatus().phase, TunnelStatus.PHASE_IDLE)
        expect(
            "фаза: переживает сериализацию",
            TunnelStatus.fromJson(TunnelStatus(phase = TunnelStatus.PHASE_RECONNECTING).toJson())?.phase,
            TunnelStatus.PHASE_RECONNECTING
        )
        expect(
            "фаза: «идёт подключение» у подъёма",
            TunnelStatus(phase = TunnelStatus.PHASE_STARTING).isStarting,
            true
        )
        expect(
            "фаза: «идёт подключение» у переподключения",
            TunnelStatus(phase = TunnelStatus.PHASE_RECONNECTING).isStarting,
            true
        )
        expect("фаза: работа — это не «идёт подключение»", TunnelStatus(phase = TunnelStatus.PHASE_UP).isStarting, false)
        expect(
            "фаза: «нет сети» — отдельный признак",
            TunnelStatus(phase = TunnelStatus.PHASE_NO_NETWORK).hasNoNetwork,
            true
        )
        expect(
            "фаза: старый снимок без фазы читается как простой",
            TunnelStatus.fromJson("{\"up\": false}")?.phase,
            TunnelStatus.PHASE_IDLE
        )

        // Совместимость: снимок без новых полей (он же — снимок старой версии приложения).
        val legacy = TunnelStatus.fromJson("{\"up\": true, \"status\": \"старый снимок\"}")
        expect("снимок: читается без новых полей", legacy?.status, "старый снимок")
        expect("снимок: отсутствующие поля по умолчанию", legacy, TunnelStatus(up = true, status = "старый снимок"))
    }

    // ----------------------------------------------------------- scoring/report

    private fun scoring() {
        fun stats(verdict: Verdict, rtts: List<Double>, loss: Double, ep: Endpoint = Endpoint("1.2.3.4", 500)) =
            EndpointStats(
                ep,
                rtts.mapIndexed { i, r -> ProbeSample(ep, verdict, r, i) },
                verdict,
                replies = rtts.size,
                attempts = (rtts.size / (1 - loss / 100.0)).toInt().coerceAtLeast(rtts.size)
            )

        val good = Scoring.evaluate(stats(Verdict.HANDSHAKE_OK, listOf(20.0, 21.0, 22.0), 0.0), true, 0, 0, Weights())
        expect("скоринг: живой + быстрый + шум проходит", good.total, 1000 + 300 + 200 + 100 + 150)
        val dead = Scoring.evaluate(stats(Verdict.UDP_CLOSED, emptyList(), 100.0), null, 0, 0, Weights())
        expect("скоринг: закрытый порт", dead.total, -500)
        val silent = Scoring.evaluate(stats(Verdict.UDP_SILENT, listOf(300.0), 100.0), false, 0, 0, Weights())
        // 60 (silent) + 40 (rtt 300мс) + 0 (потери 100%) − 150 (шум не прошёл)
        expect("скоринг: тишина + шум зарезан", silent.total, 60 + 40 + 0 - 150)
        check("скоринг: живой всегда лучше тихого", good.total > silent.total)
        check("вердикт: лучший = сильнейший (rank, а не последний в списке)",
            Verdict.bestOf(Verdict.HANDSHAKE_OK, Verdict.UDP_SILENT) == Verdict.HANDSHAKE_OK &&
                Verdict.bestOf(Verdict.UDP_CLOSED, Verdict.ERROR) == Verdict.UDP_CLOSED &&
                Verdict.bestOf(Verdict.TLS_OK, Verdict.COOKIE_REPLY) == Verdict.COOKIE_REPLY)
        val mixed = EndpointStats(Endpoint("1.2.3.4", 500),
            listOf(ProbeSample(Endpoint("1.2.3.4", 500), Verdict.UDP_SILENT, null, 0, "none"),
                ProbeSample(Endpoint("1.2.3.4", 500), Verdict.HANDSHAKE_OK, 30.0, 1, "none")),
            Verdict.HANDSHAKE_OK, 1, 2)
        check("вердикт: один живой образец не тонет в тишине", mixed.bestVerdict == Verdict.HANDSHAKE_OK)
    }

    private fun reportRendering() {
        val cfg = dev.warpscout.core.model.WarpConfig(
            name = "тест",
            account = dev.warpscout.core.model.WarpAccount("a=".repeat(1), "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=", "172.16.0.2", "2606::1"),
            endpoint = Endpoint("188.114.98.2", 943),
            junk = dev.warpscout.core.junk.JunkLibrary.quic("ivi.ru", 3, 1),
            allowedIps = "0.0.0.0/0, ::/0"
        )
        val st = EndpointStats(cfg.endpoint, listOf(ProbeSample(cfg.endpoint, Verdict.HANDSHAKE_OK, 33.0, 0)), Verdict.HANDSHAKE_OK, 1, 1)
        val cand = dev.warpscout.core.model.Candidate(cfg, st, Scoring.evaluate(st, true), emptyList())
        val report = dev.warpscout.core.model.TuningReport("т", "т", "профиль", listOf(cand), emptyList(), 12, listOf("заметка <1>"))

        val json = Report.toJson(report, includeConfig = false)
        val parsed = dev.warpscout.core.json.parseJson(json) as dev.warpscout.core.json.JsonVal.Obj
        expect("отчёт JSON: читается обратно, candidates", (parsed.arr("candidates")?.items?.size), 1)
        expect("отчёт JSON: endpoint", parsed.arr("candidates")?.items?.firstOrNull()?.let { (it as dev.warpscout.core.json.JsonVal.Obj).str("endpoint") }, "188.114.98.2:943")
        expect("отчёт JSON: score", parsed.arr("candidates")?.items?.firstOrNull()?.let { (it as dev.warpscout.core.json.JsonVal.Obj).num("score")?.toInt() }, cand.score)
        val html = Report.toHtml(report)
        check("отчёт HTML: содержит endpoint и экранирует заметки",
            html.contains("188.114.98.2:943") && html.contains("&lt;1&gt;") && html.startsWith("<!doctype html"))
        check("отчёт CSV: строка на кандидата", Report.toCsv(report).trim().lines().size == 2)
        check("отчёт MD: таблица кандидатов", Report.toMarkdown(report).contains("188.114.98.2:943"))
        val conf = WgConf.render(cfg)
        check("конфиг: содержит AWG-параметры", conf.contains("Jc = 4") && conf.contains("I1 = <b 0x"))
        check("конфиг: Clash YAML собирается", dev.warpscout.core.report.ConfigExport.clashYaml(cfg).contains("amnezia-wg-option"))
    }

    // ---------------------------------------------------------------- live: сеть

    private fun liveNetwork() {
        val keys = KeySource()
        val acc = runCatching { keys.fetchFresh() }.getOrNull()
        check("ключи: генератор ответил", acc != null, "все зеркала недоступны")
        if (acc != null) {
            check("ключи: приватный похож на Curve25519", KeySource.looksLikeCurve25519(acc.privateB64), acc.privateB64)
            expect("ключи: публичный ключ пира", acc.peerPublicB64, "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=")
            println("    источник: ${acc.source}, v4=${acc.ipv4}, v6=${acc.ipv6}")
        }

        val dns = dev.warpscout.core.net.DnsInspector()
        val res = dns.check(listOf("youtube.com", "mesh.clouflare.invalid"))
        check("DNS: DoH-резолвер отвечает", res.any { it.cloudflareDoH.isNotEmpty() })
        res.forEach { println("    ${it.domain}: system=${it.system.take(2)} cf=${it.cloudflareDoH.take(2)} → ${it.verdict}") }

        val tls = TlsProber(NetSettings(connectTimeoutMs = 3000))
        val sample = listOf(Endpoint("1.1.1.1", 443), Endpoint("162.159.198.2", 443)).map { tls.probe(it, "www.google.com") }
        sample.forEach { println("    TLS ${it.endpoint.render()} → ${it.verdict} ${it.rttMs} ${it.note}") }
        check("TLS: хотя бы один эндпоинт отвечает (иначе сеть не для живых проверок)",
            sample.any { it.verdict == Verdict.TLS_OK })

        val resources = dev.warpscout.core.net.ResourceProber()
        val rr = resources.checkAll(dev.warpscout.core.presets.Presets.RESOURCE_CHECKS.take(4), 4)
        rr.forEach { println("    ${it.check.name}: ok=${it.ok} status=${it.status} err=${it.errorClass} ${it.elapsedMs}мс") }
        check("ресурсы: контроль-точка доступна", rr.firstOrNull()?.ok == true, "даже базовый сайт недоступен из этой сети")
    }

    /**
     * Туннельный data plane целиком: живой UDP-сокет, фейковый-peer отвечает по спецификации,
     * мы проверяем, что IP-пакет ушёл зашифрованным и вернулся обратно расшифрованным.
     */
    /** Пакет-«пользовательские данные»: 48 байт с правдоподобным IPv4-заголовком. */
    private fun testPacket(): ByteArray = ByteArray(48).also { b ->
        b[0] = 0x45; b[12] = 108.toByte(); b[13] = 64.toByte()
        b[16] = 1.toByte(); b[17] = 1; b[18] = 1; b[19] = 1
        for (i in 20 until 48) b[i] = (i % 251).toByte()
    }

    /** Обвязка для тестов data plane: туннель без настоящего tun-устройства. */
    private class PlaneHarness(
        val plane: dev.warpscout.core.tunnel.DataPlane,
        val tunIn: QueueInputStream,
        val tunOut: QueueOutputStream,
        val log: StringBuilder,
        val thread: Thread
    ) {
        fun awaitUp(timeoutMs: Long): Boolean {
            val until = System.currentTimeMillis() + timeoutMs
            while (!plane.handshakeOk && System.currentTimeMillis() < until) Thread.sleep(10)
            return plane.handshakeOk
        }

        fun stop() {
            plane.stop()
            runCatching { thread.join(1500) }
        }
    }

    private fun startPlane(
        clientPriv: ByteArray,
        serverPub: ByteArray,
        port: Int,
        settings: NetSettings
    ): PlaneHarness {
        val tunIn = QueueInputStream()
        val tunOut = QueueOutputStream()
        val sock = java.net.DatagramSocket().apply {
            connect(java.net.InetSocketAddress("127.0.0.1", port))
            soTimeout = 300
        }
        val config = dev.warpscout.core.model.WarpConfig(
            name = "test",
            account = dev.warpscout.core.model.WarpAccount(Crypto.base64(clientPriv), Crypto.base64(serverPub)),
            endpoint = Endpoint("127.0.0.1", port),
            junk = dev.warpscout.core.junk.JunkLibrary.none(),
            persistentKeepalive = null
        )
        val log = StringBuilder()
        val plane = dev.warpscout.core.tunnel.DataPlane(
            dev.warpscout.core.tunnel.SocketUdpChannel(sock, Endpoint("127.0.0.1", port), 300),
            tunIn, tunOut, config, settings
        ) { line -> log.append(line).append("; ") }
        val thread = Thread { plane.run() }.apply { isDaemon = true; start() }
        return PlaneHarness(plane, tunIn, tunOut, log, thread)
    }

    /**
     * ICMP port unreachable — самый частый ответ на «мёртвой» точке: сервер прямо говорит, что на
     * этом порту WARP нет. Раньше это тонуло в общем «чтение сокета» и туннель продолжал ждать
     * ещё пять инициаций по 400 мс — то есть каждая мёртвая точка стоила двух с половиной секунд
     * и лишних датаграмм. Проверяем именно это: отказ быстрый и с внятной причиной.
     */
    private fun deadPortFailsFast() {
        val clientPriv = ByteArray(32) { (it * 3 + 7).toByte() }
        val serverPriv = ByteArray(32) { (it * 5 + 11).toByte() }
        val dead = object : dev.warpscout.core.tunnel.UdpChannel {
            override fun send(packet: ByteArray) = Unit
            override fun receive(): ByteArray? =
                throw java.net.PortUnreachableException("ICMP Port Unreachable")
            override fun close() = Unit
        }
        val config = WarpConfig(
            name = "test",
            account = WarpAccount(Crypto.base64(clientPriv), Crypto.base64(Crypto.publicOf(serverPriv))),
            endpoint = Endpoint("127.0.0.1", 9),
            junk = JunkLibrary.none(),
            persistentKeepalive = null
        )
        val startedAt = System.currentTimeMillis()
        val plane = dev.warpscout.core.tunnel.DataPlane(
            dead,
            java.io.PipedInputStream(),
            java.io.ByteArrayOutputStream(),
            config,
            NetSettings(attempts = 5, timeoutMs = 1000, retryEveryMs = 400, junkPacketsBeforeHandshake = 1)
        )
        val ok = plane.run()
        val took = System.currentTimeMillis() - startedAt
        check("закрытый порт: туннель не поднят", !ok)
        check(
            "закрытый порт: причина названа портом, а не «сервер молчит»",
            plane.failureReason?.contains("порт закрыт") == true,
            plane.failureReason ?: "причина не записана"
        )
        check("закрытый порт: не ждём остальные инициации", took < 1_500, "$took мс")
    }

    private fun dataPlaneLoopback() {
        val clientPriv = ByteArray(32) { (it * 3 + 7).toByte() }
        val serverPriv = ByteArray(32) { (it * 5 + 11).toByte() }
        val server = LoopbackServer(serverPriv).start()
        val h = startPlane(clientPriv, Crypto.publicOf(serverPriv), server.port,
            NetSettings(attempts = 3, timeoutMs = 1200))
        try {
            val ipPacket = testPacket()
            h.tunIn.offer(ipPacket)
            val seen = server.firstPacket(8000)
            check("data plane: handshake поднят", h.plane.handshakeOk, h.log.toString())
            check("data plane: пакет дошёл до пира", seen?.contentEquals(ipPacket) == true,
                server.error ?: "payload=${seen?.size}")
            val back = h.tunOut.poll(3000L)
            check("data plane: эхо вернулось в tun", back?.contentEquals(ipPacket) == true, "back=${back?.size}")
            val counterDeadline = System.currentTimeMillis() + 1000
            while (System.currentTimeMillis() < counterDeadline &&
                (h.plane.bytesUp < ipPacket.size || h.plane.bytesDown == 0L)
            ) Thread.sleep(25)
            check(
                "data plane: счётчики учтены",
                h.plane.bytesUp == ipPacket.size.toLong() && h.plane.bytesDown == ipPacket.size.toLong(),
                "up=${h.plane.bytesUp} down=${h.plane.bytesDown} ожидалось=${ipPacket.size}"
            )
        } finally {
            h.stop()
            server.stop()
        }
    }

    /**
     * Пересогласование сессии (rekey) — регрессия на «работает 3–5 минут, потом Telegram пишет
     * Соединение…». Таймеры ускорены, сервер локальный, поэтому проверка идёт офлайн.
     */
    private fun dataPlaneRekey() {
        val clientPriv = ByteArray(32) { (it * 3 + 17).toByte() }
        val serverPriv = ByteArray(32) { (it * 5 + 23).toByte() }
        val server = LoopbackServer(serverPriv).start()
        val h = startPlane(clientPriv, Crypto.publicOf(serverPriv), server.port,
            NetSettings(attempts = 2, timeoutMs = 1000, rekeyAfterMs = 700, rekeyRetryMs = 150))
        try {
            check("rekey: сессия поднялась", h.awaitUp(4000), h.log.toString())

            // Пересогласование по требованию (1.10.13): в полной тишине rekey не выполняется —
            // иначе модем просыпается каждые 150 с без всякой пользы. Значит, чтобы проверить
            // плановый rekey, нужен живой трафик: подкидываем по пакету, пока не наберётся два.
            val rekeyUntil = System.currentTimeMillis() + 6000
            while (h.plane.rekeyCount < 2 && System.currentTimeMillis() < rekeyUntil) {
                h.tunIn.offer(testPacket())
                Thread.sleep(50)
            }
            check(
                "rekey: сессия пересогласована сама (2 раза)",
                h.plane.rekeyCount >= 2,
                "rekey=${h.plane.rekeyCount}, инициаций=${server.initiations.get()}, ${h.log}"
            )

            val ipPacket = testPacket()
            h.tunIn.offer(ipPacket)
            val back = h.tunOut.poll(4000L)
            check("rekey: данные идут после пересогласования", back?.contentEquals(ipPacket) == true,
                server.error ?: "back=${back?.size}; ${h.log}")
            check("rekey: возраст сессии обнулился", h.plane.sessionAgeMs() < 4000,
                "age=${h.plane.sessionAgeMs()}")
            // Как настоящий сервер: каждая инициация обязана нести метку новее прошлой, иначе он
            // молча отбросит её как повтор (WARP этого не проверяет — свой сервер проверяет).
            check(
                "rekey: метка времени каждой инициации новее прошлой",
                server.staleStamps.get() == 0,
                "инициаций с меткой не новее прошлой: ${server.staleStamps.get()} из ${server.initiations.get()}"
            )

            // Тишина: ждём дольше, чем rekeyAfterMs, и убеждаемся, что рукопожатий не прибавилось.
            // Это и есть «не будить радио зря»: расход батареи в простое давали именно эти
            // пересогласования каждые 150 секунд.
            //
            // Сначала даём плоскости доработать накопленные пакеты и трафику стихнуть: пока хоть
            // один пакет идёт, «живой трафик» — это правда, и плановый rekey в это время законен.
            // Заодно вычерпываем эхо, иначе очередь в tun переполнится и задержит доставку.
            val settleUntil = System.currentTimeMillis() + 1200
            while (System.currentTimeMillis() < settleUntil) {
                h.tunOut.poll(50L)
            }
            val before = h.plane.rekeyCount
            Thread.sleep(1400)
            check(
                "rekey: в тишине сессия не пересогласовывается",
                h.plane.rekeyCount == before,
                "было $before, стало ${h.plane.rekeyCount}; ${h.log}"
            )

            // А первый пакет после простоя должен вернуть сессию: либо уже действующую, либо
            // пересогласованную на месте (см. tunToUdp).
            val afterIdle = testPacket()
            h.tunIn.offer(afterIdle)
            check(
                "rekey: после простоя данные идут",
                h.tunOut.poll(4000L) != null,
                "back=null; ${h.log}"
            )
        } finally {
            h.stop()
            server.stop()
        }
    }

    /** Окна пересогласования (1.10.40): ответ на rekey ждём дольше, чем 2,6 с прежнего окна. */
    private fun slowNetSettings() {
        val service = NetSettings(attempts = 5, timeoutMs = 1000, retryEveryMs = 400)
        val rekeyWindow = service.retryEveryMs * (service.attempts - 1) + maxOf(service.timeoutMs.toLong(), service.rekeyWaitMs)
        check("медленная связь: окно rekey шире прежних 2,6 с (журнал 23.11, 15:50 — ответ шёл 4,8 с)",
            rekeyWindow >= 6_000L, "$rekeyWindow мс")
        expect("медленная связь: предел сессии — 180 с (REJECT_AFTER_TIME)", NetSettings().rejectAfterMs, 180_000L)
        check("медленная связь: rekey начинается раньше предела, есть время на повторы",
            NetSettings().rejectAfterMs - NetSettings().rekeyAfterMs >= 3 * NetSettings().rekeyRetryMs)
    }

    /** Data plane для проверок медленной сети: с отчётом о смерти сессии ([fatal]). */
    private class SlowHarness(
        val plane: dev.warpscout.core.tunnel.DataPlane,
        val tunIn: QueueInputStream,
        val tunOut: QueueOutputStream,
        val log: StringBuffer,
        val fatal: java.util.concurrent.atomic.AtomicReference<String?>,
        val fatalAt: java.util.concurrent.atomic.AtomicLong,
    ) {
        fun stop() {
            runCatching { plane.stop() }
            runCatching { tunIn.close() }
        }

        fun awaitUp(ms: Long): Boolean {
            val until = System.currentTimeMillis() + ms
            while (System.currentTimeMillis() < until) {
                if (plane.handshakeOk) return true
                Thread.sleep(20)
            }
            return plane.handshakeOk
        }
    }

    private fun startSlowPlane(serverPriv: ByteArray, port: Int, settings: NetSettings): SlowHarness {
        val clientPriv = ByteArray(32) { (it * 7 + 29).toByte() }
        val tunIn = QueueInputStream()
        val tunOut = QueueOutputStream()
        val sock = java.net.DatagramSocket().apply {
            connect(java.net.InetSocketAddress("127.0.0.1", port))
            soTimeout = 300
        }
        val config = WarpConfig(
            name = "test",
            account = WarpAccount(Crypto.base64(clientPriv), Crypto.base64(Crypto.publicOf(serverPriv))),
            endpoint = Endpoint("127.0.0.1", port),
            junk = JunkLibrary.none(),
            persistentKeepalive = null
        )
        val log = StringBuffer()
        val fatal = java.util.concurrent.atomic.AtomicReference<String?>(null)
        val fatalAt = java.util.concurrent.atomic.AtomicLong(0L)
        val plane = dev.warpscout.core.tunnel.DataPlane(
            udp = dev.warpscout.core.tunnel.SocketUdpChannel(sock, Endpoint("127.0.0.1", port), 300),
            tunInput = tunIn,
            tunOutput = tunOut,
            config = config,
            settings = settings,
            log = { line -> log.append(line).append("; ") },
            onFatal = { reason ->
                if (fatal.compareAndSet(null, reason)) fatalAt.set(System.currentTimeMillis())
            }
        )
        Thread { plane.run() }.apply { isDaemon = true; start() }
        return SlowHarness(plane, tunIn, tunOut, log, fatal, fatalAt)
    }

    /**
     * H/H+ под нагрузкой: сервер отвечает на rekey через 1,5 с — дольше прежнего окна (0,6 с в этих
     * ускоренных настройках), но в пределах окна пересогласования. Сессия обязана обновиться, а
     * туннель — не быть объявлен мёртвым.
     */
    private fun dataPlaneSlowRekey() {
        val serverPriv = ByteArray(32) { (it * 11 + 3).toByte() }
        val server = LoopbackServer(serverPriv, delayResponse = { n -> if (n == 1) 0L else 1_500L }).start()
        val h = startSlowPlane(serverPriv, server.port, NetSettings(
            attempts = 2, timeoutMs = 400, retryEveryMs = 200,
            rekeyAfterMs = 600, rekeyRetryMs = 150, rekeyWaitMs = 3_000
        ))
        try {
            check("медленная связь: сессия поднялась", h.awaitUp(4_000), h.log.toString())
            val until = System.currentTimeMillis() + 5_000
            while (h.plane.rekeyCount < 1 && System.currentTimeMillis() < until) {
                h.tunIn.offer(testPacket())
                h.tunOut.poll(40L)
            }
            check("медленная связь: rekey дождался ответа через 1,5 с", h.plane.rekeyCount >= 1,
                "rekey=${h.plane.rekeyCount}, инициаций=${server.initiations.get()}; ${h.log}")
            check("медленная связь: туннель не объявлен мёртвым", h.fatal.get() == null, h.fatal.get() ?: "")
            val ip = testPacket()
            h.tunIn.offer(ip)
            check("медленная связь: данные идут после медленного rekey", h.tunOut.poll(3_000L)?.contentEquals(ip) == true, h.log.toString())
        } finally {
            h.stop()
            server.stop()
        }
    }

    /**
     * Сервер на rekey молчит, а данные по нынешней сессии возит (журнал 23.11, 15:50). Туннель не
     * рвём, пока сессия не старше предела ([NetSettings.rejectAfterMs], здесь 3 с), — и всё это время
     * пакеты идут без задержек: отправитель не стоит на пересогласовании. После предела — обрыв.
     */
    private fun dataPlaneRekeyAliveKeeps() {
        val serverPriv = ByteArray(32) { (it * 13 + 5).toByte() }
        val server = LoopbackServer(serverPriv, answerInitiation = { it == 1 }).start()
        val h = startSlowPlane(serverPriv, server.port, NetSettings(
            attempts = 2, timeoutMs = 400, retryEveryMs = 150,
            rekeyAfterMs = 500, rekeyRetryMs = 150, rekeyWaitMs = 600, rejectAfterMs = 3_000
        ))
        try {
            check("rekey молчит, данные идут: сессия поднялась", h.awaitUp(4_000), h.log.toString())
            val upAt = System.currentTimeMillis()
            var worst = 0L
            var lost = 0
            var echoed = 0
            while (System.currentTimeMillis() - upAt < 2_700L && h.fatal.get() == null) {
                val ip = testPacket()
                val sent = System.currentTimeMillis()
                h.tunIn.offer(ip)
                val back = h.tunOut.poll(1_500L)
                if (back == null) lost++ else {
                    echoed++
                    worst = maxOf(worst, System.currentTimeMillis() - sent)
                }
                Thread.sleep(30)
            }
            val keptFor = System.currentTimeMillis() - upAt
            check("rekey молчит, данные идут: пересогласование и правда не проходит", h.plane.rekeyCount == 0,
                "rekey=${h.plane.rekeyCount}")
            check("rekey молчит, данные идут: туннель не рвётся, пока сессия действует",
                h.fatal.get() == null, "${h.fatal.get()} через $keptFor мс; ${h.log}")
            check("rekey молчит, данные идут: пакеты не стоят на пересогласовании",
                worst < 350L && lost == 0 && echoed > 20, "худший ответ $worst мс, потеряно $lost, дошло $echoed")
            check("rekey молчит, данные идут: в журнале — «сеть медленная, туннель не рву»",
                h.log.contains("туннель не рву"), h.log.toString().takeLast(300))
            // Дальше сессия просрочена — сервер её не примет: рвём, как раньше.
            val until = System.currentTimeMillis() + 3_000
            while (h.fatal.get() == null && System.currentTimeMillis() < until) {
                h.tunIn.offer(testPacket())
                h.tunOut.poll(50L)
            }
            val after = if (h.fatalAt.get() > 0L) h.fatalAt.get() - upAt else -1L
            check("rekey молчит, данные идут: после предела сессии — обрыв",
                h.fatal.get()?.contains("не пересогласовывается") == true && after >= 3_000L,
                "${h.fatal.get()} через $after мс")
        } finally {
            h.stop()
            server.stop()
        }
    }

    /** Сервер умер совсем: на rekey молчит и данных не возит — обрыв после двух неудач, как раньше. */
    private fun dataPlaneRekeyDeadFails() {
        val serverPriv = ByteArray(32) { (it * 17 + 9).toByte() }
        val dead = java.util.concurrent.atomic.AtomicBoolean(false)
        val server = LoopbackServer(
            serverPriv,
            answerInitiation = { it == 1 },
            answerData = { if (dead.get()) null else it }
        ).start()
        val h = startSlowPlane(serverPriv, server.port, NetSettings(
            attempts = 2, timeoutMs = 400, retryEveryMs = 150,
            rekeyAfterMs = 500, rekeyRetryMs = 150, rekeyWaitMs = 600, rejectAfterMs = 60_000
        ))
        try {
            check("сервер умер: сессия поднялась", h.awaitUp(4_000), h.log.toString())
            val upAt = System.currentTimeMillis()
            dead.set(true)
            val until = upAt + 5_000
            while (h.fatal.get() == null && System.currentTimeMillis() < until) {
                h.tunIn.offer(testPacket())
                h.tunOut.poll(50L)
            }
            val after = if (h.fatalAt.get() > 0L) h.fatalAt.get() - upAt else -1L
            check("сервер умер: обрыв после двух неудачных rekey, не дожидаясь предела сессии",
                h.fatal.get()?.contains("не пересогласовывается") == true && after in 0L..4_000L,
                "${h.fatal.get()} через $after мс; ${h.log}")
        } finally {
            h.stop()
            server.stop()
        }
    }

    /**
     * «Поднимается только с пятой попытки» — регрессия ровно на эту жалобу.
     *
     * Сервер нарочно игнорирует первую инициацию (так ведёт себя сеть, теряющая первый датаграмм
     * нового UDP-потока). Клиент обязан не ждать полное окно `timeoutMs`, а повторить инициацию
     * через `retryEveryMs` и подняться быстро.
     */
    private fun dataPlaneRetryAfterLoss() {
        val clientPriv = ByteArray(32) { (it * 7 + 3).toByte() }
        val serverPriv = ByteArray(32) { (it * 11 + 5).toByte() }
        val server = LoopbackServer(serverPriv, answerInitiation = { n -> n >= 2 }).start()
        val h = startPlane(clientPriv, Crypto.publicOf(serverPriv), server.port,
            NetSettings(attempts = 5, timeoutMs = 1000, retryEveryMs = 200))
        val startedAt = System.currentTimeMillis()
        try {
            val up = h.awaitUp(4000)
            val took = System.currentTimeMillis() - startedAt
            check("сеть: handshake переживает потерю первой инициации", up, h.log.toString())
            check("сеть: повтор ушёл раньше общего окна (быстро)", up && took < 1500,
                "заняло ${took} мс; ${h.log}")
            check("сеть: потребовалось больше одной инициации", h.plane.attemptCount >= 2,
                "инициаций=${h.plane.attemptCount}")

            val ipPacket = testPacket()
            h.tunIn.offer(ipPacket)
            val back = h.tunOut.poll(3000L)
            check("сеть: данные идут после потери инициации", back?.contentEquals(ipPacket) == true,
                "back=${back?.size}; ${h.log}")
        } finally {
            h.stop()
            server.stop()
        }
    }

    private fun liveIntegration(target: String) {
        val (host, portStr) = target.split(':')
        val endpoint = Endpoint(host, portStr.toInt())
        val priv = ByteArray(32) { (it + 3).toByte() }.also { it[31] = 0 }
        val account = dev.warpscout.core.model.WarpAccount(Crypto.base64(priv), Crypto.base64(Crypto.publicOf(priv)))
        val peerPriv = ByteArray(32) { (it * 2 + 1).toByte() }.also { it[31] = 0 }
        val prober = WgProber(NetSettings(attempts = 2, timeoutMs = 2500, betweenAttemptsMs = 50, concurrency = 2))
        val res = prober.probe(endpoint, account, Crypto.publicOf(peerPriv), dev.warpscout.core.junk.JunkLibrary.tlsFixed())
        expect("integration: фейковый сервер подтвердил handshake", res.stats.bestVerdict.toString(), "HANDSHAKE_OK")
        check("integration: RTT померен", (res.stats.minRtt ?: 0.0) > 0.0, "rtt=${res.stats.minRtt}")

        val closed = prober.probe(Endpoint("127.0.0.1", 1), account, Crypto.publicOf(peerPriv), null)
        // UDP_CLOSED — ICMP port unreachable; UDP_SILENT — молчит (тоже «не живой»);
        // ERROR — сокет не смог отправить/принять (в контейнерах ICMP отрезан). Все три означают
        // «порт не подтвердился», и именно это проверяется: закрытый порт НЕ выдаёт себя за живой.
        check("integration: закрытый порт отличается от «молчит»",
            closed.stats.bestVerdict in setOf(Verdict.UDP_CLOSED, Verdict.UDP_SILENT, Verdict.ERROR),
            "вердикт=${closed.stats.bestVerdict}, примечание=${closed.stats.samples.firstOrNull()?.note}")

        // Транспорт сквозь НЕЗАВИСИМУЮ реализацию (tools/fake_warp_endpoint.py) — причём не «ручной»
        // обмен пакетами, а настоящий DataPlane: мусор → инициация → cookie → сессия → эхо в tun.
        runCatching {
            val peerPub = Crypto.publicOf(peerPriv)
            val cfg = dev.warpscout.core.model.WarpConfig(
                name = "integration",
                account = dev.warpscout.core.model.WarpAccount(
                    privateB64 = Crypto.base64(priv),
                    peerPublicB64 = Crypto.base64(peerPub)
                ),
                endpoint = endpoint,
                junk = dev.warpscout.core.junk.JunkLibrary.tlsFixed(),
                persistentKeepalive = null
            )
            val tunIn = QueueInputStream()
            val tunOut = QueueOutputStream()
            val sock = java.net.DatagramSocket().apply {
                soTimeout = 800
                connect(java.net.InetSocketAddress(host, portStr.toInt()))
            }
            val planeLog = StringBuilder()
            val plane = dev.warpscout.core.tunnel.DataPlane(
                dev.warpscout.core.tunnel.SocketUdpChannel(sock, endpoint, 800),
                tunIn, tunOut, cfg,
                NetSettings(
                    attempts = 3, timeoutMs = 2500, betweenAttemptsMs = 120, junkPacketsBeforeHandshake = 1,
                    // Ускоренный rekey: проверяем само пересогласование, а не то, что 120 с проходят.
                    rekeyAfterMs = 900, rekeyRetryMs = 200
                )
            ) { line -> planeLog.append(line).append("; ") }
            val thread = Thread { plane.run() }.apply { isDaemon = true; start() }
            try {
                val until = System.currentTimeMillis() + 9000
                while (!plane.handshakeOk && System.currentTimeMillis() < until) Thread.sleep(50)
                check("integration: data plane поднял сессию", plane.handshakeOk, planeLog.toString())

                val ip = ByteArray(48).also { b ->
                    b[0] = 0x45; b[12] = 108.toByte(); b[13] = 64.toByte()
                    b[16] = 1.toByte(); b[17] = 1; b[18] = 1; b[19] = 1
                    for (i in 20 until 48) b[i] = (i % 251).toByte()
                }
                tunIn.offer(ip)
                val back = tunOut.poll(5000L)
                check("integration: пакет прошёл сквозь tun туда и обратно",
                    back?.contentEquals(ip) == true, "back=${back?.size} байт; $planeLog")
                var waited = 0
                while (waited < 1000 && (plane.bytesUp < ip.size || plane.bytesDown < ip.size)) {
                    Thread.sleep(25); waited += 25
                }
                check("integration: data plane посчитал трафик",
                    plane.bytesUp == ip.size.toLong() && plane.bytesDown == ip.size.toLong(),
                    "up=${plane.bytesUp} down=${plane.bytesDown}")

                // Ровно тот баг, из-за которого Telegram умирал через три минуты: сессия обязана
                // пересогласовываться САМА, без перезапуска сервиса.
                // Трафик во время ожидания обязателен: с 1.10.13 в полной тишине пересогласования
                // нет (не будим радио зря), а с потоком пакетов плановый rekey работает как раньше.
                val rekeyUntil = System.currentTimeMillis() + 6000
                while (plane.rekeyCount < 1 && System.currentTimeMillis() < rekeyUntil) {
                    tunIn.offer(ip)
                    tunOut.poll(200L)
                    Thread.sleep(50)
                }
                check("integration: сессия пересогласована автоматически", plane.rekeyCount >= 1,
                    "rekey=${plane.rekeyCount}; ${planeLog}")
            } finally {
                plane.stop()
                runCatching { sock.close() }
                runCatching { thread.join(1500) }
            }
        }.onFailure { reportFail("integration: data plane упал — ${it.javaClass.simpleName}: ${it.message}") }
    }

    // --------------------------------------------------- SOCKS5 / сравнение с ByeDPI

    private fun socks5ByeDpiCompare() {
        expect("socks5: разбор host:port", Socks5Endpoint.parse("127.0.0.1:1080")?.render(), "127.0.0.1:1080")
        expect("socks5: только порт = loopback", Socks5Endpoint.parse("1080")?.render(), "127.0.0.1:1080")
        expect("socks5: префикс схемы и скобки", Socks5Endpoint.parse("socks5://[::1]:1080")?.render(), "::1:1080")
        check("socks5: пусто → null", Socks5Endpoint.parse("   ") == null)
        check("socks5: мусор → null", Socks5Endpoint.parse("localhost") == null && Socks5Endpoint.parse("host:") == null)
        check("socks5: порт вне диапазона → null", Socks5Endpoint.parse("127.0.0.1:99999") == null)
        check("socks5: конфиг ByeDPI по умолчанию", Socks5Endpoint.BYEDPI_DEFAULT.render() == "127.0.0.1:1080")

        val origin = FakeHttpOrigin()
        val proxy = FakeSocks5Relay(origin.port)
        try {
            val target = "http://127.0.0.1:${origin.port}/"

            val sock = Socks5.connect(Socks5Endpoint("127.0.0.1", proxy.port), "127.0.0.1", origin.port, 3000)
            sock.getOutputStream().write("GET / HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n".toByteArray())
            val text = sock.getInputStream().readBytes().toString(Charsets.UTF_8)
            sock.close()
            check("socks5: байты прошли через прокси", text.contains("200 OK"), text.take(60).replace("\r\n", " "))
            expect("socks5: цель передана как IPv4 (ATYPE 1)", proxy.lastAtyp.toString(), "1")
            expect("socks5: порт цели в сетевом порядке", proxy.lastPort, origin.port)

            val viaProxy = HttpClient(3000, proxy = Socks5Endpoint("127.0.0.1", proxy.port))
            expect("HttpClient через SOCKS5: статус", viaProxy.get(target).status, 200)

            val cmp = DpiComparator(timeoutMs = 4000, connectTimeoutMs = 1500).compare(
                listOf(
                    ResourceCheck("открыто всегда", target),
                    // домен в зоне .invalid не резолвится никогда (RFC 6761) — «напрямую» обязано лечь,
                    // а наш фейковый прокси умеет подменять его на живой источник: ровно картина DPI-блокировки
                    ResourceCheck("лежит напрямую", "http://blocked.invalid:80/")
                ),
                Socks5Endpoint("127.0.0.1", proxy.port)
            )
            check("comparator: сравнение состоялось", cmp.usable, cmp.headline())
            expect("comparator: открыто и там и там", cmp.rows[0].outcome.name, "OPEN_BOTH")
            expect("comparator: оживает только через обход", cmp.rows[1].outcome.name, "OPEN_ONLY_VIA_PROXY")
            expect("comparator: счётчик DPI-образных", cmp.dpiShaped, 1)
            check("comparator: вывод по-русски и по делу",
                cmp.headline().contains("DPI") && cmp.renderText().contains("через SOCKS5"), cmp.headline())

            val dead = DpiComparator(1500, 800).compare(listOf(ResourceCheck("t", target)), Socks5Endpoint("127.0.0.1", 1))
            expect("comparator: мёртвый прокси → PROXY_UNREACHABLE", dead.rows.single().outcome.name, "PROXY_UNREACHABLE")
            check("comparator: при мёртвом прокси не врёт про блокировки",
                !dead.usable && dead.headline().contains("режим прокси"), dead.headline())

            val auth = FakeSocks5NeedsAuth()
            val err = runCatching {
                Socks5.connect(Socks5Endpoint("127.0.0.1", auth.port), "127.0.0.1", origin.port, 1500)
            }.exceptionOrNull()
            check("socks5: требование авторизации объясняется по-человечески",
                err?.message?.contains("аутентификац") == true, err?.message.orEmpty())
            auth.close()
        } finally {
            origin.close()
            proxy.close()
        }
    }

    // ------------------------------- списки allow-domains, маршруты, клиенты конфига

    private fun allowListsAndRoutes() {
        val sample = """
            # комментарий как в репозитории
            ; и такой тоже
            youtube.com
            .googlevideo.com
            *.youtu.be
            91.108.4.0/22
            2001:67c:4e8::/48
            DOMAIN-SUFFIX,discord.com
            IP-CIDR,149.154.160.0/20
            ||blocked.tld
            !excluded.tld
            мусорная строка
            no-dot-here
        """.trimIndent()
        val parsed = AllowLists.parse(sample)
        expect("списки: домены распознаны", parsed.domains.size, 6)
        expect("списки: подсети распознаны", parsed.prefixes.size, 3)
        check("списки: ведущая точка/звёздочка сняты", "youtu.be" in parsed.domains && "googlevideo.com" in parsed.domains)
        check("списки: surge/uBlock-форматы поняты",
            "discord.com" in parsed.domains && "blocked.tld" in parsed.domains && "excluded.tld" in parsed.domains)
        check("списки: CIDR из surge-строки понят", "149.154.160.0/20" in parsed.prefixes)
        check("списки: мусор и голые имена отвергнуты",
            parsed.domains.none { it.contains("мусор") } && parsed.domains.none { it == "no-dot-here" })

        // --- план маршрутов: подсети берём как есть, домены резолвим, бюджет соблюдаем
        val block = listOf(AllowList("t1", "Тест1", ListSide.BLOCK, "x"))
        val direct = listOf(AllowList("t2", "Тест2", ListSide.DIRECT, "y"))
        val maps = mapOf("t1" to parsed, "t2" to AllowLists.Parsed(listOf("alfabank.ru"), listOf("1.2.3.0/24")))
        val resolver: (String) -> List<String> = { host ->
            when (host) {
                "youtube.com" -> listOf("172.64.0.1", "2606:4700::1")
                "googlevideo.com" -> listOf("216.58.200.14")
                "youtu.be" -> emptyList()          // «не разрешилось» должно быть видно, а не проглочено
                else -> emptyList()
            }
        }
        val plan = AllowListPlanner.plan(block, direct, maps, fullTunnel = false, maxDomains = 6, resolver = resolver)
        check("маршруты: подсети из списка попали", "91.108.4.0/22" in plan.include && "2001:67c:4e8::/48" in plan.include)
        check("маршруты: домен развёрнут в /32 и /128",
            "172.64.0.1/32" in plan.include && "2606:4700::1/128" in plan.include)
        check("маршруты: не разрешилось записано, а не проигнорировано", "youtu.be" in plan.unresolved)
        check("маршруты: чужие домены (DIRECT) не попали в AllowedIPs",
            plan.include.none { it.startsWith("1.2.3.") } && plan.excludeNote.contains("alfabank.ru"))
        check("маршруты: allowedIps — это CIDR-список",
            plan.allowedIps.split(", ").toSet() == plan.include.toSet() && plan.allowedIps.contains("/32"),
            plan.allowedIps.take(120))
        // бюджет — на домены, а не на подсети: 1 подсеть + 1 домен в лимите 1
        val tight = AllowListPlanner.plan(block, direct, maps, fullTunnel = false, maxDomains = 1, resolver = resolver)
        check("маршруты: бюджет режет домены, но не подсети",
            tight.include.any { it == "91.108.4.0/22" } && tight.include.count { it.endsWith("/32") } <= 2,
            tight.include.take(6).joinToString())
        check("маршруты: сводка объяснимая", plan.summary().contains("маршрутов"), plan.summary())
        // 1.10.31: у списка youtube — ещё и сети Google, откуда идёт видео (googlevideo.com заранее не развернуть).
        val yt = AllowListPlanner.plan(
            listOf(AllowList("youtube", "YouTube", ListSide.BLOCK, "x")), emptyList(),
            mapOf("youtube" to AllowLists.Parsed(listOf("youtube.com"), emptyList())),
            fullTunnel = false, maxDomains = 6, resolver = resolver
        )
        check("маршруты: видео YouTube — сети Google в маршрутах",
            "142.250.0.0/15" in yt.include && "173.194.0.0/16" in yt.include && "2a00:1450::/32" in yt.include,
            yt.include.take(6).joinToString())
        check("маршруты: чужому списку сети Google не добавляются", plan.include.none { it == "142.250.0.0/15" })
        // 1.10.33: в 192.178.0.0/15 — около 8 % видеосерверов YouTube, в 1.10.31 её не было.
        check("маршруты: видео YouTube — и сеть 192.178.0.0/15", "192.178.0.0/15" in yt.include)
        check("маршруты: сети видео YouTube = сети списка youtube",
            AllowLists.YOUTUBE_VIDEO_NETS.isNotEmpty() && AllowLists.YOUTUBE_VIDEO_NETS.all { it in yt.include })
        // Подсети к уже собранным маршрутам (с 1.10.33): маршруты прежних версий сетей Google не содержали.
        expect(
            "маршруты: недостающие подсети добавляются, имеющиеся — нет",
            SplitRoutes.withExtra("1.2.3.4/32, 142.250.0.0/15", listOf("142.250.0.0/15", "192.178.0.0/15", "2a00:1450::/32")),
            "1.2.3.4/32, 142.250.0.0/15, 192.178.0.0/15, 2a00:1450::/32"
        )
        expect(
            "маршруты: весь трафик — подсети не добавляются",
            SplitRoutes.withExtra("0.0.0.0/0, ::/0", AllowLists.YOUTUBE_VIDEO_NETS),
            "0.0.0.0/0, ::/0"
        )
        expect(
            "маршруты: весь IPv4 — добавляются только IPv6-сети",
            SplitRoutes.missing("0.0.0.0/0", listOf("192.178.0.0/15", "2a00:1450::/32")),
            listOf("2a00:1450::/32")
        )
        expect(
            "маршруты: сеть внутри более широкой не дублируется",
            SplitRoutes.missing("142.0.0.0/8, 10.0.0.0/8", listOf("142.250.0.0/15", "172.217.0.0/16")),
            listOf("172.217.0.0/16")
        )
        expect("маршруты: без маршрутов ничего не придумываем", SplitRoutes.withExtra("", AllowLists.YOUTUBE_VIDEO_NETS), "")
        expect(
            "маршруты: повтор в списке добавок — один раз",
            SplitRoutes.missing("1.2.3.4/32", listOf("192.178.0.0/15", "192.178.0.0/15")),
            listOf("192.178.0.0/15")
        )
        val full = AllowListPlanner.plan(block, direct, maps, fullTunnel = true)
        expect("маршруты: «весь трафик» = два default-маршрута", full.allowedIps, "0.0.0.0/0, ::/0")
        check("маршруты: пустой кеш не рождает битый конфиг",
            AllowListPlanner.plan(block, direct, emptyMap()).allowedIps == "0.0.0.0/0, ::/0")

        // --- SplitRoutes: общий лимит на число маршрутов
        val many = (1..1200).map { "h$it.example.com" }
        val capped = SplitRoutes.build(many, { listOf("203.0.113.7") })
        check("SplitRoutes: лимит маршрутов соблюдён",
            capped.prefixes.size <= SplitRoutes.MAX_PREFIXES, "получено ${capped.prefixes.size}")
        expect("SplitRoutes: fullTunnel короткое", SplitRoutes.build(many, { listOf("1.1.1.1") }, fullTunnel = true).allowedIps,
            "0.0.0.0/0, ::/0")
        expect("SplitRoutes: парсинг обратно", SplitRoutes.prefixesOf("0.0.0.0/0, ::/0").size, 2)

        // --- проверки «по обе стороны»: blocked-сторона и «не трогать»
        val checks = AllowLists.checksFor(AllowList("t1", "Тест1", ListSide.BLOCK, "x"), parsed, limit = 2)
        expect("списки: проверки построены", checks.size, 2)
        val directChecks = AllowLists.checksFor(AllowList("t2", "Тест2", ListSide.DIRECT, "y"),
            AllowLists.Parsed(listOf("alfabank.ru"), emptyList()), limit = 1)
        check("списки: «держать напрямую» помечено baselineExpected",
            directChecks.single().baselineExpected && !checks.first().baselineExpected)
        check("списки: статусы принимаем любые HTTP-ответы (403 — тоже «достучались»)",
            checks.first().expectStatus.last >= 400)

        // --- категории: обе стороны должны присутствовать и URL'ы должны быть пути из репозитория
        check("списки: есть BLOCK и DIRECT категории",
            AllowLists.bySide(ListSide.BLOCK).isNotEmpty() && AllowLists.bySide(ListSide.DIRECT).size >= 3)
        check("списки: путь собирется из RAW + относительного пути",
            AllowLists.url("Categories/01-youtube.lst") == "https://raw.githubusercontent.com/haritos90/allow-domains/main/Categories/01-youtube.lst")
        check("списки: telegram указан с подсетями (без них он не работает)",
            AllowLists.byId.getValue("telegram").hasSubnets)
        val fresh = AllowLists.freshnessOf(System.currentTimeMillis() - 3L * 3_600_000L)
        check("списки: свежесть по-человечески", fresh.contains("3 ч"), fresh)
    }

    // ------------------------------------------------ 1.10.31: второй выход и свои сайты

    private fun ipText(p: ByteArray, off: Int): String =
        (0 until 4).joinToString(".") { (p[off + it].toInt() and 0xFF).toString() }

    /** IPv4-пакет: заголовок 20 байт и [l4] после него; сумма заголовка посчитана. */
    private fun ip4(src: String, dst: String, proto: Int, l4: ByteArray): ByteArray {
        val p = ByteArray(20 + l4.size)
        p[0] = 0x45
        PacketMath.put16(p, 2, p.size)
        p[8] = 64
        p[9] = proto.toByte()
        System.arraycopy(PacketMath.addrOf(src)!!, 0, p, 12, 4)
        System.arraycopy(PacketMath.addrOf(dst)!!, 0, p, 16, 4)
        PacketMath.put16(p, 10, PacketMath.checksum(p, 0, 20))
        System.arraycopy(l4, 0, p, 20, l4.size)
        return p
    }

    /** TCP SYN с опцией MSS и верной суммой (IPv4). */
    private fun tcpSyn4(src: String, dst: String, mss: Int): ByteArray {
        val t = ByteArray(24)
        PacketMath.put16(t, 0, 40000)
        PacketMath.put16(t, 2, 443)
        t[12] = (6 shl 4).toByte()
        t[13] = 0x02
        PacketMath.put16(t, 14, 65535)
        t[20] = 2
        t[21] = 4
        PacketMath.put16(t, 22, mss)
        val p = ip4(src, dst, 6, t)
        val pseudo = PacketMath.sum(p, 12, 8) + 6L + 24L
        PacketMath.put16(p, 36, PacketMath.checksum(p, 20, 24, pseudo))
        return p
    }

    private fun udp4(src: String, sport: Int, dst: String, dport: Int, payload: ByteArray): ByteArray {
        val u = ByteArray(8 + payload.size)
        PacketMath.put16(u, 0, sport)
        PacketMath.put16(u, 2, dport)
        PacketMath.put16(u, 4, u.size)
        System.arraycopy(payload, 0, u, 8, payload.size)
        val p = ip4(src, dst, 17, u)
        val pseudo = PacketMath.sum(p, 12, 8) + 17L + u.size
        var c = PacketMath.checksum(p, 20, u.size, pseudo)
        if (c == 0) c = 0xFFFF
        PacketMath.put16(p, 26, c)
        return p
    }

    private fun ip4Ok(p: ByteArray): Boolean = PacketMath.fold(PacketMath.sum(p, 0, 20)) == 0xFFFF

    private fun l4v4Ok(p: ByteArray, proto: Int): Boolean {
        val len = PacketMath.u16(p, 2) - 20
        return PacketMath.fold(PacketMath.sum(p, 20, len, PacketMath.sum(p, 12, 8) + proto + len)) == 0xFFFF
    }

    /** IPv6-пакет с TCP SYN (20 байт TCP) и верной суммой. */
    private fun tcpSyn6(src: String, dst: String): ByteArray {
        val p = ByteArray(60)
        p[0] = 0x60
        PacketMath.put16(p, 4, 20)
        p[6] = 6
        p[7] = 64
        System.arraycopy(PacketMath.addrOf(src)!!, 0, p, 8, 16)
        System.arraycopy(PacketMath.addrOf(dst)!!, 0, p, 24, 16)
        PacketMath.put16(p, 40, 40001)
        PacketMath.put16(p, 42, 443)
        p[52] = (5 shl 4).toByte()
        p[53] = 0x02
        val pseudo = PacketMath.sum(p, 8, 32) + 20L + 6L
        PacketMath.put16(p, 56, PacketMath.checksum(p, 40, 20, pseudo))
        return p
    }

    private fun l4v6Ok(p: ByteArray, proto: Int): Boolean {
        val len = PacketMath.u16(p, 4)
        return PacketMath.fold(PacketMath.sum(p, 40, len, PacketMath.sum(p, 8, 32) + proto + len)) == 0xFFFF
    }

    private fun siteListChecks() {
        expect("выход: страна из «HEL · RU · адрес»", dev.warpscout.core.net.CfTrace.countryOf("HEL · RU · 185.1.2.3"), "RU")
        expect("выход: IPv6-адрес не путается со страной", dev.warpscout.core.net.CfTrace.countryOf("FRA · DE · 2a09:bac1::1"), "DE")
        expect("выход: нет страны — пусто", dev.warpscout.core.net.CfTrace.countryOf("не определён"), "")

        val sites = SiteList.parse(
            "https://chatgpt.com/c/1\n*.openai.com, 1.2.3.4\n10.1.2.3/24 # офис\nсайт.рф\n2a00:1450::1\nмусор!\nexample.com:8443"
        )
        expect("сайты: домены из ссылок, масок, кириллицы и «домен:порт»", sites.hosts,
            listOf("chatgpt.com", "openai.com", "xn--80aswg.xn--p1ai", "example.com"))
        expect("сайты: адрес, подсеть с обнулённым узлом, IPv6", sites.prefixes,
            listOf("1.2.3.4/32", "10.1.2.0/24", "2a00:1450::1/128"))
        expect("сайты: непонятное не принято, а названо", sites.bad, listOf("мусор!"))
        expect("сайты: www-вариант только у домена второго уровня",
            SiteList.withWww(listOf("chatgpt.com", "api.openai.com")), listOf("chatgpt.com", "www.chatgpt.com", "api.openai.com"))
        val routes = SiteList.cidrs(sites, mapOf(
            "chatgpt.com" to listOf("104.18.32.47", "2606:4700:0:0:0:0:6812:202f"),
            "openai.com" to emptyList()
        ))
        check("сайты: адреса доменов стали маршрутами",
            "104.18.32.47/32" in routes && "2606:4700::6812:202f/128" in routes && "10.1.2.0/24" in routes, routes.toString())
        expect("сайты: подсеть IPv6 нормализуется", SiteList.cidrOf("2001:db8::1/32"), "2001:db8::/32")
        expect("сайты: битая маска — не подсеть", SiteList.cidrOf("1.2.3.4/40"), null)

        val old = ServiceSettings.fromJson("{\"ver\":1,\"secondExitOn\":true}")
        check("настройки сервиса: старый снимок — второй выход через WARP", old?.secondViaWarp == true)
        val direct = ServiceSettings.fromJson(ServiceSettings(secondViaWarp = false).toJson())
        check("настройки сервиса: «напрямую» переживает запись и чтение", direct?.secondViaWarp == false)
    }

    private fun secondExitNat() {
        val conf4 = "[Interface]\nPrivateKey = AAAA\nAddress = 10.8.0.2/32\n[Peer]\nPublicKey = BBBB\nEndpoint = 203.0.113.5:51820\n"
        val nat = ExitNat.of("172.16.0.2", "2606:4700:110:8a36::1", conf4)
        val syn = tcpSyn4("172.16.0.2", "104.18.32.47", 1460)
        check("NAT: исходный пакет собран верно", ip4Ok(syn) && l4v4Ok(syn, 6))
        check("NAT: пакет во второй выход принят", nat.outbound(syn, syn.size))
        expect("NAT: отправитель — адрес из второго конфига", ipText(syn, 12), "10.8.0.2")
        check("NAT: суммы IPv4 и TCP верны после подмены", ip4Ok(syn) && l4v4Ok(syn, 6))
        nat.clampMss(syn, syn.size, 1160)
        expect("NAT: MSS урезан под туннель в туннеле", PacketMath.u16(syn, 42), 1160)
        check("NAT: сумма TCP верна после MSS", l4v4Ok(syn, 6))

        val back = tcpSyn4("104.18.32.47", "10.8.0.2", 1400)
        check("NAT: ответ принят", nat.inbound(back, back.size))
        expect("NAT: получатель ответа — снова адрес tun", ipText(back, 16), "172.16.0.2")
        check("NAT: суммы ответа верны", ip4Ok(back) && l4v4Ok(back, 6))

        val dgram = udp4("172.16.0.2", 5353, "104.18.32.47", 443, ByteArray(33) { (it * 7).toByte() })
        check("NAT: UDP (нечётная длина) — сумма верна после подмены", nat.outbound(dgram, dgram.size) && l4v4Ok(dgram, 17))

        val v6 = tcpSyn6("2606:4700:110:8a36::1", "2606:4700::6812:202f")
        check("NAT: IPv6 без IPv6 у второго сервера во второй выход не идёт", !nat.outbound(v6.copyOf(), v6.size))
        val rej = Icmp6Reject.build(v6, v6.size)
        check("отказ IPv6: «запрещено» возвращается отправителю",
            rej != null && rej[40] == 1.toByte() && rej[41] == 1.toByte() &&
                PacketMath.same(rej, 24, PacketMath.addrOf("2606:4700:110:8a36::1")!!))
        check("отказ IPv6: сумма ICMPv6 верна", rej != null && l4v6Ok(rej, 58))

        val conf6 = "[Interface]\nPrivateKey = AAAA\nAddress = fd00::2/128, 10.8.0.2/32\n[Peer]\nPublicKey = BBBB\n"
        val nat6 = ExitNat.of("172.16.0.2", "2606:4700:110:8a36::1", conf6)
        check("NAT: адреса берутся по виду, IPv6 может стоять первым", nat6.v4 && nat6.v6)
        val v6b = tcpSyn6("2606:4700:110:8a36::1", "2606:4700::6812:202f")
        check("NAT: IPv6 подменяется, сумма TCP верна",
            nat6.outbound(v6b, v6b.size) && PacketMath.same(v6b, 8, PacketMath.addrOf("fd00::2")!!) && l4v6Ok(v6b, 6))
        val same = ExitNat.of("172.16.0.2", null, "[Interface]\nAddress = 172.16.0.2/32\n")
        val untouched = tcpSyn4("172.16.0.2", "1.1.1.1", 1460)
        val copy = untouched.copyOf()
        check("NAT: второй конфиг WARP (тот же адрес) — пакет не меняется",
            same.outbound(untouched, untouched.size) && untouched.contentEquals(copy))
    }

    private fun secondExitInner() {
        val sent = ArrayList<ByteArray>()
        val ch = InnerUdpChannel(
            inject = { sent += it },
            localIp = PacketMath.addrOf("172.16.0.2")!!,
            remoteIp = PacketMath.addrOf("203.0.113.5")!!,
            remotePort = 51820,
            maxPacket = 1280,
            timeoutMs = 200L,
            random = java.util.Random(1),
        )
        ch.send(ByteArray(148) { it.toByte() })
        check("внутри WARP: датаграмма завёрнута в один IPv4/UDP-пакет",
            sent.size == 1 && sent[0].size == 176 && ip4Ok(sent[0]) && l4v4Ok(sent[0], 17))
        expect("внутри WARP: пакет идёт к своему серверу", ipText(sent[0], 16), "203.0.113.5")
        val reply = udp4("203.0.113.5", 51820, "172.16.0.2", ch.localPort, ByteArray(92) { 5 })
        check("внутри WARP: ответ сервера забран из основного туннеля", ch.accept(reply, reply.size))
        expect("внутри WARP: ответ отдан второму туннелю", ch.receive()?.size, 92)
        val alien = udp4("203.0.113.6", 51820, "172.16.0.2", ch.localPort, ByteArray(10))
        check("внутри WARP: чужой пакет остаётся приложениям", !ch.accept(alien, alien.size))

        sent.clear()
        val big = ByteArray(1400) { (it % 251).toByte() }
        ch.send(big)
        val ordered = sent.sortedBy { PacketMath.u16(it, 6) and 0x1FFF }
        val whole = java.io.ByteArrayOutputStream()
        ordered.forEach { whole.write(it, 20, it.size - 20) }
        val udp = whole.toByteArray()
        val pseudo = PacketMath.sum(PacketMath.addrOf("172.16.0.2")!!, 0, 4) +
            PacketMath.sum(PacketMath.addrOf("203.0.113.5")!!, 0, 4) + 17L + udp.size
        check("внутри WARP: большая датаграмма — фрагменты не больше MTU",
            sent.size == 2 && sent.all { it.size <= 1280 && ip4Ok(it) } &&
                (PacketMath.u16(ordered[0], 6) and 0x2000) != 0 && (PacketMath.u16(ordered[1], 6) and 0x2000) == 0)
        check("внутри WARP: из фрагментов собирается та же датаграмма",
            udp.size == 8 + big.size && udp.copyOfRange(8, udp.size).contentEquals(big) &&
                PacketMath.fold(PacketMath.sum(udp, 0, udp.size, pseudo)) == 0xFFFF)
        ch.close()
    }

    /**
     * Второй выход целиком, офлайн: data plane второго сервера ходит через [InnerUdpChannel]
     * («основной туннель» здесь — прозрачная труба до локального сервера), пакеты приложений
     * проходят подмену адреса туда и обратно. Сервер должен увидеть адрес из своего конфига,
     * а приложение — ответ на свой адрес.
     */
    /**
     * 1.10.31: Proton VPN Free с автопоиском — конфиг узнаётся, список gluetun разбирается, порядок
     * перебора предсказуемый, а смена сервера не закрывает очередь второго выхода.
     */
    /**
     * Проверка второго выхода (с 1.10.32): адрес из таблицы второго выхода, честный разбор ответа
     * (через WARP — не «Россия»), строка для настроек и прежний её формат, сырой HTTP.
     */
    private fun exitCheckChecks() {
        val router = ExitRouter.of(listOf("104.18.32.0/24", "2606:4700:4400::ac40:9bd1/128"))
        expect("выход: из адресов сайта берётся тот, что во втором выходе",
            ExitCheck.pickRouted(listOf("172.64.155.209", "104.18.32.47"), router), "104.18.32.47")
        expect("выход: IPv4 раньше IPv6",
            ExitCheck.pickRouted(listOf("2606:4700:4400::ac40:9bd1", "104.18.32.47"), router), "104.18.32.47")
        expect("выход: IPv6 — если IPv4 в таблице нет",
            ExitCheck.pickRouted(listOf("2606:4700:4400::ac40:9bd1", "172.64.155.209"), router), "2606:4700:4400::ac40:9bd1")
        check("выход: ни один адрес не в таблице — null",
            ExitCheck.pickRouted(listOf("172.64.155.209", "мусор", ""), router) == null)
        // 1.10.44-beta3: проверка пробует несколько адресов по очереди (журнал 24.11, 14:50 — первый не ответил).
        expect("выход: все адреса из таблицы, IPv4 первыми, без повторов",
            ExitCheck.routedAll(listOf("2606:4700:4400::ac40:9bd1", "104.18.32.47", "172.64.155.209", "104.18.32.7", "104.18.32.47"), router),
            listOf("104.18.32.47", "104.18.32.7", "2606:4700:4400::ac40:9bd1"))
        expect("выход: не больше трёх адресов",
            ExitCheck.routedAll((1..9).map { "104.18.32.$it" }, router).size, 3)
        check("выход: ни одного адреса в таблице — пусто",
            ExitCheck.routedAll(listOf("172.64.155.209", "мусор", ""), router).isEmpty())

        val nl = CfTrace.parse("fl=1\nh=chatgpt.com\nip=185.107.56.3\nloc=NL\ncolo=AMS\nwarp=off\n")
        val warp = CfTrace.parse("fl=1\nip=2a09:bac1::1\nloc=RU\ncolo=HEL\nwarp=on\n")
        val ru = CfTrace.parse("fl=1\nip=95.24.1.1\nloc=RU\ncolo=HEL\nwarp=off\n")
        val vNl = ExitCheck.verdict(nl, null, 1000L, 230)
        check("выход: ответ из NL мимо WARP — успех", vNl.code == "NL" && vNl.ok && vNl.detail == "185.107.56.3" && vNl.ms == 230, vNl.toString())
        val vW = ExitCheck.verdict(warp, null, 1000L, 90)
        check("выход: ответ через WARP — не «Россия», а «ушло через WARP»", vW.code == ExitCheck.VIA_WARP && !vW.ok, vW.toString())
        val vRu = ExitCheck.verdict(ru, null, 1000L, 50)
        check("выход: свой сервер в России — «RU», не успех", vRu.code == "RU" && !vRu.ok, vRu.toString())
        val vFail = ExitCheck.verdict(null, "SocketTimeoutException", 1000L)
        check("выход: нет ответа — причина словами", vFail.code == ExitCheck.FAIL && vFail.detail == "SocketTimeoutException", vFail.toString())
        expect("выход: ответ без страны — не успех", ExitCheck.verdict(CfTrace.parse("ip=1.2.3.4\ncolo=AMS"), null, 1L).code, ExitCheck.FAIL)

        expect("выход: строка для настроек — туда и обратно", ExitCheck.decode(vNl.encode()), vNl)
        expect("выход: прежняя строка без мс читается", ExitCheck.decode("DE|1.2.3.4|1700000000000"),
            ExitCheck.Result("DE", "1.2.3.4", 1700000000000L, -1))
        expect("выход: причина с «|» не ломает строку",
            ExitCheck.decode(ExitCheck.Result(ExitCheck.FAIL, "a|b", 5L).encode())?.detail, "a/b")
        check("выход: пустая или битая строка — проверки не было",
            ExitCheck.decode("") == null && ExitCheck.decode("NL|x") == null && ExitCheck.decode("NL|x|не-время") == null)

        val plain = ExitCheck.parseHttp("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nip=1.2.3.4\nloc=NL\nwarp=off\n".toByteArray())
        check("выход: HTTP-ответ разобран", plain.code == 200 && CfTrace.parse(plain.body)?.loc == "NL", plain.toString())
        val body = "ip=1.2.3.4\nloc=DE\nwarp=off\n"
        val chunked = ExitCheck.parseHttp(
            ("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" +
                Integer.toHexString(11) + "\r\n" + body.substring(0, 11) + "\r\n" +
                Integer.toHexString(body.length - 11) + "\r\n" + body.substring(11) + "\r\n0\r\n\r\n").toByteArray()
        )
        check("выход: ответ по частям (chunked) склеен", chunked.code == 200 && chunked.body == body, chunked.toString())
        expect("выход: код ошибки виден", ExitCheck.parseHttp("HTTP/1.1 403 Forbidden\r\n\r\nno".toByteArray()).code, 403)
        expect("выход: не HTTP — код -1", ExitCheck.parseHttp("<html>portal</html>".toByteArray()).code, -1)

        val seen = java.util.Collections.synchronizedList(mutableListOf<Int>())
        val resolved = AllowListPlanner.resolveAll(listOf("a.test", "b.test", "c.test"), resolve = { listOf("1.1.1.1") }, threads = 2) { n, total ->
            if (total == 3) seen += n
        }
        check("DoH: ход «готово N из M» — по каждому домену", resolved.size == 3 && seen.sorted() == listOf(1, 2, 3), seen.toString())
    }

    private fun protonFreeChecks() {
        val key1 = "1fGFZtHU8r8qwdnron9E80NdvLw5WcUdhPgh7phzQnA="
        val key2 = "cFWV9L1uNf/u4Hiojt0u4G4E4I12WB65JRq7nkHl0ns="
        val conf = """
            [Interface]
            # Key for NL-FREE#1
            PrivateKey = ${"A".repeat(43)}=
            Address = 10.2.0.2/32
            DNS = 10.2.0.1

            [Peer]
            # NL-FREE#1
            PublicKey = $key1
            AllowedIPs = 0.0.0.0/0
            Endpoint = 195.242.214.66:51820
        """.trimIndent()
        check("Proton: конфиг узнан по адресу и DNS", ProtonFree.isProton(conf))
        check("Proton: конфиг WARP — не Proton",
            !ProtonFree.isProton("[Interface]\nAddress = 172.16.0.2/32\nDNS = 1.1.1.1\n[Peer]\nEndpoint = 162.159.192.1:2408"))
        val peer = ProtonFree.peerOf(conf)
        check("Proton: сервер из конфига прочитан", peer?.publicKey == key1 && peer.ip == "195.242.214.66" && peer.port == 51820,
            peer.toString())
        val json = """{"version":4,"servers":[
            {"vpn":"openvpn","country":"Netherlands","server_name":"NL-FREE#9","free":true,"ips":["1.1.1.1"]},
            {"vpn":"wireguard","country":"Netherlands","city":"Amsterdam","server_name":"NL-FREE#1","hostname":"node-nl-1.protonvpn.net","wgpubkey":"$key1","free":true,"ips":["195.242.214.66","2a0d::1"]},
            {"vpn":"wireguard","country":"United States","city":"NYC","server_name":"US-FREE#5","wgpubkey":"$key2","free":true,"ips":["2a0d::5","10.9.8.7"]},
            {"vpn":"wireguard","country":"Germany","server_name":"DE#3","wgpubkey":"$key2","ips":["9.9.9.9"]},
            {"vpn":"wireguard","country":"Japan","server_name":"JP-FREE#2","wgpubkey":"bad","free":true,"ips":["8.8.8.8"]}
        ]}"""
        val parsed = ProtonFree.parseGluetun(json)
        expect("Proton: из списка gluetun — только бесплатные WireGuard с ключом и IPv4", parsed.map { it.name }, listOf("NL-FREE#1", "US-FREE#5"))
        expect("Proton: берётся адрес IPv4, даже если IPv6 первым", parsed.getOrNull(1)?.ip, "10.9.8.7")
        expect("Proton: код страны из имени сервера", parsed.map { it.code }, listOf("NL", "US"))
        expect("Proton: кеш — запись и чтение без потерь", ProtonFree.parseCompact(ProtonFree.render(parsed)), parsed)
        val enc = ProtonFree.encode(parsed[0])
        val dec = ProtonFree.decode(enc)
        check("Proton: строка для сервиса — туда и обратно",
            dec != null && dec.name == "NL-FREE#1" && dec.ip == "195.242.214.66" && dec.port == 51820 && dec.publicKey == key1, enc)
        check("Proton: битая строка не принимается", ProtonFree.decode("x|1.2.3.4|99999|$key1") == null && ProtonFree.decode("кривая") == null)
        check("Proton: встроенный список на месте",
            ProtonFree.BUILTIN.size >= 50 && ProtonFree.BUILTIN.all { it.publicKey.length == 44 && it.ip.isNotBlank() },
            "серверов ${ProtonFree.BUILTIN.size}")
        val servers = listOf(
            ProtonFree.Server("US-FREE#1", "United States", "", "10.0.0.1", key1),
            ProtonFree.Server("NL-FREE#1", "Netherlands", "", "10.0.0.2", key1),
            ProtonFree.Server("NL-FREE#2", "Netherlands", "", "10.0.0.3", key2),
            ProtonFree.Server("JP-FREE#1", "Japan", "", "10.0.0.4", key2),
        )
        val any = ProtonFree.ordered(servers, prefer = "", lastGood = "", original = null, seed = 0)
        expect("Proton: «любая страна» — ближние первыми", any.map { it.code }, listOf("NL", "NL", "US", "JP"))
        val us = ProtonFree.ordered(servers, prefer = "US", lastGood = "NL-FREE#2", original = null, seed = 0)
        expect("Proton: выбранная страна первой, прежний сервер другой страны — не первым", us.first().name, "US-FREE#1")
        val last = ProtonFree.ordered(servers, prefer = "", lastGood = "JP-FREE#1", original = servers[2], seed = 0)
        // С 1.10.36: при «любой стране» ближний сервер из конфига — раньше дальнего работавшего.
        expect("Proton: ближний из конфига — первым, дальний работавший — следом", last.take(3).map { it.name },
            listOf("NL-FREE#2", "JP-FREE#1", "NL-FREE#1"))
        check("Proton: без повторов", last.size == servers.size)
        val rotated = ProtonFree.ordered(servers, prefer = "NL", lastGood = "", original = null, seed = 1)
        expect("Proton: внутри страны — по кругу от дня", rotated.first().name, "NL-FREE#2")

        // Смена сервера второго выхода: закрытие «вида» не закрывает очередь — диспетчер не вернёт
        // сайты в WARP, а следующий сервер читает ту же очередь.
        val lane = PacketQueueIn("второй")
        val first = lane.view()
        first.close()
        check("очередь: закрытый вид не закрывает очередь", !lane.isClosed())
        lane.offer(byteArrayOf(1, 2, 3))
        val buf = ByteArray(8)
        expect("очередь: следующий вид читает пакет", lane.view().read(buf, 0, buf.size), 3)
        expect("очередь: закрытый вид больше не читает", first.read(buf, 0, buf.size), -1)
        lane.close()
        expect("очередь: закрытая очередь — конец и для вида", lane.view().read(buf, 0, buf.size), -1)

        val settings = ServiceSettings(secondPeers = listOf(enc))
        expect("настройки сервиса: серверы второго выхода переживают JSON", ServiceSettings.fromJson(settings.toJson())?.secondPeers, listOf(enc))
        expect("настройки сервиса: старый снимок — серверов нет", ServiceSettings.fromJson("{}")?.secondPeers, emptyList<String>())
        expect("снимок: сервер второго выхода переживает JSON",
            TunnelStatus.fromJson(TunnelStatus(secondPeer = "NL-FREE#1").toJson())?.secondPeer, "NL-FREE#1")
    }

    private fun secondExitPipeline() {
        val clientPriv = ByteArray(32) { (it * 3 + 29).toByte() }
        val serverPriv = ByteArray(32) { (it * 5 + 31).toByte() }
        val server = LoopbackServer(serverPriv, answerData = { tcpSyn4("104.18.32.47", "10.8.0.2", 1400) }).start()
        val sock = java.net.DatagramSocket().apply {
            connect(java.net.InetSocketAddress("127.0.0.1", server.port))
            soTimeout = 200
        }
        val ch = InnerUdpChannel(
            inject = { ip ->
                val ihl = (ip[0].toInt() and 0x0F) * 4
                val payload = ip.copyOfRange(ihl + 8, ip.size)
                runCatching { sock.send(java.net.DatagramPacket(payload, payload.size)) }
            },
            localIp = PacketMath.addrOf("172.16.0.2")!!,
            remoteIp = PacketMath.addrOf("203.0.113.5")!!,
            remotePort = 51820,
            maxPacket = 1420,
            timeoutMs = 300L,
        )
        val stop = java.util.concurrent.atomic.AtomicBoolean(false)
        val pump = Thread {
            val buf = ByteArray(4096)
            while (!stop.get()) {
                val dp = java.net.DatagramPacket(buf, buf.size)
                try {
                    sock.receive(dp)
                } catch (e: java.net.SocketTimeoutException) {
                    continue
                } catch (e: Exception) {
                    break
                }
                val pkt = udp4("203.0.113.5", 51820, "172.16.0.2", ch.localPort, buf.copyOfRange(0, dp.length))
                ch.accept(pkt, pkt.size)
            }
        }.apply { isDaemon = true; start() }
        val tunIn = QueueInputStream()
        val tunOut = QueueOutputStream()
        val nat = ExitNat.of("172.16.0.2", null, "[Interface]\nAddress = 10.8.0.2/32\n")
        val config = WarpConfig(
            name = "второй выход",
            account = WarpAccount(Crypto.base64(clientPriv), Crypto.base64(Crypto.publicOf(serverPriv))),
            endpoint = Endpoint("203.0.113.5", 51820),
            junk = JunkLibrary.none(),
            persistentKeepalive = null
        )
        val log = StringBuilder()
        val plane = dev.warpscout.core.tunnel.DataPlane(
            ch,
            dev.warpscout.core.tunnel.NatPacketIn(tunIn, nat),
            dev.warpscout.core.tunnel.NatPacketOut(tunOut, nat),
            config,
            NetSettings(attempts = 3, timeoutMs = 1000)
        ) { line -> log.append(line).append("; ") }
        val thread = Thread { plane.run() }.apply { isDaemon = true; start() }
        try {
            tunIn.offer(tcpSyn4("172.16.0.2", "104.18.32.47", 1460))
            val seen = server.firstPacket(8000)
            check("второй выход целиком: рукопожатие через туннель в туннеле", plane.handshakeOk, log.toString())
            check("второй выход целиком: сервер видит адрес из своего конфига",
                seen != null && ipText(seen, 12) == "10.8.0.2" && ip4Ok(seen) && l4v4Ok(seen, 6),
                server.error ?: "payload=${seen?.size}")
            val back = tunOut.poll(3000L)
            check("второй выход целиком: ответ пришёл приложению на адрес tun",
                back != null && ipText(back, 16) == "172.16.0.2" && ip4Ok(back) && l4v4Ok(back, 6), "back=${back?.size}")
        } finally {
            plane.stop()
            stop.set(true)
            runCatching { thread.join(1500) }
            runCatching { sock.close() }
            runCatching { pump.join(1000) }
            server.stop()
        }
    }

    private fun secondExitAwg() {
        val conf = "[Interface]\nPrivateKey = x\nJc = 3\nJmin = 10\nJmax = 50\nS1 = 15\nS2 = 20\n" +
            "H1 = 1234567\nH2 = 2345678\nH3 = 3456789\nH4 = 4567890\n"
        val params = AwgChannel.paramsOf(conf)
        check("AmneziaWG: параметры разобраны", params != null && params.s1 == 15 && params.h4 == 4567890L..4567890L)
        check("AmneziaWG: обычный WireGuard — без обёртки", AwgChannel.paramsOf("[Interface]\nPrivateKey = x\n") == null)
        expect("AmneziaWG 2: диапазон типов", AwgChannel.paramsOf("[Interface]\nH1 = 100-200\n")?.h1, 100L..200L)
        if (params == null) return

        val out = ArrayList<ByteArray>()
        val inbox = java.util.ArrayDeque<ByteArray>()
        val rec = object : dev.warpscout.core.tunnel.UdpChannel {
            override fun send(packet: ByteArray) {
                out += packet.copyOf()
            }
            override fun receive(): ByteArray? = inbox.pollFirst()
            override fun close() = Unit
        }
        val cPriv = ByteArray(32) { (it * 3 + 7).toByte() }
        val sPriv = ByteArray(32) { (it * 5 + 11).toByte() }
        val cPub = Crypto.publicOf(cPriv)
        val sPub = Crypto.publicOf(sPriv)
        val awg = AwgChannel(rec, params, cPub, sPub, java.util.Random(7))
        val init = Wg.buildInitiation(cPriv, cPub, sPub, 0x1234)
        awg.send(init.packet)
        val sentInit = out.last()
        check("AmneziaWG: Jc пакетов шума перед инициацией", out.size == 4 && out.dropLast(1).all { it.size in 10..50 })
        check("AmneziaWG: S1 случайных байт и тип H1", sentInit.size == 15 + 148 && Crypto.readLe32(sentInit, 15) == 1234567)
        val msg = sentInit.copyOfRange(15, sentInit.size)
        val mac1 = Blake2s.mac(Blake2s.hash("mac1----".toByteArray() + sPub), msg.copyOfRange(0, 116))
        check("AmneziaWG: mac1 посчитан по своему типу — сервер его примет", mac1.contentEquals(msg.copyOfRange(116, 132)))

        val std = msg.copyOf().also { Crypto.le32(1).copyInto(it, 0) }
        val (resp, _) = WgResponder.respondWithSession(std, sPriv)
        val wrapped = resp.copyOf().also {
            Crypto.le32(2345678).copyInto(it, 0)
            Wg.remac1(it, cPub)
        }
        inbox.add(ByteArray(20) { 9 } + wrapped)
        val got = awg.receive()
        check("AmneziaWG: ответ распознан и приведён к WireGuard", got != null && got.size == 92 && Crypto.readLe32(got, 0) == 2)
        val res = got?.let { Wg.consumeResponse(it, init, sPub) }
        check("AmneziaWG: рукопожатие сходится", res?.kind == Wg.ResponseKind.HANDSHAKE_RESPONSE, res?.kind.toString())

        out.clear()
        awg.send(ByteArray(48).also { Crypto.le32(4).copyInto(it, 0) })
        check("AmneziaWG: данные уходят с типом H4", out.size == 1 && Crypto.readLe32(out[0], 0) == 4567890)
        inbox.add(ByteArray(48).also { Crypto.le32(4567890).copyInto(it, 0) })
        check("AmneziaWG: входящие данные приведены к типу 4", awg.receive()?.let { Crypto.readLe32(it, 0) } == 4)
    }

    /**
     * AmneziaWG 3 (AmneziaVPN 5.1+) во втором выходе: подписи I1–I5, защита заголовков ChaCha20 и
     * «хвосты» (с 1.10.49-beta1). «Сервер» здесь разбирает пакеты так же, как amneziawg-go
     * (DeterminePacketTypeAndPadding в device/receive.go): nonce — первые 12 байт пакета, тип
     * открывается первыми 4 байтами потока ChaCha20, остальное сообщение — следующими.
     */
    private fun amneziaV3() {
        // RFC 8439, приложение A.1, вектор 1: нулевые ключ и nonce, счётчик 0.
        val ks = ByteArray(16)
        Crypto.chacha20Xor(ByteArray(32), ByteArray(12), ks, 0, 16)
        expect("ChaCha20: вектор RFC 8439 (A.1 #1)", Crypto.hex(ks), "76b8e0ada0f13d90405d6ae55386bd28")

        val obf = dev.warpscout.core.tunnel.AwgObf
        val built = obf.parse("<r 2><b 0x8580><t><rc 3><rd 2><dz 2><d>")?.build(java.util.Random(1), nowSec = 0x01020304L)
        check("подписи I1–I5: длина как у amneziawg-go", built?.size == 2 + 2 + 4 + 3 + 2 + 2, "${built?.size}")
        check(
            "подписи I1–I5: байты, время big-endian, буквы, цифры, нули",
            built != null && built[2] == 0x85.toByte() && built[3] == 0x80.toByte() &&
                built.copyOfRange(4, 8).contentEquals(byteArrayOf(1, 2, 3, 4)) &&
                built.copyOfRange(8, 11).all { (it.toInt() and 0xff).toChar().isLetter() } &&
                built.copyOfRange(11, 13).all { (it.toInt() and 0xff).toChar().isDigit() } &&
                built[13] == 0.toByte() && built[14] == 0.toByte()
        )
        check(
            "подписи I1–I5: неизвестный тег и нечётный hex — ошибка, как у amneziawg-go",
            runCatching { obf.parse("<x 1>") }.isFailure && runCatching { obf.parse("<b 0x123>") }.isFailure
        )
        check("подписи I1–I5: без тегов — пакета нет", obf.parse("просто текст") == null)

        val hpk = ByteArray(32) { (it * 7 + 1).toByte() }
        val conf = "[Interface]\nPrivateKey = x\nJc = 4\nJmin = 10\nJmax = 50\nS1 = 12\nS2 = 12\nS3 = 12\nS4 = 12\n" +
            "H1 = 1\nH2 = 2\nH3 = 3\nH4 = 4\nI1 = <r 2><b 0x858000010001>\nHeaderProtectionKey = ${Crypto.base64(hpk)}\n" +
            "ContentPaddingAddition = 10-100\nRekeyAfterTime = 100-120\nRandomTrailers = on\nDisableCookies = on\n"
        val p = AwgChannel.paramsOf(conf)
        check(
            "AmneziaWG 3: параметры AmneziaVPN 5.1 разобраны",
            p != null && p.version == "3" && p.headerKey?.contentEquals(hpk) == true && p.randomTrailers &&
                p.ipackets.size == 1 && "ContentPaddingAddition" in p.notApplied && p.problems.isEmpty(),
            p?.describe().orEmpty()
        )
        if (p == null) return

        val out = ArrayList<ByteArray>()
        val inbox = java.util.ArrayDeque<ByteArray>()
        val rec = object : dev.warpscout.core.tunnel.UdpChannel {
            override fun send(packet: ByteArray) {
                out += packet.copyOf()
            }
            override fun receive(): ByteArray? = inbox.pollFirst()
            override fun close() = Unit
        }
        val cPriv = ByteArray(32) { (it * 3 + 7).toByte() }
        val sPriv = ByteArray(32) { (it * 5 + 11).toByte() }
        val cPub = Crypto.publicOf(cPriv)
        val sPub = Crypto.publicOf(sPriv)
        val awg = AwgChannel(rec, p, cPub, sPub, java.util.Random(11))

        fun serverOpen(d: ByteArray, pad: Int, len: Int): ByteArray {
            val msg = d.copyOfRange(pad, pad + len)
            Crypto.chacha20Xor(hpk, d.copyOfRange(0, 12), msg, 0, len)
            return msg
        }

        val init = Wg.buildInitiation(cPriv, cPub, sPub, 0x4321)
        awg.send(init.packet)
        val sentInit = out.last()
        check(
            "AmneziaWG 3: подпись I1 и Jc пакетов шума перед инициацией",
            out.size == 1 + 4 + 1 && out[0].size == 2 + 6 && out[0][2] == 0x85.toByte() &&
                out.subList(1, 5).all { it.size in 10..50 },
            "пакетов ${out.size}"
        )
        check(
            "AmneziaWG 3: инициация — 12 случайных байт, сообщение и хвост в пределах окна",
            sentInit.size in (12 + 148)..AwgChannel.DEFAULT_UDP_WINDOW, "${sentInit.size}"
        )
        val openedInit = serverOpen(sentInit, 12, 148)
        val mac1 = Blake2s.mac(Blake2s.hash("mac1----".toByteArray() + sPub), openedInit.copyOfRange(0, 116))
        check(
            "AmneziaWG 3: сервер (как amneziawg-go) разбирает инициацию — тип H1, mac1 сходится",
            Crypto.readLe32(openedInit, 0) == 1 && mac1.contentEquals(openedInit.copyOfRange(116, 132))
        )
        check("AmneziaWG 3: заголовок в сети закрыт", !sentInit.copyOfRange(12, 16).contentEquals(byteArrayOf(1, 0, 0, 0)))

        val std = openedInit.copyOf().also { Crypto.le32(1).copyInto(it, 0) }
        val (resp, _) = WgResponder.respondWithSession(std, sPriv)
        // Ответ сервера: 12 случайных байт, сообщение с типом H2 (mac1 по нему), всё под XOR, хвост.
        val padR = ByteArray(12) { (40 + it).toByte() }
        val msgR = resp.copyOf().also {
            Crypto.le32(2).copyInto(it, 0)
            Wg.remac1(it, cPub)
        }
        Crypto.chacha20Xor(hpk, padR, msgR, 0, msgR.size)
        inbox.add(padR + msgR + ByteArray(37) { 7 })
        val res = awg.receive()?.let { Wg.consumeResponse(it, init, sPub) }
        check(
            "AmneziaWG 3: ответ сервера с хвостом распознан, рукопожатие сходится",
            res?.kind == Wg.ResponseKind.HANDSHAKE_RESPONSE, res?.kind.toString()
        )

        out.clear()
        val data = ByteArray(64) { it.toByte() }.also {
            Crypto.le32(4).copyInto(it, 0)
            Crypto.le32(0x0a0b0c0d).copyInto(it, 4)
        }
        awg.send(data)
        val sentData = out.singleOrNull()
        val hdr = sentData?.let { serverOpen(it, 12, 16) }
        check(
            "AmneziaWG 3: данные — сервер открывает 16 байт заголовка: тип H4, индекс на месте",
            sentData != null && sentData.size == 12 + 64 && hdr != null && Crypto.readLe32(hdr, 0) == 4 &&
                Crypto.readLe32(hdr, 4) == 0x0a0b0c0d && sentData.copyOfRange(28, 76).contentEquals(data.copyOfRange(16, 64))
        )
        val padD = ByteArray(12) { (90 + it).toByte() }
        val fromServer = ByteArray(64) { (it * 3).toByte() }.also {
            Crypto.le32(4).copyInto(it, 0)
            Crypto.le32(0x11223344).copyInto(it, 4)
        }
        val wire = fromServer.copyOf().also { Crypto.chacha20Xor(hpk, padD, it, 0, 16) }
        inbox.add(padD + wire)
        check("AmneziaWG 3: входящие данные открыты и приведены к типу 4", awg.receive()?.contentEquals(fromServer) == true)
    }

    /** Ключи AmneziaVPN «vpn://…» во втором выходе (с 1.10.49-beta1). */
    private fun amneziaKeys() {
        val J = dev.warpscout.core.json.JsonVal
        fun key(json: String): String {
            val raw = json.toByteArray()
            val deflater = java.util.zip.Deflater(8)
            deflater.setInput(raw)
            deflater.finish()
            val buf = ByteArray(raw.size + 256)
            val n = deflater.deflate(buf)
            deflater.end()
            val head = byteArrayOf((raw.size ushr 24).toByte(), (raw.size ushr 16).toByte(), (raw.size ushr 8).toByte(), raw.size.toByte())
            return "vpn://" + java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(head + buf.copyOf(n))
        }
        fun k(n: Int) = Crypto.base64(ByteArray(32) { n.toByte() })
        val native = "[Interface]\nAddress = 10.8.1.2/32\nDNS = \$PRIMARY_DNS, \$SECONDARY_DNS\nPrivateKey = ${k(1)}\n" +
            "Jc = 4\nJmin = 10\nJmax = 50\nS1 = 12\nS2 = 12\nS3 = 12\nS4 = 12\nH1 = 1\nH2 = 2\nH3 = 3\nH4 = 4\n" +
            "I1 = <r 2><b 0x8580>\nHeaderProtectionKey = ${k(2)}\nRandomTrailers = on\n\n[Peer]\nPublicKey = ${k(3)}\n" +
            "PresharedKey = ${k(4)}\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = 203.0.113.7:55424\nPersistentKeepalive = 25-35\n"
        val last = J.obj("config" to J.str(native), "hostName" to J.str("203.0.113.7"), "port" to J.num(55424)).render()
        val awgKey = key(
            J.obj(
                "containers" to J.arr(listOf(J.obj(
                    "container" to J.str("amnezia-awg"),
                    "awg" to J.obj("last_config" to J.str(last), "protocol_version" to J.str("3.1"), "port" to J.str("55424")),
                ))),
                "defaultContainer" to J.str("amnezia-awg"),
                "dns1" to J.str("9.9.9.9"), "dns2" to J.str("149.112.112.112"),
                "description" to J.str("Мой сервер"),
            ).render()
        )
        val r1 = dev.warpscout.core.config.AmneziaKey.decode(awgKey)
        check(
            "ключ vpn:// (AmneziaVPN): AmneziaWG — конфиг извлечён",
            r1 is dev.warpscout.core.config.AmneziaKey.Result.Conf && r1.protocol == "AmneziaWG 3.1" &&
                r1.name == "Мой сервер" && r1.text.contains("DNS = 9.9.9.9, 149.112.112.112") && r1.text.contains("HeaderProtectionKey"),
            r1.toString().take(160)
        )
        val text1 = (r1 as? dev.warpscout.core.config.AmneziaKey.Result.Conf)?.text.orEmpty()
        val cfg1 = runCatching { WgConf.toWarpConfig("k1", text1) }.getOrNull()
        check(
            "ключ vpn://: сервер, keepalive «25-35» → 25, параметры AmneziaWG 3",
            cfg1 != null && cfg1.endpoint.render() == "203.0.113.7:55424" && cfg1.persistentKeepalive == 25 &&
                AwgChannel.paramsOf(text1)?.version == "3",
            "${cfg1?.endpoint?.render()} ka=${cfg1?.persistentKeepalive}"
        )

        val last2 = J.obj(
            "client_ip" to J.str("10.8.1.3"), "client_priv_key" to J.str(k(5)), "server_pub_key" to J.str(k(6)),
            "hostName" to J.str("198.51.100.9"), "port" to J.num(51820), "Jc" to J.str("3"), "S1" to J.str("20"),
            "H1" to J.str("100-200"), "persistent_keep_alive" to J.str("25"),
        ).render()
        val r2 = dev.warpscout.core.config.AmneziaKey.decode(key(J.obj(
            "containers" to J.arr(listOf(J.obj("container" to J.str("amnezia-awg"), "awg" to J.obj("last_config" to J.str(last2))))),
            "defaultContainer" to J.str("amnezia-awg"),
        ).render()))
        val text2 = (r2 as? dev.warpscout.core.config.AmneziaKey.Result.Conf)?.text.orEmpty()
        val cfg2 = runCatching { WgConf.toWarpConfig("k2", text2) }.getOrNull()
        check(
            "ключ vpn:// без готового .conf — конфиг собран из полей",
            cfg2 != null && cfg2.endpoint.render() == "198.51.100.9:51820" && text2.contains("Address = 10.8.1.3/32") &&
                AwgChannel.paramsOf(text2)?.h1 == 100L..200L,
            r2.toString().take(200)
        )

        val premium = dev.warpscout.core.config.AmneziaKey.decode(key(J.obj("auth_data" to J.obj("api_key" to J.str("x")), "api_config" to J.obj()).render()))
        check(
            "ключ vpn:// Amnezia Premium — объяснение: конфига в нём нет",
            premium is dev.warpscout.core.config.AmneziaKey.Result.Unsupported && premium.reason.contains("Premium")
        )
        val xray = dev.warpscout.core.config.AmneziaKey.decode(key(J.obj(
            "containers" to J.arr(listOf(J.obj("container" to J.str("amnezia-xray"), "xray" to J.obj("last_config" to J.str("{}"))))),
            "defaultContainer" to J.str("amnezia-xray"),
        ).render()))
        check(
            "ключ vpn:// с XRay — объяснение: нужен AmneziaWG или WireGuard",
            xray is dev.warpscout.core.config.AmneziaKey.Result.Unsupported && xray.reason.contains("XRay")
        )
        check(
            "ключ vpn:// битый — отказ без падения",
            dev.warpscout.core.config.AmneziaKey.decode("vpn://@@@") is dev.warpscout.core.config.AmneziaKey.Result.Unsupported &&
                dev.warpscout.core.config.AmneziaKey.decode("vpn://AAAA") is dev.warpscout.core.config.AmneziaKey.Result.Unsupported
        )
        check(
            "ключ vpn:// узнаётся по началу",
            dev.warpscout.core.config.AmneziaKey.looksLike("  vpn://abc") && !dev.warpscout.core.config.AmneziaKey.looksLike("[Interface]")
        )
    }

    private fun confTargets() {
        val acc = dev.warpscout.core.model.WarpAccount(
            privateB64 = "yHpLW0aFVZ0aGnJQpMhCqQYbKxwJmZ2eSbUvEjNnQ0=",
            peerPublicB64 = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
            ipv4 = "172.16.0.2", ipv6 = "2606:4700:110:8d5e:0:0:0:2", source = "test"
        )
        val cfg = WarpConfig(
            name = "test", account = acc, endpoint = Endpoint("188.114.96.3", 4500),
            junk = JunkLibrary.tlsFixed(),
            allowedIps = "0.0.0.0/0, ::/0", dns = listOf("1.1.1.1"), mtu = 1280, persistentKeepalive = 25
        )
        val amnezia = WgConf.render(cfg, ConfTarget.AMNEZIA)
        val stock = WgConf.render(cfg, ConfTarget.WIREGUARD)
        check("конфиг: AmneziaWG содержит AWG-ключи", amnezia.contains("Jc") || amnezia.contains("I1"), amnezia.take(80))
        check("конфиг: голый WG не содержит AWG-ключей",
            stock.lines().none { it.startsWith("Jc") || it.startsWith("Jmin") || it.startsWith("I1") || it.startsWith("H1") })
        check("конфиг: голый WG объясняет, что вырезано", stock.contains("стоковый"), stock.take(200))
        check("конфиг: общие обязательные поля на месте в обоих",
            listOf("PrivateKey", "Address", "PublicKey", "AllowedIPs", "Endpoint").all {
                amnezia.contains(it) && stock.contains(it)
            })
        val clash = WgConf.render(cfg, ConfTarget.CLASH)
        check("конфиг: Clash YAML — yaml, а не conf",
            clash.startsWith("proxies:") && clash.contains("amnezia-wg-option") && !clash.contains("[Interface]"))
        val routes = WgConf.render(cfg, ConfTarget.ROUTES)
        check("конфиг: режим «только маршруты» не содержит ключей",
            !routes.contains("PrivateKey") && routes.contains("AllowedIPs =") && routes.contains("0.0.0.0/0"))
        expect("конфиг: расширение по цели", ConfigExport.filename(cfg, ConfTarget.CLASH).substringAfterLast('.'), "yaml")
        expect("конфиг: расширение AmneziaWG", ConfigExport.filename(cfg, ConfTarget.AMNEZIA).substringAfterLast('.'), "conf")

        // ---- второй выход: таблица «адрес → выход» и разбор IP-пакета ----
        val router = ExitRouter.of(
            ExitRouter.parse("31.13.0.0/16, 5.6.7.8/32, 2a00:1450:4001:800::/128, мусор, 1.2.3.4/33")
        )
        fun route(ip: String) = router.route(ExitRouter.ipBytes(ip)!!)
        expect("router: во второй выход по /16", route("31.13.9.9"), 1)
        expect("router: тот же диапазон — граница", route("31.13.255.255"), 1)
        expect("router: вне диапазона", route("31.14.0.1"), 0)
        expect("router: точный /32", route("5.6.7.8"), 1)
        expect("router: соседний адрес", route("5.6.7.9"), 0)
        expect("router: IPv6 /128", route("2a00:1450:4001:800::"), 1)
        expect("router: IPv6 другой", route("2a00:1450:4001:801::"), 0)
        expect("router: битый CIDR не ломает таблицу", router.size, 3)

        val v4Packet = ByteArray(20).also {
            it[0] = 0x45
            it[9] = 6
            it[16] = 31; it[17] = 13; it[18] = 9; it[19] = 9
        }
        expect("пакет: адрес назначения IPv4", ExitRouter.ipBytes("31.13.9.9")!!.toList(), IpPacket.dst(v4Packet)!!.toList())
        expect("пакет: протокол TCP", IpPacket.protocol(v4Packet), 6)
        expect("пакет: не IP", IpPacket.dst(ByteArray(4)), null)
        check("конфиг: имя файла различает цели",
            ConfigExport.filename(cfg, ConfTarget.AMNEZIA) != ConfigExport.filename(cfg, ConfTarget.WIREGUARD))
    }
}


/**
 * Мини-сервер WireGuard «на другой стороне» — ровно обратные операции из спецификации.
 * Нужен только чтобы проверить нашего же клиента; в проде не используется.
 */
object WgResponder {

    fun respond(initiation: ByteArray, serverPrivate: ByteArray, receiverIndex: Int? = null): ByteArray =
        respondWithSession(initiation, serverPrivate, receiverIndex).first

    /**
     * Ответ + ключи сессии сервера (receiving = out1, sending = out2 — зеркально инициатору).
     *
     * [senderIndex] — наш адрес, на который клиент шлёт transport-пакеты. Настоящий WireGuard
     * выдаёт новый индекс на каждое рукопожатие и держит несколько сессий одновременно; тестам
     * это тоже нужно, иначе параллельные инициации (повтор через 400 мс) путают сессии.
     */
    fun respondWithSession(
        initiation: ByteArray,
        serverPrivate: ByteArray,
        receiverIndex: Int? = null,
        senderIndex: Int = 0x5a5a5a5a
    ): Pair<ByteArray, dev.warpscout.core.wg.Wg.Session> {
        val serverPublic = Crypto.publicOf(serverPrivate)
        var ck = Blake2s.hash("Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s".toByteArray())
        var h = Blake2s.hash(ck + "WireGuard v1 zx2c4 Jason@zx2c4.com".toByteArray())
        h = Blake2s.hash(h + serverPublic)

        val clientEph = initiation.copyOfRange(8, 40)
        h = Blake2s.hash(h + clientEph)

        var temp = Blake2s.hmac(ck, clientEph)
        ck = Blake2s.hmac(temp, byteArrayOf(0x01))
        temp = Blake2s.hmac(ck, Crypto.dh(serverPrivate, clientEph))
        ck = Blake2s.hmac(temp, byteArrayOf(0x01))
        var key = Blake2s.hmac(temp, ck + byteArrayOf(0x02))

        val encStatic = initiation.copyOfRange(40, 88)
        val clientStatic = Crypto.chacha20Poly1305Open(key, ByteArray(12), encStatic, h)
            ?: error("не расшифровался статический ключ клиента")
        h = Blake2s.hash(h + encStatic)

        temp = Blake2s.hmac(ck, Crypto.dh(serverPrivate, clientStatic))
        ck = Blake2s.hmac(temp, byteArrayOf(0x01))
        key = Blake2s.hmac(temp, ck + byteArrayOf(0x02))
        val encTs = initiation.copyOfRange(88, 116)
        val ts = Crypto.chacha20Poly1305Open(key, ByteArray(12), encTs, h) ?: error("не расшифровался timestamp")
        h = Blake2s.hash(h + encTs)
        require(ts.size == 12)

        // ---- собираем response: e, ee, se, psk
        val respEphPriv = ByteArray(32) { (it * 7 + 5).toByte() }.also { it[31] = 0 }
        val respEphPub = Crypto.publicOf(respEphPriv)
        val out = ByteArray(Wg.RESPONSE_LEN)
        Crypto.le32(Wg.TYPE_RESPONSE).copyInto(out, 0)
        Crypto.le32(senderIndex).copyInto(out, 4)
        Crypto.le32(receiverIndex ?: Crypto.readLe32(initiation, 4)).copyInto(out, 8)
        respEphPub.copyInto(out, 12)

        h = Blake2s.hash(h + respEphPub)
        temp = Blake2s.hmac(ck, respEphPub)
        ck = Blake2s.hmac(temp, byteArrayOf(0x01))
        temp = Blake2s.hmac(ck, Crypto.dh(respEphPriv, clientEph))
        ck = Blake2s.hmac(temp, byteArrayOf(0x01))
        temp = Blake2s.hmac(ck, Crypto.dh(respEphPriv, clientStatic))
        ck = Blake2s.hmac(temp, byteArrayOf(0x01))
        temp = Blake2s.hmac(ck, ByteArray(32))
        ck = Blake2s.hmac(temp, byteArrayOf(0x01))
        val temp2 = Blake2s.hmac(temp, ck + byteArrayOf(0x02))
        val k = Blake2s.hmac(temp, temp2 + byteArrayOf(0x03))
        h = Blake2s.hash(h + temp2)
        val encNothing = Crypto.chacha20Poly1305Seal(k, ByteArray(12), ByteArray(0), h)
        encNothing.copyInto(out, 44)
        h = Blake2s.hash(h + encNothing)

        val mac1Key = Blake2s.hash("mac1----".toByteArray() + clientStatic)
        Blake2s.mac(mac1Key, out.copyOfRange(0, 60)).copyInto(out, 60)
        // derive_keys(ck): out1 = HMAC(HMAC(ck, ""), 0x01), out2 = HMAC(temp, out1 || 0x02).
        // Инициатору — (sending=out1, receiving=out2), responder'у зеркально.
        val srvTemp = Blake2s.hmac(ck, ByteArray(0))
        val srvRecv = Blake2s.hmac(srvTemp, byteArrayOf(0x01))
        val srvSend = Blake2s.hmac(srvTemp, srvRecv + byteArrayOf(0x02))
        val serverSession = dev.warpscout.core.wg.Wg.Session(receiveKey = srvRecv, sendKey = srvSend)
        return out to serverSession
    }

    /**
     * Расшифрованная метка времени инициации (12 байт TAI64N) — то, что настоящий сервер сверяет с
     * прошлой принятой. null — инициация не для этого ключа сервера.
     */
    fun timestampOf(initiation: ByteArray, serverPrivate: ByteArray): ByteArray? = runCatching {
        val serverPublic = Crypto.publicOf(serverPrivate)
        var ck = Blake2s.hash("Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s".toByteArray())
        var h = Blake2s.hash(ck + "WireGuard v1 zx2c4 Jason@zx2c4.com".toByteArray())
        h = Blake2s.hash(h + serverPublic)
        val clientEph = initiation.copyOfRange(8, 40)
        h = Blake2s.hash(h + clientEph)
        var temp = Blake2s.hmac(ck, clientEph)
        ck = Blake2s.hmac(temp, byteArrayOf(0x01))
        temp = Blake2s.hmac(ck, Crypto.dh(serverPrivate, clientEph))
        ck = Blake2s.hmac(temp, byteArrayOf(0x01))
        var key = Blake2s.hmac(temp, ck + byteArrayOf(0x02))
        val encStatic = initiation.copyOfRange(40, 88)
        val clientStatic = Crypto.chacha20Poly1305Open(key, ByteArray(12), encStatic, h) ?: return@runCatching null
        h = Blake2s.hash(h + encStatic)
        temp = Blake2s.hmac(ck, Crypto.dh(serverPrivate, clientStatic))
        ck = Blake2s.hmac(temp, byteArrayOf(0x01))
        key = Blake2s.hmac(temp, ck + byteArrayOf(0x02))
        Crypto.chacha20Poly1305Open(key, ByteArray(12), initiation.copyOfRange(88, 116), h)
    }.getOrNull()

    /**
     * Cookie reply (64 байта) как его шлёт ядро: type=3, receiver_index, nonce(24),
     * encrypted_cookie = XChaCha20Poly1305(BLAKE2s("cookie--" || pub_сервера), nonce, cookie, AAD = mac1 инициации).
     */
    fun cookieReply(initiation: ByteArray, serverPrivate: ByteArray, cookie: ByteArray = ByteArray(16) { (it + 1).toByte() }): ByteArray {
        val out = ByteArray(dev.warpscout.core.wg.Wg.COOKIE_MSG_LEN)
        Crypto.le32(3).copyInto(out, 0)
        Crypto.readLe32(initiation, 4).let { Crypto.le32(it).copyInto(out, 4) }
        val nonce = ByteArray(24).also { java.security.SecureRandom().nextBytes(it) }
        nonce.copyInto(out, 8)
        val key = Blake2s.hash("cookie--".toByteArray() + Crypto.publicOf(serverPrivate))
        Crypto.xChaCha20Poly1305Seal(key, nonce, cookie, initiation.copyOfRange(116, 132))
            .copyInto(out, 32)
        return out
    }

    /** Проверка mac2 (cookie) в инициации — ровно как wg_cookie_check в ядре. */
    fun mac2Valid(initiation: ByteArray, cookie: ByteArray): Boolean {
        val expected = Blake2s.mac(cookie, initiation.copyOfRange(0, 132))
        return expected.contentEquals(initiation.copyOfRange(132, 148))
    }
}

/**
 * Ответ резолвера на «id.server» класса CHAOS: тот же вопрос плюс запись TXT с кодом площадки
 * [site] — имя в ответе сжато ссылкой на вопрос (0xC00C), как отвечают настоящие резолверы.
 * Обычные запросы — как [fakeDnsReply]. [pad] — нули после пакета, как дополнение WireGuard.
 */
private fun fakeSiteReply(query: ByteArray, site: String = "DME", pad: Int = 0): ByteArray? {
    if (query.size < 28 || ((query[0].toInt() ushr 4) and 0x0f) != 4 || (query[9].toInt() and 0xff) != 17) return null
    val ihl = (query[0].toInt() and 0x0f) * 4
    val dns = query.copyOfRange(ihl + 8, query.size)
    if (dns.size < 16) return null
    val qclass = ((dns[dns.size - 2].toInt() and 0xff) shl 8) or (dns[dns.size - 1].toInt() and 0xff)
    if (qclass != 3) return fakeDnsReply(query)
    val src = query.copyOfRange(12, 16)
    val dst = query.copyOfRange(16, 20)
    val sport = ((query[ihl].toInt() and 0xff) shl 8) or (query[ihl + 1].toInt() and 0xff)
    val out = java.io.ByteArrayOutputStream()
    out.write(dns, 0, 2)                         // номер запроса
    out.write(0x84); out.write(0x00)             // ответ, авторитетный
    out.write(0); out.write(1)                   // QDCOUNT
    out.write(0); out.write(1)                   // ANCOUNT
    repeat(4) { out.write(0) }
    out.write(dns, 12, dns.size - 12)            // вопрос как есть
    out.write(0xC0); out.write(0x0C)             // имя — ссылка на вопрос
    out.write(0); out.write(16)                  // TXT
    out.write(0); out.write(3)                   // CH
    repeat(4) { out.write(0) }                   // TTL
    val txt = site.toByteArray(Charsets.US_ASCII)
    out.write(0); out.write(txt.size + 1)
    out.write(txt.size)
    out.write(txt, 0, txt.size)
    val packet = dev.warpscout.core.tunnel.DataProbe.udp4(dst, 53, src, sport, out.toByteArray())
    return if (pad > 0) packet + ByteArray(pad) else packet
}

/**
 * Ответ «DNS-сервера» на пробу данных: те же адреса и порты наоборот, флаг «ответ». null — это не
 * DNS-запрос (тогда тестовый сервер пакет выбрасывает).
 */
private fun fakeDnsReply(query: ByteArray): ByteArray? {
    if (query.size < 28 || ((query[0].toInt() ushr 4) and 0x0f) != 4 || (query[9].toInt() and 0xff) != 17) return null
    val ihl = (query[0].toInt() and 0x0f) * 4
    if (query.size < ihl + 8 + 12) return null
    val src = query.copyOfRange(12, 16)
    val dst = query.copyOfRange(16, 20)
    val sport = ((query[ihl].toInt() and 0xff) shl 8) or (query[ihl + 1].toInt() and 0xff)
    val dport = ((query[ihl + 2].toInt() and 0xff) shl 8) or (query[ihl + 3].toInt() and 0xff)
    if (dport != 53) return null
    val dns = query.copyOfRange(ihl + 8, query.size)
    dns[2] = (dns[2].toInt() or 0x80).toByte()
    return dev.warpscout.core.tunnel.DataProbe.udp4(dst, 53, src, sport, dns)
}

/** Сравнение меток TAI64N побайтно без знака — ровно как memcmp в ядре Linux. */
private fun stampCompare(a: ByteArray, b: ByteArray): Int {
    for (i in 0 until minOf(a.size, b.size)) {
        val d = (a[i].toInt() and 0xff) - (b[i].toInt() and 0xff)
        if (d != 0) return d
    }
    return a.size - b.size
}

/**
 * Локальный «сервер» WireGuard для тестов: отвечает на инициации и эхом возвращает transport.
 *
 * Держит несколько сессий одновременно — у каждого рукопожатия свой sender_index, ровно как
 * в настоящем WireGuard. Это обязательно: клиент повторяет инициацию через 400 мс, и ответ на
 * повтор может прийти позже ответа на первую — сервер не должен путать сессии.
 */
private class LoopbackServer(
    private val serverPrivate: ByteArray,
    /** false — инициацию «теряем» (имитация сети, которая съела первый датаграмм). */
    private val answerInitiation: (Int) -> Boolean = { true },
    /**
     * Что вернуть на пакет данных: по умолчанию эхо; null — выбросить (сеть, которая пропускает
     * рукопожатие, но режет данные — «вверх есть, вниз 0»).
     */
    private val answerData: (ByteArray) -> ByteArray? = { it },
    /** Через сколько мс ответить на n-ю инициацию (медленная сеть, 1.10.40); 0 — сразу. */
    private val delayResponse: (Int) -> Long = { 0L }
) {
    private val socket = java.net.DatagramSocket()
    private val sessions = HashMap<Int, dev.warpscout.core.wg.Wg.Session>()
    private val clientIndex = HashMap<Int, Int>()
    private var serverIndex = 0x5a5a0000
    private val stopped = java.util.concurrent.atomic.AtomicBoolean(false)
    private val thread = Thread { loop() }

    val port: Int get() = socket.localPort
    val initiations = java.util.concurrent.atomic.AtomicInteger(0)

    /**
     * Инициации, чья метка времени не новее прошлой принятой: настоящий сервер на них молчит
     * (защита от повтора). Здесь отвечаем всё равно — чтобы не ломать остальные проверки, — но
     * считаем: проверка rekey требует ноль.
     */
    val staleStamps = java.util.concurrent.atomic.AtomicInteger(0)
    private var newestStamp: ByteArray? = null

    @Volatile
    var lastPayload: ByteArray? = null

    @Volatile
    var error: String? = null

    fun start(): LoopbackServer {
        thread.isDaemon = true
        thread.start()
        return this
    }

    fun stop() {
        stopped.set(true)
        runCatching { socket.close() }
        runCatching { thread.join(1500) }
    }

    /** Ждёт первый непустой пользовательский пакет (keepalive не считается). */
    fun firstPacket(timeoutMs: Long): ByteArray? {
        val until = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < until) {
            lastPayload?.let { return it }
            Thread.sleep(10)
        }
        return null
    }

    private fun loop() {
        try {
            socket.soTimeout = 300
            val buf = ByteArray(65536)
            while (!stopped.get()) {
                val p = java.net.DatagramPacket(buf, buf.size)
                try {
                    socket.receive(p)
                } catch (e: java.net.SocketTimeoutException) {
                    continue
                }
                val pkt = p.data.copyOfRange(0, p.length)
                when (if (pkt.size >= 4) Crypto.readLe32(pkt, 0) else -1) {
                    dev.warpscout.core.wg.Wg.TYPE_INITIATION -> {
                        if (pkt.size != dev.warpscout.core.wg.Wg.INITIATION_LEN) continue
                        val n = initiations.incrementAndGet()
                        if (!answerInitiation(n)) continue
                        val stamp = WgResponder.timestampOf(pkt, serverPrivate)
                        val newest = newestStamp
                        if (stamp != null) {
                            if (newest != null && stampCompare(stamp, newest) <= 0) staleStamps.incrementAndGet()
                            else newestStamp = stamp
                        }
                        val idx = serverIndex++
                        val (resp, srv) = WgResponder.respondWithSession(pkt, serverPrivate, senderIndex = idx)
                        sessions[idx] = srv
                        clientIndex[idx] = Crypto.readLe32(pkt, 4)
                        val delay = delayResponse(n)
                        if (delay > 0L) {
                            val to = p.socketAddress
                            Thread {
                                runCatching {
                                    Thread.sleep(delay)
                                    socket.send(java.net.DatagramPacket(resp, resp.size, to))
                                }
                            }.apply { isDaemon = true; start() }
                        } else {
                            socket.send(java.net.DatagramPacket(resp, resp.size, p.socketAddress))
                        }
                    }

                    dev.warpscout.core.wg.Wg.TYPE_TRANSPORT -> {
                        val idx = if (pkt.size >= 8) Crypto.readLe32(pkt, 4) else -1
                        val s = sessions[idx] ?: continue
                        val got = dev.warpscout.core.wg.Wg.openTransport(pkt, idx, s) ?: continue
                        sessions[idx] = got.second
                        if (got.first.isEmpty()) continue   // keepalive: подтверждаем и молчим
                        lastPayload = got.first
                        val client = clientIndex[idx] ?: continue
                        val answer = answerData(got.first) ?: continue
                        val (echo, next) = dev.warpscout.core.wg.Wg.buildTransport(client, got.second, answer)
                        sessions[idx] = next
                        socket.send(java.net.DatagramPacket(echo, echo.size, p.socketAddress))
                    }
                }
            }
        } catch (e: Exception) {
            if (!stopped.get()) error = "${e.javaClass.simpleName}: ${e.message}"
        } finally {
            runCatching { socket.close() }
        }
    }
}

/** Поток-очередь: чтобы тестировать туннель без настоящего tun-устройства. */
private class QueueInputStream : java.io.InputStream() {
    private val q = java.util.concurrent.LinkedBlockingQueue<ByteArray>()

    @Volatile
    private var closed = false

    private var current: ByteArray? = null
    private var position = 0

    fun offer(b: ByteArray) {
        q.put(b)
    }

    override fun read(): Int {
        val b = ByteArray(1)
        val n = read(b, 0, 1)
        return if (n <= 0) -1 else b[0].toInt() and 0xff
    }

    override fun read(b: ByteArray, off: Int, len: Int): Int {
        var cur = current
        if (cur == null) {
            cur = q.poll(2, java.util.concurrent.TimeUnit.SECONDS) ?: return if (closed) -1 else 0
            current = cur
            position = 0
        }
        val n = minOf(len, cur.size - position)
        System.arraycopy(cur, position, b, off, n)
        position += n
        if (position >= cur.size) current = null
        return n
    }

    override fun close() {
        closed = true
    }
}

/** Второй конец — собирает то, что туннель пишет в tun. */
private class QueueOutputStream : java.io.OutputStream() {
    private val q = java.util.concurrent.LinkedBlockingQueue<ByteArray>()

    @Volatile
    private var closed = false

    fun poll(timeoutMs: Long): ByteArray? = q.poll(timeoutMs, java.util.concurrent.TimeUnit.MILLISECONDS)

    override fun write(b: ByteArray, off: Int, len: Int) {
        if (closed) throw java.io.IOException("поток закрыт")
        q.put(b.copyOfRange(off, off + len))
    }

    override fun write(b: Int) = write(byteArrayOf(b.toByte()), 0, 1)

    override fun flush() {}

    override fun close() {
        closed = true
    }
}


/**
 * Фейковый HTTP-источник для офлайн-проверок: на любой запрос отдаёт 200 с телом `ok`.
 * Нужен, чтобы проверить SOCKS5-путь без выхода в сеть.
 */
private class FakeHttpOrigin {
    private val srv = java.net.ServerSocket(0, 32, java.net.InetAddress.getByName("127.0.0.1"))
    val port: Int get() = srv.localPort
    @Volatile private var stopped = false

    init {
        daemon {
            while (!stopped) {
                val c = runCatching { srv.accept() }.getOrNull() ?: break
                daemon {
                    runCatching {
                        c.getInputStream().drainUntilHeaders()
                        val body = "ok"
                        val resp = "HTTP/1.1 200 OK\r\nContent-Length: ${body.length}\r\n" +
                            "Connection: close\r\n\r\n$body"
                        c.getOutputStream().apply {
                            write(resp.toByteArray(Charsets.UTF_8))
                            flush()
                        }
                    }
                    runCatching { c.close() }
                }
            }
        }
    }

    fun close() {
        stopped = true
        runCatching { srv.close() }
    }
}

/**
 * Фейковый SOCKS5: проверяет наш клиент по RFC 1928 и релееит трафик.
 * Домен `blocked.invalid` подменяет на [originPort] — так воспроизводится «напрямую лежит, через
 * обход DPI открывается», не трогая настоящую сеть.
 */
private class FakeSocks5Relay(private val originPort: Int) {
    private val srv = java.net.ServerSocket(0, 32, java.net.InetAddress.getByName("127.0.0.1"))
    val port: Int get() = srv.localPort
    @Volatile var lastAtyp: Int? = null
    @Volatile var lastPort: Int? = null
    @Volatile private var stopped = false

    init {
        daemon {
            while (!stopped) {
                val c = runCatching { srv.accept() }.getOrNull() ?: break
                daemon { serve(c) }
            }
        }
    }

    private fun serve(c: java.net.Socket) {
        runCatching {
            val input = c.getInputStream()
            val out = c.getOutputStream()
            val ver = input.read()
            val nmethods = input.read()
            repeat(nmethods.coerceAtLeast(0)) { input.read() }
            if (ver != 5) {
                c.close()
                return
            }
            out.write(byteArrayOf(5, 0))
            out.flush()

            require(input.read() == 5)
            val cmd = input.read()
            input.read()  // RSV
            val atyp = input.read()
            lastAtyp = atyp
            val host = when (atyp) {
                1 -> ByteArray(4).also { readInto(input, it) }.joinToString(".") { (it.toInt() and 0xFF).toString() }
                3 -> ByteArray(input.read()).also { readInto(input, it) }.toString(Charsets.UTF_8)
                4 -> {
                    val raw = ByteArray(16).also { readInto(input, it) }
                    raw.joinToString(":") { (it.toInt() and 0xFF).toString(16) }
                }
                else -> {
                    c.close()
                    return
                }
            }
            val portValue = ((input.read() and 0xFF) shl 8) or (input.read() and 0xFF)
            lastPort = portValue

            val denied = cmd != 1
            val mappedHost = if (host == "blocked.invalid") "127.0.0.1" else host
            val mappedPort = if (host == "blocked.invalid") originPort else portValue
            val upstream = if (denied) null else runCatching { java.net.Socket(mappedHost, mappedPort) }.getOrNull()
            if (upstream == null) {
                // 0x04 «host unreachable»: прокси жив, цели нет — клиент должен отличать это от «прокси умер»
                out.write(byteArrayOf(5, 4, 0, 1, 0, 0, 0, 0, 0, 0))
                out.flush()
                runCatching { c.close() }
                return
            }
            val bound = upstream.localPort
            out.write(byteArrayOf(5, 0, 0, 1, 127, 0, 0, 1, (bound shr 8).toByte(), (bound and 0xFF).toByte()))
            out.flush()
            val fromUpstream = upstream.getInputStream()
            val fromClient = c.getInputStream()
            val toClient = c.getOutputStream()
            val toUpstream = upstream.getOutputStream()
            // Направление важно: если перепутать, «прокси» вернёт клиенту его собственный запрос.
            val t1 = daemon { runCatching { fromUpstream.copyTo(toClient) } }
            val t2 = daemon { runCatching { fromClient.copyTo(toUpstream) } }
            t1.join(4000); t2.join(4000)
            runCatching { upstream.close() }
        }
        runCatching { c.close() }
    }

    fun close() {
        stopped = true
        runCatching { srv.close() }
    }
}

/** Прокси «как у взрослых с аутентификацией»: мы должны честно сказать, что сами такое не умеем. */
private class FakeSocks5NeedsAuth {
    private val srv = java.net.ServerSocket(0, 8, java.net.InetAddress.getByName("127.0.0.1"))
    val port: Int get() = srv.localPort
    @Volatile private var stopped = false

    init {
        daemon {
            while (!stopped) {
                val c = runCatching { srv.accept() }.getOrNull() ?: break
                daemon {
                    runCatching {
                        // читаем вручную: readNBytes появился в Android только с API 32, а нам нужен 26+
                        val input = c.getInputStream()
                        input.read(); input.read(); input.read()
                        c.getOutputStream().write(byteArrayOf(5, 0xFF.toByte()))
                        c.getOutputStream().flush()
                        Thread.sleep(50)
                    }
                    runCatching { c.close() }
                }
            }
        }
    }

    fun close() {
        stopped = true
        runCatching { srv.close() }
    }
}

/**
 * Локальный HTTP-сервер для проверки Telegram (см. telegramFetchChecks): на каждое соединение —
 * разобрать запрос (путь, заголовки строчными) и отдать, что скажет [handler].
 */
private class HttpLoopback(
    private val handler: (path: String, headers: Map<String, String>, out: java.io.OutputStream) -> Unit
) {
    private val srv = java.net.ServerSocket(0, 16, java.net.InetAddress.getByName("127.0.0.1"))
    val port: Int get() = srv.localPort
    val connections = java.util.concurrent.atomic.AtomicInteger(0)

    @Volatile
    private var stopped = false

    init {
        daemon {
            while (!stopped) {
                val c = runCatching { srv.accept() }.getOrNull() ?: break
                connections.incrementAndGet()
                daemon {
                    runCatching {
                        c.soTimeout = 5_000
                        val input = c.getInputStream()
                        val head = StringBuilder()
                        while (head.length < 16 * 1024 && !head.endsWith("\r\n\r\n")) {
                            val b = input.read()
                            if (b < 0) break
                            head.append(b.toChar())
                        }
                        val lines = head.toString().split("\r\n")
                        val path = lines.firstOrNull().orEmpty().split(' ').getOrNull(1).orEmpty()
                        val headers = lines.drop(1).filter { ':' in it }.associate {
                            it.substringBefore(':').trim().lowercase() to it.substringAfter(':').trim()
                        }
                        val out = c.getOutputStream()
                        handler(path, headers, out)
                        out.flush()
                    }
                    runCatching { c.close() }
                }
            }
        }
    }

    fun close() {
        stopped = true
        runCatching { srv.close() }
    }
}

/** readFully есть у DataInputStream, а у InputStream его нет — и на Android его не дождёшься. */
private fun readInto(input: java.io.InputStream, buf: ByteArray) {
    var got = 0
    while (got < buf.size) {
        val n = input.read(buf, got, buf.size - got)
        if (n < 0) {
            if (got == 0) throw java.io.EOFException("прокси закрыл поток до конца адреса")
            throw java.io.EOFException("прокси оборвался на " + got + "/" + buf.size + " байтах")
        }
        got += n
    }
}

private fun daemon(block: () -> Unit): Thread = Thread { block() }.apply { isDaemon = true; start() }

private fun java.io.InputStream.drainUntilHeaders(limit: Int = 16 * 1024) {
    var read = 0
    var tail = ""
    while (read < limit) {
        val b = this.read()
        if (b < 0) return
        read++
        tail = (tail + b.toChar()).takeLast(4)
        if (tail.endsWith("\r\n\r\n")) return
    }
}
