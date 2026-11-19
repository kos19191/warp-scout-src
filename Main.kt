package dev.warpscout.cli

import dev.warpscout.core.config.WgConf
import dev.warpscout.core.crypto.Crypto
import dev.warpscout.core.junk.JunkLibrary
import dev.warpscout.core.keys.AccountStore
import dev.warpscout.core.keys.KeySource
import dev.warpscout.core.model.Endpoint
import dev.warpscout.core.model.JunkProfile
import dev.warpscout.core.model.WarpAccount
import dev.warpscout.core.model.WarpConfig
import dev.warpscout.core.net.EndpointPool
import dev.warpscout.core.net.EndpointSpec
import dev.warpscout.core.net.NetSettings
import dev.warpscout.core.net.PoolMode
import dev.warpscout.core.net.WgProber
import dev.warpscout.core.presets.Presets
import dev.warpscout.core.report.ConfigExport
import dev.warpscout.core.report.Report
import dev.warpscout.core.test.SelfCheck
import dev.warpscout.core.tune.ProgressSink
import dev.warpscout.core.tune.TuningSpec
import dev.warpscout.core.tune.AutoTuner
import java.io.File
import kotlin.system.exitProcess

/**
 * Десктопная версия ядра: те же сканер/скоринг/генератор, что и в приложении.
 * Полезна, чтобы прогнать большой перебор с ноутбука (там не жалко 5000 точек и 100 потоков)
 * и принести результат на телефон, либо просто проверить, что логика работает.
 *
 *   warp-scout selftest [--live] [--integration host:port]
 *   warp-scout tune [--endpoints file] [--max 200] [--attempts 3] [--out out] [--seed N] [--masque] [--json-only]
 *   warp-scout scan --endpoints my-endpoints.txt [--out out]
 *   warp-scout gen --priv <base64> --endpoint 1.2.3.4:943 --junk quic --sni ivi.ru [--out conf]
 *   warp-scout parse file.conf
 */
fun main(args: Array<String>) {
    val cmd = args.firstOrNull() ?: "help"
    val opts = parseOpts(args.drop(1))
    try {
        when (cmd) {
            "selftest" -> exitProcess(SelfCheck(live = opts.containsKey("live"), integration = opts["integration"]).run())
            "tune" -> tune(opts)
            "scan" -> scan(opts)
            "gen" -> gen(opts)
            "parse" -> parse(opts)
            else -> help()
        }
    } catch (e: Exception) {
        System.err.println("ошибка: ${e.javaClass.simpleName}: ${e.message}")
        if (System.getenv("WARP_SCOUT_DEBUG") != null) e.printStackTrace()
        exitProcess(2)
    }
}

private fun parseOpts(args: List<String>): Map<String, String?> {
    val out = LinkedHashMap<String, String?>()
    var i = 0
    while (i < args.size) {
        val a = args[i]
        when {
            a.startsWith("--") -> {
                val name = a.removePrefix("--")
                val next = args.getOrNull(i + 1)
                if (next != null && !next.startsWith("--")) {
                    out[name] = next; i += 2
                } else { out[name] = "true"; i++ }
            }
            else -> out[positionKey(i)] = a
        }
        i++
    }
    return out
}

private fun positionKey(i: Int) = "#$i"

private fun help() {
    println(
        """
WARP Scout CLI — подбор доступной WARP/AmneziaWG конфигурации из-под РФ.

Команды:
  selftest              самопроверка ядра (векторы, парсер, скоринг). --live — добавить сетевые проверки,
                        --integration 127.0.0.1:34567 — прогнать пробу против tools/fake_warp_endpoint.py
  tune                  полный цикл: ключи → скан → профили шума → отчёт → лучший .conf
      --endpoints FILE  свой список «host:port» (иначе 14 подсетей × 54 порта из документации)
      --max N           сколько endpoint'ов максимум (по умолчанию 200)
      --attempts N      попыток на точку (3)
      --concurrency N     параллельных сокетов (64)
      --profiles N      сколько SNI-профилей QUIC перебирать (3)
      --seed N          детерминированная выборка
      --out DIR         куда писать отчёты и конфиг (./out)
      --masque          добавить маска-подсети и их TLS-проверку
      --full            перебор всех 255 октетов вместо 1..10 (долго!)
      --json            только JSON-отчёт
  scan                  только скан доступности (без генератора отчётов)
  gen                   сгенерировать один конфиг
      --priv B64        приватный ключ (или --from file.conf, или --fetch — со свежими ключами)
      --endpoint h:p    конечная точка
      --junk none|tls|quic|sip|http   --sni домен   --level 1..4
  parse FILE.conf       разобрать конфиг и показать, что внутри
        """.trimIndent()
    )
}

private fun commonSpec(opts: Map<String, String?>): Pair<EndpointSpec, NetSettings> {
    val ports = if (opts["masque"] == "true") WarpDefaultsPortsMasque else WarpDefaultsPorts
    val spec = EndpointSpec(
        subnets = dev.warpscout.core.net.WarpDefaults.AWG_SUBNETS,
        ports = ports,
        mode = if (opts["full"] == "true") PoolMode.FULL else PoolMode.STRATIFIED,
        maxEndpoints = (opts["max"]?.toIntOrNull() ?: 200),
        samplesPerKey = (opts["per-port"]?.toIntOrNull() ?: 2),
        seed = (opts["seed"]?.toLongOrNull() ?: 20261119L),
        hostnames = if (opts["endpoints"] != null) emptyList() else dev.warpscout.core.net.WarpDefaults.AWG_HOSTNAMES
    )
    val net = NetSettings(
        attempts = opts["attempts"]?.toIntOrNull() ?: 3,
        concurrency = opts["concurrency"]?.toIntOrNull() ?: 64,
        timeoutMs = opts["timeout"]?.toIntOrNull() ?: 1200
    )
    return spec to net
}

private val WarpDefaultsPorts = dev.warpscout.core.net.WarpDefaults.AWG_PORTS
private val WarpDefaultsPortsMasque = dev.warpscout.core.net.WarpDefaults.MASQUE_PORTS

private fun tune(opts: Map<String, String?>) {
    val (spec, net) = commonSpec(opts)
    val outDir = File(opts["out"] ?: "out")
    val keySource = KeySource(store = AccountStore.file("${outDir.path}/account-cache.json"))
    val profiles = JunkLibrary.defaultPool(sniCount = opts["profiles"]?.toIntOrNull() ?: 3)

    val endpointsOverride = opts["endpoints"]?.let { EndpointPool.parseList(File(it).readText()) }
    val effectiveSpec = if (endpointsOverride != null) {
        spec.copy(subnets = emptyList(), hostnames = endpointsOverride.map { it.render() }, mode = PoolMode.EXPLICIT, maxEndpoints = endpointsOverride.size)
    } else spec

    println("Подбираю конфигурацию… (endpoint'ов: ${effectiveSpec.maxEndpoints}, профилей шума: ${profiles.size})")
    val result = AutoTuner(keySource, WgProber(net)).run(
        TuningSpec(endpointSpec = effectiveSpec, junkProfiles = profiles, net = net),
        ProgressSink.STDOUT
    )

    outDir.mkdirs()
    val written = if (opts["json"] == "true") {
        val f = File(outDir, "report.json"); f.writeText(Report.toJson(result.report)); listOf(f)
    } else Report.writeAll(result.report, outDir)
    val extra = result.configText?.let {
        val name = result.report.best?.let { b -> ConfigExport.filename(b.config) } ?: "best.conf"
        val f = File(outDir, name)
        f.writeText(it)
        listOf(f)
    } ?: emptyList()
    println()
    println("Отчёты: ${(written + extra).joinToString { it.name }}")
    result.best?.let {
        println("Лучший выбор: ${it.endpoint.render()} · шум ${it.junk.name} · ${result.report.best?.let { b -> b.score } ?: ""} балла")
        println(ConfigExport.handoffHint(it))
    }
    println("Ключи: ${result.accountSource}")
}

private fun scan(opts: Map<String, String?>) {
    val (spec, net) = commonSpec(opts)
    val account = opts["priv"]?.let {
        WarpAccount(it, opts["pub"] ?: dev.warpscout.core.net.WarpDefaults.WARP_PEER_PUBLIC)
    } ?: KeySource().account()
    val endpoints = opts["endpoints"]?.let { EndpointPool.parseList(File(it).readText()) }
        ?: EndpointPool.build(spec)
    println("Сканирую ${endpoints.size} конечных точек, ${net.attempts} попыток, concurrency=${net.concurrency}")
    val stats = WgProber(net).scan(endpoints, account, Crypto.unBase64(account.peerPublicB64))
    stats.sortedWith(compareByDescending<dev.warpscout.core.model.EndpointStats> { it.bestVerdict.ordinal }.thenBy { it.minRtt ?: 9e9 })
        .take(opts["top"]?.toIntOrNull() ?: 30)
        .forEach { println("  ${"%-28s".format(it.endpoint.render())} ${it.bestVerdict} rtt=${it.minRtt?.let { r -> String.format("%.0f", r) } ?: "-"}ms loss=${String.format("%.0f", it.lossPct)}%") }
}

private fun gen(opts: Map<String, String?>) {
    val account = when {
        opts["priv"] != null -> WarpAccount(
            opts["priv"]!!,
            opts["pub"] ?: dev.warpscout.core.net.WarpDefaults.WARP_PEER_PUBLIC,
            opts["ipv4"] ?: "172.16.0.2",
            opts["ipv6"]
        )
        opts["from"] != null -> WgConf.toWarpConfig("from-file", File(opts["from"]!!).readText())?.account
            ?: error("в файле нет [Interface] PrivateKey")
        else -> KeySource().account()
    }
    val endpoint = opts["endpoint"]?.let { EndpointPool.parseOne(it).first() }
        ?: Endpoint("engage.cloudflareclient.com", 2408, dev.warpscout.core.model.AddrFamily.HOSTNAME)

    val junk: JunkProfile = when (opts["junk"] ?: "quic") {
        "none" -> JunkLibrary.none()
        "tls" -> JunkLibrary.tlsFixed()
        "sip" -> JunkLibrary.sip()
        "http" -> JunkLibrary.httpGet(opts["sni"] ?: "www.gstatic.com")
        else -> JunkLibrary.quic(opts["sni"] ?: JunkLibrary.SNI_DOMAINS.random(), opts["level"]?.toIntOrNull() ?: 3)
    }

    val cfg = WarpConfig(
        name = opts["name"] ?: "WARP ${endpoint.render()}",
        account = account,
        endpoint = endpoint,
        junk = junk,
        allowedIps = if (opts["bypass"] == "true") dev.warpscout.core.presets.RoutePresets.BYPASS_WHITELIST_CSV else "0.0.0.0/0, ::/0",
        dns = (opts["dns"] ?: Presets.DNS.first().servers.joinToString(", ")).split(',', ' ').map { it.trim() }.filter { it.isNotEmpty() },
        mtu = opts["mtu"]?.toIntOrNull() ?: 1280,
        persistentKeepalive = opts["keepalive"]?.toIntOrNull() ?: 25,
        enableIpv6Address = opts["ipv6-only"] != "true"
    )
    val text = WgConf.render(cfg)
    val out = opts["out"]?.let { File(it) } ?: File(ConfigExport.filename(cfg))
    out.parentFile?.mkdirs()
    out.writeText(text)
    File(out.path + ".yaml").writeText(ConfigExport.clashYaml(cfg))
    println(text)
    println("записано: ${out.path} (и ${out.name}.yaml для Clash/Mihomo)")
    println(ConfigExport.handoffHint(cfg))
}

private fun parse(opts: Map<String, String?>) {
    val path = opts["#0"] ?: opts["file"] ?: error("нужен путь к .conf")
    val text = File(path).readText()
    val cfg = WgConf.toWarpConfig(File(path).nameWithoutExtension, text) ?: error("не похоже на конфиг WireGuard")
    println("имя:            ${cfg.name}")
    println("endpoint:       ${cfg.endpoint.render()}")
    println("приватный ключ: ${cfg.account.privateB64.take(6)}… (длина ${cfg.account.privateB64.length})")
    println("адреса:         ${cfg.account.ipv4}${cfg.account.ipv6?.let { ", $it" } ?: ""}")
    println("DNS:            ${cfg.dns.joinToString(", ")}")
    println("MTU / keepalive:${cfg.mtu} / ${cfg.persistentKeepalive ?: "нет"}")
    println("AllowedIPs:     ${cfg.allowedIps.take(80)}${if (cfg.allowedIps.length > 80) "…" else ""}")
    println("профиль шума:   ${cfg.junk.name} (${cfg.junk.kind.name}), I1=${cfg.junk.i1.size} чанк(ов), I2=${cfg.junk.i2.size}")
    println("AWG:            Jc=${cfg.junk.awg.jc} Jmin=${cfg.junk.awg.jmin} Jmax=${cfg.junk.awg.jmax} H=${cfg.junk.awg.h1},${cfg.junk.awg.h2},${cfg.junk.awg.h3},${cfg.junk.awg.h4} S=${cfg.junk.awg.s1},${cfg.junk.awg.s2},${cfg.junk.awg.s3},${cfg.junk.awg.s4}")
    if (cfg.junk.i1.isNotEmpty()) {
        val bytes = cfg.junk.i1.sumOf { it.size }
        println("мусорный пакет: $bytes байт, sha-like профиль ${Crypto.hex(dev.warpscout.core.crypto.Blake2s.hash(cfg.junk.i1.joinToString("").toByteArray())).take(16)}")
    }
}
