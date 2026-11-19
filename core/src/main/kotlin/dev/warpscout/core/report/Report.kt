package dev.warpscout.core.report

import dev.warpscout.core.config.WgConf
import dev.warpscout.core.json.JsonVal
import dev.warpscout.core.model.Candidate
import dev.warpscout.core.model.TuningReport
import dev.warpscout.core.model.Verdict
import dev.warpscout.core.model.WarpConfig
import java.io.File

/** Отчёты: JSON (машиночитаемо), HTML (человечески, один файл), CSV (в таблицу), Markdown (в чат). */
object Report {

    fun toJson(report: TuningReport, includeConfig: Boolean = true): String {
        val candidates = JsonVal.arr(report.candidates.map { cand ->
            val fields = linkedMapOf<String, JsonVal>(
                "endpoint" to JsonVal.str(cand.config.endpoint.render()),
                "verdict" to JsonVal.str(cand.stats.bestVerdict.name),
                "score" to JsonVal.num(cand.score),
                "junk_profile" to JsonVal.str(cand.junk.name),
                "junk_kind" to JsonVal.str(cand.junk.kind.name),
                "rtt_min_ms" to (cand.stats.minRtt?.let { JsonVal.num(round(it, 1)) } ?: JsonVal.Null),
                "rtt_median_ms" to (cand.stats.medianRtt?.let { JsonVal.num(round(it, 1)) } ?: JsonVal.Null),
                "jitter_ms" to (cand.stats.jitterMs?.let { JsonVal.num(round(it, 1)) } ?: JsonVal.Null),
                "loss_pct" to JsonVal.num(round(cand.stats.lossPct, 1)),
                "attempts" to JsonVal.num(cand.stats.attempts),
                "replies" to JsonVal.num(cand.stats.replies),
                "parts" to JsonVal.obj(cand.parts.asMap().mapValues { JsonVal.num(it.value) })
            )
            if (includeConfig) fields["config"] = JsonVal.str(WgConf.render(cand.config))
            JsonVal.obj(fields)
        })

        val root = linkedMapOf<String, JsonVal>(
            "tool" to JsonVal.str("WARP Scout"),
            "started_at" to JsonVal.str(report.startedAt),
            "finished_at" to JsonVal.str(report.finishedAt),
            "profile" to JsonVal.str(report.profileName),
            "endpoints_tested" to JsonVal.num(report.endpointsTested),
            "best" to (report.best?.let { JsonVal.str(it.config.endpoint.render() + " / " + it.junk.name) } ?: JsonVal.Null),
            "notes" to JsonVal.arr(report.notes.map { JsonVal.str(it) }),
            "resources" to JsonVal.arr(report.resources.map { r ->
                JsonVal.obj(
                    "name" to JsonVal.str(r.check.name),
                    "url" to JsonVal.str(r.check.url),
                    "ok" to JsonVal.bool(r.ok),
                    "status" to (r.status?.let { JsonVal.num(it) } ?: JsonVal.Null),
                    "error" to (r.errorClass?.let { JsonVal.str(it) } ?: JsonVal.Null),
                    "elapsed_ms" to JsonVal.num(r.elapsedMs)
                )
            }),
            "candidates" to candidates
        )
        return JsonVal.obj(root).render(0)
    }

    fun toCsv(report: TuningReport): String = buildString {
        appendLine("rank;endpoint;junk;verdict;score;rtt_min_ms;rtt_median_ms;jitter_ms;loss_pct;attempts;replies")
        report.candidates.forEachIndexed { i, c ->
            appendLine(
                listOf(
                    i + 1, c.config.endpoint.render(), c.junk.name, c.stats.bestVerdict.name, c.score,
                    c.stats.minRtt?.let { round(it, 1) }?.toString() ?: "",
                    c.stats.medianRtt?.let { round(it, 1) }?.toString() ?: "",
                    c.stats.jitterMs?.let { round(it, 1) }?.toString() ?: "",
                    round(c.stats.lossPct, 1), c.stats.attempts, c.stats.replies
                ).joinToString(";")
            )
        }
    }

    fun toMarkdown(report: TuningReport): String = buildString {
        appendLine("# WARP Scout — отчёт")
        appendLine()
        appendLine("Профиль: `${report.profileName}` · проверки: ${report.endpointsTested} endpoint'ов · ${report.startedAt} → ${report.finishedAt}")
        appendLine()
        report.best?.let {
            appendLine("**Лучшая конфигурация:** `${it.config.endpoint.render()}` + шум `${it.junk.name}` → **${it.score}** баллов")
            appendLine()
        }
        if (report.notes.isNotEmpty()) {
            appendLine("## Заметки")
            report.notes.forEach { appendLine("- $it") }
            appendLine()
        }
        appendLine("## Кандидаты")
        appendLine()
        appendLine("| # | endpoint | шум | вердикт | RTT min | потеря | балл |")
        appendLine("|---|---|---|---|---|---|---|")
        report.candidates.forEachIndexed { i, c ->
            val rtt = c.stats.minRtt?.let { "${round(it, 1)} мс" } ?: "—"
            appendLine("| ${i + 1} | ${c.config.endpoint.render()} | ${c.junk.name} | ${c.stats.bestVerdict.name} | $rtt | ${round(c.stats.lossPct, 0)}% | ${c.score} |")
        }
        if (report.resources.isNotEmpty()) {
            appendLine()
            appendLine("## Доступность ресурсов")
            appendLine()
            appendLine("| ресурс | итог | код/ошибка | время |")
            appendLine("|---|---|---|---|")
            report.resources.forEach { r ->
                appendLine("| ${r.check.name} | ${if (r.ok) "✅" else "⛔"} | ${r.status ?: r.errorClass ?: "—"} | ${r.elapsedMs} мс |")
            }
        }
    }

    fun toHtml(report: TuningReport): String {
        val rows = report.candidates.take(40).mapIndexed { i, c ->
            val cls = when (c.stats.bestVerdict) {
                Verdict.HANDSHAKE_OK -> "ok"
                Verdict.COOKIE_REPLY, Verdict.TLS_OK -> "good"
                Verdict.UDP_SILENT -> "warn"
                else -> "bad"
            }
            """<tr><td>${i + 1}</td><td class="$cls"><b>${esc(c.config.endpoint.render())}</b></td>
               <td>${esc(c.junk.name)}<div class="dim">${esc(c.junk.kind.name)}</div></td>
               <td>${c.stats.bestVerdict.name}</td>
               <td>${c.stats.minRtt?.let { fmt(it) } ?: "—"}</td>
               <td>${c.stats.jitterMs?.let { fmt(it) } ?: "—"}</td>
               <td>${fmt(c.stats.lossPct)}%</td>
               <td><b>${c.score}</b><div class="dim">${esc(c.parts.asMap().entries.joinToString(" ") { "${it.key}:${it.value}" })}</div></td></tr>"""
        }.joinToString("\n")

        val resRows = report.resources.joinToString("\n") { r ->
            """<tr><td class="${if (r.ok) "ok" else "bad"}">${esc(r.check.name)}</td><td>${r.status ?: esc(r.errorClass ?: "—")}</td>
               <td>${r.elapsedMs} мс</td><td>${esc(r.check.url)}</td></tr>"""
        }
        val bestConf = report.best?.let { "<pre>${esc(WgConf.render(it.config))}</pre>" }
            ?: "<p class=dim>Нет кандидатов.</p>"

        return """<!doctype html><html lang="ru"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>WARP Scout — отчёт ${esc(report.finishedAt)}</title>
<style>
:root{color-scheme:dark light}
body{font:15px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;margin:24px auto;max-width:1080px;padding:0 16px;color:#15181d}
h1{font-size:22px;margin:0 0 4px}
h2{font-size:17px;margin:26px 0 8px}
.sub{color:#5b6472;font-size:13px;margin-bottom:18px}
table{border-collapse:collapse;width:100%;font-size:13.5px}
th,td{text-align:left;padding:7px 9px;border-bottom:1px solid #e6e9ee;vertical-align:top}
th{background:#f4f6f9;position:sticky;top:0}
.ok{color:#0b7a3d}.good{color:#1365b8}.warn{color:#a76a00}.bad{color:#b3261e}
.dim{color:#7a8494;font-size:11.5px}
pre{background:#0f1116;color:#d7e0ea;padding:14px;border-radius:10px;overflow:auto;font-size:12px;word-break:break-all;white-space:pre-wrap}
.card{background:#f7f9fc;border:1px solid #e6e9ee;border-radius:12px;padding:14px 16px;margin:10px 0}
@media (prefers-color-scheme:dark){body{background:#0f1116;color:#dfe4ea}th{background:#171b22}th,td{border-color:#242a35}.card{background:#151a22;border-color:#242a35}}
</style>
<h1>WARP Scout — отчёт по подбору конфигурации</h1>
<div class="sub">${esc(report.profileName)} · проверено ${report.endpointsTested} конечных точек · ${esc(report.startedAt)} → ${esc(report.finishedAt)}</div>
${report.notes.joinToString("") { "<div class='card'>${esc(it)}</div>" }}
<h2>Лучшая конфигурация</h2>
${bestConf}
<h2>Кандидаты</h2>
<table><thead><tr><th>#</th><th>endpoint</th><th>шум</th><th>вердикт</th><th>RTT min</th><th>джиттер</th><th>потери</th><th>балл</th></tr></thead>
<tbody>$rows</tbody></table>
${if (report.resources.isNotEmpty()) "<h2>Доступность ресурсов</h2><table><thead><tr><th>ресурс</th><th>код</th><th>время</th><th>URL</th></tr></thead><tbody>$resRows</tbody></table>" else ""}
<div class="sub" style="margin-top:26px">Сгенерировано локально, без отправки статистики. Вердикт HANDSHAKE_OK означает, что сервер WireGuard проверил и принял именно ваш ключ.</div>
</html>"""
    }

    fun writeAll(report: TuningReport, dir: File, baseName: String = "warpscout-report"): List<File> {
        dir.mkdirs()
        val stamp = report.finishedAt.replace(Regex("[^0-9A-Za-z-]"), "-")
        val files = listOf(
            File(dir, "$baseName-$stamp.json") to toJson(report),
            File(dir, "$baseName-$stamp.html") to toHtml(report),
            File(dir, "$baseName-$stamp.csv") to toCsv(report),
            File(dir, "$baseName-$stamp.md") to toMarkdown(report)
        )
        files.forEach { (f, content) -> f.writeText(content) }
        report.best?.let { File(dir, "best-${it.config.endpoint.host}_${it.config.endpoint.port}.conf").writeText(WgConf.render(it.config)) }
        return files.map { it.first } + report.best?.let { listOf(File(dir, "best-${it.config.endpoint.host}_${it.config.endpoint.port}.conf")) }.orEmpty()
    }

    private fun esc(s: String): String = s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
    private fun fmt(d: Double): String = if (d == d.toLong().toDouble()) d.toLong().toString() else String.format("%.1f", d)
    private fun round(v: Double, digits: Int): Double {
        var m = 1.0
        repeat(digits) { m *= 10 }
        return Math.round(v * m) / m
    }
}

/** Экспорт конфигураций в форматы разных клиентов. */
object ConfigExport {

    fun filename(cfg: WarpConfig): String {
        val safe = cfg.endpoint.render().replace(':', '_').replace(Regex("[^A-Za-z0-9_.:-]"), "")
        return "WARP_${cfg.junk.kind.name.lowercase()}_$safe.conf"
    }

    fun clashYaml(cfg: WarpConfig): String = buildString {
        appendLine("proxies:")
        appendLine("- name: \"${cfg.name}\"")
        appendLine("  type: wireguard")
        appendLine("  server: ${cfg.endpoint.host}")
        appendLine("  port: ${cfg.endpoint.port}")
        appendLine("  private-key: ${cfg.account.privateB64}")
        appendLine("  public-key: ${cfg.account.peerPublicB64}")
        appendLine("  ip: ${cfg.account.ipv4}/32")
        if (cfg.enableIpv6Address && cfg.account.ipv6 != null) appendLine("  ipv6: ${cfg.account.ipv6}/128")
        appendLine("  allowed-ips: [\"${cfg.allowedIps.replace(",", "\", \"")}\"]")
        appendLine("  mtu: ${cfg.mtu}")
        appendLine("  udp: true")
        appendLine("  keepalive: ${cfg.persistentKeepalive ?: 25}")
        appendLine("  dns: [${cfg.dns.joinToString(", ")}]")
        appendLine("  remote-dns-resolve: true")
        appendLine("  amnezia-wg-option:")
        appendLine("    version: 3")
        appendLine("    jc: ${cfg.junk.awg.jc}")
        appendLine("    jmin: ${cfg.junk.awg.jmin}")
        appendLine("    jmax: ${cfg.junk.awg.jmax}")
        if (cfg.junk.i1.isNotEmpty()) appendLine("    i1: ${WgConf.renderJunk(cfg.junk.i1)}")
        if (cfg.junk.i2.isNotEmpty()) appendLine("    i2: ${WgConf.renderJunk(cfg.junk.i2)}")
        appendLine("    h1: ${cfg.junk.awg.h1}")
        appendLine("    h2: ${cfg.junk.awg.h2}")
        appendLine("    h3: ${cfg.junk.awg.h3}")
        appendLine("    h4: ${cfg.junk.awg.h4}")
        appendLine("    s1: ${cfg.junk.awg.s1}")
        appendLine("    s2: ${cfg.junk.awg.s2}")
        appendLine("    s3: ${cfg.junk.awg.s3}")
        appendLine("    s4: ${cfg.junk.awg.s4}")
    }

    /** Короткая подсказка, что делать с конфигом (показывается в UI и в CLI). */
    fun handoffHint(cfg: WarpConfig): String = """
        |AmneziaVPN: Настройки → Настройки протокола → включите AmneziaWG → «Добавить профиль» → «Добавить из файла» (этот .conf) → включить.
        |Или вручную: раздел Interface, параметр Endpoint = ${cfg.endpoint.render()}, I1/I2 = профиль «${cfg.junk.name}».
    """.trimMargin()
}
