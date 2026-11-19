#!/usr/bin/env python3
"""Сборка снапшота списков allow-domains в ресурсы ядра.

Источник: https://github.com/haritos90/allow-domains (списки доменов и подсетей,
обновляются апстримом еженедельно; проект — форк itdoginfo/allow-domains).

Зачем снапшот в APK, а не загрузка по сети:
  * WireGuard умеет маршрутизировать только по IP, поэтому нужны именно подсети;
  * списки нужны в момент генерации конфига, когда сеть может быть уже «сломана»
    (именно из-за блокировок приложение и запускают);
  * офлайн-снапшот детерминирован: одинаковый вход даёт одинаковый APK.

Что на выходе:
  core/src/main/resources/rules/<id>.v4.lst      — CIDR IPv4, схлопнутые и отсортированные
  core/src/main/resources/rules/<id>.v6.lst      — CIDR IPv6
  core/src/main/resources/rules/<id>.domains.lst — домены категории (для DoH-резолва и проверок)
  core/src/main/resources/rules/union.v4.lst     — объединение всех подсетей апстрима (Subnets/IPv4/all.lst)
  core/src/main/resources/rules/union.v6.lst
  core/src/main/kotlin/dev/warpscout/core/presets/RuleCatalog.kt — метаданные категорий

Использование:
  python3 tools/gen_rules.py --source /path/to/allow-domains
  python3 tools/gen_rules.py --tarball allow-domains.tar.gz     # можно прямо tarball с codeload

Обновление списков:
  curl -sSL -o /tmp/ad.tar.gz https://codeload.github.com/haritos90/allow-domains/tar.gz/refs/heads/main
  python3 tools/gen_rules.py --tarball /tmp/ad.tar.gz
"""

from __future__ import annotations

import argparse
import datetime as _dt
import ipaddress
import os
import re
import shutil
import sys
import tarfile
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RES_DIR = ROOT / "core/src/main/resources/rules"
KOTLIN_OUT = ROOT / "core/src/main/kotlin/dev/warpscout/core/presets/RuleCatalog.kt"

# Порядок и человеческие названия. Апстрим нумерует файлы "NN-slug.lst".
TITLES = {
    "01-youtube": "YouTube",
    "02-discord": "Discord",
    "03-meta": "Meta (Instagram, Facebook, WhatsApp)",
    "04-telegram": "Telegram",
    "05-twitter": "Twitter / X / Grok",
    "06-google-ai": "Google AI (Gemini)",
    "07-google-play": "Google Play",
    "08-google-meet": "Google Meet",
    "09-tiktok": "TikTok",
    "10-hdrezka": "HDRezka и зеркала",
    "11-roblox": "Roblox",
    "12-openai": "OpenAI / ChatGPT / Sora",
    "13-claude": "Claude (Anthropic)",
    "14-hodca": "Хостинги (Hetzner, OVH, DO, AWS…)",
    "15-ru-ip-blocked": "Сайты, закрытые для РФ-адресов",
    "16-news": "Новостные сайты",
    "17-anime": "Аниме",
    "18-adult": "Для взрослых",
    "19-blocked": "Прочее заблокированное",
    "20-zscaler": "Zscaler (корпоративный)",
    "21-hosters-ip-blocked": "Сайты, закрытые для дата-центров",
}

# ru_blocked  — ресурс недоступен из РФ, туннель должен его открыть;
# blocks_ru   — ресурс наоборот закрыт для РФ-адресов: через WARP тоже, скорее всего, не откроется;
# infra       — служебные диапазоны (хостинги, корпоративные), туннелировать по желанию.
KINDS = {
    **{f"{n:02d}-{slug}": "ru_blocked" for n, slug in [
        (1, "youtube"), (2, "discord"), (3, "meta"), (4, "telegram"), (5, "twitter"),
        (6, "google-ai"), (7, "google-play"), (8, "google-meet"), (9, "tiktok"),
        (10, "hdrezka"), (11, "roblox"), (12, "openai"), (13, "claude"),
        (16, "news"), (17, "anime"), (18, "adult"), (19, "blocked"),
    ]},
    "14-hodca": "infra",
    "15-ru-ip-blocked": "blocks_ru",
    "21-hosters-ip-blocked": "blocks_ru",
    "20-zscaler": "infra",
}

# Что показывать в проверке доступности: сначала пробуем «человеческий» домен,
# если его нет в списке категории — берём первые домены из файла.
PREFERRED_CHECK = {
    "01-youtube": ["youtube.com", "www.youtube.com", "youtu.be"],
    "02-discord": ["discord.com", "discord.gg"],
    "03-meta": ["instagram.com", "www.instagram.com"],
    "04-telegram": ["web.telegram.org", "telegram.org", "t.me"],
    "05-twitter": ["x.com", "twitter.com"],
    "06-google-ai": ["gemini.google.com", "aistudio.google.com"],
    "07-google-play": ["play.google.com"],
    "08-google-meet": ["meet.google.com"],
    "09-tiktok": ["www.tiktok.com", "tiktok.com"],
    "10-hdrezka": ["hdrezka.ag", "hdrezka.fi"],
    "11-roblox": ["www.roblox.com", "roblox.com"],
    "12-openai": ["chatgpt.com", "api.openai.com"],
    "13-claude": ["claude.ai", "api.anthropic.com"],
    "15-ru-ip-blocked": ["4pda.to", "adr.it"],
    "16-news": ["meduza.io", "bbc.com", "www.dw.com"],
    "19-blocked": [],
    "21-hosters-ip-blocked": ["adr.it"],
}

DEFAULT_SELECTED = ["01-youtube", "02-discord", "03-meta", "04-telegram", "05-twitter", "12-openai", "13-claude"]


# --------------------------------------------------------------------- CIDR


def _merge(nets: list) -> list:
    """Схлопывает список сетей одного семейства в минимальный набор префиксов."""
    if not nets:
        return []
    nets = sorted(nets, key=lambda n: (int(n.network_address), n.prefixlen))
    out = []
    for net in nets:
        if not out:
            out.append(net)
            continue
        last = out[-1]
        if net.subnet_of(last):
            continue
        if int(net.network_address) == int(last.broadcast_address) + 1:
            # Пробуем слить соседей в суперсеть.
            merged = list(ipaddress.summarize_address_range(last.network_address, net.broadcast_address))
            out.pop()
            for m in merged:
                if out and m.subnet_of(out[-1]):
                    continue
                out.append(m)
            continue
        out.append(net)
    # Второй проход: summarize мог дать префиксы, которые схлопываются с предыдущими.
    changed = True
    while changed:
        changed = False
        i = 0
        while i < len(out) - 1:
            a, b = out[i], out[i + 1]
            if b.subnet_of(a):
                out.pop(i + 1)
                changed = True
                continue
            if int(a.broadcast_address) + 1 == int(b.network_address):
                merged = list(ipaddress.summarize_address_range(a.network_address, b.broadcast_address))
                if len(merged) < 2:
                    out[i:i + 2] = merged
                    changed = True
                    continue
            i += 1
    return out


def read_lines(path: Path) -> list[str]:
    if not path.exists():
        return []
    out = []
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith(";") or line.startswith("//"):
            continue
        out.append(line)
    return out


def read_cidrs(path: Path, version: int) -> list:
    nets = []
    for line in read_lines(path):
        token = line.split()[0].lstrip("-").strip()
        token = re.sub(r"^(IP-CIDR6?|IP6-CIDR),", "", token, flags=re.I)
        if "/" not in token:
            continue
        try:
            net = ipaddress.ip_network(token, strict=False)
        except ValueError:
            continue
        if net.version == version:
            nets.append(net)
    return _merge(nets)


def read_domains(path: Path) -> list[str]:
    out = []
    for line in read_lines(path):
        token = line.split()[0]
        if token.startswith("DOMAIN-SUFFIX,"):
            token = token.split(",", 1)[1]
        if "/" in token or ":" in token:
            continue
        token = token.lstrip(".").lower().strip()
        if not re.fullmatch(r"[a-z0-9*_.-]+\.[a-z]{2,}", token):
            continue
        out.append(token)
    # dedupe с сохранением порядка
    seen, uniq = set(), []
    for d in out:
        if d not in seen:
            seen.add(d)
            uniq.append(d)
    return uniq


# ------------------------------------------------------------------ сборка


def find_source(args) -> tuple[Path, str]:
    if args.source:
        src = Path(args.source).expanduser().resolve()
        commit = args.commit or ""
        return src, commit
    if args.tarball:
        tmp = Path(tempfile.mkdtemp(prefix="allow-domains-"))
        with tarfile.open(args.tarball, "r:*") as tar:
            tar.extractall(tmp)
        inner = [p for p in tmp.iterdir() if p.is_dir()]
        if not inner:
            sys.exit("в архиве нет каталога репозитория")
        return inner[0], args.commit or ""
    sys.exit("укажите --source <каталог репозитория> или --tarball <архив>")


def main() -> int:
    ap = argparse.ArgumentParser(description="Снапшот allow-domains → ресурсы core")
    ap.add_argument("--source", help="каталог распакованного репозитория allow-domains")
    ap.add_argument("--tarball", help="tar.gz с codeload")
    ap.add_argument("--commit", default=os.environ.get("ALLOW_DOMAINS_COMMIT", ""),
                    help="хэш коммита апстрима (для метаданных)")
    ap.add_argument("--max-prefixes", type=int, default=4000,
                    help="предупреждать, если категория даёт больше префиксов")
    args = ap.parse_args()

    src, commit = find_source(args)
    print(f"источник: {src}")

    RES_DIR.mkdir(parents=True, exist_ok=True)
    for old in RES_DIR.glob("*.lst"):
        old.unlink()

    cats_path = src / "Categories"
    v4_path = src / "Subnets/IPv4"
    v6_path = src / "Subnets/IPv6"
    ids = sorted({p.name[:-4] for p in cats_path.glob("*.lst")} |
                 {p.name[:-4] for p in v4_path.glob("*.lst")} |
                 {p.name[:-4] for p in v6_path.glob("*.lst")} - {"all"})
    ids = [i for i in ids if re.match(r"^\d{2}-", i)]

    entries = []
    total_bytes = 0
    for cid in ids:
        v4 = read_cidrs(v4_path / f"{cid}.lst", 4)
        v6 = read_cidrs(v6_path / f"{cid}.lst", 6)
        domains = read_domains(cats_path / f"{cid}.lst")

        if v4:
            text = "\n".join(str(n) for n in v4) + "\n"
            (RES_DIR / f"{cid}.v4.lst").write_text(text, encoding="utf-8")
            total_bytes += len(text)
        if v6:
            text = "\n".join(str(n) for n in v6) + "\n"
            (RES_DIR / f"{cid}.v6.lst").write_text(text, encoding="utf-8")
            total_bytes += len(text)
        if domains:
            text = "\n".join(domains) + "\n"
            (RES_DIR / f"{cid}.domains.lst").write_text(text, encoding="utf-8")
            total_bytes += len(text)

        number = int(cid[:2])
        title = TITLES.get(cid, cid)
        kind = KINDS.get(cid, "ru_blocked")

        checks: list[str] = []
        for cand in PREFERRED_CHECK.get(cid, []):
            if cand in domains or not domains:
                checks.append(cand)
            if len(checks) >= 2:
                break
        if not checks and domains and kind != "infra":
            checks = domains[:1]

        entries.append(dict(id=cid, number=number, title=title, kind=kind,
                            v4=len(v4), v6=len(v6), domains=len(domains),
                            checks=checks))
        if len(v4) + len(v6) > args.max_prefixes:
            print(f"  ! {cid}: {len(v4) + len(v6)} префиксов — больше порога "
                  f"{args.max_prefixes}, проверьте AllowedIPs")

    # union (апстрим уже склеил все подсетевые категории в all.lst)
    union4 = read_cidrs(v4_path / "all.lst", 4)
    union6 = read_cidrs(v6_path / "all.lst", 6)
    if union4:
        text = "\n".join(str(n) for n in union4) + "\n"
        (RES_DIR / "union.v4.lst").write_text(text, encoding="utf-8")
        total_bytes += len(text)
    if union6:
        text = "\n".join(str(n) for n in union6) + "\n"
        (RES_DIR / "union.v6.lst").write_text(text, encoding="utf-8")
        total_bytes += len(text)

    write_kotlin(entries, union4, union6, commit)

    print(f"готово: {len(entries)} категорий, ресурсов {total_bytes / 1024:.0f} КБ")
    print(f"union: {len(union4)} IPv4 + {len(union6)} IPv6 префиксов")
    for e in entries:
        print(f"  {e['id']:<22} v4={e['v4']:<4} v6={e['v6']:<4} доменов={e['domains']:<4} {e['kind']}")
    return 0


def write_kotlin(entries: list[dict], union4: list, union6: list, commit: str) -> None:
    stamp = _dt.date.today().isoformat()
    lines = [
        "// AUTO-GENERATED by tools/gen_rules.py — не править руками.",
        "//",
        f"// Источник: github.com/haritos90/allow-domains (форк itdoginfo/allow-domains).",
        f"// Снапшот: {stamp}" + (f", коммит {commit}" if commit else "") + ".",
        "// Данные лежат рядом: core/src/main/resources/rules/<id>.v4.lst|.v6.lst|.domains.lst.",
        "//",
        "// Обновить: ./tools/gen_rules.py --tarball ad.tar.gz (см. шапку скрипта).",
        "package dev.warpscout.core.presets",
        "",
        "object RuleCatalog {",
        "",
        f'    const val SNAPSHOT_DATE: String = "{stamp}"',
        f'    const val SNAPSHOT_COMMIT: String = "{commit}"',
        '    const val SOURCE: String = "github.com/haritos90/allow-domains"',
        "",
        "    /** Чья сторона блокирует ресурс — от этого зависит, что считать «работает». */",
        "    enum class Kind {",
        "        /** Ресурс недоступен из РФ: поднятый туннель обязан его открыть. */",
        "        RU_BLOCKED,",
        "        /** Ресурс закрыт для РФ-адресов (или дата-центров): он и через WARP может не открыться. */",
        "        BLOCKS_RU,",
        "        /** Служебные диапазоны (хостинги, корпоративные сети) — туннелировать по желанию. */",
        "        INFRA,", 
        "    }",
        "",
        "    data class Category(",
        "        val id: String,",
        "        val number: Int,",
        "        val title: String,",
        "        val kind: Kind,",
        "        /** Сколько префиксов IPv4 в снапшоте (0 — подсетей в апстриме нет). */",
        "        val prefixesV4: Int,",
        "        val prefixesV6: Int,",
        "        /** Сколько доменов в снапшоте (для DoH-резолва и проверок). */",
        "        val domainCount: Int,",
        "        /** Домены, по которым проверяем доступность ресурса из-под туннеля. */",
        "        val checkDomains: List<String>,",
        "    ) {",
        "        val hasSubnets: Boolean get() = prefixesV4 > 0 || prefixesV6 > 0",
        "    }",
        "",
        "    val ALL: List<Category> = listOf(",
    ]
    kind_map = {"ru_blocked": "Kind.RU_BLOCKED", "blocks_ru": "Kind.BLOCKS_RU", "infra": "Kind.INFRA"}
    for e in entries:
        checks = ", ".join(f'"{c}"' for c in e["checks"])
        lines += [
            "        Category(",
            f'            id = "{e["id"]}",',
            f'            number = {e["number"]},',
            f'            title = "{e["title"].replace(chr(34), chr(92) + chr(34))}",',
            f'            kind = {kind_map.get(e["kind"], "Kind.RU_BLOCKED")},',
            f'            prefixesV4 = {e["v4"]},',
            f'            prefixesV6 = {e["v6"]},',
            f'            domainCount = {e["domains"]},',
            f'            checkDomains = listOf({checks}),',
            "        ),",
        ]
    lines += [
        "    )",
        "",
        "    val BY_ID: Map<String, Category> = ALL.associateBy { it.id }",
        "",
        "    /** Что включено по умолчанию: то, что в РФ реально режут. */",
        f"    val DEFAULT_SELECTED: Set<String> = linkedSetOf({', '.join(chr(34) + s + chr(34) for s in DEFAULT_SELECTED if s in {e['id'] for e in entries})})",
        "",
        "    /** Объединение всех подсетей апстрима — режим «только заблокированное в РФ». */",
        f"    const val UNION_PREFIXES_V4: Int = {len(union4)}",
        f"    const val UNION_PREFIXES_V6: Int = {len(union6)}",
        "",
        "    fun of(kind: Kind): List<Category> = ALL.filter { it.kind == kind }",
        "}",
        "",
    ]
    KOTLIN_OUT.parent.mkdir(parents=True, exist_ok=True)
    KOTLIN_OUT.write_text("\n".join(lines), encoding="utf-8")


if __name__ == "__main__":
    sys.exit(main())
