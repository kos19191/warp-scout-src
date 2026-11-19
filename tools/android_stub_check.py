#!/usr/bin/env python3
"""Оффлайн-проверка Android-слоя без Gradle и без Android SDK.

`./gradlew :app:assembleScoutDebug` требует SDK, которого в песочнице нет. Но «нет SDK» — не
повод отдавать Kotlin, который никогда не видел компилятора. Скрипт делает два независимых шага:

1. валидация ресурсов: парсит все XML, ищет дубликаты имён внутри одного типа (на этом
   падает aapt2) и висячие ссылки `@string/…`, `@id/…`, `@style/…`, `@dimen/…`, `@color/…`;
2. генерирует заглушки `R` и `*Binding` строго из фактической разметки (тип поля = тег view),
   и запускает kotlinc против настоящего `android.jar` + jar'ов androidx/material.

Типы в заглушке берутся из layout, поэтому «в коде TextView, а в разметке MaterialSwitch»
превращается в ошибку компиляции, а не в ClassCastException на устройстве.

    python3 tools/android_stub_check.py --compile \
        --android-jar ~/.cache/android/jar/android.jar \
        --jar-dir ~/.cache/android/jar --kotlinc ~/.cache/tools/kotlinc/bin/kotlinc
"""
from __future__ import annotations

import tempfile

import argparse
import os
import re
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

A = "{http://schemas.android.com/apk/res/android}"
ROOT = Path(__file__).resolve().parent.parent
RES = ROOT / "app/src/main/res"
KOTLIN_DIRS = [ROOT / "app/src/main/kotlin", ROOT / "app/src/scout/kotlin", ROOT / "app/src/tunnel/kotlin"]
# Типы ресурсов, которые живут в values*.xml тегом, а не отдельным файлом.
VALUE_KINDS = ["string", "color", "dimen", "style", "bool", "integer"]
FILE_KINDS = {"drawable": ["drawable", "drawable-night", "mipmap"], "xml": ["xml"], "layout": ["layout"], "menu": ["menu"]}

ALLOWED_FGS_TYPES = {
    "none", "manifest", "camera", "connectedDevice", "dataSync", "health", "location",
    "mediaPlayback", "mediaProjection", "microphone", "phoneCall", "remoteMessaging",
    "shortService", "specialUse", "systemExempted",
}

FRAMEWORK = {
    "TextView": "android.widget.TextView", "EditText": "android.widget.EditText",
    "Spinner": "android.widget.Spinner", "CheckBox": "android.widget.CheckBox",
    "Button": "android.widget.Button", "LinearLayout": "android.widget.LinearLayout",
    "FrameLayout": "android.widget.FrameLayout", "RelativeLayout": "android.widget.RelativeLayout",
    "ScrollView": "android.widget.ScrollView", "HorizontalScrollView": "android.widget.HorizontalScrollView",
    "ImageView": "android.widget.ImageView", "ProgressBar": "android.widget.ProgressBar",
    "View": "android.view.View", "Space": "android.widget.Space",
    "RadioGroup": "android.widget.RadioGroup", "RadioButton": "android.widget.RadioButton",
    "include": "android.view.View", "merge": "android.view.View", "fragment": "android.view.View",
}


def java_type(tag: str) -> str:
    return FRAMEWORK.get(tag, tag)


def field_name(xml_id: str) -> str:
    head, *rest = xml_id.split("_")
    return head + "".join(p[:1].upper() + p[1:] for p in rest)


def camel_upper(xml_id: str) -> str:
    n = field_name(xml_id)
    return n[:1].upper() + n[1:]


def binding_class(layout: str) -> str:
    return "".join(p[:1].upper() + p[1:] for p in layout.split("_")) + "Binding"


def parse(path: Path) -> ET.ElementTree:
    try:
        return ET.parse(path)
    except ET.ParseError as e:
        raise SystemExit(f"FAIL битый XML {path.relative_to(ROOT)}: {e}")


def all_xml() -> list[Path]:
    return sorted(p for d in ["layout", "values", "values-night", "xml", "drawable", "mipmap"]
                  for p in (RES / d).glob("*.xml") if (RES / d).is_dir())


def layouts() -> list[str]:
    return sorted(p.stem for p in (RES / "layout").glob("*.xml"))


def ids_by_layout() -> dict[str, list[tuple[str, str]]]:
    """layout → [(xml id, java тип)] для полей ViewBinding.

    Корневой id не попадает в поля: у binding'а он уже есть как getRoot().
    """
    out: dict[str, list[tuple[str, str]]] = {}
    for layout in layouts():
        tree = parse(RES / "layout" / f"{layout}.xml")
        pairs: list[tuple[str, str]] = []
        for node in tree.iter():
            rid = node.attrib.get(A + "id", "")
            if not rid.startswith("@+id/"):
                continue
            xml_id = rid[len("@+id/"):]
            if xml_id == "root":
                continue
            pairs.append((xml_id, java_type(node.tag)))
        out[layout] = pairs
    return out


def declared_ids() -> set[str]:
    """Все id, объявленные в разметке (включая корневые) — для проверки ссылок."""
    out: set[str] = set()
    for f in (RES / "layout").glob("*.xml") if (RES / "layout").is_dir() else []:
        out |= set(re.findall(r"@\+id/([a-zA-Z_0-9]+)", f.read_text(encoding="utf-8")))
    return out


def value_resources() -> dict[str, list[str]]:
    """kind → имена, объявленные в values*.xml (с повторами — их ловит проверка дубликатов)."""
    out: dict[str, list[str]] = {k: [] for k in VALUE_KINDS + list(FILE_KINDS)}
    for kind in VALUE_KINDS:
        for d in ("values", "values-night"):
            for f in sorted((RES / d).glob("*.xml")) if (RES / d).is_dir() else []:
                for node in parse(f).getroot():
                    if node.tag == kind:
                        n = node.attrib.get(A + "name") or node.attrib.get("name")
                        if n:
                            out[kind].append(n)
    for kind, dirs in FILE_KINDS.items():
        for d in dirs:
            for f in sorted((RES / d).glob("*.xml")) if (RES / d).is_dir() else []:
                out[kind].append(f.stem)
        for f in sorted((RES / (dirs[0])).glob("*.*")) if (RES / dirs[0]).is_dir() else []:
            out[kind].append(f.stem)
    return {k: v for k, v in out.items()}


SCROLL_LIKE = {"ScrollView", "HorizontalScrollView"}


def check_layout_nesting() -> list[str]:
    """
    Ловит то, что не видит ни aapt2, ни компилятор: разметку, которая роняет приложение при
    старте. ScrollView умеет только одного ребёнка — лишний элемент даёт IllegalStateException
    при инфляции, то есть «приложение сразу закрывается», и никакой журнал этого не покажет.
    Проверяются также дубли `@+id` внутри одного файла (findViewById вернёт не тот view).
    """
    problems: list[str] = []
    for f in sorted((RES / "layout").glob("*.xml")):
        try:
            root = parse(f).getroot()
        except ET.ParseError:
            continue  # про синтаксис скажет общий разбор XML
        for node in root.iter():
            tag = node.tag.split("}")[-1]
            if tag in SCROLL_LIKE and len(list(node)) > 1:
                vid = (node.attrib.get(A + "id") or "").replace("@+id/", "") or "?"
                problems.append(
                    f"layout/{f.name}: {tag} (@id/{vid}) имеет {len(list(node))} детей — "
                    "допустим ровно один (иначе IllegalStateException при запуске)"
                )
        ids = [v.replace("@+id/", "") for v in (n.attrib.get(A + "id") or "" for n in root.iter()) if v]
        duplicates = {i for i in ids if ids.count(i) > 1}
        for d in sorted(duplicates):
            problems.append(f"layout/{f.name}: @+id/{d} объявлен больше одного раза")
    return problems

def check_resources() -> list[str]:
    problems: list[str] = []
    seen: dict[tuple[str, str], str] = {}
    for d in ("values", "values-night"):
        base = RES / d
        for f in sorted(base.glob("*.xml")) if base.is_dir() else []:
            for node in parse(f).getroot():
                if node.tag in VALUE_KINDS:
                    n = node.attrib.get(A + "name") or node.attrib.get("name")
                    if n:
                        key = (node.tag, n)
                        # дубликат в одной конфигурации — aapt2 ругается; в -night это переопределение
                        if key in seen and d == "values" and seen[key].startswith(d):
                            problems.append(f"дубликат @{node.tag}/{n} в {f.name} и {seen[key]}")
                        seen[key] = f"{d}/{f.name}"

    ids_declared = declared_ids()
    values = value_resources()
    names = {k: set(v) for k, v in values.items()}
    names["id"] = ids_declared
    # манифесты: там тоже ссылки на ресурсы (@string/app_name, @style/…, @xml/file_paths)
    manifests = sorted((ROOT / "app/src").glob("*/AndroidManifest.xml"))
    for f in all_xml() + manifests:
        text = f.read_text(encoding="utf-8")
        for kind, name in re.findall(r"@(?:\+)?(string|id|layout|style|dimen|color|drawable|xml|menu|mipmap)/([a-zA-Z_0-9.]+)", text):
            if "." in name:  # @style/Widget.Material3… — ресурс из библиотеки, не отсюда
                continue
            if name not in names.get(kind, set()):
                problems.append(f"{f.relative_to(RES)}: висячая ссылка @{kind}/{name}")

    kt = "\n".join(p.read_text(encoding="utf-8") for d in KOTLIN_DIRS if d.is_dir() for p in d.rglob("*.kt"))
    for kind, name in re.findall(r"(?<![a-zA-Z.])R\.(string|id|layout|style|dimen|color|drawable|xml|menu)\.([a-zA-Z_0-9]+)", kt):
        if name not in names.get(kind, set()):
            problems.append(f"Kotlin: R.{kind}.{name} нигде не определён")
    # foregroundServiceType: приложение имеет право объявить только типы из разрешённого
    # перечисления (проверено по ServiceInfo в android.jar); «vpn» среди них нет — на 34+
    # за него система кидает MissingForegroundServiceTypeException, а aapt2 ругается значением.
    for f in sorted((ROOT / "app/src").glob("*/AndroidManifest.xml")):
        text = f.read_text(encoding="utf-8")
        for value in re.findall(r'android:foregroundServiceType="([^"]+)"', text):
            for part in value.split("|"):
                part = part.strip()
                if part and part not in ALLOWED_FGS_TYPES:
                    problems.append(
                        f"{f.relative_to(ROOT)}: foregroundServiceType=\"{part}\" недопустим для приложения; "
                        f"разрешено: {', '.join(sorted(ALLOWED_FGS_TYPES))}"
                    )
        for value in re.findall(r'android:foregroundServiceType="([^"]+)"', text):
            if "specialUse" in value and "PROPERTY_SPECIAL_USE_FGS_SUBTYPE" not in text:
                problems.append(f"{f.relative_to(ROOT)}: specialUse без подтипа — нужен "
                                "android.app.PROPERTY_SPECIAL_USE_FGS_SUBTYPE (для VPN: vpn)")
            for t_ in value.split("|"):
                perm = "android.permission.FOREGROUND_SERVICE_" + t_.strip().upper()
                if t_.strip() and t_.strip() not in ("none", "manifest") and perm not in text:
                    has_generic = "android.permission.FOREGROUND_SERVICE\" />" in text
                    if not has_generic and "FOREGROUND_SERVICE" not in text:
                        problems.append(f"{f.relative_to(ROOT)}: для типа «{t_.strip()}» не хватает {perm}")
    problems += check_format_strings(kt)
    problems += check_layout_nesting()
    return problems


def strings_map() -> dict[str, str]:
    out: dict[str, str] = {}
    for f in sorted((RES / "values").glob("*.xml")) if (RES / "values").is_dir() else []:
        for node in parse(f).getroot():
            if node.tag == "string":
                n = node.attrib.get("name") or node.attrib.get(A + "name") or ""
                if n:
                    out[n] = (node.text or "").strip()
    return out


def scan_calls(kt: str) -> list[tuple[str, list[str]]]:
    """(имя строки, аргументы) для каждого getString(R.string.x, …) — со сбалансированными скобками."""
    calls: list[tuple[str, list[str]]] = []
    for m in re.finditer(r"getString\(\s*R\.string\.([a-zA-Z_0-9]+)", kt):
        i, depth, args, cur = m.end(), 1, [], ""
        while i < len(kt):
            ch = kt[i]
            if ch == '"':
                j = i + 1
                while j < len(kt):
                    if kt[j] == "\\":
                        j += 2
                        continue
                    if kt[j] == '"':
                        break
                    j += 1
                i = j + 1
                cur += "LIT"  # сам литерал не важен, важно что аргумент есть
                continue
            if ch in "([{":
                depth += 1
            elif ch in ")]}":
                depth -= 1
                if depth == 0:
                    break
            if ch == "," and depth == 1:
                args.append(cur.strip())
                cur = ""
            else:
                cur += ch
            i += 1
        if cur.strip():
            args.append(cur.strip())
        calls.append((m.group(1), [a for a in args if a]))
    return calls


def check_format_strings(kt: str) -> list[str]:
    """getString обязан передать ровно столько аргументов, сколько просит формат.

    Такую ошибку не ловит ни kotlinc (R.string.x — просто Int), ни IDE: приложение падает
    на первом же показе строки. Проверяем и %1$s, и «голые» %s, и одиночный процент,
    который Android тоже считает спецификатором (его надо писать как %%).
    """
    problems: list[str] = []
    strings = strings_map()
    for name, args in scan_calls(kt):
        fmt = strings.get(name)
        if fmt is None:
            continue
        indexed = [int(n) for n in re.findall(r"%(\d+)\$", fmt)]
        positional = re.findall(r"%(?!\d)[sdif]", fmt)
        want = max(indexed) if indexed else len(positional)
        got = len(args)
        if got != want:
            problems.append(f"R.string.{name}: формат ждёт {want} аргумент(а), передано {got} — «{fmt[:70]}»")
        if want:
            for spec in re.findall(r"%(?!\d\$|s\b|d\b|i\b|f\b|%)(.)", fmt):
                problems.append(f"R.string.{name}: «%{spec}» в строке с аргументами — экранируйте как %%, «{fmt[:70]}»")
    return problems


def write_stubs(dirn: Path, declared: dict[str, list[tuple[str, str]]], names: dict[str, set[str]], extra_ids: set[str] = frozenset()) -> list[str]:
    pkg = dirn / "dev/warpscout/app"
    (pkg / "databinding").mkdir(parents=True, exist_ok=True)
    dirn.mkdir(parents=True, exist_ok=True)
    written: list[str] = []

    r = ["// Сгенерировано tools/android_stub_check.py — не править вручную.",
         "package dev.warpscout.app;", "", "public final class R {", "    private R() {}"]
    kinds: dict[str, set[str]] = dict(names)
    kinds["id"] = {i for pairs in declared.values() for i, _ in pairs} | set(extra_ids)
    for kind in sorted(kinds):
        if not kinds[kind]:
            continue
        r.append(f"    public static final class {kind} {{")
        r.append(f"        private {kind}() {{}}")
        for i, n in enumerate(sorted(kinds[kind])):
            r.append(f"        public static final int {n} = 0x7f0a{i:04d};")
        r.append("    }")
    r.append("}")
    path = pkg / "R.java"
    path.write_text("\n".join(r) + "\n", encoding="utf-8")
    written.append(str(path))

    for layout, pairs in declared.items():
        tree = parse(RES / "layout" / f"{layout}.xml")
        root_type = java_type(tree.getroot().tag)
        cls = binding_class(layout)
        b = [f"// Сгенерировано: поля = id из разметки, типы = теги view.",
             "package dev.warpscout.app.databinding;", "",
             f"public final class {cls} {{",
             f"    private final {root_type} root;"]
        for name, t in pairs:
            b.append(f"    private {t} {field_name(name)};")
        b += ["", f"    private {cls}({root_type} root, android.view.View finder) {{",
              f"        this.root = root;"]
        for name, t in pairs:
            b.append(f"        this.{field_name(name)} = ({t}) finder.findViewById(R.id.{name});")
        b.append("    }")
        b.append("")
        b.append(f"    public {root_type} getRoot() {{ return root; }}")
        for name, t in pairs:
            getter, setter = f"get{camel_upper(name)}", f"set{camel_upper(name)}"
            b.append(f"    public {t} {getter}() {{ return {field_name(name)}; }}")
            b.append(f"    public void {setter}({t} v) {{ this.{field_name(name)} = v; }}")
        b += ["", f"    public static {cls} inflate(android.view.LayoutInflater in) {{",
              f"        android.view.View v = in.inflate(R.layout.{layout}, null);",
              f"        return new {cls}(({root_type}) v, v);", "    }",
              f"    public static {cls} bind(android.view.View v) {{ return new {cls}(({root_type}) v, v); }}",
              "}"]
        p2 = pkg / "databinding" / f"{cls}.java"
        p2.write_text("\n".join(b) + "\n", encoding="utf-8")
        written.append(str(p2))
    return written


def compile_flavor(flavor: str, kotlinc: str, cp: str, stubs: list[str], out: str) -> int:
    """Один flavor за раз: TunnelFactory объявлен в каждом по-своему, вместе они конфликтуют."""
    dirs = [ROOT / "core/src/main/kotlin", ROOT / "app/src/main/kotlin", ROOT / f"app/src/{flavor}/kotlin"]
    sources = [str(p) for d in dirs for p in sorted(d.rglob("*.kt")) if d.is_dir()] + stubs
    cmd = [kotlinc, "-nowarn", "-jvm-target", "1.8", "-cp", cp, *sources, "-d", out]
    print(f"[{flavor}] компиляция {len(sources)} файлов …")
    proc = subprocess.run(cmd, capture_output=True, text=True)
    lines = (proc.stdout + proc.stderr).splitlines()
    errors = [l for l in lines if ": error:" in l]
    for line in errors[:80]:
        print("  " + line)
    if errors:
        print(f"[{flavor}] ОШИБОК КОМПИЛЯЦИИ: {len(errors)}")
        return 1
    warns = [l for l in lines if ": warning:" in l]
    print(f"[{flavor}] компиляция OK (предупреждений: {len(warns)})")
    for w in warns[:8]:
        print("   note:", w[w.index("warning:") + 9:][:150])
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--android-jar", default=os.environ.get("ANDROID_JAR", ""))
    ap.add_argument("--jar-dir", default=os.environ.get("ANDROID_JARS", ""))
    ap.add_argument("--kotlinc", default=os.environ.get("KOTLINC", ""))
    ap.add_argument("--compile", action="store_true")
    # Никаких личных путей: по умолчанию — временный каталог, который есть на любой машине
    # (раньше здесь стоял /home/user/... и CI на чистом раннере падал с FileNotFoundError).
    ap.add_argument("--stub-dir", default=str(Path(tempfile.mkdtemp(prefix="warpscout-stubs-"))))
    ap.add_argument("--out", default=str(Path(tempfile.mkdtemp(prefix="warpscout-out-"))))
    ap.add_argument("--flavors", default="scout,tunnel")
    args = ap.parse_args()

    declared = ids_by_layout()
    all_ids = declared_ids()
    values = value_resources()
    print(f"layout'ов: {len(declared)}, id: {sum(len(v) for v in declared.values())}, "
          f"строк: {len(values.get('string', []))}, dimen: {len(values.get('dimen', []))}")
    problems = check_resources()
    for p in problems:
        print("FAIL", p)
    print("ресурсы:", "OK" if not problems else f"{len(problems)} проблем")

    stubs = write_stubs(Path(args.stub_dir), declared, {k: set(v) for k, v in values.items()}, all_ids)
    print("заглушки:", ", ".join(Path(s).name for s in stubs))
    if not args.compile:
        return 1 if problems else 0
    if not (args.kotlinc and (args.android_jar or args.jar_dir)):
        print("FAIL --compile требует --kotlinc и --android-jar (или --jar-dir)")
        return 2
    jars = ([args.android_jar] if args.android_jar else [])
    if args.jar_dir:
        jars += sorted(str(p) for p in Path(args.jar_dir).glob("*.jar"))
    if args.android_jar and args.jar_dir:
        jars = [str(p) for p in Path(args.jar_dir).glob("*.jar") if "android.jar" not in p.name] + [args.android_jar]
    cp = ":".join(dict.fromkeys(jars))
    rc = 0
    for i, flavor in enumerate(args.flavors.split(",")):
        rc |= compile_flavor(flavor.strip(), args.kotlinc, cp, stubs, f"{args.out}-{flavor.strip()}")
    return rc or (1 if problems else 0)


if __name__ == "__main__":
    sys.exit(main())
