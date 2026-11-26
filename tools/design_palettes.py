#!/usr/bin/env python3
"""
Цвета и темы дизайнов «Нежный» и «Стекло» (с 1.10.49-beta8).

Палитры выводятся из нескольких исходных цветов на оттенок — так же, как в живом макете
(design/mockup/designs.js), поэтому приложение и макет выглядят одинаково. Скрипт пишет:

  app/src/main/res/values/colors_designs.xml        — светлая тема
  app/src/main/res/values-night/colors_designs.xml  — тёмная тема
  app/src/main/res/values/themes_designs.xml        — темы окна: по одной на оттенок и «…Welcome»

Править цвета — здесь, потом запустить:  python3 tools/design_palettes.py
"""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RES = ROOT / "app/src/main/res"

# «Нежный»: пастель для заливок, глубокий оттенок того же цвета для текста и значков, цвет-напарник.
SOFT = [
    ("lavender", "Лаванда", "#C9B8F2", "#6B55C0", "#F4BCD2"),
    ("mint", "Мята", "#A9E4D0", "#2E8A6E", "#B5D3F5"),
    ("peach", "Персик", "#FFCAB0", "#C8633A", "#F7C2D4"),
    ("sky", "Небо", "#B3D1F6", "#3A73BD", "#CBBDF3"),
    ("rose", "Роза", "#F6BED2", "#BD4C77", "#FFD3B8"),
    ("vanilla", "Ваниль", "#F2DE9A", "#94700C", "#B5E5D3"),
]

# «Стекло»: два неоновых цвета; для светлой темы — их насыщенные тёмные варианты.
GLASS = [
    ("cyber", "Киберпанк", "#22E1FF", "#FF3DF2", "#0096B8", "#C215B8"),
    ("aurora", "Аврора", "#3DFFB0", "#4D8DFF", "#0E9F6E", "#2E63D6"),
    ("sunset", "Закат", "#FF4D8D", "#FFB443", "#DB2266", "#D97706"),
    ("violet", "Ультрафиолет", "#A066FF", "#38CFFF", "#7434E0", "#0284C7"),
    ("acid", "Кислота", "#C8FF3D", "#2BF5D0", "#4D8A06", "#0B8F80"),
]


def rgb(c):
    c = c.lstrip("#")
    return tuple(int(c[i:i + 2], 16) for i in (0, 2, 4))


def mix(a, b, t):
    x, y = rgb(a), rgb(b)
    return "#%02X%02X%02X" % tuple(round(x[i] + (y[i] - x[i]) * t) for i in range(3))


def alpha(c, a):
    """#AARRGGBB — цвет с прозрачностью a (0..1)."""
    return "#%02X%s" % (round(a * 255), c.lstrip("#").upper())


def soft(p, d, q, dark):
    if not dark:
        ink = mix(d, "#1D1A26", 0.72)
        bg0, bg1 = mix(p, "#FFFFFF", 0.90), mix(p, "#FFFFFF", 0.78)
        return {
            "accent": d, "accent_deep": mix(d, "#000000", 0.12), "accent_light": p, "partner": q,
            "neon_a": p, "neon_b": q, "on_accent": "#FFFFFF",
            "accent_container": mix(p, "#FFFFFF", 0.45), "on_accent_container": mix(d, "#000000", 0.35),
            "tonal": mix(p, "#FFFFFF", 0.55), "on_tonal": mix(d, "#000000", 0.2),
            "bg0": bg0, "bg1": bg1, "surface": bg0, "surface_lowest": "#FFFFFF",
            "surface_low": mix(p, "#FFFFFF", 0.86), "surface_cont": mix(p, "#FFFFFF", 0.80),
            "surface_high": mix(p, "#FFFFFF", 0.72), "surface_variant": mix(p, "#FFFFFF", 0.70),
            "on_surface": ink, "on_surface_variant": mix(ink, "#FFFFFF", 0.38), "outline": mix(ink, "#FFFFFF", 0.58),
            "outline_variant": mix(p, "#FFFFFF", 0.35), "error": "#C2415A",
            "card": alpha("#FFFFFF", 0.80), "card_stroke": alpha(d, 0.12), "nav": alpha("#FFFFFF", 0.86),
            "button_bg": p, "button_text": mix(d, "#1D1A26", 0.6),
            "disc_a": "#FFFFFF", "disc_b": mix(p, "#FFFFFF", 0.55), "ring_off": mix(p, "#FFFFFF", 0.35), "core": "#FFFFFF",
            "map_bg": mix(p, "#FFFFFF", 0.82), "map_block": mix(p, "#FFFFFF", 0.45), "map_road": alpha("#FFFFFF", 0.95),
            "route_core": "#FFFFFF", "blue": "#5B93D1",
        }
    bg = mix(d, "#15131C", 0.82)
    return {
        "accent": p, "accent_deep": mix(p, d, 0.35), "accent_light": mix(p, "#FFFFFF", 0.4), "partner": q,
        "neon_a": p, "neon_b": q, "on_accent": "#221F2B",
        "accent_container": mix(d, bg, 0.55), "on_accent_container": mix(p, "#FFFFFF", 0.5),
        "tonal": mix(p, bg, 0.82), "on_tonal": mix(p, "#FFFFFF", 0.3),
        "bg0": bg, "bg1": mix(d, "#1C1A26", 0.72), "surface": bg, "surface_lowest": mix(bg, "#000000", 0.2),
        "surface_low": mix(bg, "#FFFFFF", 0.03), "surface_cont": mix(bg, "#FFFFFF", 0.06),
        "surface_high": mix(bg, "#FFFFFF", 0.10), "surface_variant": mix(bg, p, 0.12),
        "on_surface": mix(p, "#FFFFFF", 0.82), "on_surface_variant": mix(p, "#A7A2B4", 0.7),
        "outline": mix(p, "#6F6A7C", 0.75), "outline_variant": mix(bg, p, 0.2), "error": "#F28B9A",
        "card": alpha("#FFFFFF", 0.06), "card_stroke": alpha("#FFFFFF", 0.09), "nav": alpha(bg, 0.92),
        "button_bg": p, "button_text": "#221F2B",
        "disc_a": mix(bg, p, 0.12), "disc_b": mix(bg, "#000000", 0.15), "ring_off": mix(bg, p, 0.2),
        "core": mix(p, "#FFFFFF", 0.75),
        "map_bg": mix(bg, "#000000", 0.2), "map_block": mix(bg, p, 0.16), "map_road": alpha(p, 0.16),
        "route_core": mix(p, "#FFFFFF", 0.75), "blue": "#9CC3F2",
    }


def glass(a, b, la, lb, dark):
    if dark:
        return {
            "accent": a, "accent_deep": b, "accent_light": mix(a, "#FFFFFF", 0.45), "partner": b,
            "neon_a": a, "neon_b": b, "on_accent": "#0A0A16",
            "accent_container": mix(a, "#07070D", 0.78), "on_accent_container": mix(a, "#FFFFFF", 0.55),
            "tonal": mix(a, "#0E0D1A", 0.84), "on_tonal": mix(a, "#FFFFFF", 0.45),
            "bg0": "#07070D", "bg1": "#0E0D1A", "surface": "#07070D", "surface_lowest": "#050509",
            "surface_low": "#10101C", "surface_cont": "#141424", "surface_high": "#1A1A2E", "surface_variant": "#1C1C30",
            "on_surface": "#F3F4FF", "on_surface_variant": "#AAB0CC", "outline": "#6F7594",
            "outline_variant": "#2A2B40", "error": "#FF5470",
            "card": alpha("#FFFFFF", 0.07), "card_stroke": alpha("#FFFFFF", 0.16), "nav": alpha("#0E0E1C", 0.78),
            "button_bg": a, "button_text": "#0A0A16",
            "disc_a": alpha("#FFFFFF", 0.13), "disc_b": alpha("#FFFFFF", 0.025), "ring_off": alpha("#FFFFFF", 0.20),
            "core": "#FFFFFF",
            "map_bg": "#08080F", "map_block": "#151528", "map_road": alpha(b, 0.16), "route_core": "#FFFFFF", "blue": b,
        }
    return {
        "accent": la, "accent_deep": lb, "accent_light": a, "partner": lb,
        "neon_a": a, "neon_b": b, "on_accent": "#FFFFFF",
        "accent_container": mix(a, "#FFFFFF", 0.78), "on_accent_container": mix(la, "#000000", 0.45),
        "tonal": mix(a, "#FFFFFF", 0.84), "on_tonal": mix(la, "#000000", 0.3),
        "bg0": "#EEF0F9", "bg1": "#E3E6F5", "surface": "#EEF0F9", "surface_lowest": "#FFFFFF",
        "surface_low": "#F5F6FC", "surface_cont": "#E9EBF6", "surface_high": "#E1E4F2", "surface_variant": "#E1E4F2",
        "on_surface": "#13152B", "on_surface_variant": "#50567A", "outline": "#8A90AE",
        "outline_variant": "#CDD2E6", "error": "#E11D48",
        "card": alpha("#FFFFFF", 0.72), "card_stroke": alpha("#1E285A", 0.10), "nav": alpha("#FFFFFF", 0.82),
        "button_bg": mix(la, "#000000", 0.1), "button_text": "#FFFFFF",
        "disc_a": alpha("#FFFFFF", 0.85), "disc_b": alpha("#FFFFFF", 0.35), "ring_off": alpha("#1E285A", 0.14),
        "core": "#FFFFFF",
        "map_bg": "#E8EBF7", "map_block": "#D5DAF0", "map_road": alpha("#FFFFFF", 0.95), "route_core": "#FFFFFF", "blue": lb,
    }


# Атрибуты темы → роль палитры. Material — цвета компонентов; ws* — то, что код рисует сам (attrs.xml).
THEME_ITEMS = [
    ("colorPrimary", "accent"), ("colorOnPrimary", "on_accent"),
    ("colorPrimaryContainer", "accent_container"), ("colorOnPrimaryContainer", "on_accent_container"),
    ("colorSecondary", "accent_deep"), ("colorSecondaryContainer", "tonal"), ("colorOnSecondaryContainer", "on_tonal"),
    ("android:colorBackground", "bg0"), ("colorSurface", "surface"), ("colorOnSurface", "on_surface"),
    ("colorSurfaceVariant", "surface_variant"), ("colorOnSurfaceVariant", "on_surface_variant"),
    ("colorSurfaceContainerLowest", "surface_lowest"), ("colorSurfaceContainerLow", "surface_low"),
    ("colorSurfaceContainer", "surface_cont"), ("colorSurfaceContainerHigh", "surface_high"),
    ("colorOutline", "outline"), ("colorOutlineVariant", "outline_variant"), ("colorError", "error"),
    ("android:statusBarColor", "bg1"), ("android:navigationBarColor", "bg1"),
    ("wsCardBg", "card"), ("wsCardStroke", "card_stroke"), ("wsPanelBg", "card"), ("wsPanelStroke", "card_stroke"),
    ("wsNavBg", "nav"), ("wsButtonBg", "button_bg"), ("wsButtonText", "button_text"),
    ("wsAccent", "accent"), ("wsAccentDeep", "accent_deep"), ("wsAccentLight", "accent_light"),
    ("wsPartner", "partner"), ("wsNeonA", "neon_a"), ("wsNeonB", "neon_b"),
    ("wsOnSurface", "on_surface"), ("wsOnSurfaceVariant", "on_surface_variant"), ("wsOutline", "outline"),
    ("wsError", "error"), ("wsBlue", "blue"), ("wsBg0", "bg0"), ("wsBg1", "bg1"),
    ("wsDiscA", "disc_a"), ("wsDiscB", "disc_b"), ("wsRingOff", "ring_off"), ("wsCore", "core"),
    ("wsMapBg", "map_bg"), ("wsMapBlock", "map_block"), ("wsMapRoad", "map_road"), ("wsRouteCore", "route_core"),
]

HEAD = "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<!-- Сгенерировано tools/design_palettes.py — правьте там и запустите скрипт заново. -->\n"


def palettes():
    out = []
    for tid, name, p, d, q in SOFT:
        out.append(("soft", tid, name, soft(p, d, q, False), soft(p, d, q, True)))
    for tid, name, a, b, la, lb in GLASS:
        out.append(("glass", tid, name, glass(a, b, la, lb, False), glass(a, b, la, lb, True)))
    return out


def colors_xml(dark):
    lines = [HEAD + "<resources>"]
    for design, tid, name, light, night in palettes():
        pal = night if dark else light
        lines.append("    <!-- %s · %s -->" % ("Нежный" if design == "soft" else "Стекло", name))
        for role, value in pal.items():
            lines.append('    <color name="%s_%s_%s">%s</color>' % (design, tid, role, value))
    lines.append("</resources>\n")
    return "\n".join(lines)


def themes_xml():
    lines = [HEAD + "<resources xmlns:tools=\"http://schemas.android.com/tools\">"]
    for design, tid, name, light, night in palettes():
        base = "Theme.WarpScout.Soft" if design == "soft" else "Theme.WarpScout.Glass"
        style = "%s.%s" % (base, tid.capitalize())
        lines.append("")
        lines.append("    <!-- %s · %s -->" % ("Нежный" if design == "soft" else "Стекло", name))
        lines.append('    <style name="%s" parent="%s">' % (style, base))
        for attr, role in THEME_ITEMS:
            target = ' tools:targetApi="l"' if attr in ("android:statusBarColor", "android:navigationBarColor") else ""
            lines.append('        <item name="%s"%s>@color/%s_%s_%s</item>' % (attr, target, design, tid, role))
        lines.append("    </style>")
        lines.append('    <style name="%s.Welcome" parent="%s">' % (style, style))
        lines.append('        <item name="android:windowIsFloating">false</item>')
        lines.append('        <item name="android:windowBackground">@color/%s_%s_bg0</item>' % (design, tid))
        lines.append('        <item name="android:windowSoftInputMode">adjustResize</item>')
        lines.append('        <item name="android:windowAnimationStyle">@android:style/Animation.Dialog</item>')
        lines.append("    </style>")
    lines.append("</resources>\n")
    return "\n".join(lines)


def main():
    (RES / "values/colors_designs.xml").write_text(colors_xml(False), encoding="utf-8")
    (RES / "values-night/colors_designs.xml").write_text(colors_xml(True), encoding="utf-8")
    (RES / "values/themes_designs.xml").write_text(themes_xml(), encoding="utf-8")
    print("палитры: %d оттенков, %d цветов на тему" % (len(palettes()), len(palettes()[0][3])))


if __name__ == "__main__":
    main()
