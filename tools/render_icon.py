"""Одноразовый рендер знака WarpScout в PNG (для превью в docs).

Читает настоящий app/src/main/res/drawable/ic_fox_shield.xml и рисует его через PIL —
чтобы превью в документации совпадало с тем, что попадает в APK.
"""

import re

from PIL import Image, ImageDraw

SCALE = 6


def parse_path(data):
    tokens = re.findall(r"[MLHVCZmlhvcz]|-?\d*\.?\d+", data)
    pts, i, cmd, cur, start = [], 0, None, (0.0, 0.0), (0.0, 0.0)

    def num():
        nonlocal i
        v = float(tokens[i])
        i += 1
        return v

    while i < len(tokens):
        if re.match(r"^[A-Za-z]$", tokens[i]):
            cmd = tokens[i]
            i += 1
            if cmd in "Zz":
                cur = start
                continue
        if cmd in "Mm":
            cur = (num(), num())
            start = cur
            pts.append(cur)
            cmd = "L" if cmd == "M" else "l"
        elif cmd in "Ll":
            cur = (num(), num())
            pts.append(cur)
        elif cmd in "Hh":
            cur = (num(), cur[1])
            pts.append(cur)
        elif cmd in "Vv":
            cur = (cur[0], num())
            pts.append(cur)
        elif cmd in "Cc":
            p1 = (num(), num())
            p2 = (num(), num())
            p3 = (num(), num())
            for k in range(1, 25):
                t = k / 24
                u = 1 - t
                pts.append((
                    u ** 3 * cur[0] + 3 * u * u * t * p1[0] + 3 * u * t * t * p2[0] + t ** 3 * p3[0],
                    u ** 3 * cur[1] + 3 * u * u * t * p1[1] + 3 * u * t * t * p2[1] + t ** 3 * p3[1],
                ))
            cur = p3
        else:
            raise SystemExit(f"неизвестная команда пути: {cmd}")
    return pts


def color(value, alpha=1.0):
    value = value.lstrip("#")
    r, g, b = (int(value[i:i + 2], 16) for i in (0, 2, 4))
    return (r, g, b, int(round(alpha * 255)))


def render(xml_path, out_path, background=(20, 17, 15, 255)):
    xml = open(xml_path, encoding="utf-8").read()
    size = int(re.search(r'viewportWidth="(\d+)"', xml).group(1))
    img = Image.new("RGBA", (size * SCALE, size * SCALE), background)

    for path in re.findall(r"<path[^>]*/>", xml, re.S):
        data = re.search(r'android:pathData="([^"]+)"', path).group(1)
        stroke = re.search(r'android:strokeColor="([^"]+)"', path)
        width = re.search(r'android:strokeWidth="([\d.]+)"', path)
        fill = re.search(r'android:fillColor="([^"]+)"', path)
        falpha = re.search(r'android:fillAlpha="([\d.]+)"', path)
        salpha = re.search(r'android:strokeAlpha="([\d.]+)"', path)

        line = [(x * SCALE, y * SCALE) for x, y in parse_path(data)]
        layer = Image.new("RGBA", img.size, (0, 0, 0, 0))
        d = ImageDraw.Draw(layer)
        if stroke and width:
            d.line(line, fill=color(stroke.group(1), float(salpha.group(1)) if salpha else 1.0),
                   width=int(float(width.group(1)) * SCALE), joint="curve")
        if fill:
            d.polygon(line, fill=color(fill.group(1), float(falpha.group(1)) if falpha else 1.0))
        img = Image.alpha_composite(img, layer)

    img.resize((512, 512), Image.LANCZOS).save(out_path)
    print("готово:", out_path)


if __name__ == "__main__":
    render("app/src/main/res/drawable/ic_fox_shield.xml", "docs/warpscout-icon.png")
