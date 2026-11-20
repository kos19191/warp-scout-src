"""Рендер знака WarpScout из векторных файлов Android в PNG.

Нужен, чтобы превью в документации совпадало с иконкой в APK: читается тот же
`app/src/main/res/drawable/ic_fox_shield*.xml`. Поддержаны `group` (масштаб вокруг pivot),
`fillType="evenOdd"` (дырки) и простые `stroke`-линии.
"""

import re

from PIL import Image, ImageChops, ImageDraw

SCALE = 6


def parse_path(data):
    """pathData → список подпутей; каждый подпуть — список точек."""
    tokens = re.findall(r"[MLHVCZmlhvcz]|-?\d*\.?\d+", data)
    subpaths, cur, start, cmd, i = [], [], (0.0, 0.0), None, 0

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
                if cur:
                    subpaths.append(cur)
                cur, start = [], start
                continue
        if cmd in "Mm":
            if cur:
                subpaths.append(cur)
            cur = []
            start = (num(), num())
            cur.append(start)
            cmd = "L" if cmd == "M" else "l"
        elif cmd in "Ll":
            cur.append((num(), num()))
        elif cmd in "Hh":
            cur.append((num(), cur[-1][1] if cur else start[1]))
        elif cmd in "Vv":
            cur.append((cur[-1][0] if cur else start[0], num()))
        elif cmd in "Cc":
            p0 = cur[-1]
            p1 = (num(), num())
            p2 = (num(), num())
            p3 = (num(), num())
            for k in range(1, 25):
                t = k / 24
                u = 1 - t
                cur.append((
                    u ** 3 * p0[0] + 3 * u * u * t * p1[0] + 3 * u * t * t * p2[0] + t ** 3 * p3[0],
                    u ** 3 * p0[1] + 3 * u * u * t * p1[1] + 3 * u * t * t * p2[1] + t ** 3 * p3[1],
                ))
        else:
            raise SystemExit(f"неизвестная команда пути: {cmd}")
    if cur:
        subpaths.append(cur)
    return subpaths


def color(value, alpha=1.0):
    value = value.lstrip("#")
    r, g, b = (int(value[i:i + 2], 16) for i in (0, 2, 4))
    return (r, g, b, int(round(alpha * 255)))


def mask_for(subpaths, size_px, even_odd):
    mask = Image.new("L", (size_px, size_px), 0)
    for idx, sub in enumerate(subpaths):
        if len(sub) < 3:
            continue
        tmp = Image.new("L", (size_px, size_px), 0)
        ImageDraw.Draw(tmp).polygon([(x * SCALE, y * SCALE) for x, y in sub], fill=255)
        if idx == 0 or not even_odd:
            mask = ImageChops.lighter(mask, tmp)
        else:
            # evenOdd = XOR: для двоичных масок (0/255) это |a−b|.
            mask = ImageChops.difference(mask, tmp)
    return mask


def render(xml_path, out_path, background=(20, 17, 15, 255)):
    xml = open(xml_path, encoding="utf-8").read()
    size = int(re.search(r'viewportWidth="(\d+)"', xml).group(1))
    px = size * SCALE

    group = re.search(r"<group[^>]*>", xml, re.S)
    scale, pivot = 1.0, (size / 2, size / 2)
    if group:
        g = group.group(0)
        m = re.search(r'android:scaleX="([\d.]+)"', g)
        if m:
            scale = float(m.group(1))
        mx = re.search(r'android:pivotX="([\d.]+)"', g)
        my = re.search(r'android:pivotY="([\d.]+)"', g)
        pivot = (float(mx.group(1)) if mx else pivot[0], float(my.group(1)) if my else pivot[1])

    def place(subpaths):
        return [[(pivot[0] + (x - pivot[0]) * scale, pivot[1] + (y - pivot[1]) * scale) for x, y in sub]
                for sub in subpaths]

    img = Image.new("RGBA", (px, px), background)
    for path in re.findall(r"<path[^>]*/>", xml, re.S):
        data = re.search(r'android:pathData="([^"]+)"', path).group(1)
        subpaths = place(parse_path(data))
        fill = re.search(r'android:fillColor="([^"]+)"', path)
        even = 'fillType="evenOdd"' in path
        stroke = re.search(r'android:strokeColor="([^"]+)"', path)
        width = re.search(r'android:strokeWidth="([\d.]+)"', path)

        if fill:
            mask = mask_for(subpaths, px, even)
            layer = Image.new("RGBA", (px, px), color(fill.group(1)))
            layer.putalpha(mask)
            img = Image.alpha_composite(img, layer)
        if stroke and width:
            layer = Image.new("RGBA", (px, px), (0, 0, 0, 0))
            d = ImageDraw.Draw(layer)
            for sub in subpaths:
                d.line([(x * SCALE, y * SCALE) for x, y in sub], fill=color(stroke.group(1)),
                       width=int(float(width.group(1)) * SCALE), joint="curve")
            img = Image.alpha_composite(img, layer)

    img.resize((512, 512), Image.LANCZOS).save(out_path)
    img.resize((96, 96), Image.LANCZOS).save(out_path.replace(".png", "-small.png"))
    print("готово:", out_path)


if __name__ == "__main__":
    render("app/src/main/res/drawable/ic_fox_shield.xml", "docs/warpscout-icon.png")
    render("app/src/main/res/drawable/ic_fox_shield_mono.xml", "docs/warpscout-icon-mono.png",
           background=(250, 247, 243, 255))
