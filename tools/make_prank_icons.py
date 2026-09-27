#!/usr/bin/env python3
"""Иконка пранка six seven triple t — неоновые «67» в семисегментном стиле
с циановым глитч-смещением. Чистый Python, как и tools/make_icons.py."""

from __future__ import annotations

import os
import struct
import zlib

BG = (10, 10, 13, 255)
BG_EDGE = (40, 10, 32, 255)
PINK = (255, 47, 126, 255)
CYAN = (54, 224, 224, 140)  # полупрозрачная тень

SIZES = {
    "mipmap-mdpi": 48,
    "mipmap-hdpi": 72,
    "mipmap-xhdpi": 96,
    "mipmap-xxhdpi": 144,
    "mipmap-xxxhdpi": 192,
}

SS = 4

SEG = {
    "a": (0.18, 0.04, 0.82, 0.13),
    "b": (0.88, 0.08, 0.97, 0.47),
    "c": (0.88, 0.53, 0.97, 0.92),
    "d": (0.18, 0.87, 0.82, 0.96),
    "e": (0.03, 0.53, 0.12, 0.92),
    "f": (0.03, 0.08, 0.12, 0.47),
    "g": (0.18, 0.455, 0.82, 0.545),
}
DIGITS = {
    "6": "acdefg",
    "7": "abc",
}


def blend(dst, src):
    a = src[3] / 255.0
    return (
        round(dst[0] * (1 - a) + src[0] * a),
        round(dst[1] * (1 - a) + src[1] * a),
        round(dst[2] * (1 - a) + src[2] * a),
        255 if dst[3] else src[3],
    )


def rect(px, w, h, x0, y0, x1, y1, r, color):
    for y in range(max(0, int(y0)), min(h - 1, int(y1)) + 1):
        for x in range(max(0, int(x0)), min(w - 1, int(x1)) + 1):
            cx = min(max(x, x0 + r), x1 - r)
            cy = min(max(y, y0 + r), y1 - r)
            if (x - cx) ** 2 + (y - cy) ** 2 <= r * r:
                px[y][x] = blend(px[y][x], color)


def digit(px, w, h, ox, oy, dw, dh, which, color):
    for s in DIGITS[which]:
        x0, y0, x1, y1 = SEG[s]
        rect(px, w, h,
             ox + x0 * dw, oy + y0 * dh,
             ox + x1 * dw, oy + y1 * dh,
             dw * 0.06, color)


def render(size):
    w = h = size * SS
    px = [[(0, 0, 0, 0)] * w for _ in range(h)]
    rect(px, w, h, 0, 0, w - 1, h - 1, w * 0.22, BG_EDGE)
    rect(px, w, h, w * 0.015, w * 0.015, w - 1 - w * 0.015, h - 1 - w * 0.015, w * 0.215, BG)

    dw = w * 0.30
    dh = h * 0.62
    oy = h * 0.19
    ox6 = w * 0.10
    ox7 = w * 0.55
    off = w * 0.025
    # циановая глитч-тень чуть сбоку
    digit(px, w, h, ox6 - off, oy + off, dw, dh, "6", CYAN)
    digit(px, w, h, ox7 - off, oy + off, dw, dh, "7", CYAN)
    # основной розовый
    digit(px, w, h, ox6, oy, dw, dh, "6", PINK)
    digit(px, w, h, ox7, oy, dw, dh, "7", PINK)

    out = []
    for y in range(size):
        row = []
        for x in range(size):
            r = g = b = a = 0
            for dy in range(SS):
                for dx in range(SS):
                    p = px[y * SS + dy][x * SS + dx]
                    r += p[0] * p[3]
                    g += p[1] * p[3]
                    b += p[2] * p[3]
                    a += p[3]
            n = SS * SS
            row.append((0, 0, 0, 0) if a == 0 else (round(r / a), round(g / a), round(b / a), round(a / n)))
        out.append(row)
    return out


def write_png(path, rows):
    size = len(rows)
    raw = bytearray()
    for row in rows:
        raw.append(0)
        for p in row:
            raw += bytes(p)

    def chunk(tag, data):
        return struct.pack(">I", len(data)) + tag + data + struct.pack(
            ">I", zlib.crc32(tag + data) & 0xFFFFFFFF)

    png = b"\x89PNG\r\n\x1a\n"
    png += chunk(b"IHDR", struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0))
    png += chunk(b"IDAT", zlib.compress(bytes(raw), 9))
    png += chunk(b"IEND", b"")
    with open(path, "wb") as fh:
        fh.write(png)


def main():
    base = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        "android", "prank", "src", "main", "res")
    for folder, size in SIZES.items():
        target = os.path.join(base, folder)
        os.makedirs(target, exist_ok=True)
        write_png(os.path.join(target, "ic_launcher.png"), render(size))
        print(f"{folder}/ic_launcher.png  {size}×{size}")


if __name__ == "__main__":
    main()
