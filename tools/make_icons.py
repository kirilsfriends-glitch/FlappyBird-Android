#!/usr/bin/env python3
"""Генератор иконок приложения — чистый Python (zlib + struct), без зависимостей.

Рисует «三» нефритового цвета на тёмном скруглённом квадрате и раскладывает
PNG по плотностям mipmap-*. Сглаживание — через рендер в 4× и усреднение.
"""

from __future__ import annotations

import os
import struct
import zlib

BG = (11, 18, 16, 255)        # #0B1210
BG_EDGE = (24, 48, 36, 255)   # рамка
JADE = (63, 185, 138, 255)    # #3FB98A
JADE_LIGHT = (127, 224, 184, 255)

SIZES = {
    "mipmap-mdpi": 48,
    "mipmap-hdpi": 72,
    "mipmap-xhdpi": 96,
    "mipmap-xxhdpi": 144,
    "mipmap-xxxhdpi": 192,
}

SS = 4  # суперсэмплинг


def blend(dst, src):
    a = src[3] / 255.0
    return (
        round(dst[0] * (1 - a) + src[0] * a),
        round(dst[1] * (1 - a) + src[1] * a),
        round(dst[2] * (1 - a) + src[2] * a),
        255,
    )


def rounded_rect(px, w, h, x0, y0, x1, y1, r, color):
    for y in range(max(0, int(y0)), min(h, int(y1) + 1)):
        for x in range(max(0, int(x0)), min(w, int(x1) + 1)):
            cx = min(max(x, x0 + r), x1 - r)
            cy = min(max(y, y0 + r), y1 - r)
            if (x - cx) ** 2 + (y - cy) ** 2 <= r * r:
                px[y][x] = blend(px[y][x], color)


def render(size: int):
    w = h = size * SS
    px = [[(0, 0, 0, 0)] * w for _ in range(h)]
    # фон-плитка со скруглением
    pad = w * 0.02
    rounded_rect(px, w, h, pad, pad, w - 1 - pad, h - 1 - pad, w * 0.22, BG_EDGE)
    pad2 = w * 0.035
    rounded_rect(px, w, h, pad2, pad2, w - 1 - pad2, h - 1 - pad2, w * 0.205, BG)

    # три черты
    bars = (
        (0.265, 0.735, 0.325, JADE),
        (0.335, 0.665, 0.470, JADE_LIGHT),
        (0.235, 0.765, 0.615, JADE),
    )
    thick = w * 0.062
    for left, right, cy, color in bars:
        y0 = cy * h - thick / 2
        rounded_rect(px, w, h, left * w, y0, right * w, y0 + thick, thick / 2, color)

    # даунсэмплинг
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
            if a == 0:
                row.append((0, 0, 0, 0))
            else:
                row.append((round(r / a), round(g / a), round(b / a), round(a / n)))
        out.append(row)
    return out


def write_png(path: str, rows):
    size = len(rows)
    raw = bytearray()
    for row in rows:
        raw.append(0)
        for p in row:
            raw += bytes(p)

    def chunk(tag: bytes, data: bytes) -> bytes:
        return (
            struct.pack(">I", len(data))
            + tag
            + data
            + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)
        )

    png = b"\x89PNG\r\n\x1a\n"
    png += chunk(b"IHDR", struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0))
    png += chunk(b"IDAT", zlib.compress(bytes(raw), 9))
    png += chunk(b"IEND", b"")
    with open(path, "wb") as fh:
        fh.write(png)


def main() -> None:
    base = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        "android", "app", "src", "main", "res")
    for folder, size in SIZES.items():
        target = os.path.join(base, folder)
        os.makedirs(target, exist_ok=True)
        rows = render(size)
        write_png(os.path.join(target, "ic_launcher.png"), rows)
        write_png(os.path.join(target, "ic_launcher_round.png"), rows)
        print(f"{folder}/ic_launcher.png  {size}×{size}")


if __name__ == "__main__":
    main()
