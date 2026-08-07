#!/usr/bin/env python3
"""Generate pUI Tauri icons (PNG/ICO) from the SVG design, supersampled.

Design: blue-gradient rounded square + two white lifelines + request arrow
(white, left->right) + response arrow (amber, right->left).
"""
import math
import os

from PIL import Image, ImageDraw

BASE = os.path.normpath(os.path.join(os.path.dirname(__file__), '..', 'src-tauri', 'icons'))

SS = 4
S = 128 * SS  # 512 base


def lerp(a, b, t):
    return int(a + (b - a) * t)


img = Image.new('RGBA', (S, S), (0, 0, 0, 0))

# vertical blue gradient background
g = Image.new('RGB', (1, S))
for y in range(S):
    t = y / S
    g.putpixel((0, y), (lerp(0x25, 0x0E, t), lerp(0x63, 0xA5, t), lerp(0xEB, 0xE9, t)))
bg = g.resize((S, S))
mask = Image.new('L', (S, S), 0)
ImageDraw.Draw(mask).rounded_rectangle([0, 0, S - 1, S - 1], radius=S * 28 // 128, fill=255)
img.paste(bg, (0, 0), mask)

d = ImageDraw.Draw(img)


def arrow(p1, p2, color, w):
    d.line([p1, p2], fill=color, width=w)
    dx, dy = p2[0] - p1[0], p2[1] - p1[1]
    L = math.hypot(dx, dy)
    ux, uy = dx / L, dy / L
    size = S * 26 // 128
    bx, by = p2[0] - ux * size, p2[1] - uy * size
    px, py = -uy * size * 0.5, ux * size * 0.5
    d.polygon([p2, (bx + px, by + py), (bx - px, by - py)], fill=color)


bar = S * 12 // 128
d.rounded_rectangle([S * 26 // 128, S * 20 // 128, S * 26 // 128 + bar, S * 108 // 128], radius=S * 6 // 128, fill=(255, 255, 255, 235))
d.rounded_rectangle([S * 90 // 128, S * 20 // 128, S * 90 // 128 + bar, S * 108 // 128], radius=S * 6 // 128, fill=(255, 255, 255, 235))

arrow((S * 32 // 128, S * 42 // 128), (S * 90 // 128, S * 52 // 128), (255, 255, 255, 255), S * 7 // 128)
arrow((S * 96 // 128, S * 78 // 128), (S * 38 // 128, S * 88 // 128), (0xFB, 0xBF, 0x24, 255), S * 7 // 128)

img512 = img.resize((512, 512), Image.LANCZOS)


def save_png(name, size):
    img512.resize((size, size), Image.LANCZOS).save(os.path.join(BASE, name))


save_png('icon.png', 512)
save_png('128x128@2x.png', 256)
save_png('128x128.png', 128)
save_png('32x32.png', 32)
img512.save(os.path.join(BASE, 'icon.ico'), sizes=[(16, 16), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)])

print('icons regenerated in', BASE)
