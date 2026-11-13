#!/usr/bin/env python3
"""Put a superscript ™ on the Rowanholt wordmark: docs/images/rowanholt.png -> rowanholt-tm.png.

The logo is a painted image, not generated, so the ™ is composited on: about 0.3 of the
capitals' height, in the letters' gold, top-aligned with the capitals just after the final T.
The T is found from the pixels, so a redrawn logo of the same style needs no new numbers.
The plain logo stays for the favicon and app icons (a ™ is unreadable that small).

Needs Pillow, which Rowanholt itself doesn't use: run it from any Python that has it, e.g.
    python3 -m venv /tmp/pil && /tmp/pil/bin/pip install pillow && /tmp/pil/bin/python scripts/brand/add_tm.py
"""

import argparse
import shutil
from pathlib import Path
from typing import Tuple

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "docs" / "images" / "rowanholt.png"
OUTPUTS = [ROOT / "docs" / "images" / "rowanholt-tm.png",
           ROOT / "src" / "web" / "frontend" / "public" / "images" / "rowanholt-tm.png"]
FONT = "/System/Library/Fonts/Supplemental/Georgia Bold.ttf"
TM_SCALE = 0.3  # of the capitals' height


def is_gold(pixel: Tuple[int, int, int]) -> bool:
    """The wordmark's gilt, against the dark vignette and the painted scene."""
    r, g, b = pixel
    return r > 170 and g > 130 and b < 120 and r - b > 90


def final_letter(im: Image.Image) -> Tuple[int, int, int, Tuple[int, int, int]]:
    """The last capital's right edge, top and bottom, and its average colour."""
    w, h = im.size
    px = im.load()
    band = range(int(h * 0.5), int(h * 0.76))  # the wordmark's line, below the painted arch
    cols = [x for x in range(int(w * 0.85), w) if sum(is_gold(px[x, y]) for y in band) > 8]
    right = max(cols)
    span = range(right - 110, right + 1)
    rows = [y for y in range(int(h * 0.44), int(h * 0.78)) if sum(is_gold(px[x, y]) for x in span) > 10]
    top, bottom = min(rows), max(rows)
    gilt = [px[x, y] for x in span for y in range(top + 5, top + 25) if is_gold(px[x, y])]
    colour = tuple(sum(c[i] for c in gilt) // len(gilt) for i in range(3))
    return right, top, bottom, colour


def add_tm(source: Path, dest: Path) -> None:
    """Write source with a ™ after its wordmark to dest."""
    im = Image.open(source).convert("RGBA")
    right, top, bottom, colour = final_letter(im.convert("RGB"))
    height = round((bottom - top) * TM_SCALE)
    # Size the font so the ™ glyph itself, not the font's line box, is `height` tall
    size = height
    for _ in range(20):
        font = ImageFont.truetype(FONT, size)
        x0, y0, x1, y1 = font.getbbox("™")
        if abs((y1 - y0) - height) <= 1:
            break
        size = max(4, round(size * height / (y1 - y0)))
    gap = round(height * 0.18)
    x, y = right + gap - x0, top - y0
    stroke = max(1, round(height / 26))
    if right + gap + (x1 - x0) + stroke >= im.width:
        raise SystemExit(f"No room for the ™ after the wordmark in {source}")
    ImageDraw.Draw(im).text((x, y), "™", font=font, fill=colour + (255,),
                            stroke_width=stroke, stroke_fill=(48, 32, 8, 255))
    dest.parent.mkdir(parents=True, exist_ok=True)
    im.save(dest, optimize=True)  # RGBA: the logo's background is transparent


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--source", type=Path, default=SOURCE)
    args = parser.parse_args()
    add_tm(args.source, OUTPUTS[0])
    for extra in OUTPUTS[1:]:
        shutil.copyfile(OUTPUTS[0], extra)
    for out in OUTPUTS:
        print(out.relative_to(ROOT))


if __name__ == "__main__":
    main()
