"""The colours and logos a Word case report is drawn in: Rowanholt's own, or a customer's brand.

A brand gives one or two colours and up to three logos; everything else is derived here (as ostraka's
reports/theme.py does), so a report stays readable whatever was chosen. Headings carry the primary
colour, so it's darkened until it passes WCAG AA (4.5:1) on the white page; the secondary colour
marks second-level headings and quotes, held to the same bar because it's text too. Table headers
get a light tint of the primary with dark text, and the table rules a grey with a trace of its hue.

Which brand a report gets, and whether it gets one at all, is the backend's decision (branding.py,
under the licence's report-branding and brand-library features); this module only draws it.
Stdlib only, like the rest of this package.
"""

import colorsys
import re
import struct
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

RGB = Tuple[int, int, int]

HEX = re.compile(r"^#[0-9a-fA-F]{6}$")
TEXT_CONTRAST = 4.5
PAGE = (255, 255, 255)


@dataclass(frozen=True)
class Palette:
    """Every colour the Word report uses, as six-digit hex without the #."""

    heading: str  # the title and first-level headings
    subheading: str  # second-level headings and the quote rule
    header_fill: str  # table header rows
    rule: str  # table borders


# Rowanholt's own style: the colours document.py has always used
ROWANHOLT = Palette(heading="17365D", subheading="1F6F78", header_fill="D5E3E8", rule="A6A6A6")


@dataclass(frozen=True)
class Theme:
    """A palette and, for a customer's brand, its logos as PNG (cleaned by the backend)."""

    palette: Palette = ROWANHOLT
    cover_logo: Optional[bytes] = None  # above the title
    header_logo: Optional[bytes] = None  # small, in every page header
    client_logo: Optional[bytes] = None  # beside "Prepared for" under the title
    prepared_for: str = ""
    brand: str = ""  # the brand's name, for the record of the export
    notes: Tuple[str, ...] = field(default=(), compare=False)  # colours that had to change


ROWANHOLT_THEME = Theme()


def parse_hex(text: str) -> RGB:
    if not HEX.match(text or ""):
        raise ValueError(f"{text!r} isn't a colour like #1f6feb.")
    return (int(text[1:3], 16), int(text[3:5], 16), int(text[5:7], 16))


def to_hex(rgb: RGB) -> str:
    return "{:02X}{:02X}{:02X}".format(*rgb)


def luminance(rgb: RGB) -> float:
    def channel(c: int) -> float:
        c = c / 255
        return c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4

    r, g, b = rgb
    return 0.2126 * channel(r) + 0.7152 * channel(g) + 0.0722 * channel(b)


def contrast(a: RGB, b: RGB) -> float:
    """The WCAG contrast ratio, 1 to 21."""
    hi, lo = sorted((luminance(a), luminance(b)), reverse=True)
    return (hi + 0.05) / (lo + 0.05)


def _hls(h: float, lightness: float, s: float) -> RGB:
    r, g, b = colorsys.hls_to_rgb(h, lightness, s)
    return (round(r * 255), round(g * 255), round(b * 255))


def _darken_until(rgb: RGB, ground: RGB, ratio: float) -> RGB:
    """`rgb` with its lightness lowered just enough to reach `ratio` against `ground`."""
    h, lightness, s = colorsys.rgb_to_hls(*(c / 255 for c in rgb))
    out = rgb
    while contrast(out, ground) < ratio and lightness > 0:
        lightness = max(lightness - 0.01, 0)
        out = _hls(h, lightness, s)
    return out


def _mix(a: RGB, b: RGB, t: float) -> RGB:
    return tuple(round(x + (y - x) * t) for x, y in zip(a, b))  # type: ignore[return-value]


def derive(primary: str, secondary: str = "") -> Tuple[Palette, List[str]]:
    """A full palette from a brand's colours, and a note for each colour that had to change to stay
    readable."""
    notes: List[str] = []
    given = parse_hex(primary)
    h, _, s = colorsys.rgb_to_hls(*(c / 255 for c in given))
    heading = _darken_until(given, PAGE, TEXT_CONTRAST)
    if heading != given:
        notes.append(f"The primary colour {primary.lower()} is too light for headings on a white page; "
                     f"reports use #{to_hex(heading).lower()}, the nearest shade that reads clearly.")
    if secondary:
        second = parse_hex(secondary)
        subheading = _darken_until(second, PAGE, TEXT_CONTRAST)
        if subheading != second:
            notes.append(f"The secondary colour {secondary.lower()} is too light for headings; "
                         f"reports use #{to_hex(subheading).lower()}.")
    else:
        subheading = heading
    palette = Palette(
        heading=to_hex(heading),
        subheading=to_hex(subheading),
        header_fill=to_hex(_mix(heading, PAGE, 0.82)),  # dark table text stays readable on it
        rule=to_hex(_hls(h, 0.68, min(s, 0.12))),
    )
    return palette, notes


def brand_theme(primary: str, secondary: str = "", cover_logo: Optional[bytes] = None,
                header_logo: Optional[bytes] = None, client_logo: Optional[bytes] = None,
                prepared_for: str = "", brand: str = "") -> Theme:
    palette, notes = derive(primary, secondary)
    return Theme(palette, cover_logo, header_logo, client_logo, prepared_for, brand, tuple(notes))


def png_size(data: bytes) -> Tuple[int, int]:
    """A PNG's width and height from its header (the backend stores logos only as PNG)."""
    if len(data) < 24 or data[:8] != b"\x89PNG\r\n\x1a\n" or data[12:16] != b"IHDR":
        raise ValueError("not a PNG")
    return struct.unpack(">II", data[16:24])
