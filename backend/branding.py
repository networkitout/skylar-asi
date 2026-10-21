"""Product identity shared by every export surface.

The wordmark is orange SKY + blue LAR (see docs/UI_CONVENTIONS.md). Surfaces that
cannot use rich text - PDF, spreadsheet images - get it rendered to a PNG
here. Rendering prefers DejaVu Sans Bold (installed in the backend image)
and falls back to Pillow's built-in scalable face with a faux-bold stroke,
so a manual install without system fonts still gets a logo.
"""

import io
import os
from functools import lru_cache
from typing import Optional, Sequence, Tuple

PRODUCT = "SKYLAR"
TAGLINE = "Attack surface intelligence"
TAGLINE_LONG = f"{TAGLINE} for Cloudflare"

ORANGE = "#E56A1F"
BLUE = "#2496ED"
TERTIARY = "#6B7280"

_BOLD_FONTS = (
    "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
    "/usr/share/fonts/dejavu/DejaVuSans-Bold.ttf",
    "/Library/Fonts/Arial Bold.ttf",
    "C:/Windows/Fonts/arialbd.ttf",
)
_REGULAR_FONTS = (
    "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
    "/usr/share/fonts/dejavu/DejaVuSans.ttf",
    "/Library/Fonts/Arial.ttf",
    "C:/Windows/Fonts/arial.ttf",
)


def _load_font(candidates: Sequence[str], size: int) -> Tuple[Optional[object], bool]:
    """(font, is_real_truetype). Pillow >= 10.1 ships a scalable default."""
    from PIL import ImageFont
    for path in candidates:
        if os.path.exists(path):
            return ImageFont.truetype(path, size), True
    try:
        return ImageFont.load_default(size=size), False
    except TypeError:
        return None, False


@lru_cache(maxsize=8)
def wordmark_png(size: int = 96, tagline: bool = True) -> Optional[bytes]:
    """Transparent PNG of the wordmark, optionally with the tagline beneath.

    `size` is the wordmark font size in pixels; render at 2x the intended
    display size and scale down in the consumer for crisp edges.
    """
    try:
        from PIL import Image, ImageDraw
    except ImportError:
        return None
    bold, real_bold = _load_font(_BOLD_FONTS, size)
    if bold is None:
        return None
    small, _ = _load_font(_REGULAR_FONTS, max(12, int(size * 0.26)))

    probe = ImageDraw.Draw(Image.new("RGBA", (1, 1)))
    stroke = 0 if real_bold else max(1, size // 28)
    sky_w = probe.textlength("SKY", font=bold) + stroke * 2
    lar_w = probe.textlength("LAR", font=bold) + stroke * 2
    ascent, descent = bold.getmetrics()
    pad = max(4, size // 8)

    tag_text = TAGLINE.upper()
    gap = max(1, int(small.size * 0.14))  # letter spacing for the uppercase label (3.3)
    tag_w = sum(probe.textlength(ch, font=small) for ch in tag_text) + gap * (len(tag_text) - 1)
    tag_h = int(small.size * 1.5) if tagline else 0

    width = int(max(sky_w + lar_w, tag_w if tagline else 0) + pad * 2)
    height = int(ascent + descent + tag_h + pad * 2)
    img = Image.new("RGBA", (width, height), (255, 255, 255, 0))
    draw = ImageDraw.Draw(img)

    y = pad
    draw.text((pad, y), "SKY", font=bold, fill=ORANGE, stroke_width=stroke, stroke_fill=ORANGE)
    draw.text((pad + sky_w, y), "LAR", font=bold, fill=BLUE, stroke_width=stroke, stroke_fill=BLUE)
    if tagline:
        x = pad + stroke
        ty = y + ascent + descent + int(size * 0.02)
        for ch in tag_text:
            draw.text((x, ty), ch, font=small, fill=TERTIARY)
            x += probe.textlength(ch, font=small) + gap

    out = io.BytesIO()
    img.save(out, format="PNG")
    return out.getvalue()
