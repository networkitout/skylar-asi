"""Wordmark rendering shared by PDF and XLSX exports."""
import io

import pytest

import branding


def test_wordmark_png_is_a_transparent_two_tone_image():
    from PIL import Image
    png = branding.wordmark_png(size=64)
    assert png and png[:8] == b"\x89PNG\r\n\x1a\n"
    img = Image.open(io.BytesIO(png)).convert("RGBA")
    assert img.width > img.height * 2            # a wide lockup, not a square
    pixels = {px[:3] for px in img.getdata() if px[3] > 200}
    def near(rgb, hex_color, tol=40):
        want = tuple(int(hex_color[i:i + 2], 16) for i in (1, 3, 5))
        return all(abs(a - b) <= tol for a, b in zip(rgb, want))
    assert any(near(p, branding.ORANGE) for p in pixels), "no orange SKY"
    assert any(near(p, branding.BLUE) for p in pixels), "no blue LAR"
    assert any(near(p, branding.TERTIARY) for p in pixels), "no tagline"
    assert img.getpixel((0, 0))[3] == 0          # transparent background


def test_wordmark_png_is_cached_and_tagline_optional():
    assert branding.wordmark_png(size=48) is branding.wordmark_png(size=48)
    from PIL import Image
    with_tag = Image.open(io.BytesIO(branding.wordmark_png(size=48)))
    without = Image.open(io.BytesIO(branding.wordmark_png(size=48, tagline=False)))
    assert without.height < with_tag.height


def test_tagline_matches_frontend():
    import os, re
    path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
                        "frontend", "src", "components", "Wordmark.jsx")
    if not os.path.exists(path):
        pytest.skip("frontend sources not available alongside the backend")
    src = open(path, encoding="utf-8").read()
    assert re.search(r"TAGLINE = '([^']+)'", src).group(1) == branding.TAGLINE
