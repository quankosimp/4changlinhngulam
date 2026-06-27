from __future__ import annotations

from pathlib import Path

import fitz

_FONT_CANDIDATES = (
    "/usr/share/fonts/truetype/noto/NotoSans-Regular.ttf",
    "/usr/share/fonts/noto/NotoSans-Regular.ttf",
    "/usr/share/fonts/TTF/NotoSans-Regular.ttf",
)


def _select_font() -> str | None:
    for candidate in _FONT_CANDIDATES:
        if Path(candidate).exists():
            return candidate
    return None


def make_pdf(path: Path, pages: list[str]) -> Path:
    document = fitz.open()
    font_file = _select_font()

    for text in pages:
        page = document.new_page()
        if not text:
            continue

        if font_file is None:
            page.insert_text((72, 72), text, fontsize=12)
            continue

        font = fitz.Font(fontfile=font_file)
        tw = fitz.TextWriter(page.rect)
        x, y = 72, 72
        for line in text.splitlines():
            tw.append((x, y), line, font=font, fontsize=12)
            y += 14
        tw.write_text(page)

    document.save(path)
    document.close()
    return path
