"""Small, generic I/O helpers shared across the package."""

from __future__ import annotations

from pathlib import Path

_ENCODINGS_TO_TRY = ("utf-8-sig", "utf-16", "utf-8", "latin-1")


def read_text_lines_multi_encoding(filepath: str | Path) -> list[str]:
    """
    Read a text file's lines, trying several encodings in order.

    Tetragon telemetry files are sometimes produced on Windows with a BOM
    or UTF-16 encoding; falling through a short list of encodings avoids
    failing to parse an otherwise-valid file.
    """
    for encoding in _ENCODINGS_TO_TRY:
        try:
            with open(filepath, encoding=encoding) as f:
                return f.readlines()
        except (UnicodeDecodeError, UnicodeError):
            continue
    return []
