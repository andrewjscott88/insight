"""Small helpers every domain module uses: text folding, LIKE patterns and timestamp strings."""

from __future__ import annotations

import unicodedata
from datetime import UTC, datetime

from ..extraction import ZERO_WIDTH


def fold(text: str) -> str:
    """Case-, accent- and width-insensitive form for search and watch terms.

    NFKD, drop combining marks and zero-width characters, casefold, NFC. So ``ÜBERWACHUNG``, ``überwachung``
    and ``uberwachung`` match; ``İSTANBUL`` matches ``istanbul``; NFC and NFD spellings of ``café`` match.
    The same function runs in Python for stored text and queries, so SQLite and PostgreSQL behave identically.
    """
    decomposed = unicodedata.normalize('NFKD', text)
    kept = ''.join(c for c in decomposed if not unicodedata.combining(c) and c not in ZERO_WIDTH)
    return unicodedata.normalize('NFC', kept.casefold())


def like_pattern(term: str) -> str:
    """Escape ``term`` for a literal ``LIKE/ILIKE ... ESCAPE '\\'`` substring match."""
    escaped = term.replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_')
    return f'%{escaped}%'


def stamp(moment: datetime) -> str:
    """The stored form of a moment: ISO-8601 in UTC, so strings sort in time order."""
    return moment.astimezone(UTC).isoformat()
