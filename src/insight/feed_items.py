"""Items passed from a source parser to report ingestion."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from .schemas import DocumentInput

MAX_FEED_ITEMS: Final = 100


@dataclass(frozen=True, slots=True)
class FeedItem:
    """A parsed feed entry and its stable identity at the publisher (``None`` if it has none)."""

    document: DocumentInput
    external_id: str | None
    #: The publisher's summary was longer than the configured limit and was cut.
    truncated: bool = False
