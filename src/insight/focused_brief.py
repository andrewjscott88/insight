"""Small, plain-text views for a topic's Intel Brief; no source bodies or model output."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class BriefItem:
    document_id: str
    title: str
    source_name: str
    created_at: str
    relevance: str = ''


@dataclass(frozen=True, slots=True)
class BriefSection:
    title: str
    lines: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class BriefSource:
    name: str
    url: str


@dataclass(frozen=True, slots=True)
class FocusedBrief:
    kind: str
    ref: str
    title: str
    tlp: str
    days: int
    summary: tuple[str, ...]
    notes: tuple[str, ...]
    reports: tuple[BriefItem, ...]
    sections: tuple[BriefSection, ...] = ()
    sources: tuple[BriefSource, ...] = ()
