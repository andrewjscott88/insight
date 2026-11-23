"""Serializable evidence-linked brief views shared by the API and workspace."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class BriefItem:
    """One line of a section: it opens a report, looks up an indicator, or searches the reports for a word."""

    text: str
    document_id: str | None = None
    entity: str | None = None
    search: str | None = None


@dataclass(frozen=True, slots=True)
class BriefSection:
    title: str
    items: tuple[BriefItem, ...]
    #: Shown instead of the items when there are none.
    empty: str


@dataclass(frozen=True, slots=True)
class BriefHighlight:
    """A plain-language finding, a conditional next step, and its stored evidence."""

    title: str
    text: str
    action: str
    evidence: tuple[BriefItem, ...]


@dataclass(frozen=True, slots=True)
class Brief:
    days: int
    since: str
    #: The executive summary: short plain sentences, most important first.
    summary: tuple[str, ...]
    sections: tuple[BriefSection, ...]
    as_of: str
    #: Receipt count retained for API clients; Intel Brief does not display it.
    recent_reports: int
    report_count: int
    source_count: int
    highlights: tuple[BriefHighlight, ...]
    coverage: tuple[str, ...]
