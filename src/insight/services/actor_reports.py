"""Bounded, reader-filtered report references shared by actor guides and timelines."""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy.orm import Session

from ..schemas import most_restrictive
from .actors import GroupSubject, linked_reports
from .threat_profiles import MAX_SCANNED, Mention, find_mentions

MAX_NAMED = 50


@dataclass(frozen=True, slots=True)
class ReportRef:
    document_id: str
    title: str
    tlp: str
    created_at: str
    source_name: str
    via: str  # 'linked' or 'named'
    evidence: str  # the analyst's note for a link, the text around the name otherwise


def _guide_reports(
    db: Session, subject: GroupSubject, max_tlp: str | None, *, current_only: bool = False
) -> tuple[list[ReportRef], list[Mention], bool]:
    """Linked reports, then up to ``MAX_NAMED`` reports that only name the group; and every mention found."""
    linked = [
        ReportRef(
            d.id,
            d.title,
            most_restrictive(d.tlp, link.tlp, subject.tlp),
            d.created_at,
            d.source_name,
            'linked',
            link.note,
        )
        for d, link in linked_reports(db, subject.ref, max_tlp=max_tlp, current_only=current_only)
    ]
    seen = {r.document_id for r in linked}
    found, scanned = find_mentions(db, {subject.ref: subject.names}, max_tlp=max_tlp)
    mentions = found[subject.ref]
    named = [
        ReportRef(m.document_id, m.title, m.tlp, m.created_at, m.source_name, 'named', m.evidence)
        for m in mentions
        if m.document_id not in seen
    ]
    return (
        linked + named[:MAX_NAMED],
        mentions,
        scanned >= MAX_SCANNED or len(linked) >= 200 or len(named) > MAX_NAMED,
    )
