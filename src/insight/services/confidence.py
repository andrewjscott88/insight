"""Confidence, source reliability and report credibility (TIP 4.2, ADR 0033).

The analyst grades each source (Admiralty reliability A-F) and each report (credibility 1-6). An indicator's
confidence says how strongly the reports a reader may see support it: each current report that mentions it
(unless review rejected the mention) adds weight by its source's reliability, its own credibility and its age,
and independent sources add up. Nothing is stored: confidence is computed on read, so it ages by itself and a
TLP-limited reader's score uses only the reports it may see.

Ageing halves a report's weight every ``half_life_days``: by indicator type (an IP address goes stale faster
than a domain; a file hash or CVE does not age), or by the source's own setting.
"""

from __future__ import annotations

import json
import math
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Final

from sqlalchemy import Select, func, select
from sqlalchemy.orm import Session

from ..models import Document, Entity, Observation, SourceRating, now
from ..schemas import CredibilityInput, SourceRatingInput
from .actors import _who
from .audit import audit
from .tlp import _visible

RELIABILITY: Final = {
    'A': 'Completely reliable',
    'B': 'Usually reliable',
    'C': 'Fairly reliable',
    'D': 'Not usually reliable',
    'E': 'Unreliable',
    'F': 'Reliability cannot be judged',
}
CREDIBILITY: Final = {
    1: 'Confirmed by other sources',
    2: 'Probably true',
    3: 'Possibly true',
    4: 'Doubtful',
    5: 'Improbable',
    6: 'Truth cannot be judged',
}
_RELIABILITY_WEIGHT: Final = {'A': 1.0, 'B': 0.85, 'C': 0.65, 'D': 0.4, 'E': 0.15, 'F': 0.5}
_CREDIBILITY_WEIGHT: Final = {1: 1.0, 2: 0.85, 3: 0.65, 4: 0.4, 5: 0.15, 6: 0.5}
#: The most one report can add: even a confirmed report from a completely reliable source needs company.
_REPORT_WEIGHT: Final = 0.6
#: An unreviewed mention counts a little less than one an analyst accepted.
_UNREVIEWED: Final = 0.8
#: Days for a report's weight to halve, by indicator type; ``None`` never ages.
HALF_LIFE_DAYS: Final[dict[str, int | None]] = {
    'ip': 30, 'cidr': 30, 'url': 60, 'domain': 90, 'email': 180,
    'md5': None, 'sha1': None, 'sha256': None, 'sha512': None, 'cve': None,
}  # fmt: skip
_MAX_ROWS: Final = 5_000
_MAX_SOURCES: Final = 500


@dataclass(frozen=True, slots=True)
class SourceContribution:
    source_name: str
    reliability: str
    reports: int
    newest_at: str
    #: The source's share of support, 0-100, after credibility and ageing.
    weight: int


@dataclass(frozen=True, slots=True)
class Confidence:
    score: int
    band: str  # 'high', 'medium', 'low' or 'none'
    half_life_days: int | None
    sources: tuple[SourceContribution, ...]


@dataclass(frozen=True, slots=True)
class SourceStats:
    source_name: str
    reliability: str
    half_life_days: int | None
    note: str
    reports: int
    indicators: int
    #: Indicators no other visible source mentions.
    unique_indicators: int
    reviewed: int
    rejected: int
    last_report_at: str | None


def band(score: int) -> str:
    return 'high' if score >= 70 else 'medium' if score >= 40 else 'low' if score > 0 else 'none'


def _ratings(db: Session, names: set[str]) -> dict[str, SourceRating]:
    if not names:
        return {}
    return {
        r.source_name: r for r in db.scalars(select(SourceRating).where(SourceRating.source_name.in_(names)))
    }


def _age_days(created_at: str, at: datetime) -> float:
    try:
        when = datetime.fromisoformat(created_at)
    except ValueError:
        return 0.0
    if when.tzinfo is None:
        when = when.replace(tzinfo=UTC)
    return max(0.0, (at - when).total_seconds() / 86_400)


def indicator_confidence(
    db: Session, entity_id: str, *, max_tlp: str | None = None, at: datetime | None = None
) -> Confidence:
    """How strongly the visible, current reports support one indicator (see the module docstring)."""
    at = at or datetime.now(UTC)
    kind = db.scalar(select(Entity.kind).where(Entity.id == entity_id)) or ''
    rows = db.execute(
        select(Document.source_name, Document.created_at, Document.credibility, Observation.review_status)
        .join(Observation, Observation.document_id == Document.id)
        .where(
            Observation.entity_id == entity_id,
            Observation.review_status != 'rejected',
            Document.is_current.is_(True),
            *_visible(max_tlp),
        )
        .order_by(Document.created_at.desc())
        .limit(_MAX_ROWS)
    ).all()
    ratings = _ratings(db, {str(r[0]) for r in rows})
    default_half_life = HALF_LIFE_DAYS.get(kind)
    best: dict[str, float] = {}
    reports: dict[str, set[str]] = {}
    newest: dict[str, str] = {}
    for source, created_at, credibility, review in rows:
        rating = ratings.get(source)
        grade = rating.reliability if rating else 'F'
        half_life = default_half_life  # Hashes and CVEs never age, whatever the source says.
        if half_life is not None and rating is not None and rating.half_life_days:
            half_life = rating.half_life_days
        decay = 0.5 ** (_age_days(created_at, at) / half_life) if half_life else 1.0
        weight = _REPORT_WEIGHT * _RELIABILITY_WEIGHT[grade] * _CREDIBILITY_WEIGHT.get(int(credibility), 0.5)
        weight *= decay * (1.0 if review == 'accepted' else _UNREVIEWED)
        best[source] = max(best.get(source, 0.0), weight)
        reports.setdefault(source, set()).add(created_at)
        newest[source] = max(newest.get(source, ''), created_at)
    support = 1.0 - math.prod(1.0 - w for w in best.values())
    score = round(100 * support)
    contributions = sorted(
        (
            SourceContribution(
                s, ratings[s].reliability if s in ratings else 'F', len(reports[s]), newest[s], round(100 * w)
            )
            for s, w in best.items()
        ),
        key=lambda c: (-c.weight, c.source_name),
    )
    return Confidence(score, band(score), default_half_life, tuple(contributions))


def rate_source(db: Session, payload: SourceRatingInput) -> SourceRating:
    """Set a source's reliability grade and ageing. Audited as ``source.rate``."""
    name = payload.source_name.strip()
    row = db.get(SourceRating, name) or SourceRating(source_name=name)
    row.reliability, row.half_life_days, row.note = (
        payload.reliability,
        payload.half_life_days,
        payload.note.strip(),
    )
    row.updated_at, row.actor = now(), _who(db)
    db.add(row)
    detail = {'reliability': row.reliability, 'half_life_days': row.half_life_days}
    audit(db, 'source.rate', name[:200], json.dumps(detail, sort_keys=True))
    return row


def set_credibility(
    db: Session, document_id: str, payload: CredibilityInput, *, max_tlp: str | None = None
) -> Document:
    """Grade what one visible report says. Audited as ``document.credibility``."""
    doc = db.scalar(select(Document).where(Document.id == document_id, *_visible(max_tlp)).with_for_update())
    if doc is None:
        raise LookupError('Report not found')
    if doc.credibility != payload.credibility:
        doc.credibility = payload.credibility
        audit(db, 'document.credibility', doc.id, str(payload.credibility))
    return doc


def _grouped(db: Session, stmt: Select[Any]) -> dict[str, int]:
    return {str(row[0]): int(row[1]) for row in db.execute(stmt).all()}


def source_statistics(db: Session, *, max_tlp: str | None = None) -> list[SourceStats]:
    """Per source, from the current reports the reader may see: reports, indicators, indicators no other
    source mentions, reviewed and rejected mentions, and the newest report. Rated sources without visible
    reports are listed only for unlimited readers (a name alone could reveal a restricted source)."""
    visible = [Document.is_current.is_(True), *_visible(max_tlp)]
    counts = db.execute(
        select(Document.source_name, func.count(Document.id), func.max(Document.created_at))
        .where(*visible)
        .group_by(Document.source_name)
        .order_by(func.count(Document.id).desc())
        .limit(_MAX_SOURCES)
    ).all()
    mentions = (
        select(Document.source_name.label('source'), Observation.entity_id, Observation.review_status)
        .join(Observation, Observation.document_id == Document.id)
        .where(*visible)
        .subquery()
    )
    kept = (
        select(mentions.c.source, mentions.c.entity_id)
        .where(mentions.c.review_status != 'rejected')
        .subquery()
    )
    indicators = _grouped(
        db, select(kept.c.source, func.count(func.distinct(kept.c.entity_id))).group_by(kept.c.source)
    )
    single = (
        select(kept.c.entity_id)
        .group_by(kept.c.entity_id)
        .having(func.count(func.distinct(kept.c.source)) == 1)
        .subquery()
    )
    unique = _grouped(
        db,
        select(kept.c.source, func.count(func.distinct(kept.c.entity_id)))
        .where(kept.c.entity_id.in_(select(single.c.entity_id)))
        .group_by(kept.c.source),
    )
    reviewed = _grouped(
        db,
        select(mentions.c.source, func.count())
        .where(mentions.c.review_status != 'unreviewed')
        .group_by(mentions.c.source),
    )
    rejected = _grouped(
        db,
        select(mentions.c.source, func.count())
        .where(mentions.c.review_status == 'rejected')
        .group_by(mentions.c.source),
    )
    names = [str(c[0]) for c in counts]
    ratings = _ratings(db, set(names))
    if max_tlp is None:
        extra = db.scalars(
            select(SourceRating).where(SourceRating.source_name.not_in(names)).limit(_MAX_SOURCES)
        )
        ratings |= {r.source_name: r for r in extra}
    found = {str(n): (int(c), str(last)) for n, c, last in counts}
    stats = []
    for name in [*names, *sorted(set(ratings) - set(names))]:
        rating = ratings.get(name)
        total, last = found.get(name, (0, None))
        stats.append(
            SourceStats(
                name, rating.reliability if rating else 'F', rating.half_life_days if rating else None,
                rating.note if rating else '', total, indicators.get(name, 0), unique.get(name, 0),
                reviewed.get(name, 0), rejected.get(name, 0), last,
            )
        )  # fmt: skip
    return stats
