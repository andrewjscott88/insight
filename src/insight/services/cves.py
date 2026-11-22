"""What Insight knows about each CVE in the reports a reader may see, for the prioritised CVE view (TIP 1.3).

One row per CVE: how many reports and sources mention it, when it was first and last seen, its newest
report, the highest CVSS score a visible CISA advisory gives it, its CISA KEV entry (with known ransomware
use), and the cached NIST NVD and FIRST EPSS scores (ADR 0023). ``insight.cve_priority`` ranks the rows; this
module only reads. Every report-derived value follows the reader's TLP limit; the KEV catalog and the provider
scores are public facts about the CVE.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Collection
from dataclasses import dataclass
from typing import Final

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..cve_scores import CSAF_SCORE_LINE, CveScores
from ..models import Document, Entity, KEVRecord, Observation
from .brief import KEV_SOURCE, BriefKev
from .exploits import ExploitContext, exploit_context
from .lookups import cve_scores
from .tlp import _visible

#: Mentions read at most (newest reports first); the view says so when it reached the limit.
MAX_CVE_MENTIONS: Final = 20_000
#: Reports whose text carries CVSS scores (the CISA CSAF connector's lines).
CSAF_SOURCE: Final = 'cisa-csaf'


@dataclass(frozen=True, slots=True)
class CveSignal:
    cve: str
    reports: int
    #: Distinct sources: connector key, or the case-folded source name of other reports.
    sources: int
    first_seen: str
    last_seen: str
    report_id: str
    report_title: str
    #: The highest CVSS base score a visible CISA advisory gives this CVE, if any.
    csaf_score: float | None
    kev: BriefKev | None
    scores: CveScores
    #: Public exploit code and exploitation reported for it (TIP 3.3), within the reader's TLP limit.
    exploit: ExploitContext | None = None


@dataclass(frozen=True, slots=True)
class CveSignals:
    since: str
    signals: list[CveSignal]
    #: The mention limit was reached: older reports were left out.
    truncated: bool


def cve_signals(
    db: Session, *, since: str, max_tlp: str | None = None, ignore: Collection[tuple[str, str]] = ()
) -> CveSignals:
    """Every CVE that a current report received at or after ``since`` mentions (a mention the analyst has not
    rejected), from the reports the reader may see. ``ignore`` lists ``(title, source name)`` pairs to leave
    out (the synthetic demo)."""
    rows = db.execute(
        select(
            Entity.value,
            Document.id,
            Document.title,
            Document.source_key,
            Document.source_name,
            Document.created_at,
        )
        .join(Observation, Observation.entity_id == Entity.id)
        .join(Document, Observation.document_id == Document.id)
        .where(
            Entity.kind == 'cve',
            Document.is_current.is_(True),
            Document.created_at >= since,
            Observation.review_status != 'rejected',
            *_visible(max_tlp),
        )
        .order_by(Document.created_at.desc(), Document.id)
        .limit(MAX_CVE_MENTIONS + 1)
    ).all()
    truncated = len(rows) > MAX_CVE_MENTIONS
    rows = [r for r in rows[:MAX_CVE_MENTIONS] if (r[2], r[4]) not in ignore]
    reports: dict[str, dict[str, tuple[str, str]]] = defaultdict(dict)  # cve -> report id -> (title, created)
    sources: dict[str, set[str]] = defaultdict(set)
    csaf_reports: set[str] = set()
    for cve, doc_id, title, source_key, source_name, created in rows:
        reports[cve].setdefault(doc_id, (title, created))
        sources[cve].add(source_key or ' '.join(source_name.split()).casefold())
        if source_key == CSAF_SOURCE:
            csaf_reports.add(doc_id)
    csaf = _csaf_scores(db, csaf_reports)
    kev = _kev(db, list(reports), max_tlp)
    scores = cve_scores(db, list(reports))
    exploits = exploit_context(db, list(reports), max_tlp=max_tlp)
    signals = []
    for cve, seen in reports.items():
        newest_id, (newest_title, last_seen) = max(seen.items(), key=lambda item: (item[1][1], item[0]))
        signals.append(
            CveSignal(
                cve=cve,
                reports=len(seen),
                sources=len(sources[cve]),
                first_seen=min(created for _, created in seen.values()),
                last_seen=last_seen,
                report_id=newest_id,
                report_title=newest_title,
                csaf_score=max((s for doc, s in csaf.get(cve, []) if doc in seen), default=None),
                kev=kev.get(cve),
                scores=scores.get(cve) or CveScores(cve),
                exploit=exploits.get(cve),
            )
        )
    return CveSignals(since=since, signals=signals, truncated=truncated)


def _csaf_scores(db: Session, ids: set[str]) -> dict[str, list[tuple[str, float]]]:
    """``cve -> [(report id, CVSS score)]`` from the CSAF connector's lines in those reports."""
    found: dict[str, list[tuple[str, float]]] = defaultdict(list)
    for doc_id, body in db.execute(select(Document.id, Document.body).where(Document.id.in_(sorted(ids)))):
        for cve, score in CSAF_SCORE_LINE.findall(body):
            if 0 <= (rated := float(score)) <= 10:
                found[cve].append((doc_id, rated))
    return found


def _kev(db: Session, cves: list[str], max_tlp: str | None) -> dict[str, BriefKev]:
    if not cves:
        return {}
    records = db.scalars(select(KEVRecord).where(KEVRecord.cve.in_(cves))).all()
    reports = dict(
        db.execute(
            select(Document.external_id, Document.id).where(
                Document.source_key == KEV_SOURCE,
                Document.external_id.in_([k.cve for k in records]),
                Document.is_current.is_(True),
                *_visible(max_tlp),
            )
        ).all()
    )
    return {
        k.cve: BriefKev(
            k.cve,
            k.vendor,
            k.product,
            k.date_added,
            k.due_date,
            reports.get(k.cve) or '',
            ransomware=k.ransomware,
            name=k.vulnerability_name,
        )
        for k in records
    }
