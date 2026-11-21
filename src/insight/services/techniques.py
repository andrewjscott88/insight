"""MITRE ATT&CK techniques on reports: written in the report, or added by an analyst (ADR 0019).

Tags belong to one report revision. A new revision of a synced item gets the techniques written in its own
text, plus every decision an analyst made on the revision it replaces: techniques they added stay added,
techniques they removed stay removed, even if the new text still names them. Every read takes ``max_tlp``
(a TLP-limited API key sees tags only on reports it may see) and counts current revisions only.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Any, Final

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from .. import __version__
from ..attack import catalog, find_techniques, technique
from ..models import Document, DocumentTechnique
from .audit import DEFAULT_ACTOR, audit
from .tlp import _visible

TAGGED: Final = 'tagged'
REMOVED: Final = 'removed'
NAVIGATOR_VERSION: Final = '5.0.0'
LAYER_FORMAT: Final = '4.5'
MAX_PIVOT_PAGE: Final = 200


@dataclass(frozen=True, slots=True)
class TechniqueTag:
    technique_id: str
    name: str  # full name; the ID itself if the technique is no longer in the catalog
    tactics: tuple[str, ...]  # tactic names, in matrix order
    source: str  # 'report' or 'analyst'
    evidence: str
    actor: str
    created_at: str
    in_catalog: bool

    @property
    def url(self) -> str:
        return f'https://attack.mitre.org/techniques/{self.technique_id.replace(".", "/")}/'


@dataclass(frozen=True, slots=True)
class TechniqueCount:
    technique_id: str
    reports: int
    last_seen: str  # when the newest report tagged with it was added


def _actor(db: Session) -> str:
    return str(db.info.get('actor', DEFAULT_ACTOR))


def _visible_document(db: Session, document_id: str, max_tlp: str | None) -> Document:
    doc = db.scalar(select(Document).where(Document.id == document_id, *_visible(max_tlp)))
    if doc is None:
        raise LookupError('Report not found')
    return doc


def _rows(db: Session, document_id: str) -> dict[str, DocumentTechnique]:
    stmt = select(DocumentTechnique).where(DocumentTechnique.document_id == document_id)
    return {row.technique_id: row for row in db.scalars(stmt)}


def _decisions(db: Session, document_id: str) -> dict[str, DocumentTechnique]:
    """What an analyst decided on a revision: techniques they added, and tags they removed."""
    stmt = select(DocumentTechnique).where(
        DocumentTechnique.document_id == document_id,
        or_(DocumentTechnique.source == 'analyst', DocumentTechnique.status == REMOVED),
    )
    return {row.technique_id: row for row in db.scalars(stmt)}


def _copy(row: DocumentTechnique, document_id: str) -> DocumentTechnique:
    return DocumentTechnique(
        document_id=document_id,
        technique_id=row.technique_id,
        source=row.source,
        status=row.status,
        evidence=row.evidence,
        actor=row.actor,
    )


def record_report_techniques(db: Session, doc: Document, *, previous: Document | None = None) -> int:
    """At ingest: tag the technique IDs written in ``doc``; copy the analyst's decisions from ``previous``.

    Returns the number of techniques tagged from the text.
    """
    decided = _decisions(db, previous.id) if previous is not None else {}
    db.add_all(_copy(row, doc.id) for row in decided.values())
    added = 0
    for mention in find_techniques(doc.body):
        if mention.technique_id in decided:
            continue  # the analyst's decision on the previous revision wins
        db.add(
            DocumentTechnique(
                document_id=doc.id,
                technique_id=mention.technique_id,
                source='report',
                evidence=mention.evidence,
            )
        )
        added += 1
    return added


def carry_decisions(db: Session, *, from_doc: Document, to_doc: Document) -> None:
    """When a publisher reverts to an earlier revision, apply the analyst's later decisions to it as well."""
    existing = _rows(db, to_doc.id)
    for technique_id, row in _decisions(db, from_doc.id).items():
        if technique_id in existing:
            existing[technique_id].status = row.status
        else:
            db.add(_copy(row, to_doc.id))


def backfill_techniques(db: Session) -> tuple[int, int]:
    """Tag the techniques written in reports stored before technique tagging existed.

    Only reports with no technique rows at all are read, so running it again changes nothing. Returns
    ``(reports read, tags added)``.
    """
    tagged = select(DocumentTechnique.document_id).distinct()
    reports = added = 0
    for doc in db.scalars(select(Document).where(Document.id.not_in(tagged)).order_by(Document.created_at)):
        reports += 1
        added += record_report_techniques(db, doc)
    if added:
        audit(db, 'technique.backfill', 'documents', f'{added} technique tag(s) on {reports} report(s)')
    return reports, added


def _view(row: DocumentTechnique) -> TechniqueTag:
    found = technique(row.technique_id)
    return TechniqueTag(
        technique_id=row.technique_id,
        name=found.full_name if found else row.technique_id,
        tactics=catalog().tactic_names(found) if found else (),
        source=row.source,
        evidence=row.evidence,
        actor=row.actor,
        created_at=row.created_at,
        in_catalog=found is not None,
    )


def document_techniques(db: Session, document_id: str, *, max_tlp: str | None = None) -> list[TechniqueTag]:
    """The techniques tagged on a report the reader may see, by ID (``LookupError`` otherwise)."""
    _visible_document(db, document_id, max_tlp)
    rows = [row for row in _rows(db, document_id).values() if row.status == TAGGED]
    return [_view(row) for row in sorted(rows, key=lambda r: r.technique_id)]


def tag_technique(
    db: Session, document_id: str, technique_id: str, *, max_tlp: str | None = None
) -> TechniqueTag:
    """Add a technique to a report (or restore one that was removed). Audited as ``technique.tag``.

    ``ValueError`` for an ID that is not a current technique; ``LookupError`` if the reader cannot see the
    report.
    """
    found = technique(technique_id)
    if found is None:
        raise ValueError('Not a current ATT&CK technique ID (for example T1059 or T1059.001)')
    _visible_document(db, document_id, max_tlp)
    row = _rows(db, document_id).get(found.id)
    if row is not None and row.status == TAGGED:
        return _view(row)
    if row is None:
        row = DocumentTechnique(document_id=document_id, technique_id=found.id, source='analyst')
        db.add(row)
    row.status = TAGGED
    row.actor = _actor(db)
    audit(db, 'technique.tag', document_id, found.id)
    db.flush()
    return _view(row)


def untag_technique(db: Session, document_id: str, technique_id: str, *, max_tlp: str | None = None) -> None:
    """Remove a technique from a report; it stays removed in later revisions. Audited as ``technique.untag``.

    ``LookupError`` if the reader cannot see the report or the technique is not tagged on it.
    """
    _visible_document(db, document_id, max_tlp)
    row = _rows(db, document_id).get(technique_id.strip().upper())
    if row is None or row.status != TAGGED:
        raise LookupError('That technique is not tagged on this report')
    row.status = REMOVED
    row.actor = _actor(db)
    audit(db, 'technique.untag', document_id, row.technique_id)


def _tagged_current(max_tlp: str | None, since: str | None) -> list[Any]:
    conditions = [
        DocumentTechnique.status == TAGGED,
        Document.is_current.is_(True),
        *_visible(max_tlp),
    ]
    if since:
        conditions.append(Document.created_at >= since)
    return conditions


def technique_summary(
    db: Session, *, max_tlp: str | None = None, since: str | None = None
) -> list[TechniqueCount]:
    """Techniques on current reports the reader may see (added on or after ``since``), most reports first."""
    stmt = (
        select(
            DocumentTechnique.technique_id,
            func.count(func.distinct(DocumentTechnique.document_id)),
            func.max(Document.created_at),
        )
        .join(Document, DocumentTechnique.document_id == Document.id)
        .where(*_tagged_current(max_tlp, since))
        .group_by(DocumentTechnique.technique_id)
    )
    counts = [TechniqueCount(t, n, last) for t, n, last in db.execute(stmt)]
    return sorted(counts, key=lambda c: (-c.reports, c.technique_id))


def technique_labels(
    db: Session, technique_ids: Iterable[str], *, max_tlp: str | None = None, since: str | None = None
) -> set[str]:
    """The TLP labels of the current reports the reader may see that are tagged with any of these techniques.

    A count of such reports (``technique_summary``) is derived from them, so whatever shows the count carries
    their labels.
    """
    wanted = sorted(set(technique_ids))
    if not wanted:
        return set()
    stmt = (
        select(Document.tlp)
        .join(DocumentTechnique, DocumentTechnique.document_id == Document.id)
        .where(DocumentTechnique.technique_id.in_(wanted), *_tagged_current(max_tlp, since))
        .distinct()
    )
    return set(db.scalars(stmt))


def technique_documents(
    db: Session,
    technique_id: str,
    *,
    max_tlp: str | None = None,
    since: str | None = None,
    offset: int = 0,
    limit: int = 25,
) -> list[Document]:
    """One page of current reports tagged with the technique, newest first."""
    stmt = (
        select(Document)
        .join(DocumentTechnique, DocumentTechnique.document_id == Document.id)
        .where(
            DocumentTechnique.technique_id == technique_id.strip().upper(), *_tagged_current(max_tlp, since)
        )
        .order_by(Document.created_at.desc(), Document.id)
        .offset(max(0, offset))
        .limit(min(max(1, limit), MAX_PIVOT_PAGE))
    )
    return list(db.scalars(stmt))


def navigator_layer(counts: Sequence[TechniqueCount], *, period: str) -> dict[str, Any]:
    """An ATT&CK Navigator layer (format 4.5): each technique scored by the number of reports tagged with it.

    Open it at https://mitre-attack.github.io/attack-navigator/ ("Open Existing Layer", "Upload from local").
    """
    top = max((c.reports for c in counts), default=1)
    return {
        'name': f'Insight: techniques in reports ({period})',
        'versions': {'attack': catalog().version, 'navigator': NAVIGATOR_VERSION, 'layer': LAYER_FORMAT},
        'domain': 'enterprise-attack',
        'description': (
            f'Techniques tagged on current Insight reports ({period}). The score is the number of reports. '
            'Tags record what reports say or what an analyst decided; they are not detections.'
        ),
        'layout': {'layout': 'side', 'showID': True, 'showName': True, 'expandedSubtechniques': 'annotated'},
        'gradient': {'colors': ['#fff3e0', '#e65100'], 'minValue': 0, 'maxValue': max(1, top)},
        'techniques': [
            {
                'techniqueID': c.technique_id,
                'score': c.reports,
                'comment': f'{c.reports} report(s); latest added {c.last_seen[:10]}',
                'enabled': True,
            }
            for c in counts
            if technique(c.technique_id) is not None
        ],
        'metadata': [
            {'name': 'Generated by', 'value': f'Insight {__version__}'},
            {'name': 'ATT&CK', 'value': catalog().notice},
        ],
    }
