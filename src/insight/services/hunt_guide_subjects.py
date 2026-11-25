"""Hunt plans that start from saved reports, flaws, indicators or explicit campaigns."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import Select, select
from sqlalchemy.orm import Session

from ..hunt_guide import GuideSection, HuntGuide
from ..hunt_guide_plan import planning_sections
from ..models import Document, DocumentTechnique, Entity, KEVRecord, Observation
from ..schemas import most_restrictive
from .actor_reports import ReportRef
from .campaigns import get_campaign, list_campaigns, list_threat_links
from .common import like_pattern
from .exploits import exploit_context
from .search import DocumentQuery, search_documents
from .techniques import TAGGED
from .threat_guides import SweepEntry
from .tlp import _visible

_KINDS = ('cve', 'document', 'exploit', 'indicator', 'campaign')
_REPORT_CAP = 20


def _text(value: str) -> str:
    return ' '.join(value.split())[:1_200]


def _entities(max_tlp: str | None, q: str = '') -> Select[Entity]:
    present = (
        select(Observation.entity_id)
        .join(Document, Document.id == Observation.document_id)
        .where(Document.is_current.is_(True), Observation.review_status != 'rejected', *_visible(max_tlp))
    )
    return (
        select(Entity)
        .where(Entity.id.in_(present), Entity.value.ilike(like_pattern(q.strip()[:120]), escape='\\'))
        .order_by(Entity.value, Entity.id)
    )


def hunt_guide_subject_choices(
    db: Session, *, max_tlp: str | None = None, kind: str, q: str
) -> list[tuple[str, str]]:
    """Search before the 50-choice cap; rejected or superseded-only mentions cannot start a plan."""
    if kind == 'document':
        reports = search_documents(db, DocumentQuery(q=q, limit=50, max_tlp=max_tlp))
        return [(r.id, _text(f'{r.title} — {r.source_name}')) for r in reports]
    if kind == 'campaign':
        return [(c.id, _text(c.name)) for c in list_campaigns(db, q=q, limit=50, max_tlp=max_tlp)]
    if kind not in _KINDS:
        raise LookupError('Hunt guide choice not found')
    stmt = _entities(max_tlp, q)
    if kind in ('cve', 'exploit'):
        stmt = stmt.where(Entity.kind == 'cve')
    if kind != 'exploit':
        return [
            (e.value if kind == 'cve' else e.id, _text(f'{e.value} ({e.kind})'))
            for e in db.scalars(stmt.limit(50))
        ]
    # Exploit facts can be in saved reports or cached catalog answers. Page through matching CVEs so
    # filtering after the first 50 does not hide older eligible subjects. Never trigger a lookup.
    choices: list[tuple[str, str]] = []
    offset = 0
    while True:
        values = [e.value for e in db.scalars(stmt.offset(offset).limit(200))]
        context = exploit_context(db, values, max_tlp=max_tlp)
        kev = set(db.scalars(select(KEVRecord.cve).where(KEVRecord.cve.in_(values))))
        for value in values:
            found = context.get(value)
            if value in kev or (found and (found.public_exploit or found.reported_exploited)):
                choices.append((value, value))
                if len(choices) == 50:
                    return choices
        if len(values) < 200:
            return choices
        offset += 200


def _ref(doc: Document, label: str = 'CLEAR') -> ReportRef:
    return ReportRef(
        doc.id, doc.title, most_restrictive(doc.tlp, label), doc.created_at, doc.source_name, 'linked', ''
    )


def _reports(db: Session, entity: Entity, max_tlp: str | None) -> list[ReportRef]:
    mentions = select(Observation.document_id).where(
        Observation.entity_id == entity.id, Observation.review_status != 'rejected'
    )
    rows = db.scalars(
        select(Document)
        .where(Document.id.in_(mentions), Document.is_current.is_(True), *_visible(max_tlp))
        .order_by(Document.created_at.desc(), Document.id)
        .limit(_REPORT_CAP + 1)
    )
    return [_ref(d) for d in rows]


def _flaw_context(db: Session, cve: str, max_tlp: str | None) -> tuple[list[str], bool, str]:
    """Public catalog metadata plus visible exploit-report signals, with the latter's label preserved."""
    lines = [f'{cve} is a software flaw. First check whether you use the affected product and version.']
    kev = db.get(KEVRecord, cve)
    if kev:
        lines += [
            f'CISA lists this flaw as used in real attacks. Listed since {kev.date_added}. '
            f'Product: {_text(kev.vendor)} {_text(kev.product)}.',
            'Check the vendor notice for fixed versions and steps to reduce risk. '
            'Patching closes the flaw; it does not tell you whether an earlier attack succeeded.',
        ]
    context = exploit_context(db, [cve], max_tlp=max_tlp).get(cve)
    if context and context.public_exploit:
        lines.append(
            'Saved evidence says exploit code is public. Public code does not prove an attack occurred.'
        )
    if context and context.reported_exploited:
        lines.append('The saved VulnCheck catalog answer lists this flaw as used in attacks.')
    if not kev and not (context and context.reported_exploited):
        lines.append('The saved catalogs do not confirm use in attacks. This is not proof that it is unused.')
    # Context counts can include more reports than the 20 shown in the plan. Include every contributing
    # visible report's label, so an AMBER exploit claim never becomes a CLEAR export.
    from ..models import ExploitSignal

    labels = list(
        db.scalars(
            select(Document.tlp)
            .join(ExploitSignal, ExploitSignal.document_id == Document.id)
            .where(
                ExploitSignal.cve == cve,
                Document.is_current.is_(True),
                *_visible(max_tlp),
                Document.id.in_(
                    select(Observation.document_id)
                    .join(Entity, Entity.id == Observation.entity_id)
                    .where(Entity.value == cve, Entity.kind == 'cve', Observation.review_status != 'rejected')
                ),
            )
            .distinct()
        )
    )
    return (
        lines,
        bool(kev or (context and (context.public_exploit or context.reported_exploited))),
        (most_restrictive('CLEAR', *labels)),
    )


def _campaign(
    db: Session, ref: str, max_tlp: str | None
) -> tuple[str, str, list[str], list[ReportRef], list[str]]:
    campaign = get_campaign(db, ref, max_tlp=max_tlp)
    links = list_threat_links(db, 'campaign', ref, max_tlp=max_tlp, limit=200)
    doc_labels = {link.target_id: link.tlp for link in links if link.target_kind == 'document'}
    reports = [
        _ref(d, doc_labels[d.id])
        for d in db.scalars(
            select(Document)
            .where(Document.id.in_(doc_labels), Document.is_current.is_(True), *_visible(max_tlp))
            .order_by(Document.created_at.desc(), Document.id)
            .limit(_REPORT_CAP + 1)
        )
    ]
    techniques = [link.target_id for link in links if link.target_kind == 'technique']
    why = [
        'Start with reports and techniques an analyst linked to this campaign. '
        'Shared names, methods or indicators do not prove that events are related.'
    ]
    if len(links) == 200:
        why.append('This plan uses the first 200 visible links. Review the campaign page for more.')
    if any(link.target_kind in ('indicator', 'software') for link in links):
        why.append(
            'The campaign also has indicator or software links. Review them on its page. '
            'The indicator list below uses only reviewed mentions in the linked reports.'
        )
    label = most_restrictive(campaign.tlp, *(link.tlp for link in links))
    return campaign.name, label, why, reports, techniques


def _report_flaws(db: Session, doc_id: str, max_tlp: str | None) -> tuple[list[str], str]:
    """CVE mentions select cached facts; they never infer a report's actor or method."""
    values = list(
        db.scalars(
            select(Entity.value)
            .join(Observation, Observation.entity_id == Entity.id)
            .where(
                Observation.document_id == doc_id,
                Observation.review_status != 'rejected',
                Entity.kind == 'cve',
            )
            .distinct()
            .order_by(Entity.value)
            .limit(13)
        )
    )
    lines, labels = [], []
    for cve in values[:12]:
        facts, _, label = _flaw_context(db, cve, max_tlp)
        lines.extend(facts)
        labels.append(label)
    if len(values) > 12:
        lines.append('Shows the first 12 flaws in the report. Read the full report for the rest.')
    return lines, most_restrictive('CLEAR', *labels)


def _subject_parts(
    db: Session, kind: str, ref: str, *, max_tlp: str | None = None, now: datetime
) -> tuple[HuntGuide, list[ReportRef], tuple[str, ...], tuple[SweepEntry, ...]]:
    """Keep the plan's actual evidence beside its text for an explicit save."""
    from .hunt_guides import _evidence

    label = 'CLEAR'
    techniques: list[str] = []
    if kind == 'campaign':
        name, label, why, reports, techniques = _campaign(db, ref, max_tlp)
    elif kind == 'document':
        doc = db.scalar(
            select(Document).where(Document.id == ref, Document.is_current.is_(True), *_visible(max_tlp))
        )
        if doc is None:
            raise LookupError('Hunt guide choice not found')
        name, reports = doc.title, [_ref(doc)]
        why = [
            f'Start with this saved report or advisory from {_text(doc.source_name)}.',
            'Read the source for affected products, dates and attack methods. '
            'A bulletin may describe a risk without saying that an attack happened.',
            f'Source reference: {_text(doc.source_url) or "No source URL was saved."}',
        ]
        flaws, label = _report_flaws(db, doc.id, max_tlp)
        why.extend(flaws)
    elif kind in ('cve', 'exploit', 'indicator'):
        stmt = _entities(max_tlp)
        if kind == 'indicator':
            stmt = stmt.where(Entity.id == ref)
        else:
            stmt = stmt.where(Entity.kind == 'cve', Entity.value == ref.strip().upper())
        entity = db.scalar(stmt)
        if entity is None:
            raise LookupError('Hunt guide choice not found')
        name, reports = entity.value, _reports(db, entity, max_tlp)
        ref = entity.id if kind == 'indicator' else entity.value
        if entity.kind == 'cve':
            why, exploitable, label = _flaw_context(db, entity.value, max_tlp)
            if kind == 'exploit' and not exploitable:
                raise LookupError('Hunt guide choice not found')
            why += [
                'Check exposed systems, unusual sign-ins and new processes around the dates in the reports. '
                'Use the vendor notice to choose the exact logs and signs to check.',
            ]
        else:
            why = [
                f'Start by reviewing this {entity.kind} value: {_text(entity.value)}.',
                'A mention is not a harmful verdict. Check its source, review state and age first. '
                'A match in your logs is a lead to review, not proof of an attack.',
            ]
    else:
        raise LookupError('Hunt guide choice not found')
    techniques += list(
        db.scalars(
            select(DocumentTechnique.technique_id)
            .where(
                DocumentTechnique.document_id.in_([r.document_id for r in reports[:_REPORT_CAP]]),
                DocumentTechnique.status == TAGGED,
            )
            .distinct()
            .order_by(DocumentTechnique.technique_id)
        )
    )
    evidence, evidence_label, sweep = _evidence(db, reports, max_tlp, now)
    sections = (
        GuideSection('Why this hunt matters', tuple(_text(line) for line in why)),
        *planning_sections(techniques),
        *evidence,
        GuideSection(
            'Gaps and limits',
            (
                'This is a plan, not proof that your systems are affected. '
                'No search, exploit or rule has run.',
                'Only current reports within your sharing limit are used. Publisher text and private notes '
                'are left out. Open the report for full context and reuse terms.',
                'Techniques come from saved report tags or explicit campaign links. '
                'They are context to review, not proof that a flaw has a specific attack method.',
                'Only eligible reviewed indicators are listed for checks. Known safe, warning-listed and '
                'expired-verdict indicators are left out. '
                'An accepted indicator may still have an unknown verdict.',
                'No match does not prove safety. Confirm the time range and log coverage in your hunt tool.',
            ),
        ),
    )
    guide = HuntGuide(
        kind,
        ref,
        _text(f'Threat hunt guide: {name}'),
        'A plan based on saved evidence, with checks to tailor to your systems.',
        most_restrictive(label, evidence_label),
        now.isoformat(),
        sections,
    )
    return guide, reports, tuple(techniques), sweep


def hunt_guide_subject(
    db: Session, kind: str, ref: str, *, max_tlp: str | None = None, now: datetime
) -> HuntGuide:
    """Build from a reader-visible subject. Hidden, rejected-only and missing subjects look the same."""
    return _subject_parts(db, kind, ref, max_tlp=max_tlp, now=now)[0]
