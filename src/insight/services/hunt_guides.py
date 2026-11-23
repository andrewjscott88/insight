"""Read-only hunt plans from catalog facts and reader-visible, explicit evidence (ADR 0041)."""

from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from ..hunt_guide import GuideSection, HuntGuide, bounded
from ..hunt_guide_plan import planning_sections
from ..models import Document, DocumentTechnique, SoftwareDocument, ThreatActor
from ..schemas import most_restrictive
from ..themes import THEMES, THEMES_BY_KEY, Theme
from ..threat_library import library
from .actor_reports import ReportRef
from .actors import actor_aliases, linked_reports, resolve_group
from .common import fold, like_pattern
from .techniques import TAGGED
from .threat_guides import GuideData, sweep_list
from .tlp import _visible, visible_levels

_KINDS = ('theme', 'actor', 'software', 'cve', 'document', 'exploit', 'indicator', 'campaign')
_MAX_REPORTS = 20
_MAX_INDICATORS = 100
_MAX_TEXT = 1_200


def _text(value: str) -> str:
    clean = ' '.join(value.split())
    return clean if len(clean) <= _MAX_TEXT else clean[: _MAX_TEXT - 16] + ' [text shortened]'


def _label(name: str, ref: str, aliases: tuple[str, ...] = ()) -> str:
    other = ', '.join(aliases[:5])
    return _text(f'{name} ({ref})' + (f' — {other}' if other else ''))


def _choices(db: Session, kind: str, q: str, max_tlp: str | None) -> list[tuple[str, str]]:
    lib, query = library(), q.casefold()
    if kind == 'theme':
        return [(t.key, t.name) for t in THEMES if query in f'{t.name} {t.key}'.casefold()]
    if kind == 'software':
        items = sorted(lib.software.values(), key=lambda s: (s.name.casefold(), s.id))
        return [
            (s.id, _label(s.name, s.id, s.aliases))
            for s in items
            if any(query in name.casefold() for name in (s.id, *s.names))
        ][:50]
    if kind == 'actor':
        groups = [
            (g.id, _label(g.name, g.id, g.aliases))
            for g in lib.groups.values()
            if any(query in name.casefold() for name in (g.id, *g.names))
        ]
        pattern = like_pattern(q)
        stmt = (
            select(ThreatActor)
            .where(
                ThreatActor.tlp.in_(visible_levels(max_tlp)),
                or_(
                    ThreatActor.name.ilike(pattern, escape='\\'),
                    ThreatActor.aliases.ilike(pattern, escape='\\'),
                    ThreatActor.id.ilike(pattern, escape='\\'),
                ),
            )
            .order_by(ThreatActor.name, ThreatActor.id)
            .limit(50)
        )
        groups += [(a.id, _label(a.name, a.id, actor_aliases(a))) for a in db.scalars(stmt)]
        return sorted(groups, key=lambda pair: (pair[1].casefold(), pair[0]))[:50]
    from .hunt_guide_subjects import hunt_guide_subject_choices

    return hunt_guide_subject_choices(db, kind=kind, q=q, max_tlp=max_tlp)


def hunt_guide_choices(
    db: Session, *, max_tlp: str | None = None, kind: str | None = None, q: str = ''
) -> dict[str, list[tuple[str, str]]]:
    """Up to 50 matches per kind. Search again to reach choices beyond that first page."""
    if kind is not None and kind not in _KINDS:
        raise LookupError('Hunt guide choice not found')
    return {k: _choices(db, k, q.strip()[:120], max_tlp) for k in ((kind,) if kind else _KINDS)}


def _theme_reports(db: Session, theme: Theme, max_tlp: str | None) -> list[ReportRef]:
    matches = [Document.search_text.like(like_pattern(fold(w)), escape='\\') for w in theme.words]
    if theme.techniques:
        tagged = select(DocumentTechnique.document_id).where(
            DocumentTechnique.status == TAGGED,
            or_(
                *(DocumentTechnique.technique_id == tid for tid in theme.techniques),
                *(DocumentTechnique.technique_id.like(f'{tid}.%') for tid in theme.techniques),
            ),
        )
        matches.append(Document.id.in_(tagged))
    rows = db.execute(
        select(Document.id, Document.title, Document.tlp, Document.created_at, Document.source_name)
        .where(Document.is_current.is_(True), *_visible(max_tlp), or_(*matches))
        .order_by(Document.created_at.desc(), Document.id)
        .limit(_MAX_REPORTS + 1)
    )
    return [ReportRef(*row, 'theme', '') for row in rows]


def _software_reports(db: Session, ref: str, max_tlp: str | None) -> list[ReportRef]:
    rows = db.execute(
        select(
            Document.id,
            Document.title,
            Document.tlp,
            Document.created_at,
            Document.source_name,
            SoftwareDocument.tlp,
        )
        .join(SoftwareDocument, SoftwareDocument.document_id == Document.id)
        .where(
            SoftwareDocument.software_id == ref,
            SoftwareDocument.tlp.in_(visible_levels(max_tlp)),
            Document.is_current.is_(True),
            *_visible(max_tlp),
        )
        .order_by(Document.created_at.desc(), Document.id)
        .limit(_MAX_REPORTS + 1)
    )
    return [
        ReportRef(i, title, most_restrictive(tlp, link), created, source, 'linked', '')
        for i, title, tlp, created, source, link in rows
    ]


def _evidence(
    db: Session, reports: list[ReportRef], max_tlp: str | None, now: datetime
) -> tuple[tuple[GuideSection, ...], str]:
    shown = reports[:_MAX_REPORTS]
    sweep, truncated = sweep_list(db, shown, max_tlp=max_tlp, now=now)
    indicators = [
        f'{e.kind}: {_text(e.value)}. Review: accepted; verdict: {e.verdict}. '
        f'First report: {e.first_seen[:10]}; last report: {e.last_seen[:10]}. '
        f'Reports: {", ".join(e.reports[:5])}.'
        for e in sweep[:_MAX_INDICATORS]
    ]
    if truncated or len(sweep) > _MAX_INDICATORS:
        indicators.append(
            f'Shows the first {_MAX_INDICATORS} eligible indicators. Use report pages for more.'
        )
    urls = dict(
        db.execute(
            select(Document.id, Document.source_url).where(
                Document.id.in_([r.document_id for r in shown]), *_visible(max_tlp)
            )
        ).all()
    )
    sources = [
        f'{_text(r.title)}. Source: {_text(r.source_name)}. Added: {r.created_at[:10]}. '
        f'TLP:{r.tlp}. Report: {r.document_id}.'
        + (f' Source URL: {_text(urls[r.document_id])}' if urls.get(r.document_id) else '')
        for r in shown
    ]
    if len(reports) > _MAX_REPORTS:
        sources.append(
            f'Shows the latest {_MAX_REPORTS} matching reports. Other reports are not in this plan.'
        )
    return (
        (
            GuideSection(
                'Reviewed indicators to check',
                tuple(indicators) or ('No eligible reviewed indicators are in these reports yet.',),
            ),
            GuideSection(
                'Reports used', tuple(sources) or ('No current, linked or matching reports are available.',)
            ),
        ),
        most_restrictive('CLEAR', *(r.tlp for r in reports), *(e.tlp for e in sweep)),
    )


def _actor(
    db: Session, ref: str, max_tlp: str | None, now: datetime
) -> tuple[str, str, str, list[str], list[ReportRef], tuple[str, ...]]:
    # Compose the established actor plan with only current, explicit links. Named reports and unrelated
    # trends do not become attribution, evidence or labels in this focused product.
    from ..threat_guide import compose

    subject = resolve_group(db, ref, max_tlp=max_tlp)
    reports = [
        ReportRef(d.id, d.title, most_restrictive(d.tlp, link.tlp), d.created_at, d.source_name, 'linked', '')
        for d, link in linked_reports(db, subject.ref, max_tlp=max_tlp, current_only=True)
    ][: _MAX_REPORTS + 1]
    techniques = Counter(
        db.scalars(
            select(DocumentTechnique.technique_id).where(
                DocumentTechnique.document_id.in_([r.document_id for r in reports[:_MAX_REPORTS]]),
                DocumentTechnique.status == TAGGED,
            )
        )
    )
    data = GuideData(
        subject,
        (),
        (),
        tuple(reports),
        0,
        dict(techniques),
        {},
        (),
        False,
        (),
        (),
        now.isoformat(),
        max_tlp,
    )
    plan = compose(data, library())
    return (
        subject.ref,
        subject.name,
        subject.tlp,
        [
            'Start with the methods in the threat library and reports an analyst linked to this group. '
            'A shared method or indicator does not prove who is behind an event.'
        ],
        reports,
        tuple(h.technique_id for h in plan.hypotheses),
    )


def hunt_guide(
    db: Session, kind: str, ref: str, *, max_tlp: str | None = None, now: datetime | None = None
) -> HuntGuide:
    """Build a bounded plan, without saving a hunt, product, finding or attribution."""
    when = now or datetime.now(UTC)
    if kind == 'actor':
        ref, name, label, why, reports, techniques = _actor(db, ref, max_tlp, when)
    elif kind == 'theme':
        theme = THEMES_BY_KEY.get(ref)
        if theme is None:
            raise LookupError('Hunt guide choice not found')
        name, label = theme.name, 'CLEAR'
        why = [theme.what, theme.impact, theme.check]
        why.append(
            'Reports match the words or techniques used by this threat type in Intel Brief. '
            'A match is context to review; it is not proof of an attack or who caused it.'
        )
        reports, techniques = _theme_reports(db, theme, max_tlp), theme.techniques
    elif kind == 'software':
        item = library().software.get(ref.strip().upper())
        if item is None:
            raise LookupError('Hunt guide choice not found')
        ref, name, label = item.id, item.name, 'CLEAR'
        why = [
            f'Look for the methods the ATT&CK library lists for {item.name}. '
            'Only reports an analyst linked to this software are used. A match does not identify an actor.'
        ]
        reports, techniques = _software_reports(db, ref, max_tlp), item.techniques
    elif kind in _KINDS:
        from .hunt_guide_subjects import hunt_guide_subject

        return bounded(hunt_guide_subject(db, kind, ref, max_tlp=max_tlp, now=when))
    else:
        raise LookupError('Hunt guide choice not found')
    evidence, evidence_label = _evidence(db, reports, max_tlp, when)
    sections = (
        GuideSection('Why this hunt matters', tuple(_text(line) for line in why)),
        *planning_sections(techniques),
        *evidence,
        GuideSection(
            'Gaps and limits',
            (
                'This is a starting plan, not proof that your systems are affected. '
                'No search or rule has run.',
                'Confirm the scope, dates and log coverage before using it. No match does not prove safety.',
                'Only current reports within your sharing limit are used. Publisher text and analyst notes '
                'are left out; open the report in Insight for context and reuse terms.',
                'Unreviewed, known safe, warning-listed and expired-verdict indicators are left out. '
                'An accepted indicator can still have an unknown verdict.',
                f'Technique and log guidance comes from MITRE ATT&CK {library().attack_version}. '
                'Some techniques have no log-based check in this edition.',
            ),
        ),
    )
    return bounded(
        HuntGuide(
            kind,
            ref,
            _text(f'Threat hunt guide: {name}'),
            'A plan to check your own logs, review leads and record what needs a closer look.',
            most_restrictive(label, evidence_label),
            when.isoformat(),
            sections,
        )
    )
