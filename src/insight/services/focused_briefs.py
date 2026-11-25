"""Focused intelligence briefs from stored facts, with dated coverage and explicit associations."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from ..actor_brief import actor_profile
from ..focused_brief import BriefItem, BriefSection, BriefSource, FocusedBrief
from ..models import (
    ActorDocument,
    Document,
    DocumentTechnique,
    Entity,
    ExploitSignal,
    KEVRecord,
    Observation,
    SoftwareDocument,
    ThreatLink,
)
from ..schemas import most_restrictive
from ..themes import THEMES_BY_KEY
from ..threat_library import library
from .actors import analyst_claims, resolve_group
from .campaigns import get_campaign
from .common import fold, like_pattern
from .focused_brief_subjects import _catalog, _dated, _entity_focus, _Focus, _query, _text
from .industry_briefs import _industry_brief
from .techniques import TAGGED
from .tlp import _visible, visible_levels

_REPORT_CAP = 100


def _focus(db: Session, kind: str, ref: str, max_tlp: str | None, moment: datetime) -> _Focus:
    if kind in ('cve', 'exploit', 'indicator'):
        return _entity_focus(db, kind, ref, max_tlp, moment)
    if kind == 'theme':
        theme = THEMES_BY_KEY.get(ref)
        if theme is None:
            raise LookupError('Brief topic not found')
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
        return _Focus(ref, theme.name, 'CLEAR', 'Background: ' + theme.what, _query().where(or_(*matches)))
    if kind == 'actor':
        actor = resolve_group(db, ref, max_tlp=max_tlp)
        query = (
            _query(ActorDocument.tlp)
            .join(ActorDocument, ActorDocument.document_id == Document.id)
            .where(
                ActorDocument.group_ref == actor.ref,
                ActorDocument.tlp.in_(visible_levels(max_tlp)),
            )
        )
        background = (
            _catalog(actor.catalog.description, actor.catalog.name + ' is a threat group')
            if actor.catalog
            else f'{_text(actor.name, 150)} is an actor tracked by your analysts.'
        )
        return _Focus(actor.ref, actor.name, actor.tlp, background, query)
    if kind == 'software':
        software = library().software.get(ref.upper())
        if software is None:
            raise LookupError('Brief topic not found')
        query = (
            _query(SoftwareDocument.tlp)
            .join(
                SoftwareDocument,
                SoftwareDocument.document_id == Document.id,
            )
            .where(
                SoftwareDocument.software_id == software.id, SoftwareDocument.tlp.in_(visible_levels(max_tlp))
            )
        )
        return _Focus(
            software.id,
            software.name,
            'CLEAR',
            _catalog(software.description, software.name + ' is a ' + software.type),
            query,
        )
    if kind == 'campaign':
        campaign = get_campaign(db, ref, max_tlp=max_tlp)
        query = (
            _query(ThreatLink.tlp)
            .join(ThreatLink, ThreatLink.document_id == Document.id)
            .where(
                ThreatLink.campaign_id == ref,
                ThreatLink.tlp.in_(visible_levels(max_tlp)),
            )
        )
        return _Focus(
            ref,
            campaign.name,
            campaign.tlp,
            'This campaign groups activity that your analysts chose to track together.',
            query,
        )
    if kind == 'document':
        doc = db.execute(
            _query().where(Document.id == ref, Document.is_current.is_(True), *_visible(max_tlp))
        )
        row = doc.first()
        if row is None:
            raise LookupError('Brief topic not found')
        return _Focus(
            ref,
            row[1],
            row[2],
            f'Saved report from {_text(row[4], 150)}: {_text(row[1], 200)}.',
            _query().where(Document.id == ref),
        )
    raise LookupError('Brief topic not found')


def _report_facts(db: Session, ids: list[str], cve: str | None, moment: datetime) -> str:
    if not ids:
        return ''
    mentions = (
        select(Entity.value)
        .join(Observation, Observation.entity_id == Entity.id)
        .where(
            Observation.document_id.in_(ids),
            Observation.review_status != 'rejected',
            Entity.kind == 'cve',
        )
    )
    if cve:
        mentions = mentions.where(Entity.value == cve)
    values = list(db.scalars(mentions.distinct().order_by(Entity.value).limit(51)))
    if not values:
        return ''
    selected = values[:50]
    known = [
        row.cve
        for row in db.scalars(select(KEVRecord).where(KEVRecord.cve.in_(selected)).order_by(KEVRecord.cve))
        if _dated(row.date_added, moment)
    ]
    kept = (
        select(Observation.id)
        .join(Entity, Entity.id == Observation.entity_id)
        .where(
            Observation.document_id == ExploitSignal.document_id,
            Entity.value == ExploitSignal.cve,
            Entity.kind == 'cve',
            Observation.review_status != 'rejected',
        )
        .exists()
    )
    code = db.scalar(
        select(ExploitSignal.id)
        .where(
            ExploitSignal.document_id.in_(ids),
            ExploitSignal.cve.in_(selected),
            kept,
        )
        .limit(1)
    )
    prefix = 'Among the first 50 flaws named in these reports, ' if len(values) > 50 else 'In these reports, '
    if known:
        names = ', '.join(known[:3]) + (' and others' if len(known) > 3 else '')
        return prefix + f"{names} appear in CISA's saved list of flaws used in real attacks."
    if code is not None:
        return prefix + 'public exploit code is mentioned. This does not prove that an attack occurred.'
    return prefix + "software flaws are named, but none checked here appear in CISA's saved attack list."


def focused_brief(
    db: Session,
    kind: str,
    ref: str,
    *,
    days: int = 30,
    max_tlp: str | None = None,
    now: datetime | None = None,
) -> FocusedBrief:
    """Summarize one visible topic without inferring attribution or calling a model or provider."""
    if days not in (7, 30):
        raise ValueError('Choose a 7 or 30 day brief')
    moment = now or datetime.now(UTC)
    moment = moment.replace(tzinfo=UTC) if moment.tzinfo is None else moment.astimezone(UTC)
    if kind == 'industry':
        return _industry_brief(db, ref, days=days, max_tlp=max_tlp, now=moment)
    focus = _focus(db, kind, ref, max_tlp, moment)
    cutoff = moment - timedelta(days=days)
    rows = list(
        db.execute(
            focus.query.where(
                Document.is_current.is_(True),
                *_visible(max_tlp),
                Document.created_at >= cutoff.isoformat(),
                Document.created_at <= moment.isoformat(),
            )
            .order_by(Document.created_at.desc(), Document.id)
            .limit(_REPORT_CAP + 1)
        )
    )
    capped = len(rows) > _REPORT_CAP
    reports: list[BriefItem] = []
    labels = [focus.tlp]
    for doc_id, title, label, created_at, source, link_label in rows:
        try:
            added = datetime.fromisoformat(created_at)
            added = added.replace(tzinfo=UTC) if added.tzinfo is None else added.astimezone(UTC)
        except ValueError:
            continue
        if cutoff <= added <= moment:
            labels.extend((label, link_label))
            reports.append(BriefItem(doc_id, _text(title), _text(source, 150), added.isoformat()))
    reports = reports[:_REPORT_CAP]
    count = len(reports)
    scope = 'explicitly linked ' if kind in ('actor', 'software', 'campaign') else 'matching '
    coverage = (
        f'{"At least " if capped else ""}{count} {scope}current report(s) were added in the last {days} days.'
        if count
        else f'No {scope}current reports were added in the last {days} days.'
    )
    facts = _report_facts(
        db,
        [r.document_id for r in reports],
        focus.ref if kind in ('cve', 'exploit') else None,
        moment,
    )
    notes = ['Report dates show when items were added to Insight, not when attacks happened.']
    if capped:
        notes.append('Review is capped at 100 reports and lists five. Background is not new activity.')
    elif count > 5:
        notes.append(
            'Lists the five latest reports. Background facts do not show activity during this period.'
        )
    else:
        notes.append('Background facts do not show recent activity or prove that your systems are affected.')
    summary: tuple[str, ...] = (focus.background, coverage, facts) if facts else (focus.background, coverage)
    sections: tuple[BriefSection, ...] = ()
    sources: tuple[BriefSource, ...] = ()
    if kind == 'actor':
        subject = resolve_group(db, focus.ref, max_tlp=max_tlp)
        claims = analyst_claims(db, max_tlp=max_tlp, group_ref=subject.ref)
        labels.extend(c.effective_tlp for c in claims)
        profile = actor_profile(
            subject.name,
            subject.description,
            subject.aliases,
            subject.catalog,
            library(),
            added=tuple((c.industry, c.citation_url) for c in claims if c.decision == 'added'),
            removed=frozenset(c.industry for c in claims if c.decision == 'removed'),
        )
        summary = profile.summary
        sections = (
            *profile.sections,
            BriefSection(f'Recent reporting: last {days} days', (coverage, facts) if facts else (coverage,)),
        )
        sources = profile.sources
    return FocusedBrief(
        kind,
        focus.ref,
        _text(focus.title),
        most_restrictive(*labels),
        days,
        summary,
        tuple(notes),
        tuple(reports[:5]),
        sections,
        sources,
    )
