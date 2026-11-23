"""A bounded activity timeline, with explicit source and date meanings; never inferred attribution."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import ActorDocument, Document, Entity, HuntPackage, Observation, Sighting
from ..schemas import most_restrictive
from .actor_campaigns import actor_campaigns
from .actor_reports import _guide_reports
from .actors import GroupSubject, resolve_group
from .common import stamp
from .tlp import _visible, visible_levels

MAX_EVENTS = 200
MAX_INDICATORS = 5_000


@dataclass(frozen=True, slots=True)
class TimelineEvent:
    id: str
    at: str
    kind: str
    title: str
    source: str
    source_ref: str
    relation: str
    tlp: str
    detail: str = ''
    url: str = ''


@dataclass(frozen=True, slots=True)
class ActorTimeline:
    ref: str
    since: str
    until: str
    tlp: str
    events: tuple[TimelineEvent, ...]
    truncated: bool
    limit: int


def timeline_json(timeline: ActorTimeline) -> dict[str, Any]:
    return {'format': 'insight-actor-timeline-1', **asdict(timeline)}


def _date(value: str) -> str | None:
    try:
        parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
    except ValueError:
        return None
    return stamp(parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed.astimezone(UTC))


def _public(subject: GroupSubject) -> list[TimelineEvent]:
    events = []
    for campaign in subject.catalog.campaigns if subject.catalog else ():
        dates = [('first_seen', campaign.first_seen)]
        if campaign.last_seen != campaign.first_seen:
            dates.append(('last_seen', campaign.last_seen))
        for kind, when in dates:
            events.append(
                TimelineEvent(
                    f'attack:{campaign.id}:{kind}',
                    when,
                    f'campaign_{kind}',
                    campaign.name,
                    'MITRE ATT&CK',
                    campaign.id,
                    'catalog association',
                    subject.tlp,
                    f'Campaign {kind.replace("_", " ")} according to ATT&CK; not a local observation.',
                    campaign.url,
                )
            )
    return events


def _packages(db: Session, subject: GroupSubject, max_tlp: str | None) -> tuple[list[TimelineEvent], bool]:
    rows = list(
        db.scalars(
            select(HuntPackage)
            .where(
                HuntPackage.group_ref == subject.ref,
                HuntPackage.tlp.in_(visible_levels(max_tlp)),
                HuntPackage.status.in_(('published', 'retired')),
            )
            .order_by(HuntPackage.updated_at.desc(), HuntPackage.id)
            .limit(MAX_EVENTS + 1)
        )
    )
    events = []
    for package in rows:
        dates = [('published', package.published_at)]
        if package.status == 'retired':
            dates.append(('retired', package.updated_at))
        for kind, when in dates:
            if when:
                events.append(
                    TimelineEvent(
                        f'package:{package.id}:{kind}:{package.publication}',
                        when,
                        f'hunt_{kind}',
                        package.title,
                        'Hunt package',
                        package.id,
                        'explicit group',
                        most_restrictive(subject.tlp, package.tlp),
                        f'Latest recorded {kind} time; earlier publication cycles are not retained.',
                    )
                )
    return events, len(rows) > MAX_EVENTS


def _sightings(
    db: Session, subject: GroupSubject, max_tlp: str | None, since: str, until: str
) -> tuple[list[TimelineEvent], bool]:
    # Only accepted indicators in current, explicitly linked reports. A literal name match is insufficient.
    support = db.execute(
        select(Observation.entity_id, Document.tlp, ActorDocument.tlp)
        .join(Document, Document.id == Observation.document_id)
        .join(ActorDocument, ActorDocument.document_id == Document.id)
        .where(
            ActorDocument.group_ref == subject.ref,
            ActorDocument.tlp.in_(visible_levels(max_tlp)),
            *_visible(max_tlp),
            Document.is_current.is_(True),
            Observation.review_status == 'accepted',
        )
        .order_by(Document.created_at.desc(), Document.id, Observation.id)
        .limit(MAX_INDICATORS + 1)
    ).all()
    labels: dict[str, str] = {}
    for entity_id, doc_tlp, link_tlp in support[:MAX_INDICATORS]:
        labels[entity_id] = most_restrictive(subject.tlp, labels.get(entity_id, 'CLEAR'), doc_tlp, link_tlp)
    if not labels:
        return [], False
    rows = db.execute(
        select(Sighting, Entity.kind, Entity.value)
        .join(Entity, Entity.id == Sighting.entity_id)
        .where(
            Sighting.entity_id.in_(labels),
            Sighting.tlp.in_(visible_levels(max_tlp)),
            Sighting.last_seen >= since,
            Sighting.first_seen <= until,
        )
        .order_by(Sighting.last_seen.desc(), Sighting.id)
        .limit(MAX_EVENTS + 1)
    ).all()
    events = []
    for sighting, kind, value in rows:
        dates = [('first_seen', sighting.first_seen)]
        if sighting.last_seen != sighting.first_seen:
            dates.append(('last_seen', sighting.last_seen))
        for seen, when in dates:
            events.append(
                TimelineEvent(
                    f'sighting:{sighting.id}:{seen}',
                    when,
                    f'sighting_{seen}',
                    f'{kind}: {value}',
                    'Indicator sighting',
                    sighting.id,
                    'indicator in linked report',
                    most_restrictive(labels[sighting.entity_id], sighting.tlp),
                    f'{sighting.count} reported occurrence(s). '
                    f'{sighting.location or sighting.observer or "Location not given"}. '
                    'This does not attribute the sighting to this actor.',
                )
            )
    return events, len(rows) > MAX_EVENTS or len(support) > MAX_INDICATORS


def actor_timeline(
    db: Session, ref: str, *, max_tlp: str | None = None, now: datetime, days: int = 3650, limit: int = 100
) -> ActorTimeline:
    """Newest dated facts first. Date range is inclusive; caps apply after each source's TLP filtering.

    Report scans are bounded by the existing guide policy (200 linked, 50 named, 5,000 scanned).
    The capped flag is conservative when a source reaches its bound. No hidden counts are returned.
    """
    if not 1 <= days <= 36500 or not 1 <= limit <= MAX_EVENTS:
        raise ValueError('Use 1–36,500 days and 1–200 events')
    subject = resolve_group(db, ref, max_tlp=max_tlp)
    now = now.replace(tzinfo=UTC) if now.tzinfo is None else now.astimezone(UTC)
    since, until = stamp(now - timedelta(days=days)), stamp(now)
    events = _public(subject)
    reports, _, report_cap = _guide_reports(db, subject, max_tlp, current_only=True)
    for report in reports:
        events.append(
            TimelineEvent(
                f'report:{report.document_id}',
                report.created_at,
                'report_added',
                report.title,
                report.source_name,
                report.document_id,
                report.via,
                most_restrictive(subject.tlp, report.tlp),
                'Date added to Insight. '
                + (
                    'An analyst linked this report.'
                    if report.via == 'linked'
                    else 'This report names the group; naming is not attribution.'
                ),
                f'/?report={report.document_id}',
            )
        )
    campaigns = actor_campaigns(db, subject.ref, max_tlp=max_tlp, limit=MAX_EVENTS + 1)
    for campaign in campaigns:
        events.append(
            TimelineEvent(
                f'campaign:{campaign.id}',
                campaign.linked_at,
                'campaign_linked',
                campaign.name,
                'Analyst campaign',
                campaign.campaign_id,
                'explicit association',
                campaign.tlp,
                'Date an analyst linked the campaign; not an inferred activity date. ' + campaign.note,
            )
        )
    packages, package_cap = _packages(db, subject, max_tlp)
    sightings, sighting_cap = _sightings(db, subject, max_tlp, since, until)
    events.extend(packages)
    events.extend(sightings)
    dated = [
        TimelineEvent(e.id, at, e.kind, e.title, e.source, e.source_ref, e.relation, e.tlp, e.detail, e.url)
        for e in events
        if (at := _date(e.at)) is not None and since <= at <= until
    ]
    dated.sort(key=lambda e: (e.at, e.kind, e.id), reverse=True)
    chosen = tuple(dated[:limit])
    source_capped = package_cap or sighting_cap or len(campaigns) > MAX_EVENTS or report_cap
    capped = len(dated) > limit or source_capped
    # Truncation is intelligence too: an omitted AMBER event cannot change a CLEAR envelope's metadata.
    # When a source scan is capped, conservatively mark its flag at the reader ceiling (RED if unlimited).
    floor = (max_tlp or 'RED') if source_capped else subject.tlp
    return ActorTimeline(
        subject.ref,
        since,
        until,
        most_restrictive(subject.tlp, floor, *(e.tlp for e in dated)),
        chosen,
        capped,
        limit,
    )
