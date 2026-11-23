"""Dated provenance, explicit association and TLP boundaries for actor timelines."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from insight import services
from insight.models import ActorCampaign, ActorDocument, AuditEvent, Document, HuntPackage, Observation
from insight.schemas import (
    ActorCampaignInput,
    ActorInput,
    ActorLinkInput,
    CampaignInput,
    DocumentInput,
    SightingInput,
    ThreatLinkInput,
)
from insight.taxii import INDICATORS_COLLECTION
from insight.threat_guide import compose, guide_json
from insight.threat_guide_markdown import to_markdown
from insight.threat_library import library

NOW = datetime(2026, 11, 22, 18, tzinfo=UTC)


def report(db: Session, title: str, *, tlp: str = 'GREEN', linked: bool = True) -> Document:
    row, _ = services.ingest(
        db,
        DocumentInput.model_validate(
            {
                'title': title,
                'body': 'APT29 observed near 192.0.2.7.',
                'source_name': 'Synthetic feed',
                'tlp': tlp,
            }
        ),
    )
    row.created_at = (NOW - timedelta(days=2)).isoformat()
    for observation in db.scalars(select(Observation).where(Observation.document_id == row.id)):
        services.set_observation_status(db, observation.id, 'accepted')
    if linked:
        services.link_report(db, 'G0016', ActorLinkInput(document_id=row.id))
    db.flush()
    return row


def test_all_event_sources_and_exports_share_labels_and_date_meanings(db: Session) -> None:
    doc = report(db, 'Linked report')
    report(db, 'Named report', linked=False)
    campaign = services.create_campaign(db, CampaignInput(name='Analyst series', tlp='GREEN'))
    association = services.link_actor_campaign(db, 'G0016', ActorCampaignInput(campaign_id=campaign.id))
    association.created_at = (NOW - timedelta(days=1)).isoformat()
    package = HuntPackage(
        title='Latest package',
        hypothesis='Test hypothesis',
        group_ref='G0016',
        tlp='GREEN',
        status='retired',
        published_at=(NOW - timedelta(days=3)).isoformat(),
        updated_at=(NOW - timedelta(hours=4)).isoformat(),
    )
    db.add(package)
    services.record_sighting(
        db,
        SightingInput(
            value='192.0.2.7',
            first_seen=NOW - timedelta(hours=3),
            last_seen=NOW - timedelta(hours=1),
            tlp='GREEN',
        ),
    )
    timeline = services.actor_timeline(db, 'G0016', max_tlp='GREEN', now=NOW, days=36500)
    kinds = {event.kind for event in timeline.events}
    assert {
        'report_added',
        'campaign_linked',
        'hunt_published',
        'hunt_retired',
        'sighting_first_seen',
        'sighting_last_seen',
        'campaign_first_seen',
    } <= kinds
    linked = [event for event in timeline.events if event.source_ref == doc.id]
    assert len(linked) == 1
    assert linked[0].relation == 'linked'
    assert linked[0].at == doc.created_at
    assert timeline.tlp == 'GREEN'
    assert list(timeline.events) == sorted(timeline.events, key=lambda e: (e.at, e.kind, e.id), reverse=True)
    guide = compose(services.guide_data(db, 'G0016', max_tlp='GREEN', now=NOW), library())
    assert guide.data.timeline is not None
    assert guide_json(guide)['timeline'] == services.timeline_json(guide.data.timeline)
    markdown = to_markdown(guide)
    assert '## Activity timeline' in markdown
    assert 'Analyst series' in markdown
    assert 'not an inferred activity date' in markdown


def test_no_campaign_or_sighting_association_from_names_or_shared_evidence(db: Session) -> None:
    doc = report(db, 'Only a name', linked=False)
    campaign = services.create_campaign(db, CampaignInput(name='Unassociated series', tlp='GREEN'))
    services.link_threat(
        db, 'campaign', campaign.id, ThreatLinkInput(target_kind='document', target_id=doc.id, tlp='GREEN')
    )
    services.record_sighting(
        db, SightingInput(value='192.0.2.7', first_seen=NOW - timedelta(hours=1), tlp='GREEN')
    )
    events = services.actor_timeline(db, 'G0016', max_tlp='GREEN', now=NOW).events
    assert any(e.kind == 'report_added' and e.relation == 'named' for e in events)
    assert not any(e.kind.startswith('sighting') or e.kind == 'campaign_linked' for e in events)


def test_hidden_sources_and_links_do_not_change_visible_timeline(db: Session) -> None:
    before = services.actor_timeline(db, 'G0016', max_tlp='GREEN', now=NOW)
    hidden = report(db, 'HIDDEN report', tlp='AMBER')
    campaign = services.create_campaign(db, CampaignInput(name='HIDDEN campaign', tlp='AMBER'))
    services.link_actor_campaign(db, 'G0016', ActorCampaignInput(campaign_id=campaign.id))
    db.add(
        HuntPackage(
            title='HIDDEN package',
            hypothesis='secret',
            group_ref='G0016',
            tlp='AMBER',
            status='published',
            published_at=(NOW - timedelta(hours=1)).isoformat(),
        )
    )
    services.record_sighting(
        db,
        SightingInput(
            value='192.0.2.7', first_seen=NOW - timedelta(hours=1), where='HIDDEN place', tlp='AMBER'
        ),
    )
    assert services.actor_timeline(db, 'G0016', max_tlp='GREEN', now=NOW) == before
    public = report(db, 'Public report')
    link = db.scalar(select(ActorDocument).where(ActorDocument.document_id == public.id))
    assert link is not None
    link.tlp = 'AMBER'
    db.flush()
    timeline = services.actor_timeline(db, 'G0016', max_tlp='GREEN', now=NOW)
    assert not any(e.kind.startswith('sighting') for e in timeline.events)
    assert 'HIDDEN' not in str(services.timeline_json(timeline))
    assert hidden.id not in str(timeline)
    own = services.create_actor(db, ActorInput(name='Hidden actor', tlp='AMBER'))
    for ref in (own.id, 'absent'):
        with pytest.raises(LookupError):
            services.actor_timeline(db, ref, max_tlp='GREEN', now=NOW)


def test_campaign_links_audited_idempotent_sticky_and_never_inferred(db: Session) -> None:
    campaign = services.create_campaign(db, CampaignInput(name='Campaign', tlp='GREEN'))
    payload = ActorCampaignInput(campaign_id=campaign.id, note='Reason', tlp='AMBER')
    with pytest.raises(services.TlpNotPermitted):
        services.link_actor_campaign(db, 'G0016', payload, max_tlp='GREEN')
    first = services.link_actor_campaign(db, 'G0016', payload)
    assert services.link_actor_campaign(db, 'G0016', payload).id == first.id
    assert campaign.tlp == 'AMBER'
    assert services.actor_campaigns(db, 'G0016', max_tlp='GREEN') == []
    with pytest.raises(LookupError):
        services.unlink_actor_campaign(db, 'G0016', campaign.id, max_tlp='GREEN')
    services.unlink_actor_campaign(db, 'G0016', campaign.id)
    db.flush()
    assert campaign.tlp == 'AMBER'
    assert db.scalar(select(ActorCampaign)) is None
    actions = list(db.scalars(select(AuditEvent.action).where(AuditEvent.action.like('actor.campaign.%'))))
    assert actions == ['actor.campaign.link', 'actor.campaign.unlink']


def test_bounds_dates_and_known_latest_package_cycle(db: Session) -> None:
    report(db, 'A report')
    report(db, 'Another report')
    limited = services.actor_timeline(db, 'G0016', now=NOW, limit=1)
    assert len(limited.events) == 1
    assert limited.truncated
    assert not services.actor_timeline(db, 'G0016', now=NOW, days=1).events
    for days, limit in ((0, 1), (1, 0), (36501, 1), (1, 201)):
        with pytest.raises(ValueError, match='events'):
            services.actor_timeline(db, 'G0016', now=NOW, days=days, limit=limit)
    package = HuntPackage(
        title='Republished',
        hypothesis='Hypothesis',
        group_ref='G0016',
        tlp='GREEN',
        status='published',
        publication=2,
        published_at=(NOW - timedelta(hours=2)).isoformat(),
    )
    db.add(package)
    db.flush()
    events = [e for e in services.actor_timeline(db, 'G0016', now=NOW).events if e.source_ref == package.id]
    assert len(events) == 1
    assert events[0].id.endswith(':2')
    assert 'earlier publication cycles are not retained' in events[0].detail


def test_superseded_reports_and_their_sightings_are_not_current_activity(db: Session) -> None:
    doc = report(db, 'Old revision')
    services.record_sighting(
        db, SightingInput(value='192.0.2.7', first_seen=NOW - timedelta(hours=1), tlp='GREEN')
    )
    doc.is_current = False
    db.flush()
    timeline = services.actor_timeline(db, 'G0016', now=NOW)
    assert not any(e.source_ref == doc.id or e.kind.startswith('sighting') for e in timeline.events)


def test_campaign_label_raise_is_a_new_taxii_version(db: Session) -> None:
    """Regression: a new association's sticky marking must not reuse a campaign's old STIX modified time."""
    doc = report(db, 'Export report')
    campaign = services.create_campaign(db, CampaignInput(name='Shared campaign', tlp='GREEN'))
    campaign.created_at = campaign.updated_at = '2020-01-01T00:00:00+00:00'
    services.link_threat(
        db, 'campaign', campaign.id, ThreatLinkInput(target_kind='document', target_id=doc.id, tlp='GREEN')
    )
    db.flush()
    before = services.taxii_collection_objects(db, INDICATORS_COLLECTION, max_tlp=None)
    old = next(item for item in before if item.id == f'campaign--{campaign.id}')
    services.link_actor_campaign(db, 'G0016', ActorCampaignInput(campaign_id=campaign.id, tlp='AMBER'))
    after = services.taxii_collection_objects(db, INDICATORS_COLLECTION, max_tlp=None)
    new = next(item for item in after if item.id == old.id)
    assert new.date_added > old.date_added
    assert new.obj['modified'] > old.obj['modified']
    assert new.obj['created'] == old.obj['created']
    assert not any(
        item.id == old.id
        for item in services.taxii_collection_objects(db, INDICATORS_COLLECTION, max_tlp='GREEN')
    )


def test_truncation_metadata_keeps_the_omitted_event_label(db: Session) -> None:
    """Regression: an omitted AMBER event cannot change a CLEAR timeline's truncated flag."""
    actor = services.create_actor(db, ActorInput(name='Synthetic actor', tlp='CLEAR'))
    newest = report(db, 'Public event', tlp='CLEAR', linked=False)
    services.link_report(db, actor.id, ActorLinkInput(document_id=newest.id))
    before = services.actor_timeline(db, actor.id, now=NOW, limit=1)
    assert before.tlp == 'CLEAR'
    assert not before.truncated
    older = report(db, 'Restricted event', tlp='AMBER', linked=False)
    older.created_at = (NOW - timedelta(days=3)).isoformat()
    services.link_report(db, actor.id, ActorLinkInput(document_id=older.id))
    after = services.actor_timeline(db, actor.id, now=NOW, limit=1)
    assert after.events == before.events
    assert after.truncated
    assert after.tlp == 'AMBER'
    assert services.actor_timeline(db, actor.id, now=NOW, limit=1, max_tlp='GREEN') == before


def test_source_cap_metadata_uses_a_conservative_reader_label(
    db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Regression: scan-cap flags include their provenance even when all returned events are CLEAR."""
    monkeypatch.setattr('insight.services.actor_reports.MAX_NAMED', 1)
    report(db, 'First named', tlp='CLEAR', linked=False)
    report(db, 'Second named', tlp='CLEAR', linked=False)
    limited = services.actor_timeline(db, 'G0016', now=NOW, max_tlp='GREEN')
    assert limited.truncated
    assert limited.tlp == 'GREEN'
    assert services.actor_timeline(db, 'G0016', now=NOW).tlp == 'RED'
