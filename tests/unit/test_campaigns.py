"""Manual attribution records, visible endpoints and sharing labels."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from insight import services
from insight.models import ActorDocument, AuditEvent, Entity, ThreatLink
from insight.schemas import (
    ActorInput,
    ActorLinkInput,
    CampaignInput,
    DocumentInput,
    ThreatLinkInput,
    ThreatSubjectKind,
    ThreatTargetKind,
)


def _report(db: Session, title: str, ip: str, tlp: str) -> str:
    item = DocumentInput.model_validate(
        {'title': title, 'source_name': 'Lab', 'body': f'Synthetic report: {ip}, T1059.001.', 'tlp': tlp}
    )
    return services.ingest(db, item)[0].id


def _input(kind: ThreatTargetKind, ref: str, tlp: str = 'GREEN') -> ThreatLinkInput:
    return ThreatLinkInput.model_validate({'target_kind': kind, 'target_id': ref, 'tlp': tlp})


@pytest.mark.parametrize('kind', ['actor', 'campaign'])
def test_only_explicit_links_are_recorded_and_audited(db: Session, kind: ThreatSubjectKind) -> None:
    first = _report(db, 'Copper sample', '192.0.2.4', 'GREEN')
    other = _report(db, 'Copper elsewhere', '192.0.2.4', 'GREEN')
    entity = db.scalars(select(Entity).where(Entity.value == '192.0.2.4')).one().id
    actor = services.create_actor(db, ActorInput(name='Copper', tlp='GREEN'))
    campaign = services.create_campaign(
        db, CampaignInput(name='Copper', aliases=('Copper', 'Other'), tlp='GREEN')
    )
    ref = actor.id if kind == 'actor' else campaign.id
    assert services.list_threat_links(db, kind, ref) == []
    for target_kind, target in [('document', first), ('indicator', entity), ('technique', 'T1059.001')]:
        item = ThreatLinkInput.model_validate(
            {'target_kind': target_kind, 'target_id': target, 'tlp': 'GREEN'}
        )
        services.link_threat(db, kind, ref, item)
        services.link_threat(db, kind, ref, item)
    rows = services.list_threat_links(db, kind, ref)
    assert [(r.name, r.tlp) for r in rows] == [
        ('Copper sample', 'GREEN'),
        ('192.0.2.4', 'GREEN'),
        ('Command and Scripting Interpreter: PowerShell', 'GREEN'),
    ]
    assert services.list_threat_links(db, kind, ref, offset=1, limit=1) == rows[1:2]
    assert all(r.target_id != other for r in rows)
    assert len(list(db.scalars(select(AuditEvent).where(AuditEvent.action == f'{kind}.link')))) == 3
    services.unlink_threat(db, kind, ref, 'indicator', entity)
    assert len(services.list_threat_links(db, kind, ref)) == 2
    assert db.scalar(select(AuditEvent).where(AuditEvent.action == f'{kind}.unlink')) is not None
    with pytest.raises(LookupError):
        services.unlink_threat(db, kind, ref, 'indicator', entity)
    assert campaign.aliases == 'Other'


def test_hidden_link_cannot_be_read_changed_or_removed_through_either_actor_route(db: Session) -> None:
    actor = services.create_actor(db, ActorInput(name='Manual actor', tlp='CLEAR'))
    doc = _report(db, 'Shared report', '192.0.2.11', 'CLEAR')
    link = services.link_report(db, actor.id, ActorLinkInput(document_id=doc, note='Restricted note TLP:RED'))
    assert link.tlp == 'RED'
    assert services.list_threat_links(db, 'actor', actor.id, max_tlp='GREEN') == []
    assert services.linked_reports(db, actor.id, max_tlp='GREEN') == []
    assert services.report_groups(db, doc, max_tlp='GREEN') == []
    assert services.guide_data(db, actor.id, now=datetime.now(UTC)).tlp == 'RED'
    with pytest.raises(LookupError):
        services.link_report(db, actor.id, ActorLinkInput(document_id=doc, note='Overwrite'), max_tlp='GREEN')
    with pytest.raises(LookupError):
        services.unlink_report(db, actor.id, doc, max_tlp='GREEN')
    with pytest.raises(LookupError):
        services.link_threat(db, 'actor', actor.id, _input('document', doc), max_tlp='GREEN')
    with pytest.raises(LookupError):
        services.unlink_threat(db, 'actor', actor.id, 'document', doc, max_tlp='GREEN')
    services.link_threat(db, 'actor', actor.id, _input('document', doc), max_tlp='RED')
    assert db.scalars(select(ActorDocument)).one().note == 'Restricted note TLP:RED'


def test_link_visibility_tracks_remaining_indicator_sources_and_retention(db: Session) -> None:
    low = _report(db, 'Green report', '192.0.2.15', 'GREEN')
    high = _report(db, 'Red report', '192.0.2.15', 'RED')
    ref = services.create_campaign(db, CampaignInput(name='Manual campaign', tlp='CLEAR')).id
    entity = db.scalars(select(Entity).where(Entity.value == '192.0.2.15')).one().id
    services.link_threat(db, 'campaign', ref, _input('indicator', entity, 'CLEAR'))
    services.link_threat(db, 'campaign', ref, _input('document', low, 'CLEAR'))
    services.delete_document(db, low, 'retention')
    assert services.list_threat_links(db, 'campaign', ref, max_tlp='GREEN') == []
    assert services.list_threat_links(db, 'campaign', ref)[0].tlp == 'RED'
    with pytest.raises(LookupError):
        services.unlink_threat(db, 'campaign', ref, 'indicator', entity, max_tlp='GREEN')
    services.delete_document(db, high, 'retention')
    assert db.scalars(select(ThreatLink)).all() == []


def test_record_visibility_and_target_validation(db: Session) -> None:
    ref = services.create_campaign(
        db, CampaignInput(name='Restricted', description='TLP:RED', tlp='GREEN')
    ).id
    assert services.list_campaigns(db, max_tlp='GREEN') == []
    with pytest.raises(services.TlpNotPermitted):
        services.create_campaign(db, CampaignInput(name='TLP:RED', tlp='GREEN'), max_tlp='GREEN')
    with pytest.raises(LookupError):
        services.get_campaign(db, ref, max_tlp='GREEN')
    with pytest.raises(LookupError):
        services.link_threat(db, 'campaign', ref, _input('technique', 'T1059.001'), max_tlp='GREEN')
    with pytest.raises(LookupError):
        services.link_threat(db, 'campaign', ref, _input('technique', 'T9999'))
    with pytest.raises(LookupError):
        services.link_threat(db, 'actor', 'G0016', _input('technique', 'T1059.001'))
