"""Stable STIX subject and relationship versions follow explicit link changes."""

from __future__ import annotations

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from insight import services
from insight.models import Entity, Observation, ThreatLink
from insight.schemas import (
    ActorInput,
    CampaignInput,
    SoftwareLinkInput,
    ThreatLinkInput,
    ThreatSubjectKind,
    ThreatTargetKind,
)
from insight.services import campaigns
from insight.taxii import INDICATORS_COLLECTION

from .test_software import _report


@pytest.mark.parametrize(
    ('kind', 'target'), [('campaign', 'document'), ('actor', 'indicator'), ('actor', 'technique')]
)
def test_link_label_raise_advances_both_taxii_versions(
    db: Session, monkeypatch: pytest.MonkeyPatch, kind: ThreatSubjectKind, target: ThreatTargetKind
) -> None:
    """Regression: raising a link's label must publish new marked endpoint and relationship versions."""
    doc = _report(db, 'Cobalt Strike uses T1059.001 and 192.0.2.44.')
    for observation in db.scalars(select(Observation).where(Observation.document_id == doc)):
        services.set_observation_status(db, observation.id, 'accepted')
    entity = db.scalars(select(Entity).where(Entity.value == '192.0.2.44')).one()
    subject = (
        services.create_actor(db, ActorInput(name='Synthetic actor', tlp='GREEN'))
        if kind == 'actor'
        else services.create_campaign(db, CampaignInput(name='Synthetic campaign', tlp='GREEN'))
    )
    target_id = doc if target == 'document' else entity.id if target == 'indicator' else 'T1059.001'
    payload = ThreatLinkInput(target_kind=target, target_id=target_id, tlp='GREEN')
    services.link_threat(db, kind, subject.id, payload)
    before = services.taxii_collection_objects(db, INDICATORS_COLLECTION, max_tlp=None)
    old = next(item for item in before if item.obj.get('relationship_type') == 'related-to')
    monkeypatch.setattr(campaigns, 'now', lambda: '2099-03-01T00:00:00+00:00')
    services.link_threat(db, kind, subject.id, payload.model_copy(update={'tlp': 'AMBER'}))
    after = services.taxii_collection_objects(db, INDICATORS_COLLECTION, max_tlp=None)
    changed = next(item for item in after if item.obj.get('relationship_type') == 'related-to')
    assert changed.date_added > old.date_added
    assert changed.obj['modified'].startswith('2099-03-01')
    projected = next(item for item in after if item.id == changed.obj['source_ref'])
    assert projected.date_added.startswith('2099-03-01')
    assert projected.obj['modified'].startswith('2099-03-01')
    assert len({item.id for item in after}) == len(after)
    assert not any(
        item.obj.get('relationship_type') == 'related-to'
        for item in services.taxii_collection_objects(db, INDICATORS_COLLECTION, max_tlp='GREEN')
    )


def test_new_links_expose_one_old_subject_at_latest_change(db: Session) -> None:
    """Regression: an old subject's first visible links must not retain its old STIX modified time."""
    doc = _report(db)
    observation = db.scalars(select(Observation).where(Observation.document_id == doc)).first()
    assert observation
    services.set_observation_status(db, observation.id, 'accepted')
    campaign = services.create_campaign(db, CampaignInput(name='Synthetic old campaign', tlp='CLEAR'))
    campaign.created_at = '2020-01-01T00:00:00+00:00'
    services.link_threat(
        db, 'campaign', campaign.id, ThreatLinkInput(target_kind='document', target_id=doc, tlp='CLEAR')
    )
    link = db.scalars(select(ThreatLink).where(ThreatLink.campaign_id == campaign.id)).one()
    link.updated_at = '2099-03-02T00:00:00+00:00'
    services.link_software_report(db, 'S0154', SoftwareLinkInput(document_id=doc))
    services.link_threat(
        db, 'campaign', campaign.id, ThreatLinkInput(target_kind='software', target_id='S0154', tlp='CLEAR')
    )
    software = db.scalars(select(ThreatLink).where(ThreatLink.software_id == 'S0154')).one()
    software.updated_at = '2099-03-03T00:00:00+00:00'
    db.flush()
    after = services.taxii_collection_objects(db, INDICATORS_COLLECTION, max_tlp='GREEN')
    subjects = [item for item in after if item.obj['type'] == 'campaign']
    assert len(subjects) == 1
    assert subjects[0].obj['modified'].startswith('2099-03-03')
    assert subjects[0].date_added.startswith('2099-03-03')
    assert len({item.id for item in after}) == len(after)
    assert services.taxii_collection_objects(db, INDICATORS_COLLECTION, max_tlp='GREEN') == after
