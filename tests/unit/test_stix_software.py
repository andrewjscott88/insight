"""Software sharing projections preserve explicit relationships and stable TAXII change times."""

from __future__ import annotations

import json

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from insight import services
from insight.models import Observation
from insight.schemas import ActorInput, ActorLinkInput, IocExportQuery, SoftwareLinkInput, ThreatLinkInput
from insight.stix_export import TLP_MARKINGS
from insight.taxii import INDICATORS_COLLECTION
from insight.threat_library import library

from .test_software import _report
from .test_stix_threats import objects


def test_empty_selection_stays_an_empty_bundle(db: Session) -> None:
    """Regression: a software projection must not fail when a TLP filter leaves no exported objects."""
    doc = _report(db, tlp='AMBER')
    services.link_software_report(db, 'S0154', SoftwareLinkInput(document_id=doc))
    bundle = services.export_stix(db, IocExportQuery(max_tlp='GREEN'))
    assert not bundle.get('objects')


def test_higher_label_software_does_not_change_lower_label_report(db: Session) -> None:
    """Regression: an AMBER software association must not appear in a CLEAR report's references."""
    doc = _report(db)
    services.link_software_report(
        db, 'S0154', SoftwareLinkInput(document_id=doc, tlp='AMBER', note='private-note')
    )
    actor = services.create_actor(db, ActorInput(name='Synthetic actor', tlp='CLEAR'))
    services.link_report(db, actor.id, ActorLinkInput(document_id=doc))
    bundle = services.export_stix(db, IocExportQuery())
    kind = library().software['S0154'].type
    tool = next(iter(objects(bundle, kind).values()))
    report = objects(bundle, 'report')['report--' + doc]
    assert tool['object_marking_refs'] == [TLP_MARKINGS['AMBER']]
    assert tool['id'] not in report['object_refs']
    assert not [r for r in objects(bundle, 'relationship').values() if r['relationship_type'] == 'uses']
    assert 'private-note' not in json.dumps(bundle)
    assert not objects(services.export_stix(db, IocExportQuery(max_tlp='GREEN')), kind)
    services.link_threat(
        db, 'actor', actor.id, ThreatLinkInput(target_kind='software', target_id='S0154', tlp='GREEN')
    )
    explicit = services.export_stix(db, IocExportQuery(max_tlp='GREEN'))
    uses = [r for r in objects(explicit, 'relationship').values() if r['relationship_type'] == 'uses']
    assert len(uses) == 1
    assert uses[0]['object_marking_refs'] == [TLP_MARKINGS['GREEN']]


def test_malware_family_and_stable_ids_survive_catalog_removal(
    db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    doc = _report(db)
    malware = next(item for item in library().software.values() if item.type == 'malware')
    services.link_software_report(db, malware.id, SoftwareLinkInput(document_id=doc))
    one = services.export_stix(db, IocExportQuery())
    obj = next(iter(objects(one, 'malware').values()))
    assert obj['is_family'] is True
    monkeypatch.delitem(library().software, malware.id)
    two = services.export_stix(db, IocExportQuery())
    assert set(objects(one, 'malware')) == set(objects(two, 'malware'))


def test_taxii_new_link_uses_link_time_and_repeated_reads_are_stable(db: Session) -> None:
    """Regression: newly linked software must be visible to polling clients after the report's old date."""
    doc = _report(db)
    observation = db.scalars(select(Observation).where(Observation.document_id == doc)).first()
    assert observation
    services.set_observation_status(db, observation.id, 'accepted')
    link = services.link_software_report(db, 'S0154', SoftwareLinkInput(document_id=doc))
    link.created_at = '2099-01-02T00:00:00+00:00'
    link.updated_at = link.created_at
    db.flush()
    one = services.taxii_collection_objects(db, INDICATORS_COLLECTION, max_tlp='GREEN')
    two = services.taxii_collection_objects(db, INDICATORS_COLLECTION, max_tlp='GREEN')
    assert one == two
    tool = next(item for item in one if item.obj['type'] == library().software['S0154'].type)
    assert tool.date_added.startswith('2099-01-02')


def test_label_raise_is_a_new_taxii_change(db: Session, monkeypatch: pytest.MonkeyPatch) -> None:
    """Regression: raising a software link's label after a poll must not retain its old change date."""
    from insight.services import software

    doc = _report(db)
    obs = db.scalars(select(Observation).where(Observation.document_id == doc)).first()
    assert obs
    services.set_observation_status(db, obs.id, 'accepted')
    link = services.link_software_report(db, 'S0154', SoftwareLinkInput(document_id=doc))
    before = link.updated_at
    monkeypatch.setattr(software, 'now', lambda: '2099-02-03T00:00:00+00:00')
    services.link_software_report(db, 'S0154', SoftwareLinkInput(document_id=doc, tlp='AMBER'))
    assert link.updated_at > before
    items = services.taxii_collection_objects(db, INDICATORS_COLLECTION, max_tlp='AMBER')
    software_items = [i for i in items if i.obj['type'] in ('malware', 'tool')]
    assert software_items
    assert all(i.date_added.startswith('2099-02-03') for i in software_items)


def test_explicit_use_label_raise_has_current_taxii_date(
    db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Regression: a newly restricted use decision must reach clients polling after its first save."""
    from insight.services import campaigns

    doc = _report(db)
    obs = db.scalars(select(Observation).where(Observation.document_id == doc)).first()
    assert obs
    services.set_observation_status(db, obs.id, 'accepted')
    actor = services.create_actor(db, ActorInput(name='Synthetic actor', tlp='CLEAR'))
    services.link_report(db, actor.id, ActorLinkInput(document_id=doc))
    services.link_threat(
        db, 'actor', actor.id, ThreatLinkInput(target_kind='software', target_id='S0154', tlp='CLEAR')
    )
    monkeypatch.setattr(campaigns, 'now', lambda: '2099-02-04T00:00:00+00:00')
    services.link_threat(
        db, 'actor', actor.id, ThreatLinkInput(target_kind='software', target_id='S0154', tlp='AMBER')
    )
    items = services.taxii_collection_objects(db, INDICATORS_COLLECTION, max_tlp='AMBER')
    use = next(i for i in items if i.obj.get('relationship_type') == 'uses')
    assert use.date_added.startswith('2099-02-04')


def test_catalog_tool_remains_tool(db: Session) -> None:
    doc = _report(db)
    tool = next(item for item in library().software.values() if item.type == 'tool')
    services.link_software_report(db, tool.id, SoftwareLinkInput(document_id=doc))
    obj = next(iter(objects(services.export_stix(db, IocExportQuery()), 'tool').values()))
    assert 'is_family' not in obj


def test_new_use_brings_old_subject_endpoint_at_link_date(db: Session) -> None:
    """Regression: a polling client must receive the old actor newly exposed by a software use link."""
    from insight.models import ThreatLink

    doc = _report(db)
    obs = db.scalars(select(Observation).where(Observation.document_id == doc)).first()
    assert obs
    services.set_observation_status(db, obs.id, 'accepted')
    services.link_software_report(db, 'S0154', SoftwareLinkInput(document_id=doc))
    actor = services.create_actor(db, ActorInput(name='Synthetic old actor', tlp='CLEAR'))
    actor.created_at = actor.updated_at = '2020-01-01T00:00:00+00:00'
    services.link_threat(
        db,
        'actor',
        actor.id,
        ThreatLinkInput(target_kind='software', target_id='S0154', tlp='CLEAR'),
    )
    row = db.scalars(select(ThreatLink).where(ThreatLink.actor_id == actor.id)).one()
    row.updated_at = '2099-02-05T00:00:00+00:00'
    db.flush()
    items = services.taxii_collection_objects(db, INDICATORS_COLLECTION, max_tlp='GREEN')
    projected = next(i for i in items if i.obj['type'] == 'threat-actor')
    assert projected.date_added.startswith('2099-02-05')
    assert projected.obj['modified'].startswith('2099-02-05')
