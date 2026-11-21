"""Only explicit, shareable local threat relationships reach a STIX export."""

from __future__ import annotations

import json
from typing import Any

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from insight import services
from insight.models import ActorDocument, AuditEvent, Campaign, Document, Entity, ThreatActor, ThreatLink
from insight.schemas import DocumentInput, IocExportQuery
from insight.services import stix_threats
from insight.stix_export import TLP_MARKINGS


def report(db: Session, title: str, body: str, tlp: str = 'CLEAR') -> Document:
    item = DocumentInput.model_validate({'title': title, 'body': body, 'source_name': 'Lab', 'tlp': tlp})
    return services.ingest(db, item)[0]


def objects(bundle: dict[str, Any], kind: str) -> dict[str, dict[str, Any]]:
    return {obj['id']: obj for obj in bundle.get('objects', []) if obj['type'] == kind}


def audit_level(db: Session, bundle: dict[str, Any]) -> str:
    detail = db.scalars(
        select(AuditEvent.detail).where(
            AuditEvent.action == 'stix.export', AuditEvent.object_id == bundle['id'].removeprefix('bundle--')
        )
    ).one()
    return str(json.loads(detail)['tlp'])


def test_actor_and_link_markings_protect_a_clear_report(db: Session) -> None:
    source = report(db, 'Synthetic Raven bulletin', 'Synthetic Raven and G0016 appear beside 192.0.2.12.')
    restricted = ThreatActor(
        name='Protected actor', aliases='Synthetic Owl\nSynthetic Wren', tlp='RED', actor='operator-sentinel'
    )
    public = ThreatActor(name='Public actor', description='free-text-sentinel', tlp='CLEAR')
    unlinked = ThreatActor(name='Synthetic Raven', attack_group_id='G0016', tlp='CLEAR')
    db.add_all([restricted, public, unlinked])
    db.flush()
    # Older ActorDocument rows defaulted to CLEAR. The actor's TLP still governs the relationship.
    protected = ActorDocument(
        group_ref=restricted.id, document_id=source.id, tlp='CLEAR', note='note-sentinel'
    )
    link = ActorDocument(group_ref=public.id, document_id=source.id, tlp='AMBER+STRICT')
    db.add_all([protected, link, ActorDocument(group_ref='G0016', document_id=source.id)])
    db.flush()

    full = services.export_stix(db, IocExportQuery(include_evidence=False))
    actor_objects = objects(full, 'threat-actor')
    assert {obj['name'] for obj in actor_objects.values()} == {restricted.name, public.name}
    assert actor_objects['threat-actor--' + restricted.id]['aliases'] == ['Synthetic Owl', 'Synthetic Wren']
    (strict_actor,) = [obj for obj in actor_objects.values() if obj['name'] == public.name]
    assert strict_actor['id'] != 'threat-actor--' + public.id
    assert strict_actor['object_marking_refs'] == [TLP_MARKINGS['AMBER+STRICT']]
    assert strict_actor['external_references'] == [{'source_name': 'Insight', 'external_id': public.id}]
    relations = objects(full, 'relationship')
    assert len(relations) == 2
    assert relations['relationship--' + protected.id]['object_marking_refs'] == [TLP_MARKINGS['RED']]
    (strict_link,) = [obj for obj in relations.values() if obj['source_ref'] == strict_actor['id']]
    assert strict_link['object_marking_refs'] == [TLP_MARKINGS['AMBER+STRICT']]
    assert strict_link['id'] != 'relationship--' + link.id
    assert all(
        rel['relationship_type'] == 'related-to' and rel['target_ref'] == 'report--' + source.id
        for rel in relations.values()
    )
    report_obj = objects(full, 'report')['report--' + source.id]
    assert report_obj['object_marking_refs'] == [TLP_MARKINGS['CLEAR']]
    assert set(report_obj['object_refs']) == set(objects(full, 'indicator'))
    assert set(objects(full, 'marking-definition')) == {
        TLP_MARKINGS[k] for k in ('CLEAR', 'RED', 'AMBER+STRICT')
    }
    assert audit_level(db, full) == 'RED'
    clear_objects = [o for o in full['objects'] if o.get('object_marking_refs') == [TLP_MARKINGS['CLEAR']]]
    assert {o['type'] for o in clear_objects} == {'report', 'indicator'}
    assert public.id not in json.dumps(clear_objects)
    assert all(
        private not in json.dumps(full)
        for private in ('operator-sentinel', 'free-text-sentinel', 'note-sentinel')
    )

    limited = services.export_stix(db, IocExportQuery(max_tlp='AMBER', include_evidence=False))
    assert not objects(limited, 'threat-actor')
    assert not objects(limited, 'relationship')
    assert set(objects(limited, 'marking-definition')) == {TLP_MARKINGS['CLEAR']}
    assert audit_level(db, limited) == 'CLEAR'


def test_only_links_to_selected_report_indicators_and_tag_copies_are_exported(db: Session) -> None:
    clear = report(db, 'Selected public report', 'T1486, 192.0.2.40 and CVE-2024-12345.')
    report(db, 'Selected internal report', 'T1486 with 192.0.2.40.', tlp='AMBER')
    other = report(db, 'Other source', 'T1105 and 192.0.2.41.')
    ioc = db.scalars(select(Entity).where(Entity.value == '192.0.2.40')).one()
    cve = db.scalars(select(Entity).where(Entity.kind == 'cve')).one()
    indicator_only = Campaign(name='IOC-only operation', tlp='CLEAR')
    hidden = Campaign(name='Unselected operation', tlp='CLEAR')
    documented = Campaign(name='Documented operation', tlp='CLEAR')
    actor = ThreatActor(name='Synthetic Hawk', tlp='GREEN')
    db.add_all([indicator_only, hidden, documented, actor])
    db.flush()
    db.add_all(
        [
            ThreatLink(campaign_id=indicator_only.id, entity_id=ioc.id, tlp='CLEAR'),
            ThreatLink(campaign_id=hidden.id, document_id=other.id, tlp='CLEAR'),
            ThreatLink(campaign_id=hidden.id, technique_id='T1105', tlp='CLEAR'),
            ThreatLink(campaign_id=hidden.id, entity_id=cve.id, tlp='CLEAR'),
            ThreatLink(campaign_id=documented.id, document_id=clear.id, tlp='GREEN'),
            ThreatLink(actor_id=actor.id, entity_id=ioc.id, tlp='GREEN'),
            ThreatLink(actor_id=actor.id, technique_id='T1486', tlp='GREEN'),
        ]
    )
    db.flush()
    selected = services.export_stix(db, IocExportQuery(q='Selected', kinds=('ip',)))
    campaigns = objects(selected, 'campaign')
    assert {o['external_references'][0]['external_id'] for o in campaigns.values()} == {
        indicator_only.id,
        documented.id,
    }
    actors = objects(selected, 'threat-actor')
    assert {o['name'] for o in actors.values()} == {actor.name}
    assert {tuple(o['object_marking_refs']) for o in actors.values()} == {
        (TLP_MARKINGS['GREEN'],),
        (TLP_MARKINGS['AMBER'],),
    }
    assert actors['threat-actor--' + actor.id]['object_marking_refs'] == [TLP_MARKINGS['GREEN']]
    targets = {
        **objects(selected, 'attack-pattern'),
        **objects(selected, 'indicator'),
        **objects(selected, 'report'),
    }
    relations = list(objects(selected, 'relationship').values())
    assert len(relations) == 5
    assert all(r['target_ref'] in targets and r['relationship_type'] == 'related-to' for r in relations)
    (ioc_ref,) = objects(selected, 'indicator')
    (ioc_campaign,) = [ref for ref, obj in campaigns.items() if obj['name'] == indicator_only.name]
    campaign_links = [r for r in relations if r['source_ref'] == ioc_campaign]
    assert [(r['target_ref'], r['object_marking_refs']) for r in campaign_links] == [
        (ioc_ref, [TLP_MARKINGS['AMBER']])
    ]
    subjects = {**campaigns, **actors}
    for r in relations:
        assert subjects[r['source_ref']]['object_marking_refs'] == r['object_marking_refs']
        if r['source_ref'] in actors:
            label = (
                'GREEN'
                if targets[r['target_ref']]['object_marking_refs'] == [TLP_MARKINGS['CLEAR']]
                else 'AMBER'
            )
            assert r['object_marking_refs'] == [TLP_MARKINGS[label]]
    cve_only = services.export_stix(
        db, IocExportQuery(document_ids=(clear.id,), kinds=('cve',), max_tlp='CLEAR')
    )
    (vuln,) = objects(cve_only, 'vulnerability')
    assert set(objects(cve_only, 'campaign')) == {'campaign--' + hidden.id}
    assert {r['target_ref'] for r in objects(cve_only, 'relationship').values()} == {vuln}
    assert 'objects' not in services.export_stix(db, IocExportQuery(q='missing report'))


def test_limit_counts_each_linked_technique_projection_before_audit(
    db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    report(db, 'First', '192.0.2.11 T1486.')
    report(db, 'Second', '192.0.2.12 T1486.', tlp='AMBER')
    campaign = Campaign(name='Local operation', tlp='CLEAR')
    db.add(campaign)
    db.flush()
    db.add(ThreatLink(campaign_id=campaign.id, technique_id='T1486', tlp='CLEAR'))
    db.flush()
    monkeypatch.setattr(stix_threats, 'MAX_EXPORT_THREAT_RELATIONSHIPS', 1)
    with pytest.raises(ValueError, match='threat relationships match'):
        services.export_stix(db, IocExportQuery())
    assert db.scalar(select(AuditEvent.id).where(AuditEvent.action == 'stix.export')) is None
