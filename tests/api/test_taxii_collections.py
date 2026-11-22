"""TAXII follow-ups (ADR 0026): techniques, actors and campaigns in the indicators collection with stable IDs,
and a CISA KEV collection whose versions change only when an entry does."""

from __future__ import annotations

import json
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import select

from insight import services
from insight.attack import catalog
from insight.connectors import import_kev
from insight.models import AuditEvent, Document, Entity
from insight.schemas import ActorInput, CampaignInput, DocumentInput, ThreatLinkInput
from insight.services.taxii import _dated
from insight.stix_export import TLP_MARKINGS, stable_id
from insight.taxii import HUNT_PACKAGES_COLLECTION, INDICATORS_COLLECTION, KEV_COLLECTION, TAXII_MEDIA_TYPE

ROOT = '/taxii2/insight/'
OBJECTS = f'{ROOT}collections/{INDICATORS_COLLECTION}/objects/'
KEV_OBJECTS = f'{ROOT}collections/{KEV_COLLECTION}/objects/'
GREEN_IP = '192.0.2.10'
AMBER_IP = '198.51.100.20'


def report(title: str, body: str, tlp: str) -> DocumentInput:
    return DocumentInput.model_validate({'title': title, 'body': body, 'source_name': 'Partner', 'tlp': tlp})


def accept(db: Any, doc_id: str, *values: str) -> None:
    for obs in services.detail(db, db.get(Document, doc_id))['observations']:
        if obs['value'] in values:
            services.set_observation_status(db, obs['id'], 'accepted')


def link(db: Any, kind: str, ref: str, target_kind: str, target: str, tlp: str = 'GREEN') -> None:
    item = ThreatLinkInput.model_validate({'target_kind': target_kind, 'target_id': target, 'tlp': tlp})
    services.link_threat(db, kind, ref, item)  # type: ignore[arg-type]


def entity_id(db: Any, value: str) -> str:
    found: str = db.scalars(select(Entity.id).where(Entity.value == value)).one()
    return found


@pytest.fixture
def world(app: FastAPI) -> dict[str, Any]:
    """GREEN and AMBER reports with accepted indicators and techniques, a GREEN actor linked to the GREEN
    report and a technique, a GREEN campaign linked to the GREEN indicator, an AMBER actor linked to the AMBER
    report; and an unlimited read key."""
    with app.state.session_factory.begin() as db:
        green, _ = services.ingest(
            db, report('Green note', f'Scanning from {GREEN_IP} (T1059.001).', 'GREEN')
        )
        amber, _ = services.ingest(db, report('Amber briefing', f'C2 at {AMBER_IP} (T1486).', 'AMBER'))
        accept(db, green.id, GREEN_IP)
        accept(db, amber.id, AMBER_IP)
        copper = services.create_actor(db, ActorInput(name='Copper Fox', tlp='GREEN'))
        link(db, 'actor', copper.id, 'document', green.id)
        link(db, 'actor', copper.id, 'technique', 'T1059.001')
        wave = services.create_campaign(db, CampaignInput(name='Winter Wave', tlp='GREEN'))
        link(db, 'campaign', wave.id, 'indicator', entity_id(db, GREEN_IP))
        secret = services.create_actor(db, ActorInput(name='Hidden Heron', tlp='AMBER'))
        link(db, 'actor', secret.id, 'document', amber.id, tlp='AMBER')
        _, full = services.create_api_key(db, name='siem', access='read')
    return {
        'green': green.id,
        'amber': amber.id,
        'copper': copper.id,
        'wave': wave.id,
        'full': {'Authorization': f'Bearer {full}', 'Accept': TAXII_MEDIA_TYPE},
    }


def green_only(app: FastAPI) -> dict[str, str]:
    with app.state.session_factory.begin() as db:
        services.revoke_api_key(db)
        _, token = services.create_api_key(db, name='partner', access='read', max_tlp='GREEN')
    return {'Authorization': f'Bearer {token}', 'Accept': TAXII_MEDIA_TYPE}


def objects(
    client: TestClient, headers: dict[str, str], url: str = OBJECTS, **params: Any
) -> list[dict[str, Any]]:
    response = client.get(url, headers=headers, params=params)
    assert response.status_code == 200, response.text
    found: list[dict[str, Any]] = response.json()['objects']
    return found


def by_type(found: list[dict[str, Any]], kind: str) -> list[dict[str, Any]]:
    return [o for o in found if o['type'] == kind]


# --------------------------------------------------------------------------- the collections


def test_three_fixed_collections_are_listed(client: TestClient, world: dict[str, Any]) -> None:
    listed = client.get(f'{ROOT}collections/', headers=world['full']).json()['collections']
    assert [c['id'] for c in listed] == [INDICATORS_COLLECTION, KEV_COLLECTION, HUNT_PACKAGES_COLLECTION]
    for collection_id, title in ((KEV_COLLECTION, 'CISA Known Exploited Vulnerabilities'),
                                 (HUNT_PACKAGES_COLLECTION, 'Hunt packages')):  # fmt: skip
        found = client.get(f'{ROOT}collections/{collection_id}/', headers=world['full']).json()
        assert (found['title'], found['can_read'], found['can_write']) == (title, True, False)


# --------------------------------------------------------------------------- techniques, actors, campaigns


def test_techniques_actors_and_campaigns_are_served_with_stable_ids(
    client: TestClient, world: dict[str, Any], app: FastAPI
) -> None:
    first = objects(client, world['full'])
    assert objects(client, world['full']) == first
    patterns = {p['external_references'][0]['external_id']: p for p in by_type(first, 'attack-pattern')}
    assert set(patterns) == {'T1059.001', 'T1486'}
    green_marking = (TLP_MARKINGS['GREEN'],)
    version = catalog().version
    expected = stable_id('attack-pattern', 'mitre-attack', f'{version}|T1059.001|{",".join(green_marking)}')
    assert patterns['T1059.001']['id'] == expected
    actors = {a['name']: a for a in by_type(first, 'threat-actor')}
    assert set(actors) == {'Copper Fox', 'Hidden Heron'}
    assert actors['Copper Fox']['id'] == f'threat-actor--{world["copper"]}'
    [campaign] = by_type(first, 'campaign')
    assert campaign['id'] == f'campaign--{world["wave"]}'
    relationships = by_type(first, 'relationship')
    targets = {r['target_ref'] for r in relationships}
    assert f'report--{world["green"]}' in targets
    assert patterns['T1059.001']['id'] in targets
    assert all(r['modified'] >= r['created'] for r in relationships)
    green_report = next(o for o in first if o['id'] == f'report--{world["green"]}')
    assert patterns['T1059.001']['id'] in green_report['object_refs']

    limited = objects(client, green_only(app))
    assert 'Hidden Heron' not in json.dumps(limited)
    assert {p['external_references'][0]['external_id'] for p in by_type(limited, 'attack-pattern')} == {
        'T1059.001'
    }
    limited_ids = {o['id'] for o in limited if o['type'] != 'marking-definition'}
    full_ids = {o['id'] for o in first}
    assert limited_ids <= full_ids  # the same objects keep the same IDs for every key


def test_a_new_link_brings_an_older_actor_into_the_next_poll(
    client: TestClient, world: dict[str, Any], app: FastAPI
) -> None:
    with app.state.session_factory.begin() as db:
        old = services.create_actor(db, ActorInput(name='Old Otter', tlp='GREEN'))
        later, _ = services.ingest(db, report('Later note', 'Beacon to 192.0.2.99.', 'GREEN'))
        accept(db, later.id, '192.0.2.99')
    manifest = client.get(f'{ROOT}collections/{INDICATORS_COLLECTION}/manifest/', headers=world['full'])
    last = max(entry['date_added'] for entry in manifest.json()['objects'])
    assert objects(client, world['full'], added_after=last) == []
    with app.state.session_factory.begin() as db:
        link(db, 'actor', old.id, 'indicator', entity_id(db, '192.0.2.99'))
    fresh = objects(client, world['full'], added_after=last)
    assert {o['type'] for o in fresh} >= {'threat-actor', 'relationship'}
    [otter] = by_type(fresh, 'threat-actor')
    assert otter['name'] == 'Old Otter'
    assert otter['modified'] <= last  # created long ago, but new to this collection


def test_dates_follow_markings_and_first_relationships() -> None:
    marking = TLP_MARKINGS['GREEN']

    def at(day: int) -> str:
        return f'2026-11-{day:02d}T00:00:00.000000Z'

    found = _dated(
        [
            {'type': 'marking-definition', 'id': marking, 'created': '2017-01-20T00:00:00.000Z'},
            {'type': 'threat-actor', 'id': 'threat-actor--a', 'created': at(1), 'modified': at(1),
             'object_marking_refs': [marking]},
            {'type': 'relationship', 'id': 'relationship--b', 'created': at(5), 'modified': at(5),
             'source_ref': 'threat-actor--a', 'object_marking_refs': [marking]},
            {'type': 'relationship', 'id': 'relationship--c', 'created': at(3), 'modified': at(3),
             'source_ref': 'threat-actor--a', 'object_marking_refs': [marking]},
        ]
    )  # fmt: skip
    added = {item.id: item.date_added for item in found}
    assert added == {
        'threat-actor--a': at(3),  # with its first relationship, not its own older time
        'relationship--b': at(5),
        'relationship--c': at(3),
        marking: at(5),  # with the newest object it marks
    }


# --------------------------------------------------------------------------- the KEV collection


def kev_row(n: int, **changes: Any) -> dict[str, Any]:
    row = {
        'cveID': f'CVE-2024-{n}',
        'vendorProject': 'Acme',
        'product': 'Gateway',
        'vulnerabilityName': 'Acme Gateway Command Injection',
        'dateAdded': '2026-11-01',
        'dueDate': '2026-11-22',
        'requiredAction': 'Apply the update.',
        'shortDescription': 'A command injection.',
        'knownRansomwareCampaignUse': 'Unknown',
        'cwes': ['CWE-78'],
    }
    row.update(changes)
    return row


def kev(app: FastAPI, *rows: dict[str, Any]) -> None:
    with app.state.session_factory.begin() as db:
        import_kev(db, json.dumps({'vulnerabilities': list(rows)}).encode())


def test_the_kev_collection_serves_public_entries_to_every_key(
    client: TestClient, world: dict[str, Any], app: FastAPI
) -> None:
    assert objects(client, world['full'], KEV_OBJECTS) == []
    kev(app, kev_row(3400), kev_row(1111, knownRansomwareCampaignUse='Known'))
    limited = green_only(app)
    served = objects(client, limited, KEV_OBJECTS)
    [marking] = by_type(served, 'marking-definition')
    assert marking['id'] == TLP_MARKINGS['CLEAR']
    entries = {v['name']: v for v in by_type(served, 'vulnerability')}
    assert set(entries) == {'CVE-2024-3400', 'CVE-2024-1111'}
    entry = entries['CVE-2024-1111']
    assert entry['id'] == stable_id('vulnerability', 'cisa-kev', 'CVE-2024-1111')
    assert entry['id'] != stable_id('vulnerability', 'cve', 'CVE-2024-1111')
    assert entry['description'] == 'Acme Gateway Command Injection'
    assert entry['created'] == '2026-11-01T00:00:00.000000Z'
    assert entry['x_insight_kev'] == {
        'vendor': 'Acme',
        'product': 'Gateway',
        'date_added': '2026-11-01',
        'due_date': '2026-11-22',
        'required_action': 'Apply the update.',
        'known_ransomware_campaign_use': 'Known',
        'cwes': ['CWE-78'],
    }
    assert {'source_name': 'cve', 'external_id': 'CVE-2024-1111'} in entry['external_references']
    with app.state.session_factory() as db:
        events = db.scalars(select(AuditEvent).where(AuditEvent.action == 'taxii.read')).all()
    assert any(e.object_id == KEV_COLLECTION for e in events)


def test_kev_versions_change_only_when_an_entry_changes(
    client: TestClient, world: dict[str, Any], app: FastAPI
) -> None:
    manifest_url = f'{ROOT}collections/{KEV_COLLECTION}/manifest/'
    kev(app, kev_row(3400), kev_row(1111))
    before = client.get(manifest_url, headers=world['full']).json()['objects']
    kev(app, kev_row(3400), kev_row(1111))  # a sync with nothing new
    assert client.get(manifest_url, headers=world['full']).json()['objects'] == before
    last = max(entry['date_added'] for entry in before)
    kev(app, kev_row(3400), kev_row(1111, knownRansomwareCampaignUse='Known'))
    fresh = objects(client, world['full'], KEV_OBJECTS, added_after=last)
    assert [v['name'] for v in by_type(fresh, 'vulnerability')] == ['CVE-2024-1111']
    assert by_type(fresh, 'vulnerability')[0]['x_insight_kev']['known_ransomware_campaign_use'] == 'Known'
