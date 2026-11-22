"""The read-only TAXII 2.1 server (TIP 3.1, ADR 0026): API keys only, TLP per key, stable polling."""

from __future__ import annotations

from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import select

from insight import services
from insight.models import AuditEvent, Document
from insight.schemas import DocumentInput
from insight.taxii import INDICATORS_COLLECTION, STIX_MEDIA_TYPE, TAXII_MEDIA_TYPE

ROOT = '/taxii2/insight/'
OBJECTS = f'{ROOT}collections/{INDICATORS_COLLECTION}/objects/'
MANIFEST = f'{ROOT}collections/{INDICATORS_COLLECTION}/manifest/'
GREEN_IP = '192.0.2.10'
AMBER_IP = '198.51.100.20'
UNREVIEWED_IP = '203.0.113.30'


def report(title: str, body: str, tlp: str) -> DocumentInput:
    return DocumentInput.model_validate({'title': title, 'body': body, 'source_name': 'Partner', 'tlp': tlp})


def accept(db: Any, doc_id: str, *values: str) -> None:
    for obs in services.detail(db, db.get(Document, doc_id))['observations']:
        if obs['value'] in values:
            services.set_observation_status(db, obs['id'], 'accepted')


@pytest.fixture
def world(app: FastAPI) -> dict[str, Any]:
    """A GREEN and an AMBER report with accepted indicators, one unreviewed indicator, and a key."""
    with app.state.session_factory.begin() as db:
        green, _ = services.ingest(
            db,
            report('Green note', f'Scanning from {GREEN_IP}; also {UNREVIEWED_IP}. CVE-2024-3400.', 'GREEN'),
        )
        amber, _ = services.ingest(db, report('Amber briefing', f'C2 at {AMBER_IP}.', 'AMBER'))
        accept(db, green.id, GREEN_IP, 'CVE-2024-3400')
        accept(db, amber.id, AMBER_IP)
        _, full = services.create_api_key(db, name='siem', access='read')
    return {
        'green': green.id,
        'amber': amber.id,
        'full': {'Authorization': f'Bearer {full}', 'Accept': TAXII_MEDIA_TYPE},
    }


def green_only(app: FastAPI) -> dict[str, str]:
    """Replace the key with a GREEN-limited one (Insight has one active key at a time)."""
    with app.state.session_factory.begin() as db:
        services.revoke_api_key(db)
        _, token = services.create_api_key(db, name='partner', access='read', max_tlp='GREEN')
    return {'Authorization': f'Bearer {token}', 'Accept': TAXII_MEDIA_TYPE}


def objects(client: TestClient, headers: dict[str, str], **params: Any) -> dict[str, Any]:
    response = client.get(OBJECTS, headers=headers, params=params)
    assert response.status_code == 200, response.text
    assert response.headers['content-type'] == TAXII_MEDIA_TYPE
    body: dict[str, Any] = response.json()
    return body


def names(body: dict[str, Any]) -> set[str]:
    return {o['name'] for o in body['objects'] if o['type'] in ('indicator', 'vulnerability')}


# --------------------------------------------------------------------------- discovery and access


def test_discovery_api_root_and_collections(client: TestClient, world: dict[str, Any]) -> None:
    discovery = client.get('/taxii2/', headers=world['full'])
    assert discovery.status_code == 200
    assert discovery.headers['content-type'] == TAXII_MEDIA_TYPE
    assert discovery.json()['api_roots'] == ['http://testserver/taxii2/insight/']
    root = client.get(ROOT, headers=world['full']).json()
    assert root['versions'] == [TAXII_MEDIA_TYPE]
    collection, _kev = client.get(f'{ROOT}collections/', headers=world['full']).json()['collections']
    assert collection['id'] == INDICATORS_COLLECTION
    assert (collection['can_read'], collection['can_write']) == (True, False)
    assert collection['media_types'] == [STIX_MEDIA_TYPE]
    one = client.get(f'{ROOT}collections/{INDICATORS_COLLECTION}/', headers=world['full'])
    assert one.json() == collection


@pytest.mark.parametrize('path', ['/taxii2/', ROOT, f'{ROOT}collections/', OBJECTS, MANIFEST])
def test_unauthenticated_clients_are_refused(client: TestClient, path: str) -> None:
    assert client.get(path, headers={'Accept': TAXII_MEDIA_TYPE}).status_code == 401


def test_a_signed_in_browser_is_not_a_taxii_client(authed: TestClient) -> None:
    response = authed.get(OBJECTS, headers={'Accept': TAXII_MEDIA_TYPE})
    assert response.status_code == 403
    assert response.json() == {
        'title': 'TAXII is for API keys',
        'description': 'Send an API key as Authorization: Bearer <key>.',
        'http_status': '403',
    }


def test_clients_must_accept_taxii(client: TestClient, world: dict[str, Any]) -> None:
    headers = {**world['full'], 'Accept': 'text/html'}
    assert client.get(OBJECTS, headers=headers).status_code == 406
    for accept in ('*/*', 'application/taxii+json', 'application/taxii+json;version=2.1'):
        assert client.get(ROOT, headers={**world['full'], 'Accept': accept}).status_code == 200


def test_nothing_can_be_written(client: TestClient, world: dict[str, Any]) -> None:
    bundle = {'objects': [{'type': 'indicator'}]}
    assert client.post(OBJECTS, headers=world['full'], json=bundle).status_code == 405
    assert client.delete(f'{OBJECTS}indicator--x/', headers=world['full']).status_code == 405
    unknown = client.get(f'{ROOT}collections/new/objects/', headers=world['full'])
    assert unknown.status_code == 404
    assert unknown.json()['title'] == 'Collection not found'


# --------------------------------------------------------------------------- what a key may read


def test_only_accepted_indicators_within_the_key_limit(
    client: TestClient, world: dict[str, Any], app: FastAPI
) -> None:
    everything = objects(client, world['full'])
    assert names(everything) == {GREEN_IP, AMBER_IP, 'CVE-2024-3400'}  # never the unreviewed one
    limited = objects(client, green_only(app))
    assert names(limited) == {GREEN_IP, 'CVE-2024-3400'}
    assert world['amber'] not in str(limited)
    assert AMBER_IP not in str(limited)
    reports = {o['id'] for o in everything['objects'] if o['type'] == 'report'}
    assert reports == {f'report--{world["green"]}', f'report--{world["amber"]}'}
    markings = {o['name'] for o in everything['objects'] if o['type'] == 'marking-definition'}
    assert markings == {'TLP:GREEN', 'TLP:AMBER'}


def test_the_collection_matches_a_stix_export_of_the_same_filter(
    client: TestClient, world: dict[str, Any]
) -> None:
    key = {'Authorization': world['full']['Authorization']}
    stix = client.get('/api/iocs/stix', headers=key, params={'review_status': 'accepted'}).json()
    exported = {o['name'] for o in stix['objects'] if o['type'] in ('indicator', 'vulnerability')}
    exported_patterns = {o.get('pattern') for o in stix['objects'] if o['type'] == 'indicator'}
    served = objects(client, world['full'])
    assert names(served) == exported
    assert {o.get('pattern') for o in served['objects'] if o['type'] == 'indicator'} == exported_patterns


def test_ids_are_stable_between_requests_and_keys(
    client: TestClient, world: dict[str, Any], app: FastAPI
) -> None:
    first = objects(client, world['full'])
    again = objects(client, world['full'])
    assert first == again
    ids = {o['name']: o['id'] for o in first['objects'] if o['type'] == 'indicator'}
    served = objects(client, green_only(app))['objects']
    limited = {o['name']: o['id'] for o in served if o['type'] == 'indicator'}
    assert limited[GREEN_IP] == ids[GREEN_IP]


def test_reads_are_audited(client: TestClient, world: dict[str, Any], app: FastAPI) -> None:
    objects(client, green_only(app))
    with app.state.session_factory() as db:
        event = db.scalars(select(AuditEvent).where(AuditEvent.action == 'taxii.read')).one()
    assert event.actor.startswith('api-key:')
    assert '"max_tlp": "GREEN"' in event.detail


# --------------------------------------------------------------------------- polling and pagination


def test_pages_follow_next_until_more_is_false(client: TestClient, world: dict[str, Any]) -> None:
    whole = objects(client, world['full'])['objects']
    seen: list[dict[str, Any]] = []
    params: dict[str, Any] = {'limit': 2}
    while True:
        response = client.get(OBJECTS, headers=world['full'], params=params)
        body = response.json()
        seen += body['objects']
        assert response.headers['X-TAXII-Date-Added-First'] <= response.headers['X-TAXII-Date-Added-Last']
        if not body['more']:
            assert 'next' not in body
            break
        params = {'limit': 2, 'next': body['next']}
    assert seen == whole
    assert len(whole) > 2


def test_added_after_returns_newly_accepted_indicators(
    client: TestClient, world: dict[str, Any], app: FastAPI
) -> None:
    before = client.get(MANIFEST, headers=world['full']).json()['objects']
    last = max(entry['date_added'] for entry in before)
    assert objects(client, world['full'], added_after=last)['objects'] == []
    # Accepting an indicator in an old report puts it, its report and its marking after the last poll.
    with app.state.session_factory.begin() as db:
        accept(db, world['green'], UNREVIEWED_IP)
    fresh = objects(client, world['full'], added_after=last)
    assert names(fresh) == {UNREVIEWED_IP}
    kinds = {o['type'] for o in fresh['objects']}
    assert kinds == {'indicator', 'report', 'marking-definition'}
    [green_report] = [o for o in fresh['objects'] if o['type'] == 'report']
    assert green_report['modified'] > green_report['created']


def test_manifest_versions_and_single_objects(client: TestClient, world: dict[str, Any]) -> None:
    manifest = client.get(MANIFEST, headers=world['full']).json()
    entry = manifest['objects'][-1]
    assert entry['media_type'] == STIX_MEDIA_TYPE
    one = client.get(f'{OBJECTS}{entry["id"]}/', headers=world['full']).json()
    assert [o['id'] for o in one['objects']] == [entry['id']]
    versions = client.get(f'{OBJECTS}{entry["id"]}/versions/', headers=world['full']).json()
    assert versions == {'more': False, 'versions': [entry['version']]}
    by_version = objects(
        client, world['full'], **{'match[id]': entry['id'], 'match[version]': entry['version']}
    )
    assert [o['id'] for o in by_version['objects']] == [entry['id']]
    missing = client.get(f'{OBJECTS}indicator--00000000-0000-4000-8000-000000000000/', headers=world['full'])
    assert missing.status_code == 404


def test_match_type_filters(client: TestClient, world: dict[str, Any]) -> None:
    body = objects(client, world['full'], **{'match[type]': 'vulnerability'})
    assert [o['name'] for o in body['objects']] == ['CVE-2024-3400']


@pytest.mark.parametrize(
    ('params', 'title'),
    [
        ({'added_after': 'yesterday'}, 'Invalid added_after'),
        ({'added_after': '2026-01-01T00:00:00'}, 'Invalid added_after'),
        ({'next': '!!!'}, 'Invalid next'),
        ({'match[id]': ','.join(f'indicator--{i}' for i in range(101))}, 'Too many match values'),
    ],
)
def test_bad_queries_get_taxii_errors(
    client: TestClient, world: dict[str, Any], params: dict[str, str], title: str
) -> None:
    response = client.get(OBJECTS, headers=world['full'], params=params)
    assert response.status_code == 400
    assert response.json()['title'] == title
    assert client.get(OBJECTS, headers=world['full'], params={'limit': 1001}).status_code == 422
