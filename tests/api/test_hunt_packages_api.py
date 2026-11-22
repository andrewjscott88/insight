"""``/api/hunt-packages`` and the *Hunt packages* TAXII collection (TIP 4.3, ADR 0034)."""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI
from fastapi.testclient import TestClient

from insight import services
from insight.taxii import HUNT_PACKAGES_COLLECTION

OBJECTS = f'/taxii2/insight/collections/{HUNT_PACKAGES_COLLECTION}/objects/'
SIGMA = 'title: Encoded PowerShell\ndetection:\n  sel:\n    CommandLine|contains: -enc\n  condition: sel\n'


def doc(authed: TestClient, body: str, tlp: str = 'GREEN') -> str:
    response = authed.post(
        '/api/documents', json={'title': 'Advisory', 'body': body, 'source_name': 'Vendor', 'tlp': tlp}
    )
    assert response.status_code == 200, response.text
    found: str = response.json()['id']
    return found


def entity_id(authed: TestClient, value: str) -> str:
    found: str = authed.get('/api/entities', params={'q': value}).json()[0]['id']
    return found


def key(app: FastAPI, access: str, max_tlp: str | None = None) -> dict[str, str]:
    with app.state.session_factory.begin() as db:
        services.revoke_api_key(db)
        _, token = services.create_api_key(db, name=access, access=access, max_tlp=max_tlp)
    return {'Authorization': f'Bearer {token}'}


def test_a_package_is_built_published_served_and_retired(
    app: FastAPI, client: TestClient, authed: TestClient
) -> None:
    report = doc(authed, 'Beacon to 203.0.113.70 after encoded PowerShell.')
    rule = authed.post('/api/rules', json={'kind': 'sigma', 'name': 'Encoded PowerShell', 'body': SIGMA,
                                           'tlp': 'GREEN'})  # fmt: skip
    assert rule.status_code in (200, 201), rule.text
    created = authed.post(
        '/api/hunt-packages',
        json={'title': 'Encoded PowerShell beacons', 'hypothesis': 'A crew runs encoded PowerShell.',
              'group': 'G0016', 'tlp': 'GREEN', 'items': [{'kind': 'technique', 'target_id': 'T1059.001'}]},
    )  # fmt: skip
    assert created.status_code == 201, created.text
    package: dict[str, Any] = created.json()
    assert (package['status'], package['tlp'], package['group_ref'], package['created_by']) == (
        'draft', 'GREEN', 'G0016', 'operator',
    )  # fmt: skip
    base = f'/api/hunt-packages/{package["id"]}'
    for kind, target in (('indicator', entity_id(authed, '203.0.113.70')), ('rule', rule.json()['id']),
                         ('document', report)):  # fmt: skip
        added = authed.post(f'{base}/items', json={'kind': kind, 'target_id': target})
        assert added.status_code == 201, added.text
    view = authed.get(base).json()
    assert sorted(i['kind'] for i in view['items']) == ['document', 'indicator', 'rule', 'technique']
    assert view['group_name']
    listed = authed.get('/api/hunt-packages').json()['hunt_packages']
    assert [(p['id'], p['techniques'], p['indicators'], p['rules'], p['documents']) for p in listed] == [
        (package['id'], 1, 1, 1, 1)
    ]
    reader = key(app, 'read', 'GREEN')
    assert client.get(OBJECTS, headers=reader).json().get('objects', []) == []  # drafts are not served
    assert authed.post(f'{base}/publish').json()['status'] == 'published'
    served = client.get(OBJECTS, headers=reader).json()['objects']
    grouping = next(o for o in served if o['type'] == 'grouping')
    assert grouping['name'] == 'Encoded PowerShell beacons'
    assert {o['type'] for o in served} >= {'grouping', 'attack-pattern', 'indicator', 'marking-definition'}
    download = authed.get(f'{base}/stix')
    assert download.headers['content-type'].startswith('application/stix+json')
    assert download.headers['content-disposition'].endswith(f'insight-hunt-package-{package["id"]}.json"')
    assert authed.delete(base).status_code == 409
    assert authed.post(f'{base}/retire').json()['status'] == 'retired'
    assert authed.patch(base, json={'title': 'Renamed'}).status_code == 409
    revoked = client.get(OBJECTS, headers=reader).json()['objects']
    assert all(o.get('revoked') for o in revoked if o['type'] != 'marking-definition')
    assert authed.delete(base).json() == {'deleted': package['id']}
    assert authed.get(base).status_code == 404
    actions = {e['action'] for e in authed.get('/api/audit').json()}
    assert {'hunt_package.create', 'hunt_package.item.add', 'hunt_package.publish', 'hunt_package.export',
            'hunt_package.retire', 'hunt_package.delete'} <= actions  # fmt: skip


def test_bad_input_and_status_conflicts(authed: TestClient) -> None:
    assert authed.post('/api/hunt-packages', json={'title': 'T', 'hypothesis': ' '}).status_code == 422
    bad_item = {'title': 'T', 'hypothesis': 'H', 'items': [{'kind': 'technique', 'target_id': 'T9999'}]}
    assert authed.post('/api/hunt-packages', json=bad_item).status_code == 404
    created = authed.post('/api/hunt-packages', json={'title': 'T', 'hypothesis': 'H'}).json()
    base = f'/api/hunt-packages/{created["id"]}'
    assert authed.post(f'{base}/publish').status_code == 409  # nothing huntable yet
    assert authed.get(f'{base}/stix').status_code == 422
    assert authed.post(f'{base}/items', json={'kind': 'rule', 'target_id': 'nope'}).status_code == 404
    assert authed.delete(f'{base}/items/nope').status_code == 404
    cleared = authed.patch(base, json={'group': 'G0016'}).json()
    assert cleared['group_ref'] == 'G0016'
    assert authed.patch(base, json={'group': None}).json()['group_ref'] is None


def test_limited_keys_see_and_write_only_within_their_limit(
    app: FastAPI, client: TestClient, authed: TestClient
) -> None:
    hidden = doc(authed, 'C2 at 203.0.113.71.', tlp='AMBER')
    amber = authed.post(
        '/api/hunt-packages',
        json={'title': 'Amber hunt', 'hypothesis': 'H', 'tlp': 'GREEN',
              'items': [{'kind': 'document', 'target_id': hidden},
                        {'kind': 'technique', 'target_id': 'T1486'}]},
    ).json()  # fmt: skip
    assert amber['tlp'] == 'AMBER'
    authed.post(f'/api/hunt-packages/{amber["id"]}/publish')
    writer = key(app, 'read-write', 'GREEN')
    assert client.get('/api/hunt-packages', headers=writer).json() == {'hunt_packages': []}
    assert client.get(f'/api/hunt-packages/{amber["id"]}', headers=writer).status_code == 404
    assert client.get(f'/api/hunt-packages/{amber["id"]}/stix', headers=writer).status_code == 404
    assert client.get(OBJECTS, headers=writer).json().get('objects', []) == []
    above = {'title': 'T', 'hypothesis': 'H', 'tlp': 'AMBER'}
    assert client.post('/api/hunt-packages', headers=writer, json=above).status_code == 403
    mine = client.post(
        '/api/hunt-packages', headers=writer, json={'title': 'T', 'hypothesis': 'H', 'tlp': 'GREEN'}
    )
    assert mine.status_code == 201
    refused = client.post(
        f'/api/hunt-packages/{mine.json()["id"]}/items',
        headers=writer,
        json={'kind': 'document', 'target_id': hidden},
    )
    assert refused.status_code == 404
    reader = key(app, 'read')
    assert client.post('/api/hunt-packages', headers=reader, json=above).status_code == 403
