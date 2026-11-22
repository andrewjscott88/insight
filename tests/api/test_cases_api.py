"""``/api/cases`` (TIP 3.8, ADR 0029): the HTTP contract, error codes and the key's TLP limit."""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI
from fastapi.testclient import TestClient

from insight import services


def doc(authed: TestClient, title: str, body: str, tlp: str = 'GREEN') -> str:
    response = authed.post(
        '/api/documents', json={'title': title, 'body': body, 'source_name': 's', 'tlp': tlp}
    )
    assert response.status_code == 200, response.text
    found: str = response.json()['id']
    return found


def test_a_case_is_opened_filled_closed_reopened_and_deleted(authed: TestClient) -> None:
    first = doc(authed, 'Gateway advisory', 'Beacon to 192.0.2.10.')
    second = doc(authed, 'Follow-up', 'Again 192.0.2.10.')
    opened = authed.post('/api/cases', json={'title': 'Gateway intrusion', 'tlp': 'GREEN'})
    assert opened.status_code == 201
    case: dict[str, Any] = opened.json()
    assert (case['status'], case['tlp'], case['created_by']) == ('open', 'GREEN', 'operator')
    base = f'/api/cases/{case["id"]}'
    for target in (first, second):
        added = authed.post(f'{base}/items', json={'kind': 'document', 'target_id': target})
        assert added.status_code == 201
    entity = authed.get('/api/entities', params={'q': '192.0.2.10'}).json()[0]['id']
    indicator = authed.post(f'{base}/items', json={'kind': 'indicator', 'target_id': entity}).json()
    assert (indicator['name'], indicator['tlp']) == ('192.0.2.10', 'GREEN')
    note = authed.post(f'{base}/notes', json={'text': 'Asked for firewall logs.'})
    assert (note.status_code, note.json()['tlp']) == (201, 'GREEN')
    assert authed.patch(base, json={'summary': 'Edge appliance compromise.'}).json()['summary']
    assert [c['items'] for c in authed.get('/api/cases').json()['cases']] == [3]

    closed = authed.post(f'{base}/close', json={'note': 'Contained.'})
    assert (closed.status_code, closed.json()['status']) == (200, 'closed')
    refused = authed.post(f'{base}/notes', json={'text': 'late'})
    assert (refused.status_code, refused.json()['detail']) == (
        409,
        'This case is closed. Reopen it to change it.',
    )
    assert authed.get('/api/cases').json()['cases'] == []
    assert len(authed.get('/api/cases', params={'status': 'closed'}).json()['cases']) == 1
    assert authed.post(f'{base}/reopen').json()['status'] == 'open'

    removed = authed.delete(f'{base}/items/{indicator["id"]}')
    assert removed.json() == {'removed': indicator['id']}
    view = authed.get(base).json()
    assert [i['kind'] for i in view['items']] == ['document', 'document', 'note']
    events = [e['action'] for e in authed.get(f'{base}/timeline').json()['events']]
    assert events[0] == 'case.open'
    assert {
        'case.item.add',
        'case.note',
        'case.update',
        'case.close',
        'case.reopen',
        'case.item.remove',
    } <= set(events)
    assert authed.delete(base).json() == {'deleted': case['id']}
    assert authed.get(base).status_code == 404
    assert authed.get(f'/api/documents/{first}').status_code == 200  # reports stay


def test_errors_and_the_keys_tlp_limit(app: FastAPI, client: TestClient, authed: TestClient) -> None:
    amber = doc(authed, 'Partner only', 'Hidden 198.51.100.9.', tlp='AMBER')
    case = authed.post('/api/cases', json={'title': 'Mixed', 'tlp': 'GREEN'}).json()
    base = f'/api/cases/{case["id"]}'
    assert authed.post(f'{base}/items', json={'kind': 'document', 'target_id': 'nope'}).status_code == 404
    assert authed.post(f'{base}/items', json={'kind': 'technique', 'target_id': 'T1059'}).status_code == 422
    assert authed.post('/api/cases', json={'title': ''}).status_code == 422
    assert authed.get('/api/cases', params={'status': 'later'}).status_code == 422
    with app.state.session_factory.begin() as db:
        _, token = services.create_api_key(db, name='siem', access='read-write', max_tlp='GREEN')
    key = {'Authorization': f'Bearer {token}'}
    assert [c['id'] for c in client.get('/api/cases', headers=key).json()['cases']] == [case['id']]
    hidden = client.post(f'{base}/items', headers=key, json={'kind': 'document', 'target_id': amber})
    assert hidden.status_code == 404
    above = client.post('/api/cases', headers=key, json={'title': 'x', 'tlp': 'AMBER'})
    assert above.status_code == 403
    # Once the operator adds the AMBER report, the case is AMBER and disappears for the GREEN key.
    assert authed.post(f'{base}/items', json={'kind': 'document', 'target_id': amber}).status_code == 201
    assert client.get('/api/cases', headers=key).json()['cases'] == []
    assert client.get(base, headers=key).status_code == 404
    assert client.get(f'{base}/timeline', headers=key).status_code == 404
    assert client.delete(base, headers=key).status_code == 404


def test_read_only_keys_cannot_change_cases(app: FastAPI, client: TestClient, authed: TestClient) -> None:
    case = authed.post('/api/cases', json={'title': 'Readable', 'tlp': 'CLEAR'}).json()
    with app.state.session_factory.begin() as db:
        _, token = services.create_api_key(db, name='reader', access='read')
    key = {'Authorization': f'Bearer {token}'}
    assert client.get(f'/api/cases/{case["id"]}', headers=key).status_code == 200
    assert client.post('/api/cases', headers=key, json={'title': 'x'}).status_code == 403
    assert client.post(f'/api/cases/{case["id"]}/close', headers=key, json={'note': 'x'}).status_code == 403
