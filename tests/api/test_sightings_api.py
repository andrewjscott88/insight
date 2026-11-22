"""``/api/sightings`` (TIP 4.2, ADR 0035), and the ``read-feedback`` key that may send sightings and requests
for information but change nothing else."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from fastapi import FastAPI
from fastapi.testclient import TestClient

from insight import services

SEEN = (datetime.now(UTC) - timedelta(hours=2)).isoformat()


def doc(authed: TestClient, body: str, tlp: str = 'GREEN') -> None:
    response = authed.post(
        '/api/documents', json={'title': 'Note', 'body': body, 'source_name': 'S', 'tlp': tlp}
    )
    assert response.status_code == 200, response.text


def key(app: FastAPI, access: str, max_tlp: str | None = None) -> dict[str, str]:
    with app.state.session_factory.begin() as db:
        services.revoke_api_key(db)
        _, token = services.create_api_key(db, name='shift', access=access, max_tlp=max_tlp)
    return {'Authorization': f'Bearer {token}'}


def test_a_feedback_key_sends_sightings_and_requests_and_nothing_else(
    app: FastAPI, client: TestClient, authed: TestClient
) -> None:
    doc(authed, 'Beacon to 203.0.113.95.')
    shift = key(app, 'read-feedback', 'AMBER')
    sent = client.post(
        '/api/sightings',
        headers=shift,
        json={'value': '203.0.113.95', 'first_seen': SEEN, 'count': 4, 'where': 'Corp east',
              'observer': 'Shift', 'external_ref': 'hunt-7', 'tlp': 'AMBER'},
    )  # fmt: skip
    assert sent.status_code == 201, sent.text
    sighting = sent.json()
    assert (sighting['count'], sighting['where'], sighting['last_seen']) == (
        4,
        'Corp east',
        sighting['first_seen'],
    )
    assert sighting['created_by'].startswith('api-key:')
    asked = client.post('/api/rfis', headers=shift, json={'question': 'Who else uses 203.0.113.95?'})
    assert asked.status_code == 201, asked.text
    listed = client.get('/api/sightings', headers=shift, params={'entity_id': sighting['entity_id']}).json()
    assert [s['id'] for s in listed['sightings']] == [sighting['id']]
    detail = client.get(f'/api/entities/{sighting["entity_id"]}', headers=shift).json()
    assert any(s['kind'] == 'sighting' for s in detail['confidence']['sources'])
    refused = (
        client.delete(f'/api/sightings/{sighting["id"]}', headers=shift),
        client.post('/api/cases', headers=shift, json={'title': 'Not mine'}),
        client.post('/api/documents', headers=shift, json={'title': 'x', 'body': 'y', 'source_name': 'z'}),
    )
    assert [r.status_code for r in refused] == [403, 403, 403]
    assert authed.delete(f'/api/sightings/{sighting["id"]}').json() == {'deleted': sighting['id']}
    actions = {e['action'] for e in authed.get('/api/audit').json()}
    assert {'sighting.add', 'sighting.delete'} <= actions


def test_bad_sightings_are_refused(app: FastAPI, client: TestClient, authed: TestClient) -> None:
    doc(authed, 'Beacon to 203.0.113.96.', tlp='AMBER')
    doc(authed, 'Beacon to 203.0.113.97.')
    shift = key(app, 'read-feedback', 'GREEN')
    later = (datetime.now(UTC) + timedelta(days=1)).isoformat()
    for body, status in (
        ({'value': '203.0.113.96', 'first_seen': SEEN}, 404),  # above the key's limit
        ({'value': '198.51.100.251', 'first_seen': SEEN}, 404),  # not known
        ({'value': '203.0.113.96', 'first_seen': later}, 422),
        ({'value': '203.0.113.96', 'first_seen': SEEN, 'count': 0}, 422),
        ({'value': '203.0.113.97', 'first_seen': SEEN, 'tlp': 'AMBER'}, 403),  # a label above the limit
    ):
        response = client.post('/api/sightings', headers=shift, json=body)
        assert response.status_code == status, (body, response.text)
    reader = key(app, 'read')
    assert (
        client.post('/api/sightings', headers=reader, json={'value': 'x', 'first_seen': SEEN}).status_code
        == 403
    )
