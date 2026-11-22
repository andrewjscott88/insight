"""``/api/source-ratings``, report credibility and indicator confidence (TIP 4.2, ADR 0033)."""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient

from insight import services


def doc(authed: TestClient, body: str, source: str, tlp: str = 'GREEN') -> str:
    response = authed.post(
        '/api/documents', json={'title': f'{source} note', 'body': body, 'source_name': source, 'tlp': tlp}
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


def test_grades_and_credibility_raise_confidence_and_are_audited(authed: TestClient) -> None:
    first = doc(authed, 'C2 at 203.0.113.90.', 'Vendor')
    doc(authed, 'Also 203.0.113.90.', 'CERT')
    ip = entity_id(authed, '203.0.113.90')
    before = authed.get(f'/api/entities/{ip}/confidence').json()
    assert (before['band'], before['half_life_days']) == ('low', 30)

    rated = authed.put(
        '/api/source-ratings', json={'source_name': 'Vendor', 'reliability': 'A', 'note': 'Paid'}
    )
    assert rated.status_code == 200, rated.text
    assert (rated.json()['reliability'], rated.json()['updated_by']) == ('A', 'operator')
    credible = authed.put(f'/api/documents/{first}/credibility', json={'credibility': 1})
    assert credible.json() == {'id': first, 'credibility': 1}
    assert authed.get(f'/api/documents/{first}').json()['credibility'] == 1

    after = authed.get(f'/api/entities/{ip}').json()['confidence']
    assert after['score'] > before['score']
    assert after['sources'][0]['source_name'] == 'Vendor'
    assert after['sources'][0]['reliability_label'] == 'Completely reliable'
    listed = {s['source_name']: s for s in authed.get('/api/source-ratings').json()['sources']}
    assert (listed['Vendor']['reliability'], listed['CERT']['reliability']) == ('A', 'F')
    actions = {e['action'] for e in authed.get('/api/audit').json()}
    assert {'source.rate', 'document.credibility'} <= actions


def test_bad_grades_are_refused(authed: TestClient) -> None:
    first = doc(authed, 'Text.', 'Vendor')
    assert (
        authed.put('/api/source-ratings', json={'source_name': 'Vendor', 'reliability': 'G'}).status_code
        == 422
    )
    too_long = {'source_name': 'Vendor', 'reliability': 'A', 'half_life_days': 9999}
    assert authed.put('/api/source-ratings', json=too_long).status_code == 422
    assert authed.put(f'/api/documents/{first}/credibility', json={'credibility': 7}).status_code == 422
    assert authed.put('/api/documents/nope/credibility', json={'credibility': 2}).status_code == 404


def test_a_limited_key_sees_only_its_reports_and_cannot_grade_sources(
    app: FastAPI, client: TestClient, authed: TestClient
) -> None:
    doc(authed, 'C2 at 203.0.113.91.', 'Vendor')
    hidden = doc(authed, 'C2 at 203.0.113.91.', 'Partner feed', tlp='AMBER')
    only_hidden = doc(authed, 'Beacon 203.0.113.92.', 'Partner feed', tlp='AMBER')
    ip, secret = entity_id(authed, '203.0.113.91'), entity_id(authed, '203.0.113.92')
    writer = key(app, 'read-write', 'GREEN')
    seen = client.get(f'/api/entities/{ip}/confidence', headers=writer).json()
    assert [s['source_name'] for s in seen['sources']] == ['Vendor']
    assert client.get(f'/api/entities/{secret}/confidence', headers=writer).status_code == 404
    names = [s['source_name'] for s in client.get('/api/source-ratings', headers=writer).json()['sources']]
    assert names == ['Vendor']
    graded = client.put(
        '/api/source-ratings', headers=writer, json={'source_name': 'Vendor', 'reliability': 'A'}
    )
    assert graded.status_code == 403
    for target in (hidden, only_hidden):
        refused = client.put(f'/api/documents/{target}/credibility', headers=writer, json={'credibility': 1})
        assert refused.status_code == 404
    reader = key(app, 'read')
    assert (
        client.put(
            '/api/source-ratings', headers=reader, json={'source_name': 'V', 'reliability': 'A'}
        ).status_code
        == 403
    )
