"""Software API contracts through session, key, CSRF and TLP boundaries."""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient

from .test_sightings_api import key


def _report(authed: TestClient, tlp: str = 'CLEAR') -> str:
    response = authed.post(
        '/api/documents',
        json={
            'title': 'Synthetic software report',
            'source_name': 'Lab',
            'body': 'Cobalt Strike communicated with 192.0.2.71.',
            'tlp': tlp,
        },
    )
    assert response.status_code == 200
    return str(response.json()['id'])


def test_software_search_detail_links_and_validation(authed: TestClient) -> None:
    doc = _report(authed)
    assert authed.get('/api/software?q=Cobalt').json()['software'][0]['id'] == 'S0154'
    assert authed.get('/api/software?limit=201').status_code == 422
    assert authed.get('/api/software?offset=-1').status_code == 422
    detail = authed.get('/api/software/S0154').json()
    assert detail['candidates'][0]['document_id'] == doc
    linked = authed.post(
        '/api/software/S0154/documents', json={'document_id': doc, 'note': 'Checked', 'tlp': 'GREEN'}
    )
    assert linked.status_code == 201, linked.text
    assert linked.json()['created_by'] == 'operator'
    assert authed.get('/api/software/S0154/documents').json()['reports'][0]['note'] == 'Checked'
    assert authed.get(f'/api/documents/{doc}/software').json()['software'][0]['id'] == 'S0154'
    assert (
        authed.post('/api/software/S0154/documents', json={'document_id': doc, 'extra': 'no'}).status_code
        == 422
    )
    assert authed.get('/api/software/S999999').status_code == 404
    assert authed.post('/api/software/S999999/documents', json={'document_id': doc}).status_code == 404
    assert authed.get('/api/documents/missing/software').status_code == 404
    assert authed.delete(f'/api/software/S0154/documents/{doc}').json() == {'removed': doc}
    assert authed.delete(f'/api/software/S0154/documents/{doc}').status_code == 404


def test_software_link_label_and_key_permissions(
    app: FastAPI, client: TestClient, authed: TestClient
) -> None:
    doc = _report(authed)
    hidden = _report(authed, 'AMBER')
    assert (
        authed.post(
            '/api/software/S0154/documents',
            json={
                'document_id': doc,
                'note': 'Private marker',
                'tlp': 'AMBER',
            },
        ).status_code
        == 201
    )
    green = key(app, 'read-write', 'GREEN')
    assert client.get('/api/software/S0154', headers=green).json()['reports'] == []
    assert client.get(f'/api/documents/{hidden}/software', headers=green).status_code == 404
    assert (
        client.post('/api/software/S0154/documents', headers=green, json={'document_id': doc}).status_code
        == 404
    )
    assert (
        client.post('/api/software/S0154/documents', headers=green, json={'document_id': hidden}).status_code
        == 404
    )
    assert (
        client.post(
            '/api/software/S0154/documents',
            headers=green,
            json={
                'document_id': doc,
                'tlp': 'RED',
            },
        ).status_code
        == 403
    )
    assert client.delete(f'/api/software/S0154/documents/{doc}', headers=green).status_code == 404
    for access in ('read', 'read-feedback'):
        reader = key(app, access, 'GREEN')
        assert client.get('/api/software', headers=reader).status_code == 200
        assert (
            client.post(
                '/api/software/S0154/documents', headers=reader, json={'document_id': doc}
            ).status_code
            == 403
        )


def test_browser_write_requires_csrf_and_explicit_uses(authed: TestClient) -> None:
    doc = _report(authed)
    token = authed.headers.pop('X-CSRF-Token')
    assert authed.post('/api/software/S0154/documents', json={'document_id': doc}).status_code == 403
    authed.headers['X-CSRF-Token'] = token
    campaign = authed.post('/api/campaigns', json={'name': 'Synthetic campaign', 'tlp': 'GREEN'}).json()['id']
    path = f'/api/campaigns/{campaign}/links'
    result = authed.post(path, json={'target_kind': 'software', 'target_id': 'S0154', 'tlp': 'GREEN'})
    assert result.status_code == 201, result.text
    assert authed.get(path).json()['links'][0]['target_kind'] == 'software'
    assert authed.get('/api/software/S0154').json()['uses'][0]['ref'] == campaign
    assert authed.delete(path + '/software/S0154').status_code == 200
