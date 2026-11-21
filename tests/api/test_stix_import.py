"""STIX import uses the standard write boundary and commits one complete bundle."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

from fastapi import FastAPI
from fastapi.testclient import TestClient

from insight import services

URL = '/api/import/stix'
CLEAR = 'marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487'
RED = 'marking-definition--e828b379-4e03-4974-9ac4-e53a884c97c1'


def simple_bundle(*, marking: str = CLEAR) -> dict[str, Any]:
    stamp = '2024-01-01T00:00:00.000Z'
    return {'type':'bundle', 'id':f'bundle--{uuid4()}', 'objects':[{
        'type':'indicator', 'id':f'indicator--{uuid4()}', 'spec_version':'2.1', 'created':stamp,
        'modified':stamp, 'valid_from':stamp, 'object_marking_refs':[marking],
        'pattern_type':'stix', 'pattern':"[domain-name:value = 'Example.NET']",
    }]}


def test_signed_in_session_imports_and_rolls_back_a_malformed_batch(authed: TestClient) -> None:
    first = simple_bundle()
    response = authed.post(URL,json=first)
    assert response.status_code == 200, response.text
    record_id = response.json()['document_ids'][0]
    assert authed.get(f'/api/documents/{record_id}').json()['tlp'] == 'CLEAR'
    assert authed.post(URL,json=first).json()['created'] == 0
    malformed = simple_bundle()
    malformed['objects'].append({'type':'indicator','id':f'indicator--{uuid4()}'})
    assert authed.post(URL,json=malformed).status_code == 400
    assert authed.post(URL,json=simple_bundle(marking=RED)).status_code == 400
    assert len(authed.get('/api/documents').json()) == 1


def test_auth_csrf_size_and_content_type(authed: TestClient) -> None:
    assert authed.post(URL, json=simple_bundle(), headers={'x-csrf-token':'wrong'}).status_code == 403
    assert authed.post(URL, content='hello').status_code == 415
    assert authed.post(URL, content='[]', headers={'content-type':'application/json'}).status_code == 400
    assert authed.post(URL, content=b' '*2_000_001, headers={'content-type':'application/json'}).status_code == 413


def test_bearer_key_scope_and_tlp_ceiling(app: FastAPI, client: TestClient) -> None:
    with app.state.sessions.begin() as db:
        _,token = services.create_api_key(db, name='reader',access='read',max_tlp='GREEN')
    assert client.post(URL,json=simple_bundle(),headers={'authorization':f'Bearer {token}'}).status_code == 403
    with app.state.sessions.begin() as db:
        services.revoke_api_key(db)
        _,token = services.create_api_key(db, name='writer',access='read-write',max_tlp='CLEAR')
    headers = {'authorization':f'Bearer {token}'}
    assert client.post(URL,json=simple_bundle(marking=RED),headers=headers).status_code == 400
    unmarked = simple_bundle()
    unmarked['objects'][0].pop('object_marking_refs')
    assert client.post(URL,json=unmarked,headers=headers).status_code == 400
    assert client.post(URL,json=simple_bundle(),headers=headers).status_code == 200
