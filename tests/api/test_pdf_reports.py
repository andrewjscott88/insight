"""The PDF route accepts local bytes with authenticated publisher metadata and exposes the original hash."""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from insight import services

ADVISORY = Path(__file__).parents[1] / 'fixtures' / 'advisory.pdf'
ROUTE = '/api/documents/pdf'


def headers(**changes: str) -> dict[str, str]:
    data = {'title': 'PDF by Example', 'source_name': 'Example', 'tlp': 'GREEN', **changes}
    metadata = base64.urlsafe_b64encode(json.dumps(data).encode()).rstrip(b'=').decode()
    return {'content-type': 'application/pdf', 'x-insight-document': metadata}


def test_signed_in_upload_flows_into_normal_review_and_duplicate_handling(authed: TestClient) -> None:
    raw = ADVISORY.read_bytes()
    response = authed.post(ROUTE, content=raw, headers=headers())
    assert response.status_code == 200, response.text
    result = response.json()
    assert result['created']
    doc = authed.get('/api/documents/' + result['document_id']).json()
    assert doc['attachment']['sha256'] == result['file_sha256'] == hashlib.sha256(raw).hexdigest()
    assert doc['attachment']['size_bytes'] == len(raw)
    assert doc['tlp'] == 'GREEN'
    assert {o['value'] for o in doc['observations']} == {'192.0.2.17', 'example.org'}
    assert authed.post(ROUTE, content=raw, headers=headers()).json() == {**result, 'created': False}


def test_invalid_files_and_metadata_do_not_write(authed: TestClient) -> None:
    raw = ADVISORY.read_bytes()
    assert authed.post(ROUTE, content=raw, headers=headers() | {'x-csrf-token': 'wrong'}).status_code == 403
    assert authed.post(ROUTE, content=b'not a pdf', headers=headers()).status_code == 400
    assert (
        authed.post(ROUTE, content=raw, headers=headers() | {'content-type': 'text/plain'}).status_code == 415
    )
    assert authed.post(ROUTE, content=raw, headers={'content-type': 'application/pdf'}).status_code == 400
    assert authed.post(ROUTE, content=b'_' * 2_000_001, headers=headers()).status_code == 413
    assert (
        authed.post(ROUTE, content=raw, headers=headers(source_url='file:///tmp/source')).status_code == 400
    )
    assert authed.get('/api/documents').json() == []


@pytest.mark.parametrize(
    ('access', 'label', 'expected'),
    [('read', 'CLEAR', 403), ('read-write', 'RED', 400), ('read-write', 'CLEAR', 200)],
)
def test_bearer_key_ceiling(app: FastAPI, client: TestClient, access: str, label: str, expected: int) -> None:
    with app.state.session_factory.begin() as db:
        _, token = services.create_api_key(db, name='fixture', access=access, max_tlp='GREEN')
    raw = ADVISORY.read_bytes()
    result = client.post(
        ROUTE, content=raw, headers=headers(tlp=label) | {'authorization': f'Bearer {token}'}
    )
    assert result.status_code == expected, result.text
