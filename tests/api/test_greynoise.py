"""GreyNoise public context lookup permissions, provider errors and offline cache reads."""

from __future__ import annotations

from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from tests.greynoise_fixtures import IP, provider_error, reviewed

from insight import greynoise, services
from insight.lookups import THROTTLES

POST = f'/api/enrichment/greynoise/{IP}'
GET = f'/api/ips/{IP}/greynoise'


def test_greynoise_authorization_and_cached_read(
    authed: TestClient, app: FastAPI, monkeypatch: pytest.MonkeyPatch
) -> None:
    with app.state.session_factory.begin() as db:
        reviewed(db)
        _, key = services.create_api_key(db, name='limited', access='read-write', max_tlp='CLEAR')
    headers = {'Authorization': f'Bearer {key}'}
    assert authed.post(POST, headers=headers).status_code == 403
    assert authed.get(GET, headers=headers).status_code == 404
    session_response = authed.get('/api/session')
    assert session_response.status_code == 200, (session_response.status_code, session_response.text)
    csrf = {'X-CSRF-Token': session_response.json()['csrf_token']}
    assert authed.post(POST, headers={'X-CSRF-Token': 'wrong'}).status_code == 403
    monkeypatch.delenv('INSIGHT_GREYNOISE_KEY', raising=False)
    assert authed.post(POST, headers=csrf).status_code == 503
    monkeypatch.setenv('INSIGHT_GREYNOISE_KEY', 'fixture')
    codes = [401, 429, 404]

    async def fake(*args: Any, **kwargs: Any) -> bytes:
        raise provider_error(codes.pop(0), '45')

    monkeypatch.setattr(greynoise, 'download', fake)
    bad = authed.post(POST, headers=csrf)
    assert bad.status_code == 502
    assert 'PRIVATE-RAW' not in bad.text
    THROTTLES['greynoise'].reset()
    limited = authed.post(POST, headers=csrf)
    assert limited.status_code == 429
    assert limited.headers['Retry-After'] == '45'
    THROTTLES['greynoise'].reset()
    result = authed.post(POST, headers=csrf)
    assert result.status_code == 200
    assert result.json()['found'] is False
    assert authed.get(GET, headers=headers).json() == result.json()
    assert not codes
