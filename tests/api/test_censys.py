"""Censys API authorization, explicit disclosure, and private cached reads through real middleware."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from tests.greynoise_fixtures import IP, reviewed

from insight import censys, services
from insight.lookups import THROTTLES

POST = f'/api/enrichment/censys/{IP}'
GET = f'/api/ips/{IP}/censys'
RAW = (Path(__file__).parents[1] / 'fixtures' / 'censys-host.json').read_bytes()


def test_censys_requires_explicit_approval_and_unlimited_write_access(
    authed: TestClient,
    app: FastAPI,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with app.state.session_factory.begin() as db:
        reviewed(db)
        _, limited = services.create_api_key(db, name='limited', access='read-write', max_tlp='GREEN')
    calls: list[Any] = []

    async def provider(*args: Any, **kwargs: Any) -> bytes:
        calls.append(args)
        return RAW

    monkeypatch.setattr(censys, 'download', provider)
    monkeypatch.delenv('INSIGHT_CENSYS_PAT', raising=False)
    monkeypatch.delenv('INSIGHT_CENSYS_ORG_ID', raising=False)
    csrf = {'X-CSRF-Token': authed.get('/api/session').json()['csrf_token']}
    headers = {'Authorization': f'Bearer {limited}'}
    assert authed.post(POST, json={'approved': True}, headers=headers).status_code == 403
    with app.state.session_factory.begin() as db:
        key = services.active_api_key(db)
        assert key is not None
        key.access, key.max_tlp = 'read', None
    assert authed.post(POST, json={'approved': True}, headers=headers).status_code == 403
    with app.state.session_factory.begin() as db:
        key = services.active_api_key(db)
        assert key is not None
        key.access = 'read-write'
    saved_csrf = authed.headers.pop('X-CSRF-Token')
    assert authed.post(POST, json={'approved': True}).status_code == 403
    authed.headers['X-CSRF-Token'] = saved_csrf
    for payload in ({}, {'approved': False}, {'approved': 'yes'}, {'approved': True, 'extra': 1}):
        assert authed.post(POST, json=payload, headers=csrf).status_code == 422
    assert authed.post(POST, json={'approved': True}, headers=csrf).status_code == 503
    assert calls == []
    monkeypatch.setenv('INSIGHT_CENSYS_PAT', 'censys_test_token')
    result = authed.post(POST, json={'approved': True}, headers=headers)
    assert result.status_code == 200
    assert result.json()['attribution'] == censys.ATTRIBUTION
    assert 'PRIVATE' not in result.text
    assert 'censys_test_token' not in result.text
    with app.state.session_factory.begin() as db:
        key = services.active_api_key(db)
        assert key is not None
        key.access, key.max_tlp = 'read', 'GREEN'
    assert authed.get(GET, headers=headers).json() == result.json()
    assert len(calls) == 1
    THROTTLES['censys'].reset()
    assert (
        authed.post('/api/enrichment/censys/1.1.1.1', json={'approved': True}, headers=csrf).status_code
        == 404
    )


def test_open_access_mode_cannot_serve_censys_cache(
    authed: TestClient,
    app: FastAPI,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Regression: a licensed private cache must not become public when temporary open access is enabled."""
    with app.state.session_factory.begin() as db:
        reviewed(db)
        services.store_censys_context(db, IP, censys._parse(RAW, IP), max_tlp='CLEAR')
        _, writer = services.create_api_key(db, name='writer', access='read-write')
    monkeypatch.setattr(app.state, 'settings', replace(app.state.settings, dev_no_auth=True))
    headers = {'Authorization': f'Bearer {writer}'}
    assert authed.get(GET, headers=headers).status_code == 503
    assert authed.post(POST, json={'approved': True}, headers=headers).status_code == 503
