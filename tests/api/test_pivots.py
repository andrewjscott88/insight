"""Manual lookup routes use real middleware and never disclose through a limited key."""

from __future__ import annotations

from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from tests.greynoise_fixtures import reviewed

from insight import pivots, services
from insight.lookups import THROTTLES


@pytest.fixture(autouse=True)
def synthetic_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv('INSIGHT_CIRCL_PDNS_USER', 'synthetic-user')
    monkeypatch.setenv('INSIGHT_CIRCL_PDNS_PASSWORD', 'synthetic-password')


DOMAIN = 'example.com'


def test_missing_credentials_refuse_lookup_without_exposing_settings(
    authed: TestClient, app: FastAPI, monkeypatch: pytest.MonkeyPatch
) -> None:
    with app.state.session_factory.begin() as db:
        reviewed(db, DOMAIN)
        services.set_pivot_switch(db, 'circl', True)
    monkeypatch.delenv('INSIGHT_CIRCL_PDNS_PASSWORD')
    result = authed.post('/api/pivots/circl', json={'value': DOMAIN, 'approved': True})
    assert result.status_code == 503
    assert 'synthetic-user' not in result.text
    assert 'synthetic-password' not in result.text
    assert authed.get('/api/pivots', params={'value': DOMAIN}).json() == []


def test_lookup_requires_unlimited_write_access_and_per_lookup_approval(
    authed: TestClient, app: FastAPI, monkeypatch: pytest.MonkeyPatch
) -> None:
    with app.state.session_factory.begin() as db:
        reviewed(db, DOMAIN)
        services.set_pivot_switch(db, 'circl', True)
        _, token = services.create_api_key(db, name='green', access='read-write', max_tlp='GREEN')
    calls: list[str] = []

    async def fake(provider: str, value: str) -> dict[str, Any]:
        calls.append(value)
        return {'found': True, 'nodes': [{'type': 'name_server', 'value': 'ns1.example.net'}]}

    monkeypatch.setattr(pivots, '_fetch', fake)
    path = '/api/pivots/circl'
    limited = {'Authorization': f'Bearer {token}'}
    body = {'value': DOMAIN, 'approved': True}
    assert authed.post(path, json=body, headers=limited).status_code == 403
    assert authed.post(path, json={'value': DOMAIN}).status_code == 422
    assert calls == []
    THROTTLES['circl'].reset()
    response = authed.post(path, json=body)
    assert response.status_code == 200, response.text
    cached = authed.get('/api/pivots', params={'value': DOMAIN}, headers=limited)
    assert cached.json() == [response.json()]
    assert calls == [DOMAIN]
    with app.state.session_factory() as db:
        entity_id = services.eligible_pivot(db, DOMAIN, max_tlp='GREEN')
    graph = authed.get('/api/graph', params={'node': f'indicator:{entity_id}'}, headers=limited)
    assert graph.status_code == 200
    pivot_node = next(n for n in graph.json()['nodes'] if n['type'] == 'name_server')
    centred = authed.get('/api/graph', params={'node': pivot_node['id']}, headers=limited)
    assert centred.status_code == 200
    assert centred.json()['seed'] == pivot_node['id']
    assert authed.get('/api/pivots', params={'value': 'missing.example'}).status_code == 404
    assert authed.post(path, json={**body, 'extra': True}).status_code == 422
