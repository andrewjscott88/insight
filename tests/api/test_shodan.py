"""`/api/enrichment/shodan/{ip}` and `/api/ips/{ip}/shodan` (TIP 3.7): who may ask, what comes back."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from tests.greynoise_fixtures import IP, provider_error, reviewed

from insight import services, shodan
from insight.lookups import THROTTLES

POST = f'/api/enrichment/shodan/{IP}'
GET = f'/api/ips/{IP}/shodan'
FIXTURE = (Path(__file__).parents[1] / 'fixtures' / 'shodan-host.json').read_bytes()
KEY = 'testkey' * 4  # obviously fake; low entropy so secret scanners stay quiet


def test_shodan_needs_a_key_an_unlimited_caller_and_shows_refusals(
    authed: TestClient, app: FastAPI, monkeypatch: pytest.MonkeyPatch
) -> None:
    with app.state.session_factory.begin() as db:
        reviewed(db)
        _, key = services.create_api_key(db, name='limited', access='read-write', max_tlp='CLEAR')
    limited = {'Authorization': f'Bearer {key}'}
    csrf = {'X-CSRF-Token': authed.get('/api/session').json()['csrf_token']}
    assert authed.post(POST, headers=limited).status_code == 403  # TLP-limited keys never trigger lookups
    assert authed.get(GET, headers=limited).status_code == 404  # nothing cached yet
    monkeypatch.delenv('INSIGHT_SHODAN_KEY', raising=False)
    calls: list[Any] = []

    async def provider(*args: Any, **kwargs: Any) -> bytes:
        calls.append(args)
        if answers:
            raise answers.pop(0)
        return FIXTURE

    answers = [provider_error(402), provider_error(429, '12')]
    monkeypatch.setattr(shodan, 'download', provider)
    unset = authed.post(POST, headers=csrf)
    assert (unset.status_code, calls) == (503, [])  # no key, no calls
    monkeypatch.setenv('INSIGHT_SHODAN_KEY', KEY)
    credits = authed.post(POST, headers=csrf)
    assert credits.status_code == 502
    assert 'your plan, credits or access do not allow it' in credits.json()['detail']
    THROTTLES['shodan'].reset()
    busy = authed.post(POST, headers=csrf)
    assert (busy.status_code, busy.headers['Retry-After']) == (429, '12')
    THROTTLES['shodan'].reset()
    ok = authed.post(POST, headers=csrf)
    assert ok.status_code == 200
    body = ok.json()
    assert (body['ports'], body['attribution']) == ([53, 443], shodan.ATTRIBUTION)
    assert KEY not in ok.text
    assert authed.get(GET, headers=limited).json() == body  # read-only cached view for any key
    assert authed.post(f'/api/enrichment/shodan/{IP}/x', headers=csrf).status_code in (404, 405)


def test_an_address_without_a_reviewed_clear_mention_is_refused(
    authed: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv('INSIGHT_SHODAN_KEY', KEY)
    csrf = {'X-CSRF-Token': authed.get('/api/session').json()['csrf_token']}
    refused = authed.post('/api/enrichment/shodan/1.1.1.1', headers=csrf)
    assert refused.status_code == 404
    assert json.loads(refused.text)['detail'].startswith('No eligible reviewed public IPv4')
