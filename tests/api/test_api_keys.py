"""API key authentication and per-caller rate limits through the full middleware stack."""

from __future__ import annotations

import logging
from collections.abc import Callable
from datetime import UTC, datetime, timedelta

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from insight import services
from insight.ratelimit import IOC_EXPORT, READ, WRITE
from insight.web.boundary import SESSION_ONLY_ROUTES

from .test_auth import PROTECTED

DOCUMENT = {'title': 'Report', 'body': 'Seen CVE-2024-12345 at 192.0.2.8.', 'source_name': 'Test'}
SAFE = {'GET', 'HEAD'}


def issue_key(app: FastAPI, access: str = 'read') -> str:
    with app.state.session_factory.begin() as db:
        _, token = services.create_api_key(db, name='test', access=access)
    return token


def bearer(token: str) -> dict[str, str]:
    return {'Authorization': f'Bearer {token}'}


@pytest.fixture
def read_key(app: FastAPI) -> str:
    return issue_key(app, 'read')


@pytest.fixture
def write_key(app: FastAPI) -> str:
    return issue_key(app, 'read-write')


# --------------------------------------------------------------------------- authentication


@pytest.mark.parametrize(('method', 'path'), [r for r in PROTECTED if r[1] not in SESSION_ONLY_ROUTES])
def test_a_read_key_can_read_everything_and_write_nothing(
    client: TestClient, read_key: str, method: str, path: str
) -> None:
    response = client.request(method, path, headers=bearer(read_key))
    if method in SAFE or (method, path) == ('POST', '/mcp'):
        assert response.status_code not in (401, 403), response.text  # 404 for the placeholder IDs is fine
    else:
        assert response.status_code == 403
        assert response.json() == {'detail': 'This API key is read-only'}


def test_a_read_write_key_writes_without_csrf(client: TestClient, write_key: str) -> None:
    created = client.post('/api/documents', json=DOCUMENT, headers=bearer(write_key))
    assert created.status_code == 200, created.text
    doc_id = created.json()['id']
    assert client.post(
        f'/api/documents/{doc_id}/review', json={'status': 'reviewed'}, headers=bearer(write_key)
    ).json() == {'status': 'reviewed'}
    listed = client.get('/api/documents', headers=bearer(write_key)).json()
    assert [d['id'] for d in listed] == [doc_id]


@pytest.mark.parametrize('route', ['/api/demo'])
def test_regression_l4_the_demo_is_for_browser_sessions_only(
    client: TestClient, write_key: str, route: str
) -> None:
    """Review L4: any read-write key could add synthetic reports to a production dataset."""
    response = client.post(route, headers=bearer(write_key))
    assert (response.status_code, response.json()) == (403, {'detail': 'Not available to API keys'})


def test_the_session_route_is_for_browsers_only(client: TestClient, write_key: str) -> None:
    response = client.get('/api/session', headers=bearer(write_key))
    assert response.status_code == 403
    assert response.json() == {'detail': 'Not available to API keys'}


@pytest.mark.parametrize(
    'token',
    ['garbage', 'insk_0123456789ab_' + 'A' * 43, ''],
    ids=['malformed', 'unknown', 'empty-bearer'],
)
def test_invalid_keys_get_one_uniform_answer(client: TestClient, token: str) -> None:
    response = client.get('/api/stats', headers=bearer(token))
    assert response.status_code == 401
    if token:
        assert response.json() == {'detail': 'Invalid or expired API key'}
        assert response.headers['www-authenticate'] == 'Bearer error="invalid_token"'


def test_revoked_and_expired_keys_are_refused(app: FastAPI, client: TestClient, read_key: str) -> None:
    assert client.get('/api/stats', headers=bearer(read_key)).status_code == 200
    with app.state.session_factory.begin() as db:
        key = services.active_api_key(db)
        assert key is not None
        key.expires_at = (datetime.now(UTC) - timedelta(seconds=1)).isoformat()
    expired = client.get('/api/stats', headers=bearer(read_key))
    assert (expired.status_code, expired.json()) == (401, {'detail': 'Invalid or expired API key'})

    token = issue_key(app)
    assert client.get('/api/stats', headers=bearer(token)).status_code == 200
    with app.state.session_factory.begin() as db:
        services.revoke_api_key(db)
    assert client.get('/api/stats', headers=bearer(token)).status_code == 401  # immediately, no restart


def test_rotation_switches_keys_immediately(app: FastAPI, client: TestClient, read_key: str) -> None:
    with app.state.session_factory.begin() as db:
        _, new = services.rotate_api_key(db)
    assert client.get('/api/stats', headers=bearer(read_key)).status_code == 401
    assert client.get('/api/stats', headers=bearer(new)).status_code == 200


def test_a_bad_bearer_key_is_not_rescued_by_a_session_cookie(authed: TestClient) -> None:
    assert authed.get('/api/stats').status_code == 200
    assert authed.get('/api/stats', headers=bearer('garbage')).status_code == 401


def test_other_authorization_schemes_fall_back_to_the_session(authed: TestClient, client: TestClient) -> None:
    """Basic auth added by a reverse proxy must not break the signed-in workspace's own API calls."""
    assert authed.get('/api/stats', headers={'Authorization': 'Basic dXNlcjpwYXNz'}).status_code == 200
    authed.cookies.clear()
    assert authed.get('/api/stats', headers={'Authorization': 'Basic dXNlcjpwYXNz'}).status_code == 401


def test_cookie_sessions_still_need_csrf(authed: TestClient) -> None:
    del authed.headers['X-CSRF-Token']
    assert authed.post('/api/documents', json=DOCUMENT).status_code == 403


def test_keys_never_open_the_workspace(client: TestClient, write_key: str) -> None:
    """API keys authenticate /api only; the UI and its socket stay session-only."""
    response = client.get('/_nicegui_ws/socket.io/?EIO=4&transport=polling', headers=bearer(write_key))
    assert response.status_code == 403


def test_last_use_is_recorded(app: FastAPI, client: TestClient, read_key: str) -> None:
    client.get('/api/stats', headers=bearer(read_key))
    with app.state.session_factory() as db:
        key = services.active_api_key(db)
        assert key is not None
        assert key.last_used_at is not None


def test_logs_name_the_key_id_never_the_key(
    app: FastAPI, client: TestClient, write_key: str, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.INFO, logger='insight.auth')
    client.post('/api/documents', json=DOCUMENT, headers=bearer(write_key))
    forged = write_key[:-1] + ('A' if write_key[-1] != 'A' else 'B')
    client.get('/api/stats', headers=bearer(forged))
    key_id = write_key.split('_')[1]
    assert f'API key {key_id}: POST /api/documents' in caplog.text
    assert f'Rejected API key {key_id} from testclient: unknown' in caplog.text
    assert write_key not in caplog.text
    assert forged not in caplog.text


# --------------------------------------------------------------------------- rate limits


class FrozenClock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now


@pytest.fixture
def clock(app: FastAPI) -> FrozenClock:
    """Freeze the limiters: hundreds of real requests take seconds, during which buckets would refill."""
    frozen = FrozenClock()
    app.state.rate_limiter.clock = frozen
    app.state.auth_failure_limiter.clock = frozen
    return frozen


def exhaust(send: Callable[[], int], limit: int) -> None:
    statuses = [send() for _ in range(limit)]
    assert set(statuses) == {200}, statuses


def test_reads_are_limited_per_caller_with_standard_headers(
    client: TestClient, authed: TestClient, read_key: str, clock: FrozenClock
) -> None:
    first = client.get('/api/stats', headers=bearer(read_key))
    assert first.headers['ratelimit-policy'] == '"read";q=300;w=60'
    assert first.headers['ratelimit'].startswith('"read";r=299;')
    exhaust(lambda: client.get('/api/stats', headers=bearer(read_key)).status_code, READ.limit - 1)
    refused = client.get('/api/stats', headers=bearer(read_key))
    assert refused.status_code == 429
    assert refused.json() == {'detail': 'Rate limit exceeded (read); retry in 1 s'}
    assert refused.headers['retry-after'] == '1'
    assert refused.headers['ratelimit'].startswith('"read";r=0;')
    # The key's flood does not touch the operator's own budget.
    assert authed.get('/api/stats').status_code == 200
    clock.now += 0.2  # one token refills every 0.2 s
    assert client.get('/api/stats', headers=bearer(read_key)).status_code == 200


def test_writes_have_a_smaller_budget(client: TestClient, write_key: str, clock: FrozenClock) -> None:
    exhaust(
        lambda: client.post('/api/documents', json=DOCUMENT, headers=bearer(write_key)).status_code,
        WRITE.limit,
    )
    refused = client.post('/api/documents', json=DOCUMENT, headers=bearer(write_key))
    assert refused.status_code == 429
    assert refused.headers['ratelimit-policy'] == '"write";q=60;w=60'
    assert client.get('/api/stats', headers=bearer(write_key)).status_code == 200  # reads unaffected


def test_ioc_exports_have_their_own_budget(client: TestClient, read_key: str, clock: FrozenClock) -> None:
    exhaust(lambda: client.get('/api/iocs/export', headers=bearer(read_key)).status_code, IOC_EXPORT.limit)
    refused = client.get('/api/iocs/export', headers=bearer(read_key))
    assert refused.status_code == 429
    assert refused.headers['retry-after'] == '120'
    assert client.get('/api/stats', headers=bearer(read_key)).status_code == 200


def test_invalid_key_floods_are_throttled_without_locking_out_the_real_key(
    client: TestClient, read_key: str, clock: FrozenClock
) -> None:
    statuses = [client.get('/api/stats', headers=bearer('garbage')).status_code for _ in range(11)]
    assert statuses == [401] * 10 + [429]
    refused = client.get('/api/stats', headers=bearer('garbage'))
    assert refused.json() == {'detail': 'Too many invalid API key attempts'}
    assert refused.headers['retry-after'] == '6'
    assert client.get('/api/stats', headers=bearer(read_key)).status_code == 200
    clock.now += 6
    assert client.get('/api/stats', headers=bearer('garbage')).status_code == 401  # throttled, not locked


def test_unauthenticated_requests_carry_no_rate_limit_headers(client: TestClient) -> None:
    response = client.get('/api/stats')
    assert response.status_code == 401
    assert 'ratelimit' not in response.headers
    assert 'ratelimit' not in client.get('/health').headers
