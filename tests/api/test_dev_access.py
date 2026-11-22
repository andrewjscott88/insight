"""Temporary password-free browser access still uses the real session, origin and CSRF boundaries."""

from __future__ import annotations

import dataclasses
from collections.abc import Iterator

import pytest
from fastapi import FastAPI, WebSocket
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from insight.config import Settings
from insight.main import create_app


@pytest.fixture
def open_settings(settings: Settings) -> Settings:
    return dataclasses.replace(settings, dev_no_auth=True)


@pytest.fixture
def open_app(open_settings: Settings) -> FastAPI:
    app = create_app(open_settings, with_ui=False)

    @app.websocket('/_nicegui_ws/dev-test')
    async def socket(websocket: WebSocket) -> None:
        await websocket.accept()
        await websocket.send_text('session accepted')
        await websocket.close()

    return app


@pytest.fixture
def open_client(open_app: FastAPI) -> Iterator[TestClient]:
    with TestClient(open_app, follow_redirects=False) as client:
        yield client


def enter(client: TestClient) -> str:
    response = client.get('/login')
    assert response.status_code == 200
    assert 'location' not in response.headers
    assert 'href="/">Continue to workspace</a>' in response.text
    token: str = client.get('/api/session').json()['csrf_token']
    assert len(token) >= 32
    return token


def test_cross_site_entry_finishes_before_continuing(open_client: TestClient) -> None:
    """Regression: a cross-site redirect chain withheld Strict cookies and bounced back to login forever."""
    response = open_client.get(
        '/login?next=https://elsewhere.example', headers={'Sec-Fetch-Site': 'cross-site'}
    )
    assert response.status_code == 200
    assert 'location' not in response.headers
    assert 'href="/">Continue to workspace</a>' in response.text
    assert '<script src="/static/login-entry.js" defer></script>' in response.text
    assert 'elsewhere.example' not in response.text
    assert response.headers['cache-control'] == 'no-store'
    assert len(response.headers.get_list('set-cookie')) == 1
    assert open_client.get('/api/session').status_code == 200


def test_entry_does_not_redirect_when_the_browser_cannot_return_its_cookie(open_client: TestClient) -> None:
    """Regression: a browser withholding its cookie was sent through an unbounded HTTP redirect loop."""
    for _ in range(3):
        open_client.cookies.clear()
        response = open_client.get('/login')
        assert response.status_code == 200
        assert 'location' not in response.headers


def test_password_free_mode_bootstraps_only_browser_sessions(open_client: TestClient) -> None:
    assert open_client.get('/api/stats').status_code == 401
    assert open_client.get('/api/session').status_code == 401
    assert 'insight_session' not in open_client.cookies
    token = enter(open_client)
    assert open_client.get('/api/stats').status_code == 200
    assert open_client.get('/login').status_code == 303
    # Reusing the signed-in entry point must not replace the session or its CSRF token.
    assert open_client.get('/api/session').json()['csrf_token'] == token
    # A supplied invalid API key never falls back to the open-access browser session.
    assert open_client.get('/api/stats', headers={'Authorization': 'Bearer invalid'}).status_code == 401


def test_open_browser_writes_still_require_csrf_and_same_origin(open_client: TestClient) -> None:
    token = enter(open_client)
    report = {
        'title': 'Development report',
        'body': 'Check this report.',
        'source_name': 'Test',
        'tlp': 'CLEAR',
    }
    assert open_client.post('/api/documents', json=report).status_code == 403
    assert (
        open_client.post('/api/documents', json=report, headers={'X-CSRF-Token': 'wrong'}).status_code == 403
    )
    assert (
        open_client.post(
            '/api/documents',
            json=report,
            headers={'X-CSRF-Token': token, 'Origin': 'https://elsewhere.example'},
        ).status_code
        == 403
    )
    assert open_client.post('/api/documents', json=report, headers={'X-CSRF-Token': token}).status_code == 200
    assert open_client.get('/api/stats').json()['documents'] == 1


def test_cross_origin_requests_cannot_bootstrap_a_session(open_client: TestClient) -> None:
    assert open_client.get('/login', headers={'Origin': 'https://elsewhere.example'}).status_code == 403
    assert 'insight_session' not in open_client.cookies
    assert open_client.get('/api/session').status_code == 401


def test_open_access_keeps_secure_session_cookies(settings: Settings) -> None:
    app = create_app(dataclasses.replace(settings, dev_no_auth=True, secure_cookies=True), with_ui=False)
    with TestClient(app, base_url='https://testserver', follow_redirects=False) as client:
        response = client.get('/login')
        header = response.headers['set-cookie'].lower()
        assert '; secure' in header
        assert '; httponly' in header
        assert 'samesite=strict' in header
        assert client.get('/api/session').status_code == 200


def test_open_access_websockets_need_a_session_and_matching_origin(open_client: TestClient) -> None:
    with pytest.raises(WebSocketDisconnect), open_client.websocket_connect('/_nicegui_ws/dev-test'):
        pass
    enter(open_client)
    with open_client.websocket_connect(
        '/_nicegui_ws/dev-test', headers={'Origin': 'http://testserver'}
    ) as ws:
        assert ws.receive_text() == 'session accepted'
    with (
        pytest.raises(WebSocketDisconnect),
        open_client.websocket_connect(
            '/_nicegui_ws/dev-test', headers={'Origin': 'https://elsewhere.example'}
        ),
    ):
        pass


def test_turning_the_mode_off_invalidates_open_sessions_after_restart(
    open_client: TestClient, settings: Settings
) -> None:
    enter(open_client)
    cookie = open_client.cookies['insight_session']
    # Same credentials/database, normal mode: the open-mode cookie must not become proof of a password.
    with TestClient(create_app(settings, with_ui=False), follow_redirects=False) as restored:
        restored.cookies.set('insight_session', cookie)
        assert restored.get('/api/session').status_code == 401
        response = restored.get('/login')
        assert response.status_code == 200
        assert 'name="password"' in response.text
        assert restored.get('/api/stats').status_code == 401


def test_a_restart_with_open_access_keeps_its_existing_session(
    open_client: TestClient, open_settings: Settings
) -> None:
    enter(open_client)
    with TestClient(create_app(open_settings, with_ui=False), follow_redirects=False) as restarted:
        restarted.cookies.set('insight_session', open_client.cookies['insight_session'])
        assert restarted.get('/api/session').status_code == 200


def test_open_access_sign_out_everywhere_revokes_sessions(open_client: TestClient, open_app: FastAPI) -> None:
    token = enter(open_client)
    with TestClient(open_app, follow_redirects=False) as other:
        enter(other)
        response = open_client.post('/logout', data={'csrf_token': token, 'everywhere': '1'})
        assert (response.status_code, response.headers['location']) == (303, '/login')
        assert other.get('/api/session').status_code == 401
        assert open_client.get('/api/session').status_code == 401
        # Revocation is real, while the explicit mode still lets a visitor start a new session.
        enter(other)
        assert other.get('/api/session').status_code == 200
