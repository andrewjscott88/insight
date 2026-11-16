"""Authentication, CSRF, session rotation/revocation and login throttling."""

from __future__ import annotations

import asyncio
import dataclasses
import logging
import re
import time
from collections.abc import Callable

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from insight import __version__, main
from insight.config import Settings

CSRF = re.compile(r'name="csrf_token"[^>]*value="([^"]+)"')


def csrf_from(html: str) -> str:
    match = CSRF.search(html)
    assert match
    return match.group(1)


PROTECTED = [
    ('GET', '/api/session'),
    ('GET', '/api/documents'),
    ('GET', '/api/documents/x'),
    ('GET', '/api/documents/x/export'),
    ('GET', '/api/iocs/export'),
    ('GET', '/api/entities'),
    ('GET', '/api/entities/x'),
    ('GET', '/api/stats'),
    ('GET', '/api/sources'),
    ('GET', '/api/audit'),
    ('GET', '/api/watch-terms'),
    ('POST', '/api/documents'),
    ('POST', '/api/documents/x/review'),
    ('POST', '/api/documents/x/notes'),
    ('POST', '/api/observations/x/review'),
    ('POST', '/api/demo'),
    ('POST', '/api/sources/cisa-kev/sync'),
    ('POST', '/api/enrichment/epss/CVE-2024-12345'),
]


@pytest.mark.parametrize(('method', 'path'), PROTECTED)
def test_every_api_route_requires_authentication(client: TestClient, method: str, path: str) -> None:
    assert client.request(method, path).status_code == 401


def test_health_is_public(client: TestClient) -> None:
    response = client.get('/health')
    assert response.status_code == 200
    assert response.json() == {'status': 'ok', 'version': __version__}


def test_login_page_sets_csrf_and_redirects_when_signed_in(
    client: TestClient, login: Callable[..., str]
) -> None:
    page = client.get('/login')
    assert page.status_code == 200
    assert 'csrf_token' in page.text
    login(client)
    redirect = client.get('/login')
    assert (redirect.status_code, redirect.headers['location']) == (303, '/')


def test_login_requires_matching_csrf(client: TestClient) -> None:
    client.get('/login')
    assert client.post('/login', data={'password': 'longtestpassword'}).status_code == 403
    assert (
        client.post('/login', data={'csrf_token': 'wrong', 'password': 'longtestpassword'}).status_code == 403
    )


@pytest.mark.parametrize('password', ['wrong', 'incorrect-password'])
def test_forged_sentinel_csrf_is_rejected(client: TestClient, password: str) -> None:
    """Regression: with no session, the literal token 'missing' matched the fallback default.

    A correct password then logged in without a real CSRF token, and a wrong one crashed with KeyError (500).
    """
    response = client.post('/login', data={'csrf_token': 'missing', 'password': password})
    assert response.status_code == 403
    response = client.post('/login', data={'csrf_token': 'missing', 'password': 'longtestpassword'})
    assert response.status_code == 403


def test_wrong_password_renders_error_and_keeps_form_usable(
    client: TestClient, csrf_token_from: Callable[[str], str]
) -> None:
    token = csrf_token_from(client.get('/login').text)
    response = client.post('/login', data={'csrf_token': token, 'password': 'nope'})
    assert response.status_code == 401
    assert 'Incorrect password.' in response.text
    assert csrf_token_from(response.text) == token


def test_login_rotates_session_and_csrf(client: TestClient, csrf_token_from: Callable[[str], str]) -> None:
    pre_login_token = csrf_token_from(client.get('/login').text)
    pre_login_cookie = client.cookies.get('insight_session')
    client.post('/login', data={'csrf_token': pre_login_token, 'password': 'longtestpassword'})
    api_token = client.get('/api/session').json()['csrf_token']
    assert api_token != pre_login_token
    assert client.cookies.get('insight_session') != pre_login_cookie


def test_writes_require_the_csrf_header(authed: TestClient) -> None:
    for token in ['', 'wrong']:
        assert authed.post('/api/demo', headers={'X-CSRF-Token': token}).status_code == 403
    assert authed.post('/api/demo').status_code == 200


def test_logout_requires_csrf_and_revokes_stolen_cookies(authed: TestClient) -> None:
    token = authed.headers['X-CSRF-Token']
    stolen_cookie = authed.cookies.get('insight_session')
    assert stolen_cookie
    assert authed.post('/logout', data={}).status_code == 403
    assert authed.get('/api/session').status_code == 200
    response = authed.post('/logout', data={'csrf_token': token})
    assert (response.status_code, response.headers['location']) == (303, '/login')
    assert authed.get('/api/session').status_code == 401
    # Replaying the pre-logout cookie must not resurrect the session (server-side revocation).
    authed.cookies.clear()
    authed.cookies.set('insight_session', stolen_cookie)
    assert authed.get('/api/session').status_code == 401


def test_logout_page(client: TestClient, login: Callable[..., str]) -> None:
    assert client.get('/logout').headers['location'] == '/login'
    login(client)
    page = client.get('/logout')
    assert page.status_code == 200
    assert 'Sign out of Insight?' in page.text


def test_second_login_revokes_previous_session_id(
    app: FastAPI, client: TestClient, login: Callable[..., str]
) -> None:
    login(client)
    (first_sid,) = app.state.active_sessions
    client.cookies.clear()
    login(client)
    assert first_sid in app.state.active_sessions  # a different browser keeps its own session
    assert len(app.state.active_sessions) == 2


def test_expired_session_is_rejected(
    app: FastAPI, authed: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    real_time = time.time
    monkeypatch.setattr(time, 'time', lambda: real_time() + main.SESSION_TTL_SECONDS + 1)
    assert authed.get('/api/session').status_code == 401


def test_failed_logins_are_throttled_then_recover(
    client: TestClient, csrf_token_from: Callable[[str], str], monkeypatch: pytest.MonkeyPatch
) -> None:
    token = csrf_token_from(client.get('/login').text)
    for _ in range(main.LOGIN_MAX_FAILURES):
        assert client.post('/login', data={'csrf_token': token, 'password': 'bad'}).status_code == 401
    # Even the correct password is refused while throttled.
    good = {'csrf_token': token, 'password': 'longtestpassword'}
    assert client.post('/login', data=good).status_code == 429
    real_time = time.time
    monkeypatch.setattr(time, 'time', lambda: real_time() + main.LOGIN_WINDOW_SECONDS + 1)
    assert client.post('/login', data=good).status_code == 303


def test_login_form_field_limit(client: TestClient, csrf_token_from: Callable[[str], str]) -> None:
    token = csrf_token_from(client.get('/login').text)
    fields = {'csrf_token': token, 'password': 'x', **{f'f{i}': 'x' for i in range(10)}}
    assert client.post('/login', data=fields).status_code == 400


# --------------------------------------------------------------------------- decision 2: delay, not lockout


def test_operator_is_not_locked_out_by_a_handful_of_failures(
    client: TestClient, csrf_token_from: Callable[[str], str]
) -> None:
    """Regression: 10 failures (e.g. from another local process) locked the operator out for a minute."""
    token = csrf_token_from(client.get('/login').text)
    for _ in range(15):
        assert client.post('/login', data={'csrf_token': token, 'password': 'bad'}).status_code == 401
    good = {'csrf_token': token, 'password': 'longtestpassword'}
    assert client.post('/login', data=good).status_code == 303


async def test_failed_sign_ins_are_delayed_and_checked_one_at_a_time(settings: Settings) -> None:
    delay = 0.2
    app = main.create_app(dataclasses.replace(settings, failed_login_delay=delay), with_ui=False)
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url='http://testserver') as client,
    ):
        token = csrf_from((await client.get('/login')).text)
        started = time.perf_counter()
        responses = await asyncio.gather(
            *(client.post('/login', data={'csrf_token': token, 'password': f'bad{i}'}) for i in range(3))
        )
        elapsed = time.perf_counter() - started
    assert [r.status_code for r in responses] == [401, 401, 401]
    # Serialised: three concurrent guesses take at least three delays, not one.
    assert elapsed >= 3 * delay * 0.9


def test_failed_sign_ins_are_logged_without_the_password(
    client: TestClient, csrf_token_from: Callable[[str], str], caplog: pytest.LogCaptureFixture
) -> None:
    token = csrf_token_from(client.get('/login').text)
    with caplog.at_level(logging.INFO, logger='insight.auth'):
        client.post('/login', data={'csrf_token': token, 'password': 'hunter2-secret-guess'})
        client.post('/login', data={'csrf_token': token, 'password': 'longtestpassword'})
    messages = [r.getMessage() for r in caplog.records if r.name == 'insight.auth']
    assert any('Failed sign-in attempt' in m for m in messages)
    assert any('Operator signed in' in m for m in messages)
    assert not any('hunter2' in m or 'longtestpassword' in m for m in messages)
