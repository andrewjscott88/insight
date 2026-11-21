"""Authentication, CSRF, session rotation/revocation and login throttling."""

from __future__ import annotations

import asyncio
import base64
import contextlib
import dataclasses
import hashlib
import hmac
import json
import logging
import re
import time
from collections.abc import Callable, Iterator
from datetime import UTC, datetime
from typing import Any

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import select

from insight import __version__, main, services
from insight.config import Settings
from insight.models import AuditEvent, Document, OperatorSession

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
    ('GET', '/api/iocs/stix'),
    ('GET', '/api/iocs/blocklist'),
    ('GET', '/api/entities'),
    ('GET', '/api/entities/x'),
    ('GET', '/api/stats'),
    ('GET', '/api/brief'),
    ('GET', '/api/schedules'),
    ('GET', '/api/jobs'),
    ('GET', '/api/sources'),
    ('GET', '/api/audit'),
    ('GET', '/api/watch-terms'),
    ('POST', '/api/import/stix'),
    ('POST', '/api/documents'),
    ('POST', '/api/documents/x/review'),
    ('POST', '/api/documents/x/notes'),
    ('POST', '/api/observations/x/review'),
    ('POST', '/api/entities/x/assessment'),
    ('GET', '/api/attack/techniques'),
    ('GET', '/api/attack/summary'),
    ('GET', '/api/attack/techniques/x/documents'),
    ('GET', '/api/attack/navigator'),
    ('GET', '/api/landscape'),
    ('GET', '/api/landscape/briefing'),
    ('GET', '/api/documents/x/techniques'),
    ('POST', '/api/documents/x/techniques'),
    ('DELETE', '/api/documents/x/techniques/T1486'),
    ('POST', '/api/demo'),
    ('POST', '/api/sources/cisa-kev/sync'),
    ('POST', '/api/sources/sync-all'),
    ('PUT', '/api/schedules/cisa-kev'),
    ('POST', '/api/enrichment/epss/CVE-2024-12345'),
    ('GET', '/api/cves/CVE-2024-12345/scores'),
    ('GET', '/api/cves'),
    ('GET', '/api/industries'),
    ('GET', '/api/industries/government/actors'),
    ('GET', '/api/actors'),
    ('POST', '/api/actors'),
    ('GET', '/api/actors/G0016'),
    ('POST', '/api/actors/G0016/documents'),
    ('DELETE', '/api/actors/G0016/documents/x'),
    ('POST', '/api/actors/G0016/industries'),
    ('GET', '/api/actors/G0016/guide'),
    ('GET', '/api/actors/G0016/navigator'),
    ('GET', '/api/actors/G0016/sweep'),
    ('GET', '/api/actors/G0016/hunts'),
    ('POST', '/api/actors/G0016/hunts'),
    ('GET', '/api/hunts/x'),
    ('PUT', '/api/hunts/x'),
    ('PUT', '/api/hunts/x/checks/T1486'),
    ('GET', '/api/rules'),
    ('POST', '/api/rules'),
    ('GET', '/api/rules/x'),
    ('GET', '/api/rules/x/export'),
    ('DELETE', '/api/rules/x'),
    ('POST', '/api/rules/x/links'),
    ('DELETE', '/api/rules/x/links'),
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


def stored_sessions(app: FastAPI) -> int:
    with app.state.session_factory() as db:
        return services.count_operator_sessions(db, at=datetime.now(UTC))


def session_id(client: TestClient) -> str:
    """The session ID inside the signed cookie (its payload is base64 JSON before the signature)."""
    payload = client.cookies['insight_session'].split('.')[0]
    sid: str = json.loads(base64.b64decode(payload + '=' * (-len(payload) % 4)))['sid']
    return sid


def test_second_login_revokes_previous_session_id(
    app: FastAPI, client: TestClient, login: Callable[..., str]
) -> None:
    login(client)
    assert stored_sessions(app) == 1
    client.cookies.clear()
    login(client)  # a different browser keeps its own session
    assert stored_sessions(app) == 2


@pytest.fixture
def restarted(settings: Settings) -> Callable[..., contextlib.AbstractContextManager[TestClient]]:
    """``with restarted(client, **changes) as again``: a new app on the same database, with this cookie."""

    @contextlib.contextmanager
    def restart(client: TestClient, **changes: Any) -> Iterator[TestClient]:
        with TestClient(main.create_app(dataclasses.replace(settings, **changes), with_ui=False)) as again:
            again.cookies.set('insight_session', client.cookies['insight_session'])
            yield again

    return restart


def test_a_restart_keeps_the_operator_signed_in(
    authed: TestClient, restarted: Callable[..., contextlib.AbstractContextManager[TestClient]]
) -> None:
    """Review B4: sessions were held in memory, so every restart or upgrade signed the operator out."""
    with restarted(authed) as again:
        assert again.get('/api/session').status_code == 200


@pytest.mark.parametrize(
    'changes', [{'password': 'a-new-long-password'}, {'mfa': True}], ids=['password', 'mfa']
)
def test_new_credentials_sign_everyone_out(
    authed: TestClient,
    restarted: Callable[..., contextlib.AbstractContextManager[TestClient]],
    changes: dict[str, Any],
) -> None:
    """A changed password or MFA setting still ends every session, as the restart it needs always did."""
    with restarted(authed, **changes) as again:
        assert again.get('/api/session').status_code == 401


def test_sign_out_everywhere_ends_every_session(
    app: FastAPI, client: TestClient, login: Callable[..., str], caplog: pytest.LogCaptureFixture
) -> None:
    token = login(client)
    with TestClient(app, follow_redirects=False) as other_browser:
        login(other_browser)
        assert stored_sessions(app) == 2
        assert 'Sign out everywhere' in client.get('/logout').text
        with caplog.at_level(logging.INFO, logger='insight.auth'):
            response = client.post('/logout', data={'csrf_token': token, 'everywhere': '1'})
        assert (response.status_code, response.headers['location']) == (303, '/login')
        assert other_browser.get('/api/session').status_code == 401
    assert client.get('/api/session').status_code == 401
    assert stored_sessions(app) == 0
    assert 'Operator signed out everywhere: 2 session(s) ended' in caplog.text
    with app.state.session_factory() as db:
        event = db.scalars(select(AuditEvent).where(AuditEvent.action == 'session.end_all')).one()
        assert (event.actor, event.detail) == ('operator', '2 session(s) ended')


def test_the_database_cannot_sign_anyone_in(app: FastAPI, authed: TestClient) -> None:
    """Only a keyed hash of the session ID is stored, so a copy of the database cannot sign anyone in."""
    sid = session_id(authed)
    with app.state.session_factory() as db:
        (row,) = db.scalars(select(OperatorSession)).all()
    assert sid not in (row.id_hash, row.created_at, row.expires_at)
    assert row.id_hash != hashlib.sha256(sid.encode()).hexdigest()


def test_expired_session_is_rejected(
    app: FastAPI, authed: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    real_time = time.time
    monkeypatch.setattr(time, 'time', lambda: real_time() + main.SESSION_TTL_SECONDS + 1)
    assert authed.get('/api/session').status_code == 401


def test_the_backstop_refuses_wrong_passwords_then_recovers(
    app: FastAPI, client: TestClient, csrf_token_from: Callable[[str], str], monkeypatch: pytest.MonkeyPatch
) -> None:
    token = csrf_token_from(client.get('/login').text)
    bad = {'csrf_token': token, 'password': 'bad'}
    for _ in range(main.LOGIN_MAX_FAILURES):
        assert client.post('/login', data=bad).status_code == 401
    refused = client.post('/login', data=bad)
    assert (refused.status_code, refused.json()) == (
        429,
        {'detail': 'Too many login attempts; wait one minute'},
    )
    assert len(app.state.failures) == main.LOGIN_MAX_FAILURES  # bounded while the flood goes on
    real_time = time.time
    monkeypatch.setattr(time, 'time', lambda: real_time() + main.LOGIN_WINDOW_SECONDS + 1)
    assert client.post('/login', data=bad).status_code == 401


def test_regression_m1_a_flood_of_failures_cannot_lock_the_operator_out(
    app: FastAPI, csrf_token_from: Callable[[str], str]
) -> None:
    """Review M1: 30 wrong passwords from one client made the right password from another client get 429."""
    attacker = TestClient(app, follow_redirects=False)
    token = csrf_token_from(attacker.get('/login').text)
    for _ in range(main.LOGIN_MAX_FAILURES + 5):
        assert attacker.post('/login', data={'csrf_token': token, 'password': 'bad'}).status_code in (
            401,
            429,
        )
    operator = TestClient(app, follow_redirects=False)
    good = {'csrf_token': csrf_token_from(operator.get('/login').text), 'password': 'longtestpassword'}
    response = operator.post('/login', data=good)
    assert (response.status_code, response.headers['location']) == (303, '/')


def test_regression_l4_the_demo_stays_within_the_instance_tlp_limit(
    settings: Settings, login: Callable[..., str]
) -> None:
    """Review L4: the demo's AMBER+STRICT report was stored even with INSIGHT_MAX_TLP=GREEN."""
    app = main.create_app(dataclasses.replace(settings, max_tlp='GREEN'), with_ui=False)
    with TestClient(app, follow_redirects=False) as client:
        login(client)
        csrf = client.get('/api/session').json()['csrf_token']
        assert client.post('/api/demo', headers={'X-CSRF-Token': csrf}).json() == {'created': 2}
        with app.state.session_factory() as db:
            labels = set(db.scalars(select(Document.tlp)))
    assert labels == {'CLEAR', 'GREEN'}


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


async def test_every_failure_waits_but_the_operator_never_waits_behind_them(settings: Settings) -> None:
    """Review M1: the delay used to run while the sign-in lock was held, so the operator's attempt queued
    behind every pending bad guess. Each failure still waits; a right password answers at once."""
    delay = 0.5
    app = main.create_app(dataclasses.replace(settings, failed_login_delay=delay), with_ui=False)
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url='http://testserver') as client,
    ):
        token = csrf_from((await client.get('/login')).text)

        async def timed(password: str) -> tuple[int, float]:
            started = time.perf_counter()
            response = await client.post('/login', data={'csrf_token': token, 'password': password})
            return response.status_code, time.perf_counter() - started

        async def operator() -> tuple[int, float]:
            await asyncio.sleep(0.05)  # after the guesses have started their delays
            return await timed('longtestpassword')

        results = await asyncio.gather(*(timed(f'bad{i}') for i in range(5)), operator())
    *guesses, (status, waited) = results
    assert all(code == 401 and took >= delay * 0.9 for code, took in guesses)
    assert status == 303
    assert waited < delay  # not behind five delays, nor one


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


@pytest.mark.parametrize(
    ('supplied', 'same'),
    [
        ('longtestpassword', True),
        ('longtestpasswor', False),
        ('', False),
        ('longtestpassword!', False),
        ('ü', False),
        ('longtestpassword\0', False),
        ('longtestpassword' + 'x' * 400, False),
    ],
)
def test_regression_n4_the_password_check_compares_fixed_length_digests(
    supplied: str, same: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Review N4: compare_digest on the raw values leaked the password's length through timing; the
    comparison now always sees two values of one fixed width, whatever the guess's length."""
    from insight.web import auth

    lengths: list[tuple[int, int]] = []
    real = hmac.compare_digest

    def spy(a: bytes, b: bytes) -> bool:
        lengths.append((len(a), len(b)))
        return bool(real(a, b))

    monkeypatch.setattr('insight.web.auth.hmac.compare_digest', spy)
    assert auth.same_secret(supplied, 'longtestpassword') is same
    assert lengths == [(auth.SECRET_WIDTH, auth.SECRET_WIDTH)]


def test_regression_n4_a_long_stored_secret_sets_the_width() -> None:
    """A password longer than SECRET_WIDTH still compares correctly, at its own width."""
    from insight.web import auth

    secret = 'p' * (auth.SECRET_WIDTH + 10)
    assert auth.same_secret(secret, secret) is True
    assert auth.same_secret(secret[:-1], secret) is False
    assert auth.same_secret(secret + 'p', secret) is False
