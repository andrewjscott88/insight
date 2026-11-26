"""Sign-in through the identity provider, end to end through the real middleware (ADR 0046, TIP 3.4b)."""

from __future__ import annotations

import re
from collections.abc import Iterator
from typing import Any
from urllib.parse import parse_qs, urlsplit

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import select
from tests.conftest import PASSWORD, SECRET
from tests.oidc_fixtures import FakeProvider, oidc_env

from insight import services
from insight.config import Settings
from insight.main import create_app
from insight.models import AuditEvent, User
from insight.oidc_settings import OidcSettings


@pytest.fixture
def provider(monkeypatch: pytest.MonkeyPatch) -> FakeProvider:
    fake = FakeProvider()
    fake.install(monkeypatch)
    return fake


def make_app(database_url: str, **env: str) -> FastAPI:
    oidc = OidcSettings.from_env(oidc_env(**env))
    settings = Settings(
        database_url=database_url,
        password=PASSWORD,
        session_secret=SECRET,
        failed_login_delay=0,
        oidc=oidc,
        allowed_hosts=('testserver', 'insight.example.org'),
    )
    return create_app(settings, with_ui=False)


@pytest.fixture
def sso(database_url: str) -> Iterator[TestClient]:
    with TestClient(make_app(database_url), follow_redirects=False) as client:
        yield client


def sign_in(client: TestClient, provider: FakeProvider) -> Any:
    """Go to the provider and come back the way a browser does; returns the last response."""
    started = client.get('/login/sso')
    assert started.status_code == 303, started.text
    query = {k: v[0] for k, v in parse_qs(urlsplit(started.headers['location']).query).items()}
    provider.nonce = query['nonce']
    carried = client.get('/login/sso/callback', params={'code': 'the-code', 'state': query['state']})
    assert carried.status_code == 200
    fields = dict(re.findall(r'name="(code|state)" value="([^"]*)"', carried.text))
    return client.post('/login/sso/callback', data=fields)


def people(app: FastAPI) -> list[User]:
    with app.state.session_factory() as db:
        return list(db.scalars(select(User)))


def test_a_new_person_signs_in_and_waits_for_approval(sso: TestClient, provider: FakeProvider) -> None:
    app: FastAPI = sso.app  # type: ignore[assignment]
    login = sso.get('/login')
    assert 'Sign in with your organisation' in login.text
    finished = sign_in(sso, provider)
    assert (finished.status_code, finished.headers['location']) == (303, '/')
    (person,) = people(app)
    assert (person.subject, person.email, person.display_name, person.role) == (
        'subject-1',
        'ann@example.org',
        'Ann Analyst',
        None,
    )
    assert sso.get('/api/stats').status_code == 401, 'waiting people have no access'
    assert 'an administrator has not given you a role yet' in sso.get('/login').text
    with app.state.session_factory.begin() as db:
        services.set_actor(db, 'cli')
        services.set_user_role(db, person.id, 'analyst')  # ends the session
    assert sign_in(sso, provider).status_code == 303
    assert sso.get('/api/session').json()['role'] == 'analyst'
    with app.state.session_factory() as db:
        added = db.scalars(select(AuditEvent).where(AuditEvent.action == 'user.add')).one()
    assert (added.actor, added.object_id) == (f'user:{person.id}', person.id)


def test_provider_groups_give_the_role_at_every_sign_in(database_url: str, provider: FakeProvider) -> None:
    app = make_app(
        database_url, INSIGHT_OIDC_ANALYST_GROUPS='insight-analysts', INSIGHT_OIDC_ADMIN_GROUPS='ops'
    )
    with TestClient(app, follow_redirects=False) as client:
        sign_in(client, provider)
        assert client.get('/api/session').json()['role'] == 'analyst'
        provider.groups = ['ops']
        sign_in(client, provider)
        assert client.get('/api/session').json()['role'] == 'admin'
        provider.groups = []
        sign_in(client, provider)
        assert client.get('/api/stats').status_code == 401, 'leaving the groups takes the role away'
    (person,) = people(app)
    assert (person.role, person.role_from_groups) == (None, False)


def test_a_disabled_person_is_refused(sso: TestClient, provider: FakeProvider) -> None:
    app: FastAPI = sso.app  # type: ignore[assignment]
    sign_in(sso, provider)
    (person,) = people(app)
    with app.state.session_factory.begin() as db:
        services.set_user_role(db, person.id, 'admin')
        services.set_user_disabled(db, person.id, True)
    refused = sign_in(sso, provider)
    assert refused.status_code == 403
    assert 'Your account is turned off' in refused.text
    assert sso.get('/api/stats').status_code == 401


def test_the_callback_needs_this_browsers_fresh_state_once(sso: TestClient, provider: FakeProvider) -> None:
    started = sso.get('/login/sso')
    state = parse_qs(urlsplit(started.headers['location']).query)['state'][0]
    provider.nonce = parse_qs(urlsplit(started.headers['location']).query)['nonce'][0]
    assert sso.post('/login/sso/callback', data={'code': 'c', 'state': 'forged'}).status_code == 400
    assert sso.post('/login/sso/callback', data={'code': 'c', 'state': state}).status_code == 400, 'used once'
    assert not any(r.url.path.endswith('/token') for r in provider.requests), 'nothing was exchanged'
    with TestClient(sso.app, follow_redirects=False) as other_browser:
        assert (
            other_browser.post('/login/sso/callback', data={'code': 'c', 'state': state}).status_code == 400
        )


def test_failed_callbacks_are_throttled_before_the_provider_is_asked(
    sso: TestClient, provider: FakeProvider
) -> None:
    for _ in range(10):
        assert sso.post('/login/sso/callback', data={'code': 'c', 'state': 'forged'}).status_code == 400
    started = sso.get('/login/sso')
    state = parse_qs(urlsplit(started.headers['location']).query)['state'][0]
    refused = sso.post('/login/sso/callback', data={'code': 'c', 'state': state})
    assert refused.status_code == 429
    assert not any(r.url.path.endswith('/token') for r in provider.requests)


def test_a_provider_error_is_not_a_sign_in(sso: TestClient, provider: FakeProvider) -> None:
    started = sso.get('/login/sso')
    state = parse_qs(urlsplit(started.headers['location']).query)['state'][0]
    refused = sso.post('/login/sso/callback', data={'state': state, 'error': 'access_denied'})
    assert refused.status_code == 400
    assert sso.get('/api/stats').status_code == 401


def test_a_bad_token_is_refused(sso: TestClient, provider: FakeProvider) -> None:
    provider.on_token = lambda p: 'not.a.token'
    assert sign_in(sso, provider).status_code == 400
    assert people(sso.app) == []  # type: ignore[arg-type]


def test_sso_only_turns_password_sign_in_off(database_url: str, provider: FakeProvider) -> None:
    with TestClient(make_app(database_url, INSIGHT_SSO_ONLY='on'), follow_redirects=False) as client:
        page = client.get('/login')
        assert 'Sign in with your organisation' in page.text
        assert 'name="password"' not in page.text
        token = re.search(r'name="csrf_token" value="([^"]+)"', page.text)
        assert token is None
        assert client.post('/login', data={'csrf_token': 'x', 'password': PASSWORD}).status_code == 403


def test_turning_password_sign_in_off_ends_every_session(database_url: str, provider: FakeProvider) -> None:
    with TestClient(make_app(database_url), follow_redirects=False) as before:
        page = before.get('/login')
        csrf = re.search(r'name="csrf_token" value="([^"]+)"', page.text)
        assert csrf is not None
        assert (
            before.post('/login', data={'csrf_token': csrf.group(1), 'password': PASSWORD}).status_code == 303
        )
        assert before.get('/api/stats').status_code == 200
        cookies = dict(before.cookies)
    with TestClient(make_app(database_url, INSIGHT_SSO_ONLY='on'), follow_redirects=False) as after:
        after.cookies.update(cookies)
        assert after.get('/api/stats').status_code == 401


def test_without_a_provider_the_sso_routes_do_not_exist(client: TestClient) -> None:
    assert client.get('/login/sso').status_code == 404
    assert client.get('/login/sso/callback').status_code == 404
    assert client.post('/login/sso/callback', data={}).status_code == 404
    assert 'Sign in with your organisation' not in client.get('/login').text


def test_an_unreachable_provider_shows_the_sign_in_page(sso: TestClient, provider: FakeProvider) -> None:
    provider.discovery['issuer'] = 'https://elsewhere.example.org'
    refused = sso.get('/login/sso')
    assert refused.status_code == 502
    assert 'did not work' in refused.text
