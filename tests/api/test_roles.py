"""Roles and the permission matrix through the real middleware (ADR 0046, TIP 3.4a).

People who sign in through the identity provider act as a viewer, an analyst or an admin. The built-in
operator (the password sign-in) is an admin; API keys act as viewers or analysts and never as admins. Every
route's permission comes from ``web/route_permissions.py``; a role below it gets ``403``.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from datetime import UTC, datetime

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import select
from tests.conftest import DEFAULT_DOCUMENT, add_person, sign_in_as

from insight import services
from insight.models import AuditEvent
from insight.permissions import MINIMUM_ROLE, ROLES, role_allows
from insight.ratelimit import Policy
from insight.web import boundary, callers
from insight.web.route_permissions import ROUTE_PERMISSIONS

REFUSAL = 'Your role does not allow this'


def concrete(template: str) -> str:
    """A request path for a route template (``x`` for every parameter: enough to reach the auth check)."""
    return re.sub(r'\{[^}]+\}', 'x', template)


def refused_by_role(response: object) -> bool:
    status = getattr(response, 'status_code', 0)
    if status != 403:
        return False
    try:
        return bool(response.json().get('detail') == REFUSAL)  # type: ignore[attr-defined]
    except ValueError:
        return False


def key(app: FastAPI, access: str) -> dict[str, str]:
    with app.state.session_factory.begin() as db:
        services.revoke_api_key(db)
        _, token = services.create_api_key(db, name='script', access=access)
    return {'Authorization': f'Bearer {token}'}


@pytest.fixture
def offline_syncs(monkeypatch: pytest.MonkeyPatch) -> None:
    """Allowed requests run their handlers; keep *sync all* from walking every source."""

    async def nothing(*_args: object, **_kwargs: object) -> list[object]:
        return []

    monkeypatch.setattr('insight.web.routes.sources.sync_all', nothing)


@pytest.mark.usefixtures('offline_syncs')
@pytest.mark.parametrize('role', ROLES)
def test_every_route_follows_the_matrix(
    app: FastAPI, client: TestClient, person: Callable[..., str], role: str
) -> None:
    """The full matrix, every role by every route: each role is refused exactly the routes above it."""
    person(app, client, role)
    wrong = []
    for (method, template), permission in sorted(ROUTE_PERMISSIONS.items()):
        response = client.request(method, concrete(template))
        if refused_by_role(response) == role_allows(role, permission):
            wrong.append(f'{method} {template} ({permission}): {response.status_code} {response.text[:80]}')
    assert wrong == []


def test_the_operator_is_an_admin(authed: TestClient) -> None:
    assert authed.get('/api/session').json()['role'] == 'admin'
    assert authed.put('/api/schedules/cisa-kev', json={'interval_minutes': 0}).status_code == 200


@pytest.mark.parametrize(
    ('access', 'role'), [('read', 'viewer'), ('read-feedback', 'viewer'), ('read-write', 'analyst')]
)
def test_api_keys_act_as_viewers_or_analysts(
    app: FastAPI, client: TestClient, access: str, role: str
) -> None:
    assert callers.Caller('api_key', 'k', access).role == role  # type: ignore[arg-type]
    headers = key(app, access)
    assert client.get('/api/stats', headers=headers).status_code == 200
    added = client.post('/api/documents', headers=headers, json=DEFAULT_DOCUMENT)
    assert (added.status_code == 200) is (role == 'analyst'), added.text


def test_no_api_key_ever_has_admin_permissions(app: FastAPI, client: TestClient) -> None:
    headers = key(app, 'read-write')
    admin_routes = [route for route, p in ROUTE_PERMISSIONS.items() if MINIMUM_ROLE[p] == 'admin']
    assert len(admin_routes) >= 5
    for method, template in admin_routes:
        response = client.request(method, concrete(template), headers=headers)
        assert response.status_code == 403, f'{method} {template}: {response.status_code}'


def test_a_viewer_reads_but_cannot_ingest_sync_or_schedule(
    app: FastAPI, client: TestClient, person: Callable[..., str]
) -> None:
    """TIP 3.4's first acceptance criterion."""
    person(app, client, 'viewer')
    assert client.get('/api/documents').status_code == 200
    for method, path, body in (
        ('POST', '/api/documents', DEFAULT_DOCUMENT),
        ('POST', '/api/sources/cisa-kev/sync', None),
        ('POST', '/api/sources/sync-all', None),
        ('PUT', '/api/schedules/cisa-kev', {'interval_minutes': 60}),
    ):
        assert refused_by_role(client.request(method, path, json=body)), path


def test_an_analyst_triages_but_cannot_change_settings(
    app: FastAPI, client: TestClient, person: Callable[..., str]
) -> None:
    """TIP 3.4's second criterion (keys and alert destinations are not on the API at all)."""
    user_id = person(app, client, 'analyst')
    added = client.post('/api/documents', json=DEFAULT_DOCUMENT)
    assert added.status_code == 200, added.text
    doc_id = added.json()['id']
    reviewed = client.post(f'/api/documents/{doc_id}/review', json={'status': 'reviewed'})
    assert reviewed.status_code == 200, reviewed.text
    assert refused_by_role(client.put('/api/schedules/cisa-kev', json={'interval_minutes': 60}))
    assert refused_by_role(client.post('/api/demo'))
    with app.state.session_factory() as db:
        actors = set(db.scalars(select(AuditEvent.actor).where(AuditEvent.object_id == doc_id)))
    assert actors == {f'user:{user_id}'}


def test_the_session_says_who_is_signed_in(
    app: FastAPI, client: TestClient, person: Callable[..., str]
) -> None:
    user_id = person(app, client, 'analyst')
    info = client.get('/api/session').json()
    assert (info['role'], info['actor']) == ('analyst', f'user:{user_id}')


@pytest.mark.parametrize('change', ['role', 'none', 'disable', 'remove', 'sign-out'])
def test_changing_a_person_ends_their_sessions_at_once(
    app: FastAPI, client: TestClient, person: Callable[..., str], change: str
) -> None:
    user_id = person(app, client, 'admin')
    assert client.get('/api/stats').status_code == 200
    with app.state.session_factory.begin() as db:
        services.set_actor(db, 'cli')
        if change in ('role', 'none'):
            ended = services.set_user_role(db, user_id, 'viewer' if change == 'role' else None)
        elif change == 'disable':
            ended = services.set_user_disabled(db, user_id, True)
        elif change == 'remove':
            ended = services.remove_user(db, user_id)
        else:
            ended = services.sign_out_user(db, user_id)
    assert ended == 1
    assert client.get('/api/stats').status_code == 401


def test_people_waiting_for_approval_or_disabled_have_no_access(app: FastAPI, client: TestClient) -> None:
    for user_id in (add_person(app, None), add_person(app, 'admin', disabled=True)):
        sign_in_as(app, client, user_id)
        assert client.get('/api/stats').status_code == 401
        assert client.get('/', follow_redirects=False).status_code in (303, 307, 404)
        login = client.get('/login')
        assert login.status_code == 200, 'the sign-in page shows: no redirect loop'


def test_a_role_from_an_unknown_value_grants_nothing(app: FastAPI, client: TestClient) -> None:
    sign_in_as(app, client, add_person(app, 'superuser'))
    assert client.get('/api/stats').status_code == 401


def test_each_person_has_their_own_rate_limit(
    app: FastAPI, person: Callable[..., str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(boundary, 'WRITE', Policy('write', 1, 60))
    with TestClient(app) as first, TestClient(app) as second:
        person(app, first, 'analyst')
        person(app, second, 'analyst')
        assert first.post('/api/rfis', json={'question': 'Who uses 203.0.113.9?'}).status_code == 201
        assert first.post('/api/rfis', json={'question': 'And 203.0.113.10?'}).status_code == 429
        assert second.post('/api/rfis', json={'question': 'Who uses 203.0.113.11?'}).status_code == 201


def test_signing_out_everywhere_ends_only_your_own_sessions(
    app: FastAPI, client: TestClient, person: Callable[..., str], login: Callable[..., str]
) -> None:
    with TestClient(app, follow_redirects=False) as operator:
        token = login(operator)
        person(app, client, 'analyst')
        assert client.get('/api/stats').status_code == 200
        response = operator.post('/logout', data={'csrf_token': token, 'everywhere': '1'})
        assert response.status_code == 303
        assert operator.get('/api/stats').status_code == 401
        assert client.get('/api/stats').status_code == 200, "the operator ended nobody else's session"
        csrf = client.headers['X-CSRF-Token']
        assert client.post('/logout', data={'csrf_token': csrf, 'everywhere': '1'}).status_code == 303
        assert client.get('/api/stats').status_code == 401
    with app.state.session_factory() as db:
        events = db.scalars(select(AuditEvent).where(AuditEvent.action == 'session.end_all')).all()
        assert {(e.actor, e.detail) for e in events} == {
            ('operator', '1 session(s) ended'),
            (events[-1].actor, '1 session(s) ended'),
        }
        assert any(e.actor.startswith('user:') for e in events)
        assert services.count_operator_sessions(db, at=datetime.now(UTC)) == 0
