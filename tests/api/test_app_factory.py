"""The application factory's building blocks, tested without the full middleware stack.

``create_app`` composes small, importable pieces: a session checker, the auth dependency, query parsing,
session rotation and one route-registration function per area. Each can be exercised on its own here; the
full stack (middleware order, real sign-in) stays covered by ``test_auth.py`` and ``test_middleware.py``.
"""

from __future__ import annotations

import time
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any

import pytest
from fastapi import FastAPI, HTTPException, Request
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker

from insight import main, services
from insight.models import OperatorSession
from insight.permissions import Permission
from insight.schemas import DocumentInput
from insight.services import ingest
from insight.web.routes import workspace


def matched(path: str) -> SimpleNamespace:
    """What routing leaves in the scope for ``require_auth``: the matched route and its path template."""
    return SimpleNamespace(path=path)


def request(
    method: str = 'GET', session: dict[str, Any] | None = None, csrf: str | None = None, path: str = ''
) -> Request:
    headers = [(b'x-csrf-token', csrf.encode())] if csrf is not None else []
    path = path or ('/api/stats' if method == 'GET' else '/api/documents')
    return Request(
        {
            'type': 'http',
            'method': method,
            'path': path,
            'headers': headers,
            'session': session or {},
            'route': matched(path),
        }
    )


BINDING = 'test-binding'


@pytest.fixture
def session_app(session_factory: sessionmaker[Session]) -> FastAPI:
    app = FastAPI()
    app.state.session_factory = session_factory
    app.state.session_binding = BINDING
    return app


def stored_session(app: FastAPI, *, at: float) -> str:
    with app.state.session_factory.begin() as db:
        return services.start_operator_session(db, binding=BINDING, at=datetime.fromtimestamp(at, UTC))


# --------------------------------------------------------------------------- sessions and auth


def test_session_checker_requires_a_live_stored_session(session_app: FastAPI) -> None:
    now = time.time()
    live = stored_session(session_app, at=now)
    expired = stored_session(session_app, at=now - main.SESSION_TTL_SECONDS - 1)
    authenticated = main.session_checker(session_app)
    assert authenticated({'authenticated': True, 'sid': live})
    assert not authenticated({'authenticated': True, 'sid': expired})
    assert not authenticated({'authenticated': True, 'sid': 'unknown'})
    assert not authenticated({'authenticated': False, 'sid': live})  # signed cookie alone is not enough
    assert not authenticated({'authenticated': True, 'sid': ['not', 'a', 'string']})
    assert not authenticated({})
    session_app.state.session_binding = 'after a password change'
    assert not authenticated({'authenticated': True, 'sid': live})


@pytest.mark.parametrize(
    ('method', 'signed_in', 'csrf', 'status'),
    [
        ('GET', False, None, 401),
        ('GET', True, None, None),  # reads need no CSRF header
        ('POST', True, None, 403),
        ('POST', True, 'wrong', 403),
        ('POST', True, 'token', None),
    ],
)
def test_auth_dependency(method: str, signed_in: bool, csrf: str | None, status: int | None) -> None:
    require_auth = main.auth_dependency(lambda _session: main.SESSION_CALLER if signed_in else None)
    incoming = request(method, {'csrf': 'token'}, csrf)
    if status is None:
        require_auth(incoming)
        return
    with pytest.raises(HTTPException) as exc:
        require_auth(incoming)
    assert exc.value.status_code == status


@pytest.mark.parametrize(
    ('method', 'path', 'policy'),
    [
        ('GET', '/api/documents', 'read'),
        ('HEAD', '/api/stats', 'read'),
        ('GET', '/api/documents/x/export', 'read'),
        ('GET', '/api/iocs/export', 'ioc-export'),
        ('POST', '/api/documents', 'write'),
        ('POST', '/api/sources/cisa-kev/sync', 'write'),
    ],
)
def test_rate_limit_policy(method: str, path: str, policy: str) -> None:
    assert main.rate_limit_policy(method, path).name == policy


def keyed_request(method: str, token: str, path: str = '/api/stats') -> Request:
    headers = [(b'authorization', f'Bearer {token}'.encode())]
    scope = {'type': 'http', 'method': method, 'path': path, 'headers': headers, 'session': {}}
    return Request({**scope, 'route': matched(path)})


@pytest.mark.parametrize(
    ('method', 'access', 'path', 'status'),
    [
        ('GET', 'read', '/api/stats', None),
        ('POST', 'read', '/api/documents', 403),
        ('POST', 'read-write', '/api/documents', None),  # no CSRF token needed with a key
        ('GET', 'read-write', '/api/session', 403),
    ],
)
def test_auth_dependency_with_api_keys(method: str, access: str, path: str, status: int | None) -> None:
    caller = main.Caller('api_key', 'abc', 'read-write' if access == 'read-write' else 'read')

    def verify(token: str) -> tuple[main.Caller | None, str]:
        return (caller, 'ok') if token == 'good' else (None, 'unknown')

    require_auth = main.auth_dependency(lambda _session: None, verify_key=verify)
    incoming = keyed_request(method, 'good', path)
    if status is None:
        require_auth(incoming)
        assert incoming.state.caller == caller
    else:
        with pytest.raises(HTTPException) as exc:
            require_auth(incoming)
        assert exc.value.status_code == status
    with pytest.raises(HTTPException) as bad:
        require_auth(keyed_request(method, 'bad', path))
    assert bad.value.status_code == 401


def test_api_keys_are_refused_when_no_verifier_is_configured() -> None:
    require_auth = main.auth_dependency(lambda _session: main.SESSION_CALLER)
    with pytest.raises(HTTPException) as exc:
        require_auth(keyed_request('GET', 'anything'))
    assert exc.value.status_code == 401


def test_caller_limit_keys_are_distinct() -> None:
    assert main.SESSION_CALLER.limit_key == 'session'
    assert main.Caller('api_key', 'abc').limit_key == 'key:abc'
    assert main.Caller('session', user_id='u1', role='viewer').limit_key == 'user:u1'
    assert main.Caller('session', user_id='u2', role='viewer').limit_key == 'user:u2'


def test_a_callers_role_follows_from_who_it_is() -> None:
    """Only a person's role is taken as given: a key is never an admin, the operator always is."""
    assert main.Caller('api_key', 'k', 'read-write', role='admin').role == 'analyst'
    assert main.Caller('api_key', 'k', 'read', role='admin').role == 'viewer'
    assert main.Caller('session', role='viewer').role == 'admin'
    assert main.Caller('session', user_id='u1', role='viewer').role == 'viewer'
    nobody = main.Caller('session', user_id='u1')
    assert nobody.role is None
    assert not any(nobody.may(permission) for permission in Permission)


def test_callers_are_named_in_the_audit_log() -> None:
    assert main.SESSION_CALLER.actor == 'operator'
    assert main.Caller('api_key', 'abc').actor == 'api-key:abc'
    assert main.Caller('session', user_id='u1', role='analyst').actor == 'user:u1'


@pytest.mark.parametrize(
    ('role', 'method', 'path', 'allowed'),
    [
        ('viewer', 'GET', '/api/stats', True),
        ('viewer', 'POST', '/api/documents', False),
        ('analyst', 'POST', '/api/documents', True),
        ('analyst', 'PUT', '/api/schedules/{key}', False),
        ('admin', 'PUT', '/api/schedules/{key}', True),
    ],
)
def test_auth_dependency_checks_the_role(role: str, method: str, path: str, allowed: bool) -> None:
    person = main.Caller('session', user_id='u1', role=role)  # type: ignore[arg-type]
    require_auth = main.auth_dependency(lambda _session: person)
    incoming = request(method, {'csrf': 'token'}, 'token', path=path)
    if allowed:
        require_auth(incoming)
        assert incoming.state.caller == person
        return
    with pytest.raises(HTTPException) as exc:
        require_auth(incoming)
    assert (exc.value.status_code, exc.value.detail) == (403, 'Your role does not allow this')


@pytest.mark.parametrize('route', [None, matched('/api/not-in-the-table')])
def test_auth_dependency_refuses_a_route_without_a_permission(route: SimpleNamespace | None) -> None:
    """Deny by default: a route missing from the table is refused even to the operator (an admin)."""
    require_auth = main.auth_dependency(lambda _session: main.SESSION_CALLER)
    scope = {'type': 'http', 'method': 'GET', 'path': '/api/x', 'headers': [], 'session': {}}
    with pytest.raises(HTTPException) as exc:
        require_auth(Request({**scope, 'route': route} if route is not None else scope))
    assert exc.value.status_code == 403


def test_start_session_rotates_identity_and_prunes_expired_sessions(session_app: FastAPI) -> None:
    now = time.time()
    stored_session(session_app, at=now - main.SESSION_TTL_SECONDS - 1)  # stale
    old = stored_session(session_app, at=now)
    other = stored_session(session_app, at=now)
    session: dict[str, Any] = {'sid': old, 'csrf': 'pre-login', 'planted': 'by attacker'}
    main.start_session(session_app, request('POST', session), now)
    assert session['authenticated'] is True
    assert session['sid'] not in {old, other}
    assert session['csrf'] != 'pre-login'
    assert 'planted' not in session  # everything from before sign-in is discarded
    authenticated = main.session_checker(session_app)
    assert authenticated(session)
    assert authenticated({'authenticated': True, 'sid': other})  # another browser keeps its own session
    assert not authenticated({'authenticated': True, 'sid': old})
    with session_app.state.session_factory() as db:
        rows = db.scalars(select(OperatorSession)).all()
        assert len(rows) == 2, 'the stale session was deleted'
        assert {r.expires_at for r in rows} >= {
            services.stamp(datetime.fromtimestamp(now, UTC) + services.SESSION_TTL)
        }
        assert (
            db.scalar(select(func.count()).where(OperatorSession.id_hash.in_([old, other, session['sid']])))
            == 0
        )


# --------------------------------------------------------------------------- request parsing and lookups


def test_ioc_export_query_applies_defaults_and_validates() -> None:
    blank: dict[str, Any] = {
        'q': '',
        'status': '',
        'tlp': '',
        'include_superseded': False,
        'kinds': None,
        'review_statuses': None,
        'max_tlp': '',
        'defang': False,
    }
    query = main.ioc_export_query(**blank)
    assert (query.status, query.tlp, query.max_tlp) == (None, None, None)
    assert query.review_statuses == ('unreviewed', 'accepted')
    assert main.ioc_export_query(**{**blank, 'kinds': ['ip', 'cve']}).kinds == ('cve', 'ip')
    with pytest.raises(HTTPException) as exc:
        main.ioc_export_query(**{**blank, 'max_tlp': 'WHITE'})
    assert exc.value.status_code == 422
    assert 'max_tlp' in str(exc.value.detail)


def test_get_document_or_404(db: Session) -> None:
    doc, _ = ingest(db, DocumentInput(title='T', body='CVE-2024-12345', source_name='S'))
    assert main.get_document_or_404(db, doc.id) is doc
    with pytest.raises(HTTPException) as exc:
        main.get_document_or_404(db, 'missing')
    assert exc.value.status_code == 404


# --------------------------------------------------------------------------- one route group on a bare app


def test_a_route_group_can_be_mounted_and_tested_alone(session_factory: sessionmaker[Session]) -> None:
    app = FastAPI()
    calls: list[str] = []

    def record_auth(request: Request) -> None:  # stands in for the real session/CSRF check
        calls.append(request.url.path)

    workspace._register_workspace_routes(app, session_factory, record_auth)
    with session_factory.begin() as db:
        ingest(db, DocumentInput(title='T', body='CVE-2024-12345 at 192.0.2.8', source_name='S'))
    with TestClient(app) as client:
        assert client.get('/api/stats').json() == {
            'documents': 1,
            'entities': 2,
            'unreviewed': 1,
            'observations_unreviewed': 2,
        }
        assert client.get('/api/watch-terms').json() == []
    assert calls == ['/api/stats', '/api/watch-terms']  # the injected auth dependency guarded both routes


def test_the_job_runner_starts_and_stops_with_the_app(settings: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    import asyncio
    import dataclasses

    from insight import jobs

    seen: list[str] = []

    async def fake_runner(sessions: Any, lock: asyncio.Lock, stop: asyncio.Event, **_: Any) -> None:
        seen.append('started')
        await stop.wait()
        seen.append('stopped')

    monkeypatch.setattr(jobs, 'run_forever', fake_runner)
    with TestClient(main.create_app(dataclasses.replace(settings, run_jobs=True), with_ui=False)):
        assert seen == ['started']
    assert seen == ['started', 'stopped']
    with TestClient(main.create_app(settings, with_ui=False)):
        pass
    assert seen == ['started', 'stopped']  # run_jobs off: no runner
