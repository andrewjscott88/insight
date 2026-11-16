"""The application factory's building blocks, tested without the full middleware stack.

``create_app`` composes small, importable pieces: a session checker, the auth dependency, query parsing,
session rotation and one route-registration function per area. Each can be exercised on its own here; the
full stack (middleware order, real sign-in) stays covered by ``test_auth.py`` and ``test_middleware.py``.
"""

from __future__ import annotations

import time
from typing import Any

import pytest
from fastapi import FastAPI, HTTPException, Request
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session, sessionmaker

from insight import main
from insight.schemas import DocumentInput
from insight.services import ingest


def request(method: str = 'GET', session: dict[str, Any] | None = None, csrf: str | None = None) -> Request:
    headers = [(b'x-csrf-token', csrf.encode())] if csrf is not None else []
    return Request({'type': 'http', 'method': method, 'headers': headers, 'session': session or {}})


def app_with_sessions(**sessions: float) -> FastAPI:
    app = FastAPI()
    app.state.active_sessions = dict(sessions)
    return app


# --------------------------------------------------------------------------- sessions and auth


def test_session_checker_requires_a_live_server_side_session() -> None:
    app = app_with_sessions(live=time.time() + 60, expired=time.time() - 1)
    authenticated = main.session_checker(app)
    assert authenticated({'authenticated': True, 'sid': 'live'})
    assert not authenticated({'authenticated': True, 'sid': 'expired'})
    assert not authenticated({'authenticated': True, 'sid': 'unknown'})
    assert not authenticated({'authenticated': False, 'sid': 'live'})  # signed cookie alone is not enough
    assert not authenticated({})


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
    require_auth = main.auth_dependency(lambda _session: signed_in)
    incoming = request(method, {'csrf': 'token'}, csrf)
    if status is None:
        require_auth(incoming)
        return
    with pytest.raises(HTTPException) as exc:
        require_auth(incoming)
    assert exc.value.status_code == status


def test_start_session_rotates_identity_and_prunes_expired_sessions() -> None:
    now = time.time()
    app = app_with_sessions(old=now + 100, stale=now - 1, other=now + 100)
    session: dict[str, Any] = {'sid': 'old', 'csrf': 'pre-login', 'planted': 'by attacker'}
    main.start_session(app, request('POST', session), now)
    assert session['authenticated'] is True
    assert session['sid'] not in {'old', 'other'}
    assert session['csrf'] != 'pre-login'
    assert 'planted' not in session  # everything from before sign-in is discarded
    assert set(app.state.active_sessions) == {'other', session['sid']}
    assert app.state.active_sessions[session['sid']] == now + main.SESSION_TTL_SECONDS


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

    main._register_workspace_routes(app, session_factory, record_auth)
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
