"""Shared fixtures.

Design rules for this suite:

* **Offline by construction.** ``_no_network`` (autouse) makes DNS resolution and outbound TCP connections
  fail (loopback is allowed for a local test database), so a test that accidentally reaches the internet
  fails loudly instead of passing flakily. Tests marked ``live`` are the only exception.
* **Isolated state.** Every test gets a fresh, fully migrated database and a fresh app instance.
* **Both databases.** SQLite by default. Set ``INSIGHT_TEST_DATABASE_URL`` to a PostgreSQL *server* URL
  (e.g. ``postgresql+psycopg://postgres@127.0.0.1:5432/postgres``) and every database-backed test runs
  against its own throwaway PostgreSQL database instead.
* **Real stack.** API tests go through the complete middleware stack (TrustedHost → Session → Boundary).
"""

from __future__ import annotations

import ipaddress
import logging
import os
import re
import shutil
import socket
import uuid
from collections.abc import Callable, Iterator
from contextlib import AbstractContextManager, contextmanager
from pathlib import Path
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from hypothesis import HealthCheck
from hypothesis import settings as hypothesis_settings
from sqlalchemy import Engine, create_engine, event, make_url
from sqlalchemy.orm import Session, sessionmaker

from insight.config import Settings
from insight.main import create_app
from insight.models import database

PASSWORD = 'longtestpassword'
SECRET = 'x' * 40
CSRF_RE = re.compile(r'name="csrf_token"[^>]*value="([^"]+)"')
POSTGRES_SERVER_URL = os.environ.get('INSIGHT_TEST_DATABASE_URL', '')

# Hypothesis: a fast default for every push, and a deep profile for the nightly pipeline.
hypothesis_settings.register_profile('default', max_examples=300, deadline=None)
hypothesis_settings.register_profile(
    'nightly', max_examples=5000, deadline=None, suppress_health_check=[HealthCheck.too_slow]
)
hypothesis_settings.load_profile(os.environ.get('HYPOTHESIS_PROFILE', 'default'))


# --------------------------------------------------------------------------- network guard


@pytest.fixture(autouse=True)
def _isolated_insight_logger(monkeypatch: pytest.MonkeyPatch) -> None:
    """Restore the process-wide ``insight`` logger after every test, wherever the test is.

    The CLI (``serve``, ``migrate``, ``export-iocs``) configures it to write to stderr instead of to pytest.
    Restoring it only in ``test_cli.py`` was not enough: ``test_ioc_export.py`` also runs the CLI, and when
    unit tests ran before API tests (as mutation testing runs them), the sign-in logging test saw nothing.
    """
    logger = logging.getLogger('insight')
    monkeypatch.setattr(logger, 'handlers', list(logger.handlers))
    monkeypatch.setattr(logger, 'propagate', logger.propagate)
    monkeypatch.setattr(logger, 'level', logger.level)


@pytest.fixture(autouse=True)
def _dispose_app_databases(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Close the database of every app a test creates, also when the test never starts the app.

    ``create_app`` reads the database once at start-up, so its pool holds an open connection. An app whose
    lifespan never runs never disposes it, and Python 3.13 then reports the unclosed SQLite connection as a
    ``ResourceWarning`` in whichever later test the garbage collector happens to run.
    """
    from insight.web import app as web_app

    created: list[Engine] = []
    real = database  # what insight.web.app imported from insight.models

    def tracking(*args: Any, **kwargs: Any) -> tuple[Engine, sessionmaker[Session]]:
        engine, sessions = real(*args, **kwargs)
        created.append(engine)
        return engine, sessions

    monkeypatch.setattr(web_app, 'database', tracking)
    yield
    for engine in created:
        engine.dispose()


@pytest.fixture(autouse=True)
def _no_network(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch) -> None:
    if request.node.get_closest_marker('live') or request.node.get_closest_marker('e2e'):
        return  # these talk to real services by design

    def blocked(*_args: Any, **_kwargs: Any) -> Any:
        raise OSError('Network access is disabled in the test suite')

    real_connect = socket.socket.connect
    real_getaddrinfo = socket.getaddrinfo

    def loopback_only_getaddrinfo(host: Any, *args: Any, **kwargs: Any) -> Any:
        if host in ('localhost', '127.0.0.1', '::1'):
            return real_getaddrinfo(host, *args, **kwargs)
        return blocked()

    def guarded_connect(self: socket.socket, address: Any) -> Any:
        if (
            self.family in (socket.AF_INET, socket.AF_INET6)
            and not ipaddress.ip_address(address[0]).is_loopback
        ):
            blocked()
        return real_connect(self, address)

    monkeypatch.setattr(socket, 'getaddrinfo', loopback_only_getaddrinfo)
    monkeypatch.setattr(socket.socket, 'connect', guarded_connect)


# --------------------------------------------------------------------------- databases


def _postgres_admin() -> Engine:
    return create_engine(make_url(POSTGRES_SERVER_URL).set(database='postgres'), isolation_level='AUTOCOMMIT')


def _postgres_url(name: str) -> str:
    return make_url(POSTGRES_SERVER_URL).set(database=name).render_as_string(hide_password=False)


@pytest.fixture(scope='session')
def _postgres_template() -> Iterator[str | None]:
    """Migrate one template database per session; each test clones it (much faster than migrating)."""
    if not POSTGRES_SERVER_URL:
        yield None
        return
    name = f'insight_template_{uuid.uuid4().hex[:8]}'
    admin = _postgres_admin()
    with admin.connect() as conn:
        conn.exec_driver_sql(f'CREATE DATABASE "{name}"')
    engine, _ = database(_postgres_url(name))
    engine.dispose()
    yield name
    with admin.connect() as conn:
        conn.exec_driver_sql(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')
    admin.dispose()


@contextmanager
def _fresh_postgres(template: str | None) -> Iterator[str]:
    name = f'insight_test_{uuid.uuid4().hex[:12]}'
    admin = _postgres_admin()
    clone = f' TEMPLATE "{template}"' if template else ''
    with admin.connect() as conn:
        conn.exec_driver_sql(f'CREATE DATABASE "{name}"{clone}')
    try:
        yield _postgres_url(name)
    finally:
        with admin.connect() as conn:
            conn.exec_driver_sql(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')
        admin.dispose()


@pytest.fixture(scope='session')
def _sqlite_template(tmp_path_factory: pytest.TempPathFactory) -> Path:
    path = tmp_path_factory.mktemp('template') / 'migrated.db'
    engine, _ = database(f'sqlite:///{path}')
    engine.dispose()
    return path


@pytest.fixture
def database_url(tmp_path: Path, _postgres_template: str | None, _sqlite_template: Path) -> Iterator[str]:
    """A fresh, already-migrated database URL on the configured backend (cloned from a template)."""
    if _postgres_template is None:
        path = tmp_path / 'test.db'
        shutil.copyfile(_sqlite_template, path)
        yield f'sqlite:///{path}'
        return
    with _fresh_postgres(_postgres_template) as url:
        yield url


@pytest.fixture
def empty_database_url(tmp_path: Path) -> Iterator[str]:
    """A brand-new database with no tables at all (for migration tests)."""
    if not POSTGRES_SERVER_URL:
        yield f'sqlite:///{tmp_path / "empty.db"}'
        return
    with _fresh_postgres(None) as url:
        yield url


@pytest.fixture
def backend(database_url: str) -> str:
    """``'sqlite'`` or ``'postgresql'``."""
    return make_url(database_url).get_backend_name()


@pytest.fixture
def session_factory(_postgres_template: str | None) -> Iterator[sessionmaker[Session]]:
    """A standalone migrated database for service/connector unit tests (in-memory SQLite by default)."""
    if _postgres_template is None:
        engine, factory = database('sqlite://')
        yield factory
        engine.dispose()
        return
    with _fresh_postgres(_postgres_template) as url:
        engine, factory = database(url)
        yield factory
        engine.dispose()


@pytest.fixture
def db(session_factory: sessionmaker[Session]) -> Iterator[Session]:
    with session_factory.begin() as session:
        yield session


@pytest.fixture
def count_queries() -> Callable[[Engine], AbstractContextManager[list[str]]]:
    """``with count_queries(engine) as statements: ...`` records every SQL statement executed."""

    @contextmanager
    def _count(engine: Engine) -> Iterator[list[str]]:
        statements: list[str] = []

        def record(_conn: Any, _cursor: Any, statement: str, *_: Any) -> None:
            statements.append(statement)

        event.listen(engine, 'before_cursor_execute', record)
        try:
            yield statements
        finally:
            event.remove(engine, 'before_cursor_execute', record)

    return _count


# --------------------------------------------------------------------------- application


@pytest.fixture
def settings(database_url: str) -> Settings:
    # No per-failure sign-in delay in tests; tests that exercise the delay set it explicitly.
    return Settings(database_url=database_url, password=PASSWORD, session_secret=SECRET, failed_login_delay=0)


@pytest.fixture
def app(settings: Settings) -> FastAPI:
    return create_app(settings, with_ui=False)


@pytest.fixture
def client(app: FastAPI) -> Iterator[TestClient]:
    with TestClient(app, follow_redirects=False) as test_client:
        yield test_client


def csrf_from(html: str) -> str:
    match = CSRF_RE.search(html)
    assert match, 'login form has no CSRF token'
    return match.group(1)


def do_login(client: TestClient, password: str = PASSWORD) -> str:
    """Sign in through the real form flow; installs and returns the API CSRF token."""
    response = client.get('/login')
    assert response.status_code == 200
    response = client.post('/login', data={'csrf_token': csrf_from(response.text), 'password': password})
    assert response.status_code == 303, response.text
    token: str = client.get('/api/session').json()['csrf_token']
    client.headers['X-CSRF-Token'] = token
    return token


@pytest.fixture
def login() -> Callable[..., str]:
    """``login(client, password=...)`` performs the real form sign-in and returns the API CSRF token."""
    return do_login


@pytest.fixture
def csrf_token_from() -> Callable[[str], str]:
    return csrf_from


@pytest.fixture
def authed(client: TestClient) -> TestClient:
    do_login(client)
    return client


DEFAULT_DOCUMENT: dict[str, str] = {
    'title': 'Incident report',
    'body': 'Observed CVE-2024-12345 at 192.0.2.8 and Example.COM.',
    'source_name': 'Analyst',
    'source_url': 'https://example.com/report',
    'tlp': 'AMBER+STRICT',
}


@pytest.fixture
def make_document(authed: TestClient) -> Callable[..., dict[str, Any]]:
    """POST a document (defaults overridable by keyword) and return the JSON detail."""

    def _make(**changes: str) -> dict[str, Any]:
        response = authed.post('/api/documents', json={**DEFAULT_DOCUMENT, **changes})
        assert response.status_code == 200, response.text
        result: dict[str, Any] = response.json()
        return result

    return _make
