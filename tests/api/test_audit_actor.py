"""Audit events name who acted: the operator's session, the API key, the CLI or a connector."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from insight import cli, connectors, services
from insight.models import AuditEvent

DOCUMENT = {'title': 'Report', 'body': 'Seen at 192.0.2.8.', 'source_name': 'Analyst', 'tlp': 'GREEN'}


def actors(events: list[dict[str, Any]], action: str) -> list[str]:
    return [e['actor'] for e in events if e['action'] == action]


def test_the_operators_session_is_recorded(authed: TestClient) -> None:
    doc = authed.post('/api/documents', json=DOCUMENT).json()
    authed.post(f'/api/documents/{doc["id"]}/review', json={'status': 'reviewed'})
    authed.get('/api/iocs/export')
    events = authed.get('/api/audit').json()
    for action in ('document.ingest', 'document.review', 'ioc.export'):
        assert actors(events, action) == ['operator'], action


def test_the_api_key_is_recorded_by_key_id(app: FastAPI, client: TestClient, authed: TestClient) -> None:
    with app.state.session_factory.begin() as db:
        key, token = services.create_api_key(db, name='scripts', access='read-write')
    headers = {'Authorization': f'Bearer {token}'}
    doc = client.post('/api/documents', json=DOCUMENT, headers=headers).json()
    client.post(f'/api/documents/{doc["id"]}/notes', json={'body': 'from the SIEM'}, headers=headers)
    client.post('/api/demo', headers=headers)
    events = client.get('/api/audit', headers=headers).json()
    assert actors(events, 'note.add') == [f'api-key:{key.key_id}']
    assert set(actors(events, 'document.ingest')) == {f'api-key:{key.key_id}'}


async def test_connectors_are_recorded_by_source(
    session_factory: sessionmaker[Session], monkeypatch: pytest.MonkeyPatch
) -> None:
    async def feed(url: str, params: Any = None, **_: Any) -> bytes:
        return b'<rss><channel><item><title>Advisory CVE-2024-9999</title></item></channel></rss>'

    monkeypatch.setattr(connectors, 'download', feed)
    await connectors.sync_source(session_factory, 'sans-isc')
    with session_factory() as db:
        assert db.scalars(select(AuditEvent.actor)).all() == ['connector:sans-isc']


def test_the_cli_is_recorded(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(os, 'environ', {'INSIGHT_DATA_DIR': str(tmp_path / 'data')})
    assert cli.main(['migrate']) == 0
    assert cli.main(['api-key', 'create', '--name', 'siem']) == 0
    assert cli.main(['export-iocs', str(tmp_path / 'iocs.json')]) == 0
    from insight.config import database_url_from_env
    from insight.models import database

    engine, sessions = database(database_url_from_env(), migrate=False)
    with sessions() as db:
        recorded = {(e.action, e.actor) for e in db.scalars(select(AuditEvent))}
    engine.dispose()
    assert recorded == {('api_key.create', 'cli'), ('ioc.export', 'cli')}


def test_unnamed_actors_are_recorded_as_system(db: Session) -> None:
    services.audit(db, 'test.event', 'x')
    assert db.scalar(select(AuditEvent.actor)) == 'system'
