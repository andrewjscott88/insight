"""Operator feed definitions and outbound controls through the actual API boundary."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from insight import connectors, services
from insight.models import SourceRun

CATALOG = '/api/operator-sources'
FEED = {'name': 'Partner bulletin', 'url': 'https://partner.example.org/news.xml'}


def key_headers(app: FastAPI, *, ceiling: str | None = None, access: str = 'read-write') -> dict[str, str]:
    with app.state.session_factory.begin() as db:
        _, token = services.create_api_key(db, name='test-reader', access=access, max_tlp=ceiling)
    return {'Authorization': f'Bearer {token}'}


def test_browser_owns_source_settings_and_schedules(authed: TestClient) -> None:
    created = authed.post(CATALOG, json=FEED)
    assert created.status_code == 201, created.text
    source = created.json()
    key = source['key']
    assert key.startswith('op-')
    assert (source['kind'], source['tlp'], source['reuse'], source['enabled']) == (
        'rss',
        'AMBER',
        'metadata',
        False,
    )
    assert authed.get(f'{CATALOG}/{key}').json() == source
    assert authed.get(CATALOG).json() == [source]
    assert authed.post(f'/api/sources/{key}/sync').status_code == 409
    schedule = f'/api/schedules/{key}'
    assert authed.put(schedule, json={'interval_minutes': 60}).status_code == 409
    assert authed.put(f'{CATALOG}/{key}/switch', json={'enabled': True}).json()['enabled'] is True
    assert authed.put(schedule, json={'interval_minutes': 60}).json()['interval_minutes'] == 60
    edited = authed.put(f'{CATALOG}/{key}', json=FEED | {'name': 'Renamed', 'tlp': 'GREEN'})
    assert edited.status_code == 200, edited.text
    assert edited.json()['enabled']
    assert authed.put(f'{CATALOG}/{key}/switch', json={'enabled': False}).json()['enabled'] is False
    assert (
        next(s for s in authed.get('/api/schedules').json() if s['source_key'] == key)['interval_minutes']
        == 0
    )
    assert authed.delete(f'{CATALOG}/{key}').json() == {'deleted': key}
    assert authed.get(CATALOG).json() == []
    for path in (CATALOG, '/api/sources', '/api/schedules', '/api/jobs'):
        assert key not in authed.get(path).text
    missing = authed.get(f'{CATALOG}/missing')
    assert (missing.status_code, missing.json()) == (404, {'detail': 'Unknown source'})
    assert authed.get(f'{CATALOG}/{key}').json() == missing.json()
    assert authed.post(f'/api/sources/{key}/sync').status_code == 404


@pytest.mark.parametrize('access', ['read', 'read-feedback', 'read-write'])
def test_api_keys_and_missing_csrf_cannot_change_operator_sources(
    app: FastAPI, authed: TestClient, access: str
) -> None:
    key = authed.post(CATALOG, json=FEED).json()['key']
    headers = key_headers(app, access=access)
    assert authed.get(CATALOG, headers=headers).json()[0]['key'] == key
    resource = f'{CATALOG}/{key}'
    for method, path, body in (
        ('POST', CATALOG, FEED),
        ('PUT', resource, FEED),
        ('DELETE', resource, None),
        ('PUT', f'{resource}/switch', {'enabled': True}),
    ):
        assert authed.request(method, path, json=body, headers=headers).status_code == 403
        assert authed.request(method, path, json=body, headers={'X-CSRF-Token': 'wrong'}).status_code == 403
    assert authed.get(CATALOG).json()[0]['enabled'] is False


def test_invalid_settings_never_reflect_url_secrets_or_change_the_source(
    app: FastAPI, authed: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(app.state, 'settings', replace(app.state.settings, max_tlp='GREEN'))
    assert authed.post(CATALOG, json=FEED | {'tlp': 'AMBER'}).status_code == 403
    key = authed.post(CATALOG, json=FEED | {'tlp': 'GREEN'}).json()['key']
    path = f'{CATALOG}/{key}'
    assert authed.put(path, json=FEED | {'tlp': 'RED'}).status_code == 403
    secret = 'private-value-123'
    for url in ('https://user:private-value-123@partner.example.org/news', FEED['url'] + '?token=' + secret):
        response = authed.put(path, json=FEED | {'url': url, 'tlp': 'GREEN'})
        assert response.status_code == 422
        assert secret not in response.text
    assert authed.get(path).json()['tlp'] == 'GREEN'


def test_green_key_cannot_start_operator_sync_or_learn_which_hidden_sources_exist(
    app: FastAPI, authed: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    from insight.web.routes import sources as routes

    async def unexpected(*args: Any, **kwargs: Any) -> Any:
        pytest.fail('A limited key reached an outbound sync')

    monkeypatch.setattr(routes, 'sync_source', unexpected)
    monkeypatch.setattr(routes, 'sync_all', unexpected)
    known = authed.post(CATALOG, json=FEED | {'tlp': 'GREEN'}).json()['key']
    hidden = authed.post(CATALOG, json=FEED | {'name': 'Hidden'}).json()['key']
    headers = key_headers(app, ceiling='GREEN')
    assert [r['key'] for r in authed.get(CATALOG, headers=headers).json()] == [known]
    known_read = authed.get(f'{CATALOG}/{known}', headers=headers)
    assert known_read.status_code == 200
    for key in (hidden, 'op-missing'):
        missing = authed.get(f'{CATALOG}/{key}', headers=headers)
        assert (missing.status_code, missing.json()) == (404, {'detail': 'Unknown source'})
    for key in (known, hidden, 'op-missing'):
        assert authed.post(f'/api/sources/{key}/sync', headers=headers).status_code == 403
    assert authed.post('/api/sources/sync-all', headers=headers).status_code == 403


def test_history_hides_deleted_sources_and_the_period_before_a_source_label_was_lowered(
    app: FastAPI, authed: TestClient
) -> None:
    key = authed.post(CATALOG, json=FEED).json()['key']
    with app.state.session_factory.begin() as db:
        job = services.enqueue_job(db, services.SOURCE_SYNC, key, at=datetime.now(UTC), actor='schedule')
        job.message = 'old AMBER sync'
        db.add(SourceRun(source_key=key, status='success', message='old AMBER sync'))
    headers = key_headers(app, ceiling='GREEN')
    edited = authed.put(f'{CATALOG}/{key}', json=FEED | {'tlp': 'GREEN'})
    assert edited.status_code == 200
    with app.state.session_factory.begin() as db:
        db.add(SourceRun(source_key=key, status='success', message='new GREEN sync'))
    rows = authed.get('/api/sources', headers=headers).json()
    source = next(row for row in rows if row['key'] == key)
    assert [r['message'] for r in source['runs']] == ['new GREEN sync']
    assert 'old AMBER sync' not in authed.get('/api/jobs', headers=headers).text
    assert authed.delete(f'{CATALOG}/{key}').status_code == 200
    for path in ('/api/sources', '/api/jobs'):
        assert key not in authed.get(path).text


def test_unlimited_writer_syncs_only_enabled_sources_and_records_its_identity(
    app: FastAPI, authed: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    allowed = authed.post(CATALOG, json=FEED).json()['key']
    off = authed.post(CATALOG, json=FEED | {'name': 'Off', 'url': 'https://off.example.org/feed'}).json()[
        'key'
    ]
    assert authed.put(f'{CATALOG}/{allowed}/switch', json={'enabled': True}).status_code == 200
    with app.state.session_factory.begin() as db:
        for curated in connectors.SOURCES:
            services.set_source_switch(db, curated, False, at=datetime.now(UTC))
    headers = key_headers(app)
    requested: list[str] = []

    async def download(url: str, *args: Any, **kwargs: Any) -> bytes:
        requested.append(url)
        return b'<rss><channel><item><title>Partner notice</title><guid>note-1</guid></item></channel></rss>'

    monkeypatch.setattr(connectors, 'download', download)
    assert authed.post(f'/api/sources/{off}/sync', headers=headers).status_code == 409
    single = authed.post(f'/api/sources/{allowed}/sync', headers=headers)
    assert single.status_code == 200, single.text
    all_sources = authed.post('/api/sources/sync-all', headers=headers)
    assert all_sources.status_code == 200, all_sources.text
    assert [(r['key'], r['status']) for r in all_sources.json()['results']] == [(allowed, 'success')]
    assert requested == [FEED['url'], FEED['url']]
    with app.state.session_factory() as db:
        calls = [e for e in services.audit_events(db) if e.action == 'source.sync' and e.object_id == allowed]
        assert len(calls) == 2
        assert all(event.actor.startswith('api-key:') for event in calls)
