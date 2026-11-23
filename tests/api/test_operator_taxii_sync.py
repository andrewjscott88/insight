"""Atomic collection sync through the operator API, with fixed local STIX fixtures."""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from insight import cli, connectors, jobs, services, taxii_client

from .test_operator_sources_api import CATALOG
from .test_stix_import import RED, simple_bundle

COLLECTION = {
    'name': 'Research advisories',
    'kind': 'taxii',
    'url': 'https://partner.example.org/taxii/',
    'collection_id': 'reviewed',
    'tlp': 'GREEN',
}
ENV = 'INSIGHT_SOURCE_RESEARCH'
CREDENTIAL = 'synthetic-secret-not-for-reports'
FIRST = '2026-01-01T00:00:00.000Z'
SECOND = '2026-01-02T00:00:00.000Z'


def setup_feed(client: TestClient, *, credential: bool = False) -> str:
    settings = COLLECTION | ({'credential_env': ENV} if credential else {})
    result = client.post(CATALOG, json=settings)
    assert result.status_code == 201, result.text
    key: str = result.json()['key']
    assert client.put(f'{CATALOG}/{key}/switch', json={'enabled': True}).status_code == 200
    return key


def cursor(app: FastAPI, key: str) -> str:
    with app.state.session_factory() as db:
        return services.fetch_cursor(db, key)


def test_collection_sync_resumes_replays_and_accepts_an_empty_collection(
    app: FastAPI, authed: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    key = setup_feed(authed)
    wire = json.dumps(simple_bundle()).encode()
    batches = iter(
        (
            taxii_client.CollectionBatch(wire, FIRST, 1),
            taxii_client.CollectionBatch(wire, SECOND, 1),
            taxii_client.CollectionBatch(None, SECOND, 0),
        )
    )
    requested: list[str] = []

    async def fetch(root: str, collection: str, **kwargs: Any) -> taxii_client.CollectionBatch:
        assert root.rstrip('/') == COLLECTION['url'].rstrip('/')
        assert collection == COLLECTION['collection_id']
        assert not kwargs['credential_env']
        assert kwargs['allow_private'] is False
        requested.append(kwargs['added_after'])
        return next(batches)

    monkeypatch.setattr(taxii_client, 'fetch_collection', fetch)
    for expected in (FIRST, SECOND, SECOND):
        response = authed.post(f'/api/sources/{key}/sync')
        assert response.status_code == 200, response.text
        assert cursor(app, key) == expected
    assert requested == ['', FIRST, SECOND]
    documents = authed.get('/api/documents').json()
    assert len(documents) == 1
    assert documents[0]['tlp'] == 'GREEN'
    assert authed.get(f'/api/documents/{documents[0]["id"]}').json()['source_key'] == key
    with app.state.session_factory() as db:
        assert len(services.recent_source_runs(db, key)) == 3
        assert [
            e.detail for e in services.audit_events(db) if e.action == 'source.sync' and e.object_id == key
        ] == [
            'unchanged',
            'success',
            'success',
        ]


def test_missing_credentials_make_no_request_and_values_never_leave_the_server(
    app: FastAPI, authed: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv(ENV, raising=False)
    key = setup_feed(authed, credential=True)
    path = f'/api/sources/{key}/sync'

    async def never(*args: Any, **kwargs: Any) -> taxii_client.CollectionBatch:
        pytest.fail('An unconfigured collection attempted a network request')

    monkeypatch.setattr(taxii_client, 'fetch_collection', never)
    for missing in (None, ''):
        if missing is not None:
            monkeypatch.setenv(ENV, missing)
        assert not authed.get(f'{CATALOG}/{key}').json()['configured']
        result = authed.post(path)
        assert result.status_code == 503, result.text
        assert result.json() == {'detail': 'Source credentials are not configured.'}
        assert cursor(app, key) == ''
    monkeypatch.setenv(ENV, CREDENTIAL)
    assert authed.get(f'{CATALOG}/{key}').json()['configured'] is True
    for route in (CATALOG, f'{CATALOG}/{key}', '/api/sources', '/api/jobs', '/api/audit'):
        assert CREDENTIAL not in authed.get(route).text


@pytest.mark.parametrize(
    'failure',
    [
        'save-cursor',
        'validation',
        'orphan',
        'label',
        'credential-removed',
        'credential-rotated',
        'competing-sync',
    ],
)
def test_failed_collection_is_atomic_and_diagnostics_are_bounded(
    app: FastAPI, authed: TestClient, monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    monkeypatch.setenv(ENV, CREDENTIAL)
    key = setup_feed(authed, credential=True)
    saved = services.save_fetch_cursor
    bundle = simple_bundle(marking=RED) if failure == 'label' else simple_bundle()
    if failure == 'orphan':
        stamp = '2024-01-01T00:00:00.000Z'
        bundle['objects'].append(
            {
                'type': 'report',
                'spec_version': '2.1',
                'id': f'report--{uuid4()}',
                'created': stamp,
                'modified': stamp,
                'published': stamp,
                'name': 'Incomplete',
                'object_refs': [f'indicator--{uuid4()}'],
            }
        )
    data = b'invalid-' + CREDENTIAL.encode() if failure == 'validation' else json.dumps(bundle).encode()
    with app.state.session_factory.begin() as db:
        saved(db, key, FIRST)

    async def fetch(*args: Any, **kwargs: Any) -> taxii_client.CollectionBatch:
        assert kwargs['added_after'] == FIRST
        if failure == 'credential-removed':
            monkeypatch.delenv(ENV)
        if failure == 'credential-rotated':
            monkeypatch.setenv(ENV, 'replacement-secret')
        if failure == 'competing-sync':
            with app.state.session_factory.begin() as db:
                saved(db, key, SECOND)
        return taxii_client.CollectionBatch(data, SECOND, 1)

    def fail_save(*args: Any, **kwargs: Any) -> None:
        raise RuntimeError(CREDENTIAL)

    monkeypatch.setattr(taxii_client, 'fetch_collection', fetch)
    if failure == 'save-cursor':
        monkeypatch.setattr(services, 'save_fetch_cursor', fail_save)
    response = authed.post(f'/api/sources/{key}/sync')
    assert response.status_code == (503 if failure == 'credential-removed' else 502), response.text
    assert CREDENTIAL not in response.text
    assert cursor(app, key) == (SECOND if failure == 'competing-sync' else FIRST)
    assert authed.get('/api/documents').json() == []
    with app.state.session_factory() as db:
        runs = services.recent_source_runs(db, key)
        assert [r.status for r in runs] == ['error']
        assert all(CREDENTIAL not in r.message for r in runs)
        events = services.audit_events(db)
        assert not any(e.action in ('document.ingest', 'stix.import') for e in events)
        assert [e.detail for e in events if e.action == 'source.sync' and e.object_id == key] == ['error']


def test_switching_collection_during_a_poll_discards_the_old_batch(
    app: FastAPI, authed: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    key = setup_feed(authed)
    body = json.dumps(simple_bundle()).encode()

    async def fetch(*args: Any, **kwargs: Any) -> taxii_client.CollectionBatch:
        from insight.schemas import OperatorSourceInput

        with app.state.session_factory.begin() as db:
            settings = OperatorSourceInput.model_validate(COLLECTION | {'collection_id': 'different'})
            services.update_operator_source(db, key, settings)
        return taxii_client.CollectionBatch(body, FIRST, 1)

    monkeypatch.setattr(taxii_client, 'fetch_collection', fetch)
    assert authed.post(f'/api/sources/{key}/sync').status_code == 502
    assert not authed.get(f'{CATALOG}/{key}').json()['enabled']
    assert cursor(app, key) == ''
    assert authed.get('/api/documents').json() == []
    with app.state.session_factory() as db:
        assert not services.recent_source_runs(db, key)


def test_schedule_and_cli_pause_and_resume_after_host_credentials_return(
    app: FastAPI, authed: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv(ENV, raising=False)
    monkeypatch.setenv('INSIGHT_DATABASE_URL', app.state.settings.database_url)
    key = setup_feed(authed, credential=True)
    path = f'/api/schedules/{key}'
    assert authed.put(path, json={'interval_minutes': 60}).status_code == 503
    with pytest.raises(ValueError, match='not configured'):
        cli.schedule(key, '1h')
    assert authed.put(path, json={'interval_minutes': 0}).status_code == 200
    monkeypatch.setenv(ENV, CREDENTIAL)
    configured = authed.put(path, json={'interval_minutes': 60})
    assert configured.status_code == 200, configured.text
    due = configured.json()['next_run_at']
    monkeypatch.delenv(ENV)
    requests: list[str] = []

    async def fetch(*args: Any, **kwargs: Any) -> taxii_client.CollectionBatch:
        requests.append(kwargs['credential_env'])
        return taxii_client.CollectionBatch(None, '', 0)

    monkeypatch.setattr(taxii_client, 'fetch_collection', fetch)
    at = datetime.now(UTC)
    sessions = app.state.session_factory
    assert asyncio.run(jobs.run_due(sessions, asyncio.Lock(), clock=lambda: at, max_tlp='GREEN')) == 0
    assert not requests
    assert 'not configured' in cli.schedule(None, None)
    scheduled = next(s for s in authed.get('/api/schedules').json() if s['source_key'] == key)
    assert (scheduled['interval_minutes'], scheduled['next_run_at']) == (60, due)
    monkeypatch.setenv(ENV, CREDENTIAL)
    assert asyncio.run(jobs.run_due(sessions, asyncio.Lock(), clock=lambda: at, max_tlp='GREEN')) == 1
    assert requests == [ENV]
    with sessions() as db:
        assert any(e.actor == 'schedule' and e.action == 'source.sync' for e in services.audit_events(db))


def test_real_pagination_imports_a_reference_across_pages_in_one_source_transaction(
    app: FastAPI, authed: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    key = setup_feed(authed)
    indicator = simple_bundle()['objects'][0]
    stamp = '2024-01-01T00:00:00.000Z'
    report = {
        'type': 'report',
        'spec_version': '2.1',
        'id': f'report--{uuid4()}',
        'created': stamp,
        'modified': stamp,
        'published': stamp,
        'name': 'Page one report',
        'object_refs': [indicator['id']],
    }
    calls = []

    async def wire(
        url: str, params: dict[str, str], *, response_headers: connectors.DownloadHeaders, **kwargs: Any
    ) -> bytes:
        assert url == COLLECTION['url'] + f'collections/{COLLECTION["collection_id"]}/objects/'
        assert kwargs['allowed_hosts'] == frozenset({'partner.example.org'})
        assert kwargs['headers']['Accept'] == 'application/taxii+json;version=2.1'
        calls.append(dict(params))
        response_headers.content_type = 'application/taxii+json;version=2.1'
        if 'next' not in params:
            response_headers.date_added_last = FIRST
            return json.dumps({'objects': [report], 'more': True, 'next': 'next-fixture-page'}).encode()
        response_headers.date_added_last = SECOND
        return json.dumps({'objects': [indicator], 'more': False}).encode()

    monkeypatch.setattr(connectors, 'download', wire)
    result = authed.post(f'/api/sources/{key}/sync')
    assert result.status_code == 200, result.text
    assert calls == [{}, {'next': 'next-fixture-page'}]
    assert cursor(app, key) == SECOND
    docs = authed.get('/api/documents').json()
    assert [d['title'] for d in docs] == ['Page one report']
    detail = authed.get(f'/api/documents/{docs[0]["id"]}').json()
    assert detail['source_key'] == key
    assert [obs['value'] for obs in detail['observations']] == ['example.net']
