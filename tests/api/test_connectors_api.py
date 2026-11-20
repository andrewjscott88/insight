"""Source sync and enrichment endpoints: status codes, locking and throttling."""

from __future__ import annotations

import asyncio
import json
from collections.abc import Callable
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import select

from insight import connectors
from insight.models import Document, KEVRecord

KEV = json.dumps(
    {
        'vulnerabilities': [
            {
                'cveID': 'CVE-2024-12345',
                'vendorProject': 'Fixture vendor',
                'product': 'Fixture product',
                'dateAdded': '2025-01-01',
                'dueDate': '2025-01-22',
                'requiredAction': 'Apply patch',
                'shortDescription': 'A fixture vulnerability.',
            }
        ]
    }
).encode()


def fake_download(payload: bytes = b'{}', calls: list[Any] | None = None) -> Callable[..., Any]:
    async def download(url: str, params: Any = None, **_: Any) -> bytes:
        if calls is not None:
            calls.append((url, params))
        return payload

    return download


# --------------------------------------------------------------------------- sources


def test_sources_listing_has_every_registry_entry(authed: TestClient) -> None:
    listed = authed.get('/api/sources').json()
    assert [s['key'] for s in listed] == list(connectors.SOURCES)
    assert all(s['runs'] == [] for s in listed)


def test_kev_sync_provenance_and_history(
    app: FastAPI, authed: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[Any] = []
    monkeypatch.setattr(connectors, 'download', fake_download(KEV, calls))
    response = authed.post('/api/sources/cisa-kev/sync')
    assert response.status_code == 200, response.text
    assert calls == [(connectors.SOURCES['cisa-kev'].url, None)]
    (doc,) = authed.get('/api/documents').json()
    report = authed.get('/api/documents/' + doc['id']).json()
    assert report['source_name'] == connectors.SOURCES['cisa-kev'].name
    kev = next(o['kev'] for o in report['observations'] if o['kind'] == 'cve')
    assert kev['due_date'] == '2025-01-22'
    assert kev['required_action'] == 'Apply patch'
    assert kev['imported_at']
    with app.state.session_factory.begin() as db:
        assert connectors.import_kev(db, KEV) == (1, 0)
        record = db.get(KEVRecord, 'CVE-2024-12345')
        assert record is not None
        assert record.vendor == 'Fixture vendor'
        assert len(db.scalars(select(Document)).all()) == 1
    source = next(s for s in authed.get('/api/sources').json() if s['key'] == 'cisa-kev')
    assert source['runs'][0]['status'] == 'success'


def test_run_history_is_limited_to_five(authed: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(connectors, 'download', fake_download(b'<rss/>'))
    for _ in range(7):
        assert authed.post('/api/sources/ncsc/sync').status_code == 200
    source = next(s for s in authed.get('/api/sources').json() if s['key'] == 'ncsc')
    assert len(source['runs']) == 5


def test_failed_sync_is_502_recorded_and_not_partially_imported(
    app: FastAPI, authed: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    bad = b'{"vulnerabilities": [{"cveID": "CVE-2024-12345"}, {"cveID": "INVALID"}]}'
    monkeypatch.setattr(connectors, 'download', fake_download(bad))
    response = authed.post('/api/sources/cisa-kev/sync')
    assert response.status_code == 502
    assert 'Invalid CVE' in response.json()['detail']
    assert authed.get('/api/stats').json()['documents'] == 0
    with app.state.session_factory() as db:
        assert db.get(KEVRecord, 'CVE-2024-12345') is None
    source = next(s for s in authed.get('/api/sources').json() if s['key'] == 'cisa-kev')
    assert source['runs'][0]['status'] == 'error'


def test_sync_all_reports_each_source_and_records_every_run(
    authed: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def download(url: str, params: Any = None, **_: Any) -> bytes:
        if url == connectors.SOURCES['cisa-kev'].url:
            return KEV
        if url.endswith('changes.csv'):
            raise OSError('offline')
        return b'<rss/>'

    monkeypatch.setattr(connectors, 'download', download)
    response = authed.post('/api/sources/sync-all')
    assert response.status_code == 200, response.text
    results = response.json()['results']
    assert [(r['key'], r['status']) for r in results] == [
        ('cisa-kev', 'success'), ('cisa-csaf', 'error'), ('sans-isc', 'success'), ('ncsc', 'success')
    ]  # fmt: skip
    assert results[1] == {
        'key': 'cisa-csaf', 'name': connectors.SOURCES['cisa-csaf'].name, 'status': 'error',
        'message': 'OSError: offline',
    }  # fmt: skip
    listed = {s['key']: s['runs'][0]['status'] for s in authed.get('/api/sources').json()}
    assert listed == {'cisa-kev': 'success', 'cisa-csaf': 'error', 'sans-isc': 'success', 'ncsc': 'success'}


def test_unknown_source_is_404(authed: TestClient) -> None:
    assert authed.post('/api/sources/arbitrary/sync').status_code == 404


def test_concurrent_sync_is_rejected(app: FastAPI, authed: TestClient) -> None:
    lock: asyncio.Lock = app.state.sync_lock

    async def hold() -> None:
        await lock.acquire()

    asyncio.run(hold())  # The lock is not bound to a loop until contended, so this is safe.
    try:
        assert authed.post('/api/sources/cisa-kev/sync').status_code == 409
        assert authed.post('/api/sources/sync-all').status_code == 409
    finally:
        lock.release()


# --------------------------------------------------------------------------- enrichment


@pytest.fixture
def with_cve(make_document: Callable[..., dict[str, Any]]) -> str:
    make_document()
    return 'CVE-2024-12345'


def test_enrichment_success_and_throttle(
    app: FastAPI, authed: TestClient, monkeypatch: pytest.MonkeyPatch, with_cve: str
) -> None:
    monkeypatch.setattr(connectors, 'download', fake_download(b'{"data": []}'))
    response = authed.post(f'/api/enrichment/epss/{with_cve}')
    assert (response.status_code, response.json()) == (200, {'data': []})
    throttled = authed.post(f'/api/enrichment/nvd/{with_cve}')
    assert throttled.status_code == 429
    app.state.last_lookup = 0.0
    assert authed.post(f'/api/enrichment/nvd/{with_cve}').status_code == 200


@pytest.mark.parametrize(
    ('provider', 'cve'), [('bogus', 'CVE-2024-12345'), ('epss', 'CVE-24-1'), ('epss', 'cve-2024-12345')]
)
def test_invalid_requests_are_422_and_do_not_consume_the_throttle(
    app: FastAPI, authed: TestClient, provider: str, cve: str
) -> None:
    # Regression: invalid input used to reset the 6.5 s window and returned 429 on a valid retry.
    assert authed.post(f'/api/enrichment/{provider}/{cve}').status_code == 422
    assert app.state.last_lookup == 0.0


def test_unknown_cve_is_422_and_does_not_consume_the_throttle(
    app: FastAPI, authed: TestClient, monkeypatch: pytest.MonkeyPatch, with_cve: str
) -> None:
    # Regression (#8): a well-formed CVE that no report mentions was refused but still started the 6.5 s
    # window, so the next valid request was throttled.
    response = authed.post('/api/enrichment/epss/CVE-2024-99999')
    assert response.status_code == 422
    assert 'Import a report' in response.json()['detail']
    assert app.state.last_lookup == 0.0
    monkeypatch.setattr(connectors, 'download', fake_download(b'{"data": []}'))
    assert authed.post(f'/api/enrichment/epss/{with_cve}').status_code == 200


@pytest.mark.parametrize('payload', [b'<html>Rate limited</html>', b'[]'])
def test_bad_upstream_response_is_502(
    authed: TestClient, monkeypatch: pytest.MonkeyPatch, with_cve: str, payload: bytes
) -> None:
    # Regression: a non-JSON provider response was reported as a 422 client error.
    monkeypatch.setattr(connectors, 'download', fake_download(payload))
    assert authed.post(f'/api/enrichment/nvd/{with_cve}').status_code == 502


def test_unexpected_errors_are_502_without_details(
    authed: TestClient, monkeypatch: pytest.MonkeyPatch, with_cve: str
) -> None:
    async def boom(*_: Any, **__: Any) -> bytes:
        raise RuntimeError('secret internal detail')

    monkeypatch.setattr(connectors, 'download', boom)
    response = authed.post(f'/api/enrichment/epss/{with_cve}')
    assert response.status_code == 502
    assert 'secret' not in response.text


def test_publisher_edits_create_revisions_not_duplicates(
    authed: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Decision 6: a changed KEV description supersedes the old report instead of duplicating it."""

    def kev(description: str) -> bytes:
        row = {'cveID': 'CVE-2024-3400', 'dateAdded': '2024-04-12', 'shortDescription': description}
        return json.dumps({'vulnerabilities': [row]}).encode()

    monkeypatch.setattr(connectors, 'download', fake_download(kev('Command injection.')))
    assert authed.post('/api/sources/cisa-kev/sync').status_code == 200
    monkeypatch.setattr(connectors, 'download', fake_download(kev('OS command injection in GlobalProtect.')))
    assert authed.post('/api/sources/cisa-kev/sync').status_code == 200

    (current,) = authed.get('/api/documents').json()
    assert current['is_current'] is True
    every = authed.get('/api/documents', params={'include_superseded': 'true'}).json()
    assert len(every) == 2
    report = authed.get(f'/api/documents/{current["id"]}').json()
    assert 'GlobalProtect' in report['body']
    assert [r['is_current'] for r in report['revisions']] == [False, True]
    old = authed.get(f'/api/documents/{report["supersedes_id"]}').json()
    assert old['is_current'] is False
    assert 'Command injection.' in old['body']
    assert authed.get('/api/stats').json()['documents'] == 1
