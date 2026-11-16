"""Source sync and CVE enrichment orchestration (network replaced by fakes)."""

from __future__ import annotations

import json
from collections.abc import Callable, Coroutine
from typing import Any

import httpx
import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from insight import connectors
from insight.connectors import ProviderError, SourceSyncError, enrich_cve, enrichment_request, sync_source
from insight.models import Document, Enrichment, KEVRecord, SourceRun
from insight.schemas import DocumentInput
from insight.services import ingest

Download = Callable[..., Coroutine[Any, Any, bytes]]
KEV = json.dumps({'vulnerabilities': [{'cveID': 'CVE-2024-12345', 'dateAdded': '2025-01-01'}]}).encode()
RSS = b'<rss><channel><item><title>Advisory CVE-2024-9999</title></item></channel></rss>'


def returning(payload: bytes, calls: list[tuple[str, Any]] | None = None) -> Download:
    async def fake(url: str, params: Any = None, **_: Any) -> bytes:
        if calls is not None:
            calls.append((url, params))
        return payload

    return fake


def raising(exc: BaseException) -> Download:
    async def fake(url: str, params: Any = None, **_: Any) -> bytes:
        raise exc

    return fake


def runs(factory: sessionmaker[Session]) -> list[SourceRun]:
    with factory() as db:
        return list(db.scalars(select(SourceRun)))


# --------------------------------------------------------------------------- sync_source


async def test_kev_sync_stores_records_and_success_run(
    session_factory: sessionmaker[Session], monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[tuple[str, Any]] = []
    monkeypatch.setattr(connectors, 'download', returning(KEV, calls))
    message = await sync_source(session_factory, 'cisa-kev')
    assert message.startswith('Updated 1 KEV records; 1 new reports')
    assert calls == [(connectors.SOURCES['cisa-kev'].url, None)]
    with session_factory() as db:
        assert db.get(KEVRecord, 'CVE-2024-12345') is not None
    (run,) = runs(session_factory)
    assert (run.source_key, run.status, run.message) == ('cisa-kev', 'success', message)


async def test_rss_sync_ingests_feed_items(
    session_factory: sessionmaker[Session], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(connectors, 'download', returning(RSS))
    assert await sync_source(session_factory, 'sans-isc') == 'Read 1 feed items; 1 new reports.'
    assert await sync_source(session_factory, 'sans-isc') == 'Read 1 feed items; 0 new reports.'
    with session_factory() as db:
        doc = db.scalar(select(Document))
        assert doc is not None
        assert doc.source_name == connectors.SOURCES['sans-isc'].name


@pytest.mark.parametrize(
    ('exc', 'expected'),
    [
        (OSError('dns down'), 'OSError: dns down'),
        (ValueError('Redirects are disabled'), 'ValueError: Redirects are disabled'),
        (ValueError('x' * 1000), 'ValueError: ' + 'x' * 350),
    ],
)
async def test_failures_are_recorded_bounded_and_raised(
    session_factory: sessionmaker[Session], monkeypatch: pytest.MonkeyPatch, exc: Exception, expected: str
) -> None:
    monkeypatch.setattr(connectors, 'download', raising(exc))
    with pytest.raises(SourceSyncError) as info:
        await sync_source(session_factory, 'ncsc')
    assert str(info.value) == expected
    assert info.value.__cause__ is exc
    (run,) = runs(session_factory)
    assert (run.status, run.message) == ('error', expected)


async def test_invalid_payload_rolls_back_and_records_error(
    session_factory: sessionmaker[Session], monkeypatch: pytest.MonkeyPatch
) -> None:
    bad = b'{"vulnerabilities": [{"cveID": "CVE-2024-12345"}, {"cveID": "INVALID"}]}'
    monkeypatch.setattr(connectors, 'download', returning(bad))
    with pytest.raises(SourceSyncError, match='Invalid CVE'):
        await sync_source(session_factory, 'cisa-kev')
    with session_factory() as db:
        assert db.get(KEVRecord, 'CVE-2024-12345') is None
    assert [r.status for r in runs(session_factory)] == ['error']


async def test_unknown_source_is_rejected(session_factory: sessionmaker[Session]) -> None:
    with pytest.raises(ValueError, match='Unknown source'):
        await sync_source(session_factory, 'https://evil.example/')
    assert runs(session_factory) == []


# --------------------------------------------------------------------------- enrichment


@pytest.mark.parametrize(
    ('provider', 'url', 'params'),
    [
        ('epss', 'https://api.first.org/data/v1/epss', {'cve': 'CVE-2024-12345'}),
        ('nvd', 'https://services.nvd.nist.gov/rest/json/cves/2.0', {'cveId': 'CVE-2024-12345'}),
    ],
)
def test_enrichment_request_mapping(provider: str, url: str, params: dict[str, str]) -> None:
    assert enrichment_request('CVE-2024-12345', provider) == (url, params)


@pytest.mark.parametrize(
    ('cve', 'provider', 'message'),
    [
        ('CVE-2024-1', 'epss', 'Invalid CVE'),
        ('cve-2024-12345', 'epss', 'Invalid CVE'),
        ('CVE-2024-12345&x=1', 'epss', 'Invalid CVE'),
        ('CVE-2024-12345', 'shodan', 'Unknown provider'),
    ],
)
def test_enrichment_request_validation(cve: str, provider: str, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        enrichment_request(cve, provider)


@pytest.fixture
def known_cve(session_factory: sessionmaker[Session]) -> str:
    with session_factory.begin() as db:
        ingest(db, DocumentInput(title='t', body='CVE-2024-12345', source_name='s'))
    return 'CVE-2024-12345'


async def test_enrichment_requires_a_known_cve(session_factory: sessionmaker[Session]) -> None:
    with pytest.raises(ValueError, match='Import a report'):
        await enrich_cve(session_factory, 'CVE-2024-12345', 'epss')


async def test_enrichment_caches_and_upserts(
    session_factory: sessionmaker[Session], monkeypatch: pytest.MonkeyPatch, known_cve: str
) -> None:
    calls: list[tuple[str, Any]] = []
    monkeypatch.setattr(connectors, 'download', returning(b'{"data": [{"epss": "0.1"}]}', calls))
    assert await enrich_cve(session_factory, known_cve, 'epss') == {'data': [{'epss': '0.1'}]}
    assert calls == [('https://api.first.org/data/v1/epss', {'cve': known_cve})]
    monkeypatch.setattr(connectors, 'download', returning(b'{"data": [{"epss": "0.9"}]}'))
    await enrich_cve(session_factory, known_cve, 'epss')
    with session_factory() as db:
        (record,) = db.scalars(select(Enrichment))
        assert (record.cve, record.provider) == (known_cve, 'epss')
        assert json.loads(record.payload) == {'data': [{'epss': '0.9'}]}


@pytest.mark.parametrize(
    ('download', 'message'),
    [
        (returning(b'<html>Rate limited</html>'), 'non-JSON'),  # Regression: was a 422 "client" error.
        (returning(b'\xff\xfe'), 'non-JSON'),
        (returning(b'[1, 2]'), 'unexpected response'),
        (raising(httpx.ConnectTimeout('slow')), 'request failed'),
        (raising(OSError('dns')), 'request failed'),
        (raising(ValueError('Source exceeds the 8 MB payload limit')), 'request failed'),
    ],
)
async def test_upstream_failures_raise_provider_error_and_store_nothing(
    session_factory: sessionmaker[Session],
    monkeypatch: pytest.MonkeyPatch,
    known_cve: str,
    download: Download,
    message: str,
) -> None:
    monkeypatch.setattr(connectors, 'download', download)
    with pytest.raises(ProviderError, match=message):
        await enrich_cve(session_factory, known_cve, 'nvd')
    with session_factory() as db:
        assert db.scalar(select(Enrichment)) is None


async def test_rss_items_are_keyed_so_publisher_edits_become_revisions(
    session_factory: sessionmaker[Session], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Found by mutation testing: no unit test synced an RSS item that has a stable identity."""

    def feed(summary: str) -> bytes:
        return (
            '<rss><channel><item><title>Advisory</title><link>https://isc.example/1</link>'
            f'<description>{summary}</description></item></channel></rss>'
        ).encode()

    monkeypatch.setattr(connectors, 'download', returning(feed('first version')))
    await sync_source(session_factory, 'sans-isc')
    monkeypatch.setattr(connectors, 'download', returning(feed('edited by the publisher')))
    assert await sync_source(session_factory, 'sans-isc') == 'Read 1 feed items; 1 new reports.'
    with session_factory() as db:
        docs = list(db.scalars(select(Document).order_by(Document.created_at)))
    assert [(d.source_key, d.external_id, d.is_current) for d in docs] == [
        ('sans-isc', 'https://isc.example/1', False),
        ('sans-isc', 'https://isc.example/1', True),
    ]


async def test_each_provider_has_its_own_cache_entry(
    session_factory: sessionmaker[Session], monkeypatch: pytest.MonkeyPatch, known_cve: str
) -> None:
    """Found by mutation testing: dropping the provider filter from the cache upsert survived."""
    monkeypatch.setattr(connectors, 'download', returning(b'{"source": "epss"}'))
    await enrich_cve(session_factory, known_cve, 'epss')
    monkeypatch.setattr(connectors, 'download', returning(b'{"source": "nvd"}'))
    await enrich_cve(session_factory, known_cve, 'nvd')
    with session_factory() as db:
        cached = {r.provider: json.loads(r.payload) for r in db.scalars(select(Enrichment))}
    assert cached == {'epss': {'source': 'epss'}, 'nvd': {'source': 'nvd'}}


async def test_long_feed_summaries_are_flagged_as_truncated(
    session_factory: sessionmaker[Session], monkeypatch: pytest.MonkeyPatch
) -> None:
    long_item = '<item><title>Long</title><link>https://isc.example/long</link><description>' + 'x' * 600
    short_item = '<item><title>Short</title><link>https://isc.example/short</link><description>brief'
    feed = f'<rss><channel>{long_item}</description></item>{short_item}</description></item></channel></rss>'
    monkeypatch.setattr(connectors, 'download', returning(feed.encode()))
    await sync_source(session_factory, 'sans-isc')
    with session_factory() as db:
        flags = {d.title: (d.truncated, d.tlp) for d in db.scalars(select(Document))}
    assert flags == {'Long': (True, 'CLEAR'), 'Short': (False, 'CLEAR')}
