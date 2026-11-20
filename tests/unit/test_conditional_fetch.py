"""Fetching less: conditional requests, unchanged payloads and when a fetch is remembered (ADR 0018).

A scheduled sync of a feed that has not changed should cost one small request and write nothing but its run.
"""

from __future__ import annotations

import json
import socket
from typing import Any

import httpx
import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from insight import __version__, connectors
from insight.connectors import UNCHANGED, NotModified, Validators, download, sync_source
from insight.models import Document, FetchState, SourceRun

KEV_URL = connectors.SOURCES['cisa-kev'].url
SANS_URL = connectors.SOURCES['sans-isc'].url
RSS = b'<rss><channel><item><title>Advisory CVE-2024-9999</title></item></channel></rss>'
RSS2 = b'<rss><channel><item><title>Advisory CVE-2024-8888</title></item></channel></rss>'
KEV = json.dumps({'vulnerabilities': [{'cveID': 'CVE-2024-12345', 'dateAdded': '2025-01-01'}]}).encode()


@pytest.fixture
def public_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_getaddrinfo(host: str, port: int, *_: Any, **__: Any) -> list[Any]:
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('8.8.8.8', port))]

    monkeypatch.setattr(socket, 'getaddrinfo', fake_getaddrinfo)


# --------------------------------------------------------------------------- download()


@pytest.mark.usefixtures('public_dns')
async def test_validators_are_sent_and_refreshed_and_304_means_not_modified() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if request.headers.get('if-none-match') == '"v2"':
            return httpx.Response(304)
        return httpx.Response(
            200, content=b'data', headers={'ETag': '"v2"', 'Last-Modified': 'Fri, 20 Nov 2026 09:00:00 GMT'}
        )

    validators = Validators(etag='"v1"', last_modified='Thu, 19 Nov 2026 09:00:00 GMT')
    assert await download(KEV_URL, validators=validators, transport=httpx.MockTransport(handler)) == b'data'
    assert seen[0].headers['if-none-match'] == '"v1"'
    assert seen[0].headers['if-modified-since'] == 'Thu, 19 Nov 2026 09:00:00 GMT'
    assert validators == Validators('"v2"', 'Fri, 20 Nov 2026 09:00:00 GMT')
    with pytest.raises(NotModified):
        await download(KEV_URL, validators=validators, transport=httpx.MockTransport(handler))


@pytest.mark.usefixtures('public_dns')
async def test_a_plain_download_sends_no_validators_and_treats_304_as_an_error() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(304)

    with pytest.raises(ValueError, match='304 Not Modified to a request that asked for no validation'):
        await download(KEV_URL, transport=httpx.MockTransport(handler))
    assert 'if-none-match' not in seen[0].headers
    assert 'if-modified-since' not in seen[0].headers


@pytest.mark.usefixtures('public_dns')
@pytest.mark.parametrize('etag', ['x' * 201, '"bad\x7fvalue"'])
async def test_unusable_validators_from_a_server_are_not_kept(etag: str) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b'data', headers=[(b'ETag', etag.encode('latin-1'))])

    validators = Validators()
    await download(KEV_URL, validators=validators, transport=httpx.MockTransport(handler))
    assert validators.etag == ''


# --------------------------------------------------------------------------- sync_source()


class Server:
    """A fake publisher that honours ETags (or ignores them) and counts full downloads."""

    def __init__(self, files: dict[str, bytes], *, honours_etags: bool = True) -> None:
        self.files, self.honours, self.full = files, honours_etags, 0

    async def __call__(
        self, url: str, params: Any = None, *, validators: Validators | None = None, **_: Any
    ) -> bytes:
        if (body := self.files.get(url)) is None:
            raise OSError(f'404 for {url}')
        etag = f'"{hash(body)}"'
        if self.honours and validators is not None and validators.etag == etag:
            raise NotModified(url)
        if validators is not None:
            validators.etag = etag
        self.full += 1
        return body


def runs(factory: sessionmaker[Session]) -> list[str]:
    with factory() as db:
        return [r.message for r in db.scalars(select(SourceRun).order_by(SourceRun.created_at))]


@pytest.mark.parametrize('honours_etags', [True, False])
async def test_an_unchanged_feed_is_not_read_again(
    session_factory: sessionmaker[Session], monkeypatch: pytest.MonkeyPatch, honours_etags: bool
) -> None:
    server = Server({SANS_URL: RSS}, honours_etags=honours_etags)
    monkeypatch.setattr(connectors, 'download', server)
    assert await sync_source(session_factory, 'sans-isc') == 'Read 1 feed items; 1 new reports.'
    assert await sync_source(session_factory, 'sans-isc') == UNCHANGED
    server.files[SANS_URL] = RSS2
    assert await sync_source(session_factory, 'sans-isc') == 'Read 1 feed items; 1 new reports.'
    # With ETags, an unchanged feed is a 304; without, a full download whose hash matches.
    assert server.full == (2 if honours_etags else 3)
    assert runs(session_factory) == [
        'Read 1 feed items; 1 new reports.',
        UNCHANGED,
        'Read 1 feed items; 1 new reports.',
    ]


async def test_kev_unchanged_keeps_every_record_untouched(
    session_factory: sessionmaker[Session], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(connectors, 'download', Server({KEV_URL: KEV}))
    await sync_source(session_factory, 'cisa-kev')
    with session_factory() as db:
        before = [(d.id, d.created_at) for d in db.scalars(select(Document))]
    assert await sync_source(session_factory, 'cisa-kev') == UNCHANGED
    with session_factory() as db:
        assert [(d.id, d.created_at) for d in db.scalars(select(Document))] == before
        state = db.get(FetchState, KEV_URL)
        assert state is not None
        assert (state.insight_version, len(state.payload_sha256)) == (__version__, 64)


async def test_a_new_release_reads_every_source_once_more(
    session_factory: sessionmaker[Session], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Its parsing may have changed, so what it would make of an unchanged feed may differ."""
    server = Server({SANS_URL: RSS})
    monkeypatch.setattr(connectors, 'download', server)
    await sync_source(session_factory, 'sans-isc')
    monkeypatch.setattr(connectors, '__version__', '99.0.0')
    assert await sync_source(session_factory, 'sans-isc') == 'Read 1 feed items; 0 new reports.'
    assert await sync_source(session_factory, 'sans-isc') == UNCHANGED
    assert server.full == 2


async def test_a_failed_sync_is_not_remembered(
    session_factory: sessionmaker[Session], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(connectors, 'download', Server({KEV_URL: b'{"vulnerabilities": "not a list"}'}))
    with pytest.raises(connectors.SourceSyncError):
        await sync_source(session_factory, 'cisa-kev')
    with session_factory() as db:
        assert db.scalar(select(FetchState)) is None  # so the next sync reads it again


# --------------------------------------------------------------------------- CISA advisories (two indexes)

OT_INDEX, IT_INDEX = connectors.SOURCES['cisa-csaf'].indexes


def csaf_doc(advisory_id: str) -> bytes:
    document = {
        'csaf_version': '2.0',
        'title': f'Product {advisory_id}',
        'tracking': {'id': advisory_id, 'initial_release_date': '2026-11-19'},
        'distribution': {'tlp': {'label': 'WHITE'}},
    }
    return json.dumps({'document': document}).encode()


async def test_csaf_skips_when_both_indexes_are_unchanged_and_reuses_the_changed_one(
    session_factory: sessionmaker[Session], monkeypatch: pytest.MonkeyPatch
) -> None:
    files = {
        OT_INDEX: b'"2026/icsa-26-323-01.json","2026-11-19T06:00:00Z"\n',
        IT_INDEX: b'2026/va-26-317-01.json,2026-11-13T16:45:20Z\n',
        connectors.CSAF_BASE + 'OT/white/2026/icsa-26-323-01.json': csaf_doc('ICSA-26-323-01'),
        connectors.CSAF_BASE + 'IT/white/2026/va-26-317-01.json': csaf_doc('VA-26-317-01'),
        connectors.CSAF_BASE + 'OT/white/2026/icsa-26-324-01.json': csaf_doc('ICSA-26-324-01'),
    }
    server = Server(files)
    monkeypatch.setattr(connectors, 'download', server)
    assert await sync_source(session_factory, 'cisa-csaf') == 'Read 2 advisories; 2 new reports.'
    assert await sync_source(session_factory, 'cisa-csaf') == UNCHANGED
    full = server.full
    files[OT_INDEX] += b'"2026/icsa-26-324-01.json","2026-11-20T06:00:00Z"\n'
    assert await sync_source(session_factory, 'cisa-csaf') == 'Read 3 advisories; 1 new reports.'
    # The changed OT index is read once (not again by fetch_csaf); the unchanged IT index is downloaded in
    # full because a 304 has no body; then the three advisories.
    assert server.full - full == 1 + 1 + 3


async def test_csaf_keeps_reading_the_index_while_advisories_are_missing(
    session_factory: sessionmaker[Session], monkeypatch: pytest.MonkeyPatch
) -> None:
    files = {
        OT_INDEX: (
            b'"2026/icsa-26-323-01.json","2026-11-19T06:00:00Z"\n'
            b'"2026/icsa-26-322-01.json","2026-11-18T06:00:00Z"\n'
        ),
        IT_INDEX: b'',
        connectors.CSAF_BASE + 'OT/white/2026/icsa-26-323-01.json': csaf_doc('ICSA-26-323-01'),
    }
    monkeypatch.setattr(connectors, 'download', Server(files))
    assert (
        await sync_source(session_factory, 'cisa-csaf')
        == 'Read 1 advisories; 1 new reports. 1 could not be read.'
    )
    files[connectors.CSAF_BASE + 'OT/white/2026/icsa-26-322-01.json'] = csaf_doc('ICSA-26-322-01')
    assert await sync_source(session_factory, 'cisa-csaf') == 'Read 2 advisories; 1 new reports.'
    assert await sync_source(session_factory, 'cisa-csaf') == UNCHANGED
