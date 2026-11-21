"""Keyed community IOC feeds through the same switches, transport and ingest path as other sources."""

from __future__ import annotations

import ipaddress
import json
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit

import httpx
import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from insight import connectors, egress, services
from insight.models import Document, Entity, SourceRun

HASH = 'a3' * 32
KEY_ENV = 'INSIGHT_ABUSECH_AUTH_KEY'
FEEDS = {
    'urlhaus': ({'urls': [{'id': '10', 'url': 'https://example.test/path', 'url_status': 'online'}]}, 'url'),
    'threatfox': ({'data': [{'id': '19', 'ioc_type': 'ip:port', 'ioc': '192.0.2.5:443'}]}, 'ip'),
    'malwarebazaar': ({'data': [{'sha256_hash': HASH}]}, 'sha256'),
}


def switch_on(factory: sessionmaker[Session], key: str) -> None:
    with factory.begin() as db:
        services.set_source_switch(db, key, True, at=datetime.now(UTC))


@pytest.mark.parametrize('key', FEEDS)
async def test_keyed_source_uses_only_pinned_metadata_endpoint_and_deduplicates(
    session_factory: sessionmaker[Session], monkeypatch: pytest.MonkeyPatch, key: str
) -> None:
    source = connectors.SOURCES[key]
    upstream, expected_kind = FEEDS[key]
    seen: list[httpx.Request] = []
    endpoint = urlsplit(source.fetch_urls[0])

    def respond(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        assert request.url.host == '8.8.8.8'  # DNS result used by the pinned transport below.
        assert request.url.path == endpoint.path
        assert request.headers['host'] == request.extensions['sni_hostname'] == endpoint.hostname
        assert request.headers['Auth-Key'] == 'unit-test-token'
        assert 'unit-test-token' not in str(request.url)
        if key == 'urlhaus':
            assert request.method == 'GET'
            assert len(seen) == 1 or request.headers['If-None-Match'] == 'test-tag'
        elif key == 'threatfox':
            assert request.method == 'POST'
            assert json.loads(request.content) == {'query': 'get_iocs', 'days': 1}
            assert 'If-None-Match' not in request.headers
        else:
            assert request.method == 'POST'
            assert request.headers['Content-Type'] == 'application/x-www-form-urlencoded'
            assert request.content == b'query=get_recent&selector=time'
        return httpx.Response(200, json={'query_status': 'ok', **upstream}, headers={'ETag': 'test-tag'})

    download = connectors.download

    async def offline(url: str, **kwargs: Any) -> bytes:
        return await download(url, transport=httpx.MockTransport(respond), **kwargs)

    async def resolve(hostname: str, port: int) -> list[egress.IPAddress]:
        assert hostname == endpoint.hostname
        assert port == 443
        return [ipaddress.ip_address('8.8.8.8')]

    monkeypatch.setattr(connectors, 'download', offline)
    monkeypatch.setattr(egress, 'resolve', resolve)
    monkeypatch.setenv(KEY_ENV, 'unit-test-token')
    with pytest.raises(connectors.SourceSwitchedOff):
        await connectors.sync_source(session_factory, key)
    assert not seen
    switch_on(session_factory, key)
    assert '1 new reports' in await connectors.sync_source(session_factory, key)
    assert await connectors.sync_source(session_factory, key) == connectors.UNCHANGED
    assert len(seen) == 2
    with session_factory() as db:
        (doc,) = db.scalars(select(Document)).all()
        assert doc.source_key == key
        assert doc.tlp == 'CLEAR'
        assert doc.is_current
        assert doc.external_id in ('10', '19', HASH)
        assert expected_kind in db.scalars(select(Entity.kind)).all()


async def test_metadata_change_creates_a_revision(
    session_factory: sessionmaker[Session], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(KEY_ENV, 'unit-test-token')
    switch_on(session_factory, 'urlhaus')
    statuses = iter(['online', 'offline'])

    async def fetch(url: str, **kwargs: Any) -> bytes:
        record = {'id': '10', 'url': 'https://example.test/path', 'url_status': next(statuses)}
        return json.dumps({'query_status': 'ok', 'urls': [record]}).encode()

    monkeypatch.setattr(connectors, 'download', fetch)
    for _ in range(2):
        await connectors.sync_source(session_factory, 'urlhaus')
    with session_factory() as db:
        earlier, current = db.scalars(select(Document).order_by(Document.is_current)).all()
        assert current.supersedes_id == earlier.id
        assert current.external_id == earlier.external_id


@pytest.mark.parametrize('token', ['', 'TEST-SECRET\nextra'])
async def test_missing_or_malformed_key_fails_before_fetch(
    session_factory: sessionmaker[Session], monkeypatch: pytest.MonkeyPatch, token: str
) -> None:
    switch_on(session_factory, 'urlhaus')
    monkeypatch.setenv(KEY_ENV, token)
    with pytest.raises(connectors.SourceSyncError, match=KEY_ENV):
        await connectors.sync_source(session_factory, 'urlhaus')
    with session_factory() as db:
        (run,) = db.scalars(select(SourceRun)).all()
        assert run.status == 'error'
        assert 'TEST-SECRET' not in run.message


async def test_failed_keyed_request_never_records_untrusted_upstream_error_text(
    session_factory: sessionmaker[Session], monkeypatch: pytest.MonkeyPatch
) -> None:
    switch_on(session_factory, 'threatfox')
    monkeypatch.setenv(KEY_ENV, 'TEST-SECRET')

    async def fetch(url: str, **kwargs: Any) -> bytes:
        raise httpx.HTTPStatusError(
            'untrusted TEST-SECRET', request=httpx.Request('GET', url), response=httpx.Response(403)
        )

    monkeypatch.setattr(connectors, 'download', fetch)
    with pytest.raises(connectors.SourceSyncError, match='ThreatFox answered HTTP 403'):
        await connectors.sync_source(session_factory, 'threatfox')
    with session_factory() as db:
        (run,) = db.scalars(select(SourceRun)).all()
        assert run.status == 'error'
        assert 'TEST-SECRET' not in run.message
