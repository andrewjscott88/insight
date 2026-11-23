"""Offline operator feed contracts, scoped HTTP validators and atomic source rechecks."""

from __future__ import annotations

import asyncio
import ipaddress
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from insight import connectors, egress, jobs, operator_feed, services
from insight.models import Document, FetchState, SessionFactory, SourceRun
from insight.schemas import TLP, OperatorSourceInput

FIXTURES = Path(__file__).parents[1] / 'fixtures'
RSS = (FIXTURES / 'operator-feed-rss.xml').read_bytes()
ATOM = (FIXTURES / 'operator-feed-atom.xml').read_bytes()
URL = 'https://feeds.example.org/news'
SECRET = 'UNTRUSTED-FEED-DETAIL'


def _create(db: Session, *, enabled: bool = True, tlp: TLP = 'GREEN') -> str:
    source = services.create_operator_source(db, OperatorSourceInput(name='Test feed', url=URL, tlp=tlp))
    if enabled:
        services.set_operator_source_enabled(db, source.key, True)
    return source.key


@pytest.mark.parametrize(('payload', 'count'), [(RSS, 3), (ATOM, 2)])
async def test_source_scope_identity_labels_and_conditionals(
    session_factory: SessionFactory, monkeypatch: pytest.MonkeyPatch, payload: bytes, count: int
) -> None:
    with session_factory.begin() as db:
        first = _create(db)
        second = _create(db, tlp='AMBER')
    calls: list[str] = []

    async def download(url: str, *, validators: connectors.Validators, **options: Any) -> bytes:
        assert url == URL
        assert options['allowed_hosts'] == frozenset({'feeds.example.org'})
        assert not options['allow_private']
        calls.append(validators.etag)
        if validators.etag:
            raise connectors.NotModified()
        validators.etag = '"tag"'
        return payload

    monkeypatch.setattr(connectors, 'download', download)
    for key in [first, second]:
        assert f'{count} new reports' in await connectors.sync_source(
            session_factory, key, actor='api-key:test'
        )
        assert await connectors.sync_source(session_factory, key) == connectors.UNCHANGED
    assert calls == ['', '"tag"', '', '"tag"']
    with session_factory() as db:
        rows = list(db.scalars(select(Document)))
        assert len(rows) == count * 2
        for key, label in [(first, 'GREEN'), (second, 'AMBER')]:
            own = [doc for doc in rows if doc.source_key == key]
            assert len(own) == count
            assert {doc.tlp for doc in own} == {label}
            assert len({doc.external_id for doc in own}) == count
            assert all(doc.external_id for doc in own)
            assert db.get(FetchState, key)
        assert db.get(FetchState, URL) is None
        assert {r.status for r in db.scalars(select(SourceRun))} == {'success'}
        assert ('source.sync', 'api-key:test') in {(e.action, e.actor) for e in services.audit_events(db)}


async def test_changed_feed_revisions_and_content_hash(
    session_factory: SessionFactory, monkeypatch: pytest.MonkeyPatch
) -> None:
    with session_factory.begin() as db:
        key = _create(db)
    bodies = iter([ATOM, ATOM, ATOM.replace(b'A dated entry.', b'A revised dated entry.')])

    async def download(*args: Any, **kwargs: Any) -> bytes:
        return next(bodies)

    monkeypatch.setattr(connectors, 'download', download)
    assert '2 new reports' in await connectors.sync_source(session_factory, key)
    assert await connectors.sync_source(session_factory, key) == connectors.UNCHANGED
    assert '1 new reports' in await connectors.sync_source(session_factory, key)
    with session_factory() as db:
        rows = list(db.scalars(select(Document).where(Document.title == 'No ID')))
        assert len(rows) == 2
        assert len({doc.external_id for doc in rows}) == 1
        assert sum(doc.is_current for doc in rows) == 1
        assert all(doc.source_key == key for doc in rows)


@pytest.mark.parametrize('bad', ['malformed', 'nonfeed', 'size', 'network', '304', 'label'])
async def test_failure_is_bounded_atomic_and_retryable(
    session_factory: SessionFactory, monkeypatch: pytest.MonkeyPatch, bad: str
) -> None:
    with session_factory.begin() as db:
        key = _create(db)

    async def download(*args: Any, **kwargs: Any) -> bytes:
        if bad == 'network':
            raise OSError(SECRET)
        if bad == '304':
            raise connectors.NotModified(SECRET)
        if bad == 'malformed':
            return f'<rss><channel>{SECRET}'.encode()
        if bad == 'size':
            return b'x' * (connectors.MAX_BYTES + 1)
        if bad == 'label':
            return RSS.replace(b'A second headline.', b'TLP:RED ' + SECRET.encode())
        return f'<html>{SECRET}</html>'.encode()

    monkeypatch.setattr(connectors, 'download', download)
    with pytest.raises(connectors.SourceSyncError) as raised:
        await connectors.sync_source(session_factory, key, max_tlp='AMBER')
    assert SECRET not in str(raised.value)
    assert URL not in str(raised.value)
    with session_factory() as db:
        run = db.scalars(select(SourceRun)).one()
        assert run.status == 'error'
        assert run.message == str(raised.value)
        assert db.get(FetchState, key) is None
        assert db.scalar(select(Document)) is None


@pytest.mark.parametrize('change', ['disable', 'disable-enable', 'delete', 'rename'])
async def test_inflight_change_does_not_restore_reports_validators_or_history(
    session_factory: SessionFactory, monkeypatch: pytest.MonkeyPatch, change: str
) -> None:
    """Regression: a result fetched before a switch or edit must not revive the superseded configuration."""
    with session_factory.begin() as db:
        key = _create(db)

    async def download(*args: Any, **kwargs: Any) -> bytes:
        with session_factory.begin() as db:
            if change == 'delete':
                services.delete_operator_source(db, key)
            elif change == 'rename':
                services.update_operator_source(db, key, OperatorSourceInput(name='New', url=URL))
            else:
                services.set_operator_source_enabled(db, key, False)
                if change == 'disable-enable':
                    services.set_operator_source_enabled(db, key, True)
        return RSS

    monkeypatch.setattr(connectors, 'download', download)
    with pytest.raises(connectors.SourceSyncError):
        await connectors.sync_source(session_factory, key)
    with session_factory() as db:
        assert db.scalar(select(Document)) is None
        assert db.get(FetchState, key) is None
        assert db.scalar(select(SourceRun)) is None


async def test_sync_all_schedule_and_off_state_use_operator_choice(
    session_factory: SessionFactory, monkeypatch: pytest.MonkeyPatch
) -> None:
    with session_factory.begin() as db:
        on = _create(db)
        off = _create(db, enabled=False)
    calls: list[str] = []

    async def download(url: str, **options: Any) -> bytes:
        calls.append(url)
        return RSS

    monkeypatch.setattr(connectors, 'download', download)
    monkeypatch.setattr(connectors, 'SOURCES', {})
    with pytest.raises(connectors.SourceSwitchedOff):
        await connectors.sync_source(session_factory, off)
    assert calls == []
    results = await connectors.sync_all(session_factory)
    assert [(r.key, r.ok) for r in results] == [(on, True)]
    assert calls == [URL]
    assert 'No scheduled syncs' in jobs.describe_schedules(session_factory)
    at = datetime.now(UTC)
    with session_factory.begin() as db:
        services.set_schedule(db, on, 60, at=at)
    assert jobs.describe_schedules(session_factory) == f'Scheduled syncs: {on} every 60 min'
    assert await jobs.run_due(session_factory, asyncio.Lock(), clock=lambda: at) == 1
    assert calls == [URL, URL]
    with session_factory() as db:
        assert ('source.sync', 'schedule') in {(e.action, e.actor) for e in services.audit_events(db)}


@pytest.mark.parametrize('address', ['127.0.0.1', '169.254.169.254', '100.100.100.200', 'fd00:ec2::254'])
async def test_metadata_and_loopback_stay_blocked_with_private_network(
    monkeypatch: pytest.MonkeyPatch, address: str
) -> None:
    async def resolve(host: str, port: int) -> list[egress.IPAddress]:
        return [ipaddress.ip_address(address)]

    monkeypatch.setattr(egress, 'resolve', resolve)
    with pytest.raises(connectors.NonPublicDestination):
        await connectors.download(URL, allowed_hosts=frozenset({'feeds.example.org'}), allow_private=True)


async def test_operator_private_network_pin_and_redirect_boundary(monkeypatch: pytest.MonkeyPatch) -> None:
    async def resolve(host: str, port: int) -> list[egress.IPAddress]:
        assert (host, port) == ('feeds.example.org', 443)
        return [ipaddress.ip_address('10.22.33.44')]

    sent: list[httpx.Request] = []

    def redirect(request: httpx.Request) -> httpx.Response:
        sent.append(request)
        return httpx.Response(302, headers={'Location': 'https://other.example.org/secret'})

    monkeypatch.setattr(egress, 'resolve', resolve)
    monkeypatch.delenv('INSIGHT_SOURCES_PRIVATE_NETWORK', raising=False)
    hosts = frozenset({'feeds.example.org'})
    with pytest.raises(connectors.NonPublicDestination):
        await connectors.download(URL, allowed_hosts=hosts, allow_private=operator_feed.private_network())
    assert sent == []
    monkeypatch.setenv('INSIGHT_SOURCES_PRIVATE_NETWORK', 'on')
    with pytest.raises(ValueError, match='Redirects'):
        await connectors.download(
            URL,
            allowed_hosts=hosts,
            allow_private=operator_feed.private_network(),
            transport=httpx.MockTransport(redirect),
        )
    assert [r.url.host for r in sent] == ['10.22.33.44']
    assert sent[0].headers['Host'] == 'feeds.example.org'
    assert sent[0].extensions['sni_hostname'] == 'feeds.example.org'
    monkeypatch.setenv('INSIGHT_SOURCES_PRIVATE_NETWORK', 'unknown')
    with pytest.raises(ValueError, match='on or off'):
        operator_feed.private_network()


async def test_lowering_source_floor_preserves_existing_labels_and_imports_new_items(
    session_factory: SessionFactory, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Regression: retaining an old item's stricter label must not block unrelated incoming reports."""
    with session_factory.begin() as db:
        key = _create(db, tlp='AMBER')
    first = b'<item><guid>old</guid><title>Old report</title></item>'
    more = b'<item><guid>new</guid><title>New report</title></item>'
    bodies = iter(first + rest for rest in (b'', more))

    async def download(*args: Any, **kwargs: Any) -> bytes:
        return b'<rss><channel>' + next(bodies) + b'</channel></rss>'

    monkeypatch.setattr(connectors, 'download', download)
    await connectors.sync_source(session_factory, key)
    with session_factory.begin() as db:
        services.update_operator_source(db, key, OperatorSourceInput(name='Test feed', url=URL, tlp='GREEN'))
    assert '1 new reports' in await connectors.sync_source(session_factory, key)
    with session_factory() as db:
        labels = {doc.title: doc.tlp for doc in db.scalars(select(Document))}
        assert labels == {'Old report': 'AMBER', 'New report': 'GREEN'}


async def test_late_concurrent_response_cannot_rewind_newer_source_state(
    session_factory: SessionFactory, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Regression: two reads starting from one cursor must not commit a late, obsolete response last."""
    with session_factory.begin() as db:
        key = _create(db)
    entered, release = asyncio.Event(), asyncio.Event()

    async def download(*args: Any, validators: connectors.Validators, **kwargs: Any) -> bytes:
        if not entered.is_set():
            entered.set()
            await release.wait()
            validators.etag = '"old"'
            return RSS
        validators.etag = '"new"'
        return ATOM

    monkeypatch.setattr(connectors, 'download', download)
    earlier = asyncio.create_task(connectors.sync_source(session_factory, key))
    try:
        await entered.wait()
        assert '2 new reports' in await connectors.sync_source(session_factory, key)
    finally:
        release.set()
    with pytest.raises(connectors.SourceSyncError, match='changed'):
        await earlier
    with session_factory() as db:
        state = db.get(FetchState, key)
        assert state
        assert state.etag == '"new"'
        assert {doc.title for doc in db.scalars(select(Document))} == {'Analyst notice', 'No ID'}


async def test_scheduled_sync_honours_the_running_instances_tlp_ceiling(
    session_factory: SessionFactory, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Regression: a runner using explicit app settings must not fall back to a wider process setting."""
    at = datetime.now(UTC)
    with session_factory.begin() as db:
        key = _create(db, tlp='AMBER')
        services.set_schedule(db, key, 60, at=at)
    monkeypatch.setenv('INSIGHT_MAX_TLP', 'RED')

    async def download(*args: Any, **kwargs: Any) -> bytes:
        pytest.fail('A source above the running instance limit must never be contacted')

    monkeypatch.setattr(connectors, 'download', download)
    assert await jobs.run_due(session_factory, asyncio.Lock(), clock=lambda: at, max_tlp='GREEN') == 1
    with session_factory() as db:
        assert db.scalar(select(Document)) is None
        assert db.scalar(select(SourceRun)) is None
