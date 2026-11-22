"""Automatic and manual CVE lookups (TIP 1.2, ADR 0023): one throttle per provider (review B2), which CVEs
are due, the switches, and the TLP check on cached scores. The network is replaced by fakes."""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from insight import connectors, jobs, lookups, services
from insight.connectors import ProviderError, fetch_provider_json
from insight.lookups import THROTTLES, LookupThrottled, Throttle, look_up_due, request_lookup
from insight.models import AuditEvent, Document, Enrichment, Job, LookupFailure, Observation
from insight.schemas import DocumentInput
from insight.services import CVE_LOOKUP, ingest
from insight.services.common import stamp

NOW = datetime(2026, 11, 21, 12, 0, tzinfo=UTC)


class FakeClock:
    def __init__(self) -> None:
        self.now = 100.0

    def __call__(self) -> float:
        return self.now


def report(
    factory: sessionmaker[Session], body: str, *, tlp: str = 'CLEAR', created: datetime | None = None
) -> str:
    with factory.begin() as db:
        ingest(db, DocumentInput(title=body[:40], body=body, source_name='s', tlp=tlp))
        doc = db.scalars(select(Document).order_by(Document.created_at.desc())).first()
        assert doc is not None
        if created is not None:
            doc.created_at = stamp(created)
        return doc.id


def cache(factory: sessionmaker[Session], cve: str, provider: str, payload: Any, at: datetime) -> None:
    with factory.begin() as db:
        db.add(Enrichment(cve=cve, provider=provider, payload=json.dumps(payload), fetched_at=stamp(at)))


def switch_on(factory: sessionmaker[Session], *providers: str) -> None:
    with factory.begin() as db:
        for provider in providers:
            services.set_lookup_switch(db, provider, True, at=NOW)


def cached(factory: sessionmaker[Session]) -> dict[tuple[str, str], Any]:
    with factory() as db:
        return {(e.cve, e.provider): json.loads(e.payload) for e in db.scalars(select(Enrichment))}


class FakeProvider:
    """Answers like NVD or EPSS and records each request's parameters and headers."""

    def __init__(
        self, answers: dict[str, Any] | None = None, fail_on: str = '', status: dict[str, int] | None = None
    ) -> None:
        self.calls: list[tuple[str, dict[str, str], dict[str, str]]] = []
        self.answers = answers or {}
        self.fail_on = fail_on
        #: CVE -> the HTTP status NVD answers with for it.
        self.status = status or {}

    async def __call__(self, url: str, params: Any = None, headers: Any = None, **_: Any) -> bytes:
        self.calls.append((url, dict(params or {}), dict(headers or {})))
        if 'epss' in url:
            wanted = params['cve'].split(',')
            return json.dumps(
                {'status': 'OK', 'data': [self.answers[c] for c in wanted if c in self.answers]}
            ).encode()
        if params['cveId'] == self.fail_on:
            raise httpx.ConnectError('offline')
        if code := self.status.get(params['cveId']):
            response = httpx.Response(code, request=httpx.Request('GET', url))
            raise httpx.HTTPStatusError('refused', request=response.request, response=response)
        return json.dumps({'vulnerabilities': [{'cve': {'id': params['cveId']}}]}).encode()


@pytest.fixture
def sleeps(monkeypatch: pytest.MonkeyPatch) -> list[float]:
    """Record the throttle's waits instead of waiting."""
    waited: list[float] = []

    async def fake_sleep(seconds: float) -> None:
        waited.append(seconds)

    monkeypatch.setattr('insight.lookups.asyncio.sleep', fake_sleep)
    return waited


# --------------------------------------------------------------------------- the throttle (B2)


def test_try_acquire_takes_the_window_or_says_how_long_to_wait() -> None:
    clock = FakeClock()
    throttle = Throttle(6.5, clock)
    assert throttle.try_acquire() == 0
    clock.now += 2
    assert throttle.try_acquire() == pytest.approx(4.5)
    assert throttle.wait_time() == pytest.approx(4.5)  # A refused request took nothing.
    clock.now += 4.5
    assert throttle.try_acquire() == 0
    throttle.reset()
    assert throttle.wait_time() == 0


async def test_acquire_reserves_slots_so_waiting_callers_queue(sleeps: list[float]) -> None:
    clock = FakeClock()
    throttle = Throttle(6.5, clock)
    await throttle.acquire()
    await throttle.acquire()
    await throttle.acquire()
    assert sleeps == [pytest.approx(6.5), pytest.approx(13.0)]
    assert throttle.try_acquire() == pytest.approx(19.5)  # A person's lookup waits behind the queue.


def test_nvd_key_shortens_the_interval(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv('INSIGHT_NVD_API_KEY', raising=False)
    assert lookups.nvd_interval() == 6.5
    monkeypatch.setenv('INSIGHT_NVD_API_KEY', '  key  ')
    assert lookups.nvd_interval() == 0.7
    assert connectors.provider_headers('nvd') == {'apiKey': 'key'}
    assert connectors.provider_headers('epss') == {}


# --------------------------------------------------------------------------- a person's lookup


async def test_request_lookup_checks_first_and_throttles_per_provider(
    session_factory: sessionmaker[Session], monkeypatch: pytest.MonkeyPatch
) -> None:
    provider = FakeProvider({'CVE-2024-1111': {'cve': 'CVE-2024-1111', 'epss': '0.2'}})
    monkeypatch.setattr(connectors, 'download', provider)
    with pytest.raises(ValueError, match='Import a report'):
        await request_lookup(session_factory, 'CVE-2024-1111', 'nvd')
    assert THROTTLES['nvd'].wait_time() == 0  # A refused request uses no window.
    report(session_factory, 'Mentions CVE-2024-1111', tlp='RED')  # Manual lookups work at any label.
    await request_lookup(session_factory, 'CVE-2024-1111', 'nvd')
    with pytest.raises(LookupThrottled, match=r'Wait 7 more second\(s\) before the next lookup at NIST NVD'):
        await request_lookup(session_factory, 'CVE-2024-1111', 'nvd')
    await request_lookup(session_factory, 'CVE-2024-1111', 'epss')
    assert len(provider.calls) == 2
    assert set(cached(session_factory)) == {('CVE-2024-1111', 'nvd'), ('CVE-2024-1111', 'epss')}


# --------------------------------------------------------------------------- automatic lookups


async def test_epss_batch_caches_every_cve_including_those_without_a_score(
    session_factory: sessionmaker[Session], monkeypatch: pytest.MonkeyPatch, sleeps: list[float]
) -> None:
    report(session_factory, 'CVE-2024-1111 and CVE-2024-2222', created=NOW - timedelta(days=1))
    provider = FakeProvider({'CVE-2024-1111': {'cve': 'CVE-2024-1111', 'epss': '0.5', 'percentile': '0.9'}})
    monkeypatch.setattr(connectors, 'download', provider)
    message = await look_up_due(session_factory, 'epss')
    assert message == 'Looked up 2 CVEs at FIRST EPSS.'
    assert [params for _, params, _ in provider.calls] == [{'cve': 'CVE-2024-1111,CVE-2024-2222'}]
    stored = cached(session_factory)
    assert stored[('CVE-2024-1111', 'epss')] == {
        'status': 'OK',
        'total': 1,
        'data': [{'cve': 'CVE-2024-1111', 'epss': '0.5', 'percentile': '0.9'}],
    }
    assert stored[('CVE-2024-2222', 'epss')] == {'status': 'OK', 'total': 0, 'data': []}
    assert await look_up_due(session_factory, 'epss') == 'No CVEs due at FIRST EPSS.'
    assert len(provider.calls) == 1


async def test_nvd_looks_up_one_cve_at_a_time_through_the_throttle(
    session_factory: sessionmaker[Session], monkeypatch: pytest.MonkeyPatch, sleeps: list[float]
) -> None:
    report(session_factory, 'CVE-2024-1111 CVE-2024-2222 CVE-2024-3333')
    provider = FakeProvider()
    monkeypatch.setattr(connectors, 'download', provider)
    assert await look_up_due(session_factory, 'nvd') == 'Looked up 3 CVEs at NIST NVD.'
    assert sorted(params['cveId'] for _, params, _ in provider.calls) == [
        'CVE-2024-1111',
        'CVE-2024-2222',
        'CVE-2024-3333',
    ]
    assert all(headers == {} for _, _, headers in provider.calls)  # No key set: no key header.
    assert len(sleeps) == 2  # The first request goes at once; the next two wait their turn.
    assert len(cached(session_factory)) == 3


async def test_nvd_sends_the_key_header_and_keeps_answers_from_before_a_failure(
    session_factory: sessionmaker[Session], monkeypatch: pytest.MonkeyPatch, sleeps: list[float]
) -> None:
    monkeypatch.setenv('INSIGHT_NVD_API_KEY', 'secret-key')
    report(session_factory, 'CVE-2024-1111', created=NOW - timedelta(days=1))
    report(session_factory, 'CVE-2024-2222', created=NOW - timedelta(days=2))
    provider = FakeProvider(fail_on='CVE-2024-2222')
    monkeypatch.setattr(connectors, 'download', provider)
    with pytest.raises(ProviderError, match='NVD request failed: ConnectError'):
        await look_up_due(session_factory, 'nvd')
    assert [headers for _, _, headers in provider.calls] == [{'apiKey': 'secret-key'}] * 2
    assert set(cached(session_factory)) == {('CVE-2024-1111', 'nvd')}  # Newest first, cached at once.


async def test_look_up_due_refuses_an_unknown_provider(session_factory: sessionmaker[Session]) -> None:
    with pytest.raises(ValueError, match='Unknown provider'):
        await look_up_due(session_factory, 'shodan')


@pytest.mark.parametrize(('key', 'hint'), [('', ''), ('secret-key', ' (check INSIGHT_NVD_API_KEY)')])
async def test_provider_refusal_names_the_key_setting_never_the_key(
    monkeypatch: pytest.MonkeyPatch, key: str, hint: str
) -> None:
    monkeypatch.setenv('INSIGHT_NVD_API_KEY', key)
    response = httpx.Response(404, request=httpx.Request('GET', 'https://services.nvd.nist.gov/'))

    async def refused(url: str, params: Any = None, **_: Any) -> bytes:
        raise httpx.HTTPStatusError('refused', request=response.request, response=response)

    monkeypatch.setattr(connectors, 'download', refused)
    with pytest.raises(ProviderError) as caught:
        await fetch_provider_json('nvd', {'cveId': 'CVE-2024-1111'})
    assert str(caught.value) == f'NVD answered HTTP 404{hint}'
    assert 'secret' not in str(caught.value)


# --------------------------------------------------------------------------- which CVEs are due


def test_only_cves_in_current_clear_or_green_reports_are_due_newest_first(
    session_factory: sessionmaker[Session],
) -> None:
    report(session_factory, 'Old CVE-2024-1111', created=NOW - timedelta(days=9))
    report(session_factory, 'New CVE-2024-2222', tlp='GREEN', created=NOW - timedelta(days=1))
    report(session_factory, 'Middle CVE-2024-3333 and CVE-2024-1111', created=NOW - timedelta(days=5))
    report(session_factory, 'Private CVE-2024-4444', tlp='AMBER')
    report(session_factory, 'Secret CVE-2024-5555', tlp='RED')
    rejected = report(session_factory, 'Wrong CVE-2024-6666')
    with session_factory.begin() as db:
        for obs in db.scalars(select(Observation).where(Observation.document_id == rejected)):
            obs.review_status = 'rejected'
    with session_factory() as db:
        due = services.cves_to_look_up(db, 'nvd', at=NOW, limit=10)
        assert due == ['CVE-2024-2222', 'CVE-2024-1111', 'CVE-2024-3333']
        assert services.cves_to_look_up(db, 'nvd', at=NOW, limit=1) == ['CVE-2024-2222']


def test_cached_answers_are_fresh_for_a_week_at_epss_and_a_month_at_nvd(
    session_factory: sessionmaker[Session],
) -> None:
    report(session_factory, 'CVE-2024-1111')
    cache(session_factory, 'CVE-2024-1111', 'epss', {}, NOW - timedelta(days=6))
    cache(session_factory, 'CVE-2024-1111', 'nvd', {}, NOW - timedelta(days=29))
    with session_factory() as db:
        assert services.cves_to_look_up(db, 'epss', at=NOW, limit=10) == []
        assert services.cves_to_look_up(db, 'nvd', at=NOW, limit=10) == []
        later = NOW + timedelta(days=2)
        assert services.cves_to_look_up(db, 'epss', at=later, limit=10) == ['CVE-2024-1111']
        assert services.cves_to_look_up(db, 'nvd', at=later, limit=10) == ['CVE-2024-1111']
        assert services.lookup_backlog(db, at=later) == {'epss': 1, 'nvd': 1, 'vulncheck': 1}


def test_switches_start_off_are_audited_and_refuse_unknown_providers(
    session_factory: sessionmaker[Session],
) -> None:
    with session_factory.begin() as db:
        assert services.lookup_switches(db) == {'epss': False, 'nvd': False, 'vulncheck': False}
        services.set_lookup_switch(db, 'nvd', True, at=NOW)
        services.set_lookup_switch(db, 'nvd', False, at=NOW)
        services.set_lookup_switch(db, 'epss', True, at=NOW)
        with pytest.raises(ValueError, match='Unknown provider'):
            services.set_lookup_switch(db, 'shodan', True, at=NOW)
    with session_factory() as db:
        assert services.lookup_switches(db) == {'epss': True, 'nvd': False, 'vulncheck': False}
        actions = sorted((e.action, e.object_id) for e in db.scalars(select(AuditEvent)))
        assert actions == [('lookup.off', 'nvd'), ('lookup.on', 'epss'), ('lookup.on', 'nvd')]
        assert services.source_switches(db) == {}  # Lookup switches are not news sources.


def test_jobs_are_queued_only_when_switched_on_due_and_not_paused(
    session_factory: sessionmaker[Session],
) -> None:
    with session_factory.begin() as db:
        assert services.enqueue_due_lookups(db, at=NOW) == []  # Off, and nothing due.
    report(session_factory, 'CVE-2024-1111')
    with session_factory.begin() as db:
        assert services.enqueue_due_lookups(db, at=NOW) == []  # Still off.
    switch_on(session_factory, 'epss', 'nvd')
    with session_factory.begin() as db:
        assert services.enqueue_due_lookups(db, at=NOW) == ['epss', 'nvd']
        assert services.enqueue_due_lookups(db, at=NOW) == ['epss', 'nvd']  # The queued jobs are reused.
    with session_factory.begin() as db:
        jobs_now = list(db.scalars(select(Job).where(Job.kind == CVE_LOOKUP)))
        assert sorted(j.key for j in jobs_now) == ['epss', 'nvd']
        nvd = next(j for j in jobs_now if j.key == 'nvd')
        nvd.status, nvd.finished_at = 'failed', stamp(NOW - timedelta(minutes=30))
        epss = next(j for j in jobs_now if j.key == 'epss')
        epss.status, epss.finished_at = 'succeeded', stamp(NOW)
    with session_factory.begin() as db:
        assert services.enqueue_due_lookups(db, at=NOW) == ['epss']  # NVD pauses for an hour.
        assert services.enqueue_due_lookups(db, at=NOW + timedelta(minutes=31)) == ['epss', 'nvd']


async def test_the_job_runner_runs_a_lookup(
    session_factory: sessionmaker[Session], monkeypatch: pytest.MonkeyPatch
) -> None:
    report(session_factory, 'CVE-2024-1111')
    switch_on(session_factory, 'epss')
    monkeypatch.setattr(
        connectors, 'download', FakeProvider({'CVE-2024-1111': {'cve': 'CVE-2024-1111', 'epss': '0.1'}})
    )
    assert await jobs.run_due(session_factory, asyncio.Lock(), clock=lambda: datetime.now(UTC)) == 1
    with session_factory() as db:
        (job,) = db.scalars(select(Job).where(Job.kind == CVE_LOOKUP))
        assert (job.key, job.status, job.message) == ('epss', 'succeeded', 'Looked up 1 CVE at FIRST EPSS.')
    assert set(cached(session_factory)) == {('CVE-2024-1111', 'epss')}


# --------------------------------------------------------------------------- VulnCheck KEV (TIP 3.3)


class FakeVulnCheck:
    """Answers like VulnCheck's ``/v3/index/vulncheck-kev?cve=`` and records each request."""

    def __init__(self, listed: set[str]) -> None:
        self.listed = listed
        self.calls: list[tuple[str, dict[str, str], dict[str, str]]] = []

    async def __call__(self, url: str, params: Any = None, headers: Any = None, **_: Any) -> bytes:
        self.calls.append((url, dict(params or {}), dict(headers or {})))
        cve = params['cve']
        if cve not in self.listed:
            return json.dumps({'_meta': {'total_documents': 0}, 'data': []}).encode()
        row = {
            'cve': [cve],
            'date_added': '2026-11-02T00:00:00Z',
            'shortDescription': 'not kept',
            'vulncheck_xdb': [
                {
                    'xdb_id': 'abc123',
                    'xdb_url': 'https://vulncheck.com/xdb/abc123',
                    'clone_ssh_url': 'git@github.com:someone/poc.git',
                }
            ],
        }
        return json.dumps({'_meta': {'total_documents': 1}, 'data': [row]}).encode()


async def test_vulncheck_needs_its_key_and_is_skipped_by_the_scheduler_without_it(
    session_factory: sessionmaker[Session], monkeypatch: pytest.MonkeyPatch, sleeps: list[float]
) -> None:
    monkeypatch.delenv('INSIGHT_VULNCHECK_API_KEY', raising=False)
    report(session_factory, 'CVE-2024-1111')
    provider = FakeVulnCheck(set())
    monkeypatch.setattr(connectors, 'download', provider)
    with pytest.raises(ProviderError, match='VulnCheck KEV needs INSIGHT_VULNCHECK_API_KEY'):
        await look_up_due(session_factory, 'vulncheck')
    with pytest.raises(ValueError, match='Set INSIGHT_VULNCHECK_API_KEY'):
        await request_lookup(session_factory, 'CVE-2024-1111', 'vulncheck')
    assert provider.calls == []
    assert lookups.unready_providers() == {'vulncheck'}
    switch_on(session_factory, 'vulncheck')
    with session_factory.begin() as db:
        assert services.enqueue_due_lookups(db, at=NOW, unready=lookups.unready_providers()) == []
    monkeypatch.setenv('INSIGHT_VULNCHECK_API_KEY', 'vc-key')
    assert lookups.unready_providers() == frozenset()
    with session_factory.begin() as db:
        assert services.enqueue_due_lookups(db, at=NOW, unready=lookups.unready_providers()) == ['vulncheck']


async def test_vulncheck_lookups_send_the_bearer_key_and_cache_metadata_only(
    session_factory: sessionmaker[Session], monkeypatch: pytest.MonkeyPatch, sleeps: list[float]
) -> None:
    monkeypatch.setenv('INSIGHT_VULNCHECK_API_KEY', 'vc-key')
    report(session_factory, 'CVE-2024-1111 CVE-2024-2222')
    report(session_factory, 'Private CVE-2024-3333', tlp='AMBER')
    provider = FakeVulnCheck({'CVE-2024-1111'})
    monkeypatch.setattr(connectors, 'download', provider)
    assert await look_up_due(session_factory, 'vulncheck') == 'Looked up 2 CVEs at VulnCheck KEV.'
    assert sorted(params['cve'] for _, params, _ in provider.calls) == ['CVE-2024-1111', 'CVE-2024-2222']
    assert all(url.startswith('https://api.vulncheck.com/') for url, _, _ in provider.calls)
    assert [headers for _, _, headers in provider.calls] == [{'Authorization': 'Bearer vc-key'}] * 2
    stored = cached(session_factory)
    assert set(stored) == {('CVE-2024-1111', 'vulncheck'), ('CVE-2024-2222', 'vulncheck')}
    assert stored[('CVE-2024-2222', 'vulncheck')] == {'cve': 'CVE-2024-2222', 'listed': False}
    listed = stored[('CVE-2024-1111', 'vulncheck')]
    assert listed['listed'] is True
    assert listed['exploit_count'] == 1
    text = json.dumps(list(stored.values()))
    assert 'git@' not in text
    assert 'not kept' not in text
    # A manual lookup returns the same summary, never the raw answer.
    THROTTLES['vulncheck'].reset()
    answer = await request_lookup(session_factory, 'CVE-2024-1111', 'vulncheck')
    assert answer == listed
    with session_factory() as db:
        assert services.cves_to_look_up(db, 'vulncheck', at=NOW, limit=10) == []


# --------------------------------------------------------------------------- reading scores


def test_score_view_follows_the_readers_tlp_limit(session_factory: sessionmaker[Session]) -> None:
    report(session_factory, 'CVE-2024-1111', tlp='AMBER')
    report(session_factory, 'CVE-2024-2222', tlp='GREEN')
    epss = {'data': [{'cve': 'CVE-2024-1111', 'epss': '0.5'}]}
    cache(session_factory, 'CVE-2024-1111', 'epss', epss, NOW)
    with session_factory() as db:
        with pytest.raises(LookupError):
            services.cve_score_view(db, 'CVE-2024-1111', max_tlp='GREEN')
        with pytest.raises(LookupError):
            services.cve_score_view(db, 'CVE-2024-9999')
        found = services.cve_score_view(db, 'CVE-2024-1111', max_tlp='AMBER')
        assert found.epss is not None
        assert found.epss.probability == 0.5
        unscored = services.cve_score_view(db, 'CVE-2024-2222', max_tlp='GREEN')
        assert (unscored.cve, unscored.checked) == ('CVE-2024-2222', False)


def test_cve_scores_reads_many_cves_in_chunks(session_factory: sessionmaker[Session]) -> None:
    cves = [f'CVE-2024-{n:05d}' for n in range(1, 1201)]
    cache(session_factory, cves[0], 'epss', {'data': [{'epss': '0.1'}]}, NOW)
    cache(session_factory, cves[-1], 'nvd', {'vulnerabilities': []}, NOW)
    with session_factory() as db:
        found = services.cve_scores(db, cves + cves[:5])
        assert services.cve_scores(db, []) == {}
    assert sorted(found) == [cves[0], cves[-1]]
    assert found[cves[-1]].nvd is None
    assert found[cves[-1]].nvd_checked_at


# --------------------------------------------------------------------------- review M2: one bad CVE


TEN = [f'CVE-2024-{n:04d}' for n in range(1001, 1011)]


def failures(factory: sessionmaker[Session]) -> dict[str, tuple[int, str]]:
    with factory() as db:
        return {f.cve: (f.failures, f.retry_at) for f in db.scalars(select(LookupFailure))}


async def test_regression_m2_one_failing_cve_does_not_stop_the_batch(
    session_factory: sessionmaker[Session], monkeypatch: pytest.MonkeyPatch, sleeps: list[float]
) -> None:
    report(session_factory, ' '.join(TEN))
    provider = FakeProvider(status={TEN[0]: 404})
    monkeypatch.setattr(connectors, 'download', provider)
    message = await look_up_due(session_factory, 'nvd', clock=lambda: NOW)
    assert message == (
        'Looked up 9 CVEs at NIST NVD; 1 CVE could not be answered and will be tried again later.'
    )
    assert sorted(cve for cve, _ in cached(session_factory)) == TEN[1:]
    assert failures(session_factory) == {TEN[0]: (1, stamp(NOW + timedelta(hours=1)))}


async def test_regression_m2_a_failing_cve_waits_longer_each_time_and_is_forgotten_once_answered(
    session_factory: sessionmaker[Session], monkeypatch: pytest.MonkeyPatch, sleeps: list[float]
) -> None:
    report(session_factory, 'CVE-2024-1001 CVE-2024-1002')
    monkeypatch.setattr(connectors, 'download', FakeProvider(status={'CVE-2024-1001': 404}))
    await look_up_due(session_factory, 'nvd', clock=lambda: NOW)
    with session_factory() as db:
        assert services.cves_to_look_up(db, 'nvd', at=NOW, limit=10) == []  # 1002 cached, 1001 waits
        later = NOW + timedelta(hours=1, minutes=1)
        assert services.cves_to_look_up(db, 'nvd', at=later, limit=10) == ['CVE-2024-1001']
        assert services.lookup_failures(db, at=NOW) == {'epss': 0, 'nvd': 1, 'vulncheck': 0}
    second = NOW + timedelta(hours=2)
    with pytest.raises(ProviderError, match='NIST NVD could not answer for any of 1 CVE'):
        await look_up_due(session_factory, 'nvd', clock=lambda: second)
    assert failures(session_factory)['CVE-2024-1001'] == (2, stamp(second + timedelta(hours=2)))
    with session_factory.begin() as db:
        for _ in range(20):
            services.record_lookup_failure(db, 'nvd', 'CVE-2024-1001', 'x', at=second)
    assert failures(session_factory)['CVE-2024-1001'][1] == stamp(second + timedelta(days=7))  # capped
    monkeypatch.setattr(connectors, 'download', FakeProvider())
    await look_up_due(session_factory, 'nvd', clock=lambda: second + timedelta(days=8))
    assert failures(session_factory) == {}


async def test_regression_m2_a_batch_that_fails_entirely_still_fails_the_job(
    session_factory: sessionmaker[Session], monkeypatch: pytest.MonkeyPatch, sleeps: list[float]
) -> None:
    report(session_factory, 'CVE-2024-1001 CVE-2024-1002')
    switch_on(session_factory, 'nvd')
    status = {'CVE-2024-1001': 404, 'CVE-2024-1002': 400}
    monkeypatch.setattr(connectors, 'download', FakeProvider(status=status))
    assert await jobs.run_due(session_factory, asyncio.Lock(), clock=lambda: datetime.now(UTC)) == 1
    with session_factory() as db:
        (job,) = db.scalars(select(Job).where(Job.kind == CVE_LOOKUP))
        assert job.message == 'ProviderError: NIST NVD could not answer for any of 2 CVEs.'


@pytest.mark.parametrize('code', [429, 403, 401, 500, 503])
async def test_regression_m2_a_problem_with_the_provider_stops_the_job_without_blaming_a_cve(
    session_factory: sessionmaker[Session], monkeypatch: pytest.MonkeyPatch, sleeps: list[float], code: int
) -> None:
    report(session_factory, 'CVE-2024-1001 CVE-2024-1002')
    provider = FakeProvider(status={'CVE-2024-1001': code, 'CVE-2024-1002': code})
    monkeypatch.setattr(connectors, 'download', provider)
    with pytest.raises(ProviderError, match=f'NVD answered HTTP {code}'):
        await look_up_due(session_factory, 'nvd', clock=lambda: NOW)
    assert len(provider.calls) == 1  # stopped at the first answer
    assert failures(session_factory) == {}


def test_regression_n2_the_due_list_is_one_query_with_a_real_limit(
    session_factory: sessionmaker[Session], count_queries: Any
) -> None:
    """Review N2: each 15 s tick loaded every CVE and every fresh cache row, then dropped most of them."""
    report(session_factory, ' '.join(f'CVE-2024-{n:04d}' for n in range(1001, 1031)))
    for n in range(1001, 1011):  # 10 answered recently, 5 waiting after a failure
        cache(session_factory, f'CVE-2024-{n:04d}', 'nvd', {}, NOW)
    with session_factory.begin() as db:
        for n in range(1011, 1016):
            services.record_lookup_failure(db, 'nvd', f'CVE-2024-{n:04d}', 'x', at=NOW)
    with session_factory() as db:
        engine = db.get_bind()
        with count_queries(engine) as statements:
            due = services.cves_to_look_up(db, 'nvd', at=NOW, limit=3)
        assert len(statements) == 1
        assert 'NOT (EXISTS' in statements[0]
        assert 'LIMIT' in statements[0]
        assert due == ['CVE-2024-1016', 'CVE-2024-1017', 'CVE-2024-1018']
        with count_queries(engine) as statements:
            assert services.lookup_backlog(db, at=NOW) == {'epss': 30, 'nvd': 15, 'vulncheck': 30}
        assert len(statements) == 3  # one count per provider
