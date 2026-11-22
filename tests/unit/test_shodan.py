"""Optional Shodan host lookups (TIP 3.7, ADR 0031) with a fake provider and synthetic reports."""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest
from sqlalchemy import select
from tests.greynoise_fixtures import IP, provider_error, reviewed

from insight import services, shodan
from insight.connectors import ProviderError
from insight.lookups import THROTTLES
from insight.models import Enrichment, SessionFactory
from insight.schemas import TLP

FIXTURE = json.loads((Path(__file__).parents[1] / 'fixtures' / 'shodan-host.json').read_text())
KEY = 'testkey' * 4  # obviously fake; low entropy so secret scanners stay quiet


def test_the_parser_keeps_exposure_metadata_only() -> None:
    found = shodan._parse(json.dumps(FIXTURE).encode(), IP)
    assert found == {
        'found': True,
        'ports': [53, 443],
        'port_count': 2,
        'hostnames': ['dns.google'],
        'org': 'Google LLC',
        'isp': 'Google LLC',
        'asn': 'AS15169',
        'country_code': 'US',
        'os': None,
        'tags': ['cdn'],
        'vulns': ['CVE-2024-3400'],
        'last_update': '2026-11-20',
    }
    assert 'banner' not in json.dumps(found)
    assert 'raw page' not in json.dumps(found)
    # Shodan sometimes returns vulns as an object keyed by CVE.
    keyed = shodan._parse(json.dumps({**FIXTURE, 'vulns': {'CVE-2021-44228': {}}}).encode(), IP)
    assert keyed['vulns'] == ['CVE-2021-44228']


@pytest.mark.parametrize(
    'answer',
    [
        {**FIXTURE, 'ip_str': '1.1.1.1'},  # an answer about another address
        {**FIXTURE, 'ports': 'all'},
        {**FIXTURE, 'org': 'x' * 300},
        {**FIXTURE, 'last_update': 'yesterday'},
        [],
    ],
)
def test_unexpected_answers_are_refused(answer: Any) -> None:
    with pytest.raises(ProviderError, match='invalid host data'):
        shodan._parse(json.dumps(answer).encode(), IP)


async def test_no_key_no_calls_and_only_reviewed_clear_addresses_leave(
    session_factory: SessionFactory, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[Any] = []

    async def provider(*args: Any, **kwargs: Any) -> bytes:
        calls.append(args)
        return json.dumps(FIXTURE).encode()

    monkeypatch.setattr(shodan, 'download', provider)
    with session_factory.begin() as db:
        reviewed(db, '9.9.9.9', tlp='GREEN')
    for key in ('', 'short', 'has spaces in it!', 'k' * 200):
        monkeypatch.setenv('INSIGHT_SHODAN_KEY', key)
        assert shodan.configured() is False
        with pytest.raises(shodan.NotConfigured):
            await shodan.lookup(session_factory, IP, actor='operator')
    monkeypatch.setenv('INSIGHT_SHODAN_KEY', KEY)
    for ip in (IP, '9.9.9.9', '10.0.0.1'):  # not reviewed / only in a GREEN report / private
        with pytest.raises(LookupError, match='eligible'):
            await shodan.lookup(session_factory, ip, actor='operator')
    assert calls == []
    assert THROTTLES['shodan'].wait_time() == 0


async def test_one_lookup_is_cached_audited_and_removed_with_its_report(
    session_factory: SessionFactory, monkeypatch: pytest.MonkeyPatch
) -> None:
    with session_factory.begin() as db:
        report = reviewed(db)
    calls: list[tuple[str, Any, Any]] = []

    async def provider(url: str, params: Any = None, **kwargs: Any) -> bytes:
        calls.append((url, params, kwargs))
        return json.dumps(FIXTURE).encode()

    monkeypatch.setattr(shodan, 'download', provider)
    monkeypatch.setenv('INSIGHT_SHODAN_KEY', KEY)
    answer = await shodan.lookup(session_factory, IP, actor='operator')
    assert (answer['provider'], answer['ip'], answer['ports']) == ('shodan', IP, [53, 443])
    assert await shodan.lookup(session_factory, IP, actor='operator') == answer  # cached
    assert calls == [
        (
            'https://api.shodan.io/shodan/host/8.8.8.8',
            {'key': KEY, 'minify': 'true'},
            {'allowed_hosts': frozenset({'api.shodan.io'})},
        )
    ]
    with session_factory.begin() as db:
        assert [e.detail for e in services.audit_events(db) if e.action == 'ip.lookup'] == ['Shodan']
        assert KEY not in json.dumps([e.detail for e in services.audit_events(db)])
        services.delete_document(db, report, 'Synthetic retention test')
        assert db.scalars(select(Enrichment)).all() == []


async def test_greynoise_and_shodan_answers_are_cached_separately(
    session_factory: SessionFactory, monkeypatch: pytest.MonkeyPatch
) -> None:
    with session_factory.begin() as db:
        reviewed(db)
        services.store_greynoise_context(db, IP, {'found': False})
    assert services.cached_ip_context(session_factory(), 'shodan', IP) is None
    monkeypatch.setenv('INSIGHT_SHODAN_KEY', KEY)

    async def provider(*args: Any, **kwargs: Any) -> bytes:
        return json.dumps(FIXTURE).encode()

    monkeypatch.setattr(shodan, 'download', provider)
    await shodan.lookup(session_factory, IP, actor='operator')
    with session_factory() as db:
        assert services.cached_greynoise_context(db, IP) is not None
        assert services.cached_greynoise_context(db, IP)['found'] is False  # type: ignore[index]


@pytest.mark.parametrize(
    ('code', 'message'),
    [
        (401, r'refused the key \(HTTP 401\)\. Check INSIGHT_SHODAN_KEY'),
        (402, 'your plan, credits or access do not allow it'),
        (403, 'your plan, credits or access do not allow it'),
        (500, 'Shodan returned HTTP 500'),
    ],
)
async def test_key_plan_and_credit_refusals_are_named_and_never_cached(
    session_factory: SessionFactory, monkeypatch: pytest.MonkeyPatch, code: int, message: str
) -> None:
    with session_factory.begin() as db:
        reviewed(db)

    async def provider(*args: Any, **kwargs: Any) -> bytes:
        raise provider_error(code)

    monkeypatch.setattr(shodan, 'download', provider)
    monkeypatch.setenv('INSIGHT_SHODAN_KEY', KEY)
    with pytest.raises(ProviderError, match=message) as caught:
        await shodan.lookup(session_factory, IP, actor='operator')
    assert 'PRIVATE-RAW' not in str(caught.value)
    with session_factory() as db:
        assert db.scalars(select(Enrichment)).all() == []


async def test_not_found_is_cached_and_rate_limits_wait(
    session_factory: SessionFactory, monkeypatch: pytest.MonkeyPatch
) -> None:
    with session_factory.begin() as db:
        reviewed(db)
    answers = [provider_error(429, '30'), provider_error(404)]

    async def provider(*args: Any, **kwargs: Any) -> bytes:
        raise answers.pop(0)

    monkeypatch.setattr(shodan, 'download', provider)
    monkeypatch.setenv('INSIGHT_SHODAN_KEY', KEY)
    with pytest.raises(shodan.RateLimited) as limited:
        await shodan.lookup(session_factory, IP, actor='operator')
    assert limited.value.seconds == 30
    with pytest.raises(shodan.RateLimited):  # the throttle holds the wait
        await shodan.lookup(session_factory, IP, actor='operator')
    THROTTLES['shodan'].reset()
    missing = await shodan.lookup(session_factory, IP, actor='operator')
    assert missing['found'] is False
    # A day later the answer is stale and Shodan is asked again.
    with session_factory.begin() as db:
        row = db.scalars(select(Enrichment)).one()
        row.fetched_at = (datetime.now(UTC) - timedelta(days=2)).isoformat()
    THROTTLES['shodan'].reset()

    async def found(*args: Any, **kwargs: Any) -> bytes:
        return json.dumps(FIXTURE).encode()

    monkeypatch.setattr(shodan, 'download', found)
    assert (await shodan.lookup(session_factory, IP, actor='operator'))['found'] is True


async def test_the_key_never_reaches_an_error_message_or_a_log(
    session_factory: SessionFactory, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    with session_factory.begin() as db:
        reviewed(db)
    url = f'https://api.shodan.io/shodan/host/{IP}?key={KEY}&minify=true'

    async def provider(*args: Any, **kwargs: Any) -> bytes:
        raise httpx.ConnectError(f'cannot reach {url}')

    monkeypatch.setattr(shodan, 'download', provider)
    monkeypatch.setenv('INSIGHT_SHODAN_KEY', KEY)
    with pytest.raises(ProviderError) as caught:
        await shodan.lookup(session_factory, IP, actor='operator')
    assert KEY not in str(caught.value)
    # httpx logs each request URL at INFO; the filter hides the key whoever configures logging.
    with caplog.at_level(logging.INFO, logger='httpx'):
        logging.getLogger('httpx').info('HTTP Request: %s %s "%s"', 'GET', httpx.URL(url), 'HTTP/1.1 200 OK')
    assert KEY not in caplog.text
    assert 'key=[hidden]' in caplog.text


@pytest.mark.parametrize('tlp', ['GREEN', 'AMBER'])
async def test_a_report_relabelled_above_clear_stops_lookups_and_cached_reads(
    session_factory: SessionFactory, monkeypatch: pytest.MonkeyPatch, tlp: TLP
) -> None:
    src = services.SourceRef('fixture', 'stable-id')
    with session_factory.begin() as db:
        reviewed(db, source=src)
        services.store_ip_context(db, 'shodan', IP, {'found': False})
        reviewed(db, source=src, tlp=tlp)  # a new revision at a stricter label supersedes the CLEAR one
    monkeypatch.setenv('INSIGHT_SHODAN_KEY', KEY)
    with session_factory() as db, pytest.raises(LookupError):
        services.cached_ip_context(db, 'shodan', IP)
