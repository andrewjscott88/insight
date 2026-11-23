"""Censys Platform v3 metadata and disclosure policy, with synthetic offline responses."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest
from sqlalchemy import select
from tests.greynoise_fixtures import IP, provider_error, reviewed

from insight import censys, services
from insight.connectors import ProviderError
from insight.lookups import THROTTLES
from insight.models import Enrichment, Observation, SessionFactory

RAW = (Path(__file__).parents[1] / 'fixtures' / 'censys-host.json').read_bytes()
TOKEN = 'censys_test_token'


def test_v3_metadata_is_bounded_and_discards_private_fields() -> None:
    """Regression: Censys v3 wraps a host in result.resource and may use uppercase transport names."""
    answer = censys._parse(RAW, IP)
    assert [r['port'] for r in answer['services']] == [53, 443]
    assert answer['services'][1]['transport'] == 'tcp'
    assert answer['hostnames'] == ['synthetic.example.org']
    assert (answer['asn'], answer['prefix']) == (64500, '8.8.8.0/24')
    assert 'PRIVATE' not in json.dumps(answer)
    assert 'private@example.org' not in json.dumps(answer)
    many = json.loads(RAW)
    many['result']['resource']['services'] = [{'port': i + 1, 'protocol': 'HTTP'} for i in range(150)]
    capped = censys._parse(json.dumps(many).encode(), IP)
    assert len(capped['services']) == 100
    assert capped['service_count'] == 150
    for payload in (b'{}', b'[]', b'{', b' ' * (censys.MAX_BYTES + 1)):
        with pytest.raises(ProviderError, match='invalid host data'):
            censys._parse(payload, IP)
    with pytest.raises(ProviderError):
        censys._parse(RAW, '1.1.1.1')


async def test_approval_eligibility_cache_audit_and_retention(
    session_factory: SessionFactory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[dict[str, Any]] = []

    async def provider(url: str, params: Any = None, **kwargs: Any) -> bytes:
        calls.append({'url': url, 'params': params, **kwargs})
        return RAW

    monkeypatch.setattr(censys, 'download', provider)
    monkeypatch.delenv('INSIGHT_CENSYS_PAT', raising=False)
    monkeypatch.delenv('INSIGHT_CENSYS_ORG_ID', raising=False)
    with pytest.raises(ValueError, match='Approve'):
        await censys.lookup(session_factory, IP, actor='test')
    with pytest.raises(censys.NotConfigured):
        await censys.lookup(session_factory, IP, actor='test', approved=True)
    monkeypatch.setenv('INSIGHT_CENSYS_PAT', TOKEN)
    with session_factory.begin() as db:
        reviewed(db, '9.9.9.9', tlp='GREEN')
        reviewed(db, '1.1.1.1', status='unreviewed')
    for value in (IP, '9.9.9.9', '1.1.1.1', '127.0.0.1'):
        with pytest.raises(LookupError):
            await censys.lookup(session_factory, value, actor='test', approved=True)
    assert not calls
    with session_factory.begin() as db:
        doc = reviewed(db)
    result = await censys.lookup(session_factory, IP, actor='test', approved=True, max_tlp='GREEN')
    assert await censys.lookup(session_factory, IP, actor='test', approved=True) == result
    assert len(calls) == 1
    request = calls[0]
    assert request['url'] == f'https://api.platform.censys.io/v3/global/asset/host/{IP}'
    assert request['headers']['Authorization'] == f'Bearer {TOKEN}'
    assert request['headers']['Accept'] == 'application/vnd.censys.api.v3.host.v1+json'
    assert request['max_bytes'] == censys.MAX_BYTES
    assert request['allowed_hosts'] == frozenset({censys.HOST})
    assert 'organization_id' not in request['params']
    with session_factory.begin() as db:
        actions = {e.action for e in services.audit_events(db)}
        assert {'ip.lookup.request', 'ip.lookup', 'ip.lookup.cache'} <= actions
        assert TOKEN not in repr(services.audit_events(db))
        obs = db.scalar(select(Observation).where(Observation.document_id == doc))
        assert obs is not None
        obs.review_status = 'rejected'
    with session_factory() as db, pytest.raises(LookupError):
        services.cached_censys_context(db, IP, max_tlp='GREEN')
    with session_factory.begin() as db:
        services.delete_document(db, doc, 'Synthetic deletion')
        assert not db.scalars(select(Enrichment).where(Enrichment.provider == 'censys')).all()


async def test_refusals_are_sanitized_and_throttled_and_missing_results_expire(
    session_factory: SessionFactory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv('INSIGHT_CENSYS_PAT', TOKEN)
    monkeypatch.setenv('INSIGHT_CENSYS_ORG_ID', '11111111-2222-3333-4444-555555555555')
    with session_factory.begin() as db:
        reviewed(db)
    answers = [provider_error(401), provider_error(403), provider_error(429, '20'), provider_error(404)]

    async def provider(*args: Any, **kwargs: Any) -> bytes:
        if answers:
            raise answers.pop(0)
        raise httpx.ConnectError('PRIVATE ' + TOKEN)

    monkeypatch.setattr(censys, 'download', provider)
    for error in (ProviderError, ProviderError, censys.RateLimited):
        THROTTLES['censys'].reset()
        with pytest.raises(error) as caught:
            await censys.lookup(session_factory, IP, actor='test', approved=True)
        assert 'PRIVATE' not in str(caught.value)
        assert TOKEN not in str(caught.value)
    with pytest.raises(censys.RateLimited):
        await censys.lookup(session_factory, IP, actor='test', approved=True)
    THROTTLES['censys'].reset()
    assert not (await censys.lookup(session_factory, IP, actor='test', approved=True))['found']
    with session_factory.begin() as db:
        row = db.scalars(select(Enrichment).where(Enrichment.provider == 'censys')).one()
        row.fetched_at = (datetime.now(UTC) - timedelta(days=2)).isoformat()
    THROTTLES['censys'].reset()
    with pytest.raises(ProviderError) as caught:
        await censys.lookup(session_factory, IP, actor='test', approved=True)
    assert 'PRIVATE' not in str(caught.value)
    assert TOKEN not in str(caught.value)


def test_ipv6_eligibility_and_subject_check(session_factory: SessionFactory) -> None:
    value = '2606:4700:4700::1111'
    with session_factory.begin() as db:
        reviewed(db, value)
        assert services.eligible_censys_ip(db, value, max_tlp='CLEAR')
    data = json.loads(RAW)
    data['result']['resource']['ip'] = value
    data['result']['resource']['autonomous_system']['bgp_prefix'] = '2606:4700:4700::/48'
    assert censys._parse(json.dumps(data).encode(), value)['found']
