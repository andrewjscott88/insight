"""Disclosure gates, cache lifecycle and graph privacy for manual infrastructure context."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker
from tests.greynoise_fixtures import IP, reviewed

from insight import pivots, services
from insight.lookups import THROTTLES
from insight.models import Document, Enrichment, Entity, Observation

ANSWER: dict[str, Any] = {'found': True, 'nodes': [{'type': 'name_server', 'value': 'ns1.example.net'}]}


def test_graph_does_not_identify_a_hidden_known_indicator(db: Session) -> None:
    """Regression: a public provider name must not reveal its match to an AMBER-only stored indicator."""
    reviewed(db)
    reviewed(db, 'ns1.example.net', tlp='AMBER')
    db.flush()
    hidden = db.scalar(select(Entity).where(Entity.value == 'ns1.example.net'))
    assert hidden
    subject = services.eligible_pivot(db, IP, max_tlp='GREEN')
    services.set_pivot_switch(db, 'rdap', True)
    services.store_pivot(db, 'rdap', IP, ANSWER, max_tlp='GREEN')
    db.flush()
    green = services.build_graph(db, f'indicator:{subject}', max_tlp='GREEN')
    assert all(hidden.id not in node.id for node in green.nodes)
    assert any(node.label == 'ns1.example.net' and node.type == 'name_server' for node in green.nodes)
    amber = services.build_graph(db, f'indicator:{subject}', max_tlp='AMBER')
    assert any(node.id == f'indicator:{hidden.id}' for node in amber.nodes)


@pytest.mark.parametrize('change', ['delete', 'reject', 'disable'])
async def test_in_flight_lookup_cannot_restore_ineligible_cache(
    session_factory: sessionmaker[Session], monkeypatch: pytest.MonkeyPatch, change: str
) -> None:
    """Regression: an upstream answer arriving after removal or revocation must not resurrect its cache."""
    with session_factory.begin() as db:
        document_id = reviewed(db)
        services.set_pivot_switch(db, 'rdap', True)

    async def fetch(provider: str, value: str) -> dict[str, Any]:
        with session_factory.begin() as db:
            if change == 'delete':
                services.delete_document(db, document_id, 'Synthetic retention check')
            elif change == 'reject':
                for obs in db.scalars(select(Observation)):
                    obs.review_status = 'rejected'
            else:
                services.set_pivot_switch(db, provider, False)
        return ANSWER

    monkeypatch.setattr(pivots, '_fetch', fetch)
    THROTTLES['rdap'].reset()
    with pytest.raises((LookupError, ValueError)):
        await pivots.lookup(session_factory, 'rdap', IP, approved=True, actor='operator')
    with session_factory() as db:
        assert db.scalar(select(Enrichment).where(Enrichment.provider == 'rdap')) is None


def test_pivot_defaults_and_audited_switch(db: Session) -> None:
    assert services.pivot_switches(db) == {'rdap': False, 'asn': False}
    services.set_actor(db, 'operator')
    services.set_pivot_switch(db, 'rdap', True)
    assert services.pivot_switches(db)['rdap']
    assert any(e.action == 'pivot.on' for e in services.audit_events(db))


def test_cache_eligibility_expiry_and_graph(db: Session) -> None:
    doc_id = reviewed(db)
    db.flush()
    entity_id = services.eligible_pivot(db, IP, max_tlp='GREEN')
    assert entity_id
    services.set_pivot_switch(db, 'rdap', True)
    services.store_pivot(db, 'rdap', IP, ANSWER, max_tlp='GREEN')
    db.flush()
    result = services.cached_pivots(db, IP, max_tlp='GREEN')
    assert len(result) == 1
    graph = services.build_graph(db, f'indicator:{entity_id}', depth=2, max_tlp='GREEN')
    pivot_node = next(node for node in graph.nodes if node.type == 'name_server')
    assert pivot_node.label == 'ns1.example.net'
    assert any(edge.kind.startswith('rdap · ') for edge in graph.edges)
    assert services.build_graph(db, pivot_node.id, max_tlp='GREEN').seed == pivot_node.id
    row = db.scalar(select(Enrichment).where(Enrichment.provider == 'rdap'))
    assert row
    row.fetched_at = (datetime.now(UTC) - timedelta(days=2)).isoformat()
    db.flush()
    assert services.cached_pivots(db, IP, max_tlp='GREEN') == []
    with pytest.raises(LookupError):
        services.build_graph(db, pivot_node.id, max_tlp='GREEN')
    document = db.get(Document, doc_id)
    assert document
    document.tlp = 'AMBER'
    db.flush()
    with pytest.raises(LookupError):
        services.cached_pivots(db, IP, max_tlp='GREEN')
    assert services.eligible_pivot(db, IP, max_tlp=None) is None


async def test_off_unapproved_cache_throttle_and_rechecking(
    session_factory: sessionmaker[Session], monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[str] = []

    async def fetch(provider: str, value: str) -> dict[str, Any]:
        calls.append(value)
        return ANSWER

    monkeypatch.setattr(pivots, '_fetch', fetch)
    with session_factory.begin() as db:
        reviewed(db)
    with pytest.raises(pivots.NotConfigured):
        await pivots.lookup(session_factory, 'rdap', IP, approved=True, actor='operator')
    with session_factory.begin() as db:
        services.set_pivot_switch(db, 'rdap', True)
    with pytest.raises(ValueError, match='Approve'):
        await pivots.lookup(session_factory, 'rdap', IP, approved=False, actor='operator')
    assert calls == []
    THROTTLES['rdap'].reset()
    await pivots.lookup(session_factory, 'rdap', IP, approved=True, actor='operator')
    await pivots.lookup(session_factory, 'rdap', IP, approved=False, actor='operator')
    assert calls == [IP]
    with session_factory.begin() as db:
        for obs in db.scalars(select(Observation)):
            obs.review_status = 'rejected'
    with pytest.raises(LookupError):
        await pivots.lookup(session_factory, 'rdap', IP, approved=True, actor='operator')
    assert calls == [IP]
