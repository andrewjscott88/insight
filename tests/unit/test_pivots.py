"""Disclosure gates, cache lifecycle and graph privacy for manual infrastructure context."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker
from tests.greynoise_fixtures import IP, reviewed

from insight import pivot_data, pivots, services
from insight.lookups import THROTTLES
from insight.models import Document, Enrichment, Entity, Observation
from insight.schemas import TLP
from insight.services import pivot_graph
from insight.services.graph import PER_NODE

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


@pytest.mark.parametrize(
    ('label', 'status', 'current'),
    [
        ('CLEAR', 'pending', True),
        ('CLEAR', 'rejected', True),
        ('AMBER', 'accepted', True),
        ('CLEAR', 'accepted', False),
    ],
)
def test_only_current_accepted_clear_evidence_grants_pivot_access(
    db: Session, label: TLP, status: str, current: bool
) -> None:
    document_id = reviewed(db, tlp=label, status=status)
    document = db.get(Document, document_id)
    assert document
    document.is_current = current
    db.flush()
    assert services.eligible_pivot(db, IP) is None
    with pytest.raises(LookupError):
        services.cached_pivots(db, IP)


async def test_provider_lock_and_audit_actor_are_shared_between_callers(
    session_factory: sessionmaker[Session], monkeypatch: pytest.MonkeyPatch
) -> None:
    with session_factory.begin() as db:
        reviewed(db)
        services.set_pivot_switch(db, 'rdap', True)
    entered, release = asyncio.Event(), asyncio.Event()

    async def fetch(provider: str, value: str) -> dict[str, Any]:
        entered.set()
        await release.wait()
        return ANSWER

    monkeypatch.setattr(pivots, '_fetch', fetch)
    THROTTLES['rdap'].reset()
    first = asyncio.create_task(
        pivots.lookup(session_factory, 'rdap', IP, approved=True, actor='key:synthetic')
    )
    try:
        await entered.wait()
        with pytest.raises(pivots.RateLimited):
            await pivots.lookup(session_factory, 'rdap', IP, approved=True, actor='operator')
    finally:
        release.set()
        await first
    with session_factory() as db:
        events = [event for event in services.audit_events(db) if event.action.startswith('pivot.')]
        assert [(event.action, event.actor) for event in events if event.action != 'pivot.on'] == [
            ('pivot.lookup', 'key:synthetic'),
            ('pivot.request', 'key:synthetic'),
        ]
        assert db.scalar(select(func.count()).select_from(Entity)) == 1
        assert db.scalar(select(func.count()).select_from(Observation)) == 1


def test_retention_deletes_orphan_pivot_cache(db: Session) -> None:
    """Regression: cached infrastructure must not outlive its deleted, otherwise unreferenced indicator."""
    document_id = reviewed(db)
    services.set_pivot_switch(db, 'rdap', True)
    services.store_pivot(db, 'rdap', IP, ANSWER)
    db.flush()
    services.delete_document(db, document_id, 'Synthetic retention check')
    assert db.scalar(select(Enrichment).where(Enrichment.provider == 'rdap')) is None
    with pytest.raises(LookupError):
        services.cached_pivots(db, IP)


def test_graph_caps_work_before_resolving_known_indicators(
    db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Regression: a large pivot cache must not perform a known-indicator query for every undisplayed row."""
    reviewed(db)
    services.set_pivot_switch(db, 'rdap', True)
    services.store_pivot(
        db,
        'rdap',
        IP,
        {
            'found': True,
            'nodes': [{'type': 'name_server', 'value': f'ns{i}.example.net'} for i in range(500)],
        },
    )
    db.flush()
    subject = services.eligible_pivot(db, IP)
    calls: list[str] = []
    original = pivot_graph._known

    def counted(db: Session, value: str, max_tlp: str | None) -> str | None:
        calls.append(value)
        return original(db, value, max_tlp)

    monkeypatch.setattr(pivot_graph, '_known', counted)
    graph = services.build_graph(db, f'indicator:{subject}')
    assert len(calls) == PER_NODE + 1
    assert len([node for node in graph.nodes if node.type == 'name_server']) == PER_NODE
    assert next(node for node in graph.nodes if node.id == graph.seed).truncated


async def test_unsupported_kinds_are_refused_before_approval_or_provider_access(
    session_factory: sessionmaker[Session], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Regression: a provider for domains alone must not expose an empty IP pivot workflow."""
    monkeypatch.setattr(pivot_data, 'PROVIDER_KINDS', {'rdap': frozenset({'domain'})})
    with session_factory.begin() as db:
        reviewed(db)
        services.set_pivot_switch(db, 'rdap', True)
        assert services.eligible_pivot(db, IP) is None
    with pytest.raises(ValueError, match='does not support'):
        await pivots.lookup(session_factory, 'rdap', IP, approved=True, actor='operator')
