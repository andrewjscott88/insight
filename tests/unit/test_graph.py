"""The link graph (TIP 3.2, ADR 0027): recorded links only, TLP-aware, capped and deterministic."""

from __future__ import annotations

from typing import Any

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from insight import services
from insight.models import Entity, Observation
from insight.schemas import ActorInput, ActorLinkInput, CampaignInput, DocumentInput, ThreatLinkInput
from insight.services import build_graph
from insight.services import graph as graph_module

C2 = '203.0.113.50'
LOADER = 'evil-loader.example'


def add(db: Session, title: str, body: str, tlp: str = 'GREEN') -> str:
    item = DocumentInput.model_validate({'title': title, 'body': body, 'source_name': 'Feed', 'tlp': tlp})
    doc, _ = services.ingest(db, item)
    return doc.id


def entity(db: Session, value: str) -> str:
    found = db.scalar(select(Entity.id).where(Entity.value == value))
    assert found is not None
    return found


def ids(graph: services.Graph) -> set[str]:
    return {n.id for n in graph.nodes}


def edges(graph: services.Graph) -> set[tuple[str, str, str]]:
    return {(e.source, e.target, e.kind) for e in graph.edges}


@pytest.fixture
def world(db: Session) -> dict[str, Any]:
    first = add(db, 'Loader campaign', f'Phishing led to {LOADER} and C2 at {C2} (T1566.001).')
    second = add(db, 'Follow-up', f'The same C2 {C2} served a second stage (T1059.001).')
    hidden = add(db, 'Partner only', f'C2 {C2} and staging at 198.51.100.9.', 'AMBER')
    return {'first': first, 'second': second, 'hidden': hidden}


def test_a_report_links_to_its_indicators_and_techniques(db: Session, world: dict[str, Any]) -> None:
    graph = build_graph(db, f'report:{world["first"]}')
    report = f'report:{world["first"]}'
    assert ids(graph) == {
        report,
        f'indicator:{entity(db, C2)}',
        f'indicator:{entity(db, LOADER)}',
        'technique:T1566.001',
    }
    assert (
        min(report, f'indicator:{entity(db, C2)}'),
        max(report, f'indicator:{entity(db, C2)}'),
        'mentions',
    ) in edges(graph)
    seed = graph.nodes[0]
    assert (seed.id, seed.type, seed.label, seed.depth) == (report, 'report', 'Loader campaign', 0)


def test_mobile_and_ics_techniques_have_named_graph_nodes(db: Session) -> None:
    """Regression: new domain tags must remain navigable instead of becoming missing catalog nodes."""
    report_id = add(db, 'Multiple domains', 'T1398 and T0800.')
    graph = build_graph(db, f'report:{report_id}', max_tlp='GREEN')
    nodes = {n.id: n.label for n in graph.nodes}
    assert 'Boot or Logon Initialization Scripts' in nodes['technique:T1398']
    assert 'Activate Firmware Update Mode' in nodes['technique:T0800']


def test_two_steps_reach_reports_that_share_an_indicator(db: Session, world: dict[str, Any]) -> None:
    graph = build_graph(db, f'report:{world["first"]}', depth=2)
    assert f'report:{world["second"]}' in ids(graph)
    assert 'technique:T1059.001' not in ids(graph)  # three steps away
    assert {n.depth for n in graph.nodes} == {0, 1, 2}


def test_rejected_mentions_are_not_links(db: Session, world: dict[str, Any]) -> None:
    obs = db.scalar(
        select(Observation).where(
            Observation.document_id == world['first'], Observation.entity_id == entity(db, LOADER)
        )
    )
    assert obs is not None
    services.set_observation_status(db, obs.id, 'rejected')
    assert f'indicator:{entity(db, LOADER)}' not in ids(build_graph(db, f'report:{world["first"]}'))


def test_the_readers_limit_hides_reports_and_what_only_they_link(db: Session, world: dict[str, Any]) -> None:
    unlimited = build_graph(db, f'indicator:{entity(db, C2)}')
    assert f'report:{world["hidden"]}' in ids(unlimited)
    limited = build_graph(db, f'indicator:{entity(db, C2)}', max_tlp='GREEN')
    assert f'report:{world["hidden"]}' not in ids(limited)
    assert ids(limited) == {
        f'indicator:{entity(db, C2)}',
        f'report:{world["first"]}',
        f'report:{world["second"]}',
    }
    with pytest.raises(LookupError):
        build_graph(db, f'report:{world["hidden"]}', max_tlp='GREEN')
    with pytest.raises(LookupError):  # only the AMBER report mentions it
        build_graph(db, f'indicator:{entity(db, "198.51.100.9")}', max_tlp='GREEN')
    with pytest.raises(LookupError):
        build_graph(db, 'report:missing')


def test_analyst_links_to_actors_campaigns_and_groups(db: Session, world: dict[str, Any]) -> None:
    actor = services.create_actor(db, ActorInput(name='Loader crew', tlp='GREEN'))
    services.link_report(db, actor.id, ActorLinkInput(document_id=world['first'], tlp='GREEN'))
    services.link_report(db, 'G0016', ActorLinkInput(document_id=world['second'], tlp='GREEN'))
    campaign = services.create_campaign(db, CampaignInput(name='Winter wave', tlp='AMBER'))
    link = ThreatLinkInput(target_kind='indicator', target_id=entity(db, C2), tlp='AMBER')
    services.link_threat(db, 'campaign', campaign.id, link)
    around = ids(build_graph(db, f'indicator:{entity(db, C2)}', depth=2))
    assert {f'actor:{actor.id}', 'group:G0016', f'campaign:{campaign.id}'} <= around
    limited = ids(build_graph(db, f'indicator:{entity(db, C2)}', depth=2, max_tlp='GREEN'))
    assert f'campaign:{campaign.id}' not in limited  # an AMBER campaign and link
    assert f'actor:{actor.id}' in limited
    from_actor = build_graph(db, f'actor:{actor.id}')
    assert ids(from_actor) == {f'actor:{actor.id}', f'report:{world["first"]}'}
    assert build_graph(db, 'group:G0016').nodes[0].label.endswith('(G0016)')


def test_busy_nodes_are_capped_and_marked(
    db: Session, world: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(graph_module, 'PER_NODE', 1)
    graph = build_graph(db, f'indicator:{entity(db, C2)}')
    seed = graph.nodes[0]
    assert seed.truncated
    assert len([n for n in graph.nodes if n.type == 'report']) == 1
    monkeypatch.setattr(graph_module, 'PER_NODE', 25)
    monkeypatch.setattr(graph_module, 'MAX_NODES', 2)
    capped = build_graph(db, f'report:{world["first"]}', depth=2)
    assert capped.capped
    assert len(capped.nodes) == 2


def test_the_same_question_gives_the_same_graph(db: Session, world: dict[str, Any]) -> None:
    one = build_graph(db, f'report:{world["first"]}', depth=2)
    two = build_graph(db, f'report:{world["first"]}', depth=2)
    assert (one.nodes, one.edges) == (two.nodes, two.edges)
    with pytest.raises(ValueError, match='depth'):
        build_graph(db, f'report:{world["first"]}', depth=3)
