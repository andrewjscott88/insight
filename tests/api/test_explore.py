"""Ranked search and the link graph over HTTP (TIP 3.2, ADR 0027)."""

from __future__ import annotations

from typing import Any

from fastapi.testclient import TestClient


def test_search_ranks_and_explains(authed: TestClient, make_document: Any) -> None:
    make_document(title='Weekly roundup', body='Mentions Akira once among other news items and notes.')
    make_document(title='Akira ransomware affiliates', body='Affiliates used VPN appliances.')
    response = authed.get('/api/search', params={'q': 'akira'})
    assert response.status_code == 200
    body = response.json()
    assert body['terms'] == ['akira']
    assert body['total'] == 2
    assert [r['title'] for r in body['results']] == ['Akira ransomware affiliates', 'Weekly roundup']
    first = body['results'][0]
    assert first['matched_in_title'] == ['akira']
    assert first['score'] > body['results'][1]['score']
    assert {'id', 'tlp', 'source_name', 'snippet', 'entity_count'} <= first.keys()


def test_search_needs_a_query(authed: TestClient) -> None:
    assert authed.get('/api/search').status_code == 422
    assert authed.get('/api/search', params={'q': 'x' * 201}).status_code == 422
    assert authed.get('/api/search', params={'q': 'x', 'limit': 201}).status_code == 422


def test_graph_around_a_report(authed: TestClient, make_document: Any) -> None:
    doc = make_document(title='C2 note', body='Beacon to 203.0.113.80 (T1071.001).')
    response = authed.get('/api/graph', params={'node': f'report:{doc["id"]}'})
    assert response.status_code == 200
    graph = response.json()
    assert graph['seed'] == f'report:{doc["id"]}'
    assert {n['type'] for n in graph['nodes']} == {'report', 'indicator', 'technique'}
    assert {e['kind'] for e in graph['edges']} == {'mentions', 'tagged'}
    assert graph['capped'] is False


def test_graph_refuses_unknown_nodes_and_bad_input(authed: TestClient) -> None:
    assert authed.get('/api/graph', params={'node': 'report:missing'}).status_code == 404
    assert authed.get('/api/graph', params={'node': 'technique:T9999'}).status_code == 404
    assert authed.get('/api/graph', params={'node': 'nothing'}).status_code == 422
    assert authed.get('/api/graph', params={'node': 'report:x', 'depth': 3}).status_code == 422
