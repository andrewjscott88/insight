"""Entity explorer API: search and pivots."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from fastapi.testclient import TestClient


def test_entity_search_counts_distinct_documents(
    authed: TestClient, make_document: Callable[..., dict[str, Any]]
) -> None:
    make_document(body='CVE-2024-12345 and CVE-2024-12345 again')
    make_document(body='CVE-2024-12345 elsewhere', source_name='Other')
    (row,) = authed.get('/api/entities', params={'q': '2024-12345'}).json()
    assert (row['kind'], row['value'], row['document_count']) == ('cve', 'CVE-2024-12345', 2)


def test_entity_search_is_literal_and_sorted(
    authed: TestClient, make_document: Callable[..., dict[str, Any]]
) -> None:
    make_document(body='b.example.com a.example.com CVE-2024-12345 192.0.2.1')
    listed = authed.get('/api/entities').json()
    assert [(e['kind'], e['value']) for e in listed] == sorted((e['kind'], e['value']) for e in listed)
    assert authed.get('/api/entities', params={'q': '%'}).json() == []


def test_entity_detail_lists_documents(
    authed: TestClient, make_document: Callable[..., dict[str, Any]]
) -> None:
    report = make_document()
    entity_id = report['observations'][0]['entity_id']
    result = authed.get(f'/api/entities/{entity_id}').json()
    assert result['id'] == entity_id
    assert [d['id'] for d in result['documents']] == [report['id']]
    assert authed.get('/api/entities/missing').status_code == 404
