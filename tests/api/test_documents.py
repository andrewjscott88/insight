"""Document ingestion, review, notes, search, pagination and export over HTTP."""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy.exc import IntegrityError

from insight import services

MakeDocument = Callable[..., dict[str, Any]]


def test_ingest_returns_detail_with_provenance(make_document: MakeDocument) -> None:
    report = make_document()
    assert report['created'] is True
    assert report['content_hash'] == hashlib.sha256(report['body'].encode()).hexdigest()
    assert report['tlp'] == 'AMBER+STRICT'
    assert report['status'] == 'new'
    assert {(o['kind'], o['value']) for o in report['observations']} == {
        ('cve', 'CVE-2024-12345'),
        ('ip', '192.0.2.8'),
        ('domain', 'example.com'),
    }
    assert all(o['review_status'] == 'unreviewed' for o in report['observations'])


def test_dedup_and_distinct_provenance(authed: TestClient, make_document: MakeDocument) -> None:
    first = make_document()
    repeated = make_document()
    other = make_document(source_name='Second publisher')
    relabelled = make_document(tlp='GREEN')  # a different handling label is different provenance
    assert not repeated['created']
    assert repeated['id'] == first['id']
    assert len({first['id'], other['id'], relabelled['id']}) == 3
    assert first['content_hash'] == other['content_hash']
    assert authed.get('/api/stats').json()['documents'] == 3


def test_exact_offsets_reviews_pivots_notes_and_audit(
    authed: TestClient, make_document: MakeDocument
) -> None:
    body = '  Unicode ☃: cve-2024-12345 at EXAMPLE.COM; cve-2024-12345 again.\n'
    report = make_document(body=body)
    assert report['body'] == body
    for obs in report['observations']:
        assert body[obs['start_offset'] : obs['end_offset']].lower() in obs['evidence'].lower()
    cves = [o for o in report['observations'] if o['kind'] == 'cve']
    assert len(cves) == 2
    assert cves[0]['entity_id'] == cves[1]['entity_id']
    other = make_document(source_name='Other')
    pivot = authed.get('/api/entities/' + cves[0]['entity_id']).json()
    assert {d['id'] for d in pivot['documents']} == {report['id'], other['id']}

    assert authed.post(f'/api/observations/{cves[0]["id"]}/review', json={'status': 'accepted'}).json() == {
        'status': 'accepted'
    }
    assert (
        authed.post(f'/api/documents/{report["id"]}/review', json={'status': 'reviewed'}).status_code == 200
    )
    note = authed.post(f'/api/documents/{report["id"]}/notes', json={'body': 'Validate with owner.'})
    assert note.status_code == 200
    assert note.json()['id']

    refreshed = authed.get('/api/documents/' + report['id']).json()
    assert refreshed['status'] == 'reviewed'
    assert refreshed['notes'][0]['body'] == 'Validate with owner.'
    assert refreshed['observations'][0]['review_status'] == 'accepted'
    actions = {e['action'] for e in authed.get('/api/audit').json()}
    assert {'document.ingest', 'document.review', 'observation.review', 'note.add'} <= actions


def test_html_is_returned_as_inert_json_text(authed: TestClient, make_document: MakeDocument) -> None:
    body = '<script>alert(document.cookie)</script><img src=x onerror=alert(1)>'
    report = make_document(title='<script>alert(1)</script>', body=body)
    response = authed.get('/api/documents/' + report['id'])
    assert response.headers['content-type'].startswith('application/json')
    assert response.json()['body'] == body


@pytest.mark.parametrize(
    'payload',
    [
        {'title': ' ', 'body': 'text', 'source_name': 's'},
        {'title': 't', 'body': '', 'source_name': 's'},
        {'title': 't', 'body': 'b', 'source_name': 's', 'tlp': 'WHITE'},
        {'title': 't', 'body': 'b', 'source_name': 's', 'source_url': 'javascript:alert(1)'},
        {'title': 't', 'body': 'b', 'source_name': 's', 'source_url': 'https://user:pass@example.com'},
        {'title': 't', 'body': 'b'},
    ],
)
def test_invalid_documents_rejected(authed: TestClient, payload: dict[str, str]) -> None:
    assert authed.post('/api/documents', json=payload).status_code == 422


def test_too_many_mentions_is_a_client_error(authed: TestClient) -> None:
    payload = {'title': 't', 'source_name': 's', 'body': 'CVE-2024-12345 ' * 2001}
    response = authed.post('/api/documents', json=payload)
    assert response.status_code == 422
    assert 'exceeds' in response.json()['detail']
    assert authed.get('/api/stats').json()['documents'] == 0


def test_invalid_mutations_and_missing_targets(authed: TestClient, make_document: MakeDocument) -> None:
    report = make_document()
    assert (
        authed.post(f'/api/documents/{report["id"]}/review', json={'status': 'invented'}).status_code == 422
    )
    assert authed.post(f'/api/documents/{report["id"]}/notes', json={'body': '   '}).status_code == 422
    assert authed.get('/api/documents/missing').status_code == 404
    assert authed.get('/api/documents/missing/export').status_code == 404
    assert authed.post('/api/documents/missing/review', json={'status': 'reviewed'}).status_code == 404
    assert authed.post('/api/documents/missing/notes', json={'body': 'x'}).status_code == 404
    assert authed.post('/api/observations/missing/review', json={'status': 'accepted'}).status_code == 404


def test_search_is_literal_and_filters_combine(authed: TestClient, make_document: MakeDocument) -> None:
    first = make_document(title='Literal 100% report', body='needle CVE-2024-12345')
    make_document(title='Another report', body='Unrelated text', tlp='CLEAR')
    make_document(title='Under_score', body='x', tlp='CLEAR')

    def ids(**params: Any) -> list[str]:
        return [d['id'] for d in authed.get('/api/documents', params=params).json()]

    assert ids(q='needle') == [first['id']]
    assert ids(q='100%') == [first['id']]
    assert ids(q='%') == [first['id']]  # '%' is literal, not a wildcard
    assert len(ids(q='_')) == 1  # '_' is literal, not a single-character wildcard
    assert len(ids(tlp='CLEAR')) == 2
    assert ids(tlp='CLEAR', q='needle') == []
    assert ids(status='new', q='needle') == [first['id']]
    assert ids(status='reviewed') == []


def test_pagination_is_bounded(authed: TestClient, make_document: MakeDocument) -> None:
    created = [make_document(title=f'Report {i}')['id'] for i in range(5)]
    page = authed.get('/api/documents', params={'limit': 2}).json()
    assert [d['id'] for d in page] == created[::-1][:2]  # newest first
    assert len(authed.get('/api/documents', params={'limit': 0}).json()) == 1
    assert len(authed.get('/api/documents', params={'offset': -5}).json()) == 5
    assert len(authed.get('/api/documents', params={'offset': 4}).json()) == 1
    assert authed.get('/api/documents', params={'limit': 'many'}).status_code == 422


def test_export_preserves_provenance_and_is_audited(authed: TestClient, make_document: MakeDocument) -> None:
    report = make_document()
    response = authed.get(f'/api/documents/{report["id"]}/export')
    assert response.headers['content-disposition'] == (
        f'attachment; filename="insight-report-{report["id"]}.json"'
    )
    exported = response.json()
    for key in ('tlp', 'body', 'source_url', 'observations', 'content_hash'):
        assert exported[key] == report[key]
    assert exported['format'] == 'insight-report-v1'
    assert 'Not STIX' in exported['handling_notice']
    events = authed.get('/api/audit').json()
    assert events[0]['action'] == 'document.export'
    assert events[0]['detail'] == 'AMBER+STRICT'


def test_demo_endpoint_is_idempotent(authed: TestClient) -> None:
    assert authed.post('/api/demo').json() == {'created': 3}
    assert authed.post('/api/demo').json() == {'created': 0}
    stats = authed.get('/api/stats').json()
    assert stats['documents'] == 3
    assert stats['unreviewed'] == 3
    assert stats['entities'] > 0


def test_watch_terms_listing(authed: TestClient) -> None:
    assert authed.get('/api/watch-terms').json() == []


def test_concurrent_import_conflict_is_409(authed: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    def conflicting(*_: Any, **__: Any) -> Any:
        raise IntegrityError(
            'INSERT', {}, Exception('UNIQUE constraint failed: entities.kind, entities.value')
        )

    monkeypatch.setattr(services, 'ingest', conflicting)
    response = authed.post('/api/documents', json={'title': 't', 'body': 'b', 'source_name': 's'})
    assert response.status_code == 409


def test_api_search_matches_ui_semantics(authed: TestClient, make_document: MakeDocument) -> None:
    """Regression: API search was case-sensitive on PostgreSQL and ignored source names (the UI did not)."""
    target = make_document(title='GlobalProtect advisory', source_name='Vendor PSIRT', body='text')
    make_document(title='Other', source_name='Someone', body='text')
    for q in ('globalprotect', 'GLOBALPROTECT', 'vendor psirt'):
        assert [d['id'] for d in authed.get('/api/documents', params={'q': q}).json()] == [target['id']]


def test_listing_documents_uses_a_constant_number_of_queries(
    app: FastAPI, authed: TestClient, make_document: MakeDocument, count_queries: Any
) -> None:
    """Regression (decision 3): one entity-count query per listed document."""
    engine = app.state.session_factory.kw['bind']

    def statements_for_listing() -> int:
        with count_queries(engine) as statements:
            assert authed.get('/api/documents', params={'limit': 200}).status_code == 200
        return len(statements)

    make_document(title='first')
    baseline = statements_for_listing()
    for i in range(20):
        make_document(title=f'more {i}', body=f'CVE-2024-{20000 + i}')
    assert statements_for_listing() == baseline
