"""The synthetic full-length reports through the HTTP API: ingest, export, pivots, TLP policy and offsets."""

from __future__ import annotations

import dataclasses
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from insight.config import Settings

REPORTS = Path(__file__).parent.parent / 'corpus' / 'reports'
GLASS = (REPORTS / 'notional-intrusion-report.md').read_text('utf-8')
SALT = (REPORTS / 'notional-salt-meridian.md').read_text('utf-8')


@pytest.fixture
def settings(settings: Settings) -> Settings:
    """These tests process the synthetic TLP:RED report on purpose, so they opt in: INSIGHT_MAX_TLP=RED."""
    return dataclasses.replace(settings, max_tlp='RED')


def payload(body: str = GLASS, **changes: str) -> dict[str, str]:
    return {
        'title': 'Notional Intrusion Report (synthetic)',
        'body': body,
        'source_name': 'Notional CTI Cell',
        'source_url': 'https://intel.example.org/reports/NTR-2025-0314',
        'tlp': 'AMBER',
        **changes,
    }


def ingest(client: TestClient, **changes: str) -> dict[str, Any]:
    response = client.post('/api/documents', json=payload(**changes))
    assert response.status_code == 200, response.text
    result: dict[str, Any] = response.json()
    return result


@pytest.mark.parametrize(('body', 'observations', 'entities'), [(GLASS, 35, 21), (SALT, 52, 41)])
def test_reports_round_trip_through_ingest_and_export(
    authed: TestClient, body: str, observations: int, entities: int
) -> None:
    report = ingest(authed, body=body)
    assert (report['created'], len(report['observations']), report['entity_count']) == (
        True,
        observations,
        entities,
    )
    exported = authed.get(f'/api/documents/{report["id"]}/export').json()
    assert exported['body'] == body  # non-ASCII, emoji and HTML survive byte-for-byte
    assert exported['observations'] == report['observations']


def test_embedded_html_stays_inert_text(authed: TestClient) -> None:
    report = ingest(authed)
    response = authed.get(f'/api/documents/{report["id"]}')
    assert response.headers['content-type'].startswith('application/json')
    assert '<script src="https://cdn-update.example.com/x.js"></script>' in response.json()['body']


def test_pivot_from_an_indicator_back_to_the_report(authed: TestClient) -> None:
    report = ingest(authed)
    rows = authed.get('/api/entities', params={'q': '203.0.113.45'}).json()
    assert {(r['kind'], r['value']) for r in rows} == {
        ('ip', '203.0.113.45'),
        ('url', 'https://203.0.113.45:8443/api/v2/beacon'),
    }
    ip = next(r for r in rows if r['kind'] == 'ip')
    pivot = authed.get(f'/api/entities/{ip["id"]}').json()
    assert [d['id'] for d in pivot['documents']] == [report['id']]
    assert pivot['document_count'] == 1


def test_entity_pivots_are_paginated(authed: TestClient) -> None:
    for i in range(7):
        ingest(authed, title=f'Copy {i}')
    ip = next(
        r for r in authed.get('/api/entities', params={'q': '203.0.113.45'}).json() if r['kind'] == 'ip'
    )
    page = authed.get(f'/api/entities/{ip["id"]}', params={'limit': 3, 'offset': 3}).json()
    assert (page['document_count'], page['offset'], len(page['documents'])) == (7, 3, 3)


def test_windows_line_endings_deduplicate(authed: TestClient) -> None:
    """Regression: a CRLF copy of the same report became a second document."""
    first = ingest(authed)
    crlf = authed.post('/api/documents', json=payload(body=GLASS.replace('\n', '\r\n'))).json()
    assert (crlf['created'], crlf['id']) == (False, first['id'])


def test_omitted_tlp_defaults_to_amber(authed: TestClient) -> None:
    """Regression: the API defaulted to TLP:CLEAR while the UI defaulted to AMBER."""
    body = {k: v for k, v in payload(body='No marking here; CVE-2024-12345.').items() if k != 'tlp'}
    assert authed.post('/api/documents', json=body).json()['tlp'] == 'AMBER'


@pytest.mark.parametrize('submitted', ['CLEAR', 'AMBER', None])
def test_tlp_red_marking_is_enforced(authed: TestClient, submitted: str | None) -> None:
    """Regression: the TLP:RED SALT MERIDIAN report was stored as CLEAR (API) or AMBER (UI)."""
    body = payload(body=SALT, tlp=submitted or 'AMBER')
    if submitted is None:
        del body['tlp']
    report = authed.post('/api/documents', json=body).json()
    assert report['tlp'] == 'RED'
    assert report['tlp_raised_from'] == (submitted or 'AMBER')
    actions = [e['action'] for e in authed.get('/api/audit').json()]
    assert 'document.tlp_raised' in actions


def test_utf16_offsets_let_javascript_slice_correctly(authed: TestClient) -> None:
    report = ingest(authed, body=SALT)
    utf16 = SALT.encode('utf-16-le')
    for obs in report['observations']:
        raw = utf16[2 * obs['start_offset_utf16'] : 2 * obs['end_offset_utf16']].decode('utf-16-le')
        assert raw == SALT[obs['start_offset'] : obs['end_offset']]


@pytest.mark.parametrize('query', ['istanbul', 'İSTANBUL', 'café-login', 'überwachung'])
def test_search_is_unicode_aware(authed: TestClient, query: str) -> None:
    ingest(authed, body=GLASS, title='GLASS')
    ingest(authed, body=SALT, title='SALT')
    assert len(authed.get('/api/documents', params={'q': query}).json()) == 1
