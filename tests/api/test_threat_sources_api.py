"""Switched-off sources over the API, and publishers' reuse rules in the report export (ADR 0021)."""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient

from insight import services
from insight.schemas import DocumentInput
from insight.services import SourceRef


def test_sources_say_whether_they_are_in_use_and_what_may_leave(authed: TestClient) -> None:
    listed = {s['key']: s for s in authed.get('/api/sources').json()}
    assert (listed['talos']['category'], listed['talos']['optional'], listed['talos']['in_use']) == (
        'threat research',
        True,
        False,
    )
    assert listed['talos']['reuse'] == 'metadata'
    assert (listed['cisa-kev']['in_use'], listed['cisa-kev']['reuse']) == (True, 'public')
    assert listed['the-record']['category'] == 'news'


def test_a_switched_off_source_cannot_be_synced_or_scheduled(authed: TestClient) -> None:
    response = authed.post('/api/sources/talos/sync')
    assert response.status_code == 409
    detail = 'Cisco Talos is switched off. Switch it on in Settings › Sources first.'
    assert response.json()['detail'] == detail
    assert authed.put('/api/schedules/talos', json={'interval_minutes': 60}).status_code == 409
    assert authed.put('/api/schedules/talos', json={'interval_minutes': 0}).status_code == 200


def test_the_report_export_leaves_out_a_metadata_only_publishers_words(
    app: FastAPI, authed: TestClient
) -> None:
    with app.state.session_factory.begin() as db:
        doc, _ = services.ingest(
            db,
            DocumentInput(
                title='ISC diary', body='Scanning from 198.51.100.4.', source_name='SANS', tlp='CLEAR'
            ),
            ref=SourceRef('sans-isc', 'diary-1'),
        )
        public, _ = services.ingest(
            db,
            DocumentInput(
                title='KEV entry', body='Exploited: 198.51.100.5.', source_name='CISA', tlp='CLEAR'
            ),
            ref=SourceRef('cisa-kev', 'CVE-2026-0001'),
        )
    exported = authed.get(f'/api/documents/{doc.id}/export').json()
    assert exported['title'] == 'ISC diary'
    assert exported['body'] == ''
    assert [o['evidence'] for o in exported['observations']] == ['']
    assert [o['value'] for o in exported['observations']] == ['198.51.100.4']
    assert 'metadata only' in exported['handling_notice']
    kept = authed.get(f'/api/documents/{public.id}/export').json()
    assert kept['body'] == 'Exploited: 198.51.100.5.'
    assert 'metadata only' not in kept['handling_notice']
