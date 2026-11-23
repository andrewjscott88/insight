"""MITRE ATT&CK techniques over the API: catalog, tags on reports, summary, pivots, Navigator layer."""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import select

from insight import services
from insight.models import AuditEvent, DocumentTechnique
from insight.schemas import DocumentInput


def ingest(app: FastAPI, body: str, tlp: str = 'GREEN') -> str:
    with app.state.session_factory.begin() as db:
        doc, _ = services.ingest(
            db,
            DocumentInput.model_validate({'title': 'Report', 'body': body, 'source_name': 'S', 'tlp': tlp}),
        )
        return doc.id


@pytest.fixture
def signed_in(client: TestClient, login: Callable[..., str]) -> TestClient:
    login(client)
    return client


def audit_actions(app: FastAPI) -> list[str]:
    with app.state.session_factory() as db:
        return list(db.scalars(select(AuditEvent.action).where(AuditEvent.action.like('%techni%'))))


def test_the_catalog_can_be_searched(signed_in: TestClient) -> None:
    body = signed_in.get('/api/attack/techniques', params={'q': 'powershell'}).json()
    assert body['version']
    powershell = next(t for t in body['techniques'] if t['id'] == 'T1059.001')
    assert powershell == {
        'id': 'T1059.001',
        'name': 'Command and Scripting Interpreter: PowerShell',
        'tactics': ['Execution'],
        'url': 'https://attack.mitre.org/techniques/T1059/001/',
        'domain': 'enterprise',
    }
    assert len(signed_in.get('/api/attack/techniques', params={'limit': 5}).json()['techniques']) == 5


def test_a_report_shows_the_techniques_written_in_it(app: FastAPI, signed_in: TestClient) -> None:
    doc = ingest(app, 'Initial access by spearphishing attachment (T1566.001).')
    (tag,) = signed_in.get(f'/api/documents/{doc}/techniques').json()
    assert tag['id'] == 'T1566.001'
    assert tag['source'] == 'report'
    assert tag['tactics'] == ['Initial Access']
    assert 'T1566.001' in tag['evidence']
    assert tag['in_catalog'] is True


def test_analysts_add_and_remove_techniques(app: FastAPI, signed_in: TestClient) -> None:
    doc = ingest(app, 'Loader ran PowerShell (T1059.001).')
    added = signed_in.post(f'/api/documents/{doc}/techniques', json={'technique_id': 't1486'})
    assert added.status_code == 200, added.text
    assert (added.json()['id'], added.json()['source'], added.json()['actor']) == (
        'T1486',
        'analyst',
        'operator',
    )
    removed = signed_in.delete(f'/api/documents/{doc}/techniques/T1059.001')
    assert removed.json() == {'removed': 'T1059.001'}
    assert [t['id'] for t in signed_in.get(f'/api/documents/{doc}/techniques').json()] == ['T1486']
    assert sorted(audit_actions(app)) == ['technique.tag', 'technique.untag']


@pytest.mark.parametrize(
    ('payload', 'status'),
    [({'technique_id': 'T9999'}, 422), ({'technique_id': 'powershell'}, 422), ({}, 422), ({'x': 1}, 422)],
)
def test_bad_technique_ids_are_refused(
    app: FastAPI, signed_in: TestClient, payload: dict[str, Any], status: int
) -> None:
    doc = ingest(app, 'Nothing mapped.')
    assert signed_in.post(f'/api/documents/{doc}/techniques', json=payload).status_code == status


def test_unknown_reports_and_tags_are_404(app: FastAPI, signed_in: TestClient) -> None:
    doc = ingest(app, 'Nothing mapped.')
    assert signed_in.get('/api/documents/missing/techniques').status_code == 404
    assert (
        signed_in.post('/api/documents/missing/techniques', json={'technique_id': 'T1486'}).status_code == 404
    )
    assert signed_in.delete(f'/api/documents/{doc}/techniques/T1486').status_code == 404
    assert signed_in.get('/api/attack/techniques/T9999/documents').status_code == 404


def test_the_summary_and_pivot_show_what_reports_describe(app: FastAPI, signed_in: TestClient) -> None:
    first = ingest(app, 'Ransomware: T1486.')
    second = ingest(app, 'Encryption again, T1486, after T1059.001.')
    summary = signed_in.get('/api/attack/summary', params={'days': 0}).json()
    assert summary['period'] == 'all time'
    assert [(t['id'], t['reports']) for t in summary['techniques']] == [('T1486', 2), ('T1059.001', 1)]
    assert summary['techniques'][0]['tactics'] == ['Impact']
    pivot = signed_in.get('/api/attack/techniques/T1486/documents').json()
    assert pivot['name'] == 'Data Encrypted for Impact'
    assert {d['id'] for d in pivot['documents']} == {first, second}
    assert signed_in.get('/api/attack/summary', params={'days': 4000}).status_code == 422


def test_default_summary_preserves_retired_tags_but_navigator_omits_them(
    app: FastAPI, signed_in: TestClient
) -> None:
    """Regression: the new default domain filter silently hid legacy retired report tags."""
    document_id = ingest(app, 'Legacy report with a retired mapping.')
    with app.state.session_factory.begin() as db:
        db.add(
            DocumentTechnique(
                document_id=document_id, technique_id='T9999', source='analyst', status='tagged', actor='test'
            )
        )
    summary = signed_in.get('/api/attack/summary', params={'days': 0})
    assert summary.status_code == 200
    assert [(row['id'], row['reports']) for row in summary.json()['techniques']] == [('T9999', 1)]
    for domain in ('mobile', 'ics'):
        assert signed_in.get('/api/attack/summary', params={'domain': domain}).json()['techniques'] == []
    layer = signed_in.get('/api/attack/navigator', params={'days': 0})
    assert layer.status_code == 200
    assert layer.json()['techniques'] == []


def test_the_navigator_layer_downloads_and_is_audited(app: FastAPI, signed_in: TestClient) -> None:
    ingest(app, 'Ransomware: T1486.')
    response = signed_in.get('/api/attack/navigator', params={'days': 7})
    assert response.status_code == 200
    assert response.headers['content-disposition'] == 'attachment; filename="insight-attack-layer-7d.json"'
    layer = json.loads(response.text)
    assert layer['versions']['layer'] == '4.5'
    assert layer['name'] == 'Insight: techniques in reports (last 7 days)'
    assert [(t['techniqueID'], t['score']) for t in layer['techniques']] == [('T1486', 1)]
    with app.state.session_factory() as db:
        event = db.scalars(select(AuditEvent).where(AuditEvent.action == 'attack.navigator')).one()
    assert json.loads(event.detail) == {'days': 7, 'max_tlp': None, 'techniques': 1, 'domain': 'enterprise'}


@pytest.mark.parametrize(('domain', 'identifier'), [('mobile', 'T1398'), ('ics', 'T0800')])
def test_mobile_and_ics_tags_pivots_and_navigator(
    app: FastAPI,
    signed_in: TestClient,
    domain: str,
    identifier: str,
) -> None:
    """Regression: non-Enterprise tags must stay in their own catalog and Navigator domain."""
    doc = ingest(app, f'Mapped {identifier} alongside T1486.')
    catalog = signed_in.get('/api/attack/techniques', params={'q': identifier, 'domain': domain}).json()
    assert catalog['domain'] == domain
    assert catalog['techniques'][0]['id'] == identifier
    tags = signed_in.get(f'/api/documents/{doc}/techniques').json()
    assert next(t for t in tags if t['id'] == identifier)['domain'] == domain
    summary = signed_in.get('/api/attack/summary', params={'domain': domain}).json()
    assert [t['id'] for t in summary['techniques']] == [identifier]
    enterprise = signed_in.get('/api/attack/summary').json()
    assert [t['id'] for t in enterprise['techniques']] == ['T1486']
    layer = signed_in.get('/api/attack/navigator', params={'domain': domain}).json()
    assert layer['domain'] == f'{domain}-attack'
    assert [t['techniqueID'] for t in layer['techniques']] == [identifier]
    pivot = signed_in.get(f'/api/attack/techniques/{identifier}/documents').json()
    assert [d['id'] for d in pivot['documents']] == [doc]
    assert signed_in.get('/api/attack/summary', params={'domain': '../bad'}).status_code == 422
