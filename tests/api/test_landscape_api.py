"""The threat landscape over the API: JSON for scripts, a Markdown briefing to share (audited)."""

from __future__ import annotations

import json
from collections.abc import Callable

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import select

from insight import services
from insight.models import AuditEvent
from insight.schemas import DocumentInput


@pytest.fixture
def signed_in(client: TestClient, login: Callable[..., str]) -> TestClient:
    login(client)
    return client


def ingest(app: FastAPI, title: str, body: str, tlp: str = 'GREEN') -> None:
    with app.state.session_factory.begin() as db:
        services.ingest(db, DocumentInput(title=title, body=body, source_name='Feed', tlp=tlp))


def test_the_landscape_names_trending_threats_and_their_evidence(app: FastAPI, signed_in: TestClient) -> None:
    ingest(app, 'Ransom wave', 'A ransomware gang encrypted servers (T1486) after phishing (T1566.001).')
    ingest(app, 'Second wave', 'More ransomware.', tlp='AMBER')
    body = signed_in.get('/api/landscape').json()
    assert body['days'] == 7
    assert body['tlp'] == 'AMBER'
    assert body['reports'] == 2
    ransomware = next(t for t in body['threats'] if t['key'] == 'ransomware')
    assert ransomware['change'] == {'label': 'no-history', 'current': 2, 'usual': None}
    assert ransomware['impact']
    assert {r['text'] for r in ransomware['reports']} == {'Ransom wave · Feed', 'Second wave · Feed'}
    assert all(r['document_id'] for r in ransomware['reports'])
    assert {t['shortname'] for t in body['tactics']} == {'impact', 'initial-access'}
    assert body['summary'][0] == 'The most reported kind of threat is ransomware, in 2 reports.'
    assert body['summary'][-1] == 'In the last 7 days, 2 new reports came in from 1 source.'
    assert any('cannot show trends yet' in line for line in body['caveats'])
    assert body['brief']['sections'][0]['title'] == 'Exploited now'


@pytest.mark.parametrize('days', [0, 31, -1])
def test_the_period_is_one_to_thirty_days(signed_in: TestClient, days: int) -> None:
    assert signed_in.get('/api/landscape', params={'days': days}).status_code == 422
    assert signed_in.get('/api/landscape/briefing', params={'days': days}).status_code == 422


def test_the_briefing_downloads_with_its_tlp_and_is_audited(app: FastAPI, signed_in: TestClient) -> None:
    ingest(app, 'Ransom wave', 'Ransomware again.', tlp='AMBER')
    response = signed_in.get('/api/landscape/briefing', params={'days': 30})
    assert response.status_code == 200
    assert response.headers['content-type'] == 'text/markdown; charset=utf-8'
    assert response.headers['content-disposition'] == 'attachment; filename="insight-threat-landscape-30d.md"'
    lines = response.text.splitlines()
    assert lines[0] == '**TLP:AMBER**'
    assert '# Threat landscape: the last 30 days' in lines
    assert '### Ransomware: No history yet' in lines
    with app.state.session_factory() as db:
        event = db.scalars(select(AuditEvent).where(AuditEvent.action == 'landscape.briefing')).one()
    assert json.loads(event.detail) == {'days': 30, 'max_tlp': None, 'tlp': 'AMBER'}
