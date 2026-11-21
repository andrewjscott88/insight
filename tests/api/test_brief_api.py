"""``GET /api/brief``: the landing page's intel brief for scripts, limited to what the caller may see."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from insight import services
from insight.schemas import DocumentInput


def add(app: FastAPI, title: str, source: str, *, tlp: str = 'CLEAR', body: str = 'Seen 192.0.2.44.') -> None:
    with app.state.session_factory.begin() as db:
        item = {'title': title, 'body': body, 'source_name': source, 'tlp': tlp}
        services.ingest(db, DocumentInput.model_validate(item))


def test_brief_has_an_executive_summary_and_linked_sections(app: FastAPI, authed: TestClient) -> None:
    add(app, 'Scanning wave', 'SANS')
    add(app, 'Advisory', 'NCSC')
    response = authed.get('/api/brief')
    assert response.status_code == 200, response.text
    brief: dict[str, Any] = response.json()
    assert brief['days'] == 7
    assert (brief['report_count'], brief['source_count'], brief['recent_reports']) == (2, 2, 2)
    assert datetime.fromisoformat(brief['as_of']) - datetime.fromisoformat(brief['since']) == timedelta(
        days=7
    )
    assert all(isinstance(note, str) for note in brief['coverage'])
    assert {'title', 'text', 'action', 'evidence'} == brief['highlights'][-1].keys()
    assert len(brief['highlights'][-1]['evidence']) == 2
    assert brief['summary'][0] == 'In the last 7 days, 2 new reports came in from 2 sources.'
    titles = [s['title'] for s in brief['sections']]
    assert titles == [
        'Exploited now',
        'Most severe',
        'Your watch terms',
        'Seen in several sources',
        'Most-mentioned vendors',
    ]
    (shared,) = brief['sections'][3]['items']
    assert shared == {
        'text': '192.0.2.44 · 2 sources, 2 reports',
        'document_id': None,
        'entity': '192.0.2.44',
        'search': None,
    }


def test_the_demo_does_not_count(authed: TestClient) -> None:
    assert authed.post('/api/demo').status_code == 200
    brief = authed.get('/api/brief', params={'days': 1}).json()
    assert brief['summary'] == [
        'No recent reports are available for the last 1 day. Check the source status below.'
    ]
    assert all(s['items'] == [] for s in brief['sections'])


@pytest.mark.parametrize('days', ['0', '31', 'week'])
def test_days_must_be_one_to_thirty(authed: TestClient, days: str) -> None:
    assert authed.get('/api/brief', params={'days': days}).status_code == 422


def test_a_tlp_limited_key_gets_a_brief_of_what_it_may_see(app: FastAPI, client: TestClient) -> None:
    add(app, 'Public', 'Public feed', tlp='GREEN')
    add(app, 'Partner only', 'Partner', tlp='AMBER', body='Seen 192.0.2.44. Also watch-me.')
    with app.state.session_factory.begin() as db:
        services.add_watch_term(db, 'watch-me')
        _, token = services.create_api_key(db, name='siem', access='read', max_tlp='GREEN')
    limited = client.get('/api/brief', headers={'Authorization': f'Bearer {token}'}).json()
    assert limited['summary'][0] == 'In the last 7 days, 1 new report came in from 1 source.'
    assert 'None of the new reports mention your watch terms.' in limited['summary']
    assert limited['sections'][3]['items'] == []  # the AMBER report would make 192.0.2.44 "shared"
    assert (limited['report_count'], limited['source_count'], limited['recent_reports']) == (1, 1, 1)
    assert 'Partner only' not in str(limited['highlights'])
    assert all(item['title'] != 'Possible relevance to your organization' for item in limited['highlights'])
