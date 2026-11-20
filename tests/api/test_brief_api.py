"""``GET /api/brief``: the landing page's intel brief for scripts, limited to what the caller may see."""

from __future__ import annotations

from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from insight import services
from insight.schemas import DocumentInput


def test_brief_of_the_demo(authed: TestClient) -> None:
    assert authed.post('/api/demo').status_code == 200
    response = authed.get('/api/brief')
    assert response.status_code == 200, response.text
    brief: dict[str, Any] = response.json()
    assert (brief['days'], brief['headline']) == (7, '3 new reports from 3 sources.')
    assert [s['title'] for s in brief['sections']] == [
        'Exploited now', 'Most severe', 'Seen in several sources', 'Most-mentioned vendors'
    ]  # fmt: skip
    shared = brief['sections'][2]['items']
    assert {
        'text': '192.0.2.44 · 2 sources, 2 reports',
        'document_id': None,
        'entity': '192.0.2.44',
    } in shared
    assert all(s['empty'] for s in brief['sections'])


def test_an_empty_workspace_has_an_empty_brief(authed: TestClient) -> None:
    brief = authed.get('/api/brief', params={'days': 1}).json()
    assert brief['headline'] == 'No new reports in the last 1 day. Sync your sources to get the latest.'
    assert all(s['items'] == [] for s in brief['sections'])


@pytest.mark.parametrize('days', ['0', '31', 'week'])
def test_days_must_be_one_to_thirty(authed: TestClient, days: str) -> None:
    assert authed.get('/api/brief', params={'days': days}).status_code == 422


def test_a_tlp_limited_key_gets_a_brief_of_what_it_may_see(app: FastAPI, client: TestClient) -> None:
    with app.state.session_factory.begin() as db:
        for title, tlp in (('Public', 'GREEN'), ('Partner only', 'AMBER')):
            item = {'title': title, 'body': 'Seen 192.0.2.44.', 'source_name': title, 'tlp': tlp}
            services.ingest(db, DocumentInput.model_validate(item))
        _, token = services.create_api_key(db, name='siem', access='read', max_tlp='GREEN')
    headers = {'Authorization': f'Bearer {token}'}
    limited = client.get('/api/brief', headers=headers).json()
    assert limited['headline'] == '1 new report from 1 source.'
    assert limited['sections'][2]['items'] == []  # the AMBER report would make 192.0.2.44 "shared"
