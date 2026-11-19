"""INSIGHT_MAX_TLP through the HTTP API (session and API key) and the start-up warning."""

from __future__ import annotations

import dataclasses
import logging
from collections.abc import Callable

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from insight import services
from insight.config import Settings
from insight.main import create_app
from insight.schemas import TLP, DocumentInput

REPORT = {'title': 'Briefing', 'body': 'Seen at 192.0.2.8.', 'source_name': 'Partner'}


def test_red_is_refused_by_default(authed: TestClient) -> None:
    response = authed.post('/api/documents', json={**REPORT, 'tlp': 'RED'})
    assert response.status_code == 422
    assert 'TLP:RED reports cannot be stored here' in response.json()['detail']
    assert authed.get('/api/stats').json()['documents'] == 0


def test_a_red_marking_is_refused_even_when_submitted_lower(authed: TestClient) -> None:
    response = authed.post('/api/documents', json={**REPORT, 'body': 'TLP:RED\nSeen at 192.0.2.8.'})
    assert response.status_code == 422
    assert response.json()['detail'].startswith('Refused: the text carries a TLP:RED marking')
    assert authed.get('/api/stats').json()['documents'] == 0


def test_the_api_key_is_held_to_the_same_limit(app: FastAPI, client: TestClient) -> None:
    with app.state.session_factory.begin() as db:
        _, token = services.create_api_key(db, name='scripts', access='read-write')
    response = client.post(
        '/api/documents', json={**REPORT, 'tlp': 'RED'}, headers={'Authorization': f'Bearer {token}'}
    )
    assert response.status_code == 422


def test_amber_strict_is_accepted(authed: TestClient) -> None:
    response = authed.post('/api/documents', json={**REPORT, 'tlp': 'AMBER+STRICT'})
    assert response.status_code == 200
    assert response.json()['tlp'] == 'AMBER+STRICT'


def signed_in(settings: Settings, login: Callable[..., str], max_tlp: TLP) -> TestClient:
    client = TestClient(create_app(dataclasses.replace(settings, max_tlp=max_tlp), with_ui=False))
    client.follow_redirects = False
    login(client)
    return client


def test_a_lower_limit_is_enforced(settings: Settings, login: Callable[..., str]) -> None:
    client = signed_in(settings, login, 'GREEN')
    assert client.post('/api/documents', json={**REPORT, 'tlp': 'AMBER'}).status_code == 422
    assert client.post('/api/documents', json={**REPORT, 'tlp': 'GREEN'}).status_code == 200


def test_red_is_accepted_when_allowed(settings: Settings, login: Callable[..., str]) -> None:
    client = signed_in(settings, login, 'RED')
    response = client.post('/api/documents', json={**REPORT, 'body': 'TLP:RED\nSeen at 192.0.2.8.'})
    assert response.status_code == 200
    assert (response.json()['tlp'], response.json()['tlp_raised_from']) == ('RED', 'AMBER')


def test_startup_warns_about_stored_reports_above_the_limit(
    settings: Settings, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.WARNING, logger='insight.auth')
    create_app(settings, with_ui=False)
    assert 'above INSIGHT_MAX_TLP' not in caplog.text
    allowing = create_app(dataclasses.replace(settings, max_tlp='RED'), with_ui=False)
    with allowing.state.session_factory.begin() as db:
        services.ingest(db, DocumentInput.model_validate({**REPORT, 'tlp': 'RED'}))
    create_app(settings, with_ui=False)
    assert '1 stored report(s) are labelled above INSIGHT_MAX_TLP=AMBER+STRICT' in caplog.text
