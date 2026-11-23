"""The hunt builder uses real auth, sharing limits and attributed download audit events."""

from __future__ import annotations

from dataclasses import replace
from io import BytesIO

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pypdf import PdfReader
from sqlalchemy import select

from insight import services
from insight.models import AuditEvent
from insight.schemas import ActorInput, ActorLinkInput

from .test_threat_guides_api import ingest, key


@pytest.mark.parametrize('format', ['json', 'md', 'pdf'])
def test_guide_formats_preserve_labels_and_audit_the_reader(
    app: FastAPI, client: TestClient, format: str
) -> None:
    doc = ingest(app, 'Visible source', 'PUBLISHER-ONLY body. c2-hunt-domain.net', 'GREEN', accept=True)
    with app.state.session_factory.begin() as db:
        services.link_report(db, 'G0016', ActorLinkInput(document_id=doc))
    reader = key(app, access='read', max_tlp='GREEN')
    response = client.get(f'/api/hunt-guides/actor/G0016?format={format}', headers=reader)
    assert response.status_code == 200, response.text
    if format == 'pdf':
        parsed = PdfReader(BytesIO(response.content))
        content = '\n'.join(page.extract_text() for page in parsed.pages)
        assert response.headers['content-type'] == 'application/pdf'
        assert all('TLP:GREEN' in page.extract_text() for page in parsed.pages)
    else:
        content = response.text
    assert 'PUBLISHER-ONLY' not in content
    assert doc in content
    if format != 'json':
        assert f'hunt-guide-actor-G0016.{format}' in response.headers['content-disposition']
        assert response.headers['cache-control'] == 'no-store'
    else:
        assert response.json()['tlp'] == 'GREEN'
    with app.state.session_factory() as db:
        event = db.scalars(select(AuditEvent).where(AuditEvent.action == 'hunt.guide')).one()
        assert event.actor.startswith('api-key:')
        assert event.object_id == 'G0016'
        assert f'actor; {format}; TLP:GREEN' == event.detail


def test_hidden_and_missing_subjects_have_identical_responses(app: FastAPI, client: TestClient) -> None:
    with app.state.session_factory.begin() as db:
        hidden = services.create_actor(db, ActorInput(name='HIDDEN hunt group', tlp='AMBER'))
        ref = hidden.id
    reader = key(app, access='read', max_tlp='GREEN')
    known = client.get(f'/api/hunt-guides/actor/{ref}', headers=reader)
    missing = client.get('/api/hunt-guides/actor/missing', headers=reader)
    assert known.status_code == missing.status_code == 404
    assert known.json() == missing.json() == {'detail': 'Hunt guide choice not found'}
    found = client.get('/api/hunt-guides?kind=actor&q=HIDDEN+hunt+group', headers=reader)
    assert found.status_code == 200
    assert found.json() == {'actor': []}


def test_instance_limit_and_invalid_parameters(app: FastAPI, client: TestClient) -> None:
    hidden = ingest(app, 'HIDDEN ransomware', 'hidden-hunt-domain.net', 'AMBER', accept=True)
    reader = key(app, access='read')
    app.state.settings = replace(app.state.settings, max_tlp='GREEN')
    response = client.get('/api/hunt-guides/theme/ransomware', headers=reader)
    assert response.status_code == 200
    assert 'HIDDEN' not in response.text
    assert hidden not in response.text
    assert response.json()['tlp'] == 'CLEAR'
    for path, status in [
        ('/api/hunt-guides?kind=nope', 404),
        ('/api/hunt-guides/theme/nope', 404),
        ('/api/hunt-guides/theme/ransomware?format=html', 422),
        ('/api/hunt-guides?q=' + 'x' * 121, 422),
    ]:
        assert client.get(path, headers=reader).status_code == status
