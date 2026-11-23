"""Imported catalog names work through the real API without creating attribution or leaking reports."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from tests.unit.test_adversary_library import alias_cluster
from tests.unit.test_threat_library import mini_bundle

from insight import services, threat_library
from insight.schemas import ActorLinkInput, CriterionInput, RequirementInput
from insight.threat_library_build import build
from insight.threat_library_sync import render

from .test_threat_guides_api import ingest, key


@pytest.fixture(autouse=True)
def sourced_library(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Iterator[None]:
    monkeypatch.setenv('INSIGHT_DATA_DIR', str(tmp_path))
    (tmp_path / 'threat-library.json').write_text(
        render(build(mini_bundle(), alias_cluster())), encoding='utf-8'
    )
    threat_library.library.cache_clear()
    yield
    threat_library.library.cache_clear()


def test_imported_alias_search_and_report_names_respect_labels_and_never_create_links(
    app: FastAPI, client: TestClient
) -> None:
    visible = ingest(app, 'Visible report', 'New Panda uses visible-c2.biz.', accept=True)
    hidden = ingest(app, 'HIDDEN-ALIAS-REPORT', 'New Panda uses hidden-c2.biz.', 'AMBER', accept=True)
    ingest(app, 'Partial word', 'New PandaExtra is unrelated.')
    headers = key(app, access='read', max_tlp='GREEN')
    response = client.get('/api/actors', params={'q': 'new panda'}, headers=headers)
    assert response.status_code == 200
    assert [g['ref'] for g in response.json()['groups']] == ['G9001']
    guide = client.get('/api/actors/G9001/guide', headers=headers)
    assert guide.status_code == 200
    assert guide.json()['reports_naming_group'] == 1
    assert [r['id'] for r in guide.json()['reports']] == [visible]
    assert guide.json()['reports'][0]['via'] == 'named'
    assert guide.json()['hunt']['sweep']['indicators'] == []
    assert 'HIDDEN-ALIAS-REPORT' not in guide.text
    assert hidden not in guide.text
    assert client.get('/api/actors/G9001', headers=headers).json()['linked_reports'] == []


def test_requirement_alias_terms_work_but_group_criteria_still_need_a_visible_explicit_link(
    app: FastAPI, client: TestClient
) -> None:
    named = ingest(app, 'Only names it', 'New Panda sent lures.')
    hidden = ingest(app, 'HIDDEN-REQUIREMENT', 'New Panda sent lures.', 'AMBER')
    with app.state.session_factory.begin() as db:
        group = services.create_requirement(
            db,
            RequirementInput(
                kind='pir',
                question='What is linked to Test Panda?',
                tlp='GREEN',
                criteria=[CriterionInput(kind='group', value='G9001')],
            ),
        )
        term = services.create_requirement(
            db,
            RequirementInput(
                kind='pir',
                question='What names New Panda?',
                tlp='GREEN',
                criteria=[CriterionInput(kind='term', value='New Panda')],
            ),
        )
        group_id, term_id = group.id, term.id
        assert services.get_requirement(db, group_id).matches == ()
        assert {m.document_id for m in services.get_requirement(db, term_id, max_tlp='GREEN').matches} == {
            named
        }
        services.link_report(db, 'G9001', ActorLinkInput(document_id=named, tlp='AMBER'))
        services.link_report(db, 'G9001', ActorLinkInput(document_id=hidden, tlp='AMBER'))
        assert len(services.get_requirement(db, group_id).matches) == 2
        assert services.get_requirement(db, group_id, max_tlp='GREEN').matches == ()
    headers = key(app, access='read', max_tlp='GREEN')
    response = client.get(f'/api/requirements/{group_id}', headers=headers)
    assert response.status_code == 200
    assert response.json()['matches'] == []
    assert 'HIDDEN-REQUIREMENT' not in response.text
    assert hidden not in response.text
