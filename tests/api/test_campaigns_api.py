"""API tests for sharing limits on manually recorded actor and campaign links."""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient

from .test_threat_guides_api import ingest, key


def test_manual_campaign_links_obey_reader_writer_and_link_labels(app: FastAPI, authed: TestClient) -> None:
    green = key(app, max_tlp='GREEN')
    doc = ingest(app, 'Visible example', 'Synthetic 192.0.2.31.', 'GREEN')
    created = authed.post('/api/campaigns', json={'name': 'Example campaign', 'tlp': 'GREEN'})
    assert created.status_code == 201
    campaign = created.json()['id']
    path = f'/api/campaigns/{campaign}'
    assert authed.get('/api/campaigns', headers=green).json()['campaigns'][0]['id'] == campaign
    assert authed.get(path, headers=green).json()['name'] == 'Example campaign'
    data = {'target_kind': 'document', 'target_id': doc, 'tlp': 'AMBER'}
    assert authed.post(path + '/links', json=data, headers=green).status_code == 403
    assert authed.post(path + '/links', json=data).status_code == 201
    assert authed.get(path + '/links', headers=green).json() == {'links': []}
    assert authed.get(path + '/links').json()['links'][0]['tlp'] == 'AMBER'
    assert authed.delete(path + f'/links/document/{doc}', headers=green).status_code == 404
    assert authed.delete(path + f'/links/document/{doc}').status_code == 200
    assert authed.get(path + '/links').json() == {'links': []}
    restricted = authed.post('/api/campaigns', json={'name': 'Example restricted', 'tlp': 'AMBER'})
    assert restricted.status_code == 201
    assert authed.get('/api/campaigns/' + restricted.json()['id'], headers=green).status_code == 404


def test_new_actor_links_reject_catalog_groups_and_preserve_legacy_document_links(
    app: FastAPI, authed: TestClient
) -> None:
    green = key(app, max_tlp='GREEN')
    doc = ingest(app, 'Shared example', 'Example 192.0.2.44.', 'GREEN')
    actor = authed.post('/api/actors', json={'name': 'Example actor', 'tlp': 'GREEN'}).json()['ref']
    path = f'/api/actors/{actor}'
    data = {'target_kind': 'technique', 'target_id': 'T1059.001', 'tlp': 'GREEN'}
    assert authed.post('/api/actors/G0016/links', json=data).status_code == 404
    assert authed.post(path + '/links', json=data).json()['name'].endswith('PowerShell')
    assert (
        authed.post(
            path + '/documents', json={'document_id': doc, 'note': 'Restricted TLP:RED'}, headers=green
        ).status_code
        == 403
    )
    assert (
        authed.post(
            path + '/documents',
            json={'document_id': doc, 'tlp': 'AMBER', 'note': 'Private note'},
        ).status_code
        == 201
    )
    assert len(authed.get(path + '/links').json()['links']) == 2
    assert len(authed.get(path + '/links', headers=green).json()['links']) == 1
    assert 'Private note' not in authed.get(path, headers=green).text
    assert authed.delete(path + '/links/technique/T1059.001', headers=green).status_code == 200
