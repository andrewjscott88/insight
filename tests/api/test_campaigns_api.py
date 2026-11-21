"""API tests for sharing limits on manually recorded actor and campaign links."""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient

from .test_threat_guides_api import ingest, key


def test_manual_campaign_links_obey_reader_writer_and_link_labels(app: FastAPI, client: TestClient) -> None:
    writer = key(app)
    green = key(app, max_tlp='GREEN')
    reader = key(app, access='read-only')
    doc = ingest(app, 'Visible example', 'Synthetic 192.0.2.31.', 'GREEN')
    created = client.post('/api/campaigns', json={'name': 'Example campaign', 'tlp': 'GREEN'}, headers=writer)
    assert created.status_code == 201
    campaign = created.json()['id']
    path = f'/api/campaigns/{campaign}'
    assert client.get('/api/campaigns', headers=green).json()['campaigns'][0]['id'] == campaign
    assert client.get(path, headers=green).json()['name'] == 'Example campaign'
    data = {'target_kind': 'document', 'target_id': doc, 'tlp': 'AMBER'}
    assert client.post(path + '/links', json=data, headers=reader).status_code == 403
    assert client.post(path + '/links', json=data, headers=green).status_code == 403
    assert client.post(path + '/links', json=data, headers=writer).status_code == 201
    assert client.get(path + '/links', headers=green).json() == {'links': []}
    assert client.get(path + '/links', headers=writer).json()['links'][0]['tlp'] == 'AMBER'
    assert client.delete(path + f'/links/document/{doc}', headers=green).status_code == 404
    assert client.delete(path + f'/links/document/{doc}', headers=writer).status_code == 200
    assert client.get(path + '/links', headers=writer).json() == {'links': []}
    restricted = client.post(
        '/api/campaigns', json={'name': 'Example restricted', 'tlp': 'RED'}, headers=writer
    )
    assert client.get('/api/campaigns/' + restricted.json()['id'], headers=green).status_code == 404


def test_new_actor_links_reject_catalog_groups_and_preserve_legacy_document_links(
    app: FastAPI, client: TestClient
) -> None:
    writer = key(app)
    green = key(app, max_tlp='GREEN')
    doc = ingest(app, 'Shared example', 'Example 192.0.2.44.', 'GREEN')
    actor = client.post('/api/actors', json={'name': 'Example actor', 'tlp': 'GREEN'}, headers=writer).json()[
        'ref'
    ]
    path = f'/api/actors/{actor}'
    data = {'target_kind': 'technique', 'target_id': 'T1059.001', 'tlp': 'GREEN'}
    assert client.post('/api/actors/G0016/links', json=data, headers=writer).status_code == 404
    assert client.post(path + '/links', json=data, headers=writer).json()['name'].endswith('PowerShell')
    assert (
        client.post(
            path + '/documents', json={'document_id': doc, 'note': 'Restricted TLP:RED'}, headers=green
        ).status_code
        == 403
    )
    assert (
        client.post(
            path + '/documents',
            json={'document_id': doc, 'tlp': 'AMBER', 'note': 'Private note'},
            headers=writer,
        ).status_code
        == 201
    )
    assert len(client.get(path + '/links', headers=writer).json()['links']) == 2
    assert len(client.get(path + '/links', headers=green).json()['links']) == 1
    assert 'Private note' not in client.get(path, headers=green).text
    assert client.delete(path + '/links/technique/T1059.001', headers=green).status_code == 200
