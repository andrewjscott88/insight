"""A TLP-limited API key (``insight api-key create --max-tlp GREEN``) never sees more restrictive reports.

The central test plants a unique marker in an AMBER report, then sweeps every API route with a GREEN-limited
key: the marker, the report's ID and its unique indicator must not appear in any response.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from insight import services
from insight.models import Enrichment
from insight.schemas import AssessmentInput, DocumentInput
from insight.services import SourceRef

from .test_auth import PROTECTED

MARKER = 'ZEBRA-MERIDIAN-7731'
HIDDEN_TECHNIQUE = 'T1490'  # Inhibit System Recovery: written only in the AMBER report
HIDDEN_IP = '198.51.100.77'
SHARED_IP = '192.0.2.44'


def report(title: str, body: str, tlp: str) -> DocumentInput:
    return DocumentInput.model_validate({'title': title, 'body': body, 'source_name': 'Partner', 'tlp': tlp})


@pytest.fixture
def world(app: FastAPI) -> dict[str, Any]:
    """One GREEN and one AMBER report sharing an indicator, plus a synced item with a GREEN and an AMBER
    revision; and a GREEN-limited read-write key."""
    with app.state.session_factory.begin() as db:
        green, _ = services.ingest(
            db, report('Public note', f'Scanning from {SHARED_IP} (T1595.001).', 'GREEN')
        )
        amber, _ = services.ingest(
            db,
            report(
                f'{MARKER} briefing',
                f'{MARKER}: C2 at {HIDDEN_IP}, also {SHARED_IP}. {HIDDEN_TECHNIQUE}. A wiper followed.',
                'AMBER',
            ),
        )
        ref = SourceRef('partner-feed', 'item-1')
        old, _ = services.ingest(db, report('Item v1', 'CVE-2024-11111 first.', 'GREEN'), ref=ref)
        new, _ = services.ingest(db, report(f'Item v2 {MARKER}', 'CVE-2024-11111 edited.', 'AMBER'), ref=ref)
        hidden_obs = next(o for o in services.detail(db, amber)['observations'] if o['value'] == HIDDEN_IP)
        shared = next(o for o in services.detail(db, green)['observations'] if o['value'] == SHARED_IP)
        # An AMBER verdict on an indicator the GREEN key can see: its reason must stay hidden.
        services.assess_entity(
            db, shared['entity_id'], AssessmentInput(verdict='malicious', reason=MARKER, tlp='AMBER')
        )
        # A cached NVD answer for a CVE only the current AMBER revision mentions.
        nvd = {'vulnerabilities': [{'cve': {'descriptions': [{'lang': 'en', 'value': MARKER}]}}]}
        db.add(Enrichment(cve='CVE-2024-11111', provider='nvd', payload=json.dumps(nvd)))
        _, token = services.create_api_key(db, name='siem', access='read-write', max_tlp='GREEN')
    return {
        'green': green.id,
        'amber': amber.id,
        'old': old.id,
        'new': new.id,
        'hidden_obs': hidden_obs['id'],
        'hidden_entity': hidden_obs['entity_id'],
        'shared_entity': shared['entity_id'],
        'headers': {'Authorization': f'Bearer {token}'},
    }


def get(client: TestClient, world: dict[str, Any], path: str, **params: Any) -> Any:
    return client.get(path, headers=world['headers'], params=params)


def test_nothing_hidden_leaks_through_any_read_route(client: TestClient, world: dict[str, Any]) -> None:
    paths = [
        '/api/documents',
        '/api/documents?include_superseded=true',
        f'/api/documents?q={MARKER}',
        f'/api/documents/{world["green"]}',
        f'/api/documents/{world["old"]}',
        f'/api/documents/{world["amber"]}',
        f'/api/documents/{world["amber"]}/export',
        '/api/iocs/export',
        '/api/iocs/export?include_superseded=true&max_tlp=RED',
        f'/api/iocs/export?document_id={world["amber"]}',
        '/api/entities',
        f'/api/entities?q={HIDDEN_IP}',
        f'/api/entities/{world["hidden_entity"]}',
        f'/api/entities/{world["shared_entity"]}',
        '/api/iocs/blocklist?kind=ip',
        '/api/iocs/blocklist?kind=ip&format=csv',
        '/api/iocs/export?verdict=malicious',
        '/api/stats',
        '/api/brief',
        '/api/brief?days=30',
        '/api/audit',
        '/api/sources',
        '/api/schedules',
        '/api/jobs',
        '/api/watch-terms',
        '/api/attack/techniques',
        '/api/attack/summary?days=0',
        '/api/attack/navigator?days=0',
        '/api/landscape?days=7',
        '/api/landscape/briefing?days=30',
        f'/api/attack/techniques/{HIDDEN_TECHNIQUE}/documents',
        f'/api/documents/{world["green"]}/techniques',
        f'/api/documents/{world["amber"]}/techniques',
        '/api/cves/CVE-2024-11111/scores',
    ]
    # Every GET route of the API is covered by the sweep.
    covered = {path.split('?')[0] for path in paths}
    for method, route in PROTECTED:
        if method == 'GET' and route != '/api/session':
            template = route.replace('/x', '/{id}')
            assert any(p.rstrip('/').count('/') == template.count('/') for p in covered), route
    for path in paths:
        body = client.get(path, headers=world['headers']).text
        for secret in (MARKER, HIDDEN_IP, world['amber'], world['new'], world['hidden_entity']):
            # A value the caller itself sent (e.g. an IOC export echoing its filters) discloses nothing.
            if secret not in path:
                assert secret not in body, f'{secret} leaked through {path}'


def test_hidden_reports_are_indistinguishable_from_missing_ones(
    client: TestClient, world: dict[str, Any]
) -> None:
    for path in (f'/api/documents/{world["amber"]}', f'/api/documents/{world["amber"]}/export'):
        response = get(client, world, path)
        assert (response.status_code, response.json()) == (404, {'detail': 'Report not found'})
    assert get(client, world, f'/api/entities/{world["hidden_entity"]}').status_code == 404


def test_visible_data_is_counted_from_visible_reports_only(client: TestClient, world: dict[str, Any]) -> None:
    assert [d['id'] for d in get(client, world, '/api/documents').json()] == [world['green']]
    listed = get(client, world, '/api/documents', include_superseded='true').json()
    assert [d['id'] for d in listed] == [world['old'], world['green']]  # not the AMBER current revision
    entities = {e['value']: e['document_count'] for e in get(client, world, '/api/entities').json()}
    assert entities == {SHARED_IP: 1, 'CVE-2024-11111': 1}
    assert get(client, world, '/api/stats').json() == {
        'documents': 1,  # the current revision of the synced item is AMBER: only the GREEN report counts
        'entities': 2,
        'unreviewed': 1,
        'observations_unreviewed': 1,
    }
    old = get(client, world, f'/api/documents/{world["old"]}').json()
    assert [r['id'] for r in old['revisions']] == [world['old']]  # the AMBER revision is not listed


def test_ioc_exports_are_capped_at_the_key_limit(client: TestClient, world: dict[str, Any]) -> None:
    export = get(client, world, '/api/iocs/export', max_tlp='RED').json()
    assert export['filters']['max_tlp'] == 'GREEN'  # the stricter of the request and the key
    assert export['tlp'] == 'GREEN'
    assert {ioc['value'] for ioc in export['iocs']} == {SHARED_IP}


def test_the_landscape_counts_only_reports_within_the_limit(
    client: TestClient, world: dict[str, Any]
) -> None:
    body = get(client, world, '/api/landscape', days=7).json()
    assert body['tlp'] == 'GREEN'
    assert body['reports'] == 1  # the GREEN note: the AMBER report and the AMBER current revision are hidden
    assert 'wipers' not in {t['key'] for t in body['threats']}
    briefing = get(client, world, '/api/landscape/briefing', days=7).text
    assert briefing.startswith('**TLP:GREEN**')
    assert 'Destructive attacks' not in briefing


def test_techniques_from_hidden_reports_stay_hidden(client: TestClient, world: dict[str, Any]) -> None:
    summary = get(client, world, '/api/attack/summary', days=0).text
    assert 'T1595.001' in summary  # written in the GREEN report: counted
    for path in ('/api/attack/summary', '/api/attack/navigator'):
        assert HIDDEN_TECHNIQUE not in get(client, world, path, days=0).text, path
    pivot = get(client, world, f'/api/attack/techniques/{HIDDEN_TECHNIQUE}/documents').json()
    assert pivot['documents'] == []
    headers, amber = world['headers'], world['amber']
    tag = {'technique_id': 'T1486'}
    assert client.post(f'/api/documents/{amber}/techniques', json=tag, headers=headers).status_code == 404
    path = f'/api/documents/{amber}/techniques/{HIDDEN_TECHNIQUE}'
    assert client.delete(path, headers=headers).status_code == 404


def test_writes_to_hidden_reports_look_like_missing_reports(
    client: TestClient, world: dict[str, Any]
) -> None:
    headers = world['headers']
    amber = world['amber']
    assert (
        client.post(
            f'/api/documents/{amber}/review', json={'status': 'reviewed'}, headers=headers
        ).status_code
        == 404
    )
    assert (
        client.post(f'/api/documents/{amber}/notes', json={'body': 'x'}, headers=headers).status_code == 404
    )
    obs = world['hidden_obs']
    response = client.post(f'/api/observations/{obs}/review', json={'status': 'accepted'}, headers=headers)
    assert response.status_code == 404


def test_the_key_cannot_store_what_it_cannot_read(client: TestClient, world: dict[str, Any]) -> None:
    body = {'title': 'Mine', 'body': 'Seen at 203.0.113.9.', 'source_name': 'SIEM'}
    refused = client.post('/api/documents', json={**body, 'tlp': 'AMBER'}, headers=world['headers'])
    assert refused.status_code == 422
    assert 'up to TLP:GREEN' in refused.json()['detail']
    stored = client.post('/api/documents', json={**body, 'tlp': 'GREEN'}, headers=world['headers'])
    assert stored.status_code == 200


@pytest.mark.parametrize(
    ('method', 'path'),
    [('GET', '/api/audit'), ('POST', '/api/enrichment/epss/CVE-2024-11111'), ('GET', '/api/watch-terms')],
)
def test_routes_that_span_all_reports_are_refused(
    client: TestClient, world: dict[str, Any], method: str, path: str
) -> None:
    response = client.request(method, path, headers=world['headers'])
    assert (response.status_code, response.json()) == (
        403,
        {'detail': 'Not available to TLP-limited API keys'},
    )


def test_an_unlimited_key_and_the_operator_still_see_everything(
    app: FastAPI, authed: TestClient, world: dict[str, Any]
) -> None:
    assert len(authed.get('/api/documents', params={'include_superseded': 'true'}).json()) == 4
    assert authed.get(f'/api/documents/{world["amber"]}').status_code == 200
    with app.state.session_factory.begin() as db:
        _, token = services.rotate_api_key(db, max_tlp='RED')
    unlimited = {'Authorization': f'Bearer {token}'}
    assert authed.get(f'/api/documents/{world["amber"]}', headers=unlimited).status_code == 200
    # Regression: a limit of RED was stored as a limit, so the key stayed locked out of the audit log and
    # rotation could never return to an unlimited key.
    assert authed.get('/api/audit', headers=unlimited).status_code == 200
