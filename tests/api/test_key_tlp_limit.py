"""A TLP-limited API key (``insight api-key create --max-tlp GREEN``) never sees more restrictive reports.

The central test plants a unique marker in an AMBER report, then sweeps every API route with a GREEN-limited
key: the marker, the report's ID and its unique indicator must not appear in any response.
"""

from __future__ import annotations

import json
import re
import zlib
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from insight import services
from insight.mcp import TOOL_BY_NAME
from insight.models import Enrichment
from insight.schemas import (
    ActorCampaignInput,
    ActorInput,
    ActorLinkInput,
    AssessmentInput,
    CampaignInput,
    CaseInput,
    CaseItemInput,
    CriterionInput,
    DocumentInput,
    EvidenceInput,
    HuntPackageInput,
    HuntPackageItemInput,
    JudgementInput,
    RequirementInput,
    SightingInput,
    SoftwareLinkInput,
)
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
        # Actor activity must be planted here too: the central GREEN sweep exercises the real
        # timeline/campaign routes against restricted report links and explicit campaign associations.
        # The public group must hide both the AMBER report and the AMBER link to a GREEN report.
        services.link_report(db, 'G0016', ActorLinkInput(document_id=amber.id, note=MARKER, tlp='AMBER'))
        services.link_report(db, 'G0016', ActorLinkInput(document_id=green.id, tlp='AMBER', note=MARKER))
        campaign = services.create_campaign(db, CampaignInput(name=f'{MARKER} campaign', tlp='AMBER'))
        services.link_actor_campaign(
            db, 'G0016', ActorCampaignInput(campaign_id=campaign.id, note=MARKER, tlp='AMBER')
        )
        ref = SourceRef('partner-feed', 'item-1')
        old, _ = services.ingest(db, report('Item v1', 'CVE-2024-11111 first.', 'GREEN'), ref=ref)
        new, _ = services.ingest(db, report(f'Item v2 {MARKER}', 'CVE-2024-11111 edited.', 'AMBER'), ref=ref)
        hidden_obs = next(o for o in services.detail(db, amber)['observations'] if o['value'] == HIDDEN_IP)
        services.link_software_report(db, 'S0154', SoftwareLinkInput(document_id=amber.id, note=MARKER))
        services.link_software_report(
            db, 'S0154', SoftwareLinkInput(document_id=green.id, note=MARKER, tlp='AMBER')
        )
        shared = next(o for o in services.detail(db, green)['observations'] if o['value'] == SHARED_IP)
        # An AMBER verdict on an indicator the GREEN key can see: its reason must stay hidden.
        services.assess_entity(
            db, shared['entity_id'], AssessmentInput(verdict='malicious', reason=MARKER, tlp='AMBER')
        )
        # A cached NVD answer for a CVE only the current AMBER revision mentions.
        nvd = {'vulnerabilities': [{'cve': {'descriptions': [{'lang': 'en', 'value': MARKER}]}}]}
        db.add(Enrichment(cve='CVE-2024-11111', provider='nvd', payload=json.dumps(nvd)))
        # A case that holds the AMBER report is AMBER too (TIP 3.8): its title and items stay hidden.
        case = services.create_case(db, CaseInput(title=f'{MARKER} case', tlp='GREEN', bluf=MARKER))
        evidence_item = services.add_case_item(
            db, case.id, CaseItemInput(kind='document', target_id=amber.id)
        )
        # ...and so is the product it holds (TIP 4.4): its judgements, its draft and its published version.
        services.add_judgement(
            db,
            case.id,
            JudgementInput(
                statement=MARKER, likelihood='likely', confidence='low', evidence=[evidence_item.id]
            ),
        )
        services.publish_product(db, case.id)
        # A GREEN requirement whose criterion matches only the AMBER report (TIP 4.1): the key sees the
        # requirement but must not see, or count, the match. One that cites the AMBER report becomes AMBER.
        wiper = RequirementInput(
            kind='pir', question='Who deploys wipers?', tlp='GREEN',
            criteria=[CriterionInput(kind='term', value='wiper')],
        )  # fmt: skip
        open_req = services.create_requirement(db, wiper)
        asked = RequirementInput(kind='pir', question=f'{MARKER}?', tlp='GREEN')
        cited = services.create_requirement(db, asked)
        services.add_evidence(db, cited.id, EvidenceInput(document_id=amber.id))
        # A published GREEN hunt package that takes the hidden indicator becomes AMBER (TIP 4.3).
        hunt = services.create_hunt_package(
            db,
            HuntPackageInput(
                title=f'{MARKER} hunt', hypothesis='Beacons.', tlp='GREEN',
                items=[HuntPackageItemInput(kind='indicator', target_id=hidden_obs['entity_id'])],
            ),
        )  # fmt: skip
        services.publish_hunt_package(db, hunt.id)
        # An AMBER sighting of the shared indicator, and a GREEN one of the hidden indicator (TIP 4.2): the
        # key sees neither, nor the sighting in the shared indicator's confidence.
        seen = datetime.now(UTC) - timedelta(hours=1)
        services.record_sighting(
            db, SightingInput(value=SHARED_IP, first_seen=seen, note=MARKER, where=MARKER, tlp='AMBER')
        )
        services.record_sighting(db, SightingInput(value=HIDDEN_IP, first_seen=seen, tlp='GREEN'))
        hidden_actor = services.create_actor(db, ActorInput(name=f'{MARKER} actor', tlp='AMBER'))
        services.create_requirement(
            db, RequirementInput(kind='rfi', question=f'{MARKER} request?', tlp='AMBER')
        )
        _, token = services.create_api_key(db, name='siem', access='read-write', max_tlp='GREEN')
    return {
        'actor_campaign': campaign.id,
        'case': case.id,
        'hidden_actor': hidden_actor.id,
        'hunt_package': hunt.id,
        'requirement': open_req.id,
        'cited': cited.id,
        'green': green.id,
        'amber': amber.id,
        'old': old.id,
        'new': new.id,
        'hidden_obs': hidden_obs['id'],
        'hidden_entity': hidden_obs['entity_id'],
        'shared_entity': shared['entity_id'],
        'headers': {'Authorization': f'Bearer {token}'},
    }


@pytest.mark.parametrize('protocol', ['2025-11-25', '2026-07-28'])
def test_every_mcp_tool_keeps_the_green_ceiling(
    client: TestClient,
    world: dict[str, Any],
    protocol: str,
) -> None:
    """Every advertised MCP tool is swept in the same planted AMBER world as the REST API."""
    calls = [
        ('search_reports', {'q': MARKER}),
        ('search_reports', {'q': 'CVE-2024-11111'}),
        ('get_indicator', {'id': world['hidden_entity']}),
        ('get_indicator', {'id': world['shared_entity']}),
        ('search_indicators', {'q': HIDDEN_IP}),
        ('search_indicators', {'q': SHARED_IP}),
        ('get_report_summary', {'id': world['amber']}),
        ('get_report_summary', {'id': world['old']}),
        ('list_requirements', {}),
        ('list_requirements', {'kind': 'rfi'}),
        ('get_hunt_package', {'id': world['hunt_package']}),
        ('get_threat_group', {'id': world['hidden_actor']}),
        ('get_threat_group', {'id': 'G0016'}),
        ('get_landscape_summary', {}),
    ]
    assert {name for name, _ in calls} == set(TOOL_BY_NAME)
    headers = world['headers'] | {
        'Accept': 'application/json, text/event-stream',
        'MCP-Protocol-Version': protocol,
    }

    def request_tool(name: str, arguments: dict[str, Any]) -> Any:
        params: dict[str, Any] = {'name': name, 'arguments': arguments}
        sent_headers = dict(headers)
        if protocol == '2026-07-28':
            params['_meta'] = {
                'io.modelcontextprotocol/protocolVersion': protocol,
                'io.modelcontextprotocol/clientCapabilities': {},
            }
            sent_headers |= {'Mcp-Method': 'tools/call', 'Mcp-Name': name}
        return client.post(
            '/mcp',
            headers=sent_headers,
            json={'jsonrpc': '2.0', 'id': 1, 'method': 'tools/call', 'params': params},
        )

    forbidden = [
        MARKER,
        HIDDEN_IP,
        world['amber'],
        world['new'],
        world['hidden_entity'],
        world['hidden_actor'],
    ]
    for name, arguments in calls:
        response = request_tool(name, arguments)
        assert response.status_code == 200, response.text
        assert response.json()['result']['structuredContent']['sharing_tlp'] == 'GREEN'
        assert all(secret not in response.text for secret in forbidden), (name, response.text)
        data = response.json()['result']['structuredContent']
        if name == 'search_indicators' and arguments['q'] == SHARED_IP:
            assert data['indicators'][0]['reports'] == 1
        if name == 'get_landscape_summary':
            assert data['reports'] == 1
            assert 'Destructive attacks' not in {trend['name'] for trend in data['threats']}
        if name == 'list_requirements' and not arguments:
            requirement = next(row for row in data['requirements'] if row['id'] == world['requirement'])
            assert requirement['recent_matches'] == 0
            assert requirement['last_match_at'] is None
        if name == 'get_threat_group' and arguments['id'] == 'G0016':
            assert response.json()['result']['structuredContent']['linked_reports'] == []
        if arguments.get('id') in (
            world['amber'],
            world['hidden_entity'],
            world['hunt_package'],
            world['hidden_actor'],
        ):
            missing = request_tool(name, {'id': 'missing'})
            assert response.json() == missing.json()


def get(client: TestClient, world: dict[str, Any], path: str, **params: Any) -> Any:
    return client.get(path, headers=world['headers'], params=params)


def readable(response: Any) -> str:  # the test client's response (httpx or httpx2)
    """The body as text. A PDF's compressed pages and UTF-16 strings are opened, so a leak in one shows."""
    if response.headers.get('content-type') != 'application/pdf':
        text: str = response.text
        return text
    raw: bytes = response.content
    pages = re.findall(rb'stream\n(.*?)\nendstream', raw, re.DOTALL)
    strings = re.findall(rb'<FEFF([0-9A-F]*)>', raw)
    return '\n'.join(
        [raw.decode('latin-1')]
        + [zlib.decompress(page).decode('latin-1') for page in pages]
        + [bytes.fromhex(string.decode()).decode('utf-16-be') for string in strings]
    )


def test_nothing_hidden_leaks_through_any_read_route(client: TestClient, world: dict[str, Any]) -> None:
    paths = [
        '/api/software',
        '/api/software/S0154',
        '/api/software/S0154/documents',
        f'/api/documents/{world["green"]}/software',
        f'/api/documents/{world["amber"]}/software',
        '/api/documents',
        '/api/documents?include_superseded=true',
        f'/api/documents?q={MARKER}',
        f'/api/documents/{world["green"]}',
        f'/api/documents/{world["old"]}',
        f'/api/documents/{world["amber"]}',
        f'/api/documents/{world["amber"]}/export',
        '/api/iocs/export',
        '/api/iocs/export?include_superseded=true&max_tlp=RED',
        '/api/iocs/stix?include_superseded=true&max_tlp=RED',
        f'/api/iocs/stix?document_id={world["amber"]}',
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
        '/api/cves?days=365&limit=500',
        '/api/industries',
        '/api/industries/government/actors',
        '/api/actors',
        '/api/actors/G0016',
        '/api/actors/G0016/guide',
        '/api/actors/G0016/timeline',
        '/api/actors/G0016/campaigns',
        '/api/software/S0154/navigator',
        '/api/actors/G0016/guide?format=md',
        '/api/actors/G0016/navigator',
        '/api/actors/G0016/sweep?format=csv',
        '/api/actors/G0016/hunts',
        '/api/hunts/x',
        '/api/rules',
        '/api/rules/x',
        '/api/rules/x/export',
        f'/api/search?q={MARKER}',
        f'/api/search?q={HIDDEN_IP}&include_superseded=true',
        '/api/search?q=CVE-2024-11111&include_superseded=true',
        f'/api/graph?node=report:{world["amber"]}',
        f'/api/graph?node=indicator:{world["shared_entity"]}&depth=2',
        f'/api/graph?node=indicator:{world["hidden_entity"]}',
        '/api/cases?status=all',
        f'/api/cases/{world["case"]}',
        f'/api/cases/{world["case"]}/timeline',
        f'/api/cases/{world["case"]}/product',
        f'/api/cases/{world["case"]}/product?version=1',
        f'/api/cases/{world["case"]}/export?format=md',
        f'/api/cases/{world["case"]}/export?format=stix&version=1',
        f'/api/cases/{world["case"]}/export?format=pdf',
        '/api/requirements?status=all',
        f'/api/requirements/{world["requirement"]}',
        f'/api/requirements/{world["cited"]}',
        f'/api/documents/{world["amber"]}/requirements',
        f'/api/documents/{world["green"]}/requirements',
        '/api/hunt-packages',
        '/api/sightings',
        f'/api/sightings?entity_id={world["shared_entity"]}',
        f'/api/hunt-packages/{world["hunt_package"]}',
        f'/api/hunt-packages/{world["hunt_package"]}/stix',
        '/taxii2/insight/collections/9d3f6b1a-2c4e-4a7b-8e5d-1f0a3c6b9e27/objects/',
        '/api/source-ratings',
        f'/api/entities/{world["shared_entity"]}/confidence',
        f'/api/entities/{world["hidden_entity"]}/confidence',
        '/taxii2/',
        '/taxii2/insight/',
        '/taxii2/insight/collections/',
        '/taxii2/insight/collections/5b2f8a7e-4c1d-4e3a-9f6b-0d8c7a1e2f34/',
        '/taxii2/insight/collections/5b2f8a7e-4c1d-4e3a-9f6b-0d8c7a1e2f34/objects/',
        '/taxii2/insight/collections/5b2f8a7e-4c1d-4e3a-9f6b-0d8c7a1e2f34/manifest/',
        f'/taxii2/insight/collections/5b2f8a7e-4c1d-4e3a-9f6b-0d8c7a1e2f34/objects/indicator--{world["hidden_entity"]}/',
        f'/taxii2/insight/collections/5b2f8a7e-4c1d-4e3a-9f6b-0d8c7a1e2f34/objects/indicator--{world["hidden_entity"]}/versions/',
    ]
    # Every GET route of the API is covered by the sweep.
    covered = {path.split('?')[0] for path in paths}
    for method, route in PROTECTED:
        if method == 'GET' and route != '/api/session':
            template = route.replace('/x', '/{id}')
            assert any(p.rstrip('/').count('/') == template.rstrip('/').count('/') for p in covered), route
    for path in paths:
        response = client.get(path, headers=world['headers'])
        if path in {
            '/api/actors/G0016/timeline',
            '/api/actors/G0016/campaigns',
            '/api/software/S0154/navigator',
        }:
            assert response.status_code == 200, response.text
        body = readable(response)
        for secret in (
            MARKER,
            HIDDEN_IP,
            world['amber'],
            world['new'],
            world['hidden_entity'],
            world['actor_campaign'],
        ):
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


def test_stix_exports_apply_the_key_and_instance_limits(
    app: FastAPI, client: TestClient, world: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    visible = get(client, world, '/api/iocs/stix', max_tlp='RED', evidence='false')
    assert visible.status_code == 200
    assert SHARED_IP in visible.text
    assert HIDDEN_IP not in visible.text
    monkeypatch.setattr(app.state, 'settings', replace(app.state.settings, max_tlp='CLEAR'))
    hidden = get(client, world, '/api/iocs/stix', max_tlp='RED')
    assert hidden.status_code == 200
    assert SHARED_IP not in hidden.text
    assert HIDDEN_IP not in hidden.text


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
    # The sweep reads inside PDFs: the hidden product's PDF shows the marker to a key that may see it.
    pdf = authed.get(f'/api/cases/{world["case"]}/export', params={'format': 'pdf'}, headers=unlimited)
    assert MARKER in readable(pdf)
