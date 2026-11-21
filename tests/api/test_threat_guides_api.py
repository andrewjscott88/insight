"""Industry threat profiles, actor threat guides, hunts and rules over the API (TIP 2.10, ADR 0025)."""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import select

from insight import services
from insight.models import AuditEvent
from insight.schemas import DocumentInput

SIGMA = (
    'title: Encoded PowerShell\nlogsource:\n  product: windows\n'
    'detection:\n  sel:\n    x: 1\n  condition: sel\n'
)
MARKER = 'HIDDEN-MARKER-7731'


def ingest(app: FastAPI, title: str, body: str, tlp: str = 'GREEN', *, accept: bool = False) -> str:
    with app.state.session_factory.begin() as db:
        doc, _ = services.ingest(
            db,
            DocumentInput.model_validate({'title': title, 'body': body, 'source_name': 'S', 'tlp': tlp}),
        )
        if accept:
            for obs in services.detail(db, doc)['observations']:
                services.set_observation_status(db, obs['id'], 'accepted')
        return doc.id


def key(app: FastAPI, access: str = 'read-write', max_tlp: str | None = None) -> dict[str, str]:
    with app.state.session_factory.begin() as db:
        _, token = services.create_api_key(db, name='k', access=access, max_tlp=max_tlp)
    return {'Authorization': f'Bearer {token}'}


def audited(app: FastAPI, prefix: str) -> list[tuple[str, str]]:
    with app.state.session_factory() as db:
        stmt = select(AuditEvent).where(AuditEvent.action.like(f'{prefix}%')).order_by(AuditEvent.created_at)
        return [(e.action, e.detail) for e in db.scalars(stmt)]


@pytest.fixture
def signed_in(client: TestClient, login: Callable[..., str]) -> TestClient:
    login(client)
    return client


def test_industries_list_every_sector_with_group_counts(signed_in: TestClient) -> None:
    body = signed_in.get('/api/industries').json()
    assert body['library']['edition'] == 'bundled'
    assert body['library']['sources']['attack']['version'] == '20.1'
    by_key = {i['key']: i for i in body['industries']}
    assert by_key['government']['groups'] > 10
    assert {'key', 'name', 'covers', 'groups'} == set(by_key['healthcare'])


def test_the_top_groups_for_an_industry_come_with_evidence_and_reasons(
    app: FastAPI, signed_in: TestClient
) -> None:
    ingest(app, 'Cozy Bear again', 'Cozy Bear phished a ministry.')
    body = signed_in.get('/api/industries/government/actors', params={'days': 30}).json()
    assert body['industry'] == {'key': 'government', 'name': 'Government and diplomacy'}
    assert len(body['actors']) == 10
    first = body['actors'][0]
    assert (first['rank'], first['ref'], first['reports_naming_it']) == (1, 'G0016', 1)
    assert first['evidence']
    assert all('government' in e['industries'] for e in first['evidence'])
    assert body['tlp'] == 'GREEN'
    assert signed_in.get('/api/industries/nope/actors').status_code == 404
    assert len(signed_in.get('/api/industries/government/actors', params={'top': 3}).json()['actors']) == 3
    assert signed_in.get('/api/industries/government/actors', params={'top': 11}).status_code == 422


def test_groups_and_actors_can_be_searched_created_and_read(signed_in: TestClient) -> None:
    found = signed_in.get('/api/actors', params={'q': 'cozy'}).json()
    assert [g['ref'] for g in found['groups']] == ['G0016']
    created = signed_in.post(
        '/api/actors',
        json={'name': 'Copper Fox', 'aliases': ['CF-1'], 'attack_group_id': 'G0016', 'tlp': 'GREEN'},
    )
    assert created.status_code == 201, created.text
    ref = created.json()['ref']
    assert signed_in.get('/api/actors', params={'q': 'copper'}).json()['actors'][0]['ref'] == ref
    detail = signed_in.get(f'/api/actors/{ref}').json()
    assert detail['attack_group']['ref'] == 'G0016'
    assert signed_in.post('/api/actors', json={'name': 'X', 'attack_group_id': 'G9999'}).status_code == 422
    assert signed_in.get('/api/actors/G9999').status_code == 404


def test_the_guide_exports_carry_their_label_and_are_audited(app: FastAPI, signed_in: TestClient) -> None:
    amber = ingest(app, 'IR case', f'{MARKER}: C2 at evil-c2.biz; T1059.001.', 'AMBER', accept=True)
    assert signed_in.post('/api/actors/G0016/documents', json={'document_id': amber}).status_code == 201
    guide = signed_in.get('/api/actors/G0016/guide').json()
    assert guide['format'] == 'insight-threat-guide-1'
    assert guide['tlp'] == 'AMBER'
    assert guide['hunt']['sweep']['indicators'][0]['value'] == 'evil-c2.biz'
    assert guide['hunt']['hypotheses'][0]['technique'] == 'T1059.001'
    md = signed_in.get('/api/actors/G0016/guide', params={'format': 'md'})
    assert md.headers['content-type'].startswith('text/markdown')
    assert md.text.startswith('**TLP:AMBER**')
    green = signed_in.get('/api/actors/G0016/guide', params={'max_tlp': 'GREEN', 'format': 'md'}).text
    assert green.startswith('**TLP:CLEAR**')
    assert MARKER not in green
    assert 'evil-c2.biz' not in green
    layer = signed_in.get('/api/actors/G0016/navigator')
    assert 'attachment' in layer.headers['content-disposition']
    assert {'name': 'TLP', 'value': 'TLP:AMBER'} in layer.json()['metadata']
    sweep = signed_in.get('/api/actors/G0016/sweep', params={'format': 'csv'})
    assert sweep.text.startswith('# TLP:AMBER')
    assert 'evil-c2.biz' in sweep.text
    details = [json.loads(d) for _, d in audited(app, 'actor.guide')]
    assert [d['what'] for d in details] == ['guide.json', 'guide.md', 'guide.md', 'navigator', 'sweep.csv']
    assert details[2]['max_tlp'] == 'GREEN'


def test_a_limited_key_sees_no_hidden_report_in_any_threat_route(app: FastAPI, client: TestClient) -> None:
    amber = ingest(
        app, f'Cozy Bear {MARKER}', f'Cozy Bear used {MARKER}.example and T1486.', 'AMBER', accept=True
    )
    with app.state.session_factory.begin() as db:
        services.link_report(db, 'G0016', services_link(amber))
    headers = key(app, max_tlp='GREEN')
    for path in (
        '/api/industries',
        '/api/industries/government/actors',
        '/api/actors/G0016',
        '/api/actors/G0016/guide',
        '/api/actors/G0016/guide?format=md',
        '/api/actors/G0016/navigator',
        '/api/actors/G0016/sweep?format=csv',
        '/api/actors/G0016/hunts',
    ):
        response = client.get(path, headers=headers)
        assert response.status_code == 200, path
        assert MARKER not in response.text, path
        assert amber not in response.text, path
    linked = client.post('/api/actors/G0016/documents', json={'document_id': amber}, headers=headers)
    assert linked.status_code == 404


def services_link(document_id: str) -> Any:
    from insight.schemas import ActorLinkInput

    return ActorLinkInput(document_id=document_id)


def test_industry_decisions_respect_labels_and_need_evidence(app: FastAPI, client: TestClient) -> None:
    headers = key(app, max_tlp='GREEN')
    no_citation = {'industry': 'energy', 'decision': 'added', 'reason': 'trust me', 'tlp': 'GREEN'}
    assert client.post('/api/actors/G0016/industries', json=no_citation, headers=headers).status_code == 422
    too_high = {'industry': 'government', 'decision': 'removed', 'reason': 'x', 'tlp': 'AMBER'}
    response = client.post('/api/actors/G0016/industries', json=too_high, headers=headers)
    assert response.status_code == 403
    cited = {**no_citation, 'citation_url': 'https://example.org/energy-report'}
    assert client.post('/api/actors/G0016/industries', json=cited, headers=headers).status_code == 200
    http = {**cited, 'citation_url': 'http://example.org/energy-report'}
    assert client.post('/api/actors/G0016/industries', json=http, headers=headers).status_code == 422
    body = client.get('/api/industries/energy/actors', headers=headers).json()
    entry = next(a for a in body['actors'] if a['ref'] == 'G0016')
    assert entry['evidence'][-1]['source'] == 'Your own mapping'
    assert audited(app, 'actor.industry') == [('actor.industry', 'added energy (TLP:GREEN)')]


def test_hunts_and_rules_round_trip(app: FastAPI, signed_in: TestClient) -> None:
    started = signed_in.post('/api/actors/G0016/hunts', json={'title': 'Q4 hunt', 'tlp': 'AMBER'})
    assert started.status_code == 201, started.text
    hunt_id = started.json()['id']
    check = {'result': 'nothing-found', 'data_checked': 'Sysmon 1', 'period_start': '2026-10-01'}
    assert signed_in.put(f'/api/hunts/{hunt_id}/checks/t1059.001', json=check).status_code == 200
    assert signed_in.put(f'/api/hunts/{hunt_id}/checks/T9999', json=check).status_code == 422
    closed = signed_in.put(f'/api/hunts/{hunt_id}', json={'status': 'closed', 'summary': 'Clean'}).json()
    assert closed['checks'][0]['technique'] == 'T1059.001'
    assert closed['status'] == 'closed'
    assert signed_in.get('/api/actors/G0016/hunts').json()[0]['id'] == hunt_id
    rule = signed_in.post(
        '/api/rules', json={'kind': 'sigma', 'name': 'Encoded PS', 'body': SIGMA, 'tlp': 'GREEN'}
    )
    assert rule.status_code == 201, rule.text
    rule_id = rule.json()['id']
    again = signed_in.post('/api/rules', json={'kind': 'sigma', 'name': 'Again', 'body': SIGMA})
    assert again.status_code == 422
    link = {'target_kind': 'technique', 'target_id': 'T1059.001'}
    assert signed_in.post(f'/api/rules/{rule_id}/links', json=link).status_code == 200
    assert signed_in.get(f'/api/rules/{rule_id}').json()['linked_to'] == [
        {'kind': 'technique', 'id': 'T1059.001'}
    ]
    guide = signed_in.get('/api/actors/G0016/guide').json()
    assert [r['name'] for r in guide['hunt']['rules']] == ['Encoded PS']
    assert guide['hunt']['records'][0]['checks']['T1059.001']['result'] == 'nothing-found'
    assert signed_in.request('DELETE', f'/api/rules/{rule_id}/links', json=link).status_code == 200
    assert signed_in.delete(f'/api/rules/{rule_id}').status_code == 200
    assert signed_in.get(f'/api/rules/{rule_id}').status_code == 404
    assert [a for a, _ in audited(app, 'hunt.')] == ['hunt.start', 'hunt.check', 'hunt.update']


def test_a_read_only_key_cannot_change_threat_data(app: FastAPI, client: TestClient) -> None:
    headers = key(app, access='read')
    response = client.post('/api/actors/G0016/hunts', json={'title': 'x'}, headers=headers)
    assert response.status_code == 403
    assert client.get('/api/actors/G0016/guide', headers=headers).status_code == 200


def test_a_hidden_hunt_or_rule_looks_missing(app: FastAPI, signed_in: TestClient, client: TestClient) -> None:
    hunt_id = signed_in.post('/api/actors/G0016/hunts', json={'title': 'Secret', 'tlp': 'AMBER'}).json()['id']
    headers = key(app, max_tlp='GREEN')
    assert client.get(f'/api/hunts/{hunt_id}', headers=headers).status_code == 404
    assert client.put(f'/api/hunts/{hunt_id}', json={'status': 'closed'}, headers=headers).status_code == 404


def test_the_sweep_list_takes_named_reports_only_when_asked(app: FastAPI, signed_in: TestClient) -> None:
    """Review M2: by default only reports linked to the group feed the sweep list."""
    linked = ingest(app, 'IR case', 'C2 at evil-c2.biz.', accept=True)
    named = ingest(app, 'Vendor blog', 'Cozy Bear used login-microsoftonline.click.', accept=True)
    assert signed_in.post('/api/actors/G0016/documents', json={'document_id': linked}).status_code == 201
    default = signed_in.get('/api/actors/G0016/sweep').json()
    assert default['linked_only'] is True
    assert [i['value'] for i in default['indicators']] == ['evil-c2.biz']
    guide = signed_in.get('/api/actors/G0016/guide').json()
    assert named in {r['id'] for r in guide['reports']}  # listed, but not swept
    assert [i['value'] for i in guide['hunt']['sweep']['indicators']] == ['evil-c2.biz']
    wider = signed_in.get('/api/actors/G0016/sweep', params={'linked_only': 'false'}).json()
    assert wider['linked_only'] is False
    assert {i['value']: i['via'] for i in wider['indicators']} == {
        'evil-c2.biz': 'linked',
        'login-microsoftonline.click': 'named',
    }
    details = [json.loads(d) for _, d in audited(app, 'actor.guide')]
    assert [d['linked_only'] for d in details] == [True, True, False]


def test_a_hidden_industry_decision_looks_missing(
    app: FastAPI, signed_in: TestClient, client: TestClient
) -> None:
    """Review L2: a limited key gets 404, not 403, when an above-limit decision exists for the industry."""
    secret = {'industry': 'government', 'decision': 'removed', 'reason': 'Ours', 'tlp': 'AMBER'}
    assert signed_in.post('/api/actors/G0016/industries', json=secret).status_code == 200
    mine = {**secret, 'tlp': 'GREEN'}
    response = client.post('/api/actors/G0016/industries', json=mine, headers=key(app, max_tlp='GREEN'))
    assert response.status_code == 404
    assert response.json()['detail'] == 'Industry mapping not found'
