"""Finished intelligence products over HTTP (TIP 4.4, ADR 0036): judgements, gaps, publishing, versions and
the Markdown and STIX exports, with their error codes and the key's TLP limit."""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI
from fastapi.testclient import TestClient

from insight import services


def doc(authed: TestClient, title: str, body: str, tlp: str = 'GREEN') -> str:
    response = authed.post(
        '/api/documents', json={'title': title, 'body': body, 'source_name': 'V', 'tlp': tlp}
    )
    assert response.status_code == 200, response.text
    found: str = response.json()['id']
    return found


def key(app: FastAPI, access: str, max_tlp: str | None = None) -> dict[str, str]:
    with app.state.session_factory.begin() as db:
        services.revoke_api_key(db)
        _, token = services.create_api_key(db, name=access, access=access, max_tlp=max_tlp)
    return {'Authorization': f'Bearer {token}'}


def started(authed: TestClient, **fields: Any) -> str:
    body = {'title': 'Edge appliance exploitation', 'tlp': 'GREEN', 'product_type': 'assessment',
            'audience': 'CISO'} | fields  # fmt: skip
    response = authed.post('/api/cases', json=body)
    assert response.status_code == 201, response.text
    found: str = response.json()['id']
    return found


def test_a_product_is_written_published_and_exported(authed: TestClient) -> None:
    report = doc(authed, 'Vendor advisory', 'Exploitation from 203.0.113.50.')
    case_id = started(authed)
    base = f'/api/cases/{case_id}'
    item = authed.post(f'{base}/items', json={'kind': 'document', 'target_id': report}).json()
    assert authed.post(f'{base}/publish').status_code == 409
    authed.patch(base, json={'bluf': 'Expect more edge appliance exploitation.'})
    judgement = authed.post(
        f'{base}/judgements',
        json={'statement': 'The crew will keep exploiting gateways.', 'likelihood': 'very-likely',
              'confidence': 'high', 'evidence': [item['id']]},
    )  # fmt: skip
    assert judgement.status_code == 201, judgement.text
    assert (judgement.json()['position'], judgement.json()['evidence']) == (1, [item['id']])
    changed = authed.patch(f'{base}/judgements/{judgement.json()["id"]}', json={'confidence': 'moderate'})
    assert changed.json()['confidence'] == 'moderate'
    gap = authed.post(f'{base}/gaps', json={'question': 'Which gateways are exposed?'}).json()
    rfi = authed.post(f'{base}/gaps/{gap["id"]}/rfi')
    assert (rfi.status_code, rfi.json()['kind'], rfi.json()['status']) == (201, 'rfi', 'open')

    published = authed.post(f'{base}/publish')
    assert published.status_code == 200, published.text
    assert (published.json()['version'], published.json()['tlp']) == (1, 'GREEN')
    detail = authed.get(base).json()
    assert (detail['version'], detail['product_type'], detail['audience']) == (1, 'assessment', 'CISO')
    assert detail['bluf'] == 'Expect more edge appliance exploitation.'
    assert [v['version'] for v in detail['versions']] == [1]
    assert [g['requirement_id'] for g in detail['gaps']] == [rfi.json()['id']]
    product = authed.get(f'{base}/product', params={'version': 1}).json()
    assert (product['format'], product['version'], product['judgements'][0]['sources']) == (
        'insight-product-1',
        1,
        [1],
    )

    markdown = authed.get(f'{base}/export', params={'format': 'md', 'version': 1})
    assert markdown.headers['content-type'].startswith('text/markdown')
    assert markdown.headers['content-disposition'].endswith(f'insight-product-{case_id}-v1.md"')
    assert markdown.text.startswith('**TLP:GREEN**')
    stix = authed.get(f'{base}/export', params={'format': 'stix'})
    assert stix.headers['content-type'].startswith('application/stix+json')
    assert stix.headers['content-disposition'].endswith('-draft.json"')
    assert {o['type'] for o in stix.json()['objects']} == {'marking-definition', 'report', 'note'}
    assert authed.get(f'{base}/product', params={'version': 9}).status_code == 404
    assert authed.delete(f'{base}/judgements/{judgement.json()["id"]}').json() == {
        'removed': judgement.json()['id']
    }
    assert authed.delete(f'{base}/gaps/{gap["id"]}').json() == {'removed': gap['id']}
    actions = {e['action'] for e in authed.get('/api/audit').json()}
    assert {'case.judgement.add', 'case.judgement.update', 'case.gap.add', 'case.gap.rfi', 'case.publish',
            'case.export', 'case.judgement.remove', 'case.gap.remove'} <= actions  # fmt: skip


def test_bad_input_and_archived_products(authed: TestClient) -> None:
    case_id = started(authed)
    base = f'/api/cases/{case_id}'
    bad = {'statement': 'x', 'likelihood': 'probably', 'confidence': 'high'}
    assert authed.post(f'{base}/judgements', json=bad).status_code == 422
    foreign = {'statement': 'x', 'likelihood': 'likely', 'confidence': 'high', 'evidence': ['nope']}
    assert authed.post(f'{base}/judgements', json=foreign).status_code == 404
    assert authed.post(f'{base}/gaps', json={'question': 'Why?'}).status_code == 422  # too short for an RFI
    assert authed.get(f'{base}/export', params={'format': 'stix'}).status_code == 422  # nothing in it
    assert authed.get(f'{base}/export', params={'format': 'pdf'}).status_code == 422
    authed.post(f'{base}/close', json={'note': 'Not needed.'})
    ok = {'statement': 'x', 'likelihood': 'likely', 'confidence': 'high'}
    assert authed.post(f'{base}/judgements', json=ok).status_code == 409
    assert authed.post(f'{base}/publish').status_code == 409


def test_a_limited_key_sees_only_products_and_versions_within_its_limit(
    app: FastAPI, client: TestClient, authed: TestClient
) -> None:
    hidden = doc(authed, 'Partner note', 'C2 at 203.0.113.51.', tlp='AMBER')
    case_id = started(authed)
    base = f'/api/cases/{case_id}'
    item = authed.post(f'{base}/items', json={'kind': 'document', 'target_id': hidden}).json()
    authed.patch(base, json={'bluf': 'Partner traffic.'})
    authed.post(f'{base}/judgements', json={'statement': 'Seen.', 'likelihood': 'likely', 'confidence': 'low',
                                           'evidence': [item['id']]})  # fmt: skip
    authed.post(f'{base}/publish')
    reader = key(app, 'read', 'GREEN')
    for path in (base, f'{base}/product', f'{base}/product?version=1', f'{base}/export?format=md'):
        assert client.get(path, headers=reader).status_code == 404, path
    writer = key(app, 'read-write', 'GREEN')
    judgement = {'statement': 'x', 'likelihood': 'likely', 'confidence': 'high'}
    assert client.post(f'{base}/judgements', headers=writer, json=judgement).status_code == 404
    own = client.post('/api/cases', headers=writer, json={'title': 'Mine', 'tlp': 'GREEN'}).json()
    above = {'statement': 'x', 'likelihood': 'likely', 'confidence': 'high', 'tlp': 'AMBER'}
    assert client.post(f'/api/cases/{own["id"]}/judgements', headers=writer, json=above).status_code == 403
