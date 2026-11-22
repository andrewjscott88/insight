"""``/api/requirements`` and ``/api/rfis`` (TIP 4.1, ADR 0032): the HTTP contract, matching, TLP limits and
the ``read-feedback`` key that may file a request for information (or a sighting) and nothing else."""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI
from fastapi.testclient import TestClient

from insight import services


def doc(authed: TestClient, title: str, body: str, tlp: str = 'GREEN') -> str:
    response = authed.post(
        '/api/documents', json={'title': title, 'body': body, 'source_name': 's', 'tlp': tlp}
    )
    assert response.status_code == 200, response.text
    found: str = response.json()['id']
    return found


def key(app: FastAPI, access: str, max_tlp: str | None = None) -> dict[str, str]:
    """A new key (only one is active at a time, so this revokes the previous one)."""
    with app.state.session_factory.begin() as db:
        services.revoke_api_key(db)
        _, token = services.create_api_key(db, name=access, access=access, max_tlp=max_tlp)
    return {'Authorization': f'Bearer {token}'}


def test_a_pir_matches_reports_collects_evidence_and_is_answered_and_retired(authed: TestClient) -> None:
    gateway = doc(authed, 'Gateway advisory', 'Ransomware crews exploit CVE-2024-3400 on edge firewalls.')
    phishing = doc(authed, 'Invoice lures', 'A ransomware affiliate sends invoice lures.')
    doc(authed, 'Unrelated', 'A printer driver update.')
    created = authed.post(
        '/api/requirements',
        json={
            'kind': 'pir',
            'question': 'Are ransomware groups exploiting our edge devices?',
            'stakeholder': 'CISO',
            'priority': 'high',
            'tlp': 'GREEN',
            'criteria': [{'kind': 'cve', 'value': 'cve-2024-3400'}],
        },
    )
    assert created.status_code == 201, created.text
    pir: dict[str, Any] = created.json()
    assert (pir['kind'], pir['status'], pir['tlp'], pir['created_by']) == ('pir', 'open', 'GREEN', 'operator')
    base = f'/api/requirements/{pir["id"]}'
    term = authed.post(f'{base}/criteria', json={'kind': 'term', 'value': 'invoice lures'})
    assert (term.status_code, term.json()['value']) == (201, 'invoice lures')

    view = authed.get(base).json()
    assert {m['document_id']: m['because'] for m in view['matches']} == {
        gateway: ['cve: CVE-2024-3400'],
        phishing: ['term: invoice lures'],
    }
    assert (view['recent_matches'], view['quiet'], view['criteria_count']) == (2, False, 2)
    listed = authed.get('/api/requirements').json()['requirements']
    assert [(r['id'], r['recent_matches']) for r in listed] == [(pir['id'], 2)]
    addressed = authed.get(f'/api/documents/{gateway}/requirements').json()['requirements']
    assert [(r['id'], r['because']) for r in addressed] == [(pir['id'], ['cve: CVE-2024-3400'])]

    cited = authed.post(f'{base}/evidence', json={'document_id': gateway, 'note': 'Confirms exploitation.'})
    assert (cited.status_code, cited.json()['title']) == (201, 'Gateway advisory')
    answered = authed.post(f'{base}/answer', json={'answer': 'Yes: two crews since October.'}).json()
    assert (answered['status'], answered['answer']) == ('open', 'Yes: two crews since October.')

    child = authed.post(
        '/api/requirements', json={'kind': 'ir', 'parent_id': pir['id'], 'question': 'Which crews, and how?'}
    )
    assert child.status_code == 201
    assert [c['id'] for c in authed.get(base).json()['children']] == [child.json()['id']]
    assert authed.delete(base).status_code == 409  # It has an IR under it.

    assert authed.post(f'{base}/retire').json()['status'] == 'retired'
    refused = authed.post(f'{base}/criteria', json={'kind': 'term', 'value': 'later'})
    assert (refused.status_code, refused.json()['detail']) == (
        409,
        'This requirement is retired. Reopen it to change it.',
    )
    assert pir['id'] not in [r['id'] for r in authed.get('/api/requirements').json()['requirements']]
    assert authed.post(f'{base}/reopen').json()['status'] == 'open'

    removed = authed.delete(f'{base}/criteria/{term.json()["id"]}')
    assert removed.json() == {'removed': term.json()['id']}
    assert authed.delete(f'{base}/evidence/{cited.json()["id"]}').status_code == 200
    assert authed.get(base).json()['tlp'] == 'GREEN'
    assert authed.delete(f'/api/requirements/{child.json()["id"]}').status_code == 200
    assert authed.delete(base).json() == {'deleted': pir['id']}
    assert authed.get(f'/api/documents/{gateway}').status_code == 200  # Reports stay.


def test_a_requirement_with_criteria_and_no_recent_report_is_quiet(authed: TestClient) -> None:
    created = authed.post(
        '/api/requirements',
        json={'kind': 'pir', 'question': 'Is anyone selling our VPN access?', 'criteria': [
            {'kind': 'term', 'value': 'initial access broker'}]},
    ).json()  # fmt: skip
    view = authed.get(f'/api/requirements/{created["id"]}').json()
    assert (view['recent_matches'], view['last_match_at'], view['quiet']) == (0, None, True)
    bare = authed.post('/api/requirements', json={'kind': 'pir', 'question': 'No criteria yet?'}).json()
    assert authed.get(f'/api/requirements/{bare["id"]}').json()['quiet'] is False


def test_invalid_requirements_are_refused(authed: TestClient) -> None:
    pir = authed.post('/api/requirements', json={'kind': 'pir', 'question': 'A parent question?'}).json()
    rfi = authed.post('/api/requirements', json={'kind': 'rfi', 'question': 'A one-off question?'}).json()
    for body in (
        {'kind': 'ir', 'question': 'No parent here?'},
        {'kind': 'pir', 'question': 'A PIR with a parent?', 'parent_id': pir['id']},
        {'kind': 'ir', 'question': 'Under an RFI?', 'parent_id': rfi['id']},
        {'kind': 'pir', 'question': 'Bad CVE?', 'criteria': [{'kind': 'cve', 'value': 'CVE-24-1'}]},
        {'kind': 'pir', 'question': 'Bad technique?', 'criteria': [{'kind': 'technique', 'value': 'X1'}]},
        {'kind': 'pir', 'question': 'Due in the past?', 'due': '2000-01-01'},
        {'kind': 'pir', 'question': 'x'},
    ):
        assert authed.post('/api/requirements', json=body).status_code == 422, body
    missing = authed.post(
        '/api/requirements', json={'kind': 'ir', 'question': 'Hidden?', 'parent_id': 'nope'}
    )
    assert missing.status_code == 404
    group = authed.post(f'/api/requirements/{pir["id"]}/criteria', json={'kind': 'group', 'value': 'G9999'})
    assert group.status_code == 404


def test_tlp_markings_criteria_and_evidence_raise_the_label(authed: TestClient) -> None:
    amber = doc(authed, 'Partner bulletin', 'Seen from 198.51.100.9.', tlp='AMBER')
    marked = authed.post(
        '/api/requirements', json={'kind': 'pir', 'question': 'TLP:AMBER question here?', 'tlp': 'CLEAR'}
    ).json()
    assert marked['tlp'] == 'AMBER'
    pir = authed.post(
        '/api/requirements', json={'kind': 'pir', 'question': 'Plain question?', 'tlp': 'CLEAR'}
    )
    base = f'/api/requirements/{pir.json()["id"]}'
    evidence = authed.post(f'{base}/evidence', json={'document_id': amber}).json()
    assert authed.get(base).json()['tlp'] == 'AMBER'
    # Removing the citation keeps the label; an explicit change can lower it again.
    authed.delete(f'{base}/evidence/{evidence["id"]}')
    assert authed.get(base).json()['tlp'] == 'AMBER'
    assert authed.patch(base, json={'tlp': 'CLEAR'}).json()['tlp'] == 'CLEAR'


def test_a_tlp_limited_key_sees_and_counts_only_what_it_may(
    app: FastAPI, client: TestClient, authed: TestClient
) -> None:
    doc(authed, 'Open report', 'Ransomware notes.', tlp='GREEN')
    doc(authed, 'Restricted report', 'Ransomware partner notes.', tlp='AMBER')
    pir = authed.post(
        '/api/requirements',
        json={'kind': 'pir', 'question': 'Ransomware trends?', 'tlp': 'GREEN',
              'criteria': [{'kind': 'term', 'value': 'ransomware'}]},
    ).json()  # fmt: skip
    hidden = authed.post(
        '/api/requirements', json={'kind': 'pir', 'question': 'Partner only?', 'tlp': 'AMBER'}
    )
    green = key(app, 'read', 'GREEN')
    listed = client.get('/api/requirements', headers=green).json()['requirements']
    assert [(r['id'], r['recent_matches']) for r in listed] == [(pir['id'], 1)]
    assert authed.get(f'/api/requirements/{pir["id"]}').json()['recent_matches'] == 2
    assert client.get(f'/api/requirements/{hidden.json()["id"]}', headers=green).status_code == 404
    writer = key(app, 'read-write', 'GREEN')  # Replaces the reader.
    above = client.post(
        '/api/requirements', headers=writer, json={'kind': 'pir', 'question': 'x?', 'tlp': 'RED'}
    )
    assert above.status_code in (403, 422)


def test_a_read_feedback_key_files_requests_and_reads_answers_but_changes_nothing_else(
    app: FastAPI, client: TestClient, authed: TestClient
) -> None:
    hunt = key(app, 'read-feedback', 'AMBER')
    filed = client.post(
        '/api/rfis',
        headers=hunt,
        json={'question': 'Is 203.0.113.70 known C2?', 'requester': 'Shift hunt team', 'priority': 'high',
              'tlp': 'AMBER', 'external_ref': 'hunt-42'},
    )  # fmt: skip
    assert filed.status_code == 201, filed.text
    rfi: dict[str, Any] = filed.json()
    assert (rfi['kind'], rfi['status'], rfi['stakeholder'], rfi['external_ref']) == (
        'rfi',
        'open',
        'Shift hunt team',
        'hunt-42',
    )
    assert rfi['created_by'].startswith('api-key:')
    base = f'/api/requirements/{rfi["id"]}'
    assert client.post(f'{base}/answer', headers=hunt, json={'answer': 'mine'}).status_code == 403
    assert (
        client.post('/api/requirements', headers=hunt, json={'kind': 'pir', 'question': 'More?'}).status_code
        == 403
    )
    assert (
        client.post(
            '/api/documents', headers=hunt, json={'title': 't', 'body': 'b', 'source_name': 's'}
        ).status_code
        == 403
    )
    assert (
        client.post('/api/rfis', headers=hunt, json={'question': 'Too secret?', 'tlp': 'RED'}).status_code
        == 403
    )

    answered = authed.post(f'{base}/answer', json={'answer': 'Yes: listed by two feeds as C2.'}).json()
    assert (answered['status'], answered['answered_at'] is not None) == ('answered', True)
    seen = client.get(base, headers=hunt).json()
    assert (seen['status'], seen['answer']) == ('answered', 'Yes: listed by two feeds as C2.')

    reader = key(app, 'read')
    assert client.post('/api/rfis', headers=reader, json={'question': 'Allowed?'}).status_code == 403
