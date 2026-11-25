"""Verdicts on indicators and the blocklist built from them (review Design 1)."""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from insight import services
from insight.models import EntityAssessment
from insight.ratelimit import IOC_EXPORT
from insight.schemas import DocumentInput, IocExportQuery
from insight.web.boundary import rate_limit_policy

PUBLIC_IP = '93.184.216.34'
OTHER_IP = '45.33.32.156'
PRIVATE_IP = '10.20.30.40'
EVIL_DOMAIN = 'evil-updates.net'
SHA256 = hashlib.sha256(b'insight blocklist test').hexdigest()


def ingest(app: FastAPI, body: str, tlp: str = 'GREEN', title: str = 'Report') -> dict[str, Any]:
    """Ingest a report; returns its ID and ``{value: {'entity': id, 'observation': id}}``."""
    with app.state.session_factory.begin() as db:
        doc, _ = services.ingest(
            db, DocumentInput.model_validate({'title': title, 'body': body, 'source_name': 'S', 'tlp': tlp})
        )
        observations = services.detail(db, doc)['observations']
    found = {o['value']: {'entity': o['entity_id'], 'observation': o['id']} for o in observations}
    return {'id': doc.id, 'values': found}


def accept(app: FastAPI, observation_id: str) -> None:
    with app.state.session_factory.begin() as db:
        services.set_observation_status(db, observation_id, 'accepted')


def assess(client: TestClient, entity_id: str, **payload: Any) -> Any:
    return client.post(f'/api/entities/{entity_id}/assessment', json=payload)


@pytest.fixture
def signed_in(client: TestClient, login: Callable[..., str]) -> TestClient:
    login(client)
    return client


def test_a_verdict_is_recorded_shown_and_audited(app: FastAPI, signed_in: TestClient) -> None:
    report = ingest(app, f'C2 server at {PUBLIC_IP}.')
    entity = report['values'][PUBLIC_IP]['entity']
    until = (datetime.now(UTC).date() + timedelta(days=10)).isoformat()
    response = assess(
        signed_in, entity, verdict='malicious', reason='Beacons every 60 s', tlp='GREEN', valid_until=until
    )
    assert response.status_code == 200, response.text
    assert response.json()['verdict'] == 'malicious'
    shown = signed_in.get(f'/api/entities/{entity}').json()
    assert shown['assessment']['reason'] == 'Beacons every 60 s'
    assert shown['assessment']['valid_until'] == f'{until}T23:59:59+00:00'
    assert shown['assessment']['actor'] == 'operator'
    assert shown['flags'] == []
    assert shown['first_seen_at'] == shown['last_seen_at'] is not None
    events = [e for e in signed_in.get('/api/audit').json() if e['action'] == 'entity.assess']
    assert [e['detail'] for e in events] == [f'malicious (TLP:GREEN, until {until})']


def test_unknown_clears_a_verdict(app: FastAPI, signed_in: TestClient) -> None:
    entity = ingest(app, f'Seen {PUBLIC_IP}.')['values'][PUBLIC_IP]['entity']
    assess(signed_in, entity, verdict='suspicious')
    assert assess(signed_in, entity, verdict='unknown').json() == {'verdict': 'unknown'}
    assert signed_in.get(f'/api/entities/{entity}').json()['assessment'] is None


def test_flags_are_shown_on_the_entity(app: FastAPI, signed_in: TestClient) -> None:
    entity = ingest(app, f'Victim host {PRIVATE_IP}.')['values'][PRIVATE_IP]['entity']
    assert signed_in.get(f'/api/entities/{entity}').json()['flags'] == ['non-routable']


@pytest.mark.parametrize(
    ('payload', 'status'),
    [
        ({'verdict': 'evil'}, 422),
        ({'verdict': 'malicious', 'valid_until': '2020-01-01'}, 422),
        ({'verdict': 'malicious', 'tlp': 'PURPLE'}, 422),
        ({'verdict': 'malicious', 'reason': 'x' * 2001}, 422),
        ({'verdict': 'malicious', 'extra': 1}, 422),
    ],
)
def test_bad_assessments_are_refused(
    app: FastAPI, signed_in: TestClient, payload: dict[str, Any], status: int
) -> None:
    entity = ingest(app, f'Seen {PUBLIC_IP}.')['values'][PUBLIC_IP]['entity']
    assert assess(signed_in, entity, **payload).status_code == status


def test_assessing_an_unknown_entity_is_a_404(signed_in: TestClient) -> None:
    assert assess(signed_in, 'no-such-entity', verdict='malicious').status_code == 404


# --------------------------------------------------------------------------- blocklist


def blocklisted(client: TestClient, kind: str, **params: Any) -> list[str]:
    response = client.get('/api/iocs/blocklist', params={'kind': kind, **params})
    assert response.status_code == 200, response.text
    return response.text.splitlines()


def test_the_blocklist_holds_only_safe_malicious_accepted_values(app: FastAPI, signed_in: TestClient) -> None:
    report = ingest(app, f'C2 {PUBLIC_IP} and {OTHER_IP}; victim {PRIVATE_IP}; domain {EVIL_DOMAIN}.')
    values = report['values']
    for value in (PUBLIC_IP, PRIVATE_IP, EVIL_DOMAIN):
        accept(app, values[value]['observation'])  # OTHER_IP stays unreviewed
    for value in (PUBLIC_IP, OTHER_IP, PRIVATE_IP):
        assess(signed_in, values[value]['entity'], verdict='malicious')
    assess(signed_in, values[EVIL_DOMAIN]['entity'], verdict='suspicious')
    # Unreviewed (OTHER_IP), flagged (PRIVATE_IP) and merely suspicious (EVIL_DOMAIN) values stay off.
    assert blocklisted(signed_in, 'ip') == [PUBLIC_IP]
    assert blocklisted(signed_in, 'domain') == []
    csv_lines = blocklisted(signed_in, 'ip', format='csv')
    assert csv_lines[0] == 'value,kind,decided_at,expires_at,tlp'
    assert csv_lines[1].startswith(f'{PUBLIC_IP},ip,')
    assert csv_lines[1].endswith(',AMBER')
    events = [e for e in signed_in.get('/api/audit').json() if e['action'] == 'ioc.blocklist']
    assert len(events) == 3


@pytest.mark.parametrize('engine', ['suricata', 'snort'])
def test_sensor_download_reuses_the_blocklist_policy(
    app: FastAPI, signed_in: TestClient, engine: str
) -> None:
    values = ingest(app, f'{PUBLIC_IP}, {PRIVATE_IP}, {OTHER_IP}, {EVIL_DOMAIN}')['values']
    for value, ids in values.items():
        if value != OTHER_IP:
            accept(app, ids['observation'])
        assess(signed_in, ids['entity'], verdict='malicious')
    endpoint = '/api/iocs/blocklist'
    result = signed_in.get(endpoint, params={'kind': 'ip', 'format': engine})
    assert result.status_code == 200, result.text
    assert result.headers['content-disposition'] == f'attachment; filename="insight-{engine}-ip.rules"'
    assert f'alert ip any any <> {PUBLIC_IP} any' in result.text
    assert PRIVATE_IP not in result.text
    assert OTHER_IP not in result.text
    assert len([line for line in result.text.splitlines() if line.startswith('alert ')]) == 1
    dns = signed_in.get(endpoint, params={'kind': 'domain', 'format': engine})
    assert dns.status_code == 200
    assert EVIL_DOMAIN in dns.text
    kind = 'sha256'
    assert signed_in.get(endpoint, params={'kind': kind, 'format': engine}).status_code == 422
    assess(signed_in, values[EVIL_DOMAIN]['entity'], verdict='unknown')
    assert signed_in.get(endpoint, params={'kind': 'domain', 'format': engine}).status_code == 422
    events = [event for event in signed_in.get('/api/audit').json() if event['action'] == 'ioc.blocklist']
    assert len(events) == 2


def test_expired_verdicts_leave_the_blocklist(app: FastAPI, signed_in: TestClient) -> None:
    report = ingest(app, f'C2 {PUBLIC_IP} and {OTHER_IP}; payload {SHA256}.')
    values = report['values']
    for value in (PUBLIC_IP, OTHER_IP, SHA256):
        accept(app, values[value]['observation'])
        assess(signed_in, values[value]['entity'], verdict='malicious')
    long_ago = (datetime.now(UTC) - timedelta(days=400)).isoformat()
    with app.state.session_factory.begin() as db:
        own = db.get(EntityAssessment, values[PUBLIC_IP]['entity'])
        assert own is not None
        own.valid_until = (datetime.now(UTC) - timedelta(minutes=1)).isoformat()  # its own expiry passed
        for value in (OTHER_IP, SHA256):
            row = db.get(EntityAssessment, values[value]['entity'])
            assert row is not None
            row.decided_at = long_ago  # past the default lifetime for addresses; hashes have none
    assert blocklisted(signed_in, 'ip') == []
    assert blocklisted(signed_in, 'sha256') == [SHA256]


def test_reviewed_network_range_is_exportable_but_never_blocklisted(
    app: FastAPI, signed_in: TestClient
) -> None:
    subnet = '203.0.113.0/24'
    report = ingest(app, f'Reported network {subnet}.')
    entry = report['values'][subnet]
    accept(app, entry['observation'])
    assert assess(signed_in, entry['entity'], verdict='malicious').status_code == 200
    response = signed_in.get('/api/iocs/export', params={'kind': 'cidr', 'review_status': 'accepted'})
    assert response.status_code == 200
    assert [(ioc['value'], ioc['verdict']) for ioc in response.json()['iocs']] == [(subnet, 'malicious')]
    assert blocklisted(signed_in, 'ip') == []
    assert signed_in.get('/api/iocs/blocklist', params={'kind': 'cidr'}).status_code == 422


def test_blocklist_kind_must_be_blockable(signed_in: TestClient) -> None:
    response = signed_in.get('/api/iocs/blocklist', params={'kind': 'cve'})
    assert response.status_code == 422
    assert 'kind must be one of' in response.json()['detail']
    assert signed_in.get('/api/iocs/blocklist', params={'kind': 'ip', 'format': 'xml'}).status_code == 422


def test_email_export_marks_personal_data_and_can_exclude_it(app: FastAPI, signed_in: TestClient) -> None:
    address = 'intake@security.example.org'
    report = ingest(app, f'Contact {address} about CVE-2024-12345.')
    email = report['values'][address]
    accept(app, email['observation'])
    assert assess(signed_in, email['entity'], verdict='malicious').status_code == 200
    response = signed_in.get('/api/iocs/export', params={'kind': 'email', 'defang': 'true'})
    assert response.status_code == 200
    (ioc,) = response.json()['iocs']
    assert ioc['value'] == 'intake@security[.]example[.]org'
    assert 'personal-data' in ioc['flags']
    filtered = signed_in.get(
        '/api/iocs/export', params={'exclude_flag': 'personal-data', 'evidence': 'false'}
    )
    assert filtered.status_code == 200
    assert [(i['kind'], i['value']) for i in filtered.json()['iocs']] == [('cve', 'CVE-2024-12345')]
    assert signed_in.get('/api/iocs/blocklist', params={'kind': 'email'}).status_code == 422


def test_blocklists_share_the_ioc_export_rate_budget() -> None:
    assert rate_limit_policy('GET', '/api/iocs/blocklist') is IOC_EXPORT
    assert rate_limit_policy('GET', '/api/iocs/stix') is IOC_EXPORT


# --------------------------------------------------------------------------- TLP-limited keys


@pytest.fixture
def green_key(app: FastAPI) -> dict[str, str]:
    with app.state.session_factory.begin() as db:
        _, token = services.create_api_key(db, name='siem', access='read-write', max_tlp='GREEN')
    return {'Authorization': f'Bearer {token}'}


def test_a_limited_key_sees_only_verdicts_within_its_limit(
    app: FastAPI, signed_in: TestClient, client: TestClient, green_key: dict[str, str]
) -> None:
    values = ingest(app, f'C2 {PUBLIC_IP} and {OTHER_IP}.')['values']
    for value in (PUBLIC_IP, OTHER_IP):
        accept(app, values[value]['observation'])
    assess(signed_in, values[PUBLIC_IP]['entity'], verdict='malicious', reason='SECRET-REASON', tlp='AMBER')
    assess(signed_in, values[OTHER_IP]['entity'], verdict='malicious', tlp='GREEN')
    signed_in.cookies.clear()
    hidden = client.get(f'/api/entities/{values[PUBLIC_IP]["entity"]}', headers=green_key)
    assert hidden.json()['assessment'] is None
    assert 'SECRET-REASON' not in hidden.text
    listed = client.get('/api/iocs/blocklist', params={'kind': 'ip'}, headers=green_key).text.splitlines()
    assert listed == [OTHER_IP]
    for engine in ('suricata', 'snort'):
        rules = client.get('/api/iocs/blocklist', params={'kind': 'ip', 'format': engine}, headers=green_key)
        assert rules.status_code == 200
        assert OTHER_IP in rules.text
        assert PUBLIC_IP not in rules.text
    export = client.get('/api/iocs/export', headers=green_key).json()
    verdicts = {ioc['value']: ioc['verdict'] for ioc in export['iocs']}
    assert verdicts == {PUBLIC_IP: 'unknown', OTHER_IP: 'malicious'}


def test_a_limited_key_cannot_set_or_replace_verdicts_above_its_limit(
    app: FastAPI, signed_in: TestClient, client: TestClient, green_key: dict[str, str]
) -> None:
    green = ingest(app, f'C2 {PUBLIC_IP}.')['values'][PUBLIC_IP]['entity']
    amber_only = ingest(app, f'Internal note on {OTHER_IP}.', tlp='AMBER')['values'][OTHER_IP]['entity']
    assess(signed_in, green, verdict='malicious', tlp='AMBER')
    signed_in.cookies.clear()

    def post(entity: str, **payload: Any) -> Any:
        return client.post(f'/api/entities/{entity}/assessment', json=payload, headers=green_key)

    assert post(green, verdict='benign', tlp='GREEN').status_code == 403  # would overwrite an AMBER verdict
    assert post(green, verdict='unknown').status_code == 403
    assert post(amber_only, verdict='malicious', tlp='GREEN').status_code == 404  # cannot see it at all
    with app.state.session_factory() as db:
        kept = db.get(EntityAssessment, green)
        assert kept is not None
        assert kept.verdict == 'malicious'


# --------------------------------------------------------------------------- IOC export


def test_ioc_exports_carry_verdicts_and_flags_and_filter_by_them(app: FastAPI, signed_in: TestClient) -> None:
    values = ingest(app, f'C2 {PUBLIC_IP}; victim {PRIVATE_IP}; also {OTHER_IP}.')['values']
    assess(signed_in, values[PUBLIC_IP]['entity'], verdict='malicious')
    export = signed_in.get('/api/iocs/export').json()
    by_value = {ioc['value']: ioc for ioc in export['iocs']}
    assert by_value[PUBLIC_IP]['verdict'] == 'malicious'
    assert by_value[PRIVATE_IP]['flags'] == ['non-routable']
    assert by_value[OTHER_IP]['verdict'] == 'unknown'
    malicious = signed_in.get('/api/iocs/export', params={'verdict': 'malicious'}).json()
    assert [ioc['value'] for ioc in malicious['iocs']] == [PUBLIC_IP]
    assert malicious['filters']['verdicts'] == ['malicious']
    unflagged = signed_in.get('/api/iocs/export', params={'exclude_flag': 'non-routable'}).json()
    assert {ioc['value'] for ioc in unflagged['iocs']} == {PUBLIC_IP, OTHER_IP}
    assert signed_in.get('/api/iocs/export', params={'verdict': 'evil'}).status_code == 422


def test_the_export_preview_counts_what_the_filtered_export_contains(
    app: FastAPI, signed_in: TestClient
) -> None:
    values = ingest(app, f'C2 {PUBLIC_IP}; victim {PRIVATE_IP}; also {OTHER_IP}.')['values']
    assess(signed_in, values[PUBLIC_IP]['entity'], verdict='malicious')
    query = IocExportQuery(verdicts=('unknown',), exclude_flags=('non-routable',))
    with app.state.session_factory.begin() as db:
        counts = services.ioc_export_counts(db, query)
        export = services.export_iocs(db, query)
    assert counts == {key: export['counts'][key] for key in ('iocs', 'documents', 'mentions')}
    assert [ioc['value'] for ioc in export['iocs']] == [OTHER_IP]


@pytest.mark.parametrize(
    ('value', 'shown'),
    [
        ('=HYPERLINK("http://evil.example")', '\'=HYPERLINK("http://evil.example")'),
        ('+1', "'+1"),
        ('-2', "'-2"),
        ('@SUM(A1)', "'@SUM(A1)"),
        ('\tx', "'\tx"),
        ('\rx', "'\rx"),
        ('198.51.100.7', '198.51.100.7'),
        ('', ''),
    ],
)
def test_regression_n1_csv_cells_cannot_start_a_formula(value: str, shown: str) -> None:
    """Review N1: a spreadsheet opening the blocklist CSV must not evaluate a value as a formula."""
    from insight.web.routes.exports import cell

    assert cell(value) == shown
