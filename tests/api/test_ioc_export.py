"""Cross-report IOC export over HTTP: ``GET /api/iocs/export``."""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from typing import Any

import pytest
from fastapi.testclient import TestClient

from insight import services

MakeDocument = Callable[..., dict[str, Any]]
FILENAME = re.compile(r'attachment; filename="insight-iocs-\d{8}T\d{6}Z\.json"')


@pytest.fixture
def reports(make_document: MakeDocument) -> tuple[dict[str, Any], dict[str, Any]]:
    """The default AMBER+STRICT report (CVE, IP, domain) and a GREEN report that shares only the IP."""
    first = make_document()
    second = make_document(title='Second', body='Beacon to 192.0.2.8.', source_name='Other', tlp='GREEN')
    return first, second


def keys(export: dict[str, Any]) -> set[tuple[str, str]]:
    return {(ioc['kind'], ioc['value']) for ioc in export['iocs']}


def document_ids(export: dict[str, Any]) -> set[str]:
    return {source['document_id'] for ioc in export['iocs'] for source in ioc['sources']}


def test_requires_authentication(client: TestClient) -> None:
    assert client.get('/api/iocs/export').status_code == 401


def test_export_is_a_labelled_attachment(authed: TestClient, reports: tuple[dict[str, Any], ...]) -> None:
    first, second = reports
    response = authed.get('/api/iocs/export')
    assert response.status_code == 200
    assert FILENAME.fullmatch(response.headers['content-disposition'])
    assert response.headers['cache-control'] == 'no-store'
    export = response.json()
    assert export['format'] == 'insight-ioc-v1'
    assert 'Not STIX' in export['handling_notice']
    assert export['tlp'] == 'AMBER+STRICT'
    assert keys(export) == {('cve', 'CVE-2024-12345'), ('ip', '192.0.2.8'), ('domain', 'example.com')}
    (ip,) = [ioc for ioc in export['iocs'] if ioc['kind'] == 'ip']
    assert ip['tlp'] == 'AMBER+STRICT'
    assert {s['document_id'] for s in ip['sources']} == {first['id'], second['id']}
    assert export['counts']['documents'] == 2


def test_filters_by_kind_and_highest_tlp(authed: TestClient, reports: tuple[dict[str, Any], ...]) -> None:
    _, second = reports
    export = authed.get('/api/iocs/export', params={'kind': ['ip', 'domain'], 'max_tlp': 'GREEN'}).json()
    assert keys(export) == {('ip', '192.0.2.8')}
    assert export['tlp'] == 'GREEN'
    assert document_ids(export) == {second['id']}
    assert export['filters']['kinds'] == ['ip', 'domain']


def test_filters_reports_like_the_inbox(authed: TestClient, reports: tuple[dict[str, Any], ...]) -> None:
    first, second = reports
    assert document_ids(authed.get('/api/iocs/export', params={'q': 'beacon'}).json()) == {second['id']}
    assert document_ids(authed.get('/api/iocs/export', params={'tlp': 'AMBER+STRICT'}).json()) == {
        first['id']
    }
    authed.post(f'/api/documents/{first["id"]}/review', json={'status': 'reviewed'})
    assert document_ids(authed.get('/api/iocs/export', params={'status': 'reviewed'}).json()) == {first['id']}


def test_rejected_mentions_are_excluded_unless_requested(
    authed: TestClient, reports: tuple[dict[str, Any], ...]
) -> None:
    first, _ = reports
    (cve,) = [o for o in first['observations'] if o['kind'] == 'cve']
    response = authed.post(f'/api/observations/{cve["id"]}/review', json={'status': 'rejected'})
    assert response.status_code == 200
    assert ('cve', 'CVE-2024-12345') not in keys(authed.get('/api/iocs/export').json())
    rejected = authed.get('/api/iocs/export', params={'review_status': 'rejected'}).json()
    assert keys(rejected) == {('cve', 'CVE-2024-12345')}


def test_defanged_export(authed: TestClient, reports: tuple[dict[str, Any], ...]) -> None:
    export = authed.get('/api/iocs/export', params={'defang': 'true'}).json()
    assert export['defanged'] is True
    assert {('ip', '192[.]0[.]2[.]8'), ('domain', 'example[.]com')} <= keys(export)
    assert '192.0.2.8' not in json.dumps(export['iocs'])  # evidence excerpts are defanged too


def test_export_is_audited(authed: TestClient, reports: tuple[dict[str, Any], ...]) -> None:
    export = authed.get('/api/iocs/export', params={'kind': 'cve'}).json()
    event = authed.get('/api/audit').json()[0]
    assert (event['action'], event['object_id']) == ('ioc.export', export['export_id'])
    detail = json.loads(event['detail'])
    assert (detail['iocs'], detail['documents'], detail['tlp']) == (1, 1, 'AMBER+STRICT')


@pytest.mark.parametrize(
    'params',
    [
        {'kind': 'bogus'},
        {'review_status': 'maybe'},
        {'max_tlp': 'WHITE'},
        {'tlp': 'amber'},
        {'status': 'done'},
        {'q': 'x' * 201},
        {'defang': 'perhaps'},
    ],
)
def test_invalid_filters_are_rejected(authed: TestClient, params: dict[str, str]) -> None:
    response = authed.get('/api/iocs/export', params=params)
    assert response.status_code == 422
    assert not any(e['action'] == 'ioc.export' for e in authed.get('/api/audit').json())


def test_oversized_exports_ask_for_narrower_filters(
    authed: TestClient, reports: tuple[dict[str, Any], ...], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(services.exports, 'MAX_EXPORT_MENTIONS', 1)
    response = authed.get('/api/iocs/export')
    assert response.status_code == 422
    assert 'narrow the filters' in response.json()['detail']


def test_empty_workspace(authed: TestClient) -> None:
    export = authed.get('/api/iocs/export').json()
    assert export['iocs'] == []
    assert export['tlp'] == 'AMBER'


def test_document_id_exports_one_report(authed: TestClient, reports: tuple[dict[str, Any], ...]) -> None:
    first, second = reports
    export = authed.get('/api/iocs/export', params={'document_id': second['id']}).json()
    assert document_ids(export) == {second['id']}
    assert export['filters']['document_ids'] == [second['id']]
    both = authed.get('/api/iocs/export', params={'document_id': [first['id'], second['id']]}).json()
    assert document_ids(both) == {first['id'], second['id']}


def test_errors_name_the_query_parameter(authed: TestClient) -> None:
    response = authed.get('/api/iocs/export', params={'kind': 'IP'})
    assert response.status_code == 422
    assert response.json()['detail'] == (
        "kind 'IP': Input should be 'cve', 'url', 'sha512', 'sha256', 'sha1', 'md5', 'ip', 'domain', "
        "'cidr' or 'email'"
    )


def test_plus_in_amber_strict_is_encoded(authed: TestClient, reports: tuple[dict[str, Any], ...]) -> None:
    """Documented pitfall: a literal + in a query string is a space."""
    assert authed.get('/api/iocs/export?max_tlp=AMBER+STRICT').status_code == 422
    assert authed.get('/api/iocs/export?max_tlp=AMBER%2BSTRICT').status_code == 200


def test_sources_carry_the_extractor_version(authed: TestClient, reports: tuple[dict[str, Any], ...]) -> None:
    export = authed.get('/api/iocs/export').json()
    assert {s['extractor_version'] for ioc in export['iocs'] for s in ioc['sources']} == {'regex-v5'}


def test_evidence_can_be_left_out(authed: TestClient, reports: tuple[dict[str, Any], ...]) -> None:
    export = authed.get('/api/iocs/export', params={'evidence': 'false'}).json()
    assert export['filters']['include_evidence'] is False
    assert {s['evidence'] for ioc in export['iocs'] for s in ioc['sources']} == {None}
