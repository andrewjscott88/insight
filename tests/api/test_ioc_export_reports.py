"""The IOC export run end to end on the two synthetic full-length reports (tests/corpus/reports/).

Both reports go in through the HTTP API exactly as an analyst would submit them, then out through the export
API and the CLI. The exported indicators must equal the hand-labelled ground truth, labels must follow the TLP
policy, and a defanged export must contain nothing clickable or resolvable. Several defects found this way are
regression tests here: e-mail domains, CIDR ranges and names cut at excerpt edges stayed live when defanged,
and a rejected victim address still reached recipients inside a neighbouring excerpt.
"""

from __future__ import annotations

import dataclasses
import json
import os
import re
from pathlib import Path
from typing import Any

import jsonschema
import pytest
from fastapi.testclient import TestClient

from insight import cli
from insight.config import Settings
from insight.extraction import canonical, known_tlds

ROOT = Path(__file__).resolve().parents[2]
REPORTS = ROOT / 'tests' / 'corpus' / 'reports'
SCHEMA = json.loads((ROOT / 'docs' / 'schemas' / 'insight-ioc-v1.schema.json').read_text('utf-8'))
GLASS, SALT = 'notional-intrusion-report', 'notional-salt-meridian'
# The extractor's documented limitation (docs/EXTRACTION.md): an even 32+32 wrapped SHA-256 stays two MD5s.
EVEN_SPLIT_HASH = ('sha256', '9c8b7a6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b')
EVEN_SPLIT_PARTS = {('md5', '9c8b7a6d5e4f3a2b1c0d9e8f7a6b5c4d'), ('md5', '3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b')}
# Network-shaped text in these reports that is not an indicator and is deliberately left as written: file and
# code names (their "TLDs" are not real TLDs) and firmware versions.
NOT_NETWORK = {
    'Net.WebClient',
    'glassharbor.dll',
    'loader.bin',
    'svchost.exe',
    'update.bin',
    '10.2.9.1',
    '9.0.0.1',
}

Keys = set[tuple[str, str]]


@pytest.fixture
def settings(settings: Settings) -> Settings:
    """These tests process the synthetic TLP:RED report on purpose, so they opt in: INSIGHT_MAX_TLP=RED."""
    return dataclasses.replace(settings, max_tlp='RED')


def truth(name: str) -> Keys:
    data = json.loads((REPORTS / f'{name}.expected.json').read_text('utf-8'))
    found = {(kind, value) for kind, value in data['expected']}
    return (found - {EVEN_SPLIT_HASH}) | EVEN_SPLIT_PARTS if name == SALT else found


def keys(export: dict[str, Any]) -> Keys:
    return {(ioc['kind'], ioc['value']) for ioc in export['iocs']}


@pytest.fixture
def reports(authed: TestClient) -> dict[str, str]:
    """Both reports, submitted below their in-text markings (GLASS says TLP:AMBER, SALT says TLP:RED)."""
    ids = {}
    for name, submitted in ((GLASS, 'GREEN'), (SALT, 'AMBER')):
        response = authed.post(
            '/api/documents',
            json={
                'title': f'{name} (synthetic)',
                'body': (REPORTS / f'{name}.md').read_text('utf-8'),
                'source_name': 'Notional CTI Cell',
                'source_url': f'https://intel.example.org/reports/{name}',
                'tlp': submitted,
            },
        )
        assert response.status_code == 200, response.text
        ids[name] = response.json()['id']
    return ids


def export(client: TestClient, **params: Any) -> dict[str, Any]:
    response = client.get('/api/iocs/export', params=params)
    assert response.status_code == 200, response.text
    result: dict[str, Any] = response.json()
    jsonschema.validate(result, SCHEMA)
    return result


def test_exports_exactly_the_ground_truth_with_policy_labels(
    authed: TestClient, reports: dict[str, str]
) -> None:
    full = export(authed)
    assert keys(full) == truth(GLASS) | truth(SALT)
    assert (full['counts']['iocs'], full['counts']['documents'], full['counts']['mentions']) == (65, 2, 91)
    assert full['tlp'] == 'RED'  # SALT MERIDIAN's TLP:RED marking raised it; the file inherits it
    labels = {(frozenset(s['document_id'] for s in ioc['sources']), ioc['tlp']) for ioc in full['iocs']}
    assert labels == {
        (frozenset({reports[GLASS]}), 'AMBER'),
        (frozenset({reports[SALT]}), 'RED'),
        (frozenset(reports.values()), 'RED'),  # the shared CIDR inherits the stricter source label
    }


def test_max_tlp_and_document_filters(authed: TestClient, reports: dict[str, str]) -> None:
    amber = export(authed, max_tlp='AMBER')
    assert (keys(amber), amber['tlp']) == (truth(GLASS), 'AMBER')  # the RED report is left out entirely
    one = export(authed, document_id=reports[SALT])
    assert (keys(one), one['counts']['documents']) == (truth(SALT), 1)


def test_defanged_export_leaves_nothing_clickable(authed: TestClient, reports: dict[str, str]) -> None:
    original = {ioc['entity_id']: ioc['value'] for ioc in export(authed)['iocs']}
    defanged = export(authed, defang='true')
    assert all(canonical(ioc['kind'], ioc['value']) == original[ioc['entity_id']] for ioc in defanged['iocs'])
    texts = [ioc['value'] for ioc in defanged['iocs']]
    texts += [s[field] for ioc in defanged['iocs'] for s in ioc['sources'] for field in ('title', 'evidence')]
    live = re.compile(
        r'(?i)\b(?:https?|ftp)://'  # a scheme
        r'|[\w.+-]+@[\w-]+(?:\.[\w-]+)+'  # an e-mail address
        r'|(?<![\w\[.])(?:[a-z0-9-]+\.)+[a-z]{2,}(?![\w\]])'  # a dotted name
        r'|(?<![\d\[.])\d{1,3}(?:\.\d{1,3}){3}(?![\d\]])'  # an IPv4 address
        r'|(?<![\w:\[])[0-9a-f]{1,4}(?::[0-9a-f]{0,4}){2,}(?![\w\]])'  # an IPv6 address
    )
    leftovers = {match.group() for text in texts for match in live.finditer(text)}
    assert leftovers == NOT_NETWORK
    assert not {name.rsplit('.', 1)[-1].lower() for name in leftovers if not name[0].isdigit()} & known_tlds()


def test_sharing_recipe_keeps_rejected_victim_data_out(authed: TestClient, reports: dict[str, str]) -> None:
    observations = authed.get(f'/api/documents/{reports[GLASS]}').json()['observations']
    for obs in observations:
        if obs['value'] in {'https://cdn-update.example.com/assets/update.bin?id=7741', '203.0.113.45'}:
            authed.post(f'/api/observations/{obs["id"]}/review', json={'status': 'accepted'})
        if obs['value'] == '10.20.30.40':  # the victim's internal address: not for sharing
            authed.post(f'/api/observations/{obs["id"]}/review', json={'status': 'rejected'})
    with_evidence = export(authed, max_tlp='AMBER', review_status='accepted', defang='true')
    assert keys(with_evidence) == {
        ('url', 'hxxps://cdn-update[.]example[.]com/assets/update[.]bin?id=7741'),
        ('ip', '203[.]0[.]113[.]45'),
    }
    # The accepted URL's excerpt still names the rejected victim address: why to share without evidence.
    assert 'internal host 10[.]20[.]30[.]40 (victim network' in json.dumps(with_evidence)
    shared = export(authed, max_tlp='AMBER', review_status='accepted', defang='true', evidence='false')
    assert keys(shared) == keys(with_evidence)
    assert 'victim' not in json.dumps(shared)
    assert '30[.]40' not in json.dumps(shared)


def test_cli_and_api_produce_the_same_indicators(
    authed: TestClient,
    reports: dict[str, str],
    settings: Any,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(os, 'environ', {'INSIGHT_DATABASE_URL': settings.database_url})
    assert cli.main(['export-iocs', 'all.json', '--defang']) == 0
    from_cli = json.loads((tmp_path / 'all.json').read_text('utf-8'))
    jsonschema.validate(from_cli, SCHEMA)
    assert keys(from_cli) == keys(export(authed, defang='true'))
