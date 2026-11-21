"""The threat-group library: industry wording, the builder, the bundled edition and the sync (ADR 0025)."""

from __future__ import annotations

import asyncio
import json
import socket
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest

from insight import threat_library, threat_library_sync
from insight.industries import BY_KEY, INDUSTRIES, industries_in, industry_for_label, plain
from insight.threat_library import library, parse
from insight.threat_library_build import FORMAT, build, check_sentences, sha256
from insight.threat_library_sync import PINNED, Pinned, render, sync_library

BUNDLED = Path(threat_library.__file__).parent / 'data' / 'actors.json'


# --------------------------------------------------------------------------- industry wording


@pytest.mark.parametrize(
    ('text', 'expected'),
    [
        ('The group has targeted hospitals and pharmaceutical companies in Europe.', {'healthcare'}),
        ('It has targeted the hospitality sector.', {'retail'}),  # not hospitals
        ('It targets banks and other financial institutions in Asia.', {'finance'}),
        (
            'The group has primarily targeted government and military organizations.',
            {'government', 'defense'},
        ),
        ('The group is a cryptocurrency mining operation.', set()),
        ('It is attributed to the Ministry of State Security; it targets universities.', {'education'}),
        ('The group operates on behalf of the Reconnaissance General Bureau.', set()),
        ('The company named in the report makes widgets.', set()),
    ],
)
def test_industries_are_found_only_where_a_sentence_says_a_sector_was_targeted(
    text: str, expected: set[str]
) -> None:
    assert set(industries_in(text)) == expected


@pytest.mark.parametrize(
    ('text', 'expected'),
    [
        # The technique "social engineering" is not the engineering industry (ATT&CK's LAPSUS$ entry).
        ('It specializes in large-scale social engineering and extortion attacks.', set()),
        # "Multiple industrial verticals" means any industry, not manufacturing (ATT&CK's Fox Kitten entry).
        ('It has targeted multiple industrial verticals.', set()),
        # Aviation is transport; aerospace stays defence (ATT&CK's APT33 and Dragonfly entries).
        ('It has a particular interest in targeting the aviation sector.', {'transportation'}),
        ('It has targeted aerospace companies.', {'defense'}),
        # The gaming industry is video games (media and entertainment), not gambling (ATT&CK's Winnti entry).
        ('The group has heavily targeted the gaming industry.', {'media'}),
        ('It has targeted casinos and online gambling sites.', {'retail'}),
    ],
)
def test_regression_reviewed_false_matches_in_the_pinned_catalog(text: str, expected: set[str]) -> None:
    """Regression: these phrases were mapped to the wrong industry (or to one at all) before review."""
    assert set(industries_in(text)) == expected


def test_the_evidence_is_the_sentence_with_its_citations_removed() -> None:
    text = (
        '[APT0](https://attack.mitre.org/groups/G9990) is a test group. It has targeted energy companies '
        'in Europe.(Citation: Vendor 2024) Nothing else.'
    )
    found = industries_in(text)
    assert plain(found['energy']) == 'It has targeted energy companies in Europe.'


def test_catalog_labels_map_to_industries() -> None:
    assert industry_for_label('Healthcare') == 'healthcare'
    assert industry_for_label('Telecoms') == 'telecommunications'
    assert industry_for_label('Private sector') is None  # too broad to name an industry
    assert set(BY_KEY) == {i.key for i in INDUSTRIES}


# --------------------------------------------------------------------------- the builder


def _ref(attack_id: str, kind: str) -> dict[str, Any]:
    return {
        'source_name': 'mitre-attack',
        'external_id': attack_id,
        'url': f'https://attack.mitre.org/{kind}/{attack_id}',
    }


def mini_bundle() -> dict[str, Any]:
    group = {
        'type': 'intrusion-set',
        'id': 'intrusion-set--1',
        'name': 'Test Panda',
        'aliases': ['Test Panda', 'TP-1'],
        'description': (
            '[Test Panda](https://attack.mitre.org/groups/G9001) is a test group. '
            'It has targeted hospitals and telecommunications providers.(Citation: Vendor A)'
        ),
        'external_references': [
            _ref('G9001', 'groups'),
            {'source_name': 'Vendor A', 'url': 'https://a.example/r'},
        ],
        'modified': '2026-04-01T00:00:00Z',
    }
    other = {
        'type': 'intrusion-set',
        'id': 'intrusion-set--2',
        'name': 'Other Group',
        'aliases': ['Other Group', 'Shared'],
        'description': 'A group with no stated targets.',
        'external_references': [_ref('G9002', 'groups')],
    }
    third = {**other, 'id': 'intrusion-set--3', 'name': 'Third', 'aliases': ['Third', 'Shared']}
    third['external_references'] = [_ref('G9003', 'groups')]
    technique = {
        'type': 'attack-pattern',
        'id': 'attack-pattern--1',
        'name': 'PowerShell',
        'external_references': [_ref('T1059.001', 'techniques')],
    }
    mitigation = {
        'type': 'course-of-action',
        'id': 'course-of-action--1',
        'name': 'Execution Prevention',
        'external_references': [_ref('M1038', 'mitigations')],
    }
    component = {
        'type': 'x-mitre-data-component',
        'id': 'x-mitre-data-component--1',
        'name': 'Process Creation',
        'external_references': [_ref('DC0032', 'datacomponents')],
    }
    analytic = {
        'type': 'x-mitre-analytic',
        'id': 'x-mitre-analytic--1',
        'x_mitre_platforms': ['Windows'],
        'description': 'Encoded command lines.',
        'x_mitre_log_source_references': [
            {
                'x_mitre_data_component_ref': 'x-mitre-data-component--1',
                'name': 'WinEventLog:Sysmon',
                'channel': 'EventCode=1',
            }
        ],
        'external_references': [_ref('AN0001', 'analytics')],
    }
    strategy = {
        'type': 'x-mitre-detection-strategy',
        'id': 'x-mitre-detection-strategy--1',
        'name': 'Detect encoded PowerShell',
        'x_mitre_analytic_refs': ['x-mitre-analytic--1'],
        'external_references': [_ref('DET0001', 'detectionstrategies')],
    }
    campaign = {
        'type': 'campaign',
        'id': 'campaign--1',
        'name': 'Operation Test',
        'first_seen': '2025-01-01T00:00:00Z',
        'last_seen': '2025-06-01T00:00:00Z',
        'external_references': [_ref('C9001', 'campaigns')],
    }

    def rel(kind: str, source: str, target: str, n: int, description: str = '') -> dict[str, Any]:
        return {
            'type': 'relationship',
            'id': f'relationship--{n}',
            'relationship_type': kind,
            'source_ref': source,
            'target_ref': target,
            'description': description,
        }

    return {
        'type': 'bundle',
        'objects': [
            {'type': 'x-mitre-collection', 'id': 'x-mitre-collection--1', 'x_mitre_version': '99.0',
             'modified': '2026-05-01T00:00:00Z'},
            group, other, third, technique, mitigation, component, analytic, strategy, campaign,
            rel('uses', 'intrusion-set--1', 'attack-pattern--1', 1, 'Test Panda ran PowerShell.'),
            rel('mitigates', 'course-of-action--1', 'attack-pattern--1', 2),
            rel('detects', 'x-mitre-detection-strategy--1', 'attack-pattern--1', 3),
            rel('attributed-to', 'campaign--1', 'intrusion-set--1', 4),
        ],
    }  # fmt: skip


def mini_cluster() -> dict[str, Any]:
    return {
        'version': 7,
        'values': [
            {'value': 'TP-1', 'meta': {'cfr-target-category': ['Government', 'Private sector'],
                                       'cfr-suspected-victims': ['Narnia'], 'refs': ['https://www.cfr.org/x']}},
            {'value': 'Shared', 'meta': {'targeted-sector': ['Energy']}},
        ],
    }  # fmt: skip


def test_build_keeps_the_source_of_every_claim() -> None:
    built = build(mini_bundle(), mini_cluster())
    assert built['format'] == FORMAT
    assert built['sources']['attack']['version'] == '99.0'
    groups = {g['id']: g for g in built['groups']}
    panda = groups['G9001']
    attack, misp = panda['industries']
    assert attack == {
        'industries': ['healthcare', 'telecommunications'],
        'source': 'attack',
        'evidence': 'It has targeted hospitals and telecommunications providers.',
        'citations': [{'name': 'Vendor A', 'url': 'https://a.example/r'}],
    }
    assert misp['industries'] == ['government']
    assert misp['match'] == '"TP-1" is the name of this MISP entry and a name of G9001 in ATT&CK.'
    assert misp['citations'] == [{'name': 'CFR Cyber Operations Tracker', 'url': 'https://www.cfr.org/x'}]
    assert panda['regions'][0]['names'] == ['Narnia']
    assert panda['campaigns'][0]['id'] == 'C9001'
    assert panda['techniques'] == ['T1059.001']
    detection = built['techniques']['T1059.001']['detections'][0]
    assert (detection['id'], detection['components'], detection['log_sources']) == (
        'DET0001',
        ['DC0032'],
        ['WinEventLog:Sysmon'],
    )
    assert built['techniques']['T1059.001']['mitigations'] == ['M1038']
    # "Shared" names two ATT&CK groups: its MISP labels go to neither.
    assert groups['G9002']['industries'] == []
    assert groups['G9003']['industries'] == []
    assert check_sentences(built, mini_bundle()) == []


def test_tampered_evidence_is_caught() -> None:
    built = build(mini_bundle(), mini_cluster())
    built['groups'][0]['industries'][0]['evidence'] = 'It has targeted banks.'
    assert check_sentences(built, mini_bundle()) == [
        "G9001 ['healthcare', 'telecommunications']: evidence not in the ATT&CK description"
    ]


def test_the_full_edition_keeps_analytics_and_procedures() -> None:
    built = build(mini_bundle(), None, full=True)
    panda = next(g for g in built['groups'] if g['id'] == 'G9001')
    assert panda['procedures'] == {'T1059.001': 'Test Panda ran PowerShell.'}
    analytic = built['techniques']['T1059.001']['detections'][0]['analytics'][0]
    assert analytic['log_sources'] == [['DC0032', 'WinEventLog:Sysmon', 'EventCode=1']]
    parsed = parse(json.loads(render(built)), 'test')
    assert parsed.techniques['T1059.001'].detections[0].analytics[0].description == 'Encoded command lines.'


def test_build_refuses_what_is_not_an_attack_bundle() -> None:
    with pytest.raises(ValueError, match='STIX bundle'):
        build({'type': 'nope'}, None)
    with pytest.raises(ValueError, match='Not an Insight threat library'):
        parse({'format': 'other'}, 'x')


# --------------------------------------------------------------------------- the bundled edition


def test_the_bundled_edition_is_small_pinned_and_sourced() -> None:
    raw = json.loads(BUNDLED.read_text(encoding='utf-8'))
    assert BUNDLED.stat().st_size < 1_000_000
    assert raw['edition'] == 'bundled'
    assert raw['sources']['attack']['sha256'] == PINNED['attack'].sha256
    assert raw['sources']['misp-galaxy']['sha256'] == PINNED['misp-galaxy'].sha256
    assert 'MITRE' in raw['notice']
    claims = [c for g in raw['groups'] for c in g['industries']]
    assert len(raw['groups']) > 150
    assert len(claims) > 150
    for claim in claims:
        assert claim['industries']
        assert set(claim['industries']) <= set(BY_KEY)
        assert claim['evidence'].strip()
        if claim['source'] == 'misp-galaxy':
            assert claim['match'].startswith('"')
        else:
            assert claim['source'] == 'attack'
    assert render(raw) == BUNDLED.read_text(encoding='utf-8'), 'regenerate with scripts/update_actors.py'


def test_reviewed_exclusions_hold_in_the_bundled_edition() -> None:
    lib = library()
    for item in json.loads(BUNDLED.read_text(encoding='utf-8'))['reviewed_exclusions']:
        group = lib.group(item['group'])
        assert group is not None
        assert not any(item['industry'] in c.industries and c.source == 'attack' for c in group.claims)


# --------------------------------------------------------------------------- loading and syncing


@pytest.fixture
def fresh_library(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Iterator[Path]:
    monkeypatch.setenv('INSIGHT_DATA_DIR', str(tmp_path))
    threat_library.library.cache_clear()
    yield tmp_path / 'threat-library.json'
    threat_library.library.cache_clear()


def test_a_synced_library_is_preferred_and_a_broken_one_ignored(fresh_library: Path) -> None:
    fresh_library.write_text(render(build(mini_bundle(), mini_cluster(), full=True)), encoding='utf-8')
    assert threat_library.reload().group('G9001') is not None
    fresh_library.write_text('{"format": "nope"}', encoding='utf-8')
    assert threat_library.reload().edition == 'bundled'


def _public_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake(host: str, port: int, *_: Any, **__: Any) -> list[Any]:
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('8.8.8.8', port))]

    monkeypatch.setattr(socket, 'getaddrinfo', fake)


def _serve(payloads: dict[str, bytes]) -> Callable[[httpx.Request], httpx.Response]:
    def handler(request: httpx.Request) -> httpx.Response:
        # Downloads go to the checked address with the real host in Host and SNI (insight.egress).
        host = request.headers['host']
        assert request.url.host == '8.8.8.8'
        assert request.extensions['sni_hostname'] == host
        return httpx.Response(200, content=payloads[str(request.url.copy_with(host=host))])

    return handler


def _pin(monkeypatch: pytest.MonkeyPatch, attack: bytes, misp: bytes) -> dict[str, bytes]:
    pins = {
        'attack': Pinned(
            'attack', 'MITRE ATT&CK Enterprise', '99.0', PINNED['attack'].url, sha256(attack), 1_000_000
        ),
        'misp-galaxy': Pinned(
            'misp-galaxy', 'MISP galaxy', '7', PINNED['misp-galaxy'].url, sha256(misp), 1_000_000
        ),
    }
    monkeypatch.setattr(threat_library_sync, 'PINNED', pins)
    return {pins['attack'].url: attack, pins['misp-galaxy'].url: misp}


def test_sync_fetches_checks_and_writes_the_full_edition(
    monkeypatch: pytest.MonkeyPatch, fresh_library: Path
) -> None:
    _public_dns(monkeypatch)
    attack, misp = json.dumps(mini_bundle()).encode(), json.dumps(mini_cluster()).encode()
    served = _pin(monkeypatch, attack, misp)
    built = asyncio.run(sync_library(fresh_library, transport=httpx.MockTransport(_serve(served))))
    assert built['edition'] == 'full'
    assert built['sources']['attack']['sha256'] == sha256(attack)
    assert json.loads(fresh_library.read_text(encoding='utf-8'))['groups'][0]['id'] == 'G9001'


def test_sync_refuses_a_file_that_does_not_match_its_pin(
    monkeypatch: pytest.MonkeyPatch, fresh_library: Path
) -> None:
    _public_dns(monkeypatch)
    attack, misp = json.dumps(mini_bundle()).encode(), json.dumps(mini_cluster()).encode()
    served = _pin(monkeypatch, attack, misp)
    served[PINNED['attack'].url] = attack + b' '
    with pytest.raises(ValueError, match='does not match the pinned release'):
        asyncio.run(sync_library(fresh_library, transport=httpx.MockTransport(_serve(served))))
    assert not fresh_library.exists()


def test_the_pins_name_exact_commits_on_the_allow_listed_host() -> None:
    from insight.connectors import ALLOWED_HOSTS

    for pinned in PINNED.values():
        assert pinned.url.startswith('https://raw.githubusercontent.com/')
        assert 'raw.githubusercontent.com' in ALLOWED_HOSTS
        assert len(pinned.sha256) == 64
        commit = pinned.url.split('/')[5]
        assert len(commit) == 40, pinned.url
