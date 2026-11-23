"""MITRE ATT&CK catalog and technique finding (ADR 0019)."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest
from scripts import update_attack

from insight import attack

ROOT = Path(__file__).resolve().parents[2]


def test_the_bundled_catalog_is_current_enterprise_attack() -> None:
    catalog = attack.catalog()
    assert re.fullmatch(r'\d+\.\d+', catalog.version)
    assert 'The MITRE Corporation' in catalog.notice
    assert [t.name for t in catalog.tactics][:3] == [
        'Reconnaissance',
        'Resource Development',
        'Initial Access',
    ]
    assert len(catalog.techniques) > 500
    shortnames = {t.shortname for t in catalog.tactics}
    for technique in catalog.techniques.values():
        assert attack.TECHNIQUE_ID.match(technique.id), technique.id
        assert technique.tactics, technique.id
        assert set(technique.tactics) <= shortnames, technique.id


def test_sub_techniques_carry_their_parent_name() -> None:
    powershell = attack.technique('t1059.001')  # IDs are matched case-insensitively for lookups
    assert powershell is not None
    assert powershell.full_name == 'Command and Scripting Interpreter: PowerShell'
    assert powershell.is_subtechnique
    assert powershell.url == 'https://attack.mitre.org/techniques/T1059/001/'
    assert attack.catalog().tactic_names(powershell) == ('Execution',)
    parent = attack.technique('T1059')
    assert parent is not None
    assert parent.full_name == 'Command and Scripting Interpreter'
    assert attack.technique('T9999') is None


@pytest.mark.parametrize(
    ('text', 'expected'),
    [
        ('Spearphishing (T1566.001) then PowerShell [T1059.001].', ['T1566.001', 'T1059.001']),
        ('Mapped: T1486; T1486 again.', ['T1486']),  # first mention only
        ('See https://attack.mitre.org/techniques/T1486/ for details.', ['T1486']),
        ('T1059,T1105', ['T1059', 'T1105']),
        ('XT1059 T1059.0012 T1059-2 v2.T1059 t1059 T10599 T105', []),  # not a technique ID on its own
        ('Model T1000 laptop, part T9999.', []),  # not in the catalog
        ('', []),
    ],
)
def test_only_technique_ids_written_in_the_text_are_found(text: str, expected: list[str]) -> None:
    assert [m.technique_id for m in attack.find_techniques(text)] == expected


def test_a_mention_keeps_its_place_and_context() -> None:
    text = 'x' * 200 + ' Initial access: T1566.001. ' + 'y' * 200
    (mention,) = attack.find_techniques(text)
    assert text[mention.start : mention.end] == 'T1566.001'
    assert mention.evidence == text[mention.start - 90 : mention.end + 90]


def test_search_matches_id_prefixes_and_names() -> None:
    assert [t.id for t in attack.search('T1566')][:2] == ['T1566', 'T1566.001']
    assert 'T1059.001' in [t.id for t in attack.search('powershell')]
    assert 'T1059.001' in [t.id for t in attack.search('Command and Scripting Interpreter: Power')]
    assert len(attack.search('', limit=7)) == 7


# --------------------------------------------------------------------------- scripts/update_attack.py


def stix(object_type: str, attack_id: str | None = None, **fields: Any) -> dict[str, Any]:
    refs = [{'source_name': 'mitre-attack', 'external_id': attack_id}] if attack_id else []
    return {
        'type': object_type,
        'id': f'{object_type}--{attack_id or "x"}',
        'external_references': refs,
        **fields,
    }


def bundle() -> dict[str, Any]:
    phases = [{'kill_chain_name': 'mitre-attack', 'phase_name': 'execution'}]
    objects = [
        stix(
            'x-mitre-collection',
            name='Enterprise ATT&CK',
            x_mitre_version='99.1',
            modified='2030-01-02T00:00Z',
        ),
        stix(
            'x-mitre-matrix',
            name='Enterprise',
            tactic_refs=['x-mitre-tactic--TA0002', 'x-mitre-tactic--TA0001', 'x-mitre-tactic--TA9999'],
        ),
        stix('x-mitre-tactic', 'TA0001', name='Initial Access', x_mitre_shortname='initial-access'),
        stix('x-mitre-tactic', 'TA0002', name='Execution', x_mitre_shortname='execution'),
        stix('attack-pattern', 'T1059', name='Interpreter', kill_chain_phases=phases),
        stix('attack-pattern', 'T1059.001', name='PowerShell', kill_chain_phases=phases),
        stix('attack-pattern', 'T1002', name='Gone', kill_chain_phases=phases, revoked=True),
        stix('attack-pattern', 'T1003', name='Old', kill_chain_phases=phases, x_mitre_deprecated=True),
        stix('relationship'),
    ]
    return {'type': 'bundle', 'id': 'bundle--x', 'objects': objects}


def test_the_updater_keeps_current_techniques_and_matrix_order() -> None:
    compact = update_attack.compact(bundle())
    assert compact['version'] == '99.1'
    assert compact['notice'].startswith('© 2030 The MITRE Corporation.')
    assert [t['id'] for t in compact['tactics']] == ['TA0002', 'TA0001']  # matrix order; unknown refs skipped
    assert [t['id'] for t in compact['techniques']] == ['T1059', 'T1059.001']
    assert compact['techniques'][1] == {'id': 'T1059.001', 'name': 'PowerShell', 'tactics': ['execution']}


def test_the_updater_writes_stable_json(tmp_path: Path) -> None:
    source = tmp_path / 'enterprise-attack.json'
    source.write_text(json.dumps(bundle()), encoding='utf-8')
    output = tmp_path / 'catalog.json'
    assert update_attack.main([str(source), '--output', str(output)]) == 0
    written = output.read_text(encoding='utf-8')
    assert json.loads(written) == update_attack.compact(bundle())
    assert '\n    {"id": "T1059.001", "name": "PowerShell", "tactics": ["execution"]}\n' in written


@pytest.mark.parametrize('content', ['{"type": "bundle"}', '{"type": "bundle", "objects": []}', 'not json'])
def test_the_updater_refuses_anything_but_an_attack_bundle(tmp_path: Path, content: str) -> None:
    source = tmp_path / 'bad.json'
    source.write_text(content, encoding='utf-8')
    assert update_attack.main([str(source), '--output', str(tmp_path / 'out.json')]) == 1
    assert not (tmp_path / 'out.json').exists()


def test_the_committed_catalog_is_in_the_updaters_format() -> None:
    committed = (ROOT / 'src' / 'insight' / 'data' / 'attack-enterprise.json').read_text(encoding='utf-8')
    assert update_attack.render(json.loads(committed)) == committed


@pytest.mark.parametrize(('domain', 'identifier', 'count'), [('mobile', 'T1398', 125), ('ics', 'T0800', 104)])
def test_mobile_and_ics_catalogs_are_complete_pinned_and_domain_specific(
    domain: attack.Domain,
    identifier: str,
    count: int,
) -> None:
    """Regression: explicit Mobile and ICS IDs were previously treated as unknown techniques."""
    known = attack.catalog(domain)
    assert known.version == attack.catalog().version == '20.1'
    assert len(known.techniques) == count
    found = attack.technique(identifier)
    assert found is not None
    assert found.domain == domain
    assert found.kill_chain == f'mitre-{domain}-attack'
    assert known.tactic_names(found)
    assert [t.id for t in attack.search(identifier, domain=domain)] == [identifier]
    assert attack.search(identifier) == []
    assert [m.technique_id for m in attack.find_techniques(f'Mapped {identifier}.')] == [identifier]
    raw = json.loads(
        (ROOT / 'src' / 'insight' / 'data' / f'attack-{domain}.json').read_text(encoding='utf-8')
    )
    assert re.fullmatch(r'[0-9a-f]{64}', raw['source_sha256'])
    assert '/v20.1/' in raw['source']
    assert all(t.tactics for t in known.techniques.values())
    assert len(attack.all_techniques()) == sum(len(attack.catalog(d).techniques) for d in attack.DOMAINS)


def test_updater_rejects_wrong_domain_and_hash(tmp_path: Path) -> None:
    """Regression: a bundle from another domain must not silently become an empty or wrongly named catalog."""
    with pytest.raises(ValueError, match='does not match'):
        update_attack.compact(bundle(), domain='ics')
    source, output = tmp_path / 'bundle.json', tmp_path / 'catalog.json'
    source.write_text(json.dumps(bundle()), encoding='utf-8')
    assert update_attack.main([str(source), '--output', str(output), '--sha256', '0' * 64]) == 1
    assert not output.exists()
