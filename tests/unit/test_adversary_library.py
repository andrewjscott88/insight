"""TIP 4.7 part 1: catalog coverage, alias evidence and legacy format compatibility (ADR 0038)."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import jsonschema
import pytest
from tests.unit.test_threat_library import BUNDLED, mini_bundle, mini_cluster

from insight.threat_library import parse
from insight.threat_library_build import BUNDLED_SOFTWARE_DESCRIPTION, MISP_LICENCE, build
from insight.threat_library_sync import render

SCHEMA = Path(__file__).resolve().parents[2] / 'docs' / 'schemas' / 'insight-threat-library-2.schema.json'


def software_bundle() -> dict[str, Any]:
    bundle = mini_bundle()
    objects = bundle['objects']
    for number, kind in enumerate(('malware', 'tool', 'malware', 'tool'), 1):
        objects.append({
            'id': f'{kind}--s{number}', 'type': kind, 'name': f'Software {number}',
            'external_references': [{'source_name': 'mitre-attack', 'external_id': f'S900{number}'}],
            'description': '[Software](https://example.org) is used to collect files. ' * 12,
            'x_mitre_aliases': [f'Software {number}', f'Alias {number}'],
            'x_mitre_platforms': ['Windows', 'Linux', 'Windows'],
            'revoked': number == 3, 'x_mitre_deprecated': number == 4,
        })  # fmt: skip
    for number, source, target in [
        (10, 'intrusion-set--1', 'malware--s1'),
        (11, 'malware--s1', 'attack-pattern--1'),
        (12, 'intrusion-set--1', 'malware--s3'),  # revoked target
        (13, 'intrusion-set--1', 'tool--s4'),  # deprecated target
        (14, 'tool--s2', 'missing'),
        (15, 'tool--s2', 'malware--s1'),  # not a technique
        (16, 'intrusion-set--2', 'tool--s2'),  # revoked relationship
        (17, 'tool--s2', 'attack-pattern--1'),  # deprecated relationship
    ]:
        objects.append({
            'id': f'relationship--{number}', 'type': 'relationship', 'relationship_type': 'uses',
            'source_ref': source, 'target_ref': target, 'revoked': number == 16,
            'x_mitre_deprecated': number == 17,
        })  # fmt: skip
    return bundle


def alias_cluster() -> dict[str, Any]:
    cluster = mini_cluster()
    cluster['values'][0]['uuid'] = 'fixture-panda-entry'
    cluster['values'][0]['meta']['synonyms'] = ['New Panda', 'TP-1', ' new panda ', '', None, 3]
    return cluster


@pytest.mark.parametrize('full', [False, True])
def test_every_current_software_item_has_context_even_without_a_group(full: bool) -> None:
    raw = build(software_bundle(), None, full=full)
    lib = parse(raw, 'fixture')
    assert set(lib.software) == {'S9001', 'S9002'}
    malware, tool = lib.software['S9001'], lib.software['S9002']
    assert malware.id == 'S9001'
    assert malware.type == 'malware'
    assert malware.names == ('Software 1', 'Alias 1')
    assert malware.platforms == ('Linux', 'Windows')
    assert malware.techniques == ('T1059.001',)
    assert malware.groups == ('G9001',)
    assert tool.type == 'tool'
    assert tool.groups == ()
    assert tool.techniques == ()
    assert lib.groups['G9001'].software == ('S9001',)
    assert malware.url == 'https://attack.mitre.org/software/S9001/'
    assert '[' not in malware.description
    assert (
        len(malware.description) > BUNDLED_SOFTWARE_DESCRIPTION
        if full
        else len(malware.description) <= BUNDLED_SOFTWARE_DESCRIPTION + 2
    )
    assert 'MITRE' in lib.notice
    assert lib.sources['misp-galaxy']['licence'] == MISP_LICENCE


def test_software_techniques_are_kept_without_copying_them_onto_a_group() -> None:
    bundle = software_bundle()
    bundle['objects'] = [o for o in bundle['objects'] if o['id'] != 'relationship--1']
    lib = parse(build(bundle, None), 'fixture')
    assert lib.groups['G9001'].techniques == ()
    assert lib.software['S9001'].techniques == ('T1059.001',)
    assert 'T1059.001' in lib.techniques


def test_aliases_carry_each_source_and_exact_match_in_both_editions() -> None:
    for full in (False, True):
        lib = parse(build(mini_bundle(), alias_cluster(), full=full), 'fixture')
        group = lib.groups['G9001']
        assert group.aliases == ('New Panda', 'TP-1')
        assert [g.id for g in lib.search('new panda')] == ['G9001']
        sources = [s for s in group.alias_sources if s.name == 'New Panda']
        assert len(sources) == 1
        source = sources[0]
        assert (source.source, source.entry, source.entry_id, source.matched_name) == (
            'misp-galaxy',
            'TP-1',
            'fixture-panda-entry',
            'TP-1',
        )
        assert source.url == 'https://github.com/MISP/misp-galaxy'
        assert {s.source for s in group.alias_sources if s.name == 'TP-1'} == {'attack', 'misp-galaxy'}


def test_every_unique_entry_match_is_used_but_synonyms_and_similar_links_never_seed_matches() -> None:
    cluster = alias_cluster()
    cluster['values'] += [
        {'value': 'Test Panda', 'meta': {'synonyms': ['Another Panda'], 'similar': ['Other Group']}},
        {'value': 'New Panda', 'meta': {'synonyms': ['Transitive Panda']}},
        {'value': 'Unmatched', 'meta': {'synonyms': ['Test Panda', 'Unrelated Alias']}},
    ]
    lib = parse(build(mini_bundle(), cluster), 'fixture')
    assert lib.groups['G9001'].aliases == ('Another Panda', 'New Panda', 'TP-1')
    assert lib.search('Transitive') == []
    assert lib.search('Unrelated') == []
    assert lib.groups['G9002'].aliases == ('Shared',)


@pytest.mark.parametrize('ambiguous', ['Shared', 'Other Group', 'Cross Alias'])
def test_regression_misp_does_not_introduce_aliases_that_name_multiple_groups(ambiguous: str) -> None:
    """Regression: a synonym shared by imported entries must not silently join ATT&CK groups."""
    cluster = alias_cluster()
    cluster['values'][0]['meta']['synonyms'] += [ambiguous]
    cluster['values'] += [{'value': 'Other Group', 'meta': {'synonyms': ['Cross Alias']}}]
    lib = parse(build(mini_bundle(), cluster), 'fixture')
    assert ambiguous not in lib.groups['G9001'].aliases
    if ambiguous == 'Cross Alias':
        assert ambiguous not in lib.groups['G9002'].aliases


def test_ambiguous_entry_names_and_duplicate_entries_supply_no_aliases() -> None:
    cluster = alias_cluster()
    cluster['values'][1]['meta']['synonyms'] = ['Shared Import']
    cluster['values'] += [{'value': ' tp-1 ', 'meta': {'synonyms': ['Duplicate Import']}}]
    lib = parse(build(mini_bundle(), cluster), 'fixture')
    assert lib.groups['G9001'].aliases == ('TP-1',)
    assert lib.search('Shared Import') == []
    assert lib.search('Duplicate Import') == []


@pytest.mark.parametrize('meta', [None, {'synonyms': 'not a list'}, {'synonyms': {}}])
def test_missing_or_malformed_synonyms_are_not_treated_as_names(meta: Any) -> None:
    cluster = {'values': [{'value': 'TP-1', 'meta': meta}]}
    assert parse(build(mini_bundle(), cluster), 'fixture').groups['G9001'].aliases == ('TP-1',)


def test_format_one_libraries_keep_loading_with_unknown_software_context_empty() -> None:
    legacy = build(software_bundle(), None)
    legacy['format'] = 'insight-threat-library-1'
    for group in legacy['groups']:
        group.pop('alias_sources')
        group.pop('alias_references')
    legacy['software'] = {'S9001': {'name': 'Software 1', 'type': 'malware'}}
    lib = parse(legacy, 'old synced file')
    software = lib.software['S9001']
    assert software.names == ('Software 1',)
    assert (software.description, software.platforms, software.techniques, software.groups) == (
        '',
        (),
        (),
        (),
    )
    assert lib.groups['G9001'].alias_sources[0].source == 'attack'
    assert [g.id for g in lib.search('TP-1')] == ['G9001']


def test_format_two_requires_context_and_rejects_other_software_types() -> None:
    raw = build(software_bundle(), None)
    bad = copy.deepcopy(raw)
    del bad['software']['S9001']['platforms']
    with pytest.raises(KeyError):
        parse(bad, 'broken')
    raw['software']['S9001']['type'] = 'intrusion-set'
    with pytest.raises(ValueError, match='malware or tool'):
        parse(raw, 'broken')


def test_library_build_is_deterministic_and_does_not_mutate_pinned_inputs() -> None:
    bundle, cluster = software_bundle(), alias_cluster()
    before = copy.deepcopy((bundle, cluster))
    first = render(build(bundle, cluster))
    assert (bundle, cluster) == before
    assert render(build(bundle, cluster)) == first
    bundle['objects'].reverse()
    cluster['values'].reverse()
    assert render(build(bundle, cluster)) == first


@pytest.mark.parametrize('full', [False, True])
def test_both_editions_obey_the_format_two_schema(full: bool) -> None:
    schema = json.loads(SCHEMA.read_text(encoding='utf-8'))
    jsonschema.Draft202012Validator.check_schema(schema)
    built = build(software_bundle(), alias_cluster(), full=full)
    jsonschema.validate(built, schema)
    broken = copy.deepcopy(built)
    broken['software']['S9001']['groups'] = ['S9002']
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(broken, schema)
    broken = copy.deepcopy(built)
    group = broken['groups'][0]
    del group['alias_references'][group['alias_sources']['New Panda'][0]]['matched_name']
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(broken, schema)


def test_bundled_catalog_has_the_new_contract_and_alias_sources_cover_every_name() -> None:
    raw = json.loads(BUNDLED.read_text(encoding='utf-8'))
    jsonschema.validate(raw, json.loads(SCHEMA.read_text(encoding='utf-8')))
    assert any(not s['groups'] for s in raw['software'].values())
    assert {s['type'] for s in raw['software'].values()} == {'malware', 'tool'}
    assert all(t in raw['techniques'] for s in raw['software'].values() for t in s['techniques'])
    for group in raw['groups']:
        assert set(group['alias_sources']) == set(group['aliases'])
    assert any(
        source['source'] == 'misp-galaxy' for group in raw['groups'] for source in group['alias_references']
    )


@pytest.mark.parametrize('index', [-1, 999, '0', True])
def test_invalid_alias_source_indices_are_refused(index: Any) -> None:
    raw = build(mini_bundle(), alias_cluster())
    raw['groups'][0]['alias_sources']['New Panda'] = [index]
    with pytest.raises(ValueError, match='Invalid alias source reference'):
        parse(raw, 'broken')
