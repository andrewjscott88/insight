"""Report-scoped MITRE ATT&CK tags in STIX exports, including revision and sharing boundaries."""

from __future__ import annotations

import json
from typing import Any

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from insight import services
from insight.attack import catalog
from insight.models import AuditEvent, Document, DocumentTechnique
from insight.schemas import DocumentInput, IocExportQuery
from insight.services import SourceRef, stix_techniques


def report(
    db: Session, title: str, body: str, *, tlp: str = 'GREEN', ref: SourceRef | None = None
) -> Document:
    item = DocumentInput.model_validate({'title': title, 'body': body, 'source_name': 'Lab', 'tlp': tlp})
    return services.ingest(db, item, ref=ref)[0]


def tagged_reports(bundle: dict[str, Any]) -> dict[str, dict[str, dict[str, Any]]]:
    """Find each Report's attack patterns through its object_refs and reject dangling or unused patterns."""
    objects = {obj['id']: obj for obj in bundle.get('objects', [])}
    linked = set()
    reports = {}
    for item in objects.values():
        if item['type'] != 'report':
            continue
        tags = {}
        for ref in item['object_refs']:
            target = objects[ref]
            if target['type'] == 'attack-pattern':
                code = next(r['external_id'] for r in target['external_references'] if r.get('external_id'))
                assert code not in tags
                assert target['object_marking_refs'] == item['object_marking_refs']
                tags[code] = target
                linked.add(ref)
        reports[item['id'].removeprefix('report--')] = tags
    assert linked == {ref for ref, obj in objects.items() if obj['type'] == 'attack-pattern'}
    return reports


def test_pattern_is_shared_only_by_reports_with_the_same_markings(db: Session) -> None:
    first = report(db, 'First', '192.0.2.1 and T1059.001.')
    second = report(db, 'Second', '192.0.2.2 follows.')
    restricted = report(db, 'Third', '192.0.2.3, T1059.001, T1490.', tlp='AMBER')
    services.tag_technique(db, second.id, 'T1059.001')
    selected = tagged_reports(services.export_stix(db, IocExportQuery()))
    power = selected[first.id]['T1059.001']
    assert selected[second.id]['T1059.001']['id'] == power['id']
    assert selected[restricted.id]['T1059.001']['id'] != power['id']
    assert power['name'] == 'Command and Scripting Interpreter: PowerShell'
    assert {'kill_chain_name': 'mitre-attack', 'phase_name': 'execution'} in power['kill_chain_phases']
    refs = power['external_references']
    assert {
        'source_name': 'mitre-attack',
        'external_id': 'T1059.001',
        'url': 'https://attack.mitre.org/techniques/T1059/001/',
    } in refs
    assert any(r.get('url') == catalog().terms and r.get('description') == catalog().notice for r in refs)
    limited = tagged_reports(services.export_stix(db, IocExportQuery(max_tlp='GREEN')))
    assert set(limited) == {first.id, second.id}
    assert all(set(tags) == {'T1059.001'} for tags in limited.values())


def test_filters_removals_and_missing_catalog_entries_apply_before_linking(db: Session) -> None:
    selected = report(db, 'Selected group', '192.0.2.8. T1486 and T1566.001 are listed. PowerShell appeared.')
    excluded = report(db, 'Different group', '192.0.2.3. T1490 was listed.')
    report(db, 'Selected group awaiting review', '192.0.2.4 and T1566.001.')
    report(db, 'Selected group with no matching indicator', 'T1566.001 with only hash ' + 'a' * 64)
    report(db, 'Selected group with no indicator at all', 'T1490.')
    services.tag_technique(db, selected.id, 'T1105')
    services.untag_technique(db, selected.id, 'T1566.001')
    db.add(
        DocumentTechnique(document_id=selected.id, technique_id='T9999', source='analyst', status='tagged')
    )
    for doc in (selected, excluded):
        for obs in services.detail(db, doc)['observations']:
            services.set_observation_status(db, obs['id'], 'accepted')
    query = IocExportQuery(q='Selected group', kinds=('ip',), review_statuses=('accepted',))
    reports = tagged_reports(services.export_stix(db, query))
    assert set(reports) == {selected.id}
    assert set(reports[selected.id]) == {'T1486', 'T1105'}


@pytest.mark.parametrize('evidence', [True, False])
def test_technique_links_preserve_source_rights_and_never_export_tag_metadata(
    db: Session, evidence: bool
) -> None:
    source = report(
        db, 'Restricted publisher', '192.0.2.135 publisher-only-words T1486.', ref=SourceRef('talos', 'key')
    )
    services.set_actor(db, 'private-operator-identity')
    services.tag_technique(db, source.id, 'T1105')
    bundle = services.export_stix(db, IocExportQuery(include_evidence=evidence))
    assert set(tagged_reports(bundle)[source.id]) == {'T1486', 'T1105'}
    data = json.dumps(bundle)
    assert 'publisher-only-words' not in data
    assert 'private-operator-identity' not in data


def test_only_selected_revisions_contribute_tags(db: Session) -> None:
    ref = SourceRef('talos', 'revision-test')
    old = report(db, 'First revision', '192.0.2.20 and T1486.', ref=ref)
    current = report(db, 'Second revision', '192.0.2.21 and T1490.', ref=ref)
    latest = tagged_reports(services.export_stix(db, IocExportQuery()))
    assert set(latest) == {current.id}
    assert set(latest[current.id]) == {'T1490'}
    historical = tagged_reports(services.export_stix(db, IocExportQuery(document_ids=(old.id,))))
    assert set(historical) == {old.id}
    assert set(historical[old.id]) == {'T1486'}
    assert tagged_reports(services.export_stix(db, IocExportQuery(q='No matching report'))) == {}


def test_technique_tag_limit_refuses_the_export_before_audit(
    db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    report(db, 'Tagged report', '192.0.2.40. T1486 and T1490.')
    monkeypatch.setattr(stix_techniques, 'MAX_EXPORT_TECHNIQUE_TAGS', 1)
    with pytest.raises(ValueError, match='technique tags match'):
        services.export_stix(db, IocExportQuery())
    assert db.scalar(select(AuditEvent).where(AuditEvent.action == 'stix.export')) is None
