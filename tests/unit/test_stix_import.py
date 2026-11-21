"""Offline ingest of synthetic, explicitly typed STIX data, including policy and source identity."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from insight import services
from insight.models import AuditEvent, Document, Entity, Observation, database
from insight.schemas import DocumentInput, IocExportQuery
from insight.source_registry import metadata_only

STAMP = '2024-06-01T00:00:00.000Z'
CLEAR = 'marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487'
RED = 'marking-definition--e828b379-4e03-4974-9ac4-e53a884c97c1'


def obj(kind: str, **fields: Any) -> dict[str, Any]:
    return {
        'id': f'{kind}--{uuid4()}',
        'type': kind,
        'spec_version': '2.1',
        'created': STAMP,
        'modified': STAMP,
        **fields,
    }


def bundle(*objects: dict[str, Any]) -> dict[str, Any]:
    return {'id': f'bundle--{uuid4()}', 'type': 'bundle', 'objects': list(objects)}


def indicator(value: str = '192.0.2.7') -> dict[str, Any]:
    return obj(
        'indicator',
        pattern=f"[ipv4-addr:value = '{value}']",
        pattern_type='stix',
        valid_from=STAMP,
        object_marking_refs=[CLEAR],
    )


def report(*refs: str, **fields: Any) -> dict[str, Any]:
    return obj(
        'report',
        name='Fixture report',
        published=STAMP,
        report_types=['threat-report'],
        object_refs=list(refs),
        **fields,
    )


def submit(db: Session, item: dict[str, Any], *, ceiling: str = 'RED') -> dict[str, Any]:
    return services.import_stix(db, json.dumps(item).encode(), max_tlp=ceiling)


def test_external_bundle_preserves_markings_ids_offsets_and_audits(db: Session) -> None:
    ioc = indicator('192.0.2.0/24')
    record = report(
        ioc['id'],
        description='Quoted 198.51.100.10\r\ncontinued',
        object_marking_refs=[CLEAR],
        external_references=[{'source_name': 'Example publisher', 'url': 'https://example.org/source'}],
    )
    data = bundle(record, ioc)
    result = submit(db, data)
    doc_id = record['id'].split('--')[1]
    digest = hashlib.sha256(json.dumps(data).encode()).hexdigest()
    assert result == {
        'bundle_id': data['id'],
        'bundle_sha256': digest,
        'reports': 1,
        'created': 1,
        'document_ids': [doc_id],
    }
    doc = db.get_one(Document, doc_id)
    assert (doc.tlp, doc.source_name, doc.source_url, doc.external_id) == (
        'CLEAR',
        'Example publisher',
        'https://example.org/source',
        record['id'],
    )
    mention = db.scalars(select(Observation)).one()
    entity = db.get_one(Entity, mention.entity_id)
    assert (entity.kind, entity.value) == ('cidr', '192.0.2.0/24')
    assert doc.body[mention.start_offset : mention.end_offset] == entity.value
    assert submit(db, data)['created'] == 0
    assert db.scalar(select(func.count()).select_from(Document)) == 1
    assert any(digest in a.detail and a.object_id == doc_id for a in db.scalars(select(AuditEvent)))


def test_standalone_objects_are_grouped_and_unmarked_is_amber(db: Session) -> None:
    first = indicator()
    first.pop('object_marking_refs')
    cve = obj(
        'vulnerability',
        name='Example vulnerability',
        external_references=[{'source_name': 'cve', 'external_id': 'CVE-2024-12345'}],
    )
    result = submit(db, bundle(first, cve))
    assert result['reports'] == result['created'] == 1
    document = db.get_one(Document, result['document_ids'][0])
    assert document.tlp == 'AMBER'
    assert set(db.execute(select(Entity.kind, Entity.value))) == {
        ('ip', '192.0.2.7'),
        ('cve', 'CVE-2024-12345'),
    }


@pytest.mark.parametrize(
    'mutation',
    [
        'missing-reference',
        'bad-pattern',
        'unknown-marking',
        'oversized',
        'granular',
        'unlinked-technique',
        'revoked',
        'too-restrictive',
        'false-marking',
        'bad-publisher',
        'time-limited',
        'duplicate-id',
        'non-string-type',
        'null-byte',
        'unknown-pattern-type',
    ],
)
def test_invalid_late_object_rejects_whole_bundle(db: Session, mutation: str) -> None:
    first = indicator()
    good = report(first['id'])
    bad = indicator('192.0.2.9')
    items = [good, first, bad]
    if mutation == 'missing-reference':
        items.append(report(f'indicator--{uuid4()}'))
    elif mutation == 'bad-pattern':
        bad['pattern'] = "[ipv4-addr:value = '192.0.2.9' OR ipv4-addr:value = '192.0.2.10']"
    elif mutation == 'unknown-pattern-type':
        bad['pattern_type'] = 'sigma'
    elif mutation == 'null-byte':
        good['description'] = 'foo\x00bar'
    elif mutation == 'unknown-marking':
        bad['object_marking_refs'] = [f'marking-definition--{uuid4()}']
    elif mutation == 'oversized':
        good['name'] = 'x' * 301
    elif mutation == 'granular':
        bad['granular_markings'] = [{'marking_ref': RED, 'selectors': ['pattern']}]
    elif mutation == 'unlinked-technique':
        items.append(
            obj(
                'attack-pattern',
                name='Phishing',
                external_references=[{'source_name': 'mitre-attack', 'external_id': 'T1566'}],
            )
        )
    elif mutation == 'revoked':
        bad['revoked'] = True
    elif mutation == 'too-restrictive':
        bad['object_marking_refs'] = [RED]
    elif mutation == 'false-marking':
        items.append(
            obj(
                'marking-definition',
                id=CLEAR,
                name='TLP:RED',
                definition_type='statement',
                definition={'statement': 'Restricted'},
            )
        )
    elif mutation == 'bad-publisher':
        bad['created_by_ref'] = f'identity--{uuid4()}'
    elif mutation == 'time-limited':
        bad['valid_until'] = '2024-07-01T00:00:00.000Z'
    elif mutation == 'duplicate-id':
        bad['id'] = first['id']
    elif mutation == 'non-string-type':
        bad['type'] = []
    with pytest.raises(ValueError, match=r'.+'):
        submit(db, bundle(*items), ceiling='AMBER')
    for table in [Document, Entity, Observation, AuditEvent]:
        assert db.scalar(select(func.count()).select_from(table)) == 0


def test_revisions_keep_handling_restrictions_and_analyst_decisions(db: Session) -> None:
    ip = indicator()
    attack = obj(
        'attack-pattern',
        name='Phishing',
        object_marking_refs=[CLEAR],
        external_references=[{'source_name': 'mitre-attack', 'external_id': 'T1566'}],
    )
    record = report(
        ip['id'],
        attack['id'],
        description='Quoted T1490',
        x_insight_metadata_only=True,
        object_marking_refs=[CLEAR],
    )
    data = bundle(ip, attack, record)
    doc_id = submit(db, data)['document_ids'][0]
    first = db.get_one(Document, doc_id)
    assert metadata_only(first.source_key)
    assert 'Quoted' not in first.body
    assert [t.technique_id for t in services.document_techniques(db, doc_id)] == ['T1566']
    record['name'] = 'Revised fixture'
    ip['object_marking_refs'] = [RED]
    new_id = submit(db, data)['document_ids'][0]
    current = db.get_one(Document, new_id)
    assert new_id != doc_id
    assert (current.tlp, current.supersedes_id, first.is_current) == ('RED', doc_id, False)
    record['x_insight_metadata_only'] = False
    with pytest.raises(ValueError, match='handling restriction'):
        submit(db, data)
    record['x_insight_metadata_only'] = True
    ip['object_marking_refs'] = [CLEAR]
    with pytest.raises(ValueError, match='handling restriction'):
        submit(db, data)
    assert current.is_current


def test_quoted_technique_and_indicators_only_exist_when_linked(db: Session) -> None:
    ip = indicator()
    record = report(ip['id'], description='Example mentions T1490 and 198.51.100.9')
    did = submit(db, bundle(ip, record))['document_ids'][0]
    services.backfill_techniques(db)
    assert services.document_techniques(db, did) == []
    assert list(db.scalars(select(Entity.value))) == ['192.0.2.7']


def test_native_id_collision_blocks_otherwise_valid_reports(db: Session) -> None:
    native, _ = services.ingest(
        db, DocumentInput(title='Private', body='Internal note', source_name='Local', tlp='RED')
    )
    ip = indicator()
    collision = report(ip['id'], id='report--' + native.id)
    with pytest.raises(ValueError, match='conflicts'):
        submit(db, bundle(ip, report(ip['id']), collision), ceiling='AMBER')
    assert db.scalars(select(Document)).all() == [native]


def test_real_export_roundtrip_preserves_report_ids_values_and_links(
    db: Session,
    database_url: str,
) -> None:
    # The exporter/importer run on separate databases, like two analysts sharing reviewed intelligence.
    second_engine, target = database(database_url)
    try:
        a, _ = services.ingest(
            db,
            DocumentInput(
                title='Range',
                body="T1566 2001:db8::/48 and O'Brien@example.org",
                source_name='Analyst',
                tlp='GREEN',
            ),
        )
        b, _ = services.ingest(
            db,
            DocumentInput(
                title='File', body='CVE-2024-12345 and ' + 'b' * 64, source_name='Publisher', tlp='AMBER'
            ),
            ref=services.SourceRef('alienvault-otx', 'fixture'),
        )
        result = services.export_stix(db, IocExportQuery())
        with target.begin() as dest:
            imported = submit(dest, result)
            assert set(imported['document_ids']) == {a.id, b.id}
            assert imported['created'] == 2
            for original in [a, b]:
                record = dest.get_one(Document, original.id)
                assert record.tlp == original.tlp
                assert record.title == original.title
                assert metadata_only(record.source_key) == metadata_only(original.source_key)
                stmt = (
                    select(Entity.kind, Entity.value)
                    .join(Observation)
                    .where(Observation.document_id == original.id)
                )
                assert set(dest.execute(stmt)) == set(db.execute(stmt))
                assert [t.technique_id for t in services.document_techniques(dest, record.id)] == [
                    t.technique_id for t in services.document_techniques(db, original.id)
                ]
            assert submit(dest, result)['created'] == 0
    finally:
        second_engine.dispose()


def test_cli_uses_instance_ceiling_and_reports_hash(
    monkeypatch: pytest.MonkeyPatch,
    database_url: str,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from insight.cli import main

    monkeypatch.setenv('INSIGHT_DATABASE_URL', database_url)
    monkeypatch.setenv('INSIGHT_MAX_TLP', 'CLEAR')
    path = tmp_path / 'fixture.json'
    ip = indicator()
    data = bundle(ip)
    path.write_text(json.dumps(data), encoding='utf-8')
    assert main(['import-stix', str(path)]) == 0
    assert hashlib.sha256(path.read_bytes()).hexdigest() in capsys.readouterr().out
    ip['object_marking_refs'] = [RED]
    path.write_text(json.dumps(data), encoding='utf-8')
    assert main(['import-stix', str(path)]) == 1
    assert 'TLP' in capsys.readouterr().err
    assert main(['import-stix']) == 2


def test_empty_export_roundtrips_to_zero_documents(db: Session) -> None:
    data = services.export_stix(db, IocExportQuery())
    result = submit(db, data)
    assert result['reports'] == result['created'] == 0
    assert result['document_ids'] == []
    assert db.scalar(select(func.count()).select_from(Document)) == 0


def test_retention_removes_observations_and_refuses_to_export_deleted_material(db: Session) -> None:
    ip = indicator()
    record = report(ip['id'], description='Publisher excerpt')
    did = submit(db, bundle(ip, record))['document_ids'][0]
    services.delete_document(db, did, reason='Fixture retention rule')
    assert db.get(Document, did) is None
    assert db.scalar(select(func.count()).select_from(Observation)) == 0
    assert db.scalar(select(func.count()).select_from(Entity)) == 0
    assert 'objects' not in services.export_stix(db, IocExportQuery())


@pytest.mark.parametrize(
    'raw',
    [
        b'{}',
        b'{"type":"bundle","type":"bundle"}',
        b'\xff',
        b'[' * 28 + b'0' + b']' * 28,
        b'[' + b'null,' * 10_000 + b'null]',
        b' ' * 2_000_001,
        b'{"label":"\\ud800"}',
    ],
)
def test_bounded_invalid_json_refused(db: Session, raw: bytes) -> None:
    with pytest.raises(ValueError, match=r'.+'):
        services.import_stix(db, raw, max_tlp='GREEN')
    assert db.scalar(select(func.count()).select_from(Document)) == 0


def test_bundle_envelope_cannot_silently_discard_handling_restrictions(db: Session) -> None:
    data = bundle(indicator())
    data['object_marking_refs'] = [RED]
    with pytest.raises(ValueError, match='envelope markings'):
        submit(db, data, ceiling='CLEAR')
    assert db.scalar(select(func.count()).select_from(Document)) == 0
