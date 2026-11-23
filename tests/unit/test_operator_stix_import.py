"""A TAXII publisher's STIX IDs, labels and sharing restrictions belong to its configured source."""

from __future__ import annotations

import json
from typing import Any
from uuid import NAMESPACE_URL, uuid5

import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from insight import services
from insight.models import AuditEvent, Document
from insight.schemas import TLP, DocumentInput, OperatorSourceInput
from insight.services.stix_imports import import_operator_stix
from insight.stix_import import MAX_REPORTS

from .test_stix_import import CLEAR, RED, bundle, indicator, obj, report, submit


def source(db: Session, name: str) -> str:
    return services.create_operator_source(
        db,
        OperatorSourceInput(
            name=name,
            kind='taxii',
            url=f'https://{name}.example/taxii/',
            collection_id='reviewed',
            tlp='CLEAR',
            reuse='public',
        ),
    ).key


def pull(
    db: Session, key: str, *objects: dict[str, Any], floor: TLP = 'CLEAR', maximum: str = 'RED'
) -> dict[str, Any]:
    return import_operator_stix(
        db, json.dumps(bundle(*objects)).encode(), source_key=key, source_tlp=floor, max_tlp=maximum
    )


def test_same_native_ids_have_independent_histories_and_keep_manual_identity(db: Session) -> None:
    first, second = source(db, 'first'), source(db, 'second')
    ip = indicator()
    record = report(ip['id'], object_marking_refs=[CLEAR])
    manual = submit(db, bundle(record, ip))['document_ids'][0]
    a = pull(db, first, record, ip, floor='GREEN')['document_ids'][0]
    b = pull(db, second, ip, record, floor='GREEN')['document_ids'][0]
    assert len({a, b, manual}) == 3
    assert manual == record['id'].split('--')[1]
    assert pull(db, first, ip, record, floor='GREEN')['document_ids'] == [a]
    assert pull(db, second, ip, record, floor='GREEN')['created'] == 0
    assert db.get_one(Document, a).tlp == 'GREEN'
    record['name'] = 'First source revision'
    revised = db.get_one(Document, pull(db, first, ip, record, floor='GREEN')['document_ids'][0])
    assert revised.supersedes_id == a
    assert db.get_one(Document, b).is_current
    assert db.get_one(Document, manual).is_current


def test_collection_cannot_claim_an_existing_local_id(db: Session) -> None:
    key = source(db, 'collision')
    ip = indicator()
    record = report(ip['id'], object_marking_refs=[CLEAR])
    initial = str(uuid5(NAMESPACE_URL, f'insight:operator-stix:{key}:{record["id"]}'))
    manual, _ = services.ingest(
        db,
        DocumentInput(title='Analyst report', body='Independent text', source_name='Local'),
        initial_document_id=initial,
    )
    with pytest.raises(ValueError, match='handling restriction'):
        pull(db, key, indicator('192.0.2.55'), ip, record)
    assert db.scalars(select(Document)).one() is manual


def test_publisher_can_withdraw_text_on_public_source_and_cannot_restore_it(db: Session) -> None:
    key = source(db, 'withdrawal')
    ip = indicator()
    sentinel = 'Synthetic publisher prose only'
    record = report(ip['id'], description=sentinel, object_marking_refs=[CLEAR])
    original = db.get_one(Document, pull(db, key, ip, record)['document_ids'][0])
    assert sentinel in json.dumps(services.export_document(db, original.id, max_tlp='CLEAR'))
    record['x_insight_metadata_only'] = True
    restricted = db.get_one(Document, pull(db, key, ip, record)['document_ids'][0])
    assert restricted.id != original.id
    assert original.operator_publisher_metadata_only
    assert original.reuse_changed_at
    assert restricted.operator_publisher_metadata_only
    assert sentinel in original.body
    assert sentinel not in restricted.body
    for doc in (original, restricted):
        assert sentinel not in json.dumps(services.export_document(db, doc.id, max_tlp='CLEAR'))
    assert pull(db, key, ip, record)['created'] == 0
    record.pop('x_insight_metadata_only')
    clean = report(ip['id'], object_marking_refs=[CLEAR])
    record['name'] = 'Corrected title from publisher'
    outcome = pull(db, key, record, clean, ip)
    assert outcome['created'] == 2
    revised = db.get_one(Document, outcome['document_ids'][0])
    assert revised.operator_publisher_metadata_only
    assert revised.supersedes_id == restricted.id
    assert revised.title == record['name']
    assert sentinel not in revised.body
    observation = services.detail(db, revised)['observations'][0]
    assert revised.body[observation['start_offset'] : observation['end_offset']] == '192.0.2.7'
    assert sentinel not in observation['evidence']
    assert pull(db, key, clean, record, ip)['created'] == 0

    # If the operator later repoints this source at RSS with the same entry ID, its publisher
    # restriction still applies to subsequent revisions that cannot express the STIX field.
    rss_doc, _ = services.ingest(
        db,
        DocumentInput(title='Reconfigured source', body=sentinel, source_name='Synthetic', tlp='CLEAR'),
        ref=services.SourceRef(key, record['id']),
    )
    assert rss_doc.operator_publisher_metadata_only
    assert sentinel not in json.dumps(services.export_document(db, rss_doc.id, max_tlp='CLEAR'))


def test_identical_rendering_still_revises_when_publisher_restricts(db: Session) -> None:
    key = source(db, 'rights')
    ip = indicator()
    record = report(ip['id'], object_marking_refs=[CLEAR])
    public = pull(db, key, ip, record)['document_ids'][0]
    record['x_insight_metadata_only'] = True
    result = pull(db, key, ip, record)
    assert result['created'] == 1
    assert result['document_ids'] != [public]
    assert db.get_one(Document, public).operator_publisher_metadata_only


def test_creator_references_and_ceiling_are_checked_before_any_writes(db: Session) -> None:
    key = source(db, 'labels')
    identity = obj(
        'identity', name='Synthetic publisher', identity_class='organization', object_marking_refs=[RED]
    )
    ip = indicator()
    ip['created_by_ref'] = identity['id']
    record = report(ip['id'], object_marking_refs=[CLEAR])
    clean = indicator('192.0.2.22')
    with pytest.raises(ValueError, match='permitted TLP'):
        pull(db, key, clean, ip, record, identity, maximum='AMBER')
    assert db.scalar(select(func.count()).select_from(Document)) == 0
    with pytest.raises(ValueError, match='RED'):
        pull(db, key, clean, floor='RED', maximum='AMBER')
    current = db.get_one(Document, pull(db, key, record, ip, identity)['document_ids'][0])
    assert current.tlp == 'RED'
    identity['object_marking_refs'] = [CLEAR]
    record['name'] = 'Correction with a less restrictive marking'
    with pytest.raises(ValueError, match='RED'):
        pull(db, key, clean, record, ip, identity, maximum='AMBER')
    assert current.is_current
    assert db.scalar(select(func.count()).select_from(Document)) == 1
    outcome = pull(db, key, record, ip, identity, clean)
    assert outcome['created'] == 2
    corrected = db.get_one(Document, outcome['document_ids'][0])
    assert corrected.tlp == 'RED'
    assert corrected.supersedes_id == current.id
    assert db.get_one(Document, outcome['document_ids'][1]).tlp == 'CLEAR'
    # Earlier normalized observations cannot substitute for the marked, validated original objects.
    with pytest.raises(ValueError, match='resolve'):
        pull(db, key, record, clean)
    with pytest.raises(ValueError, match='creator'):
        pull(db, key, record, ip, clean)
    assert corrected.is_current
    assert db.scalar(select(func.count()).select_from(Document)) == 3


def test_source_floor_can_drop_while_the_revised_item_keeps_its_original_label(db: Session) -> None:
    key = source(db, 'floor')
    ip, later = indicator(), indicator('192.0.2.18')
    record = report(ip['id'], object_marking_refs=[CLEAR])
    first = pull(db, key, record, ip, floor='AMBER')['document_ids'][0]
    record['name'] = 'Correction after source floor change'
    outcome = pull(db, key, record, ip, later, floor='GREEN')
    assert outcome['created'] == 2
    revised = db.get_one(Document, outcome['document_ids'][0])
    assert revised.supersedes_id == first
    assert revised.tlp == 'AMBER'
    label_receipt = db.scalar(
        select(AuditEvent.detail).where(
            AuditEvent.object_id == revised.id, AuditEvent.action == 'document.tlp_raised'
        )
    )
    assert label_receipt
    assert 'previous source revision' in label_receipt
    assert db.get_one(Document, outcome['document_ids'][1]).tlp == 'GREEN'


def test_standalone_collection_items_keep_identity_across_overlapping_polls(db: Session) -> None:
    key = source(db, 'standalone')
    a, b, c = (indicator(f'192.0.2.{n}') for n in (1, 2, 3))
    first = pull(db, key, a, b)
    second = pull(db, key, c, b)
    assert first['reports'] == 2
    assert first['created'] == 2
    assert second['reports'] == 2
    assert second['created'] == 1
    assert len(set(first['document_ids']) & set(second['document_ids'])) == 1
    b['pattern'] = "[ipv4-addr:value = '198.51.100.22']"
    revised = db.get_one(Document, pull(db, key, b)['document_ids'][0])
    assert revised.external_id == b['id']
    assert revised.supersedes_id in first['document_ids']
    assert db.scalar(select(func.count()).select_from(Document)) == 4


def test_standalone_storage_respects_document_cap(db: Session) -> None:
    key = source(db, 'capacity')
    with pytest.raises(ValueError, match='Too many STIX reports or standalone'):
        pull(db, key, *(indicator() for _ in range(MAX_REPORTS + 1)))
    assert db.scalar(select(func.count()).select_from(Document)) == 0
