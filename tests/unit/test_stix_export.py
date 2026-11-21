"""STIX 2.1 projection, OASIS validation, publisher rights and retention."""

from __future__ import annotations

import json
from typing import Any

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from insight import services
from insight.models import AuditEvent
from insight.schemas import DocumentInput, IocExportQuery
from insight.stix_export import TLP_MARKINGS
from insight.stix_validation import validate_stix_bundle


def _objects(bundle: dict[str, Any], kind: str) -> list[dict[str, Any]]:
    return [item for item in bundle['objects'] if item['type'] == kind]


def test_report_associations_markings_and_publisher_rights(db: Session) -> None:
    first, _ = services.ingest(
        db,
        DocumentInput(
            title='Public advisory', body='Public quote: 192.0.2.3.', source_name='Lab', tlp='CLEAR'
        ),
    )
    second, _ = services.ingest(
        db,
        DocumentInput(
            title='Restricted advisory',
            body='Proprietary quotation: 192.0.2.3 and CVE-2025-12345.',
            source_name='SANS ISC',
            source_url='https://example.org/advisory',
            tlp='AMBER+STRICT',
        ),
        ref=services.SourceRef('sans-isc', 'synthetic-1'),
    )
    bundle = services.export_stix(db, IocExportQuery())
    reports = {r['id']: r for r in _objects(bundle, 'report')}
    (ip,) = _objects(bundle, 'indicator')
    (cve,) = _objects(bundle, 'vulnerability')
    assert ip['pattern'] == "[ipv4-addr:value = '192.0.2.3']"
    assert ip['object_marking_refs'] == cve['object_marking_refs'] == [TLP_MARKINGS['AMBER+STRICT']]
    assert cve['external_references'] == [{'source_name': 'cve', 'external_id': 'CVE-2025-12345'}]
    low, high = reports[f'report--{first.id}'], reports[f'report--{second.id}']
    assert low['object_refs'] == [ip['id']]
    assert low['object_marking_refs'] == [TLP_MARKINGS['CLEAR']]
    assert set(high['object_refs']) == {ip['id'], cve['id']}
    assert 'Public quote' in low['description']
    assert 'Proprietary quotation' not in json.dumps(bundle)
    assert high['x_insight_metadata_only']
    assert high['external_references'][0]['url'].endswith('/advisory')
    no_quotes = services.export_stix(db, IocExportQuery(include_evidence=False))
    assert all('description' not in r for r in _objects(no_quotes, 'report'))
    limited = services.export_stix(db, IocExportQuery(max_tlp='CLEAR'))
    assert [r['id'] for r in _objects(limited, 'report')] == [low['id']]
    assert _objects(limited, 'indicator')[0]['object_marking_refs'] == [TLP_MARKINGS['CLEAR']]
    assert _objects(limited, 'indicator')[0]['id'] != ip['id']
    assert not _objects(limited, 'vulnerability')


def test_deletion_and_superseded_filters_apply_to_stix(db: Session) -> None:
    ref = services.SourceRef('cisa-kev', 'example')
    old, _ = services.ingest(
        db, DocumentInput(title='Advisory', body='First 192.0.2.4', source_name='Lab'), ref=ref
    )
    current, _ = services.ingest(
        db, DocumentInput(title='Advisory', body='Latest 192.0.2.5', source_name='Lab'), ref=ref
    )
    assert {r['id'] for r in _objects(services.export_stix(db, IocExportQuery()), 'report')} == {
        f'report--{current.id}'
    }
    assert len(_objects(services.export_stix(db, IocExportQuery(include_superseded=True)), 'report')) == 2
    services.delete_document(db, old.id, 'retention period ended')
    exported = json.dumps(services.export_stix(db, IocExportQuery(include_superseded=True)))
    assert '192.0.2.4' not in exported
    assert '192.0.2.5' in exported


def test_every_indicator_kind_has_a_valid_stix_representation(db: Session) -> None:
    body = (
        '192.0.2.5 2001:db8::1 192[.]0[.]2[.]0/25 2001:db8::/32 example.net '
        "https://example.org/path Owner+ABC@example.com O'Brien@example.net CVE-2025-12345\n"
    ) + ' '.join('a' * n for n in (32, 40, 64, 128))
    services.ingest(db, DocumentInput(title='Example', body=body, source_name='Synthetic'))
    bundle = services.export_stix(db, IocExportQuery())
    paths = {s['pattern'] for s in _objects(bundle, 'indicator')}
    assert paths >= {
        "[ipv4-addr:value = '192.0.2.5']",
        "[ipv6-addr:value = '2001:db8::1']",
        "[ipv4-addr:value = '192.0.2.0/25']",
        "[ipv6-addr:value = '2001:db8::/32']",
        "[domain-name:value = 'example.net']",
        "[url:value = 'https://example.org/path']",
        "[email-addr:value = 'Owner+ABC@example.com']",
        "[email-addr:value = 'O\\'Brien@example.net']",
        *[
            f"[file:hashes.'{kind}' = '{'a' * n}']"
            for kind, n in [('MD5', 32), ('SHA-1', 40), ('SHA-256', 64), ('SHA-512', 128)]
        ],
    }
    assert len(_objects(bundle, 'vulnerability')) == 1


def test_oasis_validator_rejects_a_damaged_export(db: Session) -> None:
    services.ingest(db, DocumentInput(title='Example', body='Source 192.0.2.5.', source_name='Synthetic'))
    bundle = services.export_stix(db, IocExportQuery())
    _objects(bundle, 'indicator')[0]['pattern'] = '[this is not a STIX pattern]'
    with pytest.raises(ValueError, match=r'STIX 2[.]1 validation failed'):
        validate_stix_bundle(bundle)


def test_validation_failure_writes_no_success_audit(db: Session, monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(bundle: dict[str, Any]) -> None:
        raise ValueError('invalid generated bundle')

    monkeypatch.setattr(services.exports, 'validate_stix_bundle', refuse)
    with pytest.raises(ValueError, match='invalid generated bundle'):
        services.export_stix(db, IocExportQuery())
    assert db.scalar(select(AuditEvent.id).where(AuditEvent.action == 'stix.export')) is None
