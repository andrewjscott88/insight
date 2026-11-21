"""A PDF has distinct provenance from its text. The normal review, handling and retention paths apply."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from insight import services
from insight.models import AuditEvent, Document, DocumentAttachment, Entity, Observation
from insight.schemas import DocumentInput

ADVISORY = Path(__file__).parents[1] / 'fixtures' / 'advisory.pdf'


def test_pdf_hash_observations_and_repeat_import(db: Session) -> None:
    data = ADVISORY.read_bytes()
    submitted = {
        'title': 'PDF review',
        'source_name': 'Training',
        'source_url': 'https://example.org/reports/1',
        'tlp': 'GREEN',
        'max_tlp': 'GREEN',
    }
    first = services.import_pdf(db, data, **submitted)
    digest = hashlib.sha256(data).hexdigest()
    doc = db.get_one(Document, first['document_id'])
    assert first == {'created': True, 'document_id': doc.id, 'file_sha256': digest}
    assert doc.body == 'Synthetic advisory: example.org observed at 192.0.2.17.'
    assert doc.content_hash == hashlib.sha256(doc.body.encode()).hexdigest() != digest
    detail = services.detail(db, doc)
    assert detail['attachment'] == {
        'sha256': digest,
        'size_bytes': len(data),
        'page_count': 1,
        'media_type': 'application/pdf',
    }
    assert {(o['kind'], o['value']) for o in detail['observations']} == {
        ('domain', 'example.org'),
        ('ip', '192.0.2.17'),
    }
    for observation in detail['observations']:
        assert observation['review_status'] == 'unreviewed'
        assert doc.body[observation['start_offset'] : observation['end_offset']] == observation['value']
    assert services.import_pdf(db, data, **submitted) == {**first, 'created': False}
    assert db.scalar(select(func.count()).select_from(Document)) == 1
    assert (
        db.scalar(select(func.count()).select_from(AuditEvent).where(AuditEvent.action == 'document.pdf'))
        == 1
    )


def test_file_identity_and_retention(db: Session) -> None:
    raw = ADVISORY.read_bytes()
    params = {'title': 'PDF review', 'source_name': 'Training', 'tlp': 'GREEN', 'max_tlp': 'GREEN'}
    one = services.import_pdf(db, raw, **params)['document_id']
    two = services.import_pdf(db, raw + b'\n', **params)['document_id']
    assert one != two
    original = db.get_one(Document, one)
    plain, created = services.ingest(
        db,
        DocumentInput(
            body=original.body, title=original.title, source_name=original.source_name, tlp='GREEN'
        ),
    )
    assert created
    assert plain.id not in (one, two)
    assert 'attachment' not in services.detail(db, plain)
    services.delete_document(db, one, reason='Synthetic test retention')
    assert db.get(DocumentAttachment, one) is None
    assert db.get(DocumentAttachment, two) is not None
    assert db.scalar(select(func.count()).select_from(Observation)) == 4


def test_tlp_in_extracted_prose_can_block_import(db: Session) -> None:
    from unittest.mock import patch

    from insight.pdf_import import ParsedPdf

    service = 'insight.services.pdf_reports.parse_pdf'
    result = ParsedPdf(text='Claim 192.0.2.9. TLP:RED', sha256='e' * 64, size_bytes=404, page_count=1)
    with patch(service, return_value=result), pytest.raises(services.TlpNotPermitted, match='TLP:RED'):
        services.import_pdf(
            db, b'fixture', title='Text handling', source_name='Training', tlp='CLEAR', max_tlp='GREEN'
        )
    for table in (Document, DocumentAttachment, Entity, Observation, AuditEvent):
        assert db.scalar(select(func.count()).select_from(table)) == 0
