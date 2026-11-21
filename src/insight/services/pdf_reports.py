"""Import the text of a local PDF advisory and attach a digest of the original bytes."""

from __future__ import annotations

import json
from typing import Any

from pydantic import ValidationError
from sqlalchemy.orm import Session

from ..models import DocumentAttachment
from ..pdf_import import parse_pdf
from ..schemas import DEFAULT_TLP, DocumentInput, ReportMetadata, most_restrictive, tlp_markings
from .audit import audit
from .documents import ingest
from .tlp import _refuse_above


def import_pdf(
    db: Session,
    data: bytes,
    *,
    title: str,
    source_name: str,
    source_url: str = '',
    tlp: str = DEFAULT_TLP,
    max_tlp: str,
) -> dict[str, Any]:
    """Store a report and its original file metadata in the caller's transaction."""
    try:
        fields = {'title': title, 'source_name': source_name, 'source_url': source_url, 'tlp': tlp}
        metadata = ReportMetadata.model_validate(fields)
    except ValidationError as exc:
        raise ValueError('Check the title, publisher, source URL and sharing label') from exc
    _refuse_above(metadata.tlp, most_restrictive(metadata.tlp, *tlp_markings(metadata.title)), max_tlp)
    parsed = parse_pdf(data)
    try:
        item = DocumentInput(**metadata.model_dump(), body=parsed.text)
    except ValidationError as exc:
        raise ValueError('The PDF text cannot be stored as a report') from exc
    doc, created = ingest(db, item, max_tlp=max_tlp, file_sha256=parsed.sha256)
    if created:
        db.add(
            DocumentAttachment(
                document_id=doc.id,
                sha256=parsed.sha256,
                media_type='application/pdf',
                size_bytes=parsed.size_bytes,
                page_count=parsed.page_count,
            )
        )
        audit(
            db, 'document.pdf', doc.id, json.dumps({'sha256': parsed.sha256, 'size_bytes': parsed.size_bytes})
        )
        db.flush()
    return {'document_id': doc.id, 'created': created, 'file_sha256': parsed.sha256}
