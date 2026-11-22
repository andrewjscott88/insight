"""Import the text of a local PDF advisory and attach a digest of the original bytes.

The sandboxed parse can take up to 10 seconds, so it runs before any database session opens:
:func:`prepare_pdf_report` checks the details and parses the file without the database, then
:func:`store_pdf_report` writes the report in the caller's transaction. :func:`import_pdf` does both, for
scripts and tests that already hold a session.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from pydantic import ValidationError
from sqlalchemy.orm import Session

from ..models import DocumentAttachment
from ..pdf_import import ParsedPdf, parse_pdf
from ..schemas import DEFAULT_TLP, DocumentInput, ReportMetadata, most_restrictive, tlp_markings
from .audit import audit
from .documents import ingest
from .tlp import _refuse_above


@dataclass(frozen=True, slots=True)
class PdfReport:
    """A parsed PDF ready to store: the report to ingest and the original file's details."""

    item: DocumentInput
    parsed: ParsedPdf


def prepare_pdf_report(
    data: bytes,
    *,
    title: str,
    source_name: str,
    source_url: str = '',
    tlp: str = DEFAULT_TLP,
    max_tlp: str,
) -> PdfReport:
    """Check the details and parse the PDF, without touching the database. Raises ``ValueError`` (including
    a label above ``max_tlp``) or ``PdfUnavailable``."""
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
    return PdfReport(item, parsed)


def store_pdf_report(db: Session, report: PdfReport, *, max_tlp: str) -> dict[str, Any]:
    """Store a prepared report and its original file metadata in the caller's transaction."""
    parsed = report.parsed
    doc, created = ingest(db, report.item, max_tlp=max_tlp, file_sha256=parsed.sha256)
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
    """:func:`prepare_pdf_report` then :func:`store_pdf_report`, for callers that already hold ``db``."""
    report = prepare_pdf_report(
        data, title=title, source_name=source_name, source_url=source_url, tlp=tlp, max_tlp=max_tlp
    )
    return store_pdf_report(db, report, max_tlp=max_tlp)
