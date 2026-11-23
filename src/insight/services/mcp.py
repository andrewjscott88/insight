"""Read-only MCP projections. Each read uses the key's ceiling and shares existing domain services.

Publisher-restricted report words never leave through this interface. These projections expose bounded
facts and citations, not raw documents, rules, stored credentials or executable instructions (ADR 0039).
"""

from __future__ import annotations

from dataclasses import asdict
from typing import Any

from sqlalchemy.orm import Session

from ..schemas import (
    McpIdInput,
    McpInput,
    McpSearchInput,
)
from ..source_registry import metadata_only
from .assessments import entity_assessment, entity_seen
from .confidence import indicator_confidence
from .documents import get_document
from .entities import count_entity_documents, get_entity
from .ranked_search import ranked_search
from .search import summary


def _report(db: Session, document_id: str, max_tlp: str | None) -> dict[str, Any]:
    doc = get_document(db, document_id, max_tlp=max_tlp)
    if doc is None:
        raise LookupError('Not found')
    result = summary(db, doc)
    restricted = metadata_only(doc.source_key)
    result['summary'] = None if restricted else result['summary']
    result['text_withheld'] = restricted
    return result


def _search_reports(db: Session, args: McpSearchInput, max_tlp: str | None) -> dict[str, Any]:
    page = ranked_search(db, args.q, limit=args.limit, max_tlp=max_tlp)
    return {
        'reports': [_report(db, hit.document.id, max_tlp) for hit in page.hits],
        'total': page.total,
        'truncated': page.capped or page.total > len(page.hits),
    }


def _indicator(db: Session, entity_id: str, max_tlp: str | None) -> dict[str, Any]:
    entity = get_entity(db, entity_id)
    count = count_entity_documents(db, entity_id, max_tlp=max_tlp)
    if entity is None or count == 0:
        raise LookupError('Not found')
    assessment = entity_assessment(db, entity_id, max_tlp=max_tlp)
    first, last = entity_seen(db, entity_id, max_tlp=max_tlp)
    confidence = indicator_confidence(db, entity_id, max_tlp=max_tlp)
    return {
        'id': entity.id,
        'kind': entity.kind,
        'value': entity.value,
        'reports': count,
        'first_seen_at': first,
        'last_seen_at': last,
        'verdict': 'unknown' if assessment is None else assessment.verdict,
        'assessment': None
        if assessment is None
        else {
            'reason': assessment.reason,
            'tlp': assessment.tlp,
            'valid_until': assessment.valid_until,
            'decided_at': assessment.decided_at,
        },
        'confidence': asdict(confidence),
        'meaning': 'A mention or confidence score is not a maliciousness verdict.',
    }


def mcp_read(db: Session, name: str, arguments: McpInput, *, max_tlp: str | None) -> dict[str, Any]:
    """Dispatch an explicitly supported read; the caller never selects its own ceiling.

    Unknown and hidden IDs both raise the same ``LookupError``. No read starts a job, contacts a provider,
    exports STIX, changes analyst decisions or executes detection rules.
    """
    if name == 'search_reports' and isinstance(arguments, McpSearchInput):
        return _search_reports(db, arguments, max_tlp)
    if name == 'get_indicator' and isinstance(arguments, McpIdInput):
        return _indicator(db, arguments.id, max_tlp)
    raise ValueError('Unknown tool')
