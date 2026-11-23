"""Read-only MCP projections. Each read uses the key's ceiling and shares existing domain services.

Publisher-restricted report words never leave through this interface. These projections expose bounded
facts and citations, not raw documents, rules, stored credentials or executable instructions (ADR 0039).
"""

from __future__ import annotations

from dataclasses import asdict, replace
from datetime import UTC, datetime
from typing import Any

from sqlalchemy.orm import Session

from ..schemas import (
    McpIdInput,
    McpInput,
    McpLandscapeInput,
    McpRequirementsInput,
    McpSearchInput,
    most_restrictive,
)
from ..source_registry import metadata_only
from .actors import MAX_LINKED_REPORTS, linked_reports, resolve_group
from .assessments import entity_assessment, entity_seen
from .confidence import indicator_confidence
from .documents import get_document
from .entities import count_entity_documents, get_entity, list_entities
from .hunt_package_views import get_hunt_package
from .ranked_search import ranked_search
from .requirement_views import list_requirements
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


def _search_indicators(db: Session, args: McpSearchInput, max_tlp: str | None) -> dict[str, Any]:
    rows = list_entities(db, args.q, limit=args.limit + 1, max_tlp=max_tlp)
    return {
        'indicators': [
            {'id': entity.id, 'kind': entity.kind, 'value': entity.value, 'reports': count}
            for entity, count in rows[: args.limit]
        ],
        'truncated': len(rows) > args.limit,
    }


def _requirements(db: Session, args: McpRequirementsInput, max_tlp: str | None) -> dict[str, Any]:
    rows = list_requirements(db, status='open', kind=args.kind, max_tlp=max_tlp)
    return {'requirements': [asdict(row) for row in rows[: args.limit]], 'truncated': len(rows) > args.limit}


def _group(db: Session, ref: str, max_tlp: str | None) -> dict[str, Any]:
    group = resolve_group(db, ref, max_tlp=max_tlp)
    reports = linked_reports(db, group.ref, max_tlp=max_tlp)
    shown = reports[:50]
    catalog = group.catalog
    # Omitted rows influence truncation. A service-cap hit cannot establish their exact labels.
    label = most_restrictive(group.tlp, *(doc.tlp for doc, _ in reports), *(link.tlp for _, link in reports))
    if len(reports) == MAX_LINKED_REPORTS:
        label = most_restrictive(label, max_tlp or 'RED')
    return {
        'ref': group.ref,
        'name': group.name,
        'kind': group.kind,
        'tlp': label,
        'subject_tlp': group.tlp,
        'aliases': list(group.aliases),
        'description': group.description,
        'techniques': list(catalog.techniques) if catalog else [],
        'software': list(catalog.software) if catalog else [],
        'source_url': catalog.url if catalog else '',
        'linked_reports': [
            {
                'id': doc.id,
                'title': doc.title,
                'tlp': doc.tlp,
                'link_tlp': link.tlp,
                'source_url': doc.source_url,
            }
            for doc, link in shown
        ],
        'truncated': len(reports) > 50,
    }


def _landscape(db: Session, days: int, max_tlp: str | None) -> dict[str, Any]:
    # Deferred to avoid a cycle: pure composers import the domain-service dataclasses.
    from ..brief import DEMO, window_start
    from ..landscape import compose, period_start
    from .brief import brief_data
    from .landscape import landscape_data

    now = datetime.now(UTC)
    since = window_start(now, days)
    data = landscape_data(db, start=period_start(now, days), max_tlp=max_tlp, ignore=DEMO)
    brief = replace(brief_data(db, since=since, max_tlp=max_tlp), watch={})
    result = compose(data, brief, since=since, days=days)
    # Deliberately no watch terms, report bodies, provider payloads or free-text source excerpts.
    return {
        'days': days,
        'since': since,
        'tlp': result.tlp,
        'reports': result.reports,
        'sources': result.sources,
        'summary': [line for line in result.summary if 'watch terms' not in line],
        'caveats': list(result.caveats),
        'threats': [
            {
                'name': trend.name,
                'change': asdict(trend.change),
                'what': trend.what,
                'impact': trend.impact,
                'check': trend.check,
            }
            for trend in result.threats
        ],
        'tactics': [asdict(trend) for trend in result.tactics],
        'truncated': data.truncated,
    }


def mcp_read(db: Session, name: str, arguments: McpInput, *, max_tlp: str | None) -> dict[str, Any]:
    """Dispatch an explicitly supported read; the caller never selects its own ceiling.

    Unknown and hidden IDs both raise the same ``LookupError``. No read starts a job, contacts a provider,
    exports STIX, changes analyst decisions or executes detection rules.
    """
    if name == 'search_reports' and isinstance(arguments, McpSearchInput):
        return _search_reports(db, arguments, max_tlp)
    if name == 'search_indicators' and isinstance(arguments, McpSearchInput):
        return _search_indicators(db, arguments, max_tlp)
    if isinstance(arguments, McpIdInput):
        if name == 'get_indicator':
            return _indicator(db, arguments.id, max_tlp)
        if name == 'get_report_summary':
            return _report(db, arguments.id, max_tlp)
        if name == 'get_hunt_package':
            return asdict(get_hunt_package(db, arguments.id, max_tlp=max_tlp))
        if name == 'get_threat_group':
            return _group(db, arguments.id, max_tlp)
    if name == 'list_requirements' and isinstance(arguments, McpRequirementsInput):
        return _requirements(db, arguments, max_tlp)
    if name == 'get_landscape_summary' and isinstance(arguments, McpLandscapeInput):
        return _landscape(db, arguments.days, max_tlp)
    raise ValueError('Unknown tool')
