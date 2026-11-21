"""IOC export queries (insight-ioc-v1); the JSON is built by insight.ioc_export."""

from __future__ import annotations

import json
from typing import Any, Final

from sqlalchemy import ColumnElement, func, select
from sqlalchemy.orm import Session

from ..flags import flags
from ..ioc_export import Assessment, IocMention, build_export
from ..models import (
    Document,
    Entity,
    KEVRecord,
    Observation,
    now,
    uid,
)
from ..schemas import (
    TLP_LEVELS,
    IocExportQuery,
)
from ..source_registry import metadata_only
from ..stix_export import build_stix_bundle
from ..stix_validation import validate_stix_bundle
from .assessments import visible_assessments
from .audit import audit
from .search import _document_conditions, _kev_view

#: Upper bound on indicator mentions in one IOC export, so a single request cannot exhaust memory.
MAX_EXPORT_MENTIONS: Final = 100_000


def _ioc_conditions(query: IocExportQuery) -> list[ColumnElement[bool]]:
    """Which mentions an IOC export (or its preview) includes: report filters plus kind and review state.

    Reports chosen explicitly with ``document_ids`` are included even when they are superseded revisions.
    """
    conditions = _document_conditions(
        q=query.q,
        status=query.status,
        tlp=query.tlp,
        include_superseded=query.include_superseded or bool(query.document_ids),
    )
    if query.document_ids:
        conditions.append(Document.id.in_(query.document_ids))
    if query.max_tlp is not None:
        conditions.append(Document.tlp.in_(TLP_LEVELS[: TLP_LEVELS.index(query.max_tlp) + 1]))
    conditions.append(Entity.kind.in_(query.kinds))
    conditions.append(Observation.review_status.in_(query.review_statuses))
    return conditions


def _by_meaning(
    mentions: list[IocMention], query: IocExportQuery, verdicts: dict[str, str]
) -> list[IocMention]:
    """Keep mentions of indicators with a verdict ``query`` asks for and none of its excluded flags."""
    if not query.filters_by_meaning():
        return mentions
    excluded = set(query.exclude_flags)
    return [
        mention
        for mention in mentions
        if verdicts.get(mention.entity_id, 'unknown') in query.verdicts
        and not excluded.intersection(flags(mention.kind, mention.value))
    ]


def _meanings(db: Session, mentions: list[IocMention], query: IocExportQuery) -> dict[str, Assessment]:
    """The verdicts an export may show: those whose label is within the export's TLP limit."""
    found = visible_assessments(db, (m.entity_id for m in mentions), max_tlp=query.max_tlp)
    return {entity_id: Assessment(row.verdict, row.valid_until) for entity_id, row in found.items()}


def ioc_export_counts(db: Session, query: IocExportQuery) -> dict[str, int]:
    """``{'iocs', 'documents', 'mentions'}`` an export with ``query`` would contain. Not audited.

    Used to preview an export first; compare ``mentions`` with ``MAX_EXPORT_MENTIONS``. One SQL
    query, unless verdicts or flags narrow the export: those are judged per indicator, like the export itself.
    """
    if query.filters_by_meaning():
        mentions = ioc_mentions(db, query)
        meanings = _meanings(db, mentions, query)
        kept = _by_meaning(mentions, query, {k: v.verdict for k, v in meanings.items()})
        return {
            'iocs': len({m.entity_id for m in kept}),
            'documents': len({m.document_id for m in kept}),
            'mentions': len(kept),
        }
    row = db.execute(
        select(
            func.count(func.distinct(Entity.id)),
            func.count(func.distinct(Document.id)),
            func.count(Observation.id),
        )
        .select_from(Observation)
        .join(Entity, Observation.entity_id == Entity.id)
        .join(Document, Observation.document_id == Document.id)
        .where(*_ioc_conditions(query))
    ).one()
    return {'iocs': row[0], 'documents': row[1], 'mentions': row[2]}


def ioc_mentions(db: Session, query: IocExportQuery) -> list[IocMention]:
    """Every indicator mention matching ``query``, ordered by indicator, report age and position.

    Only the columns the export needs are selected: loading whole documents would repeat each report body
    once per mention. Raises ``ValueError`` above ``MAX_EXPORT_MENTIONS`` mentions (narrow the filters).
    """
    stmt = (
        select(
            Observation.review_status,
            Observation.evidence,
            Entity.id,
            Entity.kind,
            Entity.value,
            Document.id,
            Document.title,
            Document.source_name,
            Document.source_url,
            Document.tlp,
            Document.status,
            Document.created_at,
            Document.is_current,
            Document.extractor_version,
            Document.source_key,
            KEVRecord,
        )
        .select_from(Observation)
        .join(Entity, Observation.entity_id == Entity.id)
        .join(Document, Observation.document_id == Document.id)
        .outerjoin(KEVRecord, (Entity.kind == 'cve') & (KEVRecord.cve == Entity.value))
        .where(*_ioc_conditions(query))
        .order_by(
            Entity.kind,
            Entity.value,
            Document.created_at,
            Document.id,
            Observation.start_offset,
            Observation.id,
        )
        .limit(MAX_EXPORT_MENTIONS + 1)
    )
    mentions = [
        IocMention(
            entity_id=entity_id,
            kind=kind,
            value=value,
            review_status=review_status,
            evidence=evidence,
            document_id=document_id,
            title=title,
            source_name=source_name,
            source_url=source_url,
            tlp=tlp,
            status=status,
            created_at=created_at,
            is_current=is_current,
            kev=_kev_view(kev),
            extractor_version=extractor_version,
            metadata_only=metadata_only(source_key),
        )
        for (
            review_status,
            evidence,
            entity_id,
            kind,
            value,
            document_id,
            title,
            source_name,
            source_url,
            tlp,
            status,
            created_at,
            is_current,
            extractor_version,
            source_key,
            kev,
        ) in db.execute(stmt)
    ]
    if len(mentions) > MAX_EXPORT_MENTIONS:
        raise ValueError(
            f'More than {MAX_EXPORT_MENTIONS:,} indicator mentions match; narrow the filters '
            '(indicator types, search, TLP) and export in parts.'
        )
    return mentions


def _selected_export(db: Session, query: IocExportQuery) -> tuple[dict[str, Any], set[str]]:
    """Build both sharing formats from the same permitted set of mentions and publisher rights."""
    mentions = ioc_mentions(db, query)
    meanings = _meanings(db, mentions, query)
    mentions = _by_meaning(mentions, query, {k: v.verdict for k, v in meanings.items()})
    filters = query.model_dump(mode='json', exclude={'defang'})
    result = build_export(
        mentions,
        filters=filters,
        defanged=query.defang,
        export_id=uid(),
        generated_at=now(),
        include_evidence=query.include_evidence,
        assessments=meanings,
    )
    return result, {m.document_id for m in mentions if m.metadata_only}


def export_iocs(db: Session, query: IocExportQuery) -> dict[str, Any]:
    """Build an ``insight-ioc-v1`` export for ``query`` and audit it (``ioc.export``).

    Shared by the API, the workspace and ``insight export-iocs``. The audit event's object ID is the
    ``export_id`` written into the file, so a file found later can be traced back to its audit record.
    """
    result, _ = _selected_export(db, query)
    filters = result['filters']
    audit_detail = {
        'iocs': result['counts']['iocs'],
        'documents': result['counts']['documents'],
        'tlp': result['tlp'],
        'defanged': query.defang,
        'filters': filters,
    }
    audit(db, 'ioc.export', result['export_id'], json.dumps(audit_detail, sort_keys=True))
    return result


def export_stix(db: Session, query: IocExportQuery) -> dict[str, Any]:
    """Export a validated STIX 2.1 snapshot and audit it in the caller's transaction."""
    if query.defang:
        raise ValueError('STIX indicator patterns require original values. Turn off defanging.')
    export, metadata_only_ids = _selected_export(db, query)
    bundle = build_stix_bundle(export, metadata_only_ids)
    validate_stix_bundle(bundle)
    detail = {'counts': export['counts'], 'tlp': export['tlp'], 'filters': export['filters']}
    audit(db, 'stix.export', bundle['id'], json.dumps(detail, sort_keys=True))
    return bundle
