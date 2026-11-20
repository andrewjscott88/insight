"""IOC export queries (insight-ioc-v1); the JSON is built by insight.ioc_export."""

from __future__ import annotations

import json
from typing import Any, Final

from sqlalchemy import ColumnElement, func, select
from sqlalchemy.orm import Session

from ..ioc_export import IocMention, build_export
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


def ioc_export_counts(db: Session, query: IocExportQuery) -> dict[str, int]:
    """``{'iocs', 'documents', 'mentions'}`` an export with ``query`` would contain. One query, not audited.

    Used to preview an export before downloading it; compare ``mentions`` with ``MAX_EXPORT_MENTIONS``.
    """
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
            kev,
        ) in db.execute(stmt)
    ]
    if len(mentions) > MAX_EXPORT_MENTIONS:
        raise ValueError(
            f'More than {MAX_EXPORT_MENTIONS:,} indicator mentions match; narrow the filters '
            '(indicator types, search, TLP) and export in parts.'
        )
    return mentions


def export_iocs(db: Session, query: IocExportQuery) -> dict[str, Any]:
    """Build an ``insight-ioc-v1`` export for ``query`` and audit it (``ioc.export``).

    Shared by the API, the workspace and ``insight export-iocs``. The audit event's object ID is the
    ``export_id`` written into the file, so a file found later can be traced back to its audit record.
    """
    mentions = ioc_mentions(db, query)
    export_id = uid()
    filters = query.model_dump(mode='json', exclude={'defang'})
    result = build_export(
        mentions,
        filters=filters,
        defanged=query.defang,
        export_id=export_id,
        generated_at=now(),
        include_evidence=query.include_evidence,
    )
    audit_detail = {
        'iocs': result['counts']['iocs'],
        'documents': result['counts']['documents'],
        'tlp': result['tlp'],
        'defanged': query.defang,
        'filters': filters,
    }
    audit(db, 'ioc.export', export_id, json.dumps(audit_detail, sort_keys=True))
    return result
