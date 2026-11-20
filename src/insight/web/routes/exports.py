"""Single-report and cross-report IOC exports."""

from __future__ import annotations

from typing import Annotated, Any, Final

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from pydantic import ValidationError

from ... import services
from ...ioc_export import export_filename
from ...models import SessionFactory
from ...schemas import (
    IocExportQuery,
    validation_message,
)
from ..auth import AuthDependency, acting, reader_limit
from .documents import get_document_or_404

#: How IOC export fields are named in the query string, for error messages that match what the caller sent.
IOC_EXPORT_PARAMETERS: Final = {
    'kinds': 'kind',
    'review_statuses': 'review_status',
    'document_ids': 'document_id',
    'include_evidence': 'evidence',
}


def ioc_export_query(
    *,
    q: str,
    status: str,
    tlp: str,
    include_superseded: bool,
    kinds: list[str] | None,
    review_statuses: list[str] | None,
    max_tlp: str,
    defang: bool,
    document_ids: list[str] | None = None,
    include_evidence: bool = True,
) -> IocExportQuery:
    """Validate IOC export query parameters; empty strings and absent lists mean "use the default"."""
    params: dict[str, Any] = {
        'q': q,
        'status': status or None,
        'tlp': tlp or None,
        'include_superseded': include_superseded,
        'max_tlp': max_tlp or None,
        'defang': defang,
        'include_evidence': include_evidence,
    }
    if kinds:
        params['kinds'] = kinds
    if review_statuses:
        params['review_statuses'] = review_statuses
    if document_ids:
        params['document_ids'] = document_ids
    try:
        return IocExportQuery.model_validate(params)
    except ValidationError as exc:
        raise HTTPException(422, validation_message(exc, IOC_EXPORT_PARAMETERS)) from exc


def _register_export_routes(app: FastAPI, sessions: SessionFactory, require_auth: AuthDependency) -> None:
    """Audited JSON downloads: one report, or indicators across reports."""

    @app.get('/api/documents/{doc_id}/export', dependencies=[Depends(require_auth)])
    def export(request: Request, doc_id: str) -> JSONResponse:
        limit = reader_limit(request)
        with acting(sessions, request) as db:
            doc = get_document_or_404(db, doc_id, limit)
            result = services.detail(db, doc, max_tlp=limit)
            result['format'] = 'insight-report-v1'
            result['handling_notice'] = (
                'Local backup/export only. Preserve TLP and publisher restrictions. Not STIX.'
            )
            services.audit(db, 'document.export', doc.id, doc.tlp)
        return JSONResponse(
            result, headers={'Content-Disposition': f'attachment; filename="insight-report-{doc.id}.json"'}
        )

    @app.get('/api/iocs/export', dependencies=[Depends(require_auth)])
    def export_iocs(
        request: Request,
        q: str = '',
        status: str = '',
        tlp: str = '',
        include_superseded: bool = False,
        kind: Annotated[list[str] | None, Query()] = None,
        review_status: Annotated[list[str] | None, Query()] = None,
        max_tlp: str = '',
        defang: bool = False,
        document_id: Annotated[list[str] | None, Query()] = None,
        evidence: bool = True,
    ) -> JSONResponse:
        """Cross-report IOC export (``insight-ioc-v1``). List parameters may be repeated."""
        query = ioc_export_query(
            q=q,
            status=status,
            tlp=tlp,
            include_superseded=include_superseded,
            kinds=kind,
            review_statuses=review_status,
            max_tlp=max_tlp,
            defang=defang,
            document_ids=document_id,
            include_evidence=evidence,
        )
        # A TLP-limited key exports at most its own limit, whatever `max_tlp` it asked for.
        limit = services.stricter_limit(query.max_tlp, reader_limit(request))
        if limit != query.max_tlp:
            query = query.model_copy(update={'max_tlp': limit})
        try:
            with acting(sessions, request) as db:
                result = services.export_iocs(db, query)
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc
        filename = export_filename(result['generated_at'])
        return JSONResponse(result, headers={'Content-Disposition': f'attachment; filename="{filename}"'})
