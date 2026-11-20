"""Reports: list, read and add."""

from __future__ import annotations

from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Request
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ... import services
from ...models import Document, SessionFactory
from ...schemas import (
    DocumentInput,
)
from ..auth import AuthDependency, acting, reader_limit


def get_document_or_404(db: Session, doc_id: str, max_tlp: str | None = None) -> Document:
    """The report, or ``404`` if it does not exist or is above ``max_tlp`` (the two are indistinguishable)."""
    doc = services.get_document(db, doc_id, max_tlp=max_tlp)
    if doc is None:
        raise HTTPException(404, 'Report not found')
    return doc


def _register_document_routes(app: FastAPI, sessions: SessionFactory, require_auth: AuthDependency) -> None:
    """Search, read and ingest reports."""

    @app.get('/api/documents', dependencies=[Depends(require_auth)])
    def documents(
        request: Request,
        q: str = '',
        status: str = '',
        tlp: str = '',
        include_superseded: bool = False,
        offset: int = 0,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        query = services.DocumentQuery(
            q=q,
            status=status or None,
            tlp=tlp or None,
            include_superseded=include_superseded,
            offset=offset,
            limit=limit,
            max_tlp=reader_limit(request),
        )
        with sessions() as db:
            return services.summaries(db, services.search_documents(db, query))

    @app.get('/api/documents/{doc_id}', dependencies=[Depends(require_auth)])
    def document(request: Request, doc_id: str) -> dict[str, Any]:
        limit = reader_limit(request)
        with sessions() as db:
            return services.detail(db, get_document_or_404(db, doc_id, limit), max_tlp=limit)

    @app.post('/api/documents', dependencies=[Depends(require_auth)])
    def create_document(request: Request, item: DocumentInput) -> dict[str, Any]:
        # The stricter of the instance limit and the key's own: a key cannot store what it may not read.
        limit = services.stricter_limit(app.state.settings.max_tlp, reader_limit(request))
        try:
            with acting(sessions, request) as db:
                doc, created = services.ingest(db, item, max_tlp=limit)
                result = services.detail(db, doc, max_tlp=reader_limit(request))
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc
        except IntegrityError as exc:
            raise HTTPException(409, 'Concurrent import; retry once') from exc
        result['created'] = created
        # Set when a TLP marking in the text was more restrictive than the submitted label (never lowered).
        result['tlp_raised_from'] = item.tlp if created and result['tlp'] != item.tlp else None
        return result
