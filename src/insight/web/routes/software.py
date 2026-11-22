"""Software catalog and labelled report associations (TIP 4.7 part 2)."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, FastAPI, HTTPException, Query, Request

from ... import services
from ...models import SessionFactory
from ...schemas import SoftwareLinkInput
from ..auth import AuthDependency, acting, reader_limit
from .threats import write_limit


def _register_software_routes(app: FastAPI, sessions: SessionFactory, require_auth: AuthDependency) -> None:
    router = APIRouter(dependencies=[Depends(require_auth)])

    @router.get('/api/software')
    def search(
        request: Request,
        q: Annotated[str, Query(max_length=120)] = '',
        offset: Annotated[int, Query(ge=0)] = 0,
        limit: Annotated[int, Query(ge=1, le=200)] = 50,
    ) -> dict[str, Any]:
        return {
            'software': services.search_software(
                q=q, offset=offset, limit=limit, max_tlp=reader_limit(request)
            )
        }

    @router.get('/api/software/{ref}')
    def detail(request: Request, ref: str) -> dict[str, Any]:
        try:
            with sessions() as db:
                return services.software_detail(db, ref, max_tlp=reader_limit(request))
        except LookupError as exc:
            raise HTTPException(404, str(exc)) from exc

    @router.get('/api/software/{ref}/documents')
    def reports(
        request: Request,
        ref: str,
        offset: Annotated[int, Query(ge=0)] = 0,
        limit: Annotated[int, Query(ge=1, le=200)] = 50,
    ) -> dict[str, Any]:
        with sessions() as db:
            return {
                'reports': services.software_reports(
                    db, ref, max_tlp=reader_limit(request), offset=offset, limit=limit
                )
            }

    @router.post('/api/software/{ref}/documents', status_code=201)
    def link(request: Request, ref: str, payload: SoftwareLinkInput) -> dict[str, Any]:
        try:
            with acting(sessions, request) as db:
                return services.software_link_view(
                    services.link_software_report(db, ref, payload, max_tlp=write_limit(app, request))
                )
        except LookupError as exc:
            raise HTTPException(404, str(exc)) from exc
        except services.TlpNotPermitted as exc:
            raise HTTPException(403, str(exc)) from exc

    @router.delete('/api/software/{ref}/documents/{document_id}')
    def unlink(request: Request, ref: str, document_id: str) -> dict[str, str]:
        try:
            with acting(sessions, request) as db:
                services.unlink_software_report(db, ref, document_id, max_tlp=write_limit(app, request))
        except LookupError as exc:
            raise HTTPException(404, str(exc)) from exc
        return {'removed': document_id}

    @router.get('/api/documents/{document_id}/software')
    def linked_software(request: Request, document_id: str) -> dict[str, Any]:
        try:
            with sessions() as db:
                return {'software': services.report_software(db, document_id, max_tlp=reader_limit(request))}
        except LookupError as exc:
            raise HTTPException(404, str(exc)) from exc

    app.include_router(router)
