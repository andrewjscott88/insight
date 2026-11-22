"""Cases: one investigation's reports, indicators, actors, campaigns and notes (TIP 3.8, ADR 0029)."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import asdict
from typing import Annotated, Any

from fastapi import APIRouter, Depends, FastAPI, HTTPException, Query, Request

from ... import services
from ...models import Case, SessionFactory
from ...schemas import CaseCloseInput, CaseInput, CaseItemInput, CaseNoteInput, CaseStatusFilter, CaseUpdate
from ..auth import AuthDependency, acting
from .threats import write_limit

Offset = Annotated[int, Query(ge=0)]
PageSize = Annotated[int, Query(ge=1, le=200)]


def _row(row: Case) -> dict[str, Any]:
    return {
        'id': row.id,
        'title': row.title,
        'summary': row.summary,
        'status': row.status,
        'tlp': row.tlp,
        'created_at': row.created_at,
        'updated_at': row.updated_at,
        'closed_at': row.closed_at,
        'close_note': row.close_note,
        'created_by': row.actor,
    }


@contextmanager
def _errors() -> Iterator[None]:
    """One mapping for every case route: missing or hidden 404, above the caller's limit 403, closed 409."""
    try:
        yield
    except LookupError as exc:
        raise HTTPException(404, str(exc)) from exc
    except services.TlpNotPermitted as exc:
        raise HTTPException(403, str(exc)) from exc
    except services.CaseClosed as exc:
        raise HTTPException(409, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc


def _register_case_routes(app: FastAPI, sessions: SessionFactory, require_auth: AuthDependency) -> None:
    router = APIRouter(dependencies=[Depends(require_auth)])
    limit_of: Callable[[Request], str | None] = lambda request: write_limit(app, request)  # noqa: E731

    @router.get('/api/cases')
    def cases(
        request: Request, status: CaseStatusFilter = 'open', offset: Offset = 0, limit: PageSize = 100
    ) -> dict[str, Any]:
        with sessions() as db:
            found = services.list_cases(
                db, max_tlp=limit_of(request), status=status, offset=offset, limit=limit
            )
            return {'cases': [asdict(c) for c in found]}

    @router.post('/api/cases', status_code=201)
    def create(request: Request, payload: CaseInput) -> dict[str, Any]:
        with _errors(), acting(sessions, request) as db:
            return _row(services.create_case(db, payload, max_tlp=limit_of(request)))

    @router.get('/api/cases/{case_id}')
    def one(request: Request, case_id: str) -> dict[str, Any]:
        with _errors(), sessions() as db:
            return asdict(services.get_case(db, case_id, max_tlp=limit_of(request)))

    @router.patch('/api/cases/{case_id}')
    def update(request: Request, case_id: str, payload: CaseUpdate) -> dict[str, Any]:
        with _errors(), acting(sessions, request) as db:
            return _row(services.update_case(db, case_id, payload, max_tlp=limit_of(request)))

    @router.delete('/api/cases/{case_id}')
    def delete(request: Request, case_id: str) -> dict[str, str]:
        with _errors(), acting(sessions, request) as db:
            services.delete_case(db, case_id, max_tlp=limit_of(request))
        return {'deleted': case_id}

    @router.post('/api/cases/{case_id}/items', status_code=201)
    def add_item(request: Request, case_id: str, payload: CaseItemInput) -> dict[str, Any]:
        with _errors(), acting(sessions, request) as db:
            return asdict(services.add_case_item(db, case_id, payload, max_tlp=limit_of(request)))

    @router.delete('/api/cases/{case_id}/items/{item_id}')
    def remove_item(request: Request, case_id: str, item_id: str) -> dict[str, str]:
        with _errors(), acting(sessions, request) as db:
            services.remove_case_item(db, case_id, item_id, max_tlp=limit_of(request))
        return {'removed': item_id}

    @router.post('/api/cases/{case_id}/notes', status_code=201)
    def add_note(request: Request, case_id: str, payload: CaseNoteInput) -> dict[str, Any]:
        with _errors(), acting(sessions, request) as db:
            return asdict(services.add_case_note(db, case_id, payload, max_tlp=limit_of(request)))

    @router.post('/api/cases/{case_id}/close')
    def close(request: Request, case_id: str, payload: CaseCloseInput) -> dict[str, Any]:
        with _errors(), acting(sessions, request) as db:
            return _row(services.close_case(db, case_id, payload, max_tlp=limit_of(request)))

    @router.post('/api/cases/{case_id}/reopen')
    def reopen(request: Request, case_id: str) -> dict[str, Any]:
        with _errors(), acting(sessions, request) as db:
            return _row(services.reopen_case(db, case_id, max_tlp=limit_of(request)))

    @router.get('/api/cases/{case_id}/timeline')
    def timeline(request: Request, case_id: str) -> dict[str, Any]:
        with _errors(), sessions() as db:
            return {
                'events': [asdict(e) for e in services.case_timeline(db, case_id, max_tlp=limit_of(request))]
            }

    app.include_router(router)
