"""Intelligence requirements and requests for information (TIP 4.1, ADR 0032).

``POST /api/rfis`` is one of the two writes an API key with ``read-feedback`` access may make (``web.auth``),
so a hunt or response tool can ask a question without being able to change anything else.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import asdict
from typing import Any

from fastapi import APIRouter, Depends, FastAPI, HTTPException, Request

from ... import services
from ...models import Requirement, SessionFactory
from ...schemas import (
    AnswerInput,
    CriterionInput,
    EvidenceInput,
    RequirementInput,
    RequirementKind,
    RequirementStatusFilter,
    RequirementUpdate,
    RfiInput,
)
from ..auth import AuthDependency, acting
from .threats import write_limit


def _row(row: Requirement) -> dict[str, Any]:
    return {
        'id': row.id,
        'kind': row.kind,
        'parent_id': row.parent_id,
        'question': row.question,
        'context': row.context,
        'stakeholder': row.stakeholder,
        'priority': row.priority,
        'status': row.status,
        'tlp': row.tlp,
        'due_at': row.due_at,
        'answer': row.answer,
        'answered_at': row.answered_at,
        'external_ref': row.external_ref,
        'created_at': row.created_at,
        'updated_at': row.updated_at,
        'created_by': row.actor,
    }


def _view(view: services.RequirementView) -> dict[str, Any]:
    found = asdict(view)
    return {**found.pop('summary'), **found}


@contextmanager
def _errors() -> Iterator[None]:
    """Missing or hidden 404, above the caller's limit 403, retired or in use 409, invalid 422."""
    try:
        yield
    except LookupError as exc:
        raise HTTPException(404, str(exc)) from exc
    except services.TlpNotPermitted as exc:
        raise HTTPException(403, str(exc)) from exc
    except (services.RequirementRetired, services.RequirementInUse) as exc:
        raise HTTPException(409, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc


def _register_requirement_routes(
    app: FastAPI, sessions: SessionFactory, require_auth: AuthDependency
) -> None:
    router = APIRouter(dependencies=[Depends(require_auth)])
    limit_of: Callable[[Request], str | None] = lambda request: write_limit(app, request)  # noqa: E731

    @router.get('/api/requirements')
    def requirements(
        request: Request, status: RequirementStatusFilter = 'open', kind: RequirementKind | None = None
    ) -> dict[str, Any]:
        with sessions() as db:
            found = services.list_requirements(db, max_tlp=limit_of(request), status=status, kind=kind)
            return {'requirements': [asdict(r) for r in found]}

    @router.post('/api/requirements', status_code=201)
    def create(request: Request, payload: RequirementInput) -> dict[str, Any]:
        with _errors(), acting(sessions, request) as db:
            return _row(services.create_requirement(db, payload, max_tlp=limit_of(request)))

    @router.post('/api/rfis', status_code=201)
    def file_rfi(request: Request, payload: RfiInput) -> dict[str, Any]:
        with _errors(), acting(sessions, request) as db:
            return _row(services.file_rfi(db, payload, max_tlp=limit_of(request)))

    @router.get('/api/requirements/{requirement_id}')
    def one(request: Request, requirement_id: str) -> dict[str, Any]:
        with _errors(), sessions() as db:
            return _view(services.get_requirement(db, requirement_id, max_tlp=limit_of(request)))

    @router.patch('/api/requirements/{requirement_id}')
    def update(request: Request, requirement_id: str, payload: RequirementUpdate) -> dict[str, Any]:
        with _errors(), acting(sessions, request) as db:
            return _row(services.update_requirement(db, requirement_id, payload, max_tlp=limit_of(request)))

    @router.delete('/api/requirements/{requirement_id}')
    def delete(request: Request, requirement_id: str) -> dict[str, str]:
        with _errors(), acting(sessions, request) as db:
            services.delete_requirement(db, requirement_id, max_tlp=limit_of(request))
        return {'deleted': requirement_id}

    @router.post('/api/requirements/{requirement_id}/criteria', status_code=201)
    def add_criterion(request: Request, requirement_id: str, payload: CriterionInput) -> dict[str, Any]:
        with _errors(), acting(sessions, request) as db:
            return asdict(services.add_criterion(db, requirement_id, payload, max_tlp=limit_of(request)))

    @router.delete('/api/requirements/{requirement_id}/criteria/{criterion_id}')
    def remove_criterion(request: Request, requirement_id: str, criterion_id: str) -> dict[str, str]:
        with _errors(), acting(sessions, request) as db:
            services.remove_criterion(db, requirement_id, criterion_id, max_tlp=limit_of(request))
        return {'removed': criterion_id}

    @router.post('/api/requirements/{requirement_id}/evidence', status_code=201)
    def add_evidence(request: Request, requirement_id: str, payload: EvidenceInput) -> dict[str, Any]:
        with _errors(), acting(sessions, request) as db:
            return asdict(services.add_evidence(db, requirement_id, payload, max_tlp=limit_of(request)))

    @router.delete('/api/requirements/{requirement_id}/evidence/{evidence_id}')
    def remove_evidence(request: Request, requirement_id: str, evidence_id: str) -> dict[str, str]:
        with _errors(), acting(sessions, request) as db:
            services.remove_evidence(db, requirement_id, evidence_id, max_tlp=limit_of(request))
        return {'removed': evidence_id}

    @router.post('/api/requirements/{requirement_id}/answer')
    def answer(request: Request, requirement_id: str, payload: AnswerInput) -> dict[str, Any]:
        with _errors(), acting(sessions, request) as db:
            return _row(services.answer_requirement(db, requirement_id, payload, max_tlp=limit_of(request)))

    @router.post('/api/requirements/{requirement_id}/retire')
    def retire(request: Request, requirement_id: str) -> dict[str, Any]:
        with _errors(), acting(sessions, request) as db:
            return _row(services.retire_requirement(db, requirement_id, max_tlp=limit_of(request)))

    @router.post('/api/requirements/{requirement_id}/reopen')
    def reopen(request: Request, requirement_id: str) -> dict[str, Any]:
        with _errors(), acting(sessions, request) as db:
            return _row(services.reopen_requirement(db, requirement_id, max_tlp=limit_of(request)))

    @router.get('/api/documents/{document_id}/requirements')
    def document_requirements(request: Request, document_id: str) -> dict[str, Any]:
        with sessions() as db:
            found = services.document_requirements(db, document_id, max_tlp=limit_of(request))
            return {'requirements': [asdict(r) for r in found]}

    app.include_router(router)
