"""Finished intelligence products (TIP 4.4, ADR 0036): key judgements, intelligence gaps, publishing, the
product as a draft or a published version, and its Markdown and STIX exports. A product lives in a case."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import asdict
from typing import Annotated, Any

from fastapi import APIRouter, Depends, FastAPI, HTTPException, Query, Request
from fastapi.responses import Response

from ... import services
from ...models import SessionFactory
from ...schemas import GapInput, JudgementInput, JudgementUpdate, ProductExportFormat
from ..auth import AuthDependency, acting
from .threats import write_limit

Version = Annotated[int | None, Query(ge=1)]


@contextmanager
def _errors() -> Iterator[None]:
    """Missing or hidden 404, above the caller's limit 403, archived or not ready to publish 409, bad
    input 422."""
    try:
        yield
    except LookupError as exc:
        raise HTTPException(404, str(exc)) from exc
    except services.TlpNotPermitted as exc:
        raise HTTPException(403, str(exc)) from exc
    except (services.CaseClosed, services.ProductIncomplete) as exc:
        raise HTTPException(409, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc


def _register_product_routes(app: FastAPI, sessions: SessionFactory, require_auth: AuthDependency) -> None:
    router = APIRouter(dependencies=[Depends(require_auth)])
    limit_of: Callable[[Request], str | None] = lambda request: write_limit(app, request)  # noqa: E731

    @router.post('/api/cases/{case_id}/judgements', status_code=201)
    def add_judgement(request: Request, case_id: str, payload: JudgementInput) -> dict[str, Any]:
        with _errors(), acting(sessions, request) as db:
            return asdict(services.add_judgement(db, case_id, payload, max_tlp=limit_of(request)))

    @router.patch('/api/cases/{case_id}/judgements/{judgement_id}')
    def update_judgement(
        request: Request, case_id: str, judgement_id: str, payload: JudgementUpdate
    ) -> dict[str, Any]:
        with _errors(), acting(sessions, request) as db:
            found = services.update_judgement(db, case_id, judgement_id, payload, max_tlp=limit_of(request))
            return asdict(found)

    @router.delete('/api/cases/{case_id}/judgements/{judgement_id}')
    def remove_judgement(request: Request, case_id: str, judgement_id: str) -> dict[str, str]:
        with _errors(), acting(sessions, request) as db:
            services.remove_judgement(db, case_id, judgement_id, max_tlp=limit_of(request))
        return {'removed': judgement_id}

    @router.post('/api/cases/{case_id}/gaps', status_code=201)
    def add_gap(request: Request, case_id: str, payload: GapInput) -> dict[str, Any]:
        with _errors(), acting(sessions, request) as db:
            return asdict(services.add_gap(db, case_id, payload, max_tlp=limit_of(request)))

    @router.delete('/api/cases/{case_id}/gaps/{gap_id}')
    def remove_gap(request: Request, case_id: str, gap_id: str) -> dict[str, str]:
        with _errors(), acting(sessions, request) as db:
            services.remove_gap(db, case_id, gap_id, max_tlp=limit_of(request))
        return {'removed': gap_id}

    @router.post('/api/cases/{case_id}/gaps/{gap_id}/rfi', status_code=201)
    def ask(request: Request, case_id: str, gap_id: str) -> dict[str, Any]:
        with _errors(), acting(sessions, request) as db:
            rfi = services.ask_gap(db, case_id, gap_id, max_tlp=limit_of(request))
            return {
                'id': rfi.id,
                'kind': rfi.kind,
                'question': rfi.question,
                'status': rfi.status,
                'tlp': rfi.tlp,
            }

    @router.post('/api/cases/{case_id}/publish')
    def publish(request: Request, case_id: str) -> dict[str, Any]:
        with _errors(), acting(sessions, request) as db:
            return asdict(services.publish_product(db, case_id, max_tlp=limit_of(request)))

    @router.get('/api/cases/{case_id}/product')
    def product(request: Request, case_id: str, version: Version = None) -> dict[str, Any]:
        with _errors(), sessions() as db:
            return services.product_view(db, case_id, max_tlp=limit_of(request), version=version)

    @router.get('/api/cases/{case_id}/export')
    def export(
        request: Request, case_id: str, format: ProductExportFormat = 'md', version: Version = None
    ) -> Response:
        with _errors(), acting(sessions, request) as db:
            found = services.export_product(db, case_id, format, max_tlp=limit_of(request), version=version)
        return Response(
            found.content,
            media_type=found.media_type,
            headers={'Content-Disposition': f'attachment; filename="{found.filename}"'},
        )

    app.include_router(router)
