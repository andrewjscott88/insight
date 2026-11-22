"""Sightings: a hunt tool saw a known indicator in its own data (TIP 4.2, ADR 0035).

``POST /api/sightings`` is one of the two writes an API key with ``read-feedback`` access may make
(``web.auth``), so a hunt tool can report what it saw without being able to change anything else.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import asdict
from typing import Annotated, Any

from fastapi import APIRouter, Depends, FastAPI, HTTPException, Query, Request

from ... import services
from ...models import SessionFactory, Sighting
from ...schemas import SightingInput
from ..auth import AuthDependency, acting
from .threats import write_limit

OptionalId = Annotated[str | None, Query(min_length=1, max_length=36)]


def _row(row: Sighting) -> dict[str, Any]:
    return {
        'id': row.id,
        'entity_id': row.entity_id,
        'hunt_package_id': row.hunt_package_id,
        'first_seen': row.first_seen,
        'last_seen': row.last_seen,
        'count': row.count,
        'where': row.location,
        'observer': row.observer,
        'note': row.note,
        'external_ref': row.external_ref,
        'tlp': row.tlp,
        'created_at': row.created_at,
        'created_by': row.actor,
    }


@contextmanager
def _errors() -> Iterator[None]:
    """Unknown or hidden indicator, package or sighting 404, above the caller's limit 403, bad input 422."""
    try:
        yield
    except LookupError as exc:
        raise HTTPException(404, str(exc)) from exc
    except services.TlpNotPermitted as exc:
        raise HTTPException(403, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc


def _register_sighting_routes(app: FastAPI, sessions: SessionFactory, require_auth: AuthDependency) -> None:
    router = APIRouter(dependencies=[Depends(require_auth)])
    limit_of: Callable[[Request], str | None] = lambda request: write_limit(app, request)  # noqa: E731

    @router.post('/api/sightings', status_code=201)
    def record(request: Request, payload: SightingInput) -> dict[str, Any]:
        with _errors(), acting(sessions, request) as db:
            return _row(services.record_sighting(db, payload, max_tlp=limit_of(request)))

    @router.get('/api/sightings')
    def sightings(
        request: Request,
        entity_id: OptionalId = None,
        hunt_package_id: OptionalId = None,
        limit: Annotated[int, Query(ge=1, le=500)] = 200,
    ) -> dict[str, Any]:
        with sessions() as db:
            found = services.list_sightings(
                db,
                max_tlp=limit_of(request),
                entity_id=entity_id,
                hunt_package_id=hunt_package_id,
                limit=limit,
            )
            return {'sightings': [asdict(s) for s in found]}

    @router.delete('/api/sightings/{sighting_id}')
    def delete(request: Request, sighting_id: str) -> dict[str, str]:
        with _errors(), acting(sessions, request) as db:
            services.delete_sighting(db, sighting_id, max_tlp=limit_of(request))
        return {'deleted': sighting_id}

    app.include_router(router)
