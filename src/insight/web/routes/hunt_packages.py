"""Hunt packages: a hypothesis with the techniques, indicators, rules and reports a hunt tool needs (TIP 4.3,
ADR 0034). Published packages are also served in the *Hunt packages* TAXII collection."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import asdict
from typing import Any

from fastapi import APIRouter, Depends, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse

from ... import services
from ...models import HuntPackage, SessionFactory
from ...schemas import HuntPackageInput, HuntPackageItemInput, HuntPackageStatusFilter, HuntPackageUpdate
from ..auth import AuthDependency, acting
from .threats import write_limit


def _row(row: HuntPackage) -> dict[str, Any]:
    return {
        'id': row.id,
        'title': row.title,
        'hypothesis': row.hypothesis,
        'group_ref': row.group_ref,
        'status': row.status,
        'publication': row.publication,
        'tlp': row.tlp,
        'created_at': row.created_at,
        'updated_at': row.updated_at,
        'published_at': row.published_at,
        'created_by': row.actor,
    }


@contextmanager
def _errors() -> Iterator[None]:
    """Missing or hidden 404, above the caller's limit 403, not allowed in this status 409, bad input 422."""
    try:
        yield
    except LookupError as exc:
        raise HTTPException(404, str(exc)) from exc
    except services.TlpNotPermitted as exc:
        raise HTTPException(403, str(exc)) from exc
    except services.HuntPackageConflict as exc:
        raise HTTPException(409, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc


def _register_hunt_package_routes(
    app: FastAPI, sessions: SessionFactory, require_auth: AuthDependency
) -> None:
    router = APIRouter(dependencies=[Depends(require_auth)])
    limit_of: Callable[[Request], str | None] = lambda request: write_limit(app, request)  # noqa: E731

    @router.get('/api/hunt-packages')
    def packages(request: Request, status: HuntPackageStatusFilter = 'all') -> dict[str, Any]:
        with sessions() as db:
            found = services.list_hunt_packages(db, max_tlp=limit_of(request), status=status)
            return {'hunt_packages': [asdict(p) for p in found]}

    @router.post('/api/hunt-packages', status_code=201)
    def create(request: Request, payload: HuntPackageInput) -> dict[str, Any]:
        with _errors(), acting(sessions, request) as db:
            return _row(services.create_hunt_package(db, payload, max_tlp=limit_of(request)))

    @router.get('/api/hunt-packages/{package_id}')
    def one(request: Request, package_id: str) -> dict[str, Any]:
        with _errors(), sessions() as db:
            return asdict(services.get_hunt_package(db, package_id, max_tlp=limit_of(request)))

    @router.patch('/api/hunt-packages/{package_id}')
    def update(request: Request, package_id: str, payload: HuntPackageUpdate) -> dict[str, Any]:
        with _errors(), acting(sessions, request) as db:
            return _row(services.update_hunt_package(db, package_id, payload, max_tlp=limit_of(request)))

    @router.delete('/api/hunt-packages/{package_id}')
    def delete(request: Request, package_id: str) -> dict[str, str]:
        with _errors(), acting(sessions, request) as db:
            services.delete_hunt_package(db, package_id, max_tlp=limit_of(request))
        return {'deleted': package_id}

    @router.post('/api/hunt-packages/{package_id}/items', status_code=201)
    def add_item(request: Request, package_id: str, payload: HuntPackageItemInput) -> dict[str, Any]:
        with _errors(), acting(sessions, request) as db:
            item = services.add_hunt_package_item(db, package_id, payload, max_tlp=limit_of(request))
            return asdict(item)

    @router.delete('/api/hunt-packages/{package_id}/items/{item_id}')
    def remove_item(request: Request, package_id: str, item_id: str) -> dict[str, str]:
        with _errors(), acting(sessions, request) as db:
            services.remove_hunt_package_item(db, package_id, item_id, max_tlp=limit_of(request))
        return {'removed': item_id}

    @router.post('/api/hunt-packages/{package_id}/publish')
    def publish(request: Request, package_id: str) -> dict[str, Any]:
        with _errors(), acting(sessions, request) as db:
            return _row(services.publish_hunt_package(db, package_id, max_tlp=limit_of(request)))

    @router.post('/api/hunt-packages/{package_id}/retire')
    def retire(request: Request, package_id: str) -> dict[str, Any]:
        with _errors(), acting(sessions, request) as db:
            return _row(services.retire_hunt_package(db, package_id, max_tlp=limit_of(request)))

    @router.get('/api/hunt-packages/{package_id}/stix')
    def stix(request: Request, package_id: str) -> JSONResponse:
        """The package as a validated STIX 2.1 bundle, in any status (check a draft before publishing it)."""
        with _errors(), acting(sessions, request) as db:
            bundle = services.export_hunt_package(db, package_id, max_tlp=limit_of(request))
            stored_id = services.get_hunt_package(db, package_id, max_tlp=limit_of(request)).id
        return JSONResponse(
            bundle,
            media_type='application/stix+json;version=2.1',
            headers={'Content-Disposition': f'attachment; filename="insight-hunt-package-{stored_id}.json"'},
        )

    app.include_router(router)
