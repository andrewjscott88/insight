"""Browser-managed feed definitions. Reading the catalog uses the caller's sharing ceiling."""

from __future__ import annotations

from collections.abc import Callable, Coroutine, Iterator
from contextlib import contextmanager
from dataclasses import asdict
from typing import Any

from fastapi import APIRouter, Depends, FastAPI, HTTPException, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.routing import APIRoute

from ... import services
from ...models import SessionFactory
from ...schemas import OperatorSourceInput, OperatorSourceSwitchInput
from ..auth import AuthDependency, acting, reader_limit
from .threats import write_limit


class _SourceRoute(APIRoute):
    """FastAPI validation errors normally echo input, including secrets in a rejected URL."""

    def get_route_handler(self) -> Callable[[Request], Coroutine[Any, Any, Response]]:
        handler = super().get_route_handler()

        async def handle(request: Request) -> Response:
            try:
                return await handler(request)
            except RequestValidationError:
                raise HTTPException(
                    422, 'Invalid source settings. Check the name, URL and sharing options.'
                ) from None

        return handle


@contextmanager
def _source_errors() -> Iterator[None]:
    try:
        yield
    except services.TlpNotPermitted:
        raise HTTPException(403, 'Source label exceeds the permitted sharing level') from None
    except LookupError:
        raise HTTPException(404, 'Unknown source') from None
    except ValueError:
        raise HTTPException(422, 'Invalid source settings') from None


def _register_operator_source_routes(
    app: FastAPI, sessions: SessionFactory, require_auth: AuthDependency
) -> None:
    router = APIRouter(
        prefix='/api/operator-sources', dependencies=[Depends(require_auth)], route_class=_SourceRoute
    )

    @router.get('')
    def list_sources(request: Request) -> list[dict[str, Any]]:
        with sessions() as db:
            return [asdict(row) for row in services.list_operator_sources(db, max_tlp=reader_limit(request))]

    @router.get('/{key}')
    def detail(request: Request, key: str) -> dict[str, Any]:
        with _source_errors(), sessions() as db:
            return asdict(services.get_operator_source(db, key, max_tlp=reader_limit(request)))

    @router.post('', status_code=201)
    def create(request: Request, body: OperatorSourceInput) -> dict[str, Any]:
        with _source_errors(), acting(sessions, request) as db:
            return asdict(services.create_operator_source(db, body, max_tlp=write_limit(app, request)))

    @router.put('/{key}')
    def update(request: Request, key: str, body: OperatorSourceInput) -> dict[str, Any]:
        with _source_errors(), acting(sessions, request) as db:
            return asdict(services.update_operator_source(db, key, body, max_tlp=write_limit(app, request)))

    @router.delete('/{key}')
    def delete(request: Request, key: str) -> dict[str, str]:
        with _source_errors(), acting(sessions, request) as db:
            services.delete_operator_source(db, key, max_tlp=write_limit(app, request))
        return {'deleted': key}

    @router.put('/{key}/switch')
    def switch(request: Request, key: str, body: OperatorSourceSwitchInput) -> dict[str, Any]:
        with _source_errors(), acting(sessions, request) as db:
            return asdict(
                services.set_operator_source_enabled(db, key, body.enabled, max_tlp=write_limit(app, request))
            )

    app.include_router(router)
