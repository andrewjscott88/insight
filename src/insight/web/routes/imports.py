"""Import a bounded STIX 2.1 JSON file through a read-write key or the signed-in workspace."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import Depends, FastAPI, HTTPException, Request
from pydantic import ValidationError
from sqlalchemy.exc import IntegrityError

from ... import services
from ...models import SessionFactory
from ..auth import AuthDependency, acting, reader_limit


async def _json_body(request: Request) -> bytes:
    if request.headers.get('content-type', '').split(';')[0].strip().lower() not in {
        'application/json',
        'application/stix+json',
    }:
        raise HTTPException(415, 'Send the STIX bundle as JSON')
    # BoundaryMiddleware enforces the byte limit while reading the body, including chunked uploads.
    return await request.body()


def _register_import_routes(app: FastAPI, sessions: SessionFactory, require_auth: AuthDependency) -> None:
    @app.post('/api/import/stix', dependencies=[Depends(require_auth)])
    def import_stix(request: Request, data: Annotated[bytes, Depends(_json_body)]) -> dict[str, Any]:
        limit = services.stricter_limit(app.state.settings.max_tlp, reader_limit(request))
        try:
            with acting(sessions, request) as db:
                return services.import_stix(db, data, max_tlp=limit or app.state.settings.max_tlp)
        except ValidationError as exc:
            raise HTTPException(
                400, 'STIX report metadata exceeds a limit or contains an invalid value'
            ) from exc
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
        except IntegrityError as exc:
            raise HTTPException(409, 'Concurrent import; retry once') from exc
