"""Import local STIX and PDF files through a read-write key or the signed-in workspace."""

from __future__ import annotations

import base64
import json
from typing import Annotated, Any

from fastapi import Depends, FastAPI, HTTPException, Request
from sqlalchemy.exc import IntegrityError

from ... import services
from ...models import SessionFactory
from ...pdf_import import PdfUnavailable
from ..auth import AuthDependency, acting, reader_limit


async def _json_body(request: Request) -> bytes:
    if request.headers.get('content-type', '').split(';')[0].strip().lower() not in {
        'application/json',
        'application/stix+json',
    }:
        raise HTTPException(415, 'Send the STIX bundle as JSON')
    # BoundaryMiddleware enforces the byte limit while reading the body, including chunked uploads.
    return await request.body()


def _pdf_metadata(request: Request) -> dict[str, str]:
    # The file goes in the request body. Keep report titles and publisher URLs out of access-log URLs.
    encoded = request.headers.get('x-insight-document', '')
    if not encoded or len(encoded) > 16_384:
        raise HTTPException(400, 'Supply report metadata in X-Insight-Document')
    try:
        raw = base64.b64decode(encoded + '=' * (-len(encoded) % 4), altchars=b'-_', validate=True)
        if base64.urlsafe_b64encode(raw).rstrip(b'=').decode() != encoded:
            raise ValueError('Expected canonical base64url')
        pairs = json.loads(raw.decode('utf-8'), object_pairs_hook=lambda entries: entries)
        if not isinstance(pairs, list) or not all(
            isinstance(pair, tuple) and len(pair) == 2 and isinstance(pair[1], str) for pair in pairs
        ):
            raise ValueError('Expected a JSON object of strings')
        values: dict[str, str] = dict(pairs)
        if (
            len(values) != len(pairs)
            or not {'title', 'source_name'} <= values.keys()
            or values.keys() - {'title', 'source_name', 'source_url', 'tlp'}
        ):
            raise ValueError('Invalid metadata fields')
        # Reject escaped surrogate code points and nulls before they reach logs or database drivers.
        for value in values.values():
            value.encode('utf-8')
            if '\x00' in value:
                raise ValueError('Invalid metadata text')
        return values
    except (ValueError, RecursionError) as exc:
        raise HTTPException(
            400, 'X-Insight-Document must contain valid base64url-encoded report metadata'
        ) from exc


async def _pdf_body(request: Request) -> bytes:
    if request.headers.get('content-type', '').split(';')[0].strip().lower() != 'application/pdf':
        raise HTTPException(415, 'Send the original PDF bytes as application/pdf')
    return await request.body()


def _register_import_routes(app: FastAPI, sessions: SessionFactory, require_auth: AuthDependency) -> None:
    @app.post('/api/import/stix', dependencies=[Depends(require_auth)])
    def import_stix(request: Request, data: Annotated[bytes, Depends(_json_body)]) -> dict[str, Any]:
        limit = services.stricter_limit(app.state.settings.max_tlp, reader_limit(request))
        try:
            with acting(sessions, request) as db:
                return services.import_stix(db, data, max_tlp=limit or app.state.settings.max_tlp)
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
        except IntegrityError as exc:
            raise HTTPException(409, 'Concurrent import; retry once') from exc

    @app.post('/api/documents/pdf', dependencies=[Depends(require_auth)])
    def import_pdf(
        request: Request,
        metadata: Annotated[dict[str, str], Depends(_pdf_metadata)],
        data: Annotated[bytes, Depends(_pdf_body)],
    ) -> dict[str, Any]:
        limit = services.stricter_limit(app.state.settings.max_tlp, reader_limit(request))
        try:
            with acting(sessions, request) as db:
                return services.import_pdf(db, data, max_tlp=limit or app.state.settings.max_tlp, **metadata)
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
        except PdfUnavailable as exc:
            raise HTTPException(503, str(exc)) from exc
        except IntegrityError as exc:
            raise HTTPException(409, 'Concurrent import; retry once') from exc
