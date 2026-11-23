"""Read-only, authenticated hunt guide previews and downloads (ADR 0041)."""

from __future__ import annotations

import re
from dataclasses import asdict
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, FastAPI, HTTPException, Path, Query, Request
from fastapi.responses import Response

from ... import services
from ...hunt_guide import to_markdown, to_pdf
from ...models import SessionFactory
from ..auth import AuthDependency, acting, reader_limit


def _register_hunt_guide_routes(app: FastAPI, sessions: SessionFactory, require_auth: AuthDependency) -> None:
    router = APIRouter(dependencies=[Depends(require_auth)])

    @router.get('/api/hunt-guides')
    def choices(
        request: Request,
        kind: Annotated[str | None, Query(max_length=20)] = None,
        q: Annotated[str, Query(max_length=120)] = '',
    ) -> dict[str, list[tuple[str, str]]]:
        limit = services.stricter_limit(reader_limit(request), app.state.settings.max_tlp)
        with sessions() as db:
            try:
                return services.hunt_guide_choices(db, max_tlp=limit, kind=kind, q=q)
            except LookupError as exc:
                raise HTTPException(404, 'Hunt guide choice not found') from exc

    @router.get('/api/hunt-guides/{kind}/{ref}', response_model=None)
    def guide(
        request: Request,
        kind: Annotated[str, Path(max_length=20)],
        ref: Annotated[str, Path(max_length=128)],
        format: Literal['json', 'md', 'pdf'] = 'json',
    ) -> dict[str, Any] | Response:
        limit = services.stricter_limit(reader_limit(request), app.state.settings.max_tlp)
        with acting(sessions, request) as db:
            try:
                found = services.hunt_guide(db, kind, ref, max_tlp=limit)
            except LookupError as exc:
                raise HTTPException(404, 'Hunt guide choice not found') from exc
            services.audit(db, 'hunt.guide', found.ref, f'{found.kind}; {format}; TLP:{found.tlp}')
        if format == 'json':
            return asdict(found)
        filename = re.sub(r'[^a-zA-Z0-9_-]', '-', f'hunt-guide-{found.kind}-{found.ref}')
        return Response(
            to_pdf(found) if format == 'pdf' else to_markdown(found),
            media_type='application/pdf' if format == 'pdf' else 'text/markdown',
            headers={
                'Content-Disposition': f'attachment; filename="{filename}.{format}"',
                'Cache-Control': 'no-store',
            },
        )

    app.include_router(router)
