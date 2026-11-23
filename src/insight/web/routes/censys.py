"""Private, explicitly approved Censys host lookups; no automatic disclosure or public data serving."""

from __future__ import annotations

from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Request

from ... import censys, services
from ...connectors import ProviderError
from ...models import SessionFactory
from ...schemas import CensysLookupInput
from ..auth import AuthDependency, caller_of, reader_limit
from .threats import write_limit


def _register_censys_routes(app: FastAPI, sessions: SessionFactory, require_auth: AuthDependency) -> None:
    def private_only() -> None:
        if app.state.settings.dev_no_auth:
            raise HTTPException(
                503, 'Censys context needs private sign-in; turn off temporary open access first'
            )

    @app.get('/api/ips/{ip}/censys', dependencies=[Depends(require_auth)])
    def cached(request: Request, ip: str) -> dict[str, Any]:
        private_only()
        with sessions() as db:
            try:
                record = services.cached_censys_context(db, ip, max_tlp=reader_limit(request))
            except LookupError:
                record = None
        if record is None:
            raise HTTPException(404, 'No eligible cached Censys context')
        return {**record, 'attribution': censys.ATTRIBUTION}

    @app.post('/api/enrichment/censys/{ip}', dependencies=[Depends(require_auth)])
    async def lookup(request: Request, ip: str, payload: CensysLookupInput) -> dict[str, Any]:
        private_only()
        if not payload.approved:
            raise HTTPException(422, 'Approve sending this IP address to Censys first')
        try:
            record = await censys.lookup(
                sessions, ip, actor=caller_of(request).actor, approved=True, max_tlp=write_limit(app, request)
            )
        except censys.NotConfigured as exc:
            raise HTTPException(503, str(exc)) from None
        except LookupError as exc:
            raise HTTPException(404, str(exc)) from None
        except censys.RateLimited as exc:
            raise HTTPException(429, str(exc), headers={'Retry-After': str(exc.seconds)}) from None
        except ProviderError as exc:
            raise HTTPException(502, str(exc)) from None
        return {**record, 'attribution': censys.ATTRIBUTION}
