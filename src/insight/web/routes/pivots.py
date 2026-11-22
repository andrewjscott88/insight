"""Explicit infrastructure disclosures and read-only eligible cache views."""

from __future__ import annotations

from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Query, Request

from ... import pivots, services
from ...connectors import ProviderError
from ...models import SessionFactory
from ...schemas import PivotInput
from ..auth import AuthDependency, caller_of, reader_limit


def _register_pivot_routes(app: FastAPI, sessions: SessionFactory, require_auth: AuthDependency) -> None:
    @app.get('/api/pivots', dependencies=[Depends(require_auth)])
    def cached(request: Request, value: str = Query(min_length=1, max_length=253)) -> list[dict[str, Any]]:
        try:
            with sessions() as db:
                return services.cached_pivots(db, value, max_tlp=reader_limit(request))
        except LookupError:
            raise HTTPException(404, 'No eligible reviewed indicator') from None

    @app.post('/api/pivots/{provider}', dependencies=[Depends(require_auth)])
    async def lookup(request: Request, provider: str, payload: PivotInput) -> dict[str, Any]:
        caller = caller_of(request)
        if caller.kind == 'api_key' and (caller.access != 'read-write' or caller.max_tlp is not None):
            raise HTTPException(403, 'Lookups need a session or an unlimited read-write key')
        try:
            return await pivots.lookup(
                sessions,
                provider,
                payload.value,
                approved=payload.approved,
                actor=caller.actor,
                max_tlp=reader_limit(request),
            )
        except pivots.NotConfigured as exc:
            raise HTTPException(503, str(exc)) from None
        except LookupError:
            raise HTTPException(404, 'No eligible reviewed indicator') from None
        except pivots.RateLimited as exc:
            raise HTTPException(429, str(exc), headers={'Retry-After': str(exc.seconds)}) from None
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from None
        except ProviderError as exc:
            raise HTTPException(502, str(exc)) from None
