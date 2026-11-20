"""Entities and pivots."""

from __future__ import annotations

from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Request

from ... import services
from ...models import SessionFactory
from ..auth import AuthDependency, reader_limit


def _register_entity_routes(app: FastAPI, sessions: SessionFactory, require_auth: AuthDependency) -> None:
    """Canonical indicators and their cross-report pivots."""

    @app.get('/api/entities', dependencies=[Depends(require_auth)])
    def entities(request: Request, q: str = '') -> list[dict[str, Any]]:
        with sessions() as db:
            return [
                {'id': e.id, 'kind': e.kind, 'value': e.value, 'document_count': count}
                for e, count in services.list_entities(db, q, max_tlp=reader_limit(request))
            ]

    @app.get('/api/entities/{entity_id}', dependencies=[Depends(require_auth)])
    def entity(request: Request, entity_id: str, offset: int = 0, limit: int = 100) -> dict[str, Any]:
        max_tlp = reader_limit(request)
        with sessions() as db:
            e = services.get_entity(db, entity_id)
            # An entity mentioned only in reports the caller cannot see does not exist for that caller.
            count = 0 if e is None else services.count_entity_documents(db, e.id, max_tlp=max_tlp)
            if e is None or (max_tlp is not None and count == 0):
                raise HTTPException(404, 'Entity not found')
            docs = services.entity_documents(db, e.id, offset=offset, limit=limit, max_tlp=max_tlp)
            return {
                'id': e.id,
                'kind': e.kind,
                'value': e.value,
                'document_count': count,
                'offset': max(0, offset),
                'documents': services.summaries(db, docs),
            }
