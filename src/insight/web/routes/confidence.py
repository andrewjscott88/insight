"""Source reliability, report credibility and indicator confidence (TIP 4.2, ADR 0033)."""

from __future__ import annotations

from dataclasses import asdict
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Request

from ... import services
from ...models import SessionFactory
from ...schemas import CredibilityInput, SourceRatingInput
from ..auth import AuthDependency, acting, reader_limit


def confidence_view(found: services.Confidence) -> dict[str, Any]:
    view = asdict(found)
    for source in view['sources']:
        source['reliability_label'] = services.RELIABILITY[source['reliability']]
    return view


def _register_confidence_routes(app: FastAPI, sessions: SessionFactory, require_auth: AuthDependency) -> None:
    auth = [Depends(require_auth)]

    @app.get('/api/source-ratings', dependencies=auth)
    def source_ratings(request: Request) -> dict[str, Any]:
        with sessions() as db:
            stats = services.source_statistics(db, max_tlp=reader_limit(request))
        return {
            'sources': [
                asdict(s) | {'reliability_label': services.RELIABILITY[s.reliability]} for s in stats
            ],
            'reliability': services.RELIABILITY,
            'credibility': services.CREDIBILITY,
        }

    @app.put('/api/source-ratings', dependencies=auth)
    def rate(request: Request, payload: SourceRatingInput) -> dict[str, Any]:
        # A grade applies to every report from the source, at every label: only unlimited callers set it.
        if reader_limit(request) is not None:
            raise HTTPException(403, 'Not available to TLP-limited API keys')
        with acting(sessions, request) as db:
            row = services.rate_source(db, payload)
            return {
                'source_name': row.source_name,
                'reliability': row.reliability,
                'half_life_days': row.half_life_days,
                'note': row.note,
                'updated_at': row.updated_at,
                'updated_by': row.actor,
            }

    @app.put('/api/documents/{doc_id}/credibility', dependencies=auth)
    def credibility(request: Request, doc_id: str, payload: CredibilityInput) -> dict[str, Any]:
        try:
            with acting(sessions, request) as db:
                doc = services.set_credibility(db, doc_id, payload, max_tlp=reader_limit(request))
                return {'id': doc.id, 'credibility': doc.credibility}
        except LookupError as exc:
            raise HTTPException(404, 'Document not found') from exc

    @app.get('/api/entities/{entity_id}/confidence', dependencies=auth)
    def confidence(request: Request, entity_id: str) -> dict[str, Any]:
        max_tlp = reader_limit(request)
        with sessions() as db:
            if services.get_entity(db, entity_id) is None or (
                max_tlp is not None and services.count_entity_documents(db, entity_id, max_tlp=max_tlp) == 0
            ):
                raise HTTPException(404, 'Entity not found')
            return confidence_view(services.indicator_confidence(db, entity_id, max_tlp=max_tlp))
