"""MITRE ATT&CK techniques: the catalog, tags on reports, what is trending, and an ATT&CK Navigator layer."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any

from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response

from ... import services
from ...attack import Technique, catalog, search, technique
from ...models import SessionFactory
from ...schemas import TechniqueInput
from ..auth import AuthDependency, acting, reader_limit

Days = Annotated[int, Query(ge=0, le=3650, description='Reports added in the last N days; 0 for all time')]


def technique_view(found: Technique) -> dict[str, Any]:
    return {
        'id': found.id,
        'name': found.full_name,
        'tactics': list(catalog().tactic_names(found)),
        'url': found.url,
    }


def tag_view(tag: services.TechniqueTag) -> dict[str, Any]:
    return {
        'id': tag.technique_id,
        'name': tag.name,
        'tactics': list(tag.tactics),
        'url': tag.url,
        'source': tag.source,
        'evidence': tag.evidence,
        'actor': tag.actor,
        'created_at': tag.created_at,
        'in_catalog': tag.in_catalog,
    }


def since(days: int) -> str | None:
    return services.stamp(datetime.now(UTC) - timedelta(days=days)) if days else None


def period(days: int) -> str:
    return f'last {days} days' if days else 'all time'


def _register_technique_routes(app: FastAPI, sessions: SessionFactory, require_auth: AuthDependency) -> None:
    """The ATT&CK catalog, per-report technique tags, the technique summary and its pivots."""

    @app.get('/api/attack/techniques', dependencies=[Depends(require_auth)])
    def techniques(q: Annotated[str, Query(max_length=100)] = '', limit: int = 50) -> dict[str, Any]:
        """Search the bundled Enterprise ATT&CK catalog by ID prefix or name."""
        found = search(q, limit=min(max(1, limit), 200))
        return {'version': catalog().version, 'techniques': [technique_view(t) for t in found]}

    @app.get('/api/attack/summary', dependencies=[Depends(require_auth)])
    def summary(request: Request, days: Days = 30) -> dict[str, Any]:
        """Techniques on current reports the caller may see, most reports first."""
        with sessions() as db:
            counts = services.technique_summary(db, max_tlp=reader_limit(request), since=since(days))
        rows = []
        for count in counts:
            found = technique(count.technique_id)
            view = technique_view(found) if found else {'id': count.technique_id, 'name': count.technique_id}
            rows.append({**view, 'reports': count.reports, 'last_seen_at': count.last_seen})
        return {'version': catalog().version, 'period': period(days), 'techniques': rows}

    @app.get('/api/attack/techniques/{technique_id}/documents', dependencies=[Depends(require_auth)])
    def technique_reports(
        request: Request, technique_id: str, days: Days = 0, offset: int = 0, limit: int = 25
    ) -> dict[str, Any]:
        """Current reports tagged with the technique, newest first (paginated)."""
        found = technique(technique_id)
        if found is None:
            raise HTTPException(404, 'Not a current ATT&CK technique')
        with sessions() as db:
            docs = services.technique_documents(
                db, found.id, max_tlp=reader_limit(request), since=since(days), offset=offset, limit=limit
            )
            return {
                **technique_view(found),
                'offset': max(0, offset),
                'documents': services.summaries(db, docs),
            }

    @app.get('/api/attack/navigator', dependencies=[Depends(require_auth)])
    def navigator(request: Request, days: Days = 30) -> Response:
        """An ATT&CK Navigator layer of the summary (each technique scored by its report count). Audited."""
        limit = reader_limit(request)
        with acting(sessions, request) as db:
            counts = services.technique_summary(db, max_tlp=limit, since=since(days))
            layer = services.navigator_layer(counts, period=period(days))
            detail = {'days': days, 'techniques': len(layer['techniques']), 'max_tlp': limit}
            services.audit(db, 'attack.navigator', 'techniques', json.dumps(detail, sort_keys=True))
        filename = f'insight-attack-layer-{days or "all"}d.json' if days else 'insight-attack-layer-all.json'
        return Response(
            json.dumps(layer, indent=2),
            media_type='application/json',
            headers={'Content-Disposition': f'attachment; filename="{filename}"'},
        )

    @app.get('/api/documents/{doc_id}/techniques', dependencies=[Depends(require_auth)])
    def report_techniques(request: Request, doc_id: str) -> list[dict[str, Any]]:
        with sessions() as db:
            try:
                tags = services.document_techniques(db, doc_id, max_tlp=reader_limit(request))
            except LookupError as exc:
                raise HTTPException(404, 'Report not found') from exc
        return [tag_view(tag) for tag in tags]

    @app.post('/api/documents/{doc_id}/techniques', dependencies=[Depends(require_auth)])
    def add_technique(request: Request, doc_id: str, payload: TechniqueInput) -> dict[str, Any]:
        """Tag a report with a technique (or restore one removed earlier). Audited as ``technique.tag``."""
        try:
            with acting(sessions, request) as db:
                tag = services.tag_technique(db, doc_id, payload.technique_id, max_tlp=reader_limit(request))
        except LookupError as exc:
            raise HTTPException(404, 'Report not found') from exc
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc
        return tag_view(tag)

    @app.delete('/api/documents/{doc_id}/techniques/{technique_id}', dependencies=[Depends(require_auth)])
    def remove_technique(request: Request, doc_id: str, technique_id: str) -> dict[str, str]:
        """Remove a technique from a report (later revisions keep it removed). Audited."""
        try:
            with acting(sessions, request) as db:
                services.untag_technique(db, doc_id, technique_id, max_tlp=reader_limit(request))
        except LookupError as exc:
            raise HTTPException(404, str(exc)) from exc
        return {'removed': technique_id.strip().upper()}
