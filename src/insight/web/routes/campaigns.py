"""Analyst campaigns and explicit threat links."""

from __future__ import annotations

from dataclasses import asdict
from typing import Annotated, Any

from fastapi import APIRouter, Depends, FastAPI, HTTPException, Query, Request

from ... import services
from ...models import Campaign, SessionFactory
from ...schemas import CampaignInput, ThreatLinkInput, ThreatSubjectKind, ThreatTargetKind
from ..auth import AuthDependency, acting, reader_limit
from .threats import write_limit

Offset = Annotated[int, Query(ge=0)]
PageSize = Annotated[int, Query(ge=1, le=200)]


def _view(row: Campaign) -> dict[str, Any]:
    return {
        'id': row.id,
        'name': row.name,
        'aliases': row.aliases.splitlines(),
        'description': row.description,
        'tlp': row.tlp,
        'created_at': row.created_at,
        'created_by': row.actor,
    }


def _register_campaign_routes(app: FastAPI, sessions: SessionFactory, require_auth: AuthDependency) -> None:
    router = APIRouter(dependencies=[Depends(require_auth)])

    @router.get('/api/campaigns')
    def campaigns(request: Request, offset: Offset = 0, limit: PageSize = 100) -> dict[str, Any]:
        with sessions() as db:
            rows = services.list_campaigns(db, max_tlp=reader_limit(request), offset=offset, limit=limit)
            return {'campaigns': [_view(row) for row in rows]}

    @router.post('/api/campaigns', status_code=201)
    def create(request: Request, payload: CampaignInput) -> dict[str, Any]:
        try:
            with acting(sessions, request) as db:
                return _view(services.create_campaign(db, payload, max_tlp=write_limit(app, request)))
        except services.TlpNotPermitted as exc:
            raise HTTPException(403, str(exc)) from exc

    @router.get('/api/campaigns/{ref}')
    def campaign(request: Request, ref: str) -> dict[str, Any]:
        try:
            with sessions() as db:
                return _view(services.get_campaign(db, ref, max_tlp=reader_limit(request)))
        except LookupError as exc:
            raise HTTPException(404, str(exc)) from exc

    def register_links(kind: ThreatSubjectKind) -> None:
        path = f'/api/{kind}s/{{ref}}/links'

        @router.get(path)
        def links(request: Request, ref: str, offset: Offset = 0, limit: PageSize = 100) -> dict[str, Any]:
            try:
                with sessions() as db:
                    found = services.list_threat_links(
                        db, kind, ref, max_tlp=reader_limit(request), offset=offset, limit=limit
                    )
                    return {'links': [asdict(row) for row in found]}
            except LookupError as exc:
                raise HTTPException(404, str(exc)) from exc

        @router.post(path, status_code=201)
        def link(request: Request, ref: str, payload: ThreatLinkInput) -> dict[str, Any]:
            try:
                with acting(sessions, request) as db:
                    return asdict(
                        services.link_threat(db, kind, ref, payload, max_tlp=write_limit(app, request))
                    )
            except LookupError as exc:
                raise HTTPException(404, str(exc)) from exc
            except services.TlpNotPermitted as exc:
                raise HTTPException(403, str(exc)) from exc

        @router.delete(path + '/{target_kind}/{target_id}')
        def unlink(
            request: Request, ref: str, target_kind: ThreatTargetKind, target_id: str
        ) -> dict[str, str]:
            try:
                with acting(sessions, request) as db:
                    services.unlink_threat(
                        db, kind, ref, target_kind, target_id, max_tlp=write_limit(app, request)
                    )
            except LookupError as exc:
                raise HTTPException(404, str(exc)) from exc
            return {'removed': target_id}

    register_links('actor')
    register_links('campaign')
    app.include_router(router)
