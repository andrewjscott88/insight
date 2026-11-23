"""Reader-filtered actor timeline, explicit campaign associations and public software Navigator layers."""

from __future__ import annotations

import json
from dataclasses import asdict
from datetime import UTC, datetime
from typing import Annotated, Any

from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response

from ... import services
from ...models import SessionFactory
from ...schemas import ActorCampaignInput
from ...software_navigator import software_navigator
from ...threat_library import library
from ..auth import AuthDependency, acting, reader_limit
from .threats import write_limit


def _register_actor_activity_routes(
    app: FastAPI, sessions: SessionFactory, require_auth: AuthDependency
) -> None:
    @app.get('/api/actors/{ref}/timeline', dependencies=[Depends(require_auth)])
    def timeline(
        request: Request,
        ref: str,
        days: Annotated[int, Query(ge=1, le=36500)] = 3650,
        limit: Annotated[int, Query(ge=1, le=200)] = 100,
    ) -> dict[str, Any]:
        with sessions() as db:
            try:
                result = services.actor_timeline(
                    db, ref, max_tlp=reader_limit(request), now=datetime.now(UTC), days=days, limit=limit
                )
            except LookupError as exc:
                raise HTTPException(404, 'Group not found') from exc
        return services.timeline_json(result)

    @app.get('/api/actors/{ref}/campaigns', dependencies=[Depends(require_auth)])
    def campaigns(request: Request, ref: str) -> dict[str, Any]:
        with sessions() as db:
            try:
                rows = services.actor_campaigns(db, ref, max_tlp=reader_limit(request))
            except LookupError as exc:
                raise HTTPException(404, 'Group not found') from exc
        return {'campaigns': [asdict(row) for row in rows]}

    @app.post('/api/actors/{ref}/campaigns', status_code=201, dependencies=[Depends(require_auth)])
    def link(request: Request, ref: str, payload: ActorCampaignInput) -> dict[str, str]:
        try:
            with acting(sessions, request) as db:
                row = services.link_actor_campaign(db, ref, payload, max_tlp=write_limit(app, request))
                return {'id': row.id, 'campaign_id': row.campaign_id, 'tlp': row.tlp}
        except LookupError as exc:
            raise HTTPException(404, 'Campaign association not found') from exc
        except services.TlpNotPermitted as exc:
            raise HTTPException(403, str(exc)) from exc

    @app.delete('/api/actors/{ref}/campaigns/{campaign_id}', dependencies=[Depends(require_auth)])
    def unlink(request: Request, ref: str, campaign_id: str) -> dict[str, str]:
        try:
            with acting(sessions, request) as db:
                services.unlink_actor_campaign(db, ref, campaign_id, max_tlp=write_limit(app, request))
        except LookupError as exc:
            raise HTTPException(404, 'Campaign association not found') from exc
        return {'unlinked': campaign_id}

    @app.get('/api/software/{software_id}/navigator', dependencies=[Depends(require_auth)])
    def navigator(request: Request, software_id: str) -> Response:
        try:
            layer = software_navigator(library(), software_id)
        except LookupError as exc:
            raise HTTPException(404, str(exc)) from exc
        sid = software_id.strip().upper()
        with acting(sessions, request) as db:
            services.audit(db, 'software.navigator', sid, 'TLP:CLEAR')
        return Response(
            json.dumps(layer),
            media_type='application/json',
            headers={'Content-Disposition': f'attachment; filename="insight-software-{sid}.json"'},
        )
