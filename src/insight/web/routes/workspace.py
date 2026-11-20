"""Workspace read models: stats, the intel brief, watch terms and the audit log."""

from __future__ import annotations

from dataclasses import asdict
from datetime import UTC, datetime
from typing import Annotated, Any

from fastapi import Depends, FastAPI, Query, Request

from ... import services
from ...brief import DEFAULT_DAYS, MAX_DAYS, compose, window_start
from ...demo import seed
from ...models import SessionFactory
from ..auth import AuthDependency, acting, reader_limit


def _register_workspace_routes(app: FastAPI, sessions: SessionFactory, require_auth: AuthDependency) -> None:
    """Session token, counters, intel brief, demo data, audit log and watch terms."""

    @app.get('/api/session', dependencies=[Depends(require_auth)])
    def session_info(request: Request) -> dict[str, str]:
        return {'csrf_token': request.session['csrf']}

    @app.get('/api/stats', dependencies=[Depends(require_auth)])
    def stats(request: Request) -> dict[str, int]:
        with sessions() as db:
            return services.stats(db, max_tlp=reader_limit(request))

    @app.get('/api/brief', dependencies=[Depends(require_auth)])
    def brief(
        request: Request, days: Annotated[int, Query(ge=1, le=MAX_DAYS)] = DEFAULT_DAYS
    ) -> dict[str, Any]:
        """The intel brief for the last ``days`` days, from the reports this caller may see."""
        since = window_start(datetime.now(UTC), days)
        with sessions() as db:
            data = services.brief_data(db, since=since, max_tlp=reader_limit(request))
        return asdict(compose(data, days))

    @app.post('/api/demo', dependencies=[Depends(require_auth)])
    def demo(request: Request) -> dict[str, int]:
        with acting(sessions, request) as db:
            return {'created': seed(db)}

    @app.get('/api/audit', dependencies=[Depends(require_auth)])
    def events() -> list[dict[str, str]]:
        with sessions() as db:
            return [
                {
                    'action': e.action,
                    'object_id': e.object_id,
                    'detail': e.detail,
                    'actor': e.actor,
                    'created_at': e.created_at,
                }
                for e in services.audit_events(db)
            ]

    @app.get('/api/watch-terms', dependencies=[Depends(require_auth)])
    def watch_terms() -> list[dict[str, str]]:
        with sessions() as db:
            return [{'id': w.id, 'term': w.term} for w in services.list_watch_terms(db)]
