"""Sources, syncs, schedules, jobs and CVE enrichment."""

from __future__ import annotations

import time
from datetime import UTC, datetime
from typing import Annotated, Any, Final

from fastapi import Depends, FastAPI, HTTPException, Query, Request

from ... import services
from ...connectors import (
    ProviderError,
    SourceSwitchedOff,
    SourceSyncError,
    enrich_cve,
    sync_all,
    sync_source,
    validate_enrichment,
)
from ...models import SessionFactory
from ...schemas import (
    ScheduleInput,
)
from ...source_registry import SOURCES, in_use
from ..auth import AuthDependency, acting

ENRICHMENT_INTERVAL_SECONDS: Final = 6.5


def _register_source_routes(app: FastAPI, sessions: SessionFactory, require_auth: AuthDependency) -> None:
    """Curated connectors and their schedules. Sync is the only route besides enrichment that makes outbound
    requests; schedules make the job runner sync by itself (``insight.jobs``)."""

    @app.get('/api/sources', dependencies=[Depends(require_auth)])
    def sources() -> list[dict[str, Any]]:
        with sessions() as db:
            switches = services.source_switches(db)
            return [
                {
                    'key': s.key,
                    'name': s.name,
                    'url': s.url,
                    'note': s.note,
                    'category': s.category,
                    'optional': s.optional,
                    'reuse': s.reuse,
                    'in_use': in_use(s, switches),
                    'runs': [
                        {'status': r.status, 'message': r.message, 'created_at': r.created_at}
                        for r in services.recent_source_runs(db, s.key, limit=5)
                    ],
                }
                for s in SOURCES.values()
            ]

    @app.post('/api/sources/{key}/sync', dependencies=[Depends(require_auth)])
    async def sync(key: str) -> dict[str, str]:
        if key not in SOURCES:
            raise HTTPException(404, 'Unknown source')
        if app.state.sync_lock.locked():
            raise HTTPException(409, 'Another source job is running')
        async with app.state.sync_lock:
            try:
                return {'message': await sync_source(sessions, key)}
            except SourceSwitchedOff as exc:
                raise HTTPException(409, str(exc)) from exc
            except SourceSyncError as exc:
                raise HTTPException(502, str(exc)) from exc

    def schedule_view(key: str, schedule: Any) -> dict[str, Any]:
        on = schedule is not None and schedule.enabled
        return {
            'source_key': key,
            'interval_minutes': schedule.interval_minutes if on else 0,
            'next_run_at': schedule.next_run_at if on else None,
            'updated_at': schedule.updated_at if schedule is not None else None,
        }

    @app.get('/api/schedules', dependencies=[Depends(require_auth)])
    def schedules() -> list[dict[str, Any]]:
        """How often each source syncs by itself (0: only when asked, the default)."""
        with sessions() as db:
            stored = services.list_schedules(db)
        return [schedule_view(key, stored.get(key)) for key in SOURCES]

    @app.put('/api/schedules/{key}', dependencies=[Depends(require_auth)])
    def set_schedule(key: str, body: ScheduleInput, request: Request) -> dict[str, Any]:
        """Browser session only (see ``SESSION_ONLY_WRITE_PREFIXES``); audited as ``schedule.update``."""
        if key not in SOURCES:
            raise HTTPException(404, 'Unknown source')
        try:
            now = datetime.now(UTC)
            starts_at = services.time_of_day(body.at, now) if body.at else None
            with acting(sessions, request) as db:
                if body.interval_minutes and not in_use(SOURCES[key], services.source_switches(db)):
                    raise HTTPException(409, f'{SOURCES[key].name} is switched off. Switch it on first.')
                schedule = services.set_schedule(db, key, body.interval_minutes, at=now, starts_at=starts_at)
                return schedule_view(key, schedule)
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc

    @app.get('/api/jobs', dependencies=[Depends(require_auth)])
    def jobs(limit: Annotated[int, Query(ge=1, le=100)] = 20) -> list[dict[str, Any]]:
        """Recent background jobs (scheduled syncs), newest first."""
        with sessions() as db:
            return [
                {
                    'id': j.id,
                    'kind': j.kind,
                    'key': j.key,
                    'status': j.status,
                    'attempts': j.attempts,
                    'run_after': j.run_after,
                    'started_at': j.started_at,
                    'finished_at': j.finished_at,
                    'message': j.message,
                    'actor': j.actor,
                    'created_at': j.created_at,
                }
                for j in services.recent_jobs(db, limit)
            ]

    @app.post('/api/sources/sync-all', dependencies=[Depends(require_auth)])
    async def sync_every_source() -> dict[str, list[dict[str, str]]]:
        """Every source in turn; one failing source does not stop the rest (each result says how it went)."""
        if app.state.sync_lock.locked():
            raise HTTPException(409, 'Another source job is running')
        async with app.state.sync_lock:
            results = await sync_all(sessions)
        return {
            'results': [
                {'key': r.key, 'name': r.name, 'status': 'success' if r.ok else 'error', 'message': r.message}
                for r in results
            ]
        }


def _register_enrichment_route(app: FastAPI, sessions: SessionFactory, require_auth: AuthDependency) -> None:
    """Explicit, globally throttled CVE lookups (sends only the CVE identifier to the provider)."""

    @app.post('/api/enrichment/{provider}/{cve}', dependencies=[Depends(require_auth)])
    async def enrich(provider: str, cve: str) -> dict[str, Any]:
        try:
            # Reject bad input and CVEs no report mentions before they consume the throttle window.
            await validate_enrichment(sessions, cve, provider)
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc
        if time.monotonic() - app.state.last_lookup < ENRICHMENT_INTERVAL_SECONDS:
            raise HTTPException(429, 'Wait at least 6.5 seconds between enrichment requests')
        app.state.last_lookup = time.monotonic()
        try:
            return await enrich_cve(sessions, cve, provider)
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc
        except ProviderError as exc:
            raise HTTPException(502, str(exc)) from exc
        except Exception as exc:
            raise HTTPException(502, 'Provider request failed; retry later') from exc
