"""Sources, syncs, schedules, jobs and CVE enrichment."""

from __future__ import annotations

from dataclasses import asdict
from datetime import UTC, datetime
from typing import Annotated, Any, Final

from fastapi import Depends, FastAPI, HTTPException, Query, Request

from ... import greynoise, services
from ...connectors import (
    ProviderError,
    SourceSwitchedOff,
    SourceSyncError,
    sync_all,
    sync_source,
)
from ...lookups import NVD_INTERVAL, LookupThrottled, request_lookup
from ...models import SessionFactory
from ...schemas import (
    ScheduleInput,
)
from ...source_registry import SOURCES, in_use
from ..auth import AuthDependency, acting, caller_of, reader_limit
from .cves import exploit_view

#: The NVD window without an API key (kept for scripts that read it; ``insight.lookups`` owns the throttles).
ENRICHMENT_INTERVAL_SECONDS: Final = NVD_INTERVAL


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

    @app.get('/api/ips/{ip}/greynoise', dependencies=[Depends(require_auth)])
    def grey_cached(ip: str) -> dict[str, Any]:
        with sessions() as db:
            try:
                record = services.cached_greynoise_context(db, ip)
            except LookupError:
                record = None
        if record is None:
            raise HTTPException(404, 'No eligible cached GreyNoise context')
        return record

    @app.post('/api/enrichment/greynoise/{ip}', dependencies=[Depends(require_auth)])
    async def grey_lookup(request: Request, ip: str) -> dict[str, Any]:
        try:
            return await greynoise.lookup(sessions, ip, actor=caller_of(request).actor)
        except greynoise.NotConfigured as exc:
            raise HTTPException(503, str(exc)) from None
        except LookupError as exc:
            raise HTTPException(404, str(exc)) from None
        except greynoise.RateLimited as exc:
            raise HTTPException(429, str(exc), headers={'Retry-After': str(exc.seconds)}) from None
        except ProviderError as exc:
            raise HTTPException(502, str(exc)) from None

    @app.post('/api/enrichment/{provider}/{cve}', dependencies=[Depends(require_auth)])
    async def enrich(provider: str, cve: str) -> dict[str, Any]:
        """Look ``cve`` up now. Invalid input and CVEs no report mentions are refused before they use the
        provider's throttle window, which the workspace and automatic lookups share (review B2)."""
        try:
            return await request_lookup(sessions, cve, provider)
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc
        except LookupThrottled as exc:
            raise HTTPException(429, str(exc), headers={'Retry-After': str(max(1, round(exc.wait)))}) from exc
        except ProviderError as exc:
            raise HTTPException(502, str(exc)) from exc
        except Exception as exc:
            raise HTTPException(502, 'Provider request failed; retry later') from exc

    # Not under /api/enrichment/: TLP-limited keys may read scores of CVEs in reports they can see, but
    # not start lookups (which would name CVEs from any report to a provider).
    @app.get('/api/cves/{cve}/scores', dependencies=[Depends(require_auth)])
    def cached_scores(request: Request, cve: str) -> dict[str, Any]:
        """The cached NVD, EPSS and VulnCheck KEV answers for ``cve``, plus exploit signals from reports the
        caller may see (never contacts a provider). ``404`` unless a report the caller may see mentions it."""
        try:
            with sessions() as db:
                found = services.cve_score_view(db, cve, max_tlp=reader_limit(request))
                exploit = services.exploit_context(db, [found.cve], max_tlp=reader_limit(request)).get(
                    found.cve
                )
        except LookupError as exc:
            raise HTTPException(404, 'No report you can see mentions this CVE') from exc
        return {**asdict(found), 'exploit': exploit_view(exploit)}
