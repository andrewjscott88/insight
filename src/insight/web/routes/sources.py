"""Sources, syncs, schedules, jobs and CVE enrichment."""

from __future__ import annotations

from dataclasses import asdict
from datetime import UTC, datetime
from typing import Annotated, Any, Final

from fastapi import Depends, FastAPI, HTTPException, Query, Request

from ... import greynoise, services, shodan
from ...connectors import (
    ProviderError,
    SourceSwitchedOff,
    SourceSyncError,
    sync_all,
    sync_source,
)
from ...lookups import NVD_INTERVAL, LookupThrottled, request_lookup
from ...models import SessionFactory
from ...operator_feed import SourceNotConfigured
from ...schemas import (
    ScheduleInput,
)
from ...source_registry import SOURCES, in_use, is_operator_source
from ...taxii_client import TaxiiNotConfigured
from ..auth import AuthDependency, acting, caller_of, reader_limit
from .cves import exploit_view
from .threats import write_limit

#: The NVD window without an API key (kept for scripts that read it; ``insight.lookups`` owns the throttles).
ENRICHMENT_INTERVAL_SECONDS: Final = NVD_INTERVAL


def _history_message(source_key: str, message: str, max_tlp: str | None) -> str:
    # One permitted subscription can contain reports above the reader's ceiling.
    return '' if max_tlp is not None and is_operator_source(source_key) else message


def _register_source_routes(app: FastAPI, sessions: SessionFactory, require_auth: AuthDependency) -> None:
    """Curated connectors and their schedules. Sync is the only route besides enrichment that makes outbound
    requests; schedules make the job runner sync by itself (``insight.jobs``)."""

    @app.get('/api/sources', dependencies=[Depends(require_auth)])
    def sources(request: Request) -> list[dict[str, Any]]:
        with sessions() as db:
            switches = services.source_switches(db)
            limit = reader_limit(request)

            def runs(key: str) -> list[dict[str, str]]:
                return [
                    {
                        'status': r.status,
                        'message': _history_message(key, r.message, limit),
                        'created_at': r.created_at,
                    }
                    for r in services.recent_source_runs(db, key, limit=5, max_tlp=limit)
                ]

            curated = [
                {
                    'key': s.key,
                    'name': s.name,
                    'url': s.url,
                    'note': s.note,
                    'category': s.category,
                    'optional': s.optional,
                    'reuse': s.reuse,
                    'in_use': in_use(s, switches),
                    'runs': runs(s.key),
                }
                for s in SOURCES.values()
            ]
            return curated + [
                {
                    'key': row.key,
                    'name': row.name,
                    'url': row.url,
                    'note': '',
                    'category': 'operator',
                    'optional': True,
                    'reuse': row.reuse,
                    'tlp': row.tlp,
                    'in_use': row.enabled,
                    'kind': row.kind,
                    'configured': row.configured,
                    'runs': runs(row.key),
                }
                for row in services.list_operator_sources(db, max_tlp=limit)
            ]

    @app.post('/api/sources/{key}/sync', dependencies=[Depends(require_auth)])
    async def sync(request: Request, key: str) -> dict[str, str]:
        if key not in SOURCES:
            if reader_limit(request) is not None:
                raise HTTPException(403, 'A TLP-limited key cannot start operator source syncs')
            try:
                with sessions() as db:
                    services.get_operator_source(db, key, max_tlp=write_limit(app, request))
            except LookupError:
                raise HTTPException(404, 'Unknown source') from None
        if app.state.sync_lock.locked():
            raise HTTPException(409, 'Another source job is running')
        async with app.state.sync_lock:
            try:
                result = await sync_source(
                    sessions, key, max_tlp=write_limit(app, request), actor=caller_of(request).actor
                )
                return {'message': result}
            except LookupError:
                raise HTTPException(404, 'Unknown source') from None
            except SourceSwitchedOff as exc:
                raise HTTPException(409, str(exc)) from exc
            except SourceNotConfigured:
                raise HTTPException(503, 'Source credentials are not configured.') from None
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
    def schedules(request: Request) -> list[dict[str, Any]]:
        """How often each source syncs by itself (0: only when asked, the default)."""
        with sessions() as db:
            stored = services.list_schedules(db)
            operator = services.list_operator_sources(db, max_tlp=reader_limit(request))
            return [schedule_view(key, stored.get(key)) for key in [*SOURCES, *(s.key for s in operator)]]

    @app.put('/api/schedules/{key}', dependencies=[Depends(require_auth)])
    def set_schedule(key: str, body: ScheduleInput, request: Request) -> dict[str, Any]:
        """Browser session only (see ``SESSION_ONLY_WRITE_PREFIXES``); audited as ``schedule.update``."""
        try:
            now = datetime.now(UTC)
            starts_at = services.time_of_day(body.at, now) if body.at else None
            with acting(sessions, request) as db:
                if key in SOURCES:
                    enabled = in_use(SOURCES[key], services.source_switches(db))
                else:
                    enabled = services.get_operator_source(
                        db, key, lock=True, max_tlp=write_limit(app, request)
                    ).enabled
                if body.interval_minutes and not enabled:
                    raise HTTPException(409, 'Source is switched off. Switch it on first.')
                schedule = services.set_schedule(
                    db,
                    key,
                    body.interval_minutes,
                    at=now,
                    starts_at=starts_at,
                    max_tlp=write_limit(app, request),
                )
                return schedule_view(key, schedule)
        except TaxiiNotConfigured:
            raise HTTPException(503, 'Source credentials are not configured.') from None
        except LookupError:
            raise HTTPException(404, 'Unknown source') from None
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc

    @app.get('/api/jobs', dependencies=[Depends(require_auth)])
    def jobs(request: Request, limit: Annotated[int, Query(ge=1, le=100)] = 20) -> list[dict[str, Any]]:
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
                    'message': _history_message(j.key, j.message, reader_limit(request))
                    if j.kind == services.SOURCE_SYNC
                    else j.message,
                    'actor': j.actor,
                    'created_at': j.created_at,
                }
                for j in services.recent_jobs(db, limit, max_tlp=reader_limit(request))
            ]

    @app.post('/api/sources/sync-all', dependencies=[Depends(require_auth)])
    async def sync_every_source(request: Request) -> dict[str, list[dict[str, str]]]:
        """Every source in turn; one failing source does not stop the rest (each result says how it went)."""
        if reader_limit(request) is not None:
            raise HTTPException(403, 'A TLP-limited key cannot start sync-all')
        if app.state.sync_lock.locked():
            raise HTTPException(409, 'Another source job is running')
        async with app.state.sync_lock:
            results = await sync_all(
                sessions, max_tlp=write_limit(app, request), actor=caller_of(request).actor
            )
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

    @app.get('/api/ips/{ip}/shodan', dependencies=[Depends(require_auth)])
    def shodan_cached(ip: str) -> dict[str, Any]:
        """The last cached Shodan answer (TIP 3.7), without contacting Shodan."""
        with sessions() as db:
            try:
                record = services.cached_ip_context(db, 'shodan', ip)
            except LookupError:
                record = None
        if record is None:
            raise HTTPException(404, 'No eligible cached Shodan context')
        return {**record, 'attribution': shodan.ATTRIBUTION}

    @app.post('/api/enrichment/shodan/{ip}', dependencies=[Depends(require_auth)])
    async def shodan_lookup(request: Request, ip: str) -> dict[str, Any]:
        """Approve one Shodan host lookup (TIP 3.7); disabled without ``INSIGHT_SHODAN_KEY``."""
        try:
            found = await shodan.lookup(sessions, ip, actor=caller_of(request).actor)
        except shodan.NotConfigured as exc:
            raise HTTPException(503, str(exc)) from None
        except LookupError as exc:
            raise HTTPException(404, str(exc)) from None
        except shodan.RateLimited as exc:
            raise HTTPException(429, str(exc), headers={'Retry-After': str(exc.seconds)}) from None
        except ProviderError as exc:
            raise HTTPException(502, str(exc)) from None
        return {**found, 'attribution': shodan.ATTRIBUTION}

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
