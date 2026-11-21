"""CVE lookups at NIST NVD and FIRST EPSS: one throttle for everyone, people's lookups and automatic ones.

**One throttle per provider** (review B2), shared by the API, the workspace and the job runner in this
process: NVD allows 5 requests in 30 seconds without a key (one every 6.5 s here) and 50 with one
(``INSIGHT_NVD_API_KEY``: one every 0.7 s); EPSS gets one request a second. A person's lookup that would break
the window is refused (:class:`LookupThrottled`); an automatic one waits its turn.

**Automatic lookups** (ADR 0023) run as ``lookup`` jobs, queued by ``services.enqueue_due_lookups`` for the
CVEs that ``services.cves_to_look_up`` names. EPSS answers up to 100 CVEs in one request; NVD one at a time,
10 per job, so a backlog never blocks syncs for long. Each answer is cached as soon as it arrives. Only CVE
numbers are sent, never report text.
"""

from __future__ import annotations

import asyncio
import math
import os
import time
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any, Final

from . import services
from .brief import count_of
from .connectors import (
    CVE_RE,
    ProviderError,
    enrich_cve,
    fetch_provider_json,
    store_enrichment,
    validate_enrichment,
)
from .models import SessionFactory

NVD_INTERVAL: Final = 6.5
NVD_KEYED_INTERVAL: Final = 0.7
EPSS_INTERVAL: Final = 1.0
#: CVEs per automatic lookup job.
BATCH: Final[dict[str, int]] = {'epss': 100, 'nvd': 10}
NAMES: Final[dict[str, str]] = {'epss': 'FIRST EPSS', 'nvd': 'NIST NVD'}


class Throttle:
    """At most one request every ``interval`` seconds."""

    def __init__(self, interval: float, clock: Callable[[], float] = time.monotonic) -> None:
        self.interval = interval
        self._clock = clock
        self._last = -math.inf

    def wait_time(self) -> float:
        return max(0.0, self._last + self.interval - self._clock())

    def try_acquire(self) -> float:
        """Take the window and return 0, or return how many seconds are left (taking nothing)."""
        if (wait := self.wait_time()) > 0:
            return wait
        self._last = self._clock()
        return 0.0

    async def acquire(self) -> None:
        """Reserve the next window, then wait for it (callers that arrive meanwhile queue behind it)."""
        now = self._clock()
        slot = max(now, self._last + self.interval)
        self._last = slot
        if slot > now:
            await asyncio.sleep(slot - now)

    def reset(self) -> None:
        self._last = -math.inf


def nvd_interval() -> float:
    return NVD_KEYED_INTERVAL if os.environ.get('INSIGHT_NVD_API_KEY', '').strip() else NVD_INTERVAL


#: The process-wide throttles. One worker per instance (the runbook's rule), so one set.
THROTTLES: Final[dict[str, Throttle]] = {'nvd': Throttle(nvd_interval()), 'epss': Throttle(EPSS_INTERVAL)}


class LookupThrottled(Exception):
    """A person's lookup came too soon after the last one at the same provider."""

    def __init__(self, provider: str, wait: float) -> None:
        self.wait = wait
        name = NAMES.get(provider, provider)
        super().__init__(
            f'Wait {math.ceil(wait)} more second(s) before the next lookup at {name}. '
            'Insight may also be looking CVEs up by itself.'
        )


async def request_lookup(session_factory: SessionFactory, cve: str, provider: str) -> dict[str, Any]:
    """A person's lookup of ``cve`` at ``provider``: checked first (a refused request uses no window), then
    throttled. Raises ``ValueError``, :class:`LookupThrottled` or ``connectors.ProviderError``."""
    await validate_enrichment(session_factory, cve, provider)
    if wait := THROTTLES[provider].try_acquire():
        raise LookupThrottled(provider, wait)
    return await enrich_cve(session_factory, cve, provider)


def _answered(session_factory: SessionFactory, provider: str, cve: str, payload: dict[str, Any]) -> None:
    store_enrichment(session_factory, cve, provider, payload)
    with session_factory.begin() as db:
        services.clear_lookup_failure(db, provider, cve)


def _failed(session_factory: SessionFactory, provider: str, cve: str, message: str, at: datetime) -> None:
    with session_factory.begin() as db:
        services.record_lookup_failure(db, provider, cve, message, at=at)


def _due(session_factory: SessionFactory, provider: str, at: datetime) -> list[str]:
    with session_factory() as db:
        cves = services.cves_to_look_up(db, provider, at=at, limit=BATCH[provider])
    return [cve for cve in cves if CVE_RE.fullmatch(cve)]


async def look_up_due(
    session_factory: SessionFactory,
    provider: str,
    *,
    clock: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> str:
    """Look up the CVEs due at ``provider`` (one batch) and cache each answer. Raises ``ProviderError``."""
    if provider not in BATCH:
        raise ValueError(f'Unknown provider {provider!r}')
    cves = await asyncio.to_thread(_due, session_factory, provider, clock())
    if not cves:
        return f'No CVEs due at {NAMES[provider]}.'
    if provider == 'epss':
        await THROTTLES['epss'].acquire()
        payload = await fetch_provider_json('epss', {'cve': ','.join(cves)})
        rows = {r.get('cve'): r for r in payload.get('data') or [] if isinstance(r, dict)}
        envelope: dict[str, Any] = {
            k: payload[k] for k in ('status', 'status-code', 'version') if k in payload
        }
        for cve in cves:  # A CVE missing from the answer has no score yet; caching that avoids asking daily.
            answer = {
                **envelope,
                'total': 1 if cve in rows else 0,
                'data': [rows[cve]] if cve in rows else [],
            }
            await asyncio.to_thread(store_enrichment, session_factory, cve, 'epss', answer)
    else:
        # One CVE the provider cannot answer for is set aside with a growing wait and the others go on
        # (review M2); a problem with the provider itself (network, rate limit, key) stops the job.
        failed: list[str] = []
        for cve in cves:
            await THROTTLES['nvd'].acquire()
            try:
                payload = await fetch_provider_json('nvd', {'cveId': cve})
            except ProviderError as exc:
                if exc.provider_wide:
                    raise
                await asyncio.to_thread(_failed, session_factory, 'nvd', cve, str(exc), clock())
                failed.append(cve)
                continue
            await asyncio.to_thread(_answered, session_factory, 'nvd', cve, payload)
        if failed and len(failed) == len(cves):
            raise ProviderError(
                f'{NAMES[provider]} could not answer for any of {count_of(len(cves), "CVE")}.'
            )
        if failed:
            looked_up = count_of(len(cves) - len(failed), 'CVE')
            return (
                f'Looked up {looked_up} at {NAMES[provider]}; '
                f'{count_of(len(failed), "CVE")} could not be answered and will be tried again later.'
            )
    return f'Looked up {count_of(len(cves), "CVE")} at {NAMES[provider]}.'
