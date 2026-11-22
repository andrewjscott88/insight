"""One approved, globally throttled infrastructure lookup; never scheduled (ADR 0037)."""

from __future__ import annotations

import asyncio
import math
import threading
from typing import Any

import httpx

from . import passive_dns, pivot_data, services
from .connectors import ProviderError, download
from .lookups import THROTTLES
from .models import SessionFactory

_BUSY = {provider: threading.Lock() for provider in pivot_data.PROVIDERS}


class NotConfigured(ValueError):
    pass


class RateLimited(Exception):
    def __init__(self, seconds: float) -> None:
        self.seconds = max(1, math.ceil(seconds))
        super().__init__(f'Wait {self.seconds} seconds before another lookup at this provider.')


async def _request(
    url: str,
    provider: str,
    hosts: frozenset[str],
    params: dict[str, str] | None = None,
    *,
    headers: dict[str, str] | None = None,
) -> bytes:
    try:
        async with asyncio.timeout(30):
            return await download(
                url, params, headers=headers, allowed_hosts=hosts, max_bytes=pivot_data.MAX_BYTES
            )
    except httpx.HTTPStatusError as exc:
        if exc.response.status_code == 429:
            raw = exc.response.headers.get('Retry-After', '')
            delay = int(raw) if raw.isascii() and raw.isdecimal() and len(raw) <= 6 else 60
            THROTTLES[provider].defer(delay)
            raise RateLimited(delay) from None
        raise ProviderError(f'{pivot_data.PROVIDERS[provider]} refused the request.') from None
    except (httpx.HTTPError, OSError, ValueError, TimeoutError):
        raise ProviderError('The lookup failed its connection, redirect or response limits.') from None


async def _fetch(provider: str, value: str) -> dict[str, Any]:
    # Validate before attaching credentials; the value can never supply a path, query or another host.
    pivot_data.subject(value)
    if not passive_dns.configured():
        raise NotConfigured('Set the CIRCL passive DNS credentials on the server first.')
    try:
        raw = await _request(
            passive_dns.URL + value,
            provider,
            frozenset({passive_dns.HOST}),
            headers=passive_dns.request_headers(),
        )
        return passive_dns.parse(raw, value)
    except (KeyError, TypeError, ValueError, RecursionError, OverflowError, OSError, AttributeError):
        raise ProviderError('The provider returned invalid or unrelated infrastructure data.') from None


async def lookup(
    sessions: SessionFactory,
    provider: str,
    value: str,
    *,
    approved: bool,
    actor: str,
    max_tlp: str | None = None,
) -> dict[str, Any]:
    if provider not in pivot_data.PROVIDERS:
        raise ValueError('Unknown pivot provider')
    kind, _ = pivot_data.subject(value)
    if kind not in pivot_data.PROVIDER_KINDS[provider]:
        raise ValueError('This provider does not support this indicator type')

    def fresh() -> dict[str, Any] | None:
        with sessions() as db:
            if not services.pivot_switches(db)[provider]:
                raise NotConfigured('This provider is off. Turn it on in Settings first.')
            found = services.cached_pivots(db, value, max_tlp=max_tlp)
            return next((r for r in found if r['provider'] == provider), None)

    if cached := await asyncio.to_thread(fresh):
        return cached
    if not approved:
        raise ValueError('Approve sending this value to the provider for this lookup')
    if not _BUSY[provider].acquire(blocking=False):
        raise RateLimited(1)
    try:
        if cached := await asyncio.to_thread(fresh):
            return cached
        if wait := THROTTLES[provider].try_acquire():
            raise RateLimited(wait)

        def audit_attempt() -> None:
            with sessions.begin() as db:
                services.set_actor(db, actor)
                entity_id = services.eligible_pivot(db, value, max_tlp=max_tlp)
                if entity_id is None:
                    raise LookupError('No eligible reviewed indicator')
                if not services.pivot_switches(db)[provider]:
                    raise NotConfigured('This provider is off')
                services.audit(db, 'pivot.request', entity_id, provider)

        await asyncio.to_thread(audit_attempt)
        payload = await _fetch(provider, value)

        def save() -> dict[str, Any]:
            with sessions.begin() as db:
                services.set_actor(db, actor)
                return services.store_pivot(db, provider, value, payload, max_tlp=max_tlp)

        return await asyncio.to_thread(save)
    finally:
        _BUSY[provider].release()
