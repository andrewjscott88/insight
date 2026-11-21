"""Manual GreyNoise Community lookups of explicitly reviewed IPv4 indicators."""

from __future__ import annotations

import asyncio
import json
import math
import os
import re
import threading
from datetime import UTC, date, datetime, timedelta
from email.utils import parsedate_to_datetime
from typing import Any, Final

import httpx

from . import services
from .connectors import ProviderError, download
from .lookups import THROTTLES
from .models import SessionFactory

_HOST: Final = 'api.greynoise.io'
_TTL: Final = timedelta(days=1)
_BUSY: Final = threading.Lock()


class NotConfigured(ValueError):
    pass


class RateLimited(Exception):
    def __init__(self, wait: float) -> None:
        self.seconds = max(1, math.ceil(wait))
        super().__init__(f'GreyNoise lookup limit reached. Try again in {self.seconds} seconds.')


def _key() -> str:
    value = os.environ.get('INSIGHT_GREYNOISE_KEY', '')
    return value if re.fullmatch(r'[!-~]{1,512}', value) else ''


def configured() -> bool:
    return bool(_key())


def _retry_after(value: str) -> int:
    if re.fullmatch(r'[0-9]{1,10}', value):
        return max(1, int(value))
    try:
        end = parsedate_to_datetime(value)
        return max(1, math.ceil((end - datetime.now(UTC)).total_seconds()))
    except (ValueError, TypeError, OverflowError):
        return 24 * 60 * 60


def _parse(raw: bytes, ip: str) -> dict[str, Any]:
    try:
        data = json.loads(raw)
        if not isinstance(data, dict) or data.get('ip') != ip:
            raise ValueError
        noise, riot, classification = data['noise'], data['riot'], data['classification']
        if type(noise) is not bool or type(riot) is not bool:
            raise ValueError
        if classification not in ('benign', 'suspicious', 'malicious', 'unknown'):
            raise ValueError
        name, last_seen = data.get('name'), data.get('last_seen')
        if name is not None and (not isinstance(name, str) or len(name) > 256 or not name.isprintable()):
            raise ValueError
        if last_seen is not None and (
            not isinstance(last_seen, str) or date.fromisoformat(last_seen).isoformat() != last_seen
        ):
            raise ValueError
    except (KeyError, RecursionError, ValueError, TypeError):
        raise ProviderError('GreyNoise returned invalid Community IP context') from None
    return {
        'found': True,
        'classification': classification,
        'noise': noise,
        'riot': riot,
        'name': name,
        'last_seen': last_seen,
    }


async def _fetch(value: str, key: str) -> dict[str, Any]:
    try:
        raw = await download(
            f'https://{_HOST}/v3/community/{value}', headers={'key': key}, allowed_hosts=frozenset({_HOST})
        )
    except httpx.HTTPStatusError as exc:
        code = exc.response.status_code
        if code == 404:
            return {'found': False}
        if code == 429:
            wait = _retry_after(exc.response.headers.get('Retry-After', ''))
            THROTTLES['greynoise'].defer(wait)
            raise RateLimited(wait) from None
        hint = ' Check INSIGHT_GREYNOISE_KEY.' if code in (401, 403) else ''
        raise ProviderError(f'GreyNoise returned HTTP {code}.{hint}') from None
    except (httpx.HTTPError, OSError, ValueError):
        raise ProviderError('GreyNoise request failed its connection, redirect or response limits') from None
    return _parse(raw, value)


async def lookup(sessions: SessionFactory, value: str, *, actor: str) -> dict[str, Any]:
    """Share only a public IPv4. Cache positive/negative answers for a day, rechecking current eligibility."""
    if not (key := _key()):
        raise NotConfigured('Set INSIGHT_GREYNOISE_KEY on the host to enable GreyNoise Community lookups')

    def read() -> dict[str, Any] | None:
        with sessions() as db:
            return services.cached_greynoise_context(db, value)

    acquired = _BUSY.acquire(blocking=False)
    try:
        found = await asyncio.to_thread(read)
        if found and datetime.fromisoformat(found['fetched_at']) > datetime.now(UTC) - _TTL:
            return found
        if not acquired:
            raise RateLimited(1)
        if wait := THROTTLES['greynoise'].try_acquire():
            raise RateLimited(wait)
        payload = await _fetch(value, key)

        def save() -> dict[str, Any]:
            with sessions.begin() as db:
                services.set_actor(db, actor)
                return services.store_greynoise_context(db, value, payload)

        return await asyncio.to_thread(save)
    finally:
        if acquired:
            _BUSY.release()
