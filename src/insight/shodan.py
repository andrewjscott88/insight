"""Manual Shodan host lookups of explicitly reviewed public IPv4 indicators (TIP 3.7, ADR 0031).

Optional and paid: nothing runs without ``INSIGHT_SHODAN_KEY``, and nothing runs on a schedule. A host lookup
does not spend Shodan query credits, but plans differ in what they allow; refusals for the key, plan or
credits are shown as they are. Insight keeps only exposure metadata (open ports, host names, organisation,
network, country, operating system, tags, CVE IDs Shodan associates, last update), never service banners,
and labels it as Shodan's data, as Shodan's terms ask.
"""

from __future__ import annotations

import asyncio
import json
import logging
import math
import os
import re
import threading
from datetime import UTC, datetime, timedelta
from email.utils import parsedate_to_datetime
from typing import Any, Final

import httpx

from . import services
from .connectors import ProviderError, download
from .lookups import THROTTLES
from .models import SessionFactory

_HOST: Final = 'api.shodan.io'
_TTL: Final = timedelta(days=1)
_BUSY: Final = threading.Lock()
ATTRIBUTION: Final = 'Exposure data from Shodan (shodan.io).'
MAX_PORTS: Final = 100
_HOSTNAME = re.compile(r'(?=.{1,253}\Z)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,62}', re.I)
_TAG = re.compile(r'[a-z0-9][a-z0-9 _.-]{0,39}', re.I)
_CVE = re.compile(r'CVE-[0-9]{4}-[0-9]{4,7}')
_ASN = re.compile(r'AS[0-9]{1,10}')
_KEY_IN_URL = re.compile(r'([?&]key=)[^&\s"]+')


class _HideKey(logging.Filter):
    """httpx logs each request URL; Shodan's key travels in it, so never let it reach a log line."""

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.args, tuple) and record.args:
            record.args = tuple(
                _KEY_IN_URL.sub(r'\1[hidden]', str(a)) if _HOST in str(a) else a for a in record.args
            )
        record.msg = (
            _KEY_IN_URL.sub(r'\1[hidden]', str(record.msg)) if _HOST in str(record.msg) else record.msg
        )
        return True


_FILTER: Final = _HideKey()
for _name in ('httpx', 'httpcore'):
    if not any(isinstance(f, _HideKey) for f in logging.getLogger(_name).filters):
        logging.getLogger(_name).addFilter(_FILTER)


class NotConfigured(ValueError):
    pass


class RateLimited(Exception):
    def __init__(self, wait: float) -> None:
        self.seconds = max(1, math.ceil(wait))
        super().__init__(f'Shodan lookup limit reached. Try again in {self.seconds} seconds.')


def _key() -> str:
    value = os.environ.get('INSIGHT_SHODAN_KEY', '')
    return value if re.fullmatch(r'[A-Za-z0-9]{8,128}', value) else ''


def configured() -> bool:
    return bool(_key())


def _retry_after(value: str) -> int:
    if re.fullmatch(r'[0-9]{1,10}', value):
        return max(1, int(value))
    try:
        end = parsedate_to_datetime(value)
        return max(1, math.ceil((end - datetime.now(UTC)).total_seconds()))
    except (ValueError, TypeError, OverflowError):
        return 60


def _text(value: Any, limit: int = 256) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or len(value) > limit or not value.isprintable():
        raise ValueError
    return value or None


def _strings(value: Any, pattern: re.Pattern[str], limit: int) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise ValueError
    return sorted({v for v in value if isinstance(v, str) and pattern.fullmatch(v)})[:limit]


def _parse(raw: bytes, ip: str) -> dict[str, Any]:
    """Keep exposure metadata only; drop banners, raw data and anything unexpected."""
    try:
        data = json.loads(raw)
        if not isinstance(data, dict) or data.get('ip_str') != ip:
            raise ValueError
        ports_raw = data.get('ports', [])
        if not isinstance(ports_raw, list):
            raise ValueError
        ports = sorted({p for p in ports_raw if type(p) is int and 0 < p < 65536})
        vulns_raw = data.get('vulns')
        vulns = _strings(list(vulns_raw) if isinstance(vulns_raw, dict) else vulns_raw, _CVE, 100)
        asn = _text(data.get('asn'), 16)
        country = _text(data.get('country_code'), 2)
        last_update = _text(data.get('last_update'), 40)
        if last_update is not None:
            last_update = datetime.fromisoformat(last_update).date().isoformat()
        found = {
            'found': True,
            'ports': ports[:MAX_PORTS],
            'port_count': len(ports),
            'hostnames': _strings(data.get('hostnames'), _HOSTNAME, 20),
            'org': _text(data.get('org')),
            'isp': _text(data.get('isp')),
            'asn': asn if asn is None or _ASN.fullmatch(asn) else None,
            'country_code': country if country is None or re.fullmatch(r'[A-Z]{2}', country) else None,
            'os': _text(data.get('os'), 120),
            'tags': _strings(data.get('tags'), _TAG, 20),
            'vulns': vulns,
            'last_update': last_update,
        }
    except (KeyError, RecursionError, ValueError, TypeError):
        raise ProviderError('Shodan returned invalid host data') from None
    return found


async def _fetch(value: str, key: str) -> dict[str, Any]:
    try:
        raw = await download(
            f'https://{_HOST}/shodan/host/{value}',
            {'key': key, 'minify': 'true'},
            allowed_hosts=frozenset({_HOST}),
        )
    except httpx.HTTPStatusError as exc:
        code = exc.response.status_code
        if code == 404:
            return {'found': False}
        if code == 429:
            wait = _retry_after(exc.response.headers.get('Retry-After', ''))
            THROTTLES['shodan'].defer(wait)
            raise RateLimited(wait) from None
        if code == 401:
            raise ProviderError('Shodan refused the key (HTTP 401). Check INSIGHT_SHODAN_KEY.') from None
        if code in (402, 403):
            raise ProviderError(
                f'Shodan refused the lookup (HTTP {code}): your plan, credits or access do not allow it. '
                'Check your Shodan account.'
            ) from None
        raise ProviderError(f'Shodan returned HTTP {code}.') from None
    except (httpx.HTTPError, OSError, ValueError):
        # Never str(exc): httpx messages contain the request URL, and the key is in it.
        raise ProviderError('Shodan request failed its connection, redirect or response limits') from None
    return _parse(raw, value)


async def lookup(sessions: SessionFactory, value: str, *, actor: str) -> dict[str, Any]:
    """Share only a reviewed public IPv4. Cache answers (including "no record") for a day, rechecking
    eligibility on every read."""
    if not (key := _key()):
        raise NotConfigured('Set INSIGHT_SHODAN_KEY on the host to enable Shodan lookups')

    def fresh() -> dict[str, Any] | None:
        with sessions() as db:
            found = services.cached_ip_context(db, 'shodan', value)
        if found and datetime.fromisoformat(found['fetched_at']) > datetime.now(UTC) - _TTL:
            return found
        return None

    if cached := await asyncio.to_thread(fresh):
        return cached
    if not _BUSY.acquire(blocking=False):
        raise RateLimited(1)
    try:
        if cached := await asyncio.to_thread(fresh):
            return cached
        if wait := THROTTLES['shodan'].try_acquire():
            raise RateLimited(wait)
        payload = await _fetch(value, key)

        def save() -> dict[str, Any]:
            with sessions.begin() as db:
                services.set_actor(db, actor)
                return services.store_ip_context(db, 'shodan', value, payload)

        return await asyncio.to_thread(save)
    finally:
        _BUSY.release()
