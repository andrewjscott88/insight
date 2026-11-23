"""Approved single-host Censys Platform v3 lookups; bounded metadata, no scans or bulk searches."""

from __future__ import annotations

import asyncio
import ipaddress
import json
import math
import os
import re
import threading
from datetime import UTC, datetime, timedelta
from email.utils import parsedate_to_datetime
from typing import Any, Final
from urllib.parse import quote
from uuid import UUID

import httpx

from . import services
from .connectors import ProviderError, download
from .lookups import THROTTLES
from .models import SessionFactory

HOST: Final = 'api.platform.censys.io'
ATTRIBUTION: Final = 'Infrastructure data from Censys (censys.com). For your permitted internal use.'
MAX_BYTES: Final = 1_000_000
MAX_SERVICES: Final = 100
_TTL: Final = timedelta(hours=24)
_BUSY: Final = threading.Lock()
_NAME = re.compile(r'(?=.{1,253}\Z)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,62}', re.I)
_FIELDS: Final = (
    'ip,dns.names,autonomous_system.asn,autonomous_system.name,autonomous_system.bgp_prefix,'
    'location.country_code,services.port,services.protocol,services.transport_protocol,services.scan_time'
)


class NotConfigured(ValueError):
    pass


class RateLimited(Exception):
    def __init__(self, wait: float) -> None:
        self.seconds = max(1, math.ceil(wait))
        super().__init__(f'Censys lookup limit reached. Try again in {self.seconds} seconds.')


def _credentials() -> tuple[str, str]:
    token = os.environ.get('INSIGHT_CENSYS_PAT', '').strip()
    organization = os.environ.get('INSIGHT_CENSYS_ORG_ID', '').strip()
    if not re.fullmatch(r'[A-Za-z0-9_.~-]{8,512}', token):
        return '', ''
    if organization:
        try:
            organization = str(UUID(organization))
        except ValueError:
            return '', ''
    return token, organization


def configured() -> bool:
    return bool(_credentials()[0])


def _text(value: Any, cap: int = 256) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or len(value) > cap or not value.isprintable():
        raise ValueError
    return value or None


def _object(value: Any) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ValueError
    return value


def _parse(raw: bytes, ip: str) -> dict[str, Any]:
    """Discard contact details, banners, certificates, headers, coordinates and unknown provider fields."""
    try:
        if len(raw) > MAX_BYTES:
            raise ValueError
        resource = _object(_object(_object(json.loads(raw)).get('result')).get('resource'))
        address = ipaddress.ip_address(resource['ip'])
        if address != ipaddress.ip_address(ip):
            raise ValueError
        network = _object(resource.get('autonomous_system'))
        asn = network.get('asn')
        if asn is not None and (type(asn) is not int or not 0 < asn <= 4294967295):
            raise ValueError
        prefix = _text(network.get('bgp_prefix'), 50)
        if prefix and address not in ipaddress.ip_network(prefix):
            raise ValueError
        country = _text(_object(resource.get('location')).get('country_code'), 2)
        if country and not re.fullmatch(r'[A-Z]{2}', country):
            raise ValueError
        names = _object(resource.get('dns')).get('names', [])
        rows = resource.get('services', [])
        if not isinstance(names, list) or not isinstance(rows, list) or len(rows) > 2000:
            raise ValueError
        kept: list[dict[str, Any]] = []
        seen: set[tuple[int, str, str]] = set()
        for row in rows:
            row = _object(row)
            port = row.get('port')
            protocol = _text(row.get('protocol'), 80) or 'Unknown'
            transport = (_text(row.get('transport_protocol'), 10) or 'unknown').lower()
            if (
                type(port) is not int
                or not 0 < port < 65536
                or transport not in ('tcp', 'udp', 'quic', 'unknown')
            ):
                raise ValueError
            scanned = _text(row.get('scan_time'), 40)
            if scanned:
                scanned = datetime.fromisoformat(scanned).isoformat()
            key = port, transport, protocol
            if key not in seen:
                seen.add(key)
                kept.append(
                    {'port': port, 'protocol': protocol, 'transport': transport, 'observed_at': scanned}
                )
        return {
            'found': True,
            'services': sorted(kept, key=lambda item: (item['port'], item['transport']))[:MAX_SERVICES],
            'service_count': len(kept),
            'hostnames': sorted({n for n in names if isinstance(n, str) and _NAME.fullmatch(n)})[:20],
            'asn': asn,
            'network_name': _text(network.get('name')),
            'prefix': prefix,
            'country_code': country,
        }
    except (KeyError, RecursionError, UnicodeError, ValueError, TypeError):
        raise ProviderError('Censys returned invalid host data') from None


def _retry_after(value: str) -> int:
    if re.fullmatch(r'[0-9]{1,10}', value):
        return max(1, min(int(value), 86400))
    try:
        return max(
            1, min(math.ceil((parsedate_to_datetime(value) - datetime.now(UTC)).total_seconds()), 86400)
        )
    except (ValueError, TypeError, OverflowError):
        return 60


async def _fetch(ip: str, token: str, organization: str) -> dict[str, Any]:
    headers = {'Authorization': f'Bearer {token}', 'Accept': 'application/vnd.censys.api.v3.host.v1+json'}
    params = {'fields': _FIELDS}
    if organization:
        params['organization_id'] = organization
    try:
        raw = await download(
            f'https://{HOST}/v3/global/asset/host/{quote(ip, safe="")}',
            params,
            headers=headers,
            allowed_hosts=frozenset({HOST}),
            max_bytes=MAX_BYTES,
        )
    except httpx.HTTPStatusError as exc:
        code = exc.response.status_code
        if code == 404:
            return {'found': False}
        if code in (429, 503):
            wait = _retry_after(exc.response.headers.get('Retry-After', ''))
            THROTTLES['censys'].defer(wait)
            raise RateLimited(wait) from None
        if code == 401:
            raise ProviderError('Censys refused the token (HTTP 401). Check INSIGHT_CENSYS_PAT.') from None
        if code in (402, 403):
            raise ProviderError(
                'Censys refused access. Check your plan, credits, API role and organization.'
            ) from None
        raise ProviderError(f'Censys returned HTTP {code}.') from None
    except (httpx.HTTPError, OSError, ValueError):
        raise ProviderError('Censys request failed its connection, redirect or response limits') from None
    return _parse(raw, ip)


async def lookup(
    sessions: SessionFactory,
    value: str,
    *,
    actor: str,
    approved: bool = False,
    max_tlp: str | None = None,
) -> dict[str, Any]:
    """An explicit approval sends one eligible address; provider errors never echo supplied data."""
    if not approved:
        raise ValueError('Approve sending this IP address to Censys first')
    token, organization = _credentials()
    if not token:
        raise NotConfigured('Set INSIGHT_CENSYS_PAT and check the optional INSIGHT_CENSYS_ORG_ID on the host')

    def fresh() -> dict[str, Any] | None:
        with sessions() as db:
            record = services.cached_censys_context(db, value, max_tlp=max_tlp)
        return (
            record
            if record and datetime.fromisoformat(record['fetched_at']) > datetime.now(UTC) - _TTL
            else None
        )

    def audit_request(cached: bool) -> None:
        with sessions.begin() as db:
            entity_id = services.eligible_censys_ip(db, value, max_tlp=max_tlp)
            if entity_id is None:
                raise LookupError('No eligible reviewed public IP in a current TLP:CLEAR report')
            services.set_actor(db, actor)
            services.audit(
                db, 'ip.lookup.cache' if cached else 'ip.lookup.request', entity_id, 'Censys Platform'
            )

    if record := await asyncio.to_thread(fresh):
        await asyncio.to_thread(audit_request, True)
        return record
    if not _BUSY.acquire(blocking=False):
        raise RateLimited(1)
    try:
        if record := await asyncio.to_thread(fresh):
            await asyncio.to_thread(audit_request, True)
            return record
        if wait := THROTTLES['censys'].try_acquire():
            raise RateLimited(wait)
        await asyncio.to_thread(audit_request, False)
        payload = await _fetch(str(ipaddress.ip_address(value)), token, organization)

        def save() -> dict[str, Any]:
            with sessions.begin() as db:
                services.set_actor(db, actor)
                return services.store_censys_context(db, value, payload, max_tlp=max_tlp)

        return await asyncio.to_thread(save)
    finally:
        _BUSY.release()
