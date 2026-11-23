"""Bounded values shared by manual infrastructure lookups (ADR 0037)."""

from __future__ import annotations

import ipaddress
import json
import re
from datetime import datetime
from typing import Any, Final

from . import egress

MAX_BYTES: Final = 2_000_000
MAX_ROWS: Final = 500
PROVIDERS: Final = {'rdap': 'RDAP', 'asn': 'RIPEstat', 'crtsh': 'crt.sh', 'circl': 'CIRCL passive DNS'}
PROVIDER_KINDS: Final = {
    'rdap': frozenset({'domain', 'ip'}),
    'asn': frozenset({'ip'}),
    'crtsh': frozenset({'domain'}),
    'circl': frozenset({'domain', 'ip'}),
}
_DOMAIN = re.compile(r'(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,62}')


def subject(value: str) -> tuple[str, str]:
    """Only canonical public IP addresses and DNS names; never a URL or arbitrary query."""
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        if _DOMAIN.fullmatch(value) and not value.endswith(('.localhost', '.local', '.internal')):
            return 'domain', value
    else:
        if str(address) == value and egress.is_public(address):
            return 'ip', value
    raise ValueError('Use a public IP address or a lower-case domain name')


def text(value: Any, limit: int = 256) -> str:
    if not isinstance(value, str) or len(value) > limit or (value and not value.isprintable()):
        raise ValueError('Invalid metadata')
    return value


def name(value: Any) -> str:
    result = text(value, 253).lower().rstrip('.')
    if not _DOMAIN.fullmatch(result):
        raise ValueError('Invalid DNS name')
    return result


def date(value: Any) -> str:
    result = text(value, 40)
    datetime.fromisoformat(result.replace('Z', '+00:00'))
    return result


def object_data(raw: bytes) -> dict[str, Any]:
    if len(raw) > MAX_BYTES:
        raise ValueError('Response too large')
    data = json.loads(raw)
    if not isinstance(data, dict):
        raise ValueError('Invalid metadata')
    return data
