"""Bounded, read-only polling of one explicitly configured TAXII 2.1 collection (ADR 0040)."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Final
from urllib.parse import urlsplit

import httpx

from . import connectors, stix_import
from .config import parse_dev_no_auth
from .operator_endpoints import valid_collection_id
from .schemas import OperatorSourceInput
from .stix_export import stable_id
from .taxii import TAXII_MEDIA_TYPE

MAX_PAGES: Final = 20
MAX_BYTES: Final = stix_import.MAX_BUNDLE_BYTES
MAX_OBJECTS: Final = stix_import.MAX_OBJECTS
DEADLINE: Final = 120.0
_NAME = re.compile(r'INSIGHT_SOURCE_[A-Z0-9_]{1,40}', re.ASCII)
_TIMESTAMP = re.compile(
    r'([0-9]{4}-[0-9]{2}-[0-9]{2}[Tt][0-9]{2}:[0-9]{2}:[0-9]{2})(?:\.([0-9]{1,64}))?'
    r'([Zz]|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])'
)
_PARAMETER = re.compile(
    r"""([!#$%&'*+.^_`|~A-Za-z0-9-]+)\s*=\s*(?:([!#$%&'*+.^_`|~A-Za-z0-9-]+)|"([^"\\]*)")"""
)


class TaxiiClientError(ValueError):
    """A local message safe to show in job, source and API status."""


class TaxiiNotConfigured(ValueError):
    """The referenced host credential is unavailable. No request has been made."""


@dataclass(frozen=True, slots=True)
class CollectionBatch:
    bundle: bytes | None
    watermark: str
    object_count: int


def _auth_header(name: str | None) -> dict[str, str]:
    if not name:
        return {}
    if parse_dev_no_auth(os.environ.get('INSIGHT_DEV_NO_AUTH', '')):
        # In temporary open access anyone who reaches the workspace can point a source at a host of their
        # choosing, and a host credential would follow it there. The source shows as not configured instead.
        raise TaxiiNotConfigured('TAXII source credentials are not used in temporary open access.')
    if not _NAME.fullmatch(name):
        raise TaxiiNotConfigured('The TAXII source credentials are not configured.')
    value = os.environ.get(name, '')
    if not (1 <= len(value) <= 2048 and value.isascii() and value.isprintable()):
        raise TaxiiNotConfigured('The TAXII source credentials are not configured.')
    if ':' in value:
        user, _, password = value.partition(':')
        if not user.strip() or not password.strip():
            raise TaxiiNotConfigured('The TAXII source credentials are not configured.')
        token = base64.b64encode(value.encode('ascii')).decode('ascii')
        return {'Authorization': f'Basic {token}'}
    if not re.fullmatch(r'[A-Za-z0-9._~+/-]+=*', value):
        raise TaxiiNotConfigured('The TAXII source credentials are not configured.')
    return {'Authorization': f'Bearer {value}'}


def credentials_configured(credential_env: str | None) -> bool:
    try:
        _auth_header(credential_env)
    except TaxiiNotConfigured:
        return False
    return True


def _instant(value: str) -> tuple[datetime, str]:
    match = _TIMESTAMP.fullmatch(value)
    if not match:
        raise ValueError('Invalid timestamp')
    seconds, fraction, offset = match.groups()
    # datetime truncates fractions at microseconds. Compare whole UTC seconds and the exact decimal fraction.
    zone = '+00:00' if offset.upper() == 'Z' else offset
    return datetime.fromisoformat(seconds + zone).astimezone(UTC), (fraction or '').rstrip('0')


def _check_content_type(raw: str) -> None:
    media, *parameters = raw.lower().split(';')
    if media.strip() != 'application/taxii+json':
        raise ValueError('Wrong media type')
    seen = set()
    for parameter in parameters:
        match = _PARAMETER.fullmatch(parameter.strip())
        if not match:
            raise ValueError('Invalid media parameter')
        name, token, quoted = match.groups()
        value = token if token is not None else quoted
        if name in seen or (name == 'version' and value != '2.1') or (name == 'charset' and value != 'utf-8'):
            raise ValueError('Unsupported media parameter')
        seen.add(name)


def _unique_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    obj = dict(pairs)
    if len(obj) != len(pairs):
        raise ValueError('Duplicate JSON field')
    return obj


def _page(raw: bytes) -> tuple[list[dict[str, Any]], str | None]:
    obj = json.loads(raw.decode('utf-8'), object_pairs_hook=_unique_keys)
    if not isinstance(obj, dict) or any(
        k not in ('objects', 'more', 'next') and not k.startswith('x_') for k in obj
    ):
        raise ValueError('Invalid TAXII envelope')
    records = obj.get('objects', [])
    if not isinstance(records, list) or len(records) > MAX_OBJECTS:
        raise ValueError('Invalid objects')
    if any(
        not isinstance(item, dict)
        or not isinstance(item.get('type'), str)
        or not isinstance(item.get('id'), str)
        or item.get('spec_version') != '2.1'
        for item in records
    ):
        raise ValueError('Invalid STIX object')
    more = obj.get('more', False)
    if not isinstance(more, bool) or ('next' in obj) != more:
        raise ValueError('Invalid pagination')
    token = obj.get('next')
    if more and (
        not records
        or not isinstance(token, str)
        or not re.fullmatch(r'[!-~]{1,1024}', token)
        or '://' in token
        or token.startswith(('/', '\\'))
        or '\\' in token
    ):
        raise ValueError('Invalid pagination')
    return records, token


def _bundle(records: list[dict[str, Any]]) -> bytes:
    records.sort(key=lambda item: item['id'])
    if len({item['id'] for item in records}) != len(records):
        raise ValueError('Repeated STIX identifier')
    members = json.dumps(
        records, sort_keys=True, ensure_ascii=False, allow_nan=False, separators=(',', ':')
    ).encode()
    bundle_id = stable_id('bundle', 'operator-taxii', hashlib.sha256(members).hexdigest())
    result = b'{"type":"bundle","id":"' + bundle_id.encode() + b'","objects":' + members + b'}'
    if len(result) > MAX_BYTES:
        raise ValueError('STIX bundle exceeds size limit')
    return result


async def fetch_collection(
    api_root: str,
    collection_id: str,
    *,
    credential_env: str | None = None,
    added_after: str = '',
    allow_private: bool = False,
) -> CollectionBatch:
    """Read every bounded page, then return one batch for atomic import and cursor advancement."""
    headers = {**_auth_header(credential_env), 'Accept': TAXII_MEDIA_TYPE}
    try:
        # Apply the same URL policy to stored configurations and direct callers before attaching credentials.
        if len(api_root) > 2048:
            raise ValueError('Invalid API root')
        base = OperatorSourceInput.feed_url(api_root).rstrip('/')
        host = urlsplit(base).hostname
        if not host or not valid_collection_id(collection_id):
            raise ValueError('Invalid collection')
        endpoint = f'{base}/collections/{collection_id}/objects/'
        start = _instant(added_after) if added_after else None
        last = start
        watermark = added_after
        params = {'added_after': added_after} if added_after else {}
        records: list[dict[str, Any]] = []
        tokens: set[str] = set()
        remaining = MAX_BYTES
        async with asyncio.timeout(DEADLINE):
            for _ in range(MAX_PAGES):
                response = connectors.DownloadHeaders()
                raw = await connectors.download(
                    endpoint,
                    params,
                    headers=headers,
                    allowed_hosts=frozenset({host}),
                    allow_private=allow_private,
                    max_bytes=remaining,
                    response_headers=response,
                )
                remaining -= len(raw)
                if remaining < 0:
                    raise ValueError('Collection exceeds size limit')
                _check_content_type(response.content_type)
                page, token = _page(raw)
                if page:
                    instant = _instant(response.date_added_last)
                    if (start is not None and instant <= start) or (last is not None and instant < last):
                        raise ValueError('Non-monotonic date added')
                    last, watermark = instant, response.date_added_last
                elif response.date_added_last:
                    raise ValueError('Unexpected date on empty page')
                if len(records) + len(page) > MAX_OBJECTS:
                    raise ValueError('Collection exceeds object limit')
                records.extend(page)
                if token is None:
                    return CollectionBatch(_bundle(records) if records else None, watermark, len(records))
                if token in tokens or remaining == 0:
                    raise ValueError('Invalid page continuation')
                tokens.add(token)
                params['next'] = token
        raise ValueError('Collection exceeds page limit')
    except (
        ValueError,
        KeyError,
        TypeError,
        UnicodeError,
        OverflowError,
        RecursionError,
        OSError,
        httpx.HTTPError,
    ):
        raise TaxiiClientError(
            'The TAXII collection could not be read within its protocol and size limits.'
        ) from None
