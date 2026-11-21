"""Exchange a single unpublished event with the operator's configured MISP instance."""

from __future__ import annotations

import json
import os
import re
from urllib.parse import urlsplit
from uuid import UUID

import httpx

from .connectors import download


def _origin() -> tuple[str, str]:
    raw = os.environ.get('INSIGHT_MISP_URL', '')
    if not raw or any(c.isspace() or not c.isprintable() for c in raw):
        raise ValueError('Set INSIGHT_MISP_URL to the HTTPS address of the trusted MISP instance')
    try:
        parts = urlsplit(raw)
        host, port = parts.hostname, parts.port
    except ValueError:
        raise ValueError('Invalid INSIGHT_MISP_URL') from None
    if (
        parts.scheme != 'https'
        or not host
        or port not in (None, 443)
        or parts.username is not None
        or parts.password is not None
        or any(ch in raw for ch in '?#\\')
        or not re.fullmatch(r'(?:/[A-Za-z0-9._~-]+)*/?', parts.path)
        or any(part in {'.', '..'} for part in parts.path.split('/'))
    ):
        raise ValueError('INSIGHT_MISP_URL must be HTTPS on port 443 with no credentials, query or fragment')
    return raw.rstrip('/'), host


async def exchange(
    *, event_uuid: str, body: bytes | None = None, transport: httpx.AsyncBaseTransport | None = None
) -> bytes:
    """GET a single UUID, or POST a new event and check MISP's receipt. No redirects or ambient proxy."""
    base, host = _origin()
    key = os.environ.get('INSIGHT_MISP_KEY', '')
    if not re.fullmatch(r'[!-~]{1,512}', key):
        raise ValueError('Set INSIGHT_MISP_KEY to the host-side MISP API key')
    try:
        event_uuid = str(UUID(event_uuid))
    except ValueError:
        raise ValueError('A MISP event UUID is required') from None
    path = 'events/add' if body is not None else f'events/view/{event_uuid}'
    try:
        response = await download(
            f'{base}/{path}',
            body=body,
            headers={'Authorization': key, 'Accept': 'application/json', 'Content-Type': 'application/json'},
            allowed_hosts=frozenset({host}),
            transport=transport,
        )
    except httpx.HTTPStatusError as exc:
        raise ValueError(f'MISP returned HTTP {exc.response.status_code}') from None
    except (httpx.HTTPError, OSError, ValueError):
        raise ValueError('MISP request failed its connection, redirect or response limits') from None
    if body is not None:
        try:
            result = json.loads(response)
        except (ValueError, RecursionError):
            result = None
        if (
            not isinstance(result, dict)
            or not isinstance(event := result.get('Event'), dict)
            or event.get('uuid') != event_uuid
        ):
            raise ValueError('MISP did not confirm the event UUID. Check the destination before retrying.')
    return response
