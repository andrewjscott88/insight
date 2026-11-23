"""Bounded crt.sh certificate-name metadata; no certificates, keys or subject contacts are retained."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any, Final

from . import pivot_data

HOST: Final = 'crt.sh'
URL: Final = 'https://crt.sh/'
MAX_CERTIFICATES: Final = 10_000
MAX_NAME_TEXT: Final = 65_536


def _name(value: str) -> str:
    wildcard = value.startswith('*.')
    plain = pivot_data.name(value[2:] if wildcard else value)
    return '*.' + plain if wildcard else plain


def _date(value: Any) -> str:
    raw = pivot_data.text(value, 40)
    parsed = datetime.fromisoformat(raw.replace('Z', '+00:00'))
    # crt.sh represents X.509 UTC validity times without a zone suffix.
    return parsed.replace(tzinfo=parsed.tzinfo or UTC).astimezone(UTC).isoformat()


def parse(raw: bytes, value: str) -> dict[str, Any]:
    """Bind every certificate row to the requested domain before retaining any names from that row.

    A certificate may have other names too; those are provider context, never inferred indicators.
    Duplicate log entries and renewals yield one row per name, choosing its latest validity start.
    """
    kind, subject = pivot_data.subject(value)
    if kind != 'domain':
        raise ValueError('Certificate names need a domain')
    if len(raw) > pivot_data.MAX_BYTES:
        raise ValueError('Response too large')
    data = json.loads(raw)
    if not isinstance(data, list) or len(data) > MAX_CERTIFICATES:
        raise ValueError('Invalid certificate list')
    names: dict[str, tuple[str, str, str]] = {}
    for row in data:
        if not isinstance(row, dict):
            raise ValueError('Invalid certificate metadata')
        raw_names = row.get('name_value')
        if not isinstance(raw_names, str) or not raw_names or len(raw_names) > MAX_NAME_TEXT:
            raise ValueError('Invalid certificate names')
        found = {_name(item) for item in raw_names.splitlines()}
        if not any(
            name.removeprefix('*.') == subject or name.removeprefix('*.').endswith('.' + subject)
            for name in found
        ):
            raise ValueError('Certificate does not match the requested domain')
        issuer = pivot_data.text(row.get('issuer_name'), 1024)
        before, after = _date(row.get('not_before')), _date(row.get('not_after'))
        if not issuer or after < before:
            raise ValueError('Invalid certificate validity or issuer')
        metadata = (before, after, issuer)
        for name in found:
            names[name] = max(names.get(name, metadata), metadata)
    selected = sorted(names)[: pivot_data.MAX_ROWS]
    return {
        'found': bool(selected),
        'certificates': [
            {
                'name': name,
                'issuer': names[name][2],
                'not_before': names[name][0],
                'not_after': names[name][1],
            }
            for name in selected
        ],
        'truncated': len(names) > pivot_data.MAX_ROWS or len(data) == MAX_CERTIFICATES,
        'nodes': [{'type': 'certificate_name', 'value': name} for name in selected],
    }
