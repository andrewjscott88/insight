"""TAXII 2.1 protocol pieces for Insight's read-only server (TIP 3.1, ADR 0026). No database or network.

Only what a polling client needs: discovery, one API root, fixed collections, objects with ``added_after``,
``match[id]``, ``match[type]``, ``match[version]`` and ``match[spec_version]`` filters, a manifest, per-object
versions and keyset pagination (``limit`` and ``next``). Nothing can be written.
"""

from __future__ import annotations

import base64
import binascii
import json
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Final

TAXII_MEDIA_TYPE: Final = 'application/taxii+json;version=2.1'
STIX_MEDIA_TYPE: Final = 'application/stix+json;version=2.1'
API_ROOT: Final = 'insight'
#: Every page is built from a full, validated snapshot, so keep pages large and the count of requests low.
DEFAULT_PAGE: Final = 1000
MAX_PAGE: Final = 1000
MAX_MATCH_VALUES: Final = 100

#: The collections are fixed here: no API key, setting or database row can create one.
INDICATORS_COLLECTION: Final = '5b2f8a7e-4c1d-4e3a-9f6b-0d8c7a1e2f34'
KEV_COLLECTION: Final = 'c4e1b7d2-6a35-4f08-8b9e-3d7f2a5c1e60'
HUNT_PACKAGES_COLLECTION: Final = '9d3f6b1a-2c4e-4a7b-8e5d-1f0a3c6b9e27'
COLLECTIONS: Final = {
    INDICATORS_COLLECTION: {
        'id': INDICATORS_COLLECTION,
        'title': 'Reviewed indicators',
        'description': (
            'Indicators and CVEs an analyst accepted in Insight, with the reports that mention them, their '
            "ATT&CK techniques, linked actors and campaigns, and TLP markings, up to the API key's TLP "
            'limit. Publisher text appears only where the publisher allows it.'
        ),
        'can_read': True,
        'can_write': False,
        'media_types': [STIX_MEDIA_TYPE],
    },
    KEV_COLLECTION: {
        'id': KEV_COLLECTION,
        'title': 'CISA Known Exploited Vulnerabilities',
        'description': (
            "Every entry of CISA's Known Exploited Vulnerabilities catalog that Insight has synced, as STIX "
            'vulnerabilities with the dates, required action and ransomware use CISA publishes. Public '
            'data (TLP:CLEAR).'
        ),
        'can_read': True,
        'can_write': False,
        'media_types': [STIX_MEDIA_TYPE],
    },
    HUNT_PACKAGES_COLLECTION: {
        'id': HUNT_PACKAGES_COLLECTION,
        'title': 'Hunt packages',
        'description': (
            'Hypotheses for a hunt tool to test: for each published package, a STIX grouping with its ATT&CK '
            'techniques, indicators and detection rules (Sigma, YARA, Suricata and Snort, as indicators of '
            "those pattern types), up to the API key's TLP limit. Retired packages come back as revoked."
        ),
        'can_read': True,
        'can_write': False,
        'media_types': [STIX_MEDIA_TYPE],
    },
}


class TaxiiError(Exception):
    """A request the server must refuse, with the TAXII error message to send."""

    def __init__(self, status: int, title: str, description: str = '') -> None:
        super().__init__(title)
        self.status = status
        self.title = title
        self.description = description

    def body(self) -> dict[str, Any]:
        body: dict[str, Any] = {'title': self.title, 'http_status': str(self.status)}
        if self.description:
            body['description'] = self.description
        return body


@dataclass(frozen=True)
class TaxiiObject:
    """One STIX object in a collection, with the time it (in this version) entered the collection."""

    date_added: str
    obj: dict[str, Any]

    @property
    def id(self) -> str:
        return str(self.obj['id'])

    @property
    def version(self) -> str:
        # Marking definitions have no ``modified``; their version is their creation time.
        return str(self.obj.get('modified') or self.obj['created'])


@dataclass(frozen=True)
class Page:
    objects: list[TaxiiObject]
    more: bool
    next: str | None


def accepts_taxii(accept: str) -> bool:
    """Clients must ask for TAXII 2.1 (a missing header or ``*/*`` is accepted)."""
    if not accept.strip():
        return True
    for item in accept.split(','):
        media = item.split(';')[0].strip().lower()
        params = {p.split('=')[0].strip().lower(): p.partition('=')[2].strip() for p in item.split(';')[1:]}
        if media in ('*/*', 'application/*'):
            return True
        if media == 'application/taxii+json' and params.get('version', '2.1') == '2.1':
            return True
    return False


def timestamp(value: str, name: str = 'added_after') -> str:
    """Parse an RFC 3339 timestamp from a query and return it as a comparable STIX timestamp."""
    try:
        if len(value) > 40:
            raise ValueError
        stamp = datetime.fromisoformat(value.replace('Z', '+00:00').replace('z', '+00:00'))
    except ValueError:
        raise TaxiiError(
            400, f'Invalid {name}', 'Use an RFC 3339 timestamp, such as 2026-11-21T00:00:00Z.'
        ) from None
    if stamp.tzinfo is None:
        raise TaxiiError(400, f'Invalid {name}', 'The timestamp needs a time zone, such as Z.')
    return stamp.astimezone(UTC).isoformat(timespec='microseconds').replace('+00:00', 'Z')


def _values(raw: str | None) -> set[str] | None:
    if raw is None:
        return None
    values = {v.strip() for v in raw.split(',') if v.strip()}
    if len(values) > MAX_MATCH_VALUES:
        raise TaxiiError(400, 'Too many match values', f'Send at most {MAX_MATCH_VALUES} per filter.')
    return values


def encode_cursor(item: TaxiiObject) -> str:
    raw = json.dumps([item.date_added, item.id], separators=(',', ':')).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip('=')


def decode_cursor(token: str) -> tuple[str, str]:
    try:
        if len(token) > 512:
            raise ValueError
        raw = base64.urlsafe_b64decode(token + '=' * (-len(token) % 4))
        date_added, object_id = json.loads(raw)
        if not isinstance(date_added, str) or not isinstance(object_id, str):
            raise ValueError
    except (ValueError, TypeError, binascii.Error, RecursionError):
        raise TaxiiError(
            400, 'Invalid next', 'Use the next value from the previous page unchanged.'
        ) from None
    return date_added, object_id


def select_page(
    objects: Sequence[TaxiiObject],
    *,
    added_after: str | None = None,
    match_id: str | None = None,
    match_type: str | None = None,
    match_version: str | None = None,
    match_spec_version: str | None = None,
    limit: int | None = None,
    next_token: str | None = None,
) -> Page:
    """Filter a collection sorted by ``(date_added, id)`` and cut one page after the ``next`` cursor.

    Each object has one version (the current one), so ``match[version]`` values ``last``, ``first`` and
    ``all`` all select it, and a timestamp selects it only if it is that version.
    """
    size = DEFAULT_PAGE if limit is None else limit
    if not 1 <= size <= MAX_PAGE:
        raise TaxiiError(400, 'Invalid limit', f'Use a limit from 1 to {MAX_PAGE}.')
    after = timestamp(added_after) if added_after else None
    ids, types = _values(match_id), _values(match_type)
    versions = _values(match_version)
    spec = _values(match_spec_version)
    exact = None
    if versions is not None:
        named = versions & {'last', 'first', 'all'}
        exact = {timestamp(v, 'match[version]') for v in versions - named}
        if named:
            exact = None
    cursor = decode_cursor(next_token) if next_token else None
    selected: list[TaxiiObject] = []
    for item in objects:
        if after is not None and item.date_added <= after:
            continue
        if cursor is not None and (item.date_added, item.id) <= cursor:
            continue
        if ids is not None and item.id not in ids:
            continue
        if types is not None and item.obj['type'] not in types:
            continue
        if spec is not None and item.obj.get('spec_version', '2.1') not in spec:
            continue
        if exact is not None and timestamp(item.version, 'version') not in exact:
            continue
        selected.append(item)
        if len(selected) > size:
            break
    more = len(selected) > size
    page = selected[:size]
    return Page(page, more, encode_cursor(page[-1]) if more else None)


def envelope(page: Page) -> dict[str, Any]:
    body: dict[str, Any] = {'more': page.more, 'objects': [item.obj for item in page.objects]}
    if page.next:
        body['next'] = page.next
    return body


def manifest(page: Page) -> dict[str, Any]:
    body: dict[str, Any] = {
        'more': page.more,
        'objects': [
            {'id': i.id, 'date_added': i.date_added, 'version': i.version, 'media_type': STIX_MEDIA_TYPE}
            for i in page.objects
        ],
    }
    if page.next:
        body['next'] = page.next
    return body


def date_headers(page: Page) -> dict[str, str]:
    if not page.objects:
        return {}
    return {
        'X-TAXII-Date-Added-First': page.objects[0].date_added,
        'X-TAXII-Date-Added-Last': page.objects[-1].date_added,
    }
