"""Read the metadata of public OTX subscription pulses. References and attachments are never fetched."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Final

from .extraction import canonical, refang
from .feed_items import FeedItem
from .schemas import DocumentInput, tlp_markings
from .source_registry import Source

PAGE_SIZE: Final = 25
#: Pages read per sync (issue #11); a longer backlog continues at the next sync.
MAX_PAGES: Final = 4
INDICATOR_LIMIT: Final = 100
_PULSE_ID = re.compile(r'[0-9a-fA-F]{24}', re.ASCII)
_KINDS: Final = {
    'IPv4': 'ip',
    'IPv6': 'ip',
    'CIDR': 'cidr',
    'domain': 'domain',
    'hostname': 'domain',
    'email': 'email',
    'Email': 'email',
    'URL': 'url',
    'CVE': 'cve',
    'FileHash-MD5': 'md5',
    'FileHash-SHA1': 'sha1',
    'FileHash-SHA256': 'sha256',
    'FileHash-SHA512': 'sha512',
}


@dataclass(frozen=True, slots=True)
class PulseBatch:
    items: list[FeedItem]
    skipped: int
    #: The newest ``modified`` time on this page (normalised ISO-8601), ``''`` if none could be read.
    newest: str = ''
    #: OTX says another page follows. Only a signal: its ``next`` link is never followed.
    more: bool = False


@dataclass(frozen=True, slots=True)
class Cursor:
    """Where the next OTX sync starts (issue #11). ``since`` is sent as ``modified_since``; ``page`` is the
    next page of that pass (above 1 after a failure or the page limit); ``newest`` is the newest change seen
    so far in the pass, which becomes ``since`` once the pass reaches the last page."""

    since: str = ''
    page: int = 1
    newest: str = ''

    @classmethod
    def parse(cls, stored: str) -> Cursor:
        try:
            raw = json.loads(stored) if stored else {}
        except (ValueError, RecursionError):
            return cls()
        if not isinstance(raw, dict):
            return cls()
        page = raw.get('page')
        return cls(
            since=_moment(raw.get('since')),
            page=page if isinstance(page, int) and not isinstance(page, bool) and 1 <= page <= 10_000 else 1,
            newest=_moment(raw.get('newest')),
        )

    def dump(self) -> str:
        return json.dumps({'since': self.since, 'page': self.page, 'newest': self.newest}, sort_keys=True)

    def after(self, batch: PulseBatch) -> Cursor:
        """The cursor once ``batch`` (page ``self.page``) is stored."""
        newest = max(self.newest, batch.newest)
        if batch.more:
            return Cursor(self.since, self.page + 1, newest)
        return Cursor(newest or self.since, 1, '')


def _moment(value: Any) -> str:
    """OTX's ``modified`` as ISO-8601 UTC without an offset (OTX's own form), or ``''`` if unreadable."""
    if not isinstance(value, str) or not value or len(value) > 40:
        return ''
    try:
        moment = datetime.fromisoformat(value.replace('Z', '+00:00'))
    except ValueError:
        return ''
    if moment.tzinfo is not None:
        moment = moment.astimezone(UTC).replace(tzinfo=None)
    return moment.isoformat(timespec='microseconds')


def _public_clear(pulse: dict[str, Any]) -> bool:
    # The wire flag is 0/1 or a JSON boolean. A non-empty string such as "false" is not public.
    public = pulse.get('public')
    if not isinstance(public, int) or public != 1:
        return False
    labels = [pulse[key] for key in ('tlp', 'TLP') if key in pulse]
    return bool(labels) and all(
        isinstance(label, str) and label.strip().upper().removeprefix('TLP:') in ('WHITE', 'CLEAR')
        for label in labels
    )


def _indicator(row: Any) -> str | None:
    if not isinstance(row, dict) or not isinstance(row.get('type'), str):
        return None
    kind = _KINDS.get(row['type'])
    value = row.get('indicator')
    if kind is None or not isinstance(value, str) or len(value) > 1000 or not value.isprintable():
        return None
    value = value.strip()
    if any(char.isspace() for char in value):
        return None
    if kind == 'ip' and (':' in refang(value)) != (row['type'] == 'IPv6'):
        return None
    try:
        return canonical(kind, value)
    except ValueError:
        return None


def _pulse(row: Any, source: Source) -> FeedItem | None:
    if not isinstance(row, dict) or not _public_clear(row):
        return None
    pulse_id, name, indicators = row.get('id'), row.get('name'), row.get('indicators')
    if not isinstance(pulse_id, str) or not _PULSE_ID.fullmatch(pulse_id):
        return None
    if not isinstance(name, str) or not name.strip() or not isinstance(indicators, list):
        return None
    # Explicitly tighter markings in publisher text take precedence over the structured public label.
    description = row.get('description') or ''
    if not isinstance(description, str) or any(
        label != 'CLEAR' for label in tlp_markings(name + '\n' + description)
    ):
        return None
    title = ' '.join(name.split())[:300]
    values = sorted({value for entry in indicators[:INDICATOR_LIMIT] if (value := _indicator(entry))})
    body = '\n'.join(values) or 'No supported indicators in this pulse.'
    if any(label != 'CLEAR' for label in tlp_markings(body)):
        return None
    identity = pulse_id.lower()
    document = DocumentInput(
        title=title,
        body=body,
        source_name=source.name,
        source_url=f'https://otx.alienvault.com/pulse/{identity}',
        tlp='CLEAR',
    )
    return FeedItem(document, identity, truncated=len(indicators) > INDICATOR_LIMIT)


def parse_pulses(payload: bytes, source: Source) -> PulseBatch:
    """Read one bounded subscription page; a malformed envelope is a failed sync, not an empty page."""
    try:
        page = json.loads(payload)
    except (ValueError, RecursionError):
        raise ValueError('OTX returned unreadable JSON') from None
    if not isinstance(page, dict) or not isinstance(page.get('results'), list):
        raise ValueError('OTX did not return a pulse list')
    rows = page['results'][:PAGE_SIZE]
    items = [item for row in rows if (item := _pulse(row, source)) is not None]
    newest = max(
        (m for row in rows if isinstance(row, dict) and (m := _moment(row.get('modified')))), default=''
    )
    return PulseBatch(items, len(rows) - len(items), newest, bool(page.get('next')))
