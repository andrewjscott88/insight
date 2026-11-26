"""Curated, opt-in connectors. No arbitrary URL fetch endpoint; no article crawling."""

from __future__ import annotations

import asyncio
import csv
import hashlib
import io
import json
import os
import re
import ssl
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from functools import partial
from html import unescape
from itertools import islice
from typing import Any, Final, cast
from urllib.parse import urlsplit

import httpx
from defusedxml import ElementTree
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import __version__, egress, otx
from .abusech import parse_abusech
from .cve_scores import summarise_vulncheck
from .feed_items import MAX_FEED_ITEMS as MAX_FEED_ITEMS
from .feed_items import FeedItem as FeedItem
from .models import Enrichment, Entity, KEVRecord, SessionFactory, SourceRun, now
from .schemas import TLP, DocumentInput, most_restrictive, tlp_markings
from .services import (
    SourceRef,
    fetch_cursor,
    get_fetch_state,
    ingest,
    save_fetch_cursor,
    save_fetch_state,
    set_actor,
    source_switches,
)
from .services.alerts import known_kev, queue_kev_alerts

# Re-exported: the registry used to live here, and tests and scripts still name it through this module.
from .source_registry import CSAF_BASE as CSAF_BASE
from .source_registry import CSAF_INBOX_LIMIT as CSAF_INBOX_LIMIT
from .source_registry import OTX_SUBSCRIBED_URL, in_use
from .source_registry import SOURCES as SOURCES
from .source_registry import Source as Source

MAX_BYTES: Final = 8_000_000
#: Seconds one whole download may take (code review L6). ``httpx.Timeout(25)`` only limits each wait for data,
#: so a server sending a little every 24 s could otherwise stretch one sync out for hours.
DOWNLOAD_DEADLINE: Final = 120.0
MAX_FEED_SUMMARY: Final = 500
MAX_KEV_ROWS: Final = 20_000
MAX_KEV_FIELD: Final = 10_000
#: KEV inbox policy (TIP 1.1, RUNBOOK section 8). Every sync reports the newest entries by date added...
KEV_INBOX_LIMIT: Final = 100
#: ...and, after the first sync, every CVE added since the last one, up to this many per sync. Older entries
#: stay catalog-only; they still annotate CVEs in the reader, the brief and the CVE view.
KEV_NEW_ENTRY_LIMIT: Final = 500
MAX_CSAF_INDEX_ROWS: Final = 50_000
MAX_CSAF_VULNERABILITIES: Final = 100
MAX_CSAF_NOTE: Final = 4_000
MAX_CSAF_BODY: Final = 60_000
#: ``changes.csv`` paths: a year folder and a file name. Nothing else (``..``, absolute URLs) is followed.
CSAF_PATH_RE: Final = re.compile(r'\d{4}/[a-z0-9][a-z0-9._-]{0,99}\.json', re.ASCII)
CSAF_ID_RE: Final = re.compile(r'[A-Za-z0-9][A-Za-z0-9._:-]{0,99}', re.ASCII)
#: Advisory file names carry their publication date: ``icsa-26-323-03.json`` is 2026, day 323.
CSAF_DATE_RE: Final = re.compile(r'[a-z]+-(\d{2})-(\d{3})-\d{2}', re.ASCII)
#: CSAF 2.0 uses TLP 1.0 labels; TLP 2.0 renamed WHITE to CLEAR.
CSAF_TLP: Final[dict[str, str]] = {
    'WHITE': 'CLEAR', 'CLEAR': 'CLEAR', 'GREEN': 'GREEN', 'AMBER': 'AMBER', 'RED': 'RED'
}  # fmt: skip
CSAF_SCORES: Final = (('cvss_v4', '4.0'), ('cvss_v3', '3'), ('cvss_v2', '2.0'))
USER_AGENT: Final = f'Insight/{__version__} (local analyst workbench)'
ATOM: Final = '{http://www.w3.org/2005/Atom}'
CVE_RE: Final = re.compile(r'CVE-\d{4}-\d{4,}', re.ASCII)
KEV_STRING_FIELDS: Final = (
    'vendorProject',
    'product',
    'dateAdded',
    'dueDate',
    'requiredAction',
    'shortDescription',
    'vulnerabilityName',
    'knownRansomwareCampaignUse',
    'notes',
)
#: CISA writes ``Known`` or ``Unknown``; anything else is stored as ``''`` (not known either way).
KEV_RANSOMWARE: Final = frozenset({'Known', 'Unknown'})
KEV_CWE: Final = re.compile(r'CWE-\d{1,5}', re.ASCII)
MAX_KEV_CWES: Final = 20

PROVIDERS: Final[dict[str, str]] = {
    'epss': 'https://api.first.org/data/v1/epss',
    'nvd': 'https://services.nvd.nist.gov/rest/json/cves/2.0',
    # TIP 3.3: needs the operator's free VulnCheck community key (INSIGHT_VULNCHECK_API_KEY).
    'vulncheck': 'https://api.vulncheck.com/v3/index/vulncheck-kev',
}
_PROVIDER_PARAM: Final[dict[str, str]] = {'epss': 'cve', 'nvd': 'cveId', 'vulncheck': 'cve'}
#: Each provider's key setting (never logged; only named in error hints).
PROVIDER_KEYS: Final[dict[str, str]] = {
    'nvd': 'INSIGHT_NVD_API_KEY',
    'vulncheck': 'INSIGHT_VULNCHECK_API_KEY',
}
#: Providers that cannot be asked at all without their key.
KEY_REQUIRED: Final = frozenset({'vulncheck'})


class ConnectorError(Exception):
    """Base class for failures talking to, or interpreting data from, an external source."""


class ProviderError(ConnectorError):
    """An upstream provider failed or returned something unusable (maps to HTTP 502).

    ``provider_wide`` says whether the problem stops every lookup at the provider (no network, rate limit,
    refused key, server error) or only concerns the one request's answer (review M2).
    """

    def __init__(self, message: str, *, provider_wide: bool = True) -> None:
        super().__init__(message)
        self.provider_wide = provider_wide


#: HTTP answers that concern the whole provider, not one CVE: a refused key or rate limit, and server errors.
PROVIDER_WIDE_STATUSES: Final = frozenset({401, 403, 429})


class SourceSyncError(ConnectorError):
    """A curated source sync failed. The failure has already been recorded as a ``SourceRun``."""


class SourceSwitchedOff(ConnectorError):
    """The source is switched off: Insight does not contact it (nothing is recorded)."""

    def __init__(self, source: Source) -> None:
        name = 'This source' if source.key.startswith('op-') else source.name
        super().__init__(f'{name} is switched off. Switch it on in Settings › Sources first.')


ALLOWED_HOSTS: Final[frozenset[str]] = frozenset(
    {h for s in SOURCES.values() for u in s.fetch_urls if (h := urlsplit(u).hostname)}
    | {urlsplit(u).hostname or '' for u in PROVIDERS.values()}
)


class NonPublicDestination(ValueError):
    """A host resolves to an address this request may not reach."""


async def _public_addresses(hostname: str, *, allow_private: bool = False) -> list[egress.IPAddress]:
    """The addresses of ``hostname``, all of them public (or, with ``allow_private``, on a private network),
    or :class:`NonPublicDestination` (review L1: the request then goes to one of these exact addresses, so a
    second DNS answer cannot redirect it)."""
    addresses = await egress.resolve(hostname, 443)
    allowed = (
        (lambda a: egress.is_public(a) or egress.is_private_network(a)) if allow_private else egress.is_public
    )
    if not addresses or not all(allowed(a) for a in addresses):
        raise NonPublicDestination('Source resolves to a non-public destination')
    return addresses


def _status_error(response: httpx.Response, url: str) -> httpx.HTTPStatusError:
    """httpx's error for a failed answer, naming the host the operator knows rather than its address."""
    code = response.status_code
    kind = 'Client error' if code < 500 else 'Server error'
    message = f"{kind} '{code} {response.reason_phrase}' for url '{url}'"
    return httpx.HTTPStatusError(message, request=response.request, response=response)


#: The run message when a source has not changed since its last successful sync.
UNCHANGED: Final = 'Unchanged since the last sync.'


@dataclass(slots=True)
class Validators:
    """HTTP cache validators for one URL: sent as ``If-None-Match`` / ``If-Modified-Since`` and replaced by
    what the response carries."""

    etag: str = ''
    last_modified: str = ''


@dataclass(slots=True)
class DownloadHeaders:
    """Only the bounded response fields needed by a TAXII reader; never expose arbitrary response headers."""

    content_type: str = ''
    date_added_last: str = ''

    def read(self, response: httpx.Response) -> None:
        def bounded(name: str, limit: int) -> str:
            values = response.headers.get_list(name)
            if not values:
                return ''
            value = values[0]
            if len(values) != 1 or not (0 < len(value) <= limit and value.isascii() and value.isprintable()):
                raise ValueError('Invalid download response headers')
            return value

        self.content_type = bounded('Content-Type', 256)
        self.date_added_last = bounded('X-TAXII-Date-Added-Last', 128)


class NotModified(Exception):
    """The server answered ``304 Not Modified`` to a request that carried :class:`Validators`."""


def _validator(response: httpx.Response, name: str, limit: int) -> str:
    value = response.headers.get(name, '').strip()
    return value if len(value) <= limit and value.isprintable() else ''


async def download(
    url: str,
    params: Mapping[str, str] | None = None,
    *,
    transport: httpx.AsyncBaseTransport | None = None,
    validators: Validators | None = None,
    response_headers: DownloadHeaders | None = None,
    headers: Mapping[str, str] | None = None,
    body: bytes | None = None,
    max_bytes: int = MAX_BYTES,
    allowed_hosts: frozenset[str] = ALLOWED_HOSTS,
    allow_private: bool = False,
    ca_file: str | None = None,
) -> bytes:
    """Fetch from the curated registry or an explicitly configured host, with the same HTTPS egress policy.

    With ``validators``, the request is conditional: an unchanged resource raises :class:`NotModified`, and a
    changed one updates ``validators`` from the response. Keyed feeds can add headers and a fixed POST body.
    ``max_bytes`` raises the size limit for one pinned, hash-checked download (the threat library sync).
    ``allow_private`` lets one explicitly configured host be on a private network (the operator's MISP
    instance, opt-in); loopback, link-local, multicast and reserved addresses stay blocked.
    ``ca_file`` (PEM) replaces the public certificate authorities for one explicitly configured host (an
    identity provider signed by an internal CA); certificates are still verified, host names included.
    ``transport`` exists for offline testing; production code never passes it.
    """
    parts = urlsplit(url)
    if parts.scheme != 'https' or parts.hostname not in allowed_hosts or parts.username or parts.password:
        raise ValueError('Outbound URL is not in the curated HTTPS source registry')
    try:
        port = parts.port
    except ValueError:
        port = -1
    if port not in (None, 443):
        raise ValueError('Outbound URL is not in the curated HTTPS source registry')
    request_headers = {**(headers or {}), 'User-Agent': USER_AGENT, 'Accept-Encoding': 'identity'}
    if validators is not None and validators.etag:
        request_headers['If-None-Match'] = validators.etag
    if validators is not None and validators.last_modified:
        request_headers['If-Modified-Since'] = validators.last_modified
    # Include DNS in the total deadline and connect only to addresses checked here (review L1).
    try:
        async with asyncio.timeout(DOWNLOAD_DEADLINE):
            addresses = await _public_addresses(parts.hostname, allow_private=allow_private)
            return await _fetch(
                url,
                addresses,
                params,
                request_headers,
                validators,
                transport,
                body,
                max_bytes,
                response_headers,
                ca_file,
            )
    except TimeoutError as exc:  # The overall deadline (L6); a normal fetch failure, recorded like any other.
        raise TimeoutError(f'The download took longer than {DOWNLOAD_DEADLINE:g} seconds') from exc


async def _fetch(
    url: str,
    addresses: list[egress.IPAddress],
    params: Mapping[str, str] | None,
    request_headers: dict[str, str],
    validators: Validators | None,
    transport: httpx.AsyncBaseTransport | None,
    body: bytes | None,
    max_bytes: int = MAX_BYTES,
    response_headers: DownloadHeaders | None = None,
    ca_file: str | None = None,
) -> bytes:
    # Verification is never off: the public authorities, or a verifying context for the given CA file.
    verify: ssl.SSLContext | bool = True
    if ca_file is not None:
        verify = ssl.create_default_context(cafile=ca_file)
    async with httpx.AsyncClient(
        timeout=httpx.Timeout(25),
        follow_redirects=False,
        trust_env=False,
        transport=transport,
        verify=verify,
    ) as client:
        for index, address in enumerate(addresses):
            target = egress.pin(url, address)
            try:
                async with client.stream(
                    'GET' if body is None else 'POST',
                    target.url,
                    content=body,
                    params=params,
                    headers={**request_headers, **target.headers},
                    extensions=target.extensions,
                ) as response:
                    return await _read(response, url, validators, max_bytes, response_headers)
            except httpx.ConnectError:
                if index == len(addresses) - 1:  # Every checked address refused: report the last error.
                    raise
    raise AssertionError('unreachable')  # pragma: no cover - the loop returns or raises


async def _read(
    response: httpx.Response,
    url: str,
    validators: Validators | None,
    max_bytes: int = MAX_BYTES,
    response_headers: DownloadHeaders | None = None,
) -> bytes:
    if response.status_code == 304:
        if validators is not None:
            raise NotModified(url)
        raise ValueError('The server answered 304 Not Modified to a request that asked for no validation')
    # Check before the status: httpx treats 3xx as an error, which would hide this message.
    if response.is_redirect:
        raise ValueError('Redirects are disabled; update the registry after reviewing the source')
    if not response.is_success:
        raise _status_error(response, url)
    if validators is not None:
        validators.etag = _validator(response, 'etag', 200)
        validators.last_modified = _validator(response, 'last-modified', 100)
    data = bytearray()
    async for chunk in response.aiter_bytes():
        data.extend(chunk)
        if len(data) > max_bytes:
            raise ValueError(f'Source exceeds the {max_bytes // 1_000_000} MB payload limit')
    if response_headers is not None:
        response_headers.read(response)
    return bytes(data)


def text_only(value: str | None) -> str:
    """Reduce feed HTML to plain text. Output is always rendered as text, never as markup."""
    return unescape(re.sub(r'<[^>]*>', ' ', value or '')).strip()


def _find_text(item: Any, name: str, *, nested: bool = False) -> str:
    el = item.find(name)
    if el is None:
        el = item.find(ATOM + name)
    if el is None:
        return ''
    # Atom's XHTML text constructs put the displayed text in child elements.
    return ' '.join(el.itertext()) if nested and len(el) else (el.text or '')


def _atom_link(item: Any) -> str:
    for el in item.findall(ATOM + 'link'):
        if el.get('rel', 'alternate') == 'alternate':
            return str(el.get('href', ''))
    return ''


def parse_feed(payload: bytes, source: Source, *, operator_tlp: TLP | None = None) -> list[FeedItem]:
    """Parse RSS 2.0 or Atom into at most :data:`MAX_FEED_ITEMS` bounded items.

    Identity preference: the (validated) link, then ``<guid>``/Atom ``<id>``. Links come first so that
    documents imported by 0.1.0, which stored only the link, keep matching after the upgrade.
    """
    if len(payload) > MAX_BYTES:
        raise ValueError('Source exceeds size limit')
    root = ElementTree.fromstring(payload)
    if operator_tlp is not None and not (
        root.tag == ATOM + 'feed' or (root.tag == 'rss' and root.find('channel') is not None)
    ):
        raise ValueError('Expected an RSS or Atom feed')
    items = root.findall('.//item') or root.findall(ATOM + 'entry')
    docs: list[FeedItem] = []
    for item in items[:MAX_FEED_ITEMS]:
        raw_title = _find_text(item, 'title', nested=operator_tlp is not None)
        full_title = text_only(raw_title)
        title = full_title[:300] or 'Untitled feed item'
        link = _find_text(item, 'link').strip() or _atom_link(item)
        full_summary = text_only(
            _find_text(item, 'description', nested=operator_tlp is not None)
            or _find_text(item, 'summary', nested=operator_tlp is not None)
        )
        summary = full_summary[:MAX_FEED_SUMMARY]
        body = title + '\n\n' + summary
        guid = (_find_text(item, 'guid') or _find_text(item, 'id')).strip()
        # Curated public feeds are CLEAR. Every operator feed carries its configured floor.
        tlp = operator_tlp or 'CLEAR'
        if operator_tlp is not None and (len(full_title) > 300 or len(full_summary) > MAX_FEED_SUMMARY):
            # A publisher's marking in the omitted text still applies to the retained excerpt.
            tlp = cast(
                'TLP', most_restrictive(operator_tlp, *tlp_markings(full_title), *tlp_markings(full_summary))
            )
        try:
            document = DocumentInput(
                title=title, body=body, source_name=source.name, source_url=link, tlp=tlp
            )
        except ValueError:
            # A malformed item cannot turn a dangerous link into a clickable source URL.
            document = DocumentInput(title=title, body=body, source_name=source.name, tlp=tlp)
        external_id = (document.source_url or guid)[:500] or None
        if operator_tlp is not None:
            # Hash the complete publisher ID so distinct long GUIDs cannot collide at the column limit.
            identity = document.source_url or guid
            if not identity:
                published = (_find_text(item, 'pubDate') or _find_text(item, 'published')).strip()
                # Without any publisher identity/date, only exact title+summary redeliveries can be matched.
                identity_field = ('published', published) if published else ('summary', full_summary)
                material = json.dumps([raw_title, *identity_field])
                identity = 'fallback:' + hashlib.sha256(material.encode()).hexdigest()
            else:
                identity = 'publisher:' + hashlib.sha256(identity.encode()).hexdigest()
            external_id = identity
        docs.append(FeedItem(document, external_id, truncated=len(full_summary) > MAX_FEED_SUMMARY))
    return docs


@dataclass(frozen=True, slots=True)
class CsafEntry:
    """One advisory file named by a CSAF ``changes.csv`` index, and when the publisher last changed it."""

    url: str
    changed: datetime
    #: The publication date in the advisory's file name, when it has one.
    published: date | None = None


def advisory_date(file_name: str) -> date | None:
    """The publication date in a CISA advisory file name (``icsa-26-323-03.json``: 2026-11-19) or ``None``.

    Two-digit years are 2000s; CISA's advisories start in 2010.
    """
    match = CSAF_DATE_RE.match(file_name)
    if not match or not 1 <= (day := int(match.group(2))) <= 366:
        return None
    first = date(2000 + int(match.group(1)), 1, 1)
    published = first + timedelta(days=day - 1)
    return published if published.year == first.year else None


def parse_csaf_changes(payload: bytes, index_url: str) -> list[CsafEntry]:
    """Parse a CSAF ``changes.csv`` index (``"path","timestamp"`` rows, quoted or not).

    Paths must be a year folder and a ``.json`` file name; anything else, and rows with an unreadable
    timestamp, are skipped. Raises ``ValueError`` if the index is too large or not UTF-8.
    """
    if len(payload) > MAX_BYTES:
        raise ValueError('CSAF index exceeds size limit')
    rows = list(islice(csv.reader(io.StringIO(payload.decode('utf-8'))), MAX_CSAF_INDEX_ROWS + 1))
    if len(rows) > MAX_CSAF_INDEX_ROWS:
        raise ValueError(f'CSAF index has more than {MAX_CSAF_INDEX_ROWS} rows')
    base = index_url.rsplit('/', 1)[0] + '/'
    entries: list[CsafEntry] = []
    for row in rows:
        if len(row) != 2 or not CSAF_PATH_RE.fullmatch(path := row[0].strip()):
            continue
        try:
            changed = datetime.fromisoformat(row[1].strip())
        except ValueError:
            continue
        changed = changed if changed.tzinfo else changed.replace(tzinfo=UTC)
        entries.append(CsafEntry(base + path, changed, advisory_date(path.rsplit('/', 1)[-1])))
    return entries


def _obj(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _items(value: Any) -> list[dict[str, Any]]:
    return [v for v in value if isinstance(v, dict)] if isinstance(value, list) else []


def _str(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ''


def _csaf_score(vulnerability: dict[str, Any]) -> str:
    for score in _items(vulnerability.get('scores')):
        for key, version in CSAF_SCORES:
            base = _obj(score.get(key)).get('baseScore')
            if isinstance(base, int | float) and not isinstance(base, bool):
                return f'CVSS {version} base score {base}'
    return ''


def parse_csaf(payload: bytes, source: Source, url: str) -> FeedItem:
    """Turn one CSAF 2.0 advisory into a report: its summary, vendors, sectors and every CVE with its score.

    Legal notices, generic recommended practices and product trees are left out. The report links to CISA's
    web page for the advisory when the file names one, otherwise to the file. ``truncated`` is set when
    vulnerabilities or long notes were cut. Raises ``ValueError`` for anything that is not a usable CSAF 2.0
    advisory.
    """
    if len(payload) > MAX_BYTES:
        raise ValueError('CSAF document exceeds size limit')
    data = _obj(json.loads(payload))
    doc = _obj(data.get('document'))
    tracking = _obj(doc.get('tracking'))
    advisory_id, title = _str(tracking.get('id')), _str(doc.get('title'))
    if doc.get('csaf_version') != '2.0' or not CSAF_ID_RE.fullmatch(advisory_id) or not title:
        raise ValueError('Not a CSAF 2.0 advisory with an ID and a title')
    label = _str(_obj(_obj(doc.get('distribution')).get('tlp')).get('label')).upper()
    tlp = CSAF_TLP.get(label or 'WHITE')  # files in CISA's public "white" folders without a label are public
    if tlp is None:
        raise ValueError('Unknown TLP label in CSAF document')

    cut = False

    def bounded(text: str) -> str:
        nonlocal cut
        cut = cut or len(text) > MAX_CSAF_NOTE
        return text[:MAX_CSAF_NOTE]

    notes = _items(doc.get('notes'))
    summary = ' '.join(
        bounded(t) for n in notes if n.get('category') == 'summary' and (t := _str(n.get('text')))
    )
    sectors = [
        bounded(t)
        for n in notes
        if n.get('category') == 'other'
        and 'sector' in _str(n.get('title')).lower()
        and (t := _str(n.get('text')))
    ]
    vendors = [
        name
        for b in _items(_obj(data.get('product_tree')).get('branches'))
        if b.get('category') == 'vendor' and (name := _str(b.get('name')))
    ]
    lines = [f'{advisory_id}: {title}', '']
    if summary:
        lines += [summary, '']
    if vendors:
        lines.append('Vendors: ' + ', '.join(vendors[:20]))
    if sectors:
        lines.append('Critical infrastructure sectors: ' + '; '.join(sectors))
    released, current = (
        _str(tracking.get('initial_release_date'))[:10],
        _str(tracking.get('current_release_date'))[:10],
    )
    version = _str(tracking.get('version'))
    if released:
        lines.append(
            f'Released {released}'
            + (f'; current version {version} ({current})' if version and current else '')
            + '.'
        )
    vulnerabilities = _items(data.get('vulnerabilities'))
    if vulnerabilities:
        lines += ['', 'Vulnerabilities:']
    for vulnerability in vulnerabilities[:MAX_CSAF_VULNERABILITIES]:
        cve = _str(vulnerability.get('cve'))
        about = next(
            (t for n in _items(vulnerability.get('notes')) if n.get('category') in ('summary', 'description')
             and (t := _str(n.get('text')))),
            _str(vulnerability.get('title')),
        )  # fmt: skip
        label_parts = [p for p in (cve if CVE_RE.fullmatch(cve) else '', _csaf_score(vulnerability)) if p]
        lines.append(f'- {", ".join(label_parts) or "No CVE"}: {bounded(about) or "No description"}')
    if len(vulnerabilities) > MAX_CSAF_VULNERABILITIES:
        cut = True
        lines.append(f'... and {len(vulnerabilities) - MAX_CSAF_VULNERABILITIES} more in the full advisory.')
    body = '\n'.join(lines)
    if len(body) > MAX_CSAF_BODY:
        body, cut = body[:MAX_CSAF_BODY], True

    web_page = next(
        (u for r in _items(doc.get('references'))
         if r.get('category') == 'self' and (u := _str(r.get('url'))).startswith('https://www.cisa.gov/')),
        '',
    )  # fmt: skip
    fields = {'title': f'{advisory_id} · {title}'[:300], 'body': body, 'source_name': source.name, 'tlp': tlp}
    try:
        document = DocumentInput(**fields, source_url=web_page or url)
    except ValueError:
        # A malformed link in the file cannot become a clickable source URL; the file's own address is safe.
        document = DocumentInput(**fields, source_url=url)
    return FeedItem(document, advisory_id, truncated=cut)


async def fetch_csaf(
    source: Source, prefetched: Mapping[str, bytes] | None = None
) -> tuple[list[FeedItem], int]:
    """Read every index of ``source``, then fetch and parse its :data:`CSAF_INBOX_LIMIT` newest advisories.

    Newest by publication date (from the file name), then by last change. Ranking by change time alone let
    CISA's bulk re-saves of years-old advisories crowd out new ones. Advisories already stored are fetched
    again while they stay among the newest, so CISA's updates to them still become revisions.

    Returns ``(items, skipped)``. One unreadable advisory is skipped and counted; an unreadable index, or no
    readable advisory at all, raises. ``prefetched`` holds index payloads the caller already downloaded.
    """
    entries: dict[str, CsafEntry] = {}
    for index_url in source.indexes:
        index = (prefetched or {}).get(index_url)
        for entry in parse_csaf_changes(index if index is not None else await download(index_url), index_url):
            entries.setdefault(entry.url, entry)
    by_age = sorted(
        entries.values(), key=lambda e: (e.published or e.changed.date(), e.changed), reverse=True
    )
    newest = by_age[:CSAF_INBOX_LIMIT]
    if not newest:
        raise ValueError('The CSAF index lists no advisories')
    items: list[FeedItem] = []
    for entry in newest:
        try:
            items.append(parse_csaf(await download(entry.url), source, entry.url))
        except (httpx.HTTPError, OSError, ValueError, RecursionError):
            continue
    if not items:
        raise ValueError(f'None of the {len(newest)} newest CSAF advisories could be read')
    return items, len(newest) - len(items)


def _validate_kev_rows(payload: bytes) -> list[dict[str, str]]:
    if len(payload) > MAX_BYTES:
        raise ValueError('KEV file exceeds size limit')
    try:
        data = json.loads(payload)
    except json.JSONDecodeError as exc:
        raise ValueError('KEV payload is not valid JSON') from exc
    rows = data.get('vulnerabilities') if isinstance(data, dict) else None
    if not isinstance(rows, list) or len(rows) > MAX_KEV_ROWS:
        raise ValueError('Expected a bounded CISA KEV vulnerabilities array')
    validated: list[dict[str, str]] = []
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError('Invalid KEV record')
        cve = row.get('cveID')
        if not isinstance(cve, str) or not CVE_RE.fullmatch(cve):
            raise ValueError('Invalid CVE in KEV input')
        clean = {'cveID': cve}
        for key in KEV_STRING_FIELDS:
            value = row.get(key, '')
            if not isinstance(value, str) or len(value) > MAX_KEV_FIELD:
                raise ValueError('Invalid KEV record field')
            clean[key] = value
        if clean['knownRansomwareCampaignUse'] not in KEV_RANSOMWARE:
            clean['knownRansomwareCampaignUse'] = ''
        cwes = row.get('cwes', [])
        if not isinstance(cwes, list) or len(cwes) > MAX_KEV_CWES:
            raise ValueError('Invalid KEV record field')
        if not all(isinstance(c, str) and KEV_CWE.fullmatch(c) for c in cwes):
            raise ValueError('Invalid KEV record field')
        clean['cwes'] = ','.join(dict.fromkeys(cwes))
        validated.append(clean)
    return validated


def import_kev(db: Session, payload: bytes) -> tuple[int, int]:
    """Upsert the full KEV catalog and add inbox documents under the KEV inbox policy (TIP 1.1).

    Reports are made for the newest ``KEV_INBOX_LIMIT`` entries by date added, and, after the first import,
    for every CVE new to the catalog since the last one (newest first, at most ``KEV_NEW_ENTRY_LIMIT``), so
    a CISA addition is never missed because more than the limit arrived between syncs or it carries an
    older date. The first import treats the whole catalog as background, not news.

    The payload is fully validated before any write, so malformed input never causes a partial import.
    Returns ``(records_validated, documents_created)``.
    """
    validated = _validate_kev_rows(payload)
    imported_at = now()
    known = known_kev(db)  # Empty on the first import: the whole catalog is not news.
    fresh: list[dict[str, str]] = []
    if known:
        fresh = [r for r in validated if r['cveID'] not in known]
        queue_kev_alerts(db, [(r['cveID'], r['vendorProject'], r['product']) for r in fresh])
    for row in validated:
        record = db.get(KEVRecord, row['cveID'])
        if record is None:
            record = KEVRecord(cve=row['cveID'])
            db.add(record)
        fields = {
            'vendor': row['vendorProject'],
            'product': row['product'],
            'date_added': row['dateAdded'],
            'due_date': row['dueDate'],
            'required_action': row['requiredAction'],
            'vulnerability_name': row['vulnerabilityName'],
            'ransomware_use': row['knownRansomwareCampaignUse'],
            'notes': row['notes'],
            'cwes': row['cwes'],
        }
        if not record.changed_at or any(getattr(record, name) != value for name, value in fields.items()):
            record.changed_at = imported_at
        for name, value in fields.items():
            setattr(record, name, value)
        record.imported_at = imported_at
    added = 0
    by_date = sorted(validated, key=lambda r: r['dateAdded'], reverse=True)
    reported = {r['cveID']: r for r in by_date[:KEV_INBOX_LIMIT]}
    for row in sorted(fresh, key=lambda r: r['dateAdded'], reverse=True)[:KEV_NEW_ENTRY_LIMIT]:
        reported.setdefault(row['cveID'], row)
    for row in reported.values():
        title = f'{row["cveID"]} · {row["vendorProject"]} {row["product"]}'[:300]
        body = (
            f'{title}\n\n{row["shortDescription"]}\n\nRequired action: {row["requiredAction"]}\n'
            f'Date added: {row["dateAdded"]}\nFederal remediation due date: {row["dueDate"]}'
        )
        _, created = ingest(
            db,
            DocumentInput(
                title=title,
                body=body[:200_000],
                source_name=SOURCES['cisa-kev'].name,
                source_url='https://www.cisa.gov/known-exploited-vulnerabilities-catalog',
                tlp='CLEAR',
            ),
            ref=SourceRef('cisa-kev', row['cveID']),
        )
        added += created
    return len(validated), added


@dataclass(frozen=True, slots=True)
class Fetched:
    """A changed payload of one URL, with what to remember about it once it is stored."""

    url: str
    payload: bytes
    validators: Validators
    sha256: str


def _remember(db: Session, fetched: list[Fetched]) -> None:
    for f in fetched:
        save_fetch_state(
            db,
            f.url,
            etag=f.validators.etag,
            last_modified=f.validators.last_modified,
            payload_sha256=f.sha256,
            version=__version__,
        )


def _load_validators(session_factory: SessionFactory, url: str) -> tuple[Validators, str] | None:
    """Validators and payload hash stored for ``url`` by this version of Insight, or ``None``."""
    with session_factory() as db:
        state = get_fetch_state(db, url)
        if state is None or state.insight_version != __version__:
            return None  # A new release re-reads every source once, in case its parsing changed.
        return Validators(state.etag, state.last_modified), state.payload_sha256


async def fetch_if_changed(
    session_factory: SessionFactory,
    url: str,
    *,
    headers: Mapping[str, str] | None = None,
    body: bytes | None = None,
    state_key: str | None = None,
    allowed_hosts: frozenset[str] | None = None,
    allow_private: bool = False,
) -> Fetched | None:
    """Download ``url`` unless it is unchanged since it was last stored: ``None`` then.

    Unchanged means a ``304`` to a conditional request, or the same bytes as last time (for servers that
    ignore ``If-None-Match`` and ``If-Modified-Since``).
    """
    key = state_key or url
    stored = await asyncio.to_thread(_load_validators, session_factory, key)
    validators = Validators(stored[0].etag, stored[0].last_modified) if stored else Validators()
    fetch = (
        download
        if allowed_hosts is None
        else partial(download, allowed_hosts=allowed_hosts, allow_private=allow_private)
    )
    try:
        payload = await fetch(
            url, headers=headers, body=body, validators=validators if body is None else None
        )
    except NotModified:
        if state_key is not None and not (stored and (stored[0].etag or stored[0].last_modified)):
            raise ValueError('Unexpected unchanged response to an unconditional request') from None
        return None
    digest = hashlib.sha256(payload).hexdigest()
    if stored is not None and digest == stored[1]:
        return None
    return Fetched(key, payload, validators, digest)


def _record_unchanged(session_factory: SessionFactory, source: Source) -> str:
    with session_factory.begin() as db:
        db.add(SourceRun(source_key=source.key, status='success', message=UNCHANGED))
    return UNCHANGED


def _store_source(session_factory: SessionFactory, source: Source, fetched: Fetched) -> str:
    payload = fetched.payload
    with session_factory.begin() as db:
        set_actor(db, f'connector:{source.key}')
        _remember(db, [fetched])
        if source.kind == 'kev':
            count, added = import_kev(db, payload)
            message = (
                f'Updated {count} KEV records; {added} new reports '
                f'(the newest {KEV_INBOX_LIMIT} entries and any added since the last sync).'
            )
        else:
            docs = parse_abusech(payload, source) if source.kind == 'abusech' else parse_feed(payload, source)
            message = f'Read {len(docs)} feed items; {_ingest_items(db, source, docs)} new reports.'
        db.add(SourceRun(source_key=source.key, status='success', message=message))
    return message


def _ingest_items(db: Session, source: Source, items: list[FeedItem]) -> int:
    """Store feed or advisory items keyed by their publisher identity; returns how many reports are new."""
    return sum(
        ingest(
            db,
            item.document,
            ref=SourceRef(source.key, item.external_id) if item.external_id else None,
            truncated=item.truncated,
        )[1]
        for item in items
    )


def _store_csaf(
    session_factory: SessionFactory,
    source: Source,
    items: list[FeedItem],
    skipped: int,
    indexes: list[Fetched],
) -> str:
    with session_factory.begin() as db:
        set_actor(db, f'connector:{source.key}')
        if not skipped:  # With advisories left unread, keep reading the index until they are all in.
            _remember(db, indexes)
        message = f'Read {len(items)} advisories; {_ingest_items(db, source, items)} new reports.'
        if skipped:
            message += f' {skipped} could not be read.'
        db.add(SourceRun(source_key=source.key, status='success', message=message))
    return message


def _record_failure(session_factory: SessionFactory, key: str, message: str) -> None:
    with session_factory.begin() as db:
        db.add(SourceRun(source_key=key, status='error', message=message))


async def fetch_otx(page: int = 1, since: str = '') -> bytes:
    """Fetch one page of this operator's subscriptions changed since ``since`` (all of them when ``''``).
    Pages are numbered here; OTX's ``next`` link is never followed."""
    key = os.environ.get('INSIGHT_OTX_API_KEY', '').strip()
    if not key:
        raise ValueError('Set INSIGHT_OTX_API_KEY to sync subscribed pulses')
    if len(key) > 512 or not key.isascii() or not key.isprintable() or ' ' in key:
        raise ValueError('Check INSIGHT_OTX_API_KEY: the key must be one printable token')
    try:
        params = {'page': str(page), 'limit': str(otx.PAGE_SIZE)}
        if since:
            params['modified_since'] = since
        return await download(OTX_SUBSCRIBED_URL, params, headers={'X-OTX-API-KEY': key})
    except httpx.HTTPStatusError as exc:
        status = exc.response.status_code
        hint = ' (check INSIGHT_OTX_API_KEY)' if status in (401, 403) else ''
        raise ValueError(f'OTX answered HTTP {status}{hint}') from None
    except Exception:
        # Transport diagnostics can quote a request header, including its secret value.
        raise ValueError('The OTX subscription request failed') from None


def _otx_cursor(session_factory: SessionFactory) -> otx.Cursor:
    with session_factory() as db:
        return otx.Cursor.parse(fetch_cursor(db, OTX_SUBSCRIBED_URL))


def _store_otx_page(
    session_factory: SessionFactory, source: Source, batch: otx.PulseBatch, cursor: otx.Cursor
) -> tuple[int, otx.Cursor]:
    """Store one page and where the next sync resumes, together: a later failure keeps this page's work."""
    following = cursor.after(batch)
    with session_factory.begin() as db:
        set_actor(db, f'connector:{source.key}')
        added = _ingest_items(db, source, batch.items)
        save_fetch_cursor(db, OTX_SUBSCRIBED_URL, following.dump())
    return added, following


def _record_otx(session_factory: SessionFactory, source: Source, message: str) -> str:
    with session_factory.begin() as db:
        db.add(SourceRun(source_key=source.key, status='success', message=message))
    return message


async def _sync_otx(session_factory: SessionFactory, source: Source) -> str:
    """Read up to ``otx.MAX_PAGES`` pages from the saved cursor (issue #11). Each page is stored with the
    cursor after it, so a failure or the page limit leaves the next sync to continue from the next page."""
    cursor = await asyncio.to_thread(_otx_cursor, session_factory)
    read = added = skipped = pages = 0
    for _ in range(otx.MAX_PAGES):
        batch = otx.parse_pulses(await fetch_otx(cursor.page, cursor.since), source)
        new, cursor = await asyncio.to_thread(_store_otx_page, session_factory, source, batch, cursor)
        read, added, skipped, pages = read + len(batch.items), added + new, skipped + batch.skipped, pages + 1
        if cursor.page == 1:  # the pass reached OTX's last page
            break
    message = (
        f'Read {read} public pulses on {pages} page{"s" if pages != 1 else ""}; {added} new reports. '
        f'Skipped {skipped} pulses.'
    )
    if cursor.page > 1:
        message += f' More remain; the next sync continues from page {cursor.page}.'
    return await asyncio.to_thread(_record_otx, session_factory, source, message)


def switches(session_factory: SessionFactory) -> dict[str, bool]:
    with session_factory() as db:
        return source_switches(db)


def sources_in_use(session_factory: SessionFactory, *, max_tlp: str | None = None) -> list[Source]:
    """The sources Insight may contact, in registry order (optional ones only once switched on)."""
    from . import operator_feed

    current = switches(session_factory)
    curated = [s for s in SOURCES.values() if in_use(s, current)]
    with session_factory() as db:
        return curated + operator_feed.enabled_sources(db, max_tlp=max_tlp)


def abusech_request(source: Source) -> tuple[dict[str, str], bytes | None]:
    """One fixed, read-only metadata query per source. The key is sent only as an HTTP header."""
    if source.kind != 'abusech':
        raise ValueError('Expected an abuse.ch source')
    key = os.environ.get('INSIGHT_ABUSECH_AUTH_KEY', '')
    if not key:
        raise ValueError('Set INSIGHT_ABUSECH_AUTH_KEY to use this source')
    if len(key) > 512 or not re.fullmatch(r'[!-~]+', key):
        raise ValueError('INSIGHT_ABUSECH_AUTH_KEY must be a single printable token')
    headers = {'Auth-Key': key}
    if source.key == 'urlhaus':
        return headers, None
    if source.key == 'threatfox':
        return {**headers, 'Content-Type': 'application/json'}, b'{"query":"get_iocs","days":1}'
    if source.key == 'malwarebazaar':
        return {
            **headers,
            'Content-Type': 'application/x-www-form-urlencoded',
        }, b'query=get_recent&selector=time'
    raise ValueError('Unknown abuse.ch source')


async def sync_source(
    session_factory: SessionFactory, key: str, *, max_tlp: str | None = None, actor: str = 'operator'
) -> str:
    """Download, validate and store one curated source. Every attempt is recorded as a ``SourceRun``.

    A source that has not changed since its last successful sync is not read again (:data:`UNCHANGED`).

    Raises ``ValueError`` for an unknown source, :class:`SourceSwitchedOff` for a source that is switched off
    and :class:`SourceSyncError` for any sync failure.
    """
    if key.startswith('op-'):
        from . import operator_feed

        return await operator_feed.sync(session_factory, key, max_tlp=max_tlp, actor=actor)
    source = SOURCES.get(key)
    if source is None:
        raise ValueError('Unknown source')
    if not in_use(source, await asyncio.to_thread(switches, session_factory)):
        raise SourceSwitchedOff(source)
    try:
        # Database work is synchronous; keep it off the event loop so the UI stays responsive.
        if source.kind == 'otx':
            return await _sync_otx(session_factory, source)
        if source.kind == 'csaf':
            changed = [f for url in source.indexes if (f := await fetch_if_changed(session_factory, url))]
            if not changed:
                return await asyncio.to_thread(_record_unchanged, session_factory, source)
            items, skipped = await fetch_csaf(source, {f.url: f.payload for f in changed})
            return await asyncio.to_thread(_store_csaf, session_factory, source, items, skipped, changed)
        if source.kind == 'abusech':
            headers, body = abusech_request(source)
            try:
                fetched = await fetch_if_changed(
                    session_factory, source.fetch_urls[0], headers=headers, body=body
                )
            except httpx.HTTPStatusError as exc:
                raise ValueError(f'{source.name} answered HTTP {exc.response.status_code}') from None
            except httpx.RequestError as exc:
                raise ValueError(f'{source.name} request failed ({type(exc).__name__})') from None
        else:
            fetched = await fetch_if_changed(session_factory, source.url)
        if fetched is None:
            return await asyncio.to_thread(_record_unchanged, session_factory, source)
        return await asyncio.to_thread(_store_source, session_factory, source, fetched)
    except Exception as exc:
        # Store a bounded diagnostic, never response bodies or credentials.
        message = f'{type(exc).__name__}: {str(exc)[:350]}'
        await asyncio.to_thread(_record_failure, session_factory, key, message)
        raise SourceSyncError(message) from exc


@dataclass(frozen=True, slots=True)
class SyncResult:
    """How one source fared in :func:`sync_all`: its run message, or the failure that was recorded."""

    key: str
    name: str
    ok: bool
    message: str


async def sync_all(
    session_factory: SessionFactory,
    *,
    on_start: Callable[[int, int, Source], None] | None = None,
    max_tlp: str | None = None,
    actor: str = 'operator',
) -> list[SyncResult]:
    """Sync every source in use (:func:`sources_in_use`) in registry order, one at a time, and report each.

    A failing source does not stop the others: its failure is recorded as a ``SourceRun`` (as for
    :func:`sync_source`) and returned. ``on_start(position, total, source)`` is called before each source,
    so a front end can show progress. Callers hold the sync lock, as for a single sync.
    """
    results: list[SyncResult] = []
    sources = await asyncio.to_thread(sources_in_use, session_factory, max_tlp=max_tlp)
    for position, source in enumerate(sources, start=1):
        if on_start is not None:
            on_start(position, len(sources), source)
        try:
            if source.key.startswith('op-'):
                message = await sync_source(session_factory, source.key, max_tlp=max_tlp, actor=actor)
            else:
                message = await sync_source(session_factory, source.key)
            results.append(SyncResult(source.key, source.name, True, message))
        except (SourceSyncError, SourceSwitchedOff) as exc:
            results.append(SyncResult(source.key, source.name, False, str(exc)))
        except LookupError:
            # An operator may remove an entry while earlier sources are being read.
            results.append(SyncResult(source.key, source.name, False, 'The source is no longer available.'))
    return results


def enrichment_request(cve: str, provider: str) -> tuple[str, dict[str, str]]:
    """Validate an enrichment request and return ``(url, params)``. Raises ``ValueError`` if invalid."""
    if not CVE_RE.fullmatch(cve):
        raise ValueError('Invalid CVE')
    if provider not in PROVIDERS:
        raise ValueError('Unknown provider')
    return PROVIDERS[provider], {_PROVIDER_PARAM[provider]: cve}


def _cve_is_known(session_factory: SessionFactory, cve: str) -> bool:
    with session_factory() as db:
        return db.scalar(select(Entity.id).where(Entity.kind == 'cve', Entity.value == cve)) is not None


def _store_enrichment(
    session_factory: SessionFactory, cve: str, provider: str, payload: dict[str, Any]
) -> None:
    if provider == 'vulncheck':  # Metadata only: never descriptions, code or clone URLs (ADR 0028).
        payload = summarise_vulncheck(payload, cve)
    with session_factory.begin() as db:
        record = db.scalar(select(Enrichment).where(Enrichment.cve == cve, Enrichment.provider == provider))
        if record is None:
            record = Enrichment(cve=cve, provider=provider)
            db.add(record)
        record.payload, record.fetched_at = json.dumps(payload), now()


async def validate_enrichment(session_factory: SessionFactory, cve: str, provider: str) -> None:
    """Raise ``ValueError`` unless :func:`enrich_cve` would send this request (valid CVE and provider, and a
    report mentions the CVE). Callers check this before consuming the enrichment throttle window."""
    enrichment_request(cve, provider)
    if provider in KEY_REQUIRED and not provider_key(provider):
        raise ValueError(f'Set {PROVIDER_KEYS[provider]} to look CVEs up at this provider')
    if not await asyncio.to_thread(_cve_is_known, session_factory, cve):
        raise ValueError('Import a report mentioning this CVE first')


def provider_key(provider: str) -> str:
    """The operator's key for ``provider`` from its setting, or ``''``."""
    setting = PROVIDER_KEYS.get(provider)
    return os.environ.get(setting, '').strip() if setting else ''


def provider_headers(provider: str) -> dict[str, str]:
    """Headers for ``provider``: NVD's ``apiKey`` or VulnCheck's Bearer token, when set (never logged)."""
    key = provider_key(provider)
    if not key:
        return {}
    return {'Authorization': f'Bearer {key}'} if provider == 'vulncheck' else {'apiKey': key}


async def fetch_provider_json(provider: str, params: Mapping[str, str]) -> dict[str, Any]:
    """GET ``provider``'s API with ``params`` and return its JSON object. Raises :class:`ProviderError`."""
    headers = provider_headers(provider)
    try:
        if headers:
            raw = await download(PROVIDERS[provider], params, headers=headers)
        else:  # Keeps the call the tests' fake downloads expect.
            raw = await download(PROVIDERS[provider], params)
    except httpx.HTTPStatusError as exc:
        code = exc.response.status_code
        # A provider refuses a wrong key with a client error, so point at the setting (never at the key).
        hint = f' (check {PROVIDER_KEYS[provider]})' if headers and code in (401, 403, 404) else ''
        wide = code in PROVIDER_WIDE_STATUSES or code >= 500
        raise ProviderError(f'{provider.upper()} answered HTTP {code}{hint}', provider_wide=wide) from exc
    except (httpx.HTTPError, OSError, ValueError) as exc:
        # Size-limit, redirect and DNS-policy violations are upstream problems too, not bad client input.
        raise ProviderError(f'{provider.upper()} request failed: {type(exc).__name__}') from exc
    try:
        payload = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ProviderError(f'{provider.upper()} returned a non-JSON response', provider_wide=False) from exc
    if not isinstance(payload, dict):
        raise ProviderError(f'{provider.upper()} returned an unexpected response', provider_wide=False)
    return payload


def store_enrichment(
    session_factory: SessionFactory, cve: str, provider: str, payload: dict[str, Any]
) -> None:
    """Cache ``payload`` as ``provider``'s answer for ``cve`` (one row per CVE and provider)."""
    _store_enrichment(session_factory, cve, provider, payload)


async def enrich_cve(session_factory: SessionFactory, cve: str, provider: str) -> dict[str, Any]:
    """Look up ``cve`` at ``provider`` (``epss``, ``nvd`` or ``vulncheck``) and cache the answer, unthrottled.

    People's lookups go through ``insight.lookups.request_lookup``, which applies the shared throttle. Raises
    ``ValueError`` for invalid requests and :class:`ProviderError` for upstream failures.
    """
    await validate_enrichment(session_factory, cve, provider)
    _, params = enrichment_request(cve, provider)
    payload = await fetch_provider_json(provider, params)
    await asyncio.to_thread(_store_enrichment, session_factory, cve, provider, payload)
    return summarise_vulncheck(payload, cve) if provider == 'vulncheck' else payload
