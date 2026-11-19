"""Curated, opt-in connectors. No arbitrary URL fetch endpoint; no article crawling."""

from __future__ import annotations

import asyncio
import ipaddress
import json
import re
import socket
from collections.abc import Mapping
from dataclasses import dataclass
from html import unescape
from typing import Any, Final, Literal
from urllib.parse import urlsplit

import httpx
from defusedxml import ElementTree
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import __version__
from .models import Enrichment, Entity, KEVRecord, SessionFactory, SourceRun, now
from .schemas import DocumentInput
from .services import SourceRef, ingest, set_actor

MAX_BYTES: Final = 8_000_000
MAX_FEED_ITEMS: Final = 100
MAX_FEED_SUMMARY: Final = 500
MAX_KEV_ROWS: Final = 20_000
MAX_KEV_FIELD: Final = 10_000
KEV_INBOX_LIMIT: Final = 100
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
)

PROVIDERS: Final[dict[str, str]] = {
    'epss': 'https://api.first.org/data/v1/epss',
    'nvd': 'https://services.nvd.nist.gov/rest/json/cves/2.0',
}
_PROVIDER_PARAM: Final[dict[str, str]] = {'epss': 'cve', 'nvd': 'cveId'}


class ConnectorError(Exception):
    """Base class for failures talking to, or interpreting data from, an external source."""


class ProviderError(ConnectorError):
    """An upstream provider failed or returned something unusable (maps to HTTP 502)."""


class SourceSyncError(ConnectorError):
    """A curated source sync failed. The failure has already been recorded as a ``SourceRun``."""


@dataclass(frozen=True, slots=True)
class Source:
    key: str
    name: str
    url: str
    kind: Literal['kev', 'rss']
    note: str


SOURCES: Final[dict[str, Source]] = {
    s.key: s
    for s in (
        Source(
            'cisa-kev',
            'CISA Known Exploited Vulnerabilities',
            'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
            'kev',
            'Known exploitation evidence; due dates apply to covered federal agencies, '
            'not a universal deadline.',
        ),
        Source(
            'cisa-advisories',
            'CISA Cybersecurity Advisories',
            'https://www.cisa.gov/cybersecurity-advisories/all.xml',
            'rss',
            'Metadata and up to 500 characters of feed summary; no full-article crawling.',
        ),
        Source(
            'sans-isc',
            'SANS Internet Storm Center',
            'https://isc.sans.edu/rssfeed.xml',
            'rss',
            'Feed metadata only. Publisher terms still apply; free access is not a redistribution license.',
        ),
        Source(
            'ncsc',
            'UK NCSC Reports',
            'https://www.ncsc.gov.uk/api/1/services/v1/report-rss-feed.xml',
            'rss',
            'Feed metadata only. Check publisher attribution and reuse terms.',
        ),
    )
}
ALLOWED_HOSTS: Final[frozenset[str]] = frozenset(
    {h for s in SOURCES.values() if (h := urlsplit(s.url).hostname)}
    | {urlsplit(u).hostname or '' for u in PROVIDERS.values()}
)


async def _assert_public(hostname: str) -> None:
    addresses = await asyncio.to_thread(socket.getaddrinfo, hostname, 443, 0, socket.SOCK_STREAM)
    if not addresses or any(not ipaddress.ip_address(str(a[4][0])).is_global for a in addresses):
        raise ValueError('Source resolves to a non-public destination')


async def download(
    url: str,
    params: Mapping[str, str] | None = None,
    *,
    transport: httpx.AsyncBaseTransport | None = None,
) -> bytes:
    """Fetch ``url`` from the curated HTTPS registry with strict size and redirect limits.

    ``transport`` exists for offline testing; production code never passes it.
    """
    parts = urlsplit(url)
    if parts.scheme != 'https' or parts.hostname not in ALLOWED_HOSTS or parts.username or parts.password:
        raise ValueError('Outbound URL is not in the curated HTTPS source registry')
    try:
        port = parts.port
    except ValueError:
        port = -1
    if port not in (None, 443):
        raise ValueError('Outbound URL is not in the curated HTTPS source registry')
    await _assert_public(parts.hostname)
    # Fixed application-owned hosts only. An egress firewall remains recommended against DNS rebinding.
    async with (
        httpx.AsyncClient(
            timeout=httpx.Timeout(25), follow_redirects=False, trust_env=False, transport=transport
        ) as client,
        client.stream(
            'GET', url, params=params, headers={'User-Agent': USER_AGENT, 'Accept-Encoding': 'identity'}
        ) as response,
    ):
        # Check before raise_for_status(): httpx treats 3xx as an error, which would hide this message.
        if response.is_redirect:
            raise ValueError('Redirects are disabled; update the registry after reviewing the source')
        response.raise_for_status()
        data = bytearray()
        async for chunk in response.aiter_bytes():
            data.extend(chunk)
            if len(data) > MAX_BYTES:
                raise ValueError('Source exceeds the 8 MB payload limit')
        return bytes(data)


def text_only(value: str | None) -> str:
    """Reduce feed HTML to plain text. Output is always rendered as text, never as markup."""
    return unescape(re.sub(r'<[^>]*>', ' ', value or '')).strip()


def _find_text(item: Any, name: str) -> str:
    el = item.find(name)
    if el is None:
        el = item.find(ATOM + name)
    return (el.text or '') if el is not None else ''


def _atom_link(item: Any) -> str:
    for el in item.findall(ATOM + 'link'):
        if el.get('rel', 'alternate') == 'alternate':
            return str(el.get('href', ''))
    return ''


@dataclass(frozen=True, slots=True)
class FeedItem:
    """A parsed feed entry and its stable identity at the publisher (``None`` if it has none)."""

    document: DocumentInput
    external_id: str | None
    #: The publisher's summary was longer than :data:`MAX_FEED_SUMMARY` and was cut.
    truncated: bool = False


def parse_feed(payload: bytes, source: Source) -> list[FeedItem]:
    """Parse RSS 2.0 or Atom into at most :data:`MAX_FEED_ITEMS` bounded items.

    Identity preference: the (validated) link, then ``<guid>``/Atom ``<id>``. Links come first so that
    documents imported by 0.1.0, which stored only the link, keep matching after the upgrade.
    """
    if len(payload) > MAX_BYTES:
        raise ValueError('Source exceeds size limit')
    root = ElementTree.fromstring(payload)
    items = root.findall('.//item') or root.findall(ATOM + 'entry')
    docs: list[FeedItem] = []
    for item in items[:MAX_FEED_ITEMS]:
        title = text_only(_find_text(item, 'title'))[:300] or 'Untitled feed item'
        link = _find_text(item, 'link').strip() or _atom_link(item)
        full_summary = text_only(_find_text(item, 'description') or _find_text(item, 'summary'))
        summary = full_summary[:MAX_FEED_SUMMARY]
        body = title + '\n\n' + summary
        guid = (_find_text(item, 'guid') or _find_text(item, 'id')).strip()
        # Public feeds are TLP:CLEAR (explicit: the schema default is the more restrictive AMBER).
        try:
            document = DocumentInput(
                title=title, body=body, source_name=source.name, source_url=link, tlp='CLEAR'
            )
        except ValueError:
            # A malformed item cannot turn a dangerous link into a clickable source URL.
            document = DocumentInput(title=title, body=body, source_name=source.name, tlp='CLEAR')
        external_id = (document.source_url or guid)[:500] or None
        docs.append(FeedItem(document, external_id, truncated=len(full_summary) > MAX_FEED_SUMMARY))
    return docs


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
        validated.append(clean)
    return validated


def import_kev(db: Session, payload: bytes) -> tuple[int, int]:
    """Upsert the full KEV catalog and add inbox documents for the newest entries.

    The payload is fully validated before any write, so malformed input never causes a partial import.
    Returns ``(records_validated, documents_created)``.
    """
    validated = _validate_kev_rows(payload)
    imported_at = now()
    for row in validated:
        record = db.get(KEVRecord, row['cveID'])
        if record is None:
            record = KEVRecord(cve=row['cveID'])
            db.add(record)
        record.vendor = row['vendorProject']
        record.product = row['product']
        record.date_added = row['dateAdded']
        record.due_date = row['dueDate']
        record.required_action = row['requiredAction']
        record.imported_at = imported_at
    added = 0
    newest = sorted(validated, key=lambda r: r['dateAdded'], reverse=True)[:KEV_INBOX_LIMIT]
    for row in newest:
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


def _store_source(session_factory: SessionFactory, source: Source, payload: bytes) -> str:
    with session_factory.begin() as db:
        set_actor(db, f'connector:{source.key}')
        if source.kind == 'kev':
            count, added = import_kev(db, payload)
            message = (
                f'Updated {count} KEV records; {added} new reports from the latest {KEV_INBOX_LIMIT} entries.'
            )
        else:
            docs = parse_feed(payload, source)
            added = sum(
                ingest(
                    db,
                    d.document,
                    ref=SourceRef(source.key, d.external_id) if d.external_id else None,
                    truncated=d.truncated,
                )[1]
                for d in docs
            )
            message = f'Read {len(docs)} feed items; {added} new reports.'
        db.add(SourceRun(source_key=source.key, status='success', message=message))
    return message


def _record_failure(session_factory: SessionFactory, key: str, message: str) -> None:
    with session_factory.begin() as db:
        db.add(SourceRun(source_key=key, status='error', message=message))


async def sync_source(session_factory: SessionFactory, key: str) -> str:
    """Download, validate and store one curated source. Every attempt is recorded as a ``SourceRun``.

    Raises ``ValueError`` for an unknown source and :class:`SourceSyncError` for any sync failure.
    """
    source = SOURCES.get(key)
    if source is None:
        raise ValueError('Unknown source')
    try:
        payload = await download(source.url)
        # Database work is synchronous; keep it off the event loop so the UI stays responsive.
        return await asyncio.to_thread(_store_source, session_factory, source, payload)
    except Exception as exc:
        # Store a bounded diagnostic, never response bodies or credentials.
        message = f'{type(exc).__name__}: {str(exc)[:350]}'
        await asyncio.to_thread(_record_failure, session_factory, key, message)
        raise SourceSyncError(message) from exc


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
    with session_factory.begin() as db:
        record = db.scalar(select(Enrichment).where(Enrichment.cve == cve, Enrichment.provider == provider))
        if record is None:
            record = Enrichment(cve=cve, provider=provider)
            db.add(record)
        record.payload, record.fetched_at = json.dumps(payload), now()


async def enrich_cve(session_factory: SessionFactory, cve: str, provider: str) -> dict[str, Any]:
    """Look up ``cve`` at ``provider`` (``epss`` or ``nvd``) and cache the JSON response.

    Raises ``ValueError`` for invalid requests and :class:`ProviderError` for upstream failures.
    """
    url, params = enrichment_request(cve, provider)
    if not await asyncio.to_thread(_cve_is_known, session_factory, cve):
        raise ValueError('Import a report mentioning this CVE first')
    try:
        raw = await download(url, params)
    except (httpx.HTTPError, OSError, ValueError) as exc:
        # Size-limit, redirect and DNS-policy violations are upstream problems too, not bad client input.
        raise ProviderError(f'{provider.upper()} request failed: {type(exc).__name__}') from exc
    try:
        payload = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ProviderError(f'{provider.upper()} returned a non-JSON response') from exc
    if not isinstance(payload, dict):
        raise ProviderError(f'{provider.upper()} returned an unexpected response')
    await asyncio.to_thread(_store_enrichment, session_factory, cve, provider, payload)
    return payload
