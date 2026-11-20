"""Curated, opt-in connectors. No arbitrary URL fetch endpoint; no article crawling."""

from __future__ import annotations

import asyncio
import csv
import io
import ipaddress
import json
import re
import socket
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from html import unescape
from itertools import islice
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
#: CISA publishes its advisories as CSAF 2.0 files on GitHub (its RSS feeds refuse automated clients).
#: Folder OT holds the industrial control system advisories, IT the other vulnerability advisories; VA
#: repeats IT.
CSAF_BASE: Final = 'https://raw.githubusercontent.com/cisagov/CSAF/develop/csaf_files/'
CSAF_INBOX_LIMIT: Final = 25
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
    #: The feed for ``kev`` and ``rss`` sources. For ``csaf`` sources, the page people open to browse them.
    url: str
    kind: Literal['kev', 'rss', 'csaf']
    note: str
    #: ``csaf`` sources: the ``changes.csv`` index of each CSAF folder that is read.
    indexes: tuple[str, ...] = ()

    @property
    def fetch_urls(self) -> tuple[str, ...]:
        """The URLs a sync requests first (advisory files named by a CSAF index sit beside it)."""
        return self.indexes or (self.url,)


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
            'cisa-csaf',
            'CISA Security Advisories',
            'https://github.com/cisagov/CSAF',
            'csaf',
            f'The {CSAF_INBOX_LIMIT} newest advisories CISA has published about weaknesses in industrial '
            "control systems and other products, from CISA's machine-readable files (CSAF). Advisories about "
            'attacker groups are not included.',
            indexes=(CSAF_BASE + 'OT/white/changes.csv', CSAF_BASE + 'IT/white/changes.csv'),
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
    {h for s in SOURCES.values() for u in s.fetch_urls if (h := urlsplit(u).hostname)}
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


async def fetch_csaf(source: Source) -> tuple[list[FeedItem], int]:
    """Read every index of ``source``, then fetch and parse its :data:`CSAF_INBOX_LIMIT` newest advisories.

    Newest by publication date (from the file name), then by last change. Ranking by change time alone let
    CISA's bulk re-saves of years-old advisories crowd out new ones. Advisories already stored are fetched
    again while they stay among the newest, so CISA's updates to them still become revisions.

    Returns ``(items, skipped)``. One unreadable advisory is skipped and counted; an unreadable index, or no
    readable advisory at all, raises.
    """
    entries: dict[str, CsafEntry] = {}
    for index_url in source.indexes:
        for entry in parse_csaf_changes(await download(index_url), index_url):
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


def _store_csaf(session_factory: SessionFactory, source: Source, items: list[FeedItem], skipped: int) -> str:
    with session_factory.begin() as db:
        set_actor(db, f'connector:{source.key}')
        message = f'Read {len(items)} advisories; {_ingest_items(db, source, items)} new reports.'
        if skipped:
            message += f' {skipped} could not be read.'
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
        # Database work is synchronous; keep it off the event loop so the UI stays responsive.
        if source.kind == 'csaf':
            items, skipped = await fetch_csaf(source)
            return await asyncio.to_thread(_store_csaf, session_factory, source, items, skipped)
        payload = await download(source.url)
        return await asyncio.to_thread(_store_source, session_factory, source, payload)
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
    session_factory: SessionFactory, *, on_start: Callable[[int, int, Source], None] | None = None
) -> list[SyncResult]:
    """Sync every curated source in registry order, one at a time, and report each result.

    A failing source does not stop the others: its failure is recorded as a ``SourceRun`` (as for
    :func:`sync_source`) and returned. ``on_start(position, total, source)`` is called before each source,
    so a front end can show progress. Callers hold the sync lock, as for a single sync.
    """
    results: list[SyncResult] = []
    for position, source in enumerate(SOURCES.values(), start=1):
        if on_start is not None:
            on_start(position, len(SOURCES), source)
        try:
            results.append(
                SyncResult(source.key, source.name, True, await sync_source(session_factory, source.key))
            )
        except SourceSyncError as exc:
            results.append(SyncResult(source.key, source.name, False, str(exc)))
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
    if not await asyncio.to_thread(_cve_is_known, session_factory, cve):
        raise ValueError('Import a report mentioning this CVE first')


async def enrich_cve(session_factory: SessionFactory, cve: str, provider: str) -> dict[str, Any]:
    """Look up ``cve`` at ``provider`` (``epss`` or ``nvd``) and cache the JSON response.

    Raises ``ValueError`` for invalid requests and :class:`ProviderError` for upstream failures.
    """
    await validate_enrichment(session_factory, cve, provider)
    url, params = enrichment_request(cve, provider)
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
