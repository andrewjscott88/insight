"""CISA CSAF advisories: index parsing, advisory mapping, bounds and the sync (network replaced by fakes).

The two fixtures are real CISA advisories (US government works): ``icsa-26-323-03`` from the OT folder, which
links to its web page, and ``va-26-317-01`` from the IT folder, which does not.
"""

from __future__ import annotations

import copy
import json
from collections.abc import Callable, Coroutine
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import httpx
import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from insight import connectors
from insight.connectors import (
    ALLOWED_HOSTS,
    CSAF_BASE,
    CSAF_INBOX_LIMIT,
    MAX_CSAF_INDEX_ROWS,
    MAX_CSAF_VULNERABILITIES,
    SOURCES,
    SourceSyncError,
    parse_csaf,
    parse_csaf_changes,
    sync_source,
)
from insight.models import Document, SourceRun

FIXTURES = Path(__file__).parents[1] / 'fixtures' / 'csaf'
ICS = (FIXTURES / 'icsa-26-323-03.json').read_bytes()
IT = (FIXTURES / 'va-26-317-01.json').read_bytes()
SOURCE = SOURCES['cisa-csaf']
OT_INDEX, IT_INDEX = SOURCE.indexes
ICS_URL = CSAF_BASE + 'OT/white/2026/icsa-26-323-03.json'
IT_URL = CSAF_BASE + 'IT/white/2026/va-26-317-01.json'

Download = Callable[..., Coroutine[Any, Any, bytes]]


def advisory(raw: bytes = ICS, **changes: Any) -> dict[str, Any]:
    """A copy of a real advisory with top-level ``document`` fields replaced."""
    data: dict[str, Any] = copy.deepcopy(json.loads(raw))
    data['document'].update(changes)
    return data


def encode(data: dict[str, Any]) -> bytes:
    return json.dumps(data).encode()


def serving(files: dict[str, bytes | BaseException], calls: list[str] | None = None) -> Download:
    """A fake ``download`` that serves ``files`` by URL (an exception value is raised instead)."""

    async def fake(url: str, params: Any = None, **_: Any) -> bytes:
        if calls is not None:
            calls.append(url)
        found = files.get(url, httpx.HTTPStatusError('404', request=httpx.Request('GET', url), response=None))  # type: ignore[arg-type]
        if isinstance(found, BaseException):
            raise found
        return found

    return fake


# --------------------------------------------------------------------------- registry


def test_csaf_source_fetches_only_from_cisas_raw_github_folders() -> None:
    assert SOURCE.kind == 'csaf'
    assert SOURCE.fetch_urls == SOURCE.indexes
    assert all(u.startswith(CSAF_BASE) and u.endswith('/white/changes.csv') for u in SOURCE.indexes)
    assert 'raw.githubusercontent.com' in ALLOWED_HOSTS
    # The browse link is for people; it is never fetched, so its host is not allowed for downloads.
    assert urlsplit(SOURCE.url).hostname == 'github.com'
    assert 'github.com' not in ALLOWED_HOSTS


def test_the_blocked_cisa_rss_feed_is_gone() -> None:
    """Regression: cisa.gov answers 403 Access Denied to automated clients for its advisories RSS feed."""
    assert 'cisa-advisories' not in SOURCES
    assert all('cybersecurity-advisories' not in u for s in SOURCES.values() for u in s.fetch_urls)


# --------------------------------------------------------------------------- changes.csv


def test_index_rows_quoted_or_not_become_absolute_urls() -> None:
    payload = (
        b'"2026/icsa-26-323-03.json","2026-11-19T06:00:00.000000Z"\n'
        b'2026/va-26-317-01.json,2026-11-13T16:45:20Z\n'
        b'2025/naive-time.json,2025-01-02T03:04:05\n'
    )
    entries = parse_csaf_changes(payload, OT_INDEX)
    assert [e.url for e in entries] == [
        CSAF_BASE + 'OT/white/2026/icsa-26-323-03.json',
        CSAF_BASE + 'OT/white/2026/va-26-317-01.json',
        CSAF_BASE + 'OT/white/2025/naive-time.json',
    ]
    assert [e.changed.isoformat() for e in entries] == [
        '2026-11-19T06:00:00+00:00',
        '2026-11-13T16:45:20+00:00',
        '2025-01-02T03:04:05+00:00',
    ]


@pytest.mark.parametrize(
    'row',
    [
        '../../../secrets.json,2026-01-01T00:00:00Z',
        '2026/../../x.json,2026-01-01T00:00:00Z',
        '/etc/passwd.json,2026-01-01T00:00:00Z',
        'https://evil.example/2026/a.json,2026-01-01T00:00:00Z',
        '2026/A-UPPER.json,2026-01-01T00:00:00Z',
        '2026/advisory.json.asc,2026-01-01T00:00:00Z',
        '2026/advisory.json,not a date',
        '2026/advisory.json',
        '2026/advisory.json,2026-01-01T00:00:00Z,extra',
        '',
    ],
)
def test_index_rows_outside_the_folder_or_malformed_are_skipped(row: str) -> None:
    assert parse_csaf_changes(row.encode(), OT_INDEX) == []


def test_index_size_is_bounded() -> None:
    rows = b'2026/a.json,2026-01-01T00:00:00Z\n' * (MAX_CSAF_INDEX_ROWS + 1)
    with pytest.raises(ValueError, match='more than'):
        parse_csaf_changes(rows, OT_INDEX)
    with pytest.raises(ValueError, match='size limit'):
        parse_csaf_changes(b'x' * (connectors.MAX_BYTES + 1), OT_INDEX)


# --------------------------------------------------------------------------- one advisory


def test_ics_advisory_becomes_a_public_report_linked_to_cisas_web_page() -> None:
    item = parse_csaf(ICS, SOURCE, ICS_URL)
    doc = item.document
    assert item.external_id == 'ICSA-26-323-03'
    assert not item.truncated
    assert (doc.title, doc.source_name, doc.tlp) == ('ICSA-26-323-03 · libumqtt', SOURCE.name, 'CLEAR')
    assert doc.source_url == 'https://www.cisa.gov/news-events/ics-advisories/icsa-26-323-03'
    assert doc.body.startswith('ICSA-26-323-03: libumqtt\n\nSuccessful exploitation')
    assert 'Vendors: libumqtt' in doc.body
    assert 'Critical infrastructure sectors: Critical Manufacturing, Energy' in doc.body
    assert 'Released 2026-11-19; current version 1 (2026-11-19).' in doc.body
    assert '- CVE-2026-125132, CVSS 3 base score 8.6: The affected product is vulnerable' in doc.body
    # Boilerplate stays out: it is the same in every advisory and would drown the signal.
    assert 'Legal Notice' not in doc.body
    assert 'Recommended' not in doc.body


def test_it_advisory_without_a_web_page_links_to_the_file() -> None:
    item = parse_csaf(IT, SOURCE, IT_URL)
    assert item.external_id == 'VA-26-317-01'
    assert item.document.source_url == IT_URL
    assert item.document.title == 'VA-26-317-01 · Jet Admin Cloud Platform Prompt Injection'
    assert '- CVE-2026-123965, CVSS 3 base score 9.9: A prompt injection vulnerability' in item.document.body


@pytest.mark.parametrize(
    ('label', 'tlp'), [('WHITE', 'CLEAR'), ('clear', 'CLEAR'), ('GREEN', 'GREEN'), ('AMBER', 'AMBER')]
)
def test_tlp_labels_map_to_tlp_2(label: str, tlp: str) -> None:
    data = advisory(distribution={'tlp': {'label': label}})
    assert parse_csaf(encode(data), SOURCE, ICS_URL).document.tlp == tlp


def test_missing_tlp_in_the_public_folder_is_clear() -> None:
    data = advisory(distribution={})
    assert parse_csaf(encode(data), SOURCE, ICS_URL).document.tlp == 'CLEAR'


NOT_CSAF = 'Not a CSAF 2.0 advisory'


@pytest.mark.parametrize(
    ('payload', 'message'),
    [
        (b'not json', 'Expecting value'),
        (b'[]', NOT_CSAF),
        (b'{"document": "x"}', NOT_CSAF),
        (encode(advisory(csaf_version='2.1')), NOT_CSAF),
        (encode(advisory(title='   ')), NOT_CSAF),
        (encode(advisory(tracking={'id': '../evil'})), NOT_CSAF),
        (encode(advisory(tracking={'id': 7})), NOT_CSAF),
        (encode(advisory(distribution={'tlp': {'label': 'PURPLE'}})), 'Unknown TLP label'),
    ],
)
def test_unusable_documents_raise_value_error(payload: bytes, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        parse_csaf(payload, SOURCE, ICS_URL)


def test_many_vulnerabilities_are_capped_and_marked_truncated() -> None:
    data = advisory()
    (one,) = data['vulnerabilities']
    data['vulnerabilities'] = [
        {**one, 'cve': f'CVE-2026-{100000 + n}'} for n in range(MAX_CSAF_VULNERABILITIES + 3)
    ]
    item = parse_csaf(encode(data), SOURCE, ICS_URL)
    assert item.truncated
    assert item.document.body.count('\n- CVE-2026-') == MAX_CSAF_VULNERABILITIES
    assert item.document.body.endswith('... and 3 more in the full advisory.')


def test_a_very_long_note_is_cut_and_marked_truncated() -> None:
    data = advisory()
    data['document']['notes'].append({'category': 'summary', 'text': 'x' * (connectors.MAX_CSAF_NOTE + 1)})
    item = parse_csaf(encode(data), SOURCE, ICS_URL)
    assert item.truncated
    assert 'x' * connectors.MAX_CSAF_NOTE in item.document.body
    assert 'x' * (connectors.MAX_CSAF_NOTE + 1) not in item.document.body


def test_hostile_values_in_known_fields_are_ignored_not_trusted() -> None:
    data = advisory(
        references=[{'category': 'self', 'url': 'https://www.cisa.gov.evil.example/x'}, 'not an object'],
        notes=[{'category': 'summary', 'text': ['not', 'text']}, None],
    )
    data['vulnerabilities'] = [{'cve': 'not-a-cve', 'scores': [{'cvss_v3': {'baseScore': True}}]}, 'junk']
    data['product_tree'] = {'branches': 'not a list'}
    item = parse_csaf(encode(data), SOURCE, ICS_URL)
    assert '- No CVE: No description' in item.document.body
    assert 'Vendors:' not in item.document.body
    assert item.document.source_url == ICS_URL  # only CISA's own web pages replace the file's address


def test_document_and_body_sizes_are_bounded() -> None:
    with pytest.raises(ValueError, match='size limit'):
        parse_csaf(b'x' * (connectors.MAX_BYTES + 1), SOURCE, ICS_URL)
    data = advisory()
    (one,) = data['vulnerabilities']
    long_note = [{'category': 'summary', 'text': 'y' * connectors.MAX_CSAF_NOTE}]
    data['vulnerabilities'] = [{**one, 'notes': long_note} for _ in range(MAX_CSAF_VULNERABILITIES)]
    item = parse_csaf(encode(data), SOURCE, ICS_URL)
    assert len(item.document.body) == connectors.MAX_CSAF_BODY
    assert item.truncated


def test_an_overlong_web_page_link_falls_back_to_the_file() -> None:
    page = 'https://www.cisa.gov/' + 'a' * 2100  # longer than a report's source URL may be
    data = advisory(references=[{'category': 'self', 'url': page}])
    assert parse_csaf(encode(data), SOURCE, ICS_URL).document.source_url == ICS_URL


@pytest.mark.parametrize(
    ('tracking', 'line'),
    [
        ({'initial_release_date': '2026-01-02T00:00:00Z'}, 'Released 2026-01-02.'),
        ({'initial_release_date': '2026-01-02', 'version': '3'}, 'Released 2026-01-02.'),
        ({}, None),
    ],
)
def test_release_line_uses_only_the_dates_present(tracking: dict[str, str], line: str | None) -> None:
    data = advisory(tracking={'id': 'ICSA-26-001-01', **tracking})
    body = parse_csaf(encode(data), SOURCE, ICS_URL).document.body
    released = [text for text in body.splitlines() if text.startswith('Released')]
    assert released == ([line] if line else [])


# --------------------------------------------------------------------------- sync


def index(*rows: tuple[str, str]) -> bytes:
    return ''.join(f'"{path}","{stamp}"\n' for path, stamp in rows).encode()


def numbered(n: int) -> bytes:
    return encode(advisory(tracking={'id': f'ICSA-26-001-{n:02d}', 'initial_release_date': '2026-01-01'}))


async def test_sync_reads_the_newest_advisories_across_folders(
    session_factory: sessionmaker[Session], monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[str] = []
    monkeypatch.setattr(
        connectors,
        'download',
        serving(
            {
                OT_INDEX: index(('2026/icsa-26-323-03.json', '2026-11-19T06:00:00Z')),
                IT_INDEX: index(('2026/va-26-317-01.json', '2026-11-13T16:45:20Z')),
                ICS_URL: ICS,
                IT_URL: IT,
            },
            calls,
        ),
    )
    message = await sync_source(session_factory, 'cisa-csaf')
    assert message == 'Read 2 advisories; 2 new reports.'
    assert calls == [OT_INDEX, IT_INDEX, ICS_URL, IT_URL]  # indexes first, then newest first
    assert await sync_source(session_factory, 'cisa-csaf') == 'Read 2 advisories; 0 new reports.'
    with session_factory() as db:
        docs = db.scalars(select(Document).order_by(Document.external_id)).all()
        assert [(d.source_key, d.external_id, d.tlp) for d in docs] == [
            ('cisa-csaf', 'ICSA-26-323-03', 'CLEAR'),
            ('cisa-csaf', 'VA-26-317-01', 'CLEAR'),
        ]
        assert [r.status for r in db.scalars(select(SourceRun))] == ['success', 'success']


async def test_sync_takes_at_most_the_limit_newest_first(
    session_factory: sessionmaker[Session], monkeypatch: pytest.MonkeyPatch
) -> None:
    total = CSAF_INBOX_LIMIT + 5
    rows = [(f'2026/icsa-26-001-{n:02d}.json', f'2026-01-01T00:{n:02d}:00Z') for n in range(total)]
    files: dict[str, bytes | BaseException] = {
        CSAF_BASE + 'OT/white/' + path: numbered(n) for n, (path, _) in enumerate(rows)
    }
    files |= {OT_INDEX: index(*rows), IT_INDEX: b''}
    calls: list[str] = []
    monkeypatch.setattr(connectors, 'download', serving(files, calls))
    assert (
        await sync_source(session_factory, 'cisa-csaf')
        == f'Read {CSAF_INBOX_LIMIT} advisories; {CSAF_INBOX_LIMIT} new reports.'
    )
    fetched = [u.rsplit('-', 1)[-1] for u in calls[2:]]
    assert fetched == [f'{n:02d}.json' for n in range(total - 1, total - 1 - CSAF_INBOX_LIMIT, -1)]


async def test_an_updated_advisory_becomes_a_revision(
    session_factory: sessionmaker[Session], monkeypatch: pytest.MonkeyPatch
) -> None:
    files: dict[str, bytes | BaseException] = {
        OT_INDEX: index(('2026/icsa-26-323-03.json', '2026-11-19T06:00:00Z')),
        IT_INDEX: b'',
        ICS_URL: ICS,
    }
    monkeypatch.setattr(connectors, 'download', serving(files))
    await sync_source(session_factory, 'cisa-csaf')
    updated = advisory()
    updated['document']['tracking'] |= {'version': '2', 'current_release_date': '2026-12-01T00:00:00Z'}
    files[ICS_URL] = encode(updated)
    assert await sync_source(session_factory, 'cisa-csaf') == 'Read 1 advisories; 1 new reports.'
    with session_factory() as db:
        docs = db.scalars(select(Document).order_by(Document.created_at)).all()
        assert [(d.external_id, d.is_current) for d in docs] == [
            ('ICSA-26-323-03', False),
            ('ICSA-26-323-03', True),
        ]
        assert 'current version 2 (2026-12-01)' in docs[1].body


async def test_unreadable_advisories_are_skipped_and_counted(
    session_factory: sessionmaker[Session], monkeypatch: pytest.MonkeyPatch
) -> None:
    files: dict[str, bytes | BaseException] = {
        OT_INDEX: index(
            ('2026/icsa-26-323-03.json', '2026-11-19T06:00:00Z'),
            ('2026/broken.json', '2026-11-18T06:00:00Z'),
            ('2026/missing.json', '2026-11-17T06:00:00Z'),
            ('2026/offline.json', '2026-11-16T06:00:00Z'),
        ),
        IT_INDEX: b'',
        ICS_URL: ICS,
        CSAF_BASE + 'OT/white/2026/broken.json': b'{"document": {}}',
        CSAF_BASE + 'OT/white/2026/offline.json': OSError('connection reset'),
    }
    monkeypatch.setattr(connectors, 'download', serving(files))
    message = await sync_source(session_factory, 'cisa-csaf')
    assert message == 'Read 1 advisories; 1 new reports. 3 could not be read.'
    with session_factory() as db:
        (run,) = db.scalars(select(SourceRun)).all()
        assert (run.status, run.message) == ('success', message)


@pytest.mark.parametrize(
    ('files', 'expected'),
    [
        ({OT_INDEX: b'', IT_INDEX: b''}, 'ValueError: The CSAF index lists no advisories'),
        (
            {OT_INDEX: index(('2026/broken.json', '2026-11-18T06:00:00Z')), IT_INDEX: b''},
            'ValueError: None of the 1 newest CSAF advisories could be read',
        ),
        ({OT_INDEX: OSError('dns down'), IT_INDEX: b''}, 'OSError: dns down'),
    ],
)
async def test_sync_failures_are_recorded_and_raised(
    session_factory: sessionmaker[Session],
    monkeypatch: pytest.MonkeyPatch,
    files: dict[str, bytes | BaseException],
    expected: str,
) -> None:
    monkeypatch.setattr(connectors, 'download', serving(files))
    with pytest.raises(SourceSyncError) as info:
        await sync_source(session_factory, 'cisa-csaf')
    assert str(info.value) == expected
    with session_factory() as db:
        (run,) = db.scalars(select(SourceRun)).all()
        assert (run.source_key, run.status, run.message) == ('cisa-csaf', 'error', expected)
        assert db.scalar(select(Document)) is None
