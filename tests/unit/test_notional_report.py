"""Two realistic, synthetic, full-length intrusion reports run through extraction and the service layer.

``tests/corpus/reports/`` holds the reports and their hand-labelled ground truth:

* ``notional-intrusion-report.md`` (GLASS HARBOR): defanged indicators, IPv6, ports, CIDR, upper-case hashes,
  a Cyrillic homoglyph domain, e-mail addresses, PowerShell, file names, versions, non-ASCII text, an astral
  emoji, embedded HTML, a TLP:AMBER marking.
* ``notional-salt-meridian.md`` (SALT MERIDIAN): IPv6 zone IDs, IPv4-mapped and bracketed addresses, IPv6
  CIDR, zero-padded octets, a wrapped hash, SHA-512, a zero-width space and an NFD accent in domain names,
  ``_dmarc`` labels, trailing-dot FQDNs, punycode, credential URLs, Turkish and Japanese text, TLP:RED.

Every defect these reports exposed in 0.1.x is now a regression test here (see docs/TESTING.md).
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from insight import services
from insight.connectors import SOURCES, parse_feed
from insight.extraction import canonical, extract
from insight.models import AuditEvent, KEVRecord
from insight.schemas import DocumentInput

REPORTS = Path(__file__).parent.parent / 'corpus' / 'reports'
GLASS = 'notional-intrusion-report'
SALT = 'notional-salt-meridian'


def text_of(name: str) -> str:
    return (REPORTS / f'{name}.md').read_text(encoding='utf-8')


def truth_of(name: str) -> set[tuple[str, str]]:
    data = json.loads((REPORTS / f'{name}.expected.json').read_text(encoding='utf-8'))
    return {(kind, value) for kind, value in data['expected']}


def found_in(name: str) -> set[tuple[str, str]]:
    return {(m.kind, m.value) for m in extract(text_of(name))}


def report(name: str = GLASS, **changes: str) -> DocumentInput:
    fields = {
        'title': f'Synthetic report {name}',
        'body': text_of(name),
        'source_name': 'Notional CTI Cell',
        'source_url': 'https://intel.example.org/reports/1',
        'tlp': 'AMBER',
    }
    return DocumentInput(**{**fields, **changes})


# The even 32+32 split in the SALT MERIDIAN table is one SHA-256 to a reader but is indistinguishable from two
# MD5 lines; the extractor deliberately keeps the safe reading (see docs/EXTRACTION.md).
EVEN_SPLIT_HASH = ('sha256', '9c8b7a6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b')
EVEN_SPLIT_PARTS = {('md5', '9c8b7a6d5e4f3a2b1c0d9e8f7a6b5c4d'), ('md5', '3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b')}


# --------------------------------------------------------------------------- extraction against ground truth


def test_glass_harbor_extraction_matches_ground_truth_exactly() -> None:
    assert found_in(GLASS) == truth_of(GLASS)


def test_salt_meridian_extraction_matches_ground_truth_except_the_documented_even_split() -> None:
    found, truth = found_in(SALT), truth_of(SALT)
    assert truth - found == {EVEN_SPLIT_HASH}
    assert found - truth == EVEN_SPLIT_PARTS


@pytest.mark.parametrize(('name', 'mentions'), [(GLASS, 37), (SALT, 54)])
def test_mention_counts_are_stable(name: str, mentions: int) -> None:
    """A change here is a behaviour change: review the benchmark report and re-baseline deliberately."""
    result = extract(text_of(name))
    assert len(result) == mentions
    assert result == extract(text_of(name))


@pytest.mark.parametrize('name', [GLASS, SALT])
def test_every_span_recanonicalises_and_sits_in_its_evidence(name: str) -> None:
    text = text_of(name)
    for mention in extract(text):
        raw = text[mention.start : mention.end]
        assert canonical(mention.kind, raw) == mention.value
        assert raw in mention.evidence


@pytest.mark.parametrize(
    'wrong',
    [
        ('domain', 'mple-login.com'),  # tail of a Cyrillic homoglyph
        ('domain', 'files.example'),  # half of a defanged name
        ('domain', 'ple.com'),  # tail of a name with a zero-width space
        ('ip', '::ffff:203'),  # truncated IPv4-mapped address (a different, valid address)
        ('ip', '203.0.113.0'),  # CIDR network address
        ('ip', '2001:db8::'),  # IPv6 CIDR network address
        ('ip', '10.2.9.1'),  # firmware version
        ('domain', 'svchost.exe'),
        ('domain', 'logon.aspx'),  # URL path segment
        ('domain', 'net.webclient'),
    ],
)
def test_no_fabricated_or_truncated_indicators(wrong: tuple[str, str]) -> None:
    assert wrong not in found_in(GLASS) | found_in(SALT)


def test_offsets_are_code_points_and_utf16_is_available(db: Session) -> None:
    """Offsets index Python strings. After an astral emoji they differ from JavaScript indices by one, so the
    API also returns ``*_utf16`` offsets for JavaScript consumers."""
    text = text_of(SALT)
    start = text.index('🧨 203.0.113.77') + 2
    doc, _ = services.ingest(db, report(SALT))
    observation = next(o for o in services.detail(db, doc)['observations'] if o['start_offset'] == start)
    assert text[observation['start_offset'] : observation['end_offset']] == '203.0.113.77'
    utf16 = text.encode('utf-16-le')
    begin, end = observation['start_offset_utf16'], observation['end_offset_utf16']
    assert utf16[2 * begin : 2 * end].decode('utf-16-le') == '203.0.113.77'
    assert begin == start + 1


# --------------------------------------------------------------------------- services (both databases)


@pytest.mark.parametrize(('name', 'observations'), [(GLASS, 37), (SALT, 54)])
def test_ingest_preserves_exact_evidence(db: Session, name: str, observations: int) -> None:
    text = text_of(name)
    doc, created = services.ingest(db, report(name))
    detail = services.detail(db, doc)
    assert created
    assert doc.body == text
    assert doc.content_hash == hashlib.sha256(text.encode()).hexdigest()
    assert len(detail['observations']) == observations
    for obs in detail['observations']:
        raw = text[obs['start_offset'] : obs['end_offset']]
        assert canonical(obs['kind'], raw) == obs['value']


def test_kev_context_and_deduplication(db: Session) -> None:
    db.add(
        KEVRecord(
            cve='CVE-2024-3400',
            vendor='Palo Alto Networks',
            product='PAN-OS',
            date_added='2024-04-12',
            due_date='2024-04-19',
            required_action='Apply mitigations per vendor instructions.',
        )
    )
    doc, _ = services.ingest(db, report())
    cves = [o for o in services.detail(db, doc)['observations'] if o['value'] == 'CVE-2024-3400']
    assert len(cves) == 2
    assert all(o['kev'] and o['kev']['due_date'] == '2024-04-19' for o in cves)
    again, created = services.ingest(db, report())
    assert (again.id, created) == (doc.id, False)


def test_windows_line_endings_deduplicate(db: Session) -> None:
    """Regression: a CRLF copy (e.g. an API import of a Windows file) used to become a second report."""
    first, _ = services.ingest(db, report())
    second, created = services.ingest(db, report(body=text_of(GLASS).replace('\n', '\r\n')))
    assert (second.id, created) == (first.id, False)


@pytest.mark.parametrize(
    ('name', 'query'),
    [
        (GLASS, 'GLASS HARBOR'),
        (GLASS, 'glass harbor'),
        (GLASS, 'T1059.001'),
        (GLASS, '<script'),
        (GLASS, 'überwachung'),  # regression: SQLite only folded ASCII
        (GLASS, 'ÜBERWACHUNG'),
        (GLASS, 'uberwachung'),  # accent-insensitive
        (GLASS, 'ZÜRICH'),
        (SALT, 'istanbul'),  # regression: Turkish dotted capital I
        (SALT, 'İSTANBUL'),
        (SALT, 'café-login'),  # regression: NFC query, NFD text (failed on both databases)
        (SALT, '標的型攻撃'),
        (SALT, 'salt meridian'),
    ],
)
def test_search_finds_the_report_on_every_backend(db: Session, name: str, query: str) -> None:
    services.ingest(db, report(name))
    assert len(services.search_documents(db, services.DocumentQuery(q=query))) == 1


def test_watch_terms_fold_exactly_like_search(db: Session) -> None:
    doc, _ = services.ingest(db, report(SALT))
    assert services.watch_matches(['ISTANBUL', 'cafe-login'], doc.title + ' ' + doc.body) == [
        'ISTANBUL',
        'cafe-login',
    ]


def test_tlp_marking_in_the_text_raises_the_label(db: Session) -> None:
    """Regression: the SALT MERIDIAN report is marked TLP:RED but was stored as AMBER (UI) or CLEAR (API)."""
    doc, created = services.ingest(db, report(SALT, tlp='AMBER'))
    assert created
    assert doc.tlp == 'RED'
    event = db.scalar(select(AuditEvent).where(AuditEvent.action == 'document.tlp_raised'))
    assert event is not None
    assert event.detail.startswith('AMBER -> RED')


def test_tlp_marking_never_lowers_the_label(db: Session) -> None:
    doc, _ = services.ingest(db, report(GLASS, tlp='RED'))  # text says TLP:AMBER
    assert doc.tlp == 'RED'


def test_feed_items_keep_only_a_summary_and_say_so() -> None:
    """By design feeds keep 500 summary characters; the item is now flagged as truncated for the analyst."""
    feed = (
        '<rss><channel><item><title>GLASS HARBOR</title><link>https://intel.example.org/r/1</link>'
        f'<description><![CDATA[{text_of(GLASS)}]]></description></item></channel></rss>'
    )
    (item,) = parse_feed(feed.encode(), SOURCES['sans-isc'])
    assert item.truncated
    assert item.document.tlp == 'CLEAR'
    kept = {(m.kind, m.value) for m in extract(item.document.body)} & truth_of(GLASS)
    assert len(kept) < len(truth_of(GLASS)) / 4
