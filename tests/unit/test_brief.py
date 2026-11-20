"""The intel brief: the facts it gathers (window, TLP visibility, KEV, shared indicators) and its wording.

Everything in it comes from the data; ``compose`` adds counts and labels but no claims of its own.
"""

from __future__ import annotations

import importlib.util
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy.orm import Session, sessionmaker

from insight import brief, services
from insight.brief import CRITICAL, SECTION_ITEMS, compose, window_start
from insight.connectors import SOURCES, parse_csaf
from insight.models import Document, KEVRecord
from insight.schemas import DocumentInput
from insight.services import BriefData, BriefDocument, BriefKev, BriefShared, SourceRef, brief_data

FIXTURES = Path(__file__).parents[1] / 'fixtures' / 'csaf'
NOW = datetime(2026, 11, 19, 12, 0, tzinfo=UTC)
SINCE = window_start(NOW)

_spec = importlib.util.spec_from_file_location('plain', Path(__file__).with_name('test_plain_language.py'))
assert _spec
assert _spec.loader
plain = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(plain)


def report(title: str, body: str, *, source: str = 'Partner', tlp: str = 'CLEAR') -> DocumentInput:
    return DocumentInput.model_validate({'title': title, 'body': body, 'source_name': source, 'tlp': tlp})


def add(db: Session, item: DocumentInput, *, ref: SourceRef | None = None, age_days: float = 1) -> Document:
    doc, _ = services.ingest(db, item, ref=ref)
    doc.created_at = (NOW - timedelta(days=age_days)).isoformat()
    return doc


def kev(db: Session, cve: str, added: str, vendor: str = 'Acme', product: str = 'Gateway') -> None:
    db.add(
        KEVRecord(cve=cve, vendor=vendor, product=product, date_added=added, due_date='', required_action='')
    )


# --------------------------------------------------------------------------- gathering the facts


def test_window_and_tlp_decide_which_reports_count(session_factory: sessionmaker[Session]) -> None:
    with session_factory.begin() as db:
        new = add(db, report('New', 'Plain news.'))
        hidden = add(db, report('Partner only', 'Restricted.', tlp='AMBER'))
        add(db, report('Old', 'Last month.'), age_days=10)
    with session_factory() as db:
        assert {d.id for d in brief_data(db, since=SINCE).documents} == {new.id, hidden.id}
        assert [d.id for d in brief_data(db, since=SINCE, max_tlp='GREEN').documents] == [new.id]


def test_only_superseding_revisions_count(session_factory: sessionmaker[Session]) -> None:
    ref = SourceRef('partner-feed', 'item-1')
    with session_factory.begin() as db:
        add(db, report('Item v1', 'First.'), ref=ref)
        current = add(db, report('Item v2', 'Edited.'), ref=ref)
    with session_factory() as db:
        assert [d.id for d in brief_data(db, since=SINCE).documents] == [current.id]


def test_bodies_are_loaded_for_scored_sources_only(session_factory: sessionmaker[Session]) -> None:
    item = parse_csaf(
        (FIXTURES / 'va-26-317-01.json').read_bytes(), SOURCES['cisa-csaf'], 'https://x.test/a.json'
    )
    with session_factory.begin() as db:
        add(db, item.document, ref=SourceRef('cisa-csaf', 'VA-26-317-01'))
        add(db, report('Blog', 'A long blog post.'))
    with session_factory() as db:
        bodies = {d.title: d.body for d in brief_data(db, since=SINCE).documents}
    assert 'CVSS 3 base score 9.9' in bodies['VA-26-317-01 · Jet Admin Cloud Platform Prompt Injection']
    assert bodies['Blog'] == ''


def test_kev_added_in_the_window_links_to_its_kev_report(session_factory: sessionmaker[Session]) -> None:
    with session_factory.begin() as db:
        kev(db, 'CVE-2026-0001', '2026-11-18')
        kev(db, 'CVE-2020-1234', '2020-01-01')
        kev_doc = add(
            db,
            report('CVE-2026-0001 · Acme Gateway', 'CVE-2026-0001'),
            ref=SourceRef('cisa-kev', 'CVE-2026-0001'),
        )
    with session_factory() as db:
        (added,) = brief_data(db, since=SINCE).kev_added
    assert (added.cve, added.date_added, added.document_id) == ('CVE-2026-0001', '2026-11-18', kev_doc.id)


def test_kev_cves_named_by_other_sources_are_reported_with_their_newest_report(
    session_factory: sessionmaker[Session],
) -> None:
    with session_factory.begin() as db:
        kev(db, 'CVE-2020-1234', '2020-01-01', vendor='Old', product='Router')
        add(db, report('KEV item', 'CVE-2020-1234'), ref=SourceRef('cisa-kev', 'CVE-2020-1234'))
        add(db, report('Earlier', 'Exploitation of CVE-2020-1234 seen.', source='SANS'), age_days=3)
        newest = add(db, report('Later', 'CVE-2020-1234 again.', source='NCSC'), age_days=2)
        add(db, report('Not on the list', 'CVE-2024-9999 is new.', source='SANS'))
    with session_factory() as db:
        (mentioned,) = brief_data(db, since=SINCE).kev_mentioned
    assert (mentioned.cve, mentioned.reports, mentioned.document_id) == ('CVE-2020-1234', 2, newest.id)
    assert (mentioned.vendor, mentioned.product) == ('Old', 'Router')


def test_shared_indicators_need_two_different_sources(session_factory: sessionmaker[Session]) -> None:
    with session_factory.begin() as db:
        add(db, report('A', 'Seen 192.0.2.44 and 198.51.100.7.', source='SANS'))
        add(db, report('B', 'Seen 192.0.2.44 too.', source='NCSC'))
        add(db, report('C', 'Seen 198.51.100.7 again.', source='SANS'))
    with session_factory() as db:
        assert brief_data(db, since=SINCE).shared == [BriefShared('ip', '192.0.2.44', 2, 2)]


def test_reports_above_the_readers_limit_feed_nothing(session_factory: sessionmaker[Session]) -> None:
    with session_factory.begin() as db:
        kev(db, 'CVE-2020-1234', '2020-01-01')
        add(db, report('A', 'Seen 192.0.2.44.', source='SANS'))
        add(db, report('B', 'Seen 192.0.2.44 with CVE-2020-1234.', source='Partner', tlp='AMBER'))
    with session_factory() as db:
        everything = brief_data(db, since=SINCE)
        limited = brief_data(db, since=SINCE, max_tlp='GREEN')
    assert [s.value for s in everything.shared] == ['192.0.2.44']
    assert [k.cve for k in everything.kev_mentioned] == ['CVE-2020-1234']
    assert (limited.shared, limited.kev_mentioned) == ([], [])


# --------------------------------------------------------------------------- wording


def data(**fields: object) -> BriefData:
    defaults: dict[str, object] = {
        'since': SINCE,
        'documents': [],
        'kev_added': [],
        'kev_mentioned': [],
        'shared': [],
    }
    return BriefData(**(defaults | fields))  # type: ignore[arg-type]


def doc(n: int, *, source: str = 'SANS', body: str = '', title: str = '') -> BriefDocument:
    return BriefDocument(f'd{n}', title or f'Report {n}', source, None, SINCE, body)


def test_an_empty_week_says_so_and_how_to_fill_it() -> None:
    result = compose(data())
    assert result.headline == 'No new reports in the last 7 days. Sync your sources to get the latest.'
    assert [s.title for s in result.sections] == [
        'Exploited now', 'Most severe', 'Seen in several sources', 'Most-mentioned vendors'
    ]  # fmt: skip
    assert all(s.items == () and s.empty for s in result.sections)


def test_headline_counts_reports_sources_new_kev_entries_and_critical_weaknesses() -> None:
    csaf = parse_csaf(
        (FIXTURES / 'va-26-317-01.json').read_bytes(), SOURCES['cisa-csaf'], 'https://x.test/a.json'
    )
    docs = [doc(1, body=csaf.document.body, title=csaf.document.title), doc(2, source='NCSC'), doc(3)]
    one_kev = [BriefKev('CVE-2026-0001', 'Acme', 'Gateway', '2026-11-18', 'k1')]
    assert compose(data(documents=docs, kev_added=one_kev)).headline == (
        '3 new reports from 2 sources. CISA says attackers are now using 1 more weakness. '
        '1 weakness is rated critical.'
    )
    two_kev = [*one_kev, BriefKev('CVE-2026-0002', 'Acme', '', '2026-11-17', '')]
    assert compose(data(documents=docs[1:2], kev_added=two_kev)).headline == (
        '1 new report from 1 source. CISA says attackers are now using 2 more weaknesses.'
    )


def test_most_severe_reads_scores_from_the_csaf_connectors_own_lines() -> None:
    """Contract with ``connectors.parse_csaf``: if its line format changes, this test fails."""
    ics = parse_csaf(
        (FIXTURES / 'icsa-26-323-03.json').read_bytes(), SOURCES['cisa-csaf'], 'https://x.test/b.json'
    )
    it = parse_csaf(
        (FIXTURES / 'va-26-317-01.json').read_bytes(), SOURCES['cisa-csaf'], 'https://x.test/a.json'
    )
    docs = [
        doc(1, body=ics.document.body, title=ics.document.title),
        doc(2, body=it.document.body, title=it.document.title),
    ]
    result = compose(data(documents=docs))
    severe = result.sections[1].items
    assert [(i.text, i.document_id) for i in severe] == [
        ('CVE-2026-123965 · CVSS 9.9 · VA-26-317-01 · Jet Admin Cloud Platform Prompt Injection', 'd2')
    ]  # 8.6 for libumqtt is below the critical band (9.0)
    assert [i.text for i in result.sections[3].items] == ['Jet Admin (1)', 'libumqtt (1)']


def test_severe_items_are_highest_first_one_per_cve_and_capped() -> None:
    lines = '\n'.join(f'- CVE-2026-{n:04d}, CVSS 3 base score {9.0 + n / 10:.1f}: x' for n in range(8))
    docs = [doc(1, body=lines), doc(2, body='- CVE-2026-0000, CVSS 3 base score 9.9: same CVE, higher score')]
    items = compose(data(documents=docs)).sections[1].items
    assert len(items) == SECTION_ITEMS
    assert items[0].text.startswith('CVE-2026-0000 · CVSS 9.9')
    assert [i.text.split(' · ')[0] for i in items[1:]] == [
        'CVE-2026-0007',
        'CVE-2026-0006',
        'CVE-2026-0005',
        'CVE-2026-0004',
    ]
    assert all(float(i.text.split('CVSS ')[1].split(' ')[0]) >= CRITICAL for i in items)


def test_exploited_now_lists_new_kev_entries_first_without_repeating_them() -> None:
    added = [BriefKev('CVE-2026-0001', 'Acme', 'Gateway', '2026-11-18', 'k1')]
    mentioned = [
        BriefKev('CVE-2026-0001', 'Acme', 'Gateway', '2026-11-18', 'r1', reports=3),
        BriefKev('CVE-2020-1234', '', '', '2020-01-01', '', reports=1),
    ]
    items = compose(data(kev_added=added, kev_mentioned=mentioned)).sections[0].items
    assert [(i.text, i.document_id) for i in items] == [
        ('CVE-2026-0001 · Acme Gateway · added 2026-11-18', 'k1'),
        ('CVE-2020-1234 · Unknown product · in 1 new report', None),
    ]


def test_shared_indicators_open_the_entity_explorer() -> None:
    shared = [BriefShared('ip', '192.0.2.44', 3, 4)]
    (item,) = compose(data(shared=shared)).sections[2].items
    assert (item.text, item.entity, item.document_id) == (
        '192.0.2.44 · 3 sources, 4 reports',
        '192.0.2.44',
        None,
    )


def test_vendors_count_kev_additions_and_csaf_vendor_lines() -> None:
    docs = [doc(1, body='x\nVendors: Siemens, Acme\n'), doc(2, body='Vendors: Siemens')]
    added = [BriefKev('CVE-2026-0001', 'Acme', 'Gateway', '2026-11-18', '')]
    items = compose(data(documents=docs, kev_added=added)).sections[3].items
    assert [i.text for i in items] == ['Acme (2)', 'Siemens (2)']


@pytest.mark.parametrize('documents', [0, 1, 3])
def test_every_sentence_of_the_brief_is_plain(documents: int) -> None:
    docs = [
        doc(n, source=f'S{n % 2}', body='- CVE-2026-0001, CVSS 3 base score 9.8: x') for n in range(documents)
    ]
    kevs = [BriefKev('CVE-2026-0001', 'Acme', 'Gateway', '2026-11-18', '')] * min(documents, 2)
    result = compose(data(documents=docs, kev_added=kevs))
    for text in [result.headline, *(s.empty for s in result.sections)]:
        assert plain.grade(text) <= plain.MAX_GRADE, text


@pytest.mark.parametrize('days', [0, 31])
def test_window_is_one_to_thirty_days(days: int) -> None:
    with pytest.raises(ValueError, match='between 1 and 30'):
        window_start(NOW, days)
    assert window_start(NOW, 7) == '2026-11-12T12:00:00+00:00'
    assert brief.MAX_DAYS == 30
