"""The intel brief: the facts it gathers, what counts as new, the executive summary and the sections.

Everything in it comes from the data; ``compose`` adds counts, dates and labels but no claims of its own.
"""

from __future__ import annotations

import importlib.util
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy.orm import Session, sessionmaker

from insight import brief, services
from insight.brief import SECTION_ITEMS, compose, is_demo, published, window_start
from insight.connectors import SOURCES, parse_csaf
from insight.demo import seed
from insight.models import Document, KEVRecord
from insight.schemas import DocumentInput
from insight.services import BriefData, BriefDocument, BriefKev, SourceRef, brief_data

FIXTURES = Path(__file__).parents[1] / 'fixtures' / 'csaf'
NOW = datetime(2026, 11, 19, 12, 0, tzinfo=UTC)
SINCE = window_start(NOW)  # 2026-11-12T12:00:00+00:00
CSAF = SOURCES['cisa-csaf']

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


def kev(db: Session, cve: str, added: str, vendor: str = 'Acme', due: str = '2026-12-01') -> None:
    db.add(
        KEVRecord(
            cve=cve, vendor=vendor, product='Gateway', date_added=added, due_date=due, required_action=''
        )
    )


def advisory(name: str) -> DocumentInput:
    return parse_csaf((FIXTURES / name).read_bytes(), CSAF, 'https://x.test/' + name).document


# --------------------------------------------------------------------------- gathering the facts


def test_reports_received_in_the_window_and_visible_to_the_reader(
    session_factory: sessionmaker[Session],
) -> None:
    with session_factory.begin() as db:
        new = add(db, report('New', 'Plain news.'))
        hidden = add(db, report('Partner only', 'Restricted.', tlp='AMBER'))
        add(db, report('Old', 'Last month.'), age_days=10)
        ref = SourceRef('partner-feed', 'item-1')
        add(db, report('Item v1', 'First.'), ref=ref)
        current = add(db, report('Item v2', 'Edited.'), ref=ref)
    with session_factory() as db:
        assert {d.id for d in brief_data(db, since=SINCE).documents} == {new.id, hidden.id, current.id}
        assert {d.id for d in brief_data(db, since=SINCE, max_tlp='GREEN').documents} == {new.id, current.id}


def test_kev_reports_carry_the_day_cisa_added_the_cve(session_factory: sessionmaker[Session]) -> None:
    with session_factory.begin() as db:
        kev(db, 'CVE-2020-1234', '2020-01-01')
        add(db, report('KEV item', 'CVE-2020-1234'), ref=SourceRef('cisa-kev', 'CVE-2020-1234'))
        add(db, report('Blog', 'CVE-2020-1234 is back.'))
    with session_factory() as db:
        dates = {d.title: d.published for d in brief_data(db, since=SINCE).documents}
    assert dates == {'KEV item': '2020-01-01', 'Blog': ''}


def test_bodies_mentions_kev_entries_and_watch_hits_are_gathered(
    session_factory: sessionmaker[Session],
) -> None:
    with session_factory.begin() as db:
        services.add_watch_term(db, 'jet admin')
        services.add_watch_term(db, 'Nothing matches this')
        kev(db, 'CVE-2026-0001', '2026-11-18')
        kev(db, 'CVE-2020-1234', '2020-01-01')
        kev(db, 'CVE-2019-0001', '2019-01-01')  # neither new nor mentioned: not gathered
        it = add(db, advisory('va-26-317-01.json'), ref=SourceRef('cisa-csaf', 'VA-26-317-01'))
        blog = add(db, report('Blog', 'Seen 192.0.2.44 and CVE-2020-1234.'))
    with session_factory() as db:
        data = brief_data(db, since=SINCE)
    bodies = {d.id: d.body for d in data.documents}
    assert 'CVSS 3 base score 9.9' in bodies[it.id]
    assert bodies[blog.id] == ''  # only CISA advisories are read line by line
    assert {(doc, kind, value) for doc, kind, value in data.mentions if doc == blog.id} == {
        (blog.id, 'ip', '192.0.2.44'),
        (blog.id, 'cve', 'CVE-2020-1234'),
    }
    assert sorted(data.kev) == ['CVE-2020-1234', 'CVE-2026-0001']
    assert data.watch == {'jet admin': {it.id}, 'Nothing matches this': set()}


def test_nothing_comes_from_reports_above_the_readers_limit(session_factory: sessionmaker[Session]) -> None:
    with session_factory.begin() as db:
        services.add_watch_term(db, 'zebra')
        kev(db, 'CVE-2020-1234', '2020-01-01')
        add(db, report('Partner only', 'zebra, 198.51.100.9 and CVE-2020-1234.', tlp='AMBER'))
    with session_factory() as db:
        data = brief_data(db, since=SINCE, max_tlp='GREEN')
    assert (data.documents, data.mentions, data.kev, data.watch) == ([], [], {}, {'zebra': set()})


# --------------------------------------------------------------------------- what counts as new


def data(**fields: object) -> BriefData:
    defaults: dict[str, object] = {'since': SINCE, 'documents': [], 'mentions': [], 'kev': {}, 'watch': {}}
    return BriefData(**(defaults | fields))  # type: ignore[arg-type]


def doc(
    n: int,
    *,
    source: str = 'SANS',
    body: str = '',
    title: str = '',
    published: str = '',
    key: str | None = None,
) -> BriefDocument:
    return BriefDocument(
        f'd{n}', title or f'Report {n}', source, key, '2026-11-18T09:00:00+00:00', published, body
    )


def entry(
    cve: str, added: str = '2026-11-18', due: str = '2026-12-01', vendor: str = 'Acme', document: str = ''
) -> BriefKev:
    return BriefKev(cve, vendor, 'Gateway', added, due, document)


def test_new_means_published_in_the_window() -> None:
    assert published(doc(1)) == '2026-11-18'  # no publisher date: the day Insight received it
    assert published(doc(2, published='2020-01-01')) == '2020-01-01'  # a KEV report: the day CISA added it
    first_release = 'Released 2021-07-27; current version 3 (2026-11-19).'
    assert published(doc(3, body=f'x\n{first_release}\n')) == '2021-07-27'  # an advisory: its first release
    old = [
        doc(1, published='2020-01-01'),
        doc(2, body=f'{first_release}\n- CVE-2021-1, CVSS 3 base score 9.8: x'),
    ]
    result = compose(data(documents=old))
    assert result.summary == ('Nothing new in the last 7 days. Sync your sources to get the latest.',)
    assert result.sections[1].items == ()


def test_the_synthetic_demo_is_left_out(session_factory: sessionmaker[Session]) -> None:
    with session_factory.begin() as db:
        seed(db)
    with session_factory() as db:
        demo = brief_data(db, since=window_start(datetime.now(UTC))).documents
    assert len(demo) == 3
    assert all(is_demo(d) for d in demo)
    assert compose(data(documents=demo)).summary[0].startswith('Nothing new')


# --------------------------------------------------------------------------- the executive summary


def test_an_empty_week_says_so_and_what_to_do() -> None:
    result = compose(data())
    assert result.summary == ('Nothing new in the last 7 days. Sync your sources to get the latest.',)
    titles = [
        'Exploited now',
        'Most severe',
        'Your watch terms',
        'Seen in several sources',
        'Most-mentioned vendors',
    ]
    assert [s.title for s in result.sections] == titles
    assert all(s.items == () and s.empty for s in result.sections)


def test_a_full_week_summary_reads_from_most_to_least_urgent() -> None:
    it = parse_csaf((FIXTURES / 'va-26-317-01.json').read_bytes(), CSAF, 'https://x.test/a.json').document
    docs = [
        doc(1, body=it.body, title=it.title, key='cisa-csaf', source=CSAF.name),
        doc(2, source='NCSC'),
        doc(3, source='SANS'),
        doc(4, published='2026-11-18', key='cisa-kev', source='CISA KEV'),
    ]
    kevs = {
        'CVE-2026-0001': entry('CVE-2026-0001', due='2026-12-01', vendor='Acme', document='d4'),
        'CVE-2026-0002': entry('CVE-2026-0002', due='2026-11-21', vendor='Bolt'),
        'CVE-2020-1234': entry('CVE-2020-1234', added='2020-01-01', vendor='Old'),
    }
    mentions = [
        ('d2', 'cve', 'CVE-2020-1234'),
        ('d3', 'cve', 'CVE-2020-1234'),
        ('d4', 'cve', 'CVE-2026-0001'),
    ]
    watch = {'Jet Admin': {'d1'}, 'Siemens': set()}
    result = compose(data(documents=docs, kev=kevs, mentions=mentions, watch=watch))
    assert result.summary == (
        'In the last 7 days, 4 new reports came in from 4 sources.',
        'CISA confirmed that attackers are using 2 more weaknesses, in products from Acme and Bolt.',
        'US federal agencies must fix the next of them by 2026-11-21.',
        '1 weakness that attackers use also appears in new reports from NCSC and SANS.',
        'The most serious new weakness is CVE-2026-123965 in Jet Admin Cloud Platform Prompt Injection, '
        'scored 9.9 out of 10.',
        '1 new report mentions your watch terms: Jet Admin (1).',
        'First step: check whether you use any of these products, and fix the ones attackers use first.',
    )
    for sentence in result.summary:
        assert plain.grade(sentence) <= plain.MAX_GRADE, sentence


@pytest.mark.parametrize(
    ('dues', 'sentence'),
    [
        (['2026-11-21'], 'US federal agencies must fix it by 2026-11-21.'),
        (['2026-11-16'], 'The date by which US federal agencies had to fix it has passed.'),
        (
            ['2026-11-16', '2026-11-16'],
            'The date by which US federal agencies had to fix 2 of them has passed.',
        ),
        (['2026-11-16', '2026-11-30'], 'US federal agencies must fix the next of them by 2026-11-30.'),
    ],
)
def test_the_federal_deadline_is_the_next_one_or_says_it_has_passed(dues: list[str], sentence: str) -> None:
    kevs = {f'CVE-2026-{n:04d}': entry(f'CVE-2026-{n:04d}', due=due) for n, due in enumerate(dues)}
    summary = compose(data(kev=kevs)).summary  # "today" is the end of the window: 2026-11-19
    assert sentence in summary
    assert plain.grade(sentence) <= plain.MAX_GRADE


def test_watch_terms_without_matches_and_without_terms() -> None:
    docs = [doc(1)]
    assert (
        'None of the new reports mention your watch terms.'
        in compose(data(documents=docs, watch={'x': set()})).summary
    )
    nudge = 'Add watch terms for the products you use, and this summary will say which reports concern you.'
    assert nudge in compose(data(documents=docs)).summary
    assert 'First step' not in ' '.join(compose(data(documents=docs)).summary)  # nothing urgent, no advice


@pytest.mark.parametrize('documents', [0, 1, 4])
def test_every_sentence_and_empty_message_is_plain(documents: int) -> None:
    docs = [
        doc(n, source=f'S{n % 2}', body='- CVE-2026-0001, CVSS 3 base score 9.8: x') for n in range(documents)
    ]
    kevs = {'CVE-2026-0001': entry('CVE-2026-0001')} if documents else {}
    result = compose(data(documents=docs, kev=kevs, watch={'Acme': {'d0'}} if documents else {}))
    for text in [*result.summary, *(s.empty for s in result.sections)]:
        assert plain.grade(text) <= plain.MAX_GRADE, text


# --------------------------------------------------------------------------- sections


def test_most_severe_reads_scores_from_the_csaf_connectors_own_lines() -> None:
    """Contract with ``connectors.parse_csaf``: if its line format changes, this test fails."""
    ics, it = advisory('icsa-26-323-03.json'), advisory('va-26-317-01.json')
    docs = [doc(1, body=ics.body, title=ics.title), doc(2, body=it.body, title=it.title)]
    assert [published(d) for d in docs] == ['2026-11-19', '2026-11-13']
    result = compose(data(documents=docs))
    assert [(i.text, i.document_id) for i in result.sections[1].items] == [
        ('CVE-2026-123965 · CVSS 9.9 · VA-26-317-01 · Jet Admin Cloud Platform Prompt Injection', 'd2')
    ]  # 8.6 for libumqtt is below the critical band (9.0)
    assert [(i.text, i.search) for i in result.sections[4].items] == [
        ('Jet Admin (1)', 'Jet Admin'),
        ('libumqtt (1)', 'libumqtt'),
    ]


def test_severe_items_are_highest_first_one_per_cve_and_capped() -> None:
    lines = '\n'.join(f'- CVE-2026-{n:04d}, CVSS 3 base score {9.0 + n / 10:.1f}: x' for n in range(8))
    docs = [doc(1, body=lines), doc(2, body='- CVE-2026-0000, CVSS 3 base score 9.9: same CVE, higher score')]
    items = compose(data(documents=docs)).sections[1].items
    assert [i.text.split(' · ')[:2] for i in items] == [
        ['CVE-2026-0000', 'CVSS 9.9'], ['CVE-2026-0007', 'CVSS 9.7'], ['CVE-2026-0006', 'CVSS 9.6'],
        ['CVE-2026-0005', 'CVSS 9.5'], ['CVE-2026-0004', 'CVSS 9.4'],
    ]  # fmt: skip
    assert len(items) == SECTION_ITEMS


def test_exploited_now_lists_new_kev_entries_first_then_ones_other_reports_name() -> None:
    kevs = {
        'CVE-2026-0001': entry('CVE-2026-0001', document='k1'),
        'CVE-2020-1234': BriefKev('CVE-2020-1234', '', '', '2020-01-01', '', ''),
    }
    docs = [doc(1), doc(2, source='NCSC')]
    mentions = [
        ('d1', 'cve', 'CVE-2026-0001'),
        ('d1', 'cve', 'CVE-2020-1234'),
        ('d2', 'cve', 'CVE-2020-1234'),
    ]
    items = compose(data(documents=docs, kev=kevs, mentions=mentions)).sections[0].items
    assert [(i.text, i.document_id) for i in items] == [
        ('CVE-2026-0001 · Acme Gateway · added 2026-11-18', 'k1'),
        ('CVE-2020-1234 · Unknown product · in 2 new reports', 'd2'),
    ]


def test_watch_term_lines_search_the_reports() -> None:
    watch = {'Siemens': {'d1', 'd2'}, 'acme': {'d2'}, 'Unused': set()}
    items = compose(data(documents=[doc(1), doc(2)], watch=watch)).sections[2].items
    assert [(i.text, i.search) for i in items] == [
        ('Siemens · 2 new reports', 'Siemens'),
        ('acme · 1 new report', 'acme'),
    ]


def test_shared_indicators_need_two_sources_and_open_the_entity_explorer() -> None:
    docs = [doc(1, source='SANS'), doc(2, source='NCSC'), doc(3, source='SANS')]
    mentions = [
        ('d1', 'ip', '192.0.2.44'),
        ('d2', 'ip', '192.0.2.44'),
        ('d1', 'ip', '198.51.100.7'),
        ('d3', 'ip', '198.51.100.7'),
    ]
    (item,) = compose(data(documents=docs, mentions=mentions)).sections[3].items
    assert (item.text, item.entity, item.document_id) == (
        '192.0.2.44 · 2 sources, 2 reports',
        '192.0.2.44',
        None,
    )


def test_vendor_spellings_that_differ_only_in_case_are_one_vendor() -> None:
    docs = [
        doc(1, body='Vendors: LCDS Ltda ME, Siemens\n'),
        doc(2, body='Vendors: LCDS LTDA ME\n'),
        doc(3, body='Vendors: LCDS Ltda  ME\n'),
    ]
    kevs = {'CVE-2026-0001': entry('CVE-2026-0001', vendor='siemens')}
    items = compose(data(documents=docs, kev=kevs)).sections[4].items
    assert [i.text for i in items] == ['LCDS Ltda ME (3)', 'Siemens (2)']


@pytest.mark.parametrize('days', [0, 31])
def test_window_is_one_to_thirty_days(days: int) -> None:
    with pytest.raises(ValueError, match='between 1 and 30'):
        window_start(NOW, days)
    assert window_start(NOW, 7) == '2026-11-12T12:00:00+00:00'
    assert brief.MAX_DAYS == 30
