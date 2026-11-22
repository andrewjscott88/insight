"""Ranked search (TIP 3.2, ADR 0027): the same ranking on SQLite and PostgreSQL, within the TLP limit."""

from __future__ import annotations

import pytest
from sqlalchemy.orm import Session

from insight import services
from insight.schemas import DocumentInput
from insight.services import SourceRef, ranked_search, search_terms


def add(db: Session, title: str, body: str, tlp: str = 'CLEAR', ref: SourceRef | None = None) -> str:
    item = DocumentInput.model_validate({'title': title, 'body': body, 'source_name': 'Feed', 'tlp': tlp})
    doc, _ = services.ingest(db, item, ref=ref)
    return doc.id


def titles(db: Session, q: str, **kwargs: object) -> list[str]:
    return [hit.document.title for hit in ranked_search(db, q, **kwargs).hits]  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ('query', 'expected'),
    [
        ('Ransomware  LockBit', ['ransomware', 'lockbit']),
        ('"initial access" broker', ['initial access', 'broker']),
        ('ÜBERWACHUNG überwachung', ['uberwachung']),  # folded, then deduplicated
        ('', []),
        ('a b c d e f g h i j', ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h']),
    ],
)
def test_search_terms(query: str, expected: list[str]) -> None:
    assert search_terms(query) == expected


def test_every_word_must_match_and_phrases_stay_together(db: Session) -> None:
    add(db, 'Broker note', 'An initial access broker sold VPN logins.')
    add(db, 'Scattered', 'Initial reports; access was later sold by a broker.')
    assert sorted(titles(db, 'broker access')) == ['Broker note', 'Scattered']
    assert titles(db, '"initial access" broker') == ['Broker note']
    assert titles(db, 'broker wiper') == []


def test_title_matches_and_frequent_words_rank_higher(db: Session) -> None:
    add(db, 'Weekly roundup', 'Patch notes. LockBit was mentioned once among many other things and topics.')
    add(db, 'LockBit affiliates return', 'Affiliates resumed operations after the takedown.')
    add(db, 'Incident notes', 'LockBit, LockBit and again LockBit: the encryptor, the leak site, the panel.')
    assert titles(db, 'lockbit') == ['LockBit affiliates return', 'Incident notes', 'Weekly roundup']


def test_rare_words_weigh_more_than_common_ones(db: Session) -> None:
    for n in range(4):
        add(db, f'Filler {n}', 'Phishing campaign observed this week.')
    add(db, 'Common word twice', 'Phishing and phishing campaign with a loader.')
    add(db, 'Rare word', 'Phishing campaign delivering Latrodectus once.')
    ranked = titles(db, 'phishing latrodectus')
    assert ranked == ['Rare word']  # every word must match
    ranked = titles(db, 'campaign')
    assert len(ranked) == 6


def test_ties_go_to_the_newer_report_and_the_order_is_stable(db: Session) -> None:
    first = add(db, 'Same', 'Cobalt Strike beacon one.')
    second = add(db, 'Same', 'Cobalt Strike beacon two.')  # same length and counts: an exact tie
    hits = ranked_search(db, 'beacon').hits
    assert [h.document.id for h in hits] == [second, first]
    assert hits[0].score == hits[1].score
    assert [h.document.id for h in ranked_search(db, 'beacon').hits] == [second, first]


def test_only_reports_within_the_readers_limit(db: Session) -> None:
    add(db, 'Public QakBot note', 'QakBot returns.', 'GREEN')
    add(db, 'Partner QakBot briefing', 'QakBot infrastructure list.', 'AMBER')
    assert sorted(titles(db, 'qakbot')) == ['Partner QakBot briefing', 'Public QakBot note']
    page = ranked_search(db, 'qakbot', max_tlp='GREEN')
    assert [h.document.title for h in page.hits] == ['Public QakBot note']
    assert page.total == 1


def test_superseded_revisions_only_on_request(db: Session) -> None:
    ref = SourceRef('feed', 'item-1')
    add(db, 'Emotet v1', 'Emotet spam wave.', ref=ref)
    add(db, 'Emotet v2', 'Emotet spam wave, updated.', ref=ref)
    assert titles(db, 'emotet') == ['Emotet v2']
    assert sorted(titles(db, 'emotet', include_superseded=True)) == ['Emotet v1', 'Emotet v2']


def test_results_say_why_and_page(db: Session) -> None:
    for n in range(5):
        add(db, f'Volt Typhoon {n}', f'Living off the land, part {n}.')
    page = ranked_search(db, 'typhoon', limit=2)
    assert (page.total, len(page.hits), page.terms) == (5, 2, ('typhoon',))
    assert page.hits[0].matched_in_title == ('typhoon',)
    rest = ranked_search(db, 'typhoon', offset=2, limit=10)
    assert len(rest.hits) == 3
    assert not {h.document.id for h in page.hits} & {h.document.id for h in rest.hits}


def test_snippets_show_the_match(db: Session) -> None:
    add(
        db,
        'Long report',
        'Background. ' * 40 + 'The SystemBC proxy was used for tunnelling. ' + 'More. ' * 40,
    )
    [hit] = ranked_search(db, 'systembc').hits
    assert 'SystemBC proxy' in hit.snippet
    assert hit.snippet.startswith('…')


def test_an_empty_query_finds_nothing(db: Session) -> None:
    add(db, 'Anything', 'Text.')
    page = ranked_search(db, '   ')
    assert (page.hits, page.total) == ([], 0)
