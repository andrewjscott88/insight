"""The threat landscape composer: trends, plain sentences, coverage caveats, TLP and the Markdown briefing."""

from __future__ import annotations

import importlib.util
from collections.abc import Iterable
from pathlib import Path

import pytest

from insight import landscape as ls
from insight.attack import catalog
from insight.brief import DEMO
from insight.briefing import LABELS, escape, to_markdown
from insight.services import BriefData, BriefDocument, BriefKev, LandscapeData, fold
from insight.themes import THEMES, THEMES_BY_KEY

_spec = importlib.util.spec_from_file_location('plain', Path(__file__).with_name('test_plain_language.py'))
assert _spec
assert _spec.loader
plain = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(plain)

SINCE = '2026-11-14T12:00:00+00:00'  # a 7-day period ending 2026-11-21; history from 2026-10-17
FRESH_DAY = '2026-11-18'
OLD_DAY = '2026-10-25'


def doc(doc_id: str, day: str, *, source: str = 'Feed A', title: str = '') -> BriefDocument:
    return BriefDocument(doc_id, title or f'Report {doc_id}', source, None, f'{day}T09:00:00+00:00', '', '')


def reports(prefix: str, count: int, day: str, source: str = 'Feed A') -> list[BriefDocument]:
    return [doc(f'{prefix}{i}', day, source=source) for i in range(count)]


def make(
    docs: Iterable[BriefDocument],
    *,
    themes: dict[str, set[str]] | None = None,
    techniques: Iterable[tuple[str, str]] = (),
    kev: Iterable[BriefKev] = (),
    tlp: dict[str, str] | None = None,
    first: str = '2026-01-01T00:00:00+00:00',
    truncated: bool = False,
) -> tuple[LandscapeData, BriefData]:
    docs = list(docs)
    data = LandscapeData(
        start='2026-10-17T12:00:00+00:00',
        documents=docs,
        tlp=tlp or {d.id: 'GREEN' for d in docs},
        theme_words=themes or {},
        techniques=list(techniques),
        kev=list(kev),
        watch={},
        first_received=first,
        truncated=truncated,
    )
    fresh = [d for d in docs if d.created_at >= SINCE]
    return data, BriefData(since=SINCE, documents=fresh, mentions=[], kev={k.cve: k for k in kev}, watch={})


def compose(data: tuple[LandscapeData, BriefData], days: int = 7) -> ls.Landscape:
    return ls.compose(data[0], data[1], since=SINCE, days=days)


def ids(docs: Iterable[BriefDocument]) -> set[str]:
    return {d.id for d in docs}


# --------------------------------------------------------------------------- comparing


@pytest.mark.parametrize(
    ('current', 'before', 'periods', 'label'),
    [
        (3, 0, 4, ls.NEW),
        (0, 0, 4, ls.STEADY),
        (6, 8, 4, ls.RISING),  # usual 2 a period: 6 >= 2 * 1.5 + 1
        (3, 8, 4, ls.STEADY),
        (1, 0.0, 0, ls.NO_HISTORY),
        (1, 16, 4, ls.QUIETER),  # usual 4, now 1
        (1, 4, 4, ls.STEADY),  # usual 1: too few to call quieter
        (2, 1, 4, ls.RISING),
    ],
)
def test_compare_classifies_a_count_against_its_usual_number(
    current: int, before: int, periods: float, label: str
) -> None:
    assert ls.compare(current, int(before), periods).label == label


def test_a_rise_must_show_in_the_share_of_reports_too() -> None:
    """A source that doubles the number of reports does not make every theme rise."""
    assert ls.compare(20, 40, 4).label == ls.RISING
    assert ls.compare(20, 40, 4, share_now=0.25, share_before=0.25).label == ls.STEADY
    assert ls.compare(20, 40, 4, share_now=0.5, share_before=0.25).label == ls.RISING
    assert ls.compare(1, 16, 4, share_now=0.2, share_before=0.2).label == ls.STEADY


def test_usual_text_reads_naturally() -> None:
    assert ls.usual_text(ls.Change(ls.RISING, 6, 2.0), 7) == 'usually about 2 a week'
    assert ls.usual_text(ls.Change(ls.RISING, 3, 0.25), 7) == 'usually fewer than 1 a week'
    assert ls.usual_text(ls.Change(ls.NEW, 3, 0.0), 30) == 'new'
    assert ls.usual_text(ls.Change(ls.STEADY, 3, 4.4), 30) == 'usually about 4 every 30 days'
    assert ls.usual_text(ls.Change(ls.NO_HISTORY, 3, None), 7) == ''


# --------------------------------------------------------------------------- the landscape


def test_a_rising_theme_leads_the_summary_with_why_it_matters() -> None:
    fresh = reports('n', 8, FRESH_DAY, 'Feed A') + reports('m', 2, FRESH_DAY, 'Feed B')
    old = reports('o', 16, OLD_DAY)
    ransom = ids(fresh[:5]) | ids(old[:2])
    result = compose(make(fresh + old, themes={'ransomware': ransom}))
    top = result.threats[0]
    assert (top.key, top.change.label, top.change.current, top.change.usual) == (
        'ransomware',
        ls.RISING,
        5,
        0.5,
    )
    assert top.sources == 1
    assert top.what == THEMES_BY_KEY['ransomware'].what
    assert len(top.reports) == ls.EVIDENCE_REPORTS
    assert result.summary[0] == (
        'In the last 7 days, 10 new reports came in from 2 sources, more than usual (usually about 4 a week).'
    )
    assert result.summary[1] == 'Trending: Ransomware (5 reports, usually fewer than 1 a week).'
    assert result.reports == 10
    assert result.compared_periods == 4


def test_new_themes_are_named_and_quieter_ones_are_mentioned() -> None:
    fresh = reports('n', 10, FRESH_DAY)
    old = reports('o', 40, OLD_DAY)
    result = compose(make(fresh + old, themes={'phishing': ids(fresh[:2]), 'ddos': ids(old[:24])}))
    assert [(t.key, t.change.label) for t in result.threats] == [('phishing', ls.NEW)]
    assert [t.key for t in result.quieter] == ['ddos']
    assert 'Trending: Phishing (2 reports, new).' in result.summary
    assert 'Quieter than usual: Denial of service (DDoS).' in result.summary


def test_without_history_there_are_no_trends_only_counts() -> None:
    fresh = reports('n', 4, FRESH_DAY)
    result = compose(make(fresh, themes={'phishing': ids(fresh[:3])}, first=f'{FRESH_DAY}T00:00:00+00:00'))
    assert result.compared_since is None
    assert result.threats[0].change.label == ls.NO_HISTORY
    assert result.summary[:2] == (
        'In the last 7 days, 4 new reports came in from 1 source.',
        'The most reported kind of threat is phishing, in 3 reports.',
    )
    assert any('cannot show trends yet' in line for line in result.caveats)


def test_partial_history_is_called_rough() -> None:
    fresh = reports('n', 4, FRESH_DAY)
    old = reports('o', 4, '2026-11-08')
    result = compose(make(fresh + old, first='2026-11-01T00:00:00+00:00'))
    assert 1 < result.compared_periods < ls.COMPARE_PERIODS
    assert any('only part of the 4 weeks before' in line for line in result.caveats)


def test_attacker_behaviour_comes_from_tactics_in_plain_words() -> None:
    fresh = reports('n', 6, FRESH_DAY)
    old = reports('o', 24, OLD_DAY)
    techniques = [(d.id, 'T1566.001') for d in fresh[:4]] + [(fresh[5].id, 'T1486')]
    techniques += [(d.id, 'T1486') for d in old[:8]] + [(old[9].id, 'T1566.002')]
    result = compose(make(fresh + old, techniques=techniques))
    first = result.tactics[0]
    assert (first.shortname, first.plain, first.change.label) == ('initial-access', 'getting in', ls.RISING)
    assert first.techniques == (('T1566.001', 'Phishing: Spearphishing Attachment', 4),)
    assert 'More reports than usual describe attackers getting in (Initial Access).' in result.summary
    assert 'That is 4 reports, usually fewer than 1 a week.' in result.summary
    # A technique can make a report count towards a theme without any of its words.
    assert {t.key for t in result.threats} >= {'phishing', 'ransomware'}


def test_reports_without_techniques_get_a_hint() -> None:
    result = compose(make(reports('n', 2, FRESH_DAY)))
    assert result.tactics == ()
    assert any('No report in this period has ATT&CK techniques yet' in line for line in result.caveats)


def test_the_demo_reports_do_not_count() -> None:
    title, source = sorted(DEMO)[0]
    demo = doc('demo', FRESH_DAY, source=source, title=title)
    result = compose(make([demo, doc('real', FRESH_DAY)], themes={'phishing': {'demo'}}))
    assert result.reports == 1
    assert result.threats == ()


def test_the_landscape_carries_the_most_restrictive_tlp_it_counted() -> None:
    fresh = reports('n', 2, FRESH_DAY)
    old = reports('o', 2, OLD_DAY)
    labels = {'n0': 'GREEN', 'n1': 'CLEAR', 'o0': 'AMBER', 'o1': 'GREEN'}
    assert compose(make(fresh + old, tlp=labels)).tlp == 'AMBER'
    assert compose(make([])).tlp == 'CLEAR'


def test_kev_growth_is_compared_with_earlier_periods() -> None:
    def kev(n: int, day: str) -> BriefKev:
        return BriefKev(f'CVE-2026-{n:04d}', 'Acme', 'Gateway', day, '2026-12-09', '')

    entries = [kev(i, FRESH_DAY) for i in range(9)] + [kev(100 + i, OLD_DAY) for i in range(8)]
    result = compose(make(reports('n', 1, FRESH_DAY), kev=entries))
    summary = ' '.join(result.summary)
    assert 'CISA added 9 more weaknesses to its known exploited list, in products from Acme.' in summary
    assert 'That is more than usual: CISA added about 2 a week before.' in summary


def test_nothing_new_says_so() -> None:
    result = compose(make(reports('o', 3, OLD_DAY)))
    assert result.summary == (
        (
            'No recent reports are available for the last 7 days. Sync your sources, and check their '
            'status in About this brief.'
        ),
    )


def test_a_cut_off_read_is_reported() -> None:
    result = compose(make(reports('n', 2, FRESH_DAY), truncated=True))
    assert 'Only the newest 2 reports were counted.' in result.caveats


def test_thirty_day_periods() -> None:
    since = '2026-10-22T12:00:00+00:00'
    fresh = reports('n', 6, '2026-11-01')
    old = reports('o', 8, '2026-08-01')
    data, _ = make(fresh + old, themes={'phishing': ids(fresh)})
    result = ls.compose(data, BriefData(since, fresh, [], {}, {}), since=since, days=30)
    assert result.threats[0].change.label == ls.NEW
    assert result.summary[0].startswith('In the last 30 days, 6 new reports came in from 1 source')


def test_every_sentence_is_plain() -> None:
    fresh = reports('n', 8, FRESH_DAY) + reports('m', 2, FRESH_DAY, 'Feed B')
    old = reports('o', 32, OLD_DAY)
    themes = {'ransomware': ids(fresh[:5]), 'phishing': ids(fresh[5:7]), 'ddos': ids(old[:24])}
    techniques = [(d.id, 'T1566.001') for d in fresh[:4]]
    for result in (
        compose(make(fresh + old, themes=themes, techniques=techniques)),
        compose(make(fresh, themes=themes, first=f'{FRESH_DAY}T00:00:00+00:00')),
    ):
        for line in (*result.summary, *result.caveats):
            assert plain.grade(as_read(line)) <= plain.MAX_GRADE, line


def as_read(line: str) -> str:
    """Names of themes and tactics are read as names, like the official names in the plain-language test."""
    names = [t.name for t in catalog().tactics] + [t.name for t in THEMES]
    for name in sorted(names, key=len, reverse=True):
        line = line.replace(name, 'Name')
    return line


# --------------------------------------------------------------------------- themes


def test_themes_are_well_formed_and_plain() -> None:
    assert len({t.key for t in THEMES}) == len(THEMES) >= 12
    techniques = catalog().techniques
    for theme in THEMES:
        assert theme.words or theme.techniques, theme.key
        for word in theme.words:
            assert word == fold(word), word
            assert len(word) >= 4, word
        for technique_id in theme.techniques:
            assert technique_id in techniques, technique_id
        for text in (theme.what, theme.impact, theme.check):
            assert plain.grade(text) <= plain.MAX_GRADE, f'{theme.key}: {text}'


@pytest.mark.parametrize('text', ['a 30-day window', 'the denial of service condition', 'adapt the plan'])
def test_common_advisory_wording_matches_no_theme(text: str) -> None:
    folded = fold(text)
    assert [t.key for t in THEMES if any(word in folded for word in t.words)] == []


def test_sub_techniques_count_for_their_parent() -> None:
    phishing = THEMES_BY_KEY['phishing']
    assert phishing.has_technique('T1566')
    assert phishing.has_technique('T1566.002')
    assert not phishing.has_technique('T15660')


# --------------------------------------------------------------------------- the briefing


def test_the_briefing_is_marked_and_escapes_report_text() -> None:
    fresh = [doc('w', '2026-11-19', title='[click](javascript:alert(1)) <b>bold</b> # head')]
    fresh += reports('n', 3, FRESH_DAY)
    result = compose(make(fresh, themes={'ransomware': ids(fresh)}, tlp={d.id: 'AMBER' for d in fresh}))
    text = to_markdown(result, generated='2026-11-21T06:00:00+00:00', version='0.7.0')
    lines = text.splitlines()
    assert lines[0] == lines[-1] == '**TLP:AMBER**'
    assert '# Threat landscape: the last 7 days' in lines
    assert 'Made by Insight 0.7.0 on 2026-11-21 06:00 UTC' in text
    assert '### Ransomware: New' in lines
    assert '\\[click\\](javascript:alert(1)) \\<b\\>bold\\</b\\> \\# head' in text
    assert '<b>' not in text
    assert '## Exploited now' in lines
    assert '## How to read this' in lines


def test_escape_flattens_whitespace() -> None:
    assert escape('a\n\n*b*') == 'a \\*b\\*'
    assert set(LABELS) == {ls.RISING, ls.NEW, ls.STEADY, ls.QUIETER, ls.NO_HISTORY}
