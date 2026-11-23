"""The threat landscape: what is trending in your reports, why it matters, and what to check first.

Like the intel brief (``insight.brief``), no model writes it. Every number is a count from the database,
and the explanation of each kind of threat is fixed, reviewed text in ``insight.themes``.
``services.landscape_data`` gathers the rows; :func:`compose` counts, compares and words them;
``insight.briefing`` turns the result into a briefing to share (ADR 0020).

**Trends.** The chosen period (the last 7 or 30 days) is compared with the :data:`COMPARE_PERIODS` periods
before it. A theme or tactic is *rising* when it is in at least :data:`MIN_RISING` reports, clearly more than
its usual number per period, *and* a bigger share of the reports than before, so a new or busy source does
not make everything look like it is rising. It is *new* when no report in the earlier periods had it, and
*quieter* when it fell to half its usual number and share or less. When Insight has no reports from before
the period, there is nothing to compare with, and the landscape says so instead of calling everything new.

**Dates.** As in the brief, a report counts on the day it was published when Insight knows it (KEV entries and
CISA advisories), else on the day Insight received it, and the synthetic demo reports are left out.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Final

from .attack import catalog
from .brief import Brief, BriefItem, count_of, is_demo, name_list, published
from .brief import compose as compose_brief
from .schemas import most_restrictive
from .services import BriefData, BriefDocument, LandscapeData
from .themes import THEMES, Theme

PERIOD_CHOICES: Final = (7, 30)
#: How many periods before the chosen one make up "usual".
COMPARE_PERIODS: Final = 4
#: Fewest reports in the period for a theme or tactic to count as rising.
MIN_RISING: Final = 2
EVIDENCE_REPORTS: Final = 3
TOP_TECHNIQUES: Final = 3

NEW: Final = 'new'
RISING: Final = 'rising'
STEADY: Final = 'steady'
QUIETER: Final = 'quieter'
#: Insight has nothing from before the period to compare with.
NO_HISTORY: Final = 'no-history'
_ORDER: Final = {RISING: 0, NEW: 1, STEADY: 2, NO_HISTORY: 2, QUIETER: 3}

#: What each ATT&CK tactic means in everyday words ("Reports describe attackers ...").
PLAIN_TACTICS: Final[dict[str, str]] = {
    'reconnaissance': 'scouting for targets',
    'resource-development': 'setting up tools and servers',
    'initial-access': 'getting in',
    'execution': 'running their code',
    'persistence': 'making sure they can come back',
    'privilege-escalation': 'gaining more control',
    'stealth': 'staying hidden',
    'defense-impairment': 'switching off defences',
    'credential-access': 'stealing passwords and keys',
    'discovery': 'looking around the network',
    'lateral-movement': 'spreading to other systems',
    'collection': 'gathering data',
    'command-and-control': 'controlling hacked systems',
    'exfiltration': 'taking data out',
    'impact': 'causing damage or disruption',
}


@dataclass(frozen=True, slots=True)
class Change:
    """How a count in the chosen period compares with the periods before it."""

    label: str
    current: int
    #: Reports per period in the comparison periods; ``None`` when there is nothing to compare with.
    usual: float | None


@dataclass(frozen=True, slots=True)
class ThreatTrend:
    key: str
    name: str
    change: Change
    #: How many sources the reports in the period came from.
    sources: int
    what: str
    impact: str
    check: str
    #: The newest reports in the period, each opening its report.
    reports: tuple[BriefItem, ...]
    #: How Insight spots the theme: its words, then its ATT&CK techniques.
    words: tuple[str, ...]
    techniques: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class TacticTrend:
    shortname: str
    name: str
    plain: str
    change: Change
    #: ``(technique ID, name, reports)`` of the techniques most reported in the period.
    techniques: tuple[tuple[str, str, int], ...]


@dataclass(frozen=True, slots=True)
class Landscape:
    days: int
    since: str
    #: Start of the history the period is compared with; ``None`` when there is none.
    compared_since: str | None
    #: How many whole or part periods of history there are (up to :data:`COMPARE_PERIODS`).
    compared_periods: float
    #: The most restrictive TLP label of the reports counted: share the landscape no wider.
    tlp: str
    reports: int
    sources: int
    #: The executive summary: short plain sentences, most important first.
    summary: tuple[str, ...]
    #: How to read the numbers, and what they leave out.
    caveats: tuple[str, ...]
    #: Kinds of threat in the period's reports, rising and new first.
    threats: tuple[ThreatTrend, ...]
    #: Kinds of threat that are quieter than usual (some may have no report in the period).
    quieter: tuple[ThreatTrend, ...]
    #: ATT&CK tactics in the period's reports, rising first, then most reported.
    tactics: tuple[TacticTrend, ...]
    #: The intel brief for the same period: exploited weaknesses, severe ones, watch terms and more.
    brief: Brief


def period_start(now: datetime, days: int) -> str:
    """ISO-8601 start of the earliest comparison period for a landscape of ``days`` days ending at ``now``."""
    return (now - timedelta(days=days * (COMPARE_PERIODS + 1))).isoformat()


# --------------------------------------------------------------------------- words


def per_period(days: int) -> str:
    return {1: 'a day', 7: 'a week'}.get(days, f'every {days} days')


def periods_name(days: int) -> str:
    return {1: 'days', 7: 'weeks'}.get(days, f'{days}-day periods')


def usual_text(change: Change, days: int) -> str:
    """``usually about 4 a week``, ``usually fewer than 1 a week``, ``new``, or ``''`` without history."""
    if change.usual is None:
        return ''
    if change.label == NEW:
        return 'new'
    if change.usual < 1:
        return f'usually fewer than 1 {per_period(days)}'
    return f'usually about {round(change.usual)} {per_period(days)}'


def _counted(change: Change, days: int, noun: str = 'report') -> str:
    """``6 reports, usually about 2 a week`` (or just ``6 reports`` without history)."""
    usual = usual_text(change, days)
    return count_of(change.current, noun) + (f', {usual}' if usual else '')


# --------------------------------------------------------------------------- counting


def compare(
    current: int,
    before: int,
    periods: float,
    *,
    share_now: float | None = None,
    share_before: float | None = None,
) -> Change:
    """Classify ``current`` against ``before`` (the total over ``periods`` earlier periods).

    With shares (the part of all reports in each window), a rise or fall must show in the share too.
    """
    if periods <= 0:
        return Change(NO_HISTORY, current, None)
    usual = before / periods
    if before == 0:
        return Change(NEW if current else STEADY, current, 0.0)
    more = current >= MIN_RISING and current >= 1.5 * usual + 1
    less = usual >= MIN_RISING and current <= usual / 2
    if share_now is not None and share_before:
        more = more and share_now >= 1.25 * share_before
        less = less and share_now <= 0.8 * share_before
    return Change(RISING if more else QUIETER if less else STEADY, current, usual)


def _share(part: int, whole: int) -> float:
    return part / whole if whole else 0.0


def _rank(change: Change) -> tuple[int, float, int]:
    return (_ORDER[change.label], -(change.current - (change.usual or 0.0)), -change.current)


@dataclass(frozen=True, slots=True)
class _Windows:
    since_date: str
    start_date: str
    periods: float
    compared_since: str | None
    #: Reports in the chosen period and in the comparison periods, by ID.
    now: dict[str, BriefDocument]
    before: dict[str, BriefDocument]


def _windows(data: LandscapeData, days: int, since: str) -> _Windows:
    since_date = since[:10]
    start = (datetime.fromisoformat(since) - timedelta(days=days * COMPARE_PERIODS)).isoformat()
    # History starts when Insight received its first (non-demo) report, or at the comparison start if earlier.
    history = max(start, data.first_received) if data.first_received else since
    covered = (datetime.fromisoformat(since) - datetime.fromisoformat(history)).total_seconds() / 86_400
    periods = round(min(covered / days, COMPARE_PERIODS), 2) if covered >= days / 2 else 0.0
    now: dict[str, BriefDocument] = {}
    before: dict[str, BriefDocument] = {}
    for doc in data.documents:
        if is_demo(doc):
            continue
        day = published(doc)
        if day >= since_date:
            now[doc.id] = doc
        elif periods and day >= history[:10]:
            before[doc.id] = doc
    return _Windows(since_date, history[:10], periods, history if periods else None, now, before)


def _evidence(docs: Iterable[BriefDocument]) -> tuple[BriefItem, ...]:
    newest = sorted(docs, key=lambda d: (published(d), d.created_at, d.id), reverse=True)
    return tuple(BriefItem(f'{d.title} · {d.source_name}', d.id) for d in newest[:EVIDENCE_REPORTS])


def _themes(data: LandscapeData, w: _Windows) -> list[ThreatTrend]:
    by_technique: dict[str, set[str]] = defaultdict(set)
    for doc_id, technique_id in data.techniques:
        for theme in THEMES:
            if theme.has_technique(technique_id):
                by_technique[theme.key].add(doc_id)
    trends = []
    for theme in THEMES:
        ids = data.theme_words.get(theme.key, set()) | by_technique[theme.key]
        now = [w.now[i] for i in ids if i in w.now]
        before = sum(1 for i in ids if i in w.before)
        change = compare(
            len(now),
            before,
            w.periods,
            share_now=_share(len(now), len(w.now)),
            share_before=_share(before, len(w.before)),
        )
        trends.append(_trend(theme, change, now))
    return trends


def _trend(theme: Theme, change: Change, docs: list[BriefDocument]) -> ThreatTrend:
    return ThreatTrend(
        key=theme.key,
        name=theme.name,
        change=change,
        sources=len({d.source_name for d in docs}),
        what=theme.what,
        impact=theme.impact,
        check=theme.check,
        reports=_evidence(docs),
        words=theme.words,
        techniques=theme.techniques,
    )


def _tactics(data: LandscapeData, w: _Windows) -> list[TacticTrend]:
    known = catalog()
    tactics_now: dict[str, set[str]] = defaultdict(set)
    tactics_before: dict[str, set[str]] = defaultdict(set)
    techniques_now: dict[str, Counter[str]] = defaultdict(Counter)
    tagged_now: set[str] = set()
    tagged_before: set[str] = set()
    seen: set[tuple[str, str]] = set()
    for doc_id, technique_id in data.techniques:
        if (found := known.techniques.get(technique_id)) is None or (doc_id, technique_id) in seen:
            continue
        seen.add((doc_id, technique_id))
        if doc_id in w.now:
            tagged_now.add(doc_id)
            for shortname in found.tactics:
                tactics_now[shortname].add(doc_id)
                techniques_now[shortname][technique_id] += 1
        elif doc_id in w.before:
            tagged_before.add(doc_id)
            for shortname in found.tactics:
                tactics_before[shortname].add(doc_id)
    trends = []
    for tactic in known.tactics:
        current = len(tactics_now[tactic.shortname])
        if not current:
            continue
        before = len(tactics_before[tactic.shortname])
        change = compare(
            current,
            before,
            w.periods,
            share_now=_share(current, len(tagged_now)),
            share_before=_share(before, len(tagged_before)),
        )
        top = sorted(techniques_now[tactic.shortname].items(), key=lambda t: (-t[1], t[0]))[:TOP_TECHNIQUES]
        techniques = tuple((t, known.techniques[t].full_name, n) for t, n in top)
        plain = PLAIN_TACTICS.get(tactic.shortname, tactic.name.lower())
        trends.append(TacticTrend(tactic.shortname, tactic.name, plain, change, techniques))
    return sorted(trends, key=lambda t: (_ORDER[t.change.label] != _ORDER[RISING], -t.change.current))


# --------------------------------------------------------------------------- the summary


def _activity(w: _Windows, days: int, sources: int) -> str:
    period = f'the last {count_of(days, "day")}'
    if not w.now:
        return f'No new reports came in during {period}.'
    line = f'In {period}, {count_of(len(w.now), "new report")} came in from {count_of(sources, "source")}'
    change = compare(len(w.now), len(w.before), w.periods)
    if change.label == RISING:
        return f'{line}, more than usual ({usual_text(change, days)}).'
    if change.label == QUIETER:
        return f'{line}, fewer than usual ({usual_text(change, days)}).'
    if change.label == STEADY:
        return f'{line}, about as many as usual.'
    return f'{line}.'


def _trending(threats: list[ThreatTrend], quieter: list[ThreatTrend], days: int) -> list[str]:
    lines = []
    if hot := [t for t in threats if t.change.label in (RISING, NEW)][:3]:
        named = name_list([f'{t.name} ({_counted(t.change, days)})' for t in hot], limit=3)
        lines.append(f'Trending: {named}.')
    elif threats:
        top = threats[0]
        lines.append(
            f'The most reported kind of threat is {top.name.lower()}, in {_counted(top.change, days)}.'
        )
    if threats:
        first = hot[0] if hot else threats[0]
        lines.extend((f'Why it matters: {first.impact}', f'What to check: {first.check}'))
    if quieter:
        lines.append(f'Quieter than usual: {name_list([t.name for t in quieter], limit=2)}.')
    return lines


def _behaviour(tactics: list[TacticTrend], days: int) -> list[str]:
    if rising := [t for t in tactics if t.change.label == RISING][:2]:
        first = rising[0]
        lines = [f'More reports than usual describe attackers {first.plain}.']
        if len(rising) == 1:
            lines.append(f'That is {_counted(first.change, days)}.')
        else:
            lines.append(f'The same goes for {rising[1].plain}.')
        return lines
    if tactics:
        top = max(tactics, key=lambda t: (t.change.current, -_ORDER[t.change.label]))
        return [f'The reports most often show attackers {top.plain}.']
    return []


def _kev_trend(data: LandscapeData, w: _Windows, days: int) -> str:
    """KEV entries in the period against the periods before (CISA's list spans years: always comparable)."""
    current = sum(1 for k in data.kev if k.date_added >= w.since_date)
    start = (datetime.fromisoformat(w.since_date) - timedelta(days=days * COMPARE_PERIODS)).date().isoformat()
    before = sum(1 for k in data.kev if start <= k.date_added < w.since_date)
    change = compare(current, before, COMPARE_PERIODS)
    if change.label == RISING:
        return (
            f'That is more than usual: CISA added about {round(change.usual or 0)} {per_period(days)} before.'
        )
    return ''


def _caveats(data: LandscapeData, w: _Windows, days: int, tagged: bool) -> tuple[str, ...]:
    lines = [
        'Counts come from terms and tagged attack methods in your reports. A rise can mean more reporting, '
        'not more attacks.'
    ]
    if not w.periods:
        lines.append(
            'Insight has no reports from before this period, so it cannot show trends yet. They will show '
            f'once it has a few {periods_name(days)} of history.'
        )
    elif w.periods < COMPARE_PERIODS:
        lines.append(
            f'Insight has reports for only part of the {COMPARE_PERIODS} {periods_name(days)} before, so the '
            'comparison is rough.'
        )
    if data.truncated:
        lines.append(f'Only the newest {len(data.documents):,} reports were counted.')
    if w.now and not tagged:
        lines.append(
            'No report in this period has ATT&CK techniques yet. Add them in the reader to see what '
            'attackers are doing.'
        )
    return tuple(lines)


def compose(data: LandscapeData, brief_data: BriefData, *, since: str, days: int) -> Landscape:
    """The threat landscape for the ``days`` days from ``since`` (``brief.window_start``).

    ``data`` comes from ``services.landscape_data`` from :func:`period_start`, ``brief_data`` from
    ``services.brief_data`` from ``since``, both read with the same TLP limit.
    """
    w = _windows(data, days, since)
    brief = compose_brief(brief_data, days, kev_trend=_kev_trend(data, w, days))
    themes = _themes(data, w)
    threats = sorted((t for t in themes if t.change.current), key=lambda t: (*_rank(t.change), t.name))
    quieter = sorted((t for t in themes if t.change.label == QUIETER), key=lambda t: -(t.change.usual or 0.0))
    tactics = _tactics(data, w)
    sources = len({d.source_name for d in w.now.values()})
    # Lead with known exploited/severe flaws when present; otherwise lead with the reported threat.
    # Report volume remains context, not the lead finding. Detail sections retain exact CVEs and scores.
    urgent = bool(brief.sections[0].items or brief.sections[1].items)
    summary = [
        *(brief.summary[1:] if urgent else ()),
        *_trending(threats, quieter, days),
        *_behaviour(tactics, days),
        *(brief.summary[1:] if not urgent else ()),
        _activity(w, days, sources),
    ]
    if not w.now and not any(k.date_added >= w.since_date for k in data.kev):
        summary = [
            f'No recent reports are available for the last {count_of(days, "day")}. Sync your sources, and '
            'check their status in About this brief.'
        ]
    labels = [data.tlp[i] for i in (*w.now, *w.before) if i in data.tlp]
    return Landscape(
        days=days,
        since=since,
        compared_since=w.compared_since,
        compared_periods=w.periods,
        tlp=most_restrictive(*labels) if labels else 'CLEAR',
        reports=len(w.now),
        sources=sources,
        summary=tuple(summary),
        caveats=_caveats(data, w, days, tagged=any(doc_id in w.now for doc_id, _ in data.techniques)),
        threats=tuple(threats),
        quieter=tuple(quieter),
        tactics=tuple(tactics),
        brief=brief,
    )
