"""Deterministic executive brief from stored reports, with links back to its evidence."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Final

from .brief_facts import SECTION_ITEMS as SECTION_ITEMS
from .brief_facts import _count, _day, _Facts, _facts, _names, _product, _source, _time
from .brief_facts import is_demo as is_demo
from .brief_facts import published as published
from .brief_highlights import coverage, highlights
from .brief_types import Brief, BriefSection
from .brief_types import BriefHighlight as BriefHighlight
from .brief_types import BriefItem as BriefItem
from .services import BriefData, BriefKev

DEFAULT_DAYS: Final = 7
MAX_DAYS: Final = 30


def window_start(now: datetime, days: int = DEFAULT_DAYS) -> str:
    """ISO-8601 start of a window of ``days`` days (1 to :data:`MAX_DAYS`) ending at ``now``."""
    if not 1 <= days <= MAX_DAYS:
        raise ValueError(f'days must be between 1 and {MAX_DAYS}')
    return (now - timedelta(days=days)).isoformat()


# --------------------------------------------------------------------------- the brief


def _deadline(added: list[BriefKev], today: str) -> list[str]:
    """CISA's fix-by date for US federal agencies: the next one, or else that it has passed (dates apply to
    those agencies only, not to everyone)."""
    dues = sorted(k.due_date for k in added if _day(k.due_date) is not None)
    if upcoming := [d for d in dues if d >= today]:
        which = 'it' if len(added) == 1 else 'the next of them'
        return [f'US federal agencies must fix {which} by {upcoming[0]}.']
    if dues:
        which = 'it' if len(added) == 1 else f'{len(dues)} of them'
        return [f'The date by which US federal agencies had to fix {which} has passed.']
    return []


def _summary(facts: _Facts, days: int, today: str) -> tuple[str, ...]:
    period = f'the last {_count(days, "day")}'
    if not facts.fresh and not facts.kev_added:
        return (f'No recent reports are available for {period}. Check the source status below.',)
    sources = len({_source(d) for d in facts.fresh})
    if facts.fresh:
        lines = [
            f'In {period}, {_count(len(facts.fresh), "new report")} came in from {_count(sources, "source")}.'
        ]
    else:
        lines = [f'No new reports came in during {period}.']
    if added := facts.kev_added:
        more = _count(len(added), 'more weakness', 'more weaknesses')
        vendors = _names([k.vendor or k.product for k in added])
        lines.append(
            f'CISA added {more} to its known exploited list'
            + (f', in products from {vendors}.' if vendors else '.')
        )
        lines += _deadline(added, today)
    if mentioned := facts.kev_mentioned:
        verb = 'appears' if len(mentioned) == 1 else 'appear'
        sources_named = _names([name for m in mentioned for name in m[3]])
        lines.append(
            f"{_count(len(mentioned), 'weakness', 'weaknesses')} already on CISA's list also {verb} in new "
            f'reports from {sources_named}.'
        )
    if facts.severe:
        score, cve, title, _ = facts.severe[0]
        product = title.split(' · ', 1)[-1]
        lines.append(f'The highest listed base score is {score:g} out of 10 for {cve} in {product}.')
    if facts.watch is None:
        lines.append(
            'Add watch terms for the products you use, and this summary will say which reports concern you.'
        )
    elif not facts.watch:
        lines.append('None of the new reports mention your watch terms.')
    else:
        verb = 'mentions' if facts.watch_reports == 1 else 'mention'
        terms = ', '.join(f'{term} ({n})' for term, n in facts.watch[:SECTION_ITEMS])
        lines.append(f'{_count(facts.watch_reports, "new report")} {verb} your watch terms: {terms}.')
    if facts.kev_added or facts.kev_mentioned or facts.severe:
        lines.append(
            'First step: check whether you use any of these products, and fix the ones attackers use first.'
        )
    return tuple(lines)


def compose(data: BriefData, days: int = DEFAULT_DAYS, *, as_of: datetime | None = None) -> Brief:
    """Turn :class:`~insight.services.BriefData` into an executive summary and five short sections."""
    start = _time(data.since)
    if start is None or not 1 <= days <= MAX_DAYS:
        raise ValueError('The brief needs an aware start time and a window of 1 to 30 days')
    end = as_of or start + timedelta(days=days)
    if end.tzinfo is None or end < start:
        raise ValueError('The end of the brief must be an aware time at or after its start')
    end = end.astimezone(UTC)
    facts = _facts(data, end)
    added = {k.cve for k in facts.kev_added}
    exploited = [
        BriefItem(f'{k.cve} · {_product(k)} · added {k.date_added}', k.document_id or None)
        for k in facts.kev_added
    ]
    exploited += [
        BriefItem(f'{k.cve} · {_product(k)} · in {_count(n, "new report")}', newest)
        for k, n, newest, _ in facts.kev_mentioned
        if k.cve not in added
    ]
    severe = [BriefItem(f'{cve} · CVSS {score:g} · {title}', doc) for score, cve, title, doc in facts.severe]
    watch = [BriefItem(f'{term} · {_count(n, "new report")}', search=term) for term, n in facts.watch or []]
    shared = [
        BriefItem(f'{value} · {_count(n, "source")}, {_count(reports, "report")}', entity=value)
        for _, value, n, reports in facts.shared
    ]
    vendors = [BriefItem(f'{name} ({n})', search=name) for name, n in facts.vendors]
    no_terms = 'You have no watch terms yet. Add the products you use in the Watch tab.'
    sections = (
        BriefSection(
            'Exploited now',
            tuple(exploited[:SECTION_ITEMS]),
            'No recent additions or report mentions from the CISA list of known exploited flaws.',
        ),
        BriefSection(
            'Most severe',
            tuple(severe[:SECTION_ITEMS]),
            'No new CISA advisory has a weakness with a score of 9 or more (CVSS).',
        ),
        BriefSection(
            'Your watch terms',
            tuple(watch[:SECTION_ITEMS]),
            no_terms if facts.watch is None else 'None of the new reports mention your watch terms.',
        ),
        BriefSection(
            'Seen in several sources',
            tuple(shared[:SECTION_ITEMS]),
            'No indicator appears in reports from more than one source.',
        ),
        BriefSection(
            'Most-mentioned vendors',
            tuple(vendors[:SECTION_ITEMS]),
            'No vendors named in the new advisories.',
        ),
    )
    recent = sum(
        (received := _time(doc.created_at)) is not None and end - timedelta(hours=24) <= received <= end
        for doc in facts.fresh
    )
    return Brief(
        days=days,
        since=data.since,
        summary=_summary(facts, days, end.date().isoformat()),
        sections=sections,
        as_of=end.isoformat(),
        recent_reports=recent,
        report_count=len(facts.fresh),
        source_count=len({_source(doc) for doc in facts.fresh}),
        highlights=highlights(data, facts, end),
        coverage=coverage(data, facts, end),
    )
