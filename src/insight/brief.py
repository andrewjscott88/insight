"""The intel brief: an executive summary and short sections on recent intelligence, built from the data alone.

No model writes it, so it never states anything the reports do not: every sentence is a count, a date or a
value from the database, and every line below the summary opens its evidence. ``services.brief_data`` gathers
the raw facts; :func:`compose` decides what counts as new and words it.

"New" means published in the window: CISA KEV entries by the day CISA added them, CISA advisories by the day
CISA first released them, and other reports by the day Insight received them. So a first sync of years of
history, or CISA updating old advisories, does not flood the brief. The synthetic demo reports are left out.
"""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Final

from .demo import REPORTS as DEMO_REPORTS
from .services import KEV_SOURCE, BriefData, BriefDocument, BriefKev

DEFAULT_DAYS: Final = 7
MAX_DAYS: Final = 30
SECTION_ITEMS: Final = 5
#: CVSS base score from which a weakness counts as critical (the CVSS v3 and v4 "Critical" band).
CRITICAL: Final = 9.0
#: Lines that ``connectors.parse_csaf`` writes (``tests/unit/test_brief.py`` checks the contract).
SCORE_LINE: Final = re.compile(r'^- (CVE-\d{4}-\d{4,}), CVSS [\d.]+ base score (\d{1,2}(?:\.\d+)?):', re.M)
VENDOR_LINE: Final = re.compile(r'^Vendors: (.+)$', re.M)
RELEASE_LINE: Final = re.compile(
    r'^Released (\d{4}-\d{2}-\d{2})(?:; current version .* \((\d{4}-\d{2}-\d{2})\))?\.$', re.M
)
DEMO: Final = frozenset((title, source) for title, source, _, _ in DEMO_REPORTS)


@dataclass(frozen=True, slots=True)
class BriefItem:
    """One line of a section: it opens a report, looks up an indicator, or searches the reports for a word."""

    text: str
    document_id: str | None = None
    entity: str | None = None
    search: str | None = None


@dataclass(frozen=True, slots=True)
class BriefSection:
    title: str
    items: tuple[BriefItem, ...]
    #: Shown instead of the items when there are none.
    empty: str


@dataclass(frozen=True, slots=True)
class Brief:
    days: int
    since: str
    #: The executive summary: short plain sentences, most important first.
    summary: tuple[str, ...]
    sections: tuple[BriefSection, ...]


def window_start(now: datetime, days: int = DEFAULT_DAYS) -> str:
    """ISO-8601 start of a window of ``days`` days (1 to :data:`MAX_DAYS`) ending at ``now``."""
    if not 1 <= days <= MAX_DAYS:
        raise ValueError(f'days must be between 1 and {MAX_DAYS}')
    return (now - timedelta(days=days)).isoformat()


# --------------------------------------------------------------------------- words


def _count(count: int, singular: str, plural: str | None = None) -> str:
    return f'{count} {singular if count == 1 else plural or singular + "s"}'


def _names(names: list[str], limit: int = 3) -> str:
    """``A``, ``A and B``, ``A, B and C``, or ``A, B, C and 2 others``."""
    unique = list(dict.fromkeys(n for n in names if n))
    shown, rest = unique[:limit], len(unique) - limit
    if rest > 0:
        return ', '.join(shown) + f' and {_count(rest, "other")}'
    return ' and '.join([', '.join(shown[:-1]), shown[-1]]) if len(shown) > 1 else ''.join(shown)


def _product(kev: BriefKev) -> str:
    return ' '.join(part for part in (kev.vendor, kev.product) if part) or 'Unknown product'


# --------------------------------------------------------------------------- facts


def published(doc: BriefDocument) -> str:
    """When ``doc`` was published (``YYYY-MM-DD``): the publisher's date if known, else the day it arrived."""
    # A CISA advisory counts from its first release: CISA also updates advisories that are years old.
    dates = [doc.published, *(released for released, _ in RELEASE_LINE.findall(doc.body))]
    return max((d for d in dates if d), default=doc.created_at[:10])


def _cve_order(cve: str) -> tuple[int, ...]:
    return tuple(int(part) for part in cve.split('-')[1:] if part.isdigit())


def is_demo(doc: BriefDocument) -> bool:
    return (doc.title, doc.source_name) in DEMO


@dataclass(frozen=True, slots=True)
class _Facts:
    fresh: list[BriefDocument]
    kev_added: list[BriefKev]
    #: ``(kev, reports, newest report id, source names)`` for KEV CVEs that fresh non-KEV reports mention.
    kev_mentioned: list[tuple[BriefKev, int, str, list[str]]]
    #: ``(score, cve, title, report id)``, highest first.
    severe: list[tuple[float, str, str, str]]
    #: ``(kind, value, sources, reports)``.
    shared: list[tuple[str, str, int, int]]
    vendors: list[tuple[str, int]]
    #: ``(term, reports)`` for terms with matches, most first; ``None`` when no watch terms exist.
    watch: list[tuple[str, int]] | None
    watch_reports: int


def _facts(data: BriefData) -> _Facts:
    since = data.since[:10]
    fresh = [d for d in data.documents if not is_demo(d) and published(d) >= since]
    by_id = {d.id: d for d in fresh}
    # Newest day first; within a day, by CVE number (CVE-2026-9999 before CVE-2026-10000).
    kev_added = sorted(
        (k for k in data.kev.values() if k.date_added >= since), key=lambda k: _cve_order(k.cve)
    )
    kev_added.sort(key=lambda k: k.date_added, reverse=True)

    mentioned: dict[str, list[BriefDocument]] = defaultdict(list)
    seen_in: dict[tuple[str, str], set[str]] = defaultdict(set)
    for doc_id, kind, value in data.mentions:
        if (doc := by_id.get(doc_id)) is None:
            continue
        seen_in[(kind, value)].add(doc_id)
        if kind == 'cve' and value in data.kev and doc.source_key != KEV_SOURCE:
            mentioned[value].append(doc)
    kev_mentioned = [
        (
            data.kev[cve],
            len(docs),
            max(docs, key=lambda d: (d.created_at, d.id)).id,
            [d.source_name for d in docs],
        )
        for cve, docs in mentioned.items()
    ]
    kev_mentioned.sort(key=lambda m: (-m[1], m[0].cve))

    shared = [
        (kind, value, len({by_id[i].source_name for i in ids}), len(ids))
        for (kind, value), ids in seen_in.items()
        if len({by_id[i].source_name for i in ids}) >= 2
    ]
    shared.sort(key=lambda s: (-s[2], -s[3], s[0], s[1]))

    best: dict[str, tuple[float, str, str, str]] = {}
    spellings: dict[str, Counter[str]] = defaultdict(Counter)
    for doc in fresh:
        for cve, score in SCORE_LINE.findall(doc.body):
            if (rated := float(score)) >= CRITICAL and rated > best.get(cve, (0.0,))[0]:
                best[cve] = (rated, cve, doc.title, doc.id)
        for line in VENDOR_LINE.findall(doc.body):
            for name in {' '.join(v.split()) for v in line.split(',')} - {''}:
                spellings[name.casefold()][name] += 1
    for kev in kev_added:
        if name := ' '.join(kev.vendor.split()):
            spellings[name.casefold()][name] += 1
    # One vendor per case-insensitive name, shown in its most common spelling ("Ltda" and "LTDA" are one).
    vendors = [(names.most_common(1)[0][0], sum(names.values())) for names in spellings.values()]
    vendors.sort(key=lambda v: (-v[1], v[0].casefold()))

    watch = None
    reports: set[str] = set()
    if data.watch:
        hits = {term: ids & by_id.keys() for term, ids in data.watch.items()}
        watch = sorted(
            ((t, len(ids)) for t, ids in hits.items() if ids), key=lambda w: (-w[1], w[0].casefold())
        )
        reports = set().union(*hits.values())
    return _Facts(
        fresh=fresh,
        kev_added=kev_added,
        kev_mentioned=kev_mentioned,
        severe=sorted(best.values(), key=lambda s: (-s[0], s[1])),
        shared=shared,
        vendors=vendors,
        watch=watch,
        watch_reports=len(reports),
    )


# --------------------------------------------------------------------------- the brief


def _deadline(added: list[BriefKev], today: str) -> list[str]:
    """CISA's fix-by date for US federal agencies: the next one, or else that it has passed (dates apply to
    those agencies only, not to everyone)."""
    dues = sorted(k.due_date for k in added if k.due_date)
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
        return (f'Nothing new in {period}. Sync your sources to get the latest.',)
    sources = len({d.source_name for d in facts.fresh})
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
            f'CISA confirmed that attackers are using {more}'
            + (f', in products from {vendors}.' if vendors else '.')
        )
        lines += _deadline(added, today)
    if mentioned := facts.kev_mentioned:
        verb = 'appears' if len(mentioned) == 1 else 'appear'
        sources_named = _names([name for m in mentioned for name in m[3]])
        lines.append(
            f'{_count(len(mentioned), "weakness", "weaknesses")} that attackers use also {verb} in new '
            f'reports from {sources_named}.'
        )
    if facts.severe:
        score, cve, title, _ = facts.severe[0]
        product = title.split(' · ', 1)[-1]
        lines.append(f'The most serious new weakness is {cve} in {product}, scored {score:g} out of 10.')
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


def compose(data: BriefData, days: int = DEFAULT_DAYS) -> Brief:
    """Turn :class:`~insight.services.BriefData` into an executive summary and five short sections."""
    facts = _facts(data)
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
            'Nothing new from the list of weaknesses that attackers use (CISA KEV).',
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
    today = (datetime.fromisoformat(data.since) + timedelta(days=days)).date().isoformat()
    return Brief(days=days, since=data.since, summary=_summary(facts, days, today), sections=sections)
