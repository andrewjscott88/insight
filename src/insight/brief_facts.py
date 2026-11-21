"""Bounded, date-aware facts from stored intelligence; no fetching or generated claims."""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import UTC, date, datetime
from typing import Final

from .cve_scores import CSAF_SCORE_LINE
from .demo import REPORTS as DEMO_REPORTS
from .services import KEV_SOURCE, BriefData, BriefDocument, BriefKev

SECTION_ITEMS: Final = 5
#: CVSS base score from which a weakness counts as critical (the CVSS v3 and v4 "Critical" band).
CRITICAL: Final = 9.0
#: EPSS probability from which the brief calls a weakness likely to be attacked soon (TIP 1.3): 10% within
#: 30 days is in roughly the top 2% of scored CVEs.
LIKELY: Final = 0.1
#: Where a severity score comes from.
CISA_ADVISORY: Final = 'CISA advisory'
NIST_NVD: Final = 'NIST NVD'
#: Lines that ``connectors.parse_csaf`` writes (``tests/unit/test_brief.py`` checks the contract).
SCORE_LINE: Final = CSAF_SCORE_LINE
VENDOR_LINE: Final = re.compile(r'^Vendors: (.+)$', re.M)
RELEASE_LINE: Final = re.compile(
    r'^Released (\d{4}-\d{2}-\d{2})(?:; current version .* \((\d{4}-\d{2}-\d{2})\))?\.$', re.M
)
DEMO: Final = frozenset((title, source) for title, source, _, _ in DEMO_REPORTS)


# --------------------------------------------------------------------------- words


def count_of(count: int, singular: str, plural: str | None = None) -> str:
    return f'{count} {singular if count == 1 else plural or singular + "s"}'


def name_list(names: list[str], limit: int = 3) -> str:
    """``A``, ``A and B``, ``A, B and C``, or ``A, B, C and 2 others``."""
    unique = list(dict.fromkeys(n for n in names if n))
    shown, rest = unique[:limit], len(unique) - limit
    if rest > 0:
        return ', '.join(shown) + f' and {count_of(rest, "other")}'
    return ' and '.join([', '.join(shown[:-1]), shown[-1]]) if len(shown) > 1 else ''.join(shown)


def _product(kev: BriefKev) -> str:
    return ' '.join(part for part in (kev.vendor, kev.product) if part) or 'Unknown product'


# --------------------------------------------------------------------------- facts


def published(doc: BriefDocument) -> str:
    """When ``doc`` was published (``YYYY-MM-DD``): the publisher's date if known, else the day it arrived."""
    # A CISA advisory counts from its first release: CISA also updates advisories that are years old.
    dates = [doc.published, *(released for released, _ in RELEASE_LINE.findall(doc.body))]
    known = [value for value in dates if value]
    if any(_day(value) is None for value in known):
        return ''
    if not known and re.search(r'^Released ', doc.body, re.M):
        return ''  # A malformed publisher date is not replaced with a recent receipt date.
    received = _time(doc.created_at)
    return max(known, default=received.date().isoformat() if received is not None else '')


def _day(value: str) -> date | None:
    try:
        return date.fromisoformat(value) if re.fullmatch(r'\d{4}-\d{2}-\d{2}', value) else None
    except ValueError:
        return None


def _time(value: str) -> datetime | None:
    try:
        moment = datetime.fromisoformat(value)
        return moment.astimezone(UTC) if moment.tzinfo is not None else None
    except ValueError:
        return None


def _source(doc: BriefDocument) -> str:
    return doc.source_key or ' '.join(doc.source_name.casefold().split())


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
    #: ``(score, cve, title, report id, origin)``, highest first; origin is :data:`CISA_ADVISORY` (the score
    #: in a new CISA advisory) or :data:`NIST_NVD` (NVD's cached score of a CVE a new report mentions).
    severe: list[tuple[float, str, str, str, str]]
    #: ``(EPSS probability, cve, title, report id)`` of the CVEs in new reports with EPSS of :data:`LIKELY` or
    #: more, highest first.
    likely: list[tuple[float, str, str, str]]
    #: ``(kind, value, sources, reports)``.
    shared: list[tuple[str, str, int, int]]
    vendors: list[tuple[str, int]]
    #: ``(term, reports)`` for terms with matches, most first; ``None`` when no watch terms exist.
    watch: list[tuple[str, int]] | None
    watch_reports: int


def _facts(data: BriefData, as_of: datetime) -> _Facts:
    start = _time(data.since)
    if start is None:
        raise ValueError('The brief needs an aware start time')
    fresh = [
        d
        for d in data.documents
        if not is_demo(d)
        and (received := _time(d.created_at)) is not None
        and start <= received <= as_of
        and (released := _day(published(d))) is not None
        and start.date() <= released <= as_of.date()
    ]
    by_id = {d.id: d for d in fresh}
    # Newest day first; within a day, by CVE number (CVE-2026-9999 before CVE-2026-10000).
    kev_added = sorted(
        (
            k
            for k in data.kev.values()
            if (added := _day(k.date_added)) is not None and start.date() <= added <= as_of.date()
        ),
        key=lambda k: _cve_order(k.cve),
    )
    kev_added.sort(key=lambda k: k.date_added, reverse=True)

    mentioned: dict[str, list[BriefDocument]] = defaultdict(list)
    seen_in: dict[tuple[str, str], set[str]] = defaultdict(set)
    for doc_id, kind, value in sorted(set(data.mentions)):
        if (doc := by_id.get(doc_id)) is None:
            continue
        seen_in[(kind, value)].add(doc_id)
        if (
            kind == 'cve'
            and value in data.kev
            and doc.source_key != KEV_SOURCE
            and (added := _day(data.kev[value].date_added)) is not None
            and added <= as_of.date()
        ):
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
        (kind, value, len({_source(by_id[i]) for i in ids}), len(ids))
        for (kind, value), ids in seen_in.items()
        if len({_source(by_id[i]) for i in ids}) >= 2
    ]
    shared.sort(key=lambda s: (-s[2], -s[3], s[0], s[1]))

    best: dict[str, tuple[float, str, str, str, str]] = {}
    spellings: dict[str, Counter[str]] = defaultdict(Counter)
    for doc in fresh:
        for cve, score in SCORE_LINE.findall(doc.body):
            if CRITICAL <= (rated := float(score)) <= 10 and rated > best.get(cve, (0.0,))[0]:
                best[cve] = (rated, cve, doc.title, doc.id, CISA_ADVISORY)
        for line in VENDOR_LINE.findall(doc.body):
            for name in {' '.join(v.split()) for v in line.split(',')} - {''}:
                spellings[name.casefold()][name] += 1
    for kev in kev_added:
        if name := ' '.join(kev.vendor.split()):
            spellings[name.casefold()][name] += 1
    # NVD's score of a CVE that a new report mentions (TIP 1.3): it joins, or beats, a CISA advisory's.
    newest_mention: dict[str, BriefDocument] = {}
    for (kind, value), ids in seen_in.items():
        if kind == 'cve':
            newest_mention[value] = max((by_id[i] for i in ids), key=lambda d: (d.created_at, d.id))
    likely = []
    for cve, doc in newest_mention.items():
        found = data.scores.get(cve)
        nvd = found.nvd.score if found and found.nvd and found.nvd.status != 'Rejected' else None
        if nvd is not None and CRITICAL <= nvd <= 10 and nvd > best.get(cve, (0.0,))[0]:
            best[cve] = (nvd, cve, doc.title, doc.id, NIST_NVD)
        if found and found.epss and found.epss.probability >= LIKELY:
            likely.append((found.epss.probability, cve, doc.title, doc.id))
    likely.sort(key=lambda entry: (-entry[0], entry[1]))
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
        likely=likely,
        shared=shared,
        vendors=vendors,
        watch=watch,
        watch_reports=len(reports),
    )
