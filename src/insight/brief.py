"""The intel brief: a short, plain-language summary of recent intelligence, built from the data alone.

No model writes it, so it never states anything the reports do not: every line is a count or a value from the
database and links back to its report or indicator. ``services.brief_data`` gathers the facts; :func:`compose`
turns them into a headline and short sections. Front ends render the result as they like.
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Final

from .services import BriefData, BriefKev

DEFAULT_DAYS: Final = 7
MAX_DAYS: Final = 30
SECTION_ITEMS: Final = 5
#: CVSS base score from which a weakness counts as critical (the CVSS v3 and v4 "Critical" band).
CRITICAL: Final = 9.0
#: Lines that ``connectors.parse_csaf`` writes: ``- CVE-2026-1, CVSS 3 base score 9.8: ...`` and
#: ``Vendors: a, b``.
SCORE_LINE: Final = re.compile(r'^- (CVE-\d{4}-\d{4,}), CVSS [\d.]+ base score (\d{1,2}(?:\.\d+)?):', re.M)
VENDOR_LINE: Final = re.compile(r'^Vendors: (.+)$', re.M)


@dataclass(frozen=True, slots=True)
class BriefItem:
    """One line of a section. It opens ``document_id`` or looks up the indicator ``entity`` when set."""

    text: str
    document_id: str | None = None
    entity: str | None = None


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
    headline: str
    sections: tuple[BriefSection, ...]


def window_start(now: datetime, days: int = DEFAULT_DAYS) -> str:
    """ISO-8601 start of a window of ``days`` days (1 to :data:`MAX_DAYS`) ending at ``now``."""
    if not 1 <= days <= MAX_DAYS:
        raise ValueError(f'days must be between 1 and {MAX_DAYS}')
    return (now - timedelta(days=days)).isoformat()


def _count(count: int, singular: str, plural: str | None = None) -> str:
    return f'{count} {singular if count == 1 else plural or singular + "s"}'


def _kev_label(kev: BriefKev) -> str:
    return ' '.join(part for part in (kev.vendor, kev.product) if part) or 'Unknown product'


def _severe(data: BriefData) -> list[tuple[float, str, str, str]]:
    """``(score, cve, title, document_id)``: critical CVEs in scored reports, highest first, one per CVE."""
    best: dict[str, tuple[float, str, str, str]] = {}
    for doc in data.documents:
        for cve, score in SCORE_LINE.findall(doc.body):
            value = float(score)
            if value >= CRITICAL and value > best.get(cve, (0.0,))[0]:
                best[cve] = (value, cve, doc.title, doc.id)
    return sorted(best.values(), key=lambda s: (-s[0], s[1]))


def _vendors(data: BriefData) -> Counter[str]:
    counts: Counter[str] = Counter()
    for doc in data.documents:
        for line in VENDOR_LINE.findall(doc.body):
            counts.update({v.strip() for v in line.split(',') if v.strip()})
    counts.update(k.vendor for k in data.kev_added if k.vendor)
    return counts


def _headline(data: BriefData, days: int, critical: int) -> str:
    if not data.documents and not data.kev_added:
        return f'No new reports in the last {_count(days, "day")}. Sync your sources to get the latest.'
    sources = len({d.source_name for d in data.documents})
    parts = [f'{_count(len(data.documents), "new report")} from {_count(sources, "source")}.']
    if data.kev_added:
        more = _count(len(data.kev_added), 'more weakness', 'more weaknesses')
        parts.append(f'CISA says attackers are now using {more}.')
    if critical:
        parts.append(f'{_count(critical, "weakness is", "weaknesses are")} rated critical.')
    return ' '.join(parts)


def compose(data: BriefData, days: int = DEFAULT_DAYS) -> Brief:
    """Turn :class:`~insight.services.BriefData` into a headline and four short sections."""
    severe = _severe(data)
    exploited = [
        BriefItem(f'{k.cve} · {_kev_label(k)} · added {k.date_added}', k.document_id or None)
        for k in data.kev_added
    ]
    listed = {k.cve for k in data.kev_added}
    exploited += [
        BriefItem(f'{k.cve} · {_kev_label(k)} · in {_count(k.reports, "new report")}', k.document_id or None)
        for k in data.kev_mentioned
        if k.cve not in listed
    ]
    severe_items = tuple(
        BriefItem(f'{cve} · CVSS {score:g} · {title}', doc)
        for score, cve, title, doc in severe[:SECTION_ITEMS]
    )
    shared_items = tuple(
        BriefItem(f'{s.value} · {_count(s.sources, "source")}, {_count(s.reports, "report")}', entity=s.value)
        for s in data.shared[:SECTION_ITEMS]
    )
    vendors = sorted(_vendors(data).items(), key=lambda v: (-v[1], v[0].casefold()))[:SECTION_ITEMS]
    vendor_items = tuple(BriefItem(f'{name} ({count})') for name, count in vendors)
    sections = (
        BriefSection(
            'Exploited now',
            tuple(exploited[:SECTION_ITEMS]),
            'Nothing new from the list of weaknesses that attackers use (CISA KEV).',
        ),
        BriefSection(
            'Most severe',
            severe_items,
            'No new CISA advisory has a weakness with a score of 9 or more (CVSS).',
        ),
        BriefSection(
            'Seen in several sources',
            shared_items,
            'No indicator appears in reports from more than one source.',
        ),
        BriefSection('Most-mentioned vendors', vendor_items, 'No vendors named in the new advisories.'),
    )
    return Brief(days=days, since=data.since, headline=_headline(data, days, len(severe)), sections=sections)
