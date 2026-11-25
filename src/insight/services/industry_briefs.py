"""Bounded sector briefs from cited target mappings and explicitly linked, visible reports."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..actor_brief import actor_profile
from ..focused_brief import BriefItem, BriefSection, BriefSource, FocusedBrief
from ..industries import BY_KEY, plain
from ..models import ActorDocument, Document
from ..schemas import most_restrictive
from ..threat_library import library
from .threat_profiles import _candidates
from .tlp import _visible, visible_levels

_REPORT_CAP = 100
_SCAN_CAP = 500
_GROUP_CAP = 5


def _text(value: str, cap: int = 250) -> str:
    clean = plain(value)
    return clean if len(clean) <= cap else clean[: cap - 1].rstrip() + '…'


@dataclass(frozen=True)
class _Reports:
    items: tuple[BriefItem, ...]
    labels: tuple[str, ...]
    by_group: Counter[str]
    mentioned: int
    linked: int
    capped: bool
    scan_capped: bool
    report_labels: dict[str, str]
    mention_ids: frozenset[str]
    linked_ids: frozenset[str]


def _sector_reports(
    db: Session,
    ref: str,
    refs: tuple[str, ...],
    *,
    days: int,
    max_tlp: str | None,
    now: datetime,
) -> _Reports:
    rows = list(
        db.execute(
            select(
                Document.id,
                Document.title,
                Document.tlp,
                Document.created_at,
                Document.source_name,
                Document.body,
            )
            .where(
                Document.is_current.is_(True),
                *_visible(max_tlp),
                Document.created_at >= (now - timedelta(days=days)).isoformat(),
                Document.created_at <= now.isoformat(),
            )
            .order_by(Document.created_at.desc(), Document.id)
            .limit(_SCAN_CAP + 1)
        )
    )
    scan_capped = len(rows) > _SCAN_CAP
    # The scan-limit flag describes the visible collection, so keep the labels that contributed to it.
    labels = [row[2] for row in rows] if scan_capped else []
    rows = rows[:_SCAN_CAP]
    linked_ids: set[str] = set()
    link_labels: dict[str, list[str]] = {}
    by_group: Counter[str] = Counter()
    links = db.execute(
        select(
            ActorDocument.document_id,
            ActorDocument.group_ref,
            ActorDocument.tlp,
        ).where(
            ActorDocument.group_ref.in_(refs),
            ActorDocument.document_id.in_([row[0] for row in rows]),
            ActorDocument.tlp.in_(visible_levels(max_tlp)),
        )
    )
    for doc_id, group_ref, label in links:
        linked_ids.add(doc_id)
        link_labels.setdefault(doc_id, []).append(label)
        by_group[group_ref] += 1
    reports: list[BriefItem] = []
    report_labels: dict[str, str] = {}
    mention_ids: set[str] = set()
    mentions = 0
    for doc_id, title, label, created_at, source, body in rows:
        mentioned = bool(BY_KEY[ref].phrases.search(plain(title + '\n' + body)))
        linked = doc_id in linked_ids
        if not mentioned and not linked:
            continue
        mentions += mentioned
        if mentioned:
            mention_ids.add(doc_id)
        labels.extend((label, *link_labels.get(doc_id, [])))
        report_labels[doc_id] = most_restrictive(label, *link_labels.get(doc_id, []))
        reasons = [
            text
            for match, text in (
                (mentioned, 'Mentions this sector'),
                (linked, 'Linked to a sector-targeting group'),
            )
            if match
        ]
        reports.append(BriefItem(doc_id, _text(title), _text(source, 120), created_at, '; '.join(reasons)))
    return _Reports(
        tuple(reports[:_REPORT_CAP]),
        tuple(labels),
        by_group,
        mentions,
        len(linked_ids),
        len(reports) > _REPORT_CAP,
        scan_capped,
        report_labels,
        frozenset(mention_ids),
        frozenset(linked_ids),
    )


def _industry_brief(
    db: Session,
    ref: str,
    *,
    days: int,
    max_tlp: str | None,
    now: datetime,
) -> FocusedBrief:
    if ref not in BY_KEY:
        raise LookupError('Brief topic not found')
    industry = BY_KEY[ref]
    candidates, removed = _candidates(db, ref, max_tlp)
    labels = ['CLEAR', *(value[2] for value in candidates.values())]
    labels.extend(row.effective_tlp for row in removed)
    refs = tuple(sorted(candidates))
    evidence = _sector_reports(db, ref, refs, days=days, max_tlp=max_tlp, now=now)
    reports = evidence.items
    labels.extend(evidence.labels)
    ordered = sorted(
        candidates,
        key=lambda key: (-evidence.by_group[key], candidates[key][0].name.casefold(), key),
    )
    shown = ordered[:_GROUP_CAP]
    sources: list[BriefSource] = []
    group_lines: list[str] = []
    methods: list[str] = []
    watch: list[str] = []
    lib = library()
    for key in shown:
        subject, claims, _ = candidates[key]
        claim_evidence = next((claim for claim in claims if claim.evidence), None)
        attribution = ', '.join(dict.fromkeys(claim.source_name for claim in claims))
        line = f'{_text(subject.name, 80)} — {_text(attribution, 100)}'
        if claim_evidence:
            line += ': ' + _text(claim_evidence.evidence, 200)
        group_lines.append(line)
        sources.extend(
            BriefSource(f'{_text(subject.name, 60)}: {claim.source_name}', claim.url)
            for claim in claims
            if claim.url.startswith(('https://', 'http://'))
        )
        if subject.catalog:
            profile = actor_profile(subject.name, subject.description, subject.aliases, subject.catalog, lib)
            for section in profile.sections:
                if section.title == 'How they operate' and section.lines:
                    methods.append(f'{_text(subject.name, 80)}: {section.lines[0]}')
                if section.title == 'What to watch for':
                    watch.extend(section.lines[:2])
    coverage = (
        f'{"At least " if evidence.capped or evidence.scan_capped else ""}{len(reports)} related current '
        f'report(s) were added in the last {days} days.'
        if reports
        else f'No related current reports were found in the last {days} days.'
    )
    summary = (
        industry.covers,
        f'Saved sources name {len(candidates)} threat group(s) as having targeted this sector.'
        if candidates
        else 'No source-backed threat groups are recorded for this sector yet.',
        coverage,
    )
    sections: list[BriefSection] = []
    if group_lines:
        group_lines.append(
            f'Shows {len(shown)} of {len(candidates)} groups, with recent linked reports first. '
            'This describes saved background, not a current attack ranking.'
        )
        sections.append(BriefSection('Groups known to target this sector', tuple(group_lines)))
    if methods:
        sections.append(
            BriefSection(
                'Methods recorded for these groups',
                (
                    *tuple(methods[:3]),
                    'These methods are recorded for the groups; their use against this sector '
                    'is not established here.',
                ),
            )
        )
    if watch:
        sections.append(
            BriefSection(
                'What to watch for',
                (
                    *tuple(dict.fromkeys(watch))[:3],
                    'Use these checks to plan a review of your systems. '
                    'They do not show that you have been attacked.',
                ),
            )
        )
    sections.append(
        BriefSection(
            'Reports mentioning this sector',
            (
                f'{evidence.mentioned} report(s) mention sector terms in their title or text, '
                'within the scan limit.',
                'A mention shows relevance; it does not confirm an attack on this sector '
                'or link a report to a group.',
            ),
        )
    )
    sections.append(
        BriefSection(
            'Reports linked to sector-targeting groups',
            (
                f'{evidence.linked} report(s) have an analyst-made link to a group '
                'with a cited target mapping.',
                'These reports may cover other sectors too. A report can appear in both groups '
                'and is listed only once.',
            ),
        )
    )
    note = 'Report dates show when items were added to Insight, not when attacks happened.'
    cap_note = (
        f'Only the latest {_SCAN_CAP} current reports were scanned; relevant reports may be missing.'
        if evidence.scan_capped
        else f'Review is capped at {_REPORT_CAP} matching reports and lists the latest five.'
        if evidence.capped
        else 'Lists up to five latest reports. Target mappings and report links keep their sharing limits.'
    )
    return FocusedBrief(
        'industry',
        ref,
        industry.name,
        most_restrictive(*labels),
        days,
        summary,
        (note, cap_note),
        reports[:5],
        tuple(sections),
        tuple(dict.fromkeys(sources))[:6],
    )
