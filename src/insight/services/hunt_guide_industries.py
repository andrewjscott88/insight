"""Sector hunt plans from cited group context and distinct report-relevance signals."""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..hunt_guide import GuideSection, HuntGuide
from ..hunt_guide_plan import planning_sections
from ..industries import BY_KEY, plain
from ..models import DocumentTechnique
from ..schemas import most_restrictive
from .actor_reports import ReportRef
from .industry_briefs import _sector_reports
from .techniques import TAGGED
from .threat_guides import SweepEntry
from .threat_profiles import _candidates

_DAYS = 30
_GROUP_CAP = 5
_REPORT_CAP = 20


def _text(value: str, limit: int = 600) -> str:
    return plain(value)[:limit]


def _industry_parts(
    db: Session,
    ref: str,
    *,
    max_tlp: str | None,
    now: datetime,
) -> tuple[HuntGuide, list[ReportRef], tuple[str, ...], tuple[SweepEntry, ...]]:
    from .hunt_guides import _evidence

    if ref not in BY_KEY:
        raise LookupError('Hunt guide choice not found')
    when = now.replace(tzinfo=UTC) if now.tzinfo is None else now.astimezone(UTC)
    industry = BY_KEY[ref]
    candidates, removed = _candidates(db, ref, max_tlp)
    labels = ['CLEAR', *(value[2] for value in candidates.values())]
    labels.extend(row.effective_tlp for row in removed)
    selection = _sector_reports(
        db,
        ref,
        tuple(sorted(candidates)),
        days=_DAYS,
        max_tlp=max_tlp,
        now=when,
    )
    labels.extend(selection.labels)
    ordered = sorted(
        candidates,
        key=lambda key: (-selection.by_group[key], candidates[key][0].name.casefold(), key),
    )
    group_lines: list[str] = []
    catalog_techniques: list[str] = []
    for key in ordered[:_GROUP_CAP]:
        subject, claims, _ = candidates[key]
        citations = list(dict.fromkeys(f'{claim.source_name}: {claim.url}' for claim in claims if claim.url))
        group_lines.append(
            f'{_text(subject.name, 100)} ({subject.ref}). Target mapping: '
            + (
                '; '.join(_text(citation, 250) for citation in citations[:3])
                or ', '.join(dict.fromkeys(claim.source_name for claim in claims))
            )
        )
        if subject.catalog:
            catalog_techniques.extend(sorted(subject.catalog.techniques))
    group_lines.append(
        f'Shows {min(_GROUP_CAP, len(candidates))} of {len(candidates)} cited groups. '
        'Recent linked-report counts select the groups shown; this is not a threat or attack ranking. '
        'Reports may link to any group in the full cited sector profile, including groups not shown here.'
    )
    reports = [
        ReportRef(
            item.document_id,
            item.title,
            selection.report_labels[item.document_id],
            item.created_at,
            item.source_name,
            'sector',
            '',
        )
        for item in selection.items[: _REPORT_CAP + 1]
    ]
    used = reports[:_REPORT_CAP]
    report_techniques = db.scalars(
        select(DocumentTechnique.technique_id)
        .where(
            DocumentTechnique.document_id.in_([item.document_id for item in used]),
            DocumentTechnique.status == TAGGED,
        )
        .distinct()
        .order_by(DocumentTechnique.technique_id)
    )
    techniques = tuple(dict.fromkeys((*report_techniques, *catalog_techniques)))
    evidence, evidence_label, sweep = _evidence(db, reports, max_tlp, when)
    labels.append(evidence_label)
    sector_lines = tuple(
        f'{_text(item.title, 180)}. Report: {item.document_id}.'
        for item in used
        if item.document_id in selection.mention_ids
    )
    linked_lines = tuple(
        f'{_text(item.title, 180)}. Report: {item.document_id}.'
        for item in used
        if item.document_id in selection.linked_ids
    )
    limits = [
        f'Report selection covers the last {_DAYS} days by date added to Insight, not attack date. '
        'Future-dated and superseded reports are left out.',
        f'At most the latest {_REPORT_CAP} matching reports are used. A report can match both relevance '
        'routes; it is attached once.',
        'A sector mention shows relevance, not a confirmed attack. A linked group may have targeted '
        'other sectors too. No report or indicator is assigned to an actor by this guide.',
        'Techniques tagged on included reports come first, then catalog techniques of the groups shown. '
        'IDs break ties. A catalog method is not proof of its use against this sector.',
        'Only current reports within your sharing limit are used. Publisher text and private analyst notes '
        'are left out. Open each report for its context and reuse terms.',
        'Indicators must be reviewed and eligible. Known safe, warning-listed and expired-verdict values '
        'are left out. No search or rule has run; no match does not prove safety.',
    ]
    if selection.scan_capped:
        limits.append('Only the latest 500 current reports were scanned. Matching reports may be missing.')
    if selection.capped:
        limits.append('The sector scan retained the first 100 matches before this plan selected its reports.')
    guide = HuntGuide(
        'industry',
        ref,
        f'Threat hunt guide: {industry.name}',
        'A sector-focused plan to adapt to your systems, using saved evidence and cited background.',
        most_restrictive(*labels),
        when.isoformat(),
        (
            GuideSection(
                'Why this hunt matters',
                (
                    industry.covers,
                    'Use the cited groups and recent reports to choose a small set of behaviours to check. '
                    'Start with systems that support your most important services.',
                    'Keep sector mentions separate from explicit group links. '
                    'Neither proves an attack on you.',
                ),
            ),
            GuideSection('Groups known to target this sector', tuple(group_lines)),
            *planning_sections(techniques),
            GuideSection(
                'Reports mentioning this sector',
                sector_lines or ('No included report directly mentions a reviewed sector term.',),
            ),
            GuideSection(
                'Reports linked to sector-targeting groups',
                linked_lines
                or ('No included report has an explicit link to a cited sector-targeting group.',),
            ),
            *evidence,
            GuideSection('Gaps and limits', tuple(limits)),
        ),
    )
    return guide, reports, techniques, sweep
