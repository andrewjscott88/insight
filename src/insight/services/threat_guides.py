"""The analyst's data in an actor threat guide (TIP 2.10, ADR 0025): reports, sweep list, rules and hunts.

:func:`guide_data` gathers, for one group and one reader, everything in the guide that comes from this
instance; :mod:`insight.threat_guide` turns it and the threat library into the guide and its exports.

The **indicator sweep list** holds accepted indicators from reports the analyst *linked* to the group. Only
when asked (``linked_only=False``) does it also take them from reports that merely *name* the group; those
reports are always listed in the guide, but by default their indicators stay out of the sweep list (ADR 0025).
It is a list of things to search for in your own logs,
not a statement that the group used them: Insight never attributes from co-occurrence. Indicators with a
warning flag, a ``benign`` verdict or a verdict whose own ``valid_until`` has passed are left out. The
blocklist's default lifetimes are not applied (a sweep looks back), so each entry carries when it was seen.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Final

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..flags import flags
from ..models import Document, DocumentTechnique, Entity, Hunt, Observation
from ..schemas import most_restrictive
from .actor_reports import ReportRef as ReportRef
from .actor_reports import _guide_reports
from .actor_timeline import ActorTimeline, actor_timeline
from .actors import GroupSubject, analyst_claims, resolve_group
from .assessments import _expires_at, visible_assessments
from .campaigns import list_threat_links
from .common import stamp
from .hunts import hunt_checks, hunts_for
from .rules import LinkedRule, rules_for_group
from .techniques import TAGGED, technique_labels, technique_summary
from .threat_profiles import PROFILE_DAYS
from .tlp import _visible

SWEEP_KINDS: Final = ('ip', 'domain', 'url', 'md5', 'sha1', 'sha256', 'sha512')
MAX_SWEEP_REPORTS: Final = 200
MAX_SWEEP: Final = 5_000


@dataclass(frozen=True, slots=True)
class SweepEntry:
    kind: str
    value: str
    verdict: str  # 'unknown' when there is none the reader may see
    verdict_until: str | None
    first_seen: str
    last_seen: str
    reports: tuple[str, ...]  # report IDs
    via: str  # 'linked' when any report is linked to the group, else 'named'
    tlp: str  # most restrictive label of the reports it came from


@dataclass(frozen=True, slots=True)
class HuntView:
    hunt: Hunt
    checks: dict[str, tuple[str, str, str, str, str]]  # technique -> (result, data, start, end, notes)


@dataclass(frozen=True, slots=True)
class GuideData:
    subject: GroupSubject
    added: tuple[tuple[str, str, str, str], ...]  # (industry, citation URL or report link, reason, TLP)
    removed: tuple[tuple[str, str, str], ...]  # (industry, reason, TLP)
    reports: tuple[ReportRef, ...]
    named_total: int
    report_techniques: dict[str, int]  # techniques tagged on linked reports: number of those reports
    trending: dict[str, int]  # techniques on all the reader's reports in the last PROFILE_DAYS days
    sweep: tuple[SweepEntry, ...]
    sweep_truncated: bool
    rules: tuple[LinkedRule, ...]
    hunts: tuple[HuntView, ...]
    generated: str
    max_tlp: str | None
    labels: tuple[str, ...] = field(default=())  # every TLP label of what went in
    sweep_linked_only: bool = True  # False: the sweep list also has indicators from reports naming the group
    timeline: ActorTimeline | None = None
    linked_software: tuple[str, ...] = ()  # explicit analyst actor/software decisions, Navigator context only

    @property
    def tlp(self) -> str:
        """The guide's label: at least as restrictive as everything in it, sweep rows included."""
        return most_restrictive(
            'CLEAR',
            self.subject.tlp,
            *self.labels,
            *(e.tlp for e in self.sweep),
            self.timeline.tlp if self.timeline else 'CLEAR',
        )


def _report_techniques(db: Session, document_ids: list[str]) -> dict[str, int]:
    if not document_ids:
        return {}
    stmt = select(DocumentTechnique.technique_id, DocumentTechnique.document_id).where(
        DocumentTechnique.document_id.in_(document_ids[:MAX_SWEEP_REPORTS]),
        DocumentTechnique.status == TAGGED,
    )
    return dict(Counter(t for t, _ in set(db.execute(stmt))))


def sweep_list(
    db: Session,
    reports: list[ReportRef],
    *,
    max_tlp: str | None = None,
    now: datetime,
    apply_default_lifetimes: bool = False,
) -> tuple[list[SweepEntry], bool]:
    """Eligible indicators; current hunt plans may also apply the verdict's default lifetime.

    Legacy actor sweep exports look back and retain their explicit-expiry-only policy by default.
    """
    by_id = {r.document_id: r for r in reports[:MAX_SWEEP_REPORTS]}
    if not by_id:
        return [], False
    stmt = (
        select(Entity.id, Entity.kind, Entity.value, Observation.document_id)
        .join(Observation, Observation.entity_id == Entity.id)
        .join(Document, Document.id == Observation.document_id)
        .where(
            Observation.document_id.in_(list(by_id)),
            Observation.review_status == 'accepted',
            Entity.kind.in_(SWEEP_KINDS),
            *_visible(max_tlp),
        )
    )
    found: dict[str, tuple[str, str, set[str]]] = {}
    for entity_id, kind, value, doc_id in db.execute(stmt):
        found.setdefault(entity_id, (kind, value, set()))[2].add(doc_id)
    verdicts = visible_assessments(db, found, max_tlp=max_tlp)
    today = stamp(now)
    entries = []
    for entity_id, (kind, value, doc_ids) in found.items():
        verdict = verdicts.get(entity_id)
        if flags(kind, value) or (verdict is not None and verdict.verdict == 'benign'):
            continue
        expires = (
            (_expires_at(kind, verdict) if apply_default_lifetimes else verdict.valid_until)
            if verdict is not None
            else None
        )
        if expires is not None and expires <= today:
            continue
        docs = sorted((by_id[d] for d in doc_ids), key=lambda r: r.created_at)
        entries.append(
            SweepEntry(
                kind=kind,
                value=value,
                verdict=verdict.verdict if verdict else 'unknown',
                verdict_until=expires,
                first_seen=docs[0].created_at,
                last_seen=docs[-1].created_at,
                reports=tuple(d.document_id for d in docs),
                via='linked' if any(d.via == 'linked' for d in docs) else 'named',
                tlp=most_restrictive(*(d.tlp for d in docs), *([verdict.tlp] if verdict else [])),
            )
        )
    entries.sort(key=lambda e: (e.last_seen, e.kind, e.value), reverse=True)
    return entries[:MAX_SWEEP], len(entries) > MAX_SWEEP


def guide_data(
    db: Session, ref: str, *, max_tlp: str | None = None, now: datetime, linked_only: bool = True
) -> GuideData:
    """Everything from this instance that goes into ``ref``'s guide for this reader (``LookupError``).

    The guide always lists reports that name the group; ``linked_only=False`` also puts their indicators in
    the sweep list (an explicit opt-in: naming a group is not attributing anything to it).
    """
    subject = resolve_group(db, ref, max_tlp=max_tlp)
    software_links = [
        link
        for link in (
            list_threat_links(db, 'actor', subject.ref, max_tlp=max_tlp, limit=200)
            if subject.kind == 'analyst'
            else []
        )
        if str(link.target_kind) == 'software'
    ]
    claims = analyst_claims(db, max_tlp=max_tlp, group_ref=subject.ref)
    reports, mentions, _ = _guide_reports(db, subject, max_tlp)
    linked_ids = [r.document_id for r in reports if r.via == 'linked']
    report_techniques = _report_techniques(db, linked_ids)
    techniques = {*report_techniques, *(subject.catalog.techniques if subject.catalog else ())}
    since = stamp(now - timedelta(days=PROFILE_DAYS))
    trending = {
        c.technique_id: c.reports
        for c in technique_summary(db, max_tlp=max_tlp, since=since)
        if c.technique_id in techniques
    }
    swept = [r for r in reports if r.via == 'linked'] if linked_only else reports
    sweep, truncated = sweep_list(db, swept, max_tlp=max_tlp, now=now)
    rules = rules_for_group(db, subject.ref, techniques, reports=linked_ids, max_tlp=max_tlp)
    hunts = tuple(HuntView(h, hunt_checks(db, h.id)) for h in hunts_for(db, subject.ref, max_tlp=max_tlp))
    # Every label of what the guide shows or counts: the banner is never less restrictive than its content.
    labels = (
        [c.effective_tlp for c in claims]
        + [r.tlp for r in reports]
        + [m.tlp for m in mentions]  # named_total counts them all, not only the MAX_NAMED listed
        + sorted(technique_labels(db, trending, max_tlp=max_tlp, since=since))  # the "recent reports" counts
        + [e.tlp for e in sweep]  # a verdict's label can be stricter than its reports'
        + [r.tlp for r in rules]
        + [h.hunt.effective_tlp for h in hunts]
        + [link.tlp for link in software_links]
    )
    return GuideData(
        subject=subject,
        added=tuple(
            (
                c.industry,
                c.citation_url or (f'/?report={c.document_id}' if c.document_id else ''),
                c.reason,
                c.effective_tlp,
            )
            for c in claims
            if c.decision == 'added'
        ),
        removed=tuple((c.industry, c.reason, c.effective_tlp) for c in claims if c.decision == 'removed'),
        reports=tuple(reports),
        named_total=len(mentions),
        report_techniques=report_techniques,
        trending=trending,
        sweep=tuple(sweep),
        sweep_truncated=truncated,
        rules=tuple(rules),
        hunts=hunts,
        generated=stamp(now),
        max_tlp=max_tlp,
        labels=tuple(labels),
        sweep_linked_only=linked_only,
        timeline=actor_timeline(db, subject.ref, max_tlp=max_tlp, now=now),
        linked_software=tuple(link.target_id for link in software_links),
    )
