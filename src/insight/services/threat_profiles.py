"""Industry threat profiles and the data behind actor threat guides (TIP 2.10, ADR 0025).

* **Which groups target an industry**: only groups a cited source names for it (the threat library's
  ATT&CK and MISP galaxy claims, and the analyst's own mappings with their citations), less the catalog
  claims the analyst removed. A group no source names for the industry is never listed.
* **Ranked, never scored**: by how many of the reader's current reports name the group in the last
  ``days`` days, then the most recent publicly reported activity (the newest ATT&CK campaign attributed to
  it), then how many ATT&CK techniques it has. Every entry carries the reasons for its place.
* **"Named in your reports"** is a literal match of the group's names and aliases, like a watch term. It
  says a report *mentions* the group, nothing more; Insight never attributes activity from shared indicators.

Every read takes ``max_tlp``; counts and titles come only from reports the reader may see.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Final

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..industries import BY_KEY, Industry
from ..models import Document, IndustryClaim
from ..schemas import most_restrictive
from ..threat_library import Campaign, Claim, library
from .actors import GroupSubject, analyst_claims, list_actors, resolve_group
from .common import stamp
from .tlp import _visible

TOP: Final = 10
PROFILE_DAYS: Final = 90
#: Newest reports read when counting mentions; the profile says when the limit was reached.
MAX_SCANNED: Final = 5_000
MIN_NAME: Final = 3
EVIDENCE_CONTEXT: Final = 80
_ONE_WORD: Final = re.compile(r'[A-Za-z]+')


@dataclass(frozen=True, slots=True)
class Mention:
    """A report that names a group (the first name found in it), with the text around it."""

    document_id: str
    title: str
    tlp: str
    created_at: str
    source_name: str
    name: str
    evidence: str


@dataclass(frozen=True, slots=True)
class ProfileEntry:
    subject: GroupSubject
    claims: tuple[Claim, ...]
    mentions: int
    last_mention: str | None
    last_activity: Campaign | None
    techniques: int
    reasons: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class IndustryProfile:
    industry: Industry
    entries: tuple[ProfileEntry, ...]
    candidates: int  # groups a source names for the industry, before the top ten
    removed: tuple[IndustryClaim, ...]  # catalog claims the analyst removed, still visible as decisions
    days: int
    scanned: int
    capped: bool
    tlp: str


def case_sensitive(name: str) -> bool:
    """One plain word (``Tick``, ``PLATINUM``) is matched as written: such words are often ordinary text."""
    return bool(_ONE_WORD.fullmatch(name))


def _index(
    names_by_ref: Mapping[str, Iterable[str]],
) -> tuple[re.Pattern[str] | None, dict[str, list[tuple[str, str]]]]:
    index: dict[str, list[tuple[str, str]]] = {}
    for ref, names in names_by_ref.items():
        for name in {n.strip() for n in names if len(n.strip()) >= MIN_NAME}:
            index.setdefault(name.casefold(), []).append((ref, name))
    if not index:
        return None, index
    alternatives = sorted((re.escape(k) for k in index), key=len, reverse=True)
    return re.compile(r'(?<![\w-])(' + '|'.join(alternatives) + r')(?![\w-])', re.IGNORECASE), index


def find_mentions(
    db: Session,
    names_by_ref: Mapping[str, Iterable[str]],
    *,
    max_tlp: str | None = None,
    since: str | None = None,
    limit: int = MAX_SCANNED,
) -> tuple[dict[str, list[Mention]], int]:
    """Current reports the reader may see that name each group, newest first, and how many were read."""
    pattern, index = _index(names_by_ref)
    found: dict[str, list[Mention]] = {ref: [] for ref in names_by_ref}
    if pattern is None:
        return found, 0
    conditions = [Document.is_current.is_(True), *_visible(max_tlp)]
    if since:
        conditions.append(Document.created_at >= since)
    stmt = (
        select(
            Document.id,
            Document.title,
            Document.tlp,
            Document.created_at,
            Document.source_name,
            Document.body,
        )
        .where(*conditions)
        .order_by(Document.created_at.desc(), Document.id)
        .limit(limit)
    )
    scanned = 0
    for doc_id, title, tlp, created_at, source_name, body in db.execute(stmt):
        scanned += 1
        text = f'{title}\n{body}'
        seen: set[str] = set()
        for match in pattern.finditer(text):
            written = match.group(1)
            for ref, name in index.get(written.casefold(), []):
                if ref in seen or (case_sensitive(name) and written != name):
                    continue
                seen.add(ref)
                start, end = match.span(1)
                evidence = ' '.join(text[max(0, start - EVIDENCE_CONTEXT) : end + EVIDENCE_CONTEXT].split())
                found[ref].append(Mention(doc_id, title, tlp, created_at, source_name, name, evidence))
    return found, scanned


def analyst_claim_view(row: IndustryClaim) -> Claim:
    """An analyst's added mapping in the same shape as a catalog claim, with its citation."""
    url = row.citation_url or (f'/?report={row.document_id}' if row.document_id else '')
    words = f'Added by {row.actor or "the analyst"} on {row.created_at[:10]}.'
    return Claim((row.industry,), 'analyst', f'{words} {row.reason}'.strip(), url)


def _candidates(
    db: Session, industry: str, max_tlp: str | None
) -> tuple[dict[str, tuple[GroupSubject, list[Claim], str]], list[IndustryClaim]]:
    """``{ref: (subject, claims, TLP of what was used)}`` for every group a source names for ``industry``."""
    decisions = {row.group_ref: row for row in analyst_claims(db, max_tlp=max_tlp, industry=industry)}
    removed = [row for row in decisions.values() if row.decision == 'removed']
    out: dict[str, tuple[GroupSubject, list[Claim], str]] = {}
    for group in library().groups_for(industry):
        decision = decisions.get(group.id)
        if decision is not None and decision.decision == 'removed':
            continue
        subject = resolve_group(db, group.id)
        out[group.id] = (subject, list(group.claims_for(industry)), 'CLEAR')
    actors = {a.id for a in list_actors(db, max_tlp=max_tlp)}
    for ref, row in decisions.items():
        if row.decision != 'added' or (ref not in actors and library().group(ref) is None):
            continue
        subject = resolve_group(db, ref, max_tlp=max_tlp)
        subject_claims, label = out.get(ref, (subject, [], 'CLEAR'))[1:]
        out[ref] = (
            subject,
            [*subject_claims, analyst_claim_view(row)],
            most_restrictive(label, row.tlp, subject.tlp),
        )
    return out, removed


def _reasons(
    entry_claims: list[Claim], mentions: list[Mention], days: int, subject: GroupSubject
) -> tuple[str, ...]:
    reasons = [f'{c.source_name}: {c.evidence}' for c in entry_claims]
    if mentions:
        reasons.append(
            f'Named in {len(mentions)} of your reports in the last {days} days, '
            f'last on {mentions[0].created_at[:10]}.'
        )
    activity = subject.catalog.last_activity if subject.catalog else None
    if activity is not None:
        reasons.append(f'Latest public activity in ATT&CK: {activity.name}, last seen {activity.last_seen}.')
    if subject.catalog is not None:
        reasons.append(f'ATT&CK lists {len(subject.catalog.techniques)} techniques for it.')
    return tuple(reasons)


def industry_profile(
    db: Session,
    industry: str,
    *,
    max_tlp: str | None = None,
    now: datetime,
    days: int = PROFILE_DAYS,
    top: int = TOP,
) -> IndustryProfile:
    """The top ``top`` groups that cited sources name for ``industry`` (``LookupError`` if unknown)."""
    if industry not in BY_KEY:
        raise LookupError(f'Unknown industry: {industry}')
    candidates, removed = _candidates(db, industry, max_tlp)
    since = stamp(now - timedelta(days=days))
    mentions, scanned = find_mentions(
        db, {ref: subject.names for ref, (subject, _, _) in candidates.items()}, max_tlp=max_tlp, since=since
    )
    entries = []
    for ref, (subject, claims, _) in candidates.items():
        named = mentions.get(ref, [])
        entries.append(
            ProfileEntry(
                subject=subject,
                claims=tuple(claims),
                mentions=len(named),
                last_mention=named[0].created_at if named else None,
                last_activity=subject.catalog.last_activity if subject.catalog else None,
                techniques=len(subject.catalog.techniques) if subject.catalog else 0,
                reasons=_reasons(claims, named, days, subject),
            )
        )
    # Mentions, then latest public activity, then technique count (each largest first), then name.
    entries.sort(key=lambda e: e.subject.name.casefold())
    entries.sort(
        key=lambda e: (e.last_activity.last_seen if e.last_activity else '', e.techniques), reverse=True
    )
    entries.sort(key=lambda e: -e.mentions)
    chosen = tuple(entries[: max(1, min(top, TOP))])
    labels = ['CLEAR']
    for entry in chosen:
        labels.append(candidates[entry.subject.ref][2])
        labels += [m.tlp for m in mentions.get(entry.subject.ref, [])]
    labels += [row.tlp for row in removed]
    return IndustryProfile(
        industry=BY_KEY[industry],
        entries=chosen,
        candidates=len(candidates),
        removed=tuple(removed),
        days=days,
        scanned=scanned,
        capped=scanned >= MAX_SCANNED,
        tlp=most_restrictive(*labels),
    )


def industry_counts(db: Session, *, max_tlp: str | None = None) -> dict[str, int]:
    """How many groups a source names for each industry, after the analyst's own decisions."""
    return {key: len(_candidates(db, key, max_tlp)[0]) for key in BY_KEY}
