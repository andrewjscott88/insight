"""YARA and Sigma rules as linked artifacts (TIP 2.7 minimum, for TIP 2.10 threat guides; ADR 0024).

Insight *carries* detection content: it stores the rule text with its source, licence and SHA-256, links it
to groups, ATT&CK techniques or reports, and exports it with threat guides. It never compiles, evaluates or
runs a rule, and the workspace shows rule bodies as plain text. A light shape check catches pasting the wrong
thing; it is not validation (use ``yara`` or ``sigma-cli`` on your own tooling for that).
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Final

from sqlalchemy import delete, or_, select
from sqlalchemy.orm import Session

from ..attack import technique
from ..models import DetectionRule, RuleLink
from ..schemas import RuleInput, RuleLinkInput
from .actors import _check_label, _visible_report, _who, resolve_group
from .audit import audit
from .tlp import visible_levels

_YARA: Final = re.compile(
    r'^\s*(?:(?:private|global)\s+)*rule\s+\w+[^{]*\{.*\bcondition\s*:', re.MULTILINE | re.DOTALL
)
_SIGMA: Final = (re.compile(r'^title\s*:', re.MULTILINE), re.compile(r'^detection\s*:', re.MULTILINE))
MAX_RULES: Final = 500


@dataclass(frozen=True, slots=True)
class LinkedRule:
    rule: DetectionRule
    links: tuple[tuple[str, str], ...]  # (target kind, target ID)


def rule_shape_problem(kind: str, body: str) -> str | None:
    """Why ``body`` does not look like a ``kind`` rule, or ``None``. Not a syntax check."""
    if kind == 'yara' and not _YARA.search(body):
        return 'This does not look like a YARA rule (rule NAME { ... condition: ... }).'
    if kind == 'sigma' and not all(p.search(body) for p in _SIGMA):
        return 'This does not look like a Sigma rule (it needs title: and detection: lines).'
    return None


def content_hash(body: str) -> str:
    return hashlib.sha256(body.replace('\r\n', '\n').encode('utf-8')).hexdigest()


def add_rule(db: Session, payload: RuleInput, *, max_tlp: str | None = None) -> DetectionRule:
    """Store a rule. ``ValueError`` if it does not look like its kind or is already stored. Audited."""
    _check_label(payload.tlp, max_tlp, 'rules')
    if problem := rule_shape_problem(payload.kind, payload.body):
        raise ValueError(problem)
    digest = content_hash(payload.body)
    if db.scalar(select(DetectionRule.id).where(DetectionRule.content_hash == digest)) is not None:
        raise ValueError('This rule is already stored (same text).')
    rule = DetectionRule(
        kind=payload.kind,
        name=payload.name.strip(),
        body=payload.body,
        source_url=payload.source_url,
        licence=payload.licence.strip(),
        content_hash=digest,
        tlp=payload.tlp,
        actor=_who(db),
    )
    db.add(rule)
    db.flush()
    audit(db, 'rule.add', rule.id, f'{rule.kind} {digest[:16]} (TLP:{rule.tlp})')
    return rule


def get_rule(db: Session, rule_id: str, *, max_tlp: str | None = None) -> DetectionRule | None:
    stmt = select(DetectionRule).where(DetectionRule.id == rule_id)
    if max_tlp is not None:
        stmt = stmt.where(DetectionRule.tlp.in_(visible_levels(max_tlp)))
    return db.scalar(stmt)


def rule_links(db: Session, rule_ids: Iterable[str]) -> dict[str, list[tuple[str, str]]]:
    ids = sorted(set(rule_ids))
    found: dict[str, list[tuple[str, str]]] = {i: [] for i in ids}
    if ids:
        stmt = (
            select(RuleLink)
            .where(RuleLink.rule_id.in_(ids))
            .order_by(RuleLink.target_kind, RuleLink.target_id)
        )
        for link in db.scalars(stmt):
            found[link.rule_id].append((link.target_kind, link.target_id))
    return found


def list_rules(db: Session, *, max_tlp: str | None = None, kind: str | None = None) -> list[LinkedRule]:
    """Rules the reader may see, by name, with what each is linked to."""
    stmt = select(DetectionRule).order_by(DetectionRule.name, DetectionRule.id).limit(MAX_RULES)
    if max_tlp is not None:
        stmt = stmt.where(DetectionRule.tlp.in_(visible_levels(max_tlp)))
    if kind is not None:
        stmt = stmt.where(DetectionRule.kind == kind)
    rules = list(db.scalars(stmt))
    links = rule_links(db, (r.id for r in rules))
    return [LinkedRule(r, tuple(links[r.id])) for r in rules]


def delete_rule(db: Session, rule_id: str, *, max_tlp: str | None = None) -> None:
    """Delete a rule and its links (``LookupError`` if the caller cannot see it). Audited."""
    rule = get_rule(db, rule_id, max_tlp=max_tlp)
    if rule is None:
        raise LookupError('Rule not found')
    db.execute(delete(RuleLink).where(RuleLink.rule_id == rule.id))
    audit(db, 'rule.delete', rule.id, f'{rule.kind} {rule.content_hash[:16]}')
    db.delete(rule)


def _target(db: Session, payload: RuleLinkInput, max_tlp: str | None) -> str:
    """The canonical ID of a link target the caller may see (``LookupError``/``ValueError`` otherwise)."""
    if payload.target_kind == 'technique':
        found = technique(payload.target_id)
        if found is None:
            raise ValueError('Not a current ATT&CK technique ID (for example T1059 or T1059.001)')
        return found.id
    if payload.target_kind == 'group':
        return resolve_group(db, payload.target_id, max_tlp=max_tlp).ref
    return _visible_report(db, payload.target_id, max_tlp).id


def link_rule(db: Session, rule_id: str, payload: RuleLinkInput, *, max_tlp: str | None = None) -> RuleLink:
    """Link a rule to a group, technique or report (idempotent). Audited as ``rule.link``."""
    rule = get_rule(db, rule_id, max_tlp=max_tlp)
    if rule is None:
        raise LookupError('Rule not found')
    target = _target(db, payload, max_tlp)
    row = db.scalar(
        select(RuleLink).where(
            RuleLink.rule_id == rule.id,
            RuleLink.target_kind == payload.target_kind,
            RuleLink.target_id == target,
        )
    )
    if row is None:
        row = RuleLink(rule_id=rule.id, target_kind=payload.target_kind, target_id=target, actor=_who(db))
        db.add(row)
        db.flush()
        audit(db, 'rule.link', rule.id, f'{payload.target_kind} {target}')
    return row


def unlink_rule(db: Session, rule_id: str, payload: RuleLinkInput, *, max_tlp: str | None = None) -> None:
    rule = get_rule(db, rule_id, max_tlp=max_tlp)
    if rule is None:
        raise LookupError('Rule not found')
    target = _target(db, payload, max_tlp)
    result = db.execute(
        delete(RuleLink).where(
            RuleLink.rule_id == rule.id,
            RuleLink.target_kind == payload.target_kind,
            RuleLink.target_id == target,
        )
    )
    if not getattr(result, 'rowcount', 0):
        raise LookupError('That rule is not linked there')
    audit(db, 'rule.unlink', rule.id, f'{payload.target_kind} {target}')


def rules_for_group(
    db: Session, group_ref: str, techniques: Iterable[str], *, max_tlp: str | None = None
) -> list[LinkedRule]:
    """Rules linked to the group or to any of ``techniques`` that the reader may see, by name."""
    ids = sorted(set(techniques))
    conditions = [(RuleLink.target_kind == 'group') & (RuleLink.target_id == group_ref)]
    conditions.extend(
        (RuleLink.target_kind == 'technique') & RuleLink.target_id.in_(ids[start : start + 500])
        for start in range(0, len(ids), 500)
    )
    linked = select(RuleLink.rule_id).where(or_(*conditions))
    stmt = (
        select(DetectionRule)
        .where(DetectionRule.id.in_(linked))
        .order_by(DetectionRule.name, DetectionRule.id)
    )
    if max_tlp is not None:
        stmt = stmt.where(DetectionRule.tlp.in_(visible_levels(max_tlp)))
    rules = list(db.scalars(stmt.limit(MAX_RULES)))
    links = rule_links(db, (r.id for r in rules))
    return [LinkedRule(r, tuple(links[r.id])) for r in rules]
