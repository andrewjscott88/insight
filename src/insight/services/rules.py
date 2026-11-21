"""YARA and Sigma rules as linked artifacts (TIP 2.7 minimum, for TIP 2.10 threat guides; ADR 0025).

Insight *carries* detection content: it stores the rule text with its source, licence and SHA-256, links it
to groups, ATT&CK techniques or reports, and exports it with threat guides. It never compiles, evaluates or
runs a rule, and the workspace shows rule bodies as plain text. A light shape check catches pasting the wrong
thing; it is not validation (use ``yara`` or ``sigma-cli`` on your own tooling for that).
"""

from __future__ import annotations

import hashlib
import io
import json
import re
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Final
from zipfile import ZIP_DEFLATED, ZipFile

from sqlalchemy import delete, or_, select
from sqlalchemy.dialects import postgresql, sqlite
from sqlalchemy.orm import Session

from ..attack import technique
from ..extraction import canonical
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


def _rule_bytes(body: str) -> bytes:
    return body.replace('\r\n', '\n').encode('utf-8')


def content_hash(body: str) -> str:
    return hashlib.sha256(_rule_bytes(body)).hexdigest()


def export_rule(db: Session, rule_id: str, *, max_tlp: str | None) -> bytes:
    """Package a visible rule with its handling information and audit the download."""
    rule = get_rule(db, rule_id, max_tlp=max_tlp)
    if rule is None:
        raise LookupError('Rule not found')
    filename = 'rule.yar' if rule.kind == 'yara' else 'rule.yml'
    manifest = {
        'id': rule.id,
        'name': rule.name,
        'kind': rule.kind,
        'file': filename,
        'sha256': rule.content_hash,
        'tlp': rule.tlp,
        'licence': rule.licence,
        'source_url': rule.source_url,
    }
    buffer = io.BytesIO()
    with ZipFile(buffer, 'w', compression=ZIP_DEFLATED) as archive:
        archive.writestr(filename, _rule_bytes(rule.body))
        archive.writestr('manifest.json', json.dumps(manifest, indent=2, ensure_ascii=False) + '\n')
    audit(db, 'rule.export', rule.id, f'{rule.kind} {rule.content_hash[:16]} (TLP:{rule.tlp})')
    return buffer.getvalue()


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


def list_rules(
    db: Session, *, max_tlp: str | None = None, kind: str | None = None, target: RuleLinkInput | None = None
) -> list[LinkedRule]:
    """Rules the reader may see, by name, with what each is linked to."""
    stmt = select(DetectionRule).order_by(DetectionRule.name, DetectionRule.id).limit(MAX_RULES)
    if max_tlp is not None:
        stmt = stmt.where(DetectionRule.tlp.in_(visible_levels(max_tlp)))
    if kind is not None:
        stmt = stmt.where(DetectionRule.kind == kind)
    if target is not None:
        target_id = _target(db, target, max_tlp)
        stmt = stmt.where(
            DetectionRule.id.in_(
                select(RuleLink.rule_id).where(
                    RuleLink.target_kind == target.target_kind, RuleLink.target_id == target_id
                )
            )
        )
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
    if payload.target_kind == 'cve':
        return canonical('cve', payload.target_id.strip())
    if payload.target_kind == 'malware':
        label = re.sub(' +', ' ', payload.target_id.strip().lower())
        if not re.fullmatch(r'[a-z0-9][a-z0-9 ._-]{0,35}', label):
            raise ValueError(
                'Use up to 36 letters, digits, spaces, dots, underscores or hyphens for the family'
            )
        return label
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
    match = select(RuleLink).where(
        RuleLink.rule_id == rule.id, RuleLink.target_kind == payload.target_kind, RuleLink.target_id == target
    )
    insert = sqlite.insert if db.get_bind().dialect.name == 'sqlite' else postgresql.insert
    inserted = db.scalar(
        insert(RuleLink)
        .values(rule_id=rule.id, target_kind=payload.target_kind, target_id=target, actor=_who(db))
        .on_conflict_do_nothing(index_elements=['rule_id', 'target_kind', 'target_id'])
        .returning(RuleLink.id)
    )
    if inserted is not None:
        audit(db, 'rule.link', rule.id, f'{payload.target_kind} {target}')
    return db.scalars(match).one()


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
    db: Session,
    group_ref: str,
    techniques: Iterable[str],
    *,
    reports: Iterable[str] = (),
    max_tlp: str | None = None,
) -> list[LinkedRule]:
    """Rules linked to the group or to any of ``techniques`` that the reader may see, by name."""
    ids = sorted(set(techniques))
    conditions = [(RuleLink.target_kind == 'group') & (RuleLink.target_id == group_ref)]
    conditions.extend(
        (RuleLink.target_kind == 'technique') & RuleLink.target_id.in_(ids[start : start + 500])
        for start in range(0, len(ids), 500)
    )
    report_ids = sorted(set(reports))
    conditions.extend(
        (RuleLink.target_kind == 'document') & RuleLink.target_id.in_(report_ids[start : start + 500])
        for start in range(0, len(report_ids), 500)
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
