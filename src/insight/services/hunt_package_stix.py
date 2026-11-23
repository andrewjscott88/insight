"""Hunt packages as STIX 2.1 (TIP 4.3, ADR 0034), for the *Hunt packages* TAXII collection and downloads.

One package is one ``grouping`` (context ``suspicious-activity``) whose description is the hypothesis. It
refers to an ``attack-pattern`` per ATT&CK technique, an ``indicator`` (or ``vulnerability`` for a CVE) per
indicator, and an ``indicator`` per detection rule, with the rule text as its pattern and the rule language as
its ``pattern_type`` (``sigma``, ``yara``, ``suricata`` or ``snort``). A rule linked to one of the package's
techniques ``indicates`` it. The threat group and the reports are external references: they are context, and a
report's own text never leaves in a package.

Every object carries the package's TLP marking and its ``modified`` time, so any change reaches a polling
client as a new version. IDs are derived from the package, its publication and the item, so removing and
adding an item again gives a new object. A retired package's objects are served once more as revoked.
"""

from __future__ import annotations

import json
from typing import Any, Final
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..attack import DOMAINS, catalog, technique
from ..models import DetectionRule, Document, Entity, HuntPackage, HuntPackageItem, RuleLink
from ..stix_export import TLP_MARKINGS, _pattern, stable_id, stix_timestamp, tlp_marking
from ..stix_validation import validate_stix_bundle
from .actors import is_catalog_ref, resolve_group
from .audit import audit
from .hunt_package_views import _package
from .tlp import tlp_permitted, visible_levels

#: A TAXII snapshot is built per request; a larger collection is refused rather than cut short.
MAX_SERVED_HUNT_PACKAGES: Final = 500
_RULE_LANGUAGES: Final = {'yara': 'YARA', 'sigma': 'Sigma', 'suricata': 'Suricata', 'snort': 'Snort'}


def _object_id(row: HuntPackage, object_type: str, *parts: str) -> str:
    return stable_id(object_type, 'insight-hunt-package', '|'.join((row.id, str(row.publication), *parts)))


def _common(row: HuntPackage, object_type: str, object_id: str, created: str) -> dict[str, Any]:
    modified = stix_timestamp(row.updated_at)
    obj: dict[str, Any] = {
        'type': object_type,
        'spec_version': '2.1',
        'id': object_id,
        'created': min(created, modified),
        'modified': modified,
        'object_marking_refs': [TLP_MARKINGS[row.tlp]],
    }
    if row.status == 'retired':
        obj['revoked'] = True
    return obj


def _technique(row: HuntPackage, item: HuntPackageItem) -> dict[str, Any] | None:
    found = technique(item.technique_id or '')
    if found is None:  # retired from the catalog since it was added
        return None
    source = catalog(found.domain)
    obj = _common(row, 'attack-pattern', _object_id(row, 'attack-pattern', item.id, source.version),
                  stix_timestamp(item.added_at))  # fmt: skip
    obj['name'] = found.full_name
    obj['external_references'] = [
        {'source_name': 'mitre-attack', 'external_id': found.id, 'url': found.url},
        {
            'source_name': f'MITRE ATT&CK {DOMAINS[found.domain]} {source.version}',
            'description': source.notice,
            'url': source.terms,
        },
    ]
    if found.tactics:
        obj['kill_chain_phases'] = [
            {'kill_chain_name': found.kill_chain, 'phase_name': tactic} for tactic in found.tactics
        ]
    return obj


def _indicator(row: HuntPackage, item: HuntPackageItem, entity: Entity) -> dict[str, Any]:
    created = stix_timestamp(item.added_at)
    if entity.kind == 'cve':
        obj = _common(row, 'vulnerability', _object_id(row, 'vulnerability', item.id), created)
        obj.update(
            name=entity.value, external_references=[{'source_name': 'cve', 'external_id': entity.value}]
        )
        return obj
    obj = _common(row, 'indicator', _object_id(row, 'indicator', item.id), created)
    obj.update(
        name=entity.value,
        pattern_type='stix',
        pattern_version='2.1',
        pattern=_pattern(entity.kind, entity.value),
        valid_from=obj['created'],
    )
    return obj


def _rule(row: HuntPackage, item: HuntPackageItem, rule: DetectionRule) -> dict[str, Any]:
    obj = _common(row, 'indicator', _object_id(row, 'indicator', item.id), stix_timestamp(item.added_at))
    licence = rule.licence or 'not given'
    obj.update(
        name=rule.name,
        description=f'{_RULE_LANGUAGES[rule.kind]} rule. Licence: {licence}. SHA-256: {rule.content_hash}.',
        pattern_type=rule.kind,
        pattern=rule.body,
        valid_from=stix_timestamp(rule.created_at),
        external_references=[{'source_name': 'Insight rule', 'external_id': rule.id}],
    )
    if rule.source_url:
        obj['external_references'].append({'source_name': 'rule source', 'url': rule.source_url})
    return obj


def _context(db: Session, row: HuntPackage, documents: list[Document]) -> list[dict[str, Any]]:
    """External references for the grouping: the package itself, its group, and the reports behind it."""
    refs: list[dict[str, Any]] = [{'source_name': 'Insight hunt package', 'external_id': row.id}]
    if row.group_ref:
        try:  # never name an actor whose label is now stricter than the package's
            subject = resolve_group(db, row.group_ref, max_tlp=row.tlp)
        except LookupError:  # an analyst actor deleted or relabelled since
            subject = None
        if subject is not None and is_catalog_ref(subject.ref) and subject.catalog is not None:
            refs.append({'source_name': 'mitre-attack', 'external_id': subject.ref,
                         'url': subject.catalog.url, 'description': subject.name})  # fmt: skip
        elif subject is not None:
            refs.append(
                {'source_name': 'Insight actor', 'external_id': subject.ref, 'description': subject.name}
            )
    for doc in documents:
        if not tlp_permitted(doc.tlp, row.tlp):
            continue
        ref = {'source_name': doc.source_name, 'external_id': doc.id, 'description': doc.title}
        if doc.source_url:
            ref['url'] = doc.source_url
        refs.append(ref)
    return refs


def _package_objects(db: Session, row: HuntPackage) -> list[dict[str, Any]]:
    """The package's SDOs and relationships (no marking definitions); empty if nothing huntable is left."""
    items = list(
        db.scalars(
            select(HuntPackageItem)
            .where(HuntPackageItem.package_id == row.id)
            .order_by(HuntPackageItem.kind, HuntPackageItem.added_at, HuntPackageItem.id)
        )
    )

    def rows(model: type[Any], kind: str) -> dict[str, Any]:
        ids = [i.entity_id or i.rule_id or i.document_id for i in items if i.kind == kind]
        return {r.id: r for r in db.scalars(select(model).where(model.id.in_(ids)))} if ids else {}

    entities, rules, documents = (
        rows(Entity, 'indicator'),
        rows(DetectionRule, 'rule'),
        rows(Document, 'document'),
    )
    objects: list[dict[str, Any]] = []
    techniques: dict[str, dict[str, Any]] = {}
    rule_objects: dict[str, dict[str, Any]] = {}
    for item in items:
        obj: dict[str, Any] | None = None
        if item.kind == 'technique':
            obj = _technique(row, item)
            if obj is not None:
                techniques[item.technique_id or ''] = obj
        elif item.kind == 'indicator' and item.entity_id in entities:
            obj = _indicator(row, item, entities[item.entity_id])
        elif item.kind == 'rule' and item.rule_id in rules:
            obj = _rule(row, item, rules[item.rule_id])
            rule_objects[item.rule_id] = obj
        if obj is not None:
            objects.append(obj)
    if not objects:
        return []
    if rule_objects and techniques:
        links = db.execute(
            select(RuleLink.rule_id, RuleLink.target_id)
            .where(RuleLink.rule_id.in_(sorted(rule_objects)), RuleLink.target_kind == 'technique')
            .order_by(RuleLink.rule_id, RuleLink.target_id)
        )
        for rule_id, technique_id in links:
            if technique_id not in techniques:
                continue
            source, target = rule_objects[rule_id], techniques[technique_id]
            relationship = _common(row, 'relationship',
                                   _object_id(row, 'relationship', source['id'], target['id']),
                                   max(source['created'], target['created']))  # fmt: skip
            relationship.update(
                relationship_type='indicates', source_ref=source['id'], target_ref=target['id']
            )
            objects.append(relationship)
    grouping = _common(row, 'grouping', _object_id(row, 'grouping'), stix_timestamp(row.created_at))
    grouping.update(
        name=row.title,
        description=row.hypothesis,
        context='suspicious-activity',
        object_refs=[obj['id'] for obj in objects],
        external_references=_context(db, row, [documents[d] for d in sorted(documents)]),
    )
    return [grouping, *objects]


def _hunt_package_bundle(db: Session, max_tlp: str | None) -> dict[str, Any]:
    """Every package a hunt tool should know about: published ones, and retired ones that were published."""
    served = list(
        db.scalars(
            select(HuntPackage)
            .where(
                HuntPackage.tlp.in_(visible_levels(max_tlp)),
                HuntPackage.published_at.is_not(None),
                HuntPackage.status.in_(('published', 'retired')),
            )
            .order_by(HuntPackage.id)
            .limit(MAX_SERVED_HUNT_PACKAGES + 1)
        )
    )
    if len(served) > MAX_SERVED_HUNT_PACKAGES:
        raise ValueError(
            f'More than {MAX_SERVED_HUNT_PACKAGES} hunt packages to serve; retire and delete some.'
        )
    bundle: dict[str, Any] = {
        'type': 'bundle',
        'id': stable_id('bundle', 'insight-hunt-package', 'collection'),
    }
    objects: list[dict[str, Any]] = []
    labels: set[str] = set()
    for row in served:
        if found := _package_objects(db, row):
            objects.extend(found)
            labels.add(row.tlp)
    if objects:
        bundle['objects'] = [tlp_marking(label) for label in TLP_MARKINGS if label in labels] + objects
    return bundle


def export_hunt_package(db: Session, package_id: str, *, max_tlp: str | None = None) -> dict[str, Any]:
    """One package as a validated STIX 2.1 bundle, in any status (a draft can be checked before it is
    published). ``LookupError`` if hidden; ``ValueError`` if nothing huntable is in it. Audited."""
    row = _package(db, package_id, max_tlp)
    objects = _package_objects(db, row)
    if not objects:
        raise ValueError('Add at least one ATT&CK technique, indicator or rule first.')
    bundle = {'type': 'bundle', 'id': f'bundle--{uuid4()}', 'objects': [tlp_marking(row.tlp), *objects]}
    validate_stix_bundle(bundle)
    detail = {'objects': len(objects), 'status': row.status, 'tlp': row.tlp, 'max_tlp': max_tlp}
    audit(db, 'hunt_package.export', row.id, json.dumps(detail, sort_keys=True))
    return bundle
