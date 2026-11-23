"""Explicitly save a rebuilt hunt guide and its structured evidence as a draft package."""

from __future__ import annotations

import json
from datetime import UTC, datetime

from sqlalchemy import select, tuple_
from sqlalchemy.orm import Session

from ..hunt_guide import HuntGuide
from ..hunt_guide_plan import MAX_TECHNIQUES
from ..models import Document, Entity, HuntPackage, Observation
from ..schemas import MAX_HUNT_PACKAGE_INPUT_ITEMS, HuntPackageInput, HuntPackageItemInput
from .actor_reports import ReportRef
from .audit import audit
from .hunt_guides import _MAX_REPORTS, _guide_parts
from .hunt_packages import add_hunt_package_item, create_hunt_package
from .threat_guides import SweepEntry
from .tlp import _visible


def _items(
    db: Session,
    reports: list[ReportRef],
    techniques: tuple[str, ...],
    sweep: tuple[SweepEntry, ...],
    max_tlp: str | None,
) -> list[HuntPackageItemInput]:
    report_ids = [r.document_id for r in reports[:_MAX_REPORTS]]
    values = [(entry.kind, entry.value) for entry in sweep]
    entities = {
        (kind, value): entity_id
        for kind, value, entity_id in db.execute(
            select(Entity.kind, Entity.value, Entity.id)
            .join(Observation, Observation.entity_id == Entity.id)
            .join(Document, Document.id == Observation.document_id)
            .where(
                tuple_(Entity.kind, Entity.value).in_(values),
                Document.id.in_(report_ids),
                Document.is_current.is_(True),
                Observation.review_status == 'accepted',
                *_visible(max_tlp),
            )
            .distinct()
        )
    }
    if any(value not in entities for value in values):
        raise LookupError('The guide evidence changed. Build the guide again.')
    return [
        *(
            HuntPackageItemInput(kind='technique', target_id=t)
            for t in tuple(dict.fromkeys(techniques))[:MAX_TECHNIQUES]
        ),
        *(HuntPackageItemInput(kind='document', target_id=ref) for ref in dict.fromkeys(report_ids)),
        *(HuntPackageItemInput(kind='indicator', target_id=entities[value]) for value in values),
    ]


def _hypothesis(guide: HuntGuide, items: list[HuntPackageItemInput]) -> str:
    lines = [
        guide.summary,
        f'Saved from {guide.kind}: {guide.ref}. Built: {guide.created_at}. Sharing label: TLP:{guide.tlp}.',
        'This is a draft plan. No search or rule has run. A match is a lead, not proof of an attack.',
        f'{len(items)} evidence items are attached. Review them before publishing this package.',
    ]
    for section in guide.sections:
        # The attached items carry these identities. Keep the limited hypothesis field for guidance,
        # not duplicate lists of indicators and report metadata; no text is parsed back into evidence.
        if section.title not in ('Reviewed indicators to check', 'Reports used'):
            lines.extend(('', section.title, *section.lines))
    text = '\n'.join(lines)
    if len(text) <= 10_000:
        return text
    note = '\n\nGuidance shortened to fit the saved package. Build the guide again for the full current plan.'
    return text[: 10_000 - len(note)].rstrip() + note


def create_hunt_package_from_guide(
    db: Session, kind: str, ref: str, *, max_tlp: str | None = None
) -> HuntPackage:
    """Rebuild and save a new draft; never publish, execute, or infer a group for another subject kind.

    Keeps the guide's sharing label, including verdicts that excluded indicators. At most 12 techniques,
    20 reports and 100 eligible reviewed indicators are attached. Each explicit call creates a new draft.
    The savepoint makes the package, all items and their audit records atomic within the caller's write.
    """
    with db.begin_nested():
        guide, reports, techniques, sweep = _guide_parts(
            db, kind, ref, max_tlp=max_tlp, now=datetime.now(UTC)
        )
        items = _items(db, reports, techniques, sweep, max_tlp)
        payload = HuntPackageInput.model_validate(
            {
                'title': guide.title[:200],
                'hypothesis': _hypothesis(guide, items),
                'group': guide.ref if guide.kind == 'actor' else None,
                'tlp': guide.tlp,
                'items': items[:MAX_HUNT_PACKAGE_INPUT_ITEMS],
            }
        )
        package = create_hunt_package(db, payload, max_tlp=max_tlp)
        for item in items[MAX_HUNT_PACKAGE_INPUT_ITEMS:]:
            add_hunt_package_item(db, package.id, item, max_tlp=max_tlp)
        audit(
            db,
            'hunt_package.from_guide',
            package.id,
            json.dumps(
                {'kind': guide.kind, 'ref': guide.ref, 'items': len(items), 'tlp': package.tlp},
                sort_keys=True,
            ),
        )
    return package
