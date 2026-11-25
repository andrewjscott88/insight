"""Focused regressions for explicitly saving a rebuilt hunt guide as a draft."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from insight import services
from insight.models import AuditEvent, Entity, HuntPackage
from insight.schemas import (
    ActorInput,
    ActorLinkInput,
    AssessmentInput,
    CampaignInput,
    HuntPackageItemInput,
    SoftwareLinkInput,
    ThreatLinkInput,
)
from insight.services import hunt_guide_packages

from .test_threat_guides import accept_all, report


def _entity(db: Session, value: str) -> str:
    return db.scalars(select(Entity.id).where(Entity.value == value)).one()


def test_current_hunt_plans_exclude_default_expired_verdicts_and_keep_their_labels(db: Session) -> None:
    """Regression: a verdict called expired in a focused brief stayed malicious in a saved hunt plan."""
    when = datetime.now(UTC)
    value = 'expired-hunt-review.net'
    permanent = 'a' * 64
    doc = report(db, 'Hospital advisory', f'Hospitals review {value} and {permanent}.', tlp='CLEAR')
    doc.created_at = (when - timedelta(days=1)).isoformat()
    accept_all(db, doc)
    services.link_report(db, 'G0016', ActorLinkInput(document_id=doc.id, tlp='CLEAR'))
    entity_id = _entity(db, value)
    hash_id = _entity(db, permanent)
    for target, label in ((entity_id, 'AMBER'), (hash_id, 'CLEAR')):
        verdict = services.assess_entity(
            db, target, AssessmentInput(verdict='malicious', reason='Private test reason', tlp=label)
        )
        assert verdict is not None
        verdict.decided_at = (when - timedelta(days=100)).isoformat()
    db.flush()
    focused = services.focused_brief(db, 'indicator', entity_id, max_tlp='AMBER', now=when)
    assert 'expired' in str(focused.summary)
    guide = services.hunt_guide(db, 'industry', 'healthcare', max_tlp='AMBER', now=when)
    lines = '\n'.join(line for section in guide.sections for line in section.lines)
    assert value not in lines
    assert permanent in lines
    assert guide.tlp == 'AMBER'
    saved = services.create_hunt_package_from_guide(db, 'industry', 'healthcare', max_tlp='AMBER')
    package = services.get_hunt_package(db, saved.id, max_tlp='AMBER')
    assert package.tlp == 'AMBER'
    targets = {item.target_id for item in package.items}
    assert entity_id not in targets
    assert hash_id in targets
    # The existing actor sweep remains retrospective: only an explicit expiry excludes a value there.
    legacy = services.guide_data(db, 'G0016', max_tlp='AMBER', now=when)
    assert value in {entry.value for entry in legacy.sweep}


def test_selected_guides_save_drafts_with_their_actual_structured_evidence(db: Session) -> None:
    """Regression: the built guide used to have no path to a saved hunt package."""
    doc = report(
        db,
        'Phishing source',
        'DO-NOT-COPY-PUBLISHER-TEXT. T1566.001. hunt-saved-test.net. CVE-2026-12345 public proof of concept.',
        tlp='CLEAR',
    )
    accept_all(db, doc)
    services.link_report(db, 'G1017', ActorLinkInput(document_id=doc.id, tlp='CLEAR'))
    services.link_software_report(db, 'S0154', SoftwareLinkInput(document_id=doc.id, tlp='CLEAR'))
    campaign = services.create_campaign(db, CampaignInput(name='Synthetic campaign', tlp='CLEAR'))
    services.link_threat(
        db,
        'campaign',
        campaign.id,
        ThreatLinkInput(target_kind='document', target_id=doc.id, tlp='CLEAR'),
    )
    indicator = _entity(db, 'hunt-saved-test.net')
    services.set_actor(db, 'operator')
    for kind, ref in (
        ('actor', 'G1017'),
        ('theme', 'phishing'),
        ('software', 'S0154'),
        ('document', doc.id),
        ('cve', 'CVE-2026-12345'),
        ('exploit', 'CVE-2026-12345'),
        ('indicator', indicator),
        ('campaign', campaign.id),
    ):
        package = services.create_hunt_package_from_guide(db, kind, ref, max_tlp='GREEN')
        view = services.get_hunt_package(db, package.id, max_tlp='GREEN')
        assert view.status == 'draft'
        assert view.published_at is None
        assert view.group_ref == ('G1017' if kind == 'actor' else None)
        assert 'Start the hunt' in view.hypothesis
        assert 'DO-NOT-COPY-PUBLISHER-TEXT' not in view.hypothesis
        assert len(view.hypothesis) <= 10_000
        assert ('document', doc.id) in {(item.kind, item.target_id) for item in view.items}
        assert ('indicator', indicator) in {(item.kind, item.target_id) for item in view.items}
        event = db.scalars(
            select(AuditEvent).where(
                AuditEvent.action == 'hunt_package.from_guide',
                AuditEvent.object_id == view.id,
            )
        ).one()
        assert event.actor == 'operator'
        assert json.loads(event.detail)['ref'] == ref


def test_save_rebuilds_current_evidence_and_preserves_exclusion_labels(db: Session) -> None:
    """Regression: saving a cached preview must not retain stale indicators or lose exclusion labels."""
    doc = report(db, 'Linked source', 'eligible-hunt-test.net safe-hunt-test.net.', tlp='CLEAR')
    accept_all(db, doc)
    services.link_report(db, 'G1017', ActorLinkInput(document_id=doc.id, tlp='CLEAR'))
    preview = services.hunt_guide(db, 'actor', 'G1017', max_tlp='AMBER')
    assert preview.tlp == 'CLEAR'
    safe = _entity(db, 'safe-hunt-test.net')
    services.assess_entity(
        db,
        safe,
        AssessmentInput(verdict='benign', reason='RESTRICTED REASON', tlp='AMBER'),
    )
    package = services.create_hunt_package_from_guide(db, 'actor', 'G1017', max_tlp='AMBER')
    view = services.get_hunt_package(db, package.id, max_tlp='AMBER')
    assert view.tlp == 'AMBER'
    assert 'TLP:AMBER' in view.hypothesis
    assert 'RESTRICTED REASON' not in view.hypothesis
    assert safe not in {item.target_id for item in view.items}
    assert _entity(db, 'eligible-hunt-test.net') in {item.target_id for item in view.items}
    with pytest.raises(LookupError):
        services.get_hunt_package(db, package.id, max_tlp='GREEN')
    doc.is_current = False
    rebuilt = services.create_hunt_package_from_guide(db, 'actor', 'G1017', max_tlp='GREEN')
    items = services.get_hunt_package(db, rebuilt.id, max_tlp='GREEN').items
    assert all(item.kind == 'technique' for item in items)
    hidden = services.create_actor(db, ActorInput(name='Hidden actor', tlp='AMBER'))
    count = db.scalar(select(func.count()).select_from(HuntPackage))
    with pytest.raises(LookupError):
        services.create_hunt_package_from_guide(db, 'actor', hidden.id, max_tlp='GREEN')
    assert db.scalar(select(func.count()).select_from(HuntPackage)) == count


def test_more_than_100_items_are_saved_and_any_late_failure_is_atomic(
    db: Session,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Regression: the request's 100-item cap must not silently drop a guide's reviewed indicators."""
    doc = report(db, 'Many reviewed leads', ' '.join(f'hunt-saved-{n}.net' for n in range(100)), tlp='CLEAR')
    accept_all(db, doc)
    services.link_report(db, 'G1017', ActorLinkInput(document_id=doc.id, tlp='CLEAR'))
    package = services.create_hunt_package_from_guide(db, 'actor', 'G1017', max_tlp='GREEN')
    items = services.get_hunt_package(db, package.id, max_tlp='GREEN').items
    assert len(items) == 113
    assert sum(item.kind == 'indicator' for item in items) == 100
    before = db.scalar(select(func.count()).select_from(HuntPackage))
    audits = db.scalar(select(func.count()).select_from(AuditEvent))

    def fail_late(
        db: Session,
        package_id: str,
        payload: HuntPackageItemInput,
        *,
        max_tlp: str | None = None,
    ) -> None:
        raise LookupError('Synthetic late evidence change')

    monkeypatch.setattr(hunt_guide_packages, 'add_hunt_package_item', fail_late)
    with pytest.raises(LookupError, match='Synthetic late evidence change'):
        services.create_hunt_package_from_guide(db, 'actor', 'G1017', max_tlp='GREEN')
    assert db.scalar(select(func.count()).select_from(HuntPackage)) == before
    assert db.scalar(select(func.count()).select_from(AuditEvent)) == audits
