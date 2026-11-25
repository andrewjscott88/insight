"""Sector hunt guides retain evidence boundaries through preview, downloads and explicit draft saves."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from io import BytesIO

import pytest
from pypdf import PdfReader
from sqlalchemy import select
from sqlalchemy.orm import Session

from insight import services
from insight.hunt_guide import to_markdown, to_pdf
from insight.models import AuditEvent, Entity
from insight.schemas import ActorInput, ActorLinkInput, AssessmentInput, IndustryClaimInput

from .test_hunt_guides import text
from .test_threat_guides import accept_all, report

NOW = datetime.now(UTC)


def test_sector_choices_match_aliases_and_are_available_without_reports(db: Session) -> None:
    """Regression: Sector / Industry must be a supported hunt type, including no-query browsing."""
    assert len(services.hunt_guide_choices(db, kind='industry', max_tlp='GREEN')['industry']) == 15
    assert services.hunt_guide_choices(db, q='hospitals', max_tlp='GREEN')['industry'] == [
        ('healthcare', 'Healthcare and pharmaceuticals'),
    ]
    guide = services.hunt_guide(db, 'industry', 'healthcare', max_tlp='GREEN', now=NOW)
    assert guide.kind == 'industry'
    assert guide.ref == 'healthcare'
    assert guide.title == 'Threat hunt guide: Healthcare and pharmaceuticals'
    assert 'Target mapping:' in text(guide)
    assert 'No included report' in text(guide)
    with pytest.raises(LookupError):
        services.hunt_guide(db, 'industry', 'unknown-sector', max_tlp='GREEN', now=NOW)


def test_sector_guides_separate_mentions_from_links_and_export_metadata_only(db: Session) -> None:
    """Regression: sector relevance must not become attribution or copy publisher text/private notes."""
    actor = services.create_actor(db, ActorInput(name='A synthetic sector group', tlp='CLEAR'))
    services.record_industry_claim(
        db,
        actor.id,
        IndustryClaimInput(
            industry='healthcare',
            citation_url='https://example.org/target-source',
            reason='PRIVATE MAPPING NOTE',
            tlp='GREEN',
        ),
    )
    direct = report(
        db,
        'Hospital advisory',
        'PRIVATE PUBLISHER TEXT. Hospitals check T1566.001 sector-hunt.net.',
        tlp='GREEN',
    )
    linked = report(
        db, 'Explicitly linked report', 'PRIVATE LINKED BODY. linked-sector-hunt.net.', tlp='CLEAR'
    )
    named = report(db, 'Name only', 'A synthetic sector group is named.', tlp='CLEAR')
    for doc in (direct, linked, named):
        doc.created_at = (NOW - timedelta(days=2)).isoformat()
        accept_all(db, doc)
    services.link_report(
        db,
        actor.id,
        ActorLinkInput(
            document_id=linked.id,
            note='PRIVATE LINK NOTE',
            tlp='GREEN',
        ),
    )
    for title, body, age, label in (
        ('Hidden hospital report', 'Hospitals secret-sector.net', 1, 'AMBER'),
        ('Old hospital report', 'Hospitals old-sector.net', 31, 'CLEAR'),
        ('Future hospital report', 'Hospitals future-sector.net', -1, 'CLEAR'),
    ):
        doc = report(db, title, body, tlp=label)
        doc.created_at = (NOW - timedelta(days=age)).isoformat()
        accept_all(db, doc)
    db.flush()
    guide = services.hunt_guide(db, 'industry', 'healthcare', max_tlp='GREEN', now=NOW)
    assert guide.tlp == 'GREEN'
    sections = {section.title: section.lines for section in guide.sections}
    assert direct.id in str(sections['Reports mentioning this sector'])
    assert direct.id not in str(sections['Reports linked to sector-targeting groups'])
    assert linked.id in str(sections['Reports linked to sector-targeting groups'])
    assert linked.id not in str(sections['Reports mentioning this sector'])
    content = text(guide)
    assert 'https://example.org/target-source' in content
    assert content.count('sector-hunt.net') >= 1
    assert content.count('linked-sector-hunt.net') >= 1
    for forbidden in ('PRIVATE', named.id, 'Hidden hospital', 'Old hospital', 'Future hospital'):
        assert forbidden not in content
    markdown = to_markdown(guide)
    pdf = '\n'.join(page.extract_text() for page in PdfReader(BytesIO(to_pdf(guide))).pages)
    for rendered in (markdown, pdf):
        assert 'Healthcare and pharmaceuticals' in rendered
        assert 'Reports mentioning this sector' in rendered
        assert 'TLP:GREEN' in rendered
        assert 'PRIVATE' not in rendered


def test_sector_package_keeps_focus_and_rebuilds_with_restrictions(db: Session) -> None:
    """Regression: a saved sector package must not invent an actor or retain an excluded indicator."""
    doc = report(
        db,
        'Hospital security advisory',
        'Hospitals review T1566.001 eligible-sector-hunt.net safe-sector-hunt.net.',
        tlp='CLEAR',
    )
    doc.created_at = (NOW - timedelta(days=1)).isoformat()
    accept_all(db, doc)
    safe = db.scalar(select(Entity).where(Entity.value == 'safe-sector-hunt.net'))
    eligible = db.scalar(select(Entity).where(Entity.value == 'eligible-sector-hunt.net'))
    assert safe
    assert eligible
    services.assess_entity(
        db,
        safe.id,
        AssessmentInput(
            verdict='benign',
            reason='PRIVATE VERDICT REASON',
            tlp='AMBER',
        ),
    )
    services.set_actor(db, 'sector-test-operator')
    package = services.create_hunt_package_from_guide(db, 'industry', 'healthcare', max_tlp='AMBER')
    view = services.get_hunt_package(db, package.id, max_tlp='AMBER')
    assert view.status == 'draft'
    assert view.group_ref is None
    assert view.published_at is None
    assert view.tlp == 'AMBER'
    assert 'Saved from industry: healthcare.' in view.hypothesis
    assert 'PRIVATE VERDICT REASON' not in view.hypothesis
    items = {(item.kind, item.target_id) for item in view.items}
    assert ('document', doc.id) in items
    assert ('indicator', eligible.id) in items
    assert ('indicator', safe.id) not in items
    assert ('technique', 'T1566.001') in items
    event = db.scalars(
        select(AuditEvent).where(
            AuditEvent.action == 'hunt_package.from_guide',
            AuditEvent.object_id == view.id,
        )
    ).one()
    assert event.actor == 'sector-test-operator'
    assert json.loads(event.detail)['kind'] == 'industry'
    doc.is_current = False
    rebuilt = services.create_hunt_package_from_guide(db, 'industry', 'healthcare', max_tlp='GREEN')
    rebuilt_view = services.get_hunt_package(db, rebuilt.id, max_tlp='GREEN')
    assert all(item.kind == 'technique' for item in rebuilt_view.items)


def test_sector_hunt_preserves_removed_target_and_scan_limit_labels(
    db: Session,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Regression: target removal and scan caps must remain visible decisions under the guide's label."""
    import insight.services.industry_briefs as module

    services.record_industry_claim(
        db,
        'G0016',
        IndustryClaimInput(
            industry='government',
            decision='removed',
            reason='PRIVATE REMOVAL',
            tlp='AMBER',
        ),
    )
    doc = report(db, 'Unmarked linked evidence', 'A report with no direct sector words.', tlp='CLEAR')
    doc.created_at = (NOW - timedelta(days=1)).isoformat()
    services.link_report(db, 'G0016', ActorLinkInput(document_id=doc.id, tlp='CLEAR'))
    green = services.hunt_guide(db, 'industry', 'government', max_tlp='GREEN', now=NOW)
    amber = services.hunt_guide(db, 'industry', 'government', max_tlp='AMBER', now=NOW)
    assert green.tlp == 'CLEAR'
    assert doc.id in text(green)
    assert amber.tlp == 'AMBER'
    assert doc.id not in text(amber)
    assert 'PRIVATE REMOVAL' not in text(amber)
    extra = report(db, 'New report', 'Routine bulletin.', tlp='GREEN')
    extra.created_at = NOW.isoformat()
    db.flush()
    monkeypatch.setattr(module, '_SCAN_CAP', 1)
    capped = services.hunt_guide(db, 'industry', 'government', max_tlp='GREEN', now=NOW)
    assert capped.tlp == 'GREEN'
    assert 'Matching reports may be missing' in text(capped)
