"""Narrow regressions for a factual Intel Brief scoped to the selected topic."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from insight import services
from insight.models import Entity, KEVRecord
from insight.schemas import (
    ActorInput,
    ActorLinkInput,
    AssessmentInput,
    CampaignInput,
    IndustryClaimInput,
    SoftwareLinkInput,
    ThreatLinkInput,
)

from .test_threat_guides import accept_all, report

NOW = datetime(2026, 11, 23, 18, tzinfo=UTC)


def test_eight_focuses_use_explicit_reports_without_publisher_text_or_unrelated_flaws(db: Session) -> None:
    """Regression: a selected brief must not just rename a hunt guide or show global exploit totals."""
    doc = report(
        db,
        'Selected phishing bulletin',
        'PRIVATE PUBLISHER BODY. phishing focus-test.net CVE-2026-12345 public proof of concept.',
        tlp='CLEAR',
    )
    doc.created_at = (NOW - timedelta(days=1)).isoformat()
    accept_all(db, doc)
    services.link_report(db, 'G1017', ActorLinkInput(document_id=doc.id, tlp='CLEAR'))
    services.link_software_report(db, 'S0154', SoftwareLinkInput(document_id=doc.id, tlp='CLEAR'))
    campaign = services.create_campaign(db, CampaignInput(name='Selected campaign', tlp='CLEAR'))
    services.link_threat(
        db, 'campaign', campaign.id, ThreatLinkInput(target_kind='document', target_id=doc.id, tlp='CLEAR')
    )
    entity_id = db.scalars(select(Entity.id).where(Entity.value == 'focus-test.net')).one()
    db.add(
        KEVRecord(
            cve='CVE-2026-99999',
            vendor='Unrelated',
            product='Secret product',
            date_added='2026-11-22',
            due_date='2026-12-01',
            required_action='Update',
        )
    )
    db.add(
        KEVRecord(
            cve='CVE-2026-12345',
            vendor='Future',
            product='Future catalog item',
            date_added='2026-12-01',
            due_date='2026-12-30',
            required_action='Update',
        )
    )
    db.flush()
    for kind, ref in (
        ('theme', 'phishing'),
        ('actor', 'G1017'),
        ('software', 'S0154'),
        ('document', doc.id),
        ('cve', 'CVE-2026-12345'),
        ('exploit', 'CVE-2026-12345'),
        ('indicator', entity_id),
        ('campaign', campaign.id),
    ):
        brief = services.focused_brief(db, kind, ref, now=NOW, max_tlp='GREEN')
        assert [r.document_id for r in brief.reports] == [doc.id]
        assert brief.tlp == 'CLEAR'
        assert len(brief.summary) <= 3
        assert len(brief.notes) <= 2
        content = str(brief)
        assert 'PRIVATE PUBLISHER BODY' not in content
        assert 'CVE-2026-99999' not in content
        assert 'Start the hunt' not in content
        assert 'used in real attacks' not in content
        if kind in ('cve', 'exploit'):
            assert 'Public code does not prove' in content
    dated = report(db, 'Date checks', 'CVE-2026-88888 has no stored code signal.', tlp='CLEAR')
    dated.created_at = (NOW - timedelta(days=1)).isoformat()
    catalog = KEVRecord(
        cve='CVE-2026-88888',
        vendor='Synthetic',
        product='Date checks',
        date_added='2026-12-01',
        due_date='2026-12-30',
        required_action='Update',
    )
    db.add(catalog)
    for date_added in ('2026-12-01', 'invalid-date'):
        catalog.date_added = date_added
        db.flush()
        with pytest.raises(LookupError):
            services.focused_brief(db, 'exploit', catalog.cve, max_tlp='GREEN', now=NOW)
        brief = services.focused_brief(db, 'document', dated.id, max_tlp='GREEN', now=NOW)
        assert 'used in real attacks' not in str(brief)
    catalog.date_added = '2026-11-22'
    db.flush()
    known = services.focused_brief(db, 'exploit', catalog.cve, max_tlp='GREEN', now=NOW)
    assert 'used in real attacks' in str(known)


def test_report_windows_exclude_future_old_hidden_and_retired_items_and_cap_display(db: Session) -> None:
    """Regression: background facts and future report timestamps must not become recent activity."""
    for n in range(6):
        doc = report(db, f'Recent {n}', f'ransomware recent item {n}', tlp='CLEAR')
        doc.created_at = (NOW - timedelta(hours=n + 1)).isoformat()
    old = report(db, 'Twenty days old', 'ransomware older item', tlp='CLEAR')
    old.created_at = (NOW - timedelta(days=20)).isoformat()
    future = report(db, 'Future item', 'ransomware future item', tlp='CLEAR')
    future.created_at = (NOW + timedelta(days=1)).isoformat()
    hidden = report(db, 'Hidden item', 'ransomware secret item', tlp='AMBER')
    hidden.created_at = NOW.isoformat()
    retired = report(db, 'Retired item', 'ransomware retired item', tlp='CLEAR')
    retired.created_at, retired.is_current = NOW.isoformat(), False
    db.flush()
    week = services.focused_brief(db, 'theme', 'ransomware', days=7, max_tlp='GREEN', now=NOW)
    month = services.focused_brief(db, 'theme', 'ransomware', days=30, max_tlp='GREEN', now=NOW)
    assert week.summary[1].startswith('6 matching')
    assert month.summary[1].startswith('7 matching')
    assert len(week.reports) == len(month.reports) == 5
    assert 'Lists the five latest' in month.notes[1]
    empty = services.focused_brief(db, 'actor', 'G1017', days=7, max_tlp='GREEN', now=NOW)
    assert not empty.reports
    assert empty.summary[0].startswith('MITRE ATT&CK background:')
    assert empty.sections[-1].lines[0].startswith('No explicitly linked')
    with pytest.raises(ValueError, match='Choose a 7 or 30 day brief'):
        services.focused_brief(db, 'actor', 'G1017', days=1, now=NOW)


def test_link_and_expired_verdict_labels_are_preserved_and_hidden_subjects_are_missing(db: Session) -> None:
    """Regression: a hidden link or expired verdict must never turn into an unlabelled brief fact."""
    doc = report(db, 'Visible source', 'focused-verdict.net', tlp='CLEAR')
    doc.created_at = (NOW - timedelta(days=1)).isoformat()
    accept_all(db, doc)
    services.link_report(db, 'G1017', ActorLinkInput(document_id=doc.id, tlp='AMBER'))
    green = services.focused_brief(db, 'actor', 'G1017', now=NOW, max_tlp='GREEN')
    amber = services.focused_brief(db, 'actor', 'G1017', now=NOW, max_tlp='AMBER')
    assert not green.reports
    assert green.tlp == 'CLEAR'
    assert len(amber.reports) == 1
    assert amber.tlp == 'AMBER'
    entity_id = db.scalars(select(Entity.id).where(Entity.value == 'focused-verdict.net')).one()
    verdict = services.assess_entity(
        db, entity_id, AssessmentInput(verdict='benign', reason='SECRET REASON', tlp='AMBER')
    )
    assert verdict is not None
    verdict.valid_until = (NOW - timedelta(days=1)).isoformat()
    db.flush()
    brief = services.focused_brief(db, 'indicator', entity_id, now=NOW, max_tlp='AMBER')
    assert brief.tlp == 'AMBER'
    assert 'has expired' in str(brief)
    assert 'SECRET REASON' not in str(brief)
    low = services.focused_brief(db, 'indicator', entity_id, now=NOW, max_tlp='GREEN')
    assert low.tlp == 'CLEAR'
    assert 'has expired' not in str(low)
    hidden = services.create_actor(db, ActorInput(name='Hidden actor', tlp='AMBER'))
    secret = report(db, 'Hidden report', 'CVE-2026-77777 hidden-only.net', tlp='AMBER')
    entity = db.scalars(select(Entity.id).where(Entity.value == 'hidden-only.net')).one()
    for kind, ref in (
        ('actor', hidden.id),
        ('document', secret.id),
        ('cve', 'CVE-2026-77777'),
        ('indicator', entity),
        ('theme', 'missing'),
    ):
        with pytest.raises(LookupError):
            services.focused_brief(db, kind, ref, now=NOW, max_tlp='GREEN')


def test_actor_background_is_useful_without_recent_reports_and_preserves_target_decisions(
    db: Session,
) -> None:
    """Regression: an actor brief without linked reports used to contain only one catalog sentence."""
    brief = services.focused_brief(db, 'actor', 'G1017', now=NOW, max_tlp='GREEN')
    assert len(brief.summary) == 3
    assert not brief.reports
    content = str(brief)
    assert 'critical infrastructure' in content
    assert 'Guam' in content
    assert all(value in content for value in ('T1190', 'T1078', 'T1059', 'Mimikatz', 'PsExec', 'BRONZE'))
    assert 'What to watch for' in content
    assert 'No explicitly linked' in content
    assert any(source.url.startswith('https://www.cisa.gov/') for source in brief.sources)
    assert len(brief.sources) <= 6
    assert all(len(section.lines) <= 6 for section in brief.sections)
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
    services.record_industry_claim(
        db,
        'G0016',
        IndustryClaimInput(
            industry='agriculture',
            citation_url='https://example.org/synthetic-target',
            tlp='AMBER',
        ),
    )
    lower = services.focused_brief(db, 'actor', 'G0016', now=NOW, max_tlp='GREEN')
    higher = services.focused_brief(db, 'actor', 'G0016', now=NOW, max_tlp='AMBER')
    low_targets = [
        line for section in lower.sections for line in section.lines if line.startswith('Recorded targets:')
    ]
    high_targets = [
        line for section in higher.sections for line in section.lines if line.startswith('Recorded targets:')
    ]
    assert 'Government and diplomacy' in str(low_targets)
    assert 'Government and diplomacy' not in str(high_targets)
    assert higher.tlp == 'AMBER'
    assert lower.tlp == 'CLEAR'
    assert 'PRIVATE REMOVAL' not in str(higher)
