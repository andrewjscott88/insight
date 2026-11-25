"""Sectors use sourced target decisions, not inferred attribution or unrestricted report matches."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy.orm import Session

from insight import services
from insight.industry_brief import industry_choices
from insight.schemas import ActorInput, ActorLinkInput, IndustryClaimInput

from .test_threat_guides import report

NOW = datetime(2026, 11, 23, 18, tzinfo=UTC)


def test_sector_search_uses_existing_industry_names_scope_and_aliases() -> None:
    """Regression: industry labels and everyday sector terms must resolve to the same canonical focus."""
    assert industry_choices('financial sector') == [('finance', 'Finance, banking and cryptocurrency')]
    assert industry_choices('hospitals') == [('healthcare', 'Healthcare and pharmaceuticals')]
    assert industry_choices('health care industry') == [('healthcare', 'Healthcare and pharmaceuticals')]
    assert len(industry_choices()) == 15
    assert not industry_choices('not-a-real-sector')


def test_sector_brief_uses_explicit_links_and_the_selected_window(db: Session) -> None:
    """Regression: sector briefs must not infer attacks or include hidden, future or old reports."""
    actor = services.create_actor(db, ActorInput(name='Synthetic sector group', tlp='CLEAR'))
    services.record_industry_claim(
        db,
        actor.id,
        IndustryClaimInput(
            industry='healthcare',
            citation_url='https://example.org/sector-evidence',
            reason='Cited targets',
            tlp='CLEAR',
        ),
    )
    for title, days_ago, label, link_label, current in (
        ('Recent linked report', 2, 'CLEAR', 'CLEAR', True),
        ('Twenty-day linked report', 20, 'CLEAR', 'CLEAR', True),
        ('Older linked report', 31, 'CLEAR', 'CLEAR', True),
        ('Future linked report', -1, 'CLEAR', 'CLEAR', True),
        ('Hidden linked report', 1, 'AMBER', 'AMBER', True),
        ('Hidden association', 1, 'CLEAR', 'AMBER', True),
        ('Retired linked report', 1, 'CLEAR', 'CLEAR', False),
    ):
        doc = report(db, title, 'PRIVATE PUBLISHER TEXT ' + title, tlp=label)
        doc.created_at = (NOW - timedelta(days=days_ago)).isoformat()
        services.link_report(db, actor.id, ActorLinkInput(document_id=doc.id, tlp=link_label))
        doc.is_current = current
    named = report(db, 'Name only', 'Synthetic sector group described in a general report', tlp='CLEAR')
    named.created_at = NOW.isoformat()
    direct = report(
        db, 'Hospital advisory', 'PRIVATE PUBLISHER TEXT: hospitals review their access.', tlp='CLEAR'
    )
    direct.created_at = (NOW - timedelta(days=1)).isoformat()
    for title, age, label in (
        ('Future hospital advisory', -1, 'CLEAR'),
        ('Old hospital advisory', 31, 'CLEAR'),
        ('Hidden hospital advisory', 0, 'AMBER'),
    ):
        doc = report(db, title, 'Hospitals are mentioned here.', tlp=label)
        doc.created_at = (NOW - timedelta(days=age)).isoformat()
    db.flush()
    month = services.focused_brief(db, 'industry', 'healthcare', max_tlp='GREEN', now=NOW)
    week = services.focused_brief(db, 'industry', 'healthcare', days=7, max_tlp='GREEN', now=NOW)
    assert month.days == 30
    assert month.tlp == 'CLEAR'
    assert [item.title for item in month.reports] == [
        'Hospital advisory',
        'Recent linked report',
        'Twenty-day linked report',
    ]
    assert [item.title for item in week.reports] == ['Hospital advisory', 'Recent linked report']
    assert month.reports[0].relevance == 'Mentions this sector'
    assert month.reports[1].relevance == 'Linked to a sector-targeting group'
    assert 'Synthetic sector group' in str(month)
    assert 'PRIVATE PUBLISHER TEXT' not in str(month)
    assert 'Name only' not in str(month)
    assert any(source.url == 'https://example.org/sector-evidence' for source in month.sources)
    with pytest.raises(LookupError):
        services.focused_brief(db, 'industry', 'not-a-sector', max_tlp='GREEN', now=NOW)


def test_sector_mapping_additions_and_removals_preserve_their_labels(db: Session) -> None:
    """Regression: hidden industry decisions must neither leak nor silently lower the brief's label."""
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
    actor = services.create_actor(db, ActorInput(name='Hidden sector actor', tlp='AMBER'))
    services.record_industry_claim(
        db,
        actor.id,
        IndustryClaimInput(
            industry='government',
            citation_url='https://example.org/private-target',
            tlp='AMBER',
        ),
    )
    doc = report(db, 'Hidden target report', 'Do not reveal this title or target', tlp='AMBER')
    doc.created_at = NOW.isoformat()
    services.link_report(db, actor.id, ActorLinkInput(document_id=doc.id, tlp='AMBER'))
    catalog_doc = report(db, 'Catalog group report', 'A dated source about the group.', tlp='CLEAR')
    catalog_doc.created_at = NOW.isoformat()
    services.link_report(db, 'G0016', ActorLinkInput(document_id=catalog_doc.id, tlp='CLEAR'))
    green = services.focused_brief(db, 'industry', 'government', max_tlp='GREEN', now=NOW)
    amber = services.focused_brief(db, 'industry', 'government', max_tlp='AMBER', now=NOW)
    assert green.tlp == 'CLEAR'
    assert amber.tlp == 'AMBER'
    assert 'Hidden sector actor' not in str(green)
    assert 'private-target' not in str(green)
    assert 'Hidden target report' not in str(green)
    assert 'Catalog group report' in str(green)
    assert 'Catalog group report' not in str(amber)
    assert 'Hidden sector actor' in str(amber)
    assert 'Hidden target report' in str(amber)
    assert 'PRIVATE REMOVAL' not in str(amber)


def test_sector_scan_and_result_caps_are_visible(db: Session, monkeypatch: pytest.MonkeyPatch) -> None:
    """Regression: a bounded sector scan must disclose when matching reports may be missing."""
    import insight.services.industry_briefs as module

    for index in range(4):
        doc = report(db, f'Hospital bulletin {index}', 'Hospitals reviewing access.', tlp='CLEAR')
        doc.created_at = (NOW - timedelta(hours=index)).isoformat()
    db.flush()
    monkeypatch.setattr(module, '_SCAN_CAP', 2)
    partial = services.focused_brief(db, 'industry', 'healthcare', now=NOW, max_tlp='GREEN')
    assert len(partial.reports) == 2
    assert partial.summary[-1].startswith('At least 2')
    assert 'current reports were scanned' in partial.notes[-1]
    monkeypatch.setattr(module, '_SCAN_CAP', 10)
    monkeypatch.setattr(module, '_REPORT_CAP', 1)
    capped = services.focused_brief(db, 'industry', 'healthcare', now=NOW, max_tlp='GREEN')
    assert len(capped.reports) == 1
    assert capped.summary[-1].startswith('At least 1')
    assert 'Review is capped' in capped.notes[-1]
