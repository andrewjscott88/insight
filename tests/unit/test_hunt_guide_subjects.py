"""Saved intelligence entry points for the guided hunt workspace."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from insight import services
from insight.models import Entity, KEVRecord, Observation
from insight.schemas import CampaignInput, ThreatLinkInput

from .test_hunt_guides import text
from .test_threat_guides import accept_all, report

NOW = datetime(2026, 11, 23, tzinfo=UTC)


def _kev(db: Session, cve: str) -> None:
    db.add(
        KEVRecord(
            cve=cve,
            vendor='Example vendor',
            product='Gateway',
            date_added='2026-11-22',
            due_date='2026-12-01',
            required_action='Apply the vendor fix.',
        )
    )
    db.flush()


def _entity(db: Session, value: str) -> Entity:
    return db.scalars(select(Entity).where(Entity.value == value)).one()


def test_report_advisory_plan_has_evidence_without_republishing_text(db: Session) -> None:
    doc = report(
        db,
        'FBI advisory: synthetic campaign',
        'PUBLISHER-BODY-DO-NOT-EXPORT. T1059.001. malicious-hunt-test.net.',
        tlp='GREEN',
    )
    accept_all(db, doc)
    found = services.hunt_guide(db, 'document', doc.id, max_tlp='GREEN', now=NOW)
    assert found.tlp == 'GREEN'
    rendered = text(found)
    assert 'FBI advisory' in rendered
    assert 'T1059.001' in rendered
    assert 'PUBLISHER-BODY-DO-NOT-EXPORT' not in rendered
    assert 'malicious-hunt-test.net' in rendered
    assert 'No source URL was saved' in rendered
    doc.source_url = 'https://example.org/advisory'
    assert doc.source_url in text(services.hunt_guide(db, 'document', doc.id, now=NOW))


@pytest.mark.parametrize('kind', ['document', 'cve', 'exploit', 'indicator'])
def test_subjects_above_limit_are_missing_as_are_rejected_and_superseded(db: Session, kind: str) -> None:
    """Regression: a hidden or rejected subject must not be disclosed through a hunt guide."""
    doc = report(db, 'HIDDEN-ADVISORY', 'CVE-2026-12345 public proof of concept.', tlp='AMBER')
    entity = _entity(db, 'CVE-2026-12345')
    ref = doc.id if kind == 'document' else entity.id if kind == 'indicator' else entity.value
    assert services.hunt_guide_choices(db, kind=kind, q='12345', max_tlp='GREEN')[kind] == []
    with pytest.raises(LookupError):
        services.hunt_guide(db, kind, ref, max_tlp='GREEN', now=NOW)
    assert services.hunt_guide(db, kind, ref, max_tlp='AMBER', now=NOW).tlp == 'AMBER'
    if kind != 'document':
        obs = db.scalars(select(Observation).where(Observation.document_id == doc.id)).one()
        services.set_observation_status(db, obs.id, 'rejected')
        with pytest.raises(LookupError):
            services.hunt_guide(db, kind, ref, max_tlp='AMBER', now=NOW)
    doc.is_current = False
    with pytest.raises(LookupError):
        services.hunt_guide(db, kind, ref, max_tlp='AMBER', now=NOW)


def test_cve_exploit_code_and_known_attack_use_are_distinct(db: Session) -> None:
    report(db, 'Flaw bulletin', 'CVE-2026-12345.', tlp='CLEAR')
    first = services.hunt_guide(db, 'cve', 'cve-2026-12345', max_tlp='GREEN', now=NOW)
    assert 'do not confirm use in attacks' in text(first)
    with pytest.raises(LookupError):
        services.hunt_guide(db, 'exploit', 'CVE-2026-12345', max_tlp='GREEN', now=NOW)
    report(db, 'Restricted exploit evidence', 'CVE-2026-12345 public proof of concept.', tlp='AMBER')
    assert services.hunt_guide_choices(db, kind='exploit', max_tlp='GREEN')['exploit'] == []
    full = services.hunt_guide(db, 'exploit', 'CVE-2026-12345', now=NOW)
    assert full.tlp == 'AMBER'
    assert 'code is public' in text(full)
    assert 'do not confirm use in attacks' in text(full)
    _kev(db, 'CVE-2026-12345')
    public = services.hunt_guide(db, 'exploit', 'CVE-2026-12345', max_tlp='GREEN', now=NOW)
    assert public.tlp == 'CLEAR'
    assert 'used in real attacks' in text(public)
    assert 'Example vendor Gateway' in text(public)
    assert 'Restricted exploit evidence' not in text(public)
    assert services.hunt_guide_choices(db, kind='exploit', max_tlp='GREEN')['exploit'] == [
        ('CVE-2026-12345', 'CVE-2026-12345')
    ]


def test_unreviewed_indicator_is_a_subject_but_not_a_reviewed_check(db: Session) -> None:
    doc = report(db, 'Indicator lead', 'malicious-hunt-test.net', tlp='CLEAR')
    entity = _entity(db, 'malicious-hunt-test.net')
    guide = services.hunt_guide(db, 'indicator', entity.id, max_tlp='GREEN', now=NOW)
    assert 'A mention is not a harmful verdict' in text(guide)
    assert 'No eligible reviewed indicators' in text(guide)
    accept_all(db, doc)
    reviewed = services.hunt_guide(db, 'indicator', entity.id, max_tlp='GREEN', now=NOW)
    assert 'Review: accepted; verdict: unknown' in text(reviewed)


def test_campaign_uses_visible_explicit_links_and_preserves_their_labels(db: Session) -> None:
    campaign = services.create_campaign(db, CampaignInput(name='Copper campaign', tlp='CLEAR'))
    linked = report(db, 'Linked report', 'T1059.001, CVE-2026-12345.', tlp='CLEAR')
    report(db, 'Copper campaign mentioned', 'UNLINKED-REPORT-BODY.', tlp='CLEAR')
    for kind, ref in [('document', linked.id), ('technique', 'T1003')]:
        services.link_threat(
            db,
            'campaign',
            campaign.id,
            ThreatLinkInput.model_validate({'target_kind': kind, 'target_id': ref, 'tlp': 'AMBER'}),
        )
    low = services.hunt_guide(db, 'campaign', campaign.id, max_tlp='GREEN', now=NOW)
    assert low.tlp == 'CLEAR'
    assert 'Linked report' not in text(low)
    assert 'T1003' not in text(low)
    high = services.hunt_guide(db, 'campaign', campaign.id, max_tlp='AMBER', now=NOW)
    assert high.tlp == 'AMBER'
    assert 'Linked report' in text(high)
    assert 'T1003' in text(high)
    assert 'UNLINKED-REPORT-BODY' not in text(high)
    secret = services.create_campaign(db, CampaignInput(name='SECRET campaign', tlp='AMBER'))
    assert services.hunt_guide_choices(db, kind='campaign', q='SECRET', max_tlp='GREEN')['campaign'] == []
    assert services.hunt_guide_choices(db, kind='campaign', q='Copper', max_tlp='GREEN')['campaign']
    with pytest.raises(LookupError):
        services.hunt_guide(db, 'campaign', secret.id, max_tlp='GREEN', now=NOW)


def test_choice_search_reaches_reports_and_cves_beyond_first_page(db: Session) -> None:
    for n in range(55):
        report(db, f'Bulletin {n:02}', f'CVE-2026-{10000 + n}.', tlp='CLEAR')
    assert len(services.hunt_guide_choices(db, kind='document')['document']) == 50
    assert len(services.hunt_guide_choices(db, kind='cve')['cve']) == 50
    assert len(services.hunt_guide_choices(db, kind='indicator')['indicator']) == 50
    found = services.hunt_guide_choices(db, kind='document', q='Bulletin 00')['document']
    assert len(found) == 1
    assert 'Bulletin 00' in found[0][1]
    assert services.hunt_guide_choices(db, kind='cve', q='10054')['cve'][0][0] == 'CVE-2026-10054'
    assert services.hunt_guide_choices(db, kind='indicator', q='10054')['indicator'][0][0]
    for n in range(55):
        _kev(db, f'CVE-2026-{10000 + n}')
    assert len(services.hunt_guide_choices(db, kind='exploit')['exploit']) == 50
    assert services.hunt_guide_choices(db, kind='exploit', q='10054')['exploit'][0][0] == 'CVE-2026-10054'


def test_public_subject_helper_refuses_unknown_kinds(db: Session) -> None:
    with pytest.raises(LookupError):
        services.hunt_guide_subject(db, 'invalid', 'missing', now=NOW)
    with pytest.raises(LookupError):
        services.hunt_guide_subject_choices(db, kind='invalid', q='')


def test_advisory_flaws_keep_labels_of_exploit_evidence_outside_the_report_cap(db: Session) -> None:
    """Regression: a public bulletin cannot launder an older restricted exploit claim into a public plan."""
    secret = report(db, 'OLD-RESTRICTED-CONTEXT', 'CVE-2026-12345 public proof of concept.', tlp='AMBER')
    secret.created_at = '2020-01-01T00:00:00+00:00'
    for n in range(22):
        doc = report(db, f'Current bulletin {n}', 'CVE-2026-12345.', tlp='CLEAR')
    full = services.hunt_guide(db, 'cve', 'CVE-2026-12345', max_tlp='AMBER', now=NOW)
    assert full.tlp == 'AMBER'
    assert 'code is public' in text(full)
    assert 'OLD-RESTRICTED-CONTEXT' not in text(full)
    report_plan = services.hunt_guide(db, 'document', doc.id, max_tlp='AMBER', now=NOW)
    assert report_plan.tlp == 'AMBER'
    assert 'code is public' in text(report_plan)
    public = services.hunt_guide(db, 'document', doc.id, max_tlp='GREEN', now=NOW)
    assert public.tlp == 'CLEAR'
    assert 'code is public' not in text(public)


def test_exploit_choice_search_continues_past_cves_without_evidence(db: Session) -> None:
    for n in range(201):
        report(db, f'Flaw bulletin {n}', f'CVE-2026-{20000 + n}.', tlp='CLEAR')
    _kev(db, 'CVE-2026-20200')
    assert services.hunt_guide_choices(db, kind='exploit')['exploit'] == [
        ('CVE-2026-20200', 'CVE-2026-20200')
    ]


def test_markdown_defangs_indicator_values_in_every_text_position() -> None:
    """Regression: an indicator subject's title must not leave a clickable raw address in a guide."""
    from insight.hunt_guide import GuideSection, HuntGuide, to_markdown

    guide = HuntGuide(
        'indicator',
        'test',
        'unsafe-test.net',
        'https://unsafe-test.net/a',
        'CLEAR',
        NOW.isoformat(),
        (GuideSection('unsafe-test.net', ('unsafe-test.net',)),),
    )
    rendered = to_markdown(guide)
    assert 'unsafe-test.net' not in rendered
    assert 'unsafe-test' in rendered
