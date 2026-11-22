"""Requirement matching and labels (TIP 4.1, ADR 0032): each kind of criterion, what never counts as a match,
and the TLP rules for criteria that point at an analyst's own records."""

from __future__ import annotations

import pytest
from sqlalchemy import select, update
from sqlalchemy.orm import Session

from insight import services
from insight.models import Document, Observation
from insight.schemas import (
    ActorInput,
    ActorLinkInput,
    CampaignInput,
    CriterionInput,
    DocumentInput,
    RequirementInput,
    ThreatLinkInput,
)


def report(db: Session, title: str, body: str, tlp: str = 'GREEN') -> Document:
    doc, _ = services.ingest(db, DocumentInput(title=title, body=body, source_name='S', tlp=tlp))
    return doc


def pir(db: Session, *criteria: tuple[str, str], tlp: str = 'GREEN') -> str:
    payload = RequirementInput.model_validate(
        {'kind': 'pir', 'question': 'What should we know?', 'tlp': tlp,
         'criteria': [{'kind': k, 'value': v} for k, v in criteria]}
    )  # fmt: skip
    return services.create_requirement(db, payload).id


def matched(db: Session, requirement_id: str, max_tlp: str | None = None) -> set[str]:
    return {m.title for m in services.get_requirement(db, requirement_id, max_tlp=max_tlp).matches}


def test_terms_match_case_and_accent_insensitively(db: Session) -> None:
    report(db, 'Résumé lure', 'A RANSOMWARE crew sent a résumé.')
    report(db, 'Unrelated', 'A printer update.')
    rid = pir(db, ('term', 'ransomware'), ('term', 'resume'))
    assert matched(db, rid) == {'Résumé lure'}


def test_a_cve_mention_counts_unless_review_rejected_it(db: Session) -> None:
    kept = report(db, 'Kept', 'Exploits CVE-2024-3400.')
    wrong = report(db, 'Wrong', 'Mentions CVE-2023-1111 by mistake.')
    rid = pir(db, ('cve', 'CVE-2024-3400'), ('cve', 'CVE-2023-1111'))
    assert matched(db, rid) == {'Kept', 'Wrong'}
    mention = db.scalars(select(Observation).where(Observation.document_id == wrong.id)).one()
    services.set_observation_status(db, mention.id, 'rejected')
    assert matched(db, rid) == {'Kept'}
    assert kept.id in {m.document_id for m in services.get_requirement(db, rid).matches}


def test_a_tagged_technique_counts_and_a_removed_tag_does_not(db: Session) -> None:
    doc = report(db, 'Phishing wave', 'Lures sent by e-mail.')
    rid = pir(db, ('technique', 't1566'))
    assert matched(db, rid) == set()
    services.tag_technique(db, doc.id, 'T1566')
    assert matched(db, rid) == {'Phishing wave'}
    services.untag_technique(db, doc.id, 'T1566')
    assert matched(db, rid) == set()


def test_a_catalog_group_and_an_actor_linked_to_it_count_as_one(db: Session) -> None:
    via_catalog = report(db, 'Catalog link', 'A report.')
    via_actor = report(db, 'Actor link', 'Another report.')
    actor = services.create_actor(
        db, ActorInput(name='Our APT29 view', attack_group_id='G0016', tlp='GREEN', aliases=())
    )
    services.link_report(db, 'G0016', ActorLinkInput(document_id=via_catalog.id, tlp='GREEN'))
    services.link_report(db, actor.id, ActorLinkInput(document_id=via_actor.id, tlp='GREEN'))
    assert matched(db, pir(db, ('group', 'G0016'))) == {'Catalog link', 'Actor link'}
    assert matched(db, pir(db, ('group', actor.id))) == {'Catalog link', 'Actor link'}


def test_a_campaign_link_counts_only_for_readers_who_may_see_the_link(db: Session) -> None:
    doc = report(db, 'Open report', 'Edge appliance activity.', tlp='GREEN')
    campaign = services.create_campaign(db, CampaignInput(name='Edge wave', tlp='GREEN', aliases=()))
    services.link_threat(
        db, 'campaign', campaign.id, ThreatLinkInput(target_kind='document', target_id=doc.id, tlp='AMBER')
    )
    rid = pir(db, ('campaign', campaign.id))
    assert matched(db, rid) == {'Open report'}
    assert matched(db, rid, max_tlp='GREEN') == set()  # The link itself is AMBER.


def test_superseded_revisions_and_hidden_reports_never_count(db: Session) -> None:
    report(db, 'Partner only', 'Ransomware partner notes.', tlp='AMBER')
    rid = pir(db, ('term', 'ransomware'))
    assert matched(db, rid) == {'Partner only'}
    assert matched(db, rid, max_tlp='GREEN') == set()
    summary = services.get_requirement(db, rid, max_tlp='GREEN').summary
    assert (summary.recent_matches, summary.quiet) == (0, True)
    db.execute(update(Document).values(is_current=False))
    assert matched(db, rid) == set()


def test_criteria_on_restricted_records_raise_the_label_and_hide_from_lower_readers(db: Session) -> None:
    actor = services.create_actor(db, ActorInput(name='Partner-only actor', tlp='AMBER', aliases=()))
    rid = pir(db, tlp='CLEAR')
    services.add_criterion(db, rid, CriterionInput(kind='group', value=actor.id))
    assert services.get_requirement(db, rid).summary.tlp == 'AMBER'
    with pytest.raises(LookupError):
        services.get_requirement(db, rid, max_tlp='GREEN')
    other = pir(db, tlp='CLEAR')
    with pytest.raises(LookupError):  # A GREEN caller cannot point at an actor it cannot see.
        services.add_criterion(db, other, CriterionInput(kind='group', value=actor.id), max_tlp='GREEN')


def test_document_requirements_lists_open_ones_most_urgent_first(db: Session) -> None:
    doc = report(db, 'Roundup', 'Ransomware and phishing notes.')
    low = services.create_requirement(
        db, RequirementInput(kind='pir', question='Phishing trends?', priority='low', criteria=[
            CriterionInput(kind='term', value='phishing')])
    )  # fmt: skip
    high = services.create_requirement(
        db, RequirementInput(kind='pir', question='Ransomware trends?', priority='high', criteria=[
            CriterionInput(kind='term', value='ransomware')])
    )  # fmt: skip
    retired = pir(db, ('term', 'notes'))
    services.retire_requirement(db, retired)
    assert [r.id for r in services.document_requirements(db, doc.id)] == [high.id, low.id]
    assert services.requirement_counts(db) == {'open_rfis': 0, 'quiet': 0}
