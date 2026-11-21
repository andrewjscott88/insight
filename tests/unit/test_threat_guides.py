"""Industry threat profiles, actor threat guides and hunts (TIP 2.10, ADR 0024)."""

from __future__ import annotations

import csv
import io
import json
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from insight import services
from insight.models import AuditEvent, Document, Entity, Observation
from insight.schemas import (
    ActorInput,
    ActorLinkInput,
    AssessmentInput,
    DocumentInput,
    HuntCheckInput,
    HuntInput,
    HuntUpdate,
    IndustryClaimInput,
    RuleInput,
    RuleLinkInput,
)
from insight.services import SourceRef, ingest
from insight.threat_guide import compose, guide_json, navigator_layer, sweep_csv, sweep_json
from insight.threat_guide_markdown import link, to_markdown
from insight.threat_library import library

NOW = datetime.now(UTC)
YARA = 'rule Demo_Loader {\n  strings:\n    $a = "demo-loader"\n  condition:\n    $a\n}\n'
SIGMA = (
    'title: Demo encoded PowerShell\nlogsource:\n  product: windows\n'
    'detection:\n  sel:\n    x: 1\n  condition: sel\n'
)


def report(db: Session, title: str, body: str, *, tlp: str = 'GREEN', key: str | None = None) -> Document:
    doc, _ = ingest(
        db,
        DocumentInput.model_validate({'title': title, 'body': body, 'source_name': 'Test feed', 'tlp': tlp}),
        ref=SourceRef('test', key) if key else None,
    )
    return doc


def accept_all(db: Session, doc: Document) -> None:
    for obs in db.scalars(select(Observation).where(Observation.document_id == doc.id)):
        services.set_observation_status(db, obs.id, 'accepted')


def actions(db: Session, prefix: str) -> list[str]:
    return [e.action for e in db.scalars(select(AuditEvent).where(AuditEvent.action.like(f'{prefix}%')))]


# --------------------------------------------------------------------------- industry profiles


def test_only_groups_a_source_names_for_the_industry_are_listed_with_their_evidence(db: Session) -> None:
    profile = services.industry_profile(db, 'government', now=NOW)
    assert 1 <= len(profile.entries) <= 10
    assert profile.candidates >= len(profile.entries)
    for entry in profile.entries:
        assert entry.claims, entry.subject.ref
        assert all('government' in c.industries for c in entry.claims)
        assert entry.reasons[0].startswith(('MITRE ATT&CK', 'MISP galaxy'))
    assert profile.tlp == 'CLEAR'  # catalog data only, no reports yet


def test_unknown_industry_is_refused(db: Session) -> None:
    with pytest.raises(LookupError):
        services.industry_profile(db, 'space-piracy', now=NOW)


def test_groups_named_in_recent_reports_rank_first_and_say_why(db: Session) -> None:
    report(db, 'Cozy Bear phishing wave', 'Cozy Bear sent lures to a ministry.', tlp='AMBER')
    report(db, 'Unrelated', 'Ransomware hit a school.')
    profile = services.industry_profile(db, 'government', now=NOW)
    first = profile.entries[0]
    assert first.subject.ref == 'G0016'
    assert first.mentions == 1
    assert any(r.startswith('Named in 1 of your reports in the last 90 days') for r in first.reasons)
    assert profile.tlp == 'AMBER'  # a counted report was AMBER
    hidden = services.industry_profile(db, 'government', now=NOW, max_tlp='GREEN')
    assert all(e.mentions == 0 for e in hidden.entries)  # the AMBER report is invisible at GREEN
    assert hidden.tlp == 'CLEAR'


def test_one_word_names_match_only_as_written(db: Session) -> None:
    services.set_actor(db, 'operator')
    assert services.case_sensitive('Tick')
    assert not services.case_sensitive('Cozy Bear')
    tick = report(db, 'Tick', 'Tick returned with new tools.')
    report(db, 'Lowercase', 'Every tick of the clock counts.')
    found, scanned = services.find_mentions(db, {'G0060': ['Tick']}, since=None)
    assert scanned == 2
    assert [m.document_id for m in found['G0060']] == [tick.id]


def test_an_analyst_can_remove_a_catalog_claim_or_add_one_with_a_citation(db: Session) -> None:
    services.set_actor(db, 'operator')
    with pytest.raises(ValueError, match='Give the link or the report'):
        services.record_industry_claim(
            db, 'G0016', IndustryClaimInput(industry='energy', decision='added', reason='seen it')
        )
    services.record_industry_claim(
        db,
        'G0016',
        IndustryClaimInput(
            industry='government', decision='removed', reason='Not in our region', tlp='GREEN'
        ),
    )
    assert 'G0016' not in {
        e.subject.ref for e in services.industry_profile(db, 'government', now=NOW).entries
    }
    # a reader who may not see the decision still sees the catalog claim
    services.record_industry_claim(
        db,
        'G0016',
        IndustryClaimInput(
            industry='agriculture',
            decision='added',
            citation_url='https://example.org/report',
            reason='Vendor report on seed companies',
            tlp='AMBER',
        ),
    )
    agriculture = services.industry_profile(db, 'agriculture', now=NOW)
    entry = next(e for e in agriculture.entries if e.subject.ref == 'G0016')
    assert entry.claims[-1].source_name == 'Your own mapping'
    assert entry.claims[-1].url == 'https://example.org/report'
    assert agriculture.tlp == 'AMBER'
    assert 'G0016' not in {
        e.subject.ref for e in services.industry_profile(db, 'agriculture', now=NOW, max_tlp='GREEN').entries
    }
    assert actions(db, 'actor.industry') == ['actor.industry', 'actor.industry']


def test_claims_above_the_callers_limit_are_refused(db: Session) -> None:
    with pytest.raises(services.TlpNotPermitted):
        services.record_industry_claim(
            db,
            'G0016',
            IndustryClaimInput(industry='government', decision='removed', reason='x', tlp='RED'),
            max_tlp='AMBER',
        )


# --------------------------------------------------------------------------- actors and links


def test_analyst_actors_are_created_listed_by_label_and_linked_to_reports(db: Session) -> None:
    services.set_actor(db, 'operator')
    actor = services.create_actor(
        db,
        ActorInput(name='Copper Fox', aliases=('CF-1', 'copper fox'), attack_group_id='g0016', tlp='AMBER'),
    )
    assert actor.aliases == 'CF-1'  # the name is not repeated as an alias
    assert actor.attack_group_id == 'G0016'
    assert [a.id for a in services.list_actors(db)] == [actor.id]
    assert services.list_actors(db, max_tlp='GREEN') == []
    with pytest.raises(LookupError):
        services.resolve_group(db, actor.id, max_tlp='GREEN')
    subject = services.resolve_group(db, actor.id)
    assert subject.kind == 'analyst'
    assert subject.catalog is not None
    assert 'Cozy Bear' in subject.names
    with pytest.raises(ValueError, match='not a group'):
        services.create_actor(db, ActorInput(name='X', attack_group_id='G9999'))
    doc = report(db, 'Copper notes', 'Nothing named here.')
    services.link_report(db, actor.id, ActorLinkInput(document_id=doc.id, note='Our IR case'))
    services.link_report(db, actor.id, ActorLinkInput(document_id=doc.id, note='Our IR case 2'))  # idempotent
    [(linked, link_row)] = services.linked_reports(db, actor.id)
    assert (linked.id, link_row.note) == (doc.id, 'Our IR case 2')
    services.unlink_report(db, actor.id, doc.id)
    assert services.linked_reports(db, actor.id) == []
    with pytest.raises(LookupError):
        services.unlink_report(db, actor.id, doc.id)
    assert actions(db, 'actor.') == ['actor.create', 'actor.link', 'actor.link', 'actor.unlink']


def test_hidden_reports_cannot_be_linked(db: Session) -> None:
    amber = report(db, 'A', 'B', tlp='AMBER')
    with pytest.raises(LookupError):
        services.link_report(db, 'G0016', ActorLinkInput(document_id=amber.id), max_tlp='GREEN')
    with pytest.raises(LookupError):
        services.link_report(db, 'G9999', ActorLinkInput(document_id=amber.id))


# --------------------------------------------------------------------------- rules


def test_rules_are_stored_once_checked_for_shape_and_linked(db: Session) -> None:
    services.set_actor(db, 'operator')
    rule = services.add_rule(db, RuleInput(kind='yara', name='Demo loader', body=YARA, licence='CC0-1.0'))
    with pytest.raises(ValueError, match='already stored'):
        services.add_rule(db, RuleInput(kind='yara', name='Again', body=YARA))
    with pytest.raises(ValueError, match='YARA'):
        services.add_rule(db, RuleInput(kind='yara', name='Bad', body='title: not yara'))
    with pytest.raises(ValueError, match='Sigma'):
        services.add_rule(db, RuleInput(kind='sigma', name='Bad', body=YARA))
    sigma = services.add_rule(db, RuleInput(kind='sigma', name='Encoded PowerShell', body=SIGMA, tlp='GREEN'))
    services.link_rule(db, rule.id, RuleLinkInput(target_kind='group', target_id='G0016'))
    services.link_rule(db, sigma.id, RuleLinkInput(target_kind='technique', target_id='t1059.001'))
    with pytest.raises(ValueError, match='ATT&CK technique'):
        services.link_rule(db, sigma.id, RuleLinkInput(target_kind='technique', target_id='T9999'))
    found = {r.rule.name: r.links for r in services.rules_for_group(db, 'G0016', ['T1059.001'])}
    assert found == {
        'Demo loader': (('group', 'G0016'),),
        'Encoded PowerShell': (('technique', 'T1059.001'),),
    }
    assert [r.rule.name for r in services.list_rules(db, max_tlp='GREEN')] == ['Encoded PowerShell']
    services.unlink_rule(db, sigma.id, RuleLinkInput(target_kind='technique', target_id='T1059.001'))
    services.delete_rule(db, rule.id)
    assert [r.rule.name for r in services.list_rules(db)] == ['Encoded PowerShell']
    assert actions(db, 'rule.') == [
        'rule.add',
        'rule.add',
        'rule.link',
        'rule.link',
        'rule.unlink',
        'rule.delete',
    ]


# --------------------------------------------------------------------------- hunts


def test_hunts_record_each_check_with_an_audit_trail(db: Session) -> None:
    services.set_actor(db, 'operator')
    hunt = services.start_hunt(db, 'G0016', HuntInput(title='APT29 sweep Q4', tlp='AMBER'))
    services.record_check(
        db,
        hunt.id,
        't1059.001',
        HuntCheckInput(
            result='nothing-found',
            data_checked='Sysmon process creation',
            period_start='2026-10-01',
            period_end='2026-10-31',
        ),
    )
    services.record_check(db, hunt.id, 'T1059.001', HuntCheckInput(result='suspicious', notes='One host'))
    assert services.hunt_checks(db, hunt.id) == {'T1059.001': ('suspicious', '', '', '', 'One host')}
    with pytest.raises(ValueError, match='before its start'):
        services.record_check(
            db,
            hunt.id,
            'T1003',
            HuntCheckInput(result='confirmed', period_start='2026-10-02', period_end='2026-10-01'),
        )
    services.update_hunt(db, hunt.id, HuntUpdate(status='closed', summary='Done; one host escalated.'))
    with pytest.raises(ValueError, match='closed'):
        services.record_check(db, hunt.id, 'T1003', HuntCheckInput(result='confirmed'))
    assert services.hunts_for(db, 'G0016', max_tlp='GREEN') == []
    assert services.get_hunt(db, hunt.id, max_tlp='GREEN') is None
    with pytest.raises(services.TlpNotPermitted):
        services.start_hunt(db, 'G0016', HuntInput(title='Too high', tlp='RED'), max_tlp='AMBER')
    assert actions(db, 'hunt.') == ['hunt.start', 'hunt.check', 'hunt.check', 'hunt.update']


# --------------------------------------------------------------------------- the guide


def _guide_fixture(db: Session) -> tuple[Document, Document]:
    services.set_actor(db, 'operator')
    linked = report(
        db,
        'IR case 42',
        'The intrusion used T1059.001. Beacon to 203.0.113.7 is test space; C2 was evil-c2.biz and '
        'payload hash 44d88612fea8a8f36de82e1278abb02f.',
        tlp='AMBER',
    )
    named = report(db, 'Vendor blog', 'Cozy Bear used login-microsoftonline.click for phishing.', tlp='GREEN')
    for doc in (linked, named):
        accept_all(db, doc)
    services.link_report(db, 'G0016', ActorLinkInput(document_id=linked.id, note='Our case'))
    return linked, named


def test_the_guide_brings_catalog_data_reports_hunt_and_sweep_together(db: Session) -> None:
    linked, named = _guide_fixture(db)
    rule = services.add_rule(db, RuleInput(kind='sigma', name='Encoded PowerShell', body=SIGMA, tlp='GREEN'))
    services.link_rule(db, rule.id, RuleLinkInput(target_kind='technique', target_id='T1059.001'))
    data = services.guide_data(db, 'G0016', now=NOW)
    guide = compose(data, library())
    assert data.tlp == 'AMBER'
    assert [(r.document_id, r.via) for r in data.reports] == [(linked.id, 'linked'), (named.id, 'named')]
    values = {e.value: e for e in data.sweep}
    assert '203.0.113.7' not in values  # documentation address: flagged, left out
    assert values['evil-c2.biz'].via == 'linked'
    assert values['login-microsoftonline.click'].via == 'named'
    assert data.report_techniques == {'T1059.001': 1}
    first = guide.hypotheses[0]
    assert first.technique_id == 'T1059.001'  # in the analyst's recent reports
    assert first.statement.startswith('If APT29 is active here, expect')
    assert first.data_components
    assert first.detections
    exported = guide_json(guide)
    assert exported['format'] == 'insight-threat-guide-1'
    assert exported['tlp'] == 'AMBER'
    assert exported['hunt']['rules'][0]['name'] == 'Encoded PowerShell'
    assert any(c['source'] == 'MITRE ATT&CK' for c in exported['industries'])
    json.dumps(exported)  # serialisable
    layer = navigator_layer(guide)
    assert layer['versions']['layer'] == '4.5'
    assert {'name': 'TLP', 'value': 'TLP:AMBER'} in layer['metadata']
    scored = {t['techniqueID']: t['score'] for t in layer['techniques']}
    assert scored['T1059.001'] == 2  # ATT&CK lists it, plus one linked report
    md = to_markdown(guide)
    assert md.startswith('**TLP:AMBER**')
    assert md.rstrip().endswith('**TLP:AMBER**')
    assert '### Hypotheses' in md
    assert 'Starting hypotheses' in md
    assert 'evil-c2.biz' in md


def test_a_limited_reader_gets_a_guide_without_what_they_may_not_see(db: Session) -> None:
    linked, _ = _guide_fixture(db)
    data = services.guide_data(db, 'G0016', now=NOW, max_tlp='GREEN')
    assert linked.id not in {r.document_id for r in data.reports}
    assert 'evil-c2.biz' not in {e.value for e in data.sweep}
    assert data.tlp == 'GREEN'
    catalog_only = services.guide_data(db, 'G0016', now=NOW, max_tlp='CLEAR')
    assert catalog_only.reports == ()
    assert catalog_only.tlp == 'CLEAR'


def test_linked_only_sweeps_leave_out_reports_that_only_name_the_group(db: Session) -> None:
    _guide_fixture(db)
    data = services.guide_data(db, 'G0016', now=NOW, linked_only=True)
    assert {r.via for r in data.reports} == {'linked'}
    assert 'login-microsoftonline.click' not in {e.value for e in data.sweep}


def test_benign_and_expired_verdicts_leave_the_sweep_list(db: Session) -> None:
    _guide_fixture(db)
    services.assess_entity(db, _entity_id(db, 'evil-c2.biz'), AssessmentInput(verdict='benign'))
    md5 = '44d88612fea8a8f36de82e1278abb02f'
    today = NOW.date().isoformat()
    services.assess_entity(db, _entity_id(db, md5), AssessmentInput(verdict='malicious', valid_until=today))
    current = {e.value: e for e in services.guide_data(db, 'G0016', now=NOW).sweep}
    assert 'evil-c2.biz' not in current
    assert current[md5].verdict == 'malicious'
    later = {e.value for e in services.guide_data(db, 'G0016', now=NOW + timedelta(days=2)).sweep}
    assert md5 not in later  # the verdict's own expiry has passed


def _entity_id(db: Session, value: str) -> str:
    found = db.scalar(select(Entity.id).where(Entity.value == value))
    assert found is not None
    return found


def test_sweep_exports_carry_the_label_and_resist_formula_injection(db: Session) -> None:
    _guide_fixture(db)
    guide = compose(services.guide_data(db, 'G0016', now=NOW), library())
    text = sweep_csv(guide)
    assert text.startswith('# TLP:AMBER')
    rows = list(csv.DictReader(io.StringIO(text.split('\n', 1)[1])))
    assert {r['kind'] for r in rows} >= {'domain', 'md5'}
    assert sweep_json(guide)['format'] == 'insight-sweep-v1'


def test_markdown_links_and_text_cannot_inject_markup() -> None:
    assert link('x', 'javascript:alert(1)') == 'x'
    assert link('a](b', 'https://e.org/a)b') == '[a\\](b](https://e.org/a%29b)'


def test_an_analyst_actor_without_a_catalog_group_has_a_guide_from_linked_reports(db: Session) -> None:
    services.set_actor(db, 'operator')
    actor = services.create_actor(db, ActorInput(name='Copper Fox', tlp='GREEN'))
    doc = report(db, 'Case', 'Copper Fox ran T1486 then T1490.')
    services.link_report(db, actor.id, ActorLinkInput(document_id=doc.id))
    guide = compose(services.guide_data(db, actor.id, now=NOW), library())
    assert {r.id for r in guide.techniques} == {'T1486', 'T1490'}
    assert all(not r.in_attack for r in guide.techniques)
    assert guide.tlp == 'GREEN'
    assert 'Actor you track' in to_markdown(guide)


def test_deleting_a_report_removes_its_links_and_the_mappings_that_rest_on_it(db: Session) -> None:
    from insight.models import ActorDocument, IndustryClaim, RuleLink

    services.set_actor(db, 'operator')
    doc = report(db, 'Case', 'Body')
    services.link_report(db, 'G0016', ActorLinkInput(document_id=doc.id))
    services.record_industry_claim(
        db,
        'G0016',
        IndustryClaimInput(industry='energy', decision='added', document_id=doc.id, reason='Our case'),
    )
    services.record_industry_claim(
        db,
        'G0016',
        IndustryClaimInput(
            industry='legal',
            decision='added',
            document_id=doc.id,
            citation_url='https://example.org/law-firms',
            reason='Vendor report too',
        ),
    )
    rule = services.add_rule(db, RuleInput(kind='yara', name='Demo', body=YARA))
    services.link_rule(db, rule.id, RuleLinkInput(target_kind='document', target_id=doc.id))
    services.delete_document(db, doc.id, 'retention period ended')
    assert db.scalars(select(ActorDocument)).all() == []
    assert db.scalars(select(RuleLink)).all() == []
    [kept] = db.scalars(select(IndustryClaim)).all()  # the energy claim rested only on the report
    assert (kept.industry, kept.document_id, kept.citation_url) == (
        'legal',
        None,
        'https://example.org/law-firms',
    )


def test_regression_the_reason_a_hypothesis_comes_first_keeps_the_attack_name(db: Session) -> None:
    """Regression: ``str.capitalize()`` turned "ATT&CK lists the group using it" into "Att&ck lists ..."."""
    guide = compose(services.guide_data(db, 'G0016', now=NOW), library())
    reasons = [h.why_first for h in guide.hypotheses if h.why_first]
    assert reasons
    assert all('Att&ck' not in why for why in reasons)
    assert 'ATT&CK lists the group using it' in reasons


def test_regression_the_markdown_guide_has_a_hypothesis_for_every_technique(db: Session) -> None:
    """Regression: the Markdown guide stopped after 40 hypotheses and sent readers to the JSON export."""
    guide = compose(services.guide_data(db, 'G0016', now=NOW), library())
    assert len(guide.hypotheses) > 40  # APT29 has more techniques than the old cut-off
    md = to_markdown(guide)
    assert all(f'- **{h.technique_id}**:' in md for h in guide.hypotheses)
    assert 'more in the JSON export' not in md
