"""Finished intelligence products (TIP 4.4, ADR 0036): judgements, gaps, labels, publishing and exports."""

from __future__ import annotations

import json
from typing import Any

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from insight import services
from insight.models import AuditEvent, Document, Entity, Requirement
from insight.schemas import (
    CaseInput,
    CaseItemInput,
    CaseUpdate,
    DocumentInput,
    GapInput,
    JudgementInput,
    JudgementUpdate,
    SourceRatingInput,
)


def report(db: Session, title: str, body: str, tlp: str = 'GREEN') -> Document:
    doc, _ = services.ingest(db, DocumentInput(title=title, body=body, source_name='Vendor', tlp=tlp))
    return doc


def entity(db: Session, value: str) -> str:
    found: str = db.scalars(select(Entity.id).where(Entity.value == value)).one()
    return found


def product(db: Session, **fields: Any) -> str:
    payload = {'title': 'Edge appliance exploitation', 'tlp': 'GREEN'} | fields
    return services.create_case(db, CaseInput.model_validate(payload)).id


def item(db: Session, case_id: str, kind: str, target: str) -> str:
    found: str = services.add_case_item(db, case_id, CaseItemInput(kind=kind, target_id=target)).id
    return found


def judgement(**fields: Any) -> JudgementInput:
    payload = {'statement': 'The crew will keep exploiting edge appliances.', 'likelihood': 'likely',
               'confidence': 'moderate'} | fields  # fmt: skip
    return JudgementInput.model_validate(payload)


def filled(db: Session) -> tuple[str, str, str]:
    """A product with a report, an indicator, a BLUF, one judgement citing both, and a gap."""
    doc = report(db, 'Vendor advisory', 'Exploitation of CVE-2024-3400 from 203.0.113.40.')
    case_id = product(db, bluf='Expect more edge appliance exploitation this quarter.',
                      audience='CISO', summary='First paragraph.\n\nSecond paragraph.')  # fmt: skip
    doc_item = item(db, case_id, 'document', doc.id)
    ip_item = item(db, case_id, 'indicator', entity(db, '203.0.113.40'))
    services.add_judgement(db, case_id, judgement(evidence=[doc_item, ip_item]))
    services.add_gap(db, case_id, GapInput(question='Which appliances in our estate are exposed?'))
    return case_id, doc_item, ip_item


def test_judgements_need_evidence_from_the_product_and_raise_its_label(db: Session) -> None:
    case_id = product(db)
    other = product(db, title='Other')
    doc = report(db, 'Note', 'Text.')
    foreign = item(db, other, 'document', doc.id)
    with pytest.raises(LookupError):
        services.add_judgement(db, case_id, judgement(evidence=[foreign]))
    first = services.add_judgement(db, case_id, judgement())
    assert (first.position, first.tlp, first.evidence) == (1, 'GREEN', ())
    second = services.add_judgement(db, case_id, judgement(statement='Seen with TLP:AMBER partners.'))
    assert second.tlp == 'AMBER'
    assert services.get_case(db, case_id).tlp == 'AMBER'
    moved = services.update_judgement(db, case_id, second.id, JudgementUpdate(position=1))
    assert moved.position == 1
    assert [j.id for j in services.product_parts(db, case_id).judgements] == [second.id, first.id]
    services.remove_judgement(db, case_id, second.id)
    assert services.get_case(db, case_id).tlp == 'AMBER'  # removing never lowers the label
    lowered = services.update_case(db, case_id, CaseUpdate(tlp='GREEN'))
    assert lowered.tlp == 'GREEN'


def test_a_gap_is_asked_as_a_request_for_information_once(db: Session) -> None:
    case_id = product(db)
    gap = services.add_gap(db, case_id, GapInput(question='Which appliances are exposed?'))
    rfi = services.ask_gap(db, case_id, gap.id)
    assert (rfi.kind, rfi.question, rfi.tlp) == ('rfi', 'Which appliances are exposed?', 'GREEN')
    assert services.ask_gap(db, case_id, gap.id).id == rfi.id
    assert services.product_parts(db, case_id).gaps[0].requirement_id == rfi.id
    assert len(db.scalars(select(Requirement)).all()) == 1


def test_publishing_needs_a_bottom_line_and_supported_judgements(db: Session) -> None:
    case_id = product(db)
    with pytest.raises(services.ProductIncomplete, match='a bottom line up front and at least one key'):
        services.publish_product(db, case_id)
    services.update_case(db, case_id, CaseUpdate(bluf='Expect more.'))
    services.add_judgement(db, case_id, judgement())
    with pytest.raises(services.ProductIncomplete, match='evidence for key judgement 1'):
        services.publish_product(db, case_id)


def test_a_published_version_is_kept_exactly_as_it_was(db: Session) -> None:
    case_id, _, _ = filled(db)
    services.rate_source(db, SourceRatingInput(source_name='Vendor', reliability='B'))
    first = services.publish_product(db, case_id)
    assert (first.version, first.tlp) == (1, 'GREEN')
    services.update_case(db, case_id, CaseUpdate(bluf='Changed after publishing.'))
    services.publish_product(db, case_id)
    kept = services.product_view(db, case_id, version=1)
    assert (kept['version'], kept['bluf']) == (1, 'Expect more edge appliance exploitation this quarter.')
    assert services.product_view(db, case_id)['bluf'] == 'Changed after publishing.'
    assert [v.version for v in services.product_parts(db, case_id).versions] == [2, 1]
    sources = {s['kind']: s for s in kept['sources']}
    cited = sources['document']
    assert (cited['n'], cited['reliability'], cited['credibility']) == (1, 'B', 6)
    assert sources['indicator']['name'] == '203.0.113.40'
    assert kept['judgements'][0]['sources'] == [1, 2]
    with pytest.raises(LookupError):
        services.product_view(db, case_id, version=3)
    actions = list(db.scalars(select(AuditEvent.action).where(AuditEvent.object_id == case_id)))
    assert actions.count('case.publish') == 2


def test_a_reader_sees_only_versions_within_its_limit(db: Session) -> None:
    case_id, _, _ = filled(db)
    services.publish_product(db, case_id)
    services.add_gap(db, case_id, GapInput(question='Who else is TLP:AMBER affected?'))
    services.publish_product(db, case_id)  # version 2 is AMBER
    with pytest.raises(LookupError):
        services.product_view(db, case_id, max_tlp='GREEN')  # the product itself is AMBER now
    services.update_case(db, case_id, CaseUpdate(tlp='CLEAR'))
    assert services.get_case(db, case_id).tlp == 'AMBER'  # the AMBER gap keeps it there


def test_markdown_starts_and_ends_with_the_label_and_escapes_text(db: Session) -> None:
    case_id, _, _ = filled(db)
    services.update_case(db, case_id, CaseUpdate(title='Edge [link](http://evil.example) #1'))
    text = services.export_product(db, case_id, 'md').content
    lines = text.strip().splitlines()
    assert (lines[0], lines[-1]) == ('**TLP:GREEN**', '**TLP:GREEN**')
    assert '# Edge \\[link\\](http://evil.example) \\#1' in text
    assert (
        '1. **Likely** (55-80%), moderate confidence: The crew will keep exploiting edge appliances. [1] [2]'
        in text
    )
    assert 'First paragraph.\n\nSecond paragraph.' in text
    assert '- Which appliances in our estate are exposed?' in text
    assert '1. [F6] [Vendor advisory]' not in text  # no URL: the title is plain text
    assert '1. [F6] Vendor advisory, Vendor, added ' in text
    assert 'Draft, not published' in text


def test_stix_has_a_report_with_judgements_as_notes(db: Session) -> None:
    case_id, _, _ = filled(db)
    services.publish_product(db, case_id)
    exported = services.export_product(db, case_id, 'stix', version=1)
    bundle = json.loads(exported.content)
    assert exported.filename.endswith('-v1.json')
    by_type: dict[str, list[dict[str, Any]]] = {}
    for obj in bundle['objects']:
        by_type.setdefault(obj['type'], []).append(obj)
    (report_obj,) = by_type['report']
    assert report_obj['name'] == 'Edge appliance exploitation'
    assert report_obj['description'].startswith('Expect more edge appliance exploitation')
    assert {r['source_name'] for r in report_obj['external_references']} == {'Insight product', 'Vendor'}
    key, gap = sorted(by_type['note'], key=lambda n: n['abstract'])[::-1]
    assert key['abstract'] == 'Key judgement 1: Likely (55-80%), moderate confidence'
    assert (key['confidence'], key['x_insight_likelihood']) == (50, 'likely')
    assert key['object_refs'][0] == report_obj['id']
    assert key['object_refs'][1] == by_type['indicator'][0]['id']
    assert gap['labels'] == ['intelligence-gap']
    again = json.loads(services.export_product(db, case_id, 'stix', version=1).content)
    assert {o['id'] for o in again['objects']} == {o['id'] for o in bundle['objects']}  # stable for a version
    with pytest.raises(ValueError, match='Nothing to export yet'):
        services.export_product(db, product(db, title='Empty'), 'stix')
