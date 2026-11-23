"""ATT&CK technique tags on reports: from the text, from analysts, across revisions (ADR 0019)."""

from __future__ import annotations

import pytest
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from insight import services
from insight.attack import Domain, catalog
from insight.models import AuditEvent, Document, DocumentTechnique
from insight.schemas import DocumentInput
from insight.services import SourceRef, ingest

REF = SourceRef('ncsc', 'item-1')


def report(db: Session, body: str, *, ref: SourceRef | None = None, tlp: str = 'GREEN') -> Document:
    doc, _ = ingest(
        db,
        DocumentInput.model_validate({'title': 'R', 'body': body, 'source_name': 'S', 'tlp': tlp}),
        ref=ref,
    )
    return doc


def tags(db: Session, doc: Document) -> dict[str, str]:
    return {t.technique_id: t.source for t in services.document_techniques(db, doc.id)}


def actions(db: Session) -> list[tuple[str, str, str]]:
    stmt = select(AuditEvent).where(AuditEvent.action.like('technique.%'))
    return [(e.action, e.object_id, e.detail) for e in db.scalars(stmt)]


def test_techniques_written_in_a_report_are_tagged_with_their_context(db: Session) -> None:
    doc = report(db, 'Phishing (T1566.001) delivered a loader; then T1059.001 and T9999 (not real).')
    (first, second) = services.document_techniques(db, doc.id)
    assert (first.technique_id, first.source, first.in_catalog) == ('T1059.001', 'report', True)
    assert first.name == 'Command and Scripting Interpreter: PowerShell'
    assert first.tactics == ('Execution',)
    assert 'T1059.001' in first.evidence
    assert second.technique_id == 'T1566.001'
    assert actions(db) == []  # reading the text is not an analyst action


def test_analysts_add_and_remove_techniques_with_an_audit_trail(db: Session) -> None:
    doc = report(db, 'Loader used T1059.001.')
    services.set_actor(db, 'operator')
    added = services.tag_technique(db, doc.id, 't1486')
    assert (added.technique_id, added.source, added.actor) == ('T1486', 'analyst', 'operator')
    services.tag_technique(db, doc.id, 'T1486')  # already tagged: nothing changes, nothing is audited
    services.untag_technique(db, doc.id, 'T1059.001')
    assert tags(db, doc) == {'T1486': 'analyst'}
    services.tag_technique(db, doc.id, 'T1059.001')  # restoring a removed report tag
    assert tags(db, doc) == {'T1059.001': 'report', 'T1486': 'analyst'}
    assert sorted(actions(db)) == [
        ('technique.tag', doc.id, 'T1059.001'),
        ('technique.tag', doc.id, 'T1486'),
        ('technique.untag', doc.id, 'T1059.001'),
    ]


def test_bad_tags_are_refused(db: Session) -> None:
    doc = report(db, 'Nothing mapped.')
    with pytest.raises(ValueError, match='Not a current ATT&CK technique'):
        services.tag_technique(db, doc.id, 'T9999')
    with pytest.raises(LookupError):
        services.tag_technique(db, 'missing', 'T1486')
    with pytest.raises(LookupError, match='not tagged'):
        services.untag_technique(db, doc.id, 'T1486')


def test_a_limited_reader_cannot_see_or_change_tags_on_hidden_reports(db: Session) -> None:
    amber = report(db, 'Ransomware: T1486.', tlp='AMBER')
    with pytest.raises(LookupError):
        services.document_techniques(db, amber.id, max_tlp='GREEN')
    with pytest.raises(LookupError):
        services.tag_technique(db, amber.id, 'T1490', max_tlp='GREEN')
    with pytest.raises(LookupError):
        services.untag_technique(db, amber.id, 'T1486', max_tlp='GREEN')
    assert services.technique_summary(db, max_tlp='GREEN') == []
    assert services.technique_documents(db, 'T1486', max_tlp='GREEN') == []
    assert [c.technique_id for c in services.technique_summary(db)] == ['T1486']


def test_a_new_revision_keeps_the_analysts_decisions(db: Session) -> None:
    first = report(db, 'v1 maps T1059.001.', ref=REF)
    services.tag_technique(db, first.id, 'T1486')  # added by hand
    services.untag_technique(db, first.id, 'T1059.001')  # judged wrong
    second = report(db, 'v2 still says T1059.001, and adds T1566.001.', ref=REF)
    assert second.supersedes_id == first.id
    assert tags(db, second) == {'T1486': 'analyst', 'T1566.001': 'report'}
    removed = db.scalar(
        select(DocumentTechnique).where(
            DocumentTechnique.document_id == second.id, DocumentTechnique.technique_id == 'T1059.001'
        )
    )
    assert removed is not None
    assert removed.status == 'removed'


def test_a_reverted_revision_gets_the_later_decisions(db: Session) -> None:
    first = report(db, 'v1 maps T1059.001.', ref=REF)
    second = report(db, 'v2 maps T1059.001 and T1566.001.', ref=REF)
    services.tag_technique(db, second.id, 'T1486')
    services.untag_technique(db, second.id, 'T1059.001')
    report(db, 'v1 maps T1059.001.', ref=REF)  # the publisher reverted
    db.refresh(first)
    assert first.is_current
    assert tags(db, first) == {'T1486': 'analyst'}


def test_the_summary_counts_current_reports_and_can_be_limited_in_time(db: Session) -> None:
    report(db, 'Old item T1059.001.', ref=REF)
    report(db, 'New item T1059.001 and T1486.', ref=REF)  # replaces the old one: counted once
    report(db, 'Another T1486.')
    other = report(db, 'Third T1486.')
    summary = services.technique_summary(db)
    assert [(c.technique_id, c.reports) for c in summary] == [('T1486', 3), ('T1059.001', 1)]
    assert summary[0].last_seen == other.created_at
    assert services.technique_summary(db, since='2999-01-01') == []
    pages = [d.id for d in services.technique_documents(db, 'T1486', limit=2)]
    assert len(pages) == 2
    assert pages[0] == other.id  # newest first


def test_domain_summary_keeps_retired_tags_without_assigning_them_to_a_new_domain(db: Session) -> None:
    """Regression: selecting a domain made all previously stored retired technique tags disappear."""
    doc = report(db, 'T1486 plus T1636 and T0801.', tlp='CLEAR')
    hidden = report(db, 'Restricted retired mapping.', tlp='AMBER')
    for document, tid in ((doc, 'T9999'), (hidden, 'T9998')):
        db.add(
            DocumentTechnique(
                document_id=document.id, technique_id=tid, source='analyst', status='tagged', actor='test'
            )
        )
    db.flush()
    enterprise = services.technique_summary(db, domain='enterprise', max_tlp='GREEN')
    assert {row.technique_id for row in enterprise} == {'T1486', 'T9999'}
    domains: tuple[tuple[Domain, str], ...] = (('mobile', 'T1636'), ('ics', 'T0801'))
    for domain, expected in domains:
        rows = services.technique_summary(db, domain=domain, max_tlp='GREEN')
        assert {row.technique_id for row in rows} == {expected}
    layer = services.navigator_layer(enterprise, period='all time')
    assert [row['techniqueID'] for row in layer['techniques']] == ['T1486']


def test_the_navigator_layer_scores_techniques_by_reports(db: Session) -> None:
    report(db, 'T1486 and T1059.001.')
    report(db, 'T1486 again.')
    layer = services.navigator_layer(services.technique_summary(db), period='last 30 days')
    assert layer['versions']['layer'] == '4.5'
    assert layer['versions']['attack'] == catalog().version
    assert layer['domain'] == 'enterprise-attack'
    assert layer['gradient']['maxValue'] == 2
    assert [(t['techniqueID'], t['score']) for t in layer['techniques']] == [('T1486', 2), ('T1059.001', 1)]
    assert 'The MITRE Corporation' in layer['metadata'][1]['value']
    assert services.navigator_layer([], period='all time')['techniques'] == []


def test_backfill_tags_reports_stored_before_tagging_existed(db: Session) -> None:
    doc = report(db, 'Old report naming T1486.')
    db.execute(delete(DocumentTechnique))  # as stored by 0.6.0
    assert services.backfill_techniques(db) == (1, 1)
    assert tags(db, doc) == {'T1486': 'report'}
    assert services.backfill_techniques(db) == (0, 0)  # already tagged reports are left alone


def test_deleting_a_report_deletes_its_tags(db: Session) -> None:
    doc = report(db, 'T1486.')
    services.tag_technique(db, doc.id, 'T1059.001')
    services.delete_document(db, doc.id, 'test')
    assert db.scalars(select(DocumentTechnique)).all() == []
