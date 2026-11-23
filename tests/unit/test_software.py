"""Software links remain explicit, audited and bounded by both endpoints' sharing labels."""

from __future__ import annotations

import json

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from insight import services
from insight.models import AuditEvent, SoftwareDocument
from insight.schemas import (
    ActorInput,
    CampaignInput,
    DocumentInput,
    SoftwareLinkInput,
    ThreatLinkInput,
    ThreatSubjectKind,
)
from insight.threat_library import library


def _report(db: Session, body: str = 'Cobalt Strike used 192.0.2.4.', tlp: str = 'CLEAR') -> str:
    return services.ingest(
        db,
        DocumentInput.model_validate(
            {
                'title': 'Synthetic report',
                'source_name': 'Lab',
                'body': body,
                'tlp': tlp,
            }
        ),
    )[0].id


def test_catalog_search_and_candidates_make_no_links(db: Session) -> None:
    doc = _report(db)
    _report(db, 'Cobalt Striker is a different name.')
    _report(db, 'Cobalt Strike secret-marker', 'AMBER')
    assert services.search_software(q='Cobalt', limit=1, max_tlp='CLEAR')[0]['id'] == 'S0154'
    assert services.search_software(q='not-a-catalog-entry', max_tlp='CLEAR') == []
    found = services.software_detail(db, 's0154', max_tlp='GREEN')
    assert [r['document_id'] for r in found['candidates']] == [doc]
    assert not found['reports']
    assert not found['uses']
    assert db.scalar(select(SoftwareDocument)) is None
    assert 'secret-marker' not in json.dumps(found)
    with pytest.raises(LookupError):
        services.software_detail(db, 'S999999')


def test_link_label_audit_idempotence_and_removal(db: Session) -> None:
    doc = _report(db)
    services.set_actor(db, 'test-operator')
    payload = SoftwareLinkInput(document_id=doc, note='Relevant report', tlp='GREEN')
    row = services.link_software_report(db, 's0154', payload, max_tlp='GREEN')
    assert row.actor == 'test-operator'
    assert services.link_software_report(db, 'S0154', payload, max_tlp='GREEN').id == row.id
    assert len(list(db.scalars(select(AuditEvent).where(AuditEvent.action == 'software.link')))) == 1
    assert services.report_software(db, doc, max_tlp='GREEN')[0]['tlp'] == 'GREEN'
    assert not services.software_detail(db, 'S0154', max_tlp='GREEN')['candidates']
    services.link_software_report(db, 'S0154', SoftwareLinkInput(document_id=doc, tlp='CLEAR'))
    assert row.tlp == 'GREEN'
    services.unlink_software_report(db, 's0154', doc, max_tlp='GREEN')
    db.flush()
    assert services.software_reports(db, 'S0154', max_tlp='GREEN') == []
    with pytest.raises(LookupError):
        services.unlink_software_report(db, 'S0154', doc, max_tlp='GREEN')


def test_hidden_report_or_link_is_missing_and_above_limit_write_refused(db: Session) -> None:
    """Regression: a public catalog entry must not disclose a private link or its analyst note."""
    public = _report(db)
    private = _report(db, 'Cobalt Strike private report', 'AMBER')
    services.link_software_report(db, 'S0154', SoftwareLinkInput(document_id=public, note='TLP:AMBER secret'))
    services.link_software_report(db, 'S0154', SoftwareLinkInput(document_id=private))
    assert services.software_reports(db, 'S0154', max_tlp='GREEN') == []
    assert services.report_software(db, public, max_tlp='GREEN') == []
    assert services.software_detail(db, 'S0154', max_tlp='GREEN')['candidates'][0]['document_id'] == public
    for doc in (public, private):
        with pytest.raises(LookupError):
            services.link_software_report(db, 'S0154', SoftwareLinkInput(document_id=doc), max_tlp='GREEN')
        with pytest.raises(LookupError):
            services.unlink_software_report(db, 'S0154', doc, max_tlp='GREEN')
    with pytest.raises(services.TlpNotPermitted):
        services.link_software_report(
            db, 'S0154', SoftwareLinkInput(document_id=public, note='TLP:RED'), max_tlp='GREEN'
        )


@pytest.mark.parametrize('kind', ['actor', 'campaign'])
def test_explicit_uses_retirement_and_hidden_decisions(
    db: Session, kind: ThreatSubjectKind, monkeypatch: pytest.MonkeyPatch
) -> None:
    actor = services.create_actor(db, ActorInput(name='Synthetic actor', tlp='CLEAR'))
    campaign = services.create_campaign(db, CampaignInput(name='Synthetic campaign', tlp='CLEAR'))
    subject_kind = kind
    ref = actor.id if kind == 'actor' else campaign.id
    payload = ThreatLinkInput(target_kind='software', target_id='S0154', tlp='AMBER')
    services.link_threat(db, subject_kind, ref, payload)
    assert services.software_uses(db, 'S0154', max_tlp='GREEN') == []
    assert services.list_threat_links(db, subject_kind, ref, max_tlp='GREEN') == []
    with pytest.raises(LookupError):
        services.unlink_threat(db, subject_kind, ref, 'software', 'S0154', max_tlp='GREEN')
    monkeypatch.delitem(library().software, 'S0154')
    assert services.list_threat_links(db, subject_kind, ref)[0].name == 'Cobalt Strike'
    assert services.software_detail(db, 'S0154')['retired']
    with pytest.raises(LookupError):
        services.software_detail(db, 'S0154', max_tlp='GREEN')
    services.unlink_threat(db, subject_kind, ref, 'software', 's0154')
    db.flush()
    assert not services.list_threat_links(db, subject_kind, ref)


def test_retired_report_link_remains_visible_and_removable(
    db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Regression: a catalog update must not strand an analyst's saved software association."""
    doc = _report(db)
    services.link_software_report(db, 'S0154', SoftwareLinkInput(document_id=doc))
    monkeypatch.delitem(library().software, 'S0154')
    assert services.report_software(db, doc, max_tlp='CLEAR')[0]['retired']
    assert services.software_detail(db, 'S0154', max_tlp='CLEAR')['name'] == 'Cobalt Strike'
    services.unlink_software_report(db, 'S0154', doc, max_tlp='CLEAR')
    db.flush()
    with pytest.raises(LookupError):
        services.software_detail(db, 'S0154', max_tlp='CLEAR')


def test_report_retention_removes_software_links(db: Session) -> None:
    doc = _report(db)
    services.link_software_report(db, 'S0154', SoftwareLinkInput(document_id=doc))
    services.delete_document(db, doc, reason='Synthetic retention test')
    assert db.scalar(select(SoftwareDocument)) is None


def test_candidates_exclude_links_beyond_first_page(db: Session) -> None:
    """Regression: the 51st saved report must not reappear as an unlinked name-match candidate."""
    for index in range(51):
        doc = _report(db, f'Cobalt Strike report {index}.')
        services.link_software_report(db, 'S0154', SoftwareLinkInput(document_id=doc))
    detail = services.software_detail(db, 'S0154', max_tlp='GREEN')
    assert len(detail['reports']) == 50
    assert detail['candidates'] == []


def test_scan_count_keeps_nonmatching_report_labels(db: Session) -> None:
    """Regression: a count influenced by a private report must not be labelled as public metadata."""
    _report(db)
    before = services.software_detail(db, 'S0154', max_tlp='GREEN')
    _report(db, 'No software name appears in this private report.', 'AMBER')
    assert services.software_detail(db, 'S0154', max_tlp='GREEN') == before
    full = services.software_detail(db, 'S0154')
    assert full['candidates'] == before['candidates']
    assert full['reports_scanned'] == before['reports_scanned'] + 1
    assert full['tlp'] == 'AMBER'
