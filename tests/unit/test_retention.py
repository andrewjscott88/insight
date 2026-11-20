"""Deleting a report (review finding C4): what goes with it, the revision chain and the audit trail."""

from __future__ import annotations

import json

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from insight import services
from insight.models import AuditEvent, Document, Entity, EntityAssessment, Note, Observation
from insight.schemas import AssessmentInput, DocumentInput
from insight.services import SourceRef, ingest

REF = SourceRef('ncsc', 'item-1')


def report(db: Session, body: str, *, ref: SourceRef | None = None, title: str = 'Report') -> Document:
    doc, _ = ingest(db, DocumentInput(title=title, body=body, source_name='S'), ref=ref)
    return doc


def entity_id(db: Session, value: str) -> str | None:
    return db.scalar(select(Entity.id).where(Entity.value == value))


def assess(db: Session, value: str, verdict: str) -> None:
    found = entity_id(db, value)
    assert found
    services.assess_entity(db, found, AssessmentInput(verdict=verdict))


def test_a_report_goes_with_everything_only_it_held(db: Session) -> None:
    gone = report(db, 'Beacons to evil-one.net and shared-host.net', title='Victim: Example Ltd')
    kept = report(db, 'Also seen: shared-host.net')
    services.add_note(db, gone.id, 'Called the victim.')
    assess(db, 'evil-one.net', 'malicious')
    assess(db, 'shared-host.net', 'suspicious')
    services.set_actor(db, 'cli')

    result = services.delete_document(db, gone.id, '  ticket 42: retention period ended ')

    assert (result.observations, result.notes, result.entities, result.verdicts) == (2, 1, 1, 1)
    assert result.now_current is None
    assert db.get(Document, gone.id) is None
    assert db.scalars(select(Observation.document_id)).all() == [kept.id]
    assert db.scalars(select(Note)).all() == []
    assert entity_id(db, 'evil-one.net') is None
    shared = entity_id(db, 'shared-host.net')
    assert shared
    assert db.get(EntityAssessment, shared) is not None, 'a verdict on a value still in use stays'
    event = db.scalars(select(AuditEvent).where(AuditEvent.action == 'document.delete')).one()
    assert (event.object_id, event.actor) == (gone.id, 'cli')
    detail = json.loads(event.detail)
    assert detail['reason'] == 'ticket 42: retention period ended'
    assert detail['content_hash'] == gone.content_hash
    assert 'Example Ltd' not in event.detail, 'the audit log keeps the hash, never the title or text'


def test_deleting_a_middle_revision_repairs_the_chain(db: Session) -> None:
    first = report(db, 'Version one, CVE-2024-0001', ref=REF)
    middle = report(db, 'Version two, CVE-2024-0002', ref=REF)
    last = report(db, 'Version three, CVE-2024-0003', ref=REF)
    assert (last.supersedes_id, middle.supersedes_id) == (middle.id, first.id)

    result = services.delete_document(db, middle.id, 'test')

    db.refresh(last)
    assert last.supersedes_id == first.id
    assert last.is_current
    assert result.now_current is None


def test_deleting_the_current_revision_makes_the_previous_one_current(db: Session) -> None:
    first = report(db, 'Version one, CVE-2024-0001', ref=REF)
    second = report(db, 'Version two, CVE-2024-0002', ref=REF)

    result = services.delete_document(db, second.id, 'test')

    db.refresh(first)
    assert first.is_current
    assert result.now_current == first.id
    again = report(db, 'Version two, CVE-2024-0002', ref=REF)  # a later sync can add it back cleanly
    assert again.supersedes_id == first.id
    assert again.is_current


def test_an_item_never_ends_up_without_a_current_revision(db: Session) -> None:
    """A reactivated first revision has no predecessor; the newest remaining revision takes over."""
    first = report(db, 'Version one, CVE-2024-0001', ref=REF)
    second = report(db, 'Version two, CVE-2024-0002', ref=REF)
    report(db, 'Version one, CVE-2024-0001', ref=REF)  # the publisher reverted: first is current again
    db.refresh(first)
    assert first.is_current

    result = services.delete_document(db, first.id, 'test')

    db.refresh(second)
    assert second.is_current
    assert second.supersedes_id is None
    assert result.now_current == second.id


def test_the_preview_counts_what_would_go(db: Session) -> None:
    doc = report(db, 'Beacons to evil-one.net, CVE-2024-0001', ref=REF)
    report(db, 'Version two', ref=REF)
    services.add_note(db, doc.id, 'Note.')
    preview = services.deletion_preview(db, doc.id)
    assert preview is not None
    assert (preview.observations, preview.notes, preview.revisions, preview.is_current) == (2, 1, 1, False)
    assert services.deletion_preview(db, 'nope') is None


@pytest.mark.parametrize('reason', ['', '   ', 'x' * (services.MAX_REASON_LENGTH + 1)])
def test_a_reason_is_required(db: Session, reason: str) -> None:
    doc = report(db, 'Beacons to evil-one.net')
    with pytest.raises(ValueError, match='reason'):
        services.delete_document(db, doc.id, reason)
    assert db.get(Document, doc.id) is not None


def test_an_unknown_report_is_refused(db: Session) -> None:
    with pytest.raises(LookupError, match='no report with ID nope'):
        services.delete_document(db, 'nope', 'test')
