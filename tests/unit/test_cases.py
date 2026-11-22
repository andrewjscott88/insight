"""Cases (TIP 3.8, ADR 0029): collect reports, indicators, actors, campaigns and notes; TLP is the most
restrictive item and never drops by itself; closed cases do not change; deletions clean up."""

from __future__ import annotations

import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from insight import services
from insight.models import Case, CaseItem, Document, Entity
from insight.schemas import (
    ActorInput,
    CampaignInput,
    CaseCloseInput,
    CaseInput,
    CaseItemInput,
    CaseNoteInput,
    CaseUpdate,
    DocumentInput,
)
from insight.services import CaseClosed, TlpNotPermitted


def report(db: Session, title: str, body: str, tlp: str = 'GREEN') -> str:
    doc, _ = services.ingest(db, DocumentInput(title=title, body=body, source_name='S', tlp=tlp))
    return doc.id


def entity(db: Session, value: str) -> str:
    found: str = db.scalars(select(Entity.id).where(Entity.value == value)).one()
    return found


def item(kind: str, target: str, tlp: str = 'CLEAR') -> CaseItemInput:
    return CaseItemInput.model_validate({'kind': kind, 'target_id': target, 'tlp': tlp})


def opened(db: Session, title: str = 'Gateway intrusion', tlp: str = 'GREEN') -> str:
    return services.create_case(db, CaseInput.model_validate({'title': title, 'tlp': tlp})).id


def test_a_case_collects_two_reports_and_an_indicator_shows_its_timeline_and_closes(db: Session) -> None:
    first = report(db, 'Gateway advisory', 'Beacon to 192.0.2.10.')
    second = report(db, 'Follow-up', 'Also 192.0.2.10 and evil-one.net.')
    case_id = opened(db)
    services.add_case_item(db, case_id, item('document', first))
    services.add_case_item(db, case_id, item('document', second))
    added = services.add_case_item(db, case_id, item('indicator', entity(db, '192.0.2.10')))
    assert (added.kind, added.name, added.tlp) == ('indicator', '192.0.2.10', 'GREEN')
    services.add_case_note(db, case_id, CaseNoteInput(text='Firewall logs requested.'))
    services.close_case(db, case_id, CaseCloseInput(note='Contained; gateway patched.'))
    view = services.get_case(db, case_id)
    assert (view.status, view.close_note, view.tlp) == ('closed', 'Contained; gateway patched.', 'GREEN')
    assert view.closed_at is not None
    assert [(i.kind, i.name) for i in view.items] == [
        ('document', 'Gateway advisory'),
        ('document', 'Follow-up'),
        ('indicator', '192.0.2.10'),
        ('note', ''),
    ]
    assert view.items[-1].note == 'Firewall logs requested.'
    actions = [e.action for e in services.case_timeline(db, case_id)]
    assert actions == [
        'case.open',
        'case.item.add',
        'case.item.add',
        'case.item.add',
        'case.note',
        'case.close',
    ]
    assert all(e.actor for e in services.case_timeline(db, case_id))


def test_the_label_is_the_most_restrictive_item_and_unlinking_keeps_it(db: Session) -> None:
    green = report(db, 'Green', 'x 192.0.2.1')
    amber = report(db, 'Amber', 'y 192.0.2.2', tlp='AMBER')
    case_id = opened(db, tlp='CLEAR')
    services.add_case_item(db, case_id, item('document', green))
    assert services.get_case(db, case_id).tlp == 'GREEN'
    amber_item = services.add_case_item(db, case_id, item('document', amber))
    assert services.get_case(db, case_id).tlp == 'AMBER'
    services.remove_case_item(db, case_id, amber_item.id)
    assert services.get_case(db, case_id).tlp == 'AMBER'  # the summary may mention it
    # An explicit change may lower it again, but never below what the case still holds.
    services.update_case(db, case_id, CaseUpdate(tlp='CLEAR'))
    assert services.get_case(db, case_id).tlp == 'GREEN'
    services.update_case(db, case_id, CaseUpdate(summary='TLP:RED source names inside.'))
    assert services.get_case(db, case_id).tlp == 'RED'
    # A raised item label sticks to the item; a note's markings raise its label.
    raised = services.add_case_item(db, case_id, item('indicator', entity(db, '192.0.2.1'), 'AMBER'))
    assert raised.tlp == 'AMBER'
    note = services.add_case_note(db, case_id, CaseNoteInput(text='TLP:AMBER+STRICT detail', tlp='GREEN'))
    assert note.tlp == 'AMBER+STRICT'


def test_adding_the_same_target_twice_changes_nothing(db: Session) -> None:
    doc = report(db, 'Once', 'x')
    case_id = opened(db)
    first = services.add_case_item(db, case_id, item('document', doc))
    again = services.add_case_item(db, case_id, item('document', doc))
    assert first.id == again.id
    assert len(services.get_case(db, case_id).items) == 1
    actions = [e.action for e in services.case_timeline(db, case_id)]
    assert actions.count('case.item.add') == 1


def test_a_limited_reader_sees_only_cases_and_targets_within_its_limit(db: Session) -> None:
    amber_doc = report(db, 'Partner', 'z', tlp='AMBER')
    green_case = opened(db, 'Green case')
    amber_case = opened(db, 'Amber case', tlp='AMBER')
    assert [c.title for c in services.list_cases(db, max_tlp='GREEN')] == ['Green case']
    with pytest.raises(LookupError):
        services.get_case(db, amber_case, max_tlp='GREEN')
    with pytest.raises(LookupError):  # the report is hidden from this reader
        services.add_case_item(db, green_case, item('document', amber_doc), max_tlp='GREEN')
    with pytest.raises(TlpNotPermitted):
        services.add_case_note(db, green_case, CaseNoteInput(text='x', tlp='AMBER'), max_tlp='GREEN')
    with pytest.raises(TlpNotPermitted):
        services.create_case(db, CaseInput(title='x', tlp='RED'), max_tlp='AMBER')


def test_a_closed_case_does_not_change_until_reopened(db: Session) -> None:
    doc = report(db, 'Doc', 'x')
    case_id = opened(db)
    services.close_case(db, case_id, CaseCloseInput(note='Done.'))
    with pytest.raises(CaseClosed):
        services.add_case_item(db, case_id, item('document', doc))
    with pytest.raises(CaseClosed):
        services.update_case(db, case_id, CaseUpdate(title='New'))
    services.reopen_case(db, case_id)
    services.add_case_item(db, case_id, item('document', doc))
    view = services.get_case(db, case_id)
    assert (view.status, view.closed_at, len(view.items)) == ('open', None, 1)
    assert [c.id for c in services.list_cases(db, status='open')] == [case_id]
    assert services.list_cases(db, status='closed') == []


def test_actors_and_campaigns_can_be_added_and_deletions_clean_up(db: Session) -> None:
    doc = report(db, 'Doc', 'Beacon to 192.0.2.10.')
    actor = services.create_actor(db, ActorInput(name='Copper Fox', tlp='GREEN'))
    campaign = services.create_campaign(db, CampaignInput(name='Winter Wave', tlp='GREEN'))
    case_id = opened(db)
    for kind, target in (('document', doc), ('actor', actor.id), ('campaign', campaign.id)):
        services.add_case_item(db, case_id, item(kind, target))
    assert {i.name for i in services.get_case(db, case_id).items} == {'Doc', 'Copper Fox', 'Winter Wave'}
    holding = services.list_cases(db, status='all', holding=('actor', actor.id))
    assert [c.id for c in holding] == [case_id]
    services.delete_document(db, doc, reason='test')
    db.flush()
    db.expire_all()
    assert {i.kind for i in services.get_case(db, case_id).items} == {'actor', 'campaign'}
    services.delete_case(db, case_id)
    db.flush()
    assert db.scalar(select(func.count()).select_from(CaseItem)) == 0
    assert db.scalar(select(func.count()).select_from(Case)) == 0
    assert db.get(type(actor), actor.id) is not None  # the actor itself stays
    actions = [e.action for e in services.audit_events(db) if e.object_id == case_id]
    assert 'case.delete' in actions


def test_counts_leave_notes_out_and_bad_targets_are_refused(db: Session) -> None:
    doc = report(db, 'Doc', 'x')
    case_id = opened(db)
    services.add_case_item(db, case_id, item('document', doc))
    services.add_case_note(db, case_id, CaseNoteInput(text='note'))
    [summary] = services.list_cases(db)
    assert summary.items == 1
    for kind in ('document', 'indicator', 'actor', 'campaign'):
        with pytest.raises(LookupError):
            services.add_case_item(db, case_id, item(kind, 'missing'))
    with pytest.raises(LookupError):
        services.remove_case_item(db, case_id, 'missing')
    assert db.get(Document, doc) is not None
