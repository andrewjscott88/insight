"""TIP 3.8 in the workspace: open a case, add reports and indicators to it, note, close and reopen."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from nicegui import ui
from nicegui.testing.user import User
from sqlalchemy import select

from insight.models import AuditEvent, Case, CaseItem
from insight.schemas import DocumentInput
from insight.services import ingest

pytestmark = pytest.mark.ui


def add_report(env: SimpleNamespace, title: str, body: str, tlp: str = 'GREEN') -> None:
    with env.app.state.session_factory.begin() as db:
        ingest(db, DocumentInput(title=title, body=body, source_name='S', tlp=tlp))


async def test_a_case_is_opened_filled_from_the_reader_noted_and_closed(
    user: User, ui_env: SimpleNamespace
) -> None:
    add_report(ui_env, 'Gateway advisory', 'Beacon to 203.0.113.70 from the gateway.')
    await user.open('/')
    await user.should_see('Cases')
    user.find(marker='case-new').click()
    await user.should_see('Open a case')
    user.find(kind=ui.input, marker='case-title').type('Gateway intrusion')
    user.find(marker='case-save').click()
    await user.should_see('Case opened.')
    await user.should_see('Nothing yet. Use "Add to case" on a report or an indicator.')
    user.find(kind=ui.button, content='Done').click()

    user.find(kind=ui.button, content='Gateway advisory').click()
    with user.scope(marker='document-detail'):
        await user.should_see('Beacon to 203.0.113.70')
        user.find(marker='report-add-to-case').click()
    await user.should_see('Add to case')
    user.find(marker='case-add').click()
    await user.should_see('Added this report to the case.')

    with ui_env.app.state.session_factory() as db:
        case = db.scalars(select(Case)).one()
        assert [i.kind for i in db.scalars(select(CaseItem))] == ['document']
        assert case.tlp == 'AMBER'  # the default label; the GREEN report did not raise it
    await user.open('/')
    user.find(kind=ui.button, content='Gateway intrusion').click()
    await user.should_see('Report · Gateway advisory')
    user.find(kind=ui.textarea, marker='case-note').type('Asked for firewall logs.')
    user.find(marker='case-note-save').click()
    await user.should_see('Note added.')
    await user.should_see('Asked for firewall logs.')
    user.find(kind=ui.textarea, marker='case-close-note').type('Contained; gateway patched.')
    user.find(marker='case-close').click()
    await user.should_see('Case closed.')
    await user.should_see('Contained; gateway patched.')
    for event in ('Opened', 'Added a report', 'Added a note', 'Closed'):
        await user.should_see(event)
    user.find(marker='case-reopen').click()
    await user.should_see('Case reopened.')
    with ui_env.app.state.session_factory() as db:
        actions = [e.action for e in db.scalars(select(AuditEvent).where(AuditEvent.action.like('case.%')))]
    assert actions == ['case.open', 'case.item.add', 'case.note', 'case.close', 'case.reopen']


async def test_an_indicator_goes_into_a_new_case_from_the_entity_explorer(
    user: User, ui_env: SimpleNamespace
) -> None:
    add_report(ui_env, 'Partner note', 'C2 at 198.51.100.71.', tlp='AMBER')
    await user.open('/')
    user.find('Search entity values').type('198.51.100.71')
    name = 'IP · 198.51.100.71 · 1 source(s)'
    await user.should_see(kind=ui.expansion, content=name)
    user.find(kind=ui.expansion, content=name).elements.pop().open()
    await user.should_see(marker='entity-add-to-case-198.51.100.71')
    user.find(marker='entity-add-to-case-198.51.100.71').click()
    await user.should_see('Add to case')
    user.find(kind=ui.input, marker='case-new-title').type('Partner C2')
    user.find(marker='case-add').click()
    await user.should_see('Added this indicator to the case.')
    with ui_env.app.state.session_factory() as db:
        case = db.scalars(select(Case)).one()
        assert (case.title, case.tlp) == ('Partner C2', 'AMBER')  # the indicator is only in AMBER reports
        assert [i.kind for i in db.scalars(select(CaseItem))] == ['indicator']


async def test_deleting_a_case_asks_first(user: User, ui_env: SimpleNamespace) -> None:
    await user.open('/')
    user.find(marker='case-new').click()
    user.find(kind=ui.input, marker='case-title').type('Short-lived')
    user.find(marker='case-save').click()
    await user.should_see('Case opened.')
    user.find(marker='case-delete').click()
    await user.should_see('Delete this case and its notes? Its reports and indicators stay.')
    user.find(marker='case-delete-confirm').click()
    await user.should_see('Case deleted.')
    with ui_env.app.state.session_factory() as db:
        assert db.scalars(select(Case)).all() == []
