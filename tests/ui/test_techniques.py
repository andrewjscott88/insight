"""MITRE ATT&CK techniques in the workspace: the reader's section, the add dialog and the techniques tab."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from nicegui import ui
from nicegui.testing.user import User
from sqlalchemy import select

from insight.models import AuditEvent, DocumentTechnique
from insight.schemas import DocumentInput
from insight.services import ingest
from insight.ui.techniques import DIALOG_TITLE

from .test_verdicts import open_report

pytestmark = pytest.mark.ui


def add_report(env: SimpleNamespace, title: str, body: str) -> None:
    with env.app.state.session_factory.begin() as db:
        ingest(db, DocumentInput(title=title, body=body, source_name='S', tlp='GREEN'))


def tags(env: SimpleNamespace) -> set[tuple[str, str, str]]:
    with env.app.state.session_factory() as db:
        rows = db.scalars(select(DocumentTechnique))
        return {(r.technique_id, r.source, r.status) for r in rows}


def actions(env: SimpleNamespace) -> list[str]:
    with env.app.state.session_factory() as db:
        return sorted(db.scalars(select(AuditEvent.action).where(AuditEvent.action.like('technique.%'))))


async def test_the_reader_shows_techniques_written_in_the_report(user: User, ui_env: SimpleNamespace) -> None:
    add_report(ui_env, 'Ransom report', 'The group encrypted file servers (T1486).')
    await open_report(user, 'Ransom report')
    await user.should_see('ATT&CK techniques (1)')
    await user.should_see('Data Encrypted for Impact')
    await user.should_see('Tactic: Impact')
    await user.should_see('The report names it here:')
    await user.should_see('About T1486 on the ATT&CK site')


async def test_an_analyst_adds_a_technique_by_searching(user: User, ui_env: SimpleNamespace) -> None:
    add_report(ui_env, 'Phishing report', 'Staff got mail with a macro document attached.')
    await open_report(user, 'Phishing report')
    await user.should_see('ATT&CK techniques (0)')
    await user.should_see('No techniques on this report yet.')
    user.find(kind=ui.button, content='Add a technique').click()
    await user.should_see(DIALOG_TITLE)
    await user.should_see('Start typing to see matching techniques.')
    user.find(kind=ui.input, content='Technique ID or name').type('spearphishing attach')
    user.find(kind=ui.button, content='T1566.001 · Phishing: Spearphishing Attachment').click()
    await user.should_see('T1566.001 added to this report.')
    await user.should_see('ATT&CK techniques (1)')
    await user.should_see('Added by operator on')
    assert tags(ui_env) == {('T1566.001', 'analyst', 'tagged')}
    assert actions(ui_env) == ['technique.tag']


async def test_a_search_with_no_match_says_so(user: User, ui_env: SimpleNamespace) -> None:
    add_report(ui_env, 'Quiet report', 'Nothing to map.')
    await open_report(user, 'Quiet report')
    user.find(kind=ui.button, content='Add a technique').click()
    user.find(kind=ui.input, content='Technique ID or name').type('zzzz')
    await user.should_see('No technique matches. Try fewer letters.')


async def test_an_analyst_removes_a_wrong_technique(user: User, ui_env: SimpleNamespace) -> None:
    add_report(ui_env, 'Mapped report', 'The loader used PowerShell (T1059.001) and encrypted files (T1486).')
    await open_report(user, 'Mapped report')
    await user.should_see('ATT&CK techniques (2)')
    user.find(marker='remove-T1059.001').click()
    await user.should_see('T1059.001 removed. A new version of this report will not add it again.')
    await user.should_see('ATT&CK techniques (1)')
    assert tags(ui_env) == {('T1059.001', 'report', 'removed'), ('T1486', 'report', 'tagged')}
    assert actions(ui_env) == ['technique.untag']


async def test_the_tab_groups_techniques_by_tactic_and_opens_the_reports(
    user: User, ui_env: SimpleNamespace
) -> None:
    add_report(ui_env, 'First ransom report', 'Files were encrypted (T1486).')
    add_report(ui_env, 'Second ransom report', 'Encryption again (T1486), after PowerShell (T1059.001).')
    await user.open('/')
    await user.should_see('Uses version')
    await user.should_see('Impact (1)')
    await user.should_see('Execution (1)')
    await user.should_see('T1486 · Data Encrypted for Impact · 2 report(s)')
    await user.should_see('Download a layer for ATT&CK Navigator')
    await user.should_not_see('First ransom report · TLP:GREEN')  # loaded when the technique is opened
    user.find(kind=ui.expansion, content='T1486 · Data Encrypted for Impact').elements.pop().open()
    await user.should_see('First ransom report · TLP:GREEN')
    user.find(kind=ui.button, content='Second ransom report · TLP:GREEN').click()
    with user.scope(marker='document-detail'):
        await user.should_see('Second ransom report')


async def test_the_tab_period_filters_and_explains_an_empty_period(user: User, ui_env: SimpleNamespace) -> None:
    await user.open('/')
    await user.should_see('No report from this time has a technique yet. Open a report to add one.')
    add_report(ui_env, 'Ransom report', 'Files were encrypted (T1486).')
    user.find(kind=ui.select, content='Reports added in').elements.pop().set_value(0)
    await user.should_see('T1486 · Data Encrypted for Impact · 1 report(s)')
