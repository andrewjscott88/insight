"""TIP 4.1 in the workspace: add a requirement, say what makes a report relevant, see the reports that address
it, cite one as evidence and answer it; and see, in the reader, which requirements a report addresses."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from nicegui import ui
from nicegui.testing.user import User
from sqlalchemy import select

from insight.models import AuditEvent, Requirement, RequirementEvidence
from insight.schemas import DocumentInput, RequirementInput, RfiInput
from insight.services import create_requirement, file_rfi, ingest

pytestmark = pytest.mark.ui


def add_report(env: SimpleNamespace, title: str, body: str, tlp: str = 'GREEN') -> None:
    with env.app.state.session_factory.begin() as db:
        ingest(db, DocumentInput(title=title, body=body, source_name='S', tlp=tlp))


async def test_a_requirement_is_added_given_criteria_cited_and_answered(
    user: User, ui_env: SimpleNamespace
) -> None:
    add_report(ui_env, 'Gateway advisory', 'Ransomware crews exploit CVE-2024-3400 on edge firewalls.')
    await user.open('/')
    user.find(marker='req-new').click()
    await user.should_see('New requirement')
    user.find(kind=ui.input, marker='req-question').type('Are ransomware groups exploiting our edge devices?')
    user.find(marker='req-save').click()
    await user.should_see('Requirement added. Now add what makes a report relevant to it.')
    await user.should_see('No criteria yet. Add one so that reports can match.')

    user.find(kind=ui.input, marker='req-criterion-value').type('CVE-2024-3400')
    for select_ in user.find(kind=ui.select).elements:  # The criterion kind starts on "term".
        if 'term' in getattr(select_, 'options', {}):
            select_.set_value('cve')
    user.find(marker='req-criterion-add').click()
    await user.should_see('Criterion added.')
    await user.should_see('cve: CVE-2024-3400')
    await user.should_see('Gateway advisory')
    user.find(kind=ui.button, content='Cite as evidence').click()
    await user.should_see('Cited as evidence.')
    user.find(kind=ui.textarea, marker='req-answer').type('Yes: one crew so far.')
    user.find(marker='req-answer-save').click()
    await user.should_see('Answer saved.')

    with ui_env.app.state.session_factory() as db:
        row = db.scalars(select(Requirement)).one()
        assert (row.kind, row.status, row.answer) == ('pir', 'open', 'Yes: one crew so far.')
        assert len(list(db.scalars(select(RequirementEvidence)))) == 1
        audited = select(AuditEvent).where(AuditEvent.action.like('requirement.%'))
        actions = [e.action for e in db.scalars(audited)]
    assert actions == [
        'requirement.create',
        'requirement.criterion.add',
        'requirement.evidence.add',
        'requirement.answer',
    ]


async def test_the_list_shows_coverage_nested_requirements_and_requests(
    user: User, ui_env: SimpleNamespace
) -> None:
    add_report(ui_env, 'Ransomware roundup', 'Ransomware notes for the week.')
    with ui_env.app.state.session_factory.begin() as db:
        pir = create_requirement(
            db,
            RequirementInput.model_validate(
                {'kind': 'pir', 'question': 'What are ransomware groups doing?', 'priority': 'high',
                 'criteria': [{'kind': 'term', 'value': 'ransomware'}]}
            ),
        )  # fmt: skip
        create_requirement(
            db,
            RequirementInput.model_validate(
                {'kind': 'ir', 'parent_id': pir.id, 'question': 'Who sells them access?',
                 'criteria': [{'kind': 'term', 'value': 'initial access broker'}]}
            ),
        )  # fmt: skip
        file_rfi(db, RfiInput(question='Is 203.0.113.70 known C2?', requester='Shift hunt team'))
    await user.open('/')
    await user.should_see('Priority requirements')
    await user.should_see('Requests for information')
    await user.should_see('High priority')
    await user.should_see('1 report in 30 days')
    await user.should_see('Quiet: no report in 30 days')
    await user.should_see('No criteria yet: add what makes a report relevant · for Shift hunt team')


async def test_the_reader_shows_which_requirements_a_report_addresses(
    user: User, ui_env: SimpleNamespace
) -> None:
    add_report(ui_env, 'Gateway advisory', 'Ransomware crews exploit edge firewalls.')
    with ui_env.app.state.session_factory.begin() as db:
        create_requirement(
            db,
            RequirementInput.model_validate(
                {'kind': 'pir', 'question': 'Are ransomware groups targeting us?',
                 'criteria': [{'kind': 'term', 'value': 'ransomware'}]}
            ),
        )  # fmt: skip
    await user.open('/')
    user.find(kind=ui.button, content='Gateway advisory').click()
    await user.should_see('Addresses your requirements')
    with user.scope(marker='report-requirements'):
        await user.should_see('Are ransomware groups targeting us?')
        await user.should_see('term: ransomware')
        user.find(kind=ui.button, content='Cite as evidence').click()
    await user.should_see('Cited as evidence.')
    with ui_env.app.state.session_factory() as db:
        assert len(list(db.scalars(select(RequirementEvidence)))) == 1
