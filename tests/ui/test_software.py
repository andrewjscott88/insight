"""An analyst reviews a software candidate before adding or removing a labelled link."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from nicegui import ui
from nicegui.testing.user import User

from insight import services

from .test_navigation import tabs
from .test_threats import add_report

pytestmark = pytest.mark.ui


async def test_software_candidate_and_explicit_link(user: User, ui_env: SimpleNamespace) -> None:
    """Regression: opening software evidence must close its dialog and switch to the correct Triage report."""
    add_report(ui_env, 'Synthetic software note', 'Cobalt Strike used 192.0.2.81.')
    await user.open('/')
    menu, investigate = tabs(user)
    menu.set_value('investigate')
    investigate.set_value('groups')
    await user.should_see('Software library')
    user.find(kind=ui.expansion, content='Software library').elements.pop().open()
    await user.should_see('Software name or ID')
    user.find(kind=ui.input, content='Software name or ID').type('Cobalt')
    await user.should_see('Cobalt Strike (S0154)')
    user.find(kind=ui.button, content='Cobalt Strike (S0154)').click()
    await user.should_see('Reports that name it')
    await user.should_see('Link this report')
    with ui_env.app.state.session_factory() as db:
        assert services.software_reports(db, 'S0154') == []
    user.find(kind=ui.button, content='Link this report').click()
    await user.should_see('Why this report is about the software')
    user.find(kind=ui.textarea, content='Why this report is about the software').type('Reviewed the report.')
    user.find(kind=ui.button, content='Save software link').click()
    await user.should_see('Reviewed the report.')
    await user.should_see('Remove software link')
    user.find(kind=ui.button, content='Remove software link').click()
    await user.should_see('No saved report links.')
    software_dialog = user.find(marker='software-detail').elements.pop()
    assert isinstance(software_dialog, ui.dialog)
    with user.scope(marker='software-detail'):
        user.find(kind=ui.button, content='Synthetic software note').click()
    with user.scope(marker='document-detail'):
        await user.should_see('Synthetic software note')
        await user.should_see('Software links')
    assert menu.value == 'triage'
    assert not software_dialog.value
