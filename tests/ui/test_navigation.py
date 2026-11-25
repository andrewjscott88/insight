"""The side menu: the workspace's sections, in the order of an analyst's day, and the links between them."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from nicegui import ui
from nicegui.testing.user import User

from insight.schemas import DocumentInput, RequirementInput
from insight.services import create_requirement, ingest
from insight.ui.page import INVESTIGATE, SECTIONS

pytestmark = pytest.mark.ui


def tabs(user: User) -> tuple[ui.tabs, ui.tabs]:
    """The side menu and Investigate's own tabs."""
    assert user.client is not None
    found = [e for e in user.client.layout.descendants() if isinstance(e, ui.tabs)]
    menu = next(t for t in found if 'side-tabs' in t.classes)
    investigate = next(t for t in found if 'evidence-tabs' in t.classes)
    return menu, investigate


def test_the_sections_follow_an_analysts_day() -> None:
    labels = ['Intel Brief', 'Triage', 'Investigate', 'Threat Hunt', 'Share', 'Settings']
    assert [label for _, label in SECTIONS] == labels
    assert [label for _, label in INVESTIGATE] == ['Indicators', 'CVEs', 'ATT&CK techniques', 'Threat groups']


async def test_the_workspace_opens_on_intel_brief_with_every_section_in_the_menu(user: User) -> None:
    await user.open('/')
    await user.should_see('Intel brief')
    for _, label in SECTIONS:
        await user.should_see(label)
    menu, investigate = tabs(user)
    assert (menu.value, investigate.value) == ('today', 'indicators')
    await user.should_see('Cyber Threat Intelligence Platform')


async def test_removed_counters_do_not_hide_the_main_navigation(user: User, ui_env: SimpleNamespace) -> None:
    """Regression: the trimmed landing page keeps navigation without restoring its old counters."""
    with ui_env.app.state.session_factory.begin() as db:
        ingest(db, DocumentInput(title='Gateway advisory', body='Beacon to 203.0.113.70.', source_name='S'))
    await user.open('/')
    menu, investigate = tabs(user)
    await user.should_not_see(marker='stat-investigate-indicators')
    await user.should_not_see(marker='stat-triage-list')
    investigate.set_value('indicators')
    menu.set_value('investigate')
    assert (menu.value, investigate.value) == ('investigate', 'indicators')
    menu.set_value('triage')
    assert menu.value == 'triage'
    with user.scope(marker='document-list'):
        await user.should_see('Gateway advisory')


async def test_requirements_stay_available_under_settings_without_a_main_tab(
    user: User,
    ui_env: SimpleNamespace,
) -> None:
    """Regression: hiding Requirements must keep links to existing questions and requests working."""
    question = 'Are ransomware groups targeting our gateway?'
    with ui_env.app.state.session_factory.begin() as db:
        ingest(db, DocumentInput(title='Gateway advisory', body='Ransomware on gateways.', source_name='S'))
        create_requirement(
            db,
            RequirementInput.model_validate(
                {
                    'kind': 'pir',
                    'question': question,
                    'criteria': [{'kind': 'term', 'value': 'ransomware'}],
                }
            ),
        )
    await user.open('/')
    await user.should_see('Intelligence questions (advanced)')
    menu, _ = tabs(user)
    assert 'requirements' not in [child.props.get('name') for child in menu.descendants()]
    questions = user.find(marker='advanced-requirements').elements.pop()
    assert isinstance(questions, ui.expansion)
    assert not questions.value
    await user.should_not_see(marker='stat-requirements-list')
    with user.scope(marker='document-list'):
        await user.should_see('Gateway advisory')
        user.find(kind=ui.button, content='Gateway advisory').click()
    await user.should_see(marker='report-requirements')
    with user.scope(marker='report-requirements'):
        await user.should_see(question)
        user.find(kind=ui.button, content=question).click()
    assert menu.value == 'settings'
    assert questions.value
    await user.should_see('＋ New requirement')


async def test_hunt_packages_and_saved_reports_belong_to_threat_hunt(user: User) -> None:
    """Regression: moving packages must preserve both them and the existing written products."""
    await user.should_see('Saved hunt packages')
    await user.should_see('Saved intelligence reports')
    assert user.client is not None
    panels = {
        element.props['name']: element
        for element in user.client.layout.descendants()
        if isinstance(element, ui.tab_panel)
    }
    hunt_titles = {e.text for e in panels['cases'].descendants() if isinstance(e, ui.label)}
    share_titles = {e.text for e in panels['share'].descendants() if isinstance(e, ui.label)}
    assert 'Saved intelligence reports' in hunt_titles
    assert 'Hunt packages' not in share_titles
    await user.should_see(marker='saved-hunt-packages')
    packages = user.find(marker='saved-hunt-packages').elements.pop()
    assert isinstance(packages, ui.expansion)
    assert not packages.value
    assert packages in set(panels['cases'].descendants())
    saved = user.find(marker='saved-intelligence-reports').elements.pop()
    assert isinstance(saved, ui.expansion)
    assert not saved.value


async def test_share_lists_every_way_out_and_opens_the_export(user: User) -> None:
    await user.open('/')
    for title in ('Download indicators', 'TAXII 2.1 feed', 'API keys', 'MISP'):
        await user.should_see(title)
    user.find(kind=ui.button, content='Choose what to export').click()
    await user.should_see('Export indicators of compromise (IOCs)')
