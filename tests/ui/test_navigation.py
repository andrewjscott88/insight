"""The side menu: the workspace's sections, in the order of an analyst's day, and the links between them."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from nicegui import ui
from nicegui.testing.user import User

from insight.schemas import DocumentInput
from insight.services import ingest
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
    labels = ['Today', 'Triage', 'Investigate', 'Cases', 'Share', 'Settings']
    assert [label for _, label in SECTIONS] == labels
    assert [label for _, label in INVESTIGATE] == ['Indicators', 'CVEs', 'ATT&CK techniques', 'Threat groups']


async def test_the_workspace_opens_on_today_with_every_section_in_the_menu(user: User) -> None:
    await user.open('/')
    await user.should_see('Threat landscape')
    for _, label in SECTIONS:
        await user.should_see(label)
    menu, investigate = tabs(user)
    assert (menu.value, investigate.value) == ('today', 'indicators')
    await user.should_see('Threat intelligence workbench')


async def test_each_counter_opens_the_list_it_counts(user: User, ui_env: SimpleNamespace) -> None:
    with ui_env.app.state.session_factory.begin() as db:
        ingest(db, DocumentInput(title='Gateway advisory', body='Beacon to 203.0.113.70.', source_name='S'))
    await user.open('/')
    menu, investigate = tabs(user)
    user.find(marker='stat-investigate-indicators').click()
    assert (menu.value, investigate.value) == ('investigate', 'indicators')
    user.find(marker='stat-triage-list').click()
    assert menu.value == 'triage'


async def test_share_lists_every_way_out_and_opens_the_export(user: User) -> None:
    await user.open('/')
    for title in ('Download indicators', 'TAXII 2.1 feed', 'API keys', 'MISP'):
        await user.should_see(title)
    user.find(kind=ui.button, content='Choose what to export').click()
    await user.should_see('Export indicators of compromise (IOCs)')
