"""TIP 3.2 in the workspace: ranked inbox search and the link map."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from nicegui import ui
from nicegui.testing.user import User

from insight.schemas import DocumentInput
from insight.services import ingest

pytestmark = pytest.mark.ui


def add_report(env: SimpleNamespace, title: str, body: str) -> None:
    with env.app.state.session_factory.begin() as db:
        ingest(db, DocumentInput(title=title, body=body, source_name='S', tlp='GREEN'))


async def test_a_query_lists_the_best_match_first(user: User, ui_env: SimpleNamespace) -> None:
    add_report(ui_env, 'Weekly roundup', 'Background. ' * 30 + 'Rhysida was mentioned once. ' + 'More. ' * 30)
    add_report(ui_env, 'Rhysida affiliates', 'Affiliates of the group used remote tools.')
    await user.open('/')
    user.find(kind=ui.input, content='Search intelligence').type('rhysida')
    await user.should_see('2 sources shown · best match first')
    await user.should_see('Rhysida was mentioned once.', retries=5)  # the snippet, not the report's start
    buttons = [
        b for b in user.find(kind=ui.button).elements if b.text in ('Weekly roundup', 'Rhysida affiliates')
    ]
    assert [b.text for b in sorted(buttons, key=lambda b: b.id)] == ['Rhysida affiliates', 'Weekly roundup']


async def test_the_link_map_centres_on_any_item_and_opens_reports(
    user: User, ui_env: SimpleNamespace
) -> None:
    add_report(ui_env, 'First sighting', 'C2 at 203.0.113.61 (T1071.001).')
    add_report(ui_env, 'Second sighting', 'The same C2, 203.0.113.61, returned.')
    await user.open('/')
    user.find(kind=ui.button, content='First sighting').click()
    with user.scope(marker='document-detail'):
        await user.should_see('C2 at 203.0.113.61')
        user.find(marker='report-links').click()
    await user.should_see('Links around First sighting')
    await user.should_see('Direct links (2)')
    await user.should_see('ATT&CK techniques')
    user.find(kind=ui.button, content='203.0.113.61 · ip').click()
    await user.should_see('Links around 203.0.113.61')
    await user.should_see('Second sighting · S')
    user.find(kind=ui.toggle, marker='graph-depth').elements.pop().set_value(2)
    await user.should_see('Two steps away')
    await user.should_see('T1071.001 Application Layer Protocol: Web Protocols')  # via the first report
    user.find(kind=ui.button, content='Second sighting · S').click()
    await user.should_see('Links around Second sighting')
    user.find(kind=ui.button, content='Open this report').click()
    with user.scope(marker='document-detail'):
        await user.should_see('The same C2, 203.0.113.61, returned.')
