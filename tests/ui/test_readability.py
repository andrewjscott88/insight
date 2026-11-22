"""Readability features driven through the NiceGUI simulation of the real application (ADR 0017)."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from nicegui import ui
from nicegui.testing.user import User

from insight.appearance import TEXT_SIZE_COOKIE
from insight.ui.glossary import GLOSSARY

from .conftest import sign_in
from .test_appearance import record_scripts

pytestmark = pytest.mark.ui


def headings(user: User) -> list[tuple[str, str]]:
    """``(tag, text)`` of every heading on the page, in document order."""
    assert user.client is not None
    return [
        (element.tag, element.text)
        for element in user.client.layout.descendants()
        if element.tag in ('h1', 'h2', 'h3') and isinstance(element, ui.label) and element.visible
    ]


async def load_demo_and_open(user: User, title: str) -> None:
    user.find('Load demo').click()
    await user.should_see(title)
    with user.scope(marker='document-list'):
        user.find(kind=ui.button, content=title).click()
    with user.scope(marker='document-detail'):
        await user.should_see(title)


async def test_the_workspace_has_one_h1_and_real_section_headings(user: User) -> None:
    """Regression: every heading was a styled ``div``, so assistive technology saw none (WCAG 1.3.1)."""
    await user.should_see('Threat landscape')
    found = headings(user)
    assert [text for tag, text in found if tag == 'h1'] == ['Threat landscape']
    assert ('h2', 'Executive summary') in found
    assert found.index(('h1', 'Threat landscape')) < found.index(('h2', 'Executive summary'))
    assert {'Reports', 'Your intelligence, connected.'} <= {text for tag, text in found if tag == 'h2'}


async def test_the_report_reader_is_structured_by_headings(user: User) -> None:
    title = 'Training scenario: edge appliance activity'
    await load_demo_and_open(user, title)
    found = headings(user)
    assert ('h2', title) in found
    assert {'Report text', 'Extracted observations (4)', 'Analyst notes'} <= {
        t for tag, t in found if tag == 'h3'
    }


@pytest.mark.parametrize(('button', 'title'), [('Add intelligence', 'Add intelligence'),
                                               ('Export IOCs', 'Export indicators of compromise (IOCs)'),
                                               ('What the words mean', 'What the words mean')])  # fmt: skip
async def test_dialogs_have_a_name_and_a_heading(user: User, button: str, title: str) -> None:
    """axe ``aria-dialog-name``: an unnamed dialog is announced as just "dialog"."""
    user.find(kind=ui.button, content=button).click()
    await user.should_see(title)
    assert user.client is not None
    dialogs = [e for e in user.client.layout.descendants() if isinstance(e, ui.dialog) and e.value]
    assert [dialog.props.get('aria-label') for dialog in dialogs] == [title]
    assert ('h2', title) in headings(user)


async def test_the_glossary_explains_every_term(user: User) -> None:
    user.find(kind=ui.button, content='What the words mean').click()
    for term, explanation in GLOSSARY:
        await user.should_see(term)
        await user.should_see(explanation)


async def test_larger_text_is_off_by_default_and_switches_at_once(
    user: User, monkeypatch: pytest.MonkeyPatch
) -> None:
    scripts = record_scripts(monkeypatch)
    button = user.find(marker='text-size').elements.pop()
    assert button.props['aria-pressed'] == 'false'
    assert button.props['aria-label'] == 'Larger text'
    user.find(marker='text-size').click()
    assert button.props['aria-pressed'] == 'true'
    assert (
        f"document.cookie = '{TEXT_SIZE_COOKIE}=large; Path=/; Max-Age=31536000; SameSite=Lax';"
        in scripts[-1]
    )
    assert "document.documentElement.dataset.text = 'large';" in scripts[-1]
    user.find(marker='text-size').click()
    assert button.props['aria-pressed'] == 'false'
    assert "dataset.text = 'standard';" in scripts[-1]


async def test_larger_text_is_remembered_and_applied_before_the_page_renders(ui_env: SimpleNamespace) -> None:
    ui_env.client.cookies.set(TEXT_SIZE_COOKIE, 'large')
    await sign_in(ui_env.client)
    page = await ui_env.client.get('/')
    assert 'document.documentElement.dataset.text = "large";' in page.text
    user = User(ui_env.client)
    await user.open('/')
    assert user.find(marker='text-size').elements.pop().props['aria-pressed'] == 'true'


async def test_an_empty_note_is_explained_on_the_field(user: User) -> None:
    await load_demo_and_open(user, 'Training scenario: edge appliance activity')
    user.find('Save note').click()
    await user.should_see('Write a note first (up to 10,000 characters).')
    with user.scope(marker='document-detail'):
        note = user.find(kind=ui.textarea).elements.pop()
    assert isinstance(note, ui.textarea)
    assert note.error == 'Write a note first (up to 10,000 characters).'


async def test_links_that_open_a_new_tab_say_so(user: User) -> None:
    await load_demo_and_open(user, 'Training scenario: edge appliance activity')
    link = user.find(kind=ui.link, content="Export this report's IOCs").elements.pop()
    assert link.props['aria-label'] == "Export this report's IOCs (opens in a new tab)"


async def test_a_brief_connection_loss_does_not_reload_the_page(user: User) -> None:
    """Regression: after 3 s without a connection NiceGUI reloaded the page, losing the reader's place."""
    from nicegui import app

    assert app.config.reconnect_timeout == 30.0
