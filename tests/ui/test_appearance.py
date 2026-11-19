"""Theme switch and phone navigation, driven through the NiceGUI simulation of the real application."""

from __future__ import annotations

import dataclasses
from types import SimpleNamespace

import pytest
from nicegui import ui
from nicegui.testing.user import User

from insight.appearance import THEME_COOKIE

from .conftest import sign_in

pytestmark = pytest.mark.ui


def dark_mode(user: User) -> ui.dark_mode:
    assert user.client is not None
    found = [element for element in user.client.elements.values() if isinstance(element, ui.dark_mode)]
    assert len(found) == 1, 'exactly one dark mode element per page'
    return found[0]


def pressed(user: User) -> dict[str, str]:
    """``aria-pressed`` of each theme button."""
    return {
        theme: str(user.find(marker=f'theme-{theme}').elements.pop().props['aria-pressed'])
        for theme in ('light', 'dark', 'system')
    }


def record_scripts(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """JavaScript the page asks the browser to run (the simulator cannot execute it), in order."""
    scripts: list[str] = []
    monkeypatch.setattr(ui, 'run_javascript', lambda code, **_: scripts.append(code))
    return scripts


def matching(scripts: list[str], text: str) -> list[str]:
    return [script for script in scripts if text in script]


async def open_workspace(ui_env: SimpleNamespace, theme_cookie: str | None = None) -> User:
    if theme_cookie is not None:
        ui_env.client.cookies.set(THEME_COOKIE, theme_cookie)
    await sign_in(ui_env.client)
    user = User(ui_env.client)
    await user.open('/')
    return user


# --------------------------------------------------------------------------- theme switch


async def test_the_workspace_follows_the_device_by_default(user: User) -> None:
    await user.should_see(marker='theme-switch')
    assert dark_mode(user).value is None  # Quasar "auto": the device's light/dark setting
    assert pressed(user) == {'light': 'false', 'dark': 'false', 'system': 'true'}


async def test_each_theme_button_switches_at_once_and_is_remembered(
    user: User, monkeypatch: pytest.MonkeyPatch
) -> None:
    scripts = record_scripts(monkeypatch)
    for theme, value in (('light', False), ('dark', True), ('system', None)):
        user.find(marker=f'theme-{theme}').click()
        assert dark_mode(user).value is value
        assert pressed(user)[theme] == 'true'
        assert list(pressed(user).values()).count('true') == 1
        cookie = f"document.cookie = '{THEME_COOKIE}={theme}; Path=/; Max-Age=31536000; SameSite=Lax';"
        assert cookie in scripts[-1]
        assert "name: 'theme-color'" in scripts[-1], 'the address bar follows the theme'
    assert len(matching(scripts, THEME_COOKIE)) == 3


async def test_the_theme_buttons_are_labelled_for_screen_readers(user: User) -> None:
    for theme, label in (('light', 'Light theme'), ('dark', 'Dark theme'), ('system', 'System theme')):
        button = user.find(marker=f'theme-{theme}').elements.pop()
        assert button.props['aria-label'] == label


@pytest.mark.parametrize(('cookie', 'value', 'button'), [('light', False, 'light'), ('dark', True, 'dark')])
async def test_a_theme_picked_on_this_device_is_used_on_the_next_visit(
    ui_env: SimpleNamespace, cookie: str, value: bool, button: str
) -> None:
    user = await open_workspace(ui_env, theme_cookie=cookie)
    assert dark_mode(user).value is value
    assert pressed(user)[button] == 'true'


async def test_the_instance_default_applies_to_devices_without_a_choice(ui_env: SimpleNamespace) -> None:
    ui_env.app.state.settings = dataclasses.replace(ui_env.app.state.settings, theme='dark')
    user = await open_workspace(ui_env)
    assert dark_mode(user).value is True
    assert pressed(user)['dark'] == 'true'


async def test_an_unknown_theme_cookie_falls_back_to_the_default(ui_env: SimpleNamespace) -> None:
    user = await open_workspace(ui_env, theme_cookie='sepia')
    assert dark_mode(user).value is None


async def test_the_theme_cookie_is_secure_behind_https(
    ui_env: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    ui_env.app.state.settings = dataclasses.replace(ui_env.app.state.settings, secure_cookies=True)
    user = await open_workspace(ui_env)
    scripts = record_scripts(monkeypatch)
    user.find(marker='theme-light').click()
    assert 'SameSite=Lax; Secure' in scripts[-1]


async def test_a_revoked_session_cannot_change_the_theme(
    user: User, ui_env: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    navigated: list[str] = []
    monkeypatch.setattr(user.navigate, 'to', lambda target, new_tab=False: navigated.append(target))
    scripts = record_scripts(monkeypatch)
    ui_env.app.state.active_sessions.clear()  # signed out in another tab
    user.find(marker='theme-dark').click()
    assert navigated == ['/login']
    assert matching(scripts, THEME_COOKIE) == []
    assert dark_mode(user).value is None


# --------------------------------------------------------------------------- phone inbox navigation


async def test_opening_a_report_brings_the_reader_into_view_on_a_phone(
    user: User, monkeypatch: pytest.MonkeyPatch
) -> None:
    scripts = record_scripts(monkeypatch)
    user.find('Load demo').click()
    await user.should_see('Training scenario: edge appliance activity')
    with user.scope(marker='document-list'):
        user.find(kind=ui.button, content='Training scenario: shared infrastructure pivot').click()
    reader = matching(scripts, '.document-reader')
    assert reader, 'choosing a report scrolls the reader into view'
    assert "matchMedia('(max-width: 1023.98px)')" in reader[-1], 'only where the list is stacked above it'
    assert 'prefers-reduced-motion' in reader[-1]


async def test_back_to_list_returns_to_the_list_and_keeps_the_unsaved_note(
    user: User, monkeypatch: pytest.MonkeyPatch
) -> None:
    scripts = record_scripts(monkeypatch)
    user.find('Load demo').click()
    await user.should_see('Training scenario: edge appliance activity')
    with user.scope(marker='document-detail'):
        await user.should_see(marker='back-to-list')
        user.find(kind=ui.textarea).type('half-written assessment')
        user.find(marker='back-to-list').click()
    back = matching(scripts, '.document-list-pane')
    assert back
    assert '.source-selected' in back[-1], 'the open report stays in view in the list'
    with user.scope(marker='document-detail'):
        assert user.find(kind=ui.textarea).elements.pop().value == 'half-written assessment'


async def test_no_back_button_without_an_open_report(user: User) -> None:
    await user.should_see('Choose a report from the list')
    await user.should_not_see(marker='back-to-list')
