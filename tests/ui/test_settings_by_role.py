"""Settings show each role only the controls it may use (ADR 0046, TIP 3.4b): admins change sources,
schedules, lookup providers, feeds and alert destinations; analysts sync and grade sources; viewers read.
Everyone else sees the setting in words. The server-side check stays the control (``test_roles_ui.py``)."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from nicegui import ui
from nicegui.testing.user import User
from tests.conftest import add_person, sign_in_as
from tests.ui.conftest import sign_in

from insight import services
from insight.permissions import NOT_PERMITTED
from insight.schemas import DocumentInput

pytestmark = pytest.mark.ui


async def open_as(ui_env: SimpleNamespace, role: str) -> User:
    if role == 'operator':
        await sign_in(ui_env.client)
    else:
        sign_in_as(ui_env.app, ui_env.client, add_person(ui_env.app, role, email=f'{role}@example.org'))
    user = User(ui_env.client)
    await user.open('/')
    await user.should_see('Public sources')
    return user


def count(user: User, kind: type[ui.element], content: str) -> int:
    return len(user.find(kind=kind, content=content).elements) if _any(user, kind, content) else 0


def _any(user: User, kind: type[ui.element], content: str) -> bool:
    try:
        user.find(kind=kind, content=content)
    except AssertionError:
        return False
    return True


def labelled(user: User, label: str) -> int:
    return sum(1 for e in user.find(kind=ui.select).elements if e.props.get('label') == label)


def a_report(ui_env: SimpleNamespace) -> None:
    with ui_env.app.state.session_factory.begin() as db:
        services.ingest(
            db, DocumentInput(title='Rated', body='Seen at 192.0.2.4.', source_name='Rated', tlp='GREEN')
        )


async def test_admins_get_every_control(ui_env: SimpleNamespace) -> None:
    a_report(ui_env)
    user = await open_as(ui_env, 'operator')
    assert count(user, ui.switch, 'Use this source') > 0
    assert count(user, ui.button, 'Sync now') > 0
    assert labelled(user, 'Sync by itself') > 0
    assert labelled(user, 'Sync all sources you use by themselves') == 1
    assert count(user, ui.button, 'Add a feed') == 1
    assert count(user, ui.switch, 'Look up severity at NIST NVD by itself') == 1
    assert count(user, ui.button, 'Add destination') == 1
    assert labelled(user, 'Reliability') == 1
    assert count(user, ui.button, 'Sync all sources') == 1


async def test_analysts_sync_and_grade_but_change_no_settings(ui_env: SimpleNamespace) -> None:
    a_report(ui_env)
    user = await open_as(ui_env, 'analyst')
    assert count(user, ui.switch, 'Use this source') == 0
    await user.should_see('In use')
    await user.should_see('Not in use')
    assert count(user, ui.button, 'Sync now') > 0, 'analysts may sync a source now'
    assert count(user, ui.button, 'Sync all sources') == 1
    assert labelled(user, 'Sync by itself') == 0
    assert labelled(user, 'Sync all sources you use by themselves') == 0
    await user.should_see('Syncs only when you ask.')
    assert count(user, ui.button, 'Add a feed') == 0
    assert count(user, ui.switch, 'Look up severity at NIST NVD by itself') == 0
    await user.should_see('Look up severity at NIST NVD by itself: off')
    assert count(user, ui.switch, 'Use RDAP') == 0
    assert count(user, ui.button, 'Add destination') == 0
    await user.should_see('An admin chooses where alerts go.')
    assert labelled(user, 'Reliability') == 1, 'grading sources is review work'


async def test_viewers_read_settings_in_words(ui_env: SimpleNamespace) -> None:
    a_report(ui_env)
    user = await open_as(ui_env, 'viewer')
    assert count(user, ui.button, 'Sync now') == 0
    assert count(user, ui.button, 'Sync all sources') == 0
    assert labelled(user, 'Reliability') == 0
    await user.should_see('ageing: default for the type')
    await user.should_see('Not in use')


async def test_a_hidden_control_is_still_refused(ui_env: SimpleNamespace) -> None:
    """Hiding is a courtesy: an analyst page that kept an admin control is refused when it is used."""
    user = await open_as(ui_env, 'operator')
    switch = sorted(user.find(kind=ui.switch, content='Use this source').elements, key=lambda s: s.id)[0]
    with ui_env.app.state.session_factory.begin() as db:
        services.set_actor(db, 'cli')
    # The operator's page, but the caller is now an analyst: the role is looked up on every callback.
    analyst = SimpleNamespace(
        kind='session', max_tlp=None, actor='user:u1', user_id='u1', may=lambda p: p.value in {'read'}
    )
    ui_env.app.state.workspace_caller = lambda _session: analyst
    switch.set_value(not switch.value)
    await user.should_see(NOT_PERMITTED)
