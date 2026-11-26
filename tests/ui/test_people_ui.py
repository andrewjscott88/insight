"""Settings → People (ADR 0046, TIP 3.4b): admins approve people, change roles, turn people off, sign them out
and remove them; nobody else sees the section, and an admin cannot change their own account here."""

from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace

import pytest
from nicegui import ui
from nicegui.testing.user import User
from sqlalchemy import select
from tests.conftest import add_person, sign_in_as

from insight import services
from insight.models import AuditEvent, OperatorSession
from insight.models import User as Person
from insight.ui.activity import actor_name
from insight.ui.people import OWN_ACCOUNT

pytestmark = pytest.mark.ui


def role_selects(user: User) -> list[ui.select]:
    return [e for e in user.find(kind=ui.select).elements if e.props.get('label') == 'Role']


def open_activity(user: User) -> None:
    """Recent activity is drawn only while its section is open."""
    section = user.find(marker='recent-activity').elements.pop()
    assert isinstance(section, ui.expansion)
    section.open()


def person(ui_env: SimpleNamespace, user_id: str) -> Person | None:
    with ui_env.app.state.session_factory() as db:
        found: Person | None = db.get(Person, user_id)
        if found is not None:
            db.expunge(found)
        return found


def sessions_of(ui_env: SimpleNamespace, user_id: str) -> int:
    with ui_env.app.state.session_factory() as db:
        return len(db.scalars(select(OperatorSession).where(OperatorSession.user_id == user_id)).all())


def open_session(ui_env: SimpleNamespace, user_id: str) -> None:
    """The person is signed in somewhere else."""
    with ui_env.app.state.session_factory.begin() as db:
        services.start_operator_session(
            db, binding=ui_env.app.state.session_binding, at=datetime.now(UTC), user_id=user_id
        )


async def open_as(ui_env: SimpleNamespace, role: str) -> tuple[User, str]:
    user_id = add_person(ui_env.app, role, email=f'{role}@example.org')
    sign_in_as(ui_env.app, ui_env.client, user_id)
    simulated = User(ui_env.client)
    await simulated.open('/')
    return simulated, user_id


async def test_an_admin_approves_someone_waiting(ui_env: SimpleNamespace) -> None:
    waiting = add_person(ui_env.app, None, email='new@example.org')
    open_session(ui_env, waiting)
    user = await _operator(ui_env)
    await user.should_see('Waiting for approval')
    await user.should_see('new@example.org')
    (choice,) = role_selects(user)
    assert choice.value == 'none'
    choice.set_value('analyst')
    await user.should_see('Test pending is now an analyst. They sign in again.')
    found = person(ui_env, waiting)
    assert found is not None
    assert (found.role, found.role_from_groups) == ('analyst', False)
    assert sessions_of(ui_env, waiting) == 0, 'the change applies at once'
    with ui_env.app.state.session_factory() as db:
        event = db.scalars(select(AuditEvent).where(AuditEvent.action == 'user.role')).one()
    assert (event.actor, event.object_id) == ('operator', waiting)
    open_activity(user)
    await user.should_see('Operator (workspace password) · user.role')


async def test_turn_off_sign_out_and_remove(ui_env: SimpleNamespace) -> None:
    someone = add_person(ui_env.app, 'viewer', email='bo@example.org')
    open_session(ui_env, someone)
    user = await _operator(ui_env)
    await user.should_see('1 open session(s)')
    user.find(kind=ui.button, content='Sign out').click()
    await user.should_see('Test viewer is signed out everywhere.')
    assert sessions_of(ui_env, someone) == 0
    user.find(kind=ui.button, content='Turn off').click()
    await user.should_see('Test viewer is turned off and signed out.')
    found = person(ui_env, someone)
    assert found is not None
    assert found.disabled
    await user.should_see('Turned off · Role: viewer')
    user.find(kind=ui.button, content='Turn on').click()
    await user.should_see('Test viewer is turned on again.')
    user.find(kind=ui.button, content='Remove').click()
    await user.should_see('Remove this person?')
    user.find(marker='confirm-remove-person').click()
    await user.should_see('Test viewer was removed.')
    assert person(ui_env, someone) is None
    with ui_env.app.state.session_factory() as db:
        actions = [e.action for e in db.scalars(select(AuditEvent).order_by(AuditEvent.created_at))]
    assert actions == ['user.sign_out', 'user.disable', 'user.enable', 'user.remove']
    open_activity(user)
    await user.should_see(f'Removed person ({someone})')


async def test_roles_from_groups_are_changed_in_the_provider(ui_env: SimpleNamespace) -> None:
    grouped = add_person(ui_env.app, 'analyst')
    with ui_env.app.state.session_factory.begin() as db:
        found = db.get(Person, grouped)
        assert found is not None
        found.role_from_groups = True
    user = await _operator(ui_env)
    await user.should_see('Role: analyst, from provider groups')
    await user.should_see('Change this role in your identity provider’s groups.')
    assert role_selects(user) == []
    await user.should_see('Turn off')


async def test_an_admin_leaves_their_own_account_alone(ui_env: SimpleNamespace) -> None:
    other = add_person(ui_env.app, 'viewer', email='other@example.org')
    user, me = await open_as(ui_env, 'admin')
    await user.should_see(OWN_ACCOUNT)
    assert len(role_selects(user)) == 1, 'only the other person has controls'
    assert len(user.find(kind=ui.button, content='Remove').elements) == 1
    role_selects(user)[0].set_value('analyst')
    await user.should_see('Test viewer is now an analyst. They sign in again.')
    with ui_env.app.state.session_factory() as db:
        event = db.scalars(select(AuditEvent).where(AuditEvent.action == 'user.role')).one()
    assert (event.actor, event.object_id) == (f'user:{me}', other)
    open_activity(user)
    await user.should_see('Test admin <admin@example.org> · user.role')


async def test_recent_activity_is_drawn_only_while_open(ui_env: SimpleNamespace) -> None:
    user = await _operator(ui_env)
    await user.should_see('Recent activity')
    await user.should_not_see('Nothing has happened yet.')
    open_activity(user)
    await user.should_see('Nothing has happened yet.')


@pytest.mark.parametrize('role', ['viewer', 'analyst'])
async def test_only_admins_see_people(ui_env: SimpleNamespace, role: str) -> None:
    add_person(ui_env.app, None, email='new@example.org')
    user, _ = await open_as(ui_env, role)
    await user.should_see('Source reliability')
    await user.should_not_see(marker='people')
    await user.should_not_see('Waiting for approval')
    await user.should_not_see('new@example.org')


async def test_a_demoted_admin_cannot_use_an_open_page(ui_env: SimpleNamespace) -> None:
    other = add_person(ui_env.app, None)
    user, me = await open_as(ui_env, 'admin')
    await user.should_see('Waiting for approval')
    with ui_env.app.state.session_factory.begin() as db:
        services.set_actor(db, 'cli')
        services.set_user_role(db, me, 'analyst')  # ends their session
        services.set_user_role(db, me, 'admin')
    role_selects(user)[0].set_value('admin')
    found = person(ui_env, other)
    assert found is not None
    assert found.role is None, 'the session that saw the page has ended'


def test_actors_are_named_in_words() -> None:
    labels = {'u1': 'Ann <ann@example.org>'}
    assert actor_name('user:u1', labels) == 'Ann <ann@example.org>'
    assert actor_name('user:gone', labels) == 'Removed person (gone)'
    assert actor_name('api-key:k1', labels) == 'API key k1'
    assert actor_name('connector:cisa-kev', labels) == 'Source sync (cisa-kev)'
    assert actor_name('cli', labels) == 'Host command line'
    assert actor_name('something-new', labels) == 'something-new'


async def _operator(ui_env: SimpleNamespace) -> User:
    from tests.ui.conftest import sign_in

    await sign_in(ui_env.client)
    simulated = User(ui_env.client)
    await simulated.open('/')
    return simulated
