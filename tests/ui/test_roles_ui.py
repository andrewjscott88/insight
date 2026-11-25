"""Roles in the workspace (ADR 0046): every write checks the session's role on every callback."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from nicegui.testing.user import User
from sqlalchemy import select
from tests.conftest import add_person, sign_in_as

from insight import services
from insight.models import AuditEvent, Document
from insight.permissions import NOT_PERMITTED, Permission
from insight.ui.workspace import NotPermitted, Workspace

pytestmark = pytest.mark.ui


async def open_as(ui_env: SimpleNamespace, role: str) -> tuple[User, str]:
    user_id = add_person(ui_env.app, role, email=f'{role}@example.org')
    sign_in_as(ui_env.app, ui_env.client, user_id)
    simulated = User(ui_env.client)
    await simulated.open('/')
    return simulated, user_id


async def add_intelligence(user: User) -> None:
    user.find('Add intelligence').click()
    user.find('Document title').type('Analyst paste')
    user.find('Source name').type('Analyst')
    user.find('Source content').type('Seen at 192.0.2.8.')
    user.find('Ingest document').click()


async def test_a_viewer_reads_but_cannot_add_intelligence(ui_env: SimpleNamespace) -> None:
    user, _ = await open_as(ui_env, 'viewer')
    await user.should_see('Intel Brief')
    await add_intelligence(user)
    await user.should_see(NOT_PERMITTED)
    with ui_env.app.state.session_factory() as db:
        assert db.scalar(select(Document)) is None


async def test_an_analyst_adds_intelligence_as_themselves(ui_env: SimpleNamespace) -> None:
    user, user_id = await open_as(ui_env, 'analyst')
    await add_intelligence(user)
    await user.should_see('Document ingested.')
    with ui_env.app.state.session_factory() as db:
        assert set(db.scalars(select(AuditEvent.actor))) == {f'user:{user_id}'}


async def test_a_role_change_applies_to_the_next_action(ui_env: SimpleNamespace) -> None:
    user, user_id = await open_as(ui_env, 'analyst')
    with ui_env.app.state.session_factory.begin() as db:
        services.set_user_role(db, user_id, 'viewer')  # ends the session, as every role change does
    await add_intelligence(user)
    with ui_env.app.state.session_factory() as db:
        assert db.scalar(select(Document)) is None


async def test_the_write_check_is_the_control(ui_env: SimpleNamespace) -> None:
    """``allowed`` only spares the person an error: ``write`` and ``actor`` refuse on their own."""
    request = SimpleNamespace(session={})
    ws = Workspace(app=ui_env.app, sessions=ui_env.app.state.session_factory, request=request)  # type: ignore[arg-type]
    for session in ({}, {'authenticated': True, 'sid': 'not-a-session'}):
        request.session = session
        with pytest.raises(NotPermitted), ws.write(Permission.READ):
            pass
    viewer = SimpleNamespace(actor='user:u1', may=lambda p: p == Permission.READ)
    ui_env.app.state.session_caller = lambda _session: viewer
    with ws.write(Permission.READ) as db:
        assert db.info['actor'] == 'user:u1'
    assert ws.actor(Permission.READ) == 'user:u1'
    for permission in (Permission.ADD_REPORTS, Permission.SOURCES, Permission.LOOKUPS):
        with pytest.raises(NotPermitted), ws.write(permission):
            pass
        with pytest.raises(NotPermitted):
            ws.actor(permission)
