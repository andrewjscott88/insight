"""A TAXII source shows whether the host has credentials without displaying their value."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from nicegui import ui
from nicegui.testing.user import User

from insight import services

pytestmark = pytest.mark.ui


async def test_taxii_source_uses_a_host_variable_and_starts_off(
    user: User, ui_env: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    variable = 'INSIGHT_SOURCE_TRAINING'
    token = 'synthetic-local-fixture'
    monkeypatch.delenv(variable, raising=False)
    await user.should_see('Your sources')
    user.find(kind=ui.button, content='Add a feed').click()
    await user.should_see(marker='add-operator-feed')
    with user.scope(marker='add-operator-feed'):
        user.find(kind=ui.select, content='Source type').elements.pop().set_value('taxii')
        await user.should_see('Web address of the TAXII API root')
        user.find(kind=ui.input, content='Feed name').type('Training collection')
        user.find(kind=ui.input, content='Web address of the TAXII API root').type(
            'https://example.org/root/'
        )
        user.find(kind=ui.input, content='Collection ID').type('training')
        user.find(kind=ui.input, content='Host variable name').type(variable)
        user.find(kind=ui.button, content='Save feed').click()
    await user.should_see('Credentials not configured.')
    with ui_env.app.state.session_factory() as db:
        (source,) = services.list_operator_sources(db)
    assert (source.kind, source.collection_id, source.credential_env) == ('taxii', 'training', variable)
    assert not source.enabled
    assert not source.configured
    with user.scope(marker='feed-' + source.key):
        user.find(kind=ui.switch, content='Use this feed').click()
    await user.should_see('Feed is on.')
    with user.scope(marker='feed-' + source.key):
        assert not user.find(kind=ui.button, content='Sync now').elements.pop().enabled
        assert not user.find(kind=ui.select, content='Sync by itself').elements.pop().enabled
    user.find(kind=ui.select, content='Sync all sources you use by themselves').elements.pop().set_value(60)
    await user.should_see('Saved schedules for feeds that are ready.')
    with ui_env.app.state.session_factory() as db:
        assert source.key not in services.list_schedules(db)
    monkeypatch.setenv(variable, token)
    await user.open('/')
    await user.should_see('Credentials configured on the host')
    await user.should_not_see(token)
    with user.scope(marker='feed-' + source.key):
        assert user.find(kind=ui.button, content='Sync now').elements.pop().enabled
        user.find(kind=ui.select, content='Sync by itself').elements.pop().set_value(360)
    monkeypatch.delenv(variable)
    await user.open('/')
    await user.should_see('Credentials not configured.')
    with user.scope(marker='feed-' + source.key):
        schedule = user.find(kind=ui.select, content='Sync by itself').elements.pop()
        assert set(schedule.options) == {0, 360}
        schedule.set_value(0)
        assert not schedule.enabled
        user.find(kind=ui.button, content='Edit feed').click()
    await user.should_see(marker='edit-operator-feed')
    with user.scope(marker='edit-operator-feed'):
        field = user.find(kind=ui.input, content='Host variable name').elements.pop()
        assert field.value == variable
        user.find(kind=ui.select, content='Source type').elements.pop().set_value('rss')
        await user.should_see('Feed web address')
        user.find(kind=ui.button, content='Save feed').click()
    await user.should_see('Feed saved.')
    with ui_env.app.state.session_factory() as db:
        saved = services.get_operator_source(db, source.key)
    assert (saved.kind, saved.collection_id, saved.credential_env, saved.enabled) == (
        'rss',
        None,
        None,
        False,
    )
