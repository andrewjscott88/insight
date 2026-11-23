"""An operator manages their own feed from Settings without contacting a publisher."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from nicegui import ui
from nicegui.testing.user import User

from insight import services
from insight.models import SessionFactory
from insight.schemas import OperatorSourceInput

pytestmark = pytest.mark.ui


async def add_feed(user: User) -> None:
    await user.should_see('Your sources')
    user.find(kind=ui.button, content='Add a feed').click()
    await user.should_see('Feed web address')
    user.find(kind=ui.input, content='Feed name').type('Training feed')
    user.find(kind=ui.input, content='Feed web address').type('https://example.org/training.xml')
    user.find(kind=ui.button, content='Save feed').click()
    await user.should_see('Feed saved.')
    await user.should_see('Share titles, dates and links only.')


async def test_feed_starts_off_and_sync_and_schedule_require_enabling(
    user: User, ui_env: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    from insight.ui import sources

    calls = []

    async def sync(sessions: SessionFactory, key: str, *, max_tlp: str | None = None) -> str:
        calls.append(key)
        return 'Training feed checked.'

    monkeypatch.setattr(sources, 'sync_source', sync)
    await add_feed(user)
    with ui_env.app.state.session_factory() as db:
        (source,) = services.list_operator_sources(db)
    assert (source.enabled, source.reuse, source.tlp) == (False, 'metadata', 'AMBER')
    with user.scope(marker='feed-' + source.key):
        await user.should_see('Share titles, dates and links only.')
        assert not user.find(kind=ui.button, content='Sync now').elements.pop().enabled
        assert not user.find(kind=ui.select, content='Sync by itself').elements.pop().enabled
        user.find(kind=ui.switch, content='Use this feed').click()
    await user.should_see('Feed is on.')
    await user.should_see(marker='feed-' + source.key)
    with user.scope(marker='feed-' + source.key):
        user.find(kind=ui.button, content='Sync now').click()
    await user.should_see('Training feed checked.')
    await user.should_see(marker='feed-' + source.key)
    assert calls == [source.key]
    with user.scope(marker='feed-' + source.key):
        user.find(kind=ui.select, content='Sync by itself').elements.pop().set_value(60)
    await user.should_see('The schedule is saved')
    with ui_env.app.state.session_factory() as db:
        assert services.list_schedules(db)[source.key].interval_minutes == 60
    user.find(kind=ui.select, content='Sync all sources you use by themselves').elements.pop().set_value(360)
    with ui_env.app.state.session_factory() as db:
        assert services.list_schedules(db)[source.key].interval_minutes == 360
    with user.scope(marker='feed-' + source.key):
        user.find(kind=ui.button, content='Edit feed').click()
    await user.should_see(marker='edit-operator-feed')
    with user.scope(marker='edit-operator-feed'):
        await user.should_see('The publisher allows sharing its report text.')
        user.find(kind=ui.checkbox, content='The publisher allows sharing its report text.').click()
        user.find(kind=ui.select, content='Sharing label (TLP)').elements.pop().set_value('GREEN')
        user.find(kind=ui.button, content='Save feed').click()
    await user.should_see(kind=ui.label, content='The publisher allows sharing its report text.')
    with user.scope(marker='feed-' + source.key):
        await user.should_see('TLP:GREEN')

    with ui_env.app.state.session_factory() as db:
        edited = services.get_operator_source(db, source.key)
        assert (edited.reuse, edited.tlp, edited.enabled) == ('public', 'GREEN', True)
    with user.scope(marker='feed-' + source.key):
        user.find(kind=ui.switch, content='Use this feed').click()
    await user.should_see('Feed is off. Its schedule is off too.')
    with ui_env.app.state.session_factory() as db:
        assert not services.list_schedules(db)[source.key].enabled
    with user.scope(marker='feed-' + source.key):
        user.find(kind=ui.button, content='Delete feed').click()
    await user.should_see('Its reports stay in Insight.')
    user.find(marker='confirm-delete-feed').click()
    await user.should_see('You have no feeds yet.')
    assert calls == [source.key]


async def test_stale_feed_switch_does_not_enable_a_replaced_address(
    user: User, ui_env: SimpleNamespace
) -> None:
    """Regression: consent shown for one address must not enable a replacement from another tab."""
    await add_feed(user)
    with ui_env.app.state.session_factory.begin() as db:
        (original,) = services.list_operator_sources(db)
        services.update_operator_source(
            db, original.key, OperatorSourceInput(name='Another feed', url='https://example.org/another.xml')
        )
    with user.scope(marker='feed-' + original.key):
        user.find(kind=ui.switch, content='Use this feed').click()
    await user.should_see('This feed has changed. Check its settings and try again.')
    await user.should_see('Another feed')
    with ui_env.app.state.session_factory() as db:
        assert not services.get_operator_source(db, original.key).enabled


async def test_invalid_feed_form_does_not_echo_or_store_the_address(
    user: User, ui_env: SimpleNamespace
) -> None:
    await user.should_see('Your sources')
    user.find(kind=ui.button, content='Add a feed').click()
    await user.should_see('Feed web address')
    with user.scope(marker='add-operator-feed'):
        user.find(kind=ui.input, content='Feed name').type('Training feed')
        user.find(kind=ui.input, content='Feed web address').type(
            'https://example.org/feed?x=synthetic-marker'
        )
        user.find(kind=ui.button, content='Save feed').click()
        await user.should_see('Check the feed name and address.')
        await user.should_not_see(kind=ui.label, content='synthetic-marker')
    with ui_env.app.state.session_factory() as db:
        assert not services.list_operator_sources(db)
