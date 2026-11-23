"""Analysts can create a campaign and explicitly link and unlink a report in the workspace."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from nicegui import ui
from nicegui.testing.user import User

from insight import services

from .test_threats import add_report

pytestmark = pytest.mark.ui


async def test_create_campaign_and_manage_report_links(user: User, ui_env: SimpleNamespace) -> None:
    add_report(ui_env, 'Synthetic advisory', 'Example 192.0.2.71.')
    await user.open('/')
    await user.should_see('Actors and campaigns you track')
    user.find(kind=ui.expansion, content='Actors and campaigns you track').elements.pop().open()
    user.find(kind=ui.button, content='New campaign').click()
    await user.should_see('Campaign name')
    user.find(kind=ui.input, content='Campaign name').type('Example series')
    user.find(kind=ui.button, content='Save campaign').click()
    await user.should_see('Example series (campaign)')
    user.find(kind=ui.button, content='Example series (campaign)').click()
    await user.should_see('Saved links')
    user.find(kind=ui.input, content='Find a report, indicator, technique, or software').type(
        'Synthetic advisory'
    )
    await user.should_see('Link Synthetic advisory')
    user.find(kind=ui.button, content='Link Synthetic advisory').click()
    await user.should_see('Remove link')
    with ui_env.app.state.session_factory() as db:
        campaign = services.list_campaigns(db)[0]
        assert services.list_threat_links(db, 'campaign', campaign.id)[0].name == 'Synthetic advisory'
    user.find(kind=ui.button, content='Remove link').click()
    await user.should_see('No saved links on this page.')
