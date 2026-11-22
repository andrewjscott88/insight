"""The guide shows dated events and requires a deliberate campaign association."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from nicegui import ui
from nicegui.testing.user import User

from insight import services
from insight.schemas import CampaignInput

from .test_threats import open_guide

pytestmark = pytest.mark.ui


async def test_guide_timeline_campaign_association(user: User, ui_env: SimpleNamespace) -> None:
    with ui_env.app.state.session_factory.begin() as db:
        services.create_campaign(db, CampaignInput(name='Synthetic campaign', tlp='GREEN'))
    await user.open('/')
    await open_guide(user, 'G0016', 'APT29')
    await user.should_see('Activity timeline')
    await user.should_see('Download activity timeline (JSON)')
    user.find(kind=ui.button, content='Link a campaign').click()
    user.find(kind=ui.input, content='Find a campaign').type('Synthetic')
    await user.should_see('Link campaign: Synthetic campaign')
    user.find(kind=ui.button, content='Link campaign: Synthetic campaign').click()
    await user.should_see('Campaign association saved.')
    with ui_env.app.state.session_factory() as db:
        assert services.actor_campaigns(db, 'G0016')[0].name == 'Synthetic campaign'
    user.find(kind=ui.button, content='Link a campaign').click()
    await user.should_see('Remove campaign association')
    user.find(kind=ui.button, content='Remove campaign association').click()
    await user.should_see('Campaign association removed.')
