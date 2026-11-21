"""An explicit review and third-party approval precede every uncached IP disclosure."""

from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any

import pytest
from nicegui import ui
from nicegui.testing import User
from tests.greynoise_fixtures import ANSWER, IP, reviewed

from insight import greynoise

pytestmark = pytest.mark.ui


async def test_expanding_an_ip_or_opening_context_never_sends_the_ip(
    user: User, ui_env: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    with ui_env.app.state.session_factory.begin() as db:
        reviewed(db)
    monkeypatch.setenv('INSIGHT_GREYNOISE_KEY', 'fixture')
    calls = []

    async def fake(url: str, **kwargs: Any) -> bytes:
        calls.append(url)
        return json.dumps(ANSWER).encode()

    monkeypatch.setattr(greynoise, 'download', fake)
    await user.open('/')
    user.find(kind=ui.expansion, content=IP).elements.pop().open()
    user.find(kind=ui.button, content='GreyNoise Community context').click()
    await user.should_see('No cached GreyNoise context.')
    assert not user.find(kind=ui.button, content='Look up at GreyNoise').elements.pop().enabled
    assert not calls
    user.find(kind=ui.checkbox, content=f'I approve sending {IP} to GreyNoise.').click()
    user.find(kind=ui.button, content='Look up at GreyNoise').click()
    await user.should_see('GreyNoise classification: benign')
    await user.should_see('Synthetic Lab')
    assert len(calls) == 1


@pytest.mark.parametrize(('configured', 'accepted'), [(False, True), (True, False)])
async def test_action_hidden_without_host_key_or_review(
    user: User, ui_env: SimpleNamespace, monkeypatch: pytest.MonkeyPatch, configured: bool, accepted: bool
) -> None:
    monkeypatch.setenv('INSIGHT_GREYNOISE_KEY', 'fixture' if configured else '')
    with ui_env.app.state.session_factory.begin() as db:
        reviewed(db, status='accepted' if accepted else 'unreviewed')
    await user.open('/')
    user.find(kind=ui.expansion, content=IP).elements.pop().open()
    await user.should_see('In reports added from')
    await user.should_not_see('GreyNoise Community context')
