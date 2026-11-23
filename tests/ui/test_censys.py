"""Censys stays discoverable without credentials, requires consent and shows only private metadata."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from nicegui import ui
from nicegui.testing import User
from tests.greynoise_fixtures import IP, reviewed

from insight import censys

pytestmark = pytest.mark.ui
RAW = (Path(__file__).parents[1] / 'fixtures' / 'censys-host.json').read_bytes()


async def test_private_censys_lookup_requires_consent(
    user: User,
    ui_env: SimpleNamespace,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with ui_env.app.state.session_factory.begin() as db:
        reviewed(db)
    monkeypatch.setenv('INSIGHT_CENSYS_PAT', 'censys_test_token')
    monkeypatch.delenv('INSIGHT_CENSYS_ORG_ID', raising=False)
    calls: list[Any] = []

    async def provider(*args: Any, **kwargs: Any) -> bytes:
        calls.append(args)
        return RAW

    monkeypatch.setattr(censys, 'download', provider)
    await user.open('/')
    await user.should_see(kind=ui.expansion, content=IP)
    user.find(kind=ui.expansion, content=IP).elements.pop().open()
    await user.should_see(marker=f'entity-censys-{IP}')
    user.find(marker=f'entity-censys-{IP}').click()
    await user.should_see(marker='censys-fetch')
    button = user.find(marker='censys-fetch').elements.pop()
    assert isinstance(button, ui.button)
    assert not button.enabled
    assert not calls
    await user.should_see(marker='censys-consent')
    user.find(marker='censys-consent').click()
    user.find(marker='censys-fetch').click()
    await user.should_see('Synthetic network')
    await user.should_see('443/tcp')
    await user.should_see(censys.ATTRIBUTION)
    await user.should_not_see('PRIVATE BANNER')
    assert len(calls) == 1


async def test_setup_is_visible_without_a_token_and_open_access_cannot_lookup(
    user: User,
    ui_env: SimpleNamespace,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv('INSIGHT_CENSYS_PAT', raising=False)
    with ui_env.app.state.session_factory.begin() as db:
        reviewed(db)
    await user.open('/')
    await user.should_see(kind=ui.expansion, content=IP)
    user.find(kind=ui.expansion, content=IP).elements.pop().open()
    await user.should_see(marker=f'entity-censys-{IP}')
    user.find(marker=f'entity-censys-{IP}').click()
    await user.should_see(marker='censys-token-required')
    await user.should_see(marker='censys-consent')
    consent = user.find(marker='censys-consent').elements.pop()
    assert isinstance(consent, ui.checkbox)
    assert not consent.enabled
    # Switching the application mode does not change the existing session; reopen the dialog directly.
    user.find('Close').click()
    monkeypatch.setattr(ui_env.app.state, 'settings', replace(ui_env.app.state.settings, dev_no_auth=True))
    user.find(marker=f'entity-censys-{IP}').click()
    await user.should_see(marker='censys-private-required')
