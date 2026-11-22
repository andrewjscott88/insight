"""Manual pivots require an enabled provider and fresh explicit operator consent."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest
from nicegui import ui
from nicegui.testing import User
from tests.greynoise_fixtures import reviewed

from insight import pivots, services
from insight.lookups import THROTTLES


@pytest.fixture(autouse=True)
def synthetic_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv('INSIGHT_CIRCL_PDNS_USER', 'synthetic-user')
    monkeypatch.setenv('INSIGHT_CIRCL_PDNS_PASSWORD', 'synthetic-password')


DOMAIN = 'example.com'


pytestmark = pytest.mark.ui


async def test_missing_credentials_disable_the_provider_switch(
    user: User, ui_env: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv('INSIGHT_CIRCL_PDNS_PASSWORD')
    await user.open('/')
    await user.should_see('Set the CIRCL passive DNS credentials on the server first.')
    switch = user.find(kind=ui.switch, content='Use CIRCL passive DNS').elements.pop()
    assert not switch.enabled
    assert not switch.value


async def test_manual_pivot_consent(
    user: User, ui_env: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    with ui_env.app.state.session_factory.begin() as db:
        reviewed(db, DOMAIN)
        services.set_pivot_switch(db, 'circl', True)
    calls: list[str] = []

    async def fake(provider: str, value: str) -> dict[str, Any]:
        calls.append(value)
        return {
            'found': True,
            'records': [
                {
                    'name': 'ns1.example.net',
                    'type': 'A',
                    'answer': '198.51.100.5',
                    'first_seen': '2025-01-01T00:00:00+00:00',
                    'last_seen': '2026-01-01T00:00:00+00:00',
                    'count': 12,
                }
            ],
            'nodes': [],
        }

    monkeypatch.setattr(pivots, '_fetch', fake)
    THROTTLES['circl'].reset()
    await user.open('/')
    await user.should_see(DOMAIN)
    user.find(kind=ui.expansion, content=DOMAIN).elements.pop().open()
    await user.should_see('Pivot')
    user.find(kind=ui.button, content='Pivot').click()
    await user.should_see('No fresh cached results.')
    assert any(
        dialog.props.get('aria-label') == 'Infrastructure pivots' and dialog.value
        for dialog in user.find(kind=ui.dialog).elements
    )
    await user.should_see('Look up at CIRCL passive DNS')
    assert not user.find(kind=ui.button, content='Look up at CIRCL passive DNS').elements.pop().enabled
    assert calls == []
    await user.should_see(f'I approve sending {DOMAIN} to CIRCL passive DNS.')
    user.find(kind=ui.checkbox, content=f'I approve sending {DOMAIN} to CIRCL passive DNS.').click()
    user.find(kind=ui.button, content='Look up at CIRCL passive DNS').click()
    await user.should_see('ns1.example.net')
    assert calls == [DOMAIN]
