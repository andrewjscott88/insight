"""Manual pivots require an enabled provider and fresh explicit operator consent."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from typing import Any

import pytest
from nicegui import ui
from nicegui.testing import User
from tests.greynoise_fixtures import reviewed

from insight import pivot_data, pivots, services
from insight.lookups import THROTTLES

pytestmark = pytest.mark.ui


async def test_manual_pivot_consent(
    user: User, ui_env: SimpleNamespace, monkeypatch: pytest.MonkeyPatch, pivot_case: tuple[str, str]
) -> None:
    """Regression: the infrastructure dialog must have an accessible name before lookup consent."""
    provider_key, indicator = pivot_case
    with ui_env.app.state.session_factory.begin() as db:
        reviewed(db, indicator)
        services.set_pivot_switch(db, provider_key, True)
    calls: list[str] = []

    async def fake(provider: str, value: str) -> dict[str, Any]:
        calls.append(value)
        if provider == 'asn':
            return {'found': True, 'networks': [{'asn': 64496, 'holder': 'Synthetic network'}], 'nodes': []}
        if provider == 'circl':
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
        if provider == 'crtsh':
            return {
                'found': True,
                'certificates': [
                    {
                        'name': 'ns1.example.net',
                        'issuer': 'Synthetic CA',
                        'not_before': '2025-01-01T00:00:00+00:00',
                        'not_after': '2027-01-01T00:00:00+00:00',
                    }
                ],
                'nodes': [],
            }
        return {'found': True, 'name_servers': ['ns1.example.net'], 'nodes': []}

    monkeypatch.setattr(pivots, '_fetch', fake)
    name = pivot_data.PROVIDERS[provider_key]
    THROTTLES[provider_key].reset()
    await user.open('/')
    await user.should_see(indicator)
    user.find(kind=ui.expansion, content=indicator).elements.pop().open()
    await user.should_see('Pivot')
    user.find(kind=ui.button, content='Pivot').click()
    await user.should_see('No fresh cached results.')
    assert any(
        dialog.props.get('aria-label') == 'Infrastructure pivots' and dialog.value
        for dialog in user.find(kind=ui.dialog).elements
    )
    await user.should_see(f'Look up at {name}')
    assert not user.find(kind=ui.button, content=f'Look up at {name}').elements.pop().enabled
    assert calls == []
    await user.should_see(f'I approve sending {indicator} to {name}.')
    user.find(kind=ui.checkbox, content=f'I approve sending {indicator} to {name}.').click()
    # NiceGUI schedules the handler. Wait for its database work and render before inspecting the result.
    running = asyncio.all_tasks()
    user.find(kind=ui.button, content=f'Look up at {name}').click()
    handlers = asyncio.all_tasks() - running
    assert handlers
    await asyncio.gather(*handlers)
    expected = {'rdap': 'Name server: ns1.example.net', 'asn': 'Network number 64496: Synthetic network'}
    await user.should_see(expected.get(provider_key, 'ns1.example.net'))
    assert calls == [indicator]


async def test_missing_credentials_disable_the_provider_switch(
    user: User, ui_env: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv('INSIGHT_CIRCL_PDNS_PASSWORD', raising=False)
    await user.open('/')
    await user.should_see('Set the CIRCL passive DNS credentials on the server first.')
    switch = user.find(kind=ui.switch, content='Use CIRCL passive DNS').elements.pop()
    assert not switch.enabled
    assert not switch.value
    for name in ('RDAP', 'RIPEstat', 'crt.sh'):
        assert user.find(kind=ui.switch, content=f'Use {name}').elements.pop().enabled
