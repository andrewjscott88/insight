"""Manual pivots require an enabled provider and fresh explicit operator consent."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest
from nicegui import ui
from nicegui.testing import User
from tests.greynoise_fixtures import IP, reviewed

from insight import pivot_data, pivots, services
from insight.lookups import THROTTLES

pytestmark = pytest.mark.ui


@pytest.mark.parametrize(('provider_key', 'indicator'), [('rdap', IP), ('crtsh', 'example.com')])
async def test_manual_pivot_consent(
    user: User, ui_env: SimpleNamespace, monkeypatch: pytest.MonkeyPatch, provider_key: str, indicator: str
) -> None:
    """Regression: the infrastructure dialog must have an accessible name before lookup consent."""
    with ui_env.app.state.session_factory.begin() as db:
        reviewed(db, indicator)
        services.set_pivot_switch(db, provider_key, True)
    calls: list[str] = []

    async def fake(provider: str, value: str) -> dict[str, Any]:
        calls.append(value)
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
    user.find(kind=ui.button, content=f'Look up at {name}').click()
    await user.should_see('ns1.example.net' if provider_key == 'crtsh' else 'Name server: ns1.example.net')
    assert calls == [indicator]
