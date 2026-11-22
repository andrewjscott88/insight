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

DOMAIN = 'example.com'


pytestmark = pytest.mark.ui


async def test_manual_pivot_consent(
    user: User, ui_env: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    with ui_env.app.state.session_factory.begin() as db:
        reviewed(db, DOMAIN)
        services.set_pivot_switch(db, 'crtsh', True)
    calls: list[str] = []

    async def fake(provider: str, value: str) -> dict[str, Any]:
        calls.append(value)
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

    monkeypatch.setattr(pivots, '_fetch', fake)
    THROTTLES['crtsh'].reset()
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
    await user.should_see('Look up at crt.sh')
    assert not user.find(kind=ui.button, content='Look up at crt.sh').elements.pop().enabled
    assert calls == []
    await user.should_see(f'I approve sending {DOMAIN} to crt.sh.')
    user.find(kind=ui.checkbox, content=f'I approve sending {DOMAIN} to crt.sh.').click()
    user.find(kind=ui.button, content='Look up at crt.sh').click()
    await user.should_see('ns1.example.net')
    assert calls == [DOMAIN]
