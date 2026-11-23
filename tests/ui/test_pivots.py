"""Manual pivots require an enabled provider and fresh explicit operator consent."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest
from nicegui import ui
from nicegui.testing import User
from tests.greynoise_fixtures import IP, reviewed

from insight import pivots, services
from insight.lookups import THROTTLES

pytestmark = pytest.mark.ui


async def test_manual_pivot_consent(
    user: User, ui_env: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Regression: the infrastructure dialog must have an accessible name before lookup consent."""
    with ui_env.app.state.session_factory.begin() as db:
        reviewed(db)
        services.set_pivot_switch(db, 'rdap', True)
    calls: list[str] = []

    async def fake(provider: str, value: str) -> dict[str, Any]:
        calls.append(value)
        return {'found': True, 'name_servers': ['ns1.example.net'], 'nodes': []}

    monkeypatch.setattr(pivots, '_fetch', fake)
    THROTTLES['rdap'].reset()
    await user.open('/')
    await user.should_see(IP)
    user.find(kind=ui.expansion, content=IP).elements.pop().open()
    await user.should_see('Pivot')
    user.find(kind=ui.button, content='Pivot').click()
    await user.should_see('No fresh cached results.')
    assert any(
        dialog.props.get('aria-label') == 'Infrastructure pivots' and dialog.value
        for dialog in user.find(kind=ui.dialog).elements
    )
    await user.should_see('Look up at RDAP')
    assert not user.find(kind=ui.button, content='Look up at RDAP').elements.pop().enabled
    assert calls == []
    await user.should_see(f'I approve sending {IP} to RDAP.')
    user.find(kind=ui.checkbox, content=f'I approve sending {IP} to RDAP.').click()
    user.find(kind=ui.button, content='Look up at RDAP').click()
    await user.should_see('Name server: ns1.example.net')
    assert calls == [IP]
