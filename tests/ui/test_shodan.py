"""Shodan (TIP 3.7) in the entity explorer: only with a key, only after review and explicit approval."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from nicegui import ui
from nicegui.testing import User
from tests.greynoise_fixtures import IP, provider_error, reviewed

from insight import shodan
from insight.lookups import THROTTLES

pytestmark = pytest.mark.ui
FIXTURE = (Path(__file__).parents[1] / 'fixtures' / 'shodan-host.json').read_bytes()
KEY = 'testkey' * 4  # obviously fake; low entropy so secret scanners stay quiet


async def test_a_lookup_needs_approval_and_shows_refusals_and_attribution(
    user: User, ui_env: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    with ui_env.app.state.session_factory.begin() as db:
        reviewed(db)
    monkeypatch.setenv('INSIGHT_SHODAN_KEY', KEY)
    answers: list[Any] = [provider_error(403)]
    calls: list[Any] = []

    async def fake(*args: Any, **kwargs: Any) -> bytes:
        calls.append(args)
        if answers:
            raise answers.pop(0)
        return FIXTURE

    monkeypatch.setattr(shodan, 'download', fake)
    await user.open('/')
    user.find(kind=ui.expansion, content=IP).elements.pop().open()
    user.find(marker=f'entity-shodan-{IP}').click()
    await user.should_see('No cached Shodan context.')
    assert not user.find(marker='shodan-fetch').elements.pop().enabled
    assert calls == []
    user.find(marker='shodan-consent').click()
    user.find(marker='shodan-fetch').click()
    await user.should_see('your plan, credits or access do not allow it')
    THROTTLES['shodan'].reset()
    user.find(marker='shodan-consent').click()
    user.find(marker='shodan-fetch').click()
    await user.should_see('Open ports Shodan saw: 53, 443')
    await user.should_see('CVEs Shodan links to this host: CVE-2024-3400')
    await user.should_see(shodan.ATTRIBUTION)
    assert len(calls) == 2


async def test_no_key_no_button(user: User, ui_env: SimpleNamespace, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv('INSIGHT_SHODAN_KEY', raising=False)
    with ui_env.app.state.session_factory.begin() as db:
        reviewed(db)
    await user.open('/')
    user.find(kind=ui.expansion, content=IP).elements.pop().open()
    await user.should_see('In reports added from')
    await user.should_not_see('Shodan exposure context')
