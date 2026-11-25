"""Alerts in the workspace: adding destinations, the one-time signing secret, test alerts, removing."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest
from nicegui import ui
from nicegui.testing.user import User
from sqlalchemy import select

from insight import alerts
from insight.models import Alert, AlertTarget

pytestmark = pytest.mark.ui


def fill(user: User, style: str, name: str, address: str) -> None:
    user.find(kind=ui.select, content='Kind').elements.pop().set_value(style)
    user.find(kind=ui.input, content='Name').type(name)
    user.find(kind=ui.input, content='Webhook address or e-mail').type(address)
    user.find(kind=ui.button, content='Add destination').click()


async def test_an_analyst_adds_a_chat_webhook_and_sends_a_test(
    user: User, ui_env: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Regression: setup text about tokens must not be mistaken for a leaked webhook credential."""
    sent: list[str] = []

    async def fake_send(alert: Any, settings: Any, **_: Any) -> None:
        sent.append(alert.target.name)

    monkeypatch.setattr(alerts, 'send', fake_send)
    await user.open('/')
    await user.should_see('No alert destinations yet.')
    webhook = 'https://hooks.example.org/services/T0/B0/private-test-webhook-token'
    fill(user, 'chat', 'Security team', webhook)
    await user.should_see('Destination added. Send a test alert to check it.')
    await user.should_see('Chat webhook (Slack, Mattermost, Google Chat) · hooks.example.org')
    await user.should_not_see('private-test-webhook-token')
    await user.should_not_see(webhook)
    user.find(kind=ui.button, content='Send a test alert').click()
    await user.should_see('Test alert sent.')
    assert sent == ['Security team']
    await user.should_see('Test alert · Security team · Sent')


async def test_a_signed_webhook_shows_its_secret_once(user: User, ui_env: SimpleNamespace) -> None:
    await user.open('/')
    fill(user, 'json', 'Automation', 'https://soar.example.org/insight')
    await user.should_see('Signing secret')
    with ui_env.app.state.session_factory() as db:
        secret = db.scalars(select(AlertTarget.secret)).one()
    await user.should_see(secret)


async def test_bad_addresses_and_removal(user: User, ui_env: SimpleNamespace) -> None:
    await user.open('/')
    fill(user, 'chat', 'Plain', 'http://hooks.example.org/x')
    await user.should_see('Enter a webhook address that starts with https://.')
    fill(user, 'email', 'Mailbox', 'soc@example.org')
    await user.should_see('soc@example.org')
    user.find(kind=ui.button, content='Remove').click()
    await user.should_see('Destination removed.')
    with ui_env.app.state.session_factory() as db:
        assert db.scalars(select(AlertTarget)).all() == []
        assert db.scalars(select(Alert)).all() == []
