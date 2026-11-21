"""The Sources tab: threat-research and news sources start switched off; switching one on is audited."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from nicegui import ui
from nicegui.testing.user import User
from sqlalchemy import select

from insight.models import AuditEvent

pytestmark = pytest.mark.ui


def sync_buttons(user: User) -> list[ui.button]:
    """In page order (``find`` returns a set)."""
    return sorted(user.find(kind=ui.button, content='Sync now').elements, key=lambda b: b.id)


async def test_optional_sources_start_off_and_can_be_switched_on(user: User, ui_env: SimpleNamespace) -> None:
    await user.should_see('Threat research')
    await user.should_see('Security news')
    await user.should_see('Cisco Talos')
    buttons = sync_buttons(user)
    assert len(buttons) == 10
    assert [b.enabled for b in buttons] == [True] * 4 + [False] * 6
    switches = sorted(user.find(kind=ui.switch, content='Use this source').elements, key=lambda s: s.id)
    assert [s.value for s in switches] == [True] * 4 + [False] * 6
    switches[4].set_value(True)  # Cisco Talos
    await user.should_see('Cisco Talos is on. Press Sync now to fetch its reports.')
    assert sync_buttons(user)[4].enabled
    switches[0].set_value(False)  # CISA KEV
    await user.should_see('CISA Known Exploited Vulnerabilities is off. Insight will not contact it.')
    assert not sync_buttons(user)[0].enabled
    with ui_env.app.state.session_factory() as db:
        events = db.scalars(select(AuditEvent).where(AuditEvent.action.like('source.%'))).all()
    assert [(e.action, e.object_id, e.actor) for e in events] == [
        ('source.on', 'talos', 'operator'),
        ('source.off', 'cisa-kev', 'operator'),
    ]
