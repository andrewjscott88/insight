"""The Sources tab: optional sources and automatic CVE lookups start switched off; switching is audited."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from nicegui import ui
from nicegui.testing.user import User
from sqlalchemy import select

from insight.cve_scores import NVD_NOTICE, VULNCHECK_NOTICE
from insight.models import AuditEvent
from insight.source_registry import CATEGORIES, SOURCES

pytestmark = pytest.mark.ui


def sync_buttons(user: User) -> list[ui.button]:
    """In page order (``find`` returns a set)."""
    return sorted(user.find(kind=ui.button, content='Sync now').elements, key=lambda b: b.id)


async def test_optional_sources_start_off_and_can_be_switched_on(user: User, ui_env: SimpleNamespace) -> None:
    await user.should_see('Threat research')
    await user.should_see('Security news')
    await user.should_see('Cisco Talos')
    await user.should_see('AlienVault Open Threat Exchange (OTX)')
    defaults = [not s.optional for category in CATEGORIES for s in SOURCES.values() if s.category == category]
    buttons = sync_buttons(user)
    for name in ('Indicator feeds', 'URLhaus', 'ThreatFox', 'MalwareBazaar'):
        await user.should_see(name)
    assert [b.enabled for b in buttons] == defaults
    switches = sorted(user.find(kind=ui.switch, content='Use this source').elements, key=lambda s: s.id)
    assert [s.value for s in switches] == defaults
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


async def test_automatic_lookups_start_off_and_show_what_waits(user: User, ui_env: SimpleNamespace) -> None:
    await user.should_see('Automatic CVE lookups')
    await user.should_see(NVD_NOTICE)
    nvd = user.find(kind=ui.switch, content='Look up severity at NIST NVD by itself').elements.pop()
    epss = user.find(
        kind=ui.switch, content='Look up attack likelihood at FIRST EPSS by itself'
    ).elements.pop()
    assert (nvd.value, epss.value) == (False, False)
    nvd.set_value(True)
    await user.should_see('Insight will look up CVEs at NIST NVD by itself. It sends only CVE numbers.')
    await user.should_see('NIST NVD: all looked up')  # The workspace starts empty.
    await user.should_not_see('FIRST EPSS: all looked up')
    nvd.set_value(False)
    await user.should_see('Automatic lookups at NIST NVD are off.')
    with ui_env.app.state.session_factory() as db:
        events = db.scalars(select(AuditEvent).where(AuditEvent.action.like('lookup.%'))).all()
        assert [(e.action, e.object_id, e.actor) for e in events] == [
            ('lookup.on', 'nvd', 'operator'),
            ('lookup.off', 'nvd', 'operator'),
        ]


async def test_vulncheck_lookups_show_their_notice_and_wait_for_the_key(
    user: User, ui_env: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    """TIP 3.3: VulnCheck KEV needs the operator's own key; without it the switch says what is missing."""
    monkeypatch.delenv('INSIGHT_VULNCHECK_API_KEY', raising=False)
    await user.should_see(VULNCHECK_NOTICE)
    vulncheck = user.find(
        kind=ui.switch, content='Look up exploitation and public exploits at VulnCheck KEV by itself'
    ).elements.pop()
    assert vulncheck.value is False
    vulncheck.set_value(True)
    await user.should_see('VulnCheck KEV: waiting for INSIGHT_VULNCHECK_API_KEY')
    monkeypatch.setenv('INSIGHT_VULNCHECK_API_KEY', 'vc-key')
    vulncheck.set_value(False)
    vulncheck.set_value(True)
    await user.should_see('VulnCheck KEV: all looked up')
