"""TIP 1.3: the prioritised CVE tab ranks the CVEs in your reports, says why, and opens their evidence."""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest
from nicegui import ui
from nicegui.testing.user import User

from insight.cve_scores import VULNCHECK_NOTICE
from insight.models import Enrichment, KEVRecord
from insight.schemas import DocumentInput
from insight.services import ingest

pytestmark = pytest.mark.ui


def add_report(env: SimpleNamespace, title: str, body: str) -> None:
    with env.app.state.session_factory.begin() as db:
        ingest(db, DocumentInput(title=title, body=body, source_name='S', tlp='GREEN'))


async def test_the_tab_ranks_cves_says_why_and_opens_the_newest_report(
    user: User, ui_env: SimpleNamespace
) -> None:
    await user.should_see('Prioritised CVEs')
    await user.should_see('No report from this time mentions a CVE yet.')
    add_report(ui_env, 'Gateway advisory', 'Patch CVE-2026-1111 and CVE-2026-2222 now.')
    with ui_env.app.state.session_factory.begin() as db:
        db.add(
            KEVRecord(
                cve='CVE-2026-2222', vendor='Acme', product='Gateway', date_added='2026-11-10',
                due_date='2026-12-01', required_action='Patch', ransomware_use='Known',
            )
        )  # fmt: skip
    await user.open('/')
    await user.should_see('Used in ransomware: 1 · No strong signal: 1')
    with user.scope(marker='cve-CVE-2026-2222'):
        await user.should_see('CISA knows of ransomware campaigns that use it.')
        await user.should_see('US federal agencies must fix it by 2026-12-01.')
    with user.scope(marker='cve-CVE-2026-1111'):
        await user.should_see('Not looked up at NIST NVD or FIRST EPSS yet.')
    rows = [e for e in user.find(kind=ui.label).elements if e.text in ('CVE-2026-2222', 'CVE-2026-1111')]
    assert [r.text for r in sorted(rows, key=lambda e: e.id)] == ['CVE-2026-2222', 'CVE-2026-1111']
    with user.scope(marker='cve-CVE-2026-2222'):
        user.find(kind=ui.button, content='Open the newest report: Gateway advisory').click()
    with user.scope(marker='document-detail'):
        await user.should_see('Gateway advisory')


async def test_regression_each_tab_has_its_own_period_control(user: User, ui_env: SimpleNamespace) -> None:
    """Both tabs label their period "Reports added in"; tests and code must find each by its marker.

    Finding the select by its label picked either one at random (a set), which made the techniques test
    flaky once this tab was added."""
    await user.should_see('Prioritised CVEs')
    [cve_period] = user.find(kind=ui.select, marker='cve-period').elements
    [technique_period] = user.find(kind=ui.select, marker='technique-period').elements
    before = technique_period.value
    cve_period.set_value(7)
    assert technique_period.value == before
    assert cve_period.value == 7


async def test_public_exploits_raise_a_cve_and_the_reader_shows_the_reports_signal(
    user: User, ui_env: SimpleNamespace
) -> None:
    """TIP 3.3: a public PoC in a report, or VulnCheck KEV, moves a CVE above EPSS and CVSS signals."""
    await user.should_see('Prioritised CVEs')
    add_report(ui_env, 'Exploit write-up', 'A public PoC for CVE-2026-3333 was published on GitHub.')
    add_report(ui_env, 'Router note', 'CVE-2026-4444 affects Acme routers.')
    listed = {'cve': 'CVE-2026-4444', 'listed': True, 'date_added': '2026-11-02', 'exploit_count': 2}
    with ui_env.app.state.session_factory.begin() as db:
        db.add(Enrichment(cve='CVE-2026-4444', provider='vulncheck', payload=json.dumps(listed)))
    await user.open('/')
    await user.should_see('Reported exploited: 1 · Public exploit: 1')
    with user.scope(marker='cve-CVE-2026-4444'):
        await user.should_see('VulnCheck KEV: exploited, listed 2026-11-02, 2 public exploits')
        await user.should_see(VULNCHECK_NOTICE)
        await user.should_see('Not looked up at NIST NVD or FIRST EPSS yet.')
    with user.scope(marker='cve-CVE-2026-3333'):
        await user.should_see('1 report mentions a public proof of concept near it')
        user.find(kind=ui.button, content='Open the newest report: Exploit write-up').click()
    with user.scope(marker='document-detail'):
        await user.should_see('This report mentions a public proof of concept near it.')
