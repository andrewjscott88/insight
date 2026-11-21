"""TIP 1.3: the prioritised CVE tab ranks the CVEs in your reports, says why, and opens their evidence."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from nicegui import ui
from nicegui.testing.user import User

from insight.models import KEVRecord
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
