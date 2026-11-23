"""The threat landscape panel: executive summary, trending threats with why they matter, tactics, evidence."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from nicegui import ui
from nicegui.testing.user import User

from insight.models import Document
from insight.schemas import DocumentInput
from insight.services import ingest
from insight.themes import THEMES_BY_KEY

pytestmark = pytest.mark.ui


def add_report(env: SimpleNamespace, title: str, body: str, *, days_ago: int = 0) -> None:
    with env.app.state.session_factory.begin() as db:
        doc, _ = ingest(db, DocumentInput(title=title, body=body, source_name='Feed', tlp='GREEN'))
        if days_ago:
            doc.created_at = (datetime.now(UTC) - timedelta(days=days_ago)).isoformat()


async def test_the_landscape_explains_each_threat_and_opens_its_reports(
    user: User, ui_env: SimpleNamespace
) -> None:
    add_report(ui_env, 'Ransom wave', 'A ransomware gang got in by phishing (T1566.001).')
    await user.open('/')
    with user.scope(marker='intel-brief'):
        await user.should_see('Intel brief')
        await user.should_see('Ransomware')
        await user.should_see('No history yet')
        await user.should_see('Why it matters: ' + THEMES_BY_KEY['ransomware'].impact)
        await user.should_see('What to check: ' + THEMES_BY_KEY['ransomware'].check)
        await user.should_see('Getting in (Initial Access) · 1 report · No history yet')
        await user.should_see('T1566.001 Phishing: Spearphishing Attachment (1)')
        await user.should_see('Download as a briefing to share')
        user.find(kind=ui.button, content='Ransom wave · Feed').click()
    with user.scope(marker='document-detail'):
        await user.should_see(kind=ui.label, content='Ransom wave')


async def test_a_rising_threat_leads_the_summary(user: User, ui_env: SimpleNamespace) -> None:
    for i in range(8):
        add_report(ui_env, f'Older report {i}', 'Routine patch notes.', days_ago=10 + i)
    for i in range(3):
        add_report(ui_env, f'Botnet report {i}', 'A new botnet of routers.')
    await user.open('/')
    with user.scope(marker='brief-summary'):
        await user.should_see('Trending: Botnets (3 reports, new).')
    with user.scope(marker='intel-brief'):
        await user.should_see('New')


async def test_the_period_can_be_thirty_days(user: User, ui_env: SimpleNamespace) -> None:
    add_report(ui_env, 'Earlier', 'Phishing kit.', days_ago=20)
    await user.open('/')
    with user.scope(marker='brief-summary'):
        await user.should_see(
            'No recent reports are available for the last 7 days. Sync your sources, and check their '
            'status in About this brief.'
        )
    user.find(kind=ui.toggle).elements.pop().set_value(30)
    await user.should_see('In the last 30 days, 1 new report came in from 1 source.')
    with ui_env.app.state.session_factory() as db:
        assert db.query(Document).count() == 1


@pytest.mark.parametrize(
    ('label', 'audience', 'guidance'),
    [
        ('CLEAR', 'Public', 'May be shared publicly. Copyright and source terms still apply.'),
        (
            'AMBER+STRICT',
            'Your organization only',
            'Share only with people who need to know in your organization. Do not share with clients.',
        ),
    ],
)
async def test_brief_explains_sharing_without_changing_the_source_label(
    user: User, ui_env: SimpleNamespace, label: str, audience: str, guidance: str
) -> None:
    """Regression: public feed content looked restricted, while restricted content still needs a warning."""
    with ui_env.app.state.session_factory.begin() as db:
        doc, _ = ingest(
            db,
            DocumentInput(title='Source report', body='A report on phishing.', source_name='Feed', tlp=label),
        )
        doc_id = doc.id
    await user.open('/')
    with user.scope(marker='intel-brief'):
        await user.should_see(f'{audience} · TLP:{label}')
        await user.should_see(guidance)
        await user.should_not_see('Received in the last 24 hours')
        await user.should_not_see('Reports in this brief received in the last 24 hours.')
        await user.should_see('1 report · 1 source')
        await user.should_see('Across the last 7 days')
        if label == 'CLEAR':
            await user.should_not_see('This brief has limits on who may read it.')
        else:
            await user.should_see('This brief has limits on who may read it. Keep its sharing label.')
    with ui_env.app.state.session_factory() as db:
        stored = db.get(Document, doc_id)
        assert stored is not None
        assert stored.tlp == label
