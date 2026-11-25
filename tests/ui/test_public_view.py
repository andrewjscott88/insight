"""The read-only public view (``INSIGHT_PUBLIC_VIEW=on``, ADR 0046): visitors who are not signed in read the
TLP:CLEAR intelligence as viewers. They cannot change anything, download through the API, or see settings,
sharing, working notes or anything above TLP:CLEAR."""

from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any

import pytest
from nicegui import ui
from nicegui.testing.user import User
from sqlalchemy import func, select

from insight import services
from insight.models import AuditEvent, Document
from insight.ratelimit import Policy
from insight.schemas import DocumentInput

from .conftest import sign_in

pytestmark = pytest.mark.ui


@pytest.fixture
def ui_settings() -> dict[str, Any]:
    return {'public_view': True, 'max_tlp': 'CLEAR'}


def plant(ui_env: SimpleNamespace, title: str, tlp: str, body: str = 'Seen at 192.0.2.8.') -> str:
    """Store a report directly (a report from before ``INSIGHT_MAX_TLP=CLEAR`` may be above it)."""
    with ui_env.app.state.session_factory.begin() as db:
        doc, _ = services.ingest(db, DocumentInput(title=title, body=body, source_name='Analyst', tlp=tlp))
        services.add_note(db, doc.id, 'Internal: escalate to the client.')
        return doc.id


@pytest.fixture
async def visitor(ui_env: SimpleNamespace) -> User:
    simulated = User(ui_env.client)
    await simulated.open('/')
    return simulated


async def test_a_visitor_reads_without_signing_in(visitor: User) -> None:
    await visitor.should_see('Public view')
    await visitor.should_see(kind=ui.tab, content='Intel Brief')
    await visitor.should_see(kind=ui.link, content='Sign in')
    for tab in ('Settings', 'Share'):
        await visitor.should_not_see(kind=ui.tab, content=tab)
    for button in ('Import Intel', 'Export IOCs'):
        await visitor.should_not_see(kind=ui.button, content=button)
    await visitor.should_not_see(kind=ui.link, content='Sign out')


async def test_a_visitor_sees_clear_reports_only_and_no_working_notes(
    ui_env: SimpleNamespace, visitor: User
) -> None:
    clear = plant(ui_env, 'Clear advisory', 'CLEAR')
    plant(ui_env, 'Amber internal report', 'AMBER')
    await visitor.open(f'/?report={clear}')
    await visitor.should_see('Clear advisory')
    await visitor.should_not_see('Amber internal report')
    await visitor.should_not_see('Internal: escalate to the client.')
    for button in ('Accept', 'Add to product', 'Add to hunt package', 'Look up this CVE'):
        await visitor.should_not_see(kind=ui.button, content=button)
    await visitor.should_not_see(kind=ui.textarea, content='Add a note')
    await visitor.should_not_see(kind=ui.link, content='Download this report as JSON')
    await visitor.should_see('Document review:')


async def test_a_report_above_clear_opens_nothing(ui_env: SimpleNamespace, visitor: User) -> None:
    amber = plant(ui_env, 'Amber internal report', 'AMBER')
    await visitor.open(f'/?report={amber}')
    await visitor.should_not_see('Amber internal report')
    await visitor.should_not_see('Seen at 192.0.2.8.')


async def test_a_visitor_cannot_write_even_by_calling_the_workspace(ui_env: SimpleNamespace) -> None:
    from insight.permissions import Permission
    from insight.ui.workspace import NotPermitted, Workspace

    request: Any = SimpleNamespace(session={})
    ws = Workspace(app=ui_env.app, sessions=ui_env.app.state.session_factory, request=request)
    assert ws.public
    assert ws.reader_limit == 'CLEAR'
    assert not any(ws.can(permission) for permission in Permission)
    with pytest.raises(NotPermitted), ws.write(Permission.READ):
        pass


async def test_a_visitor_builds_a_guide_without_leaving_a_trace(
    ui_env: SimpleNamespace, visitor: User
) -> None:
    await visitor.should_see(kind=ui.tab, content='Threat Hunt')
    visitor.find(kind=ui.tab, content='Threat Hunt').click()
    await visitor.should_see(marker='hunt-guide-builder')
    await visitor.should_not_see(marker='saved-hunt-packages')
    await visitor.should_not_see(marker='saved-intelligence-reports')
    with ui_env.app.state.session_factory() as db:
        assert db.scalar(select(func.count()).select_from(AuditEvent)) == 0


async def test_the_api_stays_closed_to_visitors(ui_env: SimpleNamespace) -> None:
    client = ui_env.client
    for method, path in (('GET', '/api/stats'), ('GET', '/api/session'), ('GET', '/api/documents')):
        assert (await client.request(method, path)).status_code == 401, path
    assert (await client.post('/api/documents', json={})).status_code in (401, 403)


async def test_signing_in_still_opens_the_whole_workspace(ui_env: SimpleNamespace) -> None:
    login = await ui_env.client.get('/login')
    assert 'Read the public view without signing in' in login.text
    await sign_in(ui_env.client)
    operator = User(ui_env.client)
    await operator.open('/')
    await operator.should_see(kind=ui.tab, content='Settings')
    await operator.should_see(kind=ui.button, content='Import Intel')
    await operator.should_not_see(marker='public-view-banner')


async def test_page_loads_are_rate_limited_by_address(
    ui_env: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr('insight.ui.page.READ', Policy('read', 1, 60))
    assert (await ui_env.client.get('/')).status_code == 200
    refused = await ui_env.client.get('/')
    assert refused.status_code == 429
    assert 'retry-after' in refused.headers


async def test_nothing_is_stored_by_a_visit(ui_env: SimpleNamespace, visitor: User) -> None:
    await visitor.should_see('Intel Brief')
    with ui_env.app.state.session_factory() as db:
        assert db.scalar(select(func.count()).select_from(Document)) == 0
        assert services.count_operator_sessions(db, at=datetime.now(UTC)) == 0
