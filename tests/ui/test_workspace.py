"""Analyst workflows driven through the NiceGUI UI (no browser required)."""

from __future__ import annotations

import asyncio
import dataclasses
import json
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from nicegui import Client, ui
from nicegui.element_filter import ElementFilter
from nicegui.testing.user import User
from sqlalchemy import select

from insight import connectors
from insight.models import AuditEvent, Document, Note, Observation, WatchTerm
from insight.schemas import INDICATOR_KINDS, DocumentInput
from insight.services import SourceRef, ingest

pytestmark = pytest.mark.ui


def audit_actions(env: SimpleNamespace) -> list[str]:
    with env.app.state.session_factory() as db:
        return list(db.scalars(select(AuditEvent.action)))


async def load_demo(user: User) -> None:
    user.find('Load demo').click()
    await user.should_see('Synthetic demo loaded: 3 new reports')
    # NiceGUI 3 refreshes run as background tasks; should_see() polls until the list is re-rendered.
    await user.should_see('Training scenario: edge appliance activity')


async def open_document(user: User, title: str) -> None:
    # Scoped: the entity explorer also renders buttons containing document titles.
    with user.scope(marker='document-list'):
        user.find(kind=ui.button, content=title).click()
    with user.scope(marker='document-detail'):
        await user.should_see(kind=ui.label, content=title)


async def test_unauthenticated_visitors_are_redirected(ui_env: SimpleNamespace) -> None:
    response = await ui_env.client.get('/', follow_redirects=False)
    assert (response.status_code, response.headers['location']) == (303, '/login')


async def test_workspace_renders_empty_state(user: User) -> None:
    await user.should_see('Intelligence workspace')
    await user.should_see('No reports match.')
    await user.should_see('Choose a report from the list')
    await user.should_see('No watch terms yet.')
    await user.should_see('No source syncs yet.')


async def test_demo_load_is_idempotent(user: User) -> None:
    await load_demo(user)
    await user.should_see('Training scenario: edge appliance activity')
    await user.should_see('3 sources shown')
    user.find('Load demo').click()
    await user.should_see('Synthetic demo loaded: 0 new reports')


async def test_review_observation_and_note_are_audited(user: User, ui_env: SimpleNamespace) -> None:
    await load_demo(user)
    await open_document(user, 'Training scenario: edge appliance activity')
    user.find(kind=ui.button, content='Accept').click()  # lowest id = first observation
    user.find(kind=ui.textarea, content='Add a note').type('Confirmed with asset owner.')
    user.find('Save note').click()
    await user.should_see('Note saved.')
    with ui_env.app.state.session_factory() as db:
        assert db.scalar(select(Note.body)) == 'Confirmed with asset owner.'
        assert 'accepted' in db.scalars(select(Observation.review_status)).all()
    actions = audit_actions(ui_env)
    assert 'observation.review' in actions
    # Regression: the UI recorded 'note.create' while the API recorded 'note.add'.
    assert 'note.add' in actions
    assert 'note.create' not in actions


async def test_blank_note_is_rejected(user: User) -> None:
    await load_demo(user)
    await open_document(user, 'Training scenario: edge appliance activity')
    user.find('Save note').click()
    await user.should_see('Write a note first (up to 10,000 characters).')


async def test_document_status_review(user: User, ui_env: SimpleNamespace) -> None:
    await load_demo(user)
    await open_document(user, 'Training scenario: edge appliance activity')
    user.find(kind=ui.select, content='Document review').elements.pop().set_value('reviewed')
    with ui_env.app.state.session_factory() as db:
        assert 'reviewed' in db.scalars(select(Document.status)).all()
    assert 'document.review' in audit_actions(ui_env)


async def test_ingest_dialog_creates_and_deduplicates(user: User, ui_env: SimpleNamespace) -> None:
    user.find('Ingest intelligence').click()
    user.find('Document title').type('Pasted report')
    user.find('Source name').type('Analyst desk')
    user.find('Source content').type('Beacon to 192.0.2.8. Tracking CVE-2024-12345.')
    user.find('Ingest document').click()
    await user.should_see('Document ingested.')
    with ui_env.app.state.session_factory() as db:
        doc = db.scalar(select(Document))
        assert doc is not None
        assert (doc.title, doc.tlp) == ('Pasted report', 'AMBER')  # the dialog defaults to AMBER


def field_error(field: ui.input) -> str | None:
    """The message shown under a field (read through a function: mypy would keep a narrowed attribute)."""
    return field.error


async def test_ingest_dialog_validation(user: User) -> None:
    user.find('Ingest intelligence').click()
    user.find('Ingest document').click()
    # Plain-language messages on the fields themselves (WCAG 3.3.1, 3.3.3), announced by Quasar (role=alert).
    await user.should_see('Enter a title for the report (up to 300 characters).')
    title = user.find('Document title').elements.pop()
    assert isinstance(title, ui.input)
    assert field_error(title) == 'Enter a title for the report (up to 300 characters).'
    assert title.props['aria-invalid'] == 'true'
    assert not user.notify.messages, 'no message behind the dialog: the fields say it'
    user.find('Document title').type('t')
    assert field_error(title) is None, 'the message goes away as soon as the field is changed'
    assert title.props['aria-invalid'] == 'false'
    user.find('Source name').type('s')
    user.find('Source content').type('b')
    user.find('Source URL (optional)').type('javascript:alert(1)')
    user.find('Ingest document').click()
    await user.should_see('Enter a web address that starts with http:// or https://')
    url = user.find('Source URL (optional)').elements.pop()
    assert isinstance(url, ui.input)
    assert (
        field_error(url) == 'Enter a web address that starts with http:// or https://, or leave this empty.'
    )


async def test_ioc_export_dialog_opens_with_its_options(user: User) -> None:
    user.find('Export IOCs').click()
    await user.should_see('Export indicators of compromise')
    await user.should_see('Most restrictive TLP to include')
    await user.should_see('Defang values')


async def test_ioc_export_dialog_requires_an_indicator_type(user: User) -> None:
    user.find('Export IOCs').click()
    await user.should_see('Export indicators of compromise')
    user.find(kind=ui.select, content='Indicator types').elements.pop().set_value([])
    user.find('Download JSON').click()
    await user.should_see('Choose at least one indicator type')


async def test_ioc_export_dialog_previews_the_download(user: User) -> None:
    await load_demo(user)
    user.find('Export IOCs').click()
    await user.should_see('Will export 7 indicators from 3 reports (9 mentions).')
    user.find(kind=ui.select, content='Observation review status').elements.pop().set_value(['rejected'])
    await user.should_see('Nothing matches these filters.')


def record_navigation(user: User, monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, bool]]:
    """Record download navigations instead of performing them (the simulator can only open pages).

    NiceGUI <= 3.18 routes `ui.navigate.to` straight to the simulated user's `navigate.to`; 3.19 sends it
    through `Client.open`, and the simulator then drops `new_tab`. Patching both records the call once on
    either version.
    """
    calls: list[tuple[str, bool]] = []
    monkeypatch.setattr(
        user.navigate, 'to', lambda target, new_tab=False: calls.append((str(target), new_tab))
    )
    monkeypatch.setattr(
        Client, 'open', lambda _client, target, new_tab=False: calls.append((str(target), new_tab))
    )
    return calls


async def test_ioc_export_dialog_downloads_in_a_new_tab(user: User, monkeypatch: pytest.MonkeyPatch) -> None:
    calls = record_navigation(user, monkeypatch)
    await load_demo(user)
    user.find('Export IOCs').click()
    await user.should_see('Will export 7 indicators')
    user.find('Download JSON').click()
    await asyncio.sleep(0.1)
    assert calls == [
        (
            '/api/iocs/export?'
            + '&'.join(f'kind={k}' for k in INDICATOR_KINDS)
            + '&review_status=unreviewed&review_status=accepted',
            True,
        )
    ]


async def test_ioc_export_dialog_blocks_an_empty_download(
    user: User, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Regression: an empty or over-limit export opened a new tab showing a raw JSON error or empty file."""
    calls = record_navigation(user, monkeypatch)
    user.find('Export IOCs').click()
    await user.should_see('Nothing matches these filters.')  # empty workspace
    user.find('Download JSON').click()
    await asyncio.sleep(0.1)
    # Said inside the dialog: a message would wait behind it.
    await user.should_see('Nothing to download. Nothing matches these filters.')
    assert calls == []


async def test_report_reader_links_to_that_reports_iocs(user: User) -> None:
    await load_demo(user)
    await open_document(user, 'Training scenario: edge appliance activity')
    with user.scope(marker='document-detail'):
        link = user.find(kind=ui.link, content="Export this report's IOCs").elements.pop()
    assert link.props['href'].startswith('/api/iocs/export?document_id=')


def test_ioc_export_preview_text() -> None:
    from insight.ui.ioc_export import preview_text  # Imported late: ui_env resets NiceGUI's module state.

    assert preview_text({'iocs': 2, 'documents': 1, 'mentions': 3}) == (
        'Will export 2 indicators from 1 report (3 mentions).'
    )
    assert preview_text({'iocs': 0, 'documents': 0, 'mentions': 0}) == 'Nothing matches these filters.'
    assert preview_text({'iocs': 9, 'documents': 9, 'mentions': 100_001}).startswith(
        'Too large: 100,001 mentions'
    )


def test_ioc_export_url_can_leave_out_evidence() -> None:
    from insight.ui.ioc_export import export_url  # Imported late: ui_env resets NiceGUI's module state.

    assert export_url(kinds=['ip'], review_statuses=['accepted'], evidence=False) == (
        '/api/iocs/export?kind=ip&review_status=accepted&evidence=false'
    )


def test_ioc_export_url_carries_choices_and_inbox_filters() -> None:
    from insight.ui.ioc_export import export_url  # Imported late: ui_env resets NiceGUI's module state.
    from insight.ui.workspace import WorkspaceState

    inbox = WorkspaceState(q='  edge  ', status='new', tlp='AMBER+STRICT', include_superseded=True)
    url = export_url(kinds=['ip'], review_statuses=['accepted'], max_tlp='GREEN', defang=True, inbox=inbox)
    assert url == (
        '/api/iocs/export?kind=ip&review_status=accepted&max_tlp=GREEN&defang=true'
        '&q=edge&status=new&tlp=AMBER%2BSTRICT&include_superseded=true'
    )
    assert export_url(kinds=[], review_statuses=[]) == '/api/iocs/export'


async def test_search_filters_document_list(user: User) -> None:
    await load_demo(user)
    user.find('Search intelligence').type('malware')
    await user.should_see('1 sources shown')
    user.find('Search intelligence').clear()
    await user.should_see('3 sources shown')


async def test_watch_terms_highlight_and_can_be_removed(user: User, ui_env: SimpleNamespace) -> None:
    await load_demo(user)
    user.find(kind=ui.input, content='Watch term').type('Appliance')
    user.find('Add watch term').click()
    await user.should_see('Watch matches: Appliance')
    user.find(kind=ui.input, content='Watch term').type('appliance')
    user.find('Add watch term').click()
    await user.should_see('That watch term already exists.')
    user.find('Remove').click()
    await user.should_not_see('Watch matches: Appliance')
    with ui_env.app.state.session_factory() as db:
        assert db.scalar(select(WatchTerm)) is None
    assert {'watch_term.create', 'watch_term.remove'} <= set(audit_actions(ui_env))


async def test_source_sync_success_and_failure(
    user: User, ui_env: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    kev = {'vulnerabilities': [{'cveID': 'CVE-2024-12345', 'dateAdded': '2025-01-01'}]}

    async def feed(*_: Any, **__: Any) -> bytes:
        return json.dumps(kev).encode()

    monkeypatch.setattr(connectors, 'download', feed)
    user.find(kind=ui.button, content='Sync now').click()  # lowest id = first registry entry (CISA KEV)
    await user.should_see('Updated 1 KEV records; 1 new reports')
    await user.should_see('cisa-kev · success')

    async def broken(*_: Any, **__: Any) -> bytes:
        raise OSError('offline')

    monkeypatch.setattr(connectors, 'download', broken)
    user.find(kind=ui.button, content='Sync now').click()
    await user.should_see('Sync failed: OSError: offline')
    await user.should_see('cisa-kev · error')


async def test_enrichment_dialog_requires_consent(
    user: User, ui_env: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[Any] = []

    async def provider(url: str, params: Any = None, **_: Any) -> bytes:
        calls.append(params)
        return json.dumps({'data': [{'cve': 'CVE-2024-3400', 'epss': '0.97'}]}).encode()

    monkeypatch.setattr(connectors, 'download', provider)
    await load_demo(user)
    await open_document(user, 'Training scenario: edge appliance activity')
    user.find('Look up this CVE').click()
    await user.should_see('Look up CVE-2024-3400')
    fetch = user.find(kind=ui.button, content='Fetch from provider')
    assert not fetch.elements.pop().enabled  # disabled until the analyst consents
    user.find(kind=ui.checkbox).click()
    user.find(kind=ui.button, content='Fetch from provider').click()
    await user.should_see('Provider response')
    assert calls == [{'cve': 'CVE-2024-3400'}]


async def test_revoked_session_stops_callbacks(
    user: User, ui_env: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    navigated: list[str] = []
    monkeypatch.setattr(user.navigate, 'to', lambda target, new_tab=False: navigated.append(target))
    ui_env.app.state.active_sessions.clear()  # e.g. signed out in another tab
    user.find('Load demo').click()
    assert navigated
    assert set(navigated) == {'/login'}
    with ui_env.app.state.session_factory() as db:
        assert db.scalar(select(Document)) is None


# --------------------------------------------------------------------------- decision 6: revisions in the UI


@pytest.fixture
def kev_revisions(ui_env: SimpleNamespace) -> None:
    ref = SourceRef('cisa-kev', 'CVE-2024-3400')
    with ui_env.app.state.session_factory.begin() as db:
        for body in ('Original description CVE-2024-3400', 'Publisher edit CVE-2024-3400'):
            ingest(
                db, DocumentInput(title='CVE-2024-3400 · PAN-OS', body=body, source_name='CISA KEV'), ref=ref
            )


@pytest.mark.usefixtures('kev_revisions')
async def test_inbox_shows_current_revision_and_history(user: User) -> None:
    user.find('Search intelligence').type('PAN-OS')  # triggers a refresh that picks up the new data
    await user.should_see('1 sources shown')
    await open_document(user, 'CVE-2024-3400 · PAN-OS')
    await user.should_see('Publisher edit')
    await user.should_see('Revisions · 2')
    await user.should_not_see('Superseded revision.')


@pytest.mark.usefixtures('kev_revisions')
async def test_superseded_revision_banner_links_to_current(user: User) -> None:
    user.find(kind=ui.switch).click()  # include superseded revisions
    await user.should_see('2 sources shown')
    await user.should_see('new · superseded')
    user.find('Search intelligence').type('Original description')  # matches only the old revision
    await user.should_see('1 sources shown')
    await open_document(user, 'CVE-2024-3400 · PAN-OS')
    await user.should_see(
        'Superseded revision. This is an old version: the publisher has changed this report since.'
    )
    await user.should_see('Original description')
    user.find('Open current revision').click()
    await user.should_see('Publisher edit')
    await user.should_not_see('Superseded revision.')


async def test_unsaved_note_survives_a_refresh(user: User, ui_env: SimpleNamespace) -> None:
    """Regression (found by the browser gate): any re-render - a review click, a background source sync
    finishing - recreated the note box and silently discarded the analyst's unsaved text."""
    await load_demo(user)
    await open_document(user, 'Training scenario: edge appliance activity')
    user.find(kind=ui.textarea, content='Add a note').type('Half-written assessment')
    user.find(kind=ui.button, content='Accept').click()  # triggers a full refresh of the detail pane
    await user.should_see('accepted')
    await user.should_see(kind=ui.textarea, content='Half-written assessment')
    user.find('Save note').click()
    await user.should_see('Note saved.')
    with ui_env.app.state.session_factory() as db:
        assert db.scalar(select(Note.body)) == 'Half-written assessment'
    await user.should_not_see(kind=ui.textarea, content='Half-written assessment')  # draft cleared


async def test_full_length_report_through_the_ingest_dialog(user: User, ui_env: SimpleNamespace) -> None:
    """The synthetic notional report pasted into the dialog: stored exactly, all observations rendered."""
    text = (Path(__file__).parent.parent / 'corpus' / 'reports' / 'notional-intrusion-report.md').read_text(
        'utf-8'
    )
    user.find('Ingest intelligence').click()
    user.find('Document title').type('Notional Intrusion Report: Operation GLASS HARBOR (synthetic)')
    user.find('Source name').type('Notional CTI Cell')
    user.find('Source content').type(text)
    user.find('Ingest document').click()
    await user.should_see('Document ingested.')
    await user.should_see('Extracted observations (35)')
    await user.should_see('CVE-2024-3400')
    with ui_env.app.state.session_factory() as db:
        stored = db.scalar(select(Document))
        assert stored is not None
        assert stored.body == text
        assert stored.tlp == 'AMBER'


@pytest.mark.slow
async def test_workspace_size_does_not_grow_with_recurring_indicators(
    user: User, ui_env: SimpleNamespace
) -> None:
    """Regression: 100 reports sharing indicators produced ~3,500 UI elements (SALT MERIDIAN: ~5,200, 1.7 MB)
    because every entity pre-rendered all of its documents. Pivots now load lazily, a page at a time."""
    text = (Path(__file__).parent.parent / 'corpus' / 'reports' / 'notional-intrusion-report.md').read_text(
        'utf-8'
    )
    with ui_env.app.state.session_factory.begin() as db:
        for i in range(100):
            ingest(
                db, DocumentInput(title=f'GLASS HARBOR copy {i}', body=text, source_name='Notional CTI Cell')
            )
    await user.open('/')
    with user:
        elements = len(list(ElementFilter(local_scope=False)))
    assert elements < 1500, f'{elements} UI elements'


async def test_tlp_marking_raises_the_label_and_warns(user: User, ui_env: SimpleNamespace) -> None:
    """With RED allowed, the TLP:RED SALT MERIDIAN report pasted as AMBER is stored as RED, visibly."""
    ui_env.app.state.settings = dataclasses.replace(ui_env.app.state.settings, max_tlp='RED')
    text = (Path(__file__).parent.parent / 'corpus' / 'reports' / 'notional-salt-meridian.md').read_text(
        'utf-8'
    )
    user.find('Ingest intelligence').click()
    user.find('Document title').type('SALT MERIDIAN wave 2')
    user.find('Source name').type('Notional CTI Cell')
    user.find('Source content').type(text)
    user.find('Ingest document').click()
    await user.should_see('Handling label raised from TLP:AMBER to TLP:RED')
    await user.should_see('TLP:RED')
    with ui_env.app.state.session_factory() as db:
        stored = db.scalar(select(Document))
        assert stored is not None
        assert stored.tlp == 'RED'


async def test_red_reports_are_refused_by_default(user: User, ui_env: SimpleNamespace) -> None:
    """By default (INSIGHT_MAX_TLP=AMBER+STRICT) RED is not offered and a RED marking is refused."""
    user.find('Ingest intelligence').click()
    label = user.find(kind=ui.select, content='Traffic Light Protocol').elements.pop()
    assert isinstance(label, ui.select)
    assert label.options == ['CLEAR', 'GREEN', 'AMBER', 'AMBER+STRICT']
    assert label.value == 'AMBER'
    user.find('Document title').type('Partner briefing')
    user.find('Source name').type('Partner')
    user.find('Source content').type('TLP:RED\nSeen at 192.0.2.8.')
    user.find('Ingest document').click()
    await user.should_see('Refused: the text carries a TLP:RED marking')
    with ui_env.app.state.session_factory() as db:
        assert db.scalar(select(Document)) is None


async def test_workspace_actions_are_audited_as_the_operator(user: User, ui_env: SimpleNamespace) -> None:
    user.find('Ingest intelligence').click()
    user.find('Document title').type('Analyst paste')
    user.find('Source name').type('Analyst')
    user.find('Source content').type('Seen at 192.0.2.8.')
    user.find('Ingest document').click()
    await user.should_see('Document ingested.')
    with ui_env.app.state.session_factory() as db:
        assert set(db.scalars(select(AuditEvent.actor))) == {'operator'}


async def test_the_default_label_stays_valid_under_a_low_limit(user: User, ui_env: SimpleNamespace) -> None:
    ui_env.app.state.settings = dataclasses.replace(ui_env.app.state.settings, max_tlp='GREEN')
    await user.open('/')  # the dialog is built when the page loads
    user.find('Ingest intelligence').click()
    label = user.find(kind=ui.select, content='Traffic Light Protocol').elements.pop()
    assert isinstance(label, ui.select)
    assert (label.options, label.value) == (['CLEAR', 'GREEN'], 'GREEN')


async def test_entity_pivots_load_lazily_and_page(user: User, ui_env: SimpleNamespace) -> None:
    with ui_env.app.state.session_factory.begin() as db:
        for i in range(30):
            ingest(
                db, DocumentInput(title=f'Pivot report {i:02d}', body='Shared 192.0.2.99', source_name='S')
            )
    await user.open('/')
    await user.should_see('IP · 192.0.2.99 · 30 source(s)')
    await user.should_not_see('Pivot report 29 · TLP:AMBER')  # nothing rendered until the entity is opened
    expansion = user.find(kind=ui.expansion, content='192.0.2.99').elements.pop()
    expansion.open()
    await user.should_see('Pivot report 29 · TLP:AMBER')  # newest first
    await user.should_see('Show more (5 remaining)')
    await user.should_not_see('Pivot report 00 · TLP:AMBER')
    user.find('Show more (5 remaining)').click()
    await user.should_see('Pivot report 00 · TLP:AMBER')
    await user.should_not_see('Show more')


async def test_truncated_feed_items_are_labelled(user: User, ui_env: SimpleNamespace) -> None:
    with ui_env.app.state.session_factory.begin() as db:
        ingest(
            db,
            DocumentInput(title='Long feed item', body='summary', source_name='S', tlp='CLEAR'),
            truncated=True,
        )
    await user.open('/')
    await open_document(user, 'Long feed item')
    await user.should_see('Only part of this report was saved.')


# --------------------------------------------------------------------------- intel brief and sync all

CSAF_FIXTURE = Path(__file__).parents[1] / 'fixtures' / 'csaf' / 'icsa-26-323-03.json'
RSS_ITEM = b'<rss><channel><item><title>Advisory CVE-2024-9999</title></item></channel></rss>'
KEV_ONE = json.dumps({'vulnerabilities': [{'cveID': 'CVE-2024-12345', 'dateAdded': '2025-01-01'}]}).encode()


async def test_intel_brief_starts_empty_and_links_to_the_evidence(user: User) -> None:
    with user.scope(marker='intel-brief'):
        await user.should_see('No new reports in the last 7 days. Sync your sources to get the latest.')
    await load_demo(user)
    with user.scope(marker='intel-brief'):
        await user.should_see('3 new reports from 3 sources.')
        user.find(kind=ui.button, content='192.0.2.44 · 2 sources, 2 reports').click()
    # The entity explorer opens, already searching for that indicator.
    await user.should_see('IP · 192.0.2.44 · 2 source(s)')
    await user.should_not_see('DOMAIN · relay.example.org')


async def test_sync_all_sources_names_the_ones_that_failed(
    user: User, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def download(url: str, params: Any = None, **_: Any) -> bytes:
        if url == connectors.SOURCES['cisa-kev'].url:
            return KEV_ONE
        if url.endswith('changes.csv'):
            raise OSError('offline')
        return RSS_ITEM

    monkeypatch.setattr(connectors, 'download', download)
    user.find(kind=ui.button, content='Sync all sources').click()
    await user.should_see(
        '3 of 4 sources synced. Failed: CISA Security Advisories. The Sources tab shows why.'
    )
    await user.should_see('cisa-csaf · error')
    with user.scope(marker='intel-brief'):
        await user.should_see('3 new reports from 3 sources.')
    button = user.find(kind=ui.button, content='Sync all sources').elements.pop()
    assert button.enabled  # ready for the next run


async def test_sync_all_sources_success_feeds_the_brief(user: User, monkeypatch: pytest.MonkeyPatch) -> None:
    ot_index, _ = connectors.SOURCES['cisa-csaf'].indexes
    advisory = connectors.CSAF_BASE + 'OT/white/2026/icsa-26-323-03.json'
    today = datetime.now(UTC).date().isoformat()
    kev = {'cveID': 'CVE-2024-12345', 'vendorProject': 'Acme', 'product': 'Gateway', 'dateAdded': today}

    async def download(url: str, params: Any = None, **_: Any) -> bytes:
        if url == connectors.SOURCES['cisa-kev'].url:
            return json.dumps({'vulnerabilities': [kev]}).encode()
        if url == ot_index:
            return b'"2026/icsa-26-323-03.json","2026-11-19T06:00:00Z"\n'
        if url.endswith('changes.csv'):
            return b''
        if url == advisory:
            return CSAF_FIXTURE.read_bytes()
        return RSS_ITEM

    monkeypatch.setattr(connectors, 'download', download)
    user.find(kind=ui.button, content='Sync all sources').click()
    await user.should_see('All 4 sources synced. The Sources tab shows what each one added.')
    with user.scope(marker='intel-brief'):
        await user.should_see(
            '4 new reports from 4 sources. CISA says attackers are now using 1 more weakness.'
        )
        await user.should_see('Acme (1)')
        await user.should_see('libumqtt (1)')
        user.find(kind=ui.button, content=f'CVE-2024-12345 · Acme Gateway · added {today}').click()
    with user.scope(marker='document-detail'):
        await user.should_see(kind=ui.label, content='CVE-2024-12345 · Acme Gateway')


async def test_sync_all_waits_for_a_running_sync(user: User, ui_env: SimpleNamespace) -> None:
    lock: asyncio.Lock = ui_env.app.state.sync_lock
    await lock.acquire()
    try:
        user.find(kind=ui.button, content='Sync all sources').click()
        await user.should_see('Another source sync is running. Try again when it finishes.')
    finally:
        lock.release()
