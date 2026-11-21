"""Real-browser end-to-end tests (milestone gate) against a running instance, e.g. the built container.

    INSIGHT_E2E_URL=http://127.0.0.1:8080 INSIGHT_E2E_PASSWORD=... pytest tests/e2e -m e2e

Unlike the NiceGUI simulation tests, these execute the real JavaScript/Vue/Quasar front end, websockets,
cookies and browser security behaviour. Skipped unless ``INSIGHT_E2E_URL`` is set.

Start the server with ``INSIGHT_MAX_TLP=RED``: one test ingests the synthetic TLP:RED report to check that its
marking raises the label (the default limit would refuse it).
"""

from __future__ import annotations

import os
import re
import uuid
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

pytestmark = pytest.mark.e2e

BASE_URL = os.environ.get('INSIGHT_E2E_URL', '')
PASSWORD = os.environ.get('INSIGHT_E2E_PASSWORD', '')
if not BASE_URL or not PASSWORD:
    pytest.skip('set INSIGHT_E2E_URL and INSIGHT_E2E_PASSWORD to run browser tests', allow_module_level=True)
playwright_api = pytest.importorskip('playwright.sync_api')
expect = playwright_api.expect
TIMEOUT = 15_000  # generous: the first page load in a fresh browser context fetches ~1 MB of framework JS
expect.set_options(timeout=TIMEOUT)


@pytest.fixture(scope='module')
def browser() -> Iterator[Any]:
    with playwright_api.sync_playwright() as playwright:
        # INSIGHT_E2E_CHROMIUM: an already-installed Chromium/Chrome instead of Playwright's download.
        browser = playwright.chromium.launch(executable_path=os.environ.get('INSIGHT_E2E_CHROMIUM') or None)
        yield browser
        browser.close()


@pytest.fixture
def context(browser: Any) -> Iterator[Any]:
    context = browser.new_context(base_url=BASE_URL)
    context.set_default_timeout(TIMEOUT)
    yield context
    context.close()


def sign_in(page: Any, password: str = PASSWORD) -> None:
    page.goto('/login')
    page.get_by_label('Workspace password').fill(password)
    page.get_by_role('button', name='Open workspace').click()


def open_document(page: Any, title: str) -> None:
    """Click a list entry and wait until the detail pane shows *that* document.

    Loading the demo auto-selects a document, so "Extracted observations" may already be visible for a
    different one; typing before the pane re-renders would target a textarea that is about to be replaced.
    """
    page.get_by_role('button', name=title).first.click()
    expect(page.locator('.document-reader h2', has_text=title)).to_be_visible()


def test_wrong_password_is_rejected(context: Any) -> None:
    page = context.new_page()
    sign_in(page, 'definitely-not-the-password')
    expect(page.get_by_role('alert')).to_have_text('Incorrect password.')
    expect(page).to_have_url(re.compile(r'/login$'))


def test_security_headers_reach_the_browser(context: Any) -> None:
    page = context.new_page()
    response = page.goto('/login')
    assert response is not None
    headers = response.headers
    assert headers['x-frame-options'] == 'DENY'
    assert headers['x-content-type-options'] == 'nosniff'
    cookie = next(c for c in context.cookies() if c['name'] == 'insight_session')
    assert cookie['httpOnly'] is True
    assert cookie['sameSite'] == 'Strict'


def test_demo_loads(context: Any) -> None:
    page = context.new_page()
    sign_in(page)
    page.get_by_role('button', name='Load demo').click()
    expect(page.get_by_text('Synthetic demo loaded')).to_be_visible()
    expect(
        page.get_by_role('button', name='Training scenario: edge appliance activity').first
    ).to_be_visible()


def test_analyst_workflow(context: Any) -> None:
    """Ingest -> review an observation -> write a note, on a document unique to this run.

    The server is long-lived (a container in CI), so browser tests create their own data instead of relying on
    shared demo documents whose review state earlier runs may already have changed.
    """
    title = f'E2E report {uuid.uuid4().hex[:8]}'
    page = context.new_page()
    sign_in(page)
    expect(page.get_by_role('heading', name='Threat landscape', exact=True)).to_be_visible()
    page.get_by_role('button', name='Ingest intelligence').click()
    page.get_by_label('Document title').fill(title)
    page.get_by_label('Source name').fill('Browser test')
    page.get_by_label('Source content').fill('Exploitation of CVE-2024-3400 from 192.0.2.77 was observed.')
    page.get_by_role('button', name='Ingest document').click()
    expect(page.get_by_text('Document ingested.')).to_be_visible()
    expect(page.locator('.document-reader h2', has_text=title)).to_be_visible()
    page.get_by_role('button', name='Accept').first.click()
    # Wait for the server to confirm the review (the pane re-renders) before typing into it.
    expect(page.get_by_text(re.compile(r'· accepted$')).first).to_be_visible()
    page.get_by_label('Add a note').fill('Reviewed in the browser end-to-end test.')
    page.get_by_role('button', name='Save note').click()
    expect(page.get_by_text('Note saved.')).to_be_visible()
    expect(page.get_by_text('Reviewed in the browser end-to-end test.').first).to_be_visible()


def test_search_filters_the_inbox(context: Any) -> None:
    page = context.new_page()
    sign_in(page)
    page.get_by_role('button', name='Load demo').click()
    page.get_by_label('Search intelligence').fill('malware')
    expect(page.get_by_text(re.compile(r'^1 sources shown'))).to_be_visible()


def test_sign_out_revokes_other_tabs(context: Any) -> None:
    workspace = context.new_page()
    sign_in(workspace)
    expect(workspace.get_by_role('heading', name='Threat landscape', exact=True)).to_be_visible()
    other = context.new_page()
    other.goto('/logout')
    # exact: the page also has "Sign out everywhere", and Playwright matches names by substring.
    other.get_by_role('button', name='Sign out', exact=True).click()
    expect(other).to_have_url(re.compile(r'/login$'))
    # The first tab is still open; its next action must be refused and bounce to the sign-in page.
    workspace.get_by_role('button', name='Load demo').click()
    expect(workspace).to_have_url(re.compile(r'/login'))


def test_sign_out_everywhere_reaches_another_browser(browser: Any, context: Any) -> None:
    """Review B4: a second browser (its own cookies, like another device) signs this one out too."""
    workspace = context.new_page()
    sign_in(workspace)
    expect(workspace.get_by_role('heading', name='Threat landscape', exact=True)).to_be_visible()
    other_device = browser.new_context(base_url=BASE_URL)
    other_device.set_default_timeout(TIMEOUT)
    try:
        page = other_device.new_page()
        sign_in(page)
        expect(page.get_by_role('heading', name='Threat landscape', exact=True)).to_be_visible()
        page.goto('/logout')
        page.get_by_role('button', name='Sign out everywhere', exact=True).click()
        expect(page).to_have_url(re.compile(r'/login$'))
    finally:
        other_device.close()
    workspace.get_by_role('button', name='Load demo').click()
    expect(workspace).to_have_url(re.compile(r'/login'))


def test_full_length_notional_report(context: Any) -> None:
    """The synthetic notional report pasted into the real browser dialog.

    Checks that the embedded <script> tag stays inert text, nothing is fetched from the report's
    infrastructure, and every extracted observation is rendered.
    """
    text = (Path(__file__).parent.parent / 'corpus' / 'reports' / 'notional-intrusion-report.md').read_text(
        'utf-8'
    )
    title = f'GLASS HARBOR {uuid.uuid4().hex[:8]}'
    page = context.new_page()
    requests: list[str] = []
    page.on('request', lambda request: requests.append(request.url))
    sign_in(page)
    page.get_by_role('button', name='Ingest intelligence').click()
    page.get_by_label('Document title').fill(title)
    page.get_by_label('Source name').fill('Notional CTI Cell')
    page.get_by_label('Source content').fill(text)
    page.get_by_role('button', name='Ingest document').click()
    expect(page.locator('.document-reader h2', has_text=title)).to_be_visible()
    expect(page.get_by_text('Extracted observations (37)')).to_be_visible()
    assert page.locator('script[src*="cdn-update"]').count() == 0
    assert not [url for url in requests if 'example.com' in url or 'example.net' in url]


def test_second_notional_report_tlp_and_javascript_offsets(context: Any) -> None:
    """SALT MERIDIAN: its TLP:RED marking is enforced, and the API's *_utf16 offsets slice correctly in
    JavaScript even after the astral-plane emoji (the code-point offsets would be off by one there)."""
    text = (Path(__file__).parent.parent / 'corpus' / 'reports' / 'notional-salt-meridian.md').read_text(
        'utf-8'
    )
    title = f'SALT MERIDIAN {uuid.uuid4().hex[:8]}'
    page = context.new_page()
    sign_in(page)
    page.get_by_role('button', name='Ingest intelligence').click()
    page.get_by_label('Document title').fill(title)
    page.get_by_label('Source name').fill('Notional CTI Cell')
    page.get_by_label('Source content').fill(text)
    page.get_by_role('button', name='Ingest document').click()
    expect(page.locator('.document-reader h2', has_text=title)).to_be_visible()
    expect(page.get_by_text('Handling label raised from TLP:AMBER to TLP:RED')).to_be_visible()
    expect(page.get_by_text('Extracted observations (54)')).to_be_visible()
    doc_id = page.locator('a', has_text='Download this report as JSON').get_attribute('href').split('/')[3]
    # Array.from() iterates code points (Python semantics); String.slice() uses UTF-16 code units.
    check = page.evaluate(
        """async (id) => {
            const d = await (await fetch('/api/documents/' + id)).json();
            const points = Array.from(d.body);
            const bad = d.observations.filter(o =>
                d.body.slice(o.start_offset_utf16, o.end_offset_utf16) !==
                points.slice(o.start_offset, o.end_offset).join(''));
            const naive = d.observations.filter(o =>
                d.body.slice(o.start_offset, o.end_offset) !==
                points.slice(o.start_offset, o.end_offset).join(''));
            return {total: d.observations.length, bad: bad.length, naive: naive.length};
        }""",
        doc_id,
    )
    assert check['bad'] == 0
    assert check['naive'] > 0  # the code-point offsets really are wrong for JavaScript after the emoji
