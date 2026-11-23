"""Browser cookie policy against the real app, using reserved HTTPS hosts and no network services.

Chromium's Fetch interception routes both hosts locally, including each HTTP redirect hop. The ASGI
client's cookie jar is cleared on every request, so only cookies actually sent by the browser reach the
app. An ordinary HTTP client cannot reproduce SameSite.
"""

from __future__ import annotations

import base64
import dataclasses
import os
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any
from urllib.parse import urlsplit

import pytest
from fastapi import Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.testclient import TestClient
from starlette.responses import Response

from insight.config import Settings
from insight.main import create_app

pytestmark = pytest.mark.e2e
if not os.environ.get('INSIGHT_E2E_URL'):
    pytest.skip('set INSIGHT_E2E_URL to run browser tests', allow_module_level=True)
playwright_api = pytest.importorskip('playwright.sync_api')
expect = playwright_api.expect
WORKSPACE = 'https://insight.example'
ENTRY = 'https://entry.example/'


@pytest.fixture(scope='module')
def browser() -> Iterator[Any]:
    with playwright_api.sync_playwright() as playwright:
        browser = playwright.chromium.launch(executable_path=os.environ.get('INSIGHT_E2E_CHROMIUM') or None)
        yield browser
        browser.close()


@contextmanager
def app_context(
    browser: Any,
    settings: Settings,
    *,
    open_access: bool = True,
    javascript: bool = True,
    reject_session: bool = False,
) -> Iterator[tuple[Any, Any]]:
    settings = dataclasses.replace(
        settings, dev_no_auth=open_access, secure_cookies=True, allowed_hosts=('insight.example',)
    )
    app = create_app(settings, with_ui=False)

    @app.get('/')
    def workspace(request: Request) -> Response:
        # A tiny workspace behind the same stored-session gate, without NiceGUI's global page registry.
        if not app.state.is_authenticated(request.session):
            return RedirectResponse('/login', status_code=303)
        return HTMLResponse('<!doctype html><html lang="en"><h1>Workspace</h1></html>')

    context = browser.new_context(java_script_enabled=javascript)
    context.set_default_timeout(10_000)
    with TestClient(app, base_url=WORKSPACE, follow_redirects=False) as client:

        def intercept(page: Any) -> None:
            # context.route can miss a fulfilled redirect's next request in pinned Chromium versions.
            # Fetch pauses every hop, preserving browser navigation and cookie policy without real DNS.
            cdp = context.new_cdp_session(page)

            def handle(event: dict[str, Any]) -> None:
                request = event['request']
                url = request['url']
                if url == ENTRY:
                    status = 200
                    headers = [('content-type', 'text/html')]
                    body = (
                        f'<a href="{WORKSPACE}/">Open workspace</a>'
                        f'<a href="{WORKSPACE}/login">Open sign in</a>'
                    ).encode()
                elif url == WORKSPACE + '/api/session' and reject_session:
                    status, headers, body = 401, [('content-type', 'application/json')], b'{}'
                elif urlsplit(url).netloc == 'insight.example':
                    client.cookies.clear()
                    response = client.request(
                        request['method'],
                        url,
                        headers=request['headers'],
                        content=request.get('postData'),
                    )
                    assert len(response.headers.get_list('set-cookie')) <= 1, 'Do not merge multiple cookies'
                    status, headers, body = (
                        response.status_code,
                        list(response.headers.multi_items()),
                        response.content,
                    )
                else:
                    cdp.send(
                        'Fetch.failRequest',
                        {'requestId': event['requestId'], 'errorReason': 'BlockedByClient'},
                    )
                    return
                cdp.send(
                    'Fetch.fulfillRequest',
                    {
                        'requestId': event['requestId'],
                        'responseCode': status,
                        'responseHeaders': [{'name': name, 'value': value} for name, value in headers],
                        'body': base64.b64encode(body).decode('ascii'),
                    },
                )

            cdp.on('Fetch.requestPaused', handle)
            cdp.send('Fetch.enable', {'patterns': [{'urlPattern': '*', 'requestStage': 'Request'}]})

        page = context.new_page()
        intercept(page)
        try:
            yield context, page
        finally:
            context.close()


@pytest.mark.parametrize('link', ['Open workspace', 'Open sign in'])
@pytest.mark.parametrize('javascript', [True, False])
def test_external_entry_keeps_strict_cookies_and_reaches_the_workspace(
    browser: Any, settings: Settings, link: str, javascript: bool
) -> None:
    """Regression: external links withheld Strict cookies through an endless login redirect chain."""
    with app_context(browser, settings, javascript=javascript) as (context, page):
        page.goto(ENTRY)
        page.get_by_role('link', name=link, exact=True).click()
        if not javascript:
            page.get_by_role('link', name='Continue to workspace', exact=True).click()
        expect(page.get_by_role('heading', name='Workspace', exact=True)).to_be_visible()
        expect(page).to_have_url(WORKSPACE + '/')
        cookie = next(c for c in context.cookies() if c['name'] == 'insight_session')
        assert cookie['sameSite'] == 'Strict'
        assert cookie['secure'] is True
        assert cookie['httpOnly'] is True


def test_cookie_rejection_stays_on_the_entry_page(browser: Any, settings: Settings) -> None:
    """Regression: unavailable session cookies caused repeated navigation instead of a usable entry page."""
    with app_context(browser, settings, reject_session=True) as (_, page):
        # Reject just the session probe, as a browser that cannot return its session cookie would see it.
        page.goto(WORKSPACE + '/login')
        expect(page.get_by_role('status')).to_have_text('Allow cookies for this site, then try again.')
        expect(page.get_by_role('link', name='Continue to workspace', exact=True)).to_be_visible()
        expect(page).to_have_url(WORKSPACE + '/login')


@pytest.mark.parametrize('theme', ['light', 'dark'])
def test_entry_fits_a_small_phone_with_large_text(browser: Any, settings: Settings, theme: str) -> None:
    """Regression: the entry page and longer product descriptor must fit a phone at larger text sizes."""
    with app_context(browser, settings, javascript=False) as (context, page):
        context.add_cookies(
            [
                {'name': 'insight_theme', 'value': theme, 'url': WORKSPACE},
                {'name': 'insight_text', 'value': 'large', 'url': WORKSPACE},
            ]
        )
        page.set_viewport_size({'width': 320, 'height': 700})
        page.goto(WORKSPACE + '/login')
        expect(page.get_by_text('Cyber Threat Intelligence Platform', exact=True)).to_be_visible()
        expect(page.locator('html')).to_have_attribute('data-text', 'large')
        expect(page.locator('html')).to_have_attribute('data-theme', theme)
        assert page.evaluate('document.documentElement.scrollWidth <= window.innerWidth')
        target = page.get_by_role('link', name='Continue to workspace', exact=True).bounding_box()
        assert target is not None
        assert target['height'] >= 44
        assert target['width'] >= 44


def test_protected_mode_external_entry_still_requires_sign_in(browser: Any, settings: Settings) -> None:
    """Regression: external entry must end on a page without bypassing password checks or relaxing cookies."""
    with app_context(browser, settings, open_access=False) as (_, page):
        page.goto(WORKSPACE + '/login')
        page.get_by_label('Workspace password').fill(settings.password)
        page.get_by_role('button', name='Open workspace', exact=False).click()
        expect(page.get_by_role('heading', name='Workspace', exact=True)).to_be_visible()
        page.goto(ENTRY)
        page.get_by_role('link', name='Open workspace', exact=True).click()
        expect(page.get_by_label('Workspace password')).to_be_visible()
        expect(page).to_have_url(WORKSPACE + '/login')
        page.get_by_label('Workspace password').fill(settings.password)
        page.get_by_role('button', name='Open workspace', exact=False).click()
        expect(page.get_by_role('heading', name='Workspace', exact=True)).to_be_visible()
