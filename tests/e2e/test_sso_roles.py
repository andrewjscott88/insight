"""Sign-in through a real provider, and the role matrix in a real browser (ADR 0046, TIP 3.4d).

The milestone gate starts Keycloak (pinned by digest, test realm ``tests/e2e/sso/realm.json``), Insight and a
TLS proxy, then runs this module. Keycloak's groups give the roles (``INSIGHT_OIDC_*_GROUPS``):
``viewer``, ``analyst`` and ``admin`` each sign in through Keycloak's own form, and ``newcomer``, in no
group, waits for approval. Each role is checked twice: what the workspace offers, and what the server does
when the browser calls the API itself, with the session's CSRF token, so a refusal can only be the role's.

The tests run in file order: the admin test comes last and finds the others in Settings → People. The gate
checks the analyst's session cookie on its own before handing it to ZAP's active scan.
Skipped unless ``INSIGHT_E2E_SSO_URL`` is set.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from typing import Any

import pytest

pytestmark = pytest.mark.e2e
if not os.environ.get('INSIGHT_E2E_SSO_URL') or not os.environ.get('INSIGHT_E2E_SSO_PASSWORD'):
    pytest.skip(
        'set INSIGHT_E2E_SSO_URL and INSIGHT_E2E_SSO_PASSWORD to run the SSO gate', allow_module_level=True
    )
playwright_api = pytest.importorskip('playwright.sync_api')
expect = playwright_api.expect
expect.set_options(timeout=30_000)

from tests.e2e.sso_flow import URL, launch, new_context, sign_in  # noqa: E402

REFUSED = 'Your role does not allow this'
#: (method, path, JSON body) → whether a viewer, an analyst and an admin may. One route per kind of permission
#: that a browser session can reach without side effects on the other tests.
MATRIX: list[tuple[str, str, dict[str, object] | None, tuple[bool, bool, bool]]] = [
    ('GET', '/api/brief', None, (True, True, True)),
    ('GET', '/api/audit', None, (True, True, True)),
    ('GET', '/api/sources', None, (True, True, True)),
    (
        'POST',
        '/api/documents',
        {'title': 'SSO gate report', 'source_name': 'SSO gate', 'body': 'Seen at 198.51.100.7.'},
        (False, True, True),
    ),
    ('PUT', '/api/schedules/cisa-kev', {'interval_minutes': 0}, (False, False, True)),
]
ROLES = ('viewer', 'analyst', 'admin')

CALL = """async ([method, path, body]) => {
  const session = await (await fetch('/api/session')).json();
  const response = await fetch(path, {
    method,
    headers: {'X-CSRF-Token': session.csrf_token, 'Content-Type': 'application/json'},
    body: body === null ? undefined : JSON.stringify(body),
  });
  return [response.status, (await response.text()).slice(0, 300)];
}"""


@pytest.fixture(scope='module')
def browser() -> Iterator[Any]:
    with playwright_api.sync_playwright() as playwright:
        browser = launch(playwright)
        yield browser
        browser.close()


@pytest.fixture
def context(browser: Any) -> Iterator[Any]:
    context = new_context(browser)
    yield context
    context.close()


def call(page: Any, method: str, path: str, body: dict[str, object] | None) -> tuple[int, str]:
    status, text = page.evaluate(CALL, [method, path, body])
    return int(status), str(text)


def check_matrix(page: Any, role: str) -> None:
    column = ROLES.index(role)
    for method, path, body, allowed in MATRIX:
        status, text = call(page, method, path, body)
        if allowed[column]:
            assert 200 <= status < 300, f'{role}: {method} {path} -> {status} {text}'
        else:  # Refused for the role, not for anything else (the CSRF token is sent).
            assert status == 403, f'{role}: {method} {path} -> {status} {text}'
            assert REFUSED in text, f'{role}: {method} {path} was refused for another reason: {text}'


def check_session(page: Any, context: Any, role: str) -> None:
    session = page.evaluate("async () => (await fetch('/api/session')).json()")
    assert session['role'] == role
    assert session['actor'].startswith('user:')
    (cookie,) = [c for c in context.cookies(URL) if c['name'] == 'insight_session']
    assert (cookie['secure'], cookie['httpOnly'], cookie['sameSite']) == (True, True, 'Strict')


def open_settings(page: Any) -> None:
    page.locator('.side-tabs').get_by_role('tab', name='Settings', exact=True).click()
    expect(page.get_by_text('Public sources').first).to_be_visible()


def test_a_newcomer_waits_for_approval(context: Any) -> None:
    page = sign_in(context, 'newcomer', expect_workspace=False)
    expect(page.get_by_text('an administrator has not given you a role yet')).to_be_visible()
    status = page.evaluate("async () => (await fetch('/api/session')).status")
    assert status == 401


def test_a_viewer_reads(context: Any) -> None:
    page = sign_in(context, 'viewer')
    check_session(page, context, 'viewer')
    expect(page.get_by_text('Intel brief').first).to_be_visible()
    expect(page.get_by_role('button', name='Import Intel')).to_have_count(0)
    expect(page.get_by_role('button', name='Sync all sources')).to_have_count(0)
    check_matrix(page, 'viewer')
    open_settings(page)
    expect(page.get_by_role('button', name='Sync now')).to_have_count(0)
    expect(page.get_by_text('Recent activity')).to_have_count(0)


def test_an_analyst_works_but_changes_no_settings(context: Any) -> None:
    page = sign_in(context, 'analyst')
    check_session(page, context, 'analyst')
    expect(page.get_by_role('button', name='Import Intel')).to_be_visible()
    check_matrix(page, 'analyst')
    open_settings(page)
    expect(page.get_by_role('switch', name='Use this source')).to_have_count(0)
    expect(page.get_by_text('Not in use').first).to_be_visible()
    expect(page.get_by_text('Recent activity')).to_have_count(0)


def test_an_admin_manages_people(context: Any) -> None:
    page = sign_in(context, 'admin')
    check_session(page, context, 'admin')
    check_matrix(page, 'admin')
    open_settings(page)
    expect(page.get_by_role('switch', name='Use this source').first).to_be_visible()
    for name in ('Vera Viewer', 'Andy Analyst', 'Noor Newcomer', 'Ada Admin'):
        expect(page.get_by_text(name, exact=True).first).to_be_visible()
    expect(page.get_by_text('Waiting for approval')).to_be_visible()
    expect(page.get_by_text('Role: analyst, from provider groups')).to_be_visible()
    expect(page.get_by_text('This is you.', exact=False)).to_be_visible()
    expect(page.get_by_text('Recent activity')).to_be_visible()
