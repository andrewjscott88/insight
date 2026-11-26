"""Sign in through the gate's containerised Keycloak in a real browser (ADR 0046, TIP 3.4d).

Used by ``test_sso_roles.py``, and run as a script by the milestone gate to hand ZAP an analyst's session:

    INSIGHT_E2E_SSO_URL=https://insight.insight.test INSIGHT_E2E_SSO_PASSWORD=... \\
        python tests/e2e/sso_flow.py analyst      # prints "insight_session=..."

The gate maps ``*.insight.test`` to its TLS proxy on this machine (``INSIGHT_E2E_HOST_RULES``) and signs
both names with a throwaway CA, which the browser is told to accept; Insight itself verifies the provider
against that CA (``INSIGHT_OIDC_CA_FILE``).
"""

from __future__ import annotations

import os
import re
import sys
from typing import Any

URL = os.environ.get('INSIGHT_E2E_SSO_URL', '').rstrip('/')
PASSWORD = os.environ.get('INSIGHT_E2E_SSO_PASSWORD', '')
HOST_RULES = os.environ.get('INSIGHT_E2E_HOST_RULES', 'MAP *.insight.test 127.0.0.1')
PROVIDER = re.compile(r'^https://idp\.insight\.test/')
TIMEOUT = 30_000  # Keycloak's first login page and the workspace's first load are both slow in CI.


def launch(playwright: Any) -> Any:
    """Chromium that resolves the gate's names to the local proxy."""
    return playwright.chromium.launch(
        executable_path=os.environ.get('INSIGHT_E2E_CHROMIUM') or None,
        args=[f'--host-resolver-rules={HOST_RULES}'],
    )


def new_context(browser: Any) -> Any:
    context = browser.new_context(base_url=URL, ignore_https_errors=True)
    context.set_default_timeout(TIMEOUT)
    return context


def sign_in(context: Any, username: str, *, expect_workspace: bool = True) -> Any:
    """Sign-in page → provider → Keycloak's form → the callback page that posts on → Insight; the page."""
    page = context.new_page()
    page.goto('/login')
    page.get_by_role('link', name='Sign in with your organisation').click()
    page.wait_for_url(PROVIDER)
    page.locator('#username').fill(username)
    page.locator('#password').fill(PASSWORD)
    page.locator('#kc-login').click()
    if expect_workspace:
        page.wait_for_url(f'{URL}/')
    else:
        page.wait_for_url(f'{URL}/login')
    return page


def session_cookie(context: Any) -> str:
    (cookie,) = [c for c in context.cookies(URL) if c['name'] == 'insight_session']
    return f'{cookie["name"]}={cookie["value"]}'


def main(username: str) -> int:
    from playwright.sync_api import sync_playwright

    if not URL or not PASSWORD:
        sys.stderr.write('set INSIGHT_E2E_SSO_URL and INSIGHT_E2E_SSO_PASSWORD\n')
        return 2
    with sync_playwright() as playwright:
        browser = launch(playwright)
        context = new_context(browser)
        sign_in(context, username)
        sys.stdout.write(session_cookie(context) + '\n')
        browser.close()
    return 0


if __name__ == '__main__':
    raise SystemExit(main(sys.argv[1] if len(sys.argv) > 1 else 'analyst'))
