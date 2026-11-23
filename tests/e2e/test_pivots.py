"""Infrastructure confirmation fits phones without making a provider request."""

from __future__ import annotations

import os
import re
import uuid
from typing import Any

import pytest

if not os.environ.get('INSIGHT_E2E_URL') or not os.environ.get('INSIGHT_E2E_PASSWORD'):
    pytest.skip('set INSIGHT_E2E_URL and INSIGHT_E2E_PASSWORD to run browser tests', allow_module_level=True)

from .test_browser import BASE_URL, browser, context, expect, show, sign_in

__all__ = ['browser', 'context']
pytestmark = pytest.mark.e2e


@pytest.mark.parametrize(('width', 'theme'), [(320, 'light'), (390, 'dark')])
def test_long_domain_confirmation_fits_a_phone(context: Any, width: int, theme: str) -> None:
    """Regression: a long subject overflowed the pivot dialog's heading and approval label on phones."""
    page = context.new_page()
    page.set_viewport_size({'width': width, 'height': 844})
    sign_in(page)
    expect(page.locator('.side-tabs')).to_be_visible()
    csrf = context.request.get('/api/session').json()['csrf_token']
    headers = {'X-CSRF-Token': csrf, 'Origin': BASE_URL}
    domain = 'node-' + uuid.uuid4().hex[:16] + 'a' * 39 + '.' + 'b' * 55 + '.example.com'
    response = context.request.post(
        '/api/documents',
        data={
            'title': f'Synthetic pivot layout {uuid.uuid4()}',
            'source_name': 'Browser fixture',
            'body': f'Synthetic infrastructure context: {domain}.',
            'tlp': 'CLEAR',
        },
        headers=headers,
    )
    assert response.ok, response.text()
    observation = next(item for item in response.json()['observations'] if item['value'] == domain)
    reviewed = context.request.post(
        f'/api/observations/{observation["id"]}/review', data={'status': 'accepted'}, headers=headers
    )
    assert reviewed.ok, reviewed.text()
    eligible = context.request.get('/api/pivots', params={'value': domain})
    assert eligible.ok, eligible.text()
    page.reload()
    show(page, 'Settings')
    toggle = page.get_by_role('switch', name='Use crt.sh', exact=True)
    expect(toggle).to_be_visible()
    initially_on = toggle.get_attribute('aria-checked') == 'true'
    if not initially_on:
        toggle.click()
        message = page.get_by_role('alert').filter(has_text='crt.sh is on.')
        expect(message).to_be_visible()
        message.get_by_role('button', name='Dismiss', exact=True).click()
        expect(message).to_be_hidden()
    expect(toggle).to_have_attribute('aria-checked', 'true')
    try:
        page.get_by_role('button', name=f'{theme.title()} theme', exact=True).click()
        page.get_by_role('button', name='Larger text', exact=True).click()
        expect(page.locator('html')).to_have_attribute('data-text', 'large')
        page.wait_for_function("getComputedStyle(document.documentElement).fontSize === '19px'")
        show(page, 'Investigate', 'Indicators')
        previous_result = page.locator('.q-expansion-item:visible').first.element_handle()
        assert previous_result is not None
        page.get_by_label('Search entity values', exact=True).fill(domain)
        page.wait_for_function('element => !element.isConnected', arg=previous_result)
        expect(page.locator('.q-expansion-item:visible')).to_have_count(1)
        page.get_by_role('button', name=re.compile(r'DOMAIN.*' + re.escape(domain))).click()
        page.get_by_role('button', name='Pivot', exact=True).click()
        dialog = page.get_by_role('dialog', name='Infrastructure pivots', exact=True)
        expect(dialog).to_be_visible()
        expect(dialog.get_by_role('button', name='Look up at crt.sh', exact=True)).to_be_disabled()
        for element in (
            dialog.locator('.q-card'),
            dialog.get_by_role('heading', name=f'Infrastructure around {domain}', exact=True),
            dialog.get_by_role('checkbox', name=f'I approve sending {domain} to crt.sh.', exact=True),
            dialog.get_by_role('checkbox', name=f'I approve sending {domain} to crt.sh.', exact=True).locator(
                '.q-checkbox__label'
            ),
        ):
            assert element.evaluate('e => e.scrollWidth <= e.clientWidth + 1')
        assert page.evaluate('document.documentElement.scrollWidth <= innerWidth + 1')
        dialog.get_by_role('button', name='Close', exact=True).click()
    finally:
        page.keyboard.press('Escape')
        show(page, 'Settings')
        if not initially_on:
            toggle.click()
            expect(toggle).to_have_attribute('aria-checked', 'false')
