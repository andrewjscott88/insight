"""Long real-world feed text fits the smallest phone with larger text, including open access."""

from __future__ import annotations

import os
import uuid
from typing import Any

import pytest

if not os.environ.get('INSIGHT_E2E_URL') or not os.environ.get('INSIGHT_E2E_PASSWORD'):
    pytest.skip('set INSIGHT_E2E_URL and INSIGHT_E2E_PASSWORD to run browser tests', allow_module_level=True)

from .test_browser import BASE_URL, browser, context, expect, sign_in

__all__ = ['browser', 'context']
pytestmark = pytest.mark.e2e


@pytest.mark.parametrize('theme', ['light', 'dark'])
def test_long_feed_text_fits_a_320px_phone_with_larger_text(context: Any, theme: str) -> None:
    page = context.new_page()
    page.set_viewport_size({'width': 320, 'height': 740})
    if os.environ.get('INSIGHT_E2E_DEV_NO_AUTH') == 'on':
        page.goto('/')
        expect(page.get_by_text('Temporary open access', exact=True)).to_be_visible()
        expect(page.get_by_role('link', name='End session', exact=True)).to_be_visible()
    else:
        sign_in(page)
    expect(page.get_by_role('heading', name='Threat landscape', exact=True)).to_be_visible()
    token = context.request.get('/api/session').json()['csrf_token']
    long_url = 'https://example.invalid/' + 'feeditem' * 15 + '/' + uuid.uuid4().hex
    response = context.request.post(
        '/api/documents',
        data={
            'title': long_url,
            'source_name': 'FeedPublisher' * 8,
            'body': f'Synthetic narrow-screen test only. Link: {long_url}',
            'tlp': 'CLEAR',
        },
        headers={'X-CSRF-Token': token, 'Origin': BASE_URL},
    )
    assert response.ok, response.text()
    page.reload()
    page.get_by_role('button', name=f'{theme.title()} theme', exact=True).click()
    page.get_by_role('button', name='Larger text', exact=True).click()
    expect(page.locator('html')).to_have_attribute('data-text', 'large')
    page.wait_for_function("getComputedStyle(document.documentElement).fontSize === '19px'")
    page.get_by_role('heading', name='Threat landscape', exact=True).click()
    page.mouse.move(0, 0)
    assert page.evaluate('document.documentElement.scrollWidth <= window.innerWidth')
    assert page.locator('.workspace-controls > *').evaluate_all(
        'elements => elements.every(e => e.getBoundingClientRect().right <= innerWidth)'
    )
    assert page.locator('.brief-evidence .block').evaluate_all(
        'elements => elements.length > 0 && elements.every(e => e.scrollWidth <= e.clientWidth)'
    )
    card = page.locator('.source-card').filter(has=page.get_by_role('button', name=long_url, exact=True))
    expect(card).to_be_visible()
    # The inbox is a scroller: root width alone misses clipped titles and summaries inside its cards.
    assert card.evaluate('e => e.scrollWidth <= e.clientWidth')
    for selector in ('.q-btn__content', '.q-btn__content > .block', '.line-clamp-2'):
        assert card.locator(selector).evaluate('e => e.scrollWidth <= e.clientWidth')
    card.get_by_role('button', name=long_url, exact=True).click()
    reader = page.locator('.document-reader')
    expect(reader.get_by_role('heading', name=long_url, exact=True)).to_be_visible()
    # The tab panel clips reader overflow too: include title, source metadata, controls and indicators.
    assert reader.evaluate('e => e.scrollWidth <= e.clientWidth')
