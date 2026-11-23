"""The guide's report buttons and timeline remain separate at narrow widths with larger text."""

from __future__ import annotations

import os
import uuid
from typing import Any

import pytest

if not os.environ.get('INSIGHT_E2E_URL') or not os.environ.get('INSIGHT_E2E_PASSWORD'):
    pytest.skip('set INSIGHT_E2E_URL and INSIGHT_E2E_PASSWORD to run browser tests', allow_module_level=True)

from .test_browser import BASE_URL, browser, context, expect, show, sign_in

__all__ = ['browser', 'context']
pytestmark = pytest.mark.e2e


@pytest.mark.parametrize(('width', 'theme'), [(320, 'light'), (390, 'dark')])
def test_report_title_does_not_overlap_timeline(context: Any, width: int, theme: str) -> None:
    """Regression: flex shrinking a multiline report button let its text overlap the timeline heading."""
    page = context.new_page()
    page.set_viewport_size({'width': width, 'height': 844})
    if os.environ.get('INSIGHT_E2E_DEV_NO_AUTH') == 'on':
        page.goto('/')
        expect(page.get_by_role('link', name='End session', exact=True)).to_be_visible()
    else:
        sign_in(page)
    expect(page.get_by_role('heading', name='Threat landscape', exact=True)).to_be_visible()
    token = context.request.get('/api/session').json()['csrf_token']
    headers = {'X-CSRF-Token': token, 'Origin': BASE_URL}
    title = f'Synthetic activity report with a long narrow phone title {uuid.uuid4().hex[:8]}'
    report = context.request.post(
        '/api/documents',
        data={
            'title': title,
            'body': 'Synthetic APT29 browser fixture.',
            'source_name': 'Browser fixture',
            'tlp': 'GREEN',
        },
        headers=headers,
    )
    assert report.ok, report.text()
    linked = context.request.post(
        '/api/actors/G0016/documents', data={'document_id': report.json()['id']}, headers=headers
    )
    assert linked.ok, linked.text()
    page.reload()
    page.get_by_role('button', name=f'{theme.title()} theme', exact=True).click()
    page.get_by_role('button', name='Larger text', exact=True).click()
    page.wait_for_function("getComputedStyle(document.documentElement).fontSize === '19px'")
    show(page, 'Investigate', 'Threat groups')
    page.get_by_text('Find any group by name', exact=True).click()
    page.get_by_label('Group name or ID, such as APT29 or G0016', exact=True).fill('G0016')
    page.get_by_role('button', name='G0016 · APT29', exact=True).click()
    dialog = page.get_by_role('dialog', name='Threat guide: APT29')
    button = dialog.get_by_role('button', name=title, exact=False)
    button.scroll_into_view_if_needed()
    text_box = button.locator('.q-btn__content .block').bounding_box()
    button_box = button.bounding_box()
    timeline_box = dialog.get_by_role('heading', name='Activity timeline', exact=True).bounding_box()
    assert text_box is not None
    assert button_box is not None
    assert timeline_box is not None
    assert text_box['y'] + text_box['height'] <= button_box['y'] + button_box['height'] + 1
    assert button_box['y'] + button_box['height'] <= timeline_box['y']
    assert button.evaluate('e => e.scrollWidth <= e.clientWidth')
