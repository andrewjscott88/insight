"""The executive brief stays readable and leads to the evidence behind a claim."""

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


def test_summary_links_to_its_source_report_on_phone_and_desktop(context: Any) -> None:
    """Regression: a headline must open its supporting report after the longer brief is rendered."""
    page = context.new_page()
    sign_in(page)
    expect(page.get_by_role('heading', name='Intel brief', exact=True)).to_be_visible()
    token = context.request.get('/api/session').json()['csrf_token']
    cve = f'CVE-2026-{uuid.uuid4().int % 900_000 + 100_000}'
    titles = {}
    for source in ('A', 'B'):
        title = f'Brief browser fixture {source} {uuid.uuid4().hex[:8]}'
        response = context.request.post(
            '/api/documents',
            data={
                'title': title,
                'source_name': f'Brief test source {source}',
                'body': f'Synthetic browser test only. This report mentions {cve}.',
                'tlp': 'CLEAR',
            },
            headers={'X-CSRF-Token': token, 'Origin': BASE_URL},
        )
        assert response.ok, response.text()
        titles[response.json()['id']] = title
    brief = context.request.get('/api/brief').json()
    recent = next(h for h in brief['highlights'] if h['title'] == 'Received in the last 24 hours')
    evidence = next(item for item in recent['evidence'] if item['document_id'] in titles)
    page.set_viewport_size({'width': 390, 'height': 844})
    page.reload()
    expect(page.get_by_role('heading', name='Executive summary', exact=True)).to_be_visible()
    expect(page.get_by_role('heading', name='A recurring topic in the reports', exact=True)).to_be_visible()
    expect(page.get_by_role('heading', name='Exploited now', exact=True)).to_be_visible()
    expect(page.get_by_role('heading', name='Most severe', exact=True)).to_be_visible()
    assert page.evaluate('document.documentElement.scrollWidth <= window.innerWidth')
    # This title can also appear in another highlight; the recent-receipt card is the intended context.
    card = page.locator('.brief-priority').filter(
        has=page.get_by_role('heading', name='Received in the last 24 hours', exact=True)
    )
    card.get_by_role('button', name=f'View evidence: {evidence["text"]}', exact=True).click()
    reader = page.locator('.document-reader h2', has_text=titles[evidence['document_id']])
    expect(reader).to_be_visible()
    expect(reader).to_be_in_viewport()
    page.set_viewport_size({'width': 1280, 'height': 900})
    page.reload()
    card.get_by_role('button', name=f'View evidence: {evidence["text"]}', exact=True).click()
    expect(reader).to_be_visible()
    expect(reader).to_be_in_viewport()
