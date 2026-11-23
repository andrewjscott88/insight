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


def test_restricted_sharing_label_wraps_at_phone_widths(context: Any) -> None:
    """Regression: the plain audience plus a long TLP token must fit without clipping or scrolling."""
    page = context.new_page()
    sign_in(page)
    token = context.request.get('/api/session').json()['csrf_token']
    response = context.request.post(
        '/api/documents',
        data={
            'title': f'Sharing label browser fixture {uuid.uuid4().hex[:8]}',
            'body': 'Synthetic test only. A report on phishing.',
            'source_name': 'Sharing label test source',
            'tlp': 'AMBER+STRICT',
        },
        headers={'X-CSRF-Token': token, 'Origin': BASE_URL},
    )
    assert response.ok, response.text()
    for width in (320, 390, 1280):
        page.set_viewport_size({'width': width, 'height': 844})
        page.reload()
        badge = page.locator('.intel-brief .tlp-badge')
        expect(badge).to_have_text('Your organization only · TLP:AMBER+STRICT')
        expect(badge).to_be_visible()
        assert badge.evaluate('(el) => el.scrollWidth <= el.clientWidth')
        assert page.evaluate('document.documentElement.scrollWidth <= window.innerWidth')
        expect(page.get_by_text('Received in the last 24 hours', exact=True)).to_have_count(0)
        expect(page.locator('.brief-context')).to_have_count(0)
        expect(page.get_by_text('About this brief', exact=True)).to_have_count(0)
        summary = page.locator('.summary-box').bounding_box()
        available = page.locator('.brief-overview').bounding_box()
        assert summary is not None
        assert available is not None
        assert abs(summary['width'] - available['width']) <= 1


def test_summary_links_to_its_source_report_on_phone_and_desktop(context: Any) -> None:
    """Regression: a headline must open its supporting report after the longer brief is rendered."""
    page = context.new_page()
    sign_in(page)
    expect(page.get_by_role('heading', name='Intel brief', exact=True)).to_be_visible()
    token = context.request.get('/api/session').json()['csrf_token']
    cve = f'CVE-2026-{uuid.uuid4().int % 900_000 + 100_000}'
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
    brief = context.request.get('/api/brief').json()
    recurring = next(h for h in brief['highlights'] if h['title'] == 'A recurring topic in the reports')
    evidence = recurring['evidence'][0]
    page.set_viewport_size({'width': 390, 'height': 844})
    page.reload()
    expect(page.get_by_role('heading', name='Executive summary', exact=True)).to_be_visible()
    expect(page.get_by_role('heading', name='A recurring topic in the reports', exact=True)).to_be_visible()
    expect(page.get_by_role('heading', name='Exploited now', exact=True)).to_be_visible()
    expect(page.get_by_role('heading', name='Most severe', exact=True)).to_be_visible()
    assert page.evaluate('document.documentElement.scrollWidth <= window.innerWidth')
    # Other reports can share this topic. Follow the exact evidence chosen by the recurring-topic card.
    card = page.locator('.brief-priority').filter(
        has=page.get_by_role('heading', name='A recurring topic in the reports', exact=True)
    )
    card.get_by_role('button', name=f'View evidence: {evidence["text"]}', exact=True).click()
    reader = page.locator('.document-reader h2', has_text=evidence['text'])
    expect(reader).to_be_visible()
    expect(reader).to_be_in_viewport()
    page.set_viewport_size({'width': 1280, 'height': 900})
    page.reload()
    card.get_by_role('button', name=f'View evidence: {evidence["text"]}', exact=True).click()
    expect(reader).to_be_visible()
    expect(reader).to_be_in_viewport()
