"""Screenshots of every section on a phone and a desktop, in both themes, for a person to look at.

The other browser tests check measurable things (no sideways scrolling, tap sizes, contrast, axe). Whether a
screen *looks* right needs eyes: the gate keeps these pictures with its results (artifact ``e2e-and-dast``).
They show only the synthetic demo data. Each picture also re-checks that the screen fits its width.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import pytest

if not os.environ.get('INSIGHT_E2E_URL') or not os.environ.get('INSIGHT_E2E_PASSWORD'):
    pytest.skip('set INSIGHT_E2E_URL and INSIGHT_E2E_PASSWORD to run browser tests', allow_module_level=True)

from .test_browser import expect, open_document, show, sign_in
from .test_theme_and_mobile import (
    DEMO_TITLE,
    INVESTIGATE,
    IPHONE_13,
    SECTIONS,
    browser,
    load_demo,
    new_context,
    overflow,
)

__all__ = ['browser']  # the fixture is used by name
pytestmark = pytest.mark.e2e
OUT = Path('screenshots')
#: (id, device options)
DEVICES = [
    ('phone', IPHONE_13),
    ('desktop', {'viewport': {'width': 1366, 'height': 900}}),
]


def snap(page: Any, name: str) -> None:
    page.wait_for_timeout(400)  # Let Quasar finish its transitions.
    page.screenshot(path=str(OUT / f'{name}.png'), full_page=True)
    assert overflow(page) <= 0, f'{name} scrolls sideways'


@pytest.mark.parametrize('scheme', ['dark', 'light'])
@pytest.mark.parametrize(('device_id', 'device'), DEVICES, ids=[d for d, _ in DEVICES])
def test_screenshot_every_section(browser: Any, device_id: str, device: dict[str, Any], scheme: str) -> None:
    OUT.mkdir(exist_ok=True)
    context = new_context(browser, device, color_scheme=scheme)
    page = context.new_page()
    try:
        sign_in(page)
        load_demo(page)
        prefix = f'{device_id}-{scheme}'
        for number, section in enumerate(SECTIONS, start=1):
            show(page, section)
            snap(page, f'{prefix}-{number}-{section.lower()}')
        for number, tab in enumerate(INVESTIGATE, start=1):
            show(page, 'Investigate', tab)
            snap(page, f'{prefix}-3{number}-investigate-{tab.split()[0].lower()}')
        show(page, 'Triage')
        open_document(page, DEMO_TITLE)
        expect(page.locator('.document-reader')).to_be_visible()
        snap(page, f'{prefix}-21-reader')
    finally:
        context.close()
