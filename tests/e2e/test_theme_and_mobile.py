"""Real-browser checks of the colour themes and the phone layout (milestone gate, like test_browser.py).

Only a browser computes styles and layout: which theme Quasar applies, whether text is readable as
rendered, whether anything overflows a 320 px screen, input font sizes (iOS zooms below 16 px) and where the
page scrolls.
"""

from __future__ import annotations

import os
import re
from collections.abc import Iterator
from typing import Any

import pytest

if not os.environ.get('INSIGHT_E2E_URL') or not os.environ.get('INSIGHT_E2E_PASSWORD'):
    pytest.skip('set INSIGHT_E2E_URL and INSIGHT_E2E_PASSWORD to run browser tests', allow_module_level=True)

# Shares test_browser's browser fixture and sign-in helpers.
from .test_browser import BASE_URL, TIMEOUT, browser, expect, open_document, sign_in

__all__ = ['browser']  # the fixture is used by name

pytestmark = pytest.mark.e2e

PAGE_BACKGROUND = {'light': 'rgb(243, 245, 247)', 'dark': 'rgb(11, 18, 28)'}
DEMO_TITLE = 'Training scenario: edge appliance activity'
#: Playwright's descriptors for these phones (pinned: a second Playwright instance cannot run beside the
#: shared browser fixture's). Viewport, touch and pixel ratio are what matter for layout.
IPHONE_13: dict[str, Any] = {
    'user_agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X) AppleWebKit/605.1.15 '
    '(KHTML, like Gecko) Version/15.0 Mobile/15E148 Safari/604.1',
    'viewport': {'width': 390, 'height': 664},
    'device_scale_factor': 3,
    'is_mobile': True,
    'has_touch': True,
}
PIXEL_7: dict[str, Any] = {
    'user_agent': 'Mozilla/5.0 (Linux; Android 14; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) '
    'Chrome/141.0.0.0 Mobile Safari/537.36',
    'viewport': {'width': 412, 'height': 839},
    'device_scale_factor': 2.625,
    'is_mobile': True,
    'has_touch': True,
}
SMALLEST: dict[str, Any] = {'viewport': {'width': 320, 'height': 640}, 'is_mobile': True, 'has_touch': True}
#: (id, device, colour scheme)
PHONES = [
    ('iphone-13-dark', IPHONE_13, 'dark'),
    ('pixel-7-light', PIXEL_7, 'light'),
    ('320px-light', SMALLEST, 'light'),
]


def new_context(browser: Any, device: dict[str, Any] | None = None, **options: Any) -> Any:
    context = browser.new_context(base_url=BASE_URL, **(device or {}), **options)
    context.set_default_timeout(TIMEOUT)
    return context


def body_theme(page: Any) -> str:
    classes = page.evaluate('document.body.className')
    return 'dark' if 'body--dark' in classes else 'light' if 'body--light' in classes else 'none'


def background(page: Any, selector: str = 'body') -> str:
    return str(page.eval_on_selector(selector, 'e => getComputedStyle(e).backgroundColor'))


def overflow(page: Any) -> int:
    """How many pixels the page is wider than the screen (anything > 0 means sideways scrolling)."""
    return int(page.evaluate('document.documentElement.scrollWidth - window.innerWidth'))


def luminance(rgb: str) -> float:
    channels = [int(c) / 255 for c in re.findall(r'\d+', rgb)[:3]]
    r, g, b = (c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4 for c in channels)
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def contrast(foreground: str, background: str) -> float:
    light, dark = sorted((luminance(foreground), luminance(background)), reverse=True)
    return (light + 0.05) / (dark + 0.05)


#: The colour of an element and of the first ancestor (or itself) with an opaque background.
RENDERED_COLOURS = """e => {
    let node = e;
    while (node && ['rgba(0, 0, 0, 0)', 'transparent'].includes(getComputedStyle(node).backgroundColor)) {
        node = node.parentElement;
    }
    return [getComputedStyle(e).color, node ? getComputedStyle(node).backgroundColor : 'rgb(255, 255, 255)'];
}"""


def rendered_contrast(locator: Any) -> float:
    foreground, back = locator.evaluate(RENDERED_COLOURS)
    return contrast(foreground, back)


#: True once the reader's top edge is in the top quarter of the screen, i.e. the page scrolled to it (merely
#: being partly visible below the list does not count).
READER_AT_TOP = """() => {
    const top = document.querySelector('.document-reader')?.getBoundingClientRect().top;
    return top !== undefined && top >= -1 && top < window.innerHeight / 4;
}"""


def load_demo(page: Any) -> None:
    page.get_by_role('button', name='Load demo').click()
    expect(page.get_by_text('Synthetic demo loaded').first).to_be_visible()
    expect(page.get_by_role('button', name=DEMO_TITLE).first).to_be_visible()


# --------------------------------------------------------------------------- themes


@pytest.mark.parametrize('scheme', ['light', 'dark'])
def test_system_theme_follows_the_device(browser: Any, scheme: str) -> None:
    context = new_context(browser, color_scheme=scheme)
    page = context.new_page()
    page.goto('/login')
    assert page.evaluate('document.documentElement.dataset.theme') == 'system'
    assert background(page) == PAGE_BACKGROUND[scheme]
    sign_in(page)
    expect(page.get_by_role('button', name='System theme')).to_have_attribute('aria-pressed', 'true')
    assert body_theme(page) == scheme
    assert background(page) == PAGE_BACKGROUND[scheme]
    context.close()


def test_a_theme_choice_applies_at_once_and_is_remembered_on_this_device_only(browser: Any) -> None:
    context = new_context(browser, color_scheme='dark')
    page = context.new_page()
    sign_in(page)
    expect(page.get_by_role('button', name='System theme')).to_be_visible()
    assert body_theme(page) == 'dark'

    page.get_by_role('button', name='Light theme').click()
    expect(page.locator('body.body--light')).to_have_count(1)
    assert background(page) == PAGE_BACKGROUND['light']
    assert page.eval_on_selector('meta[name=theme-color]', 'm => m.content') == '#f3f5f7'
    cookie = next(c for c in context.cookies() if c['name'] == 'insight_theme')
    assert (cookie['value'], cookie['sameSite'], cookie['path']) == ('light', 'Lax', '/')

    page.reload()
    expect(page.get_by_role('button', name='Light theme')).to_have_attribute('aria-pressed', 'true')
    assert body_theme(page) == 'light'
    page.goto('/logout')
    assert page.evaluate('document.documentElement.dataset.theme') == 'light'
    assert background(page) == PAGE_BACKGROUND['light']

    other_device = new_context(browser, color_scheme='dark')
    other = other_device.new_page()
    other.goto('/login')
    assert background(other) == PAGE_BACKGROUND['dark']
    other_device.close()
    context.close()


def test_dark_choice_overrides_a_light_device(browser: Any) -> None:
    context = new_context(browser, color_scheme='light')
    page = context.new_page()
    sign_in(page)
    page.get_by_role('button', name='Dark theme').click()
    expect(page.locator('body.body--dark')).to_have_count(1)
    page.get_by_role('button', name='System theme').click()
    expect(page.locator('body.body--light')).to_have_count(1)
    context.close()


@pytest.mark.parametrize('scheme', ['light', 'dark'])
def test_rendered_text_is_readable(browser: Any, scheme: str) -> None:
    """Contrast as the browser renders it (Quasar's own styles included), not just the token values."""
    context = new_context(browser, color_scheme=scheme)
    page = context.new_page()
    sign_in(page)
    load_demo(page)
    samples = {
        'filled button': page.get_by_role('button', name='Ingest intelligence'),
        'outlined button': page.get_by_role('button', name='Export IOCs'),
        'muted label': page.get_by_text(re.compile(r'sources shown · newest first')),
        'TLP badge': page.get_by_text('TLP:GREEN', exact=True).first,
        'TLP AMBER+STRICT badge': page.get_by_text('TLP:AMBER+STRICT', exact=True).first,
        'selected theme button': page.get_by_role('button', name='System theme'),
    }
    for name, locator in samples.items():
        ratio = rendered_contrast(locator)
        assert ratio >= 4.5, f'{scheme}: {name} renders at {ratio:.2f}:1'
    context.close()


def test_regression_desktop_shows_every_tab_label(browser: Any) -> None:
    """Regression: `hidden sm:block` labels never showed (Quasar's `.hidden` is !important)."""
    context = new_context(browser, viewport={'width': 1280, 'height': 900})
    page = context.new_page()
    sign_in(page)
    for label in ('Intelligence inbox', 'Entity explorer', 'Watch terms', 'Sources'):
        expect(page.get_by_role('tab', name=label)).to_be_visible()
    expect(page.get_by_text('Private intelligence workspace')).to_be_visible()
    expect(page.get_by_role('button', name='Back to list')).to_have_count(0)
    context.close()


# --------------------------------------------------------------------------- phones


@pytest.fixture(params=PHONES, ids=[phone[0] for phone in PHONES])
def phone(browser: Any, request: pytest.FixtureRequest) -> Iterator[Any]:
    _, device, scheme = request.param
    context = new_context(browser, device, color_scheme=scheme)
    yield context
    context.close()


def test_phone_sign_in_fits_and_does_not_zoom(phone: Any) -> None:
    page = phone.new_page()
    page.goto('/login')
    assert overflow(page) <= 0
    password = page.get_by_label('Workspace password')
    assert float(password.evaluate('e => parseFloat(getComputedStyle(e).fontSize)')) >= 16
    box = page.locator('.login-card').bounding_box()
    assert box['x'] >= 0
    assert box['x'] + box['width'] <= page.viewport_size['width']


def test_phone_workspace_fits_every_tab_and_dialog(phone: Any) -> None:
    page = phone.new_page()
    sign_in(page)
    load_demo(page)
    assert overflow(page) <= 0
    for short in ('Entities', 'Watch', 'Sources', 'Inbox'):
        tab = page.get_by_role('tab', name=short)
        expect(tab).to_be_visible()
        tab.click()
        expect(tab).to_have_attribute('aria-selected', 'true')
        assert overflow(page) <= 0, f'{short} tab overflows'
    for button, close in (('Ingest intelligence', 'Cancel'), ('Export IOCs', 'Cancel')):
        page.get_by_role('button', name=button).click()
        dialog = page.locator('.q-dialog .dialog-card')
        expect(dialog).to_be_visible()
        box = dialog.bounding_box()
        assert box['x'] >= 0
        assert box['x'] + box['width'] <= page.viewport_size['width'], f'{button} dialog is too wide'
        page.get_by_role('button', name=close).click()
        expect(dialog).to_have_count(0)


def test_phone_inputs_are_16px_and_buttons_are_easy_to_tap(phone: Any) -> None:
    page = phone.new_page()
    sign_in(page)
    load_demo(page)
    sizes = page.evaluate(
        """() => [...document.querySelectorAll('input, textarea')]
            .filter(e => e.offsetParent !== null && e.type !== 'checkbox' && e.type !== 'hidden')
            .map(e => parseFloat(getComputedStyle(e).fontSize))"""
    )
    assert sizes
    assert min(sizes) >= 16, 'iOS zooms into inputs below 16px'
    open_document(page, DEMO_TITLE)
    for name in ('Load demo', 'Export IOCs', 'Ingest intelligence', 'Accept', 'Back to list', 'Light theme'):
        box = page.get_by_role('button', name=name).first.bounding_box()
        assert box['height'] >= 40, f'{name} is {box["height"]}px tall'


def test_phone_reader_comes_into_view_and_back_to_list_returns(phone: Any) -> None:
    page = phone.new_page()
    sign_in(page)
    load_demo(page)
    page.evaluate('window.scrollTo(0, 0)')
    # The first (newest) card: the one furthest above the reader.
    page.locator('.document-list .source-card').first.get_by_role('button').click()
    page.wait_for_function(READER_AT_TOP)
    expect(page.locator('.document-reader h2')).to_be_in_viewport()
    page.get_by_role('button', name='Back to list').click()
    expect(page.locator('.document-list-pane .source-selected')).to_be_in_viewport()


def test_phone_opening_a_report_from_the_entity_explorer_shows_it(phone: Any) -> None:
    page = phone.new_page()
    sign_in(page)
    load_demo(page)
    page.get_by_role('tab', name='Entities').click()
    page.get_by_text('IP · 192.0.2.44', exact=False).first.click()
    page.get_by_role('button', name=re.compile('^Training scenario: edge appliance activity · TLP')).click()
    expect(page.locator('.document-reader h2', has_text=DEMO_TITLE)).to_be_visible()
    page.wait_for_function(READER_AT_TOP)
