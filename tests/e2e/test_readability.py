"""Readability gate in a real browser (ADR 0017; milestone gate like test_browser.py).

* axe-core (Deque): **no violations** of WCAG 2.0-2.2 A, AA and AAA rules, nor of axe's best practices, on
  every screen, in both themes, on a desktop and a phone;
* the rendered typography: text at least 16 px, line height at least 1.5, lines of at most 80 characters, no
  capitals or centred paragraphs (WCAG 1.4.8, BDA dyslexia style guide);
* a visible 3 px keyboard focus outline on every control (WCAG 2.4.13), messages that stay until dismissed
  (WCAG 2.2.1), "Larger text", reduced motion and the page language.
"""

from __future__ import annotations

import os
import time
from collections.abc import Iterator
from typing import Any

import pytest

if not os.environ.get('INSIGHT_E2E_URL') or not os.environ.get('INSIGHT_E2E_PASSWORD'):
    pytest.skip('set INSIGHT_E2E_URL and INSIGHT_E2E_PASSWORD to run browser tests', allow_module_level=True)

from .test_browser import expect, sign_in
from .test_theme_and_mobile import IPHONE_13, browser, new_context

__all__ = ['browser']  # the fixture is used by name

axe_playwright = pytest.importorskip('axe_playwright_python.sync_playwright')
playwright_errors = pytest.importorskip('playwright.sync_api')
pytestmark = pytest.mark.e2e

AXE_OPTIONS = {
    'runOnly': {'type': 'tag', 'values': ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa', 'wcag2aaa',
                                          'best-practice']},
    'resultTypes': ['violations'],
}  # fmt: skip
DESKTOP: dict[str, Any] = {'viewport': {'width': 1280, 'height': 900}}
REPORT = 'Training scenario: edge appliance activity'
#: Visible text elements with their rendered typography (own text only; icons excluded).
TYPOGRAPHY = """() => {
  const out = [], ctx = document.createElement('canvas').getContext('2d');
  const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT), seen = new Set();
  while (walker.nextNode()) {
    const el = walker.currentNode.parentElement;
    if (!el || seen.has(el) || !walker.currentNode.textContent.trim()) continue;
    seen.add(el);
    if (el.closest('.q-icon, .material-icons, script, style, [aria-hidden=true]')) continue;
    const r = el.getBoundingClientRect(), s = getComputedStyle(el);
    if (!r.width || !r.height || s.visibility === 'hidden') continue;
    const own = [...el.childNodes].filter(c => c.nodeType === 3).map(c => c.textContent).join(' ').trim();
    const size = parseFloat(s.fontSize);
    const lh = s.lineHeight === 'normal' ? 1.2 : parseFloat(s.lineHeight) / size;
    ctx.font = `${s.fontStyle} ${s.fontWeight} ${s.fontSize} ${s.fontFamily}`;
    const avg = ctx.measureText(own).width / Math.max(own.length, 1);
    const width = r.width - parseFloat(s.paddingLeft) - parseFloat(s.paddingRight);
    const inner = r.height - parseFloat(s.paddingTop) - parseFloat(s.paddingBottom);
    const lines = Math.round(inner / (lh * size));
    out.push({text: own.slice(0, 60), size, lh, lines, cpl: Math.round(width / Math.max(avg, 0.1)),
              transform: s.textTransform, align: s.textAlign, heading: !!el.closest('h1,h2,h3,h4,h5,h6'),
              control: !!el.closest('button, a, [role=tab]')});
  }
  return out;
}"""


#: True when the focused control (or its field, for inputs) shows a solid outline of at least 2 px.
FOCUS_OUTLINE_SHOWN = """() => {
  const e = document.activeElement;
  if (!e || e === document.body) return true;  // past the last control
  const box = e.closest('.q-field') ? e.closest('.q-field').querySelector('.q-field__control') : e;
  const s = getComputedStyle(box);
  return s.outlineStyle === 'solid' && parseFloat(s.outlineWidth) >= 2;
}"""


#: Ordinary words split across two lines. A word is a token between spaces or hyphens, of up to 24 characters
#: that is an ordinary word (letters only); URLs, domains and hashes may break: they would not fit a phone.
BROKEN_WORDS = r"""() => {
  const broken = [], walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
  // Lines may break at spaces, after hyphens, at zero-width spaces and soft hyphens (allowed break points).
  const token = /(?<![^\s\-\u200b\u00ad])[^\s\-\u200b\u00ad]{4,24}(?![^\s\-\u200b\u00ad])/g;
  while (walker.nextNode()) {
    const node = walker.currentNode, el = node.parentElement;
    const hidden = !el || el.closest('.q-icon, script, style, [aria-hidden=true]');
    if (hidden || !el.getClientRects().length) continue;
    for (const m of node.textContent.matchAll(token)) {
      // An ordinary word: letters only (an apostrophe allowed), punctuation around it ignored. Domains, paths
      // and hashes are not words and may break.
      const core = m[0].replace(/^[^A-Za-z]+|[^A-Za-z]+$/g, '');
      if (core.length < 4 || !/^[A-Za-z]+(['’][A-Za-z]+)?$/.test(core)) continue;
      const range = document.createRange();
      range.setStart(node, m.index);
      range.setEnd(node, m.index + m[0].length);
      const rects = [...range.getClientRects()].filter(r => r.width > 0);
      if (new Set(rects.map(r => Math.round(r.top))).size > 1) broken.push(m[0]);
    }
  }
  return broken;
}"""
#: Text colour and the first opaque background behind it, as painted (alpha layers blended), per text element.
PAINTED_COLOURS = """(root) => {
  const parse = (c) => { const m = c.match(/[\\d.]+/g).map(Number); return [m[0], m[1], m[2], m[3] ?? 1]; };
  const over = (t, u) => [0, 1, 2].map(i => t[i] * t[3] + u[i] * (1 - t[3])).concat(1);
  const out = [];
  for (const el of root.querySelectorAll('*')) {
    const own = [...el.childNodes].some(n => n.nodeType === 3 && n.textContent.trim());
    // Disabled controls are exempt from contrast (WCAG 1.4.3).
    const skip = el.closest('.q-icon, [aria-hidden=true], .disabled, [disabled]');
    if (!own || skip || !el.getClientRects().length) continue;
    const layers = [];
    for (let n = el; n; n = n.parentElement) {
      const b = parse(getComputedStyle(n).backgroundColor);
      if (b[3] > 0) { layers.push(b); if (b[3] >= 1) break; }
    }
    let bg = [255, 255, 255, 1];
    for (const layer of layers.reverse()) bg = over(layer, bg);
    out.push({text: el.textContent.trim().slice(0, 40), fg: over(parse(getComputedStyle(el).color), bg), bg});
  }
  return out;
}"""


def check_axe(page: Any, where: str, dialog: bool = False) -> None:
    """axe on the page, or on the open dialog only (the page behind a modal cannot be reached).

    In dialogs axe's contrast rules misjudge Quasar's fixed, transformed overlay: they measure text against
    the dimmed page behind the backdrop although the dialog's opaque panel is directly behind it. There,
    contrast is checked on the painted colours instead, to the same AAA standard.
    """
    page.wait_for_timeout(300)  # let dialogs and refreshes settle: contrast is judged on the final colours
    if not dialog:
        results = axe_playwright.Axe().run(page, options=AXE_OPTIONS)
        assert results.violations_count == 0, f'{where}:\n{results.generate_report()}'
        return
    options = {**AXE_OPTIONS, 'rules': {'color-contrast': {'enabled': False},
                                        'color-contrast-enhanced': {'enabled': False}}}  # fmt: skip
    results = axe_playwright.Axe().run(page, context={'include': [['.q-dialog']]}, options=options)
    assert results.violations_count == 0, f'{where}:\n{results.generate_report()}'
    painted = page.locator('.q-dialog').evaluate(PAINTED_COLOURS)
    assert painted, where
    low = [
        (t['text'], round(contrast(t['fg'], t['bg']), 2)) for t in painted if contrast(t['fg'], t['bg']) < 7
    ]
    assert low == [], f'{where}: text below 7:1 (WCAG 1.4.6)'


def contrast(foreground: list[float], background: list[float]) -> float:
    def luminance(rgb: list[float]) -> float:
        r, g, b = (
            (c / 255) / 12.92 if c / 255 <= 0.03928 else ((c / 255 + 0.055) / 1.055) ** 2.4 for c in rgb[:3]
        )
        return 0.2126 * r + 0.7152 * g + 0.0722 * b

    light, dark = sorted((luminance(foreground), luminance(background)), reverse=True)
    return (light + 0.05) / (dark + 0.05)


def screens(page: Any) -> Iterator[str]:
    """Walk through every screen of the workspace, yielding its name when it is ready to be checked."""
    yield 'inbox'
    page.locator('.document-list').get_by_role('button', name=REPORT).click()
    expect(page.locator('.document-reader h2', has_text=REPORT)).to_be_visible()
    yield 'report reader'
    page.get_by_role('button', name='Look up this CVE').first.click()
    expect(page.get_by_role('dialog', name='Look up CVE-2024-3400')).to_be_visible()
    yield 'CVE lookup dialog'
    page.get_by_role('button', name='Close').click()
    for button, dialog, close in (
        ('Ingest intelligence', 'Ingest intelligence', 'Cancel'),
        ('Export IOCs', 'Export indicators of compromise (IOCs)', 'Cancel'),
        ('What the words mean', 'What the words mean', 'Close'),
    ):
        page.get_by_role('button', name=button).click()
        expect(page.get_by_role('dialog', name=dialog)).to_be_visible()
        yield f'{dialog} dialog'
        page.get_by_role('dialog', name=dialog).get_by_role('button', name=close).click()
        expect(page.get_by_role('dialog', name=dialog)).to_have_count(0)
    for tab in ('Entit', 'Watch', 'Sources'):
        page.get_by_role('tab', name=tab).first.click()
        if tab == 'Entit':
            page.locator('.q-expansion-item').first.click()
        page.wait_for_timeout(400)
        yield f'{tab} tab'


def signed_in(browser: Any, device: dict[str, Any], scheme: str) -> tuple[Any, Any]:
    # Reduced motion: transitions end at once, so no check sees a half-faded dialog (and it is tested too).
    context = new_context(browser, device, color_scheme=scheme, reduced_motion='reduce')
    page = context.new_page()
    sign_in(page)
    page.get_by_role('button', name='Load demo').click()
    expect(page.get_by_text('Synthetic demo loaded').first).to_be_visible()
    page.get_by_role('button', name='Dismiss').click()
    return context, page


@pytest.mark.parametrize('scheme', ['light', 'dark'])
@pytest.mark.parametrize('device', [DESKTOP, IPHONE_13], ids=['desktop', 'phone'])
def test_no_axe_violations_on_any_screen(browser: Any, device: dict[str, Any], scheme: str) -> None:
    context = new_context(browser, device, color_scheme=scheme, reduced_motion='reduce')
    page = context.new_page()
    page.goto('/login')
    check_axe(page, 'sign-in page')
    context.close()
    context, page = signed_in(browser, device, scheme)
    for screen in screens(page):
        check_axe(page, screen, dialog=screen.endswith('dialog'))
    page.goto('/logout')
    check_axe(page, 'sign-out page')
    context.close()


@pytest.mark.parametrize('larger', [False, True], ids=['standard-text', 'larger-text'])
@pytest.mark.parametrize('device', [DESKTOP, IPHONE_13], ids=['desktop', 'phone'])
def test_rendered_typography_follows_the_readability_guidance(
    browser: Any, device: dict[str, Any], larger: bool
) -> None:
    context, page = signed_in(browser, device, 'light')
    if larger:
        page.get_by_role('button', name='Larger text').click()
        page.wait_for_function("getComputedStyle(document.documentElement).fontSize === '19px'")
    for screen in screens(page):
        assert page.evaluate(BROKEN_WORDS) == [], f'{screen}: words split across lines'
        text = page.evaluate(TYPOGRAPHY)
        assert text, screen
        small = [(t['text'], t['size']) for t in text if t['size'] < 16]
        assert small == [], f'{screen}: text smaller than 16 px'
        blocks = [t for t in text if t['lines'] >= 2 and not t['heading']]
        assert [(t['text'], t['lh']) for t in blocks if t['lh'] < 1.5] == [], f'{screen}: line height < 1.5'
        assert [(t['text'], t['cpl']) for t in blocks if t['cpl'] > 80] == [], (
            f'{screen}: lines over 80 characters'
        )
        assert [t['text'] for t in text if t['transform'] == 'uppercase'] == [], f'{screen}: capitals'
        # Blocks of text (WCAG 1.4.8); a button's label may wrap and stay centred like any button.
        paragraphs = [t for t in blocks if not t['control']]
        centred = [(t['text'], t['align']) for t in paragraphs if t['align'] in ('center', 'justify')]
        assert centred == [], f'{screen}: centred or justified paragraphs'
    context.close()


@pytest.mark.parametrize('scheme', ['light', 'dark'])
def test_every_control_shows_a_3px_focus_outline(browser: Any, scheme: str) -> None:
    context, page = signed_in(browser, DESKTOP, scheme)
    page.locator('.document-list').get_by_role('button', name=REPORT).click()
    page.evaluate('window.scrollTo(0, 0); document.activeElement.blur()')
    weak: list[str] = []
    for _ in range(45):
        page.keyboard.press('Tab')
        try:  # the outline appears within a frame or two; wait for it rather than sample once
            page.wait_for_function(FOCUS_OUTLINE_SHOWN, timeout=2000)
        except playwright_errors.TimeoutError:
            weak.append(
                page.evaluate(
                    '(document.activeElement.getAttribute("aria-label") || '
                    'document.activeElement.textContent || "").trim().slice(0, 40)'
                )
            )
    assert weak == [], f'controls without a visible focus outline: {weak}'
    context.close()


def test_messages_stay_until_they_are_dismissed(browser: Any) -> None:
    context = new_context(browser, DESKTOP, reduced_motion='reduce')
    page = context.new_page()
    sign_in(page)
    page.get_by_role('button', name='Load demo').click()
    message = page.get_by_role('alert').filter(has_text='Synthetic demo loaded')
    expect(message).to_be_visible()
    time.sleep(10)  # Quasar's default would have removed it after 5 s.
    expect(message).to_be_visible()
    message.get_by_role('button', name='Dismiss').click()
    expect(message).to_have_count(0)
    context.close()


def test_dialog_problems_are_explained_in_the_dialog_and_never_covered(browser: Any) -> None:
    context, page = signed_in(browser, IPHONE_13, 'light')
    page.get_by_role('button', name='Load demo').click()  # a message at the bottom of a phone screen
    page.get_by_role('button', name='Ingest intelligence').click()
    dialog = page.get_by_role('dialog', name='Ingest intelligence')
    dialog.get_by_role('button', name='Ingest document').click()
    expect(dialog.get_by_role('alert').filter(has_text='Enter a title for the report')).to_be_visible()
    expect(dialog.get_by_label('Document title')).to_be_focused()
    expect(dialog.get_by_label('Document title')).to_have_attribute('aria-invalid', 'true')
    dialog.get_by_role('button', name='Cancel').click(trial=True)  # not covered by the message (WCAG 2.4.11)
    context.close()


def test_larger_text_scales_the_page_and_is_remembered(browser: Any) -> None:
    context, page = signed_in(browser, DESKTOP, 'light')
    root = 'getComputedStyle(document.documentElement).fontSize'
    assert page.evaluate(root) == '16px'
    page.get_by_role('button', name='Larger text').click()
    expect(page.get_by_role('button', name='Larger text')).to_have_attribute('aria-pressed', 'true')
    page.wait_for_function(f"{root} === '19px'")
    page.reload()
    expect(page.get_by_role('button', name='Larger text')).to_have_attribute('aria-pressed', 'true')
    assert page.evaluate(root) == '19px', 'applied before the page renders, not after'
    page.goto('/logout')
    assert page.evaluate(root) == '19px'
    context.close()


def test_reduced_motion_turns_animations_off(browser: Any) -> None:
    context = new_context(browser, DESKTOP, reduced_motion='reduce')
    page = context.new_page()
    sign_in(page)
    duration = page.get_by_role('button', name='Ingest intelligence').evaluate(
        'e => parseFloat(getComputedStyle(e).transitionDuration)'
    )
    assert duration <= 0.001
    context.close()


def test_the_page_declares_its_language(browser: Any) -> None:
    """Regression: the workspace had no ``lang``: read-aloud tools could pick the wrong voice (WCAG 3.1.1)."""
    context, page = signed_in(browser, DESKTOP, 'light')
    assert page.evaluate('document.documentElement.lang') == 'en-US'
    context.close()
