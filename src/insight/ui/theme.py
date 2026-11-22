"""Colour tokens for the light and dark themes, and small shared widgets.

Every colour in the workspace comes from :data:`PALETTES`, exposed to CSS as ``--ins-*`` custom properties on
``body.body--dark`` / ``body.body--light`` (the classes Quasar sets). Panels use the classes in ``styles.py``
(``muted``, ``text-warn``, ``tlp-badge``...), never a hex value or a fixed Tailwind shade. The readability
target (ADR 0017): every text colour at least 7:1 (WCAG 2.2 AAA) on every background it is used on, and APCA
|Lc| 90+ for body text and 75+ for everything else, in both themes. ``tests/unit/test_theme.py`` checks this.
"""

from __future__ import annotations

from typing import Final

from nicegui import ui

from ..appearance import PAGE_BACKGROUND, TextSize, Theme
from .styles import QUASAR_OVERRIDES, STYLE, TEXT_SIZE_STYLE

#: Colour tokens per theme.
PALETTES: Final[dict[str, dict[str, str]]] = {
    'dark': {
        'bg': PAGE_BACKGROUND['dark'], 'panel': '#0c0a12', 'card': '#100d18', 'hover': '#19142a',
        'selected': '#211837', 'field': '#07060b', 'evidence-bg': '#0b0912',
        'line': '#2b2442', 'evidence-line': '#6d58b0', 'field-border': '#8c82ad', 'focus': '#d8cbff',
        'text': '#f4f1fb', 'muted': '#e4def3', 'accent': '#d8cbff', 'on-accent': '#12082e',
        'link': '#b9d4ff', 'warn': '#ffd98c', 'error': '#ffc6ce',
        'secondary': '#2a2145', 'highlight': '#ff8fa3',
        'tlp-clear': '#e8e5f1', 'tlp-clear-bg': '#1f1b2c', 'tlp-green': '#a6ecc9', 'tlp-green-bg': '#10241e',
        'tlp-amber': '#f7d79b', 'tlp-amber-bg': '#291f12', 'tlp-red': '#ffc2cc', 'tlp-red-bg': '#2e1119',
        'notice-bg': '#ece8f7', 'notice-text': '#0a0812',
        'notice-warn-bg': '#f7d79b', 'notice-warn-text': '#2a1a02',
        'notice-error-bg': '#ffc2cc', 'notice-error-text': '#3b0a12',
    },
    'light': {
        'bg': PAGE_BACKGROUND['light'], 'panel': '#fdfcff', 'card': '#fdfcff', 'hover': '#f1edf9',
        'selected': '#efe9fb', 'field': '#ffffff', 'evidence-bg': '#f3f1f8',
        'line': '#d8d3e4', 'evidence-line': '#8b74c8', 'field-border': '#6e6886', 'focus': '#4a1d9e',
        'text': '#15121d', 'muted': '#36314a', 'accent': '#4a1d9e', 'on-accent': '#ffffff',
        'link': '#1b3794', 'warn': '#7a3306', 'error': '#8f1d14',
        'secondary': '#e2dcf0', 'highlight': '#8f1d3a',
        'tlp-clear': '#27313d', 'tlp-clear-bg': '#e6ebf0', 'tlp-green': '#14532d', 'tlp-green-bg': '#d9f5e3',
        'tlp-amber': '#6f2f07', 'tlp-amber-bg': '#fcefc7', 'tlp-red': '#881337', 'tlp-red-bg': '#ffe2e6',
        'notice-bg': '#15121d', 'notice-text': '#ffffff',
        'notice-warn-bg': '#fcefc7', 'notice-warn-text': '#4a2204',
        'notice-error-bg': '#7f1d1d', 'notice-error-text': '#ffffff',
    },
}  # fmt: skip

TLP_CLASSES: Final = {
    'CLEAR': 'tlp-clear',
    'GREEN': 'tlp-green',
    'AMBER': 'tlp-amber',
    'AMBER+STRICT': 'tlp-amber',
    'RED': 'tlp-red',
}

#: Quasar's own colour variables, mapped onto the tokens so its components follow the theme. ``!important``
#: because NiceGUI writes its default colours as an inline style on ``<body>``. ``--q-dark`` is Quasar's
#: *dark-mode surface* (and the colour of its ``text-dark``), so it is only remapped in the dark theme.
QUASAR_VARIABLES: Final = {
    '--q-primary': 'accent',
    '--q-secondary': 'secondary',
    '--q-accent': 'highlight',
}
QUASAR_DARK_VARIABLES: Final = {'--q-dark': 'panel', '--q-dark-page': 'bg'}


def palette_css(theme: str) -> str:
    tokens = PALETTES[theme]
    variables = {**QUASAR_VARIABLES, **(QUASAR_DARK_VARIABLES if theme == 'dark' else {})}
    lines = [f'--ins-{name}:{value};' for name, value in tokens.items()]
    lines += [f'{variable}:{tokens[token]} !important;' for variable, token in variables.items()]
    return f'body.body--{theme}{{{"".join(lines)}}}'


def theme_head_html(theme: Theme, text_size: TextSize = 'standard') -> str:
    """First paint: page background, address-bar colour and text size, before the page's scripts run."""
    # Runs before <body> renders, so "Larger text" never flashes at the standard size.
    size = f'<script>document.documentElement.dataset.text = "{text_size}";</script>'
    if theme == 'system':
        return size + ''.join(
            f'<meta name="theme-color" media="(prefers-color-scheme: {name})" content="{color}">'
            f'<style>@media (prefers-color-scheme: {name}) {{ html {{ background:{color}; }} }}</style>'
            for name, color in PAGE_BACKGROUND.items()
        )
    color = PAGE_BACKGROUND[theme]
    return size + f'<meta name="theme-color" content="{color}"><style>html {{ background:{color}; }}</style>'


def apply_theme(theme: Theme, text_size: TextSize = 'standard') -> None:
    """Add the theme's styles to the current page (the dark mode element itself is created by the page)."""
    ui.add_head_html(theme_head_html(theme, text_size))
    page_backgrounds = ''.join(
        f'html:has(> body.body--{name}) {{ background:{color}; }}' for name, color in PAGE_BACKGROUND.items()
    )
    palettes = ''.join(palette_css(name) for name in PALETTES)
    ui.add_css(palettes + page_backgrounds + STYLE + TEXT_SIZE_STYLE + QUASAR_OVERRIDES)


def tlp_badge(value: str) -> None:
    css_class = TLP_CLASSES.get(value, TLP_CLASSES['CLEAR'])
    ui.label(f'TLP:{value}').classes(f'tlp-badge {css_class} text-xs rounded px-2 py-1')
