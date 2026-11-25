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
        'bg': PAGE_BACKGROUND['dark'], 'panel': '#101820', 'card': '#121d26', 'hover': '#192a34',
        'selected': '#12333f', 'field': '#0a1117', 'evidence-bg': '#0d1922',
        'line': '#29414e', 'evidence-line': '#527c91', 'field-border': '#779baa', 'focus': '#7cecff',
        'text': '#f3f8fb', 'muted': '#d3e3eb', 'accent': '#7cecff', 'on-accent': '#031319',
        'link': '#a3edff', 'warn': '#ffd98c', 'error': '#ffc6ce',
        'secondary': '#17303a', 'highlight': '#ff8fa3',
        'tlp-clear': '#e4eff5', 'tlp-clear-bg': '#1b2932', 'tlp-green': '#a6ecc9', 'tlp-green-bg': '#10241e',
        'tlp-amber': '#f7d79b', 'tlp-amber-bg': '#291f12', 'tlp-red': '#ffc2cc', 'tlp-red-bg': '#2e1119',
        'notice-bg': '#dff8ff', 'notice-text': '#07151b',
        'notice-warn-bg': '#f7d79b', 'notice-warn-text': '#2a1a02',
        'notice-error-bg': '#ffc2cc', 'notice-error-text': '#3b0a12',
    },
    'light': {
        'bg': PAGE_BACKGROUND['light'], 'panel': '#ffffff', 'card': '#ffffff', 'hover': '#e8f1f4',
        'selected': '#e0f2f4', 'field': '#ffffff', 'evidence-bg': '#eaf1f4',
        'line': '#c4d3db', 'evidence-line': '#5f8296', 'field-border': '#526b7a', 'focus': '#005564',
        'text': '#10202c', 'muted': '#2c4655', 'accent': '#005564', 'on-accent': '#ffffff',
        'link': '#064f63', 'warn': '#7a3306', 'error': '#8f1d14',
        'secondary': '#dce9ed', 'highlight': '#8f1d3a',
        'tlp-clear': '#27313d', 'tlp-clear-bg': '#e6ebf0', 'tlp-green': '#14532d', 'tlp-green-bg': '#d9f5e3',
        'tlp-amber': '#6f2f07', 'tlp-amber-bg': '#fcefc7', 'tlp-red': '#881337', 'tlp-red-bg': '#ffe2e6',
        'notice-bg': '#10202c', 'notice-text': '#ffffff',
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

# Keep the standard token intact; an audience description does not replace a sharing rule.
# FIRST TLP 2.0: https://www.first.org/tlp/
TLP_AUDIENCES: Final = {
    'CLEAR': 'Public',
    'GREEN': 'Community only',
    'AMBER': 'Need to know',
    'AMBER+STRICT': 'Your organization only',
    'RED': 'Named recipients only',
}
TLP_GUIDANCE: Final = {
    'CLEAR': 'May be shared publicly. Copyright and source terms still apply.',
    'GREEN': "Share within the source's community only. Do not post publicly.",
    'AMBER': 'Share only with people who need to know in your organization and its clients.',
    'AMBER+STRICT': (
        'Share only with people who need to know in your organization. Do not share with clients.'
    ),
    'RED': 'Only the people who received this may read it. Do not share it further.',
}


def tlp_text(value: str) -> str:
    """An audience hint beside the exact stored label, never a new classification."""
    return f'{TLP_AUDIENCES.get(value, "Sharing not confirmed")} · TLP:{value}'


def tlp_guidance(value: str) -> str:
    """Explain who may receive the information, without changing its source terms."""
    return TLP_GUIDANCE.get(value, 'Do not share this until the source confirms its sharing label.')


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
    css_class = TLP_CLASSES.get(value, TLP_CLASSES['RED'])
    ui.label(tlp_text(value)).classes(
        f'tlp-badge {css_class} text-xs rounded px-2 py-1 max-w-full whitespace-normal break-value shrink-0'
    ).tooltip(tlp_guidance(value))
