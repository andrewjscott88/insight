"""Colour themes and readability of the colours (ADR 0016, ADR 0017).

Contrast is checked from the same token values the pages use, in both themes:

* WCAG 2.2 **AAA**: 7:1 for every text colour on every background it is used on (SC 1.4.6), 3:1 for field
  borders and the focus outline (SC 1.4.11, 2.4.13);
* **APCA** (the contrast method in the WCAG 3 drafts; informative): |Lc| 90+ for body text, 75+ for everything
  else. The formula is ported from the reference implementation ``apca-w3`` 0.1.9 and checked against it.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st

import insight
from insight.appearance import (
    DEFAULT_TEXT_SIZE,
    DEFAULT_THEME,
    PAGE_BACKGROUND,
    TEXT_SIZE_COOKIE,
    TEXT_SIZES,
    THEME_COOKIE,
    THEMES,
    dark_mode_value,
    parse_theme,
    text_size_choice,
    text_size_cookie_script,
    theme_choice,
    theme_cookie_script,
)
from insight.ui.appearance import theme_color_script
from insight.ui.styles import QUASAR_OVERRIDES, STYLE, TEXT_SIZE_STYLE
from insight.ui.theme import PALETTES, TLP_CLASSES, palette_css, theme_head_html

APP_CSS = (Path(insight.__file__).parent / 'static' / 'app.css').read_text()
TEXT_AAA = 7.0  # WCAG 1.4.6 Contrast (Enhanced)
NON_TEXT = 3.0  # WCAG 1.4.11 Non-text Contrast; 2.4.13 Focus Appearance
APCA_BODY = 90.0  # APCA: preferred for body text
APCA_MIN = 75.0  # APCA: minimum for body text
TEXT_TOKENS = ('text', 'muted', 'accent', 'link', 'warn', 'error')
BACKGROUNDS = ('bg', 'panel', 'card', 'hover', 'selected', 'field', 'evidence-bg')


def luminance(color: str) -> float:
    channels = [int(color.lstrip('#')[i : i + 2], 16) / 255 for i in (0, 2, 4)]
    r, g, b = (c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4 for c in channels)
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def contrast(foreground: str, background: str) -> float:
    light, dark = sorted((luminance(foreground), luminance(background)), reverse=True)
    return (light + 0.05) / (dark + 0.05)


def apca(text: str, background: str) -> float:
    """APCA lightness contrast Lc (apca-w3 0.1.9, constants 0.0.98G-4g). Positive: dark text on light."""

    def y(color: str) -> float:
        r, g, b = (int(color.lstrip('#')[i : i + 2], 16) / 255 for i in (0, 2, 4))
        value = float(0.2126729 * r**2.4 + 0.7151522 * g**2.4 + 0.0721750 * b**2.4)
        return value if value > 0.022 else value + float((0.022 - value) ** 1.414)

    text_y, background_y = y(text), y(background)
    if abs(background_y - text_y) < 0.0005:
        return 0.0
    if background_y > text_y:
        sapc = float(background_y**0.56 - text_y**0.57) * 1.14
        return 0.0 if sapc < 0.1 else (sapc - 0.027) * 100
    sapc = float(background_y**0.65 - text_y**0.62) * 1.14
    return 0.0 if sapc > -0.1 else (sapc + 0.027) * 100


def test_contrast_formulas_match_their_references() -> None:
    assert contrast('#000000', '#ffffff') == pytest.approx(21.0)
    assert contrast('#777777', '#ffffff') == pytest.approx(4.48, abs=0.01)
    # Values from the reference JavaScript implementation (apca-w3 0.1.9, APCAcontrast(sRGBtoY(...))).
    for text, background, expected in (
        ('#000000', '#ffffff', 106.04),
        ('#ffffff', '#000000', -107.88),
        ('#94a5ba', '#111c29', -51.09),
        ('#4f5e70', '#ffffff', 82.78),
        ('#777777', '#ffffff', 71.11),
        ('#eef3f8', '#111c29', -98.03),
    ):
        assert apca(text, background) == pytest.approx(expected, abs=0.05), (text, background)


# --------------------------------------------------------------------------- preference vocabulary


def test_system_theme_and_standard_text_are_the_defaults() -> None:
    assert DEFAULT_THEME == 'system'
    assert THEMES == ('system', 'light', 'dark')
    assert (DEFAULT_TEXT_SIZE, TEXT_SIZES) == ('standard', ('standard', 'large'))


@pytest.mark.parametrize(
    ('raw', 'expected'), [('', 'system'), ('  ', 'system'), ('LIGHT', 'light'), (' dark ', 'dark')]
)
def test_parse_theme(raw: str, expected: str) -> None:
    assert parse_theme(raw) == expected


@pytest.mark.parametrize('raw', ['drak', 'auto', 'on', 'light,dark'])
def test_an_invalid_instance_theme_fails_closed(raw: str) -> None:
    with pytest.raises(RuntimeError, match='INSIGHT_THEME must be one of system, light, dark'):
        parse_theme(raw)


@pytest.mark.parametrize(
    ('cookie', 'default', 'expected'),
    [
        (None, 'system', 'system'),
        ('light', 'system', 'light'),
        ('DARK', 'light', 'dark'),
        ('system', 'dark', 'system'),  # an explicit "System" choice overrides a dark instance default
        ('', 'dark', 'dark'),
        ('<script>alert(1)</script>', 'light', 'light'),
        ('dark; Path=/', 'system', 'system'),
    ],
)
def test_theme_choice_prefers_the_cookie_and_falls_back_to_the_default(
    cookie: str | None, default: str, expected: str
) -> None:
    assert theme_choice(cookie, default) == expected  # type: ignore[arg-type]


@given(st.text())
def test_any_cookie_value_yields_a_known_theme_and_text_size(cookie: str) -> None:
    assert theme_choice(cookie) in THEMES
    assert text_size_choice(cookie) in TEXT_SIZES


def test_dark_mode_values() -> None:
    assert [dark_mode_value(theme) for theme in THEMES] == [None, False, True]


def test_cookie_scripts_remember_the_choice_for_a_year_and_are_secure_behind_https() -> None:
    plain = theme_cookie_script('light', secure=False)
    assert f"document.cookie = '{THEME_COOKIE}=light; Path=/; Max-Age=31536000; SameSite=Lax';" == plain
    assert theme_cookie_script('dark', secure=True).endswith("SameSite=Lax; Secure';")
    size = text_size_cookie_script('large', secure=True)
    assert (
        f"document.cookie = '{TEXT_SIZE_COOKIE}=large; Path=/; Max-Age=31536000; SameSite=Lax; Secure';"
        == size
    )


def test_cookie_scripts_only_ever_write_a_known_value() -> None:
    assert f'{THEME_COOKIE}=system;' in theme_cookie_script("x'; alert(1); '", secure=False)  # type: ignore[arg-type]
    assert f'{TEXT_SIZE_COOKIE}=standard;' in text_size_cookie_script("x'; '", secure=False)  # type: ignore[arg-type]


# --------------------------------------------------------------------------- palettes and contrast


def test_both_palettes_define_the_same_tokens() -> None:
    assert set(PALETTES) == {'dark', 'light'}
    assert PALETTES['dark'].keys() == PALETTES['light'].keys()
    assert all(
        re.fullmatch(r'#[0-9a-f]{6}', value) for palette in PALETTES.values() for value in palette.values()
    )


def test_page_background_matches_the_palettes() -> None:
    assert {theme: palette['bg'] for theme, palette in PALETTES.items()} == PAGE_BACKGROUND


def test_every_token_the_styles_use_is_defined() -> None:
    used = set(re.findall(r'var\(--ins-([a-z-]+)\)', STYLE + QUASAR_OVERRIDES))
    assert used
    assert used <= PALETTES['dark'].keys()


@pytest.mark.parametrize('theme', ['dark', 'light'])
@pytest.mark.parametrize('foreground', TEXT_TOKENS)
def test_text_meets_wcag_aaa_on_every_background(theme: str, foreground: str) -> None:
    palette = PALETTES[theme]
    for background in BACKGROUNDS:
        ratio = contrast(palette[foreground], palette[background])
        assert ratio >= TEXT_AAA, f'{theme}: {foreground} on {background} is {ratio:.2f}:1'


@pytest.mark.parametrize('theme', ['dark', 'light'])
@pytest.mark.parametrize(
    ('foreground', 'minimum'), [('text', APCA_BODY), *((t, APCA_MIN) for t in TEXT_TOKENS[1:])]
)
def test_text_meets_apca_on_every_background(theme: str, foreground: str, minimum: float) -> None:
    palette = PALETTES[theme]
    for background in BACKGROUNDS:
        lc = abs(apca(palette[foreground], palette[background]))
        assert lc >= minimum, f'{theme}: {foreground} on {background} is Lc {lc:.1f}'


def test_regression_dark_secondary_text_was_far_too_faint_for_apca() -> None:
    """Regression: #94a5ba on #111c29 passed WCAG 2 (6.8:1) but is APCA Lc 51: legible only at ~31 px."""
    assert contrast('#94a5ba', '#111c29') > 4.5
    assert abs(apca('#94a5ba', '#111c29')) < 55
    assert abs(apca(PALETTES['dark']['muted'], PALETTES['dark']['panel'])) >= 85


@pytest.mark.parametrize('theme', ['dark', 'light'])
def test_labels_on_filled_buttons_badges_and_messages_meet_aaa(theme: str) -> None:
    palette = PALETTES[theme]
    pairs = [('on-accent', 'accent')] + [
        (label, f'{label}-bg') for label in sorted(set(TLP_CLASSES.values()))
    ]
    pairs += [('notice-text', 'notice-bg'), ('notice-warn-text', 'notice-warn-bg')]
    pairs += [('notice-error-text', 'notice-error-bg')]
    for foreground, background in pairs:
        ratio = contrast(palette[foreground], palette[background])
        assert ratio >= TEXT_AAA, f'{theme}: {foreground} on {background} is {ratio:.2f}:1'
        assert abs(apca(palette[foreground], palette[background])) >= APCA_MIN, (theme, foreground)


def test_regression_white_labels_on_the_mint_primary_were_unreadable() -> None:
    """Regression: Quasar painted filled buttons' labels white on #76dfc7 (1.6:1). The override must stay."""
    assert contrast('#ffffff', '#76dfc7') < 2
    assert '@layer theme' in QUASAR_OVERRIDES
    assert '.q-btn.bg-primary.text-white { color:var(--ins-on-accent) !important; }' in QUASAR_OVERRIDES


@pytest.mark.parametrize('theme', ['dark', 'light'])
def test_field_borders_and_the_focus_outline_are_visible(theme: str) -> None:
    """Regression: light-theme field borders were 1.78:1, so the search box and fields were hard to see."""
    palette = PALETTES[theme]
    for background in ('bg', 'panel', 'card', 'field', 'selected'):
        assert contrast(palette['field-border'], palette[background]) >= NON_TEXT, (theme, background)
        assert contrast(palette['focus'], palette[background]) >= NON_TEXT, (theme, background)


def test_quasar_colour_variables_follow_the_theme_over_nicegui_inline_defaults() -> None:
    for theme in PALETTES:
        css = palette_css(theme)
        assert css.startswith(f'body.body--{theme}{{')
        assert f'--q-primary:{PALETTES[theme]["accent"]} !important;' in css


def test_regression_quasars_dark_surface_is_only_remapped_in_the_dark_theme() -> None:
    """--q-dark is also Quasar's ``text-dark`` colour: a light value made dark text white in light mode."""
    assert '--q-dark:' in palette_css('dark')
    assert '--q-dark' not in palette_css('light')


def test_theme_head_html_sets_the_first_paint_and_the_text_size() -> None:
    system = theme_head_html('system')
    assert system.count('<meta name="theme-color"') == 2
    assert 'media="(prefers-color-scheme: light)" content="#f6f4fa"' in system
    assert 'media="(prefers-color-scheme: dark)" content="#050407"' in system
    light = theme_head_html('light', 'large')
    assert light.count('<meta name="theme-color"') == 1
    assert 'content="#f6f4fa"' in light
    assert 'prefers-color-scheme' not in light
    assert 'document.documentElement.dataset.text = "large";' in light


def test_theme_color_script_replaces_the_address_bar_colour() -> None:
    assert theme_color_script('dark').count("name: 'theme-color'") == 1
    assert "content: '#050407'" in theme_color_script('dark')
    assert theme_color_script('system').count('prefers-color-scheme') == 2


# --------------------------------------------------------------------------- typography (ADR 0017)


def test_no_text_is_smaller_than_16px_and_lines_are_spaced_1_5() -> None:
    """BDA style guide: 16-19 px; WCAG 1.4.8: line spacing at least 1.5. Tailwind's sizes are remapped."""
    assert (
        ':root { --text-xs:1rem;--text-xs--line-height:1.5;--text-sm:1rem;--text-sm--line-height:1.5;'
        in STYLE
    )
    assert 'font-size:1rem;\n  line-height:1.5;' in STYLE
    sizes = [float(size) for size in re.findall(r'font-size:([\d.]+)rem', STYLE)]
    assert min(sizes) >= 1.0
    assert 'px;' not in ''.join(re.findall(r'font-size:[^;]+;', STYLE)), (
        'sizes in rem, so "Larger text" scales'
    )


def test_lines_are_about_70_characters_and_nothing_is_in_capitals() -> None:
    assert '.prose, .source-body, .evidence { max-width:56ch; }' in STYLE
    assert 'text-transform:none' in STYLE
    assert 'uppercase' not in STYLE + QUASAR_OVERRIDES


def test_keyboard_focus_is_a_3px_outline_and_motion_can_be_turned_off() -> None:
    assert 'outline:3px solid var(--ins-focus) !important' in QUASAR_OVERRIDES
    assert '@media (prefers-reduced-motion: reduce)' in QUASAR_OVERRIDES
    assert (
        '.q-btn { text-transform:none;font-weight:600;font-size:1rem;line-height:1.5;min-height:2.75rem; }'
        in STYLE
    )


def test_larger_text_scales_everything_and_adds_space() -> None:
    assert 'html[data-text="large"] { font-size:118.75%;' in TEXT_SIZE_STYLE
    assert 'letter-spacing:0.03em;word-spacing:0.1em;' in TEXT_SIZE_STYLE
    assert '[data-text="large"] { font-size: 118.75%; }' in APP_CSS


# --------------------------------------------------------------------------- sign-in stylesheet (app.css)

SHARED_TOKENS = (
    'bg',
    'panel',
    'field',
    'line',
    'field-border',
    'focus',
    'text',
    'muted',
    'accent',
    'on-accent',
)


def css_block(selector: str, css: str = APP_CSS) -> dict[str, str]:
    match = re.search(re.escape(selector) + r'\s*\{([^}]*)\}', css)
    assert match, f'no {selector} block in app.css'
    return dict(re.findall(r'--([a-z-]+):\s*([^;]+);', match.group(1)))


def app_css_palettes() -> dict[str, dict[str, str]]:
    return {'dark': css_block('[data-theme="dark"]'), 'light': css_block('[data-theme="light"]')}


def test_app_css_system_theme_uses_the_light_tokens_when_the_device_is_light() -> None:
    media = APP_CSS[APP_CSS.index('@media (prefers-color-scheme: light)') :]
    assert css_block('[data-theme="system"]', media) == app_css_palettes()['light']
    assert APP_CSS.index(':root,') < APP_CSS.index('[data-theme="dark"]'), 'dark is the fallback'


def test_app_css_matches_the_workspace_palettes() -> None:
    for theme, tokens in app_css_palettes().items():
        assert tokens.keys() == {*SHARED_TOKENS, 'error', 'glow'}
        for name in (*SHARED_TOKENS, 'error'):
            assert tokens[name] == PALETTES[theme][name], f'{theme} --{name}'


@pytest.mark.parametrize('theme', ['dark', 'light'])
def test_sign_in_page_colours_meet_aaa(theme: str) -> None:
    tokens = app_css_palettes()[theme]
    for foreground in ('text', 'muted', 'accent', 'error'):
        for background in ('bg', 'panel', 'field'):
            assert contrast(tokens[foreground], tokens[background]) >= TEXT_AAA, (
                theme,
                foreground,
                background,
            )
    assert contrast(tokens['on-accent'], tokens['accent']) >= TEXT_AAA
    assert contrast(tokens['field-border'], tokens['field']) >= NON_TEXT


def test_sign_in_text_and_inputs_are_16px_and_in_rem() -> None:
    assert re.search(r'\ninput \{[^}]*font-size: 1rem;', APP_CSS)
    assert re.search(r'\nbody \{[^}]*font-size: 1rem;\s*line-height: 1.5;', APP_CSS)
    sizes = [float(size) for size in re.findall(r'font-size: ([\d.]+)rem', APP_CSS)]
    assert min(sizes) >= 1.0
    assert 'outline: 3px solid var(--focus);' in APP_CSS


def test_regression_the_sign_in_card_fits_a_phone_screen() -> None:
    """Regression: `max-width: calc(100% - 32px)` inside the grid resolved against the card itself."""
    block = re.search(r'\.login-card \{([^}]*)\}', re.sub(r'/\*.*?\*/', '', APP_CSS, flags=re.DOTALL))
    assert block
    assert 'width: min(28rem, calc(100vw - 32px));' in block.group(1)
    assert 'max-width: calc(100%' not in block.group(1)


def test_a_field_example_stays_hidden_while_the_label_sits_in_the_field() -> None:
    """Regression: the readable placeholder colour must not undo Quasar's hiding of an example (overlap)."""
    shown = STYLE.index(
        '.q-field__native::placeholder, .q-field__input::placeholder { color:var(--ins-muted)'
    )
    hidden = STYLE.index('.q-field--labeled:not(.q-field--float) .q-field__native::placeholder')
    assert shown < hidden
    rule = STYLE[hidden : STYLE.index('}', hidden)]
    assert '.q-field--labeled:not(.q-field--float) .q-field__input::placeholder' in rule
    assert 'color:transparent' in rule
