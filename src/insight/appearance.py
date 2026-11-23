"""Colour theme vocabulary shared by the configuration, the sign-in pages and the workspace.

Three themes: ``system`` follows the device's light/dark preference (and changes with it); ``light``
and ``dark`` are fixed. The operator sets the instance default with ``INSIGHT_THEME``. A browser that picks
a theme in the workspace remembers it in the ``insight_theme`` cookie, per device. That cookie is a display
preference: it holds no secret and is never used for authentication. See ADR 0016.

The text size works the same way: ``standard`` or ``large`` ("Larger text": bigger type and more space between
letters, words and lines, for people who find dense text hard to read), remembered per device in the
``insight_text`` cookie. See ADR 0017.
"""

from __future__ import annotations

from typing import Final, Literal, TypeAlias

Theme: TypeAlias = Literal['system', 'light', 'dark']
TextSize: TypeAlias = Literal['standard', 'large']
THEMES: Final[tuple[Theme, ...]] = ('system', 'light', 'dark')
DEFAULT_THEME: Final[Theme] = 'system'
THEME_COOKIE: Final = 'insight_theme'
#: One year: a display preference should outlive sessions, restarts and upgrades.
THEME_COOKIE_MAX_AGE: Final = 365 * 24 * 60 * 60
TEXT_SIZES: Final[tuple[TextSize, ...]] = ('standard', 'large')
DEFAULT_TEXT_SIZE: Final[TextSize] = 'standard'
TEXT_SIZE_COOKIE: Final = 'insight_text'
#: Page background per theme, also used for the mobile browser's address bar (``<meta name="theme-color">``).
PAGE_BACKGROUND: Final = {'light': '#f1f5f7', 'dark': '#080c10'}


def parse_theme(value: str) -> Theme:
    """``INSIGHT_THEME``: ``system``, ``light`` or ``dark`` (case-insensitive); empty means ``system``.

    Strict, like every other setting: a typo such as ``INSIGHT_THEME=drak`` stops start-up with a message
    instead of silently doing something else.
    """
    word = value.strip().lower() or DEFAULT_THEME
    if word not in THEMES:
        raise RuntimeError(f'INSIGHT_THEME must be one of {", ".join(THEMES)}; got {value!r}')
    return word


def theme_choice(cookie: str | None, default: Theme = DEFAULT_THEME) -> Theme:
    """The theme a browser asked for in its cookie, or the instance ``default``.

    Lenient, unlike :func:`parse_theme`: the cookie comes from the browser, so anything unexpected (tampered,
    truncated, from a future version) falls back to the default and is never echoed into a page.
    """
    word = (cookie or '').strip().lower()
    return word if word in THEMES else default


def text_size_choice(cookie: str | None) -> TextSize:
    """The text size a browser asked for in its cookie; anything unexpected means ``standard``."""
    word = (cookie or '').strip().lower()
    return word if word in TEXT_SIZES else DEFAULT_TEXT_SIZE


def dark_mode_value(theme: Theme) -> bool | None:
    """The theme as NiceGUI/Quasar's dark mode value: ``None`` is "auto" (follow the device)."""
    return {'system': None, 'light': False, 'dark': True}[theme]


def _cookie_script(name: str, value: str, *, secure: bool) -> str:
    attributes = f'Path=/; Max-Age={THEME_COOKIE_MAX_AGE}; SameSite=Lax' + ('; Secure' if secure else '')
    return f"document.cookie = '{name}={value}; {attributes}';"


def theme_cookie_script(theme: Theme, *, secure: bool) -> str:
    """JavaScript that remembers ``theme`` in this browser (run when the operator picks one)."""
    return _cookie_script(THEME_COOKIE, theme_choice(theme), secure=secure)


def text_size_cookie_script(size: TextSize, *, secure: bool) -> str:
    """JavaScript that remembers the text size in this browser."""
    return _cookie_script(TEXT_SIZE_COOKIE, text_size_choice(size), secure=secure)
