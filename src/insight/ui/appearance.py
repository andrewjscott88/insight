"""Display settings in the workspace header, remembered per device.

Theme: Light, Dark or System (ADR 0016). Text size: "Larger text" on or off (ADR 0017).
"""

from __future__ import annotations

from typing import Final

from nicegui import ui

from ..appearance import (
    PAGE_BACKGROUND,
    TextSize,
    Theme,
    dark_mode_value,
    text_size_cookie_script,
    theme_cookie_script,
)
from .workspace import Workspace

#: (theme, Material icon, button label, tooltip)
THEME_OPTIONS: Final[tuple[tuple[Theme, str, str, str], ...]] = (
    ('light', 'light_mode', 'Light', 'Light theme on this device'),
    ('dark', 'dark_mode', 'Dark', 'Dark theme on this device'),
    ('system', 'brightness_auto', 'System', "Follow this device's light/dark setting"),
)


def theme_color_script(theme: Theme) -> str:
    """JavaScript that recolours the mobile browser's address bar (``<meta name="theme-color">``)."""
    if theme == 'system':
        metas = [(f'(prefers-color-scheme: {name})', color) for name, color in PAGE_BACKGROUND.items()]
    else:
        metas = [('', PAGE_BACKGROUND[theme])]
    adds = ''
    for media, color in metas:
        media_attribute = f", media: '{media}'" if media else ''
        adds += (
            "document.head.append(Object.assign(document.createElement('meta'), "
            f"{{name: 'theme-color', content: '{color}'{media_attribute}}}));"
        )
    return f"document.querySelectorAll('meta[name=theme-color]').forEach((m) => m.remove());{adds}"


class ThemeSwitch:
    """Three buttons; the current choice is highlighted and announced (``aria-pressed``)."""

    def __init__(self, ws: Workspace, dark: ui.dark_mode, current: Theme) -> None:
        self.ws, self.dark, self.current = ws, dark, current
        self.buttons: dict[Theme, ui.button] = {}
        with ui.button_group().props('flat').classes('theme-switch rounded').mark('theme-switch'):
            for theme, icon, label, tip in THEME_OPTIONS:
                # color=None: no Quasar colour class, so the theme's muted/active colours apply.
                button = ui.button(label, icon=icon, color=None, on_click=lambda t=theme: self.choose(t))
                button.props(f'flat dense no-caps aria-label="{label} theme"').mark(f'theme-{theme}')
                button.tooltip(tip)
                self.buttons[theme] = button
        self.show()

    def choose(self, theme: Theme) -> None:
        if not self.ws.authorized():
            return
        self.current = theme
        self.dark.set_value(dark_mode_value(theme))
        secure = bool(self.ws.app.state.settings.secure_cookies)
        ui.run_javascript(theme_cookie_script(theme, secure=secure) + theme_color_script(theme))
        self.show()

    def show(self) -> None:
        for theme, button in self.buttons.items():
            active = theme == self.current
            button.props(f'aria-pressed={str(active).lower()}')
            if active:
                button.classes(add='theme-active')
            else:
                button.classes(remove='theme-active')


class TextSizeSwitch:
    """One toggle button: larger type and more space between letters, words and lines."""

    LABEL: Final = 'Larger text'

    def __init__(self, ws: Workspace, current: TextSize) -> None:
        self.ws, self.current = ws, current
        with ui.element('div').classes('text-size-switch').mark('text-size-switch'):
            self.button = ui.button(self.LABEL, icon='format_size', color=None, on_click=self.toggle)
            self.button.props(f'flat dense no-caps aria-label="{self.LABEL}"').mark('text-size')
            self.button.tooltip('Bigger text with more space, on this device')
        self.show()

    def toggle(self) -> None:
        if not self.ws.authorized():
            return
        self.current = 'standard' if self.current == 'large' else 'large'
        secure = bool(self.ws.app.state.settings.secure_cookies)
        ui.run_javascript(
            text_size_cookie_script(self.current, secure=secure)
            + f"document.documentElement.dataset.text = '{self.current}';"
        )
        self.show()

    def show(self) -> None:
        large = self.current == 'large'
        self.button.props(f'aria-pressed={str(large).lower()}')
        if large:
            self.button.classes(add='theme-active')
        else:
            self.button.classes(remove='theme-active')
