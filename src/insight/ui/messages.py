"""On-screen messages that people can read at their own pace (WCAG 2.2.1, 2.2.3; W3C COGA).

Quasar's notifications disappeared after about five seconds, errors included: too short for many readers.
Every message now stays until it is dismissed, or until the next message replaces it: they share one Quasar
``group``, so only the newest is on screen and they never pile up over the page. Screen readers announce them
(Quasar gives notifications ``role="alert"``). Colours come from the theme (7:1).

Messages sit below dialogs, so they never cover a dialog's buttons (WCAG 2.4.11). A problem that happens while
a dialog stays open is therefore written *inside* the dialog, in its :func:`problem_area`.
"""

from __future__ import annotations

from typing import Final, Literal

from nicegui import ui

Kind = Literal['info', 'success', 'warning', 'error']
GROUP: Final = 'insight-message'
DISMISS: Final = 'Dismiss'
_QUASAR_TYPES: Final[dict[str, str]] = {'warning': 'warning', 'error': 'negative'}


def tell(message: str, kind: Kind = 'info') -> None:
    """Show ``message`` until the reader dismisses it or a newer message replaces it."""
    options: dict[str, object] = {
        'timeout': 0,
        'group': GROUP,
        'close_button': DISMISS,
        'multi_line': True,
        'classes': f'insight-notice insight-notice--{kind}',
    }
    if kind in _QUASAR_TYPES:
        options['type'] = _QUASAR_TYPES[kind]  # Announced with the matching icon.
    ui.notify(message, **options)  # type: ignore[arg-type]


def problem_area() -> ui.label:
    """A line inside a dialog where problems are written; screen readers announce it (``role="alert"``)."""
    return ui.label().classes('text-error prose').props('role=alert').mark('problem')
